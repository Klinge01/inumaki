//! M4 spec §16.3: every released gateway result is journaled under its
//! activity record's id, sealed; blocked results are not; `show` prints
//! tokens by default and rehydrates locally on request; the journal can
//! be switched off without losing activity records; the sweeper applies
//! `[journal]` retention and budget; a tampered row is a fixed error; no
//! payload, value, slug, or query string reaches a log line or an error.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use common::gateway::*;
use common::{BASE_CONFIG, Capture, TestDaemon, start_with};
use hyper::Method;
use inumaki_vault::{Clock, Direction, FrontDoor, NewActivity, Verdict};
use rmcp::model::CallToolRequestParams;
use serde_json::json;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

async fn journal(d: &TestDaemon, dataset: &str) -> Vec<serde_json::Value> {
    let (code, body) = d
        .call(
            Method::GET,
            &format!("/v1/datasets/{dataset}/journal"),
            None,
        )
        .await;
    assert_eq!(code, 200, "{body}");
    body["entries"].as_array().unwrap().clone()
}

async fn wait_journal(d: &TestDaemon, dataset: &str, n: usize) -> Vec<serde_json::Value> {
    for _ in 0..100 {
        let e = journal(d, dataset).await;
        if e.len() >= n {
            return e;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("fewer than {n} journal entries");
}

async fn wait_records(d: &TestDaemon, dataset: &str, n: usize) -> Vec<serde_json::Value> {
    for _ in 0..100 {
        let (_, body) = d
            .call(
                Method::GET,
                &format!("/v1/activity?dataset={dataset}"),
                None,
            )
            .await;
        let recs = body["records"].as_array().unwrap().clone();
        if recs.len() >= n {
            return recs;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("fewer than {n} activity records");
}

/// An object's keys, sorted.
fn keys_of(v: &serde_json::Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

/// The JSON shapes are a contract the M6 app consumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_released_result_is_journaled_and_linked_to_its_record() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let person = token_in(&texts(&r), "<PERSON_");
    let entries = wait_journal(&d, "crm", 1).await;
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(
        keys_of(e),
        ["at", "bytes", "id", "released"],
        "listing entry shape"
    );
    let id = e["id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 32);
    assert!(e["at"].is_i64());
    assert!(e["bytes"].as_u64().unwrap() > 0);
    assert_eq!(e["released"].as_str().unwrap().len(), 64);
    let recs = wait_records(&d, "crm", 1).await;
    let rec = recs
        .iter()
        .find(|x| x["id"] == id)
        .expect("the journal entry names an activity record");
    assert_eq!(rec["verdict"], "released");
    assert_eq!(
        rec["released"], e["released"],
        "linked by digest as well as id"
    );
    assert_eq!(rec["bytes"], e["bytes"]);
    // tokens by default
    let (code, s) = d
        .call(Method::GET, &format!("/v1/datasets/crm/journal/{id}"), None)
        .await;
    assert_eq!(code, 200, "{s}");
    assert_eq!(
        keys_of(&s),
        [
            "at",
            "bytes",
            "id",
            "label",
            "payload",
            "released",
            "show_values",
            "unresolved"
        ],
        "show body shape"
    );
    assert_eq!(s["id"], id);
    assert_eq!(s["at"], e["at"]);
    assert_eq!(s["bytes"], e["bytes"]);
    assert_eq!(s["released"], e["released"]);
    assert_eq!(s["show_values"], false);
    assert_eq!(s["unresolved"], 0);
    assert_eq!(s["label"], "released payload as sent (tokens)");
    let payload = s["payload"].as_str().unwrap();
    assert_eq!(payload.len() as u64, e["bytes"].as_u64().unwrap());
    assert!(
        payload.contains(&person) && !payload.contains("Zyxwuria"),
        "{payload}"
    );
    // What the client received, compared as JSON (serialization order may
    // differ). The rmcp round trip is lossless for this result, so the
    // whole value is compared, not only `content`/`structuredContent`.
    let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
    assert_eq!(parsed, serde_json::to_value(&r).unwrap());
    assert_eq!(parsed["structuredContent"]["customer"]["name"], person);
    assert!(
        !serde_json::to_string(&entries)
            .unwrap()
            .contains("Zyxwuria")
    );
    // originals on explicit request
    let (code, v) = d
        .call(
            Method::GET,
            &format!("/v1/datasets/crm/journal/{id}?show_values=true"),
            None,
        )
        .await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["show_values"], true);
    assert!(v["payload"].as_str().unwrap().contains(CANARY), "{v}");
    assert!(!v["payload"].as_str().unwrap().contains(&person));
    assert_eq!(v["unresolved"], 0);
    assert_eq!(
        v["label"],
        "originals revealed locally — not for transmission"
    );
    // shape errors never echo the input
    let (code, b) = d
        .call(Method::GET, "/v1/datasets/crm/journal/not-an-id", None)
        .await;
    assert_eq!(code, 400, "{b}");
    assert!(!b.to_string().contains("not-an-id"));
    let (code, b) = d
        .call(
            Method::GET,
            &format!("/v1/datasets/crm/journal/{}", "0".repeat(32)),
            None,
        )
        .await;
    assert_eq!(code, 404, "{b}");
    assert_eq!(b["error"]["type"], "not_found");
    let (code, _) = d.call(Method::GET, "/v1/datasets/nope/journal", None).await;
    assert_eq!(code, 404);
    // a second call is journaled too; the listing is newest first
    c.peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let entries = wait_journal(&d, "crm", 2).await;
    assert_ne!(entries[0]["id"], entries[1]["id"]);
    assert!(entries[0]["at"].as_i64().unwrap() >= entries[1]["at"].as_i64().unwrap());
    let (_, one) = d
        .call(Method::GET, "/v1/datasets/crm/journal?limit=1", None)
        .await;
    assert_eq!(one["entries"].as_array().unwrap().len(), 1);
    assert_eq!(one["entries"][0]["id"], entries[0]["id"]);
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["gateway"]["journal_dropped"], 0);
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_results_are_not_journaled() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "blocky").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    assert_eq!(r.is_error, Some(true));
    let recs = wait_records(&d, "crm", 1).await;
    assert_eq!(recs[0]["verdict"], "blocked");
    // an unresolved argument is refused before dispatch: not journaled either
    let e = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo")
                .with_arguments(args(json!({ "query": "<PERSON_000000>" }))),
        )
        .await
        .unwrap_err();
    assert_eq!(mcp_err(e).message, "unresolved_token");
    wait_records(&d, "crm", 2).await;
    // Records and payloads leave the queue together, so once the records
    // are listed a journal entry would be too; wait a little regardless.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        journal(&d, "crm").await.is_empty(),
        "nothing left, nothing journaled"
    );
    c.cancel().await.ok();
    d.stop().await;
}

/// Review Focus 5 (daemon side).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabled_journal_keeps_activity_records() {
    let (d, _dict) = daemon("\n[journal]\nenabled = false\n").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    c.peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let recs = wait_records(&d, "crm", 1).await;
    assert_eq!(recs[0]["verdict"], "released");
    assert!(
        recs[0]["released"].is_string(),
        "the record keeps its digest"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(journal(&d, "crm").await.is_empty());
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(
        st["gateway"]["journal_dropped"], 0,
        "disabled is not a drop"
    );
    assert_eq!(st["gateway"]["activity_dropped"], 0);
    c.cancel().await.ok();
    d.stop().await;
}

#[test]
fn journal_config_defaults_and_rejections() {
    use inumakid::config::{DaemonConfig, parse_bytes};
    let base = format!("{BASE_CONFIG}\n[daemon]\ndefault_profile = \"offline\"\n");
    let c = DaemonConfig::from_toml(&base).unwrap();
    assert!(c.journal.enabled);
    assert_eq!(c.journal_retention, Duration::from_secs(24 * 3600));
    assert_eq!(c.journal_max_bytes, 64_000_000);
    assert!(c.gateway_config().journal);
    let c = DaemonConfig::from_toml(&format!(
        "{base}[journal]\nenabled = false\nretention = \"2h\"\nmax_bytes = \"8MiB\"\n"
    ))
    .unwrap();
    assert!(!c.journal.enabled && !c.gateway_config().journal);
    assert_eq!(
        (c.journal_retention, c.journal_max_bytes),
        (Duration::from_secs(7200), 8 << 20)
    );
    assert_eq!(parse_bytes("64MB"), Some(64_000_000));
    assert_eq!(parse_bytes("2GB"), Some(2_000_000_000));
    assert_eq!(parse_bytes("1GiB"), Some(1 << 30));
    assert_eq!(parse_bytes("10KB"), Some(10_000));
    for (extra, key) in [
        ("[journal]\nretention = \"soon\"\n", "journal.retention"),
        ("[journal]\nretention = \"0s\"\n", "journal.retention"),
        ("[journal]\nmax_bytes = \"1KiB\"\n", "journal.max_bytes"),
        ("[journal]\nmax_bytes = \"lots\"\n", "journal.max_bytes"),
    ] {
        let e = DaemonConfig::from_toml(&format!("{base}{extra}")).unwrap_err();
        assert!(format!("{e}").contains(key), "{extra}: {e}");
        assert!(!format!("{e}").contains("soon") && !format!("{e}").contains("lots"));
    }
}

struct FakeClock(AtomicI64);
impl Clock for FakeClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Store a released record and its journal entry directly in the vault.
fn put(d: &TestDaemon, dataset: &str, payload: &[u8]) {
    let v = &d.state.vault;
    let rec = v
        .append_activity(NewActivity {
            dataset: v.opaque_ref(dataset),
            front_door: FrontDoor::Gateway,
            upstream: None,
            direction: Direction::Result,
            verdict: Verdict::Released,
            checks: Vec::new(),
            kinds: Vec::new(),
            tripwire: false,
            bytes: payload.len() as u64,
            released: Some(v.released_digest(payload)),
        })
        .unwrap();
    v.append_journal(
        dataset,
        &rec.id,
        rec.at,
        rec.released.as_ref().unwrap(),
        payload,
    )
    .unwrap();
}

/// The sweeper applies `[journal] retention` and the per-dataset
/// `max_bytes` from the configuration (the vault's own tests pin the
/// oldest-first and per-dataset rules).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweeper_applies_journal_retention_and_budget() {
    let clock = Arc::new(FakeClock(AtomicI64::new(1_700_000_000)));
    let d = start_with(
        "",
        "[journal]\nretention = \"1h\"\nmax_bytes = \"64KiB\"\n",
        Duration::from_secs(3600),
        Some(Arc::clone(&clock) as Arc<dyn Clock>),
    )
    .await;
    d.dataset("crm").await;
    d.dataset("quiet").await;
    put(&d, "crm", &[b'a'; 1000]);
    put(&d, "quiet", &[b'q'; 1000]);
    clock.0.fetch_add(2 * 3600, Ordering::SeqCst);
    for fill in *b"bcd" {
        put(&d, "crm", &[fill; 30 * 1024]);
    }
    put(&d, "quiet", &[b'r'; 1000]);
    let s = d.state.sweep_once();
    assert_eq!((s.journal_expired, s.journal_over_budget), (2, 1), "{s:?}");
    let crm = journal(&d, "crm").await;
    assert_eq!(crm.len(), 2, "the two newest fit the 64 KiB budget");
    assert_eq!(journal(&d, "quiet").await.len(), 1);
    let s = d.state.sweep_once();
    assert_eq!((s.journal_expired, s.journal_over_budget), (0, 0));
    d.stop().await;
}

/// Every journal endpoint under a TRACE subscriber behind the daemon's
/// privacy filter: the canary name, its token, the payload, the dataset
/// slug, and raw query strings never reach a log line; error bodies
/// (including a tampered row's) are fixed and carry none of them either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn journal_endpoints_never_log_values_and_tampered_rows_fail_closed() {
    const SLUG: &str = "qwxzvk-canary-slug";
    let cap = Capture::new();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(inumakid::run::log_filter(EnvFilter::new("trace"))),
        )
        .init();
    let (d, _dict) = daemon("").await;
    add_dataset(&d, SLUG, "offline").await;
    add_stdio(&d, SLUG, "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, SLUG, "a").await;
    let c = socket_client(&d, SLUG).await.unwrap();
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let person = token_in(&texts(&r), "<PERSON_");
    let entries = wait_journal(&d, SLUG, 1).await;
    let id = entries[0]["id"].as_str().unwrap().to_string();
    let base = format!("/v1/datasets/{SLUG}/journal");
    let (code, s) = d.call(Method::GET, &format!("{base}/{id}"), None).await;
    assert_eq!(code, 200, "{s}");
    let (code, v) = d
        .call(Method::GET, &format!("{base}/{id}?show_values=true"), None)
        .await;
    assert_eq!(code, 200, "{v}");
    assert!(v["payload"].as_str().unwrap().contains(CANARY));
    let mut errors = Vec::new();
    for (path, want) in [
        (format!("{base}?since=hunter2-canary"), 400),
        (format!("{base}?limit=Zyxwuria"), 400),
        (format!("{base}/{id}?show_values=Zyxwuria"), 400),
        (format!("{base}/hunter2-canary"), 400),
        (format!("{base}/{}", "f".repeat(32)), 404),
        (format!("/v1/datasets/{SLUG}-gone/journal"), 404),
        (format!("/v1/datasets/{SLUG}-gone/journal/{id}"), 404),
        ("/v1/datasets/Zyxwuria%2Fx/journal".to_string(), 400),
    ] {
        let (code, b) = d.call(Method::GET, &path, None).await;
        assert_eq!(code, want, "{path}: {b}");
        assert!(b["error"]["message"].is_string(), "{b}");
        errors.push(b.to_string());
    }
    // Tamper with the stored payload: one flipped ciphertext byte.
    {
        let db =
            rusqlite::Connection::open(d.dir.path().join("data").join("vault.sqlite")).unwrap();
        let mut blob: Vec<u8> = db
            .query_row(
                "SELECT payload FROM journal WHERE record_id = ?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        blob[0] ^= 1;
        db.execute(
            "UPDATE journal SET payload = ?1 WHERE record_id = ?2",
            rusqlite::params![blob, id],
        )
        .unwrap();
    }
    for q in ["", "?show_values=true"] {
        let (code, b) = d.call(Method::GET, &format!("{base}/{id}{q}"), None).await;
        assert_eq!(code, 500, "{b}");
        assert_eq!(b["error"]["type"], "journal_record");
        assert_eq!(
            b["error"]["message"],
            "a journal entry failed validation; nothing is shown"
        );
        errors.push(b.to_string());
    }
    c.cancel().await.ok();
    d.stop().await;
    let logs = cap.text();
    assert!(
        logs.contains("journal entry shown"),
        "the handlers log at all"
    );
    assert!(
        logs.contains("reveal=true"),
        "the reveal flag is logged by name"
    );
    for needle in [
        "Zyxwuria",
        "Quolnath",
        "hunter2",
        "qwxzvk",
        "show_values=true",
        "structuredContent",
        &person,
        &id,
    ] {
        assert!(
            !logs.contains(needle),
            "{needle} leaked into the logs:\n{logs}"
        );
        for e in &errors {
            assert!(!e.contains(needle), "{needle} leaked into an error: {e}");
        }
    }
}
