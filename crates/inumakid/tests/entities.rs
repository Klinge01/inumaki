//! M4 spec §16.3: a dataset's entities are listed by token (originals on
//! request), and one entity can be forgotten by token or by value: its rows
//! in every epoch, its known-entity entry, its working-set copy, and every
//! cached result go; the next mention mints a fresh token; journal entries
//! that carry the old token show it as unresolved.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::gateway::*;
use common::{TestDaemon, encode_segment};
use hyper::Method;
use rmcp::model::CallToolRequestParams;
use serde_json::json;

const IBAN: &str = "AT61 1904 3002 3457 3201";

async fn entities(d: &TestDaemon, dataset: &str, show_values: bool) -> Vec<serde_json::Value> {
    let (code, body) = d
        .call(
            Method::GET,
            &format!("/v1/datasets/{dataset}/entities?show_values={show_values}"),
            None,
        )
        .await;
    assert_eq!(code, 200, "{body}");
    body["entities"].as_array().unwrap().clone()
}

async fn sanitize(d: &TestDaemon, dataset: &str, text: &str) -> serde_json::Value {
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": dataset, "text": text })),
        )
        .await;
    assert_eq!(code, 200, "{body}");
    body
}

async fn forget_token(d: &TestDaemon, dataset: &str, token: &str) -> (u16, serde_json::Value) {
    d.call(
        Method::DELETE,
        &format!("/v1/datasets/{dataset}/entities/{}", encode_segment(token)),
        None,
    )
    .await
}

fn keys_of(v: &serde_json::Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn entities_list_and_forget_by_token_and_by_value() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    let text = format!("{CANARY}, IBAN {IBAN}, danke.");
    let a = sanitize(&d, "crm", &text).await;
    let person = token_in(a["text"].as_str().unwrap(), "<PERSON_");
    let iban = token_in(a["text"].as_str().unwrap(), "<IBAN_");
    let list = entities(&d, "crm", false).await;
    assert_eq!(list.len(), 2, "{list:?}");
    let p = list.iter().find(|e| e["token"] == person).unwrap();
    // The JSON shape is a contract (the M6 app reads it).
    assert_eq!(
        keys_of(p),
        [
            "current_epoch",
            "epoch_id",
            "first_use",
            "kind",
            "last_use",
            "surface_forms",
            "token",
            "uses"
        ]
    );
    assert_eq!(p["kind"], "PERSON");
    assert_eq!(p["uses"], 1);
    assert_eq!(p["current_epoch"], true);
    assert!(p["epoch_id"].is_i64());
    assert!(p.get("original").is_none(), "metadata by default");
    assert!(p["first_use"].as_i64().unwrap() > 0 && p["first_use"] == p["last_use"]);
    assert!(!serde_json::to_string(&list).unwrap().contains("Zyxwuria"));
    let with = entities(&d, "crm", true).await;
    let pw = with.iter().find(|e| e["token"] == person).unwrap();
    assert_eq!(pw["original"], CANARY);
    assert_eq!(keys_of(pw).len(), 9);
    assert_eq!(
        with.iter().find(|e| e["token"] == iban).unwrap()["original"],
        IBAN
    );
    let (_, one) = d
        .call(Method::GET, "/v1/datasets/crm/entities?limit=1", None)
        .await;
    assert_eq!(one["entities"].as_array().unwrap().len(), 1);
    // A malformed query is a fixed 400 that echoes nothing.
    let (code, b) = d
        .call(
            Method::GET,
            "/v1/datasets/crm/entities?show_values=Zyxwuria",
            None,
        )
        .await;
    assert_eq!(code, 400, "{b}");
    assert!(!b.to_string().contains("Zyxwuria"), "{b}");
    // forget by token: the row, then a fresh token on the next mention, no cache hit
    let (code, f) = forget_token(&d, "crm", &person).await;
    assert_eq!(code, 200, "{f}");
    // Nothing else writes in this test, so the WAL is still empty from
    // forget's wal_checkpoint(TRUNCATE): no pre-delete page image is left.
    let wal = d.dir.path().join("data").join("vault.sqlite-wal");
    assert_eq!(std::fs::metadata(&wal).map_or(0, |m| m.len()), 0);
    assert_eq!(keys_of(&f), ["kinds", "rows", "tokens"]);
    assert_eq!(f["kinds"], json!(["PERSON"]));
    assert_eq!((&f["tokens"], &f["rows"]), (&json!(1), &json!(1)));
    assert_eq!(entities(&d, "crm", false).await.len(), 1);
    let (code, b) = forget_token(&d, "crm", &person).await;
    assert_eq!(code, 404);
    assert_eq!(b["error"]["type"], "not_found");
    assert!(!b.to_string().contains("PERSON_"), "{b}");
    let b = sanitize(&d, "crm", &text).await;
    assert_eq!(b["cached"], false, "the dataset's cache was invalidated");
    let fresh = token_in(b["text"].as_str().unwrap(), "<PERSON_");
    assert_ne!(fresh, person, "a later occurrence mints a fresh token");
    assert_eq!(
        token_in(b["text"].as_str().unwrap(), "<IBAN_"),
        iban,
        "the other entity kept its token"
    );
    // forget by value goes through the HMAC index; the value is never echoed
    let (code, f) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/entities/forget",
            Some(json!({ "value": IBAN.to_lowercase() })),
        )
        .await;
    assert_eq!(code, 200, "{f}");
    assert_eq!(f["kinds"], json!(["IBAN"]));
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/entities/forget",
            Some(json!({ "value": IBAN })),
        )
        .await;
    assert_eq!(code, 404, "{b}");
    assert_eq!(b["error"]["type"], "not_found");
    assert!(!b.to_string().contains("AT61"), "{b}");
    for bad in [json!({ "value": "" }), json!({ "value": "  " })] {
        let (code, b) = d
            .call(Method::POST, "/v1/datasets/crm/entities/forget", Some(bad))
            .await;
        assert_eq!(code, 400, "{b}");
        assert_eq!(b["error"]["type"], "bad_request");
    }
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/entities/forget",
            Some(json!({ "value": ["Zyxwuria"] })),
        )
        .await;
    assert_eq!(code, 400, "{b}");
    assert!(!b.to_string().contains("Zyxwuria"), "{b}");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/nope/entities/forget",
            Some(json!({ "value": "x" })),
        )
        .await;
    assert_eq!(code, 404);
    let (code, _) = d
        .call(Method::GET, "/v1/datasets/nope/entities", None)
        .await;
    assert_eq!(code, 404);
    let (code, _) = forget_token(&d, "nope", &iban).await;
    assert_eq!(code, 404);
    assert_eq!(
        entities(&d, "crm", false).await.len(),
        1,
        "only the re-minted person is left"
    );
    d.stop().await;
}

/// Review Focus 2, through the gateway.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forget_evicts_cache_working_set_and_detector() {
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
    let echo =
        |q: String| CallToolRequestParams::new("echo").with_arguments(args(json!({ "query": q })));
    // the tripwire knows the canary now
    c.peer()
        .call_tool(echo(format!("find {CANARY}")))
        .await
        .unwrap();
    let hits = |st: &serde_json::Value| {
        st["gateway"]["datasets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["id"] == "crm")
            .unwrap()["clear_value_hits"]
            .as_u64()
            .unwrap()
    };
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(hits(&st), 1);
    let (code, f) = forget_token(&d, "crm", &person).await;
    assert_eq!(code, 200, "{f}");
    // forgotten: the detector no longer knows the name, so the same argument does not trip
    c.peer()
        .call_tool(echo(format!("find {CANARY}")))
        .await
        .unwrap();
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(hits(&st), 1, "no new hit after forget");
    // the token itself is unknown now: strict restoration refuses it
    let e = c
        .peer()
        .call_tool(echo(format!("find {person}")))
        .await
        .unwrap_err();
    assert_eq!(mcp_err(e).message, "unresolved_token");
    // the same result again is not served from the cache with the old token
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let fresh = token_in(&texts(&r), "<PERSON_");
    assert_ne!(fresh, person);
    assert_eq!(r.structured_content.unwrap()["customer"]["name"], fresh);
    c.cancel().await.ok();
    d.stop().await;
}

/// Review Focus 7, through the journal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forgotten_tokens_are_unresolved_in_the_journal() {
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
    let mut entries = Vec::new();
    for _ in 0..100 {
        let (_, b) = d.call(Method::GET, "/v1/datasets/crm/journal", None).await;
        entries = b["entries"].as_array().unwrap().clone();
        if !entries.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let id = entries[0]["id"].as_str().unwrap().to_string();
    let (code, v) = d
        .call(
            Method::GET,
            &format!("/v1/datasets/crm/journal/{id}?show_values=true"),
            None,
        )
        .await;
    assert_eq!(code, 200, "{v}");
    assert!(v["payload"].as_str().unwrap().contains(CANARY));
    // rotate first so the token sits in a closed epoch, then forget it
    let (code, _) = d.call(Method::POST, "/v1/datasets/crm/rotate", None).await;
    assert_eq!(code, 200);
    let listed = entities(&d, "crm", false).await;
    let old = listed.iter().find(|e| e["token"] == person).unwrap();
    assert_eq!(old["current_epoch"], false, "{old}");
    let (code, f) = forget_token(&d, "crm", &person).await;
    assert_eq!(code, 200, "{f}");
    let (code, v) = d
        .call(
            Method::GET,
            &format!("/v1/datasets/crm/journal/{id}?show_values=true"),
            None,
        )
        .await;
    assert_eq!(code, 200, "{v}");
    let payload = v["payload"].as_str().unwrap();
    assert!(
        payload.contains(&person) && !payload.contains("Zyxwuria"),
        "the forgotten token stays in place: {payload}"
    );
    assert!(v["unresolved"].as_u64().unwrap() >= 1, "{v}");
    c.cancel().await.ok();
    d.stop().await;
}
