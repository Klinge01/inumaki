//! M6 spec §5.2, §9.7: the hook endpoint's scope, dataset selection,
//! cross-dataset re-scan, activity record, TCP absence, fail-closed errors,
//! and contract. Valid request bodies are serialized from the client's
//! `HookRequest` (cross-lane contract, preflight F10).

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::*;
use hyper::Method;
use inumaki_client::{HookHarness, HookRequest, HookResponse, HookTool};
use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use serde_json::{Value, json};

const CANARY: &str = "Zyxwuria Quolnath";

async fn seed(d: &TestDaemon, dataset: &str, kind: EntityKind, value: &str) {
    if d.state.vault.dataset(dataset).is_err() {
        d.dataset(dataset).await;
    }
    let ns = d.state.namespace(dataset).unwrap();
    let mut n = ns.lock().unwrap();
    n.token_for(&kind, value).unwrap();
    n.rebuild_detector_now().unwrap();
}

/// One tool result as the hook sends it, serialized from the client type:
/// here a `{"stdout": text}` output, so the texts are the key and the value.
fn body(text: &str, cwd: &str, paths: &[&str]) -> Value {
    serde_json::to_value(HookRequest {
        harness: HookHarness::ClaudeCode,
        tool: HookTool::Read,
        cwd: cwd.to_string(),
        paths: paths.iter().map(|p| p.to_string()).collect(),
        texts: vec!["stdout".to_string(), text.to_string()],
    })
    .unwrap()
}

/// The 200 answer decodes as the client's `HookResponse` and re-encodes
/// to the same value.
fn contract(r: &Value) {
    inumaki_client::contract::assert_value_round_trip::<HookResponse>(r);
}

async fn records(d: &TestDaemon, dataset: &str) -> Vec<Value> {
    let (code, act) = d
        .call(
            Method::GET,
            &format!("/v1/activity?dataset={dataset}"),
            None,
        )
        .await;
    assert_eq!(code, 200, "{act}");
    act["records"].as_array().unwrap().clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn output_without_known_entities_passes_and_a_single_word_does_not_trigger() {
    let d = start().await;
    seed(&d, "a", EntityKind::Person, CANARY).await;
    seed(&d, "a", EntityKind::Person, "Max").await;
    // A URL and an email are validated-regex hits: alone they do not
    // trigger the hook (spec §5.2).
    let text = "fn main() { let max_results = Max; } // see https://example.com, ops@example.com";
    let (code, r) = d
        .call(Method::POST, "/v1/hook", Some(body(text, "/tmp", &[])))
        .await;
    assert_eq!((code, &r), (200, &json!({ "action": "pass" })));
    contract(&r);
    assert!(records(&d, "a").await.is_empty(), "a pass writes no record");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_known_multi_word_original_is_replaced_and_recorded() {
    let d = start().await;
    seed(&d, "a", EntityKind::Person, CANARY).await;
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/hook",
            Some(body(&format!("cat: {CANARY} wohnt hier"), "/tmp", &[])),
        )
        .await;
    assert_eq!(code, 200, "{r}");
    contract(&r);
    assert_eq!(r["action"], "replace");
    let texts = r["texts"].as_array().unwrap();
    assert_eq!(texts.len(), 2, "same length as the request: {r}");
    assert_eq!(texts[0], "stdout", "same order; the key is unchanged");
    let text = texts[1].as_str().unwrap();
    assert!(
        !text.contains("Zyxwuria") && text.contains("<PERSON_") && text.ends_with(" wohnt hier"),
        "{text}"
    );
    assert_eq!(r["kinds"], json!(["PERSON"]));
    let recs = records(&d, "a").await;
    assert_eq!(recs.len(), 1, "one record per tool result: {recs:?}");
    let rec = &recs[0];
    assert_eq!(rec["front_door"], "hook", "{rec}");
    assert_eq!(rec["verdict"], "released", "{rec}");
    assert_eq!(rec["direction"], "result", "{rec}");
    assert_eq!(rec["tripwire"], true, "{rec}");
    let shown = rec.to_string();
    assert!(
        !shown.contains("Zyxwuria") && !shown.contains("wohnt") && !shown.contains("stdout"),
        "the record holds no text: {shown}"
    );
    d.stop().await;
}

/// The dataset with the most trigger hits is used, so its tokens are the
/// ones the gateway and mirror produce (spec §5.2 step 4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dataset_with_the_most_hits_is_used() {
    let d = start().await;
    seed(&d, "a", EntityKind::Person, CANARY).await;
    seed(&d, "b", EntityKind::Person, CANARY).await;
    seed(&d, "b", EntityKind::Person, "Quarlo Vintek").await;
    let text = format!("{CANARY} schreibt an Quarlo Vintek");
    let (code, r) = d
        .call(Method::POST, "/v1/hook", Some(body(&text, "/tmp", &[])))
        .await;
    assert_eq!(code, 200, "{r}");
    assert_eq!(r["action"], "replace", "{r}");
    let out = r["texts"][1].as_str().unwrap();
    assert!(
        !out.contains("Zyxwuria") && !out.contains("Vintek"),
        "{out}"
    );
    // `b`'s own token for the canary, not `a`'s.
    let ns = d.state.namespace("b").unwrap();
    let tok = ns
        .lock()
        .unwrap()
        .token_for(&EntityKind::Person, CANARY)
        .unwrap();
    assert!(out.contains(tok.as_str()), "{out}");
    assert_eq!(records(&d, "b").await.len(), 1);
    assert!(records(&d, "a").await.is_empty());
    d.stop().await;
}

/// Review Focus 5.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_known_original_of_another_dataset_left_after_sanitizing_blocks() {
    let d = start().await;
    seed(&d, "a", EntityKind::Person, CANARY).await;
    seed(&d, "b", EntityKind::Person, "Sarah Leitner").await;
    // Two hits in `a` choose `a`. `b`'s surname alone is a low-confidence,
    // single-word span: it does not trigger, but it is still in the text
    // after `a` sanitized it, and the re-scan counts it (review C2).
    let text = format!("{CANARY} und {CANARY}, Kollege Leitner");
    let (code, r) = d
        .call(Method::POST, "/v1/hook", Some(body(&text, "/tmp", &[])))
        .await;
    assert_eq!(code, 451, "{r}");
    assert_eq!(r["error"]["type"], "privacy_block");
    assert!(
        r["error"]["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k == "PERSON")
    );
    let shown = r.to_string();
    assert!(
        !shown.contains("Leitner") && !shown.contains("Zyxwuria"),
        "{shown}"
    );
    let recs = records(&d, "a").await;
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0]["verdict"], "blocked");
    assert_eq!(recs[0]["front_door"], "hook");
    d.stop().await;
}

struct TestFolders {
    roots: Vec<(String, PathBuf)>,
    outboxes: Vec<(String, PathBuf)>,
    mirror: PathBuf,
}

impl inumakid::hook::FolderRegistry for TestFolders {
    fn source_roots(&self) -> Vec<(String, PathBuf)> {
        self.roots.clone()
    }
    fn outbox_destinations(&self) -> Vec<(String, PathBuf)> {
        self.outboxes.clone()
    }
    fn mirror_root(&self) -> Option<PathBuf> {
        Some(self.mirror.clone())
    }
}

/// Review Focus 4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paths_are_canonicalized_before_the_folder_rule() {
    let d = start().await;
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("akten");
    let sub = t.path().join("work");
    let mirror = t.path().join("mirror");
    let dest = t.path().join("akten-out");
    for p in [&src, &sub, &mirror, &dest] {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(src.join("a.txt"), "x").unwrap();
    std::fs::write(mirror.join("a.txt"), "x").unwrap();
    std::fs::write(dest.join("reply.txt"), "x").unwrap();
    std::os::unix::fs::symlink(&src, t.path().join("link")).unwrap();
    d.dataset("folder-1").await;
    // `folder-2` contains the mirror only to exercise the exemption (M5's
    // validation refuses such a folder); the deeper root wins for `akten`.
    let roots = vec![
        ("folder-1".into(), src.clone()),
        ("folder-2".into(), t.path().to_path_buf()),
    ];
    let outboxes = vec![("folder-1".into(), dest.clone())];
    d.state
        .mirror
        .get()
        .unwrap()
        .override_registry_for_test(Arc::new(TestFolders {
            roots,
            outboxes,
            mirror: mirror.clone(),
        }));
    let cwd = sub.to_string_lossy().to_string();
    // Relative with `..`, through a symlink, a new file through the
    // symlink (it does not exist yet), and under the outbox destination.
    for p in [
        "../akten/a.txt",
        "../link/a.txt",
        "../link/new.txt",
        "../akten-out/reply.txt",
    ] {
        let (code, r) = d
            .call(
                Method::POST,
                "/v1/hook",
                Some(body("Rechnung Nr. 17", &cwd, &[p])),
            )
            .await;
        assert_eq!(
            (code, r["action"].as_str()),
            (200, Some("replace")),
            "{p}: {r}"
        );
        contract(&r);
    }
    assert_eq!(
        records(&d, "folder-1").await.len(),
        4,
        "all four were sanitized with the folder's dataset"
    );
    // The exemption holds while no folder root holds the mirror (review
    // I1): `folder-2` above does, so it is dropped for the exemption.
    d.state
        .mirror
        .get()
        .unwrap()
        .override_registry_for_test(Arc::new(TestFolders {
            roots: vec![("folder-1".into(), src.clone())],
            outboxes: vec![("folder-1".into(), dest.clone())],
            mirror: mirror.clone(),
        }));
    let under_mirror = mirror.join("a.txt").to_string_lossy().to_string();
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/hook",
            Some(body("Rechnung Nr. 17", &cwd, &[&under_mirror])),
        )
        .await;
    assert_eq!(
        (code, r),
        (200, json!({ "action": "pass" })),
        "the mirror is exempt from the path rule"
    );
    d.stop().await;
}

/// Fail closed: a folder whose dataset is gone cannot be checked, so the
/// output is withheld, and the error names neither the dataset nor the text.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failure_withholds_the_output_without_naming_the_dataset() {
    let d = start().await;
    let t = tempfile::tempdir().unwrap();
    std::fs::write(t.path().join("a.txt"), "x").unwrap();
    d.state
        .mirror
        .get()
        .unwrap()
        .override_registry_for_test(Arc::new(TestFolders {
            roots: vec![("qwxzvk-gone".into(), t.path().to_path_buf())],
            outboxes: Vec::new(),
            mirror: t.path().join("no-mirror"),
        }));
    let p = t.path().join("a.txt").to_string_lossy().to_string();
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/hook",
            Some(body(&format!("{CANARY} hier"), "/", &[&p])),
        )
        .await;
    assert_ne!(code, 200, "{r}");
    assert!(r["error"].is_object(), "{r}");
    let shown = r.to_string();
    assert!(
        !shown.contains("qwxzvk") && !shown.contains("Zyxwuria"),
        "{shown}"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_over_the_limit_is_413() {
    let d = start().await;
    let big = "x".repeat(inumakid::api::BODY_LIMIT + 1);
    let (code, r) = d
        .call(Method::POST, "/v1/hook", Some(body(&big, "/tmp", &[])))
        .await;
    assert_eq!(code, 413);
    assert_eq!(r["error"]["type"], "payload_too_large");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hook_is_control_socket_only_and_bad_bodies_are_400() {
    use tower::ServiceExt as _;
    let d = start().await;
    let addr = d.gateway_addr();
    let tcp = inumakid::api::gateway::tcp_router(Arc::clone(&d.state), addr);
    let req = hyper::Request::post("/v1/hook")
        .header("host", addr.to_string())
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body("x", "/tmp", &[]).to_string()))
        .unwrap();
    let resp = tcp.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 404, "the TCP listener has no /v1/hook");
    // Invalid on purpose, so not expressible as a `HookRequest`.
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/hook",
            Some(
                json!({ "harness": "hermes", "tool": "read", "cwd": "/", "paths": [], "texts": ["x"] }),
            ),
        )
        .await;
    assert_eq!(code, 400, "hermes gets no hook");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/hook",
            Some(
                json!({ "harness": "codex", "tool": "shell", "cwd": "/", "paths": [], "texts": ["x"] }),
            ),
        )
        .await;
    assert_eq!(code, 400, "tool is a closed set");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/hook",
            Some(
                json!({ "harness": "codex", "tool": "bash", "cwd": "/", "paths": [], "text": "x" }),
            ),
        )
        .await;
    assert_eq!(code, 400, "the withdrawn single-text shape is refused");
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/hook",
            Some(body("x", "relative/dir", &["a.txt"])),
        )
        .await;
    assert_eq!(code, 400, "a relative cwd is refused: {r}");
    assert!(!r.to_string().contains("relative/dir"), "{r}");
    d.stop().await;
}

/// Fail closed at the sanitizer: an uncertain result (the `lax` profile
/// escalates instead of retrying) and an engine block (the `blocky`
/// profile blocks IBANs) are both 451 with a `blocked` record, never a
/// replace (Global Constraints: `PassUncertain` from sanitization is a
/// block).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uncertain_or_blocked_sanitization_blocks() {
    let (d, _dict) = common::gateway::daemon("").await;
    common::gateway::add_dataset(&d, "lax", "lax").await;
    common::gateway::add_dataset(&d, "crm", "blocky").await;
    for (ds, name) in [("lax", "Quarlo Vintek"), ("crm", "Marvik Oltrane")] {
        seed(&d, ds, EntityKind::Person, name).await;
    }
    for (ds, text, check) in [
        (
            "lax",
            "Quarlo Vintek, Elektriker seit 01.02.2020 in 1010 Wien.",
            "Combination",
        ),
        (
            "crm",
            "Marvik Oltrane: IBAN AT61 1904 3002 3457 3201 bitte.",
            "",
        ),
    ] {
        let (code, r) = d
            .call(Method::POST, "/v1/hook", Some(body(text, "/tmp", &[])))
            .await;
        assert_eq!(code, 451, "{ds}: {r}");
        assert_eq!(r["error"]["type"], "privacy_block", "{ds}: {r}");
        if !check.is_empty() {
            assert!(
                r["error"]["checks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|c| c == check),
                "{ds}: {r}"
            );
        }
        let shown = r.to_string();
        for needle in ["Vintek", "Oltrane", "Elektriker", "AT61", "1904"] {
            assert!(!shown.contains(needle), "{ds}: {needle} in {shown}");
        }
        let recs = records(&d, ds).await;
        assert_eq!(recs.len(), 1, "{ds}: {recs:?}");
        assert_eq!(recs[0]["verdict"], "blocked", "{ds}");
        assert_eq!(recs[0]["front_door"], "hook", "{ds}");
    }
    d.stop().await;
}

/// Review I1: a mirror root that overlaps a folder root, or that an agent
/// replaced with a symlink to a source, exempts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_mirror_exemption_needs_a_real_root_that_overlaps_no_folder() {
    let d = start().await;
    d.dataset("folder-1").await;
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("akten");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), "x").unwrap();
    let registry = |mirror: PathBuf, root: PathBuf| {
        d.state
            .mirror
            .get()
            .unwrap()
            .override_registry_for_test(Arc::new(TestFolders {
                roots: vec![("folder-1".into(), root)],
                outboxes: Vec::new(),
                mirror,
            }));
    };
    let cwd = t.path().to_string_lossy().to_string();
    let p = src.join("a.txt").to_string_lossy().to_string();
    let action = |r: &Value| r["action"].as_str().map(str::to_string);
    // The mirror root is a symlink to the source (`mv ~/Inumaki x; ln -s src ~/Inumaki`).
    let link = t.path().join("Inumaki");
    std::os::unix::fs::symlink(&src, &link).unwrap();
    registry(link.clone(), src.clone());
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/hook",
            Some(body("Rechnung Nr. 17", &cwd, &[&p])),
        )
        .await;
    assert_eq!((code, action(&r)), (200, Some("replace".into())), "{r}");
    // A real mirror root that holds the folder root.
    let outer = t.path().to_path_buf();
    registry(outer, src.clone());
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/hook",
            Some(body("Rechnung Nr. 17", &cwd, &[&p])),
        )
        .await;
    assert_eq!((code, action(&r)), (200, Some("replace".into())), "{r}");
    d.stop().await;
}
