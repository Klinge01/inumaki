//! Spec §10: with a TRACE subscriber behind the production filter capturing
//! every log line, hook requests that pass, replace, block, and fail never
//! log their text, paths, or the canary, and no error body echoes them.

mod common;

use common::*;
use hyper::Method;
use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use serde_json::json;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

struct TestFolders {
    root: (String, std::path::PathBuf),
    mirror: std::path::PathBuf,
}

impl inumakid::hook::FolderRegistry for TestFolders {
    fn source_roots(&self) -> Vec<(String, std::path::PathBuf)> {
        vec![self.root.clone()]
    }
    fn outbox_destinations(&self) -> Vec<(String, std::path::PathBuf)> {
        Vec::new()
    }
    fn mirror_root(&self) -> Option<std::path::PathBuf> {
        Some(self.mirror.clone())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hook_traffic_never_reaches_logs_or_error_bodies() {
    let cap = Capture::new();
    // The production filter at TRACE, as `gateway_canary.rs` installs it.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(inumakid::run::log_filter(EnvFilter::new("trace"))),
        )
        .init();
    // Preflight F5: the control API converts body rejections itself, so
    // axum never logs one on this path. Emit what axum would (a rejection
    // quoting the body, at TRACE under `axum::rejection`) to pin that the
    // privacy filter drops the target.
    tracing::event!(
        target: "axum::rejection",
        tracing::Level::TRACE,
        body = "Zyxwuria Quolnath qwxzvk",
        "rejecting request"
    );
    let d = start().await;
    // Two parts: a bare one-part PERSON is never a known entity (plan 4a);
    // the 0.80 surname rule still matches the lone `Leitner` in the text.
    for (ds, v) in [("a", "Zyxwuria Quolnath"), ("b", "Sarah Leitner")] {
        d.dataset(ds).await;
        let ns = d.state.namespace(ds).unwrap();
        let mut n = ns.lock().unwrap();
        n.token_for(&EntityKind::Person, v).unwrap();
        n.rebuild_detector_now().unwrap();
    }
    let mut bodies = Vec::new();
    let mut codes = Vec::new();
    for text in [
        "plain qwxzvk-path output",
        "Zyxwuria Quolnath hier",
        "Zyxwuria Quolnath und Zyxwuria Quolnath, Leitner",
    ] {
        let (code, r) = d
            .call(
                Method::POST,
                "/v1/hook",
                Some(
                    json!({ "harness": "claude-code", "tool": "bash", "cwd": "/Users/qwxzvk", "paths": ["/Users/qwxzvk/akten/a.txt"], "texts": ["stdout", text] }),
                ),
            )
            .await;
        codes.push(code);
        bodies.push(r.to_string());
    }
    assert_eq!(codes, [200, 200, 451], "pass, replace, block: {bodies:?}");
    // Bad bodies: a missing field, and a wrong type whose value is the
    // canary (serde quotes the offending value in its message, review I10).
    for bad in [
        json!({ "harness": "claude-code", "tool": "bash", "texts": ["Zyxwuria Quolnath"] }),
        json!({ "harness": "claude-code", "tool": "bash", "cwd": "/", "paths": "Zyxwuria Quolnath", "texts": ["Zyxwuria Quolnath"] }),
    ] {
        let (code, r) = d.call(Method::POST, "/v1/hook", Some(bad)).await;
        assert_eq!(code, 400);
        bodies.push(r.to_string());
    }
    // M6-3 Task 9b: the hook line says, in counts and flags only, which tool
    // class it saw, how many paths and texts, and whether a path matched a
    // connected folder root or the mirror. A folder whose root holds a
    // marker name, to show the path itself is never logged.
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("vbnmqz-akten");
    let mirror = t.path().join("vbnmqz-mirror");
    for p in [&src, &mirror] {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(src.join("a.txt"), "x").unwrap();
    d.state
        .mirror
        .get()
        .unwrap()
        .override_registry_for_test(std::sync::Arc::new(TestFolders {
            root: ("a".into(), src.clone()),
            mirror: mirror.clone(),
        }));
    for p in [src.join("a.txt"), mirror.join("a.txt")] {
        let (code, r) = d
            .call(
                Method::POST,
                "/v1/hook",
                Some(
                    json!({ "harness": "claude-code", "tool": "read", "cwd": "/", "paths": [p], "texts": ["content", "Rechnung Nr. 17"] }),
                ),
            )
            .await;
        assert_eq!(code, 200, "{r}");
        bodies.push(r.to_string());
    }
    let logs = cap.text();
    assert!(
        logs.contains("action=\"replace\"") && logs.contains("action=\"block\""),
        "the capture works: {logs}"
    );
    for line in [
        "action=\"pass\" tool=Bash paths=1 texts=2 root_match=false mirror_match=false",
        "action=\"replace\" tool=Read paths=1 texts=2 root_match=true mirror_match=false",
        "action=\"pass\" tool=Read paths=1 texts=2 root_match=false mirror_match=true",
    ] {
        assert!(logs.contains(line), "{line} missing: {logs}");
    }
    for needle in ["Zyxwuria", "Quolnath", "Leitner", "qwxzvk", "vbnmqz"] {
        assert!(!logs.contains(needle), "{needle} in logs");
    }
    for b in bodies.iter().filter(|b| b.contains("\"error\"")) {
        for needle in ["Zyxwuria", "Leitner", "qwxzvk"] {
            assert!(!b.contains(needle), "{needle} in {b}");
        }
    }
    d.stop().await;
}
