//! M8 spec §8: with a TRACE subscriber behind the daemon's own privacy
//! filter capturing every log line, drive the proxy listener and the status
//! endpoint; the per-install client value, header values, a query string,
//! a path tail, and request text never appear in the logs, in `Debug`
//! output, or in an error body.

mod common;

use std::time::Duration;

use common::*;
use hyper::Method;
use serde_json::json;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_logs_debug_and_errors_never_contain_canaries() {
    let cap = Capture::new();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(inumakid::run::log_filter(EnvFilter::new("trace"))),
        )
        .init();
    inumaki_proxy::forward::ensure_crypto_provider();
    // Every upstream is the scripted one: with the host wired (Task 10b) a
    // sanitized request is forwarded, and a test never reaches a provider.
    let (addr, up) = inumaki_proxy::scripted::spawn_http(inumaki_proxy::Script(vec![
        inumaki_proxy::Step::EchoToolResults,
    ]))
    .await;
    let mut extra = String::from("[proxy]\nlisten = \"127.0.0.1:0\"\n");
    for id in ["anthropic", "openai", "openai-codex"] {
        extra.push_str(&format!(
            "[proxy.upstreams.{id}]\nbase_url = \"http://{addr}\"\n"
        ));
    }
    let d = start_with("", &extra, Duration::from_millis(200), None).await;
    let (_, st) = d.call(Method::GET, "/v1/proxy", None).await;
    let value = st["client_header"]["value"].as_str().unwrap().to_string();
    assert_eq!(value.len(), 64);
    let base = format!("http://{}", st["listen"].as_str().unwrap());
    let c = reqwest::Client::new();
    let mut bodies = Vec::new();
    for (path, hdr) in [
        ("/anthropic/v1/messages?canary-query=1", "x-api-key"),
        ("/openai/v1/chat/completions", "authorization"),
        ("/anthropic/v1/canary-path-tail", "x-inumaki-client"),
        ("/codex/responses", "user-agent"),
    ] {
        let r = c
            .post(format!("{base}{path}"))
            .header(
                hdr,
                if hdr == "x-inumaki-client" {
                    value.as_str()
                } else {
                    "canary-header-value"
                },
            )
            .json(&json!({"messages": [{"role": "user", "content": "canary-request-text"}]}))
            .send()
            .await
            .unwrap();
        bodies.push(r.text().await.unwrap());
    }
    // A shape failure on a listed name (`session-id` is an id) and an
    // unlisted name: counted by the log line, never named or quoted.
    let r = c
        .post(format!("{base}/openai/v1/chat/completions"))
        .header("session-id", "canary-header-value@x")
        .header("x-canary-name-zyx", "1")
        .json(&json!({"messages": [{"role": "user", "content": "canary-request-text"}]}))
        .send()
        .await
        .unwrap();
    bodies.push(r.text().await.unwrap());
    let r = c
        .post(format!("{base}/anthropic/v1/messages"))
        .header("origin", "https://canary-origin.example")
        .send()
        .await
        .unwrap();
    bodies.push(r.text().await.unwrap());
    tokio::time::sleep(Duration::from_millis(500)).await; // a sweep or two
    // What reached the upstream carries neither the client value nor a
    // header canary (the scripted upstream records bodies only).
    for (_, b) in up.recorded() {
        let b = String::from_utf8_lossy(&b);
        assert!(!b.contains(value.as_str()) && !b.contains("canary-header-value"));
    }
    for l in up.lines() {
        assert!(!l.header_names.iter().any(|n| n == "x-canary-name-zyx"));
    }
    let debug = format!("{:?} {:?}", d.state, d.state.proxy.get().unwrap());
    let logs = cap.text();
    assert!(logs.contains("proxy listening"), "the capture works");
    let dropped: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("proxy dropped request headers"))
        .collect();
    assert!(
        dropped
            .iter()
            .any(|l| l.contains("shape=1") && l.contains("session-id") && l.contains("other")),
        "the shape failure is counted and the unlisted name is labelled other: {dropped:?}"
    );
    for needle in [
        value.as_str(),
        "canary-query",
        "canary-path-tail",
        "canary-header-value",
        "x-canary-name-zyx",
        "canary-request-text",
        "canary-origin",
    ] {
        assert!(!logs.contains(needle), "{needle} in the logs");
        assert!(!debug.contains(needle), "{needle} in Debug");
        for b in &bodies {
            assert!(!b.contains(needle), "{needle} in an error body: {b}");
        }
    }
    d.stop().await;
}
