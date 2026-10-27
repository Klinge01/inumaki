//! Streaming through the daemon (spec §15 test 1 for streams; the Codex route).
//! The log half of spec §15 test 16 for streams lives in `proxy_privacy.rs`,
//! whose global subscriber sees the daemon's worker threads.

mod common;

use std::sync::Arc;
use std::time::Duration;

use hyper::Method;
use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_proxy::{Script, ScriptedUpstream, Step};
use serde_json::{Value, json};

const NAME: &str = "Zyxwuria Quolnath";
const EMAIL: &str = "zyx.quolnath@example.invalid";

async fn daemon_with_scripted(script: Script) -> (common::TestDaemon, Arc<ScriptedUpstream>) {
    // The test's own reqwest client has no TLS provider of its own.
    inumaki_proxy::forward::ensure_crypto_provider();
    let (addr, up) = inumaki_proxy::scripted::spawn_http(script).await;
    let extra = format!(
        "[proxy]\nlisten = \"127.0.0.1:0\"\n[proxy.upstreams.anthropic]\nbase_url = \"http://{addr}\"\n[proxy.upstreams.openai]\nbase_url = \"http://{addr}\"\n[proxy.upstreams.openai-codex]\nbase_url = \"http://{addr}\"\n"
    );
    (
        common::start_with("", &extra, Duration::from_secs(3600), None).await,
        up,
    )
}

/// Teach the daemon the name: the `offline` profile has no NER, so only a
/// dataset makes `NAME` known to the pipeline.
fn mint(d: &common::TestDaemon, dataset: &str, value: &str) {
    let ns = d.state.namespace(dataset).unwrap();
    let mut n = ns.lock().unwrap();
    n.token_for(&EntityKind::Person, value).unwrap();
    n.rebuild_detector_now().unwrap();
}

fn url(d: &common::TestDaemon, path: &str) -> String {
    format!(
        "http://{}{path}",
        d.state.proxy.get().unwrap().status().listen
    )
}

/// Text deltas of any of the three wire formats, concatenated.
fn streamed_text(body: &str) -> String {
    let mut out = String::new();
    for d in body.lines().filter_map(|l| l.strip_prefix("data: ")) {
        let Ok(j) = serde_json::from_str::<Value>(d) else {
            continue;
        };
        if j["type"] == "content_block_delta" {
            out.push_str(j["delta"]["text"].as_str().unwrap_or(""));
        } else if j["type"] == "response.output_text.delta" {
            out.push_str(j["delta"].as_str().unwrap_or(""));
        } else {
            for c in j["choices"].as_array().into_iter().flatten() {
                out.push_str(c["delta"]["content"].as_str().unwrap_or(""));
            }
        }
    }
    out
}

fn bodies(msg: &str) -> Vec<(&'static str, Value)> {
    vec![
        (
            "/anthropic/v1/messages?beta=true",
            json!({"model": "m", "max_tokens": 50, "stream": true, "messages": [{"role": "user", "content": msg}]}),
        ),
        (
            "/openai/v1/responses",
            json!({"model": "m", "stream": true, "input": [{"type": "message", "role": "user", "content": msg}]}),
        ),
        (
            "/openai/v1/chat/completions",
            json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": msg}]}),
        ),
        (
            "/codex/responses",
            json!({"model": "m", "stream": true, "store": false, "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": msg}]}]}),
        ),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streaming_canary_through_each_route_including_codex() {
    let (d, up) = daemon_with_scripted(Script(vec![Step::EchoUserText])).await;
    d.dataset("kunden").await;
    mint(&d, "kunden", NAME);
    let (_, st) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(st["state"], "running", "{st}");
    let value = st["client_header"]["value"].as_str().unwrap().to_string();
    let msg = format!("Bitte an {NAME}, {EMAIL}");
    for (path, body) in bodies(&msg) {
        let r = reqwest::Client::new()
            .post(url(&d, path))
            .header("x-inumaki-client", &value)
            .header("session_id", "s1")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{path}");
        assert!(
            r.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream"),
            "{path}"
        );
        let text = streamed_text(&r.text().await.unwrap());
        assert!(
            text.contains(EMAIL),
            "{path}: the session token is restored: {text}"
        );
    }
    assert_eq!(up.recorded().len(), 4);
    for (_, b) in up.recorded() {
        let b = String::from_utf8_lossy(&b);
        assert!(
            !b.contains("Zyxwuria") && !b.contains("zyx.quolnath"),
            "no original upstream"
        );
    }
    let (_, st) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(st["oauth"]["codex_chatgpt"]["requests"], 1);
    assert!(st["oauth"]["codex_chatgpt"]["last_ok_at"].is_i64());
    d.stop().await;
}
