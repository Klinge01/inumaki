//! Check routes through the daemon (M8 spec §12, §15 tests 13, 15; M6-3
//! Task 4's direct check), streamed and not.

mod common;

use std::time::Duration;

use hyper::Method;
use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_proxy::{CheckId, Script, Step};
use serde_json::{Value, json};

const CANARY: &str = "Qwendolin Zirravel";
const CANARY_EMAIL: &str = "qwendolin.zirravel@example.invalid";
const ID: &str = "00112233445566778899aabbccddeeff";
const DS: &str = "check-00112233445566778899aabbccddeeff";

async fn daemon() -> common::TestDaemon {
    // The test's own reqwest client has no TLS provider of its own.
    inumaki_proxy::forward::ensure_crypto_provider();
    let d = common::start_with(
        "",
        "[proxy]\nlisten = \"127.0.0.1:0\"\n",
        Duration::from_secs(3600),
        None,
    )
    .await;
    // The check dataset is made the way M6-3's check makes it: directly in
    // the vault (the API refuses `check-`).
    d.state
        .vault
        .create_dataset(&inumaki_vault::DatasetSpec::new(DS, "check", "offline"))
        .unwrap();
    d.state
        .vault
        .create_dataset(&inumaki_vault::DatasetSpec::new(
            "kunden", "Kunden", "offline",
        ))
        .unwrap();
    d
}

fn mint(d: &common::TestDaemon, dataset: &str, kind: EntityKind, value: &str) -> String {
    let ns = d.state.namespace(dataset).unwrap();
    let mut n = ns.lock().unwrap();
    n.token_for(&kind, value).unwrap().as_str().to_string()
}

fn base(d: &common::TestDaemon) -> String {
    format!("http://{}", d.state.proxy.get().unwrap().status().listen)
}

/// Review Focus 1: the M6-3 proxy direct check as M6-3 Task 4 sends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_m6_direct_check_passes_through_the_daemon() {
    let d = daemon().await;
    let name_tok = mint(&d, DS, EntityKind::Person, CANARY);
    let email_tok = mint(&d, DS, EntityKind::Email, CANARY_EMAIL);
    let foreign = mint(&d, "kunden", EntityKind::Person, "Pellqwyn Yrsabel");
    let routes = d.state.proxy.get().unwrap().check_routes();
    let id = CheckId::from_hex(ID).unwrap();
    routes.register(
        id,
        DS,
        Script(vec![Step::EchoUserText]),
        Duration::from_secs(600),
    );
    let body = json!({"model": "inumaki-check", "max_tokens": 256, "messages": [{"role": "user",
        "content": format!("Please repeat exactly: Record: {CANARY}, email {CANARY_EMAIL}, also {foreign}")}]});
    let r = reqwest::Client::new()
        .post(format!("{}/check/{ID}/anthropic/v1/messages", base(&d)))
        .header("anthropic-version", "2023-06-01")
        .header("x-api-key", "inumaki-check-dummy")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let a: Value = r.json().await.unwrap();
    let text = a["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains(CANARY) && text.contains(CANARY_EMAIL),
        "restored with the check's namespace, no client header"
    );
    assert!(
        text.contains(&foreign) && !text.contains("Pellqwyn"),
        "a non-check dataset token stays a token"
    );
    let rec = routes.recorded(&id);
    assert_eq!(rec.len(), 1);
    let b = String::from_utf8_lossy(&rec[0].body);
    assert!(
        b.contains(&name_tok) && b.contains(&email_tok),
        "tokens upstream"
    );
    for c in ["Qwendolin", "Zirravel", "qwendolin", "inumaki-check-dummy"] {
        assert!(!b.contains(c), "no canary component or credential upstream");
    }
    // Codex streams through its check route the same way.
    let codex = json!({"model": "inumaki-check", "stream": true, "store": false, "input": [{"type": "message", "role": "user",
        "content": [{"type": "input_text", "text": format!("Record: {CANARY}, email {CANARY_EMAIL}")}]}]});
    let r = reqwest::Client::new()
        .post(format!("{}/check/{ID}/openai-codex/responses", base(&d)))
        .json(&codex)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let sse = r.text().await.unwrap();
    let text: String = sse
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str::<Value>(d).ok())
        .filter(|v| v["type"] == "response.output_text.delta")
        .map(|v| v["delta"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(text, format!("Record: {CANARY}, email {CANARY_EMAIL}"));
    let rec = routes.recorded(&id);
    assert_eq!(rec.len(), 2);
    assert_eq!(rec[1].upstream, "openai-codex");
    let b = String::from_utf8_lossy(&rec[1].body);
    assert!(b.contains(&name_tok) && b.contains(&email_tok));
    for c in ["Qwendolin", "Zirravel", "qwendolin"] {
        assert!(!b.contains(c), "no canary component upstream");
    }
    let (_, st) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(st["check_routes"], 1);
    assert_eq!(
        st["routes"][0]["requests"], 0,
        "check traffic is not route traffic"
    );
    routes.remove(&id);
    assert_eq!(
        d.call(Method::GET, "/v1/proxy", None).await.1["check_routes"],
        0
    );
    d.stop().await;
}

/// Spec §15 test 15 on check routes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_routes_are_hardened() {
    let d = daemon().await;
    let routes = d.state.proxy.get().unwrap().check_routes();
    let id = CheckId::from_hex(ID).unwrap();
    routes.register(
        id,
        DS,
        Script(vec![Step::EchoUserText]),
        Duration::from_secs(600),
    );
    let url = format!("{}/check/{ID}/anthropic/v1/messages", base(&d));
    let c = reqwest::Client::new();
    let body = json!({"messages": [{"role": "user", "content": "hi"}]});
    assert_eq!(
        c.post(&url)
            .header("origin", "https://evil.example")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        c.post(&url)
            .header("host", "evil.example")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        c.get(&url)
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .send()
            .await
            .unwrap()
            .status(),
        501
    );
    let r = c.post(&url).json(&body).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers()
            .keys()
            .all(|k| !k.as_str().starts_with("access-control-"))
    );
    // A CORS preflight is not answered with CORS headers and records nothing.
    let pre = c
        .request(reqwest::Method::OPTIONS, &url)
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    assert!(
        pre.headers()
            .keys()
            .all(|k| !k.as_str().starts_with("access-control-")),
        "no CORS headers on a preflight"
    );
    assert_eq!(
        routes.recorded(&id).len(),
        1,
        "only the allowed request reached the scripted upstream"
    );
    d.stop().await;
}
