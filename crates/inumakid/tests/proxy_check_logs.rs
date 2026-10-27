//! Spec §15 test 16 for check routes: the check id (a capability) and the
//! canary stay out of the logs. Its own binary: the subscriber is global
//! (it must also see the proxy listener's and `spawn_blocking` threads), and
//! a global subscriber can be set once per process.

mod common;

use std::time::Duration;

use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_proxy::{CheckId, Script, Step};
use serde_json::json;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const CANARY: &str = "Qwendolin Zirravel";
const ID: &str = "00112233445566778899aabbccddeeff";
const DS: &str = "check-00112233445566778899aabbccddeeff";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn check_route_logs_carry_no_id_or_canary() {
    let cap = common::Capture::new();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(inumakid::run::log_filter(
                    tracing_subscriber::EnvFilter::new("trace"),
                )),
        )
        .init();
    inumaki_proxy::forward::ensure_crypto_provider();
    let d = common::start_with(
        "",
        "[proxy]\nlisten = \"127.0.0.1:0\"\n",
        Duration::from_secs(3600),
        None,
    )
    .await;
    d.state
        .vault
        .create_dataset(&inumaki_vault::DatasetSpec::new(DS, "check", "offline"))
        .unwrap();
    {
        let ns = d.state.namespace(DS).unwrap();
        ns.lock()
            .unwrap()
            .token_for(&EntityKind::Person, CANARY)
            .unwrap();
    }
    let proxy = d.state.proxy.get().unwrap();
    let base = format!("http://{}", proxy.status().listen);
    proxy.check_routes().register(
        CheckId::from_hex(ID).unwrap(),
        DS,
        Script(vec![Step::EchoUserText]),
        Duration::from_secs(600),
    );
    for stream in [false, true] {
        let r = reqwest::Client::new()
            .post(format!("{base}/check/{ID}/anthropic/v1/messages"))
            .json(&json!({"stream": stream, "messages": [{"role": "user", "content": format!("Record: {CANARY}")}]}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let _ = r.text().await;
    }
    d.stop().await;
    let logs = cap.text();
    // Positive controls: capture is wired across threads (the server task's
    // own line and the request's access-log line are both there).
    assert!(
        logs.contains("proxy check routes ready"),
        "capture is not wired: {} bytes captured",
        logs.len()
    );
    assert!(
        logs.contains("/check/{") || logs.contains("/check/:"),
        "the request's access-log line is missing: capture does not see the listener threads"
    );
    for c in [ID, "Qwendolin", "Zirravel"] {
        assert!(!logs.contains(c), "a check id or canary is in the logs");
    }
}
