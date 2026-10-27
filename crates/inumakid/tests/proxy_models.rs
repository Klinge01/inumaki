#![cfg(feature = "models-tests")]
//! M8 spec §15 tests 1 and 13 with real models: the proxy on the
//! `support-email` profile (NER) sends a name no dataset knows, an
//! address, and an email to the upstream as tokens only, and restores them
//! in the answer. Needs `INUMAKI_MODELS_DIR`.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::*;
use inumaki_proxy::{Script, Step};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_name_only_ner_finds_never_reaches_the_upstream() {
    let models =
        PathBuf::from(std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"));
    inumaki_proxy::forward::ensure_crypto_provider();
    let (addr, up) = inumaki_proxy::scripted::spawn_http(Script(vec![Step::EchoUserText])).await;
    let config = format!(
        "{BASE_CONFIG}\n[daemon]\ndefault_profile = \"support-email\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n[proxy]\nlisten = \"127.0.0.1:0\"\n[proxy.upstreams.anthropic]\nbase_url = \"http://{addr}\"\n[proxy.upstreams.openai]\nbase_url = \"http://{addr}\"\n"
    );
    let d = start_with_config(config, Some(models), Duration::from_secs(3600), None).await;
    let listen = d.state.proxy.get().unwrap().status().listen;
    let msg = "Sarah Leitner wohnt in der Neubaugasse 22 in Wien, sarah.leitner@example.invalid.";
    let c = reqwest::Client::new();
    for (path, body) in [
        (
            "/anthropic/v1/messages",
            json!({"model": "m", "max_tokens": 10, "system": "Du bist hilfsbereit.",
                   "messages": [{"role": "user", "content": msg}]}),
        ),
        (
            "/openai/v1/chat/completions",
            json!({"model": "m", "messages": [{"role": "user", "content": msg}]}),
        ),
    ] {
        let r = c
            .post(format!("http://{listen}{path}"))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let answer = r.text().await.unwrap();
        assert_eq!(status, 200, "{path}: {answer}");
        assert!(
            answer.contains("Sarah Leitner") && answer.contains("Neubaugasse"),
            "{path}: session tokens are restored: {answer}"
        );
    }
    let recorded = up.recorded();
    assert_eq!(recorded.len(), 2);
    for (_, b) in recorded {
        let b = String::from_utf8_lossy(&b);
        for needle in ["Sarah", "Leitner", "Neubaugasse", "sarah.leitner@"] {
            assert!(!b.contains(needle), "{needle} reached the upstream: {b}");
        }
        assert!(b.contains("<PERSON_"), "{b}");
    }
    d.stop().await;
}
