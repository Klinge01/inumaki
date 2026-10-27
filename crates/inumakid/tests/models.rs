#![cfg(feature = "models-tests")]
//! Spec §13: the daemon with the `support-email` profile and real models.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::*;
use hyper::Method;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn support_email_over_the_daemon_tokenizes_names_and_caches() {
    let models =
        PathBuf::from(std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"));
    let config = format!(
        "{BASE_CONFIG}\n[daemon]\ndefault_profile = \"support-email\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n"
    );
    let d = start_with_config(config, Some(models), Duration::from_secs(3600), None).await;
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    let names: Vec<&str> = st["models"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["gliner-x-small", "mbert-ner-hrl"]);
    assert!(
        st["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["available"] == true),
        "{st}"
    );
    d.dataset("mail").await;
    let text = "Sarah Leitner wohnt in der Neubaugasse 22 in Wien.";
    let (code, a) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": text })),
        )
        .await;
    assert_eq!(code, 200, "{a}");
    let out = a["text"].as_str().unwrap().to_string();
    assert!(
        !out.contains("Sarah") && !out.contains("Neubaugasse"),
        "{out}"
    );
    let tok = out
        .split_whitespace()
        .find(|w| w.starts_with("<PERSON_"))
        .unwrap();
    assert_eq!(tok.len(), "<PERSON_".len() + 6 + 1, "{tok}");
    let (_, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": text })),
        )
        .await;
    assert_eq!(b["cached"], true);
    assert_eq!(b["text"], out);
    let (_, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "dataset": "mail", "text": out })),
        )
        .await;
    assert_eq!(r["text"], text);
    assert_eq!(r["unknown_tokens"], 0);
    // a known entity is found even in a phrasing the model may miss (surname
    // only, lower case: the known-entity detector's 0.80 surname rule)
    let (code, c) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": "leitner: bitte zurückrufen" })),
        )
        .await;
    assert_eq!(code, 200, "{c}");
    assert!(
        !c["text"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("leitner"),
        "{c}"
    );
    d.stop().await;
}
