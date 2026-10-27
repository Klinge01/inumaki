//! M4 spec §16.3 canary: with a TRACE subscriber behind the daemon's own
//! privacy filter capturing every log line, drive the journal and entity
//! endpoints in every mode (metadata, values, forget by token, forget by
//! value, bad ids, bad bodies). Revealed originals, tokens, the forget
//! value, and the dataset slug never reach the logs or an error body.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::gateway::*;
use common::{BASE_CONFIG, Capture, encode_segment, start_with_config};
use hyper::Method;
use rmcp::model::CallToolRequestParams;
use serde_json::json;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const IBAN: &str = "AT61 1904 3002 3457 3201";
const DS: &str = "qwxzvk-canary-slug";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn journal_and_entity_endpoints_never_log_values() {
    let cap = Capture::new();
    // The production filter (ruling B3): everything at TRACE except what
    // the privacy filter drops for every configuration (rmcp's payload logs).
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(inumakid::run::log_filter(EnvFilter::new("trace"))),
        )
        .init();
    let dict = tempfile::tempdir().unwrap();
    let persons = dict.path().join("persons.txt");
    std::fs::write(&persons, format!("{CANARY}\n")).unwrap();
    let base = BASE_CONFIG.replace(
        "persons = []",
        &format!("persons = [\"{}\"]", persons.display()),
    );
    let config = format!(
        "{base}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n"
    );
    let d = start_with_config(config, None, Duration::from_millis(200), None).await;
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": DS, "name": CANARY })),
        )
        .await;
    assert_eq!(code, 201);
    add_stdio(&d, DS, "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, DS, "a").await;
    let c = socket_client(&d, DS).await.unwrap();
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let person = r.structured_content.as_ref().unwrap()["customer"]["name"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(person.starts_with("<PERSON_"), "{person}");
    let (code, s) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": DS, "text": format!("IBAN {IBAN}") })),
        )
        .await;
    assert_eq!(code, 200);
    let iban_token = token_in(s["text"].as_str().unwrap(), "<IBAN_");
    let mut entries = Vec::new();
    for _ in 0..100 {
        let (_, b) = d
            .call(Method::GET, &format!("/v1/datasets/{DS}/journal"), None)
            .await;
        entries = b["entries"].as_array().unwrap().clone();
        if !entries.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let id = entries[0]["id"].as_str().unwrap().to_string();
    let mut errors: Vec<String> = Vec::new();
    let mut ok = 0;
    for (method, path, body) in [
        (Method::GET, format!("/v1/datasets/{DS}/journal/{id}"), None),
        (
            Method::GET,
            format!("/v1/datasets/{DS}/journal/{id}?show_values=true"),
            None,
        ),
        (
            Method::GET,
            format!("/v1/datasets/{DS}/journal/not-an-id"),
            None,
        ),
        (
            Method::GET,
            format!("/v1/datasets/{DS}/journal/{}", "0".repeat(32)),
            None,
        ),
        (Method::GET, format!("/v1/datasets/{DS}/entities"), None),
        (
            Method::GET,
            format!("/v1/datasets/{DS}/entities?show_values=true"),
            None,
        ),
        (
            Method::GET,
            format!("/v1/datasets/{DS}/entities?show_values=Zyxwuria"),
            None,
        ),
        (
            Method::DELETE,
            format!("/v1/datasets/{DS}/entities/{}", encode_segment(&person)),
            None,
        ),
        (
            Method::DELETE,
            format!("/v1/datasets/{DS}/entities/{}", encode_segment(&person)),
            None,
        ),
        (
            Method::POST,
            format!("/v1/datasets/{DS}/entities/forget"),
            Some(json!({ "value": IBAN })),
        ),
        (
            Method::POST,
            format!("/v1/datasets/{DS}/entities/forget"),
            Some(json!({ "value": "Zyxwuria Nobody" })),
        ),
        (
            Method::POST,
            format!("/v1/datasets/{DS}/entities/forget"),
            Some(json!({ "value": [CANARY] })),
        ),
        (
            Method::POST,
            format!("/v1/datasets/{DS}/entities/forget"),
            Some(json!({ "value": "Quolnath Nobody", "extra": CANARY })),
        ),
    ] {
        let (code, b) = d.call(method, &path, body).await;
        if code >= 400 {
            errors.push(b.to_string());
        } else {
            ok += 1;
        }
    }
    assert_eq!(ok, 6, "{errors:?}");
    assert_eq!(errors.len(), 7, "{errors:?}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    c.cancel().await.ok();
    d.stop().await;
    let logs = cap.text();
    assert!(logs.contains("journal entry shown"), "{logs}");
    assert!(logs.contains("entity forgotten"), "{logs}");
    assert!(logs.contains("entities listed"), "{logs}");
    for needle in [
        "Zyxwuria",
        "Quolnath",
        "AT61",
        "qwxzvk",
        "Nobody",
        "show_values=true",
        &person,
        &iban_token,
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
