#![cfg(feature = "models-tests")]
//! Plan 2c: the Claude Code smoke flow without the harness. The scripted
//! upstream lists under `strict` with real models, its description's
//! canary is a token, its enum values survive, and `record` then `lookup`
//! work through tokens.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use common::gateway::*;
use common::{BASE_CONFIG, start_with_config};
use rmcp::model::CallToolRequestParams;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_upstream_lists_and_calls_under_strict() {
    let models =
        PathBuf::from(std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"));
    let config = format!(
        "{BASE_CONFIG}\n[daemon]\ndefault_profile = \"strict\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n"
    );
    let d = start_with_config(config, Some(models), Duration::from_secs(3600), None).await;
    add_dataset(&d, "crm", "strict").await;
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut env = BTreeMap::new();
    env.insert(
        "INUMAKI_TEST_UPSTREAM_LOG",
        log.path().to_string_lossy().to_string(),
    );
    add_stdio(&d, "crm", "a", env, BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let tools = c
        .peer()
        .list_all_tools()
        .await
        .expect("the listing is not refused under strict");
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    for n in [
        "record",
        "lookup",
        "dynamic",
        "long",
        "change_tools",
        "qwxzvk_tool",
    ] {
        assert!(names.contains(&n.to_string()), "{n}: {names:?}");
    }
    let listed = serde_json::to_string(&tools).unwrap();
    assert!(
        !listed.contains("Zyxwuria") && !listed.contains("Quolnath"),
        "{listed}"
    );
    let record = tools.iter().find(|t| t.name == "record").unwrap();
    assert!(
        record
            .description
            .as_deref()
            .unwrap_or_default()
            .contains("<PERSON_"),
        "{:?}",
        record.description
    );
    let change = tools.iter().find(|t| t.name == "change_tools").unwrap();
    assert_eq!(
        change.input_schema["properties"]["what"]["enum"],
        json!(["extra", "lookup_schema", "lookup_description"])
    );
    // record, then lookup with the customer token, as the smoke prompt does
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let shown = serde_json::to_string(&r).unwrap();
    for v in ["Zyxwuria", "Quolnath", "AT61", "8439271"] {
        assert!(!shown.contains(v), "{v}: {shown}");
    }
    let id = token_in(&shown, "<CUSTOMER_ID_");
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("lookup").with_arguments(args(json!({ "customer_id": id }))),
        )
        .await
        .unwrap();
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let sent = std::fs::read_to_string(log.path()).unwrap();
    assert!(
        sent.lines().last().unwrap().contains("8439271"),
        "the upstream got the real number"
    );
    c.cancel().await.ok();
    d.stop().await;
}
