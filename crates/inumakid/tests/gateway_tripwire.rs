//! M4 spec §16.1: a known original or a validated identifier in clear in
//! model-written arguments is flagged (notify) or refused before dispatch
//! (block); tokens never trip it; nothing about the value is recorded.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::gateway::*;
use common::{BASE_CONFIG, TestDaemon};
use hyper::Method;
use rmcp::model::{CallToolRequestParams, GetPromptRequestParams, ReadResourceRequestParams};
use serde_json::json;

const IBAN: &str = "AT61 1904 3002 3457 3201";

async fn hits(d: &TestDaemon) -> u64 {
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    st["gateway"]["datasets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "crm")
        .unwrap()["clear_value_hits"]
        .as_u64()
        .unwrap()
}

async fn records(d: &TestDaemon) -> Vec<serde_json::Value> {
    let (_, body) = d.call(Method::GET, "/v1/activity?dataset=crm", None).await;
    body["records"].as_array().unwrap().clone()
}

async fn setup(
    extra: &str,
) -> (
    TestDaemon,
    tempfile::TempDir,
    tempfile::NamedTempFile,
    Client,
    String,
) {
    let (d, dict) = daemon(extra).await;
    let log = tempfile::NamedTempFile::new().unwrap();
    add_dataset(&d, "crm", "offline").await;
    let mut env = BTreeMap::new();
    env.insert(
        "INUMAKI_TEST_UPSTREAM_LOG",
        log.path().to_string_lossy().to_string(),
    );
    add_stdio(&d, "crm", "a", env, BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    // the namespace learns the canary from a result
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let person = token_in(&texts(&r), "<PERSON_");
    (d, dict, log, c, person)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_values_in_arguments_notify_and_the_call_proceeds() {
    let (d, _dict, log, c, person) = setup("").await;
    assert_eq!(hits(&d).await, 0);
    let q = format!("find {CANARY} and {IBAN}, also {person}");
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("echo").with_arguments(args(json!({ "query": q }))))
        .await
        .unwrap();
    assert_ne!(r.is_error, Some(true), "notify mode does not block");
    assert_eq!(hits(&d).await, 1, "one hit per call, however many values");
    let last = std::fs::read_to_string(log.path()).unwrap();
    assert!(
        last.lines().last().unwrap().contains(CANARY),
        "the call reached the upstream"
    );
    let mut recs = Vec::new();
    for _ in 0..100 {
        recs = records(&d).await;
        if recs.iter().any(|r| r["tripwire"] == true) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let trip = recs
        .iter()
        .find(|r| r["tripwire"] == true)
        .expect("a tripwire record");
    assert_eq!(trip["direction"], "arguments");
    assert_eq!(trip["verdict"], "released");
    assert_eq!(trip["checks"], json!(["ClearValue"]));
    let kinds: Vec<&str> = trip["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"PERSON") && kinds.contains(&"IBAN"),
        "{kinds:?}"
    );
    let all = serde_json::to_string(&recs).unwrap();
    assert!(!all.contains("Zyxwuria") && !all.contains("AT61"), "{all}");
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn block_mode_refuses_before_dispatch() {
    let (d, _dict, log, c, _person) = setup("tripwire = \"block\"").await;
    let before = std::fs::read_to_string(log.path()).unwrap().lines().count();
    let e = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo")
                .with_arguments(args(json!({ "query": format!("find {CANARY}") }))),
        )
        .await
        .unwrap_err();
    let e = mcp_err(e);
    assert_eq!(e.message, "privacy_block");
    let data = e.data.unwrap();
    assert_eq!(data["checks"], json!(["ClearValue"]));
    assert_eq!(data["kinds"], json!(["PERSON"]));
    assert!(!data.to_string().contains("Zyxwuria"));
    assert_eq!(
        std::fs::read_to_string(log.path()).unwrap().lines().count(),
        before,
        "the upstream saw nothing"
    );
    assert_eq!(hits(&d).await, 1);
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tokens_and_bare_surnames_do_not_trip_it() {
    let (d, _dict, _log, c, person) = setup("").await;
    // a token is the expected form
    c.peer()
        .call_tool(
            CallToolRequestParams::new("echo")
                .with_arguments(args(json!({ "query": format!("find {person}") }))),
        )
        .await
        .unwrap();
    // a bare surname is below full-match confidence: not a hit
    c.peer()
        .call_tool(
            CallToolRequestParams::new("echo").with_arguments(args(json!({ "query": "Quolnath" }))),
        )
        .await
        .unwrap();
    assert_eq!(hits(&d).await, 0);
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nested_values_are_scanned_too() {
    let (d, _dict, _log, c, _person) = setup("").await;
    assert_eq!(hits(&d).await, 0);
    c.peer()
        .call_tool(
            CallToolRequestParams::new("nested")
                .with_arguments(args(json!({ "filter": { "names": [CANARY], "n": 1 } }))),
        )
        .await
        .unwrap();
    assert_eq!(hits(&d).await, 1);
    c.cancel().await.ok();
    d.stop().await;
}

/// Review M1: a card or identifier the model wrote as a JSON *number*
/// (`"n": 4111111111111111`, not a string) is scanned like any other value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn numeric_arguments_are_scanned_too() {
    let (d, _dict, _log, c, _person) = setup("").await;
    assert_eq!(hits(&d).await, 0);
    c.peer()
        .call_tool(CallToolRequestParams::new("nested").with_arguments(args(
            json!({ "filter": { "names": [], "n": 4_111_111_111_111_111i64 } }),
        )))
        .await
        .unwrap();
    assert_eq!(hits(&d).await, 1);
    c.cancel().await.ok();
    d.stop().await;
}

/// Review I2: `get_prompt` has its own tripwire call site.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_prompt_arguments_trip_the_tripwire() {
    let (d, _dict, _log, c, _person) = setup("").await;
    assert_eq!(hits(&d).await, 0);
    c.peer()
        .get_prompt(
            GetPromptRequestParams::new("greet").with_arguments(args(json!({ "name": CANARY }))),
        )
        .await
        .unwrap();
    assert_eq!(hits(&d).await, 1);
    c.cancel().await.ok();
    d.stop().await;
}

/// Review I1 + I2: `route_template` hands the tripwire still percent-encoded
/// values (RFC 6570); a raw scan would miss `Zyxwuria%20Quolnath` entirely.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn percent_encoded_template_parameters_trip_the_tripwire() {
    let (d, _dict, _log, c, _person) = setup("").await;
    assert_eq!(hits(&d).await, 0);
    let templates = c.peer().list_all_resource_templates().await.unwrap();
    let tpl = &templates[0].uri_template;
    let filled = tpl.replace("{id}", &CANARY.replace(' ', "%20"));
    c.peer()
        .read_resource(ReadResourceRequestParams::new(filled))
        .await
        .unwrap();
    assert_eq!(hits(&d).await, 1);
    c.cancel().await.ok();
    d.stop().await;
}

/// Review I3: the regex-validated tier also skips a kind the profile
/// preserves (offline preserves URL); an IBAN is not preserved and still
/// trips, even in block mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preserved_kinds_do_not_trip_the_regex_tier_either() {
    let (d, _dict, _log, c, _person) = setup("tripwire = \"block\"").await;
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo")
                .with_arguments(args(json!({ "query": "see https://example.com/x" }))),
        )
        .await
        .unwrap();
    assert_ne!(r.is_error, Some(true), "a preserved URL does not block");
    assert_eq!(hits(&d).await, 0);
    let e = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo")
                .with_arguments(args(json!({ "query": format!("iban {IBAN}") }))),
        )
        .await
        .unwrap_err();
    assert_eq!(mcp_err(e).message, "privacy_block", "an IBAN still trips");
    assert_eq!(hits(&d).await, 1);
    c.cancel().await.ok();
    d.stop().await;
}

#[test]
fn tripwire_config_is_notify_block_or_an_error() {
    use inumakid::config::DaemonConfig;
    let base = format!("{BASE_CONFIG}\n[daemon]\ndefault_profile = \"offline\"\n");
    assert_eq!(
        DaemonConfig::from_toml(&base)
            .unwrap()
            .gateway_config()
            .tripwire,
        inumaki_gateway::TripwireMode::Notify
    );
    let block = format!("{base}[gateway]\ntripwire = \"block\"\n");
    assert_eq!(
        DaemonConfig::from_toml(&block)
            .unwrap()
            .gateway_config()
            .tripwire,
        inumaki_gateway::TripwireMode::Block
    );
    let bad = format!("{base}[gateway]\ntripwire = \"off\"\n");
    assert!(
        format!("{:?}", DaemonConfig::from_toml(&bad).unwrap_err()).contains("gateway.tripwire")
    );
}
