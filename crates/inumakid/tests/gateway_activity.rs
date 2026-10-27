//! M4 spec §16.4: every served call leaves an activity record carrying
//! verdicts, kinds, and counts only; `/v1/activity` and the CLI read them;
//! the chain verifies.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::TestDaemon;
use common::gateway::*;
use hyper::Method;
use rmcp::model::CallToolRequestParams;
use serde_json::json;

async fn activity(d: &TestDaemon, query: &str) -> serde_json::Value {
    let (code, body) = d
        .call(Method::GET, &format!("/v1/activity{query}"), None)
        .await;
    assert_eq!(code, 200, "{body}");
    body
}

async fn wait_records(d: &TestDaemon, n: usize) -> Vec<serde_json::Value> {
    for _ in 0..100 {
        let body = activity(d, "?dataset=crm").await;
        let recs = body["records"].as_array().unwrap().clone();
        if recs.len() >= n {
            return recs;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("fewer than {n} activity records");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_served_call_leaves_a_record_without_values() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let person = token_in(&texts(&r), "<PERSON_");
    let e = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo")
                .with_arguments(args(json!({ "query": "<PERSON_000000>" }))),
        )
        .await
        .unwrap_err();
    assert_eq!(mcp_err(e).message, "unresolved_token");
    let recs = wait_records(&d, 2).await;
    assert_eq!(recs[0]["verdict"], "unresolved", "newest first: {recs:?}");
    assert_eq!(recs[0]["direction"], "arguments");
    assert_eq!(recs[1]["verdict"], "released");
    assert_eq!(recs[1]["direction"], "result");
    assert_eq!(recs[1]["front_door"], "gateway");
    assert_eq!(
        recs[1]["dataset"], "crm",
        "the API maps the opaque label back to the local id"
    );
    assert!(
        recs[1]["upstream"].as_str().unwrap().len() == 16,
        "upstream is an opaque label"
    );
    assert!(
        recs[1]["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["kind"] == "PERSON")
    );
    assert!(recs[1]["released"].as_str().unwrap().len() == 64);
    assert!(recs[1]["bytes"].as_u64().unwrap() > 0);
    let all = serde_json::to_string(&activity(&d, "").await).unwrap();
    for needle in [CANARY, "Zyxwuria", "AT61", &person, "\"echo\"", "\"a\""] {
        assert!(!all.contains(needle), "{needle} in activity: {all}");
    }
    let (code, v) = d.call(Method::GET, "/v1/activity/verify", None).await;
    assert_eq!(code, 200, "{v}");
    assert!(v["records"].as_u64().unwrap() >= 2);
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["gateway"]["activity_dropped"], 0);
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_results_are_recorded_with_kinds_and_checks() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "blocky").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    assert_eq!(r.is_error, Some(true));
    let recs = wait_records(&d, 1).await;
    assert_eq!(recs[0]["verdict"], "blocked");
    assert!(
        recs[0]["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["kind"] == "IBAN"),
        "{recs:?}"
    );
    assert_eq!(recs[0]["checks"], json!(["Policy"]));
    assert!(
        recs[0]["released"].is_null(),
        "nothing left, nothing to digest"
    );
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_queries_get_the_error_body_and_unknown_datasets_list_nothing() {
    let (d, _dict) = daemon("").await;
    let (code, body) = d
        .call(Method::GET, "/v1/activity?since=yesterday", None)
        .await;
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["error"]["type"], "bad_request");
    assert!(!body.to_string().contains("yesterday"), "{body}");
    let (code, body) = d
        .call(Method::GET, "/v1/activity?dataset=Not%20An%20Id", None)
        .await;
    assert_eq!(code, 400, "{body}");
    assert!(!body.to_string().contains("Not An Id"), "{body}");
    let body = activity(&d, "?dataset=nothing-here").await;
    assert_eq!(body["records"], json!([]));
    d.stop().await;
}

/// Activity is a control-socket surface only: the gateway's TCP listener
/// has no such route (M4 spec §16.4, review M4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activity_is_not_served_on_the_gateway_listener() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (d, _dict) = daemon("").await;
    let t = token(&d).await;
    for path in ["/v1/activity", "/v1/activity/verify"] {
        let mut s = tokio::net::TcpStream::connect(d.gateway_addr())
            .await
            .unwrap();
        s.write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {t}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 404"), "{path}: {out}");
        assert!(!out.contains("records"), "{path}: {out}");
    }
    d.stop().await;
}

/// Records of calls answered just before a shutdown are on disk after it:
/// the gateway drains the activity queue before the daemon exits (M3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_of_the_last_calls_are_on_disk_after_shutdown() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    for _ in 0..5 {
        c.peer()
            .call_tool(CallToolRequestParams::new("record"))
            .await
            .unwrap();
    }
    c.cancel().await.ok();
    let state = std::sync::Arc::clone(&d.state);
    d.stop().await;
    let recs = state
        .vault
        .activity(&inumaki_vault::ActivityFilter::default())
        .unwrap();
    assert_eq!(recs.len(), 5);
    assert_eq!(state.vault.verify_activity_chain().unwrap(), 5);
}
