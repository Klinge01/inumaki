//! M4 spec §13 gateway tests against the real daemon (offline profile with
//! a dictionary canary): bearer on TCP and none on the socket; wrapped
//! stdio and HTTP servers merged with collision prefixes; contract-driven
//! rehydration and sanitization incl. the numeric identifier round trip;
//! opaque handles; blocked, uncertain, unsupported, unresolved, and
//! upstream errors as fixed classes; crash and timeout recovery; deletion
//! mid-call; token revocation; schema drift; list-changed rebuilds.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::TestDaemon;
use common::gateway::*;
use hyper::Method;
use inumaki_gateway::scripted::{CUSTOMER_ID, ScriptedUpstream, serve_scripted_http};
use rmcp::model::{
    CallToolRequestParams, ErrorCode, GetPromptRequestParams, ReadResourceRequestParams,
    ResourceContents,
};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bearer_is_required_on_tcp_and_absent_on_the_socket() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let Err(e) = tcp_client(&d, "crm", None).await else {
        panic!("no token must fail");
    };
    assert!(e.is_authorization_required(), "{e}");
    let Err(e) = tcp_client(&d, "crm", Some("inumaki-gw-not-a-token")).await else {
        panic!("bad token must fail");
    };
    assert!(e.is_authorization_required(), "{e}");
    let t = token(&d).await;
    let c = tcp_client(&d, "crm", Some(&t)).await.unwrap();
    assert!(
        c.peer()
            .list_all_tools()
            .await
            .unwrap()
            .iter()
            .any(|t| t.name == "echo")
    );
    // The model sees the opaque dataset label, never the slug (review M9).
    let server_name = c
        .peer()
        .peer_info()
        .unwrap()
        .server_info
        .as_ref()
        .unwrap()
        .name
        .clone();
    assert!(
        server_name.starts_with("inumaki/")
            && server_name.len() > "inumaki/".len()
            && !server_name.contains("crm"),
        "{server_name}"
    );
    let s = socket_client(&d, "crm").await.unwrap();
    assert!(
        s.peer()
            .list_all_tools()
            .await
            .unwrap()
            .iter()
            .any(|t| t.name == "echo")
    );
    assert!(
        tcp_client(&d, "nope", Some(&t)).await.is_err(),
        "unknown dataset is 404"
    );
    assert!(socket_client(&d, "nope").await.is_err());
    c.cancel().await.ok();
    s.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrapped_stdio_and_http_servers_merge_with_collision_prefixes() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    let mut env = BTreeMap::new();
    env.insert("INUMAKI_TEST_UPSTREAM_NAME", "a".to_string());
    let mut secret = BTreeMap::new();
    secret.insert("INUMAKI_TEST_SECRET", "hunter2-canary");
    add_stdio(&d, "crm", "a", env, secret, true).await;
    let (addr, ct) = serve_scripted_http(ScriptedUpstream::default().with_name("b")).await;
    add_http(&d, "crm", "b", &format!("http://{addr}/mcp")).await;
    wait_running(&d, "crm", "a").await;
    wait_running(&d, "crm", "b").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let names: Vec<String> = c
        .peer()
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        names.contains(&"echo".to_string()) && names.contains(&"b__echo".to_string()),
        "{names:?}"
    );
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("echo").with_arguments(args(json!({ "query": "x" }))))
        .await
        .unwrap();
    assert_eq!(texts(&r), "echo: x");
    // `b` has no contract: text works, its structured content is unsupported
    let e = mcp_err(
        c.peer()
            .call_tool(
                CallToolRequestParams::new("b__echo").with_arguments(args(json!({ "query": "y" }))),
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "unsupported_content");
    assert_eq!(e.data.unwrap()["class"], "structured_content");
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("env")
                .with_arguments(args(json!({ "name": "INUMAKI_TEST_SECRET" }))),
        )
        .await
        .unwrap();
    assert_eq!(
        texts(&r),
        "hunter2-canary",
        "the secret env reached the child"
    );
    // the daemon's own environment stays out of the child: cargo sets
    // CARGO_MANIFEST_DIR for this test process, and it is not allowlisted
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets it for tests");
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("env")
                .with_arguments(args(json!({ "name": "CARGO_MANIFEST_DIR" }))),
        )
        .await
        .unwrap();
    assert_ne!(
        texts(&r),
        manifest,
        "the daemon's environment reached the child"
    );
    assert!(texts(&r).contains("unset"), "{}", texts(&r));
    let u = upstream_status(&d, "crm", "a").await.unwrap();
    assert_eq!(u["state"], "running");
    assert_eq!(u["restarts"], 0);
    assert!(
        u["stderr_bytes"].as_u64().unwrap() > 0,
        "child stderr counted"
    );
    assert_eq!(u["contract"], "ready");
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    let ds = &st["gateway"]["datasets"][0];
    assert_eq!(ds["calls"], 4);
    assert_eq!(ds["unsupported"], 1);
    assert!(!st.to_string().contains("hunter2"), "{st}");
    c.cancel().await.ok();
    ct.cancel();
    d.stop().await;
}

/// Review Focus 1, end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn arguments_are_rehydrated_and_results_sanitized_through_the_contract() {
    let (d, _dict) = daemon("").await;
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
    let tools = c.peer().list_all_tools().await.unwrap();
    let record = tools.iter().find(|t| t.name == "record").unwrap();
    assert!(
        !record.description.as_deref().unwrap().contains("Zyxwuria"),
        "description sanitized"
    );
    assert_eq!(
        record.output_schema.as_ref().unwrap()["properties"]["customer"]["properties"]["id"]["type"],
        "string"
    );
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let text = texts(&r);
    assert!(
        !text.contains("Zyxwuria") && !text.contains("AT61"),
        "{text}"
    );
    let person = token_in(&text, "<PERSON_");
    let sc = r.structured_content.clone().unwrap();
    assert_eq!(
        sc["customer"]["name"], person,
        "same entity, same token in structured content"
    );
    let cid = sc["customer"]["id"].as_str().unwrap().to_string();
    assert!(
        cid.starts_with("<CUSTOMER_ID_"),
        "numeric identifier became a typed token: {cid}"
    );
    assert_eq!(sc["customer"]["count"], 3);
    assert_eq!(sc["customer"]["tags"][1], person);
    assert_eq!(sc["customer"]["active"], true);
    // the agent looks the customer up by token: the upstream receives the integer
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("lookup").with_arguments(args(
            json!({ "customer_id": cid, "note": format!("re {person}") }),
        )))
        .await
        .unwrap();
    assert_eq!(r.structured_content.unwrap()["customer"]["id"], cid);
    let received = std::fs::read_to_string(log.path()).unwrap();
    let last = received.lines().last().unwrap();
    assert!(
        last.contains(&format!("\"customer_id\":{CUSTOMER_ID}")),
        "integer restored upstream: {last}"
    );
    assert!(
        last.contains(&format!("re {CANARY}")) && !last.contains(&person),
        "{last}"
    );
    // echo through a token, nested arrays, and a cache hit
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo")
                .with_arguments(args(json!({ "query": format!("find {person}") }))),
        )
        .await
        .unwrap();
    assert_eq!(texts(&r), format!("echo: find {person}"));
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("nested").with_arguments(args(
            json!({ "filter": { "names": [person.clone(), "x"], "n": 2 } }),
        )))
        .await
        .unwrap();
    assert_eq!(
        r.structured_content.unwrap()["echo"]["filter"]["names"][0],
        person
    );
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    let hits_before = st["cache"]["hits"].as_u64().unwrap();
    c.peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert!(st["cache"]["hits"].as_u64().unwrap() > hits_before);
    // dynamic keys through the map rule
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("dynamic"))
        .await
        .unwrap();
    let by = r.structured_content.unwrap()["by_name"].clone();
    assert_eq!(by[&person], 3);
    assert_eq!(by["Muster GmbH"], 1);
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn foreign_token_in_result_passes_through_as_text() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo").with_arguments(args(json!({ "query": "plain" }))),
        )
        .await
        .unwrap();
    assert_eq!(texts(&r), "echo: plain");
    // a token from another dataset in an argument is unresolved, never guessed
    let e = mcp_err(
        c.peer()
            .call_tool(
                CallToolRequestParams::new("echo")
                    .with_arguments(args(json!({ "query": "<PERSON_a1b2c3> asked" }))),
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "unresolved_token");
    assert_eq!(e.data.unwrap()["unknown_tokens"], 1);
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["gateway"]["datasets"][0]["unresolved"], 1);
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_and_uncertain_results_are_tool_errors_naming_kinds_and_checks_only() {
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
    assert_eq!(
        texts(&r),
        "blocked by inumaki (kinds: IBAN; checks: Policy)"
    );
    assert!(r.structured_content.is_none());
    let whole = serde_json::to_string(&r).unwrap();
    assert!(
        !whole.contains("AT61") && !whole.contains("Zyxwuria"),
        "{whole}"
    );
    c.cancel().await.ok();
    add_dataset(&d, "lax", "lax").await;
    add_stdio(&d, "lax", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "lax", "a").await;
    let c = socket_client(&d, "lax").await.unwrap();
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("echo").with_arguments(args(
            json!({ "query": "Elektriker seit 01.02.2020 in 1010 Wien." }),
        )))
        .await
        .unwrap();
    assert_eq!(r.is_error, Some(true), "{r:?}");
    assert!(
        texts(&r).starts_with("withheld by inumaki (uncertain; kinds: "),
        "{}",
        texts(&r)
    );
    assert!(texts(&r).contains("checks: Combination"));
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    let ds: Vec<_> = st["gateway"]["datasets"]
        .as_array()
        .unwrap()
        .iter()
        .collect();
    assert_eq!(ds.iter().find(|x| x["id"] == "crm").unwrap()["blocked"], 1);
    assert_eq!(
        ds.iter().find(|x| x["id"] == "lax").unwrap()["uncertain"],
        1
    );
    assert_eq!(st["gateway"]["uncertain_checks"]["Combination"], 1);
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_content_and_unlisted_shapes_are_unsupported() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let e = mcp_err(
        c.peer()
            .call_tool(CallToolRequestParams::new("binary"))
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "unsupported_content");
    assert_eq!(e.data.unwrap()["class"], "binary");
    let resources = c.peer().list_all_resources().await.unwrap();
    let logo = resources.iter().find(|r| r.name == "logo").unwrap();
    let e = mcp_err(
        c.peer()
            .read_resource(ReadResourceRequestParams::new(logo.uri.clone()))
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "unsupported_content");
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["gateway"]["datasets"][0]["unsupported"], 2);
    c.cancel().await.ok();
    d.stop().await;
}

/// Review Focus 3, end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_error_that_echoes_arguments_is_a_fixed_class() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let e = mcp_err(
        c.peer()
            .call_tool(
                CallToolRequestParams::new("fail")
                    .with_arguments(args(json!({ "query": "harmless" }))),
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "upstream_error");
    assert_eq!(e.data.unwrap(), json!({ "code": -32603 }));
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crashed_upstream_is_unavailable_then_restarted() {
    let (d, _dict) = daemon("upstream_restart_max_backoff = \"1s\"").await;
    add_dataset(&d, "crm", "offline").await;
    let mut env = BTreeMap::new();
    env.insert("INUMAKI_TEST_UPSTREAM_ALLOW_CRASH", "1".to_string());
    add_stdio(&d, "crm", "a", env, BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let e = mcp_err(
        c.peer()
            .call_tool(CallToolRequestParams::new("crash"))
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "upstream_unavailable");
    for _ in 0..100 {
        if let Some(u) = upstream_status(&d, "crm", "a").await {
            if u["state"] == "running" && u["restarts"].as_u64() >= Some(1) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let u = upstream_status(&d, "crm", "a").await.unwrap();
    assert_eq!(
        (
            u["state"].as_str().unwrap(),
            u["restarts"].as_u64().unwrap()
        ),
        ("running", 1)
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo").with_arguments(args(json!({ "query": "back" }))),
        )
        .await
        .unwrap();
    assert_eq!(texts(&r), "echo: back");
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hung_upstream_times_out_and_the_gateway_keeps_serving() {
    let (d, _dict) = daemon("upstream_call_timeout = \"1s\"").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let t0 = std::time::Instant::now();
    let e = mcp_err(
        c.peer()
            .call_tool(
                CallToolRequestParams::new("slow").with_arguments(args(json!({ "ms": 10_000 }))),
            )
            .await
            .unwrap_err(),
    );
    assert!(t0.elapsed() < Duration::from_secs(5));
    assert_eq!(e.message, "upstream_unavailable");
    assert_eq!(e.data.unwrap()["class"], "timeout");
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo")
                .with_arguments(args(json!({ "query": "still here" }))),
        )
        .await
        .unwrap();
    assert_eq!(texts(&r), "echo: still here");
    c.cancel().await.ok();
    d.stop().await;
}

/// Review Focus 6.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataset_deleted_during_a_call_fails_that_call_and_later_ones_404() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let peer = c.peer().clone();
    let call = tokio::spawn(async move {
        peer.call_tool(
            CallToolRequestParams::new("slow").with_arguments(args(json!({ "ms": 2000 }))),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (code, _) = d.call(Method::DELETE, "/v1/datasets/crm", None).await;
    assert_eq!(code, 204);
    let outcome = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .unwrap()
        .unwrap();
    // An MCP error answered before the session ended, not a stream that
    // closed without a response.
    let e = mcp_err(outcome.expect_err("the in-flight call must not return a result"));
    assert_eq!(e.message, "upstream_unavailable", "{e:?}");
    assert!(socket_client(&d, "crm").await.is_err());
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert!(st["gateway"]["datasets"].as_array().unwrap().is_empty());
    d.stop().await;
}

/// Review Focus 7.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_token_is_refused_on_the_next_request() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/gateway/tokens",
            Some(json!({ "label": "t" })),
        )
        .await;
    assert_eq!(code, 201);
    let t = body["token"].as_str().unwrap().to_string();
    let id = body["id"].as_i64().unwrap();
    let c = tcp_client(&d, "crm", Some(&t)).await.unwrap();
    assert!(!c.peer().list_all_tools().await.unwrap().is_empty());
    let (code, _) = d
        .call(Method::DELETE, &format!("/v1/gateway/tokens/{id}"), None)
        .await;
    assert_eq!(code, 204);
    let e = c
        .peer()
        .call_tool(CallToolRequestParams::new("echo").with_arguments(args(json!({ "query": "x" }))))
        .await
        .unwrap_err();
    // The next request is refused with 401 + WWW-Authenticate (rmcp's
    // AuthRequired), not with some other transport failure.
    let shown = format!("{e:?}");
    assert!(
        matches!(e, rmcp::service::ServiceError::TransportSend(_))
            && shown.contains("AuthRequired")
            && shown.contains("Bearer realm"),
        "{shown}"
    );
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_names_and_handles_are_fixed_errors_without_the_supplied_value() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let e = mcp_err(
        c.peer()
            .call_tool(
                CallToolRequestParams::new(CANARY).with_arguments(args(json!({ "query": CANARY }))),
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(e.code, ErrorCode::INVALID_PARAMS);
    assert_eq!(e.message, "unknown_tool");
    assert!(!serde_json::to_string(&e).unwrap().contains("Zyxwuria"));
    let e = mcp_err(
        c.peer()
            .read_resource(ReadResourceRequestParams::new(format!(
                "mem://customer/{CANARY}"
            )))
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "unknown_resource", "raw uris are never routable");
    let e = mcp_err(
        c.peer()
            .read_resource(ReadResourceRequestParams::new(
                "inumaki://res/0000000000000000",
            ))
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "unknown_resource");
    let e = mcp_err(
        c.peer()
            .get_prompt(GetPromptRequestParams::new("nope"))
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "unknown_prompt");
    c.cancel().await.ok();
    d.stop().await;
}

/// Review Focus 5, end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resources_prompts_and_templates_go_through_handles_and_the_contract() {
    let (d, _dict) = daemon("").await;
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
    let resources = c.peer().list_all_resources().await.unwrap();
    assert!(
        resources
            .iter()
            .all(|r| r.uri.starts_with("inumaki://res/")),
        "{resources:?}"
    );
    assert!(
        !serde_json::to_string(&resources)
            .unwrap()
            .contains("Zyxwuria")
    );
    let customer = resources.iter().find(|r| r.name == "customer").unwrap();
    let rr = c
        .peer()
        .read_resource(ReadResourceRequestParams::new(customer.uri.clone()))
        .await
        .unwrap();
    let ResourceContents::TextResourceContents { text, uri, .. } = &rr.contents[0] else {
        panic!()
    };
    assert!(
        !text.contains("Zyxwuria") && text.contains("<PERSON_"),
        "{text}"
    );
    assert_eq!(uri, &customer.uri);
    let person = token_in(text, "<PERSON_");
    let templates = c.peer().list_all_resource_templates().await.unwrap();
    assert_eq!(templates.len(), 1);
    let tpl = &templates[0].uri_template;
    assert!(
        tpl.starts_with("inumaki://tpl/") && tpl.ends_with("/{id}"),
        "{tpl}"
    );
    let filled = tpl.replace("{id}", &person);
    let rr = c
        .peer()
        .read_resource(ReadResourceRequestParams::new(filled.clone()))
        .await
        .unwrap();
    let ResourceContents::TextResourceContents { text, uri, .. } = &rr.contents[0] else {
        panic!()
    };
    assert!(
        text.starts_with(&format!("note {person} about {person}")),
        "{text}"
    );
    assert_eq!(uri, &filled);
    let received = std::fs::read_to_string(log.path()).unwrap();
    assert!(
        received.contains(&format!("mem://note/{}", CANARY.replace(' ', "%20"))),
        "percent-encoded upstream: {received}"
    );
    let p = c
        .peer()
        .get_prompt(
            GetPromptRequestParams::new("greet")
                .with_arguments(args(json!({ "name": person.clone() }))),
        )
        .await
        .unwrap();
    assert_eq!(
        p.messages[0].content.as_text().unwrap().text,
        format!("Hello {person}, from {person}")
    );
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn schema_drift_hides_the_upstream_until_accepted() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let u = upstream_status(&d, "crm", "a").await.unwrap();
    let current = u["schema_fingerprint"].as_str().unwrap().to_string();
    assert!(current.starts_with("sha256:"));
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams/a/accept-schema",
            Some(json!({ "fingerprint": format!("sha256:{}", "0".repeat(64)) })),
        )
        .await;
    assert_eq!(code, 204);
    for _ in 0..100 {
        if upstream_status(&d, "crm", "a")
            .await
            .is_some_and(|u| u["contract"] == "drift")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        upstream_status(&d, "crm", "a").await.unwrap()["contract"],
        "drift"
    );
    let c = socket_client(&d, "crm").await.unwrap();
    assert!(
        c.peer().list_all_tools().await.unwrap().is_empty(),
        "drifted upstream hidden"
    );
    c.cancel().await.ok();
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams/a/accept-schema",
            Some(json!({ "fingerprint": current })),
        )
        .await;
    assert_eq!(code, 204);
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    assert!(!c.peer().list_all_tools().await.unwrap().is_empty());
    c.cancel().await.ok();
    d.stop().await;
}

/// Review Focus 2, end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_description_fails_the_listing_end_to_end() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "blocky").await;
    let mut env = BTreeMap::new();
    env.insert("INUMAKI_TEST_UPSTREAM_IBAN_DESC", "1".to_string());
    add_stdio(&d, "crm", "a", env, BTreeMap::new(), true).await;
    // The fingerprint is published with the rebuild that failed the listing.
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let e = mcp_err(c.peer().list_all_tools().await.unwrap_err());
    assert_eq!(e.message, "unsupported_content");
    assert_eq!(e.data.unwrap()["class"], "blocked_metadata");
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_changed_from_an_upstream_rebuilds_the_catalog() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    assert!(
        !c.peer()
            .list_all_tools()
            .await
            .unwrap()
            .iter()
            .any(|t| t.name == "extra")
    );
    c.peer()
        .call_tool(CallToolRequestParams::new("change_tools"))
        .await
        .unwrap();
    let mut seen = false;
    for _ in 0..50 {
        if c.peer()
            .list_all_tools()
            .await
            .unwrap()
            .iter()
            .any(|t| t.name == "extra")
        {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(seen);
    c.cancel().await.ok();
    d.stop().await;
}

/// Review Focus 4.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_result_is_resource_limit_without_partial_content() {
    let (d, _dict) = daemon("max_response_bytes = \"64KiB\"").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let e = mcp_err(
        c.peer()
            .call_tool(
                CallToolRequestParams::new("long")
                    // Over the 64 KiB response limit, under the transport's
                    // message cap (2 x limit + 64 KiB): refused by the
                    // limit check, the connection stays up.
                    .with_arguments(args(json!({ "bytes": 100_000 }))),
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "resource_limit");
    assert_eq!(e.data.unwrap()["limit"], "response_bytes");
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("long").with_arguments(args(json!({ "bytes": 2_000 }))),
        )
        .await
        .unwrap();
    assert!(!texts(&r).contains("Zyxwuria"));
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["gateway"]["datasets"][0]["limited"], 1);
    c.cancel().await.ok();
    d.stop().await;
}

/// Review Focus 5: a handle minted for a removed upstream never resolves,
/// not even after an upstream of the same name serving the same URI is
/// added again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handle_of_a_removed_upstream_is_unknown_after_it_is_added_again() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let old = c
        .peer()
        .list_all_resources()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.name == "customer")
        .unwrap()
        .uri
        .clone();
    c.cancel().await.ok();
    let (code, _) = d
        .call(Method::DELETE, "/v1/datasets/crm/upstreams/a", None)
        .await;
    assert_eq!(code, 204);
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let fresh = c
        .peer()
        .list_all_resources()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.name == "customer")
        .unwrap()
        .uri
        .clone();
    assert_ne!(fresh, old, "a new owner gets new handles");
    let e = mcp_err(
        c.peer()
            .read_resource(ReadResourceRequestParams::new(old))
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "unknown_resource");
    assert!(
        c.peer()
            .read_resource(ReadResourceRequestParams::new(fresh))
            .await
            .is_ok()
    );
    c.cancel().await.ok();
    d.stop().await;
}

async fn wait_contract(d: &TestDaemon, want: &str) -> serde_json::Value {
    for _ in 0..200 {
        if let Some(u) = upstream_status(d, "crm", "a").await {
            if u["contract"] == want {
                return u;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("contract never became {want}");
}

async fn tool_names(c: &Client) -> Vec<String> {
    c.peer()
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect()
}

/// Review I1: the contract is bound to the schemas it reviews. A new
/// unreviewed tool or new prose on a reviewed one keeps it bound; a changed
/// schema of a reviewed tool hides the upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reviewed_schema_changes_drift_while_new_tools_and_prose_do_not() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let reviewed = upstream_status(&d, "crm", "a").await.unwrap()["schema_fingerprint"].clone();
    let c = socket_client(&d, "crm").await.unwrap();
    // An unreviewed tool appears.
    c.peer()
        .call_tool(CallToolRequestParams::new("change_tools"))
        .await
        .unwrap();
    let mut seen = false;
    for _ in 0..100 {
        if tool_names(&c).await.contains(&"extra".to_string()) {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(seen, "extra listed");
    let u = upstream_status(&d, "crm", "a").await.unwrap();
    assert_eq!(
        (u["contract"].as_str(), &u["schema_fingerprint"]),
        (Some("ready"), &reviewed)
    );
    // New prose on a reviewed tool.
    c.peer()
        .call_tool(
            CallToolRequestParams::new("change_tools")
                .with_arguments(args(json!({ "what": "lookup_description" }))),
        )
        .await
        .unwrap();
    let mut seen = false;
    for _ in 0..100 {
        let tools = c.peer().list_all_tools().await.unwrap();
        if tools.iter().any(|t| {
            t.name == "lookup"
                && t.description.as_deref() == Some("look a customer up by their number")
        }) {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(seen, "the new description is listed");
    let u = upstream_status(&d, "crm", "a").await.unwrap();
    assert_eq!(
        (u["contract"].as_str(), &u["schema_fingerprint"]),
        (Some("ready"), &reviewed)
    );
    // A reviewed tool's schema changes: hidden until accepted.
    c.peer()
        .call_tool(
            CallToolRequestParams::new("change_tools")
                .with_arguments(args(json!({ "what": "lookup_schema" }))),
        )
        .await
        .unwrap();
    let u = wait_contract(&d, "drift").await;
    assert_ne!(u["schema_fingerprint"], reviewed);
    assert!(
        tool_names(&c).await.is_empty(),
        "the drifted upstream is hidden"
    );
    let e = mcp_err(
        c.peer()
            .call_tool(
                CallToolRequestParams::new("lookup")
                    .with_arguments(args(json!({ "customer_id": "<CUSTOMER_ID_a1b2c3>" }))),
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "unknown_tool", "lookup no longer routes");
    c.cancel().await.ok();
    d.stop().await;
}

/// Review I3: a message from a child above the transport cap (twice the
/// response limit plus envelope room) is never buffered whole: the
/// connection ends, the call answers resource_limit, the upstream restarts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_stdio_message_ends_at_the_transport() {
    let (d, _dict) =
        daemon("max_response_bytes = \"64KiB\"\nupstream_restart_max_backoff = \"1s\"").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let e = mcp_err(
        c.peer()
            .call_tool(
                CallToolRequestParams::new("long")
                    .with_arguments(args(json!({ "bytes": 3_000_000 }))),
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "resource_limit", "{e:?}");
    assert_eq!(e.data.unwrap()["limit"], "response_bytes");
    for _ in 0..100 {
        if upstream_status(&d, "crm", "a")
            .await
            .is_some_and(|u| u["state"] == "running" && u["restarts"].as_u64() >= Some(1))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo").with_arguments(args(json!({ "query": "back" }))),
        )
        .await
        .unwrap();
    assert_eq!(texts(&r), "echo: back");
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["gateway"]["datasets"][0]["limited"], 1);
    c.cancel().await.ok();
    d.stop().await;
}

/// Review I3 (HTTP): an SSE event above the cap fails the call (the
/// transport refuses it) instead of being buffered for sanitization.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_http_event_fails_the_call() {
    let (d, _dict) = daemon("max_response_bytes = \"64KiB\"\nupstream_call_timeout = \"5s\"").await;
    add_dataset(&d, "crm", "offline").await;
    let (addr, ct) = serve_scripted_http(ScriptedUpstream::default()).await;
    add_http(&d, "crm", "b", &format!("http://{addr}/mcp")).await;
    wait_running(&d, "crm", "b").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let t0 = std::time::Instant::now();
    let e = mcp_err(
        c.peer()
            .call_tool(
                CallToolRequestParams::new("long")
                    .with_arguments(args(json!({ "bytes": 3_000_000 }))),
            )
            .await
            .unwrap_err(),
    );
    assert!(t0.elapsed() < Duration::from_secs(8));
    assert!(
        matches!(
            e.message.as_ref(),
            "resource_limit" | "upstream_unavailable"
        ),
        "{e:?}"
    );
    c.cancel().await.ok();
    ct.cancel();
    d.stop().await;
}

/// Review M6: a link in a result becomes a handle that reads the linked
/// (unlisted) resource through the full sanitization path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_linked_resource_reads_through_its_handle() {
    let (d, _dict) = daemon("").await;
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
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("linked"))
        .await
        .unwrap();
    let link = r.content[1]
        .as_resource_link()
        .expect("a resource link")
        .clone();
    assert!(link.uri.starts_with("inumaki://res/"), "{}", link.uri);
    assert!(!serde_json::to_string(&r).unwrap().contains("Zyxwuria"));
    let listed = c.peer().list_all_resources().await.unwrap();
    assert!(
        listed.iter().all(|l| l.uri != link.uri),
        "the linked resource is not listed"
    );
    let rr = c
        .peer()
        .read_resource(ReadResourceRequestParams::new(link.uri.clone()))
        .await
        .unwrap();
    let ResourceContents::TextResourceContents { text, uri, .. } = &rr.contents[0] else {
        panic!()
    };
    assert_eq!(uri, &link.uri);
    assert!(
        text.starts_with("note <PERSON_") && !text.contains("Zyxwuria"),
        "{text}"
    );
    let received = std::fs::read_to_string(log.path()).unwrap();
    assert!(
        received.contains(&format!("mem://note/{CANARY}")),
        "the upstream got the raw uri"
    );
    c.cancel().await.ok();
    d.stop().await;
}

/// Plan 2c, Review Focus 3: a single-word name the dataset has tokenized
/// (`Long`, a real surname) is an ordinary word in API names, so the
/// scripted server's `long` tool still lists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_word_known_name_does_not_fail_the_listing() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    let s = std::sync::Arc::clone(&d.state);
    tokio::task::spawn_blocking(move || {
        inumakid::service::sanitize_blocks(
            &s,
            "crm",
            None,
            vec![inumakid::service::BlockInput {
                text: "Long".into(),
                hint: inumakid::service::FieldHint::Identifier(
                    inumaki_core::span::EntityKind::Person,
                ),
                redactions: Vec::new(),
            }],
        )
    })
    .await
    .unwrap()
    .unwrap();
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let c = socket_client(&d, "crm").await.unwrap();
    let names: Vec<String> = c
        .peer()
        .list_all_tools()
        .await
        .expect("the listing is not refused")
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(names.contains(&"long".to_string()), "{names:?}");
    c.cancel().await.ok();
    d.stop().await;
}
