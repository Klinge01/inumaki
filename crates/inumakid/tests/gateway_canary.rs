//! M4 spec §13 canary end to end: with a TRACE subscriber behind the
//! daemon's own privacy filter capturing every log line, drive the gateway
//! through listings, calls (including one with a canary tool name and one
//! whose arguments carry the real name after rehydration), errors,
//! unmatched paths and query strings; the canary name, IBAN, secret, tool
//! name, and dataset slug never appear in the logs or in any model-visible
//! error.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::*;
use hyper::Method;
use inumaki_gateway::scripted::IDENTITY;
use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, Implementation, InitializeRequestParams,
};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::json;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_logs_and_errors_never_contain_canaries() {
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
    std::fs::write(&persons, format!("{IDENTITY}\n")).unwrap();
    let base = BASE_CONFIG.replace(
        "persons = []",
        &format!("persons = [\"{}\"]", persons.display()),
    );
    let config = format!(
        "{base}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n"
    );
    let d = start_with_config(config, None, Duration::from_millis(200), None).await;
    let policy: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/examples/scripted-upstream.policy.json"
    ))
    .unwrap();
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "qwxzvk-canary-slug", "name": IDENTITY })),
        )
        .await;
    assert_eq!(code, 201);
    let mut secret = BTreeMap::new();
    secret.insert("TOKEN", "hunter2-canary");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/qwxzvk-canary-slug/upstreams",
            Some(json!({ "name": "a", "kind": "stdio", "command": env!("CARGO_BIN_EXE_inumaki-test-upstream"), "secret_env": secret, "content_policy": policy })),
        )
        .await;
    assert_eq!(code, 201);
    for _ in 0..200 {
        let (_, st) = d.call(Method::GET, "/v1/status", None).await;
        let u = &st["gateway"]["datasets"][0]["upstreams"][0];
        if u["state"] == "running" && u["schema_fingerprint"].is_string() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/gateway/tokens",
            Some(json!({ "label": "t" })),
        )
        .await;
    assert_eq!(code, 201);
    let token = body["token"].as_str().unwrap().to_string();
    let mut cfg = StreamableHttpClientTransportConfig::with_uri(format!(
        "http://{}/mcp/qwxzvk-canary-slug?who={}",
        d.gateway_addr(),
        IDENTITY.replace(' ', "%20")
    ));
    cfg.auth_header = Some(token.clone());
    let c =
        InitializeRequestParams::new(ClientCapabilities::default(), Implementation::new("t", "0"))
            .serve(StreamableHttpClientTransport::from_config(cfg))
            .await
            .unwrap();
    let mut errors: Vec<String> = Vec::new();
    c.peer().list_all_tools().await.unwrap();
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let person = r.structured_content.as_ref().unwrap()["customer"]["name"]
        .as_str()
        .unwrap()
        .to_string();
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo").with_arguments(
                json!({ "query": format!("find {person}") })
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
    assert!(!serde_json::to_string(&r).unwrap().contains("Zyxwuria"));
    c.peer()
        .call_tool(CallToolRequestParams::new("qwxzvk_tool"))
        .await
        .unwrap();
    for (name, a) in [
        (IDENTITY, json!({})),
        ("fail", json!({ "query": IDENTITY })),
        ("echo", json!({ "query": "<PERSON_a1b2c3>" })),
        ("binary", json!({})),
    ] {
        if let Err(e) = c
            .peer()
            .call_tool(
                CallToolRequestParams::new(name.to_string())
                    .with_arguments(a.as_object().cloned().unwrap()),
            )
            .await
        {
            errors.push(format!("{e:?}"));
        }
    }
    // unmatched TCP path, query string, and a control-socket call carrying the canary
    let q = IDENTITY.replace(' ', "%20");
    let addr = d.gateway_addr();
    assert_eq!(raw_get(addr, &format!("/nope?name={q}"), None).await, 404);
    // Malformed dataset segments and the 401 path, each with a canary query
    // string (spec §13): fixed answers, nothing echoed or logged.
    for (path, bearer, want) in [
        (format!("/mcp/%ZZ?name={q}"), None, 401),
        (format!("/mcp/%ZZ?name={q}"), Some(token.as_str()), 404),
        (format!("/mcp/a%2Fb?name={q}"), Some(token.as_str()), 404),
        (format!("/mcp/qwxzvk-canary-slug?who={q}"), None, 401),
        (
            format!("/mcp/qwxzvk-canary-slug?who={q}"),
            Some("inumaki-gw-wrong"),
            401,
        ),
    ] {
        assert_eq!(raw_get(addr, &path, bearer).await, want, "{path}");
    }
    let (code, body) = d
        .call(Method::GET, &format!("/mcp/a%2Fb?name={q}"), None)
        .await;
    assert_eq!(code, 404, "{body}");
    assert!(
        !body.to_string().contains("Zyxwuria") && !body.to_string().contains("a/b"),
        "{body}"
    );
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "qwxzvk-canary-slug", "text": format!("Hallo {IDENTITY}") })),
        )
        .await;
    assert_eq!(code, 200);
    assert!(!b["text"].as_str().unwrap().contains("Zyxwuria"));
    tokio::time::sleep(Duration::from_millis(500)).await;
    c.cancel().await.ok();
    d.stop().await;
    let logs = cap.text();
    assert!(
        logs.contains("tool call served"),
        "the gateway logged:\n{logs}"
    );
    assert!(
        logs.contains("route=/mcp/{dataset}") || logs.contains("route=\"/mcp/{dataset}\""),
        "{logs}"
    );
    for needle in [
        "Zyxwuria",
        "Quolnath",
        "AT61",
        "hunter2",
        "qwxzvk",
        "who=",
        "/nope",
        "%ZZ",
        "a%2Fb",
        "a/b",
        "inumaki-gw-wrong",
        &token,
        &person,
    ] {
        assert!(
            !logs.contains(needle),
            "{needle} leaked into the logs:\n{logs}"
        );
        for e in &errors {
            assert!(!e.contains(needle), "{needle} leaked into an error: {e}");
        }
    }
    assert!(
        errors.iter().any(|e| e.contains("unknown_tool"))
            && errors.iter().any(|e| e.contains("upstream_error"))
            && errors.iter().any(|e| e.contains("unresolved_token"))
            && errors.iter().any(|e| e.contains("unsupported_content")),
        "{errors:?}"
    );
}

/// A plain HTTP GET over a fresh TCP connection (no reqwest dependency).
async fn raw_get(addr: std::net::SocketAddr, path: &str, bearer: Option<&str>) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Connection: close\r\n\r\n",
            bearer.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"))
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf);
    head.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}
