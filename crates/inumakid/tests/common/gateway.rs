//! Gateway end-to-end helpers shared by the gateway, canary, load, and
//! later activity/tripwire tests: a daemon with a dictionary canary and a
//! random gateway port, dataset and upstream setup through the control
//! API, rmcp clients over TCP (bearer) and over the control socket.

use std::collections::BTreeMap;
use std::time::Duration;

use hyper::Method;
use inumaki_gateway::scripted::IDENTITY;
use rmcp::model::{ClientCapabilities, Implementation, InitializeRequestParams};
use rmcp::service::{ClientInitializeError, RunningService, ServiceError};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{RoleClient, ServiceExt};
use serde_json::json;

use super::{BASE_CONFIG, TestDaemon, start_with_config};

/// The canary person the scripted upstream returns.
pub const CANARY: &str = IDENTITY;
/// The reviewed contract for the scripted upstream.
pub const POLICY: &str = include_str!("../../../../docs/examples/scripted-upstream.policy.json");

/// A connected MCP client.
pub type Client = RunningService<RoleClient, InitializeRequestParams>;

/// The client's initialize parameters.
pub fn client_info() -> InitializeRequestParams {
    InitializeRequestParams::new(
        ClientCapabilities::default(),
        Implementation::new("test-client", "0"),
    )
}

/// An MCP client for `dataset` over the gateway's TCP listener.
pub async fn tcp_client(
    d: &TestDaemon,
    dataset: &str,
    token: Option<&str>,
) -> Result<Client, ClientInitializeError> {
    let mut cfg = StreamableHttpClientTransportConfig::with_uri(format!(
        "http://{}/mcp/{dataset}",
        d.gateway_addr()
    ));
    cfg.auth_header = token.map(str::to_string);
    client_info()
        .serve(StreamableHttpClientTransport::from_config(cfg))
        .await
}

/// An MCP client for `dataset` over the control socket (no token).
pub async fn socket_client(d: &TestDaemon, dataset: &str) -> Result<Client, ClientInitializeError> {
    let cfg =
        StreamableHttpClientTransportConfig::with_uri(format!("http://inumakid/mcp/{dataset}"));
    let t = StreamableHttpClientTransport::from_unix_socket_with_config(
        &d.socket.to_string_lossy(),
        cfg,
    );
    client_info().serve(t).await
}

/// A fresh gateway bearer token.
pub async fn token(d: &TestDaemon) -> String {
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/gateway/tokens",
            Some(json!({ "label": "test" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    body["token"].as_str().unwrap().to_string()
}

/// A daemon whose dictionary holds the canary (the offline profile detects
/// it), with a `blocky` profile that blocks IBANs, a `lax` profile that
/// passes uncertain results (so the gateway's withholding is observable),
/// a random gateway port, and `gateway_extra` lines in `[gateway]`.
pub async fn daemon(gateway_extra: &str) -> (TestDaemon, tempfile::TempDir) {
    let dict = tempfile::tempdir().unwrap();
    let persons = dict.path().join("persons.txt");
    std::fs::write(&persons, format!("{CANARY}\n")).unwrap();
    let base = BASE_CONFIG.replace(
        "persons = []",
        &format!("persons = [\"{}\"]", persons.display()),
    );
    assert_ne!(base, BASE_CONFIG);
    let config = format!(
        "{base}\n[[domain.patterns]]\nregex = \"Elektriker\"\nkind = \"PROFESSION\"\n\
         [daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n{gateway_extra}\n\
         [profiles.blocky]\nextends = \"offline\"\n[profiles.blocky.entities]\nIBAN = {{ action = \"block\", min_confidence = 0.0 }}\n[profiles.blocky.verifier]\nretry_profile = \"blocky\"\n\
         [profiles.lax]\nextends = \"offline\"\n[profiles.lax.entities]\nPROFESSION = {{ action = \"preserve\", min_confidence = 0.0 }}\n[profiles.lax.verifier]\non_uncertain = \"escalate\"\nretry_profile = \"lax\"\n"
    );
    let d = start_with_config(config, None, Duration::from_secs(3600), None).await;
    (d, dict)
}

/// Create dataset `id` with `profile`.
pub async fn add_dataset(d: &TestDaemon, id: &str, profile: &str) {
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": id, "name": "T", "profile": profile })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
}

/// Add the scripted upstream as a child process, with the reviewed
/// contract when `policy`.
pub async fn add_stdio(
    d: &TestDaemon,
    dataset: &str,
    name: &str,
    env: BTreeMap<&str, String>,
    secret_env: BTreeMap<&str, &str>,
    policy: bool,
) {
    let policy_value: serde_json::Value = if policy {
        serde_json::from_str(POLICY).unwrap()
    } else {
        json!({})
    };
    let (code, body) = d
        .call(
            Method::POST,
            &format!("/v1/datasets/{dataset}/upstreams"),
            Some(json!({ "name": name, "kind": "stdio", "command": env!("CARGO_BIN_EXE_inumaki-test-upstream"), "env": env, "secret_env": secret_env, "content_policy": policy_value })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
}

/// Add a Streamable HTTP upstream without a contract.
pub async fn add_http(d: &TestDaemon, dataset: &str, name: &str, url: &str) {
    let (code, body) = d
        .call(
            Method::POST,
            &format!("/v1/datasets/{dataset}/upstreams"),
            Some(json!({ "name": name, "kind": "http", "url": url })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
}

/// The status entry of one upstream.
pub async fn upstream_status(
    d: &TestDaemon,
    dataset: &str,
    upstream: &str,
) -> Option<serde_json::Value> {
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    st["gateway"]["datasets"]
        .as_array()?
        .iter()
        .find(|x| x["id"] == dataset)?["upstreams"]
        .as_array()?
        .iter()
        .find(|u| u["name"] == upstream)
        .cloned()
}

/// Wait until the upstream runs and its first listing set a fingerprint.
pub async fn wait_running(d: &TestDaemon, dataset: &str, upstream: &str) {
    for _ in 0..200 {
        if let Some(u) = upstream_status(d, dataset, upstream).await {
            if u["state"] == "running" && u["schema_fingerprint"].is_string() {
                tokio::time::sleep(Duration::from_millis(50)).await;
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("upstream {upstream} of {dataset} did not reach running with a fingerprint");
}

/// Every text item of a result, joined by newlines.
pub fn texts(r: &rmcp::model::CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A JSON object value as tool arguments.
pub fn args(v: serde_json::Value) -> rmcp::model::JsonObject {
    v.as_object().cloned().unwrap()
}

/// The first word of `text` starting with `prefix`.
pub fn token_in(text: &str, prefix: &str) -> String {
    text.split(|c: char| c.is_whitespace() || c == ',' || c == '.' || c == '"')
        .find(|w| w.starts_with(prefix))
        .unwrap_or_else(|| panic!("no {prefix} token in {text}"))
        .to_string()
}

/// The MCP error inside a service error.
pub fn mcp_err(e: ServiceError) -> rmcp::model::ErrorData {
    match e {
        ServiceError::McpError(d) => d,
        other => panic!("{other}"),
    }
}
