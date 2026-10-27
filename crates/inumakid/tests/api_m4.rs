//! M4 spec §8: upstream and gateway token endpoints, dataset kinds, the
//! `allow_binary` rejection, the status gateway block, `doctor`. Secrets
//! never appear in a response.

mod common;

use common::*;
use hyper::Method;
use serde_json::json;

const SECRET: &str = "hunter2-canary";

/// Secret names of datasets: the daemon's own `inumaki-chat/...` secrets
/// (the proxy's client value, M8) are not a dataset's and are left out.
fn dataset_secrets(d: &TestDaemon) -> Vec<String> {
    let mut names = d.state.vault.list_secret_names().unwrap();
    names.retain(|n| !n.starts_with("inumaki-chat/"));
    names
}
/// `sha256:` plus 64 lowercase hex digits (sha256 of the literal `test`):
/// the only form `accept-schema` accepts (review M1).
const FINGERPRINT: &str = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datasets_carry_kind_and_reject_allow_binary() {
    let d = start().await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "mail-work", "name": "Work", "kind": "mailbox" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(body["kind"], "mailbox");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "crm", "name": "CRM" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(body["kind"], "generic");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "x", "name": "X", "kind": "folder" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(body["kind"], "folder");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "w", "name": "W", "kind": "bogus" })),
        )
        .await;
    assert_eq!(code, 400, "{body}");
    assert_eq!(
        body["error"]["message"],
        "kind must be generic, mailbox, or folder"
    );
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "y", "name": "Y", "allow_binary": true })),
        )
        .await;
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["error"]["message"], "allow_binary is not supported");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "z", "name": "Z", "allow_binary": false })),
        )
        .await;
    assert_eq!(code, 400, "even false is refused: {body}");
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["datasets"][1]["kind"], "mailbox");
    // The bound address (ruling S6): configured `127.0.0.1:0`, reported with its port.
    let listen = st["gateway"]["listen"].as_str().unwrap();
    let port: u16 = listen.strip_prefix("127.0.0.1:").unwrap().parse().unwrap();
    assert_ne!(port, 0, "{listen}");
    assert_eq!(st["gateway"]["tokens"], 0);
    assert_eq!(st["gateway"]["qualification"], "unqualified");
    assert!(st["gateway"]["datasets"].is_array());
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_dataset_with_a_percent_encoded_slash_in_the_id_is_404_and_touches_no_secrets() {
    // Review I3: axum percent-decodes a route's `{id}` segment, so
    // `/v1/datasets/crm%2Fupstream` arrives as the id `crm/upstream` — which
    // happens to be the exact prefix every one of dataset `crm`'s upstream
    // secrets starts with. The delete-dataset secret sweep must never run
    // unless the vault actually deleted a dataset by this id.
    let d = start().await;
    d.dataset("crm").await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams",
            Some(
                json!({ "name": "a", "kind": "stdio", "command": "x", "secret_env": { "K": SECRET } }),
            ),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let before = dataset_secrets(&d);
    assert_eq!(before, ["crm/upstream/a/env"]);
    let (code, _) = d
        .call(Method::DELETE, "/v1/datasets/crm%2Fupstream", None)
        .await;
    assert_eq!(code, 404);
    assert_eq!(
        dataset_secrets(&d),
        before,
        "the dataset's real secrets survive an id that only looks like a prefix match"
    );
    assert!(
        d.state.vault.dataset("crm").is_ok(),
        "the dataset itself was never touched"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstreams_store_secrets_as_names_validate_the_policy_and_delete_with_the_upstream() {
    let d = start().await;
    d.dataset("crm").await;
    let policy = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../docs/examples/scripted-upstream.policy.json"
    ))
    .unwrap();
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams",
            Some(json!({
                "name": "crm", "kind": "stdio", "command": "npx", "args": ["-y", "@example/crm-mcp"],
                "env": { "CRM_URL": "https://crm.example" }, "secret_env": { "CRM_TOKEN": SECRET },
                "content_policy": policy
            })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(body["name"], "crm");
    assert_eq!(body["args"], json!(["-y", "@example/crm-mcp"]));
    assert_eq!(body["env"]["CRM_URL"], "https://crm.example");
    assert_eq!(body["env_secret"], "crm/upstream/crm/env");
    assert!(body["headers_secret"].is_null());
    assert_eq!(body["content_policy"]["version"], 1);
    assert!(body["schema_fingerprint"].is_null());
    assert!(!body.to_string().contains(SECRET), "{body}");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams",
            Some(json!({ "name": "wiki", "kind": "http", "url": "http://127.0.0.1:9000/mcp", "headers": { "X-Tenant": "acme" }, "secret_headers": { "Authorization": format!("Bearer {SECRET}") } })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(body["headers_secret"], "crm/upstream/wiki/headers");
    assert_eq!(body["content_policy"], json!({}));
    let (code, list) = d
        .call(Method::GET, "/v1/datasets/crm/upstreams", None)
        .await;
    assert_eq!(code, 200);
    let names: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["crm", "wiki"]);
    assert!(!list.to_string().contains(SECRET));
    assert_eq!(
        dataset_secrets(&d),
        ["crm/upstream/crm/env", "crm/upstream/wiki/headers"]
    );
    let stored = d
        .state
        .vault
        .get_secret("crm/upstream/crm/env")
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&stored).unwrap()["CRM_TOKEN"],
        SECRET
    );
    // policy validation by fixed codes, no secret left behind on failure
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams",
            Some(json!({ "name": "bad", "kind": "stdio", "command": "x", "secret_env": { "K": SECRET }, "content_policy": { "tools": { "t": { "result": { "/a": "loud" } } } } })),
        )
        .await;
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["error"]["type"], "bad_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("invalid rule")
    );
    assert_eq!(
        dataset_secrets(&d).len(),
        2,
        "no secret for the refused upstream"
    );
    // accept-schema
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams/wiki/accept-schema",
            Some(json!({ "fingerprint": "sha256:abc" })),
        )
        .await;
    assert_eq!(code, 400, "a short fingerprint is refused: {body}");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams/wiki/accept-schema",
            Some(json!({ "fingerprint": FINGERPRINT })),
        )
        .await;
    assert_eq!(code, 204);
    let (_, list) = d
        .call(Method::GET, "/v1/datasets/crm/upstreams", None)
        .await;
    assert_eq!(list[1]["schema_fingerprint"], FINGERPRINT);
    // duplicate add: the existing upstream's secret must survive untouched
    // (review I2) even when the duplicate request itself carries a secret.
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams",
            Some(
                json!({ "name": "crm", "kind": "stdio", "command": "x", "secret_headers": { "X": SECRET } }),
            ),
        )
        .await;
    assert_eq!(code, 409, "{body}");
    assert_eq!(
        dataset_secrets(&d),
        ["crm/upstream/crm/env", "crm/upstream/wiki/headers"],
        "the duplicate's own secret was never written and the original upstream's secret was never touched"
    );
    let stored = d
        .state
        .vault
        .get_secret("crm/upstream/crm/env")
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&stored).unwrap()["CRM_TOKEN"],
        SECRET,
        "the original secret's value is unchanged"
    );
    // bad kinds, mail on generic, missing dataset
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams",
            Some(json!({ "name": "m", "kind": "mail" })),
        )
        .await;
    assert_eq!(code, 400, "{body}");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams",
            Some(json!({ "name": "s", "kind": "sse", "url": "http://x" })),
        )
        .await;
    assert_eq!(code, 400);
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/nope/upstreams",
            Some(json!({ "name": "s", "kind": "stdio", "command": "x" })),
        )
        .await;
    assert_eq!(code, 404);
    let (code, _) = d
        .call(Method::DELETE, "/v1/datasets/crm/upstreams/crm", None)
        .await;
    assert_eq!(code, 204);
    assert_eq!(dataset_secrets(&d), ["crm/upstream/wiki/headers"]);
    let (code, _) = d
        .call(Method::DELETE, "/v1/datasets/crm/upstreams/crm", None)
        .await;
    assert_eq!(code, 404);
    let (code, _) = d.call(Method::DELETE, "/v1/datasets/crm", None).await;
    assert_eq!(code, 204);
    assert!(
        dataset_secrets(&d).is_empty(),
        "deleting the dataset deletes its secrets"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_tokens_are_returned_once_listed_by_label_and_revocable() {
    let d = start().await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/gateway/tokens",
            Some(json!({ "label": "claude-code" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("inumaki-gw-"));
    let id = body["id"].as_i64().unwrap();
    let (code, list) = d.call(Method::GET, "/v1/gateway/tokens", None).await;
    assert_eq!(code, 200);
    assert_eq!(list[0]["label"], "claude-code");
    assert!(list[0].get("token").is_none());
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["gateway"]["tokens"], 1);
    assert!(!st.to_string().contains(&token));
    assert!(
        d.state
            .vault
            .verify_gateway_token(&token)
            .unwrap()
            .is_some()
    );
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/gateway/tokens",
            Some(json!({ "label": "" })),
        )
        .await;
    assert_eq!(code, 400);
    let (code, _) = d
        .call(Method::DELETE, &format!("/v1/gateway/tokens/{id}"), None)
        .await;
    assert_eq!(code, 204);
    assert!(
        d.state
            .vault
            .verify_gateway_token(&token)
            .unwrap()
            .is_none()
    );
    let (code, _) = d
        .call(Method::DELETE, &format!("/v1/gateway/tokens/{id}"), None)
        .await;
    assert_eq!(code, 404);
    d.stop().await;
}

#[test]
fn gateway_config_defaults_overrides_and_rejections() {
    use inumakid::config::{DaemonConfig, parse_bytes};
    use std::time::Duration;
    let base = format!("{BASE_CONFIG}\n[daemon]\ndefault_profile = \"offline\"\n");
    let c = DaemonConfig::from_toml(&base).unwrap();
    assert_eq!(c.gateway.listen, "127.0.0.1:8789");
    assert_eq!(c.gateway.activity_retention_days, 30);
    let g = c.gateway_config();
    assert_eq!(g.restart_max_backoff, Duration::from_secs(30));
    assert_eq!(g.call_timeout, Duration::from_secs(60));
    assert_eq!(g.max_response_bytes, 4 * 1024 * 1024);
    assert_eq!(g.max_inflight, 8);
    assert_eq!(g.queue_timeout, Duration::from_secs(30));
    let c = DaemonConfig::from_toml(&format!(
        "{base}[gateway]\nlisten = \"127.0.0.1:0\"\nupstream_restart_max_backoff = \"5s\"\nupstream_call_timeout = \"1s\"\nmax_response_bytes = \"512KiB\"\nmax_inflight = 2\nqueue_timeout = \"2s\"\n"
    ))
    .unwrap();
    let g = c.gateway_config();
    assert_eq!(
        (g.listen.as_str(), g.max_response_bytes, g.max_inflight),
        ("127.0.0.1:0", 512 * 1024, 2)
    );
    assert_eq!(parse_bytes("1048576"), Some(1 << 20));
    assert_eq!(parse_bytes("4MiB"), Some(4 << 20));
    assert_eq!(parse_bytes("x"), None);
    for (extra, key) in [
        (
            "[gateway]\nupstream_call_timeout = \"soon\"\n",
            "gateway.upstream_call_timeout",
        ),
        (
            "[gateway]\nupstream_restart_max_backoff = \"0s\"\n",
            "gateway.upstream_restart_max_backoff",
        ),
        ("[gateway]\nlisten = \"0.0.0.0:8789\"\n", "gateway.listen"),
        (
            "[gateway]\nmax_response_bytes = \"1KiB\"\n",
            "gateway.max_response_bytes",
        ),
        ("[gateway]\nmax_inflight = 0\n", "gateway.max_inflight"),
        (
            "[gateway]\nactivity_retention_days = 0\n",
            "gateway.activity_retention_days",
        ),
        (
            "[gateway]\nsanitize_descriptions = true\n",
            "gateway.sanitize_descriptions",
        ),
        (
            "[gateway]\nsanitize_descriptions = false\n",
            "gateway.sanitize_descriptions",
        ),
    ] {
        let e = DaemonConfig::from_toml(&format!("{base}{extra}")).unwrap_err();
        assert!(format!("{e}").contains(key), "{extra}: {e}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_reports_fixed_reasons_and_next_steps() {
    let d = start().await;
    d.dataset("crm").await;
    d.call(
        Method::POST,
        "/v1/datasets/crm/upstreams",
        Some(
            json!({ "name": "a", "kind": "stdio", "command": "x", "secret_env": { "K": SECRET } }),
        ),
    )
    .await;
    {
        // an invalid policy behind the vault's back
        let dir = d.dir.path().join("data").join("vault.sqlite");
        let c = rusqlite::Connection::open(dir).unwrap();
        c.execute(
            "UPDATE upstreams SET content_policy = '{\"bogus\":1}' WHERE name = 'a'",
            [],
        )
        .unwrap();
    }
    let (code, b) = d.call(Method::GET, "/v1/doctor", None).await;
    assert_eq!(code, 200, "{b}");
    assert_eq!(b["vault"]["key_source"], "file");
    assert_eq!(b["vault"]["integrity_ok"], true);
    assert!(
        b["models"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["status"] == "missing")
    );
    assert!(
        b["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "offline"
                && p["available"] == true
                && p["qualification"] == "unqualified")
    );
    let ds = &b["datasets"][0];
    assert_eq!(ds["id"], "crm");
    assert_eq!(ds["upstreams"][0]["contract"], "invalid");
    assert_eq!(ds["upstreams"][0]["has_secrets"], true);
    assert_eq!(b["gateway"]["tokens"], 0);
    let steps = b["next_steps"].as_array().unwrap();
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().unwrap().contains("inumaki models pull")),
        "{steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().unwrap().contains("gateway token new")),
        "{steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().unwrap().contains("content policy")),
        "{steps:?}"
    );
    assert!(!b.to_string().contains(SECRET));
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_add_refuses_a_contract_the_profile_blocks() {
    // Review M3: a content policy that types a field as an identifier kind
    // the dataset's profile blocks (or removes) must be refused at add
    // time, before the gateway ever loads it.
    let d = start_with(
        "",
        "[profiles.blocky]\nextends = \"offline\"\n[profiles.blocky.entities]\nCUSTOMER_ID = { action = \"block\", min_confidence = 0.0 }\n",
        std::time::Duration::from_secs(3600),
        None,
    )
    .await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "crm", "name": "CRM", "profile": "blocky" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let policy = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../docs/examples/scripted-upstream.policy.json"
    ))
    .unwrap();
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams",
            Some(
                json!({ "name": "crm", "kind": "stdio", "command": "x", "content_policy": policy }),
            ),
        )
        .await;
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["error"]["type"], "bad_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("blocked or removed"),
        "{body}"
    );
    assert!(
        d.state.vault.upstreams("crm").unwrap().is_empty(),
        "nothing was added"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_body_debug_omits_secret_names_and_values() {
    // Review I6: `UpstreamBody`'s `Debug` must not print environment or
    // header values, the raw URL, argument text, or secret names.
    use inumaki_vault::{Upstream, UpstreamKind, UpstreamSpec};
    use std::collections::BTreeMap;
    let mut env = BTreeMap::new();
    env.insert("K".to_string(), SECRET.to_string());
    let mut headers = BTreeMap::new();
    headers.insert("X-Tenant".to_string(), SECRET.to_string());
    let spec = UpstreamSpec {
        name: "crm".into(),
        kind: UpstreamKind::Http,
        command: None,
        args: vec![SECRET.into()],
        cwd: Some("/secret/path".into()),
        url: Some(format!("https://user:{SECRET}@host/")),
        env,
        headers,
        env_secret: Some("crm/upstream/crm/env".into()),
        headers_secret: Some("crm/upstream/crm/headers".into()),
        content_policy: "{}".into(),
        schema_fingerprint: None,
        enabled: true,
    };
    let u = Upstream {
        id: 1,
        dataset_id: "crm".into(),
        spec,
        created_at: 0,
    };
    let dbg = format!("{:?}", inumakid::api::upstreams::UpstreamBody::from(u));
    assert!(!dbg.contains(SECRET), "{dbg}");
    assert!(!dbg.contains("/secret/path"), "{dbg}");
    assert!(!dbg.contains("crm/upstream/crm/env"), "{dbg}");
    assert!(!dbg.contains("crm/upstream/crm/headers"), "{dbg}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_body_debug_impls_omit_secrets() {
    use inumakid::api::upstreams::UpstreamCreateBody;
    use std::collections::BTreeMap;
    let mut secret_env = BTreeMap::new();
    secret_env.insert("TOKEN".to_string(), SECRET.to_string());
    let u = UpstreamCreateBody {
        name: "crm".into(),
        kind: "stdio".into(),
        command: Some("npx".into()),
        args: vec![SECRET.into()],
        cwd: None,
        url: None,
        env: BTreeMap::new(),
        headers: BTreeMap::new(),
        secret_env,
        secret_headers: BTreeMap::new(),
        content_policy: None,
    };
    let dbg = format!("{u:?}");
    assert!(!dbg.contains(SECRET), "{dbg}");
}
