//! Daemon-level proxy tests (M8 spec §15 tests 1, 2, 13, 15, 17;
//! non-streaming): the listener, the shared guard, `GET /v1/proxy`, the
//! host over the vault (Task 10b), the reserved chat dataset, activity
//! records and the chat journal. The test daemons run the `offline`
//! profile (no models); `proxy_models.rs` repeats the canary with NER.

mod common;

use std::sync::Arc;
use std::time::Duration;

use hyper::Method;
use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_proxy::{Script, ScriptedUpstream, Step};
use serde_json::{Value, json};

const NAME: &str = "Zyxwuria Quolnath";
const EMAIL: &str = "zyx.quolnath@example.invalid";

async fn daemon_with_scripted(script: Script) -> (common::TestDaemon, Arc<ScriptedUpstream>) {
    daemon_with_scripted_and(script, "").await
}

/// A daemon whose proxy forwards to a scripted upstream; `proxy_extra`
/// goes into the `[proxy]` table.
async fn daemon_with_scripted_and(
    script: Script,
    proxy_extra: &str,
) -> (common::TestDaemon, Arc<ScriptedUpstream>) {
    // The test's own reqwest client has no TLS provider of its own.
    inumaki_proxy::forward::ensure_crypto_provider();
    let (addr, up) = inumaki_proxy::scripted::spawn_http(script).await;
    let extra = scripted_proxy(addr, proxy_extra);
    (
        common::start_with("", &extra, Duration::from_secs(3600), None).await,
        up,
    )
}

/// The `[proxy]` table pointing every upstream at the scripted one.
fn scripted_proxy(addr: std::net::SocketAddr, proxy_extra: &str) -> String {
    format!(
        "[proxy]\nlisten = \"127.0.0.1:0\"\n{proxy_extra}\n[proxy.upstreams.anthropic]\nbase_url = \"http://{addr}\"\n[proxy.upstreams.openai]\nbase_url = \"http://{addr}\"\n[proxy.upstreams.openai-codex]\nbase_url = \"http://{addr}\"\n"
    )
}

fn proxy_url(d: &common::TestDaemon, path: &str) -> String {
    let st = d.state.proxy.get().unwrap().status();
    format!("http://{}{path}", st.listen)
}

/// Spec §15 test 15.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_proxy_listener_is_hardened() {
    let (d, up) = daemon_with_scripted(Script(vec![Step::EchoUserText])).await;
    let url = proxy_url(&d, "/anthropic/v1/messages");
    let c = reqwest::Client::new();
    let r = c
        .post(&url)
        .header("origin", "https://evil.example")
        .json(&json!({"messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = c
        .post(&url)
        .header("host", "evil.example")
        .json(&json!({"messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = c
        .get(&url)
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 501);
    // An unserved path is answered before it could be forwarded.
    let r = c
        .post(proxy_url(&d, "/anthropic/v1/messages/batches"))
        .json(&json!({"requests": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = c
        .get(proxy_url(&d, "/anthropic/v1/models"))
        .send()
        .await
        .unwrap();
    assert!(
        r.headers()
            .keys()
            .all(|k| !k.as_str().starts_with("access-control-"))
    );
    assert!(
        up.recorded().iter().all(|(_, b)| b.is_empty()),
        "the model list forwarded no body; nothing else reached the upstream"
    );
    d.stop().await;
}

/// Spec §15 test 17 (status part) and the contract: the body decodes as the
/// client crate's `ProxyBody` and re-encodes byte for byte (M6 §9.8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_contract() {
    let (d, _) = daemon_with_scripted(Script::default()).await;
    let r = inumaki_client::Client::new(&d.socket)
        .raw(inumaki_client::Method::GET, "/v1/proxy", Vec::new())
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    inumaki_client::contract::assert_bytes_round_trip::<inumaki_client::ProxyBody>(&r.body);
    let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(body["state"], "running");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["client_header"]["name"], "X-Inumaki-Client");
    let value = body["client_header"]["value"].as_str().unwrap();
    assert_eq!(value.len(), 64);
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    let routes = body["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 3);
    assert_eq!(
        routes[0]["paths"],
        json!([
            "/v1/messages",
            "/v1/messages/count_tokens",
            "/v1/models",
            "/v1/models/{id}"
        ])
    );
    let listen = body["listen"].as_str().unwrap();
    assert_eq!(routes[0]["base_url"], format!("http://{listen}/anthropic"));
    // M6 §9.6 amendment 2026-10-12: `timing` then `static_cache`, after
    // `client_header` (the byte-for-byte round trip above pins the order).
    // No request yet: an empty window with every sample `null`. The profile
    // has no models, but the daemon's host still provides the memo.
    assert_eq!(
        body["timing"],
        json!({"window": 0, "last_at": null, "last": null, "p50": null, "p95": null})
    );
    assert_eq!(
        body["static_cache"],
        json!({"enabled": true, "hits": 0, "misses": 0, "entries": 0, "clears": 0})
    );
    // `Value` sorts its keys, so the order is read off the raw bytes.
    let text = String::from_utf8_lossy(&r.body);
    let at = |k: &str| text.find(&format!("\"{k}\":")).unwrap();
    assert!(at("client_header") < at("timing") && at("timing") < at("static_cache"));
    assert!(
        text.trim_end().ends_with("}}"),
        "static_cache closes the body: {text}"
    );
    d.stop().await;
}

/// After one forwarded request the `timing` object holds a sample, and the
/// body still re-encodes byte for byte through the client's types (M6 §9.6
/// amendment 2026-10-12): every sample field is a whole number, the
/// forwarded request has provider times, and nothing but numbers and the
/// timestamp is in the object.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_served_request_fills_the_timing_object_and_the_body_still_round_trips() {
    let (d, _) = daemon_with_scripted(Script(vec![Step::EchoUserText])).await;
    let value = client_value(&d).await;
    let (path, body) = routes("Bitte um Rückruf.")[0].clone();
    let (s, answer, _) = post(&proxy_url(&d, path), body, &[("x-inumaki-client", &value)]).await;
    assert_eq!(s, 200, "{answer}");
    let r = inumaki_client::Client::new(&d.socket)
        .raw(inumaki_client::Method::GET, "/v1/proxy", Vec::new())
        .await
        .unwrap();
    inumaki_client::contract::assert_bytes_round_trip::<inumaki_client::ProxyBody>(&r.body);
    let st: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(st["timing"]["window"], 1);
    assert!(st["timing"]["last_at"].as_i64().unwrap() > 1_700_000_000);
    for which in ["last", "p50", "p95"] {
        let t = st["timing"][which].as_object().unwrap();
        assert_eq!(t.len(), 11, "{which}");
        for (k, v) in t {
            assert!(v.is_u64(), "{which}.{k} is a whole number: {v}");
        }
    }
    let local: u64 = [
        "read_ms",
        "queue_ms",
        "scan_ms",
        "engine_ms",
        "closure_ms",
        "restore_ms",
    ]
    .iter()
    .map(|k| st["timing"]["last"][k].as_u64().unwrap())
    .sum();
    // Each stage is truncated to whole milliseconds on its own, so the sum
    // of the six can fall short of `local_ms` by less than one each.
    let l = st["timing"]["last"]["local_ms"].as_u64().unwrap();
    assert!((local..local + 6).contains(&l), "local {l} vs sum {local}");
    d.stop().await;
}

/// The client value is created once and kept: a restart on the same data
/// directory serves the same value (adapters write it into harness files).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_value_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let d = common::start_in(dir.path(), "").await;
    let (_, a) = d.call(Method::GET, "/v1/proxy", None).await;
    d.stop().await;
    let d = common::start_in(dir.path(), "").await;
    let (_, b) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(a["client_header"]["value"], b["client_header"]["value"]);
    assert_eq!(a["client_header"]["value"].as_str().unwrap().len(), 64);
    d.stop().await;
}

/// Spec decision 21: the daemon runs, the status says why, and nothing
/// answers on the configured address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_failure_is_not_fatal() {
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = blocker.local_addr().unwrap().port();
    let d = common::start_with(
        "",
        &format!("[proxy]\nlisten = \"127.0.0.1:{port}\"\n"),
        Duration::from_secs(3600),
        None,
    )
    .await;
    let (code, body) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(code, 200);
    assert_eq!(body["state"], "bind_failed");
    assert_eq!(body["listen"], format!("127.0.0.1:{port}"));
    // The control socket still answers: the daemon is up.
    let (code, _) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(code, 200);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disabled_proxy_does_not_listen() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let d = common::start_with(
        "",
        &format!("[proxy]\nenabled = false\nlisten = \"127.0.0.1:{port}\"\n"),
        Duration::from_secs(3600),
        None,
    )
    .await;
    let (code, body) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(code, 200);
    assert_eq!(body["state"], "disabled");
    assert_eq!(body["enabled"], false);
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err(),
        "a disabled proxy binds nothing"
    );
    d.stop().await;
}

/// Spec §15 test 2 (model unavailable), the no-model path: a proxy whose
/// profile needs models that are not there refuses with a 503 that holds
/// no canary, and nothing reaches the upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_models_a_proxied_post_is_refused_and_nothing_is_forwarded() {
    let (d, up) = daemon_with_scripted_and(
        Script(vec![Step::EchoUserText]),
        "profile = \"support-email\"",
    )
    .await;
    let msg = format!("Bitte an {NAME}, {EMAIL}");
    for (path, body) in routes(&msg) {
        let (s, b, _) = post(&proxy_url(&d, path), body, &[]).await;
        assert_eq!(s, 503, "{path}: {b}");
        assert!(!b.to_string().contains("Zyxwuria") && !b.to_string().contains(EMAIL));
    }
    assert!(up.recorded().is_empty(), "nothing was forwarded");
    let (_, st) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(st["routes"][0]["requests"], 1);
    d.stop().await;
}

fn mint(d: &common::TestDaemon, dataset: &str, kind: EntityKind, value: &str) -> String {
    let ns = d.state.namespace(dataset).unwrap();
    let mut n = ns.lock().unwrap();
    let t = n.token_for(&kind, value).unwrap().as_str().to_string();
    n.rebuild_detector_now().unwrap();
    t
}

/// The three non-streaming routes with `msg` as the user's text.
fn routes(msg: &str) -> [(&'static str, Value); 3] {
    [
        (
            "/anthropic/v1/messages",
            json!({"model": "m", "max_tokens": 10, "messages": [{"role": "user", "content": msg}]}),
        ),
        (
            "/openai/v1/chat/completions",
            json!({"model": "m", "messages": [{"role": "user", "content": msg}]}),
        ),
        (
            "/openai/v1/responses",
            json!({"model": "m", "input": [{"type": "message", "role": "user", "content": msg}]}),
        ),
    ]
}

async fn post(
    url: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> (u16, Value, reqwest::header::HeaderMap) {
    let mut r = reqwest::Client::new().post(url).json(&body);
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    let r = r.send().await.unwrap();
    let (s, h) = (r.status().as_u16(), r.headers().clone());
    let text = r.text().await.unwrap();
    (
        s,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
        h,
    )
}

async fn client_value(d: &common::TestDaemon) -> String {
    let (_, st) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(st["state"], "running", "{st}");
    st["client_header"]["value"].as_str().unwrap().to_string()
}

/// Spec §15 tests 1 and 13 (non-streaming), decision 23: the canary
/// reaches the upstream as tokens only on every route; the answer restores
/// the session token always and the dataset token only for a request with
/// the client header.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canary_through_each_route_reaches_the_upstream_as_tokens_only() {
    let (d, up) = daemon_with_scripted(Script(vec![Step::EchoUserText])).await;
    d.dataset("kunden").await;
    let person = mint(&d, "kunden", EntityKind::Person, NAME);
    let value = client_value(&d).await;
    let msg = format!("Bitte an {NAME}, {EMAIL}");
    for (path, body) in routes(&msg) {
        let (s, answer, h) = post(
            &proxy_url(&d, path),
            body.clone(),
            &[("x-inumaki-client", &value)],
        )
        .await;
        assert_eq!(s, 200, "{path}: {answer}");
        let a = answer.to_string();
        assert!(a.contains(EMAIL), "{path}: the session token is restored");
        assert!(a.contains(NAME), "{path}: the dataset token is restored");
        assert!(h.get("x-inumaki-verdict").is_some());
        // Restricted mode: no header (or a wrong one), the dataset token stays.
        for hdr in [
            &[][..],
            &[("x-inumaki-client", "0".repeat(64).as_str())][..],
        ] {
            let (s, answer, _) = post(&proxy_url(&d, path), body.clone(), hdr).await;
            assert_eq!(s, 200, "{path}: {answer}");
            let a = answer.to_string();
            assert!(a.contains(EMAIL), "{path}: the session token is restored");
            assert!(!a.contains("Zyxwuria"), "{path}: restricted mode: {a}");
            assert!(a.contains(&person), "{path}: the dataset's own token");
        }
    }
    let recorded = up.recorded();
    assert_eq!(recorded.len(), 9);
    for (_, body) in recorded {
        let b = String::from_utf8_lossy(&body);
        assert!(
            !b.contains(EMAIL) && !b.contains("Zyxwuria") && !b.contains(&value),
            "no original upstream: {b}"
        );
        assert!(b.contains("<EMAIL_"), "{b}");
        assert!(
            b.contains(&person),
            "a known value keeps its dataset's token: {b}"
        );
    }
    d.stop().await;
}

/// Review C2: a known dataset value or a validated identifier inside a
/// tool definition is refused; nothing is forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_known_value_in_a_tool_definition_is_refused() {
    let (d, up) = daemon_with_scripted(Script(vec![Step::EchoUserText])).await;
    d.dataset("kunden").await;
    mint(&d, "kunden", EntityKind::Person, NAME);
    for desc in [
        format!("Looks up {NAME}'s orders"),
        format!("Mails {EMAIL}"),
    ] {
        let body = json!({"model": "m", "max_tokens": 10,
            "tools": [{"name": "crm", "description": desc, "input_schema": {"type": "object"}}],
            "messages": [{"role": "user", "content": "hi"}]});
        let (s, b, _) = post(&proxy_url(&d, "/anthropic/v1/messages"), body, &[]).await;
        assert_eq!(s, 400, "{b}");
        assert_eq!(b["error"]["type"], "unsupported_content");
        assert!(!b.to_string().contains("Zyxwuria") && !b.to_string().contains(EMAIL));
    }
    assert!(up.recorded().is_empty(), "the upstream saw nothing");
    d.stop().await;
}

/// Spec §15 test 17 (reserved names) and §9: the chat dataset is listed
/// with kind `chat`, but nothing in the API can delete, rotate, forget in,
/// sanitize against, rehydrate against, or give upstreams to it, and its
/// client value survives every dataset-wide maintenance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_chat_dataset_is_reserved() {
    let (d, _) = daemon_with_scripted(Script::default()).await;
    let before = client_value(&d).await;
    let (_, ds) = d.call(Method::GET, "/v1/datasets", None).await;
    assert!(
        ds.as_array()
            .unwrap()
            .iter()
            .any(|x| x["id"] == "inumaki-chat" && x["kind"] == "chat"),
        "{ds}"
    );
    let (code, b) = d
        .call(Method::DELETE, "/v1/datasets/inumaki-chat", None)
        .await;
    assert_eq!(code, 409, "{b}");
    for (method, path, body) in [
        (
            Method::POST,
            "/v1/sanitize",
            Some(json!({"dataset": "inumaki-chat", "text": "x"})),
        ),
        (
            Method::POST,
            "/v1/rehydrate",
            Some(json!({"dataset": "inumaki-chat", "text": "x"})),
        ),
        (Method::POST, "/v1/datasets/inumaki-chat/rotate", None),
        (
            Method::POST,
            "/v1/datasets/inumaki-chat/entities/forget",
            Some(json!({"value": NAME})),
        ),
        (
            Method::DELETE,
            "/v1/datasets/inumaki-chat/entities/%3CPERSON_abcdef%3E",
            None,
        ),
        (
            Method::POST,
            "/v1/datasets/inumaki-chat/upstreams",
            Some(json!({"name": "a", "kind": "stdio", "command": "x"})),
        ),
        (
            Method::POST,
            "/v1/datasets",
            Some(json!({"id": "inumaki-chat", "name": "x"})),
        ),
    ] {
        let (code, b) = d.call(method, path, body).await;
        assert_eq!(code, 400, "{path}: {b}");
        assert_eq!(b["error"]["type"], "reserved", "{path}: {b}");
    }
    // Not a user dataset in the status, and no gateway serves it.
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert!(st["datasets"].as_array().unwrap().is_empty(), "{st}");
    // Dataset-wide maintenance: another dataset's deletion, a sweep.
    d.dataset("kunden").await;
    let (code, _) = d.call(Method::DELETE, "/v1/datasets/kunden", None).await;
    assert_eq!(code, 204);
    let s = Arc::clone(&d.state);
    tokio::task::spawn_blocking(move || s.sweep_once())
        .await
        .unwrap();
    assert!(
        d.state
            .vault
            .get_secret(inumakid::chat::CLIENT_KEY_SECRET)
            .unwrap()
            .is_some()
    );
    assert!(d.state.vault.dataset("inumaki-chat").is_ok());
    assert_eq!(client_value(&d).await, before);
    d.stop().await;
    // A restart keeps the dataset and the value; the gateway it now loads
    // with the other datasets is not listed and serves nothing.
    let dir = tempfile::tempdir().unwrap();
    let d = common::start_in(dir.path(), "").await;
    let first = client_value(&d).await;
    d.stop().await;
    let d = common::start_in(dir.path(), "").await;
    assert_eq!(client_value(&d).await, first);
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert!(st["datasets"].as_array().unwrap().is_empty(), "{st}");
    assert!(
        st["gateway"]["datasets"].as_array().unwrap().is_empty(),
        "{st}"
    );
    let (code, b) = d
        .call(Method::POST, "/mcp/inumaki-chat", Some(json!({})))
        .await;
    assert_eq!(code, 404, "{b}");
    d.stop().await;
}

/// Spec §9: a pre-existing `inumaki-` dataset of another kind keeps the
/// proxy disabled (and the daemon running).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pre_existing_inumaki_dataset_keeps_the_proxy_disabled() {
    let dir = tempfile::tempdir().unwrap();
    {
        let v = common::open_vault(dir.path());
        v.create_dataset(&inumaki_vault::DatasetSpec::new(
            "inumaki-old",
            "old",
            "offline",
        ))
        .unwrap();
    }
    let d = common::start_in(dir.path(), "[proxy]\nlisten = \"127.0.0.1:0\"\n").await;
    let (_, body) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(body["state"], "disabled");
    assert!(d.state.vault.dataset("inumaki-chat").is_err());
    let (code, _) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(code, 200);
    d.stop().await;
}

/// Ruling 3 and review finding 3: a chat dataset whose stored profile no
/// longer exists (the `[proxy] profile` changed, or the profile was
/// removed from the configuration) breaks neither the hook's per-dataset
/// scan (a failure there would fail every harness tool call closed) nor
/// the definition scan, whose validated-regex tier runs under the current
/// proxy profile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_chat_profile_breaks_neither_the_hook_nor_the_definition_scan() {
    let dir = tempfile::tempdir().unwrap();
    {
        let v = common::open_vault(dir.path());
        let mut chat = inumaki_vault::DatasetSpec::new("inumaki-chat", "chat", "gone-profile");
        chat.kind = inumaki_vault::DatasetKind::Chat;
        v.create_dataset(&chat).unwrap();
    }
    inumaki_proxy::forward::ensure_crypto_provider();
    let (addr, up) = inumaki_proxy::scripted::spawn_http(Script(vec![Step::EchoUserText])).await;
    let d = common::start_in(dir.path(), &scripted_proxy(addr, "")).await;
    assert_eq!(
        d.state.vault.dataset_profile("inumaki-chat").unwrap(),
        "gone-profile"
    );
    d.dataset("a").await;
    mint(&d, "a", EntityKind::Person, NAME);
    let hook = |text: &str| {
        serde_json::to_value(inumaki_client::HookRequest {
            harness: inumaki_client::HookHarness::ClaudeCode,
            tool: inumaki_client::HookTool::Read,
            cwd: "/tmp".into(),
            paths: Vec::new(),
            texts: vec!["stdout".into(), text.into()],
        })
        .unwrap()
    };
    let (code, r) = d
        .call(Method::POST, "/v1/hook", Some(hook("nothing known here")))
        .await;
    assert_eq!((code, &r), (200, &json!({ "action": "pass" })));
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/hook",
            Some(hook(&format!("Kunde: {NAME}"))),
        )
        .await;
    assert_eq!(code, 200, "{r}");
    assert_eq!(r["action"], "replace", "{r}");
    assert!(!r.to_string().contains("Zyxwuria"), "{r}");
    // Definitions: an email (validated-regex tier) is refused, a clean
    // tool list is forwarded.
    for (desc, want) in [
        (format!("Mails {EMAIL}"), 400),
        ("Looks up orders".to_string(), 200),
    ] {
        let body = json!({"model": "m", "max_tokens": 10,
            "tools": [{"name": "crm", "description": desc, "input_schema": {"type": "object"}}],
            "messages": [{"role": "user", "content": "hi"}]});
        let (s, b, _) = post(&proxy_url(&d, "/anthropic/v1/messages"), body, &[]).await;
        assert_eq!(s, want, "{b}");
    }
    assert_eq!(up.recorded().len(), 1, "only the clean request left");
    d.stop().await;
}

/// The host directly: a `DaemonHost` over a running daemon's state.
fn host(d: &common::TestDaemon) -> inumakid::proxy_host::DaemonHost {
    inumakid::proxy_host::DaemonHost::new(Arc::downgrade(&d.state)).expect("the host builds")
}

fn finds(det: &Arc<dyn inumaki_core::detect::Detector>, text: &str) -> bool {
    !det.detect(text, &inumaki_core::detect::DetectCtx::for_text(text))
        .unwrap()
        .is_empty()
}

/// Review finding 1: the chat dictionary follows a dataset deleted and
/// recreated under the same id (same generation, same entry count, new
/// handle), and a mint without a rebuild; each gives a new dictionary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_chat_dictionary_follows_recreated_datasets_and_new_mints() {
    use inumaki_proxy::host::ProxyHost;
    let (d, _) = daemon_with_scripted(Script::default()).await;
    let h = host(&d);
    d.dataset("kunden").await;
    mint(&d, "kunden", EntityKind::Person, NAME);
    let a = h.dictionary().unwrap();
    assert!(finds(&a, NAME));
    let (code, _) = d.call(Method::DELETE, "/v1/datasets/kunden", None).await;
    assert_eq!(code, 204);
    d.dataset("kunden").await;
    mint(&d, "kunden", EntityKind::Person, "Qwelmarx Pellqwyn");
    let b = h.dictionary().unwrap();
    assert!(!Arc::ptr_eq(&a, &b));
    assert!(finds(&b, "Qwelmarx Pellqwyn"), "the new value is known");
    assert!(!finds(&b, NAME), "the deleted value is not");
    // A mint into the delta, no rebuild.
    {
        let ns = d.state.namespace("kunden").unwrap();
        ns.lock()
            .unwrap()
            .token_for(&EntityKind::Person, "Yrsabel Quandt")
            .unwrap();
    }
    let c = h.dictionary().unwrap();
    assert!(!Arc::ptr_eq(&b, &c));
    assert!(finds(&c, "Yrsabel Quandt"));
    assert!(
        Arc::ptr_eq(&c, &h.dictionary().unwrap()),
        "unchanged: same Arc"
    );
    d.stop().await;
}

/// Integrator ruling: a check route's scope must be a check dataset; any
/// other name resolves nothing, even a token of that very dataset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_check_scope_must_name_a_check_dataset() {
    use inumaki_proxy::host::{ProxyHost, Scope};
    let (d, _) = daemon_with_scripted(Script::default()).await;
    d.dataset("kunden").await;
    let t = mint(&d, "kunden", EntityKind::Person, NAME);
    let h = host(&d);
    assert!(
        h.resolve(std::slice::from_ref(&t), &Scope::Check("kunden".into()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(h.resolve(&[t], &Scope::Datasets).unwrap().len(), 1);
    d.stop().await;
}

/// Spec §9 and decision 19: a forwarded request writes one record under
/// `inumaki-chat` and a journal entry of the blocks it added; neither the
/// records, the journal as listed or shown, nor the vault files hold the
/// canary or a dataset slug. Revealing restores dataset tokens only:
/// session tokens stay and are counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activity_and_journal_hold_no_canary_and_reveal_restores_dataset_tokens_only() {
    let (d, _up) = daemon_with_scripted(Script(vec![Step::EchoUserText])).await;
    d.dataset("kunden").await;
    let person = mint(&d, "kunden", EntityKind::Person, NAME);
    let value = client_value(&d).await;
    let msg = format!("Bitte an {NAME}, {EMAIL}");
    let (path, body) = routes(&msg)[0].clone();
    let (s, b, _) = post(&proxy_url(&d, path), body, &[("x-inumaki-client", &value)]).await;
    assert_eq!(s, 200, "{b}");
    // A tool definition refused: a record, no journal entry.
    let refused = json!({"model": "m", "max_tokens": 10,
        "tools": [{"name": "crm", "description": format!("for {NAME}"), "input_schema": {"type": "object"}}],
        "messages": [{"role": "user", "content": "hi"}]});
    let (s, _, _) = post(&proxy_url(&d, path), refused, &[]).await;
    assert_eq!(s, 400);
    d.state
        .gateway
        .get()
        .unwrap()
        .activity()
        .flush(Duration::from_secs(10))
        .await;
    let (code, act) = d.call(Method::GET, "/v1/activity", None).await;
    assert_eq!(code, 200, "{act}");
    let records = act["records"].as_array().unwrap();
    let released: Vec<&Value> = records
        .iter()
        .filter(|r| r["front_door"] == "proxy" && r["verdict"] == "released")
        .collect();
    assert_eq!(released.len(), 1, "{act}");
    let r = released[0];
    assert_eq!(r["dataset"], "inumaki-chat");
    assert_eq!(r["direction"], "request");
    assert!(
        r["released"].is_string() && r["upstream"].is_string(),
        "{r}"
    );
    assert!(
        records
            .iter()
            .any(|r| r["front_door"] == "proxy" && r["verdict"] == "unsupported"),
        "{act}"
    );
    let a = act.to_string();
    for needle in ["Zyxwuria", EMAIL, "kunden", "<PERSON_", "<EMAIL_", &value] {
        assert!(!a.contains(needle), "{needle} in the activity: {a}");
    }
    let (code, j) = d
        .call(Method::GET, "/v1/datasets/inumaki-chat/journal", None)
        .await;
    assert_eq!(code, 200, "{j}");
    let entries = j["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "only the forwarded request: {j}");
    let id = entries[0]["id"].as_str().unwrap();
    let (code, shown) = d
        .call(
            Method::GET,
            &format!("/v1/datasets/inumaki-chat/journal/{id}"),
            None,
        )
        .await;
    assert_eq!(code, 200, "{shown}");
    let p = shown["payload"].as_str().unwrap();
    assert!(p.contains(&person) && p.contains("<EMAIL_"), "{p}");
    assert!(!p.contains("Zyxwuria") && !p.contains(EMAIL), "{p}");
    let (code, revealed) = d
        .call(
            Method::GET,
            &format!("/v1/datasets/inumaki-chat/journal/{id}?show_values=true"),
            None,
        )
        .await;
    assert_eq!(code, 200, "{revealed}");
    let p = revealed["payload"].as_str().unwrap();
    assert!(p.contains(NAME), "the dataset token is revealed: {p}");
    assert!(
        !p.contains(EMAIL) && p.contains("<EMAIL_"),
        "a session token stays: {p}"
    );
    assert_eq!(revealed["unresolved"], 1, "{revealed}");
    // The vault's files hold no canary in clear.
    d.state.vault.checkpoint().unwrap();
    let data = d.dir.path().join("data");
    for f in std::fs::read_dir(&data).unwrap() {
        let f = f.unwrap().path();
        if f.is_file() {
            let bytes = std::fs::read(&f).unwrap();
            for needle in [NAME.as_bytes(), EMAIL.as_bytes(), value.as_bytes()] {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle),
                    "a canary in {}",
                    f.display()
                );
            }
        }
    }
    d.stop().await;
}

/// Spec §9 reveal and decision 12: a chat journal entry never reveals a
/// check dataset's token or a session token; it reveals a live user
/// dataset's token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_chat_reveal_restores_live_user_dataset_tokens_only() {
    let (d, _) = daemon_with_scripted(Script::default()).await;
    d.dataset("kunden").await;
    let user = mint(&d, "kunden", EntityKind::Person, NAME);
    d.state
        .vault
        .create_dataset(&inumaki_vault::DatasetSpec::new(
            "check-0123456789ab",
            "check",
            "offline",
        ))
        .unwrap();
    let check = mint(
        &d,
        "check-0123456789ab",
        EntityKind::Email,
        "q.check@example.invalid",
    );
    let payload = format!("[\"{user} {check} <EMAIL_abcd> <PERSON_REMOVED>\"]");
    let (text, unresolved) = inumakid::chat::reveal(&d.state, &payload);
    assert!(text.contains(NAME), "{text}");
    assert!(!text.contains("q.check@"), "{text}");
    assert!(
        text.contains(&check) && text.contains("<EMAIL_abcd>"),
        "{text}"
    );
    assert_eq!(unresolved, 3, "check token, session token, removed marker");
    d.stop().await;
}

/// `[proxy] definitions_account_values` (spec §9 amendment (d)): with
/// `"refuse"`, a tool definition naming the OS login (an identity account
/// value) is refused like any definition hit and nothing is forwarded;
/// with the default `"allow"` it is forwarded. The identity is injected:
/// the OS one cannot be chosen by a test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_values_in_definitions_follow_the_setting() {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let login = "qwelmarx";
    for (setting, want) in [("refuse", 400u16), ("allow", 200)] {
        let d = common::start_with(
            "",
            &format!(
                "[proxy]\nlisten = \"127.0.0.1:0\"\ndefinitions_account_values = \"{setting}\"\n"
            ),
            Duration::from_secs(3600),
            None,
        )
        .await;
        let id = inumakid::identity::Identity {
            names: Vec::new(),
            accounts: vec![(EntityKind::Person, zeroize::Zeroizing::new(login.into()))],
        };
        let host = inumakid::proxy_host::DaemonHost::with_identity(Arc::downgrade(&d.state), id)
            .expect("the host builds");
        let up = Arc::new(ScriptedUpstream::new(Script(vec![Step::EchoUserText])));
        let proxy = inumaki_proxy::Proxy::try_with_upstream(
            d.state.cfg.proxy.clone(),
            Arc::new(host),
            zeroize::Zeroizing::new("0".repeat(64)),
            Arc::clone(&up) as Arc<dyn inumaki_proxy::upstream::Upstream>,
        )
        .unwrap();
        let body = json!({"model": "m", "max_tokens": 10,
            "tools": [{"name": "notes", "description": format!("Reads /Users/{login}/notes"),
                       "input_schema": {"type": "object"}}],
            "messages": [{"role": "user", "content": "hi"}]});
        let req = axum::http::Request::post("/anthropic/v1/messages")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let r = proxy.router().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let text =
            String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert_eq!(status, want, "{setting}: {text}");
        assert!(!text.contains(login) || want == 200, "{text}");
        if want == 400 {
            let b: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(b["error"]["type"], "unsupported_content");
            assert!(up.recorded().is_empty(), "nothing was forwarded");
        } else {
            assert_eq!(up.recorded().len(), 1);
        }
        d.stop().await;
    }
}

/// Ruling L58 over real HTTP: Codex's `x-codex-turn-metadata` header (the
/// repository path with the login name, git remote, commit hash) and the
/// body's `client_metadata["x-codex-turn-metadata"]` never reach the
/// upstream on either Responses route; Codex's other headers and the other
/// `client_metadata` members do, and the answer comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn codex_turn_metadata_never_reaches_the_upstream() {
    let (d, up) = daemon_with_scripted(Script(vec![Step::EchoUserText])).await;
    let meta = json!({"turn_id": "t1", "workspaces": {"/Users/zyxcanary/Clients/ZyxAcme/repo": {
        "associated_remote_urls": {"origin": "https://github.com/zyxorg/zyxrepo.git"},
        "latest_git_commit_hash": "0123abcd", "has_changes": true}}})
    .to_string();
    let headers = [
        ("x-codex-turn-metadata", meta.as_str()),
        ("session-id", "019a-s"),
        ("thread-id", "019a-t"),
        ("x-codex-window-id", "019a-t:0"),
        ("x-codex-turn-state", "opaque-state"),
        ("x-codex-beta-features", "a,b"),
        ("originator", "codex_exec"),
    ];
    for path in ["/openai/v1/responses", "/codex/responses"] {
        let body = json!({"model": "m", "store": false,
            "client_metadata": {"x-codex-turn-metadata": meta, "x-keep": "keep-me"},
            "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "status please"}]}]});
        let (s, answer, _) = post(&proxy_url(&d, path), body, &headers).await;
        assert_eq!(s, 200, "{path}: {answer}");
        assert!(
            answer.to_string().contains("status please"),
            "{path}: {answer}"
        );
    }
    let lines = up.lines();
    assert_eq!(lines.len(), 2);
    for l in &lines {
        assert!(!l.header_names.iter().any(|n| n == "x-codex-turn-metadata"));
        for (k, _) in &headers[1..] {
            assert!(l.header_names.iter().any(|n| n == k), "{k} still passes");
        }
    }
    let recorded = up.recorded();
    assert_eq!(recorded.len(), 2);
    for (_, body) in recorded {
        let b = String::from_utf8_lossy(&body);
        assert!(
            !b.contains("zyx") && !b.contains("x-codex-turn-metadata"),
            "{b}"
        );
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["client_metadata"], json!({"x-keep": "keep-me"}));
    }
    d.stop().await;
}

/// Spec §20 amendment of 2026-10-12 (4e) over real HTTP:
/// `[proxy.upstreams.openai] extra_headers = ["x-gw-key"]` forwards that
/// name on `/openai` only; the same header on `/anthropic` and `/codex` is
/// dropped, and so is an unlisted name on all three.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn extra_headers_apply_to_their_upstream_only() {
    inumaki_proxy::forward::ensure_crypto_provider();
    let (addr, up) = inumaki_proxy::scripted::spawn_http(Script(vec![Step::EchoUserText])).await;
    let extra = format!(
        "[proxy]\nlisten = \"127.0.0.1:0\"\n[proxy.upstreams.anthropic]\nbase_url = \"http://{addr}\"\n[proxy.upstreams.openai]\nbase_url = \"http://{addr}\"\nextra_headers = [\"x-gw-key\"]\n[proxy.upstreams.openai-codex]\nbase_url = \"http://{addr}\"\n"
    );
    let d = common::start_with("", &extra, Duration::from_secs(3600), None).await;
    let headers = [("x-gw-key", "gateway key/with a path"), ("x-other", "1")];
    for path in [
        "/openai/v1/chat/completions",
        "/anthropic/v1/messages",
        "/codex/responses",
    ] {
        let body = if path.starts_with("/codex") {
            json!({"model": "m", "store": false,
                "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "status please"}]}]})
        } else {
            json!({"model": "m", "messages": [{"role": "user", "content": "status please"}]})
        };
        let (s, answer, _) = post(&proxy_url(&d, path), body, &headers).await;
        assert_eq!(s, 200, "{path}: {answer}");
    }
    let lines = up.lines();
    assert_eq!(lines.len(), 3);
    let has =
        |l: &inumaki_proxy::scripted::RequestLine, n: &str| l.header_names.iter().any(|h| h == n);
    assert!(lines[0].path.starts_with("/v1/chat"), "{:?}", lines[0]);
    assert!(has(&lines[0], "x-gw-key"), "listed on openai");
    assert!(lines[1].path.starts_with("/v1/messages"), "{:?}", lines[1]);
    assert!(!has(&lines[1], "x-gw-key"), "not listed on anthropic");
    assert!(lines[2].path.starts_with("/responses"), "{:?}", lines[2]);
    assert!(!has(&lines[2], "x-gw-key"), "not listed on openai-codex");
    assert!(lines.iter().all(|l| !has(l, "x-other")));
    d.stop().await;
}
