//! M8 spec §15 tests 7, 8, 16 and Review Focus 2 through the daemon: a
//! running `inumakid` with the proxy listener, the vault, the chat dataset,
//! and a scripted upstream. The daemons run the `offline` profile (no
//! models); a name is known to the pipeline only because a dataset holds it.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::Method;
use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_proxy::{Script, ScriptedUpstream, Step};
use serde_json::{Value, json};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const NAME: &str = "Zyxwuria Quolnath";
const EMAIL: &str = "zyx.quolnath@example.invalid";

async fn daemon_with_scripted(script: Script) -> (common::TestDaemon, Arc<ScriptedUpstream>) {
    // The test's own reqwest client has no TLS provider of its own.
    inumaki_proxy::forward::ensure_crypto_provider();
    let (addr, up) = inumaki_proxy::scripted::spawn_http(script).await;
    (
        common::start_with("", &proxy_table(addr), Duration::from_secs(3600), None).await,
        up,
    )
}

/// The `[proxy]` table pointing every upstream at `addr`.
fn proxy_table(addr: std::net::SocketAddr) -> String {
    format!(
        "[proxy]\nlisten = \"127.0.0.1:0\"\n[proxy.upstreams.anthropic]\nbase_url = \"http://{addr}\"\n[proxy.upstreams.openai]\nbase_url = \"http://{addr}\"\n[proxy.upstreams.openai-codex]\nbase_url = \"http://{addr}\"\n"
    )
}

fn proxy_url(d: &common::TestDaemon, path: &str) -> String {
    let st = d.state.proxy.get().unwrap().status();
    format!("http://{}{path}", st.listen)
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

/// A dataset token for `value`, minted into `dataset`'s namespace.
fn mint(d: &common::TestDaemon, dataset: &str, kind: EntityKind, value: &str) -> String {
    let ns = d.state.namespace(dataset).unwrap();
    let mut n = ns.lock().unwrap();
    let t = n.token_for(&kind, value).unwrap().as_str().to_string();
    n.rebuild_detector_now().unwrap();
    t
}

async fn client_value(d: &common::TestDaemon) -> String {
    let (_, st) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(st["state"], "running", "{st}");
    st["client_header"]["value"].as_str().unwrap().to_string()
}

async fn cache_misses(d: &common::TestDaemon) -> u64 {
    d.call(Method::GET, "/v1/proxy", None).await.1["incremental_cache"]["misses"]
        .as_u64()
        .unwrap()
}

/// Review Focus 2, spec §15 test 7: after `forget`, a cached block that
/// carries the dataset token is a miss and the token no longer restores;
/// the model's answer shows the token, never the stale original.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forgotten_dataset_token_is_a_miss_and_stays_a_token() {
    let (d, up) = daemon_with_scripted(Script(vec![Step::EchoUserText])).await;
    d.dataset("kunden").await;
    let token = mint(&d, "kunden", EntityKind::Person, NAME);
    assert!(token.starts_with("<PERSON_"), "a dataset token: {token}");
    let value = client_value(&d).await;
    let h = [
        ("x-inumaki-client", value.as_str()),
        ("x-claude-code-session-id", "forget-session"),
    ];
    let url = proxy_url(&d, "/anthropic/v1/messages");
    let body = json!({"model": "m", "max_tokens": 5,
        "messages": [{"role": "user", "content": format!("Kunde {token} ruft an")}]});

    let (s, a, _) = post(&url, body.clone(), &h).await;
    assert_eq!(s, 200, "{a}");
    assert!(a.to_string().contains(NAME), "trusted: restored: {a}");
    // Control: an identical resend is a cache hit (this is what forget must break).
    let misses = cache_misses(&d).await;
    let (s, a, _) = post(&url, body.clone(), &h).await;
    assert_eq!(s, 200, "{a}");
    assert!(a.to_string().contains(NAME));
    assert_eq!(cache_misses(&d).await, misses, "the resend hit the cache");

    let (code, b) = d
        .call(
            Method::POST,
            "/v1/datasets/kunden/entities/forget",
            Some(json!({"value": NAME})),
        )
        .await;
    assert_eq!(
        code, 200,
        "forget must succeed for the test to mean anything: {b}"
    );

    let (s, b, _) = post(&url, body, &h).await;
    assert_eq!(s, 200, "{b}");
    assert!(
        cache_misses(&d).await > misses,
        "the block with the forgotten token is a miss, not a hit"
    );
    let shown = b.to_string();
    assert!(
        !shown.contains(NAME),
        "after forget no original is shown: {shown}"
    );
    assert!(shown.contains(&token), "the token stays a token: {shown}");
    for (_, sent) in up.recorded() {
        assert!(
            !String::from_utf8_lossy(&sent).contains("Zyxwuria"),
            "no original reached the upstream"
        );
    }
    d.stop().await;
}

/// What the recording upstream saw: header names and values, and the body.
type Seen = Arc<Mutex<Vec<(Vec<(String, String)>, String)>>>;

/// A model upstream of the test's own (the scripted one records bodies
/// only): it records headers too, and answers Anthropic Messages with the
/// tokens it received in a text block and in a tool call's arguments. A
/// request holding `please-fail` gets a 400 whose error text names the
/// tokens.
async fn recording_upstream() -> (std::net::SocketAddr, Seen) {
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    let app = axum::Router::new().fallback(
        move |h: hyper::HeaderMap, body: axum::body::Bytes| {
            let log = Arc::clone(&log);
            async move {
                let text = String::from_utf8_lossy(&body).to_string();
                let headers = h
                    .iter()
                    .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).to_string()))
                    .collect();
                log.lock().unwrap().push((headers, text.clone()));
                let toks = regex_tokens(&text).join(" ");
                let (status, answer) = if text.contains("please-fail") {
                    (
                        400,
                        json!({"type": "error", "error": {"type": "invalid_request_error", "message": format!("bad: {toks}")}}),
                    )
                } else {
                    (
                        200,
                        json!({"id": "m", "type": "message", "role": "assistant", "model": "m",
                            "content": [
                                {"type": "text", "text": toks},
                                {"type": "tool_use", "id": "t", "name": "write", "input": {"all": toks}}],
                            "stop_reason": "end_turn", "usage": {"input_tokens": 0, "output_tokens": 0}}),
                    )
                };
                (
                    hyper::StatusCode::from_u16(status).unwrap(),
                    [(hyper::header::CONTENT_TYPE, "application/json")],
                    answer.to_string(),
                )
            }
        },
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    (addr, seen)
}

/// `<LABEL_hex>` tokens in `text`, in order.
fn regex_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find('<') {
        let tail = &rest[i..];
        let Some(j) = tail.find('>') else { break };
        let inner = &tail[1..j];
        if let Some((label, hex)) = inner.rsplit_once('_')
            && !label.is_empty()
            && label.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
            && (4..=12).contains(&hex.len())
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            out.push(tail[..=j].to_string());
        }
        rest = &tail[1..];
    }
    out
}

/// Spec §15 test 8 (client header, I5) and test 7's provenance rules through
/// the daemon: with the header the model's text restores dataset tokens;
/// without it or with a wrong value, session tokens only; tool arguments
/// and an upstream error body restore session tokens only; the header (its
/// name and its value) never reaches the upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_header_decides_dataset_restoration_and_never_reaches_the_upstream() {
    inumaki_proxy::forward::ensure_crypto_provider();
    let (addr, seen) = recording_upstream().await;
    let d = common::start_with("", &proxy_table(addr), Duration::from_secs(3600), None).await;
    d.dataset("kunden").await;
    let person = mint(&d, "kunden", EntityKind::Person, NAME);
    let value = client_value(&d).await;
    let url = proxy_url(&d, "/anthropic/v1/messages");
    let user = |text: &str| json!({"model": "m", "max_tokens": 5, "messages": [{"role": "user", "content": text}]});
    let msg = format!("{NAME} {EMAIL}");
    let trusted = [("x-inumaki-client", value.as_str())];
    let wrong_value = "0".repeat(64);
    let wrong = [("x-inumaki-client", wrong_value.as_str())];

    // Trusted: model text restores both; tool arguments only the session token.
    let (s, a, _) = post(&url, user(&msg), &trusted).await;
    assert_eq!(s, 200, "{a}");
    let text = a["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains(NAME) && text.contains(EMAIL),
        "trusted text: {text}"
    );
    let args = a["content"][1]["input"]["all"].as_str().unwrap();
    assert!(
        args.contains(EMAIL),
        "arguments: the session token is restored: {args}"
    );
    assert!(
        !args.contains(NAME) && args.contains(&person),
        "arguments: the dataset token stays: {args}"
    );

    // Restricted: no header, a wrong header.
    for hdrs in [&[][..], &wrong[..]] {
        let (s, a, _) = post(&url, user(&msg), hdrs).await;
        assert_eq!(s, 200, "{a}");
        let text = a["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(EMAIL),
            "the session token is restored: {text}"
        );
        assert!(
            text.contains(&person) && !text.contains(NAME),
            "restricted: the dataset token stays: {text}"
        );
        assert!(!a.to_string().contains("Zyxwuria"), "{a}");
    }

    // An upstream error body restores session tokens only, even when trusted.
    let (s, e, _) = post(&url, user(&format!("please-fail {msg}")), &trusted).await;
    assert_eq!(s, 400, "{e}");
    let m = e["error"]["message"].as_str().unwrap();
    assert!(m.contains(EMAIL), "error body: session token restored: {m}");
    assert!(
        !m.contains(NAME) && m.contains(&person),
        "error body: dataset token stays: {m}"
    );

    // What the upstream saw: no client header in any form, no original.
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 4);
    for (headers, body) in seen.iter() {
        for (k, v) in headers {
            assert!(
                !k.eq_ignore_ascii_case("x-inumaki-client") && !v.contains(&value),
                "the client header reached the upstream: {k}"
            );
        }
        assert!(
            !body.contains(&value) && !body.contains("Zyxwuria") && !body.contains(EMAIL),
            "no original or header value in the upstream body: {body}"
        );
    }
    d.stop().await;
}

/// Spec §15 test 16: TRACE logs never carry a canary, a token, a dataset
/// slug, a credential, or the client header value; nor does `Debug` of the
/// daemon state. The subscriber is global because the daemon's tasks run on
/// other threads (and `spawn_blocking` ones); it sits behind the daemon's
/// own privacy filter, like the shipped subscriber.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_logs_carry_no_canary() {
    let cap = common::Capture::new();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(inumakid::run::log_filter(
                    tracing_subscriber::EnvFilter::new("trace"),
                )),
        )
        .init();
    let (d, up) = daemon_with_scripted(Script(vec![Step::EchoUserText])).await;
    d.dataset("kunden-slug-canary").await;
    let person = mint(&d, "kunden-slug-canary", EntityKind::Person, NAME);
    let value = client_value(&d).await;
    let msg = format!("{NAME} {EMAIL} {person}");
    let canary_headers = [
        ("x-inumaki-client", value.as_str()),
        ("user-agent", "claude-cli/9 Zyxwuria"),
        ("x-api-key", "sk-ant-api-Zyxwuria"),
        ("authorization", "Bearer Zyxwuria-oauth"),
        ("x-claude-code-session-id", "Zyxwuria-session"),
    ];
    let mut bodies = Vec::new();
    let mut statuses = Vec::new();
    for (path, body) in [
        (
            "/anthropic/v1/messages?beta=true",
            json!({"model": "m", "messages": [{"role": "user", "content": msg}]}),
        ),
        (
            "/openai/v1/chat/completions",
            json!({"model": "m", "messages": [{"role": "user", "content": msg}]}),
        ),
        (
            "/openai/v1/responses",
            json!({"model": "m", "input": [{"type": "message", "role": "user", "content": msg}]}),
        ),
        // Streamed answers on every streaming route, `/codex` included (the
        // client header is trusted: restored in full).
        (
            "/openai/v1/chat/completions",
            json!({"model": "m", "messages": [{"role": "user", "content": msg}], "stream": true}),
        ),
        (
            "/anthropic/v1/messages",
            json!({"model": "m", "max_tokens": 5, "stream": true, "messages": [{"role": "user", "content": msg}]}),
        ),
        (
            "/openai/v1/responses",
            json!({"model": "m", "stream": true, "input": [{"type": "message", "role": "user", "content": msg}]}),
        ),
        (
            "/codex/responses",
            json!({"model": "m", "stream": true, "store": false, "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": msg}]}]}),
        ),
        // A refusal (a tool definition hit), then binary content, which the
        // default `[proxy] binary = "placeholder"` replaces and forwards
        // (M8 spec §20 amendment 2026-10-11).
        (
            "/anthropic/v1/messages",
            json!({"model": "m", "max_tokens": 5,
                "tools": [{"name": "crm", "description": format!("for {NAME}"), "input_schema": {"type": "object"}}],
                "messages": [{"role": "user", "content": "hi"}]}),
        ),
        (
            "/anthropic/v1/messages",
            json!({"messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "Zyxwuria"}}]}]}),
        ),
    ] {
        let (s, b, _) = post(&proxy_url(&d, path), body, &canary_headers).await;
        statuses.push(s);
        bodies.push(b.to_string());
    }
    // The same through a request without any harness header.
    let (s, b, _) = post(
        &proxy_url(&d, "/anthropic/v1/messages"),
        json!({"model": "m", "messages": [{"role": "user", "content": msg}]}),
        &[],
    )
    .await;
    statuses.push(s);
    bodies.push(b.to_string());
    d.state
        .gateway
        .get()
        .unwrap()
        .activity()
        .flush(Duration::from_secs(10))
        .await;
    let debug = format!("{:?} {:?}", d.state, d.state.proxy.get().unwrap());
    d.stop().await;
    let logs = cap.text();
    assert!(
        logs.contains("proxy listening"),
        "the capture works: {logs}"
    );
    // The routes ran as scripted (the canary checks below would pass
    // vacuously if a route failed early) and the request path logged.
    assert_eq!(
        statuses,
        [200, 200, 200, 200, 200, 200, 200, 400, 200, 200],
        "{bodies:?}"
    );
    for line in ["proxy served", "proxy refused", "answer restored"] {
        assert!(logs.contains(line), "{line} not logged: {logs}");
    }
    for needle in [
        "Zyxwuria",
        "zyx.quolnath",
        "sk-ant-api",
        "kunden-slug-canary",
        person.as_str(),
        value.as_str(),
    ] {
        assert!(!logs.contains(needle), "{needle} in the logs");
        assert!(!debug.contains(needle), "{needle} in Debug");
    }
    // Every streamed row ran to its end under the capture (spec §15 test 16
    // for streams): the checks above are not vacuous.
    for (row, end) in [
        (3, "data: [DONE]"),
        (4, "message_stop"),
        (5, "response.completed"),
        (6, "response.completed"),
    ] {
        assert!(
            bodies[row].contains(end),
            "row {row} did not stream to its end"
        );
    }
    // The refusal body is fixed text, and the image row's answer echoes the
    // placeholder: no canary either.
    for b in &bodies[7..9] {
        assert!(!b.contains("Zyxwuria") && !b.contains(EMAIL), "{b}");
    }
    // End to end, the default is the placeholder: the image's payload (the
    // canary) never reached the upstream, and its replacement did.
    let sent = up.recorded();
    let placeholder = "[inumaki: an attachment (image, document, audio, or file) was removed here and not sent to the model.]";
    assert_eq!(
        sent.iter()
            .filter(|(_, b)| String::from_utf8_lossy(b).contains(placeholder))
            .count(),
        1
    );
    for (_, b) in &sent {
        assert!(!String::from_utf8_lossy(b).contains("Zyxwuria"));
    }
}

/// Spec §9: the journal holds only the blocks a request added.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_journal_holds_cache_missed_blocks_only() {
    let (d, _) = daemon_with_scripted(Script(vec![Step::EchoUserText])).await;
    let h = [("x-claude-code-session-id", "j")];
    let url = proxy_url(&d, "/anthropic/v1/messages");
    let t1 =
        json!({"model": "m", "messages": [{"role": "user", "content": format!("erste {EMAIL}")}]});
    let (s, _, _) = post(&url, t1.clone(), &h).await;
    assert_eq!(s, 200);
    let mut msgs = t1["messages"].as_array().unwrap().clone();
    msgs.push(json!({"role": "assistant", "content": "ok"}));
    msgs.push(json!({"role": "user", "content": "zweite"}));
    let (s, _, _) = post(&url, json!({"model": "m", "messages": msgs}), &h).await;
    assert_eq!(s, 200);
    d.state
        .gateway
        .get()
        .unwrap()
        .activity()
        .flush(Duration::from_secs(10))
        .await;
    let (_, j) = d
        .call(Method::GET, "/v1/datasets/inumaki-chat/journal", None)
        .await;
    let entries = j["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "one entry per forwarded request: {j}");
    let mut payloads = Vec::new();
    for e in entries {
        let id = e["id"].as_str().unwrap();
        let (code, rec) = d
            .call(
                Method::GET,
                &format!("/v1/datasets/inumaki-chat/journal/{id}"),
                None,
            )
            .await;
        assert_eq!(code, 200, "{rec}");
        payloads.push(rec["payload"].as_str().unwrap().to_string());
    }
    let second: Vec<&String> = payloads.iter().filter(|p| p.contains("zweite")).collect();
    assert_eq!(second.len(), 1, "{payloads:?}");
    assert!(
        !second[0].contains("erste"),
        "turn 2's entry holds only what it added: {}",
        second[0]
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.contains("erste") && !p.contains("zweite")),
        "turn 1's entry holds turn 1's block: {payloads:?}"
    );
    assert!(
        payloads.iter().all(|p| !p.contains(EMAIL)),
        "no original in the journal: {payloads:?}"
    );
    d.stop().await;
}
