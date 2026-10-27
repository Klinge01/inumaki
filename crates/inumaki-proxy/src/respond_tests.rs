//! Spec §15 tests 5, 7, 8, 12 (non-streaming) and Review Focus 5; the
//! tripwire in block and notify mode; fail-closed restoration.

use std::sync::Arc;

use serde_json::json;

use crate::config::TripwireMode;
use crate::handler_tests::Recording;
use crate::host::ProxyEvent;
use crate::testing::{DS_TOKEN, EMAIL, FakeHost, NAME};
use crate::upstream::{Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};

const CLIENT: &str = "client-value";

async fn call(
    p: &crate::Proxy,
    uri: &str,
    body: serde_json::Value,
    headers: &[(&str, &str)],
) -> (u16, serde_json::Value, String) {
    use tower::ServiceExt;
    let mut r = http::Request::post(uri).header("content-type", "application/json");
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    let resp = p
        .router()
        .oneshot(r.body(axum::body::Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let b = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
        String::from_utf8_lossy(&b).into_owned(),
    )
}

fn answer(status: u16, body: String) -> UpstreamResponse {
    UpstreamResponse {
        status: http::StatusCode::from_u16(status).unwrap(),
        headers: http::HeaderMap::new(),
        body: Box::pin(futures::stream::once(async move {
            Ok(bytes::Bytes::from(body))
        })),
    }
}

fn record(rec: &Recording, req: &UpstreamRequest) {
    rec.sent.lock().unwrap().push((
        req.upstream,
        req.path_and_query.clone(),
        req.body.to_vec(),
        req.headers.clone(),
    ));
}

/// An upstream that answers with text naming the tokens the request carried.
struct Echo(Recording);

impl Upstream for Echo {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        let body = String::from_utf8(req.body.to_vec()).unwrap();
        record(&self.0, &req);
        let toks: Vec<String> = regex::Regex::new(r"<[A-Z_]+_[0-9a-f]{4,12}>")
            .unwrap()
            .find_iter(&body)
            .map(|m| m.as_str().to_string())
            .collect();
        let text = toks.join(" ");
        let status = if body.contains("please-fail") {
            400
        } else {
            200
        };
        let a = if status == 200 {
            json!({"id": "msg_01XFDUDYJgAACzvnptvVoYEL", "type": "message", "role": "assistant", "content": [
                // Provider-written reasoning that holds a known original in clear (review I2).
                {"type": "thinking", "thinking": format!("thinking about {NAME} and {text}"), "signature": "sig"},
                {"type": "text", "text": text},
                {"type": "tool_use", "id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "name": "write", "input": {"path": format!("/home/{}/notes.txt", toks.last().cloned().unwrap_or_default()), "all": text}}
            ]})
        } else {
            json!({"type": "error", "error": {"type": "invalid_request_error", "message": format!("bad: {text}")}})
        };
        let s = a.to_string();
        Box::pin(async move { Ok(answer(status, s)) })
    }
}

/// An upstream that answers every request with one fixed body; optionally
/// breaks the host's vault once the request has left.
struct Canned {
    rec: Recording,
    body: String,
    break_vault: Option<Arc<FakeHost>>,
}

impl Upstream for Canned {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        record(&self.rec, &req);
        if let Some(h) = &self.break_vault {
            *h.fail_vault.lock().unwrap() = true;
        }
        let s = self.body.clone();
        Box::pin(async move { Ok(answer(200, s)) })
    }
}

fn build(host: Arc<FakeHost>, up: Arc<dyn Upstream>, tripwire: TripwireMode) -> crate::Proxy {
    let mut cfg = crate::pipeline::test_shared(host.clone()).cfg.clone();
    cfg.tripwire = tripwire;
    crate::Proxy::with_upstream(cfg, host, zeroize::Zeroizing::new(CLIENT.into()), up)
}

fn echo_proxy(host: Arc<FakeHost>) -> (crate::Proxy, Arc<Echo>) {
    let up = Arc::new(Echo(Recording::default()));
    (build(host, up.clone(), TripwireMode::Notify), up)
}

fn canned(
    host: Arc<FakeHost>,
    body: serde_json::Value,
    tripwire: TripwireMode,
) -> (crate::Proxy, Arc<Canned>) {
    canned_raw(host, body.to_string(), tripwire)
}

fn canned_raw(
    host: Arc<FakeHost>,
    body: String,
    tripwire: TripwireMode,
) -> (crate::Proxy, Arc<Canned>) {
    let up = Arc::new(Canned {
        rec: Recording::default(),
        body,
        break_vault: None,
    });
    (build(host, up.clone(), tripwire), up)
}

/// Spec §15 test 8, review I5; test 7's argument rule.
#[tokio::test]
async fn provenance_and_the_client_header_decide_restoration() {
    let (p, up) = echo_proxy(FakeHost::new());
    let body = json!({"messages": [{"role": "user", "content": format!("{NAME} {EMAIL}")}]});
    let (s, trusted, _) = call(
        &p,
        "/anthropic/v1/messages",
        body.clone(),
        &[("x-inumaki-client", CLIENT)],
    )
    .await;
    assert_eq!(s, 200);
    let text = trusted["content"][1]["text"].as_str().unwrap();
    assert!(
        text.contains(NAME) && text.contains(EMAIL),
        "trusted: both restored: {text}"
    );
    let all = trusted["content"][2]["input"]["all"].as_str().unwrap();
    assert!(
        all.contains(EMAIL) && all.contains(DS_TOKEN) && !all.contains(NAME),
        "arguments: session restored, dataset kept: {all}"
    );
    assert!(
        trusted["content"][0]["thinking"]
            .as_str()
            .unwrap()
            .contains("<EMAIL_"),
        "reasoning untouched"
    );
    for wrong in [Some("wrong"), None] {
        let h: Vec<(&str, &str)> = wrong.map(|w| ("x-inumaki-client", w)).into_iter().collect();
        let (_, restricted, _) = call(&p, "/anthropic/v1/messages", body.clone(), &h).await;
        let text = restricted["content"][1]["text"].as_str().unwrap();
        assert!(
            text.contains(EMAIL) && text.contains(DS_TOKEN) && !text.contains(NAME),
            "restricted ({wrong:?}): {text}"
        );
    }
    let (s, err, _) = call(
        &p,
        "/anthropic/v1/messages",
        json!({"messages": [{"role": "user", "content": format!("please-fail {NAME} {EMAIL}")}]}),
        &[("x-inumaki-client", CLIENT)],
    )
    .await;
    assert_eq!(s, 400);
    let m = err["error"]["message"].as_str().unwrap();
    assert!(
        m.contains(EMAIL) && m.contains(DS_TOKEN) && !m.contains(NAME),
        "error bodies: session tokens only: {m}"
    );
    // The client header never reaches the upstream.
    for (_, _, b, h) in up.0.sent.lock().unwrap().iter() {
        assert!(!h.contains_key("x-inumaki-client"));
        let b = String::from_utf8_lossy(b);
        assert!(!b.contains(CLIENT) && !b.contains(NAME) && !b.contains(EMAIL));
    }
}

/// Spec §15 test 12 and test 5 (I2).
#[tokio::test]
async fn the_next_turn_resends_history_byte_identical_and_seeded_reasoning_passes() {
    let (p, up) = echo_proxy(FakeHost::new());
    let h = [
        ("x-inumaki-client", CLIENT),
        ("x-claude-code-session-id", "s1"),
    ];
    let turn1 =
        json!({"model": "m", "messages": [{"role": "user", "content": format!("{NAME} {EMAIL}")}]});
    let (_, a1, _) = call(&p, "/anthropic/v1/messages", turn1.clone(), &h).await;
    assert!(
        a1["content"][0]["thinking"]
            .as_str()
            .unwrap()
            .contains(NAME),
        "the provider wrote the name in clear in its reasoning"
    );
    let misses_before = p.status().incremental_cache.misses;
    let mut msgs = turn1["messages"].as_array().unwrap().clone();
    msgs.push(json!({"role": "assistant", "content": a1["content"].clone()}));
    msgs.push(json!({"role": "user", "content": "und weiter"}));
    let turn2 = json!({"model": "m", "messages": msgs});
    let (s, _, _) = call(&p, "/anthropic/v1/messages", turn2.clone(), &h).await;
    assert_eq!(
        s, 200,
        "the seeded thinking block passes although it holds a known original"
    );
    assert_eq!(
        p.status().incremental_cache.misses - misses_before,
        1,
        "only the new user block ran the engine"
    );
    {
        let rec = up.0.sent.lock().unwrap();
        let (first, second) = (&rec[0].2, &rec[1].2);
        // Raw bytes: turn 1's body up to its message array's closing bracket is a prefix of turn 2's.
        let cut = first
            .windows(2)
            .rposition(|w| w == b"],")
            .expect("a message array followed by another key");
        assert!(
            second.starts_with(&first[..cut]),
            "the history prefix is byte-identical"
        );
        assert!(
            !String::from_utf8_lossy(second).contains(EMAIL),
            "no original in turn 2"
        );
    }
    // The same reasoning in a session that never received it is not provider-written there.
    let other = [
        ("x-inumaki-client", CLIENT),
        ("x-claude-code-session-id", "other"),
    ];
    let (s, _, raw) = call(&p, "/anthropic/v1/messages", turn2, &other).await;
    assert_eq!(s, 451);
    assert!(!raw.contains(NAME));
    assert_eq!(
        up.0.sent.lock().unwrap().len(),
        2,
        "the refused turn sent nothing"
    );
}

/// Review Focus 5.
#[tokio::test]
async fn identity_tokens_restore_in_tool_arguments() {
    let (p, up) = echo_proxy(FakeHost::with_identity(
        "Pellqwyn Yrsabel",
        "pellqwyn@example.invalid",
    ));
    let (_, a, _) = call(
        &p,
        "/anthropic/v1/messages",
        // The person comes last in the forwarded body, so Echo writes its token into the path.
        json!({"system": "User: pellqwyn@example.invalid (Pellqwyn Yrsabel)", "messages": [{"role": "user", "content": "hi"}]}),
        &[("x-inumaki-client", CLIENT)],
    )
    .await;
    let path = a["content"][2]["input"]["path"].as_str().unwrap();
    assert_eq!(
        path, "/home/Pellqwyn Yrsabel/notes.txt",
        "the session token in the path is restored"
    );
    let sent = String::from_utf8_lossy(&up.0.sent.lock().unwrap()[0].2).into_owned();
    assert!(
        !sent.contains("Pellqwyn") && !sent.contains("pellqwyn@"),
        "{sent}"
    );
}

/// A model that writes a known original in clear into a tool call (spec §6.4).
fn clear_value_in_args() -> serde_json::Value {
    json!({"id": "msg_01XFDUDYJgAACzvnptvVoYEL", "type": "message", "role": "assistant", "content": [
        {"type": "text", "text": "writing it"},
        {"type": "tool_use", "id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "name": "write", "input": {"to": format!("for {NAME}")}}
    ]})
}

#[tokio::test]
async fn block_mode_refuses_an_answer_whose_tool_call_holds_a_known_value() {
    let host = FakeHost::new();
    let (p, up) = canned(host.clone(), clear_value_in_args(), TripwireMode::Block);
    let (s, v, raw) = call(
        &p,
        "/anthropic/v1/messages",
        json!({"messages": [{"role": "user", "content": "hello there"}]}),
        &[("x-inumaki-client", CLIENT)],
    )
    .await;
    assert_eq!(s, 451);
    assert_eq!(v["error"]["type"], "privacy_block");
    let m = v["error"]["message"].as_str().unwrap();
    assert_eq!(
        m,
        "The request was sent sanitized; the model's answer contained a value inumaki protects and was withheld (kinds: PERSON; checks: ClearValue)."
    );
    assert!(
        !raw.contains(NAME) && !raw.contains("writing it"),
        "no part of the answer: {raw}"
    );
    // The sanitized request did leave: committed and released (spec §5 step 7).
    assert_eq!(up.rec.sent.lock().unwrap().len(), 1);
    let ev = host.events.lock().unwrap();
    assert!(ev.iter().any(|e| matches!(
        e,
        ProxyEvent::ClearValue {
            blocked: true,
            dataset: Some(_),
            ..
        }
    )));
    assert!(ev.iter().any(|e| matches!(e, ProxyEvent::Released { .. })));
    assert!(!ev.iter().any(|e| matches!(e, ProxyEvent::Refused { .. })));
    drop(ev);
    assert_eq!(
        serde_json::to_value(p.status()).unwrap()["routes"][0]["blocked"],
        1
    );
}

/// Notify mode relays the answer and records it; the clear value is not
/// seeded, so the next turn re-tokenizes it instead of forwarding it.
#[tokio::test]
async fn notify_mode_records_and_never_seeds_a_clear_value() {
    let host = FakeHost::new();
    let (p, up) = canned(host.clone(), clear_value_in_args(), TripwireMode::Notify);
    let h = [
        ("x-inumaki-client", CLIENT),
        ("x-claude-code-session-id", "n1"),
    ];
    let turn1 = json!({"model": "m", "messages": [{"role": "user", "content": "hello there"}]});
    let (s, a, _) = call(&p, "/anthropic/v1/messages", turn1.clone(), &h).await;
    assert_eq!(s, 200);
    assert_eq!(a["content"][1]["input"]["to"], format!("for {NAME}"));
    assert!(
        host.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ProxyEvent::ClearValue { blocked: false, .. }))
    );
    let mut msgs = turn1["messages"].as_array().unwrap().clone();
    msgs.push(json!({"role": "assistant", "content": a["content"].clone()}));
    msgs.push(json!({"role": "user", "content": "und weiter"}));
    let (s, _, _) = call(
        &p,
        "/anthropic/v1/messages",
        json!({"model": "m", "messages": msgs}),
        &h,
    )
    .await;
    assert_eq!(s, 200);
    let rec = up.rec.sent.lock().unwrap();
    let second = String::from_utf8_lossy(&rec[1].2);
    assert!(
        !second.contains(NAME),
        "the model's clear value went back upstream: {second}"
    );
    assert!(second.contains(DS_TOKEN), "{second}");
}

/// Fail closed: a host failure while restoring answers the fixed error and
/// never the upstream's body.
#[tokio::test]
async fn a_restoration_failure_answers_the_fixed_error_without_the_body() {
    let host = FakeHost::new();
    let up = Arc::new(Canned {
        rec: Recording::default(),
        body: json!({"type": "message", "role": "assistant", "content": [
            {"type": "text", "text": format!("about {DS_TOKEN} zyx-raw-body")}]})
        .to_string(),
        break_vault: Some(host.clone()),
    });
    let p = build(host, up.clone(), TripwireMode::Notify);
    let (s, v, raw) = call(
        &p,
        "/anthropic/v1/messages",
        json!({"messages": [{"role": "user", "content": "hello there"}]}),
        &[("x-inumaki-client", CLIENT)],
    )
    .await;
    assert_eq!(s, 503);
    assert_eq!(v["error"]["type"], "vault_unavailable");
    assert!(
        !raw.contains("zyx-raw-body") && !raw.contains(DS_TOKEN) && !raw.contains(NAME),
        "{raw}"
    );
    assert_eq!(up.rec.sent.lock().unwrap().len(), 1);
}

/// Unknown and removed tokens stay as they are; nothing a restorer or an
/// answer prints carries a restored value.
#[tokio::test]
async fn unknown_and_removed_tokens_stay_and_debug_carries_no_value() {
    let host = FakeHost::new();
    let (p, _) = canned(
        host.clone(),
        json!({"type": "message", "role": "assistant", "content": [
            {"type": "text", "text": format!("{DS_TOKEN} <PERSON_ffffff> <SECRET_REMOVED> <API_KEY_REMOVED>")}]}),
        TripwireMode::Notify,
    );
    let (s, v, _) = call(
        &p,
        "/anthropic/v1/messages",
        json!({"messages": [{"role": "user", "content": "hello there"}]}),
        &[("x-inumaki-client", CLIENT)],
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(
        v["content"][0]["text"],
        format!("{NAME} <PERSON_ffffff> <SECRET_REMOVED> <API_KEY_REMOVED>")
    );

    // Debug of the response-side types.
    let sh = crate::pipeline::test_shared(host.clone());
    let store = crate::session::SessionStore::new(
        std::time::Duration::from_secs(60),
        4,
        inumaki_core::config::TokenSettings::default(),
        1 << 20,
    );
    let session = store.get(crate::session::SessionKey([3; 32]));
    let body = json!({"content": [{"type": "text", "text": DS_TOKEN}]}).to_string();
    let a = crate::respond::non_streaming(
        &sh,
        &session,
        crate::routes::Wire::Messages,
        crate::routes::UpstreamId::Anthropic,
        crate::session::ClientMode::Trusted,
        http::StatusCode::OK,
        body.as_bytes(),
        crate::host::Scope::Datasets,
        crate::session::SeedStamp::unverified(),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&a.body).contains(NAME));
    let mut r = crate::restore::Restorer::new(
        &session,
        &*host,
        &sh.tokens,
        crate::host::Scope::Datasets,
        crate::session::ClientMode::Trusted,
    );
    assert_eq!(
        r.restore(DS_TOKEN, crate::restore::Column::Text).unwrap(),
        NAME
    );
    let dbg = format!("{a:?} {r:?}");
    assert!(!dbg.contains(NAME) && !dbg.contains("PERSON"), "{dbg}");
}

/// An answer over the size bound is not relayed, and the client is told
/// about the answer, not about its own request (spec §7 amendment).
#[tokio::test]
async fn an_oversized_answer_is_not_relayed() {
    let host = FakeHost::new();
    let big = "zyx-raw-body ".repeat(100_000); // over the 1 MiB test bound
    let (p, up) = canned(
        host.clone(),
        json!({"type": "message", "content": [{"type": "text", "text": big}]}),
        TripwireMode::Notify,
    );
    let (s, v, raw) = call(
        &p,
        "/anthropic/v1/messages",
        json!({"messages": [{"role": "user", "content": "hello there"}]}),
        &[],
    )
    .await;
    assert_eq!(s, 502);
    assert_eq!(v["error"]["type"], "resource_limit");
    let m = v["error"]["message"].as_str().unwrap();
    assert!(
        m.contains("answer") && !m.contains("request is larger"),
        "{m}"
    );
    assert!(!raw.contains("zyx-raw-body"));
    assert_eq!(up.rec.sent.lock().unwrap().len(), 1);
}

/// Block mode cannot be bypassed by the body's shape: a byte-order mark
/// before the JSON is dropped and the answer tripwired; an event stream goes
/// through the stream rewriter; any other non-JSON 2xx text is refused,
/// never relayed unchecked.
#[tokio::test]
async fn a_2xx_body_is_json_or_refused() {
    let user = json!({"messages": [{"role": "user", "content": "hello there"}]});
    let host = FakeHost::new();
    let bom = format!("\u{feff}{}", clear_value_in_args());
    let (p, _) = canned_raw(host.clone(), bom, TripwireMode::Block);
    let (s, v, raw) = call(&p, "/anthropic/v1/messages", user.clone(), &[]).await;
    assert_eq!(s, 451, "{raw}");
    assert_eq!(v["error"]["type"], "privacy_block");
    assert!(!raw.contains(NAME));
    // Notify mode: relayed, without the mark, and restored like any answer.
    let ok = format!(
        "\u{feff}{}",
        json!({"type": "message", "content": [{"type": "text", "text": DS_TOKEN}]})
    );
    let (p, _) = canned_raw(host.clone(), ok, TripwireMode::Notify);
    let (s, v, _) = call(
        &p,
        "/anthropic/v1/messages",
        user.clone(),
        &[("x-inumaki-client", CLIENT)],
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(v["content"][0]["text"], NAME);
    let sse = format!(
        "event: content_block_start\ndata: {}\n\n",
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "name": "w", "input": {"to": NAME}}})
    );
    // An event stream without a content type is sniffed and rewritten
    // (plan M8-2): a tool call whose start carries input, or a stream that
    // ends unfinished, ends with the abort event, nothing unchecked relayed.
    for body in [sse, ": keepalive\n\n".to_string()] {
        let (p, _) = canned_raw(host.clone(), body, TripwireMode::Notify);
        let (s, _, raw) = call(&p, "/anthropic/v1/messages", user.clone(), &[]).await;
        assert_eq!(s, 200, "{raw}");
        assert!(raw.contains("inumaki: stream_aborted"), "{raw}");
        assert!(!raw.contains(NAME), "{raw}");
    }
    // Any other non-JSON 2xx text is refused.
    let (p, _) = canned_raw(
        host.clone(),
        format!("plain text {NAME}"),
        TripwireMode::Notify,
    );
    let (s, v, raw) = call(&p, "/anthropic/v1/messages", user.clone(), &[]).await;
    assert_eq!(s, 502, "{raw}");
    assert_eq!(v["error"]["type"], "upstream_unreachable");
    assert!(!raw.contains(NAME), "{raw}");
    // An empty 2xx body has nothing a harness could act on.
    let (p, _) = canned_raw(host, String::new(), TripwireMode::Notify);
    let (s, _, raw) = call(&p, "/anthropic/v1/messages", user, &[]).await;
    assert_eq!((s, raw.as_str()), (200, ""));
}

/// An original holding a quote and a backslash, restored inside JSON-text
/// arguments (Responses, Chat) and a Messages input object, yields
/// arguments that parse with the exact original.
#[test]
fn escaped_originals_restore_into_valid_json_arguments() {
    use inumaki_core::token::TokenStore;
    const ORIGINAL: &str = r#"Anna "Ace" O\Neil"#;
    let host = FakeHost::new();
    let sh = crate::pipeline::test_shared(host.clone());
    let store = crate::session::SessionStore::new(
        std::time::Duration::from_secs(60),
        4,
        inumaki_core::config::TokenSettings::default(),
        1 << 20,
    );
    let session = store.get(crate::session::SessionKey([4; 32]));
    let tok = crate::session::SessionView::new(
        &session,
        &*host,
        inumaki_core::config::TokenSettings::default(),
    )
    .token_for(&inumaki_core::span::EntityKind::Person, ORIGINAL)
    .unwrap();
    let tok = tok.as_str();
    let args = json!({"to": format!("for {tok}"), tok: [tok]}).to_string();
    let cases = [
        (
            crate::routes::Wire::Responses,
            json!({"output": [{"type": "function_call", "name": "w", "arguments": args}]}),
        ),
        // A Codex MCP call (M8 spec §20 amendment 2026-10-10).
        (
            crate::routes::Wire::Responses,
            json!({"output": [{"type": "function_call", "name": "w", "namespace": "mcp__crm", "arguments": args}]}),
        ),
        (
            crate::routes::Wire::Chat,
            json!({"choices": [{"message": {"tool_calls": [{"type": "function", "function": {"name": "w", "arguments": args}}]}}]}),
        ),
        (
            crate::routes::Wire::Messages,
            json!({"content": [{"type": "tool_use", "id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "name": "w", "input": {"to": format!("for {tok}"), tok: [tok]}}]}),
        ),
    ];
    for (wire, body) in cases {
        let a = crate::respond::non_streaming(
            &sh,
            &session,
            wire,
            crate::routes::UpstreamId::Openai,
            crate::session::ClientMode::Trusted,
            http::StatusCode::OK,
            body.to_string().as_bytes(),
            crate::host::Scope::Datasets,
            crate::session::SeedStamp::unverified(),
        )
        .unwrap();
        let out: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
        let parsed: serde_json::Value = match wire {
            crate::routes::Wire::Responses => {
                serde_json::from_str(out["output"][0]["arguments"].as_str().unwrap()).unwrap()
            }
            crate::routes::Wire::Chat => serde_json::from_str(
                out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
            crate::routes::Wire::Messages => out["content"][0]["input"].clone(),
        };
        assert_eq!(parsed["to"], format!("for {ORIGINAL}"), "{wire:?}");
        assert_eq!(parsed[ORIGINAL][0], ORIGINAL, "{wire:?}: key and value");
        if let Some(ns) = body["output"][0]["namespace"].as_str() {
            assert_eq!(
                out["output"][0]["namespace"], ns,
                "the namespace is unchanged"
            );
        }
    }
}

/// Codex items that run locally or call a tool, each with a known value
/// in clear in its model-written strings (fix wave 2a, B).
fn codex_items_with_a_clear_value() -> Vec<(&'static str, serde_json::Value)> {
    let args = json!({"to": NAME}).to_string();
    vec![
        (
            "shell_call",
            json!({"type": "shell_call", "id": "sh_1", "call_id": "c1", "status": "completed", "action": {"commands": [format!("mail -s hi '{NAME}'")]}}),
        ),
        (
            "local_shell_call",
            json!({"type": "local_shell_call", "id": "ls_1", "call_id": "c2", "status": "completed", "action": {"type": "exec", "command": ["bash", "-lc", format!("echo {NAME}")], "env": {}}}),
        ),
        (
            "apply_patch_call",
            json!({"type": "apply_patch_call", "id": "ap_1", "call_id": "c3", "status": "completed", "operation": {"type": "update_file", "path": "notes.txt", "diff": format!("@@\n+{NAME}\n")}}),
        ),
        (
            "computer_call",
            json!({"type": "computer_call", "id": "cu_1", "call_id": "c4", "status": "completed", "action": {"type": "type", "text": NAME}, "pending_safety_checks": []}),
        ),
        (
            "mcp_call",
            json!({"type": "mcp_call", "id": "mcp_1", "server_label": "s", "name": "send", "arguments": args, "output": "sent"}),
        ),
        (
            "mcp_approval_request",
            json!({"type": "mcp_approval_request", "id": "mr_1", "server_label": "s", "name": "send", "arguments": args}),
        ),
    ]
}

/// Fix wave 2a (B), the whole-answer path: a Codex shell, patch, computer,
/// or MCP item holding a known value in clear withholds the answer in
/// block mode (451) and is recorded in notify mode.
#[tokio::test]
async fn codex_shell_and_patch_items_are_tripwired_without_streaming() {
    for (ty, item) in codex_items_with_a_clear_value() {
        let body =
            json!({"id": "resp_1", "object": "response", "status": "completed", "output": [item]});
        let host = FakeHost::new();
        let (p, _) = canned(host.clone(), body.clone(), TripwireMode::Block);
        let req = json!({"model": "m", "input": "hello there"});
        let (s, v, raw) = call(&p, "/openai/v1/responses", req.clone(), &[]).await;
        assert_eq!(s, 451, "{ty}: {raw}");
        assert_eq!(v["error"]["type"], "privacy_block", "{ty}");
        assert!(!raw.contains("Zyxwuria"), "{ty}: {raw}");
        assert!(
            host.events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, ProxyEvent::ClearValue { blocked: true, .. }))
        );
        let host = FakeHost::new();
        let (p, _) = canned(host.clone(), body, TripwireMode::Notify);
        let (s, _, raw) = call(&p, "/openai/v1/responses", req, &[]).await;
        assert_eq!(s, 200, "{ty}: {raw}");
        assert!(raw.contains("Zyxwuria"), "{ty}");
        assert!(
            host.events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, ProxyEvent::ClearValue { blocked: false, .. })),
            "{ty}"
        );
    }
}

/// Follow-up N4, the whole-answer path: a variant field of a Codex item (a
/// top-level `command`) holding a known value in clear refuses the answer
/// in block mode.
#[tokio::test]
async fn a_variant_field_of_a_codex_item_is_tripwired_without_streaming() {
    let item = json!({"type": "shell_call", "id": "sh_1", "call_id": "c1", "status": "completed", "command": format!("mail '{NAME}'"), "action": {"commands": []}});
    let body =
        json!({"id": "resp_1", "object": "response", "status": "completed", "output": [item]});
    let (p, _) = canned(FakeHost::new(), body, TripwireMode::Block);
    let (s, _, raw) = call(
        &p,
        "/openai/v1/responses",
        json!({"model": "m", "input": "hello there"}),
        &[],
    )
    .await;
    assert_eq!(s, 451, "{raw}");
    assert!(!raw.contains("Zyxwuria"), "{raw}");
}

/// A non-streamed Codex MCP call (M8 spec §20 amendment 2026-10-10): a
/// `function_call` with `namespace` is restored like a flat call, its
/// namespace and name unchanged; a known value in clear in the namespace
/// withholds the answer in block mode.
#[tokio::test]
async fn a_namespaced_call_is_restored_and_its_namespace_tripwired() {
    let fc = |ns: &str, args: String| {
        json!({"id": "resp_1", "object": "response", "status": "completed", "output": [
            {"type": "function_call", "id": "fc_1", "call_id": "c1", "name": "lookup_record",
             "namespace": ns, "arguments": args, "status": "completed"}]})
    };
    let req = json!({"model": "m", "input": "hello there"});
    let body = fc("mcp__inumaki_check_ab", json!({"to": DS_TOKEN}).to_string());
    let (p, _) = canned(FakeHost::new(), body, TripwireMode::Block);
    let (s, v, raw) = call(
        &p,
        "/openai/v1/responses",
        req.clone(),
        &[("x-inumaki-client", CLIENT)],
    )
    .await;
    assert_eq!(s, 200, "{raw}");
    let item = &v["output"][0];
    assert_eq!(item["namespace"], "mcp__inumaki_check_ab");
    assert_eq!(item["name"], "lookup_record");
    let a: serde_json::Value = serde_json::from_str(item["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(
        a["to"], DS_TOKEN,
        "a dataset token stays in arguments, as for a flat call"
    );

    let host = FakeHost::new();
    let (p, _) = canned(
        host.clone(),
        fc(&format!("mcp__{NAME}"), "{}".into()),
        TripwireMode::Block,
    );
    let (s, _, raw) = call(
        &p,
        "/openai/v1/responses",
        req,
        &[("x-inumaki-client", CLIENT)],
    )
    .await;
    assert_eq!(s, 451, "{raw}");
    assert!(!raw.contains("Zyxwuria"), "{raw}");
}
