//! Check routes (M8 spec §12, §15 tests 13 and 14) at the proxy, streamed
//! and not, on every upstream including Codex. Canary values are synthetic.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::check::CheckId;
use crate::handler_tests::Recording;
use crate::routes::Wire;
use crate::scripted::{Script, Step, ToolCall};
use crate::stream_tests::visible;
use crate::testing::{
    CHECK_DS, CHECK_EMAIL, CHECK_EMAIL_TOKEN, CHECK_NAME, CHECK_TOKEN, DS_TOKEN, FakeHost, NAME,
};

const ID: &str = "0123456789abcdef0123456789abcdef";

fn id() -> CheckId {
    CheckId::from_hex(ID).unwrap()
}

/// A proxy whose normal upstream records; check routes never use it.
fn proxy() -> (crate::Proxy, Arc<FakeHost>, Arc<Recording>) {
    let host = FakeHost::new();
    let cfg = crate::pipeline::test_shared(host.clone()).cfg.clone();
    let up = Arc::new(Recording::default());
    let p = crate::Proxy::with_upstream(
        cfg,
        host.clone(),
        zeroize::Zeroizing::new("client-value".into()),
        up.clone(),
    );
    (p, host, up)
}

async fn send(
    p: &crate::Proxy,
    method: http::Method,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> (u16, Vec<u8>) {
    let mut r = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    let b = body.map_or_else(Body::empty, |v| Body::from(v.to_string()));
    let resp = p.router().oneshot(r.body(b).unwrap()).await.unwrap();
    let s = resp.status().as_u16();
    (
        s,
        axum::body::to_bytes(resp.into_body(), 1 << 22)
            .await
            .unwrap()
            .to_vec(),
    )
}

fn text_of(wire: Wire, stream: bool, bytes: &[u8]) -> String {
    if stream {
        let v = visible(wire, bytes);
        assert!(v.error.is_none(), "the stream completed");
        return v.text;
    }
    let v: Value = serde_json::from_slice(bytes).unwrap();
    let t = match wire {
        Wire::Messages => &v["content"][0]["text"],
        Wire::Responses => &v["output"][0]["content"][0]["text"],
        Wire::Chat => &v["choices"][0]["message"]["content"],
    };
    t.as_str().unwrap_or_default().to_string()
}

fn register(p: &crate::Proxy, ttl: Duration) {
    p.check_routes()
        .register(id(), CHECK_DS, Script(vec![Step::EchoUserText]), ttl);
}

/// Spec §15 test 13: the canary through each check route, streamed and
/// not, without the client header: only tokens reach the scripted upstream,
/// the answer is restored with the check's scope, nothing reaches the
/// normal upstream.
#[tokio::test]
async fn canary_through_each_check_route() {
    let (p, _, normal) = proxy();
    register(&p, Duration::from_secs(60));
    let msg = format!("Record: {CHECK_NAME}, email {CHECK_EMAIL}");
    for stream in [false, true] {
        for (path, wire, body) in [
            (
                "anthropic/v1/messages",
                Wire::Messages,
                json!({"model": "m", "max_tokens": 9, "stream": stream, "messages": [{"role": "user", "content": msg}]}),
            ),
            (
                "openai/v1/responses",
                Wire::Responses,
                json!({"model": "m", "stream": stream, "input": [{"type": "message", "role": "user", "content": msg}]}),
            ),
            (
                "openai/v1/chat/completions",
                Wire::Chat,
                json!({"model": "m", "stream": stream, "messages": [{"role": "user", "content": msg}]}),
            ),
            (
                "openai-codex/responses",
                Wire::Responses,
                json!({"model": "m", "stream": stream, "store": false,
                    "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": msg}]}]}),
            ),
        ] {
            let (s, b) = send(
                &p,
                http::Method::POST,
                &format!("/check/{ID}/{path}"),
                Some(body),
                &[("x-api-key", "inumaki-check-dummy")],
            )
            .await;
            assert_eq!(s, 200, "{path} stream={stream}");
            assert_eq!(
                text_of(wire, stream, &b),
                msg,
                "{path} stream={stream}: restored with the check's scope"
            );
        }
    }
    let rec = p.check_routes().recorded(&id());
    assert_eq!(rec.len(), 8);
    assert_eq!(
        rec[..4].iter().map(|r| r.upstream).collect::<Vec<_>>(),
        ["anthropic", "openai", "openai", "openai-codex"]
    );
    for r in &rec {
        let b = String::from_utf8_lossy(&r.body);
        assert!(
            !b.contains("Vexmira") && !b.contains("Thwarnquix") && !b.contains("vexmira@"),
            "no canary component upstream"
        );
        assert!(b.contains(CHECK_TOKEN) && b.contains(CHECK_EMAIL_TOKEN));
        assert!(!b.contains("inumaki-check-dummy"), "no header recorded");
    }
    assert!(
        normal.sent.lock().unwrap().is_empty(),
        "nothing left the process"
    );
    assert_eq!(p.status().check_routes, 1);
    assert_eq!(p.check_routes().dropped(&id()), 0);
}

/// Spec §15 test 14: retries, scope, credentials, the scripted endpoints,
/// and every `404 not_served` case.
#[tokio::test]
async fn check_route_contract() {
    let (p, _, normal) = proxy();
    let routes = p.check_routes();
    register(&p, Duration::from_secs(60));
    let creds = [
        ("x-api-key", "sk-ant-api-SECRETVALUE"),
        ("authorization", "Bearer secret-token-xyz"),
        ("cookie", "session=cookie-secret"),
        ("chatgpt-account-id", "acct-secret"),
        ("x-inumaki-client", "client-value"),
    ];
    let uri = format!("/check/{ID}/anthropic/v1/messages");
    let body = json!({"model": "m", "messages": [{"role": "user", "content": format!("Kunde {DS_TOKEN}, {CHECK_NAME}")}]});
    let (sa, a) = send(&p, http::Method::POST, &uri, Some(body.clone()), &creds).await;
    let (_, b) = send(&p, http::Method::POST, &uri, Some(body), &creds).await;
    assert_eq!(sa, 200);
    assert_eq!(a, b, "a retried turn gets the same answer");
    let t = text_of(Wire::Messages, false, &a);
    assert!(t.contains(CHECK_NAME));
    assert!(
        t.contains(DS_TOKEN) && !t.contains(NAME),
        "a non-check dataset token is never restored here, even with the client header"
    );
    let rec = routes.recorded(&id());
    assert_eq!(rec.len(), 2);
    for r in &rec {
        let s = String::from_utf8_lossy(&r.body);
        for secret in [
            "SECRETVALUE",
            "secret-token",
            "cookie-secret",
            "acct-secret",
            "client-value",
        ] {
            assert!(!s.contains(secret), "no credential recorded");
        }
    }
    // Token counting and model lists: scripted, never recorded.
    let (s, ct) = send(
        &p,
        http::Method::POST,
        &format!("/check/{ID}/anthropic/v1/messages/count_tokens"),
        Some(json!({"messages": [{"role": "user", "content": "hi"}]})),
        &[],
    )
    .await;
    assert_eq!(s, 200);
    assert!(serde_json::from_slice::<Value>(&ct).unwrap()["input_tokens"].is_u64());
    for models in [
        "openai/v1/models",
        "openai-codex/models?client_version=0.47.0",
    ] {
        let (s, ml) = send(
            &p,
            http::Method::GET,
            &format!("/check/{ID}/{models}"),
            None,
            &[],
        )
        .await;
        assert_eq!(s, 200, "{models}");
        assert_eq!(
            serde_json::from_slice::<Value>(&ml).unwrap()["data"][0]["id"],
            "inumaki-check"
        );
    }
    assert_eq!(
        routes.recorded(&id()).len(),
        2,
        "scripted endpoints record nothing"
    );
    let empty = || Some(json!({"messages": []}));
    for bad in [
        format!("/check/{}/anthropic/v1/messages", ID.to_uppercase()),
        "/check/ffffffffffffffffffffffffffffffff/anthropic/v1/messages".to_string(),
        format!("/check/{ID}/gemini/v1/messages"),
        format!("/check/{ID}/anthropic/v1/messages/batches"),
        format!("/check/{ID}/anthropic/v1%2Fmessages"),
        format!("/check/{ID}/openai-codex/responses/compact"),
    ] {
        assert_eq!(
            send(&p, http::Method::POST, &bad, empty(), &[]).await.0,
            404,
            "not served"
        );
    }
    assert_eq!(routes.recorded(&id()).len(), 2, "a 404 records nothing");
    routes.remove(&id());
    assert_eq!(
        send(&p, http::Method::POST, &uri, empty(), &[]).await.0,
        404
    );
    assert!(routes.recorded(&id()).is_empty(), "removed with its bodies");
    assert_eq!(routes.dropped(&id()), 0, "a refused id records nothing");
    register(&p, Duration::ZERO);
    assert_eq!(
        send(&p, http::Method::POST, &uri, empty(), &[]).await.0,
        404,
        "expired"
    );
    assert_eq!(routes.dropped(&id()), 0, "an expired id records nothing");
    assert!(normal.sent.lock().unwrap().is_empty());
}

/// Fail closed: a blocked text leaf refuses with nothing recorded; a
/// blocked tool result becomes the placeholder; a disallowed query is
/// refused before anything is recorded.
#[tokio::test]
async fn check_route_refusals_record_nothing() {
    let (p, host, normal) = proxy();
    register(&p, Duration::from_secs(60));
    let uri = format!("/check/{ID}/anthropic/v1/messages");
    let blocked =
        json!({"model": "m", "messages": [{"role": "user", "content": "BLOCK-ME please"}]});
    let (s, b) = send(&p, http::Method::POST, &uri, Some(blocked), &[]).await;
    assert_eq!(s, 451);
    assert!(!String::from_utf8_lossy(&b).contains("BLOCK-ME"));
    let stream = json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "BLOCK-ME"}]});
    assert_eq!(
        send(&p, http::Method::POST, &uri, Some(stream), &[])
            .await
            .0,
        451,
        "a streamed request is refused like any other"
    );
    let ok = json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]});
    assert_eq!(
        send(&p, http::Method::POST, &format!("{uri}?x=1"), Some(ok), &[])
            .await
            .0,
        400
    );
    assert!(p.check_routes().recorded(&id()).is_empty());
    assert_eq!(p.check_routes().dropped(&id()), 0);
    let tool = json!({"model": "m", "messages": [
        {"role": "user", "content": "look it up"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_ink_0_0", "name": "lookup", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_ink_0_0", "content": format!("BLOCK-ME {CHECK_NAME}")}]}
    ]});
    let (s, _) = send(&p, http::Method::POST, &uri, Some(tool), &[]).await;
    assert_eq!(s, 200);
    let rec = p.check_routes().recorded(&id());
    assert_eq!(rec.len(), 1);
    let r = String::from_utf8_lossy(&rec[0].body);
    assert!(r.contains("tool result withheld"));
    assert!(!r.contains("BLOCK-ME") && !r.contains("Vexmira"));
    assert!(
        host.events.lock().unwrap().is_empty(),
        "no Refused or Withheld record"
    );
    assert!(normal.sent.lock().unwrap().is_empty());
}

/// Spec §12.3: a check route writes nothing outside the registry, streamed
/// or not: no activity record, tripwire record, session, or route counter.
#[tokio::test]
async fn a_check_route_writes_nothing() {
    let (p, host, _) = proxy();
    register(&p, Duration::from_secs(60));
    // The answer repeats a normal dataset's value in clear: a normal route's
    // tripwire would record `ClearValue`; a check route does not run it.
    for stream in [false, true] {
        let body = json!({"model": "m", "stream": stream, "messages": [{"role": "user", "content": format!("{CHECK_NAME} and {NAME}")}]});
        let (s, b) = send(
            &p,
            http::Method::POST,
            &format!("/check/{ID}/anthropic/v1/messages"),
            Some(body),
            &[("x-inumaki-client", "client-value")],
        )
        .await;
        assert_eq!(s, 200);
        assert!(text_of(Wire::Messages, stream, &b).contains(CHECK_NAME));
    }
    assert_eq!(p.check_routes().recorded(&id()).len(), 2);
    assert!(
        host.events.lock().unwrap().is_empty(),
        "no Released, ClearValue, Withheld, or Refused record"
    );
    let st = p.status();
    assert!(
        st.routes.iter().all(|r| r.requests == 0),
        "no route counter"
    );
    assert_eq!(st.sessions, 0, "no normal session");
}

/// Scanned leaves (reasoning, citations, search sources) go through the
/// check dataset's batch: a clear value there is tokenized before the
/// registry records the body, and a blocked one refuses.
#[tokio::test]
async fn scanned_leaves_on_a_check_route_are_sanitized() {
    let (p, _, _) = proxy();
    register(&p, Duration::from_secs(60));
    let uri = format!("/check/{ID}/anthropic/v1/messages");
    let body = |scan: &str| {
        json!({"model": "m", "messages": [
            {"role": "user", "content": [
                {"type": "search_result", "source": format!("https://example.invalid/{CHECK_EMAIL}"), "title": "t",
                    "content": [{"type": "text", "text": "x"}]},
                {"type": "text", "text": "hi"}
            ]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": scan, "signature": "sig"},
                {"type": "text", "text": "ok", "citations": [{"type": "char_location", "cited_text": format!("by {CHECK_NAME}")}]}
            ]},
            {"role": "user", "content": "go on"}
        ]})
    };
    let (s, _) = send(
        &p,
        http::Method::POST,
        &uri,
        Some(body(&format!("about {CHECK_NAME}"))),
        &[],
    )
    .await;
    assert_eq!(s, 200);
    let rec = p.check_routes().recorded(&id());
    assert_eq!(rec.len(), 1);
    let r = String::from_utf8_lossy(&rec[0].body);
    assert!(
        !r.contains("Vexmira") && !r.contains("Thwarnquix") && !r.contains("vexmira@"),
        "no canary in a scanned leaf recorded"
    );
    assert!(r.contains(CHECK_TOKEN) && r.contains(CHECK_EMAIL_TOKEN));
    assert!(
        r.contains("\"signature\":\"sig\""),
        "opaque fields untouched"
    );
    let (s, b) = send(&p, http::Method::POST, &uri, Some(body("BLOCK-ME")), &[]).await;
    assert_eq!(s, 451, "a blocked scanned leaf refuses");
    assert!(!String::from_utf8_lossy(&b).contains("BLOCK-ME"));
    assert_eq!(p.check_routes().recorded(&id()).len(), 1);
}

/// Review Focus 2: Codex streams through its check route; a scripted call
/// of a tool the request does not advertise (`Read`) is skipped, the
/// advertised MCP tool is called, and its result is restored in the
/// check's scope.
#[tokio::test]
async fn codex_through_a_check_route_skips_unadvertised_tools() {
    let (p, _, normal) = proxy();
    p.check_routes().register(
        id(),
        CHECK_DS,
        Script(vec![
            Step::CallTools(vec![
                ToolCall {
                    name_suffix: "lookup_record".into(),
                    arguments: json!({}),
                },
                ToolCall {
                    name_suffix: "Read".into(),
                    arguments: json!({"file_path": "/x"}),
                },
            ]),
            Step::EchoToolResults,
        ]),
        Duration::from_secs(60),
    );
    let tools = json!([
        {"type": "function", "name": "mcp__inumaki-check-ab__lookup_record", "parameters": {"type": "object", "properties": {}}},
        {"type": "function", "name": "shell", "parameters": {"type": "object", "properties": {}}}
    ]);
    let user = json!({"type": "message", "role": "user", "content": [{"type": "input_text", "text": "look it up"}]});
    let uri = format!("/check/{ID}/openai-codex/responses");
    let (s, b) = send(
        &p,
        http::Method::POST,
        &uri,
        Some(json!({"model": "m", "stream": true, "store": false, "tools": tools.clone(), "input": [user.clone()]})),
        &[],
    )
    .await;
    assert_eq!(s, 200);
    let v = visible(Wire::Responses, &b);
    assert!(v.error.is_none(), "the stream completed");
    assert_eq!(
        v.tool_starts, 1,
        "Read is not advertised: skipped, lookup_record called"
    );
    let call = json!({"type": "function_call", "call_id": "call_ink_0_0", "name": "mcp__inumaki-check-ab__lookup_record", "arguments": "{}"});
    let result = json!({"type": "function_call_output", "call_id": "call_ink_0_0", "output": format!("Record: {CHECK_TOKEN}")});
    let (s, b) = send(
        &p,
        http::Method::POST,
        &uri,
        Some(json!({"model": "m", "stream": true, "store": false, "tools": tools, "input": [user, call, result]})),
        &[],
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(
        visible(Wire::Responses, &b).text,
        format!("Tool results:\nRecord: {CHECK_NAME}")
    );
    assert!(normal.sent.lock().unwrap().is_empty());
}

/// The output items a streamed Responses answer shows the client, from
/// `output_item.done` events.
fn done_items(bytes: &[u8]) -> Vec<Value> {
    let mut p = crate::sse::SseParser::new(1 << 20);
    let mut evs = p.push(bytes).unwrap();
    evs.extend(p.finish().unwrap());
    evs.into_iter()
        .filter_map(|e| serde_json::from_slice::<Value>(&e.data?).ok())
        .filter(|j| j["type"] == "response.output_item.done")
        .map(|j| j["item"].clone())
        .collect()
}

/// Codex 0.159.2 advertises MCP tools in a `namespace` tool and calls them
/// with `namespace` + the bare name (M8 spec §20 amendment 2026-10-10): the
/// check route's scripted model calls the nested tool that way, streamed
/// and not, and echoes the result of the resent call.
#[tokio::test]
async fn codex_through_a_check_route_calls_a_namespaced_tool() {
    let (p, _, normal) = proxy();
    p.check_routes().register(
        id(),
        CHECK_DS,
        Script(vec![
            Step::CallTools(vec![ToolCall {
                name_suffix: "lookup_record".into(),
                arguments: json!({}),
            }]),
            Step::EchoToolResults,
        ]),
        Duration::from_secs(60),
    );
    let tools = json!([
        {"type": "function", "name": "shell", "parameters": {"type": "object", "properties": {}}},
        {"type": "namespace", "name": "mcp__inumaki_check_ab", "description": "Tools of the check server",
         "tools": [{"type": "function", "name": "lookup_record", "description": "Look up the check record",
                    "parameters": {"type": "object", "properties": {}}}]},
        {"type": "web_search"}
    ]);
    let user = json!({"type": "message", "role": "user", "content": [{"type": "input_text", "text": "look it up"}]});
    let uri = format!("/check/{ID}/openai/v1/responses");
    for stream in [true, false] {
        let (s, b) = send(
            &p,
            http::Method::POST,
            &uri,
            Some(
                json!({"model": "m", "stream": stream, "store": false, "tools": tools.clone(), "input": [user.clone()]}),
            ),
            &[],
        )
        .await;
        assert_eq!(s, 200);
        let items = if stream {
            assert!(visible(Wire::Responses, &b).error.is_none());
            done_items(&b)
        } else {
            serde_json::from_slice::<Value>(&b).unwrap()["output"]
                .as_array()
                .unwrap()
                .clone()
        };
        assert_eq!(items.len(), 1, "stream={stream}: {items:?}");
        assert_eq!(items[0]["type"], "function_call");
        assert_eq!(items[0]["name"], "lookup_record");
        assert_eq!(items[0]["namespace"], "mcp__inumaki_check_ab");
    }
    let call = json!({"type": "function_call", "call_id": "call_ink_0_0", "name": "lookup_record",
        "namespace": "mcp__inumaki_check_ab", "arguments": "{}"});
    let result = json!({"type": "function_call_output", "call_id": "call_ink_0_0", "output": format!("Record: {CHECK_TOKEN}")});
    let (s, b) = send(
        &p,
        http::Method::POST,
        &uri,
        Some(
            json!({"model": "m", "stream": true, "store": false, "tools": tools, "input": [user, call, result]}),
        ),
        &[],
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(
        visible(Wire::Responses, &b).text,
        format!("Tool results:\nRecord: {CHECK_NAME}")
    );
    assert!(normal.sent.lock().unwrap().is_empty());
}

/// Ruling L58 on a check route (Codex through a check, streamed and not):
/// the body's `client_metadata["x-codex-turn-metadata"]` is dropped before
/// the check's sanitizer runs, so neither the recorded body nor the
/// scripted model sees it; the other members stay. (A check route sends no
/// request headers upstream at all.)
#[tokio::test]
async fn codex_turn_metadata_never_reaches_a_check_route() {
    let (p, _, normal) = proxy();
    register(&p, Duration::from_secs(60));
    let meta = json!({"turn_id": "t1", "workspaces": {"/Users/zyxcanary/ZyxAcme/repo": {
        "latest_git_commit_hash": "0123abcd"}}})
    .to_string();
    let msg = format!("Record: {CHECK_NAME}");
    for path in ["openai-codex/responses", "openai/v1/responses"] {
        for stream in [false, true] {
            let body = json!({"model": "m", "stream": stream, "store": false,
                "client_metadata": {"x-codex-turn-metadata": meta, "x-keep": "keep-me"},
                "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": msg}]}]});
            let (s, b) = send(
                &p,
                http::Method::POST,
                &format!("/check/{ID}/{path}"),
                Some(body),
                &[("x-codex-turn-metadata", meta.as_str())],
            )
            .await;
            assert_eq!(s, 200, "{path} {stream}");
            assert_eq!(text_of(Wire::Responses, stream, &b), msg, "{path} {stream}");
        }
    }
    let rec = p.check_routes().recorded(&id());
    assert_eq!(rec.len(), 4);
    for r in rec {
        let s = String::from_utf8_lossy(&r.body);
        assert!(
            !s.contains("zyx") && !s.contains("x-codex-turn-metadata"),
            "{s}"
        );
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["client_metadata"], json!({"x-keep": "keep-me"}));
    }
    assert!(normal.sent.lock().unwrap().is_empty());
}
