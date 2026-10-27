//! Streaming through the handler: spec §15 test 1 (streaming), the client
//! header on streams, spec §15 test 5 end to end, Review Focus 3 and 4.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use futures::StreamExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::handler_tests::Recording;
use crate::routes::Wire;
use crate::scripted::{Script, ScriptedUpstream, Step};
use crate::sse::{MAX_EVENT, SseParser};
use crate::stream_tests::{ev, visible};
use crate::testing::{DS_TOKEN, EMAIL, FakeHost, NAME};
use crate::upstream::{Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};

const CLIENT: &str = "client-value";

fn proxy(host: Arc<FakeHost>, up: Arc<dyn Upstream>) -> crate::Proxy {
    let cfg = crate::pipeline::test_shared(host.clone()).cfg.clone();
    crate::Proxy::with_upstream(cfg, host, zeroize::Zeroizing::new(CLIENT.into()), up)
}

fn scripted(host: Arc<FakeHost>, script: Script) -> (crate::Proxy, Arc<ScriptedUpstream>) {
    let up = Arc::new(ScriptedUpstream::new(script));
    (proxy(host, up.clone()), up)
}

async fn call(
    p: &crate::Proxy,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> (u16, Vec<u8>) {
    let mut r = http::Request::post(uri).header("content-type", "application/json");
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    let resp = p
        .router()
        .oneshot(r.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let s = resp.status().as_u16();
    (
        s,
        axum::body::to_bytes(resp.into_body(), 1 << 22)
            .await
            .unwrap()
            .to_vec(),
    )
}

fn routes(msg: &str) -> Vec<(&'static str, Wire, Value)> {
    vec![
        (
            "/anthropic/v1/messages",
            Wire::Messages,
            json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": msg}]}),
        ),
        (
            "/openai/v1/responses",
            Wire::Responses,
            json!({"model": "m", "stream": true, "input": [{"type": "message", "role": "user", "content": msg}]}),
        ),
        (
            "/openai/v1/chat/completions",
            Wire::Chat,
            json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": msg}]}),
        ),
        (
            "/codex/responses",
            Wire::Responses,
            json!({"model": "m", "stream": true, "store": false,
            "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": msg}]}]}),
        ),
    ]
}

/// Wait until every in-flight permit is back (the stream task ended).
async fn permits_back(p: &crate::Proxy) -> bool {
    let max = p.inner.sh.cfg.max_inflight;
    for _ in 0..200 {
        if p.inner.inflight.available_permits() == max {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// Spec §15 test 1 (streaming) and the canary through each streaming route.
#[tokio::test]
async fn canary_through_each_streaming_route() {
    let (p, up) = scripted(FakeHost::new(), Script(vec![Step::EchoUserText]));
    let msg = format!("Bitte an {NAME}, {EMAIL}");
    for (uri, wire, body) in routes(&msg) {
        let (status, bytes) = call(&p, uri, body, &[("x-inumaki-client", CLIENT)]).await;
        assert_eq!(status, 200, "{uri}");
        assert_eq!(
            visible(wire, &bytes).text,
            msg,
            "{uri}: restored across 5-character deltas"
        );
    }
    assert_eq!(up.recorded().len(), 4);
    for (_, b) in up.recorded() {
        let b = String::from_utf8_lossy(&b);
        assert!(
            !b.contains("Zyxwuria") && !b.contains("zyx.quolnath"),
            "no original upstream"
        );
        assert!(b.contains("<EMAIL_"));
    }
}

/// Spec decision 23 on streams: no header, session tokens only.
#[tokio::test]
async fn without_the_client_header_a_stream_restores_session_tokens_only() {
    let (p, _) = scripted(FakeHost::new(), Script(vec![Step::EchoUserText]));
    let msg = format!("Bitte an {NAME}, {EMAIL}");
    for (uri, wire, body) in routes(&msg) {
        let (s, bytes) = call(&p, uri, body, &[]).await;
        assert_eq!(s, 200, "{uri}");
        let t = visible(wire, &bytes).text;
        assert!(
            t.contains(EMAIL) && t.contains(DS_TOKEN) && !t.contains(NAME),
            "{uri}"
        );
    }
}

/// Review Focus 3.
#[tokio::test]
async fn a_dropped_client_frees_the_permit_and_seeds_nothing() {
    let (p, _) = scripted(FakeHost::new(), Script(vec![Step::EchoUserText]));
    let long = format!("{EMAIL} {}", "lorem ipsum ".repeat(400));
    let r = http::Request::post("/anthropic/v1/messages")
        .header("content-type", "application/json")
        .header("x-claude-code-session-id", "drop")
        .body(Body::from(
            json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": long}]})
                .to_string(),
        ))
        .unwrap();
    let resp = p.router().oneshot(r).await.unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body().into_data_stream();
    let _first = body.next().await;
    drop(body);
    assert!(permits_back(&p).await, "the permit came back");
    assert_eq!(
        p.inner.sessions.entries(),
        1,
        "only the request's own leaf; the answer was not seeded"
    );
    assert_ne!(
        p.status().routes[0].state,
        "failing",
        "a client that leaves is not the route's fault"
    );
}

/// An upstream that sends one event, then stays silent.
struct Stall;
impl Upstream for Stall {
    fn send(
        &self,
        _: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        Box::pin(async {
            let mut h = http::HeaderMap::new();
            h.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/event-stream"),
            );
            let first = ev(
                Some("message_start"),
                json!({"type": "message_start", "message": {"id": "m", "type": "message", "role": "assistant", "content": []}}),
            );
            let body = futures::stream::once(async move { Ok(bytes::Bytes::from(first)) })
                .chain(futures::stream::pending())
                .boxed();
            Ok(UpstreamResponse {
                status: http::StatusCode::OK,
                headers: h,
                body,
            })
        })
    }
}

/// Plan review item 2: a client leaving a silent stream frees the permit
/// without waiting for the upstream.
#[tokio::test]
async fn a_client_leaving_a_silent_stream_frees_the_permit() {
    let p = proxy(FakeHost::new(), Arc::new(Stall));
    let r = http::Request::post("/anthropic/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "hi"}]})
                .to_string(),
        ))
        .unwrap();
    let resp = p.router().oneshot(r).await.unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body().into_data_stream();
    let _first = body.next().await;
    drop(body);
    assert!(
        permits_back(&p).await,
        "the permit came back while the upstream stayed silent"
    );
}

/// An upstream that sends half a stream, then fails (or, with `true`, its
/// body panics when read again).
struct Cut(bool);
impl Upstream for Cut {
    fn send(
        &self,
        _: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        let panics = self.0;
        Box::pin(async move {
            let mut h = http::HeaderMap::new();
            h.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/event-stream"),
            );
            let first = ev(
                Some("content_block_delta"),
                json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hallo <PERS"}}),
            );
            let first = futures::stream::once(async move { Ok(bytes::Bytes::from(first)) });
            let body = if panics {
                first
                    .chain(futures::stream::poll_fn(
                        |_| -> std::task::Poll<Option<Result<bytes::Bytes, UpstreamError>>> {
                            panic!("the upstream body panics")
                        },
                    ))
                    .boxed()
            } else {
                first
                    .chain(futures::stream::once(async { Err(UpstreamError::Body) }))
                    .boxed()
            };
            Ok(UpstreamResponse {
                status: http::StatusCode::OK,
                headers: h,
                body,
            })
        })
    }
}

/// Review Focus 4 at the route: abort event, route `failing`.
#[tokio::test]
async fn a_cut_stream_marks_the_route_failing() {
    let p = proxy(FakeHost::new(), Arc::new(Cut(false)));
    let (status, bytes) = call(
        &p,
        "/anthropic/v1/messages",
        json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "hi"}]}),
        &[],
    )
    .await;
    assert_eq!(status, 200);
    let v = visible(Wire::Messages, &bytes);
    assert_eq!(v.error.as_deref(), Some("api_error"));
    assert!(!String::from_utf8_lossy(&bytes).contains("<PERS"));
    assert!(permits_back(&p).await);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(p.status().routes[0].state, "failing");
}

/// An upstream that streams a Messages answer with provider-written
/// reasoning holding a known original in clear, then text naming the
/// request's tokens (the streaming twin of `respond_tests::Echo`).
struct EchoStream(Recording);

impl Upstream for EchoStream {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        let body = String::from_utf8(req.body.to_vec()).unwrap();
        self.0.sent.lock().unwrap().push((
            req.upstream,
            req.path_and_query.clone(),
            req.body.to_vec(),
            req.headers.clone(),
        ));
        let toks: Vec<String> = regex::Regex::new(r"<[A-Z_]+_[0-9a-f]{4,12}>")
            .unwrap()
            .find_iter(&body)
            .map(|m| m.as_str().to_string())
            .collect();
        let text = toks.join(" ");
        let thinking = format!("thinking about {NAME} and {text}");
        let delta = |i: u32, d: Value| {
            ev(
                Some("content_block_delta"),
                json!({"type": "content_block_delta", "index": i, "delta": d}),
            )
        };
        let mut events = vec![
            ev(
                Some("message_start"),
                json!({"type": "message_start", "message": {"id": "msg_01XFDUDYJgAACzvnptvVoYEL", "type": "message", "role": "assistant", "content": [], "usage": {"input_tokens": 0, "output_tokens": 0}}}),
            ),
            ev(
                Some("content_block_start"),
                json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}}),
            ),
        ];
        let chunk = |s: &str| -> Vec<String> {
            let c: Vec<char> = s.chars().collect();
            c.chunks(5).map(|x| x.iter().collect()).collect()
        };
        for c in chunk(&thinking) {
            events.push(delta(0, json!({"type": "thinking_delta", "thinking": c})));
        }
        events.push(delta(
            0,
            json!({"type": "signature_delta", "signature": "sig"}),
        ));
        events.push(ev(
            Some("content_block_stop"),
            json!({"type": "content_block_stop", "index": 0}),
        ));
        events.push(ev(
            Some("content_block_start"),
            json!({"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}),
        ));
        for c in chunk(&text) {
            events.push(delta(1, json!({"type": "text_delta", "text": c})));
        }
        events.push(ev(
            Some("content_block_stop"),
            json!({"type": "content_block_stop", "index": 1}),
        ));
        events.push(ev(
            Some("message_delta"),
            json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 0}}),
        ));
        events.push(ev(Some("message_stop"), json!({"type": "message_stop"})));
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/event-stream"),
        );
        Box::pin(async move {
            Ok(UpstreamResponse {
                status: http::StatusCode::OK,
                headers: h,
                body: futures::stream::iter(events.into_iter().map(|e| Ok(bytes::Bytes::from(e))))
                    .boxed(),
            })
        })
    }
}

/// The assistant content blocks a client assembles from a Messages stream.
fn assembled(bytes: &[u8]) -> Value {
    let mut p = SseParser::new(MAX_EVENT);
    let mut evs = p.push(bytes).unwrap();
    evs.extend(p.finish().unwrap());
    let mut blocks: Vec<Value> = Vec::new();
    for e in evs {
        let Some(d) = e.data else { continue };
        let j: Value = serde_json::from_slice(&d).unwrap();
        match j["type"].as_str() {
            Some("content_block_start") => blocks.push(j["content_block"].clone()),
            Some("content_block_delta") => {
                let b = &mut blocks[j["index"].as_u64().unwrap() as usize];
                let d = &j["delta"];
                for (field, key) in [
                    ("thinking_delta", "thinking"),
                    ("signature_delta", "signature"),
                    ("text_delta", "text"),
                ] {
                    if d["type"] == field {
                        let s = format!(
                            "{}{}",
                            b[key].as_str().unwrap_or(""),
                            d[key].as_str().unwrap()
                        );
                        b[key] = json!(s);
                    }
                }
            }
            Some("error") => panic!("the stream aborted"),
            _ => {}
        }
    }
    Value::Array(blocks)
}

/// Spec §15 test 5 end to end on a stream (integrator item c): the
/// streamed reasoning is seeded with the request's stamp, so turn 2 resends
/// it and passes; the same reasoning in a fresh session is refused.
#[tokio::test]
async fn a_streamed_turn_seeds_its_reasoning_for_the_next_turn() {
    let up = Arc::new(EchoStream(Recording::default()));
    let p = proxy(FakeHost::new(), up.clone());
    let h = [
        ("x-inumaki-client", CLIENT),
        ("x-claude-code-session-id", "s1"),
    ];
    let turn1 = json!({"model": "m", "stream": true,
        "messages": [{"role": "user", "content": format!("{NAME} {EMAIL}")}]});
    let (s, bytes) = call(&p, "/anthropic/v1/messages", turn1.clone(), &h).await;
    assert_eq!(s, 200);
    let content = assembled(&bytes);
    assert!(
        content[0]["thinking"].as_str().unwrap().contains(NAME),
        "the provider wrote the name in clear in its reasoning"
    );
    assert!(content[1]["text"].as_str().unwrap().contains(EMAIL));
    assert!(permits_back(&p).await, "the stream ended");
    let mut msgs = turn1["messages"].as_array().unwrap().clone();
    msgs.push(json!({"role": "assistant", "content": content}));
    msgs.push(json!({"role": "user", "content": "und weiter"}));
    let turn2 = json!({"model": "m", "stream": true, "messages": msgs});
    let (s, _) = call(&p, "/anthropic/v1/messages", turn2.clone(), &h).await;
    assert_eq!(
        s, 200,
        "the seeded thinking block passes although it holds a known original"
    );
    assert!(
        !String::from_utf8_lossy(&up.0.sent.lock().unwrap()[1].2).contains(EMAIL),
        "no original in turn 2"
    );
    let other = [
        ("x-inumaki-client", CLIENT),
        ("x-claude-code-session-id", "other"),
    ];
    let (s, raw) = call(&p, "/anthropic/v1/messages", turn2, &other).await;
    assert_eq!(s, 451, "unseeded in a fresh session");
    assert!(!String::from_utf8_lossy(&raw).contains(NAME));
    assert_eq!(
        up.0.sent.lock().unwrap().len(),
        2,
        "the refused turn sent nothing"
    );
}

/// Handoff item 6: a panic in the stream task (outside the daemon's panic
/// guard) ends the stream with the abort event, frees the permit, and marks
/// the route `failing`.
#[tokio::test]
async fn a_panicking_stream_ends_with_the_abort_event() {
    let p = proxy(FakeHost::new(), Arc::new(Cut(true)));
    let (status, bytes) = call(
        &p,
        "/anthropic/v1/messages",
        json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "hi"}]}),
        &[],
    )
    .await;
    assert_eq!(status, 200);
    let v = visible(Wire::Messages, &bytes);
    assert_eq!(v.error.as_deref(), Some("api_error"));
    assert!(!String::from_utf8_lossy(&bytes).contains("<PERS"));
    assert!(permits_back(&p).await, "the permit came back");
    assert_eq!(p.status().routes[0].state, "failing");
}

/// An upstream that answers each request with the next canned event stream.
struct Canned(std::sync::Mutex<std::collections::VecDeque<Vec<Vec<u8>>>>);

impl Canned {
    fn new(streams: Vec<Vec<Vec<u8>>>) -> Arc<Canned> {
        Arc::new(Canned(std::sync::Mutex::new(streams.into())))
    }
}

impl Upstream for Canned {
    fn send(
        &self,
        _: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        let events = self.0.lock().unwrap().pop_front().unwrap_or_default();
        Box::pin(async move {
            let mut h = http::HeaderMap::new();
            h.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/event-stream"),
            );
            Ok(UpstreamResponse {
                status: http::StatusCode::OK,
                headers: h,
                body: futures::stream::iter(events.into_iter().map(|e| Ok(bytes::Bytes::from(e))))
                    .boxed(),
            })
        })
    }
}

/// A Messages answer: `before` events, one text block whose single delta
/// is `text`, then the stop events.
fn big_text_stream(before: Vec<Vec<u8>>, text: &str) -> Vec<Vec<u8>> {
    let mut s = vec![ev(
        Some("content_block_start"),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
    )];
    s.extend(before);
    s.push(ev(
        Some("content_block_delta"),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}),
    ));
    s.push(ev(
        Some("content_block_stop"),
        json!({"type": "content_block_stop", "index": 0}),
    ));
    s.push(ev(Some("message_stop"), json!({"type": "message_stop"})));
    s
}

fn hi() -> Value {
    json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "hi"}]})
}

/// A proxy over `up` with a scan budget of `budget` permits.
fn budgeted(
    host: Arc<FakeHost>,
    up: Arc<dyn Upstream>,
    budget: usize,
    wait: Duration,
) -> crate::Proxy {
    let mut cfg = crate::pipeline::test_shared(host.clone()).cfg.clone();
    // The answer-side wait is `min(upstream_timeout, 10 s)`.
    cfg.upstream_timeout = wait;
    crate::Proxy::build(
        cfg,
        host,
        zeroize::Zeroizing::new(CLIENT.into()),
        up,
        budget,
    )
    .unwrap()
}

/// Final review I3 (and the Task 5 gap): an event over `SCAN_FREE` waits
/// for scan permits, bounded; a timed-out wait aborts the stream as
/// `stream_aborted` and the route is `failing`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_that_cannot_get_scan_permits_in_time_aborts() {
    let big = "x".repeat(100 << 10);
    let up = Canned::new(vec![big_text_stream(Vec::new(), &big)]);
    let p = budgeted(FakeHost::new(), up, 1 << 20, Duration::from_millis(200));
    let held = Arc::clone(&p.inner.scan).try_acquire_many_owned(1).unwrap();
    let (status, bytes) = call(&p, "/anthropic/v1/messages", hi(), &[]).await;
    assert_eq!(status, 200);
    let v = visible(Wire::Messages, &bytes);
    assert_eq!(v.error.as_deref(), Some("api_error"));
    assert!(
        v.message
            .as_deref()
            .is_some_and(|m| m.contains("stream_aborted")),
        "{:?}",
        v.message
    );
    assert!(v.text.is_empty(), "nothing of the unchecked event");
    assert!(permits_back(&p).await);
    drop(held);
    assert_eq!(p.inner.scan.available_permits(), 1 << 20);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(p.status().routes[0].state, "failing");
}

/// Final review I3: a large event's scan permits are released once it is
/// rewritten, before the driver waits on a slow client, so one client that
/// does not read cannot hold the whole scan budget for `IDLE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_client_does_not_hold_the_scan_budget() {
    let big = "x".repeat(100 << 10);
    // 32 events fill the client queue; the large one's send then waits.
    let pings: Vec<Vec<u8>> = (0..31)
        .map(|_| ev(Some("ping"), json!({"type": "ping"})))
        .collect();
    let up = Canned::new(vec![
        big_text_stream(pings, &big),
        big_text_stream(Vec::new(), &big),
    ]);
    let p = budgeted(FakeHost::new(), up, 1 << 20, Duration::from_secs(3));
    let slow = p
        .router()
        .oneshot(
            http::Request::post("/anthropic/v1/messages")
                .header("content-type", "application/json")
                .body(Body::from(hi().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(slow.status(), 200);
    // The driver takes every event and blocks on the unread client.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (status, bytes) = call(&p, "/anthropic/v1/messages", hi(), &[]).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&bytes));
    let v = visible(Wire::Messages, &bytes);
    assert_eq!(v.error, None, "{:?}", v.message);
    assert_eq!(v.text.len(), big.len());
    drop(slow);
    assert!(permits_back(&p).await);
}

/// Final review M6 (spec §7): a block-mode stream abort records the route
/// outcome `Blocked`, never `failing`.
#[tokio::test]
async fn a_block_mode_stream_abort_records_blocked() {
    let host = FakeHost::new();
    let args = format!(r#"{{"to":"{NAME}"}}"#);
    let up = Canned::new(vec![vec![
        ev(
            Some("content_block_start"),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "t", "name": "w", "input": {}}}),
        ),
        ev(
            Some("content_block_delta"),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": args}}),
        ),
        ev(
            Some("content_block_stop"),
            json!({"type": "content_block_stop", "index": 0}),
        ),
        ev(Some("message_stop"), json!({"type": "message_stop"})),
    ]]);
    let mut cfg = crate::pipeline::test_shared(host.clone()).cfg.clone();
    cfg.tripwire = crate::TripwireMode::Block;
    let p = crate::Proxy::with_upstream(cfg, host, zeroize::Zeroizing::new(CLIENT.into()), up);
    let (status, bytes) = call(&p, "/anthropic/v1/messages", hi(), &[]).await;
    assert_eq!(status, 200);
    assert_eq!(
        visible(Wire::Messages, &bytes).error.as_deref(),
        Some("privacy_block")
    );
    assert!(!String::from_utf8_lossy(&bytes).contains(NAME));
    assert!(permits_back(&p).await);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let r = &p.status().routes[0];
    assert_ne!(
        r.state, "failing",
        "a privacy block is not the route's fault"
    );
    assert_eq!(r.blocked, 1);
    assert_eq!(
        r.last_error.as_ref().map(|e| e.class),
        Some(crate::ErrorClass::PrivacyBlock)
    );
}

/// An upstream whose event stream the test feeds chunk by chunk.
struct Fed(
    std::sync::Mutex<
        Vec<futures::channel::mpsc::UnboundedReceiver<Result<bytes::Bytes, UpstreamError>>>,
    >,
);

impl Upstream for Fed {
    fn send(
        &self,
        _: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        let rx = self.0.lock().unwrap().remove(0);
        Box::pin(async move {
            let mut h = http::HeaderMap::new();
            h.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/event-stream"),
            );
            Ok(UpstreamResponse {
                status: http::StatusCode::OK,
                headers: h,
                body: rx.boxed(),
            })
        })
    }
}

/// Fix wave 2a (C, final re-review N1): the record-only tripwire scan of a
/// channel an upstream cut cuts off takes scan permits like any scan. With
/// the budget held it is skipped (the stream aborts either way); with
/// permits free it records `ClearValue`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cut_off_channel_is_recorded_only_within_the_scan_budget() {
    use crate::host::ProxyEvent;
    let host = FakeHost::new();
    let (tx1, rx1) = futures::channel::mpsc::unbounded();
    let (tx2, rx2) = futures::channel::mpsc::unbounded();
    let up = Arc::new(Fed(std::sync::Mutex::new(vec![rx1, rx2])));
    let p = budgeted(host.clone(), up, 1 << 20, Duration::from_millis(200));
    let cleared = || {
        host.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, ProxyEvent::ClearValue { .. }))
            .count()
    };
    // A tool call whose arguments (over `SCAN_FREE`) hold a known value in clear.
    let args = json!({"to": NAME, "pad": "x".repeat(100 << 10)}).to_string();
    let events = [
        ev(
            Some("content_block_start"),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "t", "name": "w", "input": {}}}),
        ),
        ev(
            Some("content_block_delta"),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": args}}),
        ),
    ];
    for (tx, hold, want) in [(tx1, true, 0), (tx2, false, 1)] {
        let resp = p
            .router()
            .oneshot(
                http::Request::post("/anthropic/v1/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(hi().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        for e in &events {
            tx.unbounded_send(Ok(bytes::Bytes::from(e.clone())))
                .unwrap();
        }
        // Read until the delta (notify mode: not queued) reached the client.
        let mut body = resp.into_body().into_data_stream();
        let mut got = Vec::new();
        while got.len() < (100 << 10) {
            got.extend_from_slice(&body.next().await.unwrap().unwrap());
        }
        let held = hold.then(|| {
            Arc::clone(&p.inner.scan)
                .try_acquire_many_owned(1 << 20)
                .unwrap()
        });
        tx.unbounded_send(Err(UpstreamError::Body)).unwrap();
        while let Some(c) = body.next().await {
            got.extend_from_slice(&c.unwrap());
        }
        assert_eq!(
            visible(Wire::Messages, &got).error.as_deref(),
            Some("api_error")
        );
        assert!(permits_back(&p).await);
        drop(held);
        assert_eq!(cleared(), want, "held budget: {hold}");
    }
}

/// Records the headers each request carried, then answers from the script.
struct HeaderTap {
    inner: Arc<ScriptedUpstream>,
    headers: std::sync::Mutex<Vec<http::HeaderMap>>,
}

impl Upstream for HeaderTap {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        self.headers.lock().unwrap().push(req.headers.clone());
        self.inner.send(req)
    }
}

/// Ruling L58 end to end on both Responses routes, streamed and not: the
/// `x-codex-turn-metadata` header and the body's
/// `client_metadata["x-codex-turn-metadata"]` never reach the upstream; the
/// rest of Codex's headers and the other `client_metadata` members do, and
/// the answer is restored as usual.
#[tokio::test]
async fn codex_turn_metadata_never_reaches_the_upstream() {
    const CANARY: &str = "/Users/zyxcanary/Clients/ZyxAcme/repo";
    let scripted = Arc::new(ScriptedUpstream::new(Script(vec![Step::EchoUserText])));
    let tap = Arc::new(HeaderTap {
        inner: Arc::clone(&scripted),
        headers: std::sync::Mutex::new(Vec::new()),
    });
    let p = proxy(FakeHost::new(), tap.clone());
    let meta = json!({"turn_id": "t1", "workspaces": {CANARY: {
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
    let msg = format!("Bitte an {NAME}, {EMAIL}");
    let mut n = 0;
    for uri in ["/openai/v1/responses", "/codex/responses"] {
        for stream in [true, false] {
            let body = json!({"model": "m", "stream": stream, "store": false,
                "client_metadata": {"x-codex-turn-metadata": meta, "x-keep": "keep-me"},
                "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": msg}]}]});
            let (status, bytes) = call(&p, uri, body, &headers).await;
            assert_eq!(status, 200, "{uri} {stream}");
            let text = if stream {
                visible(Wire::Responses, &bytes).text
            } else {
                let v: Value = serde_json::from_slice(&bytes).unwrap();
                v["output"][0]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .to_string()
            };
            // No client header: session tokens restored, dataset tokens kept.
            assert_eq!(
                text,
                format!("Bitte an {DS_TOKEN}, {EMAIL}"),
                "{uri} {stream}"
            );
            n += 1;
        }
    }
    let sent = tap.headers.lock().unwrap();
    assert_eq!(sent.len(), n);
    for h in sent.iter() {
        assert!(!h.contains_key("x-codex-turn-metadata"));
        assert!(
            h.values()
                .all(|v| !String::from_utf8_lossy(v.as_bytes()).contains("zyx")),
            "no canary in any header value"
        );
        for (k, v) in &headers[1..] {
            assert_eq!(h[*k], *v, "{k} still passes");
        }
    }
    let bodies = scripted.recorded();
    assert_eq!(bodies.len(), n);
    for (_, b) in bodies {
        let s = String::from_utf8_lossy(&b);
        assert!(
            !s.contains("zyx") && !s.contains("x-codex-turn-metadata"),
            "{s}"
        );
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["client_metadata"], json!({"x-keep": "keep-me"}));
    }
}

/// Spec §20 amendment of 2026-10-12 (4e), end to end: the recorded Claude Code
/// and Codex header sets reach each upstream through every endpoint, streamed
/// and not, with their values; framing, an unknown name, and a path-shaped
/// extra value of a repeated header never do.
#[tokio::test]
async fn recorded_headers_reach_each_upstream_streamed_and_not() {
    use crate::forward::tests::{CLAUDE_CODE_2_1_296, CODEX_0_159_2};

    let scripted = Arc::new(ScriptedUpstream::new(Script(vec![Step::EchoUserText])));
    let tap = Arc::new(HeaderTap {
        inner: Arc::clone(&scripted),
        headers: std::sync::Mutex::new(Vec::new()),
    });
    let p = proxy(FakeHost::new(), tap.clone());
    let msg = "hello";
    let chat = json!({"model": "m", "messages": [{"role": "user", "content": msg}]});
    let responses = json!({"model": "m", "store": false,
        "input": [{"type": "message", "role": "user", "content": msg}]});
    // (uri, body, the harness's header set, may stream)
    type Case<'a> = (&'a str, &'a Value, &'a [(&'a str, &'a str)], bool);
    let cases: [Case; 5] = [
        ("/anthropic/v1/messages", &chat, CLAUDE_CODE_2_1_296, true),
        (
            "/anthropic/v1/messages/count_tokens",
            &chat,
            CLAUDE_CODE_2_1_296,
            false,
        ),
        ("/openai/v1/responses", &responses, CODEX_0_159_2, true),
        ("/openai/v1/chat/completions", &chat, CODEX_0_159_2, true),
        ("/codex/responses", &responses, CODEX_0_159_2, true),
    ];
    let mut want: Vec<(&str, &[(&str, &str)])> = Vec::new();
    for (uri, body, set, may_stream) in cases {
        for stream in [true, false] {
            if stream && !may_stream {
                continue;
            }
            let mut body = body.clone();
            if may_stream {
                body["stream"] = json!(stream);
            }
            let mut r = http::Request::post(uri);
            for (k, v) in set.iter().chain(&[
                ("host", "127.0.0.1:8787"),
                ("accept-encoding", "gzip, br"),
                ("x-zyx-canary", "zyx-value"),
                ("x-codex-turn-metadata", "{\"workspaces\":{}}"),
                // A second value of a listed name that fails its rule.
                ("x-codex-window-id", "/Users/zyx/r"),
            ]) {
                r = r.header(*k, *v);
            }
            let resp = p
                .router()
                .oneshot(r.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "{uri} {stream}");
            axum::body::to_bytes(resp.into_body(), 1 << 22)
                .await
                .unwrap();
            want.push((uri, set));
        }
    }
    let sent = tap.headers.lock().unwrap();
    assert_eq!(sent.len(), want.len());
    for (h, (uri, set)) in sent.iter().zip(want) {
        let mut names: Vec<&str> = set.iter().map(|(k, _)| *k).collect();
        names.sort_unstable();
        names.dedup();
        // Every name of the set, plus `accept-encoding: identity`.
        assert_eq!(h.keys().count(), names.len() + 1, "{uri}");
        for (k, v) in set {
            assert!(
                h.get_all(*k).iter().any(|got| got == *v),
                "{uri}: {k} arrives with its value"
            );
        }
        assert_eq!(h.get_all("x-codex-window-id").iter().count(), {
            set.iter()
                .filter(|(k, _)| *k == "x-codex-window-id")
                .count()
        });
        assert_eq!(h["accept-encoding"], "identity", "{uri}");
        for gone in ["host", "x-zyx-canary", "x-codex-turn-metadata"] {
            assert!(!h.contains_key(gone), "{uri}: {gone}");
        }
        assert!(
            h.values()
                .all(|v| !String::from_utf8_lossy(v.as_bytes()).contains("/Users/zyx")),
            "{uri}: no path value"
        );
    }
}

/// M8 spec §20 amendment 2026-10-11 (F2), brief test 2: a streamed request
/// on each wire is forwarded with the placeholder (the request path is
/// shared), and the answer is relayed and restored.
#[tokio::test]
async fn streamed_requests_forward_the_placeholder_on_each_wire() {
    use crate::config::BinaryMode;
    use crate::handler_tests::parts::{P, bodies, no_part_left, object_placeholder, scripted};

    for (uri, wire, body, n) in bodies(true) {
        let (p, up) = scripted(FakeHost::new(), BinaryMode::Placeholder);
        let (status, bytes) = call(&p, uri, body, &[("x-inumaki-client", CLIENT)]).await;
        assert_eq!(status, 200, "{uri}");
        let out = String::from_utf8(up.recorded()[0].1.clone()).unwrap();
        assert_eq!(out.matches(&object_placeholder(wire)).count(), n, "{uri}");
        no_part_left(&out);
        assert!(!out.contains(EMAIL), "{uri}");
        let v = visible(wire, &bytes);
        assert!(v.error.is_none(), "{uri}: the stream completed");
        assert!(
            v.text.contains(EMAIL) && v.text.contains(P),
            "{uri}: the echo is relayed and restored: {}",
            v.text
        );
    }
}

/// Per-request timing on streams (M8 spec §20, amendment 2026-10-12, Part
/// 2): the driver completes the sample the request started, once, however
/// the stream ends, and a check route takes none.
mod timing {
    use super::*;

    fn window(p: &crate::Proxy) -> u64 {
        p.inner.status.timing_body().window
    }

    fn stream_body() -> Value {
        json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "hi"}]})
    }

    /// A streamed answer records one sample, with `first_byte` and
    /// `provider` set; `local` is the sum with the driver's `restore`.
    #[tokio::test]
    async fn a_streamed_answer_records_one_sample_with_provider_and_restore() {
        let (p, _) = scripted(FakeHost::new(), Script(vec![Step::EchoUserText]));
        let msg = format!("Bitte an {NAME}, {EMAIL}");
        let (uri, wire, body) = routes(&msg).remove(0);
        let (s, bytes) = call(&p, uri, body, &[("x-inumaki-client", CLIENT)]).await;
        assert_eq!(s, 200);
        assert_eq!(visible(wire, &bytes).text, msg);
        assert!(permits_back(&p).await);
        let b = p.inner.status.timing_body();
        assert_eq!(b.window, 1, "one sample per stream");
        let t = b.last.unwrap();
        let (first_byte, provider) = (t.first_byte_ms.unwrap(), t.provider_ms.unwrap());
        assert!(first_byte <= provider, "{first_byte} > {provider}");
        // Each field is truncated to whole milliseconds on its own.
        let sum = t.read_ms + t.queue_ms + t.scan_ms + t.engine_ms + t.closure_ms + t.restore_ms;
        assert!(t.local_ms.abs_diff(sum) <= 6, "{t:?}");
        assert!(t.total_ms >= provider, "{t:?}");
    }

    /// An aborted stream (an upstream cut, a panicking body) records one
    /// sample too, and the route's `failing` state is unchanged.
    #[tokio::test]
    async fn an_aborted_stream_records_one_sample() {
        for panics in [false, true] {
            let p = proxy(FakeHost::new(), Arc::new(Cut(panics)));
            let (s, bytes) = call(&p, "/anthropic/v1/messages", stream_body(), &[]).await;
            assert_eq!(s, 200);
            assert_eq!(
                visible(Wire::Messages, &bytes).error.as_deref(),
                Some("api_error"),
                "panics={panics}"
            );
            assert!(permits_back(&p).await);
            let b = p.inner.status.timing_body();
            assert_eq!(b.window, 1, "panics={panics}: one sample");
            let t = b.last.unwrap();
            assert!(
                t.first_byte_ms.is_some() && t.provider_ms.is_some(),
                "panics={panics}: {t:?}"
            );
        }
    }

    /// A check-route stream records no sample, normal or aborted.
    #[tokio::test]
    async fn a_check_route_stream_records_no_sample() {
        use crate::check::CheckId;
        use crate::testing::CHECK_DS;
        let (p, _) = scripted(FakeHost::new(), Script(vec![Step::EchoUserText]));
        let id = "0123456789abcdef0123456789abcdef";
        p.check_routes().register(
            CheckId::from_hex(id).unwrap(),
            CHECK_DS,
            Script(vec![Step::EchoUserText]),
            Duration::from_secs(60),
        );
        let (s, bytes) = call(
            &p,
            &format!("/check/{id}/anthropic/v1/messages"),
            stream_body(),
            &[("x-api-key", "inumaki-check-dummy")],
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(visible(Wire::Messages, &bytes).text, "hi");
        assert!(permits_back(&p).await);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(window(&p), 0, "a check route is not sampled");
    }

    /// The stream's `proxy served` line leaves off the answer-side fields
    /// (the stream is not over yet); `proxy stream timing` carries all of
    /// them, with the route only. Neither line holds a canary.
    #[tokio::test]
    async fn stream_log_lines_carry_the_split_and_no_canary() {
        let timing = crate::memo_tests::TimingLines::open();
        let logs = crate::memo_tests::LocalLogs::open();
        let (p, _) = scripted(FakeHost::new(), Script(vec![Step::EchoUserText]));
        let msg = format!("Bitte an {NAME}, {EMAIL}");
        let (uri, _, body) = routes(&msg).remove(0);
        let extra = [
            ("x-inumaki-client", CLIENT),
            ("x-inumaki-session", "sess-canary-zyx"),
            ("authorization", "Bearer zyx-secret"),
        ];
        let (s, _) = call(&p, uri, body, &extra).await;
        assert_eq!(s, 200);
        assert!(permits_back(&p).await);
        let logs = logs.close();
        let lines = timing.close();
        let served = logs
            .lines()
            .find(|l| l.contains("proxy served"))
            .unwrap_or_else(|| panic!("no served line: {logs:?}"));
        for k in [
            "read_ms=",
            "queue_ms=",
            "scan_ms=",
            "engine_ms=",
            "closure_ms=",
            "project_ms=",
            "first_byte_ms=",
        ] {
            assert!(served.contains(k), "{k}: {served}");
        }
        for k in ["restore_ms=", "local_ms=", "provider_ms="] {
            assert!(
                !served.contains(k),
                "a stream's served line has {k}: {served}"
            );
        }
        assert!(lines.lines().count() >= 1, "no timing line: {lines:?}");
        for line in lines.lines() {
            for k in [
                "route=",
                "total_ms=",
                "read_ms=",
                "queue_ms=",
                "scan_ms=",
                "engine_ms=",
                "closure_ms=",
                "project_ms=",
                "first_byte_ms=",
                "provider_ms=",
                "restore_ms=",
                "local_ms=",
            ] {
                assert!(line.contains(k), "{k}: {line}");
            }
            assert!(!line.contains("endpoint="), "route template only: {line}");
        }
        let all = format!("{logs} {lines} {p:?} {:?}", p.inner.status.timing_body());
        for needle in [EMAIL, NAME, CLIENT, "sess-canary-zyx", "zyx-secret"] {
            assert!(!all.contains(needle), "{needle} in logs or Debug");
        }
    }
}
