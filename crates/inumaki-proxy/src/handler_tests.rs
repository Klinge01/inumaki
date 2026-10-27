//! Spec §15 test 2 (HTTP part): nothing reaches the upstream on any
//! refusal; plus the commit rule, the header rules on the wire, and scan
//! admission.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use http::{Request, StatusCode};
use tower::ServiceExt;

use crate::host::{HostBlock, HostError, ProxyEvent, ProxyHost, RefusedVerdict, Scope};
use crate::routes::UpstreamId;
use crate::testing::{EMAIL, FakeHost, Mode};
use crate::upstream::{Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};

/// A canary no response, log line, or `Debug` may carry.
const CANARY_UA: &str = "ua-canary-zyx";
const CLIENT_VALUE: &str = "client-value";

type Case<'a> = (&'a str, Vec<u8>, Vec<(&'a str, &'a str)>, u16);
type Sent = (UpstreamId, String, Vec<u8>, http::HeaderMap);

/// Records what the pipeline sent; answers with a scripted status or error.
pub(crate) struct Recording {
    pub sent: Mutex<Vec<Sent>>,
    pub answer: Mutex<Result<StatusCode, UpstreamError>>,
    /// The answer's text (`ok` by default).
    pub text: Mutex<String>,
    /// The `content-encoding` the answer claims (`identity` by default).
    pub encoding: Mutex<&'static str>,
}

impl Default for Recording {
    fn default() -> Self {
        Recording {
            sent: Mutex::new(Vec::new()),
            answer: Mutex::new(Ok(StatusCode::OK)),
            text: Mutex::new("ok".into()),
            encoding: Mutex::new("identity"),
        }
    }
}

impl Upstream for Recording {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        self.sent.lock().unwrap().push((
            req.upstream,
            req.path_and_query.clone(),
            req.body.to_vec(),
            req.headers.clone(),
        ));
        let answer = *self.answer.lock().unwrap();
        let encoding = *self.encoding.lock().unwrap();
        let text = self.text.lock().unwrap().clone();
        Box::pin(async move {
            let status = answer?;
            let body = serde_json::json!({"id": "m", "type": "message", "role": "assistant",
                "content": [{"type": "text", "text": text}]})
            .to_string();
            let mut headers = http::HeaderMap::new();
            headers.insert("retry-after", "7".parse().unwrap());
            headers.insert("content-encoding", encoding.parse().unwrap());
            headers.insert("x-inumaki-verdict", "spoofed".parse().unwrap());
            if status.is_redirection() {
                headers.insert("location", "https://elsewhere.invalid/x".parse().unwrap());
            }
            Ok(UpstreamResponse {
                status,
                headers,
                body: Box::pin(futures::stream::once(async move {
                    Ok(bytes::Bytes::from(body))
                })),
            })
        })
    }
}

fn cfg_of(host: &Arc<FakeHost>) -> crate::ProxyConfig {
    crate::pipeline::test_shared(host.clone()).cfg.clone()
}

pub(crate) fn proxy(host: Arc<FakeHost>, up: Arc<Recording>) -> crate::Proxy {
    crate::Proxy::with_upstream(
        cfg_of(&host),
        host,
        zeroize::Zeroizing::new(CLIENT_VALUE.into()),
        up,
    )
}

async fn send(
    p: &crate::Proxy,
    method: &str,
    uri: &str,
    body: impl Into<Vec<u8>>,
    extra: &[(&str, &str)],
) -> http::Response<Body> {
    let mut r = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    for (k, v) in extra {
        r = r.header(*k, *v);
    }
    p.router()
        .oneshot(r.body(Body::from(body.into())).unwrap())
        .await
        .unwrap()
}

async fn post(
    p: &crate::Proxy,
    uri: &str,
    body: impl Into<Vec<u8>>,
    extra: &[(&str, &str)],
) -> http::Response<Body> {
    send(p, "POST", uri, body, extra).await
}

async fn text(r: http::Response<Body>) -> String {
    let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    String::from_utf8_lossy(&b).into_owned()
}

fn user_body() -> String {
    format!(r#"{{"model":"m","messages":[{{"role":"user","content":"{EMAIL}"}}]}}"#)
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn status_json(p: &crate::Proxy) -> serde_json::Value {
    serde_json::to_value(p.status()).unwrap()
}

#[tokio::test]
async fn refusals_send_nothing_upstream() {
    let host = FakeHost::new();
    let up = Arc::new(Recording::default());
    let p = proxy(host.clone(), up.clone());
    let user = user_body().into_bytes();
    let bomb = gzip(&vec![b' '; 4 << 20]); // 4 MiB decoded, over the 1 MiB test limit
    let none: Vec<(&str, &str)> = vec![];
    let cases: Vec<Case> = vec![
        (
            "/anthropic/v1/messages/batches",
            user.clone(),
            none.clone(),
            404,
        ),
        ("/openai/v1/files", user.clone(), none.clone(), 404),
        ("/anthropic/v1/%6Dessages", user.clone(), none.clone(), 404),
        (
            "/anthropic/v1/messages?x=1",
            user.clone(),
            none.clone(),
            400,
        ),
        (
            "/anthropic/v1/messages?beta=true&x=1",
            user.clone(),
            none.clone(),
            400,
        ),
        (
            "/anthropic/v1/messages",
            b"{\"a\":1,\"a\":2}".to_vec(),
            none.clone(),
            400,
        ),
        (
            "/anthropic/v1/messages",
            b"not json".to_vec(),
            none.clone(),
            400,
        ),
        (
            "/anthropic/v1/messages",
            user.clone(),
            vec![("content-encoding", "br")],
            400,
        ),
        (
            "/anthropic/v1/messages",
            user.clone(),
            vec![("content-encoding", "gzip")],
            400,
        ),
        (
            "/anthropic/v1/messages",
            bomb,
            vec![("content-encoding", "gzip")],
            413,
        ),
        (
            "/anthropic/v1/messages",
            vec![b'a'; (1 << 20) + 1],
            none.clone(),
            413,
        ),
        ("/codex/models", Vec::new(), none.clone(), 404),
        ("/codex/anything/else", Vec::new(), none.clone(), 404),
    ];
    for (uri, body, extra, status) in cases {
        let headers = [
            extra.as_slice(),
            &[
                ("user-agent", CANARY_UA),
                ("authorization", "Bearer zyx-secret"),
            ],
        ]
        .concat();
        let r = post(&p, uri, body, &headers).await;
        assert_eq!(r.status(), status, "{uri}");
        let b = text(r).await;
        for leak in ["zyx", CANARY_UA, "x=1", "secret"] {
            assert!(!b.contains(leak), "{uri}: {leak} in {b}");
        }
    }
    // Engine failure, then a privacy block.
    let user = String::from_utf8(user).unwrap();
    *host.fail_engine.lock().unwrap() = true;
    assert_eq!(
        post(&p, "/anthropic/v1/messages", user.clone(), &[])
            .await
            .status(),
        503
    );
    *host.fail_engine.lock().unwrap() = false;
    *host.mode.lock().unwrap() = Mode::Block;
    let blocked = r#"{"model":"m","messages":[{"role":"user","content":"ask Sperrwort now"}]}"#;
    let r = post(&p, "/anthropic/v1/messages", blocked, &[]).await;
    assert_eq!(r.status(), 451);
    assert!(!text(r).await.contains("Sperrwort"));
    assert!(
        up.sent.lock().unwrap().is_empty(),
        "the upstream saw a request"
    );
    // The refusal was recorded (kinds and checks only); nothing was released.
    let events = host.events.lock().unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        ProxyEvent::Refused {
            verdict: RefusedVerdict::Blocked,
            ..
        }
    )));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ProxyEvent::Released { .. }))
    );
    drop(events);
    // `GET /v1/proxy` lists the Codex route; the 451 counted once.
    let s = status_json(&p);
    assert_eq!(s["routes"][2]["prefix"], "/codex");
    assert_eq!(s["routes"][0]["blocked"], 1);
    assert_eq!(s["routes"][0]["last_error"]["class"], "privacy_block");
}

#[tokio::test]
async fn a_forwarded_request_carries_no_original_and_no_inumaki_header() {
    let host = FakeHost::new();
    let up = Arc::new(Recording::default());
    let p = proxy(host.clone(), up.clone());
    // Gzip in, uncompressed out.
    let r = post(
        &p,
        "/anthropic/v1/messages?beta=true",
        gzip(user_body().as_bytes()),
        &[
            ("content-encoding", "gzip"),
            ("x-inumaki-client", CLIENT_VALUE),
            ("x-inumaki-session", "sess-canary-zyx"),
            ("x-api-key", "sk-ant-oat01-tok"),
            ("accept-encoding", "gzip"),
            ("user-agent", CANARY_UA),
        ],
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-inumaki-verdict"], "pass"); // not the upstream's
    assert_eq!(r.headers().get_all("x-inumaki-verdict").iter().count(), 1);
    assert_eq!(r.headers()["x-inumaki-replacements"], "1");
    assert!(r.headers().contains_key("x-inumaki-latency-ms"));
    assert_eq!(r.headers()["retry-after"], "7");
    assert!(!r.headers().contains_key("content-encoding"));
    assert!(text(r).await.contains("\"ok\""));
    let sent = up.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    let (upstream, pq, body, headers) = &sent[0];
    assert_eq!(*upstream, UpstreamId::Anthropic);
    assert_eq!(pq, "/v1/messages?beta=true");
    assert!(!String::from_utf8_lossy(body).contains(EMAIL));
    assert!(serde_json::from_slice::<serde_json::Value>(body).is_ok());
    assert!(
        headers
            .keys()
            .all(|k| !k.as_str().starts_with("x-inumaki-"))
    );
    assert!(!headers.contains_key("x-api-key"));
    assert_eq!(headers["authorization"], "Bearer sk-ant-oat01-tok");
    assert_eq!(headers["accept-encoding"], "identity");
    assert!(!headers.contains_key("content-encoding"));
    drop(sent);
    // The OAuth move shows in the status counters, and no value does.
    let s = status_json(&p);
    assert_eq!(s["oauth"]["anthropic"]["translated"], 1);
    assert_eq!(s["clients"][0]["client"], "other");
    let all = format!("{p:?} {:?}", p.status());
    for needle in [CLIENT_VALUE, CANARY_UA, "sk-ant-oat", "sess-canary-zyx"] {
        assert!(!all.contains(needle), "{needle} in Debug");
    }
    assert!(!s.to_string().contains(CANARY_UA));
}

#[tokio::test]
async fn nothing_is_committed_unless_the_upstream_took_the_request() {
    for (answer, committed, released, code) in [
        (Ok(StatusCode::MOVED_PERMANENTLY), false, false, 502),
        (Ok(StatusCode::FOUND), false, false, 502),
        (Ok(StatusCode::TEMPORARY_REDIRECT), false, false, 502),
        (Ok(StatusCode::PERMANENT_REDIRECT), false, false, 502),
        (Err(UpstreamError::Unreachable), false, false, 502),
        (Err(UpstreamError::Timeout), false, false, 504),
        (Ok(StatusCode::SERVICE_UNAVAILABLE), false, false, 503),
        (Ok(StatusCode::TOO_MANY_REQUESTS), false, false, 429),
        (Ok(StatusCode::BAD_REQUEST), true, false, 400),
        (Ok(StatusCode::OK), true, true, 200),
    ] {
        let host = FakeHost::new();
        let up = Arc::new(Recording::default());
        *up.answer.lock().unwrap() = answer;
        let p = proxy(host.clone(), up.clone());
        let r = post(&p, "/anthropic/v1/messages", user_body(), &[]).await;
        assert_eq!(r.status(), code, "{answer:?}");
        // A redirect is an upstream error: its `Location` never reaches the
        // client, whose own client would re-send the original body there.
        assert!(!r.headers().contains_key("location"), "{answer:?}");
        if answer.is_ok_and(|s| s.is_redirection()) {
            assert!(!text(r).await.contains("elsewhere"));
            assert_eq!(status_json(&p)["routes"][0]["state"], "failing");
        }
        assert_eq!(up.sent.lock().unwrap().len(), 1);
        let entries = status_json(&p)["incremental_cache"]["entries"]
            .as_u64()
            .unwrap();
        assert_eq!(entries > 0, committed, "{answer:?}");
        let was_released = host
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ProxyEvent::Released { .. }));
        assert_eq!(was_released, released, "{answer:?}");
    }
}

#[tokio::test]
async fn a_withheld_tool_result_is_forwarded_as_the_placeholder_and_recorded_once() {
    let host = FakeHost::new();
    *host.mode.lock().unwrap() = Mode::Block;
    let up = Arc::new(Recording::default());
    let p = proxy(host.clone(), up.clone());
    let body = r#"{"model":"m","messages":[{"role":"user","content":[
        {"type":"tool_result","tool_use_id":"t1","content":"ask Sperrwort now"}]}]}"#;
    assert_eq!(
        post(&p, "/anthropic/v1/messages", body, &[]).await.status(),
        200
    );
    let sent = up.sent.lock().unwrap();
    let out = String::from_utf8_lossy(&sent[0].2).into_owned();
    assert!(
        out.contains("tool result withheld") && !out.contains("Sperrwort"),
        "{out}"
    );
    drop(sent);
    let events = host.events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, ProxyEvent::Withheld { .. }))
            .count(),
        1
    );
    drop(events);
    assert_eq!(status_json(&p)["routes"][0]["blocked"], 1);
}

#[tokio::test]
async fn model_lists_forward_with_an_empty_body_and_no_inumaki_header() {
    let host = FakeHost::new();
    let up = Arc::new(Recording::default());
    let p = proxy(host, up.clone());
    let r = send(
        &p,
        "GET",
        "/openai/v1/models/gpt-x",
        "client text that is not forwarded",
        &[("x-inumaki-client", CLIENT_VALUE)],
    )
    .await;
    assert_eq!(r.status(), 200);
    {
        let sent = up.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].2.is_empty());
        assert!(!sent[0].3.contains_key("x-inumaki-client"));
    }
    // A query outside the allowlist is refused here too.
    assert_eq!(
        send(&p, "GET", "/openai/v1/models?x=1", "", &[])
            .await
            .status(),
        400
    );
    assert_eq!(up.sent.lock().unwrap().len(), 1);
}

/// A host that parks the first `engine` call until released, so a scan can be
/// held open while other requests arrive.
struct Gate {
    inner: Arc<FakeHost>,
    armed: AtomicBool,
    entered: AtomicBool,
    release: AtomicBool,
    /// Park the first `scan_known` call (the answer-side tripwire) too.
    park_answer: AtomicBool,
    answer_entered: AtomicBool,
    answer_calls: AtomicUsize,
}

impl Gate {
    fn new(inner: Arc<FakeHost>, armed: bool) -> Arc<Gate> {
        Arc::new(Gate {
            inner,
            armed: AtomicBool::new(armed),
            entered: AtomicBool::new(false),
            release: AtomicBool::new(false),
            park_answer: AtomicBool::new(false),
            answer_entered: AtomicBool::new(false),
            answer_calls: AtomicUsize::new(0),
        })
    }
}

impl ProxyHost for Gate {
    fn engine(&self, p: &str) -> Result<Arc<inumaki_core::engine::Engine>, HostError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered.store(true, Ordering::SeqCst);
            for _ in 0..2000 {
                if self.release.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        self.inner.engine(p)
    }
    fn policy(&self, p: &str) -> Result<Arc<inumaki_core::policy::Profile>, HostError> {
        self.inner.policy(p)
    }
    fn dictionary(&self) -> Result<Arc<dyn inumaki_core::detect::Detector>, HostError> {
        self.inner.dictionary()
    }
    fn scan_known(
        &self,
        t: &[String],
    ) -> Result<Vec<(String, inumaki_core::span::EntityKind, u32)>, HostError> {
        self.answer_calls.fetch_add(1, Ordering::SeqCst);
        if self.park_answer.swap(false, Ordering::SeqCst) {
            self.answer_entered.store(true, Ordering::SeqCst);
            for _ in 0..2000 {
                if self.release.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        self.inner.scan_known(t)
    }
    fn identity(&self) -> Vec<(inumaki_core::span::EntityKind, zeroize::Zeroizing<String>)> {
        self.inner.identity()
    }
    fn dataset_token(
        &self,
        k: &inumaki_core::span::EntityKind,
        v: &str,
    ) -> Result<Option<(String, zeroize::Zeroizing<String>)>, HostError> {
        self.inner.dataset_token(k, v)
    }
    fn resolve(
        &self,
        t: &[String],
        s: &Scope,
    ) -> Result<
        Vec<(
            String,
            inumaki_core::span::EntityKind,
            zeroize::Zeroizing<String>,
        )>,
        HostError,
    > {
        self.inner.resolve(t, s)
    }
    fn released(&self, d: &[u8; 32]) -> bool {
        self.inner.released(d)
    }
    fn scan_definitions(
        &self,
        t: &[String],
    ) -> Result<Vec<(inumaki_core::span::EntityKind, u32)>, HostError> {
        self.inner.scan_definitions(t)
    }
    fn sanitize_dataset(&self, d: &str, b: Vec<String>) -> Result<Vec<HostBlock>, HostError> {
        self.inner.sanitize_dataset(d, b)
    }
    fn record(&self, e: ProxyEvent) {
        self.inner.record(e)
    }
}

/// Memory admission: scans are weighted by decoded size against a fixed
/// budget. With the budget sized for one max-size body, a second max-size
/// body is refused busy while the first is being scanned, and every permit
/// comes back afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_max_size_bodies_cannot_be_scanned_at_once() {
    let fake = FakeHost::new();
    let gate = Gate::new(fake.clone(), true);
    let mut cfg = cfg_of(&fake);
    cfg.max_request_bytes = 64 * 1024;
    let budget = cfg.max_request_bytes * crate::config::SCAN_WEIGHT;
    let up = Arc::new(Recording::default());
    let p = crate::Proxy::build(
        cfg,
        gate.clone(),
        zeroize::Zeroizing::new(CLIENT_VALUE.into()),
        up.clone(),
        budget,
    )
    .unwrap();
    // A node-heavy body just under the limit: thousands of tiny text blocks.
    let block = r#"{"type":"text","text":"a b"},"#;
    let mut body = String::from(r#"{"model":"m","messages":[{"role":"user","content":["#);
    while body.len() + block.len() + 8 < 60 * 1024 {
        body.push_str(block);
    }
    body.push_str(r#"{"type":"text","text":"end"}]}]}"#);
    assert!(body.len() > 32 * 1024 && body.len() <= 64 * 1024);

    let first = {
        let (router, body) = (p.router(), body.clone());
        tokio::spawn(async move {
            router
                .oneshot(
                    Request::post("/anthropic/v1/messages")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
        })
    };
    for _ in 0..400 {
        if gate.entered.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        gate.entered.load(Ordering::SeqCst),
        "the first scan never started"
    );
    assert!(
        p.inner.scan.available_permits() < budget,
        "the first scan holds permits"
    );

    let second = post(&p, "/anthropic/v1/messages", body.clone(), &[]).await;
    assert_eq!(second.status(), 503);
    assert!(text(second).await.contains("busy"));
    assert!(
        up.sent.lock().unwrap().is_empty(),
        "a refused body reached the upstream"
    );

    gate.release.store(true, Ordering::SeqCst);
    assert_eq!(first.await.unwrap().status(), 200);
    assert_eq!(
        p.inner.scan.available_permits(),
        budget,
        "permits were not released"
    );
    // Released: the same body is admitted again.
    assert_eq!(
        post(&p, "/anthropic/v1/messages", body, &[]).await.status(),
        200
    );
    assert_eq!(p.inner.scan.available_permits(), budget);
    // Busy is a limit, not a route failure.
    assert_eq!(status_json(&p)["routes"][0]["state"], "ok");
}

/// The relay cannot decode a coded answer (we ask for `identity`), so it
/// refuses one rather than relay bytes it cannot restore (Task 9 revisits).
#[tokio::test]
async fn a_coded_upstream_answer_is_refused_not_relayed() {
    let host = FakeHost::new();
    let up = Arc::new(Recording::default());
    *up.encoding.lock().unwrap() = "gzip";
    let p = proxy(host.clone(), up.clone());
    let r = post(&p, "/anthropic/v1/messages", user_body(), &[]).await;
    assert_eq!(r.status(), 502);
    assert!(!r.headers().contains_key("content-encoding"));
    assert_eq!(status_json(&p)["incremental_cache"]["entries"], 0);
    // Model lists too.
    assert_eq!(
        send(&p, "GET", "/openai/v1/models", "", &[]).await.status(),
        502
    );
}

#[tokio::test]
async fn odd_paths_and_methods_are_refused_and_send_nothing() {
    let host = FakeHost::new();
    let up = Arc::new(Recording::default());
    let p = proxy(host, up.clone());
    let user = user_body();
    for (method, uri) in [
        ("POST", "//anthropic/v1/messages"),
        ("POST", "/anthropic//v1/messages"),
        ("POST", "/anthropic/v1/messages/"),
        ("POST", "/anthropic/v1/../v1/messages"),
        ("POST", "/anthropic/v1/messages/.."),
        ("GET", "/anthropic/v1/models/.."),
        ("HEAD", "/anthropic/v1/messages"),
        ("PUT", "/anthropic/v1/messages"),
        ("OPTIONS", "/anthropic/v1/messages"),
        ("DELETE", "/openai/v1/responses"),
        ("GET", "/anthropic/v1/messages"),
        ("POST", "/anthropic"),
        ("POST", "/anthropic/"),
    ] {
        let r = send(&p, method, uri, user.clone(), &[]).await;
        assert!(
            matches!(r.status().as_u16(), 404 | 405),
            "{method} {uri}: {}",
            r.status()
        );
        let b = text(r).await;
        assert!(!b.contains("zyx"), "{method} {uri}");
    }
    assert!(up.sent.lock().unwrap().is_empty());
}

/// The answer-side scan takes weighted permits from the same budget and
/// WAITS (the request has left): with a budget that fits one answer, two
/// large answers are scanned one after the other, and every permit returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_are_scanned_one_at_a_time_within_the_budget() {
    let fake = FakeHost::new();
    let gate = Gate::new(fake.clone(), false);
    gate.park_answer.store(true, Ordering::SeqCst);
    let mut cfg = cfg_of(&fake);
    cfg.max_request_bytes = 8192;
    let budget = cfg.max_request_bytes * crate::config::SCAN_WEIGHT;
    let up = Arc::new(Recording::default());
    // About 6 KiB: one answer takes most of the budget, two do not fit.
    *up.text.lock().unwrap() = "a".repeat(6000);
    let p = crate::Proxy::build(
        cfg,
        gate.clone(),
        zeroize::Zeroizing::new(CLIENT_VALUE.into()),
        up.clone(),
        budget,
    )
    .unwrap();
    let spawn_one = || {
        let router = p.router();
        tokio::spawn(async move {
            router
                .oneshot(
                    Request::post("/anthropic/v1/messages")
                        .body(Body::from(user_body()))
                        .unwrap(),
                )
                .await
                .unwrap()
        })
    };
    let first = spawn_one();
    for _ in 0..400 {
        if gate.answer_entered.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        gate.answer_entered.load(Ordering::SeqCst),
        "no answer scan started"
    );
    assert!(
        p.inner.scan.available_permits() < budget / 2,
        "the answer holds permits"
    );
    let second = spawn_one();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The second answer waits for permits; its scan has not started.
    assert!(!second.is_finished());
    assert_eq!(gate.answer_calls.load(Ordering::SeqCst), 1);
    gate.release.store(true, Ordering::SeqCst);
    assert_eq!(first.await.unwrap().status(), 200);
    assert_eq!(second.await.unwrap().status(), 200);
    assert_eq!(gate.answer_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        p.inner.scan.available_permits(),
        budget,
        "permits were not released"
    );
}

/// Takes every free scan permit when the request is sent, so the answer
/// finds the budget full (another request's scan holding it).
struct Hogging {
    inner: Recording,
    scan: std::sync::OnceLock<Arc<tokio::sync::Semaphore>>,
    held: Mutex<Option<tokio::sync::OwnedSemaphorePermit>>,
}

impl Upstream for Hogging {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        if let Some(s) = self.scan.get() {
            let n = u32::try_from(s.available_permits()).unwrap();
            *self.held.lock().unwrap() = Arc::clone(s).try_acquire_many_owned(n).ok();
        }
        self.inner.send(req)
    }
}

/// The answer-side wait for scan permits is bounded (commit 4f49945): with
/// the budget held past the wait, the client gets the fixed `503 resource_limit` ("the request was sent"),
/// none of the answer is relayed, and the answer side holds no permit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_that_cannot_get_scan_permits_in_time_is_busy_and_not_relayed() {
    let fake = FakeHost::new();
    let mut cfg = cfg_of(&fake);
    cfg.max_request_bytes = 8192;
    // The wait is `min(upstream_timeout, 10 s)`.
    cfg.upstream_timeout = Duration::from_millis(200);
    let budget = cfg.max_request_bytes * crate::config::SCAN_WEIGHT;
    let up = Arc::new(Hogging {
        inner: Recording::default(),
        scan: std::sync::OnceLock::new(),
        held: Mutex::new(None),
    });
    *up.inner.text.lock().unwrap() = "relay-canary-text".into();
    let p = crate::Proxy::build(
        cfg,
        fake.clone(),
        zeroize::Zeroizing::new(CLIENT_VALUE.into()),
        up.clone(),
        budget,
    )
    .unwrap();
    let _ = up.scan.set(Arc::clone(&p.inner.scan));
    let r = p
        .router()
        .oneshot(
            Request::post("/anthropic/v1/messages")
                .body(Body::from(user_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("relay-canary"), "{text}");
    assert!(text.contains("resource_limit"), "{text}");
    assert!(
        text.contains(
            "The request was sent; the answer could not be checked in time and was withheld. Retrying will resend it."
        ),
        "{text}"
    );
    assert!(!text.contains("busy"), "{text}");
    assert_eq!(up.inner.sent.lock().unwrap().len(), 1, "the request left");
    assert!(up.held.lock().unwrap().is_some(), "the budget was held");
    *up.held.lock().unwrap() = None;
    assert_eq!(p.inner.scan.available_permits(), budget);
}

/// M8 spec §20 amendment 2026-10-11 (F2): in `placeholder` mode every binary
/// part outside tool results is replaced by one fixed text part, and no
/// byte of the part leaves. Canary values are synthetic.
pub(crate) mod parts {
    use super::*;
    use crate::config::BinaryMode;
    use crate::routes::Wire;
    use crate::scripted::{Script, ScriptedUpstream, Step};
    use serde_json::{Value, json};

    /// The placeholder as the spec words it, spelled out here rather than
    /// taken from the constant, so a drifted constant fails.
    pub(crate) const P: &str = "[inumaki: an attachment (image, document, audio, or file) was removed here and not sent to the model.]";

    /// One marker per field a part carries: payload, URL, `file_id`,
    /// filename, title, `media_type`, and the data-URI prefix.
    pub(crate) const MARKERS: &[&str] = &[
        "ZYXPAYLOAD",
        "zyx-url",
        "ZyxFileId",
        "zyx-filename",
        "ZyxTitle",
        "zyxmedia",
        "data:",
        "DATA:",
    ];

    /// The bytes an object part becomes on `wire`.
    pub(crate) fn object_placeholder(wire: Wire) -> String {
        let ty = if wire == Wire::Responses {
            "input_text"
        } else {
            "text"
        };
        format!(r#"{{"type":"{ty}","text":"{P}"}}"#)
    }

    pub(crate) fn no_part_left(out: &str) {
        for m in MARKERS {
            assert!(!out.contains(m), "{m} left the proxy: {out}");
        }
    }

    pub(crate) fn proxy_in(
        host: Arc<FakeHost>,
        up: Arc<dyn Upstream>,
        mode: BinaryMode,
    ) -> crate::Proxy {
        let mut cfg = cfg_of(&host);
        cfg.binary = mode;
        crate::Proxy::with_upstream(cfg, host, zeroize::Zeroizing::new(CLIENT_VALUE.into()), up)
    }

    pub(crate) fn scripted(
        host: Arc<FakeHost>,
        mode: BinaryMode,
    ) -> (crate::Proxy, Arc<ScriptedUpstream>) {
        let up = Arc::new(ScriptedUpstream::new(Script(vec![Step::EchoUserText])));
        (proxy_in(host, up.clone(), mode), up)
    }

    /// Per wire: the route, a body with a text part holding a synthetic
    /// email and every kind of part the brief names, and the part count.
    pub(crate) fn bodies(stream: bool) -> Vec<(&'static str, Wire, Value, usize)> {
        let mail = format!("Mail an {EMAIL}");
        vec![
            (
                "/anthropic/v1/messages",
                Wire::Messages,
                json!({"model": "m", "stream": stream, "messages": [{"role": "user", "content": [
                    {"type": "text", "text": mail},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/x-zyxmedia", "data": "iVBORZYXPAYLOAD1"}},
                    {"type": "document", "title": "ZyxTitle", "context": "ZyxTitle context",
                        "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBERZYXPAYLOAD2"},
                        "cache_control": {"type": "ephemeral"}}
                ]}]}),
                2,
            ),
            (
                "/openai/v1/chat/completions",
                Wire::Chat,
                json!({"model": "m", "stream": stream, "messages": [{"role": "user", "content": [
                    {"type": "text", "text": mail},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORZYXPAYLOAD3", "detail": "high"}},
                    {"type": "image_url", "image_url": {"url": "https://zyx-url.invalid/a.png"}},
                    {"type": "input_audio", "input_audio": {"data": "UklGRZYXPAYLOAD4", "format": "wav"}},
                    {"type": "file", "file": {"file_data": "data:application/pdf;base64,JVBERZYXPAYLOAD5", "filename": "zyx-filename.pdf"}}
                ]}]}),
                4,
            ),
            (
                "/openai/v1/responses",
                Wire::Responses,
                json!({"model": "m", "stream": stream, "input": [{"type": "message", "role": "user", "content": [
                    {"type": "input_text", "text": mail},
                    {"type": "input_image", "image_url": "https://zyx-url.invalid/b.png", "detail": "auto"},
                    {"type": "input_file", "file_id": "file-ZyxFileId0123456789", "filename": "zyx-filename.pdf"}
                ]}]}),
                2,
            ),
        ]
    }

    /// The `BINARY` count of each `Released` record, in order (0: none).
    pub(crate) fn binary_counts(host: &FakeHost) -> Vec<u32> {
        host.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                ProxyEvent::Released { kinds, .. } => Some(
                    kinds
                        .iter()
                        .filter(|(k, _)| k.label() == "BINARY")
                        .map(|(_, n)| *n)
                        .sum(),
                ),
                _ => None,
            })
            .collect()
    }

    pub(crate) async fn post_json(p: &crate::Proxy, uri: &str, body: &Value) -> (u16, String) {
        let r = post(
            p,
            uri,
            body.to_string(),
            &[("x-inumaki-client", CLIENT_VALUE)],
        )
        .await;
        let s = r.status().as_u16();
        (s, text(r).await)
    }

    /// Brief tests 1 and 9: per wire, the upstream receives the exact
    /// replacement bytes once per part, no field of any part, and the
    /// sibling text tokenized; the released record counts the parts and
    /// carries no field of them, in `Debug` or in its journal payload.
    #[tokio::test]
    async fn each_wire_forwards_the_placeholder_and_nothing_of_the_part() {
        for (uri, wire, body, n) in bodies(false) {
            let host = FakeHost::new();
            let (p, up) = scripted(host.clone(), BinaryMode::Placeholder);
            let (status, answer) = post_json(&p, uri, &body).await;
            assert_eq!(status, 200, "{uri}: {answer}");
            let rec = up.recorded();
            assert_eq!(rec.len(), 1, "{uri}");
            let out = String::from_utf8(rec[0].1.clone()).unwrap();
            assert_eq!(
                out.matches(&object_placeholder(wire)).count(),
                n,
                "{uri}: {out}"
            );
            no_part_left(&out);
            assert!(!out.contains(EMAIL) && out.contains("<EMAIL_"), "{out}");
            let v: Value = serde_json::from_str(&out).unwrap();
            // The text the model sees is the same on every wire.
            let texts = v.to_string().matches(&format!("\"text\":\"{P}\"")).count();
            assert_eq!(texts, n, "{uri}");
            assert_eq!(binary_counts(&host), vec![n as u32], "{uri}");
            for e in host.events.lock().unwrap().iter() {
                let mut shown = format!("{e:?}");
                if let ProxyEvent::Released { kinds, payload, .. } = e {
                    shown.push_str(&String::from_utf8_lossy(payload));
                    for (k, _) in kinds {
                        shown.push_str(k.label());
                    }
                }
                for m in MARKERS {
                    assert!(!shown.contains(m), "{uri}: {m} in a record: {shown}");
                }
                assert!(!shown.contains(P), "{uri}: the placeholder is no leaf");
            }
        }
    }

    /// Brief test 3 (F2 regression): an image in the first user turn no
    /// longer refuses every later turn of the session.
    #[tokio::test]
    async fn an_image_in_an_earlier_turn_is_served() {
        let (p, up) = scripted(FakeHost::new(), BinaryMode::Placeholder);
        let body = json!({"model": "m", "messages": [
            {"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORZYXPAYLOAD"}},
                {"type": "text", "text": "what is this?"}
            ]},
            {"role": "assistant", "content": "I cannot see it."},
            {"role": "user", "content": format!("then write to {EMAIL}")}
        ]});
        let (status, answer) = post_json(&p, "/anthropic/v1/messages", &body).await;
        assert_eq!(status, 200, "{answer}");
        assert!(answer.contains(EMAIL), "the answer is relayed and restored");
        let out = String::from_utf8(up.recorded()[0].1.clone()).unwrap();
        assert_eq!(out.matches(&object_placeholder(Wire::Messages)).count(), 1);
        no_part_left(&out);
    }

    /// Brief test 4: a `system` part, an assistant-message part, and a
    /// data-URI string under an unknown top-level key are replaced; a
    /// text-sourced document is sanitized, not replaced.
    #[tokio::test]
    async fn parts_are_replaced_at_every_position() {
        let (p, up) = scripted(FakeHost::new(), BinaryMode::Placeholder);
        let body = json!({"model": "m",
        "system": [
            {"type": "text", "text": "be brief"},
            {"type": "image", "source": {"type": "url", "url": "https://zyx-url.invalid/sys.png"}}
        ],
        "zyx_unknown": "data:image/png;base64,iVBORZYXPAYLOAD",
        "messages": [
            {"role": "user", "content": [
                {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": format!("schreib an {EMAIL}")}}
            ]},
            {"role": "assistant", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/x-zyxmedia", "data": "iVBORZYXPAYLOAD"}}
            ]},
            {"role": "user", "content": "weiter"}
        ]});
        let (status, answer) = post_json(&p, "/anthropic/v1/messages", &body).await;
        assert_eq!(status, 200, "{answer}");
        let out = String::from_utf8(up.recorded()[0].1.clone()).unwrap();
        assert_eq!(
            out.matches(&object_placeholder(Wire::Messages)).count(),
            2,
            "{out}"
        );
        assert!(out.contains(&format!(r#""zyx_unknown":"{P}""#)), "{out}");
        no_part_left(&out);
        let v: Value = serde_json::from_str(&out).unwrap();
        let doc = &v["messages"][0]["content"][0];
        assert_eq!(doc["type"], "document", "a text document stays");
        let data = doc["source"]["data"].as_str().unwrap();
        assert!(data.starts_with("schreib an <EMAIL_"), "{data}");
    }

    /// Brief test 5 (L63 (3)): a user part and a binary tool result in one
    /// request: the part becomes the text placeholder, the tool result the
    /// decision 18 placeholder; one `Withheld` record and one `Released`
    /// record counting the part.
    #[tokio::test]
    async fn a_user_part_and_a_binary_tool_result_coexist() {
        let host = FakeHost::new();
        let (p, up) = scripted(host.clone(), BinaryMode::Placeholder);
        let body = json!({"model": "m", "messages": [
            {"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORZYXPAYLOAD1"}},
                {"type": "tool_result", "tool_use_id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORZYXPAYLOAD2"}}
                ]}
            ]}
        ]});
        let (status, answer) = post_json(&p, "/anthropic/v1/messages", &body).await;
        assert_eq!(status, 200, "{answer}");
        let out = String::from_utf8(up.recorded()[0].1.clone()).unwrap();
        assert_eq!(out.matches(&object_placeholder(Wire::Messages)).count(), 1);
        assert!(
            out.contains(
                r#""content":"[inumaki: tool result withheld (kinds: BINARY). Nothing was sent.]""#
            ),
            "{out}"
        );
        no_part_left(&out);
        let events = host.events.lock().unwrap();
        let withheld: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ProxyEvent::Withheld { kinds, checks, .. } => Some((kinds.clone(), checks.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(withheld.len(), 1);
        assert_eq!(
            withheld[0].0.iter().map(|k| k.label()).collect::<Vec<_>>(),
            Vec::<&str>::new()
        );
        assert_eq!(withheld[0].1, vec!["Binary".to_string()]);
        drop(events);
        assert_eq!(binary_counts(&host), vec![1]);
    }

    /// Brief test 6: `refuse` keeps today's `400 unsupported_content` and its
    /// one `request`/`unsupported` record; `forward` sends the payload as
    /// received.
    #[tokio::test]
    async fn refuse_and_forward_modes_are_unchanged() {
        let body = json!({"model": "m", "messages": [{"role": "user", "content": [
            {"type": "text", "text": "look"},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORZYXPAYLOAD"}}
        ]}]});
        let host = FakeHost::new();
        let (p, up) = scripted(host.clone(), BinaryMode::Refuse);
        let (status, answer) = post_json(&p, "/anthropic/v1/messages", &body).await;
        assert_eq!(status, 400);
        assert!(answer.contains("unsupported_content"), "{answer}");
        assert!(up.recorded().is_empty(), "nothing left");
        {
            let events = host.events.lock().unwrap();
            assert_eq!(events.len(), 1, "{events:?}");
            assert!(matches!(
                events[0],
                ProxyEvent::Refused {
                    verdict: RefusedVerdict::Unsupported,
                    ..
                }
            ));
        }

        let host = FakeHost::new();
        let (p, up) = scripted(host.clone(), BinaryMode::Forward);
        let (status, _) = post_json(&p, "/anthropic/v1/messages", &body).await;
        assert_eq!(status, 200);
        let out = String::from_utf8(up.recorded()[0].1.clone()).unwrap();
        assert!(out.contains("iVBORZYXPAYLOAD") && !out.contains(P), "{out}");
        assert_eq!(binary_counts(&host), vec![0]);
    }

    /// Brief test 7: three turns of one session. The replacement is a pure
    /// function of the received bytes, so the forwarded history is a stable
    /// prefix; a part counts once, when first sent.
    #[tokio::test]
    async fn resent_parts_forward_the_same_bytes_and_count_once() {
        let host = FakeHost::new();
        let (p, up) = scripted(host.clone(), BinaryMode::Placeholder);
        let image = |d: &str| {
            json!({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": d}})
                .to_string()
        };
        let m1 = format!(
            r#"{{"role":"user","content":[{{"type":"text","text":"Hallo, {EMAIL}"}},{}]}}"#,
            image("iVBORZYXPAYLOADA")
        );
        let m2 = r#"{"role":"assistant","content":"ok"},{"role":"user","content":"weiter"}"#;
        let m3 = format!(
            r#"{{"role":"assistant","content":"ok"}},{{"role":"user","content":[{{"type":"text","text":"und das"}},{}]}}"#,
            image("iVBORZYXPAYLOADB")
        );
        let turns = [
            format!(r#"{{"model":"m","messages":[{m1}]}}"#),
            format!(r#"{{"model":"m","messages":[{m1},{m2}]}}"#),
            format!(r#"{{"model":"m","messages":[{m1},{m2},{m3}]}}"#),
        ];
        for t in &turns {
            let r = post(&p, "/anthropic/v1/messages", t.clone(), &[]).await;
            assert_eq!(r.status(), 200);
        }
        let sent: Vec<String> = up
            .recorded()
            .into_iter()
            .map(|(_, b)| String::from_utf8(b).unwrap())
            .collect();
        let open = |s: &str| s[..s.len() - 2].to_string(); // without `]}`
        assert!(sent[1].starts_with(&open(&sent[0])), "{sent:?}");
        assert!(sent[2].starts_with(&open(&sent[1])), "{sent:?}");
        for s in &sent {
            no_part_left(s);
        }
        assert_eq!(binary_counts(&host), vec![1, 0, 1]);
    }

    /// Brief test 8: a check route replaces the part too and writes no
    /// record. The last assert is a regression guard: `sanitize_check` takes
    /// no session today, so the memo cannot change; should a check route ever
    /// write the session memo, the same part on a normal route afterwards
    /// would no longer count as new.
    #[tokio::test]
    async fn a_check_route_replaces_parts_and_records_nothing() {
        const ID: &str = "0123456789abcdef0123456789abcdef";
        let host = FakeHost::new();
        let (p, _) = scripted(host.clone(), BinaryMode::Placeholder);
        let id = crate::check::CheckId::from_hex(ID).unwrap();
        p.check_routes().register(
            id,
            crate::testing::CHECK_DS,
            Script(vec![Step::EchoUserText]),
            Duration::from_secs(60),
        );
        let body = json!({"model": "m", "max_tokens": 9, "messages": [{"role": "user", "content": [
            {"type": "text", "text": "look"},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORZYXPAYLOAD"}}
        ]}]});
        let r = post(
            &p,
            &format!("/check/{ID}/anthropic/v1/messages"),
            body.to_string(),
            &[("x-api-key", "inumaki-check-dummy")],
        )
        .await;
        assert_eq!(r.status(), 200);
        let rec = p.check_routes().recorded(&id);
        assert_eq!(rec.len(), 1);
        let out = String::from_utf8(rec[0].body.clone()).unwrap();
        assert_eq!(out.matches(&object_placeholder(Wire::Messages)).count(), 1);
        no_part_left(&out);
        assert!(host.events.lock().unwrap().is_empty(), "no record");
        let (status, _) = post_json(&p, "/anthropic/v1/messages", &body).await;
        assert_eq!(status, 200);
        assert_eq!(binary_counts(&host), vec![1], "the memo did not have it");
    }

    /// Fix wave C1: an `image_generation` tool's `input_image_mask` has no
    /// `type` and names an image the provider fetches itself. It sits in a
    /// definition, which is never changed, so an https URL or a file id
    /// refuses the request in `placeholder` and `refuse` mode, and nothing
    /// reaches the upstream.
    #[tokio::test]
    async fn an_image_generation_mask_is_refused() {
        for mask in [
            json!({"image_url": "https://h.example/mask.png"}),
            json!({"file_id": "file-ZyxMask0123456789"}),
        ] {
            let body = json!({"model": "m", "input": "draw a cat",
                "tools": [{"type": "image_generation", "input_image_mask": mask}]});
            for mode in [BinaryMode::Placeholder, BinaryMode::Refuse] {
                let (p, up) = scripted(FakeHost::new(), mode);
                let (status, answer) = post_json(&p, "/openai/v1/responses", &body).await;
                assert_eq!(status, 400, "{mode:?}: {answer}");
                assert!(answer.contains("unsupported_content"), "{answer}");
                assert!(up.recorded().is_empty(), "{mode:?}: nothing left");
            }
        }
    }
}

/// Per-request timing (M8 spec §20, amendment 2026-10-12, Part 2): which
/// requests take a sample, what its fields are, and what the log lines say.
mod timing {
    use super::*;

    fn window(p: &crate::Proxy) -> u64 {
        p.inner.status.timing_body().window
    }

    /// A forwarded request takes one sample, with the upstream's fields set.
    #[tokio::test]
    async fn a_forwarded_request_takes_one_sample_with_provider_fields() {
        let host = FakeHost::new();
        let p = proxy(host, Arc::new(Recording::default()));
        assert_eq!(window(&p), 0);
        let r = post(&p, "/anthropic/v1/messages", user_body(), &[]).await;
        assert_eq!(r.status(), 200);
        let b = p.inner.status.timing_body();
        assert_eq!(b.window, 1);
        assert!(b.last_at.is_some());
        let t = b.last.unwrap();
        let (first_byte, provider) = (t.first_byte_ms.unwrap(), t.provider_ms.unwrap());
        assert!(first_byte <= provider, "{first_byte} > {provider}");
        assert!(t.total_ms >= t.local_ms.saturating_sub(6), "{t:?}");
        assert_eq!(b.p50, b.last, "one sample is its own median");
    }

    /// A refusal after sanitizing records a sample, with `first_byte` and
    /// `provider` null; the engine ran for it.
    #[tokio::test]
    async fn a_refusal_records_a_sample_without_provider_fields() {
        let host = FakeHost::new();
        *host.mode.lock().unwrap() = Mode::Block;
        let up = Arc::new(Recording::default());
        let p = proxy(host, up.clone());
        let blocked = r#"{"model":"m","messages":[{"role":"user","content":"ask Sperrwort now"}]}"#;
        assert_eq!(
            post(&p, "/anthropic/v1/messages", blocked, &[])
                .await
                .status(),
            451
        );
        assert!(up.sent.lock().unwrap().is_empty());
        let b = p.inner.status.timing_body();
        assert_eq!(b.window, 1, "the refusal is sampled");
        let t = b.last.unwrap();
        assert_eq!((t.first_byte_ms, t.provider_ms), (None, None));
        assert_eq!(b.p95.unwrap().provider_ms, None, "null in every sample");
        // A malformed body also reaches the sanitize task (the walk is in it).
        assert_eq!(
            post(&p, "/anthropic/v1/messages", "not json", &[])
                .await
                .status(),
            400
        );
        assert_eq!(window(&p), 2);
    }

    /// No sample for a model list, or for a request rejected before its
    /// body was read.
    #[tokio::test]
    async fn requests_that_never_reach_the_sanitize_task_take_no_sample() {
        let host = FakeHost::new();
        let p = proxy(host, Arc::new(Recording::default()));
        assert_eq!(
            send(&p, "GET", "/openai/v1/models", "", &[]).await.status(),
            200
        );
        // Too large (over the 1 MiB test limit), a refused query, no route.
        let big = vec![b'a'; (1 << 20) + 1];
        assert_eq!(
            post(&p, "/anthropic/v1/messages", big, &[]).await.status(),
            413
        );
        assert_eq!(
            post(&p, "/anthropic/v1/messages?x=1", user_body(), &[])
                .await
                .status(),
            400
        );
        assert_eq!(
            post(&p, "/openai/v1/files", user_body(), &[])
                .await
                .status(),
            404
        );
        assert_eq!(window(&p), 0);
    }

    /// The log lines (captured at TRACE) and every `Debug` carry the request
    /// side's fields as numbers, and no canary.
    #[tokio::test]
    async fn log_lines_and_debug_show_no_canary() {
        let logs = crate::memo_tests::LocalLogs::open();
        let host = FakeHost::new();
        let up = Arc::new(Recording::default());
        let p = proxy(host.clone(), up);
        let extra = [
            ("x-inumaki-client", CLIENT_VALUE),
            ("x-inumaki-session", "sess-canary-zyx"),
            ("authorization", "Bearer zyx-secret"),
            ("user-agent", CANARY_UA),
        ];
        assert_eq!(
            post(&p, "/anthropic/v1/messages", user_body(), &extra)
                .await
                .status(),
            200
        );
        *host.mode.lock().unwrap() = Mode::Block;
        let blocked = r#"{"model":"m","messages":[{"role":"user","content":"ask Sperrwort now"}]}"#;
        assert_eq!(
            post(&p, "/anthropic/v1/messages", blocked, &extra)
                .await
                .status(),
            451
        );
        let logs = logs.close();
        let served = logs
            .lines()
            .find(|l| l.contains("proxy served"))
            .unwrap_or_else(|| panic!("no line: {logs:?}"));
        let refused = logs.lines().find(|l| l.contains("proxy refused")).unwrap();
        for k in [
            "read_ms=",
            "queue_ms=",
            "scan_ms=",
            "engine_ms=",
            "closure_ms=",
            "project_ms=",
            "restore_ms=",
            "local_ms=",
        ] {
            assert!(served.contains(k) && refused.contains(k), "{k}: {logs}");
        }
        // Set on the served line; absent on the refusal.
        assert!(served.contains("first_byte_ms=") && served.contains("provider_ms="));
        assert!(!refused.contains("first_byte_ms=") && !refused.contains("provider_ms="));
        let all = format!(
            "{logs} {p:?} {:?} {:?}",
            p.status(),
            p.inner.status.timing_body()
        );
        for needle in [
            EMAIL,
            "Sperrwort",
            CLIENT_VALUE,
            CANARY_UA,
            "sess-canary-zyx",
            "zyx-secret",
        ] {
            assert!(!all.contains(needle), "{needle} in logs or Debug");
        }
    }
}
