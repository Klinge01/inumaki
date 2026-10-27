//! One served request (M8 spec §5, §6): route, limits, sanitize, forward,
//! commit, record, restore, respond.
//!
//! Fail closed: the only request body that reaches [`Upstream::send`] is
//! `Prepared::body` from `sanitize_request` (or the empty body of a model
//! list). Every error before `send` answers the fixed error of spec §7 and
//! the upstream receives nothing.
//!
//! The answer is relayed only through `respond::non_streaming` (restored,
//! tripwire run, seeded), through the stream rewriter (an event stream,
//! spec §6.2: restored, tripwire run, seeded when it completes), or, for
//! model lists, unchanged; a failure there answers the fixed error and none
//! of the upstream's body (spec §7). A stream that fails after its headers
//! went out ends with the wire's abort event and seeds nothing; a client
//! that leaves stops the stream, frees its in-flight permit, and seeds
//! nothing.
//!
//! Privacy: logs carry the upstream prefix, the endpoint name, the error
//! kind, the status, the duration, and counts. Never a path, a query
//! string, a header value, a body, or an upstream error body.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::response::Response;
use futures::StreamExt;
use http::{HeaderMap, HeaderValue, Method, StatusCode};

use crate::Inner;
use crate::config::SCAN_WEIGHT;
use crate::error::{ErrorClass, Fail};
use crate::host::{ProxyEvent, RefusedVerdict, Scope};
use crate::pipeline::Prepared;
use crate::routes::{Endpoint, UpstreamId, Wire};
use crate::session::{ClientMode, SeedStamp, Session};
use crate::status::{ClientKind, OauthUse, Outcome};
use crate::stream::{Abort, Rewriter};
use crate::timing::{RequestTiming, StageTimes, TimingMs};
use crate::upstream::{UpstreamError, UpstreamRequest, UpstreamResponse};

pub(crate) async fn anthropic(State(s): State<Arc<Inner>>, req: Request) -> Response {
    serve(s, UpstreamId::Anthropic, req).await
}

pub(crate) async fn openai(State(s): State<Arc<Inner>>, req: Request) -> Response {
    serve(s, UpstreamId::Openai, req).await
}

pub(crate) async fn codex(State(s): State<Arc<Inner>>, req: Request) -> Response {
    serve(s, UpstreamId::OpenaiCodex, req).await
}

/// The route outcome of a request the proxy refused itself.
fn refusal_outcome(f: &Fail) -> Outcome {
    match f {
        Fail::PrivacyBlock {
            uncertain: true, ..
        } => Outcome::Uncertain,
        Fail::PrivacyBlock { .. } | Fail::AnswerWithheld { .. } => Outcome::Blocked,
        // Caller mistakes and limits: not the route's fault.
        Fail::BadRequest | Fail::UnsupportedContent | Fail::TooLarge | Fail::Busy => {
            Outcome::NotARouteError
        }
        _ => f
            .class()
            .map_or(Outcome::NotARouteError, |c| Outcome::Failed(c, None)),
    }
}

/// The route outcome of an upstream answer: success clears `failing`, auth,
/// rate limit, and 5xx are route errors, any other 4xx is the caller's
/// (3xx never gets here: `send` refuses it).
fn upstream_outcome(s: StatusCode) -> Outcome {
    match s.as_u16() {
        200..=299 => Outcome::Ok,
        401 | 403 => Outcome::Failed(ErrorClass::UpstreamAuth, Some(s.as_u16())),
        429 => Outcome::Failed(ErrorClass::UpstreamRateLimited, Some(429)),
        500.. => Outcome::Failed(ErrorClass::Upstream5xx, Some(s.as_u16())),
        _ => Outcome::NotARouteError,
    }
}

async fn serve(inner: Arc<Inner>, up: UpstreamId, req: Request) -> Response {
    let t0 = Instant::now();
    let (parts, body) = req.into_parts();
    // The raw path: percent-encoded variants of a served path are not served.
    let Some(rest) = parts.uri.path().strip_prefix(up.prefix()) else {
        return Fail::NotServed.response(None);
    };
    let Some(ep) = crate::routes::endpoint(up, &parts.method, rest) else {
        return Fail::NotServed.response(None);
    };
    let wire = ep.wire();
    let query = parts.uri.query();
    if !crate::routes::query_allowed(up, ep, query) {
        return Fail::BadRequest.response(wire);
    }
    let path_and_query = match query {
        Some(q) => format!("{rest}?{q}"),
        None => rest.to_string(),
    };
    let client = ClientKind::from_user_agent(
        parts
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    );
    let (out_headers, oauth) =
        crate::forward::outbound_headers(&parts.headers, up, inner.sh.cfg.extra_headers.get(up));
    inner.status.request(up, client, oauth);
    let job = Job {
        up,
        ep,
        method: parts.method,
        path_and_query,
        inbound: parts.headers,
        out_headers,
        oauth,
        t0,
    };
    // Filled once the request reached the sanitize task (spec §20,
    // 2026-10-12, Part 2): no sample for a model list, a check route, or a
    // request rejected before its body was read.
    let mut sample: Option<RequestTiming> = None;
    match run(&inner, job, body, &mut sample).await {
        Ok((resp, outcome)) => {
            // `None`: a stream, whose outcome and timing its driver records.
            let streamed = outcome.is_none();
            if let Some(outcome) = outcome {
                inner.status.outcome(up, outcome, oauth);
                // A whole answer's sample is complete as its response is
                // built. A stream's is completed by its driver.
                if let Some(t) = sample.as_mut() {
                    t.total = t0.elapsed();
                    inner.status.timing(*t);
                }
            }
            let m = sample.as_ref().map(TimingMs::from);
            // A stream's answer side is still to come when this line is
            // written: `proxy stream timing` is its only complete line, so
            // the answer-side fields and the sums that include them are
            // left off here rather than printed as a misleading partial.
            let (provider_ms, restore_ms, local_ms) = match m {
                Some(m) if !streamed => (m.provider_ms, Some(m.restore_ms), Some(m.local_ms)),
                _ => (None, None, None),
            };
            tracing::info!(
                route = up.prefix(),
                endpoint = ?ep,
                status = resp.status().as_u16(),
                duration_ms = t0.elapsed().as_millis() as u64,
                read_ms = m.map(|m| m.read_ms),
                queue_ms = m.map(|m| m.queue_ms),
                scan_ms = m.map(|m| m.scan_ms),
                engine_ms = m.map(|m| m.engine_ms),
                closure_ms = m.map(|m| m.closure_ms),
                project_ms = m.map(|m| m.project_ms),
                first_byte_ms = m.and_then(|m| m.first_byte_ms),
                provider_ms,
                restore_ms,
                local_ms,
                "proxy served"
            );
            resp
        }
        Err(f) => {
            inner.status.outcome(up, refusal_outcome(&f), oauth);
            if let Some(t) = sample.as_mut() {
                t.total = t0.elapsed();
                inner.status.timing(*t);
            }
            let m = sample.as_ref().map(TimingMs::from);
            tracing::info!(
                route = up.prefix(),
                endpoint = ?ep,
                class = f.kind(),
                status = f.status().as_u16(),
                duration_ms = t0.elapsed().as_millis() as u64,
                read_ms = m.map(|m| m.read_ms),
                queue_ms = m.map(|m| m.queue_ms),
                scan_ms = m.map(|m| m.scan_ms),
                engine_ms = m.map(|m| m.engine_ms),
                closure_ms = m.map(|m| m.closure_ms),
                project_ms = m.map(|m| m.project_ms),
                first_byte_ms = m.and_then(|m| m.first_byte_ms),
                provider_ms = m.and_then(|m| m.provider_ms),
                restore_ms = m.map(|m| m.restore_ms),
                local_ms = m.map(|m| m.local_ms),
                "proxy refused"
            );
            f.response(wire)
        }
    }
}

/// Everything `run` needs about the request except its body.
struct Job {
    up: UpstreamId,
    ep: Endpoint,
    method: Method,
    path_and_query: String,
    inbound: HeaderMap,
    out_headers: HeaderMap,
    oauth: OauthUse,
    t0: Instant,
}

/// The longest an answer waits for scan permits (capped by the upstream timeout).
const ANSWER_SCAN_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Permits a scan of `len` decoded bytes takes: `len * SCAN_WEIGHT`, at
/// least one, at most the whole budget (a body larger than the budget
/// still runs, alone).
pub(crate) fn scan_permits(len: usize, total: usize) -> u32 {
    let want = len.saturating_mul(SCAN_WEIGHT).clamp(1, total.max(1));
    u32::try_from(want).unwrap_or(u32::MAX)
}

/// What the sanitize task hands back: its result and its clocks.
struct Sanitized {
    /// `spawn_blocking` to the start of the task.
    queue: Duration,
    /// The task's own time.
    ran: Duration,
    times: StageTimes,
    result: Result<(Prepared, Arc<Session>), Fail>,
}

/// The answer and its route outcome; `None` when a stream's driver records
/// it. `sample` is set once the request reached the sanitize task, and
/// filled as far as the request got, an error included (`first_byte` and
/// `provider` stay `None` until an upstream answer arrived; `total` is the
/// caller's).
async fn run(
    inner: &Arc<Inner>,
    job: Job,
    body: Body,
    sample: &mut Option<RequestTiming>,
) -> Result<(Response, Option<Outcome>), Fail> {
    let Job {
        up,
        ep,
        method,
        path_and_query,
        inbound,
        out_headers,
        oauth,
        t0,
    } = job;
    let cfg = &inner.sh.cfg;
    // 1. In-flight limit, before the body is read. Held until the answer
    // ends: a streamed answer's driver owns it.
    let inflight = Inflight::acquire(inner)?;

    // Model lists: forwarded unchanged with an empty body; whatever the
    // client sent as a body is not forwarded.
    if matches!(ep, Endpoint::Models | Endpoint::Model) {
        let req = UpstreamRequest {
            upstream: up,
            method,
            path_and_query,
            headers: out_headers,
            body: Bytes::new(),
        };
        let resp = send(inner, req).await?;
        let outcome = upstream_outcome(resp.status);
        let UpstreamResponse {
            status,
            headers,
            body,
        } = resp;
        let buf = collect(body, cfg.max_request_bytes).await?;
        return Ok((reply(status, &headers, buf, None), Some(outcome)));
    }

    // 2. Body: bounded while it is read and again after decoding.
    let read_start = Instant::now();
    let decoded = read_body(&inbound, body, cfg.max_request_bytes).await?;
    let read = read_start.elapsed();

    // 3. Scan admission by decoded size, held until sanitization ends.
    let scan_permit = Arc::clone(&inner.scan)
        .try_acquire_many_owned(scan_permits(decoded.len(), inner.scan_total))
        .map_err(|_| Fail::Busy)?;

    // 4. Walk, session, sanitize: one blocking task that owns the permit,
    // so it is released when the memory is, even if the client goes away.
    let wire = ep.wire().ok_or(Fail::Internal)?;
    let mode = crate::forward::client_mode(&inbound, &inner.client_value);
    let task_inner = Arc::clone(inner);
    let queued = Instant::now();
    let joined = tokio::task::spawn_blocking(move || {
        let started = Instant::now();
        let queue = started.duration_since(queued);
        let _scan = scan_permit;
        let mut times = StageTimes::default();
        let result = (|| {
            let w = crate::walk::walk_for(wire, &decoded, task_inner.sh.cfg.binary)
                .map_err(|_| Fail::BadRequest)?;
            let key = crate::session::session_key(
                task_inner.sh.keys.process_key(),
                up.prefix(),
                mode,
                &inbound,
                w.first_system.as_deref(),
                w.first_user.as_deref(),
            );
            let session = task_inner.sessions.get(key);
            let prepared = crate::pipeline::sanitize_request(
                &task_inner.sh,
                &session,
                wire,
                &decoded,
                &w,
                mode,
                &mut times,
            )?;
            Ok((prepared, session))
        })();
        Sanitized {
            queue,
            ran: started.elapsed(),
            times,
            result,
        }
    })
    .await;
    let sanitized = match joined {
        Ok(b) => {
            let (engine, closure) = (b.times.engine.get(), b.times.closure.get());
            *sample = Some(RequestTiming {
                read,
                queue: b.queue,
                scan: b.ran.saturating_sub(engine).saturating_sub(closure),
                engine,
                closure,
                project: b.times.project.get(),
                ..RequestTiming::default()
            });
            b.result
        }
        Err(_) => {
            *sample = Some(RequestTiming {
                read,
                ..RequestTiming::default()
            });
            Err(Fail::Internal)
        }
    };
    let (mut prepared, session) = match sanitized {
        Ok(v) => v,
        Err(f) => {
            record_refused(inner, up, &f);
            return Err(f);
        }
    };
    // Seeds of this answer carry what the request verified (ruling I1),
    // streamed or not; taken before the commit moves anything.
    let seed = prepared.seed_stamp();

    // 5. Forward the body the pipeline produced, nothing else.
    let req = UpstreamRequest {
        upstream: up,
        method,
        path_and_query,
        headers: out_headers,
        body: Bytes::from(std::mem::take(&mut prepared.body)),
    };
    let send_start = Instant::now();
    let resp = send(inner, req).await?;
    let first_byte = send_start.elapsed();
    if let Some(t) = sample.as_mut() {
        t.first_byte = Some(first_byte);
    }
    let status = resp.status;

    // 6. Commit only after the upstream took the request (spec §5 step 7).
    if status.as_u16() < 500 && status != StatusCode::TOO_MANY_REQUESTS {
        commit(inner, up, &session, &mut prepared, status);
    }

    // 7. Answer (spec §6): restored, tripwire run, and seeded on a blocking
    // thread. The request already left, so a failure here keeps the commit
    // and answers the fixed error, never the upstream's body.
    let verdict = if prepared.uncertain_passed {
        "pass-uncertain"
    } else {
        "pass"
    };
    let outcome = upstream_outcome(status);
    let UpstreamResponse { headers, body, .. } = resp;
    let collect_start = Instant::now();
    let (sse, body) = sniff(status, &headers, body).await?;
    if sse {
        // The request side of the sample goes to the driver, which
        // completes and records it when the stream ends.
        let timing = sample.as_ref().map(|t| StreamTiming {
            sample: *t,
            send_start,
            t0,
            last_byte: Instant::now(),
        });
        let ctx = StreamCtx {
            session,
            wire,
            up,
            mode,
            scope: Scope::Datasets,
            seed,
            oauth,
            timing,
        };
        let sanitized = Some((verdict, prepared.replacements, t0));
        let r = stream_reply(inner, ctx, status, &headers, body, inflight, sanitized);
        return Ok((r, None));
    }
    let buf = collect(body, cfg.max_request_bytes).await?;
    // `provider`: the time to headers plus the time to the last byte (the
    // first chunk a content-type-less answer is sniffed by included).
    if let Some(t) = sample.as_mut() {
        t.provider = Some(first_byte.saturating_add(collect_start.elapsed()));
    }
    // The answer's node list is about 50 times its size, like a request's,
    // so it takes weighted permits from the same budget. The request already
    // left, so this WAITS (a refusal would answer busy for a request that was
    // sent) and gives up only after a bounded time. No deadlock: this task
    // holds no scan permit while it waits, because the request-side permit
    // went with its blocking task before `send`. The permit moves into the
    // blocking task and is released with the memory.
    let wait = cfg.upstream_timeout.min(ANSWER_SCAN_WAIT);
    // `restore`: the permit wait and the restore task.
    let restore_start = Instant::now();
    let note_restore = |sample: &mut Option<RequestTiming>| {
        if let Some(t) = sample.as_mut() {
            t.restore = restore_start.elapsed();
        }
    };
    let answer_permit = tokio::time::timeout(
        wait,
        Arc::clone(&inner.scan).acquire_many_owned(scan_permits(buf.len(), inner.scan_total)),
    )
    .await;
    let answer_permit = match answer_permit {
        Ok(Ok(p)) => p,
        Ok(Err(_)) => {
            note_restore(sample);
            return Err(Fail::Internal);
        }
        Err(_) => {
            note_restore(sample);
            return Err(Fail::AnswerUnchecked);
        }
    };
    let task_inner = Arc::clone(inner);
    let answer = tokio::task::spawn_blocking(move || {
        let _scan = answer_permit;
        crate::respond::non_streaming(
            &task_inner.sh,
            &session,
            wire,
            up,
            mode,
            status,
            &buf,
            crate::host::Scope::Datasets,
            seed,
        )
    })
    .await;
    note_restore(sample);
    let answer = answer.map_err(|_| Fail::Internal)??;
    // Seeds were added to the session's cache.
    inner.sessions.enforce_budget();
    tracing::debug!(
        route = up.prefix(),
        restored = answer.restored,
        "answer restored"
    );
    let resp = reply(
        status,
        &headers,
        answer.body,
        Some((verdict, prepared.replacements, t0)),
    );
    drop(inflight);
    Ok((resp, Some(outcome)))
}

/// The request body, bounded by `max` while it is read and again after
/// decoding (`content-encoding`). Shared with the check routes.
pub(crate) async fn read_body(inbound: &HeaderMap, body: Body, max: usize) -> Result<Bytes, Fail> {
    let too_big = inbound
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > max);
    if too_big {
        return Err(Fail::TooLarge);
    }
    let raw = axum::body::to_bytes(body, max)
        .await
        .map_err(|_| Fail::TooLarge)?;
    if inbound.contains_key(http::header::CONTENT_ENCODING) {
        let h = inbound.clone();
        tokio::task::spawn_blocking(move || crate::forward::decode(&h, raw, max))
            .await
            .map_err(|_| Fail::Internal)?
    } else {
        crate::forward::decode(inbound, raw, max)
    }
}

/// Insert the cache entries and memoized verdicts, count the cache, and
/// record the activity events (spec §5 step 7, §9).
fn commit(
    inner: &Inner,
    up: UpstreamId,
    session: &crate::session::Session,
    p: &mut Prepared,
    status: StatusCode,
) {
    crate::pipeline::commit_cache(session, p);
    inner.sessions.enforce_budget();
    inner.status.cache(p.hits, p.misses);
    // Withheld results are counted here, only once the upstream took the
    // request: a request that failed before that sent no placeholder.
    for (uncertain, kinds, checks) in std::mem::take(&mut p.withheld) {
        inner
            .status
            .outcome(up, Outcome::Withheld { uncertain }, OauthUse::None);
        inner.sh.host.record(ProxyEvent::Withheld {
            upstream: up,
            uncertain,
            kinds,
            checks,
        });
    }
    // An upstream 4xx is not a release (spec §9).
    if status.is_success() {
        let payload = if p.missed.is_empty() {
            Vec::new()
        } else {
            serde_json::to_vec(&p.missed).unwrap_or_default()
        };
        inner.sh.host.record(ProxyEvent::Released {
            upstream: up,
            kinds: std::mem::take(&mut p.kinds),
            payload,
        });
    }
}

/// Record a refusal the activity log lists (spec §9): the privacy rows and
/// unsupported content; availability and caller mistakes are not recorded.
fn record_refused(inner: &Inner, up: UpstreamId, f: &Fail) {
    let (verdict, kinds, checks) = match f {
        Fail::PrivacyBlock {
            kinds,
            checks,
            uncertain,
        } => (
            if *uncertain {
                RefusedVerdict::Uncertain
            } else {
                RefusedVerdict::Blocked
            },
            kinds
                .iter()
                .map(|k| inumaki_core::span::EntityKind::from_label(k))
                .collect(),
            checks.clone(),
        ),
        Fail::UnsupportedContent => (RefusedVerdict::Unsupported, Vec::new(), Vec::new()),
        _ => return,
    };
    inner.sh.host.record(ProxyEvent::Refused {
        upstream: up,
        verdict,
        kinds,
        checks,
    });
}

/// Send upstream under the first-byte timeout.
async fn send(inner: &Inner, req: UpstreamRequest) -> Result<UpstreamResponse, Fail> {
    match tokio::time::timeout(inner.sh.cfg.upstream_timeout, inner.upstream.send(req)).await {
        Err(_) | Ok(Err(UpstreamError::Timeout)) => Err(Fail::UpstreamTimeout),
        Ok(Err(_)) => Err(Fail::UpstreamUnreachable),
        Ok(Ok(r)) => {
            // A redirect would make the harness's client re-send its own
            // (unsanitized) body and credentials to the `Location` host, and a
            // coded body cannot be relayed until Task 9 decodes responses
            // (we ask for `identity`). Both are upstream errors: nothing is
            // committed and neither the `Location` nor the body is relayed.
            if r.status.is_redirection() || !identity_encoded(&r.headers) {
                return Err(Fail::UpstreamUnreachable);
            }
            Ok(r)
        }
    }
}

/// Whether the response body is uncoded (`content-encoding` absent or `identity`).
fn identity_encoded(h: &HeaderMap) -> bool {
    h.get_all(http::header::CONTENT_ENCODING).iter().all(|v| {
        v.to_str()
            .is_ok_and(|v| v.trim().eq_ignore_ascii_case("identity"))
    })
}

/// The upstream's body, bounded by `max`: an answer over the bound is
/// [`Fail::ResponseTooLarge`] and none of it is relayed.
pub(crate) async fn collect(
    mut body: futures::stream::BoxStream<'static, Result<Bytes, UpstreamError>>,
    max: usize,
) -> Result<Vec<u8>, Fail> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body.next().await {
        let c = chunk.map_err(|_| Fail::UpstreamUnreachable)?;
        if buf.len().saturating_add(c.len()) > max {
            return Err(Fail::ResponseTooLarge);
        }
        buf.extend_from_slice(&c);
    }
    Ok(buf)
}

/// The client's response: the upstream's status and filtered headers, the
/// given body, and the `x-inumaki-*` headers when a request was sanitized.
pub(crate) fn reply(
    status: StatusCode,
    headers: &HeaderMap,
    body: Vec<u8>,
    sanitized: Option<(&'static str, usize, Instant)>,
) -> Response {
    let mut out = crate::forward::relay_headers(headers);
    if let Some((verdict, replacements, t0)) = sanitized {
        out.insert("x-inumaki-verdict", HeaderValue::from_static(verdict));
        out.insert("x-inumaki-replacements", HeaderValue::from(replacements));
        out.insert(
            "x-inumaki-latency-ms",
            HeaderValue::from(t0.elapsed().as_millis() as u64),
        );
    }
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    *r.headers_mut() = out;
    r
}

/// The in-flight permit, owned, so a streamed answer's driver can hold it
/// past the handler; returned to `Inner::inflight` when dropped.
pub(crate) struct Inflight(Arc<Inner>);

impl Inflight {
    /// One permit of `max_inflight`, or [`Fail::Busy`].
    pub(crate) fn acquire(inner: &Arc<Inner>) -> Result<Inflight, Fail> {
        inner
            .inflight
            .try_acquire()
            .map_err(|_| Fail::Busy)?
            .forget();
        Ok(Inflight(Arc::clone(inner)))
    }
}

impl Drop for Inflight {
    fn drop(&mut self) {
        self.0.inflight.add_permits(1);
    }
}

/// An upstream body.
pub(crate) type UpBody = futures::stream::BoxStream<'static, Result<Bytes, UpstreamError>>;

/// Idle time allowed between upstream stream chunks, and for a client to
/// take the next one (spec §4).
const IDLE: Duration = Duration::from_secs(300);

/// Events up to this size are scanned without scan permits; larger ones
/// take weighted permits like an answer (spec §20: a stream's resident scan
/// memory stays within the scan budget).
const SCAN_FREE: usize = 64 << 10;

/// Capacity of the channel between the stream driver and the client body.
const STREAM_QUEUE: usize = 32;

/// Whether a 2xx answer is an event stream (spec §6): by its content type,
/// else by its first non-empty chunk, which is put back in front of the
/// returned body. Anything else (and every non-2xx answer) is not, so it
/// goes through `respond::non_streaming`.
pub(crate) async fn sniff(
    status: StatusCode,
    headers: &HeaderMap,
    mut body: UpBody,
) -> Result<(bool, UpBody), Fail> {
    if !status.is_success() {
        return Ok((false, body));
    }
    let ct = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.trim().to_ascii_lowercase());
    match ct.as_deref() {
        Some(c) if c.starts_with("text/event-stream") => return Ok((true, body)),
        Some(c) if c.starts_with("application/json") => return Ok((false, body)),
        _ => {}
    }
    let first = loop {
        match tokio::time::timeout(IDLE, body.next()).await {
            Ok(Some(Ok(c))) if c.is_empty() => {}
            Ok(Some(Ok(c))) => break c,
            Ok(None) => return Ok((false, futures::stream::empty().boxed())),
            Ok(Some(Err(_))) => return Err(Fail::UpstreamUnreachable),
            Err(_) => return Err(Fail::UpstreamTimeout),
        }
    };
    let sse = crate::sse::looks_like_sse(&first);
    let body = futures::stream::once(async move { Ok(first) })
        .chain(body)
        .boxed();
    Ok((sse, body))
}

/// What a streamed answer is restored with. `scope` decides the rest:
/// `Scope::Datasets` (a normal route) records the route outcome, runs the
/// tripwire, and seeds; `Scope::Check(_)` (a check route) does none of it.
pub(crate) struct StreamCtx {
    pub session: Arc<Session>,
    pub wire: Wire,
    pub up: UpstreamId,
    pub mode: ClientMode,
    pub scope: Scope,
    /// The producing request's `Prepared::seed_stamp()`, exactly as
    /// `respond::non_streaming` takes it.
    pub seed: SeedStamp,
    pub oauth: OauthUse,
    /// A normal route's request-side sample, which the driver completes and
    /// records when the stream ends. `None` on a check route: no sample.
    pub timing: Option<StreamTiming>,
}

/// What the driver needs to complete a stream's timing sample (M8 spec §20,
/// amendment 2026-10-12, Part 2). Durations and instants only.
pub(crate) struct StreamTiming {
    /// The request side, as `run` left it (`first_byte` set).
    pub sample: RequestTiming,
    /// The start of `send`.
    pub send_start: Instant,
    /// The request's arrival.
    pub t0: Instant,
    /// When the sniffed first chunk was in hand: the last upstream byte
    /// until the driver reads another.
    pub last_byte: Instant,
}

/// The driver's own clocks. `restore` is its local work on the answer
/// (`Rewriter::event`, `finish` and `abort`; permit waits and client
/// delivery left out), `deliver` the time it spent handing bytes to the
/// client. `last_byte` is when the last upstream chunk arrived, with what
/// `restore` and `deliver` had come to by then, so that work done after the
/// provider's last byte is not taken off the provider's time.
struct StreamClock {
    restore: Duration,
    deliver: Duration,
    last_byte: Instant,
    restore_at_last: Duration,
    deliver_at_last: Duration,
}

impl StreamClock {
    fn new(last_byte: Instant) -> StreamClock {
        StreamClock {
            restore: Duration::ZERO,
            deliver: Duration::ZERO,
            last_byte,
            restore_at_last: Duration::ZERO,
            deliver_at_last: Duration::ZERO,
        }
    }

    /// An upstream chunk arrived now.
    fn byte(&mut self) {
        self.last_byte = Instant::now();
        self.restore_at_last = self.restore;
        self.deliver_at_last = self.deliver;
    }

    /// Run `f` as the driver's local answer-side work.
    fn restoring<T>(&mut self, f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let r = f();
        self.restore = self.restore.saturating_add(start.elapsed());
        r
    }

    /// The completed sample: `provider` is the last upstream byte minus the
    /// send start, the restore work and the client waits before it.
    fn complete(&self, t: &StreamTiming) -> RequestTiming {
        let provider = self
            .last_byte
            .saturating_duration_since(t.send_start)
            .saturating_sub(self.restore_at_last)
            .saturating_sub(self.deliver_at_last);
        RequestTiming {
            provider: Some(provider),
            restore: self.restore,
            total: t.t0.elapsed(),
            ..t.sample
        }
    }
}

/// How a stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The stream completed; it was seeded.
    Completed,
    /// An upstream cut, an idle timeout, a malformed or oversized event, a
    /// resolver error, an upstream error event, or a panic: the route's fault.
    Aborted,
    /// The block-mode tripwire stopped the answer (spec §7: never `failing`).
    Privacy,
    /// The client went away: no route outcome is recorded; the stream's one
    /// timing sample is (spec §20, Part 2).
    ClientGone,
}

/// Answer the client with the upstream's event stream, rewritten on a
/// blocking thread that owns `permit` (spec §6.2). The route outcome `Ok` is
/// recorded now, as the headers go out; an abort records its class when the
/// stream ends. `sanitized` adds the `x-inumaki-*` headers (`latency-ms` is
/// the time to headers).
pub(crate) fn stream_reply(
    inner: &Arc<Inner>,
    ctx: StreamCtx,
    status: StatusCode,
    headers: &HeaderMap,
    body: UpBody,
    permit: Inflight,
    sanitized: Option<(&'static str, usize, Instant)>,
) -> Response {
    let mut out = crate::forward::relay_headers(headers);
    out.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    if let Some((verdict, replacements, t0)) = sanitized {
        out.insert("x-inumaki-verdict", HeaderValue::from_static(verdict));
        out.insert("x-inumaki-replacements", HeaderValue::from(replacements));
        out.insert(
            "x-inumaki-latency-ms",
            HeaderValue::from(t0.elapsed().as_millis() as u64),
        );
    }
    let record = !matches!(ctx.scope, Scope::Check(_));
    // Recorded before the driver starts, so its abort is never overwritten.
    if record {
        inner.status.outcome(ctx.up, Outcome::Ok, ctx.oauth);
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(STREAM_QUEUE);
    let handle = tokio::runtime::Handle::current();
    let task_inner = Arc::clone(inner);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let inner = task_inner;
        let mut clock = StreamClock::new(
            ctx.timing
                .as_ref()
                .map_or_else(Instant::now, |t| t.last_byte),
        );
        // The daemon's panic guard covers the handler future only, not
        // this task: a panic ends the stream with the abort event. The
        // payload is never formatted.
        let end = std::panic::catch_unwind(AssertUnwindSafe(|| {
            drive(&inner, &ctx, &handle, body, &tx, &mut clock)
        }))
        .unwrap_or_else(|_| {
            let abort = crate::stream::codec(ctx.wire)
                .abort(&Abort::Stream)
                .unwrap_or_default();
            deliver(&handle, &tx, &mut clock, vec![abort]);
            tracing::error!(route = ctx.up.prefix(), "proxy stream task panicked");
            End::Aborted
        });
        // One sample per stream, whichever way it ended; none on a check
        // route (spec §20, Part 2).
        if let Some(t) = &ctx.timing {
            let sample = clock.complete(t);
            inner.status.timing(sample);
            let m = TimingMs::from(&sample);
            tracing::info!(
                route = ctx.up.prefix(),
                total_ms = m.total_ms,
                read_ms = m.read_ms,
                queue_ms = m.queue_ms,
                scan_ms = m.scan_ms,
                engine_ms = m.engine_ms,
                closure_ms = m.closure_ms,
                project_ms = m.project_ms,
                first_byte_ms = m.first_byte_ms,
                provider_ms = m.provider_ms,
                restore_ms = m.restore_ms,
                local_ms = m.local_ms,
                "proxy stream timing"
            );
        }
        match end {
            End::Completed if record => inner.sessions.enforce_budget(),
            End::Completed => {}
            End::Aborted => {
                if record {
                    inner.status.outcome(
                        ctx.up,
                        Outcome::Failed(ErrorClass::StreamAborted, None),
                        ctx.oauth,
                    );
                }
                tracing::info!(
                    route = ctx.up.prefix(),
                    class = "stream_aborted",
                    "proxy stream ended early"
                );
            }
            End::Privacy => {
                if record {
                    inner.status.outcome(ctx.up, Outcome::Blocked, ctx.oauth);
                }
                tracing::info!(
                    route = ctx.up.prefix(),
                    class = "privacy_block",
                    "proxy stream ended early"
                );
            }
            End::ClientGone => {
                // A client that left after the terminal event: the answer
                // was seeded, so the store's budget applies (final review M2).
                if record {
                    inner.sessions.enforce_budget();
                }
                tracing::debug!(route = ctx.up.prefix(), "proxy stream client left");
            }
        }
    });
    let stream = futures::stream::poll_fn(move |cx| {
        rx.poll_recv(cx)
            .map(|o| o.map(Ok::<_, std::convert::Infallible>))
    });
    let mut r = Response::new(Body::from_stream(stream));
    *r.status_mut() = status;
    *r.headers_mut() = out;
    r
}

/// Send `chunks` to the client as one piece. `false` when the client went
/// away or took nothing for [`IDLE`]. The pieces can hold restored
/// originals: they are wiped once joined (the joined copy goes to the
/// client's body and cannot be).
fn deliver(
    handle: &tokio::runtime::Handle,
    tx: &tokio::sync::mpsc::Sender<Bytes>,
    clock: &mut StreamClock,
    chunks: Vec<Vec<u8>>,
) -> bool {
    if chunks.is_empty() {
        return true;
    }
    let joined = chunks.concat();
    for mut c in chunks {
        zeroize::Zeroize::zeroize(&mut c);
    }
    let b = Bytes::from(joined);
    // The client wait is the provider's to give back, not local work.
    let start = Instant::now();
    let sent = handle
        .block_on(tokio::time::timeout(IDLE, tx.send(b)))
        .is_ok_and(|r| r.is_ok());
    clock.deliver = clock.deliver.saturating_add(start.elapsed());
    sent
}

/// Scan permits for the record-only tripwire scan an ending stream runs
/// over its cut-off argument channels (final re-review N1): sized, waited
/// for, and bounded like an event's in [`feed`]. Without them in time the
/// record is skipped (the stream ends either way: it is record-only) and a
/// fixed line is logged. `None` when no permit is needed or none was had.
fn cut_permits(
    inner: &Inner,
    handle: &tokio::runtime::Handle,
    rw: &mut Rewriter<'_>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    let len = rw.cut_scan_len();
    if len <= SCAN_FREE {
        return None;
    }
    let wait = inner.sh.cfg.upstream_timeout.min(ANSWER_SCAN_WAIT);
    let n = scan_permits(len, inner.scan_total);
    match handle.block_on(tokio::time::timeout(
        wait,
        Arc::clone(&inner.scan).acquire_many_owned(n),
    )) {
        Ok(Ok(p)) => Some(p),
        _ => {
            skip_cut_record(rw);
            None
        }
    }
}

/// Skip the record-only scan of cut-off channels, with the fixed log line.
fn skip_cut_record(rw: &mut Rewriter<'_>) {
    rw.skip_cut_record();
    tracing::info!("proxy stream cut-off record skipped: no scan permits");
}

/// Send the abort event for `why`; how the stream ended. The abort's
/// record-only scan runs under [`cut_permits`].
fn abort(
    inner: &Inner,
    handle: &tokio::runtime::Handle,
    tx: &tokio::sync::mpsc::Sender<Bytes>,
    clock: &mut StreamClock,
    rw: &mut Rewriter<'_>,
    why: &Abort,
) -> End {
    let permits = cut_permits(inner, handle, rw);
    let out = clock.restoring(|| rw.abort(why));
    drop(permits);
    deliver(handle, tx, clock, out);
    match why {
        Abort::Privacy { .. } => End::Privacy,
        Abort::Stream => End::Aborted,
    }
}

/// Read, rewrite, send (the driver contract in `stream`'s module doc).
/// Returning drops the upstream body (closing its connection); nothing is
/// seeded unless the rewriter completed the stream.
fn drive(
    inner: &Inner,
    ctx: &StreamCtx,
    handle: &tokio::runtime::Handle,
    mut body: UpBody,
    tx: &tokio::sync::mpsc::Sender<Bytes>,
    clock: &mut StreamClock,
) -> End {
    let mut rw = Rewriter::new(
        &inner.sh,
        &ctx.session,
        ctx.wire,
        ctx.up,
        ctx.mode,
        ctx.scope.clone(),
        ctx.seed.clone(),
    );
    let mut parser = crate::sse::SseParser::new(crate::sse::MAX_EVENT);
    loop {
        // A client that leaves is noticed while the upstream is silent too,
        // not only at the next send.
        let next = handle.block_on(async {
            tokio::select! {
                biased;
                () = tx.closed() => None,
                r = tokio::time::timeout(IDLE, body.next()) => Some(r),
            }
        });
        let Some(next) = next else {
            return End::ClientGone;
        };
        let events = match next {
            Ok(Some(Ok(chunk))) => {
                clock.byte();
                match parser.push(&chunk) {
                    Ok(events) => events,
                    Err(_) => return abort(inner, handle, tx, clock, &mut rw, &Abort::Stream),
                }
            }
            Ok(None) => {
                match parser.finish() {
                    Ok(Some(ev)) => {
                        if let Some(end) = feed(inner, handle, tx, clock, &mut rw, ev) {
                            return end;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => return abort(inner, handle, tx, clock, &mut rw, &Abort::Stream),
                }
                // Completed: nothing to send (and seeded). Otherwise the
                // abort event, whose record-only scan takes permits.
                let permits = cut_permits(inner, handle, &mut rw);
                let (bytes, completed) = clock.restoring(|| rw.finish());
                drop(permits);
                deliver(handle, tx, clock, bytes);
                return if completed {
                    End::Completed
                } else {
                    End::Aborted
                };
            }
            // An upstream cut or an idle upstream.
            Ok(Some(Err(_))) | Err(_) => {
                return abort(inner, handle, tx, clock, &mut rw, &Abort::Stream);
            }
        };
        for ev in events {
            if let Some(end) = feed(inner, handle, tx, clock, &mut rw, ev) {
                return end;
            }
        }
    }
}

/// One event through the rewriter; `Some` when the stream ends here.
fn feed(
    inner: &Inner,
    handle: &tokio::runtime::Handle,
    tx: &tokio::sync::mpsc::Sender<Bytes>,
    clock: &mut StreamClock,
    rw: &mut Rewriter<'_>,
    ev: crate::sse::SseEvent,
) -> Option<End> {
    // A client that left gets nothing more processed (or seeded).
    if tx.is_closed() {
        return Some(End::ClientGone);
    }
    // A large event's node list is about 50 times its size: it waits for
    // scan permits like an answer does, bounded, and aborts on timeout.
    // Any event can end the largest open argument channel, which is then
    // scanned whole, so that counts too (final review I2).
    let len = ev
        .data
        .as_ref()
        .map_or(0, Vec::len)
        .saturating_add(rw.largest_open_args());
    let scan = if len > SCAN_FREE {
        let wait = inner.sh.cfg.upstream_timeout.min(ANSWER_SCAN_WAIT);
        let n = scan_permits(len, inner.scan_total);
        let got = handle.block_on(async {
            tokio::select! {
                biased;
                () = tx.closed() => None,
                r = tokio::time::timeout(wait, Arc::clone(&inner.scan).acquire_many_owned(n)) => Some(r),
            }
        });
        match got {
            None => return Some(End::ClientGone),
            Some(Ok(Ok(p))) => Some(p),
            // No permits in time: neither for this event nor, then, for
            // the abort's record-only scan (no second wait).
            Some(_) => {
                skip_cut_record(rw);
                return Some(abort(inner, handle, tx, clock, rw, &Abort::Stream));
            }
        }
    } else {
        None
    };
    let r = clock.restoring(|| rw.event(ev));
    // The scan is over: the permits go back before the client is waited on
    // (up to `IDLE`), so a slow reader never holds the budget (final review I3).
    drop(scan);
    match r {
        Ok(out) => (!deliver(handle, tx, clock, out)).then_some(End::ClientGone),
        Err(why) => Some(abort(inner, handle, tx, clock, rw, &why)),
    }
}

#[cfg(test)]
mod stream_clock_tests {
    use super::*;

    /// `provider` is the last upstream byte minus the send start, minus the
    /// restore and delivery time that had accrued by that byte; `restore`
    /// is the whole sum. Work after the last byte does not come off the
    /// provider's time.
    #[test]
    fn provider_takes_the_work_before_the_last_byte_off_and_nothing_after() {
        let base = Instant::now();
        let ms = Duration::from_millis;
        let mut clock = StreamClock::new(base + ms(40));
        clock.restore = ms(10);
        clock.deliver = ms(5);
        // The last chunk arrived at 100 ms with 10 ms restore, 5 ms deliver.
        clock.byte();
        clock.last_byte = base + ms(100);
        // Work after it: the final events and the end of the stream.
        clock.restore = ms(30);
        clock.deliver = ms(9);
        let t = StreamTiming {
            sample: RequestTiming {
                read: ms(1),
                first_byte: Some(ms(7)),
                ..RequestTiming::default()
            },
            send_start: base,
            t0: base,
            last_byte: base,
        };
        let done = clock.complete(&t);
        assert_eq!(done.provider, Some(ms(85)));
        assert_eq!(done.restore, ms(30));
        assert_eq!((done.read, done.first_byte), (ms(1), Some(ms(7))));
        // The restore and delivery sums can never push it below zero.
        clock.last_byte = base + ms(3);
        assert_eq!(clock.complete(&t).provider, Some(Duration::ZERO));
    }
}
