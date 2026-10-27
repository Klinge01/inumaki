//! Check routes on the proxy listener (M8 spec §12): `/check/<id>/<upstream>/…`.
//!
//! The request is sanitized by the check dataset, the scripted upstream
//! answers in process, and the answer is restored with the check's scope
//! only. Nothing leaves the process, and nothing is written outside the
//! check registry: no activity record, journal entry, seed, tripwire
//! record, or route counter (spec §12.3).
//!
//! Fail closed: a malformed, unknown, removed, or expired id, an unknown
//! upstream, and an unserved path answer `404 not_served` before the body
//! is read, decoded, walked, sanitized, or recorded. The only body the
//! scripted upstream receives (and the registry records) is
//! `Prepared::body` from `sanitize_check`, with no request header.
//!
//! Privacy: the route id is a capability and is never logged; logs carry
//! the error kind only (never the id, the path, the query, or a body).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, Method};

use crate::Inner;
use crate::check::{CheckId, CheckRoutes};
use crate::error::Fail;
use crate::handler::{Inflight, StreamCtx};
use crate::host::Scope;
use crate::routes::{Endpoint, UpstreamId};
use crate::scripted::{Script, ScriptedUpstream};
use crate::session::{ClientMode, SeedStamp, Session};
use crate::status::OauthUse;
use crate::upstream::{Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};

/// The scripted upstream of one check route; records each body it receives.
pub(crate) struct CheckUpstream {
    pub routes: Arc<CheckRoutes>,
    pub id: CheckId,
    pub script: Script,
}

impl Upstream for CheckUpstream {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        self.routes.record(&self.id, req.upstream, &req.body);
        // No request header ever reaches the scripted upstream.
        let req = UpstreamRequest {
            headers: HeaderMap::new(),
            ..req
        };
        ScriptedUpstream::new(self.script.clone()).send(req)
    }
}

/// A served check route: everything decided before the body is read.
struct Target {
    id: CheckId,
    up: UpstreamId,
    ep: Endpoint,
    path: String,
    dataset: String,
    script: Script,
    session: Arc<Session>,
}

/// The route of `path` (raw, so percent-encoded variants are not served),
/// or `None` for `404 not_served`.
fn target(routes: &CheckRoutes, method: &Method, path: &str) -> Option<Target> {
    let rest = path.strip_prefix("/check/")?;
    let (id, rest) = rest.split_once('/')?;
    let (upstream, rest) = rest.split_once('/')?;
    let id = CheckId::from_hex(id)?;
    let up = UpstreamId::from_id(upstream)?;
    let path = format!("/{rest}");
    let ep = crate::routes::endpoint(up, method, &path)?;
    let (dataset, script, session) = routes.lookup(&id)?;
    Some(Target {
        id,
        up,
        ep,
        path,
        dataset,
        script,
        session,
    })
}

/// `/check/{id}/{upstream}/{*rest}`.
pub(crate) async fn serve(State(inner): State<Arc<Inner>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let Some(t) = target(&inner.check, &parts.method, parts.uri.path()) else {
        return Fail::NotServed.response(None);
    };
    let wire = t.ep.wire();
    match run(&inner, t, parts.uri.query(), &parts.headers, body).await {
        Ok(r) => r,
        Err(f) => {
            tracing::info!(route = "check", class = f.kind(), "proxy refused");
            f.response(wire)
        }
    }
}

async fn run(
    inner: &Arc<Inner>,
    t: Target,
    query: Option<&str>,
    headers: &HeaderMap,
    body: axum::body::Body,
) -> Result<Response, Fail> {
    let Target {
        id,
        up,
        ep,
        path,
        dataset,
        script,
        session,
    } = t;
    if !crate::routes::query_allowed(up, ep, query) {
        return Err(Fail::BadRequest);
    }
    // Owned: a streamed answer's driver holds it until the stream ends.
    let inflight = Inflight::acquire(inner)?;
    // Model lists (spec §12.1): answered by the script; the body is not read.
    if matches!(ep, Endpoint::Models | Endpoint::Model) {
        let (status, v) = crate::scripted::answer(ep, b"{}", &script);
        return Ok((status, axum::Json(v)).into_response());
    }
    let max = inner.sh.cfg.max_request_bytes;
    let decoded = crate::handler::read_body(headers, body, max).await?;
    // Token counting: answered by the script from the body's length only;
    // never sanitized, recorded, or restored.
    if ep == Endpoint::CountTokens {
        let (status, v) = crate::scripted::answer(ep, &decoded, &script);
        return Ok((status, axum::Json(v)).into_response());
    }
    let wire = ep.wire().ok_or(Fail::Internal)?;
    let scan_permit = Arc::clone(&inner.scan)
        .try_acquire_many_owned(crate::handler::scan_permits(
            decoded.len(),
            inner.scan_total,
        ))
        .map_err(|_| Fail::Busy)?;
    let task_inner = Arc::clone(inner);
    let ds = dataset.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        let _scan = scan_permit;
        let w = crate::walk::walk_for(wire, &decoded, task_inner.sh.cfg.binary)
            .map_err(|_| Fail::BadRequest)?;
        crate::pipeline::sanitize_check(&task_inner.sh, &ds, &decoded, &w)
    })
    .await
    .map_err(|_| Fail::Internal)??;

    let path_and_query = match query {
        Some(q) => format!("{path}?{q}"),
        None => path,
    };
    let upstream = CheckUpstream {
        routes: Arc::clone(&inner.check),
        id,
        script,
    };
    let req = UpstreamRequest {
        upstream: up,
        method: Method::POST,
        path_and_query,
        headers: HeaderMap::new(),
        body: Bytes::from(prepared.body),
    };
    let resp = upstream.send(req).await.map_err(|_| Fail::Internal)?;
    let UpstreamResponse {
        status,
        headers: resp_headers,
        body,
    } = resp;
    // Restored in the check's scope only; nothing recorded, tripwired, or
    // seeded (`Scope::Check`). The client mode is irrelevant on a check
    // route and never widens anything. No `x-inumaki-*` headers.
    let (sse, body) = crate::handler::sniff(status, &resp_headers, body).await?;
    if sse {
        let ctx = StreamCtx {
            session,
            wire,
            up,
            mode: ClientMode::Restricted,
            scope: Scope::Check(dataset),
            seed: SeedStamp::unverified(),
            oauth: OauthUse::None,
            timing: None,
        };
        return Ok(crate::handler::stream_reply(
            inner,
            ctx,
            status,
            &resp_headers,
            body,
            inflight,
            None,
        ));
    }
    let buf = crate::handler::collect(body, max).await?;
    let task_inner = Arc::clone(inner);
    let answer = tokio::task::spawn_blocking(move || {
        crate::respond::non_streaming(
            &task_inner.sh,
            &session,
            wire,
            up,
            ClientMode::Restricted,
            status,
            &buf,
            Scope::Check(dataset),
            SeedStamp::unverified(),
        )
    })
    .await
    .map_err(|_| Fail::Internal)??;
    drop(inflight);
    Ok(crate::handler::reply(
        status,
        &resp_headers,
        answer.body,
        None,
    ))
}
