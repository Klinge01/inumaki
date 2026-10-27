//! The transport guard shared by the TCP listeners (M4 spec §16.8): the
//! gateway's and the model-API proxy's. `Host` and `Origin` validation, no
//! protocol upgrades, no CORS headers out, and a fixed `500` for a panicking
//! handler. Moved out of `api::gateway` unchanged; the gateway and the proxy
//! both call [`layer`].

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::{ORIGIN, UPGRADE};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use futures::FutureExt;

use crate::api::ApiError;

/// Host names accepted on a TCP listener, with no port or with
/// the bound listen port (M4 spec §16.8, controller ruling S5), in addition
/// to the configured listen address itself (spec §16.8 bullet 2) held in
/// [`GuardConfig::listen_host`]. Kept alongside rmcp's own `allowed_hosts`
/// (Global Constraints), which runs after bearer auth and is not port-aware.
const ALLOWED_HOST_NAMES: [&str; 4] = ["localhost", "127.0.0.1", "[::1]", "inumakid"];

/// `Host`/`Origin` check inputs fixed once a TCP listener is
/// bound (review round 1 #8): no per-request lock or config lookup.
pub(crate) struct GuardConfig {
    /// The listener's `allowed_origins` setting, verbatim.
    pub(crate) allowed_origins: Vec<String>,
    /// The bound listen port.
    pub(crate) bound_port: u16,
    /// The bound listen address's host literal (bracketed for IPv6): M4
    /// spec §16.8's "the configured listen address".
    pub(crate) listen_host: String,
}

/// `127.0.0.1`, or `[::1]` for an IPv6 address (matching the bracketed form
/// a `Host` header and [`ALLOWED_HOST_NAMES`] use).
fn host_literal(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// Split a `Host` header value into its name and, if present, its port
/// text. `None` means the value is malformed and must be refused rather
/// than matched against anything: a bracketed IPv6 literal (`[::1]` or
/// `[::1]:8789`) is parsed so the brackets stay part of the name, and
/// anything after the closing bracket other than empty or `:<digits>` (a
/// stray suffix like `[::1]evil`) fails closed; likewise a plain name with
/// a colon whose tail is not all digits (`localhost:`, `a:b:c`) fails
/// closed instead of falling back to matching the whole raw string.
fn split_host_port(h: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = h.strip_prefix('[') {
        let close = rest.find(']')?;
        let name = &h[..close + 2];
        let after = &rest[close + 1..];
        if after.is_empty() {
            return Some((name, None));
        }
        let port = after.strip_prefix(':')?;
        return (!port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
            .then_some((name, Some(port)));
    }
    match h.rsplit_once(':') {
        Some((name, port)) => (!port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
            .then_some((name, Some(port))),
        None => Some((h, None)),
    }
}

/// `true` when `host_header` names one of [`ALLOWED_HOST_NAMES`] or
/// `cfg.listen_host`, and carries no port or exactly `cfg.bound_port`.
fn host_allowed(host_header: &str, cfg: &GuardConfig) -> bool {
    let Some((name, port)) = split_host_port(host_header) else {
        return false;
    };
    let name_ok = ALLOWED_HOST_NAMES
        .iter()
        .any(|a| a.eq_ignore_ascii_case(name))
        || cfg.listen_host.eq_ignore_ascii_case(name);
    if !name_ok {
        return false;
    }
    match port {
        None => true,
        Some(p) => matches!(p.parse::<u16>(), Ok(pp) if pp == cfg.bound_port),
    }
}

/// Refuse browser origins, foreign `Host` values, and protocol upgrades
/// before authentication, and never let a CORS header out (M4 spec §16.8).
/// The rejected `Host`/`Origin` value is never logged or echoed: only the
/// fixed refusal class reaches the response and the access log records
/// nothing beyond the usual method/route/status.
pub(crate) async fn origin_guard(
    State(cfg): State<Arc<GuardConfig>>,
    req: Request,
    next: Next,
) -> Response {
    let host_ok = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|h| host_allowed(h, &cfg));
    if !host_ok {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "host_not_allowed",
            "host is not allowed",
        )
        .into_response();
    }
    if req.headers().contains_key(UPGRADE) {
        return ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "upgrade_not_supported",
            "protocol upgrades are not supported",
        )
        .into_response();
    }
    if let Some(origin) = req.headers().get(ORIGIN) {
        let allowed = origin
            .to_str()
            .map(|o| cfg.allowed_origins.iter().any(|a| a == o))
            .unwrap_or(false);
        if !allowed {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "origin_not_allowed",
                "requests from browser origins are not accepted",
            )
            .into_response();
        }
    }
    let mut resp = next.run(req).await;
    let cors: Vec<_> = resp
        .headers()
        .keys()
        .filter(|k| k.as_str().starts_with("access-control-"))
        .cloned()
        .collect();
    for k in cors {
        resp.headers_mut().remove(k);
    }
    resp
}

/// Wrap `router` in the §16.8 guard for a listener bound at `bound`, and in a
/// catch-panic layer outside it: a panic in any handler answers a fixed
/// `500 internal` with an opaque request id and never carries panic text.
/// The guard covers the router's fallback too, so an unserved path is
/// checked before it is answered.
pub fn layer<S: Clone + Send + Sync + 'static>(
    router: Router<S>,
    allowed_origins: Vec<String>,
    bound: std::net::SocketAddr,
) -> Router<S> {
    let cfg = Arc::new(GuardConfig {
        allowed_origins,
        bound_port: bound.port(),
        listen_host: host_literal(bound.ip()),
    });
    router
        .layer(middleware::from_fn_with_state(cfg, origin_guard))
        .layer(middleware::from_fn(catch_panic))
}

/// Answer a panic in the handler below with a fixed body. The panic payload
/// is dropped unread: it can carry request text. The id is random, appears in
/// the log line and in the body, and names nothing.
async fn catch_panic(req: Request, next: Next) -> Response {
    match AssertUnwindSafe(next.run(req)).catch_unwind().await {
        Ok(resp) => resp,
        Err(_) => {
            let id = opaque_id();
            tracing::error!(request = %id, "a request handler panicked");
            let err = ApiError::internal("internal error");
            let mut body = err.body();
            body["error"]["request_id"] = serde_json::Value::String(id);
            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(body)).into_response()
        }
    }
}

/// 8 random bytes as 16 hex digits; `"0000000000000000"` if the system
/// has no randomness (the id carries no meaning either way).
fn opaque_id() -> String {
    let mut b = [0u8; 8];
    if getrandom::fill(&mut b).is_err() {
        b = [0; 8];
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::HeaderValue;
    use axum::routing::get;
    use tower::ServiceExt;

    use super::*;

    fn cfg(bound_port: u16, listen_host: &str, allowed_origins: &[&str]) -> Arc<GuardConfig> {
        Arc::new(GuardConfig {
            allowed_origins: allowed_origins.iter().map(|s| s.to_string()).collect(),
            bound_port,
            listen_host: listen_host.to_string(),
        })
    }

    /// Review round 1 #4: a table of `Host` values against
    /// `split_host_port`/`host_allowed`, covering the malformed and
    /// case/format edge cases the fix round asked for, plus the configured
    /// listen address (review round 1 #2).
    #[test]
    fn split_host_port_and_host_allowed_cases() {
        let c = cfg(8789, "127.0.0.2", &[]);
        let allowed = [
            "[::1]",
            "[::1]:8789",
            "LOCALHOST:8789",
            "localhost",
            "127.0.0.1",
            "127.0.0.2",      // the configured listen address, no port
            "127.0.0.2:8789", // the configured listen address, bound port
            "INUMAKID",
        ];
        for h in allowed {
            assert!(host_allowed(h, &c), "{h} should be allowed");
        }
        let refused = [
            "[::1]:other",    // non-numeric port after a bracketed literal
            "[::1]evil",      // stray suffix, no colon
            "[::1]:",         // colon with no port digits
            "localhost.",     // trailing dot never matches the bare name
            "localhost:",     // colon with no port digits
            "127.1",          // not the loopback literal exactly
            "user@localhost", // not a bare host
            "0.0.0.0",
            "a:b:c", // multi-colon, no brackets, non-numeric tail
            "evil.example",
            "127.0.0.2:9999", // configured listen address, wrong port
            "localhost:9999", // right name, wrong port
        ];
        for h in refused {
            assert!(!host_allowed(h, &c), "{h} should be refused");
        }
    }

    /// Review round 1 #5: the CORS-strip loop actually removes headers an
    /// inner service emits, not just proves the daemon never adds them.
    #[tokio::test]
    async fn cors_headers_are_stripped_even_when_the_inner_service_sets_them() {
        async fn emits_cors() -> Response {
            let mut resp = StatusCode::OK.into_response();
            resp.headers_mut()
                .insert("access-control-allow-origin", HeaderValue::from_static("*"));
            resp.headers_mut().insert(
                "access-control-allow-credentials",
                HeaderValue::from_static("true"),
            );
            resp
        }
        let app = Router::new()
            .route("/x", get(emits_cors))
            .layer(middleware::from_fn_with_state(
                cfg(8789, "127.0.0.1", &[]),
                origin_guard,
            ));
        let req = Request::builder()
            .uri("/x")
            .header("host", "127.0.0.1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            !resp
                .headers()
                .keys()
                .any(|k| k.as_str().starts_with("access-control-")),
            "{:?}",
            resp.headers()
        );
    }

    /// The guard, as mounted: a foreign `Origin` or `Host` is refused before
    /// the handler runs, an upgrade is not implemented, and a handler that
    /// panics answers the fixed 500 without its panic text.
    #[tokio::test]
    async fn layer_refuses_foreign_callers_and_survives_a_panic() {
        async fn ok() -> &'static str {
            "ok"
        }
        async fn boom() -> &'static str {
            panic!("canary-panic-text");
        }
        let bound: std::net::SocketAddr = "127.0.0.1:8787".parse().unwrap();
        let app = layer(
            Router::new()
                .route("/ok", get(ok))
                .route("/boom", get(boom)),
            vec![],
            bound,
        );
        let call = |uri: &str, headers: &[(&str, &str)]| {
            let mut r = Request::builder().uri(uri);
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            app.clone().oneshot(r.body(Body::empty()).unwrap())
        };
        let good = [("host", "127.0.0.1:8787")];
        assert_eq!(call("/ok", &good).await.unwrap().status(), StatusCode::OK);
        let bad_origin = [
            ("host", "127.0.0.1:8787"),
            ("origin", "https://evil.example"),
        ];
        assert_eq!(
            call("/ok", &bad_origin).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let bad_host = [("host", "evil.example")];
        assert_eq!(
            call("/ok", &bad_host).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let upgrade = [("host", "127.0.0.1:8787"), ("upgrade", "websocket")];
        assert_eq!(
            call("/ok", &upgrade).await.unwrap().status(),
            StatusCode::NOT_IMPLEMENTED
        );
        let resp = call("/boom", &good).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!text.contains("canary-panic-text"), "{text}");
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["error"]["type"], "internal");
        assert_eq!(v["error"]["request_id"].as_str().unwrap().len(), 16);
    }
}
