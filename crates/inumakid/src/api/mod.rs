//! Control API routes (spec §10.3). JSON over HTTP/1.1 on the Unix socket.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use tracing::Instrument;

use crate::state::AppState;

pub mod activity;
pub mod check;
pub mod datasets;
pub mod doctor;
pub mod entities;
pub mod error;
pub mod folders;
pub mod gateway;
pub mod hook;
pub mod inspect;
pub mod journal;
pub mod mailbox;
pub mod models;
pub mod proxy;
pub mod rehydrate;
pub mod sanitize;
pub mod service;
pub mod status;
pub mod upstreams;

pub use error::ApiError;

/// Request body limit; larger bodies get `413`.
pub const BODY_LIMIT: usize = 16 * 1024 * 1024;

/// Method, route template, status, duration, request id. Never a body, a
/// raw path, a query string, or a path parameter (M4 spec §5.4): the
/// template `/v1/datasets/{id}` is logged, the id is not; an unmatched
/// path is logged as the constant `unmatched`.
pub(crate) async fn access_log(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let id = state.requests.fetch_add(1, Ordering::Relaxed);
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_string(), |m| m.as_str().to_string());
    let t = Instant::now();
    let span = tracing::info_span!("request", id, %method, %route);
    async move {
        let resp = next.run(req).await;
        tracing::info!(
            status = resp.status().as_u16(),
            duration_ms = t.elapsed().as_millis() as u64,
            "access"
        );
        resp
    }
    .instrument(span)
    .await
}

/// The application router.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/status", get(status::status))
        // Activity records: control socket only (M4 spec §16.4).
        .route("/v1/activity", get(activity::list))
        .route("/v1/activity/verify", get(activity::verify))
        .route("/v1/datasets", get(datasets::list).post(datasets::create))
        .route("/v1/datasets/{id}", axum::routing::delete(datasets::remove))
        .route("/v1/datasets/{id}/rotate", post(datasets::rotate))
        // Connected folders: control socket only (M5 spec §12); the answers
        // carry paths.
        .route("/v1/folders", get(folders::list))
        .route(
            "/v1/datasets/{id}/folder",
            get(folders::show)
                .post(folders::create)
                .delete(folders::remove),
        )
        .route("/v1/datasets/{id}/folder/rescan", post(folders::rescan))
        // The egress journal: control socket only (M4 spec §16.3).
        .route("/v1/datasets/{id}/journal", get(journal::list))
        .route("/v1/datasets/{id}/journal/{record}", get(journal::show))
        // Entity listing and forget: control socket only (M4 spec §16.3).
        // The static `forget` segment wins over `{token}` in axum 0.8, and
        // a token always carries its `<`/`>` delimiters, so they never collide.
        .route("/v1/datasets/{id}/entities", get(entities::list))
        .route(
            "/v1/datasets/{id}/entities/forget",
            post(entities::forget_value),
        )
        .route(
            "/v1/datasets/{id}/entities/{token}",
            axum::routing::delete(entities::forget_token),
        )
        .route(
            "/v1/datasets/{id}/upstreams",
            get(upstreams::list).post(upstreams::create),
        )
        // Mailboxes: control socket only (M4 spec §8).
        .route(
            "/v1/datasets/{id}/mailbox",
            get(mailbox::get)
                .post(mailbox::create)
                .delete(mailbox::remove),
        )
        .route("/v1/datasets/{id}/mailbox/check", post(mailbox::check))
        .route(
            "/v1/datasets/{id}/upstreams/{name}",
            axum::routing::delete(upstreams::remove),
        )
        .route(
            "/v1/datasets/{id}/upstreams/{name}/accept-schema",
            post(upstreams::accept_schema),
        )
        .route(
            "/v1/gateway/tokens",
            get(gateway::list_tokens).post(gateway::create_token),
        )
        .route(
            "/v1/gateway/tokens/{id}",
            axum::routing::delete(gateway::revoke_token),
        )
        .route("/v1/doctor", get(doctor::doctor))
        // M6 spec §9.7: control socket only.
        .route("/v1/service", get(service::service))
        // M8 spec §11: control socket only.
        .route("/v1/proxy", get(proxy::status))
        .route("/v1/models/pull", get(models::get).post(models::start))
        .route("/v1/check", post(check::create))
        .route("/v1/check/{id}", get(check::get).delete(check::remove))
        .route("/v1/check/{id}/direct", post(check::direct))
        .route("/v1/check/{id}/harness", post(check::harness))
        .route("/v1/sanitize", post(sanitize::sanitize))
        .route("/v1/inspect", post(inspect::inspect_handler))
        // Tool-result hook: control socket only (M6 spec §9.7).
        .route("/v1/hook", post(hook::hook))
        .route("/v1/rehydrate", post(rehydrate::rehydrate))
        .route("/v1/shutdown", post(shutdown))
        // The gateway on the control socket: no bearer token, the socket's
        // file mode is the authorization (M4 spec §5.1).
        .route("/mcp/{dataset}", axum::routing::any(gateway::mcp_socket))
        // Unmatched routes and wrong methods get the documented body shape too (review I5).
        .fallback(|| async { ApiError::not_found("no such route") })
        .method_not_allowed_fallback(|| async {
            ApiError::new(
                axum::http::StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "method not allowed",
            )
        })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            access_log,
        ))
        .with_state(state)
}

/// `POST /v1/shutdown`: 202, then the server drains and exits.
async fn shutdown(
    State(state): State<Arc<AppState>>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    tracing::info!("shutdown requested over the API");
    state.shutdown.send_replace(true);
    (
        axum::http::StatusCode::ACCEPTED,
        axum::Json(serde_json::json!({ "status": "shutting_down" })),
    )
}

/// A failed task's fixed class. Never log a `JoinError` itself: its
/// `Display` and `Debug` carry the panic payload, and std's own panic
/// messages can quote content (a `str` slice prints the string).
pub(crate) fn join_class(e: &tokio::task::JoinError) -> &'static str {
    if e.is_panic() {
        "panicked"
    } else {
        "cancelled"
    }
}

/// Run a blocking closure on the blocking pool; a panic becomes a 500.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(class = join_class(&e), "request worker failed");
            Err(ApiError::internal("request worker failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex, PoisonError};

    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    /// 8b review I1: a request worker that panics with content in its
    /// message is logged as a fixed class; the payload never reaches the log.
    #[tokio::test]
    async fn a_panicking_request_worker_logs_no_payload() {
        let cap = Capture::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone()),
        );
        let _guard = tracing::subscriber::set_default(subscriber);
        let r: Result<(), ApiError> = blocking(|| {
            let text = String::from("\u{e4}Zyxwuria Quolnath");
            let cut = std::hint::black_box(1);
            let _ = &text[..cut];
            Ok(())
        })
        .await;
        assert!(r.is_err());
        let out = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("request worker failed") && out.contains("panicked"),
            "{out}"
        );
        assert!(!out.contains("Zyxwuria"), "{out}");
    }
}
