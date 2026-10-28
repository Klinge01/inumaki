//! inumaki's model-API proxy (M8 spec). Requests are sanitized leaf by
//! leaf before they leave; answers are restored locally. Everything that
//! needs the vault, models, or the activity writer comes from the injected
//! `host::ProxyHost`.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use zeroize::Zeroizing;

#[doc(hidden)]
pub mod bench_text;
pub mod cache;
pub mod check;
mod check_route;
#[cfg(test)]
mod check_tests;
mod closure;
pub mod config;
pub mod error;
pub mod forward;
mod handler;
#[cfg(test)]
mod handler_stream_tests;
#[cfg(test)]
mod handler_tests;
pub mod holdback;
pub mod host;
pub mod json;
pub mod memo;
#[cfg(test)]
mod memo_tests;
#[cfg(test)]
mod origin_tests;
mod pipeline;
#[cfg(test)]
mod pipeline_tests;
mod respond;
#[cfg(test)]
mod respond_tests;
pub mod restore;
pub mod routes;
pub mod scripted;
pub mod session;
#[cfg(feature = "closure-shadow")]
pub mod shadow;
pub mod sse;
pub mod status;
mod stream;
#[cfg(test)]
mod stream_tests;
#[cfg(test)]
mod testing;
pub mod timing;
pub mod upstream;
pub mod walk;
mod wire;

pub use check::{CheckId, CheckRoutes, RecordedRequest};
pub use config::{BaseUrls, BinaryMode, ProxyConfig, StaticNer, TripwireMode, UncertainMode};
pub use error::{ErrorClass, Fail};
pub use routes::{Endpoint, UpstreamId, Wire};
pub use scripted::{Script, ScriptedUpstream, Step, ToolCall};
pub use status::{CODEX_CHATGPT_VERIFIED, ClientKind, ListenState, ProxyStatusBody};

use host::ProxyHost;

/// What every request handler shares. No `Debug`: it holds the client value.
pub(crate) struct Inner {
    pub sh: pipeline::Shared,
    pub upstream: Arc<dyn upstream::Upstream>,
    pub sessions: session::SessionStore,
    pub status: status::Status,
    pub client_value: Zeroizing<String>,
    /// Requests in flight (`max_inflight`).
    pub inflight: tokio::sync::Semaphore,
    /// Weighted admission for scans (`config::SCAN_WEIGHT` permits per
    /// decoded body byte), so concurrent hostile bodies cannot exhaust memory.
    pub scan: Arc<tokio::sync::Semaphore>,
    /// The scan budget's size in permits.
    pub scan_total: usize,
    pub listen: Mutex<ListenState>,
    /// The check-route registry (spec §12.2).
    pub check: Arc<check::CheckRoutes>,
}

/// The proxy. Cheap to clone. `Debug` prints the type name only.
#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Proxy")
    }
}

impl Proxy {
    /// The production constructor: installs the rustls provider and builds
    /// the HTTP upstream. `client_value` is the per-install value of
    /// `X-Inumaki-Client`.
    pub fn new(
        cfg: ProxyConfig,
        host: Arc<dyn ProxyHost>,
        client_value: Zeroizing<String>,
    ) -> Result<Proxy, Fail> {
        forward::ensure_crypto_provider();
        let upstream = Arc::new(forward::HttpUpstream::new(&cfg)?);
        Proxy::try_with_upstream(cfg, host, client_value, upstream)
    }

    /// Like [`Proxy::new`] with the upstream injected (tests, the scripted
    /// check upstream). Fails closed with [`Fail::Internal`] when the
    /// identity dictionary or the session-token pattern cannot be built.
    pub fn try_with_upstream(
        cfg: ProxyConfig,
        host: Arc<dyn ProxyHost>,
        client_value: Zeroizing<String>,
        upstream: Arc<dyn upstream::Upstream>,
    ) -> Result<Proxy, Fail> {
        Proxy::build(
            cfg,
            host,
            client_value,
            upstream,
            config::SCAN_BUDGET_PERMITS,
        )
    }

    /// [`Proxy::try_with_upstream`] for this crate's unit tests, which have
    /// nothing to do about a failure. Production code uses [`Proxy::new`]
    /// or [`Proxy::try_with_upstream`].
    ///
    /// # Panics
    ///
    /// When the identity dictionary or the session-token pattern cannot be
    /// built.
    #[cfg(test)]
    pub(crate) fn with_upstream(
        cfg: ProxyConfig,
        host: Arc<dyn ProxyHost>,
        client_value: Zeroizing<String>,
        upstream: Arc<dyn upstream::Upstream>,
    ) -> Proxy {
        Proxy::try_with_upstream(cfg, host, client_value, upstream)
            .expect("the proxy builds from a valid configuration")
    }

    pub(crate) fn build(
        cfg: ProxyConfig,
        host: Arc<dyn ProxyHost>,
        client_value: Zeroizing<String>,
        upstream: Arc<dyn upstream::Upstream>,
        scan_total: usize,
    ) -> Result<Proxy, Fail> {
        let sessions = session::SessionStore::new(
            cfg.session_ttl,
            cfg.session_cap,
            cfg.session_tokens.clone(),
            cfg.cache_bytes,
        );
        let inflight = tokio::sync::Semaphore::new(cfg.max_inflight);
        let check = Arc::new(check::CheckRoutes::new(cfg.session_tokens.clone()));
        let sh = pipeline::Shared::new(cfg, host)?;
        #[cfg(feature = "closure-shadow")]
        tracing::warn!("closure shadow mode is compiled in: a measurement build, not for use");
        Ok(Proxy {
            inner: Arc::new(Inner {
                sh,
                upstream,
                sessions,
                status: status::Status::new(),
                client_value,
                inflight,
                scan: Arc::new(tokio::sync::Semaphore::new(scan_total)),
                scan_total,
                listen: Mutex::new(ListenState::Disabled),
                check,
            }),
        })
    }

    /// The routes. `inumakid` wraps the router in its transport guard.
    pub fn router(&self) -> axum::Router {
        use axum::routing::any;
        axum::Router::new()
            .route("/anthropic/{*rest}", any(handler::anthropic))
            .route("/openai/{*rest}", any(handler::openai))
            .route("/codex/{*rest}", any(handler::codex))
            .route("/check/{id}/{upstream}/{*rest}", any(check_route::serve))
            .fallback(|| async { Fail::NotServed.response(None) })
            .with_state(Arc::clone(&self.inner))
    }

    /// Record how the proxy is listening (`GET /v1/proxy`).
    pub fn set_listen(&self, s: ListenState) {
        *self
            .inner
            .listen
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = s;
    }

    /// How the proxy is listening right now.
    pub fn listen_state(&self) -> ListenState {
        *self
            .inner
            .listen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The `GET /v1/proxy` body.
    pub fn status(&self) -> ProxyStatusBody {
        let listen = *self
            .inner
            .listen
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.inner.status.body(
            &self.inner.sh.cfg,
            &listen,
            self.inner.sessions.len() as u64,
            self.inner.sessions.entries(),
            self.inner.check.len() as u64,
            &self.inner.client_value,
            timing::StaticCacheBody::new(
                self.inner.sh.cfg.static_cache,
                self.inner.sh.memo.as_ref().map(|m| m.stats()),
            ),
        )
    }

    /// Drop expired sessions and check routes; returns how many went.
    pub fn sweep(&self) -> usize {
        self.inner.sessions.sweep() + self.inner.check.sweep()
    }

    /// The check-route registry (M6 spec §9.6); the same instance for the
    /// proxy's lifetime.
    pub fn check_routes(&self) -> Arc<check::CheckRoutes> {
        Arc::clone(&self.inner.check)
    }

    /// The settings this proxy runs with.
    pub fn config(&self) -> &ProxyConfig {
        &self.inner.sh.cfg
    }
}
