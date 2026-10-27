//! The upstream seam (M8 spec §4): what the handler sends and what comes
//! back. `forward::HttpUpstream` talks to the providers; tests and the
//! scripted upstream implement [`Upstream`] in memory.
//!
//! Privacy: a request carries a sanitized body and the harness's own
//! credentials in its headers, so `Debug` prints the upstream, the method,
//! and lengths only. Errors are fixed classes.

use std::fmt;

use crate::routes::UpstreamId;

/// One request the pipeline produced, ready to send.
///
/// `Debug` prints the upstream, the method, and the body length only: never
/// the path and query, a header, or the body.
pub struct UpstreamRequest {
    /// Where it goes.
    pub upstream: UpstreamId,
    /// The HTTP method.
    pub method: http::Method,
    /// Path and query relative to the upstream's base URL.
    pub path_and_query: String,
    /// Outbound headers (after the header rules of spec §5.8).
    pub headers: http::HeaderMap,
    /// The sanitized body.
    pub body: bytes::Bytes,
}

impl fmt::Debug for UpstreamRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamRequest")
            .field("upstream", &self.upstream)
            .field("method", &self.method)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The upstream's answer: status, headers, and the body as a stream.
///
/// `Debug` prints the status and the header count only.
pub struct UpstreamResponse {
    /// The upstream's status.
    pub status: http::StatusCode,
    /// The upstream's headers, unfiltered.
    pub headers: http::HeaderMap,
    /// The body, chunk by chunk.
    pub body: futures::stream::BoxStream<'static, Result<bytes::Bytes, UpstreamError>>,
}

impl fmt::Debug for UpstreamResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamResponse")
            .field("status", &self.status)
            .field("headers", &self.headers.len())
            .finish_non_exhaustive()
    }
}

/// Why sending failed. Fixed classes only: never a URL, a header, or text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    /// Connection or TLS failure.
    #[error("upstream unreachable")]
    Unreachable,
    /// No answer in time.
    #[error("upstream timeout")]
    Timeout,
    /// The body broke off.
    #[error("upstream body failed")]
    Body,
}

/// Something that sends a request upstream.
pub trait Upstream: Send + Sync + 'static {
    /// Send `req`; resolves when the status and headers are in.
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>>;
}
