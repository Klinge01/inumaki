//! HTTP/1.1 over the control socket: one connection per request, a deadline
//! over the whole exchange (connect included), and errors that never carry
//! a body or an error message.

use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;

use crate::types::{ErrorBody, ErrorDetail};

/// Deadline per request unless [`Client::with_timeout`] sets another.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Client errors. `Display` and `Debug` show the status and the error
/// `type`, never the daemon's `message` (it can name a dataset id) and never
/// a body.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The socket could not be connected (service not running, wrong path).
    #[error("cannot connect to the inumaki service ({0:?})")]
    Connect(std::io::ErrorKind),
    /// No complete answer before the deadline.
    #[error("the inumaki service did not answer in time")]
    Timeout,
    /// The HTTP exchange failed at a fixed stage.
    #[error("http exchange failed ({0})")]
    Http(&'static str),
    /// A non-2xx answer; `error` is `None` when the body was not the
    /// documented error shape (for example axum's plain-text `413`).
    #[error("the inumaki service answered {status}{}", kind_suffix(.error))]
    Status {
        /// HTTP status.
        status: u16,
        /// The parsed error, if the body had the documented shape.
        error: Option<ErrorDetail>,
    },
    /// A 2xx body that does not have the expected shape.
    #[error("the response did not have the expected shape")]
    Decode,
    /// The request body could not be serialized.
    #[error("the request could not be encoded")]
    Encode,
}

fn kind_suffix(e: &Option<ErrorDetail>) -> String {
    e.as_ref()
        .map(|d| {
            let k = if is_safe_kind(&d.kind) {
                d.kind.as_str()
            } else {
                "unknown"
            };
            format!(" {k}")
        })
        .unwrap_or_default()
}

/// `d.kind` is the daemon's `error.type` string, untrusted input from the
/// wire. Only a value matching this shape (every real `type` in the spec:
/// `bad_request`, `not_found`, `privacy_block`, `unresolved_token`, ...) is
/// safe to print verbatim in `Display`/`Debug` output that may be logged.
fn is_safe_kind(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.chars().all(|c| c.is_ascii_lowercase() || c == '_')
}

impl ClientError {
    /// The HTTP status of a `Status` error.
    pub fn status(&self) -> Option<u16> {
        match self {
            ClientError::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The parsed error body of a `Status` error.
    pub fn detail(&self) -> Option<&ErrorDetail> {
        match self {
            ClientError::Status { error, .. } => error.as_ref(),
            _ => None,
        }
    }
}

/// A raw answer: status and body bytes.
pub struct RawReply {
    /// HTTP status.
    pub status: u16,
    /// Body bytes (empty for `204`).
    pub body: Vec<u8>,
}

impl std::fmt::Debug for RawReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawReply")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Client for one control socket.
///
/// Must run inside a Tokio runtime with both the I/O and time drivers
/// enabled (`#[tokio::main]`, or `Builder::new_multi_thread().enable_all()`):
/// `enable_io()` for the Unix socket, `enable_time()` for [`Client::raw`]'s
/// deadline. Without `enable_time()` the first call panics.
#[derive(Clone)]
pub struct Client {
    socket: PathBuf,
    timeout: Duration,
}

impl std::fmt::Debug for Client {
    /// The socket path lives under the user's home directory: not printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Client for `socket` with [`DEFAULT_TIMEOUT`].
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Client {
            socket: socket.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The same client with another deadline per request.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Send `body` (empty for none) as `application/json`; return the raw
    /// answer whatever its status. `path` must already be percent-encoded
    /// where needed: the caller (normally a method in `endpoints.rs`) is
    /// responsible for calling [`encode`] on any untrusted path segment or
    /// query value before building it; `raw` does not encode it for you.
    pub async fn raw(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Result<RawReply, ClientError> {
        tokio::time::timeout(self.timeout, self.exchange(method, path, body))
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    async fn exchange(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Result<RawReply, ClientError> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|e| ClientError::Connect(e.kind()))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| ClientError::Http("handshake"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "inumakid")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| ClientError::Http("request"))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|_| ClientError::Http("send"))?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|_| ClientError::Http("body"))?
            .to_bytes()
            .to_vec();
        Ok(RawReply { status, body })
    }

    /// Send, then return the 2xx body or a `Status` error.
    async fn call<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<Vec<u8>, ClientError> {
        let bytes = match body {
            Some(b) => serde_json::to_vec(b).map_err(|_| ClientError::Encode)?,
            None => Vec::new(),
        };
        let reply = self.raw(method, path, bytes).await?;
        if (200..300).contains(&reply.status) {
            Ok(reply.body)
        } else {
            let error = serde_json::from_slice::<ErrorBody>(&reply.body)
                .ok()
                .map(|b| b.error);
            Err(ClientError::Status {
                status: reply.status,
                error,
            })
        }
    }

    /// A call whose 2xx body decodes into `R`.
    pub(crate) async fn json<B: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<R, ClientError> {
        let bytes = self.call(method, path, body).await?;
        serde_json::from_slice(&bytes).map_err(|_| ClientError::Decode)
    }

    /// A call whose 2xx body is ignored (`204`).
    pub(crate) async fn empty<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<(), ClientError> {
        self.call(method, path, body).await.map(|_| ())
    }
}

/// Percent-encode one path segment or query value: RFC 3986 unreserved
/// characters pass, every other byte becomes `%XX`.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
