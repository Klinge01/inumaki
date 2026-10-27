//! HTTP/1.1 client over the Unix socket, shared by the CLI and the tests.
//! hyper over `tokio::net::UnixStream`; no reqwest.

use std::path::{Path, PathBuf};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

/// Client errors. Never carry a response body.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The socket could not be connected.
    #[error("cannot connect to {path}: {kind:?}")]
    Connect {
        /// Socket path.
        path: String,
        /// Error kind.
        kind: std::io::ErrorKind,
    },
    /// The HTTP exchange failed.
    #[error("http error: {0}")]
    Http(String),
    /// The response body was not JSON.
    #[error("response is not JSON")]
    Json,
}

/// A response: status and parsed JSON body (`Null` when empty).
#[derive(Clone)]
pub struct Reply {
    /// HTTP status.
    pub status: StatusCode,
    /// Body.
    pub body: serde_json::Value,
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("status", &self.status)
            .finish()
    }
}

/// Client for one socket path.
#[derive(Debug, Clone)]
pub struct Client {
    socket: PathBuf,
}

impl Client {
    /// Client for `socket`.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Client {
            socket: socket.into(),
        }
    }

    /// The socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Send a JSON body (or none) and parse the JSON reply.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Reply, ClientError> {
        let bytes = match body {
            Some(b) => serde_json::to_vec(b).map_err(|_| ClientError::Json)?,
            None => Vec::new(),
        };
        self.call_raw(method, path, bytes).await
    }

    /// Send raw bytes as `application/json` and parse the JSON reply.
    pub async fn call_raw(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Result<Reply, ClientError> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|e| ClientError::Connect {
                path: self.socket.display().to_string(),
                kind: e.kind(),
            })?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "inumakid")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?
            .to_bytes();
        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| ClientError::Json)?
        };
        Ok(Reply { status, body })
    }

    /// [`Client::call`] from synchronous code (the CLI): a current-thread
    /// runtime per call.
    pub fn call_blocking(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Reply, ClientError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ClientError::Http(e.to_string()))?;
        rt.block_on(self.call(method, path, body))
    }
}
