//! Upstream clients (M4 spec §5.2): a child process on stdio, a Streamable
//! HTTP server, or an in-process handler over a duplex pipe; each is
//! supervised and restarted with backoff. Child stderr is read and
//! discarded (byte count only). Nothing here logs command lines,
//! environment values, header values, or upstream messages; the dataset
//! appears only as the opaque label the caller passes.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use http::{HeaderName, HeaderValue};
use inumaki_vault::UpstreamKind;
use rmcp::model::{ClientCapabilities, ClientConfig, Implementation, InitializeRequestParams};
use rmcp::service::{
    ClientInitializeError, NotificationContext, RunningService, serve_server_with_ct,
};
use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::async_rw::{JsonRpcMessageCodec, JsonRpcMessageCodecError};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{ClientHandler, Peer, RoleClient, ServerHandler, ServiceExt};
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Decoder, FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;

use crate::aggregate::UpstreamLists;
use crate::handles::Owner;
use crate::status::{ContractState, UpstreamStatus};

/// A boxed `Send` future.
pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
/// Keeps an in-process server alive; dropping it stops the server.
pub type ServerGuard = Box<dyn std::any::Any + Send + Sync>;
/// A connected upstream client.
pub type Running = RunningService<RoleClient, UpstreamClient>;

/// What an upstream tells its dataset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamEvent {
    /// The lists changed (or it just connected): rebuild the catalog.
    ListChanged {
        /// Upstream name.
        upstream: String,
    },
    /// The upstream went away: rebuild the catalog. It stays in the catalog
    /// with its last-known lists ([`UpstreamHandle::last_lists`]) so its
    /// names keep their owner; calls to it answer `upstream_unavailable`
    /// until it is running again.
    Exited {
        /// Upstream name.
        upstream: String,
    },
}

/// The rmcp client handler for one upstream: forwards the allowlisted
/// list-changed notifications to the dataset's event channel. Every other
/// upstream notification is dropped (M4 spec §5.2).
#[derive(Clone)]
pub struct UpstreamClient {
    /// Upstream name.
    pub name: String,
    /// Dataset event channel.
    pub events: mpsc::UnboundedSender<UpstreamEvent>,
}

impl std::fmt::Debug for UpstreamClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamClient")
            .field("name", &self.name)
            .finish()
    }
}

impl UpstreamClient {
    fn changed(&self) {
        let _ = self.events.send(UpstreamEvent::ListChanged {
            upstream: self.name.clone(),
        });
    }
}

impl ClientHandler for UpstreamClient {
    fn get_info(&self) -> ClientConfig {
        InitializeRequestParams::new(
            ClientCapabilities::default(),
            Implementation::new("inumaki-gateway", env!("CARGO_PKG_VERSION")),
        )
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.changed();
    }

    async fn on_prompt_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.changed();
    }

    async fn on_resource_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.changed();
    }
}

/// Lifecycle state, as `status` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamState {
    /// Connecting or spawning.
    Starting,
    /// Serving calls.
    Running,
    /// Not connected; carries the failure class, never a message.
    Failed(&'static str),
    /// Stopped by the daemon.
    Stopped,
}

impl std::fmt::Display for UpstreamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamState::Starting => f.write_str("starting"),
            UpstreamState::Running => f.write_str("running"),
            UpstreamState::Failed(class) => write!(f, "failed({class})"),
            UpstreamState::Stopped => f.write_str("stopped"),
        }
    }
}

/// An upstream row with its secrets merged in. `Debug` prints counts.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedUpstream {
    /// Name.
    pub name: String,
    /// Transport.
    pub kind: UpstreamKind,
    /// `stdio`: program.
    pub command: Option<String>,
    /// `stdio`: arguments.
    pub args: Vec<String>,
    /// `stdio`: working directory.
    pub cwd: Option<String>,
    /// `http`: base URL.
    pub url: Option<String>,
    /// `stdio`: environment on top of [`INHERITED_ENV`], secrets included.
    pub env: BTreeMap<String, String>,
    /// `http`: headers, secrets included.
    pub headers: BTreeMap<String, String>,
}

impl std::fmt::Debug for ResolvedUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedUpstream")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("has_command", &self.command.is_some())
            .field("args", &self.args.len())
            .field("has_cwd", &self.cwd.is_some())
            .field("has_url", &self.url.is_some())
            .field("env", &self.env.len())
            .field("headers", &self.headers.len())
            .finish()
    }
}

/// Why an upstream could not be reached. Classes only.
#[derive(Debug, Clone, thiserror::Error)]
pub enum UpstreamError {
    /// The child could not be spawned.
    #[error("spawn failed: {0:?}")]
    Spawn(std::io::ErrorKind),
    /// The MCP handshake failed; carries a class.
    #[error("initialize failed: {0}")]
    Init(&'static str),
    /// A required field is missing or malformed; carries the field name.
    #[error("upstream configuration: {0}")]
    Config(&'static str),
    /// A built-in upstream failed; carries its error class.
    #[error("built-in upstream failed: {0}")]
    Builtin(&'static str),
}

impl UpstreamError {
    /// Short class for `status` and logs.
    pub fn class(&self) -> &'static str {
        match self {
            UpstreamError::Spawn(_) => "spawn",
            UpstreamError::Init(_) => "init",
            UpstreamError::Config(_) => "config",
            UpstreamError::Builtin(c) => c,
        }
    }
}

/// In-process upstreams the daemon provides (plan 3: the mail connector).
pub trait BuiltinUpstreams: Send + Sync + 'static {
    /// Start the built-in upstream `upstream` of `dataset` and connect `client` to it.
    fn connect(
        &self,
        dataset: &str,
        upstream: &str,
        client: UpstreamClient,
    ) -> BoxFut<Result<(Running, ServerGuard), UpstreamError>>;
}

fn init_class(e: &ClientInitializeError) -> &'static str {
    match e {
        ClientInitializeError::ExpectedInitResponse(_) => "unexpected_response",
        ClientInitializeError::ExpectedInitResult(_) => "unexpected_result",
        ClientInitializeError::ConflictInitResponseId(_, _) => "response_id",
        ClientInitializeError::ConnectionClosed(_) => "connection_closed",
        ClientInitializeError::TransportError { .. } => "transport",
        ClientInitializeError::JsonRpcError(_) => "json_rpc",
        ClientInitializeError::NoCompatibleProtocolVersion { .. } => "protocol_version",
        ClientInitializeError::Cancelled => "cancelled",
        _ => "init",
    }
}

/// Serve `server` in-process over a duplex pipe and connect `client` to
/// it. The returned guard keeps the server side alive; `ct` stops it.
pub async fn connect_in_process<S: ServerHandler>(
    server: S,
    client: UpstreamClient,
    ct: CancellationToken,
) -> Result<(Running, ServerGuard), UpstreamError> {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (a_rd, a_wr) = tokio::io::split(a);
    let (b_rd, b_wr) = tokio::io::split(b);
    let (server_side, client_side) = tokio::join!(
        serve_server_with_ct(server, (a_rd, a_wr), ct),
        client.serve((b_rd, b_wr))
    );
    let server_side = server_side.map_err(|_| UpstreamError::Init("in_process_server"))?;
    let running = client_side.map_err(|e| UpstreamError::Init(init_class(&e)))?;
    Ok((running, Box::new(server_side)))
}

/// Room for the JSON-RPC envelope on top of the escaped result bytes.
pub const ENVELOPE_HEADROOM: usize = 64 * 1024;

/// The largest single message accepted from an upstream for a
/// `max_response_bytes` limit: six times the limit (JSON escapes a control
/// character as `\u00XX`, six bytes for one) plus [`ENVELOPE_HEADROOM`],
/// so a result within the limit never ends the connection. The limit
/// itself is enforced on the decoded result ([`crate::limits::Limits`]).
pub fn max_message_bytes(max_response_bytes: usize) -> usize {
    max_response_bytes
        .saturating_mul(6)
        .saturating_add(ENVELOPE_HEADROOM)
}

/// Newline-delimited JSON-RPC from a child, at most `max` bytes per line.
/// rmcp's own stdio reader buffers a line of any length; this one keeps at
/// most `max + 1` bytes and ends the connection on a longer line (flagging
/// it, so the waiting call answers `resource_limit`). A line that is not a
/// JSON-RPC message is skipped, as rmcp's reader does.
struct BoundedCodec {
    inner: JsonRpcMessageCodec<RxJsonRpcMessage<RoleClient>>,
    oversized: Arc<AtomicBool>,
}

impl Decoder for BoundedCodec {
    type Item = RxJsonRpcMessage<RoleClient>;
    type Error = JsonRpcMessageCodecError;

    fn decode(&mut self, buf: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            let before = buf.len();
            match self.inner.decode(buf) {
                // The line is consumed before it is parsed: move on.
                Err(JsonRpcMessageCodecError::Serde(_)) => continue,
                Err(JsonRpcMessageCodecError::MaxLineLengthExceeded) => {
                    self.oversized.store(true, Ordering::Release);
                    return Err(JsonRpcMessageCodecError::MaxLineLengthExceeded);
                }
                // rmcp consumed a line it ignores (a non-standard
                // notification): the next line may already be buffered, and
                // `Ok(None)` would make the reader wait for more input first.
                Ok(None) if buf.len() < before => continue,
                other => return other,
            }
        }
    }

    fn decode_eof(&mut self, buf: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(m) = self.decode(buf)? {
            return Ok(Some(m));
        }
        match self.inner.decode_eof(buf) {
            Err(JsonRpcMessageCodecError::Serde(_)) => Ok(None),
            other => other,
        }
    }
}

/// The child's stdout as messages. Dropping it (the connection ended)
/// kills the child.
struct ChildMessages {
    frames: FramedRead<tokio::process::ChildStdout, BoundedCodec>,
    _kill: oneshot::Sender<()>,
}

impl futures::Stream for ChildMessages {
    type Item = RxJsonRpcMessage<RoleClient>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.frames).poll_next(cx) {
            Poll::Ready(Some(Ok(m))) => Poll::Ready(Some(m)),
            // A decode error (an oversized line) ends the connection.
            Poll::Ready(Some(Err(_)) | None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Variables a stdio child takes from the daemon's environment. Anything
/// else there (API keys, tokens, proxy and CA settings) stays out; an
/// upstream that needs more gets it through its configured `env` or
/// secret env.
pub const INHERITED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "USER",
    "LOGNAME",
    "SHELL",
    "XDG_RUNTIME_DIR",
];

/// The environment of a stdio child: [`INHERITED_ENV`] from `parent`, then
/// the upstream's configured environment (secrets included), which wins.
pub fn child_env(
    parent: impl IntoIterator<Item = (OsString, OsString)>,
    configured: &BTreeMap<String, String>,
) -> BTreeMap<OsString, OsString> {
    let mut env: BTreeMap<OsString, OsString> = parent
        .into_iter()
        .filter(|(k, _)| k.to_str().is_some_and(|k| INHERITED_ENV.contains(&k)))
        .collect();
    for (k, v) in configured {
        env.insert(k.into(), v.into());
    }
    env
}

/// Spawn the child with the stored arguments, working directory, and a
/// cleared environment with [`INHERITED_ENV`] from the daemon's, then the
/// stored environment, discard its stderr counting the bytes, and run the
/// MCP handshake over its stdio, reading at most `max_message` bytes per
/// message (`oversized` is set when a longer one ends the connection).
pub async fn connect_stdio(
    u: &ResolvedUpstream,
    client: UpstreamClient,
    stderr_bytes: Arc<AtomicU64>,
    max_message: usize,
    oversized: Arc<AtomicBool>,
) -> Result<Running, UpstreamError> {
    let command = u
        .command
        .as_deref()
        .ok_or(UpstreamError::Config("command"))?;
    let mut cmd = tokio::process::Command::new(command);
    cmd.args(&u.args);
    if let Some(cwd) = &u.cwd {
        cmd.current_dir(cwd);
    }
    cmd.env_clear();
    cmd.envs(child_env(std::env::vars_os(), &u.env));
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A child holding secrets in its environment must not outlive the
    // daemon, even when the runtime shuts down before the kill task runs.
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| UpstreamError::Spawn(e.kind()))?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(UpstreamError::Spawn(std::io::ErrorKind::BrokenPipe));
    };
    if let Some(mut err) = child.stderr.take() {
        let counter = Arc::clone(&stderr_bytes);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match err.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        counter.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
            }
        });
    }
    // Reap the child when it exits; kill it when the connection is dropped.
    let (kill, killed) = oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::select! {
            _ = child.wait() => {}
            _ = killed => {}
        }
        let _ = child.kill().await;
    });
    let messages = ChildMessages {
        frames: FramedRead::new(
            stdout,
            BoundedCodec {
                inner: JsonRpcMessageCodec::new_with_max_length(max_message),
                oversized,
            },
        ),
        _kill: kill,
    };
    let sink = FramedWrite::new(
        stdin,
        JsonRpcMessageCodec::<TxJsonRpcMessage<RoleClient>>::default(),
    );
    client
        .serve((sink, messages))
        .await
        .map_err(|e| UpstreamError::Init(init_class(&e)))
}

/// Connect to a Streamable HTTP server with the stored headers, accepting
/// SSE events of at most `max_message` bytes. An `Authorization: Bearer …`
/// header becomes the transport's auth header; any other `Authorization`
/// scheme is refused.
pub async fn connect_http(
    u: &ResolvedUpstream,
    client: UpstreamClient,
    max_message: usize,
) -> Result<Running, UpstreamError> {
    crate::ensure_crypto_provider();
    let url = u.url.as_deref().ok_or(UpstreamError::Config("url"))?;
    let mut cfg = StreamableHttpClientTransportConfig::with_uri(url.to_string());
    // Bounds one SSE event; a plain `application/json` response body is
    // read whole by rmcp (not capped here).
    cfg.max_sse_event_size = max_message;
    for (k, v) in &u.headers {
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|_| UpstreamError::Config("header_name"))?;
        if name == http::header::AUTHORIZATION {
            let bearer = v
                .strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
                .ok_or(UpstreamError::Config("authorization"))?;
            cfg.auth_header = Some(bearer.to_string());
            continue;
        }
        let mut value =
            HeaderValue::from_str(v).map_err(|_| UpstreamError::Config("header_value"))?;
        // Stored headers may carry secrets; keep them out of HTTP-stack debug output.
        value.set_sensitive(true);
        cfg.custom_headers.insert(name, value);
    }
    client
        .serve(StreamableHttpClientTransport::from_config(cfg))
        .await
        .map_err(|e| UpstreamError::Init(init_class(&e)))
}

/// `min(2^attempt s, max)`.
pub fn backoff(attempt: u32, max: Duration) -> Duration {
    let secs = 1u64.checked_shl(attempt.min(40)).unwrap_or(u64::MAX);
    Duration::from_secs(secs).min(max)
}

/// An upstream that stays connected at least this long has recovered: its
/// next failure restarts after the shortest backoff again. One that exits
/// sooner keeps climbing the backoff, so a server that crashes right after
/// its handshake is not restarted every second forever.
pub const STABLE_UPTIME: Duration = Duration::from_secs(30);

/// Source of [`Owner::generation`]: unique per supervisor in this process.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// The supervisor task's view of an upstream. The task holds only this,
/// never the [`UpstreamHandle`], so dropping the last handle stops the task
/// (and with it the connection and any child) even without [`UpstreamHandle::stop`].
struct Shared {
    state: RwLock<UpstreamState>,
    restarts: AtomicU32,
    stderr_bytes: Arc<AtomicU64>,
    /// The current connection ended on a message over the size limit.
    oversized: Arc<AtomicBool>,
    peer: RwLock<Option<Peer<RoleClient>>>,
    cancel: CancellationToken,
}

impl Shared {
    fn set_state(&self, s: UpstreamState) {
        *self.state.write().unwrap_or_else(PoisonError::into_inner) = s;
    }

    fn set_peer(&self, p: Option<Peer<RoleClient>>) {
        *self.peer.write().unwrap_or_else(PoisonError::into_inner) = p;
    }
}

/// One supervised upstream. Dropping it cancels the supervisor.
pub struct UpstreamHandle {
    /// Name.
    pub name: String,
    /// Transport.
    pub kind: UpstreamKind,
    generation: u64,
    shared: Arc<Shared>,
    last_lists: Mutex<Option<UpstreamLists>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for UpstreamHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamHandle")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("generation", &self.generation)
            .field("state", &self.state())
            .finish()
    }
}

impl Drop for UpstreamHandle {
    fn drop(&mut self) {
        self.shared.cancel.cancel();
    }
}

impl UpstreamHandle {
    /// Start supervising `resolved`: connect, serve until it exits, back
    /// off, reconnect; until `stop` or drop. `dataset_label` is the opaque
    /// log label; `dataset_id` is passed to built-ins only.
    pub fn spawn(
        dataset_label: String,
        dataset_id: String,
        resolved: ResolvedUpstream,
        events: mpsc::UnboundedSender<UpstreamEvent>,
        builtin: Arc<dyn BuiltinUpstreams>,
        supervision: Supervision,
    ) -> Arc<UpstreamHandle> {
        let shared = Arc::new(Shared {
            state: RwLock::new(UpstreamState::Starting),
            restarts: AtomicU32::new(0),
            stderr_bytes: Arc::new(AtomicU64::new(0)),
            oversized: Arc::new(AtomicBool::new(false)),
            peer: RwLock::new(None),
            cancel: CancellationToken::new(),
        });
        let name = resolved.name.clone();
        let kind = resolved.kind;
        let task = tokio::spawn(supervise(
            Arc::clone(&shared),
            dataset_label,
            dataset_id,
            resolved,
            events,
            builtin,
            supervision,
        ));
        Arc::new(UpstreamHandle {
            name,
            kind,
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            shared,
            last_lists: Mutex::new(None),
            task: Mutex::new(Some(task)),
        })
    }

    /// This upstream's handle owner: name plus a generation unique to this
    /// supervisor. A removed and re-added upstream of the same name is a
    /// different owner.
    pub fn owner(&self) -> Owner {
        Owner::new(self.name.clone(), self.generation)
    }

    /// Record the sanitized lists of the latest successful listing.
    pub fn set_last_lists(&self, lists: UpstreamLists) {
        *self
            .last_lists
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(lists);
    }

    /// The sanitized lists of the latest successful listing, kept while the
    /// upstream is down so a catalog rebuild keeps its names with it
    /// ([`crate::aggregate::Catalog::build`]). `None` before the first listing.
    pub fn last_lists(&self) -> Option<UpstreamLists> {
        self.last_lists
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// True when the current connection ended because the upstream sent a
    /// message over the size limit ([`max_message_bytes`]); reset on the
    /// next connect. Calls that failed with it answer `resource_limit`.
    pub fn oversized(&self) -> bool {
        self.shared.oversized.load(Ordering::Acquire)
    }

    /// Current state.
    pub fn state(&self) -> UpstreamState {
        self.shared
            .state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The connected peer, when running.
    pub fn peer(&self) -> Option<Peer<RoleClient>> {
        self.shared
            .peer
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// For `status`.
    pub fn status(&self, contract: ContractState) -> UpstreamStatus {
        UpstreamStatus {
            name: self.name.clone(),
            kind: self.kind.as_str().to_string(),
            state: self.state().to_string(),
            restarts: self.shared.restarts.load(Ordering::Relaxed),
            stderr_bytes: self.shared.stderr_bytes.load(Ordering::Relaxed),
            contract: contract.as_str().to_string(),
            schema_fingerprint: None,
        }
    }

    /// Stop the supervisor and the connection (a child is killed by the transport's drop).
    pub async fn stop(&self) {
        self.shared.cancel.cancel();
        let task = self
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(t) = task {
            let _ = t.await;
        }
        self.shared.set_peer(None);
        self.shared.set_state(UpstreamState::Stopped);
    }
}

/// How an upstream is supervised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Supervision {
    /// Cap on the restart backoff.
    pub max_backoff: Duration,
    /// A spawn plus handshake that takes longer fails (class `init`) and is
    /// retried like any failed start.
    pub handshake_timeout: Duration,
    /// Largest single message read from the upstream ([`max_message_bytes`]).
    pub max_message: usize,
}

impl Supervision {
    /// From the gateway settings.
    pub fn from_config(cfg: &crate::GatewayConfig) -> Self {
        Supervision {
            max_backoff: cfg.restart_max_backoff,
            handshake_timeout: cfg.call_timeout,
            max_message: max_message_bytes(cfg.max_response_bytes),
        }
    }
}

async fn supervise(
    shared: Arc<Shared>,
    dataset_label: String,
    dataset_id: String,
    resolved: ResolvedUpstream,
    events: mpsc::UnboundedSender<UpstreamEvent>,
    builtin: Arc<dyn BuiltinUpstreams>,
    supervision: Supervision,
) {
    let Supervision {
        max_backoff,
        handshake_timeout,
        max_message,
    } = supervision;
    let mut attempt: u32 = 0;
    loop {
        if shared.cancel.is_cancelled() {
            break;
        }
        shared.set_state(UpstreamState::Starting);
        shared.oversized.store(false, Ordering::Release);
        let client = UpstreamClient {
            name: resolved.name.clone(),
            events: events.clone(),
        };
        let connect = async {
            match resolved.kind {
                UpstreamKind::Stdio => connect_stdio(
                    &resolved,
                    client,
                    Arc::clone(&shared.stderr_bytes),
                    max_message,
                    Arc::clone(&shared.oversized),
                )
                .await
                .map(|r| (r, None)),
                UpstreamKind::Http => connect_http(&resolved, client, max_message)
                    .await
                    .map(|r| (r, None)),
                UpstreamKind::Mail => builtin
                    .connect(&dataset_id, &resolved.name, client)
                    .await
                    .map(|(r, g)| (r, Some(g))),
            }
        };
        // A hanging spawn or handshake must not hold up `stop`, nor keep
        // the upstream `starting` forever.
        let connected: Result<(Running, Option<ServerGuard>), UpstreamError> = tokio::select! {
            _ = shared.cancel.cancelled() => {
                shared.set_state(UpstreamState::Stopped);
                break;
            }
            c = tokio::time::timeout(handshake_timeout, connect) => {
                c.unwrap_or(Err(UpstreamError::Init("handshake_timeout")))
            }
        };
        match connected {
            Ok((running, guard)) => {
                let up_since = tokio::time::Instant::now();
                shared.set_peer(Some(running.peer().clone()));
                shared.set_state(UpstreamState::Running);
                tracing::info!(dataset = %dataset_label, upstream = %resolved.name, kind = resolved.kind.as_str(), "upstream running");
                let _ = events.send(UpstreamEvent::ListChanged {
                    upstream: resolved.name.clone(),
                });
                let ct = running.cancellation_token();
                let wait = running.waiting();
                tokio::pin!(wait);
                tokio::select! {
                    _ = shared.cancel.cancelled() => {
                        ct.cancel();
                        let _ = wait.await;
                        drop(guard);
                        shared.set_peer(None);
                        shared.set_state(UpstreamState::Stopped);
                        break;
                    }
                    r = &mut wait => {
                        drop(guard);
                        tracing::warn!(dataset = %dataset_label, upstream = %resolved.name, clean = r.is_ok(), "upstream exited");
                    }
                }
                if up_since.elapsed() >= STABLE_UPTIME {
                    attempt = 0;
                }
                shared.set_peer(None);
                shared.set_state(UpstreamState::Failed("exited"));
                shared.restarts.fetch_add(1, Ordering::Relaxed);
                let _ = events.send(UpstreamEvent::Exited {
                    upstream: resolved.name.clone(),
                });
            }
            Err(e) => {
                shared.set_state(UpstreamState::Failed(e.class()));
                tracing::warn!(dataset = %dataset_label, upstream = %resolved.name, class = e.class(), attempt, "upstream failed to start");
            }
        }
        let delay = backoff(attempt, max_backoff);
        attempt = attempt.saturating_add(1);
        tokio::select! {
            _ = shared.cancel.cancelled() => {
                shared.set_state(UpstreamState::Stopped);
                break;
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec() -> BoundedCodec {
        BoundedCodec {
            inner: JsonRpcMessageCodec::new_with_max_length(4096),
            oversized: Arc::new(AtomicBool::new(false)),
        }
    }

    const RESPONSE: &str =
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}"#;

    /// A non-standard notification rmcp cannot parse; its codec consumes
    /// the line and answers `Ok(None)` ("ignored").
    const IGNORED: &str = r#"{"jsonrpc":"2.0","method":"$/custom","params":5}"#;

    #[test]
    fn ignored_lines_do_not_hide_a_buffered_message() {
        // The premise: rmcp's codec swallows the line with `Ok(None)`.
        let mut raw = JsonRpcMessageCodec::<RxJsonRpcMessage<RoleClient>>::new();
        let mut buf = bytes::BytesMut::from(format!("{IGNORED}\n{RESPONSE}\n").as_str());
        assert!(raw.decode(&mut buf).unwrap().is_none());
        assert_eq!(
            buf.len(),
            RESPONSE.len() + 1,
            "the ignored line was consumed"
        );
        // Ours goes on to the response in the same chunk.
        let mut c = codec();
        let mut buf =
            bytes::BytesMut::from(format!("{IGNORED}\n{IGNORED}\nnot json\n{RESPONSE}\n").as_str());
        let m = c
            .decode(&mut buf)
            .unwrap()
            .expect("the response in the same chunk");
        assert!(
            matches!(m, rmcp::model::JsonRpcMessage::Response(_)),
            "{m:?}"
        );
        assert!(buf.is_empty());
        assert!(
            c.decode(&mut buf).unwrap().is_none(),
            "nothing left, nothing consumed"
        );
        // A partial line is left for more input.
        let mut buf = bytes::BytesMut::from(&RESPONSE[..10]);
        assert!(c.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 10);
    }

    #[test]
    fn an_overlong_line_is_flagged() {
        let mut c = codec();
        let mut buf = bytes::BytesMut::from("x".repeat(5000).as_str());
        assert!(c.decode(&mut buf).is_err());
        assert!(c.oversized.load(Ordering::Acquire));
        assert_eq!(max_message_bytes(1000), 6000 + ENVELOPE_HEADROOM);
    }

    /// Plan 2c, Review Focus 5: a stdio child gets the allowlisted part of
    /// the daemon's environment, then its own configured values, which win.
    #[test]
    fn stdio_children_get_an_allowlisted_environment() {
        use std::ffi::OsString;
        let parent = [
            ("PATH", "/usr/bin"),
            ("HOME", "/home/u"),
            ("LANG", "de_AT.UTF-8"),
            ("LC_ALL", "de_AT.UTF-8"),
            ("SSL_CERT_FILE", "/etc/ssl/corp.pem"),
            ("AWS_SECRET_ACCESS_KEY", "fake-aws-secret-canary"),
            ("OPENAI_API_KEY", "sk-fake-canary"),
            ("HTTPS_PROXY", "http://proxy.example:3128"),
        ]
        .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let mut configured = BTreeMap::new();
        configured.insert("CRM_URL".to_string(), "https://crm.example".to_string());
        configured.insert("HOME".to_string(), "/srv/crm".to_string());
        let env = child_env(parent, &configured);
        let keys: Vec<&str> = env.keys().filter_map(|k| k.to_str()).collect();
        assert_eq!(keys, ["CRM_URL", "HOME", "LANG", "LC_ALL", "PATH"]);
        assert_eq!(
            env[&OsString::from("HOME")],
            "/srv/crm",
            "configured values win"
        );
        assert!(!format!("{env:?}").contains("canary"));
    }
}
