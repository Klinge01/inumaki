#![allow(dead_code)]

pub mod gateway;
pub mod mirror;

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing_subscriber::fmt::MakeWriter;

/// An in-memory `tracing` writer: every canary test (Task 7's
/// `gateway_canary.rs`, `canary.rs`, `gateway_transport.rs`, and later
/// tests) installs this behind `inumakid::run::log_filter` and asserts a
/// canary value never appears in the captured bytes.
#[derive(Clone)]
pub struct Capture(pub Arc<Mutex<Vec<u8>>>);

impl Capture {
    /// A fresh, empty capture buffer.
    pub fn new() -> Self {
        Capture(Arc::new(Mutex::new(Vec::new())))
    }

    /// The captured bytes as a `String` so far.
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Default for Capture {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
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

/// Percent-encode one URL path segment: everything but `[A-Za-z0-9-._~]`
/// (a token's `<`/`>` included), for `…/entities/{token}` paths.
pub fn encode_segment(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

use hyper::Method;
use inumaki_vault::Clock;
use inumakid::client::Client;
use inumakid::{AppState, StartOptions};

/// The shipped config, extended per test.
pub const BASE_CONFIG: &str = include_str!("../../../../configs/default.toml");

/// The directory a test daemon runs in: its own temporary one, or one the
/// test lent it (`start_in`).
pub struct TestDir {
    _owned: Option<tempfile::TempDir>,
    path: PathBuf,
}

impl TestDir {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

/// A running in-process daemon.
pub struct TestDaemon {
    pub dir: TestDir,
    pub state: Arc<AppState>,
    pub client: Client,
    pub socket: PathBuf,
    pub task: tokio::task::JoinHandle<Result<(), inumakid::StartError>>,
}

/// macOS limits socket paths to 104 bytes and tempdirs under `/var/folders`
/// are long, so sockets go directly under the temp dir with a short name.
///
/// Adaptation: the nanosecond timestamp alone can collide between two API
/// tests starting their daemons on different threads in the same process at
/// the same instant (observed as a flaky `Connect { kind: NotFound }` or a
/// closed connection on an unrelated test, because the second daemon's
/// client ends up talking to the first daemon's socket). A process-wide
/// atomic counter makes every path unique regardless of clock resolution.
pub fn short_socket_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "inumakid-{}-{nanos}-{n}-{tag}.sock",
        std::process::id()
    ))
}

/// Start from a complete config text. The text gets `[proxy] listen =
/// "127.0.0.1:0"` unless it has a `[proxy]` table of its own, so parallel
/// test daemons never bind the real proxy port.
pub async fn start_with_config(
    config_text: String,
    models_dir: Option<PathBuf>,
    sweep_every: Duration,
    clock: Option<Arc<dyn Clock>>,
) -> TestDaemon {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    start_core(
        TestDir {
            _owned: Some(dir),
            path,
        },
        config_text,
        models_dir,
        sweep_every,
        clock,
    )
    .await
}

/// Write the test configuration into `dir` and build the start options:
/// the `[proxy]` and `[mirror]` lines unless the text has its own, a
/// `no-models` directory unless one is given, and a short socket path.
fn prepare_start(
    dir: &std::path::Path,
    mut config_text: String,
    models_dir: Option<PathBuf>,
    clock: Option<Arc<dyn Clock>>,
) -> (StartOptions, PathBuf) {
    if !config_text.lines().any(|l| l.starts_with("[proxy]")) {
        config_text.push_str("\n[proxy]\nlisten = \"127.0.0.1:0\"\n");
    }
    let cfg = dir.join("inumaki.toml");
    // The mirror root is created at start (M5 spec §7.2): never in the
    // real home directory.
    let config_text = if config_text.lines().any(|l| l.trim() == "[mirror]") {
        config_text
    } else {
        format!(
            "{config_text}\n[mirror]\nroot = \"{0}/mirror-root\"\noutbox_root = \"{0}/mirror-outbox\"\n",
            dir.display()
        )
    };
    std::fs::write(&cfg, config_text).unwrap();
    let models_dir = models_dir.unwrap_or_else(|| {
        let m = dir.join("no-models");
        std::fs::create_dir_all(&m).unwrap();
        m
    });
    let socket = short_socket_path("t");
    let opts = StartOptions {
        config: Some(cfg),
        data_dir: Some(dir.join("data")),
        socket: Some(socket.clone()),
        models_dir: Some(models_dir),
        clock,
    };
    (opts, socket)
}

async fn start_core(
    dir: TestDir,
    config_text: String,
    models_dir: Option<PathBuf>,
    sweep_every: Duration,
    clock: Option<Arc<dyn Clock>>,
) -> TestDaemon {
    let (opts, socket) = prepare_start(dir.path(), config_text, models_dir, clock);
    let state = Arc::new(
        tokio::task::spawn_blocking(move || AppState::start(&opts))
            .await
            .unwrap()
            .unwrap(),
    );
    let task = tokio::spawn(inumakid::server::serve_with(
        Arc::clone(&state),
        sweep_every,
    ));
    let client = Client::new(&socket);
    let mut ready = false;
    for _ in 0..400 {
        if client.call(Method::GET, "/v1/status", None).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(ready, "daemon did not come up");
    TestDaemon {
        dir,
        state,
        client,
        socket,
        task,
    }
}

/// The base configuration of the test daemons: offline profile, a
/// file-keyed vault, a random gateway port, and the caller's extras.
fn base_text(daemon_extra: &str, extra_toml: &str) -> String {
    format!(
        "{BASE_CONFIG}\n[daemon]\ndefault_profile = \"offline\"\n{daemon_extra}\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n{extra_toml}\n"
    )
}

/// Start with extra lines inside `[daemon]` (`daemon_extra`), extra TOML at
/// the end (`extra_toml`, e.g. profiles), a sweep period, and an optional clock.
pub async fn start_with(
    daemon_extra: &str,
    extra_toml: &str,
    sweep_every: Duration,
    clock: Option<Arc<dyn Clock>>,
) -> TestDaemon {
    start_with_config(
        base_text(daemon_extra, extra_toml),
        None,
        sweep_every,
        clock,
    )
    .await
}

/// Start the base configuration (plus `extra` TOML) on an existing
/// directory: the data directory is `dir/data`, so two daemons started one
/// after the other on the same `dir` share a vault.
pub async fn start_in(dir: &std::path::Path, extra: &str) -> TestDaemon {
    start_core(
        TestDir {
            _owned: None,
            path: dir.to_path_buf(),
        },
        base_text("", extra),
        None,
        Duration::from_secs(3600),
        None,
    )
    .await
}

/// Start the base configuration on `dir` like [`start_in`], but await
/// `serve_with` itself instead of waiting for the control API: the state,
/// the socket path, and what `serve_with` returned (a start that fails
/// after `AppState::start`).
pub async fn serve_result_in(
    dir: &std::path::Path,
) -> (Arc<AppState>, PathBuf, Result<(), inumakid::StartError>) {
    let (opts, socket) = prepare_start(dir, base_text("", ""), None, None);
    let state = Arc::new(
        tokio::task::spawn_blocking(move || AppState::start(&opts))
            .await
            .unwrap()
            .unwrap(),
    );
    // A start that wrongly succeeds would serve forever: bounded.
    let r = tokio::time::timeout(
        Duration::from_secs(30),
        inumakid::server::serve_with(Arc::clone(&state), Duration::from_secs(3600)),
    )
    .await
    .expect("serve_with did not return within 30 s: the start did not fail");
    (state, socket, r)
}

/// Open the vault of a daemon started on `dir` with exactly the options the
/// base configuration gives the daemon. Open it only while no daemon runs on
/// `dir`, or for rows the daemon reads on demand.
pub fn open_vault(dir: &std::path::Path) -> inumaki_vault::Vault {
    let cfg = inumakid::config::DaemonConfig::from_toml(&base_text("", "")).unwrap();
    let data_dir = dir.join("data");
    let aliases =
        Arc::new(inumaki_core::alias::AliasTable::from_config(&cfg.core.dictionary).unwrap());
    inumaki_vault::Vault::open(inumaki_vault::VaultOptions {
        path: data_dir.join(&cfg.vault.path),
        data_dir,
        key_source: cfg.key_source,
        key_store: None,
        tokens: cfg.vault_tokens(),
        automaton_max_entries: cfg.vault.automaton_max_entries,
        keyring_timeout: Duration::from_secs(2),
        aliases,
    })
    .unwrap()
}

/// Default: offline profile, hourly sweep, system clock.
pub async fn start() -> TestDaemon {
    start_with("", "", Duration::from_secs(3600), None).await
}

impl TestDaemon {
    /// Status code and body.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        let r = self.client.call(method, path, body.as_ref()).await.unwrap();
        (r.status.as_u16(), r.body)
    }

    /// Create a dataset with the offline profile.
    pub async fn dataset(&self, id: &str) {
        let (code, body) = self
            .call(
                Method::POST,
                "/v1/datasets",
                Some(serde_json::json!({ "id": id, "name": "Kunde" })),
            )
            .await;
        assert_eq!(code, 201, "{body}");
    }

    /// The gateway's bound TCP address.
    pub fn gateway_addr(&self) -> std::net::SocketAddr {
        self.state
            .gateway_listen
            .lock()
            .unwrap()
            .expect("gateway bound before the socket answered")
    }

    /// Request shutdown and wait for the server task.
    pub async fn stop(self) {
        self.state.shutdown.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
    }
}
