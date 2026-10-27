//! Daemons and bare states with the mirror rooted in a temporary directory.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use inumakid::{AppState, StartOptions};

use super::{BASE_CONFIG, TestDaemon, short_socket_path, start_with, start_with_config};

/// A serving daemon; `base` is the canonical temporary directory.
pub struct MirrorDaemon {
    pub d: TestDaemon,
    pub _t: tempfile::TempDir,
    pub base: PathBuf,
    pub root: PathBuf,
}

/// A state from `AppState::start` with nothing served: the mirror service
/// has not started (spec §7.2 step 2 runs in `serve_with`).
pub struct MirrorState {
    pub state: Arc<AppState>,
    pub _t: tempfile::TempDir,
    pub base: PathBuf,
    pub root: PathBuf,
}

pub fn mirror_toml(base: &Path, root: &Path) -> String {
    format!(
        "[mirror]\nroot = \"{}\"\noutbox_root = \"{}\"\n",
        root.display(),
        base.join("Outbox").display()
    )
}

pub async fn start_mirror() -> MirrorDaemon {
    let t = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(t.path()).unwrap();
    let root = base.join("Inumaki");
    let d = start_with(
        "",
        &mirror_toml(&base, &root),
        Duration::from_secs(3600),
        None,
    )
    .await;
    MirrorDaemon {
        d,
        _t: t,
        base,
        root,
    }
}

/// `start_mirror` with `INUMAKI_MODELS_DIR` as the models directory (a
/// model-backed profile needs the real files; `start_mirror` has none).
pub async fn start_mirror_with_models() -> MirrorDaemon {
    let t = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(t.path()).unwrap();
    let root = base.join("Inumaki");
    let models =
        PathBuf::from(std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"));
    let config = format!(
        "{BASE_CONFIG}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n{}",
        mirror_toml(&base, &root)
    );
    let d = start_with_config(config, Some(models), Duration::from_secs(3600), None).await;
    MirrorDaemon {
        d,
        _t: t,
        base,
        root,
    }
}

/// A daemon serving on a directory that may hold an earlier run's data,
/// with the time `AppState::start` took and the time until the control
/// socket answered (the mirror service starts in between, spec §7.2).
pub struct Serving {
    pub state: Arc<AppState>,
    pub task: tokio::task::JoinHandle<Result<(), inumakid::StartError>>,
    pub client: inumakid::client::Client,
    pub start: Duration,
    pub ready: Duration,
}

pub async fn serve_on(base: &Path, root: &Path) -> Serving {
    write_config(base, root);
    let opts = options(base);
    let socket = opts.socket.clone().unwrap();
    let t0 = std::time::Instant::now();
    let state = Arc::new(
        tokio::task::spawn_blocking(move || AppState::start(&opts))
            .await
            .unwrap()
            .unwrap(),
    );
    let start = t0.elapsed();
    let task = tokio::spawn(inumakid::server::serve_with(
        Arc::clone(&state),
        Duration::from_secs(3600),
    ));
    let client = inumakid::client::Client::new(&socket);
    let mut ready = None;
    for _ in 0..24_000 {
        if client
            .call(hyper::Method::GET, "/v1/status", None)
            .await
            .is_ok()
        {
            ready = Some(t0.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Serving {
        state,
        task,
        client,
        start,
        ready: ready.expect("daemon did not come up"),
    }
}

impl Serving {
    pub async fn stop(self) {
        self.state.shutdown.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(60), self.task).await;
    }
}

pub async fn start_state_only() -> MirrorState {
    start_state_with(|_, _| {}).await
}

fn options(base: &Path) -> StartOptions {
    StartOptions {
        config: Some(base.join("inumaki.toml")),
        data_dir: Some(base.join("data")),
        socket: Some(short_socket_path("m")),
        models_dir: Some(base.join("no-models")),
        clock: None,
    }
}

fn write_config(base: &Path, root: &Path) {
    std::fs::write(
        base.join("inumaki.toml"),
        format!(
            "{BASE_CONFIG}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n{}",
            mirror_toml(base, root)
        ),
    )
    .unwrap();
    std::fs::create_dir_all(base.join("no-models")).unwrap();
}

/// Like [`start_state_only`]; `setup(base, root)` runs before the start
/// (a root that is a symlink, a foreign directory, ...).
pub async fn start_state_with(setup: impl FnOnce(&Path, &Path)) -> MirrorState {
    let t = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(t.path()).unwrap();
    let root = base.join("Inumaki");
    setup(&base, &root);
    write_config(&base, &root);
    let opts = options(&base);
    let state = Arc::new(
        tokio::task::spawn_blocking(move || AppState::start(&opts))
            .await
            .unwrap()
            .unwrap(),
    );
    MirrorState {
        state,
        _t: t,
        base,
        root,
    }
}

impl MirrorState {
    /// Drop this state and start another on the same data directory, with
    /// the mirror root replaced when `root` is given. The temporary
    /// directory goes with the returned guard.
    pub async fn restart(
        self,
        root: Option<PathBuf>,
    ) -> (Result<AppState, inumakid::StartError>, tempfile::TempDir) {
        let MirrorState {
            state,
            _t,
            base,
            root: old,
        } = self;
        drop(state);
        write_config(&base, root.as_deref().unwrap_or(&old));
        let opts = options(&base);
        let r = tokio::task::spawn_blocking(move || AppState::start(&opts))
            .await
            .unwrap();
        (r, _t)
    }
}
