//! The end-to-end canary check (M6 spec §8). A shipped feature, not a test
//! fixture: it verifies the gateway, the mirror, and the proxy with a
//! synthetic identity, one check at a time, for at most [`CHECK_TTL`].
//! Everything it creates carries the reserved dataset prefix
//! [`CHECK_PREFIX`] or token label prefix [`CHECK_TOKEN_PREFIX`]; the public
//! endpoints refuse both and [`sweep_leftovers`] removes the generated
//! shapes of them at startup.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use crate::state::AppState;
use canary::Canary;
use gateway_probe::{GatewayProbe, RmcpProbe};
use proxy::ProxyCheckRoutes;

pub mod canary;
pub mod canary_mcp;
pub mod gateway_probe;
pub mod mirror;
pub mod proxy;
pub mod proxy_m8;
pub mod runner;
pub mod types;
pub mod verdict;

/// Temporary source and outbox directories of the mirror check live under
/// the system temp directory as `inumaki-check-<tag>-<random>`, where `tag`
/// identifies this data directory: a sweep removes only its own.
pub const TMP_PREFIX: &str = "inumaki-check-";

/// The first 12 hex digits of SHA-256 of the data directory's path.
pub fn tmp_tag(data_dir: &Path) -> String {
    Sha256::digest(data_dir.as_os_str().as_encoded_bytes())
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One in-process request to the control router, marked [`Internal`]
/// (the check's calls to the §9.5 folders contract, and the sweep's).
pub(crate) async fn internal(
    state: &Arc<AppState>,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Option<(u16, Value)> {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
        .ok()?;
    req.extensions_mut().insert(Internal);
    let resp = crate::api::router(Arc::clone(state))
        .oneshot(req)
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.ok()?;
    Some((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

/// Dataset ids of check artifacts.
pub const CHECK_PREFIX: &str = "check-";
/// Gateway token labels of check artifacts.
pub const CHECK_TOKEN_PREFIX: &str = "check:";
/// Hex digits of the check id in its dataset id and token label.
const TAG_LEN: usize = 12;
/// Suffix of the mirror check's folder dataset.
pub const MIRROR_DATASET_SUFFIX: &str = "-f";

/// The check dataset of check `id` (32 hex): `check-<first 12 hex>`.
pub fn check_dataset_id(id: &str) -> String {
    format!("{CHECK_PREFIX}{}", &id[..TAG_LEN])
}

/// The temporary gateway token label of check `id`: `check:<first 12 hex>`.
pub fn check_token_label(id: &str) -> String {
    format!("{CHECK_TOKEN_PREFIX}{}", &id[..TAG_LEN])
}

fn is_tag(s: &str) -> bool {
    s.len() == TAG_LEN && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// A dataset id the check module generates: `check-<12 hex>` or
/// `check-<12 hex>-f`. The startup sweep deletes only these, so a user's
/// `check-*` dataset from before the reservation survives (spec §8.4,
/// amended 2026-10-04).
pub fn is_generated_dataset(id: &str) -> bool {
    id.strip_prefix(CHECK_PREFIX)
        .is_some_and(|r| is_tag(r.strip_suffix(MIRROR_DATASET_SUFFIX).unwrap_or(r)))
}

/// A token label the check module generates: `check:<12 hex>`.
pub fn is_generated_token_label(label: &str) -> bool {
    label.strip_prefix(CHECK_TOKEN_PREFIX).is_some_and(is_tag)
}

/// Lifetime of one check.
pub const CHECK_TTL: Duration = Duration::from_secs(600);
/// How long one step of the mirror or proxy direct run waits (a mirrored
/// file, the rehydrated outbox file, the proxy's answer) before the path
/// is reported as `timeout`.
pub const PATH_WAIT: Duration = Duration::from_secs(30);
/// How long removing a check's datasets may hold the live-check lock. A
/// folder whose job waits on a macOS privacy prompt answers `busy` after
/// the mirror's own removal deadline (5 s); past this the rest of the
/// cleanup goes on and the startup sweep removes what is left.
pub const REMOVE_WAIT: Duration = Duration::from_secs(8);

/// Request extension the check module sets on its in-process calls to the
/// control router, so the reserved-name refusals let them through. A
/// request from the socket cannot carry an extension.
#[derive(Debug, Clone, Copy)]
pub struct Internal;

/// Remove every dataset of a generated shape ([`is_generated_dataset`]: a
/// check folder dataset loses its folder, and with it its mirror tree,
/// first), every token of a generated label ([`is_generated_token_label`]),
/// `<data_dir>/check/`, and this data directory's temporary check
/// directories. Runs at startup before the gateway loads datasets and before
/// M5's folder registry starts; returns the removed dataset ids. Logs counts only.
pub async fn sweep_leftovers(state: &Arc<AppState>) -> Vec<String> {
    let s = Arc::clone(state);
    let ids: Vec<String> = tokio::task::spawn_blocking(move || {
        s.vault
            .datasets()
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.id)
            .filter(|id| is_generated_dataset(id))
            .collect()
    })
    .await
    .unwrap_or_default();
    let s = Arc::clone(state);
    let (removed, tokens) = tokio::task::spawn_blocking(move || {
        let mut removed = Vec::new();
        for id in ids {
            // The folder (watchers, mirror tree, rows) goes first, then the
            // dataset, under one hold of the folders mutex; it works on a
            // folder the service does not watch yet and is a plain delete
            // without a folder. A folder that cannot be removed keeps its
            // dataset (the next start retries).
            let ok = match s.mirror.get() {
                Some(f) => f.remove_dataset(&s, &id).is_ok(),
                None => s.delete_dataset(&id).is_ok(),
            };
            if ok {
                removed.push(id);
            }
        }
        let mut tokens = 0usize;
        for t in s.vault.gateway_tokens().unwrap_or_default() {
            if is_generated_token_label(&t.label) && s.vault.revoke_gateway_token(t.id).is_ok() {
                tokens += 1;
            }
        }
        let _ = std::fs::remove_dir_all(s.data_dir.join("check"));
        let own = format!("{TMP_PREFIX}{}-", tmp_tag(&s.data_dir));
        if let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) {
            for e in rd.filter_map(Result::ok) {
                if e.file_name().to_string_lossy().starts_with(&own) {
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
        }
        (removed, tokens)
    })
    .await
    .unwrap_or_default();
    for id in &removed {
        state.gateway_remove(id).await;
    }
    if !removed.is_empty() || tokens > 0 {
        tracing::info!(
            datasets = removed.len(),
            tokens,
            "removed leftover check artifacts"
        );
    }
    removed
}

/// The daemon's one check, and its injectable parts.
pub struct CheckSlot {
    pub(crate) live: tokio::sync::Mutex<Option<runner::LiveCheck>>,
    program: Mutex<Option<PathBuf>>,
    next_canary: Mutex<Option<Canary>>,
    ttl: Mutex<Duration>,
    path_wait: Mutex<Duration>,
    pub(crate) proxy: RwLock<Option<Arc<dyn ProxyCheckRoutes>>>,
    probe: Mutex<Arc<dyn GatewayProbe>>,
}

impl Default for CheckSlot {
    fn default() -> Self {
        CheckSlot {
            live: tokio::sync::Mutex::new(None),
            program: Mutex::new(None),
            next_canary: Mutex::new(None),
            ttl: Mutex::new(CHECK_TTL),
            path_wait: Mutex::new(PATH_WAIT),
            proxy: RwLock::new(None),
            probe: Mutex::new(Arc::new(RmcpProbe)),
        }
    }
}

impl CheckSlot {
    /// The executable that serves `canary-mcp` (default: this process's
    /// executable, which is `inumakid` or `inumaki daemon`).
    pub fn set_canary_program(&self, p: PathBuf) {
        *self.program.lock().unwrap_or_else(PoisonError::into_inner) = Some(p);
    }
    /// Use `c` as the next check's identity (tests).
    pub fn set_next_canary(&self, c: Canary) {
        *self
            .next_canary
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(c);
    }
    /// Lifetime of later checks (tests).
    pub fn set_ttl(&self, ttl: Duration) {
        *self.ttl.lock().unwrap_or_else(PoisonError::into_inner) = ttl;
    }
    /// Step deadline of later direct runs (tests; default [`PATH_WAIT`]).
    pub fn set_path_wait(&self, wait: Duration) {
        *self
            .path_wait
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = wait;
    }
    pub(crate) fn path_wait(&self) -> Duration {
        *self
            .path_wait
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// M8's check routes (Task 9a registers them at startup).
    pub fn set_proxy_routes(&self, r: Arc<dyn ProxyCheckRoutes>) {
        *self.proxy.write().unwrap_or_else(PoisonError::into_inner) = Some(r);
    }
    /// Replace the gateway probe (tests).
    pub fn set_gateway_probe(&self, p: Arc<dyn GatewayProbe>) {
        *self.probe.lock().unwrap_or_else(PoisonError::into_inner) = p;
    }
    pub(crate) fn probe(&self) -> Arc<dyn GatewayProbe> {
        Arc::clone(&self.probe.lock().unwrap_or_else(PoisonError::into_inner))
    }
    /// Take the live check out of the slot without cleaning it up: how a
    /// test simulates a crash that left the check's artifacts behind.
    #[doc(hidden)]
    pub fn take_live_for_tests(&self) -> Option<runner::LiveCheck> {
        self.live.try_lock().ok().and_then(|mut g| g.take())
    }
    /// A check is live (not yet removed).
    pub fn is_live(&self) -> bool {
        self.live.try_lock().map(|g| g.is_some()).unwrap_or(true)
    }
    pub(crate) fn canary_program(&self) -> (PathBuf, Vec<String>) {
        let p = self
            .program
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let p = p
            .or_else(|| std::env::current_exe().ok())
            .unwrap_or_else(|| PathBuf::from("inumakid"));
        (p, vec!["canary-mcp".to_string()])
    }
    pub(crate) fn take_next_canary(&self) -> Option<Canary> {
        self.next_canary
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
    pub(crate) fn ttl(&self) -> Duration {
        *self.ttl.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Remove an expired check every 5 s; ends when the daemon state is gone
/// or shutting down.
pub fn spawn_expiry(state: Weak<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let Some(s) = state.upgrade() else { return };
            if *s.shutdown.borrow() {
                return;
            }
            let mut guard = s.check.live.lock().await;
            if guard
                .as_ref()
                .is_some_and(|l| l.deadline <= std::time::Instant::now())
            {
                if let Some(old) = guard.take() {
                    runner::remove_live(&s, old).await;
                }
            }
        }
    })
}
