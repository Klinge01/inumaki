//! The command context: paths, the control-API client, `state.json`, the
//! notifier, and window visibility. Tauri manages it as `Arc<Ctx>`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use inumaki_client::{Client, HarnessId};

use crate::appstate::{self, AppStateFile};
use crate::error::CmdError;
use crate::paths::AppPaths;

/// Sends one system notification. Bodies are fixed text plus kinds and counts (spec §6.5).
pub trait Notifier: Send + Sync {
    /// Show `body`.
    fn notify(&self, body: &str);
}

/// The real notifier.
pub struct TauriNotifier(pub tauri::AppHandle);

impl Notifier for TauriNotifier {
    fn notify(&self, body: &str) {
        use tauri_plugin_notification::NotificationExt;
        let _ = self
            .0
            .notification()
            .builder()
            .title("inumaki")
            .body(body)
            .show();
    }
}

/// Records notifications (tests).
#[derive(Default)]
pub struct RecordingNotifier {
    sent: Mutex<Vec<String>>,
}

impl RecordingNotifier {
    /// Bodies so far.
    pub fn sent(&self) -> Vec<String> {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Notifier for RecordingNotifier {
    fn notify(&self, body: &str) {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(body.to_string());
    }
}

/// Where the login-shell `PATH` comes from (spec §4.4): the real shell, or
/// a fixed value in tests.
pub type LoginPath = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// Everything a command needs.
pub struct Ctx {
    /// Paths.
    pub paths: AppPaths,
    /// Control-API client with the client's default (short) deadline. A
    /// long-running call such as `/v1/check/{id}/direct` uses
    /// `ctx.client.clone().with_timeout(..)` instead of changing this one.
    pub client: Client,
    state: Mutex<AppStateFile>,
    state_key: Option<zeroize::Zeroizing<Vec<u8>>>,
    login_path: LoginPath,
    /// The settings window is visible (poll cadence, spec §6.1).
    pub visible: AtomicBool,
    /// System notifications.
    pub notifier: Arc<dyn Notifier>,
    /// Wakes the poller early (the window was shown).
    pub wake: tokio::sync::Notify,
    /// Unix seconds until which activity records do not notify (a check is
    /// running or just ended: its records carry an opaque dataset label once
    /// the check dataset is deleted, so the `check-` filter cannot catch them).
    pub quiet_until: AtomicI64,
    /// The latest poll.
    pub snapshot: RwLock<crate::poll::Snapshot>,
    /// Notification cursor.
    pub activity: Mutex<crate::poll::Cursor>,
    /// The harnesses (Task 4b fills them from the adapter crate; tests use fakes).
    pub harnesses: Vec<Arc<dyn crate::harness::ops::HarnessOps>>,
    /// The latest Overview cards (the poller computes them on a blocking thread).
    pub cards: RwLock<Vec<crate::harness::cards::HarnessCard>>,
    /// One lock per harness, held across Connect, Revert, Reconnect, the
    /// preview, and Protect/Unprotect: Tauri runs commands concurrently, and
    /// two of them on one harness would revoke each other's token or chain a
    /// backup onto inumaki's own entries.
    harness_locks: BTreeMap<&'static str, Arc<tokio::sync::Mutex<()>>>,
    /// Harnesses recorded as disconnected after a failed Reconnect while
    /// `state.json` could not be written: the tray still turns red.
    reconnect_failed_mem: Mutex<BTreeSet<String>>,
    /// External programs (launchctl, systemctl, xattr, codesign): the real
    /// runner in `Ctx::new`, a runner that refuses every call in
    /// `Ctx::for_tests` (a test opts in to a recorder with `with_runner`).
    pub runner: Arc<dyn crate::service::runner::Runner>,
    /// `started_at` of the model job the app last restarted the service for.
    pub restart_guard: Mutex<Option<i64>>,
    /// Held across service install, remove, restart, and the start-up
    /// helper refresh, so two of them never overlap.
    pub service_lock: tokio::sync::Mutex<()>,
    /// Held across one end-to-end check: the tray and the window never
    /// start two (the second would meet the daemon's `409`).
    pub check_lock: tokio::sync::Mutex<()>,
}

fn now_unix() -> i64 {
    crate::poll::now()
}

impl Ctx {
    /// A context over `paths` with `client`. A state key that cannot be
    /// created or read leaves no key: the app still runs, but `state_key()`
    /// fails, so no server key is recorded under a guessable or short-lived key.
    pub fn new(paths: AppPaths, client: Client, notifier: Arc<dyn Notifier>) -> Ctx {
        let state = appstate::load(&paths.state_file);
        let state_key = appstate::load_or_create_key(&paths.state_key)
            .map_err(|_| crate::applog::event("state_key_unwritable"))
            .ok();
        Ctx {
            paths,
            client,
            state: Mutex::new(state),
            state_key,
            login_path: Arc::new(crate::harness::shell::login_path),
            visible: AtomicBool::new(true),
            notifier,
            wake: tokio::sync::Notify::new(),
            quiet_until: AtomicI64::new(0),
            snapshot: RwLock::new(crate::poll::Snapshot::default()),
            // Records from before the app started never notify.
            activity: Mutex::new(crate::poll::Cursor {
                at: now_unix(),
                seen: BTreeSet::new(),
            }),
            harnesses: Vec::new(),
            cards: RwLock::new(Vec::new()),
            harness_locks: [
                HarnessId::ClaudeCode,
                HarnessId::Codex,
                HarnessId::Hermes,
                HarnessId::Openclaw,
            ]
            .into_iter()
            .map(|h| {
                (
                    crate::harness::harness_key(h),
                    Arc::new(tokio::sync::Mutex::new(())),
                )
            })
            .collect(),
            reconnect_failed_mem: Mutex::new(BTreeSet::new()),
            runner: Arc::new(crate::service::runner::SystemRunner),
            restart_guard: Mutex::new(None),
            service_lock: tokio::sync::Mutex::new(()),
            check_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The lock of harness `h` (created with the context, one per harness).
    pub fn harness_lock(&self, h: HarnessId) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(
            self.harness_locks
                .get(crate::harness::harness_key(h))
                .expect("a lock for every harness id"),
        )
    }

    /// Mark `h` disconnected after a failed Reconnect (in `state.json`, and
    /// in memory when the file cannot be written).
    pub fn set_reconnect_failed(&self, h: HarnessId) {
        let key = crate::harness::harness_key(h);
        if self
            .update_state(|s| {
                s.reconnect_failed.insert(key.into());
                s.last_check.remove(key);
            })
            .is_err()
        {
            crate::applog::event("state_unwritable");
            self.reconnect_failed_mem
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(key.into());
        }
    }

    /// Clear `h`'s in-memory disconnect mark (a Connect or Revert succeeded).
    pub fn clear_reconnect_failed_mem(&self, h: HarnessId) {
        self.reconnect_failed_mem
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(crate::harness::harness_key(h));
    }

    /// A context with a recording notifier and a fixed login `PATH` (tests).
    pub fn for_tests(paths: AppPaths, client: Client) -> (Ctx, Arc<RecordingNotifier>) {
        let n = Arc::new(RecordingNotifier::default());
        let ctx = Ctx::new(paths, client, n.clone())
            .with_login_path(Arc::new(|| Some("/usr/bin:/bin".to_string())))
            .with_runner(Arc::new(crate::service::runner::FailingRunner));
        (ctx, n)
    }

    /// The same context with another runner (tests).
    pub fn with_runner(mut self, r: Arc<dyn crate::service::runner::Runner>) -> Ctx {
        self.runner = r;
        self
    }

    /// The same context with `h` as its harnesses (start-up and tests).
    pub fn with_harnesses(mut self, h: Vec<Arc<dyn crate::harness::ops::HarnessOps>>) -> Ctx {
        self.harnesses = h;
        self
    }

    /// The same context with another login-`PATH` source.
    pub fn with_login_path(mut self, p: LoginPath) -> Ctx {
        self.login_path = p;
        self
    }

    /// Suppress notifications for the next `secs` seconds (the cursor still advances).
    pub fn quiet_for(&self, secs: i64) {
        self.quiet_until
            .fetch_max(crate::poll::now().saturating_add(secs), Ordering::Relaxed);
    }

    /// End the quiet window `secs` from now, shortening a longer one. Only
    /// the end-to-end check uses it (one step at a time, under `check_lock`),
    /// so a window armed for a step that ended early does not keep real
    /// notifications quiet.
    pub fn set_quiet_for(&self, secs: i64) {
        self.quiet_until
            .store(crate::poll::now().saturating_add(secs), Ordering::Relaxed);
    }

    /// The login-shell `PATH`. Starting the shell can block for seconds,
    /// so it runs on a blocking thread.
    pub async fn login_path(&self) -> Option<String> {
        let f = Arc::clone(&self.login_path);
        tokio::task::spawn_blocking(move || f())
            .await
            .ok()
            .flatten()
    }

    /// The HMAC key for server names in `state.json`; fails closed with
    /// `state_unwritable` when no key could be created.
    pub fn state_key(&self) -> Result<&[u8], CmdError> {
        self.state_key
            .as_ref()
            .map(|k| k.as_slice())
            .ok_or_else(|| CmdError::new("state_unwritable"))
    }

    /// A copy of the state. `reconnect_failed` also holds the harnesses
    /// marked in memory only (`set_reconnect_failed` when the file could not
    /// be written), so the tray and the cards show them.
    pub fn state(&self) -> AppStateFile {
        let mut s = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        s.reconnect_failed.extend(
            self.reconnect_failed_mem
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .cloned(),
        );
        s
    }

    /// Change the state and write the file.
    pub fn update_state(&self, f: impl FnOnce(&mut AppStateFile)) -> Result<(), CmdError> {
        let mut g = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // Mutate a copy: memory changes only when the file did.
        let mut next = g.clone();
        f(&mut next);
        appstate::save(&self.paths.state_file, &next)?;
        *g = next;
        Ok(())
    }
}
