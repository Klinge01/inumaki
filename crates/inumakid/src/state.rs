//! Everything the daemon holds: config, vault, sessions, engines.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use inumaki_core::rehydrate::Rehydrator;
use inumaki_core::token::ContextStore;
use inumaki_vault::{Clock, Namespace, Rotation, SystemClock, Vault, VaultError, VaultOptions};
use tokio::sync::watch;

use crate::cache::SanitizeCache;
use crate::config::{ConfigSource, DaemonConfig};
use crate::dirs::{resolve_data_dir, resolve_in};
use crate::engines::{Engines, ProfileStatus};

/// Per-entity forget lives in `crate::forget` (`AppState::forget_entity`).
pub use crate::forget::ForgetTarget;

/// Command-line overrides for startup.
#[derive(Clone, Default)]
pub struct StartOptions {
    /// Config file; when `None`, `<data_dir>/inumaki.toml` if it exists,
    /// else the embedded default.
    pub config: Option<PathBuf>,
    /// Data directory override.
    pub data_dir: Option<PathBuf>,
    /// Socket path override.
    pub socket: Option<PathBuf>,
    /// Models directory override.
    pub models_dir: Option<PathBuf>,
    /// Clock for the vault (tests inject a fake one).
    pub clock: Option<Arc<dyn Clock>>,
}

impl std::fmt::Debug for StartOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartOptions")
            .field("config", &self.config)
            .field("data_dir", &self.data_dir)
            .field("socket", &self.socket)
            .field("models_dir", &self.models_dir)
            .field("clock", &self.clock.is_some())
            .finish()
    }
}

/// Why the daemon could not start (exit 2).
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Bad configuration.
    #[error("configuration: {0}")]
    Config(#[from] inumaki_core::Error),
    /// The vault could not be opened.
    #[error("vault: {0}")]
    Vault(#[from] VaultError),
    /// A directory or file could not be prepared.
    #[error("io error at {path}: {kind:?}")]
    Io {
        /// Path involved.
        path: String,
        /// Error kind.
        kind: std::io::ErrorKind,
    },
    /// Something already accepts connections on the socket path.
    #[error("another inumakid is listening on {0}")]
    AlreadyRunning(String),
    /// Pending gateway token revocations (offline Revert spec D7) could not
    /// be applied; the payload is a fixed stage word, never a path.
    #[error(
        "pending gateway token revocations could not be applied ({0}); the service does not start"
    )]
    Revocations(&'static str),
}

/// Shared daemon state.
pub struct AppState {
    /// Configuration.
    pub cfg: DaemonConfig,
    /// Where `cfg` came from (`GET /v1/status`).
    pub config_source: ConfigSource,
    /// Resolved data directory.
    pub data_dir: PathBuf,
    /// Resolved socket path.
    pub socket_path: PathBuf,
    /// The vault.
    pub vault: Vault,
    /// Open namespace handles by dataset id.
    namespaces: Mutex<HashMap<String, Arc<Mutex<Namespace>>>>,
    /// Session contexts (traffic without a dataset).
    pub sessions: ContextStore,
    /// Engines and models.
    pub engines: Engines,
    /// Start time.
    pub started: Instant,
    /// Rehydrator for session tokens (`suffix_len` 4 by default).
    pub session_rehydrator: Rehydrator,
    /// Rehydrator for namespace tokens (`suffix_len` 6 by default).
    pub namespace_rehydrator: Rehydrator,
    /// Sanitization cache (dataset traffic only).
    pub cache: SanitizeCache,
    /// Cache key component; see `DaemonConfig::fingerprint`.
    pub config_fingerprint: [u8; 32],
    /// Shutdown signal; `send_replace(true)` stops the server.
    pub shutdown: watch::Sender<bool>,
    /// Request counter for ids in logs.
    pub requests: AtomicU64,
    /// The MCP gateway, set once the server has bound its listener.
    pub gateway: OnceLock<Arc<inumaki_gateway::Gateway>>,
    /// The gateway's bound TCP address.
    pub gateway_listen: Mutex<Option<SocketAddr>>,
    /// The model download job (M6 spec §7.2).
    pub models_job: crate::api::models::ModelsJobSlot,
    /// The end-to-end check (M6 spec §8).
    pub check: crate::check::CheckSlot,
    /// Connected source folders for the hook (M6 spec §5.2); set by M5.
    pub folders: OnceLock<Arc<dyn crate::hook::FolderRegistry>>,
    /// The model-API proxy (M8), set once the server has tried to bind it.
    pub proxy: OnceLock<inumaki_proxy::Proxy>,
    /// Digests of released blocks (M8 spec §14).
    pub released: crate::released::ReleasedDigests,
    /// Folder datasets and the mirror service (M5); set in `start`.
    pub mirror: OnceLock<Arc<crate::folders::Folders>>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("data_dir", &self.data_dir)
            .field("sessions", &self.sessions.len())
            .field("namespaces", &self.open_namespace_ids().len())
            .finish()
    }
}

impl AppState {
    /// Spec §10.2 steps 1 and 2: config, directories, vault (fatal if it
    /// cannot open), then every profile's models (missing ones are reported
    /// by [`AppState::profiles`], not fatal).
    pub fn start(opts: &StartOptions) -> Result<AppState, StartError> {
        let data_dir = resolve_data_dir(opts.data_dir.as_deref());
        let (cfg, config_source) = DaemonConfig::resolve(opts.config.as_deref(), &data_dir)?;
        std::fs::create_dir_all(&data_dir).map_err(|e| StartError::Io {
            path: data_dir.display().to_string(),
            kind: e.kind(),
        })?;
        let socket_path = opts
            .socket
            .clone()
            .unwrap_or_else(|| resolve_in(&data_dir, &cfg.daemon.socket));
        // Alias groups come from the same dictionary files the engines read
        // (M4 spec §16.5); the vault's known-entity detector expands stored
        // canonicals through them. Config values and dictionary bytes are
        // already part of `cfg.fingerprint`, so a changed group invalidates
        // cached verdicts.
        let aliases = Arc::new(inumaki_core::alias::AliasTable::from_config(
            &cfg.core.dictionary,
        )?);
        tracing::info!(alias_groups = aliases.len(), "alias groups loaded");
        let vault = Vault::open_with_clock(
            VaultOptions {
                path: resolve_in(&data_dir, &cfg.vault.path),
                data_dir: data_dir.clone(),
                key_source: cfg.key_source,
                key_store: None,
                tokens: cfg.vault_tokens(),
                automaton_max_entries: cfg.vault.automaton_max_entries,
                keyring_timeout: inumaki_vault::keys::KEYRING_TIMEOUT,
                aliases: Arc::clone(&aliases),
            },
            opts.clock.clone().unwrap_or_else(|| Arc::new(SystemClock)),
        )?;
        let models_dir = inumaki_models::resolve_models_dir(
            opts.models_dir.as_deref(),
            cfg.core.ner.models_dir.as_deref(),
        );
        let engines = Engines::new(cfg.core.clone(), models_dir);
        for p in engines.preload() {
            if p.available {
                tracing::info!(profile = %p.name, "profile available");
            } else {
                // The reason names the models directory: `GET /v1/status` has it, the log does not (L110.1).
                tracing::warn!(profile = %p.name, "profile unavailable");
            }
        }
        let sessions = ContextStore::new(
            cfg.session_ttl,
            cfg.daemon.session_cap,
            cfg.session_tokens(),
        );
        let session_rehydrator = Rehydrator::new(&cfg.session_tokens());
        let namespace_rehydrator = Rehydrator::new(&cfg.vault_tokens());
        let cache = SanitizeCache::new(cfg.daemon.cache_bytes);
        tracing::info!(key_source = vault.key_source(), "inumakid state ready");
        let config_fingerprint = cfg.fingerprint;
        let folders = Arc::new(crate::folders::Folders::load(
            &cfg.mirror_cfg,
            &vault,
            &data_dir,
        )?);
        let state = AppState {
            cfg,
            config_source,
            data_dir,
            socket_path,
            vault,
            namespaces: Mutex::new(HashMap::new()),
            sessions,
            engines,
            started: Instant::now(),
            session_rehydrator,
            namespace_rehydrator,
            cache,
            config_fingerprint,
            shutdown: watch::channel(false).0,
            requests: AtomicU64::new(0),
            gateway: OnceLock::new(),
            gateway_listen: Mutex::new(None),
            models_job: crate::api::models::ModelsJobSlot::default(),
            check: crate::check::CheckSlot::default(),
            folders: OnceLock::new(),
            proxy: OnceLock::new(),
            released: crate::released::ReleasedDigests::new(),
            mirror: OnceLock::new(),
        };
        // Before anything is served: the hook guards every folder's source
        // from the first request (M5 spec §11).
        let _ = state.mirror.set(Arc::clone(&folders));
        let _ = state.folders.set(folders);
        Ok(state)
    }

    /// Profile availability.
    pub fn profiles(&self) -> Vec<ProfileStatus> {
        self.engines.profiles()
    }

    /// The namespace handle for a dataset, opened on first use. Opening
    /// decrypts up to `automaton_max_entries` rows, so the map lock is not
    /// held meanwhile; two concurrent first openers race and the loser drops
    /// its handle (review I10).
    pub fn namespace(&self, id: &str) -> Result<Arc<Mutex<Namespace>>, VaultError> {
        if let Some(ns) = self.namespace_if_open(id) {
            return Ok(ns);
        }
        let fresh = Arc::new(Mutex::new(self.vault.namespace(id)?));
        let mut map = self
            .namespaces
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Ok(Arc::clone(map.entry(id.to_string()).or_insert(fresh)))
    }

    /// The handle when one is open; never opens.
    pub fn namespace_if_open(&self, id: &str) -> Option<Arc<Mutex<Namespace>>> {
        self.namespaces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    /// Drop the handle for a deleted dataset.
    pub fn close_namespace(&self, id: &str) {
        self.namespaces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
    }

    /// Ids with an open handle, sorted.
    pub fn open_namespace_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .namespaces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// Time since start.
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Rotate under the namespace lock when a handle is open, so no request
    /// changes epoch halfway; a dataset no request touched is rotated in the
    /// vault alone (no automaton is built just to rotate, review I11). Then
    /// drop cached results of the old epoch, still under the namespace lock
    /// when one is held, so no batch can put back the old epoch's store
    /// dictionary after the drop (Task 7c review I1).
    pub fn rotate_dataset(&self, id: &str) -> Result<Rotation, VaultError> {
        let rot = match self.namespace_if_open(id) {
            Some(ns) => {
                let mut guard = ns.lock().unwrap_or_else(PoisonError::into_inner);
                let rot = self.vault.rotate(id)?;
                guard.refresh()?;
                self.cache.invalidate_namespace(id);
                rot
            }
            None => {
                let rot = self.vault.rotate(id)?;
                self.cache.invalidate_namespace(id);
                rot
            }
        };
        Ok(rot)
    }

    /// The bound listen address, or the configured one before binding.
    pub fn gateway_listen_string(&self) -> String {
        self.gateway_listen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map(|a| a.to_string())
            .unwrap_or_else(|| self.cfg.gateway.listen.clone())
    }

    /// The status body's gateway block (`tokens` counted by the caller on
    /// the blocking pool).
    pub async fn gateway_status(&self, tokens: usize) -> inumaki_gateway::GatewayStatus {
        match self.gateway.get() {
            Some(g) => g.status(self.gateway_listen_string(), tokens).await,
            None => inumaki_gateway::GatewayStatus {
                listen: self.gateway_listen_string(),
                datasets: Vec::new(),
                tokens,
                uncertain_checks: std::collections::BTreeMap::new(),
                qualification: "unqualified".into(),
                activity_dropped: 0,
                journal_dropped: 0,
            },
        }
    }

    /// Rebuild a dataset's gateway after its rows changed. Call it only
    /// after the whole change (rows and secrets) is written.
    pub async fn gateway_reload(&self, id: &str) {
        if let Some(g) = self.gateway.get() {
            if let Err(e) = g.reload_dataset(id).await {
                tracing::warn!(dataset = %self.vault.opaque_id(id), error = %e, "gateway reload failed");
            }
        }
    }

    /// Stop a deleted dataset's gateway.
    pub async fn gateway_remove(&self, id: &str) {
        if let Some(g) = self.gateway.get() {
            g.remove_dataset(id).await;
        }
    }

    /// Delete a dataset: close its handle, forget its engines and cached
    /// results, delete its rows.
    pub fn delete_dataset(&self, id: &str) -> Result<(), VaultError> {
        let handle = self
            .namespaces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        let r = match handle {
            Some(ns) => {
                let _guard = ns.lock().unwrap_or_else(PoisonError::into_inner);
                self.vault.delete_dataset(id)
            }
            None => self.vault.delete_dataset(id),
        };
        if r.is_ok() {
            // A dataset's secrets go with it (M4 spec §4.3), but only once
            // the vault has confirmed a dataset by exactly this id existed
            // and is now gone. Ids cannot contain `/` (`valid_dataset_id`),
            // so a real dataset's prefix never matches another one's — but
            // axum percent-decodes a route's `{id}` segment, so a path like
            // `/v1/datasets/crm%2Fupstream` arrives here as the id
            // `crm/upstream`; running the prefix sweep unconditionally would
            // have matched (and deleted) every secret of dataset `crm`
            // before `vault.delete_dataset` had any chance to reject that id
            // (review I3). Gating on success closes that hole: no real
            // dataset id can contain `/`, so `delete_dataset` above always
            // fails first for such a path.
            if let Ok(names) = self.vault.list_secret_names() {
                for n in names
                    .into_iter()
                    .filter(|n| n.starts_with(&format!("{id}/")))
                {
                    if let Err(e) = self.vault.delete_secret(&n) {
                        tracing::warn!(dataset = %self.vault.opaque_id(id), error = %e, "could not delete a dataset secret");
                    }
                }
            }
        }
        self.engines.drop_dataset(id);
        self.cache.invalidate_namespace(id);
        r
    }

    /// One sweeper pass (spec §5.3, §8): expire sessions, rotate due
    /// datasets, delete expired epochs, activity past retention, and
    /// journal entries past retention or over a dataset's budget.
    pub fn sweep_once(&self) -> SweepSummary {
        let mut s = SweepSummary {
            sessions_expired: self.sessions.sweep_expired(),
            ..SweepSummary::default()
        };
        match self.vault.due_for_rotation() {
            Ok(ids) => {
                for id in ids {
                    match self.rotate_dataset(&id) {
                        Ok(_) => s.rotated.push(id),
                        Err(e) => {
                            tracing::warn!(dataset = %self.vault.opaque_id(&id), error = %e, "automatic rotation failed")
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not list datasets due for rotation"),
        }
        match self.vault.sweep() {
            Ok(r) => {
                s.expired_epochs = r.expired_epochs;
                s.entries_deleted = r.entries_deleted;
            }
            Err(e) => tracing::warn!(error = %e, "vault sweep failed"),
        }
        if let Err(e) = self
            .vault
            .sweep_activity(self.cfg.gateway.activity_retention_days)
        {
            tracing::warn!(error = %e, "activity sweep failed");
        }
        match self.vault.sweep_journal(
            i64::try_from(self.cfg.journal_retention.as_secs()).unwrap_or(i64::MAX),
            self.cfg.journal_max_bytes,
        ) {
            Ok(j) => {
                s.journal_expired = j.expired;
                s.journal_over_budget = j.over_budget;
            }
            Err(e) => tracing::warn!(error = %e, "journal sweep failed"),
        }
        if let Err(e) = self
            .vault
            .sweep_mail_handles(self.cfg.mail.handle_retention_days)
        {
            tracing::warn!(error = %e, "mail handle sweep failed");
        }
        s
    }
}

/// What one sweeper pass did.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SweepSummary {
    /// Session contexts dropped for TTL.
    pub sessions_expired: usize,
    /// Datasets rotated because their epoch was older than `rotation_days`.
    pub rotated: Vec<String>,
    /// Closed epochs deleted after their grace period.
    pub expired_epochs: usize,
    /// Entry rows deleted with them.
    pub entries_deleted: u64,
    /// Journal entries past retention.
    pub journal_expired: usize,
    /// Journal entries removed for a dataset's byte budget.
    pub journal_over_budget: usize,
}

impl std::fmt::Debug for SweepSummary {
    /// `rotated` holds dataset ids (M4 spec §5.4: user-chosen slugs never
    /// reach logs); only the count is shown. The per-dataset rotation is
    /// already logged with an opaque id by `Vault::rotate`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SweepSummary")
            .field("sessions_expired", &self.sessions_expired)
            .field("rotated", &self.rotated.len())
            .field("expired_epochs", &self.expired_epochs)
            .field("entries_deleted", &self.entries_deleted)
            .field("journal_expired", &self.journal_expired)
            .field("journal_over_budget", &self.journal_over_budget)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inumaki_core::span::EntityKind;
    use inumaki_core::token::TokenStore;
    use inumaki_vault::DatasetSpec;

    fn config_file(dir: &std::path::Path) -> PathBuf {
        let p = dir.join("inumaki.toml");
        std::fs::write(
            &p,
            format!(
                "{}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[mirror]\nroot = \"{d}/mirror-root\"\noutbox_root = \"{d}/mirror-outbox\"\n",
                include_str!("../../../configs/default.toml"),
                d = dir.display()
            ),
        )
        .unwrap();
        p
    }

    /// L82 (1): without `--config` the daemon reads `<data_dir>/inumaki.toml`
    /// and reports it; a present but invalid file stops the start (no
    /// fallback to the embedded default), naming the file and not its text.
    #[test]
    fn start_reads_the_data_dir_config_and_fails_on_an_invalid_one() {
        let dir = tempfile::tempdir().unwrap();
        let models = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let written = config_file(dir.path());
        let p = data.join("inumaki.toml");
        std::fs::rename(&written, &p).unwrap();
        let opts = StartOptions {
            config: None,
            data_dir: Some(data.clone()),
            socket: None,
            models_dir: Some(models.path().to_path_buf()),
            clock: None,
        };
        let s = AppState::start(&opts).unwrap();
        assert_eq!(s.config_source, ConfigSource::File(p.clone()));
        assert_eq!(s.cfg.daemon.default_profile, "offline");
        assert_eq!(s.vault.key_source(), "file");
        drop(s);

        let text = std::fs::read_to_string(&p).unwrap();
        let bad = text.replace(
            "default_profile = \"offline\"",
            "default_profile = \"offline\"\ndefault_profle = \"qwxzvk-value\"",
        );
        assert_ne!(bad, text);
        std::fs::write(&p, bad).unwrap();
        let e = AppState::start(&opts).unwrap_err();
        assert!(matches!(e, StartError::Config(_)), "{e}");
        let e = e.to_string();
        assert!(e.contains(&format!("config file {}", p.display())), "{e}");
        assert!(
            e.contains("daemon table: unknown key `default_profle`"),
            "{e}"
        );
        assert!(!e.contains("qwxzvk"), "{e}");
    }

    #[test]
    fn starts_with_a_file_keyed_vault_and_reports_unavailable_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let models = tempfile::tempdir().unwrap();
        let s = AppState::start(&StartOptions {
            config: Some(config_file(dir.path())),
            data_dir: Some(dir.path().join("data")),
            socket: None,
            models_dir: Some(models.path().to_path_buf()),
            clock: None,
        })
        .unwrap();
        assert_eq!(s.socket_path, dir.path().join("data").join("inumakid.sock"));
        assert!(dir.path().join("data").join("vault.sqlite").exists());
        assert!(dir.path().join("data").join("vault.key").exists());
        assert_eq!(s.vault.key_source(), "file");
        let profiles = s.profiles();
        assert!(profiles.iter().any(|p| p.name == "offline" && p.available));
        assert!(
            profiles
                .iter()
                .any(|p| p.name == "support-email" && !p.available)
        );
        assert!(matches!(
            s.namespace("mail"),
            Err(VaultError::DatasetNotFound(_))
        ));
        s.vault
            .create_dataset(&DatasetSpec::new("mail", "x", "offline"))
            .unwrap();
        let ns = s.namespace("mail").unwrap();
        assert!(Arc::ptr_eq(&ns, &s.namespace("mail").unwrap()));
        let t = ns
            .lock()
            .unwrap()
            .token_for(&EntityKind::Person, "Sarah Leitner")
            .unwrap();
        assert_eq!(
            t.as_str().len(),
            "<PERSON_".len() + 6 + 1,
            "namespace suffix is 6"
        );
        assert_eq!(s.open_namespace_ids(), vec!["mail".to_string()]);
        s.close_namespace("mail");
        assert!(s.open_namespace_ids().is_empty());
        let sid = inumaki_core::token::ContextId("s1".into());
        let t = s
            .sessions
            .get_or_create(&sid)
            .unwrap()
            .token_for(&EntityKind::Person, "Sarah Leitner")
            .unwrap();
        assert_eq!(
            t.as_str().len(),
            "<PERSON_".len() + 4 + 1,
            "session suffix is 4"
        );
        let d = format!("{s:?}");
        assert!(!d.contains("Sarah"));
        assert_eq!(s.cache.stats(), crate::cache::CacheStats::default());
    }

    #[test]
    fn unopenable_vault_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("vault.sqlite"), b"not a database").unwrap();
        let e = AppState::start(&StartOptions {
            config: Some(config_file(dir.path())),
            data_dir: Some(data),
            socket: None,
            models_dir: None,
            clock: None,
        })
        .unwrap_err();
        assert!(matches!(e, StartError::Vault(_)), "{e}");
    }

    /// Task 7c fix round 1 (review I1), Task 7e: no store dictionary
    /// outlives its epoch. The dictionary lives on the namespace handle
    /// (shared by the engine's passes and the cache-hit re-check), and the
    /// rotation's refresh under the namespace lock drops it with the working
    /// set; the next batch builds one for the new epoch.
    #[test]
    fn no_store_dictionary_keeps_a_rotated_epoch() {
        use crate::service::{BlockInput, sanitize_blocks};
        use inumaki_core::consistency::live_layers_on_this_thread;
        let dir = tempfile::tempdir().unwrap();
        let models = tempfile::tempdir().unwrap();
        let s = AppState::start(&StartOptions {
            config: Some(config_file(dir.path())),
            data_dir: Some(dir.path().join("data")),
            socket: None,
            models_dir: Some(models.path().to_path_buf()),
            clock: None,
        })
        .unwrap();
        s.vault
            .create_dataset(&DatasetSpec::new("mail", "x", "offline"))
            .unwrap();
        let live = live_layers_on_this_thread();
        let run = |t: &str| sanitize_blocks(&s, "mail", None, vec![BlockInput::text(t)]).unwrap();
        run("Kundennummer K-928174 bitte prüfen.");
        assert!(run("Kundennummer K-928174 bitte prüfen.")[0].cached);
        assert!(live_layers_on_this_thread() > live, "kept on the handle");
        s.rotate_dataset("mail").unwrap();
        assert_eq!(live_layers_on_this_thread(), live, "rotation drops it");
        let r = run("Ganz neuer Text ohne Treffer.");
        assert!(!r[0].cached);
        assert_eq!(
            live_layers_on_this_thread() - live,
            1,
            "one, of the new epoch"
        );
    }
}
