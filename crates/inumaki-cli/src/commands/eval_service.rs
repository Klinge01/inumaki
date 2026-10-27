//! In-process daemon service path for `inumaki eval --via-service` (M4
//! spec §16.6). Spins up a real `AppState` (models, vault, engines) in a
//! temporary data directory and calls `inumakid::service` directly — no
//! socket, no daemon process — so a measurement run exercises the same
//! sanitize path the daemon serves in production without starting one.
//!
//! Landed as the minimal subset of plan 4a Task 5 that Task 7 (this track)
//! consumes, per controller ruling R5: Task 5 lands later and extends this
//! module (restart, rotate, sweep, cache-hit accounting are its job, not
//! this one's).
//!
//! Plan 4a Task 5 extends it into the full [`Sanitizer`] the mail track's
//! `evaluate_with` drives (replaced spans, token restoration, the engine's
//! verifier) plus the restart, rotation, sweep, and cache-hit hooks the
//! service-path measurements use.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use anyhow::{Context as _, Result, bail};
use inumaki_core::config::TokenSettings;
use inumaki_core::engine::Engine;
use inumaki_core::policy::Action;
use inumaki_core::span::Span;
use inumaki_core::token::TokenStore;
use inumaki_core::verify::Verifier;
use inumaki_eval::Doc;
use inumaki_eval::metrics::{DetectFailed, EvalOutcome, Replaced, Sanitizer};
use inumaki_vault::{Clock, DatasetSpec};
use inumakid::cache::CachedOutcome;
use inumakid::service::{BlockInput, BlockResult, ServiceError, sanitize_blocks};
use inumakid::state::{AppState, StartOptions, SweepSummary};

use super::EMBEDDED_CONFIG;

/// Dataset id `sanitize_batch` mints into. Fixed and shared across every
/// document a `ServiceSanitizer` sanitizes in one run: a real gateway
/// dataset is persistent across tool calls (that persistence is the whole
/// point of a vault namespace), so one dataset for the whole run models
/// that correctly, on purpose. Reported block rates therefore include
/// cross-document known-entity accumulation — an earlier, unrelated
/// document's already-tokenized name (or other known kind) can flag a
/// later, unrelated document's own mention as a "known entity" leak —
/// which is real gateway behavior for a long-lived dataset, not a
/// measurement artifact to engineer away (controller ruling R12; see
/// `docs/quality/2026-09-28-4a-tool-json.md` for the diagnosis and
/// numbers: fixing this by isolating a fresh dataset per document would
/// change what this mode measures, not just remove noise).
const DATASET: &str = "eval";

/// A vault clock the sequence runner advances: the system time at start,
/// then only what [`EvalClock::advance`] adds, so a run's recency windows and
/// grace periods do not depend on how long the machine takes.
pub struct EvalClock(std::sync::atomic::AtomicI64);

impl EvalClock {
    /// A clock reading the current system time.
    pub fn now_system() -> Arc<EvalClock> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        Arc::new(EvalClock(std::sync::atomic::AtomicI64::new(now)))
    }

    /// Move the clock forward.
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(
            i64::try_from(secs).unwrap_or(i64::MAX),
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

impl Clock for EvalClock {
    fn now(&self) -> i64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// What a [`ServiceSanitizer`] handle shares.
struct Inner {
    /// `None` while [`ServiceSanitizer::restart`] runs, and for good when it
    /// failed: the old state is dropped (vault closed) before the new one
    /// opens the same files. Every use degrades to an error (never a panic).
    state: Option<AppState>,
    engine: Arc<Engine>,
    opts: StartOptions,
    profile: String,
    /// Declared last: dropped after the state, whose vault files live in it.
    dir: tempfile::TempDir,
}

/// A running in-process daemon state, wired to one dataset for the whole
/// run (see [`DATASET`]), for measuring the sanitize-through-the-service
/// path. A cheap `Clone` handle: the sequence runner holds one for the
/// evaluation and one for the event hooks (restart, rotation, sweep, cache
/// counter). The temporary data directory is deleted when the last handle
/// drops.
#[derive(Clone)]
pub struct ServiceSanitizer {
    inner: Arc<Mutex<Inner>>,
    /// The token grammar, kept so [`Sanitizer::token_settings`] can hand out
    /// a reference without holding the lock.
    tokens: TokenSettings,
    /// Lookups that failed with a vault error (not "no such token"), shared
    /// by every handle: [`Sanitizer::restore`] can only answer `None`, and a
    /// failed lookup must not read as an expired token.
    restore_errors: Arc<std::sync::atomic::AtomicUsize>,
}

impl ServiceSanitizer {
    /// Start a fresh daemon state in a temporary data directory, keyed by
    /// a file-backed vault (never the OS keychain: an eval run must not
    /// prompt or depend on a login session), and create the `eval` dataset
    /// for `profile`.
    pub fn start(
        config: Option<&Path>,
        profile: &str,
        models_dir: Option<&Path>,
        clock: Option<Arc<dyn Clock>>,
    ) -> Result<ServiceSanitizer> {
        let base_text = match config {
            Some(p) => {
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?
            }
            None => EMBEDDED_CONFIG.to_string(),
        };
        // Force a file-backed vault key regardless of what (if anything)
        // the caller's config says about `[vault]`/`[daemon]`: those
        // tables do not exist in the plain engine config `eval` otherwise
        // uses (`--config` today only ever names a `CoreConfig`-shaped
        // file), and the default `key_source` ("auto") would try the OS
        // keychain, which an unattended measurement run must not depend
        // on.
        let table: toml::Table = base_text
            .parse()
            .with_context(|| "the config is not valid TOML".to_string())?;
        if table.contains_key("daemon") || table.contains_key("vault") {
            bail!(
                "eval --via-service needs a config without [daemon] and [vault] tables; it adds its own"
            );
        }
        let dir = tempfile::tempdir().context("creating a temporary data directory")?;
        // The mirror root is prepared at start; keep it out of the home directory.
        let text = format!(
            "{base_text}\n[vault]\nkey_source = \"file\"\n[daemon]\ndefault_profile = \"{profile}\"\n[mirror]\nroot = \"{d}/mirror-root\"\noutbox_root = \"{d}/mirror-outbox\"\n",
            d = dir.path().display()
        );
        let config_path = dir.path().join("inumaki.toml");
        std::fs::write(&config_path, &text)
            .with_context(|| format!("writing {}", config_path.display()))?;
        let opts = StartOptions {
            config: Some(config_path),
            data_dir: Some(dir.path().join("data")),
            socket: None,
            models_dir: models_dir.map(Path::to_path_buf),
            clock,
        };
        let state = AppState::start(&opts).context("starting the in-process daemon state")?;
        state
            .vault
            .create_dataset(&DatasetSpec::new(DATASET, "eval", profile))
            .context("creating the eval dataset")?;
        let engine = state
            .engines
            .engine(profile, None)
            .with_context(|| format!("loading profile {profile}"))?;
        Ok(ServiceSanitizer {
            tokens: state.vault.tokens().clone(),
            restore_errors: Arc::default(),
            inner: Arc::new(Mutex::new(Inner {
                state: Some(state),
                engine,
                opts,
                profile: profile.to_string(),
                dir,
            })),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Drop the state and start again on the same data directory (models
    /// reload, the cache is empty, the namespace reopens from the vault).
    pub fn restart(&self) -> Result<()> {
        let mut g = self.lock();
        // close the vault first: two states must not hold the same files
        g.state = None;
        let fresh = AppState::start(&g.opts).context("restarting the daemon state")?;
        g.engine = fresh.engines.engine(&g.profile, None)?;
        g.state = Some(fresh);
        Ok(())
    }

    /// Rotate the dataset's epoch.
    pub fn rotate(&self) -> Result<()> {
        let g = self.lock();
        g.state
            .as_ref()
            .context("the daemon state is closed (a restart failed)")?
            .rotate_dataset(DATASET)?;
        Ok(())
    }

    /// One sweeper pass (expired epochs are deleted after the grace period).
    /// The summary says what it deleted; `sweep_once` only logs a failing
    /// vault sweep, which shows here as `expired_epochs == 0`.
    pub fn sweep(&self) -> Result<SweepSummary> {
        let g = self.lock();
        Ok(g.state
            .as_ref()
            .context("the daemon state is closed (a restart failed)")?
            .sweep_once())
    }

    /// Lookups that failed with an error rather than finding nothing.
    pub fn restore_errors(&self) -> usize {
        self.restore_errors
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Cache hits so far.
    pub fn cache_hits(&self) -> u64 {
        self.lock()
            .state
            .as_ref()
            .map_or(0, |s| s.cache.stats().hits)
    }

    /// The temporary data directory (kept alive by this value).
    #[allow(dead_code)] // for the service-path scenario tests
    pub fn data_dir(&self) -> PathBuf {
        self.lock().dir.path().join("data")
    }

    /// Token format the sanitize path mints into: the vault namespace's
    /// settings, not a bare engine `Context`'s.
    pub fn token_settings(&self) -> &TokenSettings {
        &self.tokens
    }

    /// Sanitize one batch through the daemon's own `sanitize_blocks` (M4
    /// spec §5.3): one namespace lock, one cache entry per block, the
    /// final release re-check applied to the whole batch.
    pub fn sanitize_batch(
        &self,
        blocks: Vec<BlockInput>,
    ) -> Result<Vec<BlockResult>, ServiceError> {
        let g = self.lock();
        match &g.state {
            Some(state) => sanitize_blocks(state, DATASET, Some(&g.profile), blocks),
            None => Err(ServiceError::Unsupported("service_closed")),
        }
    }

    /// Sanitize one tool document: one batch, one block per field with its hint.
    pub fn sanitize_tool_doc(&self, d: &inumaki_eval::tool_json::ToolDoc) -> Vec<EvalOutcome> {
        use inumaki_eval::tool_json::BlockHint;
        use inumakid::service::FieldHint;
        let blocks: Vec<BlockInput> = d
            .blocks
            .iter()
            .map(|b| BlockInput {
                text: b.text.clone(),
                hint: match &b.hint {
                    BlockHint::FreeText => FieldHint::FreeText,
                    BlockHint::Identifier(k) => {
                        FieldHint::Identifier(inumaki_core::span::EntityKind::from_label(k))
                    }
                },
                redactions: Vec::new(),
            })
            .collect();
        match self.sanitize_batch(blocks) {
            Ok(v) => v.into_iter().map(Self::outcome).collect(),
            Err(_) => vec![EvalOutcome::StoreError; d.blocks.len()],
        }
    }

    /// One block result to an evaluation outcome.
    fn outcome(r: BlockResult) -> EvalOutcome {
        let replaced = r
            .replaced
            .iter()
            .map(|x| Replaced {
                start: x.start,
                end: x.end,
                out_start: x.out_start,
                out_end: x.out_end,
                kind: x.kind.label().to_string(),
                tokenized: x.action == Action::Tokenize,
            })
            .collect();
        match r.outcome {
            CachedOutcome::Pass => EvalOutcome::Pass {
                text: r.text,
                replaced,
            },
            CachedOutcome::PassUncertain => EvalOutcome::PassUncertain {
                text: r.text,
                replaced,
            },
            CachedOutcome::Blocked => EvalOutcome::Blocked,
        }
    }
}

impl Sanitizer for ServiceSanitizer {
    fn detect(&mut self, text: &str) -> Result<Vec<Span>, DetectFailed> {
        let engine = Arc::clone(&self.lock().engine);
        engine.detect(text).map_err(|_| DetectFailed)
    }
    fn process(&mut self, doc: &Doc) -> EvalOutcome {
        match self.sanitize_batch(vec![BlockInput::text(doc.text.clone())]) {
            Ok(mut v) if v.len() == 1 => Self::outcome(v.remove(0)),
            _ => EvalOutcome::StoreError,
        }
    }
    fn restore(&mut self, token: &str) -> Option<String> {
        let failed = || {
            self.restore_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        };
        let g = self.lock();
        let Some(Ok(ns)) = g.state.as_ref().map(|s| s.namespace(DATASET)) else {
            failed();
            return None;
        };
        let mut n = ns.lock().unwrap_or_else(PoisonError::into_inner);
        if n.prepare(&[token.to_string()]).is_err() {
            failed();
            return None;
        }
        n.original(token).map(str::to_string)
    }
    fn token_settings(&self) -> &TokenSettings {
        &self.tokens
    }
    fn verifier(&self) -> Option<Arc<dyn Verifier>> {
        Some(Arc::clone(self.lock().engine.verifier()))
    }
}
