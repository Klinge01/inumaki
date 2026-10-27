//! Settings view (spec §6.4): service, models, backups, app log location,
//! updates (off), version with the experimental badge and the measured
//! numbers. M6-3 adds install/remove/restart and the model download at
//! `service_info` and `models_status`.
//!
//! Backups: the list shows every adapter backup with its time and whether
//! it is the live Connect backup. Restoring the live backup is Revert
//! (`harness::connect::revert`: it takes the harness lock, revokes the
//! tokens, and reports `client_header_left`); no other backup is ever
//! restored over the current files, so Settings only deletes old ones.

use std::collections::BTreeMap;
use std::sync::Arc;

use inumaki_client::{HarnessId, ManagedBy, ModelsJob, ProfileStatus};
use serde::Serialize;

use super::folders::DataChange;
use crate::appstate::{AppStateFile, Prefs};
use crate::ctx::Ctx;
use crate::error::CmdError;
use crate::harness::connect;
use crate::harness::harness_key;
use crate::harness::ops::{BackupInfo, HarnessOps};
use crate::measured::{Measured, measured};

/// The login service as the app sees it (no `Debug`: `bin_dir` is a path).
#[derive(Serialize)]
pub struct ServiceView {
    /// The socket answers.
    pub reachable: bool,
    /// Daemon version.
    pub version: Option<String>,
    /// Who manages it.
    pub managed_by: Option<ManagedBy>,
    /// A restart is pending (after a model download).
    pub restart_required: bool,
    /// Helper binary directory (shown to the local user).
    pub bin_dir: Option<String>,
    /// The config file that names the socket cannot be read (a fixed sentence
    /// naming the file, never its content). Installing the service would not help.
    pub config_error: Option<String>,
}

/// `GET /v1/service`, or the status version before M6-3's endpoint exists.
pub async fn service_info(ctx: &Ctx) -> Result<ServiceView, CmdError> {
    if let Some(why) = &ctx.paths.config_error {
        return Ok(ServiceView {
            reachable: false,
            version: None,
            managed_by: None,
            restart_required: false,
            bin_dir: None,
            config_error: Some(why.clone()),
        });
    }
    match ctx.client.service().await {
        Ok(s) => Ok(ServiceView {
            reachable: true,
            version: Some(s.version.clone()),
            managed_by: Some(s.managed_by),
            restart_required: s.restart_required,
            bin_dir: Some(s.bin_dir.clone()),
            config_error: None,
        }),
        Err(_) => {
            let st = ctx.client.status().await.ok();
            Ok(ServiceView {
                reachable: st.is_some(),
                version: st.map(|s| s.version),
                managed_by: None,
                restart_required: false,
                bin_dir: None,
                config_error: None,
            })
        }
    }
}

/// `GET /v1/models/pull`.
pub async fn models_status(ctx: &Ctx) -> Result<ModelsJob, CmdError> {
    Ok(ctx.client.models_pull().await?)
}

/// One backup row (no `Debug`).
#[derive(Serialize)]
pub struct BackupRow {
    /// Harness.
    pub harness: &'static str,
    /// Backup.
    pub backup: BackupInfo,
    /// The live Connect backup (not deletable while connected).
    pub live: bool,
}

impl std::fmt::Debug for BackupRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupRow")
            .field("live", &self.live)
            .finish_non_exhaustive()
    }
}

/// The Settings view. `prefs` is the state of the controlled inputs
/// (`state.json` is the source of truth, the UI keeps no copy of its own).
#[derive(Serialize)]
pub struct SettingsView {
    /// App version.
    pub version: &'static str,
    /// Profiles and their availability.
    pub profiles: Vec<ProfileStatus>,
    /// Backups, oldest first per harness.
    pub backups: Vec<BackupRow>,
    /// App log location (shown locally).
    pub app_log: String,
    /// Measured numbers.
    pub measured: Vec<Measured>,
    /// Updates are installed by hand (spec §7.3).
    pub updates: &'static str,
    /// Preferences from `state.json`.
    pub prefs: Prefs,
}

impl std::fmt::Debug for SettingsView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingsView")
            .field("backups", &self.backups.len())
            .field("measured", &self.measured.len())
            .finish_non_exhaustive()
    }
}

/// Backup ids `state.json` holds for a harness without an active backup.
type Stale = Vec<(&'static str, Vec<String>)>;

/// Every backup of every harness; reads the backup directories (blocking).
/// A backup id `state.json` holds while the adapter has no active backup is
/// stale (an outside revert, a state write that failed), as for Connect:
/// it is not live, and it is returned to be cleared.
fn backup_rows(harnesses: &[Arc<dyn HarnessOps>], state: &AppStateFile) -> (Vec<BackupRow>, Stale) {
    let mut rows = Vec::new();
    let mut stale = Vec::new();
    for o in harnesses {
        let key = harness_key(o.id());
        let recorded = state.backups.get(key).cloned().unwrap_or_default();
        let active = o.active_backup();
        let live: Vec<String> = match active {
            Some(a) => recorded.into_iter().chain([a]).collect(),
            None => {
                if !recorded.is_empty() {
                    stale.push((key, recorded));
                }
                Vec::new()
            }
        };
        for b in o.backups() {
            rows.push(BackupRow {
                harness: key,
                live: live.contains(&b.id),
                backup: b,
            });
        }
    }
    (rows, stale)
}

/// Build the Settings view.
pub async fn settings(ctx: &Ctx) -> Result<SettingsView, CmdError> {
    let profiles = ctx
        .client
        .status()
        .await
        .map(|s| s.profiles)
        .unwrap_or_default();
    // The backup directories are read from a blocking thread.
    let harnesses = ctx.harnesses.clone();
    let state = ctx.state();
    let prefs = state.prefs.clone();
    let (backups, stale) = tokio::task::spawn_blocking(move || backup_rows(&harnesses, &state))
        .await
        .map_err(|_| CmdError::new("internal"))?;
    // Only the ids seen stale: a Connect that recorded a new one meanwhile keeps it.
    if !stale.is_empty()
        && ctx
            .update_state(|s| {
                for (k, ids) in &stale {
                    if s.backups.get(*k) == Some(ids) {
                        s.backups.remove(*k);
                    }
                }
            })
            .is_err()
    {
        crate::applog::event("state_unwritable");
    }
    Ok(SettingsView {
        version: env!("CARGO_PKG_VERSION"),
        profiles,
        backups,
        app_log: ctx.paths.log_file.display().to_string(),
        measured: measured(),
        updates: "Install new versions by hand.",
        prefs,
    })
}

/// Delete a backup that is not the live Connect backup. Under the harness's
/// lock: a Connect that runs meanwhile cannot make the backup live between
/// the check and the delete. The lock is taken once and no other locked
/// entry point is called from here.
pub async fn delete_backup(ctx: &Ctx, harness: HarnessId, id: &str) -> Result<(), CmdError> {
    let o = ctx
        .harnesses
        .iter()
        .find(|o| o.id() == harness)
        .cloned()
        .ok_or_else(|| CmdError::new("harness_not_found"))?;
    let lock = ctx.harness_lock(harness);
    let _held = lock.lock().await;
    let in_state = ctx
        .state()
        .backups
        .get(harness_key(harness))
        .is_some_and(|b| b.iter().any(|x| x == id));
    if in_state || o.active_backup().as_deref() == Some(id) {
        return Err(CmdError::new("backup_in_use"));
    }
    let id = id.to_string();
    tokio::task::spawn_blocking(move || o.delete_backup(&id))
        .await
        .map_err(|_| CmdError::new("internal"))??;
    Ok(())
}

/// The first-run flow was finished or skipped.
pub fn set_first_run_done(ctx: &Ctx) -> Result<(), CmdError> {
    ctx.update_state(|s| s.prefs.first_run_done = true)
}

/// Route `h`'s chat through the proxy, or not (M6 D6, every harness since
/// M9 Task 6). Claude Code's route reaches every open window at once, and
/// the support-email and strict profiles refuse Claude Code's and Codex's
/// chat today, so it is its own choice. For Codex it is also the
/// ChatGPT-login opt-in. The choice is always saved (an explicit value,
/// also when it equals what the files hold). A connected `h` is
/// reconnected through its lock, so the files follow, only when `on`
/// differs from the effective value before the save (a failure is reported
/// like a data change, the choice stays). No other harness is touched.
pub async fn set_chat_opt_in(ctx: &Ctx, h: HarnessId, on: bool) -> Result<DataChange, CmdError> {
    let changed = connect::chat_effective(ctx, h).await != on;
    ctx.update_state(|s| {
        s.prefs.chat_opt_in.insert(harness_key(h).into(), on);
    })?;
    if !changed {
        return Ok(DataChange::from_failed(Vec::new()));
    }
    Ok(DataChange::from_failed(
        connect::refresh_harness(ctx, h).await,
    ))
}

/// The preferences as the UI shows them: the stored ones, and the value
/// each harness's chat switch stands for (the choice, else what the files
/// hold).
#[derive(Debug, Serialize)]
pub struct PrefsView {
    /// The stored preferences (a harness is absent from `chat_opt_in` until
    /// the user chooses, and again after a Revert).
    #[serde(flatten)]
    pub prefs: Prefs,
    /// Harness key → its chat route is wanted: the choice, else whether the
    /// active backup holds the route. Every harness the app knows.
    pub chat_effective: BTreeMap<&'static str, bool>,
}

/// UI preferences.
pub async fn prefs(ctx: &Ctx) -> Result<PrefsView, CmdError> {
    connect::migrate_pre_m9_chat(ctx, false);
    let mut chat_effective = BTreeMap::new();
    for o in &ctx.harnesses {
        chat_effective.insert(
            harness_key(o.id()),
            connect::chat_effective(ctx, o.id()).await,
        );
    }
    Ok(PrefsView {
        prefs: ctx.state().prefs,
        chat_effective,
    })
}

/// A dataset for the Activity and Inspect pickers (no check datasets; no
/// `Debug`: the id and name are slugs and display names).
#[derive(Serialize)]
pub struct DatasetRow {
    /// Id.
    pub id: String,
    /// Display name (local).
    pub name: String,
    /// Kind.
    pub kind: inumaki_client::DatasetKind,
}

/// Datasets without check datasets.
pub async fn datasets(ctx: &Ctx) -> Result<Vec<DatasetRow>, CmdError> {
    Ok(ctx
        .client
        .datasets()
        .await?
        .into_iter()
        .filter(|d| !d.id.starts_with("check-"))
        .map(|d| DatasetRow {
            id: d.id,
            name: d.name,
            kind: d.kind,
        })
        .collect())
}
