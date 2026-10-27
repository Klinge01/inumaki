//! `<data_dir>/app/state.json` (M6 spec §6.6): 0600, atomic replace, no
//! values, tokens, secrets, paths, or server names. "Leave unprotected"
//! choices and protected servers are keyed by an HMAC of harness id and
//! server name under `state.key` (32 random bytes, 0600), so a copy of
//! `state.json` alone cannot confirm a guessed server name (M6 spec §6.6,
//! amendment 2026-09-29).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use inumaki_client::{CheckResults, PathStatus};
use serde::{Deserialize, Serialize};

use crate::error::CmdError;

/// The last check result of one harness (`"direct"` for the direct run).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckMemo {
    /// Unix seconds.
    pub at: i64,
    /// Status, reason codes, booleans, counts.
    pub results: CheckResults,
}

/// The newest check across all memos, for the Overview and the tray.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LastCheck {
    /// Unix seconds of the newest memo.
    pub at: i64,
    /// Any memo has a failed path (the tray turns red on it).
    pub failed: bool,
}

/// The last-check summary: `None` without memos; `at` is the newest memo's
/// time, `failed` is true when any memo (not only the newest) has a failed
/// path.
pub fn last_check_summary(s: &AppStateFile) -> Option<LastCheck> {
    let at = s.last_check.values().map(|m| m.at).max()?;
    let failed = s.last_check.values().any(|m| {
        [&m.results.gateway, &m.results.mirror, &m.results.proxy]
            .iter()
            .any(|r| r.status == PathStatus::Failed)
    });
    Some(LastCheck { at, failed })
}

/// UI preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(from = "PrefsFile")]
pub struct Prefs {
    /// The first-run flow was finished or skipped.
    pub first_run_done: bool,
    /// The user's choice to route a harness's chat through the proxy, by
    /// harness key (`claude-code`, `codex`, `hermes`, `openclaw`). Absent:
    /// no choice yet, so the effective value is whether the harness's active
    /// backup holds its chat route (a route written before the choice
    /// existed, by the app or by the CLI's default, stays on). A user
    /// Revert removes the entry. Connect writes no chat route unless this
    /// is on. Booleans only: no value or path.
    pub chat_opt_in: BTreeMap<String, bool>,
    /// The file predates `chat_opt_in` (M9): the connected harnesses the
    /// old app routed (Codex, Hermes Agent, OpenClaw with an API-key login)
    /// still get their choice saved as on, once their login kind is known
    /// (`harness::connect::migrate_pre_m9_chat`). Cleared when that ran.
    pub chat_migration_pending: bool,
}

/// [`Prefs`] as stored, older fields included: they are read once and
/// folded into `chat_opt_in`, never written back.
#[derive(Deserialize)]
struct PrefsFile {
    #[serde(default)]
    first_run_done: bool,
    /// Absent in files written before M9.
    #[serde(default)]
    chat_opt_in: Option<BTreeMap<String, bool>>,
    #[serde(default)]
    chat_migration_pending: bool,
    /// Before M9: Claude Code's chat choice (`null`: none).
    #[serde(default)]
    claude_code_chat_opt_in: Option<bool>,
    /// Before M9: Codex's ChatGPT-login opt-in. `false` was also the
    /// default of an API-key login that routed chat, so only `true` is a
    /// choice.
    #[serde(default)]
    codex_chatgpt_opt_in: bool,
}

impl From<PrefsFile> for Prefs {
    fn from(f: PrefsFile) -> Prefs {
        let chat_migration_pending = f.chat_migration_pending || f.chat_opt_in.is_none();
        let mut chat_opt_in = f.chat_opt_in.unwrap_or_default();
        if let Some(on) = f.claude_code_chat_opt_in {
            chat_opt_in.entry("claude-code".into()).or_insert(on);
        }
        if f.codex_chatgpt_opt_in {
            chat_opt_in.entry("codex".into()).or_insert(true);
        }
        Prefs {
            first_run_done: f.first_run_done,
            chat_opt_in,
            chat_migration_pending,
        }
    }
}

/// The file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppStateFile {
    /// Format version (1).
    #[serde(default)]
    pub version: u32,
    /// Acknowledged red-by-design paths, `"<harness>/<mcp|files|chat>"`.
    #[serde(default)]
    pub acknowledged: BTreeSet<String>,
    /// Backup ids per harness id, oldest first (the adapter's ids).
    #[serde(default)]
    pub backups: BTreeMap<String, Vec<String>>,
    /// Server keys (`harness::server_key`, an HMAC under `state.key`) of servers left unprotected.
    #[serde(default)]
    pub leave_unprotected: BTreeSet<String>,
    /// Protected servers: harness id → server key → dataset label.
    #[serde(default)]
    pub protected: BTreeMap<String, BTreeMap<String, String>>,
    /// Harnesses whose Reconnect failed after the revert: disconnected, tray red.
    #[serde(default)]
    pub reconnect_failed: BTreeSet<String>,
    /// Last check result per harness id, and `"direct"`.
    #[serde(default)]
    pub last_check: BTreeMap<String, CheckMemo>,
    /// Preferences.
    #[serde(default)]
    pub prefs: Prefs,
}

/// Read `path`; a missing or unreadable file is an empty state. A file that
/// exists but does not parse is renamed to `state.json.corrupt` (0600) before
/// anything can overwrite it: it holds the backup ids a Revert needs.
pub fn load(path: &Path) -> AppStateFile {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|_| {
            crate::applog::event("state_unreadable");
            set_aside(path);
            AppStateFile::default()
        }),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                crate::applog::event("state_unreadable");
            }
            AppStateFile::default()
        }
    }
}

/// Move a corrupt `path` to `<path>.corrupt` (then `.corrupt.2`, … so an
/// earlier copy is kept), 0600.
fn set_aside(path: &Path) {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    for n in 1..=9u32 {
        let suffix = if n == 1 {
            ".corrupt".to_string()
        } else {
            format!(".corrupt.{n}")
        };
        let to = path.with_file_name(format!("{name}{suffix}"));
        if n < 9 && to.exists() {
            continue;
        }
        if std::fs::rename(path, &to).is_ok() {
            let _ = std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o600));
        }
        return;
    }
}

/// Read the 32-byte key at `path`, creating it (0600, 0700 directory) when
/// it is missing or malformed.
pub fn load_or_create_key(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>, CmdError> {
    let fail = || CmdError::new("state_unwritable");
    if let Ok(k) = std::fs::read(path) {
        if k.len() == 32 {
            return Ok(zeroize::Zeroizing::new(k));
        }
    }
    let dir = path.parent().ok_or_else(fail)?;
    std::fs::create_dir_all(dir).map_err(|_| fail())?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|_| fail())?;
    let mut k = zeroize::Zeroizing::new(vec![0u8; 32]);
    getrandom::fill(&mut k).map_err(|_| fail())?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| fail())?;
    // `mode` applies on create only: a malformed key file being replaced keeps its old mode otherwise.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|_| fail())?;
    f.write_all(&k).map_err(|_| fail())?;
    Ok(k)
}

/// Write `s` to `path` atomically, 0600, in a 0700 directory.
pub fn save(path: &Path, s: &AppStateFile) -> Result<(), CmdError> {
    let fail = || CmdError::new("state_unwritable");
    let dir = path.parent().ok_or_else(fail)?;
    std::fs::create_dir_all(dir).map_err(|_| fail())?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|_| fail())?;
    let mut v = s.clone();
    v.version = 1;
    let bytes = serde_json::to_vec_pretty(&v).map_err(|_| fail())?;
    let tmp = dir.join(".state.json.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| fail())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| fail())?;
        f.write_all(&bytes).map_err(|_| fail())?;
        f.sync_all().map_err(|_| fail())?;
    }
    std::fs::rename(&tmp, path).map_err(|_| fail())
}
