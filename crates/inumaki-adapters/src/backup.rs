//! Backups (spec §4.2): `<data_dir>/adapters/backups/<harness>/<id>/`,
//! 0700, with `manifest.json` and full copies of user-edited files, 0600.
//! A backup holds only what the harness files already held.
//!
//! A second apply while connected chains onto the active backup: the new
//! manifest keeps the first apply's "before" state (hash, copy, records),
//! so revert always returns to the state before inumaki.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{AdapterError, DriftItem, FileRole, HarnessId};
use crate::node::Format;

/// Backups kept per harness.
pub const RETENTION: usize = 5;

/// One edit as applied, with what was there before.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum EditRecord {
    /// A key set: `before` is the previous value (`None`: absent).
    Set {
        /// Key path.
        path: Vec<String>,
        /// Previous value.
        before: Option<Value>,
        /// Value written.
        after: Value,
        /// How many of the innermost parent tables this edit created
        /// (they were absent before it). A key-level revert removes those
        /// that it leaves empty. Zero in backups written before this field.
        #[serde(default, skip_serializing_if = "is_zero")]
        created_parents: usize,
    },
    /// A key removed.
    Remove {
        /// Key path.
        path: Vec<String>,
        /// Previous value.
        before: Option<Value>,
    },
    /// An element appended.
    Push {
        /// Array path.
        path: Vec<String>,
        /// Element.
        value: Value,
        /// It was already present.
        was_present: bool,
        /// The array did not exist before this edit (a revert removes it
        /// again when it is empty after our pull, so an element the user
        /// added since stays with the array). False in backups
        /// written before this field.
        #[serde(default, skip_serializing_if = "is_false")]
        created_array: bool,
        /// How many of the innermost parent tables this edit created, as for
        /// `Set`. Zero in backups written before this field.
        #[serde(default, skip_serializing_if = "is_zero")]
        created_parents: usize,
    },
    /// Elements removed (our own earlier entries; not restored on revert).
    Pull {
        /// Array path.
        path: Vec<String>,
    },
}

/// One file in a backup.
#[derive(Clone, Serialize, Deserialize)]
pub struct FileRecord {
    /// Role.
    pub role: FileRole,
    /// The edited target (a symlink's target).
    pub path: PathBuf,
    /// Format.
    pub format: Format,
    /// The file existed before inumaki.
    pub existed: bool,
    /// SHA-256 before inumaki.
    pub sha_before: Option<String>,
    /// SHA-256 after the latest apply.
    pub sha_after: String,
    /// Mode before inumaki.
    pub mode: Option<u32>,
    /// `<role>.orig` holds the bytes before inumaki.
    pub full_copy: bool,
    /// Revert may restore the full copy: false once the file was found
    /// changed between two chained applies (review C1).
    #[serde(default = "yes")]
    pub byte_exact_ok: bool,
    /// Edits, oldest first.
    pub records: Vec<EditRecord>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn yes() -> bool {
    true
}

/// A backup. `Debug` prints counts only (records hold tokens and entries).
#[derive(Clone, Serialize, Deserialize)]
pub struct Backup {
    /// Id (`<unix-seconds>-<nanos>`), sortable.
    pub id: String,
    /// Harness id string.
    pub harness: String,
    /// Directory (not serialized).
    #[serde(skip)]
    pub dir: PathBuf,
    /// Files.
    pub files: Vec<FileRecord>,
    /// Reverted and kept by choice.
    #[serde(default)]
    pub reverted: bool,
    /// Superseded by a chained apply.
    #[serde(default)]
    pub superseded: bool,
    /// Keep this backup after a successful revert (set by the caller; not persisted).
    #[serde(skip)]
    pub keep_after_revert: bool,
}

impl std::fmt::Debug for Backup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backup")
            .field("id", &self.id)
            .field("files", &self.files.len())
            .field(
                "records",
                &self.files.iter().map(|x| x.records.len()).sum::<usize>(),
            )
            .field("reverted", &self.reverted)
            .finish_non_exhaustive()
    }
}

/// What a revert did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevertReport {
    /// Files restored byte for byte.
    pub byte_exact: Vec<FileRole>,
    /// Files reverted key by key.
    pub key_level: Vec<FileRole>,
    /// Owned keys someone else changed since apply; left alone.
    pub conflicts: Vec<DriftItem>,
    /// The backup was kept.
    pub kept: bool,
    /// inumaki's proxy client header line could not be removed (Claude
    /// Code `env.ANTHROPIC_CUSTOM_HEADERS`): the secret is still in the file
    /// and goes to the provider; the caller must tell the user to remove it.
    pub client_header_left: bool,
    /// Only [`HarnessAdapter::revert_final`](crate::HarnessAdapter::revert_final),
    /// Codex: the trust record Codex wrote for inumaki's hook could not be
    /// removed from `config.toml`. The revert stands; the user removes the
    /// record in Codex's `/hooks` ([`CODEX_TRUST_LEFT_NOTE`]).
    pub codex_trust_left: bool,
}

/// What the app and the CLI tell the user when [`RevertReport::codex_trust_left`]
/// is set. A fixed sentence: no path, no key, no hash.
pub const CODEX_TRUST_LEFT_NOTE: &str =
    "Codex's trust record for inumaki's hook could not be removed; remove it in Codex's /hooks.";

/// The backup directory of one data directory. `Debug` never prints the
/// path (ruling F1: it contains the user's data directory).
#[derive(Clone)]
pub struct BackupStore {
    root: PathBuf,
}

impl std::fmt::Debug for BackupStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupStore").finish_non_exhaustive()
    }
}

impl BackupStore {
    /// Backups under `<data_dir>/adapters/backups`.
    pub fn new(data_dir: &Path) -> Self {
        BackupStore {
            root: data_dir.join("adapters").join("backups"),
        }
    }

    /// The store a loaded backup belongs to (`<root>/<harness>/<id>`).
    pub fn of_backup(b: &Backup) -> Self {
        let root = b
            .dir
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_default();
        BackupStore { root }
    }

    /// `<root>/<harness>`.
    pub fn dir(&self, h: HarnessId) -> PathBuf {
        self.root.join(h.as_str())
    }

    /// Backup ids, oldest first.
    pub fn list(&self, h: HarnessId) -> Vec<String> {
        let mut ids: Vec<String> = fs::read_dir(self.dir(h))
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().join("manifest.json").is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        ids.sort();
        ids
    }

    /// Load one backup.
    pub fn load(&self, h: HarnessId, id: &str) -> Result<Backup, AdapterError> {
        let dir = self.dir(h).join(id);
        let bytes = fs::read(dir.join("manifest.json")).map_err(|_| AdapterError::Backup)?;
        let mut b: Backup = serde_json::from_slice(&bytes).map_err(|_| AdapterError::Backup)?;
        b.dir = dir;
        Ok(b)
    }

    /// The newest backup that is neither reverted nor superseded.
    pub fn active(&self, h: HarnessId) -> Option<Backup> {
        self.list(h)
            .iter()
            .rev()
            .filter_map(|id| self.load(h, id).ok())
            .find(|b| !b.reverted && !b.superseded)
    }

    /// A new, empty backup directory (0700). The leaf is created
    /// exclusively, so a clock that repeats (coarse resolution, a step
    /// back) never reuses an existing backup's directory: the id moves on
    /// by a nanosecond until it is free.
    pub(crate) fn create(&self, h: HarnessId) -> Result<Backup, AdapterError> {
        let parent = self.dir(h);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&parent)
            .map_err(|_| AdapterError::Backup)?;
        let mut t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..1000 {
            let id = format!("{:012}-{:09}", t / 1_000_000_000, t % 1_000_000_000);
            let dir = parent.join(&id);
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    return Ok(Backup {
                        id,
                        harness: h.as_str().to_string(),
                        dir,
                        files: Vec::new(),
                        reverted: false,
                        superseded: false,
                        keep_after_revert: false,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => t += 1,
                Err(_) => return Err(AdapterError::Backup),
            }
        }
        Err(AdapterError::Backup)
    }

    /// Delete `b`'s directory.
    pub fn delete(&self, b: &Backup) -> Result<(), AdapterError> {
        fs::remove_dir_all(&b.dir).map_err(|_| AdapterError::Backup)
    }

    /// Keep the newest [`RETENTION`] backups of `h`, never the active one.
    pub(crate) fn prune(&self, h: HarnessId) {
        let active = self.active(h).map(|b| b.id);
        let ids = self.list(h);
        let excess = ids.len().saturating_sub(RETENTION);
        for id in ids.into_iter().take(excess) {
            if Some(&id) != active.as_ref() {
                let _ = fs::remove_dir_all(self.dir(h).join(id));
            }
        }
    }
}

impl Backup {
    /// Write `manifest.json` (0600).
    pub(crate) fn save(&self) -> Result<(), AdapterError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| AdapterError::Backup)?;
        write_private(&self.dir.join("manifest.json"), &bytes)
    }

    /// Store the pre-inumaki bytes of `role` (0600).
    pub(crate) fn save_copy(&self, role: FileRole, bytes: &[u8]) -> Result<(), AdapterError> {
        write_private(&self.copy_path(role), bytes)
    }

    /// Path of the full copy of `role`.
    pub fn copy_path(&self, role: FileRole) -> PathBuf {
        let name = serde_json::to_value(role)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        self.dir.join(format!("{name}.orig"))
    }

    /// The record of `role`.
    pub fn file(&self, role: FileRole) -> Option<&FileRecord> {
        self.files.iter().find(|f| f.role == role)
    }
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AdapterError> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|_| AdapterError::Backup)?;
    // A leftover temporary file keeps its old mode through `open`: reset it.
    f.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| AdapterError::Backup)?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| AdapterError::Backup)?;
    fs::rename(&tmp, path).map_err(|_| AdapterError::Backup)
}
