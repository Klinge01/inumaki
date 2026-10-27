//! Folders (M6 spec §9.5, M5). `FolderStatus.outbox_files` is the counts
//! object that §9.5 lists as a second `outbox` key (dated amendment, Task 4).
//! Amended 2026-09-29 (M5 spec §12.4): two error classes, `with_unresolved`
//! counts refused files.

use serde::{Deserialize, Serialize};

/// `POST /v1/datasets/{id}/folder` body.
#[derive(Clone, Serialize, Deserialize)]
pub struct FolderCreate {
    /// Absolute source directory.
    pub source: String,
    /// Absolute outbox destination; the integration spec's default when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbox_destination: Option<String>,
}

debug_fields!(FolderCreate {});

/// `FolderBody`.
#[derive(Clone, Serialize, Deserialize)]
pub struct FolderBody {
    /// Dataset slug.
    pub dataset: String,
    /// Opaque label (names the mirror directory).
    pub label: String,
    /// Source directory.
    pub source: String,
    /// Agent-readable mirror.
    pub mirror: String,
    /// Agent-writable outbox inside the mirror.
    pub outbox: String,
    /// Where rehydrated outbox files go.
    pub outbox_destination: String,
    /// Unix seconds.
    pub created_at: i64,
}

debug_fields!(FolderBody { label, created_at });

/// `POST …/folder/rescan` answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescanBody {
    /// Files queued.
    pub queued: u64,
}

/// Folder state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderState {
    /// First scan.
    Scanning,
    /// Watching for changes.
    Watching,
    /// Stopped.
    Stopped,
    /// Failed; see `error`.
    Failed,
    /// A first open of the source or the outbox destination has waited for
    /// more than 2 s: on macOS, most likely the privacy prompt asking
    /// whether inumaki may read the folder is on screen.
    Pending,
}

/// Folder error class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderError {
    /// Source directory missing.
    SourceMissing,
    /// macOS privacy protection denied access (M5 spec §9.1).
    SourceNotPermitted,
    /// Source not readable.
    SourceUnreadable,
    /// Mirror not writable.
    MirrorUnwritable,
    /// The watcher failed.
    WatchFailed,
    /// The vault is unavailable.
    VaultUnavailable,
    /// A model is unavailable.
    ModelUnavailable,
    /// The outbox destination cannot be written (M5 spec §9).
    OutboxUnwritable,
    /// Anything else.
    Internal,
}

/// File counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderFiles {
    /// Files in the source.
    pub source: u64,
    /// Mirrored.
    pub mirrored: u64,
    /// Blocked.
    pub blocked: u64,
    /// Unsupported format.
    pub unsupported: u64,
    /// Waiting.
    pub pending: u64,
}

/// Outbox counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxFiles {
    /// Rehydrated to the destination.
    pub rehydrated: u64,
    /// Refused: unresolved placeholders, not written.
    pub with_unresolved: u64,
    /// Waiting.
    pub pending: u64,
}

/// One folder in `GET /v1/folders`.
#[derive(Clone, Serialize, Deserialize)]
pub struct FolderStatus {
    /// Dataset slug.
    pub dataset: String,
    /// Opaque label.
    pub label: String,
    /// Source directory.
    pub source: String,
    /// Mirror directory.
    pub mirror: String,
    /// Outbox directory (Codex `writable_roots`, §4.3).
    pub outbox: String,
    /// Where restored outbox files go (local path). Absent from older
    /// daemons: empty, which the app treats as unknown.
    #[serde(default)]
    pub outbox_destination: String,
    /// State.
    pub state: FolderState,
    /// Error class.
    pub error: Option<FolderError>,
    /// File counts.
    pub files: FolderFiles,
    /// Last mirrored file.
    pub last_mirrored_at: Option<i64>,
    /// Epoch.
    pub epoch_id: i64,
    /// A re-mirror after rotation is pending.
    pub remirror_pending: bool,
    /// Outbox counts.
    pub outbox_files: OutboxFiles,
}

debug_fields!(FolderStatus {
    label,
    state,
    error,
    files,
    last_mirrored_at,
    epoch_id,
    remirror_pending,
    outbox_files
});

/// `GET /v1/folders`.
#[derive(Clone, Serialize, Deserialize)]
pub struct FoldersBody {
    /// Mirror root, known before any folder exists.
    pub mirror_root: String,
    /// Folders.
    pub folders: Vec<FolderStatus>,
}

debug_fields!(FoldersBody { folders });
