//! Folder state, error classes, counts (M5 spec §9, §12.2).

use std::collections::BTreeSet;
use std::io;
use std::time::{Duration, Instant};

use crate::engine::EngineError;
use crate::fsops::{IoClass, map_errno};

/// `FolderStatus.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderState {
    /// First scan, rescan, or re-mirror in progress.
    Scanning,
    /// Current (events or polling).
    Watching,
    /// Not started, or being removed.
    Stopped,
    /// A failing error is set.
    Failed,
    /// A first open of the source or the outbox destination has waited
    /// longer than [`PENDING_AFTER`]: on macOS, the privacy prompt for the
    /// folder is most likely on screen (TCC spike finding 2).
    Pending,
}

/// How long a first open may take before the folder reads `pending`.
pub const PENDING_AFTER: Duration = Duration::from_secs(2);

/// `FolderStatus.error`, in precedence order (the derive orders variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FolderError {
    /// Root missing or replaced.
    SourceMissing,
    /// macOS privacy denial (`EPERM`).
    SourceNotPermitted,
    /// `EACCES` on the root.
    SourceUnreadable,
    /// The mirror cannot be written.
    MirrorUnwritable,
    /// Vault or key store.
    VaultUnavailable,
    /// The profile's model is missing.
    ModelUnavailable,
    /// The watcher could not be set up; polling.
    WatchFailed,
    /// The outbox destination cannot be written.
    OutboxUnwritable,
    /// Anything else.
    Internal,
    /// Only from [`Mirror::remove`](crate::Mirror::remove): the job in
    /// flight did not end within the removal deadline (a first open waiting
    /// on a macOS privacy prompt). Never a status error; calling `remove`
    /// again finishes the removal.
    Busy,
}

impl FolderError {
    /// The contract string.
    pub fn as_str(self) -> &'static str {
        match self {
            FolderError::SourceMissing => "source_missing",
            FolderError::SourceNotPermitted => "source_not_permitted",
            FolderError::SourceUnreadable => "source_unreadable",
            FolderError::MirrorUnwritable => "mirror_unwritable",
            FolderError::VaultUnavailable => "vault_unavailable",
            FolderError::ModelUnavailable => "model_unavailable",
            FolderError::WatchFailed => "watch_failed",
            FolderError::OutboxUnwritable => "outbox_unwritable",
            FolderError::Internal => "internal",
            FolderError::Busy => "busy",
        }
    }

    /// Whether the folder is `failed` while this is set (spec §9).
    pub fn is_failing(self) -> bool {
        !matches!(
            self,
            FolderError::WatchFailed | FolderError::OutboxUnwritable | FolderError::Internal
        )
    }

    /// From an engine error.
    pub fn from_engine(e: &EngineError) -> FolderError {
        match e {
            EngineError::VaultUnavailable | EngineError::DatasetGone => {
                FolderError::VaultUnavailable
            }
            EngineError::ModelUnavailable => FolderError::ModelUnavailable,
            EngineError::Unresolved { .. } | EngineError::Internal(_) => FolderError::Internal,
        }
    }

    /// From an error on the source root.
    pub fn from_source_io(e: &io::Error) -> FolderError {
        match map_errno(e) {
            IoClass::NotFound | IoClass::Symlink => FolderError::SourceMissing,
            IoClass::NotPermitted => FolderError::SourceNotPermitted,
            IoClass::AccessDenied => FolderError::SourceUnreadable,
            _ => FolderError::Internal,
        }
    }

    /// From an error writing the mirror.
    pub fn from_mirror_io(_e: &io::Error) -> FolderError {
        FolderError::MirrorUnwritable
    }
}

/// `FolderStatus.files`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Eligible regular files in the source.
    pub source: u64,
    /// Sanitized files.
    pub mirrored: u64,
    /// `blocked` placeholders.
    pub blocked: u64,
    /// `unsupported` placeholders.
    pub unsupported: u64,
    /// Queued.
    pub pending: u64,
}

/// `FolderStatus.outbox_files`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboxCounts {
    /// Written to the destination.
    pub rehydrated: u64,
    /// Refused for unresolved placeholders.
    pub with_unresolved: u64,
    /// Waiting.
    pub pending: u64,
}

/// One folder's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// State.
    pub state: FolderState,
    /// First error in precedence order.
    pub error: Option<FolderError>,
    /// File counts.
    pub files: Counts,
    /// Last successful write.
    pub last_mirrored_at: Option<i64>,
    /// Current epoch.
    pub epoch_id: i64,
    /// Some record is on an older epoch or fingerprint.
    pub remirror_pending: bool,
    /// Outbox counts.
    pub outbox: OutboxCounts,
}

/// Mutable status behind a mutex. No `Debug`: the retry sets hold relative
/// paths. The outbox counts live in the index (records survive a restart).
#[derive(Default)]
pub(crate) struct Status {
    pub started: bool,
    pub scanning: bool,
    pub removing: bool,
    pub errors: BTreeSet<FolderError>,
    pub last_mirrored_at: Option<i64>,
    pub source_files: u64,
    pub backoff: Option<(Instant, Duration)>,
    /// Outbox paths that failed on an unwritable destination; the poller
    /// requeues them (spec §9, review I5).
    pub pending_outbox: BTreeSet<Vec<u8>>,
    /// Source paths whose confirmed-original removal failed; the poller
    /// requeues them at removal priority on every tick (review Cr1).
    pub pending_confirmed: BTreeSet<Vec<u8>>,
}

impl Status {
    /// The state and the first error in precedence order, counting `extra`
    /// (a condition the error set does not hold, such as an untrusted root)
    /// as if it were set. A folder being removed is `stopped` whatever its
    /// errors; a folder whose first open waits (`pending`) is `pending`
    /// before any earlier failure, since the open in progress decides it.
    pub(crate) fn view(
        &self,
        extra: Option<FolderError>,
        pending: bool,
    ) -> (FolderState, Option<FolderError>) {
        let first = self.errors.iter().copied().chain(extra).min();
        let state = if self.removing || !self.started {
            FolderState::Stopped
        } else if pending {
            FolderState::Pending
        } else if first.is_some_and(FolderError::is_failing) {
            FolderState::Failed
        } else if self.scanning {
            FolderState::Scanning
        } else {
            FolderState::Watching
        };
        (state, first)
    }

    /// Set an error and schedule a retry (10 s doubling to 10 min).
    pub(crate) fn fail(&mut self, e: FolderError) {
        self.errors.insert(e);
        // Double only once the current deadline has passed, so a burst of
        // failures within one retry round counts as one.
        let now = Instant::now();
        let next = match self.backoff {
            Some((at, _)) if now < at => return,
            Some((_, d)) => (d * 2).min(Duration::from_secs(600)),
            None => Duration::from_secs(10),
        };
        self.backoff = Some((now + next, next));
    }

    /// A successful file clears the failing classes and `internal`.
    pub(crate) fn succeed(&mut self) {
        self.errors
            .retain(|e| matches!(e, FolderError::WatchFailed | FolderError::OutboxUnwritable));
        self.backoff = None;
    }
}
