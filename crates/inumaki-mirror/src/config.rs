//! Mirror settings (M5 spec §13). The daemon parses `[mirror]` into this.

use std::path::PathBuf;
use std::time::Duration;

/// Mirror settings.
#[derive(Clone, PartialEq, Eq)]
pub struct MirrorConfig {
    /// Mirror root (`~/Inumaki Mirror`).
    pub root: PathBuf,
    /// Parent of default outbox destinations (`~/Inumaki Outbox`).
    pub outbox_root: PathBuf,
    /// Watcher debounce.
    pub debounce: Duration,
    /// Largest file mirrored or restored.
    pub max_file_bytes: u64,
    /// Blocking worker threads.
    pub workers: usize,
    /// Full reconcile period.
    pub rescan_interval: Duration,
}

impl std::fmt::Debug for MirrorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MirrorConfig")
            .field("debounce", &self.debounce)
            .field("max_file_bytes", &self.max_file_bytes)
            .field("workers", &self.workers)
            .field("rescan_interval", &self.rescan_interval)
            .finish_non_exhaustive()
    }
}

impl Default for MirrorConfig {
    fn default() -> Self {
        MirrorConfig {
            root: PathBuf::new(),
            outbox_root: PathBuf::new(),
            debounce: Duration::from_millis(500),
            max_file_bytes: 1024 * 1024,
            workers: 1,
            rescan_interval: Duration::from_secs(3600),
        }
    }
}

impl MirrorConfig {
    /// Epoch, generation, and fingerprint poll (spec §7.3).
    pub const STATE_POLL: Duration = Duration::from_secs(10);
    /// Minimum spacing of tripwire passes per dataset (spec §7.4).
    pub const TRIPWIRE_MIN: Duration = Duration::from_secs(30);
    /// Poll reconcile period when the watcher failed (spec §6.2).
    pub const WATCH_POLL: Duration = Duration::from_secs(60);
    /// Watcher retry period (spec §6.2).
    pub const WATCH_RETRY: Duration = Duration::from_secs(600);
    /// Outbox settle re-check (spec §8 step 1).
    pub const SETTLE: Duration = Duration::from_millis(500);
    /// Target sub-batch size (spec §5.1 step 5).
    pub const SUB_BATCH_BYTES: usize = 8192;
    /// Engine time after which the next sub-batch is halved.
    pub const SUB_BATCH_BUDGET: Duration = Duration::from_secs(1);
    /// Largest block (a text chunk, a CSV record or field, a JSON string
    /// value, a verification block) sent to the engine. A file with a larger
    /// block is withheld whole (fail closed): one block is one engine call
    /// under the namespace lock and the file format does not bound it. The
    /// daemon enforces the same size (`service::MAX_BLOCK_BYTES`).
    pub const MAX_BLOCK_BYTES: usize = 64 * 1024;
    /// Hard ceiling on `max_file_bytes`.
    pub const MAX_FILE_BYTES_CEILING: u64 = 16 * 1024 * 1024;
}
