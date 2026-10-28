//! What the mirror needs from the daemon (M5 spec §3). Implementations map
//! their errors to [`EngineError`]'s classes; no variant carries text.

use inumaki_core::span::EntityKind;

use crate::folder::RootIdentity;

/// Why the engine could not answer. Carries classes and counts only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    /// Vault or key store failure.
    #[error("vault unavailable")]
    VaultUnavailable,
    /// The dataset profile's model is missing.
    #[error("model unavailable")]
    ModelUnavailable,
    /// The dataset no longer exists.
    #[error("dataset gone")]
    DatasetGone,
    /// Strict restoration found placeholders it cannot resolve.
    #[error("unresolved placeholders: {unknown} unknown, {removed} removed")]
    Unresolved {
        /// Unknown or foreign tokens.
        unknown: usize,
        /// Removed-value markers.
        removed: usize,
    },
    /// Anything else; a fixed class.
    #[error("internal: {0}")]
    Internal(&'static str),
}

/// One block's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Released.
    Pass,
    /// Released by the engine as uncertain; the mirror withholds it.
    Uncertain,
    /// Withheld.
    Blocked,
}

/// One sanitized block. `text` is empty unless `Pass`.
#[derive(Clone, PartialEq, Eq)]
pub struct Block {
    /// Verdict.
    pub outcome: Outcome,
    /// Sanitized text.
    pub text: String,
    /// Kinds replaced or withheld.
    pub kinds: Vec<EntityKind>,
}

impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Block")
            .field("outcome", &self.outcome)
            .field("len", &self.text.len())
            .field("kinds", &self.kinds.len())
            .finish()
    }
}

/// What the poller compares (spec §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatasetState {
    /// Current epoch id.
    pub epoch_id: i64,
    /// Entries generation ([`MirrorEngine::state`]).
    pub entries_generation: u64,
    /// Profile name, profile configuration hash, model manifest hash.
    pub fingerprint: [u8; 32],
}

/// Which way the data moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityDirection {
    /// Mirror output (toward the model).
    Result,
    /// Outbox input (from the model).
    Arguments,
}

/// What happened to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityVerdict {
    /// Written.
    Released,
    /// Withheld (blocked, or a confirmed original removed).
    Blocked,
    /// Withheld as uncertain.
    Uncertain,
    /// Outbox file refused for unresolved placeholders.
    Unresolved,
}

/// One activity record, front door `mirror`; the daemon adds the opaque
/// dataset label. `Debug` omits the dataset id (a slug).
#[derive(Clone, PartialEq, Eq)]
pub struct Activity {
    /// Dataset id (the daemon replaces it with the opaque label).
    pub dataset: String,
    /// Direction.
    pub direction: ActivityDirection,
    /// Verdict.
    pub verdict: ActivityVerdict,
    /// Kinds with counts.
    pub kinds: Vec<(EntityKind, u32)>,
    /// A known original was found in clear.
    pub tripwire: bool,
    /// Bytes written or inspected.
    pub bytes: u64,
}

impl std::fmt::Debug for Activity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Activity")
            .field("direction", &self.direction)
            .field("verdict", &self.verdict)
            .field("kinds", &self.kinds.len())
            .field("tripwire", &self.tripwire)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

/// Manifest sides (spec §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    /// Source files.
    Source,
    /// Directory components.
    Dir,
    /// Outbox files.
    Outbox,
}

impl Side {
    /// The vault's side string.
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Source => "source",
            Side::Dir => "dir",
            Side::Outbox => "outbox",
        }
    }
}

/// The engine, through the daemon's service module.
pub trait MirrorEngine: Send + Sync + 'static {
    /// Sanitize free-text blocks in one batch (`sanitize_blocks`).
    fn sanitize(&self, dataset: &str, blocks: Vec<String>) -> Result<Vec<Block>, EngineError>;
    /// Sanitize file-name stems (spec §4.3 rule 2).
    fn sanitize_names(&self, dataset: &str, stems: Vec<String>) -> Result<Vec<Block>, EngineError>;
    /// Restore every placeholder or fail with `Unresolved`.
    fn rehydrate_strict(
        &self,
        dataset: &str,
        blocks: Vec<String>,
    ) -> Result<Vec<String>, EngineError>;
    /// Known originals in clear, one entry per text (checked as written
    /// and spaced); `None` when that text is clean.
    fn known_in_clear(
        &self,
        dataset: &str,
        texts: &[String],
    ) -> Result<Vec<Option<EntityKind>>, EngineError>;
    /// The M4 §16.1 tripwire over model-written text: kind labels and counts.
    fn scan_clear(
        &self,
        dataset: &str,
        texts: &[String],
    ) -> Result<Vec<(String, u32)>, EngineError>;
    /// Epoch, entries generation, policy fingerprint.
    fn state(&self, dataset: &str) -> Result<DatasetState, EngineError>;
    /// Register the previous epoch's known originals in the current epoch
    /// through the normal mint path (fresh tokens), so known-entity
    /// detection survives a rotation (spec §7.3, amended 2026-10-04).
    /// Idempotent: an original already in the current epoch is a lookup.
    /// Returns how many originals it went through.
    fn carry_known(&self, dataset: &str) -> Result<u64, EngineError>;
    /// Append an activity record; best effort, never fails the caller.
    fn record(&self, activity: Activity);
}

/// The manifest, sealed in the vault.
pub trait ManifestStore: Send + Sync + 'static {
    /// Insert or replace a record.
    fn put(&self, dataset: &str, side: Side, rel: &[u8], record: &[u8]) -> Result<(), EngineError>;
    /// Delete a record.
    fn delete(&self, dataset: &str, side: Side, rel: &[u8]) -> Result<(), EngineError>;
    /// Every record of a side.
    fn list(&self, dataset: &str, side: Side) -> Result<Vec<Vec<u8>>, EngineError>;
    /// Delete every record of a dataset.
    fn clear(&self, dataset: &str) -> Result<(), EngineError>;
    /// Keyed MAC (`Vault::keyed_mac`).
    fn mac(&self, domain: &str, data: &[u8]) -> [u8; 32];
    /// Persist the source root's identity for a folder whose root could
    /// not be read when it was added (`Folder::root_id` was `None`, spec
    /// §9.1): the mirror adopted it before anything was mirrored. Also called
    /// once for a stored id without a generation, when the root's filesystem
    /// reports one: the daemon then adds the generation to the stored id. The
    /// daemon stores it in the folder's sealed config and passes it as
    /// `Folder::root_id` from the next start on. Until this succeeds, a
    /// restart cannot tell the mirrored root from whatever is at the path,
    /// so the mirror deletes nothing then (5c review I2).
    fn put_root_id(&self, dataset: &str, root_id: RootIdentity) -> Result<(), EngineError>;
}
