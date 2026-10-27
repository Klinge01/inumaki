//! Vault errors. Variants carry ids, paths, key names, and SQLite messages,
//! never originals, normalized keys, or key material.

/// Errors produced by the vault.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// SQLite reported an error. The message is SQLite's own (constraint
    /// names, table names); bound values never appear in it.
    #[error("sqlite: {0}")]
    Sqlite(String),
    /// A file operation failed.
    #[error("io error at {path}: {kind:?}")]
    Io {
        /// Path involved.
        path: String,
        /// Error kind.
        kind: std::io::ErrorKind,
    },
    /// The file was written by a newer inumaki.
    #[error("vault schema version {found} is newer than this binary supports ({supported})")]
    SchemaNewer {
        /// Version found in `meta`.
        found: u32,
        /// Version this binary writes.
        supported: u32,
    },
    /// `meta.key_source` differs from the requested source.
    #[error(
        "vault keys were stored in {stored} but {requested} was requested; migrate the keys first"
    )]
    KeySourceChanged {
        /// Source recorded in the vault.
        stored: String,
        /// Source requested by configuration.
        requested: String,
    },
    /// The OS secret store failed or did not answer in time.
    #[error("secret store unavailable: {0}")]
    KeyStore(String),
    /// The key file is unusable.
    #[error("key file {path} is unusable: {reason}")]
    KeyFile {
        /// Key file path.
        path: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The loaded keys do not match the vault (`meta.key_check`).
    #[error("the loaded keys do not belong to this vault")]
    WrongKeys,
    /// The OS random generator failed.
    #[error("os randomness unavailable")]
    Random,
    /// Encryption failed (should not happen with valid keys).
    #[error("encryption failed")]
    Encrypt,
    /// A stored value failed authentication or decoding.
    #[error("decryption failed for a stored value")]
    Decrypt,
    /// Dataset ids are `[a-z0-9-]{1,64}`.
    #[error("dataset id must match [a-z0-9-]{{1,64}}")]
    InvalidDatasetId,
    /// No dataset with that id. The id is not in the message (M4 spec §5.4:
    /// dataset ids are user-chosen and must not reach logs via `%e`); the
    /// caller that already knows which id it asked for still gets it in the
    /// HTTP error body, not by `Display`.
    #[error("dataset not found")]
    DatasetNotFound(String),
    /// A dataset with that id exists. The id is not in the message (dataset
    /// ids are user-chosen and must not reach logs via `%e`, same rule as
    /// `DatasetNotFound`); the caller that already knows which id it asked
    /// for still gets it in the HTTP error body, not by `Display`.
    #[error("dataset already exists")]
    DatasetExists(String),
    /// A numeric setting is outside its range; carries the key name.
    #[error("value out of range: {0}")]
    OutOfRange(&'static str),
    /// Minting failed 8 times on the unique token index.
    #[error("token space exhausted for kind {0}")]
    TokenSpaceExhausted(String),
    /// The dataset or epoch this handle refers to no longer exists.
    #[error("namespace closed: its dataset or epoch is gone")]
    Closed,
    /// `surface_token` was given a token that is not a current-epoch entity
    /// of this namespace (unknown, removed, a closed epoch, or itself a
    /// surface form). The token is not in the message.
    #[error("surface token parent unknown")]
    UnknownParent,
    /// The known-entity automaton could not be built.
    #[error("known-entity automaton build failed")]
    Automaton,
    /// Secret names are `[a-z0-9][a-z0-9/_.-]{0,127}`.
    #[error("secret name must match [a-z0-9][a-z0-9/_.-]{{0,127}}")]
    InvalidSecretName,
    /// Gateway token labels are 1 to 64 printable characters.
    #[error("token label must be 1 to 64 printable characters")]
    InvalidLabel,
    /// Upstream names are `[a-z0-9_-]{1,64}`.
    #[error("upstream name must match [a-z0-9_-]{{1,64}}")]
    InvalidUpstreamName,
    /// An upstream field is missing or malformed; carries the field name.
    #[error("upstream field {0} is missing or invalid")]
    InvalidUpstream(&'static str),
    /// An upstream with that name exists in the dataset.
    #[error("upstream {0} already exists")]
    UpstreamExists(String),
    /// No upstream with that name in the dataset.
    #[error("upstream {0} not found")]
    UpstreamNotFound(String),
    /// No gateway token with that id.
    #[error("gateway token {0} not found")]
    GatewayTokenNotFound(i64),
    /// The activity chain does not verify from this row on (an edit, a
    /// deleted middle row, or a torn write).
    #[error("activity chain broken at row {0}")]
    ActivityChain(i64),
    /// A stored activity row failed validation on load.
    #[error("activity record failed validation")]
    ActivityRecord,
    /// A journal row failed to open: the payload did not authenticate under
    /// its dataset and record id, or its digest does not match the activity
    /// record's, or a stored id has the wrong shape. Carries the row's
    /// `seq` (0 when no row is involved), never any content.
    #[error("journal entry failed validation (row {0})")]
    JournalRecord(i64),
    /// No entity with that token or value in the dataset. Neither is in the
    /// message.
    #[error("entity not found")]
    EntityNotFound,
    /// `PRAGMA wal_checkpoint(TRUNCATE)` stayed busy after repeated retries:
    /// another connection's read snapshot is blocking it, so a pre-delete
    /// page image may still be in the WAL. Never carries a value.
    #[error("wal checkpoint stayed busy")]
    CheckpointBusy,
    /// A mailbox field is missing or malformed; carries the field name.
    #[error("mailbox field {0} is missing or invalid")]
    InvalidMailbox(&'static str),
    /// The dataset has no mailbox.
    #[error("mailbox not configured")]
    MailboxNotFound,
    /// The dataset already has a folder (M5 spec §12.2).
    #[error("a folder is already connected")]
    FolderExists,
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        VaultError::Sqlite(e.to_string())
    }
}

/// `Io` from a path and an `io::Error`.
pub(crate) fn io_err(path: &std::path::Path, e: &std::io::Error) -> VaultError {
    VaultError::Io {
        path: path.display().to_string(),
        kind: e.kind(),
    }
}
