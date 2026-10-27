//! The vault handle: one SQLite connection, keys, datasets.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use inumaki_core::TokenSettings;
use inumaki_core::alias::AliasTable;
use rusqlite::{Connection, OptionalExtension, params};

use crate::clock::{Clock, SystemClock};
use crate::crypto::{Cipher, Indexer, hex, unhex};
use crate::error::{VaultError, io_err};
use crate::keys::{KEYRING_TIMEOUT, KeySource, KeyStore, OsKeyring, load_or_create};
use crate::schema::{self, SCHEMA_VERSION, meta_get, meta_set};

/// Value hashed with the index key and stored in `meta.key_check` so a
/// wrong key file or keyring entry is detected at open.
const KEY_CHECK_INPUT: &[u8] = b"inumaki-vault-key-check-v1";

/// How to open a vault.
#[derive(Clone)]
pub struct VaultOptions {
    /// SQLite file.
    pub path: PathBuf,
    /// Directory holding the key file (and by convention the SQLite file).
    pub data_dir: PathBuf,
    /// Where keys live.
    pub key_source: KeySource,
    /// Secret store to use instead of the OS keyring (tests).
    pub key_store: Option<Arc<dyn KeyStore>>,
    /// Token format for namespaces; `suffix_len` is 6 by default.
    pub tokens: TokenSettings,
    /// Cap on known-entity automaton entries per namespace.
    pub automaton_max_entries: usize,
    /// How long to wait for the OS secret store.
    pub keyring_timeout: Duration,
    /// Alias groups the known-entity detector expands stored originals
    /// through (M4 spec §16.5).
    pub aliases: Arc<AliasTable>,
}

impl std::fmt::Debug for VaultOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultOptions")
            .field("path", &self.path)
            .field("key_source", &self.key_source)
            .field("suffix_len", &self.tokens.suffix_len)
            .field("automaton_max_entries", &self.automaton_max_entries)
            .field("alias_groups", &self.aliases.len())
            .finish()
    }
}

impl VaultOptions {
    /// Defaults for `data_dir`: `vault.sqlite` inside it, `Auto` keys,
    /// suffix length 6, 200 000 automaton entries, [`KEYRING_TIMEOUT`].
    pub fn in_dir(data_dir: &Path) -> Self {
        VaultOptions {
            path: data_dir.join("vault.sqlite"),
            data_dir: data_dir.to_path_buf(),
            key_source: KeySource::Auto,
            key_store: None,
            tokens: TokenSettings {
                suffix_len: 6,
                ..TokenSettings::default()
            },
            automaton_max_entries: 200_000,
            keyring_timeout: KEYRING_TIMEOUT,
            aliases: Arc::new(AliasTable::empty()),
        }
    }

    /// Set the key source.
    #[must_use]
    pub fn with_key_source(mut self, source: KeySource) -> Self {
        self.key_source = source;
        self
    }

    /// Use a custom secret store.
    #[must_use]
    pub fn with_key_store(mut self, store: Arc<dyn KeyStore>) -> Self {
        self.key_store = Some(store);
        self
    }

    /// Use these alias groups.
    #[must_use]
    pub fn with_aliases(mut self, aliases: Arc<AliasTable>) -> Self {
        self.aliases = aliases;
        self
    }
}

/// Shared state behind every `Vault` and `Namespace` handle.
pub(crate) struct VaultInner {
    /// The SQLite file's path (plan 2b's [`crate::journal::JournalWriter`]
    /// opens a second connection to it).
    pub(crate) path: PathBuf,
    pub(crate) conn: Mutex<Connection>,
    pub(crate) cipher: Cipher,
    pub(crate) indexer: Indexer,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) tokens: TokenSettings,
    /// Bumped on every rotation and deletion; namespaces compare it to
    /// notice that their epoch changed.
    pub(crate) rotation_gen: AtomicU64,
    /// Per-dataset count of writes to `entries` (mint, removed marker,
    /// forget) since open; the mirror's tripwire pass polls it (M5 spec
    /// §7.4). In memory only: a restart runs a full pass anyway.
    pub(crate) entries_gen: Mutex<std::collections::HashMap<String, u64>>,
    /// Cap on the known-entity automaton's entry count (`[vault]
    /// automaton_max_entries`).
    pub(crate) automaton_max: usize,
    key_source: &'static str,
    /// Alias groups the known-entity detector expands stored originals
    /// through (M4 spec §16.5).
    pub(crate) aliases: Arc<AliasTable>,
}

impl VaultInner {
    /// The connection; a poisoned lock is recovered (SQLite holds no
    /// cross-statement state outside explicit transactions).
    pub(crate) fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn now(&self) -> i64 {
        self.clock.now()
    }

    pub(crate) fn generation(&self) -> u64 {
        self.rotation_gen.load(Ordering::Acquire)
    }

    pub(crate) fn bump_generation(&self) {
        self.rotation_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Called after a committed mint, removed marker, or forget. The expiry
    /// sweep does not call it: it only deletes entries of closed epochs,
    /// which no namespace reads or writes and the mirror's current-epoch
    /// known-entity set does not contain, so no output the mirror made can
    /// go stale through it. A dataset delete removes the dataset's folder
    /// and manifest with it.
    pub(crate) fn bump_entries(&self, dataset_id: &str) {
        let mut m = self
            .entries_gen
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *m.entry(dataset_id.to_string()).or_insert(0) += 1;
    }

    /// Stable, non-invertible log label for a dataset id: 8 bytes of the
    /// index-key HMAC over `log:<id>`, hex. Dataset ids are user-chosen
    /// (`mail-mueller-gmbh`) and so are configuration data, not log fields
    /// (M4 spec §5.4); an operator correlates log lines with
    /// `inumaki status`, which prints both.
    pub(crate) fn opaque(&self, id: &str) -> String {
        let mac = self.indexer.mac(format!("log:{id}").as_bytes());
        hex(&mac[..8])
    }
}

/// Handle to an open vault. Cheap to clone.
#[derive(Clone)]
pub struct Vault {
    pub(crate) inner: Arc<VaultInner>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("key_source", &self.inner.key_source)
            .finish()
    }
}

/// True for `[a-z0-9-]{1,64}`.
pub fn valid_dataset_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// What a dataset is connected to (M4 spec §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetKind {
    /// Wrapped MCP servers only.
    Generic,
    /// Mail tools plus optional wrapped servers (plan 3).
    Mailbox,
    /// The proxy's reserved chat dataset (M8).
    Chat,
    /// A connected folder mirrored by `inumaki-mirror` (M5).
    Folder,
}

/// Id of the proxy's reserved chat dataset (M8 spec §9).
pub const CHAT_DATASET: &str = "inumaki-chat";

/// Dataset ids starting with this are reserved for the daemon (M8 spec §9).
pub const RESERVED_PREFIX: &str = "inumaki-";

impl DatasetKind {
    /// The stored string.
    pub fn as_str(self) -> &'static str {
        match self {
            DatasetKind::Generic => "generic",
            DatasetKind::Mailbox => "mailbox",
            DatasetKind::Chat => "chat",
            DatasetKind::Folder => "folder",
        }
    }

    /// Parse the stored or API string (exact, lower case).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "generic" => Some(DatasetKind::Generic),
            "mailbox" => Some(DatasetKind::Mailbox),
            "chat" => Some(DatasetKind::Chat),
            "folder" => Some(DatasetKind::Folder),
            _ => None,
        }
    }
}

/// How to create a dataset.
#[derive(Clone)]
pub struct DatasetSpec {
    /// Slug, `[a-z0-9-]{1,64}`.
    pub id: String,
    /// Display name; stored encrypted.
    pub name: String,
    /// Engine profile name.
    pub profile: String,
    /// Epoch length in days, `1..=365`.
    pub rotation_days: u32,
    /// Days a closed epoch stays readable, `0..=90`.
    pub grace_days: u32,
    /// Dataset kind; `Generic` unless set.
    pub kind: DatasetKind,
}

impl std::fmt::Debug for DatasetSpec {
    /// Omits the display name (review M1: it can be a customer name).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatasetSpec")
            .field("id", &self.id)
            .field("profile", &self.profile)
            .field("rotation_days", &self.rotation_days)
            .field("grace_days", &self.grace_days)
            .field("kind", &self.kind)
            .finish()
    }
}

impl DatasetSpec {
    /// Spec with the default rotation (30 days) and grace (7 days).
    pub fn new(id: &str, name: &str, profile: &str) -> Self {
        DatasetSpec {
            id: id.to_string(),
            name: name.to_string(),
            profile: profile.to_string(),
            rotation_days: 30,
            grace_days: 7,
            kind: DatasetKind::Generic,
        }
    }
}

/// A dataset with its current epoch.
#[derive(Clone, PartialEq, Eq)]
pub struct Dataset {
    /// Slug.
    pub id: String,
    /// Display name (decrypted).
    pub name: String,
    /// Engine profile name.
    pub profile: String,
    /// Epoch length in days.
    pub rotation_days: u32,
    /// Grace period in days.
    pub grace_days: u32,
    /// Creation time, unix seconds.
    pub created_at: i64,
    /// Current epoch row id.
    pub epoch_id: i64,
    /// Current epoch start, unix seconds.
    pub epoch_started_at: i64,
    /// Tokenized entities in the current epoch (removed values and surface
    /// forms excluded: a bare first name is a spelling of its entity, not a
    /// second one).
    pub entries: u64,
    /// Dataset kind.
    pub kind: DatasetKind,
}

impl std::fmt::Debug for Dataset {
    /// Omits the display name (it can be a customer name).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dataset")
            .field("id", &self.id)
            .field("profile", &self.profile)
            .field("epoch_id", &self.epoch_id)
            .field("entries", &self.entries)
            .field("kind", &self.kind)
            .finish()
    }
}

fn name_aad(id: &str) -> Vec<u8> {
    format!("dataset:{id}").into_bytes()
}

/// `nonce || ciphertext` of `plain` under `aad`, hex-encoded, as the dataset
/// name is stored; mailbox identities (plan 3) are sealed the same way.
pub(crate) fn seal_hex(inner: &VaultInner, aad: &[u8], plain: &str) -> Result<String, VaultError> {
    let sealed = inner.cipher.seal(aad, plain.as_bytes())?;
    let mut blob = sealed.nonce;
    blob.extend_from_slice(&sealed.value);
    Ok(hex(&blob))
}

/// Inverse of [`seal_hex`]; `Decrypt` on any malformed input.
pub(crate) fn open_hex(
    inner: &VaultInner,
    aad: &[u8],
    stored: &str,
) -> Result<zeroize::Zeroizing<String>, VaultError> {
    let b = unhex(stored)
        .filter(|b| b.len() > crate::crypto::NONCE_LEN)
        .ok_or(VaultError::Decrypt)?;
    inner.cipher.open_str(
        aad,
        &b[..crate::crypto::NONCE_LEN],
        &b[crate::crypto::NONCE_LEN..],
    )
}

const DATASET_SELECT: &str = "
SELECT d.id, d.name, d.profile, d.rotation_days, d.grace_days, d.created_at,
       e.id, e.started_at,
       (SELECT count(*) FROM entries x WHERE x.epoch_id = e.id AND x.removed = 0 AND x.surface_of IS NULL),
       d.kind
FROM datasets d
JOIN epochs e ON e.dataset_id = d.id AND e.closed_at IS NULL";

impl Vault {
    /// Open (or create) the vault with the system clock.
    pub fn open(opts: VaultOptions) -> Result<Vault, VaultError> {
        Self::open_with_clock(opts, Arc::new(SystemClock))
    }

    /// Open (or create) the vault with an injected clock.
    pub fn open_with_clock(opts: VaultOptions, clock: Arc<dyn Clock>) -> Result<Vault, VaultError> {
        if let Some(parent) = opts.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_err(parent, &e))?;
        }
        let mut conn = Connection::open(&opts.path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let is_new: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
            [],
            |r| r.get(0),
        )?;
        let is_new = is_new == 0;
        if is_new {
            conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
        }
        conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        conn.execute_batch(
            "PRAGMA synchronous = NORMAL; PRAGMA secure_delete = ON; PRAGMA foreign_keys = ON;",
        )?;
        let stored_source = if is_new {
            schema::create(&conn)?;
            None
        } else {
            let found = schema::version(&conn)?;
            if found > SCHEMA_VERSION {
                return Err(VaultError::SchemaNewer {
                    found,
                    supported: SCHEMA_VERSION,
                });
            }
            if found < SCHEMA_VERSION {
                schema::migrate(&mut conn, found)?;
            }
            meta_get(&conn, "key_source")?
        };
        // A random id, stored in `meta` (plaintext) and generated once,
        // names the keyring item instead of a hash of the data directory
        // path (review I5): moving or renaming the data directory, or
        // restoring `vault.sqlite` under a different path, then still finds
        // the same Keychain/Secret Service entry. A vault opened before
        // this existed (none outside tests) gets one lazily, here.
        let vault_id = match meta_get(&conn, "vault_id")? {
            Some(id) => id,
            None => {
                let mut raw = [0u8; 16];
                getrandom::fill(&mut raw).map_err(|_| VaultError::Random)?;
                let id = hex(&raw);
                meta_set(&conn, "vault_id", &id)?;
                id
            }
        };
        let os_store;
        let store: &dyn KeyStore = match &opts.key_store {
            Some(s) => s.as_ref(),
            None => {
                os_store = OsKeyring::new(&vault_id, opts.keyring_timeout);
                &os_store
            }
        };
        let loaded = load_or_create(
            &opts.data_dir,
            opts.key_source,
            stored_source.as_deref(),
            store,
        )?;
        let indexer = Indexer::new(&loaded.keys.index);
        let check = hex(&indexer.mac(KEY_CHECK_INPUT));
        match meta_get(&conn, "key_check")? {
            Some(stored) if stored != check => return Err(VaultError::WrongKeys),
            Some(_) => {}
            None => {
                meta_set(&conn, "key_source", loaded.source)?;
                meta_set(&conn, "key_check", &check)?;
            }
        }
        let cipher = Cipher::new(&loaded.keys.enc);
        tracing::info!(key_source = loaded.source, "vault opened");
        Ok(Vault {
            inner: Arc::new(VaultInner {
                path: opts.path.clone(),
                conn: Mutex::new(conn),
                cipher,
                indexer,
                clock,
                tokens: opts.tokens,
                rotation_gen: AtomicU64::new(0),
                entries_gen: Mutex::new(std::collections::HashMap::new()),
                automaton_max: opts.automaton_max_entries,
                key_source: loaded.source,
                aliases: opts.aliases,
            }),
        })
    }

    /// `"keyring"` or `"file"`.
    pub fn key_source(&self) -> &'static str {
        self.inner.key_source
    }

    /// Token format used by namespaces.
    pub fn tokens(&self) -> &TokenSettings {
        &self.inner.tokens
    }

    /// Stable, non-invertible log label for a dataset id; see
    /// [`VaultInner::opaque`].
    pub fn opaque_id(&self, dataset_id: &str) -> String {
        self.inner.opaque(dataset_id)
    }

    /// The alias groups this vault expands known entities through.
    pub fn aliases(&self) -> &AliasTable {
        &self.inner.aliases
    }

    /// Move WAL contents into the main file (tests; shutdown).
    pub fn checkpoint(&self) -> Result<(), VaultError> {
        let conn = self.inner.lock();
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }

    /// [`Vault::checkpoint`], but checked: `PRAGMA wal_checkpoint(TRUNCATE)`
    /// returns `(busy, log, checkpointed)`; `busy` is nonzero when another
    /// connection's read snapshot (a concurrent reader, the journal writer)
    /// blocked the TRUNCATE, in which case no pre-delete page is guaranteed
    /// purged from the WAL. Retries up to 5 times, 20 ms apart, before
    /// giving up with [`VaultError::CheckpointBusy`] (a fixed, value-free
    /// variant: which row was busy is never meaningful to a caller).
    /// `forget_by_token`/`forget_by_value`'s callers (`AppState::forget_entity`,
    /// plan 2b Task 5) use this instead of `checkpoint` so a busy checkpoint
    /// is reported rather than silently ignored.
    pub fn checkpoint_truncate(&self) -> Result<(), VaultError> {
        for _ in 0..5 {
            let busy: i64 = {
                let conn = self.inner.lock();
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?
            };
            if busy == 0 {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err(VaultError::CheckpointBusy)
    }

    /// `PRAGMA integrity_check` returned `ok`.
    pub fn integrity_ok(&self) -> Result<bool, VaultError> {
        let conn = self.inner.lock();
        let r: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        Ok(r == "ok")
    }

    /// Create a dataset with its first epoch.
    pub fn create_dataset(&self, spec: &DatasetSpec) -> Result<Dataset, VaultError> {
        if !valid_dataset_id(&spec.id) {
            return Err(VaultError::InvalidDatasetId);
        }
        if !(1..=365).contains(&spec.rotation_days) {
            return Err(VaultError::OutOfRange("rotation_days"));
        }
        if spec.grace_days > 90 {
            return Err(VaultError::OutOfRange("grace_days"));
        }
        let sealed = self
            .inner
            .cipher
            .seal(&name_aad(&spec.id), spec.name.as_bytes())?;
        let mut blob = sealed.nonce.clone();
        blob.extend_from_slice(&sealed.value);
        let now = self.inner.now();
        let mut conn = self.inner.lock();
        let tx = conn.transaction()?;
        let r = tx.execute(
            "INSERT INTO datasets (id, name, profile, rotation_days, grace_days, created_at, kind) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![spec.id, hex(&blob), spec.profile, spec.rotation_days, spec.grace_days, now, spec.kind.as_str()],
        );
        match r {
            Ok(_) => {}
            Err(e) if is_constraint(&e, "datasets.id") => {
                return Err(VaultError::DatasetExists(spec.id.clone()));
            }
            Err(e) => return Err(e.into()),
        }
        tx.execute(
            "INSERT INTO epochs (dataset_id, started_at) VALUES (?1, ?2)",
            params![spec.id, now],
        )?;
        tx.commit()?;
        drop(conn);
        tracing::info!(dataset = %self.inner.opaque(&spec.id), profile = %spec.profile, "dataset created");
        self.dataset(&spec.id)
    }

    fn row_to_dataset(&self, r: &rusqlite::Row<'_>) -> rusqlite::Result<Dataset> {
        let id: String = r.get(0)?;
        let name_hex: String = r.get(1)?;
        // A failed decrypt never surfaces the ciphertext or the id's name
        // (`VaultError::Decrypt`'s message is fixed), but it is worth a
        // `warn` naming the dataset so an operator can find it instead of
        // silently seeing `<unreadable>` (review M4).
        let name = match unhex(&name_hex).filter(|b| b.len() > crate::crypto::NONCE_LEN) {
            Some(b) => match self.inner.cipher.open_str(
                &name_aad(&id),
                &b[..crate::crypto::NONCE_LEN],
                &b[crate::crypto::NONCE_LEN..],
            ) {
                Ok(z) => z.to_string(),
                Err(e) => {
                    tracing::warn!(dataset = %self.inner.opaque(&id), error = %e, "dataset name failed to decrypt");
                    "<unreadable>".to_string()
                }
            },
            None => {
                tracing::warn!(dataset = %self.inner.opaque(&id), "dataset name blob is malformed");
                "<unreadable>".to_string()
            }
        };
        let kind_s: String = r.get(9)?;
        let kind = DatasetKind::parse(&kind_s).unwrap_or(DatasetKind::Generic);
        Ok(Dataset {
            id,
            name,
            profile: r.get(2)?,
            rotation_days: r.get(3)?,
            grace_days: r.get(4)?,
            created_at: r.get(5)?,
            epoch_id: r.get(6)?,
            epoch_started_at: r.get(7)?,
            entries: r.get::<_, i64>(8)?.max(0).unsigned_abs(),
            kind,
        })
    }

    /// Every dataset, ordered by id.
    pub fn datasets(&self) -> Result<Vec<Dataset>, VaultError> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(&format!("{DATASET_SELECT} ORDER BY d.id"))?;
        let rows = stmt.query_map([], |r| self.row_to_dataset(r))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// One dataset.
    pub fn dataset(&self, id: &str) -> Result<Dataset, VaultError> {
        let conn = self.inner.lock();
        conn.query_row(
            &format!("{DATASET_SELECT} WHERE d.id = ?1"),
            params![id],
            |r| self.row_to_dataset(r),
        )
        .optional()?
        .ok_or_else(|| VaultError::DatasetNotFound(id.to_string()))
    }

    /// The profile name only: one indexed lookup, no entry count. The
    /// request path uses this (review I4); `dataset` is for status and the
    /// dataset endpoints.
    pub fn dataset_profile(&self, id: &str) -> Result<String, VaultError> {
        let conn = self.inner.lock();
        conn.query_row(
            "SELECT profile FROM datasets WHERE id = ?1",
            params![id],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| VaultError::DatasetNotFound(id.to_string()))
    }

    /// Delete a dataset with all its epochs and entries.
    pub fn delete_dataset(&self, id: &str) -> Result<(), VaultError> {
        let changed = {
            let conn = self.inner.lock();
            conn.execute("DELETE FROM datasets WHERE id = ?1", params![id])?
        };
        if changed == 0 {
            return Err(VaultError::DatasetNotFound(id.to_string()));
        }
        self.inner.bump_generation();
        tracing::info!(dataset = %self.inner.opaque(id), "dataset deleted");
        Ok(())
    }
}

/// Result of [`Vault::rotate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    /// Dataset rotated.
    pub dataset_id: String,
    /// Epoch that was closed.
    pub old_epoch: i64,
    /// Epoch that is now current.
    pub new_epoch: i64,
    /// Start of the new epoch, unix seconds.
    pub started_at: i64,
}

/// What [`Vault::sweep`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Closed epochs past their grace period that were deleted.
    pub expired_epochs: usize,
    /// Entry rows deleted with them.
    pub entries_deleted: u64,
    /// Pages returned by `incremental_vacuum`.
    pub pages_freed: usize,
}

/// One epoch of a dataset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochInfo {
    /// Row id.
    pub id: i64,
    /// Start, unix seconds.
    pub started_at: i64,
    /// Close time; `None` for the current epoch.
    pub closed_at: Option<i64>,
    /// End of the grace period; `None` for the current epoch.
    pub expires_at: Option<i64>,
}

impl Vault {
    /// Close the current epoch (readable for `grace_days` more) and open a
    /// new one. Every entity gets a new token when next seen.
    pub fn rotate(&self, dataset_id: &str) -> Result<Rotation, VaultError> {
        let ds = self.dataset(dataset_id)?;
        let now = self.inner.now();
        let expires = now + i64::from(ds.grace_days) * 86_400;
        let new_epoch = {
            let mut conn = self.inner.lock();
            let tx = conn.transaction()?;
            let closed = tx.execute(
                "UPDATE epochs SET closed_at = ?1, expires_at = ?2 WHERE dataset_id = ?3 AND closed_at IS NULL",
                params![now, expires, dataset_id],
            )?;
            if closed == 0 {
                return Err(VaultError::DatasetNotFound(dataset_id.to_string()));
            }
            tx.execute(
                "INSERT INTO epochs (dataset_id, started_at) VALUES (?1, ?2)",
                params![dataset_id, now],
            )?;
            let id = tx.last_insert_rowid();
            tx.commit()?;
            id
        };
        self.inner.bump_generation();
        tracing::info!(dataset = %self.inner.opaque(dataset_id), old_epoch = ds.epoch_id, new_epoch, "epoch rotated");
        Ok(Rotation {
            dataset_id: dataset_id.to_string(),
            old_epoch: ds.epoch_id,
            new_epoch,
            started_at: now,
        })
    }

    /// Datasets whose current epoch is at least `rotation_days` old.
    pub fn due_for_rotation(&self) -> Result<Vec<String>, VaultError> {
        let now = self.inner.now();
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT d.id FROM datasets d JOIN epochs e ON e.dataset_id = d.id AND e.closed_at IS NULL \
             WHERE e.started_at + d.rotation_days * 86400 <= ?1 ORDER BY d.id",
        )?;
        let ids = stmt
            .query_map(params![now], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// Delete epochs past their grace period (entries cascade) and give
    /// freed pages back in steps of 256 (spec §15: never a full vacuum
    /// under a request).
    pub fn sweep(&self) -> Result<SweepReport, VaultError> {
        let now = self.inner.now();
        let conn = self.inner.lock();
        let entries: i64 = conn.query_row(
            "SELECT count(*) FROM entries WHERE epoch_id IN \
             (SELECT id FROM epochs WHERE expires_at IS NOT NULL AND expires_at <= ?1)",
            params![now],
            |r| r.get(0),
        )?;
        // Entries go first, 1 000 rows per statement with the lock released in
        // between, so a 200 000-row epoch under secure_delete never stalls a
        // request for seconds (review M2). The epoch rows follow (cascade then
        // finds nothing left). This count-then-delete is safe only because
        // every write path in namespace.rs (`mint`, `try_record_removed`)
        // calls `refresh()` first and so never targets an epoch once it is
        // closed: nothing can add rows to an epoch this sweep is about to
        // delete between the count above and the deletes below.
        drop(conn);
        loop {
            let conn = self.inner.lock();
            let n = conn.execute(
                "DELETE FROM entries WHERE rowid IN (SELECT e.rowid FROM entries e JOIN epochs p ON p.id = e.epoch_id \
                 WHERE p.expires_at IS NOT NULL AND p.expires_at <= ?1 LIMIT 1000)",
                params![now],
            )?;
            if n == 0 {
                break;
            }
        }
        let conn = self.inner.lock();
        let expired_epochs = conn.execute(
            "DELETE FROM epochs WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?;
        let mut pages_freed = 0usize;
        if expired_epochs > 0 {
            // `PRAGMA incremental_vacuum(N)` returns no rows; it only has the
            // side effect of moving up to N pages off the freelist and
            // truncating the file. `freelist_count` before and after is the
            // metric, not the (empty) result set of the vacuum statement.
            let before: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
            conn.execute_batch("PRAGMA incremental_vacuum(256)")?;
            let after: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
            pages_freed = freed_pages(before, after);
            tracing::info!(expired_epochs, entries = entries, pages_freed, "sweep");
        }
        Ok(SweepReport {
            expired_epochs,
            entries_deleted: u64::try_from(entries).unwrap_or(0),
            pages_freed,
        })
    }

    /// Epochs of a dataset, oldest first.
    pub fn epochs(&self, dataset_id: &str) -> Result<Vec<EpochInfo>, VaultError> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT id, started_at, closed_at, expires_at FROM epochs WHERE dataset_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![dataset_id], |r| {
            Ok(EpochInfo {
                id: r.get(0)?,
                started_at: r.get(1)?,
                closed_at: r.get(2)?,
                expires_at: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

/// Pages `PRAGMA incremental_vacuum` reclaimed: the drop in `freelist_count`
/// it left behind. Zero when the count did not fall (nothing to free, or a
/// vacuum step that made no progress), never negative.
fn freed_pages(before: i64, after: i64) -> usize {
    usize::try_from(before.saturating_sub(after)).unwrap_or(0)
}

/// True when `e` is a `UNIQUE`/`PRIMARY KEY` violation whose SQLite message
/// names `what` (e.g. `entries.token`).
pub(crate) fn is_constraint(e: &rusqlite::Error, what: &str) -> bool {
    match e {
        rusqlite::Error::SqliteFailure(f, Some(msg)) => {
            (f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                || f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
                && msg.contains(what)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::freed_pages;

    #[test]
    fn freed_pages_is_the_drop_in_freelist_count() {
        assert_eq!(
            freed_pages(300, 44),
            256,
            "vacuum freed a full 256-page step"
        );
        assert_eq!(freed_pages(10, 10), 0, "nothing changed");
    }

    #[test]
    fn freed_pages_never_goes_negative() {
        // The freelist can only shrink from a vacuum; a defensive floor at 0
        // covers a freelist that (unexpectedly) grew between reads.
        assert_eq!(freed_pages(10, 20), 0);
    }
}
