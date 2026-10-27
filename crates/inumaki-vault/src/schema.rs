//! SQLite schema (M3 spec §5.1, M4 spec §4) and the `meta` table.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::VaultError;

/// Version written to `meta.schema_version`. v4 is the egress journal
/// (plan 2b); v5 is plan 3's mailboxes and mail-handle store; v6 (plan 4a)
/// adds surface-form rows; v7 is M5's folder datasets and mirror manifest.
pub const SCHEMA_VERSION: u32 = 7;

/// The M4 tables, applied on top of v1 by [`migrate`] and included in a
/// fresh file by [`create`]. Later plans append further schema versions in
/// merge order.
pub const SCHEMA_V2: &str = "
CREATE TABLE upstreams (
  id                 INTEGER PRIMARY KEY,
  dataset_id         TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
  name               TEXT NOT NULL,
  kind               TEXT NOT NULL,
  command            TEXT,
  args               TEXT,
  cwd                TEXT,
  url                TEXT,
  env                TEXT,
  headers            TEXT,
  env_secret         TEXT,
  headers_secret     TEXT,
  content_policy     TEXT NOT NULL DEFAULT '{}',
  schema_fingerprint TEXT,
  enabled            INTEGER NOT NULL DEFAULT 1,
  created_at         INTEGER NOT NULL,
  UNIQUE (dataset_id, name)
);
CREATE TABLE gateway_tokens (
  id         INTEGER PRIMARY KEY,
  label      TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  last_used  INTEGER
);
";

/// v3 (M4 spec §16.4): activity records. `record` is the canonical JSON of
/// an [`crate::activity::ActivityRecord`] minus `id` and `at`; `dataset` is
/// the opaque label, never the slug; `prev`/`hash` chain the rows.
pub const SCHEMA_V3: &str = "
CREATE TABLE activity (
  seq     INTEGER PRIMARY KEY AUTOINCREMENT,
  id      TEXT NOT NULL UNIQUE,
  at      INTEGER NOT NULL,
  dataset TEXT NOT NULL,
  record  TEXT NOT NULL,
  prev    TEXT NOT NULL,
  hash    TEXT NOT NULL
);
CREATE INDEX activity_at ON activity(at);
CREATE INDEX activity_dataset ON activity(dataset, at);
";

/// v4 (M4 spec §16.3): the egress journal and the entity-listing columns.
/// `payload` is the released bytes sealed under AAD
/// `journal:<dataset id>:<record id>`; `released` repeats the activity
/// record's digest so a payload can be checked against its record.
/// `entries.created_at` is the mint time (backfilled from `last_used`),
/// `entries.uses` the store-level use count (mint plus database hits).
pub const SCHEMA_V4: &str = "
CREATE TABLE journal (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
  record_id  TEXT NOT NULL UNIQUE,
  at         INTEGER NOT NULL,
  released   TEXT NOT NULL,
  bytes      INTEGER NOT NULL,
  nonce      BLOB NOT NULL,
  payload    BLOB NOT NULL
);
CREATE INDEX journal_dataset_at ON journal(dataset_id, at);
ALTER TABLE entries ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE entries ADD COLUMN uses INTEGER NOT NULL DEFAULT 1;
UPDATE entries SET created_at = last_used WHERE created_at = 0;
";

/// v5 (M4 spec §4.4, §6.2): mailboxes and the encrypted mail-handle store.
/// `username`, `drafts_folder`, and `from_address` are sealed hex like
/// dataset names; `fingerprint` is an HMAC label of (host, port, username)
/// that scopes handles; `mail_handles.value` is the sealed JSON of the
/// folder, UIDVALIDITY, and UID; `key_hmac` and `folder_hmac` are lookup
/// keys over the same fields, so nothing about a folder is readable.
pub const SCHEMA_V5: &str = "
CREATE TABLE mailboxes (
  dataset_id      TEXT PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
  preset          TEXT NOT NULL,
  imap_host       TEXT NOT NULL,
  imap_port       INTEGER NOT NULL,
  imap_tls        INTEGER NOT NULL DEFAULT 1,
  username        TEXT NOT NULL,
  password_secret TEXT NOT NULL,
  drafts_folder   TEXT,
  from_address    TEXT,
  fingerprint     TEXT NOT NULL,
  created_at      INTEGER NOT NULL
);
CREATE TABLE mail_handles (
  handle      TEXT PRIMARY KEY,
  dataset_id  TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
  mailbox_fp  TEXT NOT NULL,
  kind        TEXT NOT NULL,
  key_hmac    BLOB NOT NULL,
  folder_hmac BLOB NOT NULL,
  nonce       BLOB NOT NULL,
  value       BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  last_used   INTEGER NOT NULL,
  UNIQUE (dataset_id, key_hmac)
);
CREATE INDEX mail_handles_folder ON mail_handles(dataset_id, folder_hmac);
CREATE INDEX mail_handles_used ON mail_handles(last_used);
";

/// v6 (plan 4a): surface-form rows. A row whose `surface_of` is set is a
/// surface form (another spelling, a bare part, an alias variant) of the
/// entity whose token it names, in the same epoch. Canonical rows are
/// unchanged.
pub const SCHEMA_V6: &str = "
ALTER TABLE entries ADD COLUMN surface_of TEXT;
CREATE INDEX entries_surface_of ON entries(surface_of);
";

/// v7 (M5 spec §7.1): folder datasets and the mirror manifest. `config` and
/// `record` are sealed JSON; `path_mac` is an index-key HMAC over
/// the domain `mirror:<side>:<dataset>` and the relative path bytes, so no
/// path is stored in clear.
pub const SCHEMA_V7: &str = "
CREATE TABLE folders (
  dataset_id TEXT PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
  nonce      BLOB NOT NULL,
  config     BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE mirror_files (
  dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
  side       TEXT NOT NULL,
  path_mac   BLOB NOT NULL,
  nonce      BLOB NOT NULL,
  record     BLOB NOT NULL,
  PRIMARY KEY (dataset_id, side, path_mac)
);
";

/// Tables and indexes for a fresh file. `auto_vacuum` must be set before this runs.
pub const SCHEMA: &str = "
CREATE TABLE datasets (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  profile       TEXT NOT NULL,
  rotation_days INTEGER NOT NULL DEFAULT 30,
  grace_days    INTEGER NOT NULL DEFAULT 7,
  created_at    INTEGER NOT NULL,
  kind          TEXT NOT NULL DEFAULT 'generic'
);
CREATE TABLE epochs (
  id          INTEGER PRIMARY KEY,
  dataset_id  TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
  started_at  INTEGER NOT NULL,
  closed_at   INTEGER,
  expires_at  INTEGER
);
CREATE INDEX epochs_dataset ON epochs(dataset_id, closed_at);
CREATE TABLE entries (
  epoch_id    INTEGER NOT NULL REFERENCES epochs(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  key_hmac    BLOB NOT NULL,
  token       TEXT NOT NULL,
  nonce       BLOB NOT NULL,
  value       BLOB NOT NULL,
  removed     INTEGER NOT NULL DEFAULT 0,
  last_used   INTEGER NOT NULL,
  PRIMARY KEY (epoch_id, kind, key_hmac)
);
CREATE UNIQUE INDEX entries_token ON entries(token);
CREATE INDEX entries_epoch_used ON entries(epoch_id, last_used);
CREATE TABLE secrets (
  name  TEXT PRIMARY KEY,
  nonce BLOB NOT NULL,
  value BLOB NOT NULL
);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

/// v1 → v2: the dataset `kind` column plus the two new tables.
const MIGRATE_1_TO_2: &str = "
ALTER TABLE datasets ADD COLUMN kind TEXT NOT NULL DEFAULT 'generic';
";

/// Create every table on a fresh database and record the schema version.
pub fn create(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(SCHEMA)?;
    conn.execute_batch(SCHEMA_V2)?;
    conn.execute_batch(SCHEMA_V3)?;
    conn.execute_batch(SCHEMA_V4)?;
    conn.execute_batch(SCHEMA_V5)?;
    conn.execute_batch(SCHEMA_V6)?;
    conn.execute_batch(SCHEMA_V7)?;
    meta_set(conn, "schema_version", &SCHEMA_VERSION.to_string())?;
    Ok(())
}

/// Bring a file at version `from` up to [`SCHEMA_VERSION`], one version per
/// transaction, so a crash mid-way leaves a consistent older file.
pub fn migrate(conn: &mut Connection, from: u32) -> Result<(), VaultError> {
    let mut version = from;
    while version < SCHEMA_VERSION {
        let tx = conn.transaction()?;
        match version {
            1 => {
                tx.execute_batch(MIGRATE_1_TO_2)?;
                tx.execute_batch(SCHEMA_V2)?;
            }
            2 => tx.execute_batch(SCHEMA_V3)?,
            3 => tx.execute_batch(SCHEMA_V4)?,
            4 => tx.execute_batch(SCHEMA_V5)?,
            5 => tx.execute_batch(SCHEMA_V6)?,
            6 => tx.execute_batch(SCHEMA_V7)?,
            other => {
                return Err(VaultError::Sqlite(format!(
                    "no migration from schema version {other}"
                )));
            }
        }
        version += 1;
        meta_set(&tx, "schema_version", &version.to_string())?;
        tx.commit()?;
        tracing::info!(from = version - 1, to = version, "vault schema migrated");
    }
    Ok(())
}

/// `meta.schema_version` of an existing database.
pub fn version(conn: &Connection) -> Result<u32, VaultError> {
    let v = meta_get(conn, "schema_version")?
        .ok_or_else(|| VaultError::Sqlite("meta.schema_version missing".into()))?;
    v.parse()
        .map_err(|_| VaultError::Sqlite("meta.schema_version is not a number".into()))
}

/// Read a `meta` value.
pub fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>, VaultError> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .optional()?)
}

/// Insert or replace a `meta` value.
pub fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<(), VaultError> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}
