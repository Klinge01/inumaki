//! The egress journal (M4 spec §16.3): for every released gateway result,
//! the payload exactly as released, sealed with the vault key under AAD
//! `journal:<dataset id>:<record id>` and linked to its activity record by
//! id and digest. It holds tokens, never originals; it is read over the
//! control socket only. The gateway's writer thread appends through a
//! [`JournalWriter`], which has its own SQLite connection: a multi-megabyte
//! INSERT never holds the shared connection's mutex that the request path
//! (`lookup_db`, `mint`) takes. SQLite still serializes writers at the WAL
//! level, so a mint that coincides with a journal INSERT waits for that one
//! INSERT (tens of milliseconds for 5 MB), bounded by `busy_timeout`;
//! readers and working-set hits are never blocked. Swept by retention and
//! by a per-dataset byte budget, oldest first, in small batches.

use std::sync::Arc;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::activity::{Digest, RecordId, released_digest_with};
use crate::error::VaultError;
use crate::namespace::is_fk_violation;
use crate::vault::{Vault, VaultInner};

/// One journal entry's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// The activity record this payload belongs to.
    pub id: RecordId,
    /// Unix seconds (the activity record's time).
    pub at: i64,
    /// Payload length.
    pub bytes: u64,
    /// The activity record's keyed digest of the payload.
    pub released: Digest,
}

/// What [`Vault::sweep_journal`] deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JournalSweep {
    /// Entries older than the retention window.
    pub expired: usize,
    /// Entries removed, oldest first, to bring a dataset under its budget.
    pub over_budget: usize,
}

/// Rows deleted per statement by the sweep, so the shared connection is
/// released between batches (the same idea as `Vault::sweep`).
const SWEEP_BATCH: usize = 8;

fn aad(dataset_id: &str, record: &RecordId) -> Vec<u8> {
    format!("journal:{dataset_id}:{}", record.as_str()).into_bytes()
}

/// Seal and insert on `conn`. Shared by the vault handle and the writer.
fn append_on(
    conn: &Connection,
    inner: &VaultInner,
    dataset_id: &str,
    record: &RecordId,
    at: i64,
    released: &Digest,
    payload: &[u8],
) -> Result<(), VaultError> {
    if released_digest_with(&inner.indexer, payload) != *released {
        return Err(VaultError::JournalRecord(0));
    }
    let sealed = inner.cipher.seal(&aad(dataset_id, record), payload)?;
    let r = conn.execute(
        "INSERT INTO journal (dataset_id, record_id, at, released, bytes, nonce, payload) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![dataset_id, record.as_str(), at, released.as_str(), payload.len() as i64, sealed.nonce, sealed.value],
    );
    match r {
        Ok(_) => {}
        Err(e) if is_fk_violation(&e) => {
            return Err(VaultError::DatasetNotFound(dataset_id.to_string()));
        }
        Err(e) => return Err(e.into()),
    }
    tracing::debug!(dataset = %inner.opaque(dataset_id), bytes = payload.len(), "journal entry written");
    Ok(())
}

/// A journal appender with its own SQLite connection (same file, same
/// pragmas), for the gateway's writer thread. Not `Clone`; one per writer.
pub struct JournalWriter {
    conn: Connection,
    inner: Arc<VaultInner>,
}

impl std::fmt::Debug for JournalWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JournalWriter")
    }
}

impl JournalWriter {
    /// Store a released payload for `record`; same contract as
    /// [`Vault::append_journal`], on this writer's connection.
    pub fn append(
        &self,
        dataset_id: &str,
        record: &RecordId,
        at: i64,
        released: &Digest,
        payload: &[u8],
    ) -> Result<(), VaultError> {
        append_on(
            &self.conn,
            &self.inner,
            dataset_id,
            record,
            at,
            released,
            payload,
        )
    }
}

impl Vault {
    /// A second connection to the same file for journal writes off the
    /// shared connection. Opened with the vault's pragmas (WAL is a file
    /// property and already set).
    pub fn journal_writer(&self) -> Result<JournalWriter, VaultError> {
        let conn = Connection::open(&self.inner.path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA synchronous = NORMAL; PRAGMA secure_delete = ON; PRAGMA foreign_keys = ON;",
        )?;
        Ok(JournalWriter {
            conn,
            inner: Arc::clone(&self.inner),
        })
    }

    /// Store a released payload for `record` on the shared connection
    /// (tests and the control path). `released` must be the record's digest
    /// of exactly these bytes, else `JournalRecord(0)`.
    pub fn append_journal(
        &self,
        dataset_id: &str,
        record: &RecordId,
        at: i64,
        released: &Digest,
        payload: &[u8],
    ) -> Result<(), VaultError> {
        let conn = self.inner.lock();
        append_on(
            &conn,
            &self.inner,
            dataset_id,
            record,
            at,
            released,
            payload,
        )
    }

    /// Entries of a dataset, newest first, at or after `since`; `limit` 0
    /// means 100. A stored id or digest of the wrong shape fails the query
    /// with that row's `seq` in the error (fail closed, no content).
    pub fn journal(
        &self,
        dataset_id: &str,
        since: Option<i64>,
        limit: usize,
    ) -> Result<Vec<JournalEntry>, VaultError> {
        self.dataset_profile(dataset_id)?;
        let limit = if limit == 0 { 100 } else { limit.min(10_000) } as i64;
        let rows: Vec<(i64, String, i64, i64, String)> = {
            let conn = self.inner.lock();
            let mut stmt = conn.prepare(
                "SELECT seq, record_id, at, bytes, released FROM journal \
                 WHERE dataset_id = ?1 AND (?2 IS NULL OR at >= ?2) ORDER BY seq DESC LIMIT ?3",
            )?;
            let rows = stmt.query_map(params![dataset_id, since, limit], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        rows.into_iter()
            .map(|(seq, id, at, bytes, released)| {
                Ok(JournalEntry {
                    id: RecordId::try_from(id).map_err(|_| VaultError::JournalRecord(seq))?,
                    at,
                    bytes: u64::try_from(bytes).unwrap_or(0),
                    released: Digest::try_from(released)
                        .map_err(|_| VaultError::JournalRecord(seq))?,
                })
            })
            .collect()
    }

    /// One entry with its payload opened and checked against its digest.
    /// `Ok(None)` when the dataset has no such entry. Fails closed: a
    /// column-type error reading `nonce` or `payload` for a row whose `seq`
    /// was already read maps to `JournalRecord(seq)` rather than a generic
    /// SQLite error.
    #[allow(clippy::type_complexity)]
    pub fn journal_payload(
        &self,
        dataset_id: &str,
        record: &RecordId,
    ) -> Result<Option<(JournalEntry, Zeroizing<Vec<u8>>)>, VaultError> {
        self.dataset_profile(dataset_id)?;
        let head: Option<(i64, i64, i64, String)> = {
            let conn = self.inner.lock();
            conn.query_row(
                "SELECT seq, at, bytes, released FROM journal WHERE dataset_id = ?1 AND record_id = ?2",
                params![dataset_id, record.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
        };
        let Some((seq, at, bytes, released)) = head else {
            return Ok(None);
        };
        let (nonce, value): (Vec<u8>, Vec<u8>) = {
            let conn = self.inner.lock();
            conn.query_row(
                "SELECT nonce, payload FROM journal WHERE seq = ?1",
                params![seq],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| VaultError::JournalRecord(seq))?
        };
        let payload = self
            .inner
            .cipher
            .open(&aad(dataset_id, record), &nonce, &value)
            .map_err(|_| VaultError::JournalRecord(seq))?;
        let released = Digest::try_from(released).map_err(|_| VaultError::JournalRecord(seq))?;
        if self.released_digest(&payload) != released {
            return Err(VaultError::JournalRecord(seq));
        }
        Ok(Some((
            JournalEntry {
                id: record.clone(),
                at,
                bytes: u64::try_from(bytes).unwrap_or(0),
                released,
            },
            payload,
        )))
    }

    /// Delete entries older than `retention_secs`, then, per dataset over
    /// `max_bytes`, the oldest entries until the newest ones fit. Deletes
    /// [`SWEEP_BATCH`] rows per statement and releases the shared
    /// connection in between, so `secure_delete` over megabytes of payload
    /// never stalls a request for long.
    pub fn sweep_journal(
        &self,
        retention_secs: i64,
        max_bytes: u64,
    ) -> Result<JournalSweep, VaultError> {
        let cutoff = self.inner.now() - retention_secs;
        let budget = i64::try_from(max_bytes).unwrap_or(i64::MAX);
        let batch = SWEEP_BATCH as i64;
        let mut expired = 0usize;
        loop {
            let conn = self.inner.lock();
            let n = conn.execute(
                "DELETE FROM journal WHERE seq IN (SELECT seq FROM journal WHERE at < ?1 ORDER BY seq LIMIT ?2)",
                params![cutoff, batch],
            )?;
            if n == 0 {
                break;
            }
            expired += n;
        }
        let over: Vec<(String, Option<i64>)> = {
            let conn = self.inner.lock();
            let mut stmt = conn.prepare(
                "SELECT dataset_id FROM journal GROUP BY dataset_id HAVING sum(bytes) > ?1",
            )?;
            let ids = stmt
                .query_map(params![budget], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                // Running total from the newest entry down; every entry at or
                // beyond the one that crosses the budget goes.
                let bound: Option<i64> = conn
                    .query_row(
                        "SELECT max(seq) FROM (\
                           SELECT seq, sum(bytes) OVER (ORDER BY seq DESC ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS running \
                           FROM journal WHERE dataset_id = ?1\
                         ) WHERE running > ?2",
                        params![id, budget],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten();
                out.push((id, bound));
            }
            out
        };
        let mut over_budget = 0usize;
        for (id, bound) in over {
            let Some(bound) = bound else { continue };
            loop {
                let conn = self.inner.lock();
                let n = conn.execute(
                    "DELETE FROM journal WHERE seq IN (SELECT seq FROM journal WHERE dataset_id = ?1 AND seq <= ?2 ORDER BY seq LIMIT ?3)",
                    params![id, bound, batch],
                )?;
                if n == 0 {
                    break;
                }
                over_budget += n;
            }
        }
        if expired + over_budget > 0 {
            tracing::info!(expired, over_budget, "journal sweep");
        }
        Ok(JournalSweep {
            expired,
            over_budget,
        })
    }
}
