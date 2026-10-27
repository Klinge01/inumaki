//! Which dataset owns a token (M8 spec §5.3). Tokens are unique across all
//! namespaces and epochs (unique index `entries_token`), so one indexed
//! read answers it. Only live epochs count: current, or closed and still
//! inside their grace period.

use rusqlite::{OptionalExtension, params};

use crate::error::VaultError;
use crate::vault::{DatasetKind, Vault};

/// A dataset's id, kind, and creation time: what the proxy needs per
/// request, without the entry counts [`Vault::datasets`] computes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetHead {
    /// Slug.
    pub id: String,
    /// Kind.
    pub kind: DatasetKind,
    /// Creation time, unix seconds.
    pub created_at: i64,
}

impl Vault {
    /// The dataset id owning `token` in a live epoch, or `None`.
    pub fn dataset_of_token(&self, token: &str) -> Result<Option<String>, VaultError> {
        let now = self.inner.now();
        let conn = self.inner.lock();
        Ok(conn
            .query_row(
                "SELECT e.dataset_id FROM entries n JOIN epochs e ON e.id = n.epoch_id \
                 WHERE n.token = ?1 AND n.removed = 0 AND (e.closed_at IS NULL OR e.expires_at > ?2)",
                params![token, now],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    /// Every dataset's head in creation order (ties by id): one SELECT over
    /// `datasets`, no join, no count (the proxy's request path).
    pub fn dataset_heads(&self) -> Result<Vec<DatasetHead>, VaultError> {
        let conn = self.inner.lock();
        let mut stmt =
            conn.prepare("SELECT id, kind, created_at FROM datasets ORDER BY created_at, id")?;
        let rows = stmt.query_map([], |r| {
            let kind: String = r.get(1)?;
            Ok(DatasetHead {
                id: r.get(0)?,
                kind: DatasetKind::parse(&kind).unwrap_or(DatasetKind::Generic),
                created_at: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// The kind only: one indexed lookup, no entry count (request path).
    pub fn dataset_kind(&self, id: &str) -> Result<DatasetKind, VaultError> {
        let conn = self.inner.lock();
        let kind = conn
            .query_row(
                "SELECT kind FROM datasets WHERE id = ?1",
                params![id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| VaultError::DatasetNotFound(id.to_string()))?;
        Ok(DatasetKind::parse(&kind).unwrap_or(DatasetKind::Generic))
    }
}
