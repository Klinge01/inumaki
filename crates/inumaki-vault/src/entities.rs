//! Entity listing and per-entity forget (M4 spec §16.3). Listing shows
//! tokens with kind, first and last store use, and use count; originals
//! only on request. Forget deletes a mapping in every epoch of the dataset;
//! the caller evicts open working sets and caches (`AppState::forget_entity`).

use inumaki_core::span::EntityKind;
use inumaki_core::token::normalize;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::vault::Vault;

/// One known entity of a dataset.
#[derive(Clone)]
pub struct EntityInfo {
    /// The token.
    pub token: String,
    /// Kind.
    pub kind: EntityKind,
    /// Mint time, unix seconds.
    pub first_use: i64,
    /// Last store use, unix seconds.
    pub last_use: i64,
    /// Store-level uses (mint plus database hits).
    pub uses: u64,
    /// Epoch row id.
    pub epoch_id: i64,
    /// True when the epoch is the current one.
    pub current_epoch: bool,
    /// Surface-form rows (other spellings, bare parts, alias variants) that restore to their own text.
    pub surface_forms: usize,
    /// The original, only when requested; zeroized on drop.
    pub original: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for EntityInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityInfo")
            .field("token_len", &self.token.len())
            .field("kind", &self.kind.label())
            .field("uses", &self.uses)
            .field("epoch_id", &self.epoch_id)
            .field("current_epoch", &self.current_epoch)
            .field("surface_forms", &self.surface_forms)
            .field("has_original", &self.original.is_some())
            .finish()
    }
}

/// What a forget removed.
#[derive(Clone, PartialEq, Eq)]
pub struct Forgotten {
    /// Kinds of the removed mappings (one per matched key).
    pub kinds: Vec<EntityKind>,
    /// Every token that pointed at the entity, across epochs.
    pub tokens: Vec<String>,
    /// Rows deleted.
    pub rows: usize,
}

impl std::fmt::Debug for Forgotten {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forgotten")
            .field(
                "kinds",
                &self.kinds.iter().map(EntityKind::label).collect::<Vec<_>>(),
            )
            .field("tokens", &self.tokens.len())
            .field("rows", &self.rows)
            .finish()
    }
}

/// `(kind label, key HMAC)` pairs to delete.
type Key = (String, Vec<u8>);

impl Vault {
    /// Known entities of a dataset, most recently used first; `limit` 0
    /// means 1 000. Removed values (secrets) are not listed.
    pub fn entities(
        &self,
        dataset_id: &str,
        limit: usize,
        with_values: bool,
    ) -> Result<Vec<EntityInfo>, VaultError> {
        self.dataset_profile(dataset_id)?;
        let limit = if limit == 0 {
            1_000
        } else {
            limit.min(100_000)
        } as i64;
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            bool,
            Vec<u8>,
            Vec<u8>,
            i64,
        )> = {
            let conn = self.inner.lock();
            let mut stmt = conn.prepare(
                "SELECT e.token, e.kind, e.created_at, e.last_used, e.uses, e.epoch_id, p.closed_at IS NULL, e.nonce, e.value, \
                 (SELECT COUNT(*) FROM entries s WHERE s.surface_of = e.token) \
                 FROM entries e JOIN epochs p ON p.id = e.epoch_id \
                 WHERE p.dataset_id = ?1 AND e.removed = 0 AND e.surface_of IS NULL ORDER BY e.last_used DESC, e.token LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![dataset_id, limit], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        let mut out = Vec::with_capacity(rows.len());
        for (token, kind, created_at, last_used, uses, epoch_id, current, nonce, value, forms) in
            rows
        {
            let original = if with_values {
                Some(
                    self.inner
                        .cipher
                        .open_str(token.as_bytes(), &nonce, &value)?,
                )
            } else {
                None
            };
            out.push(EntityInfo {
                token,
                kind: EntityKind::from_label(&kind),
                first_use: created_at,
                last_use: last_used,
                uses: u64::try_from(uses).unwrap_or(0),
                epoch_id,
                current_epoch: current,
                surface_forms: usize::try_from(forms).unwrap_or(0),
                original,
            });
        }
        Ok(out)
    }

    /// Delete every row of `keys` in every epoch of the dataset, in one
    /// transaction; returns the tokens that pointed at them. `Immediate`:
    /// a `Deferred` transaction only takes its read lock on the first
    /// statement and its write lock on the first write, so if the
    /// journal writer's separate connection commits between this
    /// transaction's SELECT and its DELETE, SQLite's snapshot goes stale
    /// and the DELETE fails at once with `SQLITE_BUSY_SNAPSHOT` — not a
    /// contention `busy_timeout` retries away, a fresh transaction is
    /// required (review round 1, finding 1). Taking the write lock up
    /// front avoids that: another writer on the file waits (the ordinary
    /// `busy_timeout` path) instead of the snapshot going stale under us.
    fn forget_keys(&self, dataset_id: &str, keys: &[Key]) -> Result<Forgotten, VaultError> {
        let mut conn = self.inner.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut tokens: Vec<String> = Vec::new();
        let mut kinds: Vec<EntityKind> = Vec::new();
        let mut rows = 0usize;
        for (kind, mac) in keys {
            let mut stmt = tx.prepare(
                "SELECT token FROM entries WHERE kind = ?1 AND key_hmac = ?2 AND removed = 0 \
                 AND epoch_id IN (SELECT id FROM epochs WHERE dataset_id = ?3)",
            )?;
            let found = stmt
                .query_map(params![kind, mac, dataset_id], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            if found.is_empty() {
                continue;
            }
            // Surface forms go with their parent; their tokens are listed so
            // callers evict them from working sets and caches too.
            for parent in &found {
                let mut stmt = tx.prepare("SELECT token FROM entries WHERE surface_of = ?1")?;
                let children = stmt
                    .query_map(params![parent], |r| r.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                drop(stmt);
                rows += tx.execute("DELETE FROM entries WHERE surface_of = ?1", params![parent])?;
                tokens.extend(children);
            }
            rows += tx.execute(
                "DELETE FROM entries WHERE kind = ?1 AND key_hmac = ?2 AND removed = 0 \
                 AND epoch_id IN (SELECT id FROM epochs WHERE dataset_id = ?3)",
                params![kind, mac, dataset_id],
            )?;
            tokens.extend(found);
            kinds.push(EntityKind::from_label(kind));
        }
        tx.commit()?;
        drop(conn);
        self.inner.bump_entries(dataset_id);
        if rows == 0 {
            return Err(VaultError::EntityNotFound);
        }
        tracing::info!(dataset = %self.inner.opaque(dataset_id), kinds = kinds.len(), tokens = tokens.len(), rows, "entity forgotten");
        Ok(Forgotten {
            kinds,
            tokens,
            rows,
        })
    }

    /// Forget the entity behind `token` (any epoch of the dataset).
    pub fn forget_by_token(&self, dataset_id: &str, token: &str) -> Result<Forgotten, VaultError> {
        self.dataset_profile(dataset_id)?;
        let key: Option<Key> = {
            let conn = self.inner.lock();
            conn.query_row(
                "SELECT e.kind, e.key_hmac FROM entries e JOIN epochs p ON p.id = e.epoch_id \
                 WHERE e.token = ?1 AND p.dataset_id = ?2 AND e.removed = 0",
                params![token, dataset_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
        };
        let key = key.ok_or(VaultError::EntityNotFound)?;
        self.forget_keys(dataset_id, &[key])
    }

    /// Forget the entity whose normalized value is `value`, in every kind
    /// it was stored under. An alias variant resolves to its group's
    /// canonical as well (M4 spec §16.5), but only in the group's own
    /// kind: `value` itself is kind-agnostic (typing the exact stored text
    /// forgets it under every kind that used it, same as a plain value with
    /// no alias group), while a canonical reached only through alias
    /// expansion — the typed text differs from the stored one — must not
    /// also delete an unrelated entity of another kind that happens to
    /// share the canonical's spelling (review round 1, finding 2). The
    /// value never leaves this call.
    pub fn forget_by_value(&self, dataset_id: &str, value: &str) -> Result<Forgotten, VaultError> {
        self.dataset_profile(dataset_id)?;
        let own_mac = self
            .inner
            .indexer
            .mac(normalize(value).as_str().as_bytes())
            .to_vec();
        let mut keys: Vec<Key> = Vec::new();
        for (kind, canonical) in self.inner.aliases.canonicals_for(value) {
            let mac = self
                .inner
                .indexer
                .mac(normalize(canonical).as_str().as_bytes())
                .to_vec();
            let key = (kind.label().to_string(), mac);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        {
            let conn = self.inner.lock();
            let kinds: Vec<String> = conn
                .prepare(
                    "SELECT DISTINCT e.kind FROM entries e JOIN epochs p ON p.id = e.epoch_id \
                     WHERE p.dataset_id = ?1 AND e.removed = 0 AND e.key_hmac = ?2 ORDER BY e.kind",
                )?
                .query_map(params![dataset_id, own_mac], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?;
            keys.extend(kinds.into_iter().map(|k| (k, own_mac.clone())));
        }
        if keys.is_empty() {
            return Err(VaultError::EntityNotFound);
        }
        self.forget_keys(dataset_id, &keys)
    }
}
