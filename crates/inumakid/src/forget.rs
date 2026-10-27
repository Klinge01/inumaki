//! Per-entity forget (M4 spec §16.3): [`ForgetTarget`] and
//! [`AppState::forget_entity`]. Re-exported from [`crate::state`].
//!
//! The daemon keeps exactly one namespace handle per dataset (the map in
//! [`AppState::namespace`]; a racing second opener drops its handle before
//! anyone uses it), and every per-dataset engine holds that handle's
//! known-entity detector `Arc`, whose contents `Namespace::forget_tokens`
//! replaces in place. Evicting and rebuilding that one handle therefore
//! reaches every working set and every known-entity detector the daemon
//! has for the dataset.

use std::sync::PoisonError;

use inumaki_vault::{Forgotten, VaultError};
use zeroize::Zeroizing;

use crate::state::AppState;

/// What `forget` targets (M4 spec §16.3). `Debug` names the variant only.
pub enum ForgetTarget {
    /// A token of the dataset (any epoch).
    Token(String),
    /// An original, resolved through the HMAC index (and alias groups).
    Value(Zeroizing<String>),
}

impl std::fmt::Debug for ForgetTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ForgetTarget::Token(_) => "ForgetTarget::Token",
            ForgetTarget::Value(_) => "ForgetTarget::Value",
        })
    }
}

impl AppState {
    /// Forget one entity (M4 spec §16.3): delete its rows in every epoch,
    /// evict it from the open working set and rebuild the known-entity
    /// automaton, drop the dataset's cached results, then truncate the WAL
    /// so no pre-delete page image survives in `vault.sqlite-wal`.
    ///
    /// Lock order as [`AppState::rotate_dataset`]: the namespace lock, then
    /// the database. The handle is opened first (not only fetched when
    /// open), so a request that opens the namespace concurrently cannot
    /// load the rows about to be deleted into a working set this call never
    /// evicts. A missing dataset fails here with `DatasetNotFound`.
    ///
    /// Errors: `EntityNotFound` when nothing matched; a failed automaton
    /// rebuild is returned as an error (the rows are already gone; the
    /// handle and the dataset's engines are dropped so the next request
    /// opens a fresh handle from the database, never a stale automaton);
    /// `CheckpointBusy` when the entity is gone but the WAL could not be
    /// truncated yet.
    pub fn forget_entity(&self, id: &str, target: &ForgetTarget) -> Result<Forgotten, VaultError> {
        let ns = self.namespace(id)?;
        let forgotten = {
            let mut guard = ns.lock().unwrap_or_else(PoisonError::into_inner);
            // Follow a rotation or deletion first, so the rebuild below
            // reads the current epoch's rows.
            guard.refresh()?;
            let forgotten = match target {
                ForgetTarget::Token(t) => self.vault.forget_by_token(id, t)?,
                ForgetTarget::Value(v) => self.vault.forget_by_value(id, v)?,
            };
            if let Err(e) = guard.forget_tokens(&forgotten.tokens) {
                // The working set is already evicted; the automaton kept
                // the old contents. Never serve it: drop the handle and
                // every engine holding its detector while still under the
                // lock, so the next request rebuilds from the database.
                self.close_namespace(id);
                self.engines.drop_dataset(id);
                self.cache.invalidate_namespace(id);
                tracing::warn!(dataset = %self.vault.opaque_id(id), error = %e, "known-entity rebuild after forget failed; namespace handle dropped");
                // The rows are gone either way: still purge their pages.
                if let Err(c) = self.vault.checkpoint_truncate() {
                    tracing::warn!(error = %c, "wal truncate after forget failed");
                }
                return Err(e);
            }
            // Still under the lock: no request can cache a result carrying
            // the old token between the delete and this invalidation.
            self.cache.invalidate_namespace(id);
            forgotten
        };
        // The deleted rows' page images stay in vault.sqlite-wal until a
        // TRUNCATE checkpoint, which the daemon otherwise runs only at
        // shutdown. The rows are committed, so this needs no namespace
        // lock; releasing it first keeps the dataset's requests from
        // waiting on the checkpoint's busy retries.
        self.vault.checkpoint_truncate()?;
        tracing::info!(dataset = %self.vault.opaque_id(id), by = ?target, kinds = forgotten.kinds.len(), tokens = forgotten.tokens.len(), rows = forgotten.rows, "entity forget complete");
        Ok(forgotten)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_names_the_variant_only() {
        let t = ForgetTarget::Token("<PERSON_abc123>".into());
        let v = ForgetTarget::Value(Zeroizing::new("Zyxwuria Quolnath".into()));
        assert_eq!(format!("{t:?}"), "ForgetTarget::Token");
        assert_eq!(format!("{v:?}"), "ForgetTarget::Value");
    }
}
