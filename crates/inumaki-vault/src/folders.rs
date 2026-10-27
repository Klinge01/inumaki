//! Folder datasets and the mirror manifest (M5 spec §7.1). The vault stores
//! opaque sealed bytes: `inumakid` owns the folder configuration's shape and
//! `inumaki-mirror` the manifest records'. Paths never appear in clear:
//! folder configs and records are sealed under AADs bound to the dataset,
//! side, and path MAC, and rows are keyed by an index-key HMAC of the path.

use std::sync::PoisonError;

use inumaki_core::span::EntityKind;
use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

use crate::crypto::hex;
use crate::error::VaultError;
use crate::namespace::{is_fk_violation, load_known_rows};
use crate::vault::{Vault, is_constraint};

/// Manifest sides: source files, directory components, outbox files.
pub const MIRROR_SIDES: [&str; 3] = ["source", "dir", "outbox"];

/// A folder's decrypted configuration bytes (zeroized on drop).
pub type FolderConfig = Zeroizing<Vec<u8>>;

fn folder_aad(dataset: &str) -> Vec<u8> {
    format!("folder:{dataset}").into_bytes()
}

fn row_aad(dataset: &str, side: &str, mac: &[u8; 32]) -> Vec<u8> {
    format!("mirror:{dataset}:{side}:{}", hex(mac)).into_bytes()
}

fn check_side(side: &str) -> Result<(), VaultError> {
    if MIRROR_SIDES.contains(&side) {
        Ok(())
    } else {
        Err(VaultError::OutOfRange("side"))
    }
}

impl Vault {
    /// `HMAC-SHA256(index_key, domain || 0x00 || data)`: stable, keyed,
    /// non-invertible (content MACs, opaque names, collision suffixes).
    /// `domain` must be a unique per-feature string (`mirror:source:<id>`,
    /// never shared with another use), so two features can never produce
    /// the same MAC for the same data. `data` may be a path or file bytes,
    /// so the joined buffer is zeroized on drop.
    pub fn keyed_mac(&self, domain: &str, data: &[u8]) -> [u8; 32] {
        let mut buf = Zeroizing::new(Vec::with_capacity(domain.len() + 1 + data.len()));
        buf.extend_from_slice(domain.as_bytes());
        buf.push(0);
        buf.extend_from_slice(data);
        self.inner.indexer.mac(&buf)
    }

    /// A dataset's profile and open epoch id: two indexed lookups, no entry
    /// count. The mirror asks for it per file (`MirrorEngine::state`);
    /// [`dataset`](Self::dataset) counts the epoch's entries and is for
    /// status and the dataset endpoints.
    pub fn dataset_state(&self, id: &str) -> Result<(String, i64), VaultError> {
        let conn = self.inner.lock();
        conn.query_row(
            "SELECT d.profile, e.id FROM datasets d \
             JOIN epochs e ON e.dataset_id = d.id AND e.closed_at IS NULL WHERE d.id = ?1",
            params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or_else(|| VaultError::DatasetNotFound(id.to_string()))
    }

    /// Writes to `dataset`'s entries since this vault was opened.
    pub fn entries_generation(&self, dataset: &str) -> u64 {
        self.inner
            .entries_gen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(dataset)
            .copied()
            .unwrap_or(0)
    }

    fn path_mac(&self, dataset: &str, side: &str, rel: &[u8]) -> [u8; 32] {
        self.keyed_mac(&format!("mirror:{side}:{dataset}"), rel)
    }

    /// Store a folder's sealed configuration. `FolderExists` when the
    /// dataset already has one; `DatasetNotFound` for an unknown dataset.
    pub fn create_folder(&self, dataset: &str, config: &[u8]) -> Result<(), VaultError> {
        let sealed = self.inner.cipher.seal(&folder_aad(dataset), config)?;
        let conn = self.inner.lock();
        match conn.execute(
            "INSERT INTO folders (dataset_id, nonce, config, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![dataset, sealed.nonce, sealed.value, self.inner.now()],
        ) {
            Ok(_) => Ok(()),
            Err(e) if is_constraint(&e, "folders.dataset_id") => Err(VaultError::FolderExists),
            Err(e) if is_fk_violation(&e) => Err(VaultError::DatasetNotFound(dataset.to_string())),
            Err(e) => Err(e.into()),
        }
    }

    /// Replace a folder's sealed configuration (sealed as in
    /// [`create_folder`](Self::create_folder); the creation time and the
    /// manifest stay). `false` when the dataset has no folder: nothing is
    /// written, a folder is never created here.
    pub fn update_folder_config(&self, dataset: &str, config: &[u8]) -> Result<bool, VaultError> {
        let sealed = self.inner.cipher.seal(&folder_aad(dataset), config)?;
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE folders SET nonce = ?2, config = ?3 WHERE dataset_id = ?1",
            params![dataset, sealed.nonce, sealed.value],
        )?;
        Ok(n > 0)
    }

    /// A folder's configuration and creation time.
    pub fn folder(&self, dataset: &str) -> Result<Option<(FolderConfig, i64)>, VaultError> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = {
            let conn = self.inner.lock();
            conn.query_row(
                "SELECT nonce, config, created_at FROM folders WHERE dataset_id = ?1",
                params![dataset],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
        };
        row.map(|(n, c, at)| Ok((self.inner.cipher.open(&folder_aad(dataset), &n, &c)?, at)))
            .transpose()
    }

    /// Every folder: dataset id, configuration, creation time; by id.
    pub fn folders(&self) -> Result<Vec<(String, FolderConfig, i64)>, VaultError> {
        let rows: Vec<(String, Vec<u8>, Vec<u8>, i64)> = {
            let conn = self.inner.lock();
            let mut stmt = conn.prepare(
                "SELECT dataset_id, nonce, config, created_at FROM folders ORDER BY dataset_id",
            )?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<_, _>>()?
        };
        rows.into_iter()
            .map(|(id, n, c, at)| {
                let plain = self.inner.cipher.open(&folder_aad(&id), &n, &c)?;
                Ok((id, plain, at))
            })
            .collect()
    }

    /// Delete a folder and its whole manifest; the dataset stays. `false`
    /// when the dataset had no folder.
    pub fn remove_folder(&self, dataset: &str) -> Result<bool, VaultError> {
        let mut conn = self.inner.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM mirror_files WHERE dataset_id = ?1",
            params![dataset],
        )?;
        let n = tx.execute(
            "DELETE FROM folders WHERE dataset_id = ?1",
            params![dataset],
        )?;
        tx.commit()?;
        Ok(n > 0)
    }

    /// Insert or replace one manifest record.
    pub fn mirror_put(
        &self,
        dataset: &str,
        side: &str,
        rel: &[u8],
        record: &[u8],
    ) -> Result<(), VaultError> {
        check_side(side)?;
        let mac = self.path_mac(dataset, side, rel);
        let sealed = self
            .inner
            .cipher
            .seal(&row_aad(dataset, side, &mac), record)?;
        let conn = self.inner.lock();
        match conn.execute(
            "INSERT INTO mirror_files (dataset_id, side, path_mac, nonce, record) VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(dataset_id, side, path_mac) DO UPDATE SET nonce = excluded.nonce, record = excluded.record",
            params![dataset, side, mac.as_slice(), sealed.nonce, sealed.value],
        ) {
            Ok(_) => Ok(()),
            Err(e) if is_fk_violation(&e) => Err(VaultError::DatasetNotFound(dataset.to_string())),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete one manifest record (absent is fine).
    pub fn mirror_delete(&self, dataset: &str, side: &str, rel: &[u8]) -> Result<(), VaultError> {
        check_side(side)?;
        let mac = self.path_mac(dataset, side, rel);
        let conn = self.inner.lock();
        conn.execute(
            "DELETE FROM mirror_files WHERE dataset_id = ?1 AND side = ?2 AND path_mac = ?3",
            params![dataset, side, mac.as_slice()],
        )?;
        Ok(())
    }

    /// Every record of one side.
    pub fn mirror_list(
        &self,
        dataset: &str,
        side: &str,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>, VaultError> {
        check_side(side)?;
        let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
            let conn = self.inner.lock();
            let mut stmt = conn.prepare(
                "SELECT path_mac, nonce, record FROM mirror_files WHERE dataset_id = ?1 AND side = ?2 \
                 ORDER BY path_mac",
            )?;
            stmt.query_map(params![dataset, side], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<Result<_, _>>()?
        };
        rows.into_iter()
            .map(|(mac, n, rec)| {
                let mac: [u8; 32] = mac.try_into().map_err(|_| VaultError::Decrypt)?;
                self.inner
                    .cipher
                    .open(&row_aad(dataset, side, &mac), &n, &rec)
            })
            .collect()
    }

    /// Delete every manifest record of a dataset.
    pub fn mirror_clear(&self, dataset: &str) -> Result<(), VaultError> {
        let conn = self.inner.lock();
        conn.execute(
            "DELETE FROM mirror_files WHERE dataset_id = ?1",
            params![dataset],
        )?;
        Ok(())
    }

    /// The identifying originals of `dataset`'s most recently closed epoch,
    /// with their kinds, most recently used first (at most the automaton
    /// cap); empty when the dataset never rotated. Known originals are per
    /// epoch, so a rotation starts with an empty known-entity detector; the
    /// mirror registers these in the new epoch, with fresh tokens, before it
    /// re-mirrors (M5 spec §7.3, amended 2026-10-04). Canonical entities
    /// only: surface-form rows (plan 4a) are spellings of one of them, and
    /// carrying one would mint it as an entity of its own in the new epoch.
    pub fn previous_epoch_known(
        &self,
        dataset: &str,
    ) -> Result<Vec<(EntityKind, Zeroizing<String>)>, VaultError> {
        let epoch: Option<i64> = {
            let conn = self.inner.lock();
            conn.query_row(
                "SELECT id FROM epochs WHERE dataset_id = ?1 AND closed_at IS NOT NULL \
                 ORDER BY closed_at DESC, id DESC LIMIT 1",
                params![dataset],
                |r| r.get(0),
            )
            .optional()?
        };
        match epoch {
            Some(e) => load_known_rows(&self.inner, e, self.inner.automaton_max),
            None => Ok(Vec::new()),
        }
    }
}
