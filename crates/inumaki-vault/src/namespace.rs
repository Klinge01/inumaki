//! One dataset's current epoch as a [`TokenStore`].
//!
//! Every write returns a `StoreError` on failure; there is no fault flag to poll.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use inumaki_core::TokenSettings;
use inumaki_core::alias::AliasTable;
use inumaki_core::consistency::{StoreDict, StoreDictCache};
use inumaki_core::detect::Detector;
use inumaki_core::span::EntityKind;
use inumaki_core::token::{
    MAX_SURFACE_FORMS, StoreError, SurfaceForm, Token, TokenStore, derive_surface_token,
    format_token, normalize, random_suffix, random_surface_component,
};
use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

use crate::crypto::hex;
use crate::error::VaultError;
use crate::known::{KNOWN_KINDS_SQL, KnownEntityDetector, REBUILD_AFTER, is_known_entity};
use crate::lru::Lru;
use crate::vault::{Vault, VaultInner, is_constraint};

/// Decrypted entries a namespace keeps in memory (spec §5.5).
pub const WORKING_SET: usize = 4096;
/// Mint attempts before `TokenSpaceExhausted` (spec §12).
const MINT_RETRIES: usize = 8;
/// Removed values loaded at open for the leak check.
const REMOVED_PRELOAD: usize = 1024;

/// Kind label plus HMAC of the normalized value: the lookup key.
type KeyId = (String, [u8; 32]);

/// A `prepare` row: kind, nonce, ciphertext, key HMAC, owning epoch, parent
/// token of a surface row.
type PrepareRow = (
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<String>,
    Option<i64>,
);

/// A parent lookup row: kind, nonce, ciphertext, key HMAC.
type ParentRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

struct Cached {
    kind: EntityKind,
    original: Zeroizing<String>,
    /// Present for current-epoch entries (they may be found by value again).
    key: Option<KeyId>,
    /// Parent entity token when this is a surface form.
    surface_of: Option<String>,
    /// Unix seconds this handle last minted, looked up, or loaded it
    /// (the linker's recency window).
    used_at: i64,
    /// End of the grace period of the closed epoch this entry was loaded
    /// from; `None` for the current epoch. From this second on the entry no
    /// longer answers (`prepare`'s query refuses the same row), swept or not.
    expires_at: Option<i64>,
}

/// `(dataset, current epoch)` handle. Not `Clone`: each handle has its own
/// working set; open one per request holder and keep it behind a mutex.
pub struct Namespace {
    inner: Arc<VaultInner>,
    dataset_id: String,
    epoch_id: i64,
    seen_gen: u64,
    settings: TokenSettings,
    working: Lru<String, Cached>,
    by_key: HashMap<KeyId, String>,
    removed: Vec<(EntityKind, Zeroizing<String>)>,
    /// Latched once [`Namespace::refresh`] sees the dataset gone: every later
    /// call on this handle fails closed, without re-checking (spec §5.3).
    closed: bool,
    mints: u64,
    /// Earliest `expires_at` among working entries loaded from a closed epoch.
    next_expiry: Option<i64>,
    known: Arc<KnownEntityDetector>,
    mints_since_build: usize,
    /// The engine's consistency dictionary over `entries` and `removed`
    /// (Task 7e, ruling L62): told of every working-set insert and
    /// eviction, cleared with the working set (rotation, deletion), on
    /// forget, on expiry, and when the LRU evicts a closed epoch's entry
    /// (fix round 1), dropped with the handle.
    dict: StoreDictCache,
}

impl std::fmt::Debug for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Namespace")
            .field("dataset", &self.inner.opaque(&self.dataset_id))
            .field("epoch", &self.epoch_id)
            .field("working", &self.working.len())
            .field("removed", &self.removed.len())
            .field("mints", &self.mints)
            .field("closed", &self.closed)
            .field("known", &self.known_entities())
            .finish()
    }
}

pub(crate) fn current_epoch(
    inner: &VaultInner,
    dataset_id: &str,
) -> Result<Option<i64>, VaultError> {
    let conn = inner.lock();
    Ok(conn
        .query_row(
            "SELECT id FROM epochs WHERE dataset_id = ?1 AND closed_at IS NULL",
            params![dataset_id],
            |r| r.get(0),
        )
        .optional()?)
}

pub(crate) fn is_fk_violation(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY)
}

/// Decrypted originals of the identifying kinds in `epoch_id`, most recently
/// used first, at most `max`.
pub(crate) fn load_known_rows(
    inner: &VaultInner,
    epoch_id: i64,
    max: usize,
) -> Result<Vec<(EntityKind, Zeroizing<String>)>, VaultError> {
    // The one-part PERSON filter needs the decrypted text, so it cannot be a
    // `WHERE` clause; page through the rows (most recently used first) until
    // `max` known entities are collected, so bare names never take slots.
    let batch = max.max(1);
    let batch_sql = i64::try_from(batch).unwrap_or(i64::MAX);
    let mut out = Vec::new();
    let mut offset = 0i64;
    // One connection lock across all pages: the vault has a single
    // connection, so no write can land between pages and shift the offsets
    // (a row skipped or read twice).
    let conn = inner.lock();
    while out.len() < max {
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = {
            let mut stmt = conn.prepare(&format!(
                "SELECT kind, token, nonce, value FROM entries \
                 WHERE epoch_id = ?1 AND removed = 0 AND surface_of IS NULL AND kind IN {KNOWN_KINDS_SQL} \
                 ORDER BY last_used DESC, token LIMIT ?2 OFFSET ?3"
            ))?;
            let rows = stmt.query_map(params![epoch_id, batch_sql, offset], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        let fetched = rows.len();
        for (kind, token, nonce, value) in rows {
            let original = inner.cipher.open_str(token.as_bytes(), &nonce, &value)?;
            let kind = EntityKind::from_label(&kind);
            if out.len() < max && is_known_entity(&kind, &original) {
                out.push((kind, original));
            }
        }
        if fetched < batch {
            break;
        }
        offset += batch_sql;
    }
    Ok(out)
}

impl Vault {
    /// Handle on `dataset_id`'s current epoch with the default working set.
    pub fn namespace(&self, dataset_id: &str) -> Result<Namespace, VaultError> {
        self.namespace_with_working_set(dataset_id, WORKING_SET)
    }

    /// Handle with a custom working-set bound (tests).
    pub fn namespace_with_working_set(
        &self,
        dataset_id: &str,
        cap: usize,
    ) -> Result<Namespace, VaultError> {
        Namespace::open(Arc::clone(&self.inner), dataset_id, cap)
    }
}

impl Namespace {
    pub(crate) fn open(
        inner: Arc<VaultInner>,
        dataset_id: &str,
        cap: usize,
    ) -> Result<Namespace, VaultError> {
        let epoch_id = current_epoch(&inner, dataset_id)?
            .ok_or_else(|| VaultError::DatasetNotFound(dataset_id.to_string()))?;
        let rows = load_known_rows(&inner, epoch_id, inner.automaton_max)?;
        // A row minted before its alias group was configured holds a variant,
        // not the canonical, and stays a separate entity until forgotten
        // (docs/cli.md). Count only; never the values.
        let split = rows
            .iter()
            .filter(|(k, o)| {
                inner
                    .aliases
                    .canonical(k, o)
                    .is_some_and(|c| c != o.as_str())
            })
            .count();
        if split > 0 {
            tracing::warn!(dataset = %inner.opaque(dataset_id), rows = split, "entries minted before their alias group; forget them or they stay separate entities");
        }
        let known = Arc::new(KnownEntityDetector::build(
            rows,
            Arc::clone(&inner.aliases),
        )?);
        let mut ns = Namespace {
            seen_gen: inner.generation(),
            settings: inner.tokens.clone(),
            inner,
            dataset_id: dataset_id.to_string(),
            epoch_id,
            working: Lru::new(cap.max(1)),
            by_key: HashMap::new(),
            removed: Vec::new(),
            closed: false,
            mints: 0,
            next_expiry: None,
            known,
            mints_since_build: 0,
            dict: StoreDictCache::default(),
        };
        ns.load_removed()?;
        Ok(ns)
    }

    /// Dataset id.
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }

    /// Current epoch row id.
    pub fn epoch_id(&self) -> i64 {
        self.epoch_id
    }

    /// Decrypted entries held in memory.
    pub fn working_set_len(&self) -> usize {
        self.working.len()
    }

    /// Tokens minted (not looked up) through this handle.
    pub fn mints(&self) -> u64 {
        self.mints
    }

    /// The known-entity detector for this namespace's current epoch. The
    /// same `Arc` stays valid across rotations (its contents are replaced).
    pub fn detector(&self) -> Arc<dyn Detector> {
        Arc::clone(&self.known) as Arc<dyn Detector>
    }

    /// Rebuild the main automaton synchronously.
    pub fn rebuild_detector_now(&mut self) -> Result<(), VaultError> {
        let seen = self.known.pending();
        let rows = load_known_rows(&self.inner, self.epoch_id, self.inner.automaton_max)?;
        self.known.replace(rows, seen)?;
        self.mints_since_build = 0;
        Ok(())
    }

    /// Drop `tokens` from the working set (their rows are gone: M4 spec
    /// §16.3 forget) and rebuild the known-entity automaton now, so neither
    /// the leak check nor the detector remembers the entity.
    pub fn forget_tokens(&mut self, tokens: &[String]) -> Result<(), VaultError> {
        // Surface forms leave with their parent, whether or not the caller
        // listed them.
        self.forget_tokens_local(tokens);
        self.rebuild_detector_now()
    }

    /// Times the main automaton was rebuilt.
    pub fn detector_generation(&self) -> u64 {
        self.known.generation()
    }

    /// Entries the detector knows (main plus delta).
    pub fn known_entities(&self) -> usize {
        self.known.size() + self.known.pending()
    }

    fn spawn_rebuild(&self) {
        let inner = Arc::clone(&self.inner);
        let known = Arc::clone(&self.known);
        let epoch = self.epoch_id;
        // Computed before the thread so the raw slug never crosses into it
        // (only the opaque label is captured).
        let label = self.inner.opaque(&self.dataset_id);
        // `seen` is taken before the SELECT: entries pushed while the rows
        // are loading stay in the delta after the swap (review I3).
        let seen = self.known.pending();
        // Snapshot the generation now too: if a forget or rotation's
        // synchronous rebuild runs between this SELECT and the swap below,
        // `replace_if` refuses to swap in these now-stale rows (review item
        // 2; plan 2b Task 3's `stale_rebuild_does_not_resurrect_a_forgotten_entity`).
        let expected = self.known.generation();
        std::thread::spawn(move || {
            let r = load_known_rows(&inner, epoch, inner.automaton_max)
                .and_then(|rows| known.replace_if(rows, seen, expected));
            match r {
                Ok(true) => tracing::debug!(dataset = %label, "known-entity automaton rebuilt"),
                Ok(false) => {
                    tracing::debug!(dataset = %label, "known-entity automaton rebuild skipped: superseded")
                }
                Err(e) => {
                    tracing::warn!(dataset = %label, error = %e, "known-entity automaton rebuild failed")
                }
            }
        });
    }

    /// Follow a rotation or deletion done through another handle: reload
    /// the epoch, wipe the working set. [`VaultError::Closed`] when the
    /// dataset is gone; once that happens, every later call latches to the
    /// same error without re-checking (the `closed` flag).
    pub fn refresh(&mut self) -> Result<(), VaultError> {
        if self.closed {
            return Err(VaultError::Closed);
        }
        self.evict_expired();
        let g = self.inner.generation();
        if g == self.seen_gen {
            return Ok(());
        }
        self.seen_gen = g;
        match current_epoch(&self.inner, &self.dataset_id)? {
            Some(e) if e == self.epoch_id => Ok(()),
            Some(e) => {
                self.epoch_id = e;
                self.clear_working();
                self.removed.clear();
                self.load_removed()?;
                let seen = self.known.pending();
                self.known.replace(
                    load_known_rows(&self.inner, e, self.inner.automaton_max)?,
                    seen,
                )?;
                self.mints_since_build = 0;
                Ok(())
            }
            None => {
                self.clear_working();
                self.removed.clear();
                let _ = self.known.replace(Vec::new(), usize::MAX);
                self.closed = true;
                Err(VaultError::Closed)
            }
        }
    }

    /// The token already minted for `(kind, original)` in the current epoch
    /// (working set, then the store), without minting one. Used by the
    /// inspection overlay (M4 spec §9.1: previews never mint).
    pub fn peek_token(
        &mut self,
        kind: &EntityKind,
        original: &str,
    ) -> Result<Option<Token>, StoreError> {
        self.refresh().map_err(|e| self.store_error(e))?;
        let id = self.key_id(kind, original);
        if let Some(t) = self.by_key.get(&id).cloned() {
            return Ok(Some(Token::from(t)));
        }
        match self.lookup_db(&id) {
            Ok(Some((token, stored))) => {
                // A preview is not a recent mention: recency 0 keeps it out of
                // `link_candidates`.
                self.remember_at(token.clone(), kind.clone(), stored, Some(id), None, 0);
                Ok(Some(Token::from(token)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(self.store_error(e)),
        }
    }

    /// The surface token already minted for `(parent, surface)`, without
    /// minting one (the inspection overlay, M4 spec §9.1).
    pub fn peek_surface_token(
        &mut self,
        parent: &str,
        surface: &str,
    ) -> Result<Option<Token>, StoreError> {
        self.refresh().map_err(|e| self.store_error(e))?;
        let kind = match self.parent_kind(parent) {
            Ok(k) => k,
            Err(VaultError::UnknownParent) => return Ok(None),
            Err(e) => return Err(self.store_error(e)),
        };
        let id = self.surface_key(&kind, parent, surface);
        if let Some(t) = self.by_key.get(&id).cloned() {
            return Ok(Some(Token::from(t)));
        }
        match self.lookup_db(&id) {
            Ok(Some((token, stored))) => {
                self.remember_at(
                    token.clone(),
                    kind,
                    stored,
                    Some(id),
                    Some(parent.to_string()),
                    0,
                );
                Ok(Some(Token::from(token)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(self.store_error(e)),
        }
    }

    fn clear_working(&mut self) {
        // Every `Cached` dropped here wipes its original; the dictionary's
        // forms go with them.
        self.dict.clear();
        drop(self.working.drain());
        self.by_key.clear();
        self.next_expiry = None;
    }

    fn load_removed(&mut self) -> Result<(), VaultError> {
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = {
            let conn = self.inner.lock();
            let mut stmt = conn.prepare(
                "SELECT kind, token, nonce, value FROM entries WHERE epoch_id = ?1 AND removed = 1 \
                 ORDER BY last_used DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![self.epoch_id, REMOVED_PRELOAD as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        for (kind, token, nonce, value) in rows {
            let original = self
                .inner
                .cipher
                .open_str(token.as_bytes(), &nonce, &value)?;
            self.removed.push((EntityKind::from_label(&kind), original));
        }
        Ok(())
    }

    fn key_id(&self, kind: &EntityKind, original: &str) -> KeyId {
        let key = normalize(original);
        (
            kind.label().to_string(),
            self.inner.indexer.mac(key.as_str().as_bytes()),
        )
    }

    fn remember(
        &mut self,
        token: String,
        kind: EntityKind,
        original: Zeroizing<String>,
        key: Option<KeyId>,
        surface_of: Option<String>,
    ) {
        let now = self.inner.now();
        self.remember_at(token, kind, original, key, surface_of, now);
    }

    /// [`Namespace::remember`] with an explicit recency. Entries that are
    /// only loaded (rehydration's `prepare`, a parent lookup, a preview) pass
    /// 0: they are not a recent mention, so `link_candidates` skips them
    /// until sanitization mints or looks them up.
    fn remember_at(
        &mut self,
        token: String,
        kind: EntityKind,
        original: Zeroizing<String>,
        key: Option<KeyId>,
        surface_of: Option<String>,
        used_at: i64,
    ) {
        if let Some(k) = &key {
            self.by_key.insert(k.clone(), token.clone());
        }
        self.dict.note_entry(&kind, &original);
        let evicted = self.working.insert(
            token.clone(),
            Cached {
                kind,
                original,
                key,
                surface_of,
                used_at,
                expires_at: None,
            },
            1,
        );
        for (evicted_token, cached) in evicted {
            if cached.expires_at.is_some() {
                // A closed epoch's entry: once out of the working set the
                // expiry sweep no longer sees it, so a dead entry in the
                // cached base could outlive its rows. Its forms go now.
                self.dict.clear();
            } else {
                self.dict.note_evicted(&cached.kind, &cached.original);
            }
            if let Some(k) = cached.key {
                if evicted_token != token && self.by_key.get(&k) == Some(&evicted_token) {
                    self.by_key.remove(&k);
                }
            }
            // `cached.original` drops here and is zeroized.
        }
    }

    /// Key of a surface row: HMAC over the parent token and the surface
    /// text exactly as written (R9: not normalized, so `SARAH` and `Sarah`
    /// are distinct rows and rehydration restores exactly the replaced
    /// text), so the same surface of two entities never collides and never
    /// collides with a canonical key either.
    fn surface_key(&self, kind: &EntityKind, parent: &str, surface: &str) -> KeyId {
        let mut buf = Zeroizing::new(Vec::with_capacity(parent.len() + surface.len() + 9));
        buf.extend_from_slice(b"surface:");
        buf.extend_from_slice(parent.as_bytes());
        buf.push(b':');
        buf.extend_from_slice(surface.as_bytes());
        (kind.label().to_string(), self.inner.indexer.mac(&buf))
    }

    /// The kind of `parent` when it is a current-epoch entity row of this
    /// namespace (loaded into the working set if needed); `UnknownParent`
    /// otherwise.
    fn parent_kind(&mut self, parent: &str) -> Result<EntityKind, VaultError> {
        if let Some(c) = self.working.peek(&parent.to_string()) {
            return if c.key.is_some() && c.surface_of.is_none() {
                Ok(c.kind.clone())
            } else {
                Err(VaultError::UnknownParent)
            };
        }
        let row: Option<ParentRow> = {
            let conn = self.inner.lock();
            conn.query_row(
                "SELECT kind, nonce, value, key_hmac FROM entries \
                 WHERE token = ?1 AND epoch_id = ?2 AND removed = 0 AND surface_of IS NULL",
                params![parent, self.epoch_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
        };
        let Some((kind, nonce, value, mac)) = row else {
            return Err(VaultError::UnknownParent);
        };
        let original = self
            .inner
            .cipher
            .open_str(parent.as_bytes(), &nonce, &value)?;
        let key = <[u8; 32]>::try_from(mac.as_slice())
            .ok()
            .map(|m| (kind.clone(), m));
        let kind = EntityKind::from_label(&kind);
        self.remember_at(parent.to_string(), kind.clone(), original, key, None, 0);
        Ok(kind)
    }

    fn lookup_db(&self, id: &KeyId) -> Result<Option<(String, Zeroizing<String>)>, VaultError> {
        let conn = self.inner.lock();
        let row: Option<(String, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT token, nonce, value FROM entries WHERE epoch_id = ?1 AND kind = ?2 AND key_hmac = ?3 AND removed = 0",
                params![self.epoch_id, id.0, id.1.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((token, nonce, value)) = row else {
            return Ok(None);
        };
        conn.execute(
            "UPDATE entries SET last_used = ?1, uses = uses + 1 WHERE token = ?2",
            params![self.inner.now(), token],
        )?;
        let original = self
            .inner
            .cipher
            .open_str(token.as_bytes(), &nonce, &value)?;
        Ok(Some((token, original)))
    }

    fn mint(
        &mut self,
        kind: &EntityKind,
        original: &str,
        id: &KeyId,
    ) -> Result<String, VaultError> {
        let now = self.inner.now();
        for _ in 0..MINT_RETRIES {
            let token = format_token(&self.settings, kind, &random_suffix(&self.settings));
            let sealed = self
                .inner
                .cipher
                .seal(token.as_bytes(), original.as_bytes())?;
            let r = {
                let conn = self.inner.lock();
                conn.execute(
                    "INSERT INTO entries (epoch_id, kind, key_hmac, token, nonce, value, removed, last_used, created_at, uses) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?7, 1)",
                    params![self.epoch_id, id.0, id.1.as_slice(), token, sealed.nonce, sealed.value, now],
                )
            };
            match r {
                Ok(_) => {
                    self.inner.bump_entries(&self.dataset_id);
                    return Ok(token);
                }
                Err(e) if is_constraint(&e, "entries.token") => continue,
                Err(e) if is_constraint(&e, "entries.epoch_id") => {
                    // Another handle minted this entity first: use its token.
                    return self.lookup_db(id)?.map(|(t, _)| t).ok_or_else(|| {
                        VaultError::Sqlite("entry vanished after a lost mint race".into())
                    });
                }
                Err(e) if is_fk_violation(&e) => return Err(VaultError::Closed),
                Err(e) => return Err(e.into()),
            }
        }
        Err(VaultError::TokenSpaceExhausted(kind.label().to_string()))
    }

    fn mint_surface(
        &mut self,
        kind: &EntityKind,
        parent: &str,
        surface: &str,
        id: &KeyId,
    ) -> Result<String, VaultError> {
        let now = self.inner.now();
        for _ in 0..MINT_RETRIES {
            let token = match self.settings.surface_form {
                SurfaceForm::Derived => {
                    // Components already taken under this parent, so a
                    // nearly full parent still finds a free one.
                    let taken: HashSet<String> = {
                        let conn = self.inner.lock();
                        let mut stmt =
                            conn.prepare("SELECT token FROM entries WHERE surface_of = ?1")?;
                        stmt.query_map(params![parent], |r| r.get::<_, String>(0))?
                            .collect::<Result<_, _>>()?
                    };
                    if taken.len() >= MAX_SURFACE_FORMS {
                        return Err(VaultError::TokenSpaceExhausted(kind.label().to_string()));
                    }
                    let draw = |c: &str| derive_surface_token(&self.settings, parent, c);
                    let mut pick = None;
                    for _ in 0..16 {
                        let t = draw(&random_surface_component());
                        if !taken.contains(&t) {
                            pick = Some(t);
                            break;
                        }
                    }
                    match pick.or_else(|| {
                        (0u8..=255)
                            .map(|n| draw(&format!("{n:02x}")))
                            .find(|t| !taken.contains(t))
                    }) {
                        Some(t) => t,
                        None => {
                            return Err(VaultError::TokenSpaceExhausted(kind.label().to_string()));
                        }
                    }
                }
                SurfaceForm::Independent => {
                    format_token(&self.settings, kind, &random_suffix(&self.settings))
                }
            };
            let sealed = self
                .inner
                .cipher
                .seal(token.as_bytes(), surface.as_bytes())?;
            let r = {
                let conn = self.inner.lock();
                conn.execute(
                    // The parent must still be a live canonical row of this
                    // epoch: a parent forgotten through another handle must
                    // not get an orphan child that re-stores its text.
                    "INSERT INTO entries (epoch_id, kind, key_hmac, token, nonce, value, removed, last_used, created_at, uses, surface_of) \
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?7, 1, ?8 \
                     WHERE EXISTS (SELECT 1 FROM entries WHERE token = ?8 AND epoch_id = ?1 AND removed = 0 AND surface_of IS NULL)",
                    params![self.epoch_id, id.0, id.1.as_slice(), token, sealed.nonce, sealed.value, now, parent],
                )
            };
            match r {
                Ok(1) => {
                    // A new surface form is a new known spelling: the mirror's
                    // tripwire must see it like any other mint.
                    self.inner.bump_entries(&self.dataset_id);
                    return Ok(token);
                }
                Ok(_) => return Err(VaultError::UnknownParent),
                // another handle took the component first: draw again
                Err(e) if is_constraint(&e, "entries.token") => continue,
                Err(e) if is_constraint(&e, "entries.epoch_id") => {
                    // Another handle minted this surface form first.
                    return self.lookup_db(id)?.map(|(t, _)| t).ok_or_else(|| {
                        VaultError::Sqlite("surface row vanished after a lost mint race".into())
                    });
                }
                Err(e) if is_fk_violation(&e) => return Err(VaultError::Closed),
                Err(e) => return Err(e.into()),
            }
        }
        Err(VaultError::TokenSpaceExhausted(kind.label().to_string()))
    }

    /// Mark a working-set entry as used by sanitization just now.
    fn touch_used(&mut self, token: &str) {
        let now = self.inner.now();
        if let Some(c) = self.working.get_mut(&token.to_string()) {
            c.used_at = now;
        }
    }

    /// Drop `tokens` (and their surface children) from this handle's working
    /// set only; the rows are already gone from the store.
    fn forget_tokens_local(&mut self, tokens: &[String]) {
        let parents: HashSet<&str> = tokens.iter().map(String::as_str).collect();
        let mut doomed: Vec<String> = self
            .working
            .iter()
            .filter(|(_, c)| c.surface_of.as_deref().is_some_and(|p| parents.contains(p)))
            .map(|(t, _)| t.clone())
            .collect();
        doomed.extend(tokens.iter().cloned());
        // Forgotten values' forms go now, not at the next full build.
        self.dict.clear();
        for t in &doomed {
            if let Some(c) = self.working.remove(t) {
                if let Some(k) = c.key {
                    if self.by_key.get(&k) == Some(t) {
                        self.by_key.remove(&k);
                    }
                }
            }
        }
    }

    fn try_surface_token(&mut self, parent: &str, surface: &str) -> Result<String, VaultError> {
        self.refresh()?;
        let kind = self.parent_kind(parent)?;
        let id = self.surface_key(&kind, parent, surface);
        if let Some(t) = self.by_key.get(&id).cloned() {
            let now = self.inner.now();
            if let Some(c) = self.working.get_mut(&t) {
                c.used_at = now;
            }
            self.touch_used(parent);
            return Ok(t);
        }
        if let Some((token, stored)) = self.lookup_db(&id)? {
            self.remember(
                token.clone(),
                kind,
                stored,
                Some(id),
                Some(parent.to_string()),
            );
            self.touch_used(parent);
            return Ok(token);
        }
        let token = match self.mint_surface(&kind, parent, surface, &id) {
            Ok(t) => t,
            Err(VaultError::UnknownParent) => {
                // the parent is gone from the store: drop the stale copy
                self.forget_tokens_local(&[parent.to_string()]);
                return Err(VaultError::UnknownParent);
            }
            Err(e) => return Err(e),
        };
        self.touch_used(parent);
        self.remember(
            token.clone(),
            kind,
            Zeroizing::new(surface.to_string()),
            Some(id),
            Some(parent.to_string()),
        );
        Ok(token)
    }

    fn try_token_for(&mut self, kind: &EntityKind, original: &str) -> Result<String, VaultError> {
        self.refresh()?;
        let id = self.key_id(kind, original);
        if let Some(t) = self.by_key.get(&id).cloned() {
            let now = self.inner.now();
            if let Some(c) = self.working.get_mut(&t) {
                c.used_at = now;
            }
            return Ok(t);
        }
        if let Some((token, stored)) = self.lookup_db(&id)? {
            self.remember(token.clone(), kind.clone(), stored, Some(id), None);
            return Ok(token);
        }
        let token = self.mint(kind, original, &id)?;
        self.mints += 1;
        if is_known_entity(kind, original) {
            self.known.push(kind, original)?;
            self.mints_since_build += 1;
            if self.mints_since_build >= REBUILD_AFTER {
                self.mints_since_build = 0;
                self.spawn_rebuild();
            }
        }
        self.remember(
            token.clone(),
            kind.clone(),
            Zeroizing::new(original.to_string()),
            Some(id),
            None,
        );
        Ok(token)
    }

    fn try_record_removed(&mut self, kind: &EntityKind, original: &str) -> Result<(), VaultError> {
        self.refresh()?;
        let id = self.key_id(kind, original);
        let mut rnd = [0u8; 16];
        getrandom::fill(&mut rnd).map_err(|_| VaultError::Random)?;
        let placeholder = format!("removed:{}", hex(&rnd));
        let sealed = self
            .inner
            .cipher
            .seal(placeholder.as_bytes(), original.as_bytes())?;
        let conn = self.inner.lock();
        let r = conn.execute(
            "INSERT OR IGNORE INTO entries (epoch_id, kind, key_hmac, token, nonce, value, removed, last_used, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7)",
            params![self.epoch_id, id.0, id.1.as_slice(), placeholder, sealed.nonce, sealed.value, self.inner.now()],
        );
        match r {
            Ok(_) => {
                self.inner.bump_entries(&self.dataset_id);
                Ok(())
            }
            Err(e) if is_fk_violation(&e) => Err(VaultError::Closed),
            Err(e) => Err(e.into()),
        }
    }

    fn try_prepare(&mut self, tokens: &[String]) -> Result<(), VaultError> {
        self.refresh()?;
        let now = self.inner.now();
        for t in tokens {
            if self.working.get(t).is_some() {
                // an entry past its grace period is not "already loaded"
                self.evict_expired();
                if self.working.peek(t).is_some() {
                    continue;
                }
            }
            let row: Option<PrepareRow> = {
                let conn = self.inner.lock();
                conn.query_row(
                    "SELECT e.kind, e.nonce, e.value, e.key_hmac, e.epoch_id, e.surface_of, p.expires_at FROM entries e \
                     JOIN epochs p ON p.id = e.epoch_id \
                     WHERE e.token = ?1 AND e.removed = 0 AND p.dataset_id = ?2 \
                       AND (p.closed_at IS NULL OR p.expires_at > ?3)",
                    params![t, self.dataset_id, now],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                        ))
                    },
                )
                .optional()?
            };
            let Some((kind, nonce, value, mac, epoch, surface_of, expires_at)) = row else {
                continue;
            };
            let original = self.inner.cipher.open_str(t.as_bytes(), &nonce, &value)?;
            let key = if epoch == self.epoch_id {
                <[u8; 32]>::try_from(mac.as_slice())
                    .ok()
                    .map(|m| (kind.clone(), m))
            } else {
                None
            };
            // loaded for rehydration: not a recent mention (recency 0)
            self.remember_at(
                t.clone(),
                EntityKind::from_label(&kind),
                original,
                key,
                surface_of,
                0,
            );
            if epoch != self.epoch_id {
                if let Some(c) = self.working.get_mut(t) {
                    c.expires_at = expires_at;
                }
                if let Some(e) = expires_at {
                    self.next_expiry = Some(self.next_expiry.map_or(e, |n| n.min(e)));
                }
            }
        }
        Ok(())
    }

    /// Whether `c` may still answer: an entry loaded from a closed epoch
    /// stops at the end of its grace period, exactly where `prepare`'s query
    /// stops finding the row.
    fn live(&self, c: &Cached) -> bool {
        c.expires_at.is_none_or(|e| e > self.inner.now())
    }

    /// Drop entries of closed epochs whose grace period has passed, so their
    /// plaintext does not outlive the rows the sweep deletes. Cheap when
    /// nothing is due (`next_expiry`).
    fn evict_expired(&mut self) {
        let now = self.inner.now();
        match self.next_expiry {
            Some(n) if now >= n => {}
            _ => return,
        }
        let doomed: Vec<String> = self
            .working
            .iter()
            .filter(|(_, c)| c.expires_at.is_some_and(|e| e <= now))
            .map(|(t, _)| t.clone())
            .collect();
        if !doomed.is_empty() {
            // Expired values' forms go with them.
            self.dict.clear();
        }
        for t in &doomed {
            drop(self.working.remove(t));
        }
        self.next_expiry = self.working.iter().filter_map(|(_, c)| c.expires_at).min();
    }

    /// Map a vault failure to the core's value-free store error. Logged with
    /// the error's `Display` (ids and SQLite messages, never values).
    fn store_error(&self, e: VaultError) -> StoreError {
        // A refused parent is an ordinary answer (the alias wrapper retries
        // under the canonical), not a fault.
        if !matches!(e, VaultError::UnknownParent) {
            tracing::warn!(dataset = %self.inner.opaque(&self.dataset_id), error = %e, "namespace fault");
        }
        match e {
            VaultError::UnknownParent => StoreError::UnknownParent,
            VaultError::Closed | VaultError::DatasetNotFound(_) => StoreError::Closed,
            VaultError::TokenSpaceExhausted(kind) => StoreError::Exhausted(kind),
            _ => StoreError::Unavailable,
        }
    }
}

impl TokenStore for Namespace {
    fn token_for(&mut self, kind: &EntityKind, original: &str) -> Result<Token, StoreError> {
        self.try_token_for(kind, original)
            .map(Token::from)
            .map_err(|e| self.store_error(e))
    }

    fn original(&self, token: &str) -> Option<&str> {
        self.working
            .peek(&token.to_string())
            .filter(|c| self.live(c))
            .map(|c| c.original.as_str())
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        Box::new(
            self.working
                .iter()
                .filter(|(_, c)| self.live(c))
                .map(|(_, c)| (&c.kind, c.original.as_str())),
        )
    }

    fn record_removed(&mut self, kind: &EntityKind, original: &str) -> Result<(), StoreError> {
        if self.removed.iter().any(|(_, v)| v.as_str() == original) {
            return Ok(());
        }
        self.try_record_removed(kind, original)
            .map_err(|e| self.store_error(e))?;
        self.removed
            .push((kind.clone(), Zeroizing::new(original.to_string())));
        self.dict.note_removed(kind, original);
        Ok(())
    }

    fn removed_entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        Box::new(self.removed.iter().map(|(k, v)| (k, v.as_str())))
    }

    fn removed_marker(&self, kind: &EntityKind) -> String {
        format_token(&self.settings, kind, "REMOVED")
    }

    fn settings(&self) -> &TokenSettings {
        &self.settings
    }

    fn prepare(&mut self, tokens: &[String]) -> Result<(), StoreError> {
        self.try_prepare(tokens).map_err(|e| self.store_error(e))
    }

    fn surface_token(&mut self, parent: &Token, surface: &str) -> Result<Token, StoreError> {
        self.try_surface_token(parent.as_str(), surface)
            .map(Token::from)
            .map_err(|e| self.store_error(e))
    }

    /// The working set's dictionary (Task 7e): entries past their grace
    /// period are swept first, so the cache never answers for one.
    fn store_dict(
        &mut self,
        aliases: Option<&AliasTable>,
    ) -> Option<inumaki_core::Result<StoreDict>> {
        self.evict_expired();
        let mut cache = std::mem::take(&mut self.dict);
        let d = cache.get(&*self, aliases);
        self.dict = cache;
        Some(d)
    }

    /// The working set's leak-check index from the same cache (Task 5), as
    /// `store_dict`: expired entries are swept first.
    fn leak_index(
        &mut self,
        aliases: Option<&AliasTable>,
    ) -> Option<inumaki_core::Result<inumaki_core::verify::LeakIndex>> {
        self.evict_expired();
        let mut cache = std::mem::take(&mut self.dict);
        let d = cache.leak(&*self, aliases);
        self.dict = cache;
        Some(d)
    }

    fn link_candidates(&self, kind: &EntityKind, window: Duration) -> Vec<Zeroizing<String>> {
        let now = self.inner.now();
        let secs = i64::try_from(window.as_secs()).unwrap_or(i64::MAX);
        self.working
            .iter()
            .filter(|(_, c)| {
                c.kind == *kind
                    && c.key.is_some()
                    && c.surface_of.is_none()
                    && now - c.used_at <= secs
            })
            .map(|(_, c)| Zeroizing::new(c.original.to_string()))
            .collect()
    }
}
