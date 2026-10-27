//! A connected folder, its in-memory index of the manifest, and the
//! manifest record shapes (M5 spec §7.1). Records are JSON, sealed by the
//! store.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::engine::{DatasetState, EngineError, ManifestStore, Side};
use crate::status::{Counts, Status};

/// A connected folder. `Debug` prints the label only.
#[derive(Clone, PartialEq, Eq)]
pub struct Folder {
    /// Dataset id.
    pub dataset: String,
    /// Opaque label (the mirror directory's name).
    pub label: String,
    /// Resolved source root.
    pub source: PathBuf,
    /// Resolved outbox destination.
    pub outbox_destination: PathBuf,
    /// Root (device, inode) at add time; `None` when it could not be read then.
    pub root_id: Option<(u64, u64)>,
}

impl std::fmt::Debug for Folder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Folder")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// Why a placeholder was written (spec §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    UnsupportedFormat,
    TooLarge,
    Unreadable,
    SymbolicLink,
    Blocked,
    Uncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileState {
    Mirrored,
    Blocked,
    Unsupported,
    Pending,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SourceRecord {
    pub rel: Vec<u8>,
    pub mirror_rel: Vec<u8>,
    pub size: u64,
    pub mtime: (i64, i64),
    pub content_mac: [u8; 32],
    pub epoch_id: i64,
    pub fingerprint: [u8; 32],
    pub state: FileState,
    pub reason: Option<Reason>,
    pub mirrored_at: i64,
}

/// A directory's mirror name for one epoch and policy fingerprint (spec
/// §4.3 rule 5) and its full mirror path, so removing a directory needs no
/// engine and also reaches subtrees still on an older epoch's names (review
/// I4).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct DirRecord {
    pub rel: Vec<u8>,
    pub epoch_id: i64,
    /// The policy fingerprint the name was sanitized under: a name an older
    /// policy or model left in clear is sanitized again on a same-epoch
    /// re-mirror (5b review I1). Missing in older records: zeros, which a
    /// real fingerprint (a hash) never equals, so those names are redone.
    #[serde(default)]
    pub fingerprint: [u8; 32],
    pub component: String,
    pub mirror_rel: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutboxOutcome {
    Rehydrated,
    Unresolved,
    Refused,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OutboxRecord {
    pub rel: Vec<u8>,
    pub content_mac: [u8; 32],
    pub destination_rel: Option<Vec<u8>>,
    pub outcome: OutboxOutcome,
}

/// The manifest, in memory. Read `files` and `dirs` freely; change them only
/// through `insert_*` / `remove_*`, which keep the mirror-name map in step.
#[derive(Default)]
pub(crate) struct Index {
    pub files: HashMap<Vec<u8>, SourceRecord>,
    pub dirs: HashMap<Vec<u8>, DirRecord>,
    pub outbox: HashMap<Vec<u8>, OutboxRecord>,
    /// Case-folded mirror path -> the source entries (files and directories)
    /// that hold it; makes `mirror_taken` O(1) during a first scan.
    names: HashMap<String, Vec<Vec<u8>>>,
}

impl Index {
    pub(crate) fn load(m: &dyn ManifestStore, dataset: &str) -> Result<Index, EngineError> {
        let mut ix = Index::default();
        for b in m.list(dataset, Side::Source)? {
            let r: SourceRecord =
                serde_json::from_slice(&b).map_err(|_| EngineError::Internal("manifest"))?;
            ix.insert_file(r);
        }
        for b in m.list(dataset, Side::Dir)? {
            let r: DirRecord =
                serde_json::from_slice(&b).map_err(|_| EngineError::Internal("manifest"))?;
            ix.insert_dir(r);
        }
        for b in m.list(dataset, Side::Outbox)? {
            let r: OutboxRecord =
                serde_json::from_slice(&b).map_err(|_| EngineError::Internal("manifest"))?;
            ix.outbox.insert(r.rel.clone(), r);
        }
        Ok(ix)
    }

    pub(crate) fn counts(&self) -> Counts {
        let mut c = Counts::default();
        for r in self.files.values() {
            match r.state {
                FileState::Mirrored => c.mirrored += 1,
                FileState::Blocked => c.blocked += 1,
                FileState::Unsupported => c.unsupported += 1,
                FileState::Pending => {}
            }
        }
        c
    }

    /// `(rehydrated, with_unresolved)` from the outbox records (review
    /// minor: the counts survive a restart).
    pub(crate) fn outbox_counts(&self) -> (u64, u64) {
        let mut c = (0, 0);
        for r in self.outbox.values() {
            match r.outcome {
                OutboxOutcome::Rehydrated => c.0 += 1,
                OutboxOutcome::Unresolved => c.1 += 1,
                OutboxOutcome::Refused => {}
            }
        }
        c
    }

    fn claim(&mut self, mirror_rel: &[u8], rel: &[u8]) {
        let k = crate::names::casefold(&String::from_utf8_lossy(mirror_rel));
        self.names.entry(k).or_default().push(rel.to_vec());
    }

    fn release(&mut self, mirror_rel: &[u8], rel: &[u8]) {
        let k = crate::names::casefold(&String::from_utf8_lossy(mirror_rel));
        if let Some(owners) = self.names.get_mut(&k) {
            if let Some(i) = owners.iter().position(|o| o == rel) {
                owners.swap_remove(i);
            }
            if owners.is_empty() {
                self.names.remove(&k);
            }
        }
    }

    pub(crate) fn insert_file(&mut self, r: SourceRecord) {
        self.claim(&r.mirror_rel, &r.rel);
        if let Some(old) = self.files.insert(r.rel.clone(), r) {
            self.release(&old.mirror_rel, &old.rel);
        }
    }

    pub(crate) fn remove_file(&mut self, rel: &[u8]) {
        if let Some(old) = self.files.remove(rel) {
            self.release(&old.mirror_rel, &old.rel);
        }
    }

    pub(crate) fn insert_dir(&mut self, r: DirRecord) {
        self.claim(&r.mirror_rel, &r.rel);
        if let Some(old) = self.dirs.insert(r.rel.clone(), r) {
            self.release(&old.mirror_rel, &old.rel);
        }
    }

    pub(crate) fn remove_dir(&mut self, rel: &[u8]) {
        if let Some(old) = self.dirs.remove(rel) {
            self.release(&old.mirror_rel, &old.rel);
        }
    }

    /// Claim `mirror_rel` for `rel` unless another entry owns it (checked
    /// and claimed under one lock, so two workers cannot both take a name);
    /// `false` when taken. Every successful call is paired with
    /// [`unreserve`](Self::unreserve) once the record is written or the
    /// write abandoned.
    pub(crate) fn reserve(&mut self, mirror_rel: &[u8], rel: &[u8]) -> bool {
        let folded = crate::names::casefold(&String::from_utf8_lossy(mirror_rel));
        if self.mirror_taken(&folded, rel) {
            return false;
        }
        self.claim(mirror_rel, rel);
        true
    }

    /// Drop one [`reserve`](Self::reserve) claim.
    pub(crate) fn unreserve(&mut self, mirror_rel: &[u8], rel: &[u8]) {
        self.release(mirror_rel, rel);
    }

    /// Some entry (a record or a reservation) holds this mirror path,
    /// compared NFC and case-folded.
    pub(crate) fn claimed(&self, mirror_rel: &[u8]) -> bool {
        self.names
            .contains_key(&crate::names::casefold(&String::from_utf8_lossy(
                mirror_rel,
            )))
    }

    /// The mirror-name claims are exactly those of the records: no
    /// reservation outlived its write (5b review N2).
    pub(crate) fn claims_match_records(&self) -> bool {
        let mut want: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        let records = self
            .files
            .values()
            .map(|r| (&r.mirror_rel, &r.rel))
            .chain(self.dirs.values().map(|r| (&r.mirror_rel, &r.rel)));
        for (m, r) in records {
            want.entry(crate::names::casefold(&String::from_utf8_lossy(m)))
                .or_default()
                .push(r.clone());
        }
        let sorted = |m: &HashMap<String, Vec<Vec<u8>>>| {
            let mut v: Vec<(String, Vec<Vec<u8>>)> = m
                .iter()
                .map(|(k, o)| {
                    let mut o = o.clone();
                    o.sort();
                    (k.clone(), o)
                })
                .collect();
            v.sort();
            v
        };
        sorted(&want) == sorted(&self.names)
    }

    /// Another source entry (file or directory) already owns this mirror
    /// path, compared NFC and case-folded (spec §4.3 rule 4).
    pub(crate) fn mirror_taken(&self, mirror_rel_folded: &str, except: &[u8]) -> bool {
        self.names
            .get(mirror_rel_folded)
            .is_some_and(|owners| owners.iter().any(|o| o != except))
    }
}

/// The source root's (device, inode) as the mirror knows it (spec §6.2).
#[derive(Clone, Copy)]
pub(crate) struct RootId {
    /// Stored when the folder was added, or adopted at the first open.
    pub id: Option<(u64, u64)>,
    /// `id` is the root the mirror was built from: stored at add time, or
    /// adopted in this run before anything was mirrored. Only then may a
    /// source that is not seen delete anything (5c review I2): an id adopted
    /// over a non-empty manifest may be an empty mount point.
    pub trusted: bool,
    /// `id` is stored in the vault (`ManifestStore::put_root_id`).
    pub persisted: bool,
}

/// A registered folder at run time.
pub(crate) struct FolderRt {
    pub folder: Folder,
    pub status: Mutex<Status>,
    pub index: Mutex<Index>,
    /// Workers hold it for reading while they work; removal takes it for
    /// writing and sets it to `false`.
    pub alive: RwLock<bool>,
    pub root_id: Mutex<RootId>,
    /// Last state the poller read (for snapshots).
    pub last_state: Mutex<Option<DatasetState>>,
    /// The epoch the previous epoch's known originals were carried into
    /// (review Cr2).
    pub carried_epoch: Mutex<Option<i64>>,
    /// The entries generation the last *completed* tripwire pass started
    /// from (review Cr1).
    pub tripwire_generation: Mutex<Option<u64>>,
    pub last_tripwire: Mutex<Option<Instant>>,
    pub last_rescan: Mutex<Option<Instant>>,
    /// Since when a first open of the source or the outbox destination has
    /// been in progress (TCC spike finding 2: macOS blocks that `open()`
    /// while its privacy prompt is on screen). Set and cleared around the
    /// IO, never held across it, so a snapshot reads it without waiting.
    pub opening: Mutex<Option<Instant>>,
    /// A source listing or read succeeded in this process: later source
    /// opens are not marked (a slow large read is not `pending`).
    pub source_seen: AtomicBool,
    /// The outbox destination opened in this process.
    pub dest_seen: AtomicBool,
}

/// Which side of a folder an open reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenSide {
    Source,
    Destination,
}

/// Marks a first open as in progress until it is dropped
/// ([`FolderRt::begin_open`]).
pub(crate) struct OpenMark<'a>(Option<&'a Mutex<Option<Instant>>>);

impl Drop for OpenMark<'_> {
    fn drop(&mut self) {
        if let Some(m) = self.0 {
            *m.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }
    }
}

impl FolderRt {
    pub(crate) fn new(folder: Folder, index: Index) -> FolderRt {
        let root_id = RootId {
            id: folder.root_id,
            trusted: folder.root_id.is_some(),
            persisted: folder.root_id.is_some(),
        };
        FolderRt {
            folder,
            status: Mutex::new(Status::default()),
            index: Mutex::new(index),
            alive: RwLock::new(true),
            root_id: Mutex::new(root_id),
            last_state: Mutex::new(None),
            carried_epoch: Mutex::new(None),
            tripwire_generation: Mutex::new(None),
            last_tripwire: Mutex::new(None),
            last_rescan: Mutex::new(None),
            opening: Mutex::new(None),
            source_seen: AtomicBool::new(false),
            dest_seen: AtomicBool::new(false),
        }
    }

    fn seen(&self, side: OpenSide) -> &AtomicBool {
        match side {
            OpenSide::Source => &self.source_seen,
            OpenSide::Destination => &self.dest_seen,
        }
    }

    /// Mark an open of `side` as in progress, unless one already succeeded
    /// in this process. The mark ends when the returned guard is dropped.
    /// At most one job of a folder runs at a time, so marks never overlap.
    pub(crate) fn begin_open(&self, side: OpenSide) -> OpenMark<'_> {
        if self.seen(side).load(Ordering::Acquire) {
            return OpenMark(None);
        }
        *self.opening.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        OpenMark(Some(&self.opening))
    }

    /// A listing or read of `side` succeeded: later opens are not marked.
    pub(crate) fn opened(&self, side: OpenSide) {
        self.seen(side).store(true, Ordering::Release);
    }

    /// A marked open has been in progress for at least `after`.
    pub(crate) fn open_pending(&self, after: Duration) -> bool {
        self.opening
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some_and(|t| t.elapsed() >= after)
    }

    pub(crate) fn put_file(
        &self,
        m: &dyn ManifestStore,
        r: SourceRecord,
    ) -> Result<(), EngineError> {
        let bytes = serde_json::to_vec(&r).map_err(|_| EngineError::Internal("manifest"))?;
        m.put(&self.folder.dataset, Side::Source, &r.rel, &bytes)?;
        self.index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert_file(r);
        Ok(())
    }

    pub(crate) fn drop_file(&self, m: &dyn ManifestStore, rel: &[u8]) -> Result<(), EngineError> {
        m.delete(&self.folder.dataset, Side::Source, rel)?;
        self.index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove_file(rel);
        Ok(())
    }

    pub(crate) fn put_dir(&self, m: &dyn ManifestStore, r: DirRecord) -> Result<(), EngineError> {
        let bytes = serde_json::to_vec(&r).map_err(|_| EngineError::Internal("manifest"))?;
        m.put(&self.folder.dataset, Side::Dir, &r.rel, &bytes)?;
        self.index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert_dir(r);
        Ok(())
    }

    pub(crate) fn drop_dir(&self, m: &dyn ManifestStore, rel: &[u8]) -> Result<(), EngineError> {
        m.delete(&self.folder.dataset, Side::Dir, rel)?;
        self.index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove_dir(rel);
        Ok(())
    }

    pub(crate) fn put_outbox(
        &self,
        m: &dyn ManifestStore,
        r: OutboxRecord,
    ) -> Result<(), EngineError> {
        let bytes = serde_json::to_vec(&r).map_err(|_| EngineError::Internal("manifest"))?;
        m.put(&self.folder.dataset, Side::Outbox, &r.rel, &bytes)?;
        self.index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outbox
            .insert(r.rel.clone(), r);
        Ok(())
    }

    /// Delete an outbox record (its file left the outbox).
    pub(crate) fn drop_outbox(&self, m: &dyn ManifestStore, rel: &[u8]) -> Result<(), EngineError> {
        m.delete(&self.folder.dataset, Side::Outbox, rel)?;
        self.index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outbox
            .remove(rel);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(rel: &str, mirror: &str) -> SourceRecord {
        SourceRecord {
            rel: rel.as_bytes().to_vec(),
            mirror_rel: mirror.as_bytes().to_vec(),
            size: 0,
            mtime: (0, 0),
            content_mac: [0; 32],
            epoch_id: 1,
            fingerprint: [0; 32],
            state: FileState::Mirrored,
            reason: None,
            mirrored_at: 0,
        }
    }

    #[test]
    fn mirror_names_are_claimed_folded_and_released() {
        let mut ix = Index::default();
        ix.insert_file(file("a.txt", "Report.txt"));
        // Another entry on the same folded name is a collision; the owner is not.
        assert!(ix.mirror_taken("report.txt", b"B.txt"));
        assert!(!ix.mirror_taken("report.txt", b"a.txt"));
        // Re-pointing the record frees the old name.
        ix.insert_file(file("a.txt", "other.txt"));
        assert!(!ix.mirror_taken("report.txt", b"B.txt"));
        assert!(ix.mirror_taken("other.txt", b"B.txt"));
        ix.remove_file(b"a.txt");
        assert!(!ix.mirror_taken("other.txt", b"B.txt"));
    }
}
