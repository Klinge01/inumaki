//! Folder datasets in the daemon (M5 spec §11, §12): the registry the hook
//! reads, validation, add and remove, and the mirror service's start and
//! stop with its engine ([`MirrorGlue`], through the service module) and
//! manifest ([`VaultManifest`], in the vault).
//!
//! Nothing here logs or formats a path: errors and `Debug` output carry
//! fixed strings only.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock, TryLockError, Weak};

use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_mirror::fsops::{Dir, IoClass, delete_mirror_tree, map_errno};
use inumaki_mirror::{
    Activity, ActivityDirection, ActivityVerdict, Block, DatasetState, EngineError, Folder,
    FolderError, ManifestStore, Mirror, MirrorConfig, MirrorEngine, Outcome, Side, Snapshot,
};
use inumaki_vault::{
    DatasetKind, Direction, FrontDoor, KindCount, KindLabel, NewActivity, Vault, VaultError,
    Verdict,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cache::CachedOutcome;
use crate::engines::EngineError as DaemonEngineError;
use crate::pathcmp::{overlap, same, starts_with};
use crate::service::{self, BlockInput, RehydrateMode, ServiceError};
use crate::state::{AppState, StartError};

// The mirror withholds a file whose block exceeds its cap before calling;
// the service refuses the same size. The two must not drift apart.
const _: () = assert!(service::MAX_BLOCK_BYTES == MirrorConfig::MAX_BLOCK_BYTES);

/// A folder's stored configuration, sealed in the vault. The paths are
/// resolved (symlinks followed) once, when the folder is added.
#[derive(Clone, Serialize, Deserialize)]
pub struct FolderConfig {
    /// Resolved source.
    pub source: PathBuf,
    /// Resolved outbox destination.
    pub outbox_destination: PathBuf,
    /// Source root (device, inode) at add time; `None` when the root could
    /// not be read then (`EPERM`) and is learned at the first successful
    /// open.
    #[serde(default)]
    pub root_id: Option<(u64, u64)>,
}

impl std::fmt::Debug for FolderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FolderConfig")
    }
}

/// What `FolderBody` answers.
#[derive(Clone)]
pub struct FolderInfo {
    /// Dataset id.
    pub dataset: String,
    /// Opaque label (the mirror directory's name).
    pub label: String,
    /// Source directory.
    pub source: String,
    /// Mirror directory.
    pub mirror: String,
    /// Outbox directory inside the mirror.
    pub outbox: String,
    /// Where restored outbox files are written.
    pub outbox_destination: String,
    /// Unix seconds.
    pub created_at: i64,
}

impl std::fmt::Debug for FolderInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderInfo")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// A `400` with one of the spec §12.3 messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The source is relative.
    SourceNotAbsolute,
    /// The source is missing or not a directory.
    SourceNotDirectory,
    /// The source is the home directory.
    SourceIsHome,
    /// The source contains the mirror root, the data directory, or the home.
    SourceContainsProtected,
    /// The source is inside the mirror root or the data directory.
    SourceInsideProtected,
    /// The source contains, or is inside, another folder's source.
    SourceOverlaps,
    /// The destination is relative.
    DestNotAbsolute,
    /// The destination is inside the mirror root or the data directory.
    DestInsideProtected,
    /// The destination exists and is not a directory.
    DestNotDirectory,
}

impl Refusal {
    /// The fixed message, literally as in the spec's table.
    pub fn message(self) -> &'static str {
        match self {
            Refusal::SourceNotAbsolute => "source must be an absolute path",
            Refusal::SourceNotDirectory => "source must be an existing directory",
            Refusal::SourceIsHome => "source must not be the home directory",
            Refusal::SourceContainsProtected => {
                "source must not contain the mirror root, the data directory, or the home directory"
            }
            Refusal::SourceInsideProtected => {
                "source must not be inside the mirror root or the data directory"
            }
            Refusal::SourceOverlaps => "source overlaps another folder dataset",
            Refusal::DestNotAbsolute => "outbox_destination must be an absolute path",
            Refusal::DestInsideProtected => {
                "outbox_destination must not be inside the mirror root or the data directory"
            }
            Refusal::DestNotDirectory => "outbox_destination must be a directory",
        }
    }
}

/// Why add, remove, or rescan failed.
#[derive(Debug)]
pub enum AddError {
    /// `400` with a fixed message.
    Refused(Refusal),
    /// `400 reserved`: the proxy's reserved chat dataset (an `inumaki-` id
    /// or kind `chat`) never carries a folder.
    Reserved,
    /// `400`: the dataset's kind is not `folder`.
    WrongKind,
    /// `409`: the dataset already has a folder.
    Exists,
    /// `404 unknown dataset`.
    UnknownDataset,
    /// `500`: the vault failed.
    Vault(VaultError),
    /// `500`: the mirror service refused.
    Mirror(FolderError),
}

/// Why [`Folders::remove_dataset`] failed.
#[derive(Debug)]
pub enum RemoveDatasetError {
    /// The folder could not be removed; the dataset is kept.
    Folder(AddError),
    /// The dataset could not be deleted (its folder is already gone).
    Dataset(VaultError),
}

/// Paths validation compares against.
pub struct ValidateCtx {
    home: Option<PathBuf>,
    root: PathBuf,
    data_dir: PathBuf,
    others: Vec<PathBuf>,
}

impl ValidateCtx {
    /// For tests: home, mirror root, data directory, no other folders.
    pub fn for_test(home: &str, root: &str, data_dir: &str) -> Self {
        ValidateCtx {
            home: Some(home.into()),
            root: root.into(),
            data_dir: data_dir.into(),
            others: Vec::new(),
        }
    }

    /// For tests: the same context with other folders' sources.
    pub fn with_others(mut self, others: Vec<PathBuf>) -> Self {
        self.others = others;
        self
    }
}

/// A validated source, destination, and the source root's (device, inode).
pub type Validated = (PathBuf, PathBuf, Option<(u64, u64)>);

/// `.` and `..` removed lexically.
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// `p` with symlinks resolved where the OS allows it: the longest existing
/// ancestor is canonicalized and the rest appended after lexical
/// normalization. A destination that does not exist yet, or a source the OS
/// refuses to resolve (`EPERM`), still resolves through its ancestors.
fn resolve(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    let lex = lexical(p);
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let mut base = lex.clone();
    loop {
        if let Ok(c) = std::fs::canonicalize(&base) {
            return rest.iter().rev().fold(c, |acc, x| acc.join(x));
        }
        match base.file_name() {
            Some(name) => {
                rest.push(name.to_os_string());
                base.pop();
            }
            None => return lex,
        }
    }
}

/// Validate a source and destination (spec §12.3). `source_meta` is the
/// `metadata` result for `source`; `EPERM` accepts the folder with an
/// unknown root identity (spec §9.1). Returns the resolved source, the
/// resolved destination (empty when `dest` is `None`: the caller supplies
/// the default and validates that), and the source root's (device, inode).
/// "Inside" (equal included) is checked before "contains", so the mirror
/// root itself is refused as inside it.
pub fn validate(
    source: &Path,
    source_meta: std::io::Result<std::fs::Metadata>,
    dest: Option<&Path>,
    c: &ValidateCtx,
) -> Result<Validated, Refusal> {
    use std::os::unix::fs::MetadataExt;
    if !source.is_absolute() {
        return Err(Refusal::SourceNotAbsolute);
    }
    let (src, root_id) = match source_meta {
        Ok(m) if m.is_dir() => (resolve(source), Some((m.dev(), m.ino()))),
        Ok(_) => return Err(Refusal::SourceNotDirectory),
        // EPERM: macOS privacy protection. Not "missing": accepted, with
        // the root identity learned at the first successful open.
        Err(e) if e.raw_os_error() == Some(1) => (resolve(source), None),
        Err(_) => return Err(Refusal::SourceNotDirectory),
    };
    if c.home.as_deref().is_some_and(|h| same(h, &src)) {
        return Err(Refusal::SourceIsHome);
    }
    if starts_with(&src, &c.root) || starts_with(&src, &c.data_dir) {
        return Err(Refusal::SourceInsideProtected);
    }
    if starts_with(&c.root, &src)
        || starts_with(&c.data_dir, &src)
        || c.home.as_deref().is_some_and(|h| starts_with(h, &src))
    {
        return Err(Refusal::SourceContainsProtected);
    }
    if c.others.iter().any(|o| overlap(o, &src)) {
        return Err(Refusal::SourceOverlaps);
    }
    let Some(dest) = dest else {
        return Ok((src, PathBuf::new(), root_id));
    };
    if !dest.is_absolute() {
        return Err(Refusal::DestNotAbsolute);
    }
    let d = resolve(dest);
    if starts_with(&d, &c.root) || starts_with(&d, &c.data_dir) {
        return Err(Refusal::DestInsideProtected);
    }
    if std::fs::symlink_metadata(&d).is_ok_and(|m| !m.is_dir()) {
        return Err(Refusal::DestNotDirectory);
    }
    Ok((src, d, root_id))
}

/// The daemon's folders.
pub struct Folders {
    cfg: MirrorConfig,
    data_dir: PathBuf,
    entries: RwLock<BTreeMap<String, (Folder, i64)>>,
    /// Serializes add, remove, and start, so two overlapping sources added
    /// at once cannot both pass the overlap check and a folder added while
    /// the service starts is registered with it. The manifest's root-id
    /// update takes it too (never waiting: see [`VaultManifest`]).
    changing: Arc<Mutex<()>>,
    /// The root handle [`inumaki_mirror::prepare_root`] returned at load;
    /// the service takes it at start instead of opening the path again.
    /// `None` when the root could not be prepared.
    root_handle: Mutex<Option<Dir>>,
    mirror: OnceLock<Arc<Mirror>>,
    /// Hook tests answer the registry questions with a scripted registry
    /// (`AppState::folders` is set once, in `start`).
    #[cfg(feature = "test-fixtures")]
    registry_override: RwLock<Option<Arc<dyn crate::hook::FolderRegistry>>>,
}

impl std::fmt::Debug for Folders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Folders").finish_non_exhaustive()
    }
}

impl Folders {
    /// Spec §7.2 step 1: load every folder row and prepare the mirror root
    /// (0700 by `fchmod`, README), then keep its canonical path. A root that
    /// cannot be prepared (a symlink, not writable) does not stop the
    /// daemon: the mirror service later refuses to start
    /// (`mirror_unwritable`). A folder row whose configuration cannot be
    /// read stops the start: skipping it would leave its source unguarded
    /// by the hook. The mirror service is not started here.
    pub fn load(cfg: &MirrorConfig, vault: &Vault, data_dir: &Path) -> Result<Folders, StartError> {
        let config_invalid =
            |key: &str| StartError::Config(inumaki_core::Error::ConfigInvalid(key.into()));
        let data = resolve(data_dir);
        let outbox_root = resolve(&cfg.outbox_root);
        let mut stored = Vec::new();
        for (id, bytes, created_at) in vault.folders()? {
            let c: FolderConfig = serde_json::from_slice(&bytes)
                .map_err(|_| config_invalid("stored folder configuration"))?;
            stored.push((id, c, created_at));
        }
        // Stored paths were checked when added; the configuration may have
        // changed since (review I2). A root that now holds or sits in a
        // source, or a source or destination in the data directory or the
        // root, would let the hook exempt the source or the mirror feed on
        // itself. Checked against the root as configured before anything is
        // created there (8a re-review n1), and again after preparation
        // resolved it (the lexical check in `[mirror]` misses `/tmp/x`
        // against `/private/tmp/x/y`).
        let check = |root: &Path| -> Result<(), StartError> {
            if starts_with(root, &data) {
                return Err(config_invalid("mirror.root"));
            }
            if overlap(root, &outbox_root) {
                return Err(config_invalid("mirror.outbox_root"));
            }
            for (_, c, _) in &stored {
                if overlap(root, &c.source) {
                    return Err(config_invalid("mirror.root"));
                }
                if overlap(&data, &c.source)
                    || starts_with(&c.outbox_destination, &data)
                    || starts_with(&c.outbox_destination, root)
                {
                    return Err(config_invalid("stored folder configuration"));
                }
            }
            Ok(())
        };
        check(&resolve(&cfg.root))?;
        let mut cfg = cfg.clone();
        let mut root_handle = None;
        match inumaki_mirror::prepare_root(&cfg) {
            Ok((handle, canonical)) => {
                cfg.root = canonical;
                root_handle = Some(handle);
            }
            Err(e) => {
                tracing::warn!(error = e.as_str(), "mirror root not prepared");
                // Never follow the root's own last component: a symlink an
                // agent put there must not turn the hook's mirror exemption
                // into an exemption for what it points at.
                if let (Some(parent), Some(name)) = (cfg.root.parent(), cfg.root.file_name()) {
                    cfg.root = resolve(parent).join(name);
                }
            }
        }
        check(&cfg.root)?;
        let mut entries = BTreeMap::new();
        for (id, c, created_at) in stored {
            // The root id stored at add, or adopted later (`put_root_id`).
            let folder = Folder {
                label: vault.opaque_id(&id),
                dataset: id.clone(),
                source: c.source,
                outbox_destination: c.outbox_destination,
                root_id: c.root_id,
            };
            entries.insert(id, (folder, created_at));
        }
        Ok(Folders {
            cfg,
            data_dir: data,
            entries: RwLock::new(entries),
            changing: Arc::new(Mutex::new(())),
            root_handle: Mutex::new(root_handle),
            mirror: OnceLock::new(),
            #[cfg(feature = "test-fixtures")]
            registry_override: RwLock::new(None),
        })
    }

    /// Tests only (feature `test-fixtures`): answer the
    /// [`FolderRegistry`](crate::hook::FolderRegistry) methods from
    /// `registry` instead of the connected folders.
    #[cfg(feature = "test-fixtures")]
    #[doc(hidden)]
    pub fn override_registry_for_test(&self, registry: Arc<dyn crate::hook::FolderRegistry>) {
        *self
            .registry_override
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(registry);
    }

    #[cfg(feature = "test-fixtures")]
    fn overridden(&self) -> Option<Arc<dyn crate::hook::FolderRegistry>> {
        self.registry_override
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[cfg(not(feature = "test-fixtures"))]
    fn overridden(&self) -> Option<Arc<dyn crate::hook::FolderRegistry>> {
        None
    }

    /// Tests only (feature `test-fixtures`): the running mirror service,
    /// for its test seams (`Mirror::hold_source_opens`).
    #[cfg(feature = "test-fixtures")]
    #[doc(hidden)]
    pub fn mirror_for_test(&self) -> Option<Arc<Mirror>> {
        self.mirror.get().cloned()
    }

    /// The canonical mirror root.
    pub fn mirror_root(&self) -> &Path {
        &self.cfg.root
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, (Folder, i64)>> {
        self.entries.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn info(&self, f: &Folder, created_at: i64) -> FolderInfo {
        let mirror = self.cfg.root.join(&f.label);
        FolderInfo {
            dataset: f.dataset.clone(),
            label: f.label.clone(),
            source: f.source.display().to_string(),
            mirror: mirror.display().to_string(),
            outbox: mirror.join("outbox").display().to_string(),
            outbox_destination: f.outbox_destination.display().to_string(),
            created_at,
        }
    }

    /// Connect a folder (spec §12.2). Blocking. The dataset must exist and
    /// be of kind `folder`; a folder that cannot be registered with the
    /// running mirror service is not kept.
    pub fn add(
        &self,
        state: &AppState,
        dataset: &str,
        source: &str,
        dest: Option<&str>,
    ) -> Result<FolderInfo, AddError> {
        let _changing = self.changing.lock().unwrap_or_else(PoisonError::into_inner);
        // The reserved check comes first, also in process (the check sweep
        // and the end-to-end check call this directly).
        if dataset.starts_with(inumaki_vault::RESERVED_PREFIX) {
            return Err(AddError::Reserved);
        }
        match state.vault.dataset_kind(dataset) {
            Ok(DatasetKind::Folder) => {}
            Ok(DatasetKind::Chat) => return Err(AddError::Reserved),
            Ok(_) => return Err(AddError::WrongKind),
            Err(VaultError::DatasetNotFound(_)) => return Err(AddError::UnknownDataset),
            Err(e) => return Err(AddError::Vault(e)),
        }
        // A connected dataset answers 409 whatever the new source is (the
        // row-level `FolderExists` below stays as the backstop).
        if self.read().contains_key(dataset) {
            return Err(AddError::Exists);
        }
        let label = state.vault.opaque_id(dataset);
        let ctx = ValidateCtx {
            home: dirs::home_dir().map(|h| resolve(&h)),
            root: self.cfg.root.clone(),
            data_dir: self.data_dir.clone(),
            others: self
                .read()
                .values()
                .filter(|(f, _)| f.dataset != dataset)
                .map(|(f, _)| f.source.clone())
                .collect(),
        };
        let src = Path::new(source);
        // The default destination is validated like a given one.
        let default = self.cfg.outbox_root.join(&label);
        let requested = dest.map_or(default.as_path(), Path::new);
        let (source, destination, root_id) =
            validate(src, std::fs::metadata(src), Some(requested), &ctx)
                .map_err(AddError::Refused)?;
        let config = FolderConfig {
            source: source.clone(),
            outbox_destination: destination.clone(),
            root_id,
        };
        let bytes =
            serde_json::to_vec(&config).map_err(|_| AddError::Mirror(FolderError::Internal))?;
        match state.vault.create_folder(dataset, &bytes) {
            Ok(()) => {}
            Err(VaultError::FolderExists) => return Err(AddError::Exists),
            Err(VaultError::DatasetNotFound(_)) => return Err(AddError::UnknownDataset),
            Err(e) => return Err(AddError::Vault(e)),
        }
        let rollback = |state: &AppState| {
            if state.vault.remove_folder(dataset).is_err() {
                tracing::warn!("folder row could not be rolled back");
            }
        };
        // The creation time is the vault's own; a row that cannot be read
        // back is not kept.
        let created_at = match state.vault.folder(dataset) {
            Ok(Some((_, at))) => at,
            Ok(None) => {
                return Err(AddError::Mirror(FolderError::Internal));
            }
            Err(e) => {
                rollback(state);
                return Err(AddError::Vault(e));
            }
        };
        let folder = Folder {
            dataset: dataset.to_string(),
            label,
            source,
            outbox_destination: destination,
            root_id,
        };
        // The hook registry learns the folder before the service starts its
        // scan, so the registry always holds every folder the service runs.
        self.entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(dataset.to_string(), (folder.clone(), created_at));
        if let Some(m) = self.mirror.get() {
            if let Err(e) = m.add(folder.clone()) {
                // Not registered with the service: keep nothing.
                self.entries
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(dataset);
                rollback(state);
                return Err(AddError::Mirror(e));
            }
        }
        Ok(self.info(&folder, created_at))
    }

    /// Disconnect a folder (spec §12.2). Works before the service starts; a
    /// missing mirror root means there is no tree to delete. `false` when
    /// the dataset has no folder. Never touches the source or the
    /// destination.
    pub fn remove(&self, state: &AppState, dataset: &str) -> Result<bool, AddError> {
        let _changing = self.changing.lock().unwrap_or_else(PoisonError::into_inner);
        self.remove_locked(state, dataset)
    }

    /// Delete a dataset together with its folder. The add/remove mutex is
    /// held across both steps, so an add cannot land between the folder's
    /// removal and the dataset's deletion (it would register a folder the
    /// cascade then deletes the row of, leaving the service writing for a
    /// dataset that is gone and a mirror tree nothing removes). A dataset
    /// without a folder is just deleted. Blocking.
    pub fn remove_dataset(
        &self,
        state: &AppState,
        dataset: &str,
    ) -> Result<(), RemoveDatasetError> {
        let _changing = self.changing.lock().unwrap_or_else(PoisonError::into_inner);
        self.remove_locked(state, dataset)
            .map_err(RemoveDatasetError::Folder)?;
        state
            .delete_dataset(dataset)
            .map_err(RemoveDatasetError::Dataset)
    }

    /// [`remove`](Self::remove) for a caller that holds `changing`.
    fn remove_locked(&self, state: &AppState, dataset: &str) -> Result<bool, AddError> {
        let label = match self.read().get(dataset) {
            Some((f, _)) => f.label.clone(),
            // A failed rollback in `add` can leave a row without an entry:
            // the row is enough to remove the folder (and its tree).
            None => match state.vault.folder(dataset) {
                Ok(Some(_)) => state.vault.opaque_id(dataset),
                Ok(None) => return Ok(false),
                Err(e) => return Err(AddError::Vault(e)),
            },
        };
        // The service stops the folder's watchers and writers before it
        // deletes the tree (marker-checked). A folder the service does not
        // run (not started yet, or refused at start) has no writer: the
        // tree is deleted here, behind the same marker check.
        let removed = match self.mirror.get() {
            Some(m) => m.remove(dataset).map_err(AddError::Mirror)?,
            None => false,
        };
        if !removed {
            let unwritable = |_| AddError::Mirror(FolderError::MirrorUnwritable);
            // Before the service starts, through the handle prepared at load.
            let held = self
                .root_handle
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match held.as_ref() {
                Some(root) => {
                    delete_mirror_tree(root, &label).map_err(unwritable)?;
                }
                None => match Dir::open_root(&self.cfg.root) {
                    Ok(root) => {
                        delete_mirror_tree(&root, &label).map_err(unwritable)?;
                    }
                    Err(e) if map_errno(&e) == IoClass::NotFound => {}
                    Err(_) => return Err(AddError::Mirror(FolderError::MirrorUnwritable)),
                },
            }
        }
        state
            .vault
            .remove_folder(dataset)
            .map_err(AddError::Vault)?;
        // Dropped last, so the hook guards the source until the folder is
        // gone (spec §11).
        self.entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(dataset);
        Ok(true)
    }

    /// One folder.
    pub fn get(&self, dataset: &str) -> Option<FolderInfo> {
        self.read().get(dataset).map(|(f, at)| self.info(f, *at))
    }

    /// Every folder with its snapshot (`None` before the service starts).
    pub fn list(&self) -> Vec<(FolderInfo, Option<Snapshot>)> {
        let m = self.mirror.get();
        self.read()
            .values()
            .map(|(f, at)| (self.info(f, *at), m.and_then(|m| m.snapshot(&f.dataset))))
            .collect()
    }

    /// Full reconcile now (queued on the mirror's workers). `Ok(None)`
    /// without a folder; `Some(0)` before the service starts.
    pub fn rescan(&self, dataset: &str) -> Result<Option<u64>, AddError> {
        if !self.read().contains_key(dataset) {
            return Ok(None);
        }
        match self.mirror.get() {
            Some(m) => m.rescan(dataset).map_err(AddError::Mirror),
            None => Ok(Some(0)),
        }
    }
}

impl crate::hook::FolderRegistry for Folders {
    fn source_roots(&self) -> Vec<(String, PathBuf)> {
        if let Some(r) = self.overridden() {
            return r.source_roots();
        }
        self.read()
            .values()
            .map(|(f, _)| (f.dataset.clone(), f.source.clone()))
            .collect()
    }
    fn outbox_destinations(&self) -> Vec<(String, PathBuf)> {
        if let Some(r) = self.overridden() {
            return r.outbox_destinations();
        }
        self.read()
            .values()
            .map(|(f, _)| (f.dataset.clone(), f.outbox_destination.clone()))
            .collect()
    }
    fn mirror_root(&self) -> Option<PathBuf> {
        if let Some(r) = self.overridden() {
            return r.mirror_root();
        }
        Some(self.cfg.root.clone())
    }
}

/// The model manifest compiled into this binary (policy fingerprint).
const MODEL_MANIFEST: &[u8] = include_bytes!("../../../models/manifest.toml");

impl Folders {
    /// Start the mirror service (spec §7.2 step 2): after the check sweep,
    /// before the gateway loads datasets. It takes the root handle prepared
    /// at load (never the path again) and registers every stored folder
    /// with its root id. A root that could not be prepared leaves the
    /// service stopped (`mirror_unwritable`). Blocking; once.
    pub fn start(&self, state: &Arc<AppState>) {
        let _changing = self.changing.lock().unwrap_or_else(PoisonError::into_inner);
        if self.mirror.get().is_some() {
            return;
        }
        let Some(root) = self
            .root_handle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            tracing::warn!(
                error = FolderError::MirrorUnwritable.as_str(),
                "mirror service not started"
            );
            return;
        };
        let engine: Arc<dyn MirrorEngine> = Arc::new(MirrorGlue {
            state: Arc::downgrade(state),
            policy_base: OnceLock::new(),
        });
        let manifest: Arc<dyn ManifestStore> = Arc::new(VaultManifest {
            vault: state.vault.clone(),
            changing: Arc::clone(&self.changing),
        });
        let m = match Mirror::with_root(
            self.cfg.clone(),
            root,
            self.cfg.root.clone(),
            engine,
            manifest,
        ) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = e.as_str(), "mirror service not started");
                return;
            }
        };
        let entries = self.read();
        for (f, _) in entries.values() {
            if let Err(e) = m.register(f.clone()) {
                tracing::warn!(folder = %f.label, error = e.as_str(), "folder not registered");
            }
        }
        let n = entries.len();
        drop(entries);
        m.start();
        let _ = self.mirror.set(m);
        tracing::info!(folders = n, "mirror service started");
    }

    /// Stop the mirror service (shutdown). Blocking: waits for the jobs in
    /// flight, at most the service's stop deadline (a job parked behind a
    /// macOS prompt is left to the process exit).
    pub fn stop(&self) {
        if let Some(m) = self.mirror.get() {
            m.stop();
        }
    }
}

/// The engine, through the service module. Holds the state weakly: the
/// state owns the service.
struct MirrorGlue {
    state: Weak<AppState>,
    /// SHA-256 of the configuration fingerprint and the model manifest,
    /// which do not change while the daemon runs; hashed once.
    policy_base: OnceLock<[u8; 32]>,
}

fn map_service(e: ServiceError) -> EngineError {
    match e {
        ServiceError::Vault(VaultError::DatasetNotFound(_) | VaultError::Closed) => {
            EngineError::DatasetGone
        }
        ServiceError::Vault(_) | ServiceError::Store(_) => EngineError::VaultUnavailable,
        ServiceError::Engine(DaemonEngineError::Unavailable { .. }) => {
            EngineError::ModelUnavailable
        }
        ServiceError::Engine(_) => EngineError::Internal("profile"),
        ServiceError::Unresolved { unknown, removed } => {
            EngineError::Unresolved { unknown, removed }
        }
        ServiceError::Redaction(_) => EngineError::Internal("redactions"),
        ServiceError::Unsupported(c) => EngineError::Internal(c),
    }
}

fn map_vault(e: VaultError) -> EngineError {
    map_service(ServiceError::Vault(e))
}

/// The mirror's block: text only for `Pass` (an uncertain block is
/// withheld by the mirror and needs none).
fn block(r: service::BlockResult) -> Block {
    let outcome = match r.outcome {
        CachedOutcome::Pass => Outcome::Pass,
        CachedOutcome::PassUncertain => Outcome::Uncertain,
        CachedOutcome::Blocked => Outcome::Blocked,
    };
    Block {
        text: if outcome == Outcome::Pass {
            r.text
        } else {
            String::new()
        },
        outcome,
        kinds: r.kinds,
    }
}

impl MirrorGlue {
    fn app(&self) -> Result<Arc<AppState>, EngineError> {
        self.state
            .upgrade()
            .ok_or(EngineError::Internal("daemon_stopped"))
    }
}

impl MirrorEngine for MirrorGlue {
    fn sanitize(&self, dataset: &str, blocks: Vec<String>) -> Result<Vec<Block>, EngineError> {
        let s = self.app()?;
        // The bounded path (spec §5.1): a block over the cap withholds the
        // whole batch before the namespace is touched.
        Ok(service::sanitize_bounded(&s, dataset, blocks)
            .map_err(map_service)?
            .into_iter()
            .map(block)
            .collect())
    }
    fn sanitize_names(&self, dataset: &str, stems: Vec<String>) -> Result<Vec<Block>, EngineError> {
        let s = self.app()?;
        Ok(service::sanitize_names(&s, dataset, stems)
            .map_err(map_service)?
            .into_iter()
            .map(block)
            .collect())
    }
    fn rehydrate_strict(
        &self,
        dataset: &str,
        blocks: Vec<String>,
    ) -> Result<Vec<String>, EngineError> {
        let s = self.app()?;
        let inputs = blocks.into_iter().map(BlockInput::text).collect();
        // Strict: one unresolved placeholder fails the whole file
        // (`Unresolved`), and the mirror writes nothing.
        Ok(
            service::rehydrate_blocks(&s, dataset, inputs, RehydrateMode::Strict)
                .map_err(map_service)?
                .into_iter()
                .map(|r| r.text)
                .collect(),
        )
    }
    fn known_in_clear(
        &self,
        dataset: &str,
        texts: &[String],
    ) -> Result<Vec<Option<EntityKind>>, EngineError> {
        let s = self.app()?;
        service::known_in_clear(&s, dataset, texts).map_err(map_service)
    }
    fn scan_clear(
        &self,
        dataset: &str,
        texts: &[String],
    ) -> Result<Vec<(String, u32)>, EngineError> {
        let s = self.app()?;
        Ok(service::scan_clear(&s, dataset, texts)
            .map_err(map_service)?
            .into_iter()
            .map(|(k, n)| (k.label().to_string(), n))
            .collect())
    }
    fn state(&self, dataset: &str) -> Result<DatasetState, EngineError> {
        use sha2::{Digest, Sha256};
        let s = self.app()?;
        // Called per file: indexed lookups only, no entry count (8b review I2).
        let (profile, epoch_id) = s.vault.dataset_state(dataset).map_err(map_vault)?;
        let base = self.policy_base.get_or_init(|| {
            let mut h = Sha256::new();
            h.update(s.config_fingerprint);
            h.update(MODEL_MANIFEST);
            h.finalize().into()
        });
        let mut h = Sha256::new();
        h.update(profile.as_bytes());
        h.update([0]);
        h.update(base);
        Ok(DatasetState {
            epoch_id,
            entries_generation: s.vault.entries_generation(dataset),
            fingerprint: h.finalize().into(),
        })
    }
    fn carry_known(&self, dataset: &str) -> Result<u64, EngineError> {
        // Spec §7.3 (amended 2026-10-04, review Cr2): the previous epoch's
        // known originals are minted in the current epoch (fresh tokens)
        // and the detector rebuilt, before the mirror re-mirrors. A lookup
        // for an original the current epoch already has.
        let s = self.app()?;
        let previous = s.vault.previous_epoch_known(dataset).map_err(map_vault)?;
        if previous.is_empty() {
            return Ok(0);
        }
        let ns = s.namespace(dataset).map_err(map_vault)?;
        let mut n = ns.lock().unwrap_or_else(PoisonError::into_inner);
        n.refresh().map_err(map_vault)?;
        for (kind, original) in &previous {
            n.token_for(kind, original)
                .map_err(|e| map_service(ServiceError::Store(e)))?;
        }
        n.rebuild_detector_now().map_err(map_vault)?;
        Ok(previous.len() as u64)
    }
    fn record(&self, a: Activity) {
        let Ok(s) = self.app() else { return };
        let rec = NewActivity {
            dataset: s.vault.opaque_ref(&a.dataset),
            front_door: FrontDoor::Mirror,
            upstream: None,
            direction: match a.direction {
                ActivityDirection::Result => Direction::Result,
                ActivityDirection::Arguments => Direction::Arguments,
            },
            verdict: match a.verdict {
                ActivityVerdict::Released => Verdict::Released,
                ActivityVerdict::Blocked => Verdict::Blocked,
                ActivityVerdict::Uncertain => Verdict::Uncertain,
                ActivityVerdict::Unresolved => Verdict::Unresolved,
            },
            checks: Vec::new(),
            kinds: a
                .kinds
                .iter()
                .map(|(k, n)| KindCount {
                    kind: KindLabel::of(k),
                    count: *n,
                })
                .collect(),
            tripwire: a.tripwire,
            bytes: a.bytes,
            released: None,
        };
        if s.vault.append_activity(rec).is_err() {
            tracing::warn!("mirror activity record not written");
        }
    }
}

/// The manifest, in the vault; the root id in the folder's sealed config.
struct VaultManifest {
    vault: Vault,
    /// [`Folders::changing`]: a root-id update never interleaves with an
    /// add or a remove of the same dataset.
    changing: Arc<Mutex<()>>,
}

impl ManifestStore for VaultManifest {
    fn put(&self, dataset: &str, side: Side, rel: &[u8], record: &[u8]) -> Result<(), EngineError> {
        self.vault
            .mirror_put(dataset, side.as_str(), rel, record)
            .map_err(map_vault)
    }
    fn delete(&self, dataset: &str, side: Side, rel: &[u8]) -> Result<(), EngineError> {
        self.vault
            .mirror_delete(dataset, side.as_str(), rel)
            .map_err(map_vault)
    }
    fn list(&self, dataset: &str, side: Side) -> Result<Vec<Vec<u8>>, EngineError> {
        Ok(self
            .vault
            .mirror_list(dataset, side.as_str())
            .map_err(map_vault)?
            .into_iter()
            .map(|z| z.to_vec())
            .collect())
    }
    fn clear(&self, dataset: &str) -> Result<(), EngineError> {
        self.vault.mirror_clear(dataset).map_err(map_vault)
    }
    fn mac(&self, domain: &str, data: &[u8]) -> [u8; 32] {
        self.vault.keyed_mac(domain, data)
    }
    /// Store an adopted root id in the folder's sealed config (spec §6.2,
    /// §9.1; 5c review I2). A folder without config (removed meanwhile; the
    /// poller can run after a removal) is a no-op; a stored id is never
    /// replaced. The id is stored only
    /// while the stored source still names that directory, so a late call
    /// from a removed folder never lands in a folder added again at the same
    /// dataset. Never waits for an add or remove in progress (a removal
    /// waits for the job that calls this): it fails and is retried.
    fn put_root_id(&self, dataset: &str, root_id: (u64, u64)) -> Result<(), EngineError> {
        use std::os::unix::fs::MetadataExt;
        let _changing = match self.changing.try_lock() {
            Ok(g) => g,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return Err(EngineError::Internal("folder_busy")),
        };
        let Some((bytes, _)) = self.vault.folder(dataset).map_err(map_vault)? else {
            return Ok(());
        };
        let mut c: FolderConfig =
            serde_json::from_slice(&bytes).map_err(|_| EngineError::Internal("folder_config"))?;
        // Only an unknown id is filled; a stored one is never replaced
        // (8b review M3).
        match c.root_id {
            Some(stored) if stored == root_id => return Ok(()),
            Some(_) => return Err(EngineError::Internal("root_id")),
            None => {}
        }
        let at_source = std::fs::symlink_metadata(&c.source)
            .ok()
            .filter(std::fs::Metadata::is_dir)
            .map(|m| (m.dev(), m.ino()));
        if at_source != Some(root_id) {
            return Err(EngineError::Internal("root_id"));
        }
        c.root_id = Some(root_id);
        let out = Zeroizing::new(
            serde_json::to_vec(&c).map_err(|_| EngineError::Internal("folder_config"))?,
        );
        // `false`: removed since the read (cannot happen under the lock,
        // and would be the no-op above).
        self.vault
            .update_folder_config(dataset, &out)
            .map(|_| ())
            .map_err(map_vault)
    }
}
