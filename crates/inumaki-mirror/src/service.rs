//! The mirror service (M5 spec §6.5, §7.2, §7.3): folders, workers, the
//! poller, watches. Blocking threads; nothing here needs a Tokio runtime.
//!
//! Concurrency rules:
//! - At most one job of a folder runs at a time ([`WorkQueue`] keeps the
//!   others queued), so a whole-folder reconcile, a tripwire pass, a
//!   removal, and a file of the same folder never overlap. Other folders'
//!   jobs run on the other workers.
//! - The poller and the watcher callbacks only read state and push jobs;
//!   every change to a mirror tree happens in a job.
//! - A worker holds its folder's `alive` lock for reading while it runs a
//!   job. [`Mirror::remove`] takes it for writing, after the watchers are
//!   gone and the queue is purged, and only then deletes the tree.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, TryLockError, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::config::MirrorConfig;
use crate::engine::{EngineError, ManifestStore, MirrorEngine};
use crate::folder::{Folder, FolderRt, Index};
use crate::fsops::{self, Dir, IoClass, Kind, MARKER, map_errno};
use crate::names::OUTBOX;
use crate::pipeline::{self, Ctx, Step};
use crate::queue::{Job, Priority, WorkQueue};
use crate::status::{FolderError, OutboxCounts, PENDING_AFTER, Snapshot};
use crate::watch::{self, Signal, Watch};
use crate::{guard, outbox, reconcile};

const README: &str = "This folder is maintained by inumaki.\n\n\
Each subfolder is a sanitized copy of a folder you connected: names and\n\
identifiers are replaced by tokens such as <PERSON_a7f2c9>. The copy is\n\
one-way; changes here are overwritten.\n\n\
Files written into a subfolder's outbox/ are restored with the real names\n\
and saved to that folder's outbox destination. A file that contains a\n\
token inumaki cannot restore is not saved; a note next to it says so.\n";

/// How often the poller wakes (retries, removals, watch polls).
const TICK: Duration = Duration::from_millis(250);

/// How long [`Mirror::remove`] waits for the folder's job in flight. A
/// first open may wait on a macOS privacy prompt for as long as it is on
/// screen (TCC spike finding 2); past this the removal answers `busy`.
const REMOVE_WAIT: Duration = Duration::from_secs(5);

/// How long [`Mirror::stop`] waits for its threads. A worker still parked
/// in an open after this is left behind; process exit ends it.
const STOP_WAIT: Duration = Duration::from_secs(3);

/// How often the bounded waits above look again.
const WAIT_STEP: Duration = Duration::from_millis(10);

/// Create the mirror root if missing, refuse a symlinked root, set 0700 on
/// the open handle (`fchmod`), write `README.txt`, and return the handle
/// and the canonical path (spec §4.1, §7.2 step 1). The daemon calls it in
/// `AppState::start`, the service again when it is built.
///
/// A root this call creates gets a root marker ([`fsops::ROOT_MARKER`])
/// first. An existing directory is adopted only when it carries a valid
/// marker or is empty; any other directory (the user's own, a project
/// checkout) is refused as `MirrorUnwritable` before anything is changed:
/// no `fchmod`, no write, no README replaced.
pub fn prepare_root(cfg: &MirrorConfig) -> Result<(Dir, PathBuf), FolderError> {
    let unwritable = |_: io::Error| FolderError::MirrorUnwritable;
    let name = cfg.root.file_name().ok_or(FolderError::MirrorUnwritable)?;
    let parent = cfg.root.parent().ok_or(FolderError::MirrorUnwritable)?;
    std::fs::create_dir_all(parent).map_err(unwritable)?;
    // The parents may be symlinks (a home on another volume); only the
    // root's own last component must not be one (`O_NOFOLLOW` below).
    let parent =
        Dir::open_root(&std::fs::canonicalize(parent).map_err(unwritable)?).map_err(unwritable)?;
    // Created or not, the directory opened next is checked: another one may
    // have been renamed into its place since `mkdirat` (8a re-review n2).
    parent.mkdir_new(name, 0o700).map_err(unwritable)?;
    let root = parent.child(name).map_err(unwritable)?;
    let marked = matches!(
        root.read_file(OsStr::new(fsops::ROOT_MARKER), 64),
        Ok((b, _, _)) if b == fsops::ROOT_MARKER_BODY
    );
    if !marked && !root.entries().map_err(unwritable)?.is_empty() {
        return Err(FolderError::MirrorUnwritable);
    }
    // Marker before README: a crash in between leaves a marked root.
    root.write_atomic(
        OsStr::new(fsops::ROOT_MARKER),
        fsops::ROOT_MARKER_BODY,
        0o444,
        None,
    )
    .map_err(unwritable)?;
    root.set_mode(0o700).map_err(unwritable)?;
    // Only a root marked by an earlier run gets its README replaced. In a
    // root adopted empty, a README that appeared after the emptiness check
    // is not ours and is left alone.
    let readme = OsStr::new("README.txt");
    if marked {
        root.write_atomic(readme, README.as_bytes(), 0o444, None)
            .map_err(unwritable)?;
    } else {
        match root.write_new(readme, README.as_bytes(), 0o444) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(unwritable(e)),
        }
    }
    let canonical = std::fs::canonicalize(&cfg.root).map_err(unwritable)?;
    // The reported path (FolderBody, `additionalDirectories`) must name the
    // directory the handle writes to, not a symlink swapped in meanwhile.
    let m = root.meta().map_err(unwritable)?;
    if plain_dir(&canonical) != Some((m.dev, m.ino)) {
        return Err(FolderError::MirrorUnwritable);
    }
    Ok((root, canonical))
}

/// `<root>/<label>/` with its marker and `outbox/` (spec §4.1), created
/// where missing: at a folder's start, and before every whole-folder
/// reconcile, so a mirror directory or marker an agent deleted is rebuilt
/// instead of failing `mirror_unwritable` until a restart. Never deletes a
/// directory: the only removal is [`Dir::ensure_dir`]'s unlink of a file or
/// symlink sitting where the directory belongs (spec §6.4). A marker that
/// holds another label is left alone and refused.
pub(crate) fn prepare_folder_dir(root: &Dir, label: &str) -> io::Result<()> {
    let d = root.ensure_dir(OsStr::new(label), 0o755)?;
    match d.read_file(OsStr::new(MARKER), 64) {
        Ok((b, _, _)) if b == label.as_bytes() => {}
        Err(e) if map_errno(&e) == IoClass::NotFound => fsops::write_marker(&d, label)?,
        _ => return Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    }
    d.ensure_dir(OsStr::new(OUTBOX), 0o755)?;
    Ok(())
}

/// Run one job of a folder. The workers and the test driver share it, so
/// both dispatch the same way: `Confirmed` to the removal, `Tripwire` to
/// the pass (spec §7.4, §7.5).
pub(crate) fn run_job(ctx: &Ctx, rt: &FolderRt, job: &Job) -> Result<(), FolderError> {
    match job {
        Job::Source { rel, force, .. } => match pipeline::process_source(ctx, rt, rel, *force)? {
            Step::Subtree => reconcile::run(ctx, rt, rel, false).map(|_| ()),
            Step::Done | Step::Requeue => Ok(()),
        },
        Job::Confirmed { rel, .. } => guard::remove_confirmed(ctx, rt, rel),
        Job::Outbox { rel, .. } => outbox::process(ctx, rt, rel),
        Job::Reconcile { rel, full, .. } => {
            if rel.is_empty() {
                prepare_folder_dir(&ctx.root, &rt.folder.label)
                    .map_err(|e| FolderError::from_mirror_io(&e))?;
            }
            reconcile::run(ctx, rt, rel, *full).map(|_| ())
        }
        Job::Tripwire { .. } => guard::tripwire_pass(ctx, rt).map(|_| ()),
    }
}

/// A root id adopted over a non-empty manifest after a restart (5c review
/// I2): deletions are off until the folder is removed and added again. The
/// status shows it as `failed` / `source_missing` (ruling), never silently.
pub(crate) fn untrusted_root(rt: &FolderRt) -> bool {
    let id = lock(&rt.root_id);
    id.id.is_some() && !id.trusted
}

#[derive(Default)]
struct WatchSlot {
    source: Option<Watch>,
    outbox: Option<Watch>,
    /// (device, inode) of the `outbox/` directory being watched.
    outbox_id: Option<(u64, u64)>,
    failed_at: Option<Instant>,
    last_poll: Option<Instant>,
}

/// The mirror service.
pub struct Mirror {
    ctx: Arc<Ctx>,
    folders: RwLock<BTreeMap<String, Arc<FolderRt>>>,
    watches: Mutex<HashMap<String, WatchSlot>>,
    running: AtomicBool,
    /// Set by `stop`; a stopped service never starts again.
    stopped: AtomicBool,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for Mirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mirror").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `lstat` of `path`: a directory, not a symlink. Its (device, inode).
fn plain_dir(path: &Path) -> Option<(u64, u64)> {
    let md = std::fs::symlink_metadata(path).ok()?;
    md.is_dir().then(|| (md.dev(), md.ino()))
}

impl Mirror {
    /// Prepare the root and the service; nothing runs until `start`.
    pub fn new(
        cfg: MirrorConfig,
        engine: Arc<dyn MirrorEngine>,
        manifest: Arc<dyn ManifestStore>,
    ) -> Result<Arc<Mirror>, FolderError> {
        let (root, canonical) = prepare_root(&cfg)?;
        Mirror::with_root(cfg, root, canonical, engine, manifest)
    }

    /// [`new`](Self::new) over a root [`prepare_root`] already prepared:
    /// the daemon prepares it when it loads, and the service reuses that
    /// handle instead of opening the path again, so a directory swapped in
    /// between is never written. The canonical path must still name the
    /// handle's directory (it is what agents are told to read); otherwise
    /// `MirrorUnwritable`.
    pub fn with_root(
        cfg: MirrorConfig,
        root: Dir,
        canonical: PathBuf,
        engine: Arc<dyn MirrorEngine>,
        manifest: Arc<dyn ManifestStore>,
    ) -> Result<Arc<Mirror>, FolderError> {
        let m = root.meta().map_err(|_| FolderError::MirrorUnwritable)?;
        if plain_dir(&canonical) != Some((m.dev, m.ino)) {
            return Err(FolderError::MirrorUnwritable);
        }
        let cfg = MirrorConfig {
            root: canonical,
            ..cfg
        };
        Ok(Arc::new(Mirror {
            ctx: Arc::new(Ctx {
                cfg,
                engine,
                manifest,
                root,
                queue: WorkQueue::new(),
                before_commit: Mutex::new(None),
                source_fault: Mutex::new(None),
            }),
            folders: RwLock::new(BTreeMap::new()),
            watches: Mutex::new(HashMap::new()),
            running: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            threads: Mutex::new(Vec::new()),
        }))
    }

    /// The canonical mirror root.
    pub fn root(&self) -> &Path {
        &self.ctx.cfg.root
    }

    /// `<root>/<label>`.
    pub fn mirror_dir(&self, label: &str) -> PathBuf {
        self.ctx.cfg.root.join(label)
    }

    fn get(&self, dataset: &str) -> Option<Arc<FolderRt>> {
        self.folders
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(dataset)
            .cloned()
    }

    /// Register a folder (state `stopped` until started). A dataset that
    /// already has a folder is refused (`internal`): the caller removes it
    /// first (spec §12.2 answers `409` before this is reached), so one
    /// mirror tree never has two runtimes.
    pub fn register(&self, folder: Folder) -> Result<(), FolderError> {
        let ix = Index::load(&*self.ctx.manifest, &folder.dataset)
            .map_err(|e| FolderError::from_engine(&e))?;
        let mut all = self.folders.write().unwrap_or_else(PoisonError::into_inner);
        if all.contains_key(&folder.dataset) {
            return Err(FolderError::Internal);
        }
        all.insert(folder.dataset.clone(), Arc::new(FolderRt::new(folder, ix)));
        Ok(())
    }

    /// Register and, when running, start a folder.
    pub fn add(self: &Arc<Self>, folder: Folder) -> Result<(), FolderError> {
        let ds = folder.dataset.clone();
        self.register(folder)?;
        if self.running.load(Ordering::Acquire) {
            if let Some(rt) = self.get(&ds) {
                self.start_folder(&rt);
            }
        }
        Ok(())
    }

    /// Start workers, the poller, and every registered folder. Does nothing
    /// once [`stop`](Self::stop) has run.
    pub fn start(self: &Arc<Self>) {
        if self.stopped.load(Ordering::Acquire) || self.running.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut t = lock(&self.threads);
        for i in 0..self.ctx.cfg.workers.max(1) {
            let me = Arc::clone(self);
            t.push(
                std::thread::Builder::new()
                    .name(format!("inumaki-mirror-{i}"))
                    .spawn(move || me.worker())
                    .expect("spawn mirror worker"),
            );
        }
        let me = Arc::clone(self);
        t.push(
            std::thread::Builder::new()
                .name("inumaki-mirror-poll".into())
                .spawn(move || me.poller())
                .expect("spawn mirror poller"),
        );
        drop(t);
        let all: Vec<_> = self
            .folders
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        for rt in all {
            self.start_folder(&rt);
        }
    }

    /// Spec §7.2 step 3: the mirror directory, the watches, the startup
    /// reconcile (not forced) and one tripwire pass. The pass is required
    /// after a restart: the vault's entries generation is in memory only
    /// (review Cr1).
    fn start_folder(self: &Arc<Self>, rt: &Arc<FolderRt>) {
        // A folder whose removal failed part-way stays down: preparing it
        // here would recreate its tree outside the `alive` fence.
        if lock(&rt.status).removing {
            return;
        }
        let prepared = prepare_folder_dir(&self.ctx.root, &rt.folder.label);
        self.arm_watches(rt);
        *lock(&rt.last_rescan) = Some(Instant::now());
        let ds = rt.folder.dataset.clone();
        self.reconcile_soon(&ds);
        self.ctx
            .queue
            .push(Job::Tripwire { dataset: ds }, Priority::Tripwire);
        // After the pushes: the poller ends `scanning` once the folder has
        // no work left.
        let mut s = lock(&rt.status);
        s.started = true;
        s.scanning = true;
        if prepared.is_err() {
            s.fail(FolderError::MirrorUnwritable);
        }
    }

    /// Watch `path` (validated: a directory, not a symlink, and when
    /// `expect` is given, that directory) under its canonical path, so event
    /// paths strip against it. `None` when it cannot be watched.
    fn watch_dir(
        &self,
        path: &Path,
        expect: Option<(u64, u64)>,
        dataset: &str,
        is_outbox: bool,
        me: Weak<Mirror>,
    ) -> Option<(Watch, (u64, u64))> {
        // The watcher would resolve a symlinked root (6a review): `lstat`
        // the path, then the canonical path, and require one directory.
        let id = plain_dir(path)?;
        if expect.is_some_and(|x| x != id) {
            return None; // replaced: the reconcile reports `source_missing`
        }
        let base = std::fs::canonicalize(path).ok()?;
        if plain_dir(&base) != Some(id) {
            return None;
        }
        let ds = dataset.to_string();
        let b = base.clone();
        let w = watch::watch(&base, self.ctx.cfg.debounce, move |s| {
            if let Some(m) = me.upgrade() {
                m.on_signal(&ds, &b, is_outbox, s);
            }
        })
        .ok()?;
        Some((w, id))
    }

    /// (Re-)arm both watches of a folder; `watch_failed` when either fails
    /// (spec §6.2: a poll reconcile every 60 s, retried every 10 min).
    fn arm_watches(self: &Arc<Self>, rt: &FolderRt) {
        let ds = &rt.folder.dataset;
        let me = Arc::downgrade(self);
        let expect = lock(&rt.root_id).id;
        let source = self.watch_dir(&rt.folder.source, expect, ds, false, me.clone());
        let outbox_dir = self.mirror_dir(&rt.folder.label).join(OUTBOX);
        // Validated through the root handle; the path must name the same
        // directory (review M2).
        let outbox = self
            .outbox_id(&rt.folder.label)
            .and_then(|id| self.watch_dir(&outbox_dir, Some(id), ds, true, me));
        let failed = source.is_none() || outbox.is_none();
        let mut w = lock(&self.watches);
        // `remove` sets `removing`, and `stop` clears `running`, before they
        // take this lock: a watch armed here (the poller's retry, a rescan)
        // never outlives either.
        if lock(&rt.status).removing || !self.running.load(Ordering::Acquire) {
            return;
        }
        let slot = w.entry(ds.clone()).or_default();
        slot.outbox_id = outbox.as_ref().map(|(_, id)| *id);
        slot.source = source.map(|(w, _)| w);
        slot.outbox = outbox.map(|(w, _)| w);
        slot.failed_at = failed.then(Instant::now);
        let mut s = lock(&rt.status);
        if failed {
            s.errors.insert(FolderError::WatchFailed);
        } else {
            s.errors.remove(&FolderError::WatchFailed);
        }
    }

    /// The watcher sink: runs on the debouncer thread, so it only pushes
    /// (cheap, non-blocking), and it tolerates a late call after its watch
    /// was dropped. Paths are hints and are never logged.
    fn on_signal(&self, dataset: &str, base: &Path, is_outbox: bool, s: Signal) {
        let Some(rt) = self.get(dataset) else { return };
        if lock(&rt.status).removing {
            return;
        }
        match s {
            Signal::Rescan => self.reconcile_soon(dataset),
            Signal::Paths(paths) => {
                for p in paths {
                    let Ok(rel) = p.strip_prefix(base) else {
                        continue;
                    };
                    let rel = rel.as_os_str().as_bytes().to_vec();
                    if rel.is_empty() || rel.split(|b| *b == b'/').any(crate::names::ignored) {
                        continue;
                    }
                    let (job, p) = if is_outbox {
                        let job = Job::Outbox {
                            dataset: dataset.into(),
                            rel,
                        };
                        (job, Priority::Outbox)
                    } else {
                        let job = Job::Source {
                            dataset: dataset.into(),
                            rel,
                            force: false,
                        };
                        (job, Priority::Live)
                    };
                    self.ctx.queue.push(job, p);
                }
            }
        }
    }

    fn worker(self: Arc<Self>) {
        // Best effort: an error means a read on this thread may download a
        // cloud-only file; the pipeline's dataless check still applies.
        let _ = fsops::no_dataless_materialization();
        while let Some((job, _p)) = self.ctx.queue.pop() {
            if let Some(rt) = self.get(job.dataset()) {
                let alive = rt.alive.read().unwrap_or_else(PoisonError::into_inner);
                // A folder being removed runs nothing more: jobs queued after
                // the removal's purge (a reconcile's file jobs) would write a
                // tree being removed and, back to back, starve the removal's
                // bounded `try_write` (TCC review, fix round 1).
                if *alive && !lock(&rt.status).removing {
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run_job(&self.ctx, &rt, &job)
                    }));
                    if let Err(e) = r.unwrap_or(Err(FolderError::Internal)) {
                        let mut s = lock(&rt.status);
                        if let Job::Confirmed { rel, .. } = &job {
                            // Review Cr1: a failed removal is never dropped;
                            // the poller requeues it on its next tick.
                            s.pending_confirmed.insert(rel.clone());
                        }
                        let new = !s.errors.contains(&e);
                        s.fail(e);
                        drop(s);
                        if new {
                            tracing::warn!(
                                folder = %rt.folder.label,
                                error = e.as_str(),
                                "mirror job failed"
                            );
                        }
                    }
                }
            }
            self.ctx.queue.done(&job);
        }
    }

    fn poller(self: Arc<Self>) {
        let mut last_state: Option<Instant> = None;
        // Per folder, the (epoch, fingerprint) a re-mirror was queued for.
        let mut remirror: HashMap<String, (i64, [u8; 32])> = HashMap::new();
        while self.running.load(Ordering::Acquire) {
            std::thread::sleep(TICK);
            if !self.running.load(Ordering::Acquire) {
                break;
            }
            let all: Vec<_> = self
                .folders
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .values()
                .cloned()
                .collect();
            remirror.retain(|ds, _| all.iter().any(|rt| rt.folder.dataset == *ds));
            let state_due = last_state.is_none_or(|t| t.elapsed() >= MirrorConfig::STATE_POLL);
            if state_due {
                last_state = Some(Instant::now());
            }
            for rt in all {
                {
                    let s = lock(&rt.status);
                    if !s.started || s.removing {
                        continue;
                    }
                }
                // The poller alone drives the retries (removals, tripwire
                // passes, re-mirrors, backoff): a panic in one folder's poll
                // (daemon code behind the engine or the manifest) is that
                // folder's `internal`, never the end of the thread.
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if state_due {
                        self.poll_state(&rt, &mut remirror);
                    }
                    self.poll_retries(&rt);
                }));
                if r.is_err() {
                    let mut s = lock(&rt.status);
                    let new = !s.errors.contains(&FolderError::Internal);
                    s.fail(FolderError::Internal);
                    drop(s);
                    if new {
                        tracing::warn!(
                            folder = %rt.folder.label,
                            error = FolderError::Internal.as_str(),
                            "mirror poll failed"
                        );
                    }
                }
            }
        }
    }

    /// Spec §7.3, §7.4 every 10 s:
    /// - retry storing an adopted root id (5c review I2);
    /// - queue a whole reconcile when a record is on another epoch or
    ///   fingerprint; it carries the previous epoch's known originals before
    ///   it names anything (review Cr2), re-mirrors stale files, and renames
    ///   stale directories;
    /// - queue a tripwire pass when the entries generation differs from the
    ///   one the last completed pass started from and 30 s have passed since
    ///   it. A change seen while passes are spaced stays due until a later
    ///   poll; it is never lost (review Cr1);
    /// - rebuild a mirror directory an agent deleted, and re-arm the outbox
    ///   watch on a replaced `outbox/`.
    fn poll_state(
        self: &Arc<Self>,
        rt: &Arc<FolderRt>,
        remirror: &mut HashMap<String, (i64, [u8; 32])>,
    ) {
        let ds = rt.folder.dataset.clone();
        self.retry_root_id(rt);
        self.check_outbox(rt);
        let Ok(st) = self.ctx.engine.state(&ds) else {
            return;
        };
        *lock(&rt.last_state) = Some(st);
        let stale = {
            let ix = lock(&rt.index);
            ix.files
                .values()
                .any(|r| r.epoch_id != st.epoch_id || r.fingerprint != st.fingerprint)
                || ix
                    .dirs
                    .values()
                    .any(|d| d.epoch_id != st.epoch_id || d.fingerprint != st.fingerprint)
        };
        let key = (st.epoch_id, st.fingerprint);
        if !stale {
            // Current: any later stale record queues a re-mirror again.
            remirror.remove(&ds);
        } else if remirror.get(&ds) != Some(&key) {
            // A reconcile that fails is retried by the backoff.
            self.reconcile_soon(&ds);
            lock(&rt.status).scanning = true;
            remirror.insert(ds.clone(), key);
        }
        let done = *lock(&rt.tripwire_generation);
        let spaced =
            lock(&rt.last_tripwire).is_none_or(|t| t.elapsed() >= MirrorConfig::TRIPWIRE_MIN);
        if done != Some(st.entries_generation) && spaced {
            self.ctx
                .queue
                .push(Job::Tripwire { dataset: ds }, Priority::Tripwire);
        }
    }

    /// A root id adopted before anything was mirrored is trusted; until the
    /// vault stores it, a restart could not tell it from whatever is at the
    /// path. Every open of the root retries, and so does the poller, so a
    /// quiet folder stores it too.
    fn retry_root_id(&self, rt: &FolderRt) {
        let pending = {
            let id = lock(&rt.root_id);
            id.id.filter(|_| id.trusted && !id.persisted)
        };
        let Some(pair) = pending else { return };
        // Not for a folder being removed (its rows are being cleared). A
        // removal that starts after this check can still race the call:
        // the daemon's `put_root_id` must ignore a folder without config.
        if lock(&rt.status).removing {
            return;
        }
        if self
            .ctx
            .manifest
            .put_root_id(&rt.folder.dataset, pair)
            .is_ok()
        {
            let mut id = lock(&rt.root_id);
            if id.id == Some(pair) {
                id.persisted = true;
            }
        }
    }

    /// An agent may delete or replace `<label>/` or its `outbox/`. Missing:
    /// a whole reconcile rebuilds it (`prepare_folder_dir`). Replaced since
    /// it was watched: the watches are re-armed on the new directory.
    fn check_outbox(self: &Arc<Self>, rt: &Arc<FolderRt>) {
        let now = self.outbox_id(&rt.folder.label);
        // A deleted marker alone is rebuilt too: without it a `remove`
        // could only fail (review M4).
        let marked = self
            .ctx
            .root
            .child(OsStr::new(&rt.folder.label))
            .and_then(|d| d.stat(OsStr::new(MARKER)))
            .is_ok_and(|m| m.kind == Kind::File);
        let armed = lock(&self.watches)
            .get(&rt.folder.dataset)
            .and_then(|w| w.outbox_id);
        match (now, armed) {
            _ if now.is_none() || !marked => self.reconcile_soon(&rt.folder.dataset),
            (Some(n), Some(a)) if n != a => {
                self.arm_watches(rt);
                self.reconcile_soon(&rt.folder.dataset);
            }
            _ => {}
        }
    }

    /// (device, inode) of `<label>/outbox`, opened through the root handle
    /// one component at a time (`O_NOFOLLOW`): a symlinked `<label>` or
    /// `outbox` an agent planted is not a directory here.
    fn outbox_id(&self, label: &str) -> Option<(u64, u64)> {
        let d = self.ctx.root.child(OsStr::new(label)).ok()?;
        let m = d.child(OsStr::new(OUTBOX)).ok()?.meta().ok()?;
        Some((m.dev, m.ino))
    }

    /// A whole, unforced reconcile: covers events a watcher may have missed
    /// while it was down or being re-armed.
    fn reconcile_soon(&self, dataset: &str) {
        self.ctx.queue.push(
            Job::Reconcile {
                dataset: dataset.into(),
                rel: Vec::new(),
                full: false,
            },
            Priority::Background,
        );
    }

    fn poll_retries(self: &Arc<Self>, rt: &Arc<FolderRt>) {
        let ds = rt.folder.dataset.clone();
        // Removals that failed: every tick (review Cr1).
        let confirmed = std::mem::take(&mut lock(&rt.status).pending_confirmed);
        for rel in confirmed {
            self.ctx.queue.push(
                Job::Confirmed {
                    dataset: ds.clone(),
                    rel,
                },
                Priority::Removal,
            );
        }
        // The backoff is re-armed at the same interval when it fires, so a
        // failing folder is retried once per interval (`fail` doubles it).
        // Outbox files that met an unwritable destination are retried when
        // it fires, or at once when a success cleared it (spec §9, review I5).
        let (due, outbox_retry) = {
            let mut s = lock(&rt.status);
            let due = match s.backoff {
                Some((at, d)) if Instant::now() >= at => {
                    s.backoff = Some((Instant::now() + d, d));
                    true
                }
                _ => false,
            };
            // Copied, not taken: the set stays until each path is processed,
            // so `outbox_unwritable` holds while one is still queued (7
            // review I1).
            let outbox_retry = if due || s.backoff.is_none() {
                s.pending_outbox.clone()
            } else {
                Default::default()
            };
            (due, outbox_retry)
        };
        if due {
            self.ctx.queue.push(
                Job::Reconcile {
                    dataset: ds.clone(),
                    rel: Vec::new(),
                    full: true,
                },
                Priority::Background,
            );
        }
        for rel in outbox_retry {
            self.ctx.queue.push(
                Job::Outbox {
                    dataset: ds.clone(),
                    rel,
                },
                Priority::Outbox,
            );
        }
        let (poll, retry) = {
            let mut w = lock(&self.watches);
            match w
                .get_mut(&ds)
                .and_then(|slot| slot.failed_at.map(|at| (slot, at)))
            {
                Some((slot, at)) => {
                    let poll = slot
                        .last_poll
                        .is_none_or(|t| t.elapsed() >= MirrorConfig::WATCH_POLL);
                    if poll {
                        slot.last_poll = Some(Instant::now());
                    }
                    (poll, at.elapsed() >= MirrorConfig::WATCH_RETRY)
                }
                None => (false, false),
            }
        };
        // Arm first: a change after the walk starts is then an event.
        if retry {
            self.arm_watches(rt);
        }
        if poll || retry {
            self.reconcile_soon(&ds);
        }
        let rescan_due =
            lock(&rt.last_rescan).is_none_or(|t| t.elapsed() >= self.ctx.cfg.rescan_interval);
        if rescan_due {
            *lock(&rt.last_rescan) = Some(Instant::now());
            self.reconcile_soon(&ds);
        }
        // `scanning` ends when no source, removal, or reconcile work of the
        // folder is left, not when the walk returns (review minor).
        let scanning = lock(&rt.status).scanning;
        if scanning && !self.ctx.queue.busy(&ds) {
            lock(&rt.status).scanning = false;
        }
    }

    /// Remove a folder: stop its watchers, drop its queued work, wait for
    /// the job in flight and fence every later one, and only then delete the
    /// mirror tree (marker-checked; the precondition of
    /// [`fsops::delete_mirror_tree`]) and the manifest rows. The source and
    /// the outbox destination are never touched. `Ok(false)` when there is
    /// no such folder. The folder reads `stopped` from the first step on,
    /// also when a step fails; calling `remove` again retries.
    ///
    /// The wait for the job in flight is bounded ([`REMOVE_WAIT`]): a job
    /// parked in a first open behind a macOS prompt makes it answer
    /// [`FolderError::Busy`], with the folder still fenced (`removing`) and
    /// its tree in place.
    pub fn remove(&self, dataset: &str) -> Result<bool, FolderError> {
        let Some(rt) = self.get(dataset) else {
            return Ok(false);
        };
        // 1. No new work: a late watcher callback finds `removing` and
        //    pushes nothing; `arm_watches` never re-arms (both check it).
        lock(&rt.status).removing = true;
        lock(&self.watches).remove(dataset);
        self.ctx.queue.purge(dataset);
        // 2. Workers hold `alive` for reading while they run a job: this
        //    waits for the one in flight, at most `REMOVE_WAIT` (`busy`
        //    after that; a later call retries). A job pushed after the purge
        //    (the poller, a late callback) finds `alive` false and does
        //    nothing.
        let until = Instant::now() + REMOVE_WAIT;
        let mut alive = loop {
            match rt.alive.try_write() {
                Ok(g) => break g,
                Err(TryLockError::Poisoned(p)) => break p.into_inner(),
                Err(TryLockError::WouldBlock) if Instant::now() < until => {
                    std::thread::sleep(WAIT_STEP);
                }
                Err(TryLockError::WouldBlock) => return Err(FolderError::Busy),
            }
        };
        *alive = false;
        drop(alive);
        self.ctx.queue.purge(dataset);
        // 3. No watcher and no writer is left for this tree.
        fsops::delete_mirror_tree(&self.ctx.root, &rt.folder.label)
            .map_err(|_| FolderError::MirrorUnwritable)?;
        match self.ctx.manifest.clear(dataset) {
            // The dataset's rows went with it (cascade).
            Ok(()) | Err(EngineError::DatasetGone) => {}
            Err(e) => return Err(FolderError::from_engine(&e)),
        }
        self.folders
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(dataset);
        Ok(true)
    }

    /// Spec §12.2 rescan: clears the retry state, re-arms a failed watcher,
    /// and queues a forced full reconcile on the workers (never on the
    /// caller's thread). Returns the known source files the reconcile
    /// re-checks; files the walk finds new are counted in `pending` as they
    /// are queued (spec §12.2, amended 2026-10-04).
    pub fn rescan(self: &Arc<Self>, dataset: &str) -> Result<Option<u64>, FolderError> {
        let Some(rt) = self.get(dataset) else {
            return Ok(None);
        };
        let rearm = {
            let mut s = lock(&rt.status);
            if s.removing {
                return Ok(None);
            }
            let rearm = s.errors.contains(&FolderError::WatchFailed);
            s.errors.retain(|e| *e == FolderError::OutboxUnwritable);
            s.backoff = None;
            rearm
        };
        if rearm {
            self.arm_watches(&rt);
        }
        self.ctx.queue.push(
            Job::Reconcile {
                dataset: dataset.into(),
                rel: Vec::new(),
                full: true,
            },
            Priority::Background,
        );
        let known = lock(&rt.index).files.len() as u64;
        lock(&rt.status).scanning = true;
        Ok(Some(known))
    }

    /// The folder's status.
    pub fn snapshot(&self, dataset: &str) -> Option<Snapshot> {
        let rt = self.get(dataset)?;
        let st = (*lock(&rt.last_state)).or_else(|| self.ctx.engine.state(dataset).ok());
        let (sp, op) = self.ctx.queue.pending(dataset);
        let untrusted = untrusted_root(&rt);
        // Index before status: the index lock is never taken under status.
        let ix = lock(&rt.index);
        let mut files = ix.counts();
        files.pending = sp;
        let (rehydrated, with_unresolved) = ix.outbox_counts();
        let remirror_pending = st.is_some_and(|s| {
            ix.files
                .values()
                .any(|r| r.epoch_id != s.epoch_id || r.fingerprint != s.fingerprint)
        });
        drop(ix);
        let s = lock(&rt.status);
        files.source = s.source_files;
        let (state, error) = s.view(
            untrusted.then_some(FolderError::SourceMissing),
            rt.open_pending(PENDING_AFTER),
        );
        Some(Snapshot {
            state,
            error,
            files,
            last_mirrored_at: s.last_mirrored_at,
            epoch_id: st.map_or(0, |s| s.epoch_id),
            remirror_pending,
            outbox: OutboxCounts {
                rehydrated,
                with_unresolved,
                pending: op + s.pending_outbox.len() as u64,
            },
        })
    }

    /// Test seam: hold every open of a source root until the returned hold
    /// is released or dropped, as a macOS privacy prompt does (TCC spike
    /// finding 2). Production never calls it.
    #[doc(hidden)]
    pub fn hold_source_opens(&self) -> crate::testing::OpenHold {
        crate::testing::OpenHold::install(&self.ctx)
    }

    /// Wait until nothing is queued or in flight (tests, the check).
    pub fn wait_idle(&self, within: Duration) -> bool {
        let until = Instant::now() + within;
        while Instant::now() < until {
            if self.ctx.queue.is_idle() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }

    /// Stop workers, the poller, and the watchers for good; queued work is
    /// dropped (the next start's reconcile finds it again), the job in
    /// flight finishes or leaves only a temporary file behind. Call it
    /// before dropping the service: the threads hold it.
    ///
    /// Bounded ([`STOP_WAIT`]): a worker parked in a first open behind a
    /// macOS prompt is not joined; it ends with the process.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.running.store(false, Ordering::Release);
        self.ctx.queue.stop();
        lock(&self.watches).clear();
        let threads: Vec<_> = lock(&self.threads).drain(..).collect();
        let until = Instant::now() + STOP_WAIT;
        let mut left = 0usize;
        for t in threads {
            while !t.is_finished() && Instant::now() < until {
                std::thread::sleep(WAIT_STEP);
            }
            if t.is_finished() {
                let _ = t.join();
            } else {
                left += 1; // detached: dropping the handle does not wait
            }
        }
        if left > 0 {
            tracing::warn!(threads = left, "mirror stop left busy workers behind");
        }
    }
}
