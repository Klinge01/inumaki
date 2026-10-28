//! Test driver: one folder over temporary directories, driven without
//! watcher or threads. Test code; hidden from the docs.

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::config::MirrorConfig;
use crate::engine::{ManifestStore, MirrorEngine};
use crate::folder::{Folder, FolderRt, Index, RootIdentity, root_generation};
use crate::guard;
use crate::outbox;
use crate::pipeline::{self, Ctx, SourceFault, Step};
use crate::queue::{Job, WorkQueue};
use crate::reconcile;
use crate::service::{prepare_folder_dir, prepare_root, run_job, untrusted_root};
use crate::status::{FolderError, Snapshot};

/// The dataset id of the driver's one folder.
const DATASET: &str = "ds";
/// Its mirror directory label.
const LABEL: &str = "d1b2c3d4e5f60718";

/// Public mirror of the pipeline's `Step`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// Finished.
    Done,
    /// Run again later.
    Requeue,
    /// A subtree needs reconciling.
    Subtree,
}

impl From<Step> for StepKind {
    fn from(s: Step) -> StepKind {
        match s {
            Step::Done => StepKind::Done,
            Step::Requeue => StepKind::Requeue,
            Step::Subtree => StepKind::Subtree,
        }
    }
}

/// One started folder over temporary directories. No `Debug`: it owns paths.
pub struct TestMirror {
    tmp: Arc<tempfile::TempDir>,
    pub(crate) ctx: Arc<Ctx>,
    pub(crate) rt: Arc<FolderRt>,
    source: PathBuf,
    mirror: PathBuf,
    destination: PathBuf,
}

impl TestMirror {
    /// A folder with an empty source, an empty mirror and an empty outbox.
    pub fn new(engine: Arc<dyn MirrorEngine>, manifest: Arc<dyn ManifestStore>) -> TestMirror {
        TestMirror::with_root_id(engine, manifest, true)
    }

    /// Like [`new`](Self::new), with the root id stored as before
    /// generations were recorded: (device, inode) only.
    pub fn new_without_generation(
        engine: Arc<dyn MirrorEngine>,
        manifest: Arc<dyn ManifestStore>,
    ) -> TestMirror {
        TestMirror::with_root_id(engine, manifest, false)
    }

    fn with_root_id(
        engine: Arc<dyn MirrorEngine>,
        manifest: Arc<dyn ManifestStore>,
        generation: bool,
    ) -> TestMirror {
        let tmp = tempfile::tempdir().expect("tempdir");
        for d in ["src", "root", "dest"] {
            std::fs::create_dir_all(tmp.path().join(d)).expect("create_dir_all");
        }
        let src = tmp.path().join("src");
        let meta = std::fs::metadata(&src).expect("source metadata");
        let root_id = {
            use std::os::unix::fs::MetadataExt;
            Some(RootIdentity {
                dev: meta.dev(),
                ino: meta.ino(),
                generation: root_generation(&src, meta.dev(), meta.ino()).filter(|_| generation),
            })
        };
        TestMirror::build(Arc::new(tmp), engine, manifest, Index::default(), root_id)
    }

    /// Like [`new`](Self::new), for a folder added while its root could not
    /// be read (spec §9.1): no stored identity; the first open
    /// adopts it.
    pub fn new_unidentified(
        engine: Arc<dyn MirrorEngine>,
        manifest: Arc<dyn ManifestStore>,
    ) -> TestMirror {
        let tmp = tempfile::tempdir().expect("tempdir");
        for d in ["src", "root", "dest"] {
            std::fs::create_dir_all(tmp.path().join(d)).expect("create_dir_all");
        }
        TestMirror::build(Arc::new(tmp), engine, manifest, Index::default(), None)
    }

    /// A new `Ctx` and `FolderRt` over the same directories, engine and
    /// manifest, as after a daemon restart: the index is loaded from the
    /// manifest, the queue is fresh, and the root id is the stored one (an
    /// id adopted but never persisted is lost, as in the daemon).
    pub fn restart(&self) -> TestMirror {
        let index = Index::load(&*self.ctx.manifest, DATASET).expect("load index");
        let root = *self
            .rt
            .root_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        TestMirror::build(
            Arc::clone(&self.tmp),
            Arc::clone(&self.ctx.engine),
            Arc::clone(&self.ctx.manifest),
            index,
            root.id.filter(|_| root.persisted),
        )
    }

    fn build(
        tmp: Arc<tempfile::TempDir>,
        engine: Arc<dyn MirrorEngine>,
        manifest: Arc<dyn ManifestStore>,
        index: Index,
        root_id: Option<RootIdentity>,
    ) -> TestMirror {
        let source = tmp.path().join("src");
        let dest = tmp.path().join("dest");
        let cfg = MirrorConfig {
            root: tmp.path().join("root"),
            outbox_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        // The service's own root and folder preparation; a restart keeps
        // the existing marker.
        let (root_dir, root) = prepare_root(&cfg).expect("prepare root");
        prepare_folder_dir(&root_dir, LABEL).expect("mirror dir");
        let cfg = MirrorConfig {
            root: root.clone(),
            ..cfg
        };
        let ctx = Arc::new(Ctx {
            cfg,
            engine,
            manifest,
            root: root_dir,
            queue: WorkQueue::new(),
            before_commit: Default::default(),
            source_fault: Default::default(),
        });
        let folder = Folder {
            dataset: DATASET.to_string(),
            label: LABEL.to_string(),
            source: source.clone(),
            outbox_destination: dest.clone(),
            root_id,
        };
        let rt = Arc::new(FolderRt::new(folder, index));
        rt.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .started = true;
        TestMirror {
            mirror: root.join(LABEL),
            source,
            destination: dest,
            ctx,
            rt,
            tmp,
        }
    }

    /// The source directory.
    pub fn source(&self) -> PathBuf {
        self.source.clone()
    }

    /// The folder's mirror directory.
    pub fn mirror_dir(&self) -> PathBuf {
        self.mirror.clone()
    }

    /// The folder's `outbox/` in the mirror.
    pub fn outbox_dir(&self) -> PathBuf {
        self.mirror.join(crate::names::OUTBOX)
    }

    /// The folder's outbox destination.
    pub fn destination(&self) -> PathBuf {
        self.destination.clone()
    }

    /// Process one outbox path (relative to `outbox/`, `/` separated) once,
    /// settle wait included. Panics on an error (with its class only).
    pub fn process_outbox(&self, rel: &str) {
        if let Err(e) = self.process_outbox_result(rel) {
            panic!("outbox failed: {}", e.as_str());
        }
    }

    /// Process one outbox path once; an error is recorded on the folder's
    /// status, as a worker would.
    pub fn process_outbox_result(&self, rel: &str) -> Result<(), FolderError> {
        let r = outbox::process(&self.ctx, &self.rt, rel.as_bytes());
        self.record(r);
        r
    }

    /// Run `f` between the two `lstat`s of the outbox settle check (this
    /// thread only); `None` clears it.
    pub fn during_outbox_settle(&self, f: Option<Box<dyn FnMut()>>) {
        outbox::set_settle_hook(f);
    }

    /// The folder's status as the daemon would report it.
    pub fn snapshot(&self) -> Snapshot {
        let state = self.ctx.engine.state(DATASET).ok();
        let untrusted = untrusted_root(&self.rt);
        // Index before status: the index lock is never taken under status.
        let (mut files, outbox, remirror_pending) = {
            let ix = self.rt.index.lock().unwrap_or_else(PoisonError::into_inner);
            let stale = state.is_some_and(|s| {
                ix.files
                    .values()
                    .any(|r| r.epoch_id != s.epoch_id || r.fingerprint != s.fingerprint)
            });
            (ix.counts(), ix.outbox_counts(), stale)
        };
        let (pending, outbox_pending) = self.ctx.queue.pending(DATASET);
        files.pending = pending;
        let st = self
            .rt
            .status
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        files.source = st.source_files;
        let outbox_pending = outbox_pending + st.pending_outbox.len() as u64;
        let (folder_state, error) = st.view(
            untrusted.then_some(FolderError::SourceMissing),
            self.rt.open_pending(crate::status::PENDING_AFTER),
        );
        Snapshot {
            state: folder_state,
            error,
            files,
            last_mirrored_at: st.last_mirrored_at,
            epoch_id: state.map_or(0, |s| s.epoch_id),
            remirror_pending,
            outbox: crate::status::OutboxCounts {
                rehydrated: outbox.0,
                with_unresolved: outbox.1,
                pending: outbox_pending,
            },
        }
    }

    /// Run `f` between reading a source file and the step-8 comparison.
    pub fn before_commit(&self, f: impl Fn() + Send + 'static) {
        *self
            .ctx
            .before_commit
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(f));
    }

    /// Remove the `before_commit` hook.
    pub fn clear_before_commit(&self) {
        *self
            .ctx
            .before_commit
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Run the pipeline once on `rel` (relative to the source, `/`
    /// separated). Panics on an error.
    pub fn process(&self, rel: &str) -> StepKind {
        match self.process_result(rel) {
            Ok(s) => s,
            Err(e) => panic!("process failed: {}", e.as_str()),
        }
    }

    /// Run the pipeline once on `rel`.
    pub fn process_result(&self, rel: &str) -> Result<StepKind, FolderError> {
        pipeline::process_source(&self.ctx, &self.rt, rel.as_bytes(), false).map(StepKind::from)
    }

    /// Reconcile the whole folder, then run every queued job. An error is
    /// recorded on the folder's status, as a worker would.
    pub fn reconcile_all(&self) {
        let _ = self.reconcile_all_result();
    }

    /// [`reconcile_all`](Self::reconcile_all) as a full reconcile: every
    /// file that is not mirrored is retried with the manifest shortcut off.
    pub fn reconcile_all_forced(&self) {
        let r = reconcile::run(&self.ctx, &self.rt, b"", true);
        self.record(r.map(|_| ()));
        self.drain();
    }

    /// Reconcile the whole folder (a failure is recorded on the status, as
    /// the service does), then run every queued job.
    pub fn reconcile_all_result(&self) -> Result<u64, FolderError> {
        let r = self.reconcile_no_drain();
        self.drain();
        r
    }

    /// Reconcile the whole folder and leave the queued jobs queued.
    pub fn reconcile_no_drain(&self) -> Result<u64, FolderError> {
        let r = reconcile::run(&self.ctx, &self.rt, b"", false);
        self.record(r.map(|_| ()));
        r
    }

    /// Run queued jobs until none is left, as `Mirror::dispatch` does.
    /// Panics if the queue does not settle (a job requeueing itself).
    pub fn drain(&self) {
        for _ in 0..10_000 {
            let Some((job, _)) = self.ctx.queue.pop_timeout(Duration::ZERO) else {
                return;
            };
            let r = self.dispatch(&job);
            self.record(r);
            self.ctx.queue.done(&job);
        }
        panic!("the queue did not settle");
    }

    fn dispatch(&self, job: &Job) -> Result<(), FolderError> {
        run_job(&self.ctx, &self.rt, job)
    }

    /// Run the tripwire pass (spec §7.4), then every queued job. Returns the
    /// hits; panics on an error (with its class only).
    pub fn tripwire_pass_and_drain(&self) -> u32 {
        let hits = self.tripwire_pass();
        self.drain();
        hits
    }

    /// Run the tripwire pass and only the removals it queued, then drop
    /// every other queued job (the requeues), as a crash right after the
    /// removals would. Returns the hits.
    pub fn tripwire_pass_without_drain(&self) -> u32 {
        let hits = self.tripwire_pass();
        while let Some((job, _)) = self.ctx.queue.pop_timeout(Duration::ZERO) {
            if matches!(job, Job::Confirmed { .. }) {
                let r = self.dispatch(&job);
                self.record(r);
            }
            self.ctx.queue.done(&job);
        }
        hits
    }

    fn tripwire_pass(&self) -> u32 {
        match guard::tripwire_pass(&self.ctx, &self.rt) {
            Ok(n) => n,
            Err(e) => panic!("tripwire pass failed: {}", e.as_str()),
        }
    }

    fn record(&self, r: Result<(), FolderError>) {
        if let Err(e) = r {
            self.rt
                .status
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .fail(e);
        }
    }

    /// The index's mirror-name claims are exactly its records' (no
    /// reservation outlived its write).
    pub fn claims_balanced(&self) -> bool {
        self.rt
            .index
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .claims_match_records()
    }

    /// Take the next queued job, if any, and mark it finished.
    pub fn next_job(&self) -> Option<(crate::queue::Job, crate::queue::Priority)> {
        let (job, p) = self.ctx.queue.pop_timeout(std::time::Duration::ZERO)?;
        self.ctx.queue.done(&job);
        Some((job, p))
    }

    /// Make the source root fail to open with this errno (`None` clears it).
    pub fn inject_source_error(&self, errno: Option<i32>) {
        *self
            .ctx
            .source_fault
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = errno.map(SourceFault::Errno);
    }

    /// Hold every open of the source root ([`OpenHold`]).
    pub fn hold_source_opens(&self) -> OpenHold {
        OpenHold::install(&self.ctx)
    }

    /// Backdate the open in progress by `by`, as if it had waited that
    /// long (the `pending` threshold without the wait).
    pub fn backdate_open(&self, by: Duration) {
        let mut o = self
            .rt
            .opening
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *o = Some(o.unwrap_or_else(Instant::now) - by);
    }

    /// Run one whole reconcile on this thread (an open hold parks it).
    pub fn reconcile_once(&self) -> Result<u64, FolderError> {
        reconcile::run(&self.ctx, &self.rt, b"", false)
    }
}

/// The shared half of an [`OpenHold`]: whether it is released, and how
/// many opens wait on it.
#[derive(Default)]
pub(crate) struct Gate {
    state: Mutex<(bool, usize)>,
    cv: Condvar,
}

impl Gate {
    /// Wait until released (an open that a macOS prompt blocks).
    pub(crate) fn wait(&self) {
        let mut g = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        g.1 += 1;
        self.cv.notify_all();
        while !g.0 {
            g = self.cv.wait(g).unwrap_or_else(PoisonError::into_inner);
        }
        g.1 -= 1;
        self.cv.notify_all();
    }
}

/// Test seam: every open of a source root waits until this is released or
/// dropped, then opens, as a first open does while macOS shows its privacy
/// prompt (TCC spike finding 2). Production never installs one.
pub struct OpenHold {
    gate: Arc<Gate>,
}

impl OpenHold {
    pub(crate) fn install(ctx: &Ctx) -> OpenHold {
        let gate = Arc::new(Gate::default());
        *ctx.source_fault
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(SourceFault::Hold(Arc::clone(&gate)));
        OpenHold { gate }
    }

    /// Let every waiting and later open through.
    pub fn release(&self) {
        let mut g = self
            .gate
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        g.0 = true;
        self.gate.cv.notify_all();
    }

    /// Wait until at least one open waits on the hold.
    pub fn wait_parked(&self, within: Duration) -> bool {
        let until = Instant::now() + within;
        let mut g = self
            .gate
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while g.1 == 0 {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            g = self
                .gate
                .cv
                .wait_timeout(g, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

impl Drop for OpenHold {
    fn drop(&mut self) {
        self.release();
    }
}
