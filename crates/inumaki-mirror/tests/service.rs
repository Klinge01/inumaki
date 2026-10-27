//! M5 spec §6, §7.3, §7.4: the watcher mirrors a change, a removed folder's
//! tree goes behind its marker, the poller re-mirrors after rotation and
//! carries the previous epoch's known names first (review Cr2), and two
//! names taught within the tripwire spacing are both removed (review Cr1).
//! Also: one folder's jobs never overlap while folders run in parallel,
//! removal waits for the writer in flight before it deletes the tree, a
//! stopped service runs nothing, an untrusted root is reported, and a
//! mirror directory an agent deleted is rebuilt.

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use common::{FakeEngine, MemManifest};
use inumaki_core::span::EntityKind;
use inumaki_mirror::{
    Activity, Block, DatasetState, EngineError, Folder, FolderError, FolderState, ManifestStore,
    Mirror, MirrorConfig, MirrorEngine,
};

const LABEL: &str = "aaaaaaaaaaaaaaaa";

struct Env {
    _t: tempfile::TempDir,
    root: std::path::PathBuf,
    base: std::path::PathBuf,
}

fn env() -> Env {
    let t = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(t.path()).unwrap();
    let root = base.join("Inumaki");
    Env { root, base, _t: t }
}

fn folder(e: &Env, dataset: &str, label: &str) -> Folder {
    let src = e.base.join(format!("src-{dataset}"));
    std::fs::create_dir_all(&src).unwrap();
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(&src).unwrap();
    Folder {
        dataset: dataset.into(),
        label: label.into(),
        source: src,
        outbox_destination: e.base.join(format!("out-{dataset}")),
        root_id: Some((md.dev(), md.ino())),
    }
}

fn mirror_with(
    e: &Env,
    engine: Arc<dyn MirrorEngine>,
    manifest: Arc<dyn ManifestStore>,
    workers: usize,
) -> Arc<Mirror> {
    let cfg = MirrorConfig {
        root: e.root.clone(),
        outbox_root: e.base.join("Outbox"),
        workers,
        ..MirrorConfig::default()
    };
    Mirror::new(cfg, engine, manifest).unwrap()
}

fn mirror(e: &Env, engine: Arc<FakeEngine>) -> Arc<Mirror> {
    mirror_with(e, engine, Arc::new(MemManifest::default()), 1)
}

fn wait_until(within: Duration, f: impl Fn() -> bool) -> bool {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// A `FakeEngine` that counts the calls in flight per dataset (sanitize,
/// names, release check), holds each for `delay`, and runs `hook` at the
/// end of each while it still counts as in flight.
struct Probe {
    inner: FakeEngine,
    delay: Duration,
    active: Mutex<HashMap<String, usize>>,
    max_per_dataset: AtomicUsize,
    max_total: AtomicUsize,
    calls: AtomicUsize,
    hook: Mutex<Option<Box<dyn Fn() + Send>>>,
    /// The next `state()` call panics (daemon code behind the trait).
    panic_state: AtomicBool,
    /// When set, the first call of each dataset waits (bounded) until a call
    /// of another dataset is in flight too, so folders that can run in
    /// parallel overlap deterministically instead of by timing.
    rendezvous: AtomicBool,
    first_seen: Mutex<HashSet<String>>,
}

impl Probe {
    fn new(inner: FakeEngine, delay: Duration) -> Probe {
        Probe {
            inner,
            delay,
            active: Mutex::new(HashMap::new()),
            max_per_dataset: AtomicUsize::new(0),
            max_total: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            hook: Mutex::new(None),
            panic_state: AtomicBool::new(false),
            rendezvous: AtomicBool::new(false),
            first_seen: Mutex::new(HashSet::new()),
        }
    }

    fn other_dataset_in_flight(&self, d: &str) -> bool {
        let a = self.active.lock().unwrap();
        a.iter().any(|(k, n)| k != d && *n > 0)
    }

    fn in_flight(&self) -> usize {
        self.active.lock().unwrap().values().sum()
    }

    fn span<T>(&self, d: &str, f: impl FnOnce() -> T) -> T {
        {
            let mut a = self.active.lock().unwrap();
            *a.entry(d.to_string()).or_default() += 1;
            self.max_per_dataset.fetch_max(a[d], Ordering::SeqCst);
            self.max_total.fetch_max(a.values().sum(), Ordering::SeqCst);
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
        if self.rendezvous.load(Ordering::SeqCst)
            && self.first_seen.lock().unwrap().insert(d.to_string())
        {
            // Both folders' first calls are registered as in flight before
            // they wait, so they see each other at once when the folders run
            // in parallel. Serialized folders time out here and leave
            // `max_total` at 1.
            wait_until(Duration::from_secs(5), || self.other_dataset_in_flight(d));
        }
        let r = f();
        std::thread::sleep(self.delay);
        // A panicking hook poisons the lock; later calls still run it.
        if let Some(h) = self
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            h();
        }
        *self.active.lock().unwrap().get_mut(d).unwrap() -= 1;
        r
    }
}

impl MirrorEngine for Probe {
    fn sanitize(&self, d: &str, blocks: Vec<String>) -> Result<Vec<Block>, EngineError> {
        self.span(d, || self.inner.sanitize(d, blocks))
    }
    fn sanitize_names(&self, d: &str, stems: Vec<String>) -> Result<Vec<Block>, EngineError> {
        self.span(d, || self.inner.sanitize_names(d, stems))
    }
    fn rehydrate_strict(&self, d: &str, blocks: Vec<String>) -> Result<Vec<String>, EngineError> {
        self.inner.rehydrate_strict(d, blocks)
    }
    fn known_in_clear(
        &self,
        d: &str,
        texts: &[String],
    ) -> Result<Vec<Option<EntityKind>>, EngineError> {
        self.span(d, || self.inner.known_in_clear(d, texts))
    }
    fn scan_clear(&self, d: &str, texts: &[String]) -> Result<Vec<(String, u32)>, EngineError> {
        self.inner.scan_clear(d, texts)
    }
    fn state(&self, d: &str) -> Result<DatasetState, EngineError> {
        if self.panic_state.swap(false, Ordering::SeqCst) {
            panic!("injected panic in state");
        }
        self.inner.state(d)
    }
    fn carry_known(&self, d: &str) -> Result<u64, EngineError> {
        self.inner.carry_known(d)
    }
    fn record(&self, a: Activity) {
        self.inner.record(a)
    }
}

#[test]
fn a_change_is_mirrored_by_the_watcher() {
    let e = env();
    let m = mirror(
        &e,
        Arc::new(FakeEngine::new(&[(
            "Zyxwuria Quolnath",
            EntityKind::Person,
        )])),
    );
    let f = folder(&e, "a", LABEL);
    let src = f.source.clone();
    m.add(f).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    std::fs::write(src.join("brief.txt"), "Zyxwuria Quolnath\n").unwrap();
    let out = e.root.join(LABEL).join("brief.txt");
    assert!(wait_until(Duration::from_secs(10), || out.exists()));
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("<PERSON_") && !text.contains("Zyxwuria"));
    std::fs::remove_file(src.join("brief.txt")).unwrap();
    assert!(
        wait_until(Duration::from_secs(10), || !out.exists()),
        "the delete propagated"
    );
    m.stop();
}

#[test]
fn remove_deletes_the_tree_only_behind_its_marker_and_stops_work() {
    let e = env();
    let m = mirror(&e, Arc::new(FakeEngine::new(&[])));
    let f = folder(&e, "a", LABEL);
    std::fs::write(f.source.join("x.txt"), "x").unwrap();
    let src = f.source.clone();
    m.add(f).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    assert!(e.root.join(LABEL).join("x.txt").exists());
    assert!(m.remove("a").unwrap());
    assert!(!e.root.join(LABEL).exists());
    assert!(src.join("x.txt").exists(), "the source is never touched");
    assert!(m.snapshot("a").is_none());
    std::fs::write(src.join("y.txt"), "y").unwrap();
    std::thread::sleep(Duration::from_secs(2));
    assert!(!e.root.join(LABEL).exists(), "no work after removal");
    assert!(!m.remove("a").unwrap());

    // A tree whose marker holds another label is never deleted, and its
    // folder is not wedged: the records go, the directory stays.
    let f = folder(&e, "b", "bbbbbbbbbbbbbbbb");
    m.add(f).unwrap();
    assert!(m.wait_idle(Duration::from_secs(10)));
    let tree = e.root.join("bbbbbbbbbbbbbbbb");
    std::fs::remove_file(tree.join(".inumaki-mirror")).unwrap(); // read-only
    std::fs::write(tree.join(".inumaki-mirror"), "cccccccccccccccc").unwrap();
    assert_eq!(m.remove("b"), Ok(true));
    assert!(tree.join("outbox").exists(), "kept");
    assert!(m.snapshot("b").is_none(), "the folder is gone");

    // A marker that is not a plain file is refused: the folder reads
    // stopped, not failed, and a later remove retries.
    let f = folder(&e, "c", "cccccccccccccccc");
    m.add(f).unwrap();
    assert!(m.wait_idle(Duration::from_secs(10)));
    let tree = e.root.join("cccccccccccccccc");
    std::fs::remove_file(tree.join(".inumaki-mirror")).unwrap();
    std::os::unix::fs::symlink(e.base.join("elsewhere"), tree.join(".inumaki-mirror")).unwrap();
    assert_eq!(m.remove("c"), Err(FolderError::MirrorUnwritable));
    assert!(tree.join("outbox").exists(), "kept");
    assert_eq!(
        m.snapshot("c").unwrap().state,
        FolderState::Stopped,
        "a folder being removed reads stopped, not failed"
    );
    m.stop();
}

#[test]
fn rotation_re_mirrors_and_carries_the_previous_epochs_known_names() {
    let e = env();
    let engine = Arc::new(FakeEngine::new(&[(
        "Zyxwuria Quolnath",
        EntityKind::Person,
    )]));
    engine.learn("Qwxzvk Yolandir", EntityKind::Person); // taught by another front door
    let m = mirror(&e, engine.clone());
    let f = folder(&e, "a", LABEL);
    std::fs::write(
        f.source.join("Zyxwuria Quolnath.txt"),
        "Zyxwuria Quolnath\n",
    )
    .unwrap();
    std::fs::write(f.source.join("notiz.txt"), "Anruf von Qwxzvk Yolandir\n").unwrap();
    m.add(f).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    let dir = e.root.join(LABEL);
    let list = || -> Vec<_> {
        let mut v: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|x| x.unwrap().file_name())
            .collect();
        v.sort();
        v
    };
    let before = list();
    let notiz_before = std::fs::read_to_string(dir.join("notiz.txt")).unwrap();
    engine.rotate(); // the learned name leaves the detector until it is carried
    std::thread::sleep(MirrorConfig::STATE_POLL + Duration::from_secs(2));
    assert!(m.wait_idle(Duration::from_secs(10)));
    assert_ne!(before, list(), "new-epoch names");
    assert_eq!(before.len(), list().len(), "the old names are gone");
    let notiz = std::fs::read_to_string(dir.join("notiz.txt")).unwrap();
    assert!(
        !notiz.contains("Qwxzvk Yolandir") && notiz.contains("<PERSON_"),
        "carried before the re-mirror"
    );
    assert_ne!(notiz, notiz_before, "a fresh token");
    assert!(*engine.carried.lock().unwrap() >= 1);
    assert!(!m.snapshot("a").unwrap().remirror_pending);
    m.stop();
}

#[test]
fn two_names_taught_within_the_tripwire_spacing_are_both_removed() {
    // Review Cr1: the second change arrives while passes are spaced 30 s
    // apart; a later poll must still run a pass for it.
    let e = env();
    let engine = Arc::new(FakeEngine::new(&[]));
    let m = mirror(&e, engine.clone());
    let f = folder(&e, "a", LABEL);
    std::fs::write(f.source.join("a.txt"), "Qwxzvk Yolandir\n").unwrap();
    std::fs::write(f.source.join("b.txt"), "Zyxwuria Quolnath\n").unwrap();
    m.add(f).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    let dir = e.root.join(LABEL);
    let clean = |n: &str, o: &str| {
        std::fs::read_to_string(dir.join(n)).is_ok_and(|s| !s.contains(o) && s.contains("<PERSON_"))
    };
    let within =
        MirrorConfig::TRIPWIRE_MIN + MirrorConfig::STATE_POLL * 2 + Duration::from_secs(10);
    engine.learn("Qwxzvk Yolandir", EntityKind::Person);
    assert!(
        wait_until(within, || clean("a.txt", "Qwxzvk Yolandir")),
        "first name removed"
    );
    engine.learn("Zyxwuria Quolnath", EntityKind::Person); // inside the 30 s spacing
    assert!(
        wait_until(within, || clean("b.txt", "Zyxwuria Quolnath")),
        "second name removed too"
    );
    m.stop();
}

#[test]
fn one_folders_jobs_never_overlap_while_folders_run_in_parallel() {
    let e = env();
    let probe = Arc::new(Probe::new(
        FakeEngine::new(&[("Zyxwuria Quolnath", EntityKind::Person)]),
        Duration::from_millis(120),
    ));
    // Overlap is made observable by a rendezvous, not by timing.
    probe.rendezvous.store(true, Ordering::SeqCst);
    let m = mirror_with(&e, probe.clone(), Arc::new(MemManifest::default()), 4);
    for (ds, label) in [("a", LABEL), ("b", "bbbbbbbbbbbbbbbb")] {
        let f = folder(&e, ds, label);
        std::fs::create_dir_all(f.source.join("akten")).unwrap();
        for i in 0..5 {
            std::fs::write(f.source.join(format!("f{i}.txt")), "Zyxwuria Quolnath\n").unwrap();
            std::fs::write(f.source.join(format!("akten/g{i}.txt")), "x\n").unwrap();
        }
        m.add(f).unwrap();
    }
    m.start();
    // The bound only catches a hang: the work is 20 engine calls of 120 ms per
    // folder, and a loaded machine (load 20) has stretched it past 60 s.
    assert!(m.wait_idle(Duration::from_secs(300)));
    for label in [LABEL, "bbbbbbbbbbbbbbbb"] {
        let d = e.root.join(label);
        assert_eq!(std::fs::read_dir(d.join("akten")).unwrap().count(), 5);
        for i in 0..5 {
            let t = std::fs::read_to_string(d.join(format!("f{i}.txt"))).unwrap();
            assert!(t.contains("<PERSON_"));
        }
    }
    assert_eq!(
        probe.max_per_dataset.load(Ordering::SeqCst),
        1,
        "two jobs of one folder ran at once"
    );
    assert!(
        probe.max_total.load(Ordering::SeqCst) >= 2,
        "different folders ran in parallel"
    );
    m.stop();
}

#[test]
fn remove_waits_for_the_writer_in_flight_before_deleting_the_tree() {
    let e = env();
    let probe = Arc::new(Probe::new(FakeEngine::new(&[]), Duration::from_millis(300)));
    let m = mirror_with(&e, probe.clone(), Arc::new(MemManifest::default()), 2);
    let f = folder(&e, "a", LABEL);
    for i in 0..4 {
        std::fs::write(f.source.join(format!("x{i}.txt")), "x\n").unwrap();
    }
    let src = f.source.clone();
    let marker = e.root.join(LABEL).join(".inumaki-mirror");
    // Every engine call of the folder ends with its tree still in place.
    let deleted_under_a_writer = Arc::new(AtomicBool::new(false));
    {
        let flag = deleted_under_a_writer.clone();
        let marker = marker.clone();
        *probe.hook.lock().unwrap() = Some(Box::new(move || {
            if !marker.exists() {
                flag.store(true, Ordering::SeqCst);
            }
        }));
    }
    m.add(f).unwrap();
    m.start();
    assert!(wait_until(Duration::from_secs(10), || probe.in_flight() > 0));
    assert!(m.remove("a").unwrap());
    let calls = probe.calls.load(Ordering::SeqCst);
    assert_eq!(
        probe.in_flight(),
        0,
        "nothing in flight once remove returns"
    );
    assert!(
        !deleted_under_a_writer.load(Ordering::SeqCst),
        "the tree was deleted while a job of the folder still ran"
    );
    assert!(!e.root.join(LABEL).exists());
    std::fs::write(src.join("late.txt"), "y\n").unwrap();
    std::thread::sleep(Duration::from_secs(2));
    assert!(!e.root.join(LABEL).exists(), "nothing recreated the tree");
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        calls,
        "no work after removal"
    );
    assert_eq!(
        std::fs::read_dir(&src).unwrap().count(),
        5,
        "source untouched"
    );
    m.stop();
}

#[test]
fn a_stopped_mirror_runs_no_more_work() {
    let e = env();
    let probe = Arc::new(Probe::new(FakeEngine::new(&[]), Duration::ZERO));
    let m = mirror_with(&e, probe.clone(), Arc::new(MemManifest::default()), 2);
    let f = folder(&e, "a", LABEL);
    std::fs::write(f.source.join("x.txt"), "x\n").unwrap();
    let src = f.source.clone();
    m.add(f).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    assert!(e.root.join(LABEL).join("x.txt").exists());
    m.stop();
    let calls = probe.calls.load(Ordering::SeqCst);
    std::fs::write(src.join("y.txt"), "y\n").unwrap();
    m.add(folder(&e, "b", "bbbbbbbbbbbbbbbb")).unwrap();
    assert!(m.rescan("a").unwrap().is_some());
    m.start(); // refused after stop
    std::thread::sleep(Duration::from_secs(2));
    assert!(!e.root.join(LABEL).join("y.txt").exists());
    assert!(!e.root.join("bbbbbbbbbbbbbbbb").exists());
    assert_eq!(probe.calls.load(Ordering::SeqCst), calls, "no engine work");
}

#[test]
fn an_untrusted_root_is_reported_and_re_adding_trusts_it_again() {
    let e = env();
    let engine = Arc::new(FakeEngine::new(&[]));
    let manifest = Arc::new(MemManifest::default());
    *manifest.fail_root_id.lock().unwrap() = true;
    let f = Folder {
        root_id: None, // the root could not be read when it was added
        ..folder(&e, "a", LABEL)
    };
    std::fs::write(f.source.join("x.txt"), "x\n").unwrap();
    let m = mirror_with(&e, engine.clone(), manifest.clone(), 1);
    m.add(f.clone()).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    assert!(e.root.join(LABEL).join("x.txt").exists());
    assert_eq!(
        m.snapshot("a").unwrap().error,
        None,
        "adopted while empty: trusted"
    );
    m.stop();

    // A restart that lost the unpersisted id: the root adopted now could be
    // anything at the path, so deletions are off, and the status says so.
    let m = mirror_with(&e, engine.clone(), manifest.clone(), 1);
    m.add(f.clone()).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    let s = m.snapshot("a").unwrap();
    assert_eq!(
        (s.state, s.error),
        (FolderState::Failed, Some(FolderError::SourceMissing))
    );

    // Removing and adding it again re-trusts the root and stores its id.
    *manifest.fail_root_id.lock().unwrap() = false;
    assert!(m.remove("a").unwrap());
    m.add(f).unwrap();
    assert!(m.wait_idle(Duration::from_secs(10)));
    let s = m.snapshot("a").unwrap();
    assert_eq!(s.error, None);
    assert_ne!(s.state, FolderState::Failed);
    assert!(manifest.root_ids.lock().unwrap().contains_key("a"));
    assert!(e.root.join(LABEL).join("x.txt").exists());
    m.stop();
}

#[test]
fn the_poller_stores_an_adopted_root_id_of_a_quiet_folder() {
    let e = env();
    let manifest = Arc::new(MemManifest::default());
    *manifest.fail_root_id.lock().unwrap() = true;
    let f = Folder {
        root_id: None,
        ..folder(&e, "a", LABEL)
    };
    let m = mirror_with(&e, Arc::new(FakeEngine::new(&[])), manifest.clone(), 1);
    m.add(f).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    assert!(manifest.root_ids.lock().unwrap().is_empty());
    *manifest.fail_root_id.lock().unwrap() = false; // the vault is back
    assert!(wait_until(
        MirrorConfig::STATE_POLL + Duration::from_secs(5),
        || manifest.root_ids.lock().unwrap().contains_key("a")
    ));
    m.stop();
}

#[test]
fn a_mirror_directory_an_agent_deleted_is_rebuilt() {
    let e = env();
    let m = mirror(&e, Arc::new(FakeEngine::new(&[])));
    let f = folder(&e, "a", LABEL);
    std::fs::write(f.source.join("x.txt"), "x\n").unwrap();
    m.add(f).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    let dir = e.root.join(LABEL);
    std::fs::remove_dir_all(&dir).unwrap();
    // The poller notices within one state poll; a whole reconcile rebuilds
    // the directory, its marker and outbox, and re-mirrors the file.
    assert!(wait_until(
        MirrorConfig::STATE_POLL + Duration::from_secs(10),
        || dir.join("x.txt").exists()
    ));
    assert_eq!(
        std::fs::read_to_string(dir.join(".inumaki-mirror")).unwrap(),
        LABEL
    );
    assert!(dir.join("outbox").is_dir());
    assert_eq!(m.snapshot("a").unwrap().error, None);
    m.stop();
}

#[test]
fn the_poller_survives_a_panic_and_still_re_mirrors_after_a_rotation() {
    let e = env();
    let probe = Arc::new(Probe::new(
        FakeEngine::new(&[("Zyxwuria Quolnath", EntityKind::Person)]),
        Duration::ZERO,
    ));
    let m = mirror_with(&e, probe.clone(), Arc::new(MemManifest::default()), 1);
    let f = folder(&e, "a", LABEL);
    std::fs::write(f.source.join("Zyxwuria Quolnath.txt"), "x\n").unwrap();
    m.add(f).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    let dir = e.root.join(LABEL);
    let names = || -> Vec<_> {
        let mut v: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|x| x.unwrap().file_name())
            .collect();
        v.sort();
        v
    };
    let before = names();
    // Nothing is queued: the next `state()` is the poller's.
    probe.panic_state.store(true, Ordering::SeqCst);
    assert!(wait_until(
        MirrorConfig::STATE_POLL + Duration::from_secs(5),
        || !probe.panic_state.load(Ordering::SeqCst)
    ));
    probe.inner.rotate();
    assert!(
        wait_until(
            MirrorConfig::STATE_POLL * 2 + Duration::from_secs(5),
            || names() != before
        ),
        "the poller still runs after a panic"
    );
    assert_ne!(m.snapshot("a").unwrap().state, FolderState::Failed);
    m.stop();
}

#[test]
fn a_panicking_job_leaves_the_pool_and_the_folder_usable() {
    let e = env();
    let probe = Arc::new(Probe::new(FakeEngine::new(&[]), Duration::ZERO));
    let fired = Arc::new(AtomicBool::new(false));
    {
        let fired = fired.clone();
        *probe.hook.lock().unwrap() = Some(Box::new(move || {
            if !fired.swap(true, Ordering::SeqCst) {
                panic!("injected panic in a job");
            }
        }));
    }
    let m = mirror_with(&e, probe.clone(), Arc::new(MemManifest::default()), 1);
    let f = folder(&e, "a", LABEL);
    std::fs::write(f.source.join("a.txt"), "x\n").unwrap();
    let src = f.source.clone();
    m.add(f).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    assert!(fired.load(Ordering::SeqCst));
    // The one worker and the folder's slot are free: a later change runs.
    std::fs::write(src.join("b.txt"), "y\n").unwrap();
    let out = e.root.join(LABEL).join("b.txt");
    assert!(wait_until(Duration::from_secs(10), || out.exists()));
    assert_ne!(m.snapshot("a").unwrap().state, FolderState::Failed);
    m.stop();
}

/// 8a re-review: a folder whose marker is gone and whose directory still
/// holds files is removed: its records go, the directory stays untouched.
#[test]
fn remove_without_the_marker_drops_the_records_and_keeps_the_directory() {
    let e = env();
    let manifest = Arc::new(MemManifest::default());
    let m = mirror_with(
        &e,
        Arc::new(FakeEngine::new(&[])),
        Arc::clone(&manifest) as Arc<dyn ManifestStore>,
        1,
    );
    let f = folder(&e, "a", LABEL);
    std::fs::write(f.source.join("x.txt"), "x").unwrap();
    m.add(f).unwrap();
    m.start();
    assert!(m.wait_idle(Duration::from_secs(10)));
    let tree = e.root.join(LABEL);
    assert!(tree.join("x.txt").exists());
    assert!(
        !manifest
            .list("a", inumaki_mirror::Side::Source)
            .unwrap()
            .is_empty()
    );
    std::fs::remove_file(tree.join(".inumaki-mirror")).unwrap();
    assert_eq!(m.remove("a"), Ok(true));
    assert!(
        manifest
            .list("a", inumaki_mirror::Side::Source)
            .unwrap()
            .is_empty()
    );
    assert!(m.snapshot("a").is_none(), "the folder is gone");
    assert!(
        tree.join("x.txt").exists(),
        "an unmarked tree is never deleted"
    );
    m.stop();
}

/// 8a re-review: the service writes through the root handle the daemon
/// prepared at load. A directory swapped in at the path since then is
/// refused, and nothing is written into it.
#[test]
fn with_root_refuses_a_root_swapped_since_it_was_prepared() {
    let e = env();
    let cfg = MirrorConfig {
        root: e.root.clone(),
        outbox_root: e.base.join("Outbox"),
        ..MirrorConfig::default()
    };
    let (dir, canonical) = inumaki_mirror::prepare_root(&cfg).unwrap();
    std::fs::rename(&e.root, e.base.join("moved")).unwrap();
    std::fs::create_dir(&e.root).unwrap();
    let r = Mirror::with_root(
        cfg.clone(),
        dir,
        canonical,
        Arc::new(FakeEngine::new(&[])),
        Arc::new(MemManifest::default()),
    );
    assert_eq!(r.err(), Some(FolderError::MirrorUnwritable));
    assert_eq!(std::fs::read_dir(&e.root).unwrap().count(), 0);
    // Unchanged, the prepared handle is used as it is.
    std::fs::remove_dir(&e.root).unwrap();
    let (dir, canonical) = inumaki_mirror::prepare_root(&cfg).unwrap();
    let m = Mirror::with_root(
        cfg,
        dir,
        canonical,
        Arc::new(FakeEngine::new(&[])),
        Arc::new(MemManifest::default()),
    )
    .unwrap();
    assert_eq!(m.root(), e.root.as_path());
}

#[test]
fn a_symlinked_mirror_root_is_refused() {
    let e = env();
    let real = e.base.join("real-root");
    std::fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&real, &e.root).unwrap();
    let cfg = MirrorConfig {
        root: e.root.clone(),
        outbox_root: e.base.join("Outbox"),
        ..MirrorConfig::default()
    };
    let r = Mirror::new(
        cfg,
        Arc::new(FakeEngine::new(&[])),
        Arc::new(MemManifest::default()),
    );
    assert_eq!(r.err(), Some(FolderError::MirrorUnwritable));
    assert_eq!(
        std::fs::read_dir(&real).unwrap().count(),
        0,
        "nothing written through it"
    );
}

/// Review C1: the configured root may be a directory the user owns (the
/// old default `~/Inumaki` was the project checkout on a case-insensitive
/// volume). It is adopted only when empty or marked by an earlier run.
#[test]
fn a_foreign_non_empty_root_is_refused_untouched_and_ours_is_adopted() {
    use std::os::unix::fs::PermissionsExt;
    let e = env();
    let cfg = MirrorConfig {
        root: e.root.clone(),
        outbox_root: e.base.join("Outbox"),
        ..MirrorConfig::default()
    };
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
    // A foreign directory with a README.txt of its own.
    std::fs::create_dir_all(&e.root).unwrap();
    std::fs::set_permissions(&e.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(e.root.join("README.txt"), "qwxzvk mine").unwrap();
    std::fs::write(e.root.join("work.txt"), "x").unwrap();
    let r = inumaki_mirror::prepare_root(&cfg);
    assert!(matches!(r, Err(FolderError::MirrorUnwritable)));
    assert_eq!(mode(&e.root), 0o755, "no fchmod");
    assert_eq!(
        std::fs::read_to_string(e.root.join("README.txt")).unwrap(),
        "qwxzvk mine"
    );
    assert!(!e.root.join(".inumaki-root").exists(), "no marker written");
    // A symlink as the root is refused as well.
    let link = e.base.join("link");
    std::os::unix::fs::symlink(&e.root, &link).unwrap();
    let c2 = MirrorConfig {
        root: link,
        ..cfg.clone()
    };
    assert!(inumaki_mirror::prepare_root(&c2).is_err());
    // An empty directory is adopted; so is a marked one with content.
    let empty = MirrorConfig {
        root: e.base.join("empty"),
        ..cfg.clone()
    };
    std::fs::create_dir_all(&empty.root).unwrap();
    inumaki_mirror::prepare_root(&empty).expect("empty root adopted");
    assert_eq!(mode(&empty.root), 0o700);
    std::fs::create_dir_all(empty.root.join("aaaaaaaaaaaaaaaa")).unwrap();
    inumaki_mirror::prepare_root(&empty).expect("marked root adopted again");
    // A root this call creates is marked.
    let fresh = MirrorConfig {
        root: e.base.join("fresh"),
        ..cfg
    };
    inumaki_mirror::prepare_root(&fresh).unwrap();
    assert!(fresh.root.join(".inumaki-root").exists());
    assert!(fresh.root.join("README.txt").exists());
}

/// Review (TCC fix round 1): jobs the job in flight queues after the
/// removal's purge (a reconcile's file jobs) run back to back and must not
/// starve the removal. No open is held: a folder removed during its first
/// scan is removed well within the removal deadline, source untouched.
#[test]
fn remove_during_a_first_scan_is_not_starved_by_queued_jobs() {
    let e = env();
    let probe = Arc::new(Probe::new(FakeEngine::new(&[]), Duration::from_millis(200)));
    let m = mirror_with(&e, probe.clone(), Arc::new(MemManifest::default()), 1);
    let f = folder(&e, "a", LABEL);
    for d in 0..5 {
        let dir = f.source.join(format!("d{d}"));
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..10 {
            std::fs::write(dir.join(format!("x{i}.txt")), "x\n").unwrap();
        }
    }
    let src = f.source.clone();
    m.add(f).unwrap();
    m.start();
    // The reconcile names its directories (engine calls) before it queues
    // the files: remove while it does.
    assert!(wait_until(Duration::from_secs(10), || probe.in_flight() > 0));
    let t0 = Instant::now();
    assert_eq!(m.remove("a"), Ok(true));
    // The removal deadline under test is 5 s, but the property is the outcome:
    // the removal is not starved into `Err(Busy)`. Wall-clock time is only a
    // generous hang guard, so a machine at load 20-30 cannot fail the test.
    assert!(t0.elapsed() < Duration::from_secs(60), "{:?}", t0.elapsed());
    assert!(!e.root.join(LABEL).exists());
    for d in 0..5 {
        assert_eq!(
            std::fs::read_dir(src.join(format!("d{d}")))
                .unwrap()
                .count(),
            10,
            "source untouched"
        );
    }
    m.stop();
}
