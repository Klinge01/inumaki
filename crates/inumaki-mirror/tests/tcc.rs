//! TCC spike finding 2: on macOS a launchd job's first read of a protected
//! folder blocks inside `open()` until the user answers the privacy prompt.
//! A parked open (the `OpenHold` test seam) must not hang removal or stop,
//! and the folder must read `pending` while it waits.

mod common;

use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{FakeEngine, MemManifest};
use inumaki_mirror::{Folder, FolderError, FolderState, Mirror, MirrorConfig};

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
    std::fs::write(src.join("x.txt"), "x\n").unwrap();
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

fn mirror(e: &Env) -> Arc<Mirror> {
    let cfg = MirrorConfig {
        root: e.root.clone(),
        outbox_root: e.base.join("Outbox"),
        workers: 1,
        ..MirrorConfig::default()
    };
    Mirror::new(
        cfg,
        Arc::new(FakeEngine::new(&[])),
        Arc::new(MemManifest::default()),
    )
    .unwrap()
}

/// Run `f` on its own thread; its result, or `None` if it took longer than
/// `within` (the thread is left behind).
fn bounded<T: Send + 'static>(
    within: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(within).ok()
}

fn wait_until(within: Duration, f: impl Fn() -> bool) -> bool {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

#[test]
fn remove_with_a_parked_open_answers_busy_and_a_later_remove_finishes() {
    let e = env();
    let m = mirror(&e);
    let hold = m.hold_source_opens();
    m.add(folder(&e, "a", LABEL)).unwrap();
    m.start();
    assert!(hold.wait_parked(Duration::from_secs(10)), "no open parked");

    let t0 = Instant::now();
    let mm = Arc::clone(&m);
    let r = bounded(Duration::from_secs(11), move || mm.remove("a"))
        .expect("remove hung behind the parked open");
    assert!(t0.elapsed() < Duration::from_secs(9), "{:?}", t0.elapsed());
    assert_eq!(r, Err(FolderError::Busy));
    assert_eq!(FolderError::Busy.as_str(), "busy");
    // Kept down while the removal is unfinished; the tree is still there.
    assert_eq!(m.snapshot("a").unwrap().state, FolderState::Stopped);
    assert!(e.root.join(LABEL).exists());
    let src_file = e.base.join("src-a").join("x.txt");
    assert!(src_file.exists(), "a busy removal never touches the source");

    hold.release();
    let mm = Arc::clone(&m);
    let r =
        bounded(Duration::from_secs(10), move || mm.remove("a")).expect("the second remove hung");
    assert_eq!(r, Ok(true));
    assert!(!e.root.join(LABEL).exists(), "the tree is gone");
    assert!(src_file.exists(), "the removal never touches the source");
    assert!(m.snapshot("a").is_none());
    m.stop();
}

#[test]
fn stop_with_a_parked_open_returns_within_the_deadline() {
    let e = env();
    let m = mirror(&e);
    let hold = m.hold_source_opens();
    m.add(folder(&e, "a", LABEL)).unwrap();
    m.start();
    assert!(hold.wait_parked(Duration::from_secs(10)), "no open parked");
    let t0 = Instant::now();
    let mm = Arc::clone(&m);
    bounded(Duration::from_secs(9), move || mm.stop()).expect("stop hung behind the parked open");
    assert!(t0.elapsed() < Duration::from_secs(6), "{:?}", t0.elapsed());
    drop(hold);
}

#[test]
fn a_first_open_waiting_past_the_threshold_reads_pending_without_blocking() {
    let e = env();
    let m = mirror(&e);
    let hold = m.hold_source_opens();
    m.add(folder(&e, "a", LABEL)).unwrap();
    m.start();
    assert!(hold.wait_parked(Duration::from_secs(10)), "no open parked");
    // Before the threshold: not yet pending.
    let s = m.snapshot("a").unwrap();
    assert_ne!(s.state, FolderState::Pending);
    // The snapshot answers at once while the open waits, and turns
    // `pending` once the open has waited past the threshold.
    assert!(wait_until(Duration::from_secs(5), || {
        let t = Instant::now();
        let s = m.snapshot("a").unwrap();
        assert!(t.elapsed() < Duration::from_millis(500), "snapshot blocked");
        s.state == FolderState::Pending
    }));
    hold.release();
    assert!(m.wait_idle(Duration::from_secs(10)));
    assert!(wait_until(Duration::from_secs(5), || {
        m.snapshot("a").unwrap().state == FolderState::Watching
    }));
    assert!(
        e.root.join(LABEL).join("x.txt").exists(),
        "mirrored after the answer"
    );
    m.stop();
}

#[test]
fn the_pending_mark_covers_only_the_open_in_progress() {
    let t = Arc::new(inumaki_mirror::testing::TestMirror::new(
        Arc::new(FakeEngine::new(&[])),
        Arc::new(MemManifest::default()),
    ));
    std::fs::write(t.source().join("x.txt"), "x\n").unwrap();
    let hold = t.hold_source_opens();
    let tt = Arc::clone(&t);
    let job = std::thread::spawn(move || tt.reconcile_once());
    assert!(hold.wait_parked(Duration::from_secs(10)), "no open parked");
    assert_ne!(t.snapshot().state, FolderState::Pending, "not before 2 s");
    t.backdate_open(Duration::from_secs(3));
    assert_eq!(t.snapshot().state, FolderState::Pending);
    hold.release();
    job.join().unwrap().unwrap();
    // Cleared when the open returned: never a stale `pending`.
    assert_ne!(t.snapshot().state, FolderState::Pending);
    t.drain(); // the file jobs the reconcile queued
    assert!(t.mirror_dir().join("x.txt").exists());
}
