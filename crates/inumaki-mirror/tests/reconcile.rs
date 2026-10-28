//! M5 spec §7.2, §7.3, §7.6, §6.2, §6.3, §6.4, §9: deletes propagate (also
//! without a model); a missing, replaced, or not permitted root deletes
//! nothing and resumes; an unreadable subdirectory deletes nothing below
//! it; orphans and crash leftovers are removed; a subdirectory swapped for
//! a symlink is not followed; a kill before the rename leaves no file under
//! a real name; a policy change or a rotation renames directories and
//! removes the old ones; no name reservation outlives a failed write.

mod common;

use std::sync::Arc;

use common::{FakeEngine, MemManifest};
use inumaki_core::span::EntityKind;
use inumaki_mirror::fsops::{TMP_PREFIX, inject_crash_before_rename};
use inumaki_mirror::status::{FolderError, FolderState};
use inumaki_mirror::testing::TestMirror;
use inumaki_mirror::{EngineError, root_generation};

fn t() -> TestMirror {
    TestMirror::new(
        Arc::new(FakeEngine::new(&[(
            "Zyxwuria Quolnath",
            EntityKind::Person,
        )])),
        Arc::new(MemManifest::default()),
    )
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn all_text(root: &std::path::Path) -> String {
    let mut out = String::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            out.push_str(&p.to_string_lossy());
            out.push('\n');
            if e.file_type().unwrap().is_dir() {
                stack.push(p);
            } else {
                out.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
            }
        }
    }
    out
}

#[test]
fn deletes_and_directory_renames_propagate() {
    let t = t();
    std::fs::create_dir_all(t.source().join("akten/2026")).unwrap();
    std::fs::write(t.source().join("akten/2026/a.txt"), "a").unwrap();
    std::fs::write(t.source().join("b.txt"), "b").unwrap();
    t.reconcile_all();
    assert!(t.mirror_dir().join("akten/2026/a.txt").exists());
    std::fs::remove_file(t.source().join("b.txt")).unwrap();
    std::fs::rename(t.source().join("akten"), t.source().join("archiv")).unwrap();
    t.reconcile_all();
    assert!(!t.mirror_dir().join("b.txt").exists());
    assert!(!t.mirror_dir().join("akten").exists());
    assert!(t.mirror_dir().join("archiv/2026/a.txt").exists());
    assert_eq!(t.snapshot().files.mirrored, 1);
}

#[test]
fn deletes_continue_without_a_model() {
    // Spec §7.6, §9: deletions need no engine.
    let e = Arc::new(FakeEngine::new(&[]));
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    std::fs::create_dir_all(t.source().join("akten")).unwrap();
    std::fs::write(t.source().join("akten/a.txt"), "a").unwrap();
    std::fs::write(t.source().join("b.txt"), "b").unwrap();
    t.reconcile_all();
    *e.fail.lock().unwrap() = Some(EngineError::ModelUnavailable);
    std::fs::remove_dir_all(t.source().join("akten")).unwrap();
    std::fs::write(t.source().join("c.txt"), "c").unwrap();
    t.reconcile_all();
    assert!(
        !t.mirror_dir().join("akten").exists(),
        "the deleted directory went"
    );
    assert!(t.mirror_dir().join("b.txt").exists(), "the rest stays");
    assert!(
        !t.mirror_dir().join("c.txt").exists(),
        "nothing new without a model"
    );
    assert_eq!(t.snapshot().error, Some(FolderError::ModelUnavailable));
}

#[test]
fn a_missing_root_deletes_nothing_and_resumes() {
    // Review Focus 2: an external drive not mounted at start.
    let t = t();
    std::fs::create_dir_all(t.source().join("akten")).unwrap();
    std::fs::write(t.source().join("akten/a.txt"), "a").unwrap();
    std::fs::write(t.source().join("a.txt"), "a").unwrap();
    t.reconcile_all();
    let before = all_text(&t.mirror_dir());
    let moved = t.source().with_extension("unmounted");
    std::fs::rename(t.source(), &moved).unwrap();
    assert_eq!(t.reconcile_all_result(), Err(FolderError::SourceMissing));
    assert_eq!(all_text(&t.mirror_dir()), before, "nothing deleted");
    let s = t.snapshot();
    assert_eq!(
        (s.state, s.error),
        (FolderState::Failed, Some(FolderError::SourceMissing))
    );
    assert_eq!(s.files.mirrored, 2, "the manifest kept its rows");
    std::fs::rename(&moved, t.source()).unwrap();
    t.reconcile_all();
    let s = t.snapshot();
    assert_eq!((s.state, s.error), (FolderState::Watching, None));
    assert_eq!(all_text(&t.mirror_dir()), before);
}

#[test]
fn a_replaced_root_is_source_missing() {
    let t = t();
    std::fs::write(t.source().join("a.txt"), "a").unwrap();
    t.reconcile_all();
    std::fs::remove_dir_all(t.source()).unwrap();
    std::fs::create_dir(t.source()).unwrap(); // same path, new inode
    assert!(t.reconcile_all_result().is_err());
    assert_eq!(t.snapshot().error, Some(FolderError::SourceMissing));
    assert!(t.mirror_dir().join("a.txt").exists());
}

#[test]
fn a_stored_id_without_a_generation_learns_and_stores_it() {
    // A folder added before generations were recorded: the first open
    // stores the root's generation where the filesystem has one (Linux ext4,
    // XFS), so a later replacement is seen; elsewhere nothing changes.
    use std::os::unix::fs::MetadataExt;
    let m = Arc::new(MemManifest::default());
    let t = TestMirror::new_without_generation(Arc::new(FakeEngine::new(&[])), m.clone());
    std::fs::write(t.source().join("a.txt"), "a").unwrap();
    t.reconcile_all();
    let md = std::fs::metadata(t.source()).unwrap();
    let stored = m.root_ids.lock().unwrap().values().next().copied();
    match root_generation(&t.source(), md.dev(), md.ino()) {
        Some(g) => assert_eq!(stored.and_then(|r| r.generation), Some(g)),
        None => assert_eq!(stored, None, "nothing to learn"),
    }
    std::fs::remove_dir_all(t.source()).unwrap();
    std::fs::create_dir(t.source()).unwrap();
    assert!(
        t.reconcile_all_result().is_err(),
        "the learned id is compared"
    );
}

#[test]
fn an_eperm_root_is_source_not_permitted_deletes_nothing_and_resumes() {
    // Spec §9.1, §16.1 item 9: a privacy denial, simulated by an injected errno.
    let t = t();
    std::fs::write(t.source().join("a.txt"), "a").unwrap();
    t.reconcile_all();
    t.inject_source_error(Some(libc::EPERM));
    assert!(t.reconcile_all_result().is_err());
    let s = t.snapshot();
    assert_eq!(
        (s.state, s.error),
        (FolderState::Failed, Some(FolderError::SourceNotPermitted))
    );
    assert!(t.mirror_dir().join("a.txt").exists(), "nothing deleted");
    t.inject_source_error(None); // the user granted access
    t.reconcile_all();
    assert_eq!(t.snapshot().error, None);
}

#[test]
fn an_unreadable_subdirectory_deletes_nothing_below_it() {
    // Review I4: only NotFound and ELOOP delete; EACCES/EPERM/EIO keep.
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: a plain getter.
    if unsafe { libc::geteuid() } == 0 {
        return; // root reads everything: nothing to test here
    }
    let t = t();
    std::fs::create_dir_all(t.source().join("akten/2026")).unwrap();
    std::fs::write(t.source().join("akten/a.txt"), "a").unwrap();
    std::fs::write(t.source().join("akten/2026/b.txt"), "b").unwrap();
    t.reconcile_all();
    let dir = t.source().join("akten");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let r = t.reconcile_all_result();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(r.is_ok());
    assert!(
        t.mirror_dir().join("akten/a.txt").exists(),
        "kept while unreadable"
    );
    assert!(t.mirror_dir().join("akten/2026/b.txt").exists());
}

#[test]
fn orphans_leftovers_and_vanished_mirror_files_are_repaired() {
    let t = t();
    std::fs::create_dir_all(t.source().join("akten")).unwrap();
    std::fs::write(t.source().join("a.txt"), "a").unwrap();
    std::fs::write(t.source().join("akten/b.txt"), "b").unwrap();
    t.reconcile_all();
    let m = t.mirror_dir();
    std::fs::write(m.join("agent-wrote-this.txt"), "x").unwrap();
    std::fs::create_dir_all(m.join("agent-dir/sub")).unwrap();
    std::fs::write(m.join("agent-dir/sub/x.txt"), "x").unwrap();
    std::fs::write(m.join("akten/agent.txt"), "x").unwrap();
    std::os::unix::fs::symlink("/etc/hosts", m.join("akten/link")).unwrap();
    std::fs::write(m.join(".inumaki-tmp-0011223344556677"), "partial").unwrap();
    std::fs::remove_file(m.join("a.txt")).unwrap();
    std::fs::write(m.join("outbox/reply.txt"), "kept").unwrap();
    t.reconcile_all();
    assert!(!m.join("agent-wrote-this.txt").exists());
    assert!(!m.join("agent-dir").exists());
    assert!(!m.join("akten/agent.txt").exists());
    assert!(std::fs::symlink_metadata(m.join("akten/link")).is_err());
    assert!(!m.join(".inumaki-tmp-0011223344556677").exists());
    assert!(m.join("a.txt").exists(), "redone");
    assert!(m.join("akten/b.txt").exists());
    assert!(
        m.join("outbox/reply.txt").exists(),
        "the outbox is never swept"
    );
    assert!(m.join(".inumaki-mirror").exists());
}

#[test]
fn a_subdirectory_swapped_for_a_symlink_is_not_followed() {
    // Spec §6.4, §16.1 item 7: the walk queued `akten/a.txt`; `akten` then
    // becomes a link to a directory outside the root before the file runs.
    let t = t();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("a.txt"), "GEHEIM Qwxzvk\n").unwrap();
    std::fs::create_dir_all(t.source().join("akten")).unwrap();
    std::fs::write(t.source().join("akten/a.txt"), "harmlos\n").unwrap();
    t.reconcile_no_drain().unwrap();
    std::fs::remove_dir_all(t.source().join("akten")).unwrap();
    std::os::unix::fs::symlink(outside.path(), t.source().join("akten")).unwrap();
    t.drain();
    t.reconcile_all();
    let text = all_text(&t.mirror_dir());
    assert!(
        !text.contains("GEHEIM"),
        "the link target reached the mirror"
    );
    assert!(
        t.mirror_dir()
            .join("akten.inumaki-unsupported.txt")
            .exists()
    );
    assert!(!t.mirror_dir().join("akten").exists());
}

#[test]
fn a_kill_before_the_rename_leaves_no_real_name_and_the_next_start_cleans_up() {
    // Spec §6.3, §16.1 item 3.
    let t = t();
    std::fs::write(t.source().join("brief.txt"), "Zyxwuria Quolnath\n").unwrap();
    inject_crash_before_rename(true);
    let r = t.process_result("brief.txt");
    inject_crash_before_rename(false);
    assert!(r.is_err());
    let before = names(&t.mirror_dir());
    assert!(
        !before.contains(&"brief.txt".to_string()),
        "nothing under the real name"
    );
    assert!(
        before.iter().any(|n| n.starts_with(TMP_PREFIX)),
        "the temporary file stays, as after a kill"
    );
    let t2 = t.restart();
    t2.reconcile_all();
    let after = names(&t2.mirror_dir());
    assert!(
        after.iter().all(|n| !n.starts_with(TMP_PREFIX)),
        "{after:?}"
    );
    assert!(t2.mirror_dir().join("brief.txt").exists());
}

#[test]
fn a_policy_change_or_rotation_renames_directories_and_removes_the_old_ones() {
    // 5b review I1/M2, N2: a directory name an older policy left in clear is
    // sanitized again on a same-epoch fingerprint change, and the directory
    // under its old name (in clear, or with an older epoch's tokens) goes.
    let e = Arc::new(FakeEngine::new(&[]));
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    std::fs::create_dir_all(t.source().join("Qwxzvk/2026")).unwrap();
    std::fs::create_dir_all(t.source().join("Qwxzvk leer")).unwrap();
    std::fs::write(t.source().join("Qwxzvk/2026/a.txt"), "a\n").unwrap();
    t.reconcile_all();
    assert!(
        t.mirror_dir().join("Qwxzvk/2026/a.txt").exists(),
        "in clear under the old policy"
    );
    let epoch = t.snapshot().epoch_id;

    // The same epoch, a policy that detects the name.
    e.learn("Qwxzvk", EntityKind::Person);
    *e.fingerprint.lock().unwrap() = [7; 32];
    t.reconcile_all();
    assert_eq!(t.snapshot().epoch_id, epoch);
    let text = all_text(&t.mirror_dir());
    assert!(!text.contains("Qwxzvk"), "a name left in clear: {text}");
    let tokened: Vec<String> = names(&t.mirror_dir())
        .into_iter()
        .filter(|n| n.starts_with("<PERSON_"))
        .collect();
    assert_eq!(tokened.len(), 2, "{tokened:?}");
    let dir = tokened
        .iter()
        .find(|n| !n.ends_with(" leer"))
        .unwrap()
        .clone();
    assert!(t.mirror_dir().join(&dir).join("2026/a.txt").exists());
    assert!(!t.snapshot().remirror_pending);

    // A rotation: new tokens, so new directory names; the old ones go.
    e.rotate();
    t.reconcile_all();
    let after = names(&t.mirror_dir());
    for old in &tokened {
        assert!(!after.contains(old), "old-epoch directory kept: {after:?}");
    }
    let dir2 = after
        .iter()
        .find(|n| n.starts_with("<PERSON_") && !n.ends_with(" leer"))
        .unwrap();
    assert!(t.mirror_dir().join(dir2).join("2026/a.txt").exists());
    assert!(!all_text(&t.mirror_dir()).contains("Qwxzvk"));
    assert_eq!(after.len(), 4, "marker, outbox, two directories: {after:?}");
    assert!(t.claims_balanced());
}

#[test]
fn a_failed_write_leaves_no_name_reservation() {
    // 5b review M3/N2: `commit` reserves the mirror name before writing; a
    // write that fails must release it, or another entry would get a
    // collision suffix for a name nobody holds.
    let t = t();
    std::fs::write(t.source().join("brief.txt"), "Zyxwuria Quolnath\n").unwrap();
    inject_crash_before_rename(true);
    let r = t.process_result("brief.txt");
    inject_crash_before_rename(false);
    assert!(r.is_err());
    assert!(
        t.claims_balanced(),
        "a reservation outlived the failed write"
    );
    // Another source entry now wants the same (case-folded) name.
    std::fs::rename(t.source().join("brief.txt"), t.source().join("Brief.txt")).unwrap();
    t.reconcile_all();
    let n: Vec<String> = names(&t.mirror_dir())
        .into_iter()
        .filter(|n| n != ".inumaki-mirror" && n != "outbox")
        .collect();
    assert_eq!(n, vec!["Brief.txt".to_string()], "no collision suffix");
    assert!(t.claims_balanced());
}

#[test]
fn many_sibling_directories_walk_within_a_low_fd_limit() {
    // 5c review I1: the walk must not hold one descriptor per sibling
    // directory (macOS gives a daemon 256). Cargo raises the limit for its
    // tests, so this test re-runs itself alone in a child process with the
    // soft limit lowered to 64 and 200 sibling directories.
    const TEST: &str = "many_sibling_directories_walk_within_a_low_fd_limit";
    if std::env::var_os("INUMAKI_FD_CHILD").is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1"])
            .env("INUMAKI_FD_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "child failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain getters/setters on a valid struct.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
        lim.rlim_cur = 64;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
    }
    let t = t();
    for i in 0..200 {
        let d = t.source().join(format!("kunde-{i:03}"));
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("a.txt"), "a").unwrap();
    }
    t.reconcile_all();
    let s = t.snapshot();
    assert_eq!(s.error, None);
    assert_eq!(s.files.mirrored, 200);
}

#[test]
fn an_unpersisted_root_id_deletes_nothing_after_a_restart() {
    // 5c review I2: a folder added under a privacy denial has no stored
    // (device, inode). The id adopted before anything was mirrored is
    // trusted in that run; if it could not be persisted, a restart cannot
    // tell the mirrored root from an empty mount point at the same path.
    let m = Arc::new(MemManifest::default());
    *m.fail_root_id.lock().unwrap() = true;
    let t = TestMirror::new_unidentified(Arc::new(FakeEngine::new(&[])), m.clone());
    std::fs::write(t.source().join("a.txt"), "a").unwrap();
    std::fs::write(t.source().join("b.txt"), "b").unwrap();
    t.reconcile_all();
    std::fs::remove_file(t.source().join("b.txt")).unwrap();
    t.reconcile_all();
    assert!(
        !t.mirror_dir().join("b.txt").exists(),
        "trusted in this run"
    );
    let t2 = t.restart();
    std::fs::remove_dir_all(t2.source()).unwrap();
    std::fs::create_dir(t2.source()).unwrap(); // an empty mount point
    t2.reconcile_all();
    assert!(t2.process_result("a.txt").is_ok());
    assert!(t2.mirror_dir().join("a.txt").exists(), "nothing deleted");
    assert_eq!(t2.snapshot().files.mirrored, 1);
    assert!(
        m.root_ids.lock().unwrap().is_empty(),
        "an adopted id over a manifest is never stored"
    );
}

#[test]
fn a_persisted_adopted_root_id_detects_a_replaced_root_after_a_restart() {
    let m = Arc::new(MemManifest::default());
    let t = TestMirror::new_unidentified(Arc::new(FakeEngine::new(&[])), m.clone());
    std::fs::write(t.source().join("a.txt"), "a").unwrap();
    t.reconcile_all();
    assert_eq!(m.root_ids.lock().unwrap().len(), 1, "adopted and stored");
    let t2 = t.restart();
    std::fs::remove_dir_all(t2.source()).unwrap();
    std::fs::create_dir(t2.source()).unwrap();
    assert_eq!(t2.reconcile_all_result(), Err(FolderError::SourceMissing));
    assert!(t2.mirror_dir().join("a.txt").exists());
}

#[test]
fn a_case_rename_frees_the_old_name_before_naming() {
    // 5c review minor 2: the deletion runs first, so the renamed file takes
    // the plain name, not a collision suffix.
    let t = t();
    std::fs::write(t.source().join("brief.txt"), "a").unwrap();
    t.reconcile_all();
    std::fs::rename(t.source().join("brief.txt"), t.source().join("Brief.txt")).unwrap();
    t.reconcile_all();
    let n: Vec<String> = names(&t.mirror_dir())
        .into_iter()
        .filter(|n| n != ".inumaki-mirror" && n != "outbox")
        .collect();
    assert_eq!(n, vec!["Brief.txt".to_string()]);
    assert!(t.claims_balanced());
}

#[test]
fn unchanged_placeholders_are_not_rewritten() {
    // Integrator ruling: a link, too-large, or unreadable placeholder whose
    // entry did not change is not written again (no new inode, no event).
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let t = t();
    let src = t.source();
    std::os::unix::fs::symlink("/etc/hosts", src.join("link")).unwrap();
    std::fs::write(src.join("gross.txt"), vec![b'a'; 2 * 1024 * 1024]).unwrap();
    std::fs::write(src.join("geheim.txt"), "x").unwrap();
    // SAFETY: a plain getter.
    let unreadable = unsafe { libc::geteuid() } != 0;
    if unreadable {
        std::fs::set_permissions(
            src.join("geheim.txt"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
    }
    t.reconcile_all();
    let mut ph = vec![
        "link.inumaki-unsupported.txt",
        "gross.txt.inumaki-unsupported.txt",
    ];
    if unreadable {
        ph.push("geheim.txt.inumaki-unsupported.txt");
    }
    let inodes = |t: &TestMirror| -> Vec<u64> {
        ph.iter()
            .map(|p| std::fs::metadata(t.mirror_dir().join(p)).unwrap().ino())
            .collect()
    };
    let before = inodes(&t);
    for rel in ["link", "gross.txt", "geheim.txt"] {
        t.process(rel); // a live event
    }
    t.reconcile_all();
    t.reconcile_all_forced();
    let after = inodes(&t);
    std::fs::set_permissions(
        src.join("geheim.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(before, after, "a placeholder was rewritten");
    // A changed entry is still redone: the file shrinks under the limit.
    std::fs::write(src.join("gross.txt"), "klein").unwrap();
    t.reconcile_all();
    assert!(t.mirror_dir().join("gross.txt").exists());
    assert!(
        !t.mirror_dir()
            .join("gross.txt.inumaki-unsupported.txt")
            .exists()
    );
}
