//! M5 spec §8: strict restoration, never overwriting, sidecars with counts
//! only, no duplicate after a restart, symlinks and hard links refused,
//! restored names that cannot escape the destination, files written while
//! the daemon was down picked up by the reconcile (review I5), and nothing
//! in the user's destination ever removed (review I6). Also §9: an
//! unwritable destination keeps the file pending; a file that changes while
//! it settles is requeued, never copied.

mod common;

use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::Arc;

use common::{FakeEngine, MemManifest};
use inumaki_core::span::EntityKind;
use inumaki_mirror::Side;
use inumaki_mirror::fsops::inject_noreplace_unsupported;
use inumaki_mirror::queue::Job;
use inumaki_mirror::status::{FolderError, FolderState};
use inumaki_mirror::testing::TestMirror;

const NAME: &str = "Zyxwuria Quolnath";

fn setup() -> (TestMirror, String) {
    let e = Arc::new(FakeEngine::new(&[
        (NAME, EntityKind::Person),
        ("Neubaugasse 22/5", EntityKind::StreetAddress),
    ]));
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    std::fs::write(
        t.source().join("brief.txt"),
        format!("{NAME}, Neubaugasse 22/5\n"),
    )
    .unwrap();
    t.reconcile_all();
    let mirrored = std::fs::read_to_string(t.mirror_dir().join("brief.txt")).unwrap();
    assert!(!mirrored.contains(NAME), "the mirror holds tokens");
    (t, mirrored)
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn a_known_token_is_restored_and_unknown_ones_are_refused() {
    let (t, mirrored) = setup();
    std::fs::write(t.outbox_dir().join("reply.txt"), &mirrored).unwrap();
    t.process_outbox("reply.txt");
    assert_eq!(
        std::fs::read_to_string(t.destination().join("reply.txt")).unwrap(),
        format!("{NAME}, Neubaugasse 22/5\n")
    );
    let mode = std::fs::metadata(t.destination().join("reply.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "destination files hold originals");
    std::fs::write(
        t.outbox_dir().join("bad.txt"),
        "Hallo <PERSON_ffffff>, <PERSON_dddddd> und <SECRET_REMOVED>\n",
    )
    .unwrap();
    t.process_outbox("bad.txt");
    assert!(!t.destination().join("bad.txt").exists(), "not written");
    let note =
        std::fs::read_to_string(t.outbox_dir().join("bad.txt.inumaki-unresolved.txt")).unwrap();
    assert!(
        note.contains("2 token(s)") && note.contains("1 removed value(s)"),
        "{note}"
    );
    assert!(!note.contains("PERSON_"), "{note}");
    assert!(!note.contains(NAME));
    assert_eq!(t.snapshot().outbox.with_unresolved, 1);
    assert_eq!(t.snapshot().outbox.rehydrated, 1);
    // A token anywhere in the name is strict too: nothing is written.
    std::fs::write(t.outbox_dir().join("<PERSON_eeeeee>.txt"), "hallo\n").unwrap();
    t.process_outbox("<PERSON_eeeeee>.txt");
    assert_eq!(names(&t.destination()), vec!["reply.txt".to_string()]);
}

#[test]
fn rewriting_an_outbox_file_never_overwrites_the_destination() {
    let (t, mirrored) = setup();
    std::fs::write(t.outbox_dir().join("reply.txt"), "eins\n").unwrap();
    t.process_outbox("reply.txt");
    std::fs::write(t.outbox_dir().join("reply.txt"), format!("zwei {mirrored}")).unwrap();
    t.process_outbox("reply.txt");
    assert_eq!(
        std::fs::read_to_string(t.destination().join("reply.txt")).unwrap(),
        "eins\n"
    );
    assert!(
        std::fs::read_to_string(t.destination().join("reply (2).txt"))
            .unwrap()
            .starts_with("zwei ")
    );
    t.process_outbox("reply.txt"); // unchanged: nothing new
    assert!(!t.destination().join("reply (3).txt").exists());
    let t2 = t.restart();
    t2.process_outbox("reply.txt");
    assert!(
        !t2.destination().join("reply (3).txt").exists(),
        "no duplicate after a restart"
    );
}

#[test]
fn the_exclusive_create_fallback_never_overwrites_either() {
    // A file system without the no-replace rename (exFAT, some SMB/NFS):
    // `O_CREAT | O_EXCL` on the final name, never a plain rename.
    let (t, _) = setup();
    std::fs::write(t.destination().join("reply.txt"), "user data\n").unwrap();
    std::fs::write(t.outbox_dir().join("reply.txt"), "eins\n").unwrap();
    inject_noreplace_unsupported(true);
    let r = t.process_outbox_result("reply.txt");
    inject_noreplace_unsupported(false);
    r.unwrap();
    assert_eq!(
        std::fs::read_to_string(t.destination().join("reply.txt")).unwrap(),
        "user data\n"
    );
    assert_eq!(
        std::fs::read_to_string(t.destination().join("reply (2).txt")).unwrap(),
        "eins\n"
    );
}

#[test]
fn links_are_refused_and_restored_names_stay_inside() {
    let (t, mirrored) = setup();
    let secret = t.source().join("brief.txt");
    symlink(&secret, t.outbox_dir().join("link.txt")).unwrap();
    t.process_outbox("link.txt");
    assert!(!t.destination().join("link.txt").exists());
    assert!(t.outbox_dir().join("link.txt.inumaki-refused.txt").exists());
    std::fs::hard_link(
        t.mirror_dir().join("brief.txt"),
        t.outbox_dir().join("hard.txt"),
    )
    .unwrap();
    t.process_outbox("hard.txt");
    assert!(!t.destination().join("hard.txt").exists());
    assert!(t.outbox_dir().join("hard.txt.inumaki-refused.txt").exists());
    // A token whose original contains "/" restores into one component.
    let addr_token = mirrored.split(", ").nth(1).unwrap().trim().to_string();
    std::fs::write(t.outbox_dir().join(format!("{addr_token}.txt")), "x").unwrap();
    t.process_outbox(&format!("{addr_token}.txt"));
    let names = names(&t.destination());
    assert!(
        names.contains(&"Neubaugasse 22_5.txt".to_string()),
        "{names:?}"
    );
    assert!(!t.destination().join("Neubaugasse 22").exists());
    // A link where the destination itself belongs is never written through.
    let outside = tempfile::tempdir().unwrap();
    std::fs::remove_dir_all(t.destination()).unwrap();
    symlink(outside.path(), t.destination()).unwrap();
    std::fs::write(t.outbox_dir().join("via.txt"), "hallo\n").unwrap();
    assert_eq!(
        t.process_outbox_result("via.txt"),
        Err(FolderError::OutboxUnwritable)
    );
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn a_file_written_while_the_daemon_was_down_is_found_by_the_reconcile() {
    // Review I5: no event was ever delivered for it; the reconcile's outbox
    // walk queues every file whose content differs from its record.
    let (t, mirrored) = setup();
    std::fs::write(t.outbox_dir().join("offline.txt"), &mirrored).unwrap();
    let t2 = t.restart();
    t2.reconcile_all();
    assert_eq!(
        std::fs::read_to_string(t2.destination().join("offline.txt")).unwrap(),
        format!("{NAME}, Neubaugasse 22/5\n")
    );
    t2.reconcile_all();
    assert!(
        !t2.destination().join("offline (2).txt").exists(),
        "an unchanged file is not written again"
    );
}

#[test]
fn nothing_in_the_way_at_the_destination_is_ever_removed() {
    // Review I6: a file or a symlink where a destination directory belongs
    // is refused with a sidecar; it is never unlinked or written through.
    let (t, _) = setup();
    std::fs::create_dir_all(t.destination()).unwrap();
    std::fs::write(t.destination().join("akten"), "user data\n").unwrap();
    std::fs::create_dir_all(t.outbox_dir().join("akten")).unwrap();
    std::fs::write(t.outbox_dir().join("akten/reply.txt"), "hallo\n").unwrap();
    t.process_outbox("akten/reply.txt");
    assert_eq!(
        std::fs::read_to_string(t.destination().join("akten")).unwrap(),
        "user data\n"
    );
    assert!(
        t.outbox_dir()
            .join("akten/reply.txt.inumaki-refused.txt")
            .exists()
    );
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), t.destination().join("briefe")).unwrap();
    std::fs::create_dir_all(t.outbox_dir().join("briefe")).unwrap();
    std::fs::write(t.outbox_dir().join("briefe/reply.txt"), "hallo\n").unwrap();
    t.process_outbox("briefe/reply.txt");
    assert!(
        std::fs::symlink_metadata(t.destination().join("briefe"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link stays"
    );
    assert_eq!(
        std::fs::read_dir(outside.path()).unwrap().count(),
        0,
        "nothing written through it"
    );
}

#[test]
fn a_file_changing_while_it_settles_is_requeued_never_copied() {
    let (t, _) = setup();
    let p = t.outbox_dir().join("reply.txt");
    std::fs::write(&p, "erster Teil\n").unwrap();
    // The writer is still at work between the two checks.
    let q = p.clone();
    t.during_outbox_settle(Some(Box::new(move || {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&q).unwrap();
        f.write_all(b"zweiter Teil\n").unwrap();
    })));
    t.process_outbox("reply.txt");
    t.during_outbox_settle(None);
    assert!(
        !t.destination().join("reply.txt").exists(),
        "not copied half-written"
    );
    match t.next_job() {
        Some((Job::Outbox { rel, .. }, _)) => assert_eq!(rel, b"reply.txt"),
        other => panic!("requeued: {:?}", other.map(|(j, _)| j)),
    }
    t.process_outbox("reply.txt");
    assert_eq!(
        std::fs::read_to_string(t.destination().join("reply.txt")).unwrap(),
        "erster Teil\nzweiter Teil\n"
    );
}

#[test]
fn an_unwritable_destination_keeps_the_file_pending() {
    let (t, mirrored) = setup();
    let dest = t.destination();
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::write(t.outbox_dir().join("reply.txt"), &mirrored).unwrap();
    let r = t.process_outbox_result("reply.txt");
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(r, Err(FolderError::OutboxUnwritable));
    let s = t.snapshot();
    assert_eq!(s.error, Some(FolderError::OutboxUnwritable));
    assert_ne!(s.state, FolderState::Failed, "not failing (spec §9)");
    assert_eq!(s.outbox.pending, 1);
    assert_eq!(s.outbox.rehydrated, 0);
    assert!(
        !t.outbox_dir()
            .join("reply.txt.inumaki-refused.txt")
            .exists()
    );
    // Retried once writable: written, the error and the pending entry clear.
    t.process_outbox("reply.txt");
    assert_eq!(
        std::fs::read_to_string(dest.join("reply.txt")).unwrap(),
        format!("{NAME}, Neubaugasse 22/5\n")
    );
    let s = t.snapshot();
    assert_eq!(s.error, None);
    assert_eq!((s.outbox.pending, s.outbox.rehydrated), (0, 1));
}

#[test]
fn outbox_unwritable_follows_the_pending_files() {
    // 7 review I1: the error holds while some file is pending, also when
    // another one is written, and clears once none is, however it left.
    let (t, _) = setup();
    let sub = t.destination().join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::create_dir_all(t.outbox_dir().join("sub")).unwrap();
    std::fs::write(t.outbox_dir().join("sub/a.txt"), "a\n").unwrap();
    std::fs::write(t.outbox_dir().join("b.txt"), "b\n").unwrap();
    let a = t.process_outbox_result("sub/a.txt");
    t.process_outbox("b.txt");
    let s = t.snapshot();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(a, Err(FolderError::OutboxUnwritable));
    assert!(t.destination().join("b.txt").exists());
    assert_eq!(
        s.error,
        Some(FolderError::OutboxUnwritable),
        "a is still pending"
    );
    assert_eq!(s.outbox.pending, 1);
    // The agent deletes a: nothing is pending, the error clears.
    std::fs::remove_file(t.outbox_dir().join("sub/a.txt")).unwrap();
    t.process_outbox("sub/a.txt");
    let s = t.snapshot();
    assert_eq!((s.error, s.outbox.pending), (None, 0));
}

#[test]
fn a_failed_record_after_the_write_never_overwrites_on_retry() {
    // 7 review M7a: the destination file is durable before the record; a
    // vault failure in between costs a second file, never the first.
    let e = Arc::new(FakeEngine::new(&[(NAME, EntityKind::Person)]));
    let m = Arc::new(MemManifest::default());
    let t = TestMirror::new(e, m.clone());
    std::fs::write(t.outbox_dir().join("reply.txt"), "eins\n").unwrap();
    *m.fail_put.lock().unwrap() = true;
    let r = t.process_outbox_result("reply.txt");
    *m.fail_put.lock().unwrap() = false;
    assert_eq!(r, Err(FolderError::VaultUnavailable));
    assert_eq!(
        std::fs::read_to_string(t.destination().join("reply.txt")).unwrap(),
        "eins\n"
    );
    t.process_outbox("reply.txt");
    assert_eq!(
        std::fs::read_to_string(t.destination().join("reply.txt")).unwrap(),
        "eins\n"
    );
    assert_eq!(
        std::fs::read_to_string(t.destination().join("reply (2).txt")).unwrap(),
        "eins\n"
    );
    assert_eq!(t.snapshot().outbox.rehydrated, 1);
}

#[test]
fn a_missing_source_does_not_hold_up_the_outbox() {
    // 7 review M4: the outbox walk runs before the source root is opened.
    let (t, mirrored) = setup();
    std::fs::write(t.outbox_dir().join("offline.txt"), &mirrored).unwrap();
    let t2 = t.restart();
    std::fs::remove_dir_all(t2.source()).unwrap();
    t2.reconcile_all();
    assert_eq!(t2.snapshot().error, Some(FolderError::SourceMissing));
    assert_eq!(
        std::fs::read_to_string(t2.destination().join("offline.txt")).unwrap(),
        format!("{NAME}, Neubaugasse 22/5\n")
    );
}

#[test]
fn a_deleted_outbox_file_leaves_no_record() {
    // Integrator ruling: the record of a file that left the outbox is
    // dropped, so the counts stay truthful; by an event or by the walk.
    let e = Arc::new(FakeEngine::new(&[(NAME, EntityKind::Person)]));
    let m = Arc::new(MemManifest::default());
    let t = TestMirror::new(e, m.clone());
    let outbox_rows = || {
        m.rows
            .lock()
            .unwrap()
            .keys()
            .filter(|(_, side, _)| *side == Side::Outbox)
            .count()
    };
    for f in ["bad.txt", "gone.txt"] {
        std::fs::write(t.outbox_dir().join(f), "Hallo <PERSON_ffffff>\n").unwrap();
        t.process_outbox(f);
    }
    assert_eq!(t.snapshot().outbox.with_unresolved, 2);
    assert_eq!(outbox_rows(), 2);
    // An event for the deleted file.
    std::fs::remove_file(t.outbox_dir().join("bad.txt")).unwrap();
    t.process_outbox("bad.txt");
    assert_eq!(t.snapshot().outbox.with_unresolved, 1);
    // No event (deleted while the daemon was down): the walk finds it.
    std::fs::remove_file(t.outbox_dir().join("gone.txt")).unwrap();
    let t2 = t.restart();
    t2.reconcile_all();
    let s = t2.snapshot().outbox;
    assert_eq!((s.with_unresolved, s.rehydrated, s.pending), (0, 0, 0));
    assert_eq!(outbox_rows(), 0, "no manifest record left");
}
