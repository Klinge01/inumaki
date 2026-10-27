//! M5 spec §5.4, §7.4, §7.5: a name that a later file (or another front
//! door) teaches is removed from the mirror before the file is redone, in
//! content and in names (including a directory name and an empty
//! directory), and a crash after the removal cannot bring it back. Long
//! files are checked in bounded windows; a removal runs whatever the
//! source root's state.

mod common;

use std::sync::Arc;

use common::{FakeEngine, MemManifest};
use inumaki_core::span::EntityKind;
use inumaki_mirror::MirrorConfig;
use inumaki_mirror::testing::{StepKind, TestMirror};

const MISSED: &str = "Qwxzvk Yolandir";

fn walk_all(root: &std::path::Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if p.is_dir() {
                stack.push(p);
                out.push((rel, String::new()));
            } else {
                out.push((rel, std::fs::read_to_string(&p).unwrap_or_default()));
            }
        }
    }
    out
}

fn assert_gone(t: &TestMirror, what: &str) {
    for (p, c) in walk_all(&t.mirror_dir()) {
        assert!(
            !p.contains(MISSED) && !c.contains(MISSED),
            "{what}: in clear"
        );
    }
}

#[test]
fn a_name_taught_later_is_removed_first_and_redone() {
    let e = Arc::new(FakeEngine::new(&[]));
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    std::fs::create_dir_all(t.source().join(format!("Kunde {MISSED}"))).unwrap();
    std::fs::write(
        t.source().join(format!("Kunde {MISSED}/notiz.txt")),
        format!("Anruf von {MISSED}.\n"),
    )
    .unwrap();
    t.reconcile_all();
    assert!(
        walk_all(&t.mirror_dir())
            .iter()
            .any(|(p, c)| p.contains(MISSED) || c.contains(MISSED)),
        "NER missed it"
    );
    e.learn(MISSED, EntityKind::Person); // e.g. seeded, or taught by the gateway
    assert!(t.tripwire_pass_and_drain() >= 1);
    assert_gone(&t, "after the pass");
    assert!(
        walk_all(&t.mirror_dir())
            .iter()
            .any(|(p, c)| p.ends_with("notiz.txt") && c.contains("<PERSON_")),
        "redone with a token"
    );
    assert!(e.records.lock().unwrap().iter().any(|a| a.tripwire));
    // A second pass on the same generation does nothing.
    assert_eq!(t.tripwire_pass_and_drain(), 0);
    assert!(t.claims_balanced());
}

#[test]
fn an_empty_directory_named_after_a_name_taught_later_is_renamed() {
    // Review I3: the tripwire pass also checks directory records.
    let e = Arc::new(FakeEngine::new(&[]));
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    std::fs::create_dir_all(t.source().join(format!("Akten/Kunde {MISSED}"))).unwrap();
    t.reconcile_all();
    assert!(
        t.mirror_dir()
            .join(format!("Akten/Kunde {MISSED}"))
            .is_dir()
    );
    e.learn(MISSED, EntityKind::Person);
    t.tripwire_pass_and_drain();
    assert_gone(&t, "after the pass");
    assert!(e.records.lock().unwrap().iter().any(|a| a.tripwire));
    t.reconcile_all();
    assert_gone(&t, "a reconcile brought it back");
    let akten: Vec<_> = std::fs::read_dir(t.mirror_dir().join("Akten"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(akten.len(), 1, "one directory, renamed, not two");
    assert!(akten[0].is_dir());
    assert!(t.claims_balanced());
}

#[test]
fn a_crash_after_removal_cannot_bring_the_original_back() {
    let e = Arc::new(FakeEngine::new(&[]));
    let m = Arc::new(MemManifest::default());
    let t = TestMirror::new(e.clone(), m.clone());
    std::fs::write(t.source().join("notiz.txt"), format!("{MISSED}\n")).unwrap();
    t.reconcile_all();
    e.learn(MISSED, EntityKind::Person);
    t.tripwire_pass_without_drain(); // removal done, requeue lost with the "crash"
    assert_gone(&t, "after the removal");
    let t2 = t.restart(); // same manifest, same directories, fresh queue
    t2.reconcile_all();
    assert_gone(&t2, "after the restart");
    assert!(
        walk_all(&t2.mirror_dir())
            .iter()
            .any(|(_, c)| c.contains("<PERSON_")),
        "redone with a token"
    );
}

#[test]
fn a_second_release_check_hit_writes_a_blocked_placeholder_with_opaque_names() {
    // An engine that never tokenizes MISSED but whose known_in_clear sees it.
    let e = Arc::new(FakeEngine::new(&[]));
    e.learn_clear_only(MISSED);
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    std::fs::write(
        t.source().join(format!("{MISSED}.txt")),
        format!("{MISSED}\n"),
    )
    .unwrap();
    t.reconcile_all();
    let all = walk_all(&t.mirror_dir());
    assert!(
        all.iter()
            .all(|(p, c)| !p.contains(MISSED) && !c.contains(MISSED))
    );
    assert!(
        all.iter()
            .any(|(p, _)| p.starts_with("f-") && p.ends_with(".inumaki-blocked.txt")),
        "no opaque blocked placeholder"
    );
}

#[test]
fn a_long_file_is_checked_in_bounded_windows() {
    // The original straddles the end of the first window: only the
    // overlapping second window holds it whole.
    let e = Arc::new(FakeEngine::new(&[]));
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    let max = MirrorConfig::MAX_BLOCK_BYTES;
    let mut text = "Notiz zum Termin.\n\n".repeat(3 * max / 19 + 1);
    let at = max - 5;
    text.replace_range(at..at + MISSED.len(), MISSED);
    std::fs::write(t.source().join("lang.txt"), &text).unwrap();
    t.reconcile_all();
    assert!(
        walk_all(&t.mirror_dir())
            .iter()
            .any(|(_, c)| c.contains(MISSED)),
        "NER missed it"
    );
    e.learn(MISSED, EntityKind::Person);
    t.tripwire_pass_and_drain();
    assert_gone(&t, "after the pass");
    assert!(
        *e.largest_clear_text.lock().unwrap() <= max,
        "known_in_clear got a text over the block cap"
    );
}

#[test]
fn a_removal_runs_while_the_source_root_cannot_be_opened() {
    // The removal deletes a clear copy from the mirror; it does not depend
    // on the source (unlike a delete, which an unusable root stops).
    let e = Arc::new(FakeEngine::new(&[]));
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    std::fs::create_dir_all(t.source().join(format!("Kunde {MISSED}"))).unwrap();
    std::fs::write(
        t.source().join(format!("Kunde {MISSED}/notiz.txt")),
        format!("{MISSED}\n"),
    )
    .unwrap();
    t.reconcile_all();
    e.learn(MISSED, EntityKind::Person);
    t.inject_source_error(Some(1)); // EPERM
    t.tripwire_pass_and_drain();
    assert_gone(&t, "while the root fails");
    t.inject_source_error(None);
    t.reconcile_all();
    assert_gone(&t, "after the root is back");
    assert!(
        walk_all(&t.mirror_dir())
            .iter()
            .any(|(_, c)| c.contains("<PERSON_")),
        "redone with a token"
    );
}

#[test]
fn a_directory_name_hit_renames_the_directory_and_mirrors_the_file() {
    // Only a directory component holds the original: the file is mirrored
    // under the renamed directory, not withheld.
    let e = Arc::new(FakeEngine::new(&[]));
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    let dir = format!("Kunde {MISSED}");
    std::fs::create_dir_all(t.source().join(&dir)).unwrap();
    std::fs::write(t.source().join(format!("{dir}/a.txt")), "hallo\n").unwrap();
    t.reconcile_all();
    e.learn(MISSED, EntityKind::Person);
    std::fs::write(t.source().join(format!("{dir}/b.txt")), "servus\n").unwrap();
    assert_eq!(t.process(&format!("{dir}/b.txt")), StepKind::Done);
    assert_gone(&t, "after the live change");
    let all = walk_all(&t.mirror_dir());
    assert!(
        all.iter()
            .any(|(p, c)| p.ends_with("/b.txt") && c == "servus\n")
    );
    assert!(
        all.iter()
            .any(|(p, c)| p.ends_with("/a.txt") && c == "hallo\n")
    );
    assert!(!all.iter().any(|(p, _)| p.contains("inumaki-blocked")));
    assert!(t.claims_balanced());
    // Moving a clear directory name out of the mirror is a tripwire record
    // (spec §7.5).
    assert!(e.records.lock().unwrap().iter().any(|a| a.tripwire));
}

#[test]
fn an_unreadable_mirror_copy_counts_as_a_hit_and_is_redone() {
    // Fail closed: a mirror copy the pass cannot read as the text the
    // mirror wrote (not UTF-8, or over the read cap) is a hit, removed and
    // redone, even though no known original is in its name.
    let e = Arc::new(FakeEngine::new(&[]));
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    std::fs::write(t.source().join("a.txt"), "hallo\n").unwrap();
    std::fs::write(t.source().join("b.txt"), "servus\n").unwrap();
    t.reconcile_all();
    let (a, b) = (t.mirror_dir().join("a.txt"), t.mirror_dir().join("b.txt"));
    std::fs::remove_file(&a).unwrap();
    std::fs::write(&a, [0xff, 0xfe, b'x']).unwrap();
    let cap = 8 * MirrorConfig::default().max_file_bytes as usize;
    std::fs::remove_file(&b).unwrap();
    std::fs::write(&b, vec![b'x'; cap + 1]).unwrap();
    e.learn("Zzyxq Unrelated", EntityKind::Person); // a generation bump
    assert_eq!(t.tripwire_pass_and_drain(), 2);
    assert_eq!(std::fs::read_to_string(&a).unwrap(), "hallo\n");
    assert_eq!(std::fs::read_to_string(&b).unwrap(), "servus\n");
    assert!(t.claims_balanced());
}

/// The empty-directory case up to the learn.
fn empty_dir_learned() -> (Arc<FakeEngine>, TestMirror) {
    let e = Arc::new(FakeEngine::new(&[]));
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    std::fs::create_dir_all(t.source().join(format!("Akten/Kunde {MISSED}"))).unwrap();
    t.reconcile_all();
    e.learn(MISSED, EntityKind::Person);
    (e, t)
}

#[test]
fn an_occupied_opaque_target_takes_the_next_name() {
    // The opaque name is keyed by dataset, epoch, and path, so a first run
    // tells which name the second one will want.
    let (_, t1) = empty_dir_learned();
    t1.tripwire_pass_and_drain();
    let want: Vec<_> = std::fs::read_dir(t1.mirror_dir().join("Akten"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(want.len(), 1);
    // A non-empty directory the manifest does not name sits there.
    let (_, t) = empty_dir_learned();
    let occupied = t.mirror_dir().join("Akten").join(&want[0]);
    std::fs::create_dir_all(&occupied).unwrap();
    std::fs::write(occupied.join("agent.txt"), "notiz\n").unwrap();
    t.tripwire_pass_and_drain();
    assert_gone(&t, "with the target occupied");
    assert_eq!(
        std::fs::read_dir(t.mirror_dir().join("Akten"))
            .unwrap()
            .count(),
        2
    );
    t.reconcile_all(); // the sweep takes the leftover
    assert_gone(&t, "after the reconcile");
    assert_eq!(
        std::fs::read_dir(t.mirror_dir().join("Akten"))
            .unwrap()
            .count(),
        1
    );
    assert!(t.claims_balanced());
}
