//! M5 spec §5.1, §4.3, §5.5, §6.3: one file through the pipeline. No
//! original reaches the mirror (content and names), whole-file withholding,
//! a file changed mid-way is requeued, case collisions, no extended
//! attribute is copied, and a polling reader never sees a partial file.

mod common;

use std::os::unix::fs::symlink;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::{FakeEngine, MemManifest};
use inumaki_core::span::EntityKind;
use inumaki_mirror::queue::{Job, Priority};
use inumaki_mirror::testing::{StepKind, TestMirror};

const NAME: &str = "Zyxwuria Quolnath";

fn all_mirror_bytes(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if e.file_type().unwrap().is_dir() {
                stack.push(p.clone());
                out.push((rel, Vec::new()));
            } else {
                out.push((rel, std::fs::read(&p).unwrap_or_default()));
            }
        }
    }
    out
}

fn assert_no_original(root: &std::path::Path, originals: &[&str]) {
    use unicode_normalization::UnicodeNormalization;
    for (path, bytes) in all_mirror_bytes(root) {
        for o in originals {
            for v in [
                o.to_string(),
                o.nfd().collect(),
                o.to_lowercase(),
                o.replace(' ', "_"),
            ] {
                assert!(!path.contains(&v), "original in a path: {path}");
                assert!(
                    !String::from_utf8_lossy(&bytes).contains(&v),
                    "original in {path}"
                );
            }
        }
    }
}

fn engine() -> Arc<FakeEngine> {
    Arc::new(FakeEngine::new(&[
        (NAME, EntityKind::Person),
        ("Quolnath GmbH", EntityKind::Organization),
        ("Quolnath", EntityKind::Person),
    ]))
}

#[test]
fn no_original_reaches_the_mirror_in_content_or_names() {
    let t = TestMirror::new(engine(), Arc::new(MemManifest::default()));
    let src = t.source();
    std::fs::create_dir_all(src.join("Kunden/Quolnath GmbH")).unwrap();
    std::fs::create_dir_all(src.join("Kunde.Quolnath")).unwrap();
    std::fs::create_dir_all(src.join("Zyxwuria Quolnath")).unwrap(); // empty directory named after a person
    std::fs::write(
        src.join("Angebot_Zyxwuria_Quolnath.txt"),
        format!("Sehr geehrter Herr {NAME},\n"),
    )
    .unwrap();
    std::fs::write(
        src.join("Kunden/Quolnath GmbH/liste.csv"),
        format!("name,city\n\"{NAME}\",Wien\n"),
    )
    .unwrap();
    std::fs::write(
        src.join("Kunde.Quolnath/k.json"),
        format!("{{\"{NAME}\": {{\"first\": \"Zyxwuria\"}}}}"),
    )
    .unwrap();
    std::fs::write(src.join("Brief.Zyxwuria Quolnath"), "x").unwrap();
    std::fs::write(
        src.join("seite.html"),
        format!("<p>{}</p>", NAME.replace('u', "&#117;")),
    )
    .unwrap();
    std::fs::write(
        src.join("mail.eml"),
        format!("From: {NAME} <z@example.invalid>\r\nSubject: Hallo\r\n\r\nGruss, {NAME}\r\n"),
    )
    .unwrap();
    std::fs::write(
        src.join("gross Zyxwuria Quolnath.txt"),
        vec![b'a'; 2 * 1024 * 1024],
    )
    .unwrap();
    symlink("/etc/hosts", src.join("link Zyxwuria Quolnath")).unwrap();
    t.reconcile_all();
    assert_no_original(&t.mirror_dir(), &[NAME, "Quolnath"]);
    let s = t.snapshot();
    assert!(s.files.mirrored >= 5, "{s:?}");
    assert!(
        s.files.unsupported >= 3,
        "too large, symlink, unsupported format: {s:?}"
    );
}

#[test]
fn one_uncertain_block_withholds_the_whole_file() {
    let e = engine();
    *e.uncertain_marker.lock().unwrap() = Some("UNSICHER".into());
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    let body = format!("{}\n\nUNSICHER {NAME}\n", "harmlos ".repeat(2000));
    std::fs::write(t.source().join("brief.txt"), body).unwrap();
    t.reconcile_all();
    assert!(!t.mirror_dir().join("brief.txt").exists());
    let ph = std::fs::read_to_string(t.mirror_dir().join("brief.txt.inumaki-blocked.txt")).unwrap();
    assert!(
        ph.contains("uncertain") && !ph.contains("harmlos") && !ph.contains("PERSON"),
        "{ph}"
    );
    assert_eq!(t.snapshot().files.blocked, 1);
    assert!(
        e.records
            .lock()
            .unwrap()
            .iter()
            .any(|a| a.verdict == inumaki_mirror::ActivityVerdict::Uncertain)
    );
}

#[test]
fn a_file_changed_during_processing_is_requeued_not_written() {
    let e = engine();
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    let p = t.source().join("brief.txt");
    std::fs::write(&p, format!("erste Fassung {NAME}\n")).unwrap();
    // The hook runs between reading and committing (spec §5.1 step 8).
    t.before_commit(move || std::fs::write(&p, "zweite Fassung, länger als die erste\n").unwrap());
    let step = t.process("brief.txt");
    assert_eq!(step, StepKind::Requeue);
    let names: Vec<String> = all_mirror_bytes(&t.mirror_dir())
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert!(
        names
            .iter()
            .all(|p| p == "outbox" || p == ".inumaki-mirror"),
        "nothing written: {names:?}"
    );
    match t.next_job() {
        Some((
            Job::Source {
                rel, force: false, ..
            },
            Priority::Live,
        )) => assert_eq!(rel, b"brief.txt"),
        other => panic!("expected a live requeue, got {other:?}"),
    }
    t.clear_before_commit();
    t.process("brief.txt");
    assert_eq!(
        std::fs::read_to_string(t.mirror_dir().join("brief.txt")).unwrap(),
        "zweite Fassung, länger als die erste\n"
    );
}

#[test]
fn case_collisions_keep_both_files_stably() {
    let t = TestMirror::new(engine(), Arc::new(MemManifest::default()));
    std::fs::write(t.source().join("Angebot.txt"), "eins").unwrap();
    std::fs::write(t.source().join("angebot.txt"), "zwei").unwrap();
    if std::fs::read_dir(t.source()).unwrap().count() < 2 {
        return; // case-insensitive file system: nothing to test here
    }
    t.reconcile_all();
    let first = all_mirror_bytes(&t.mirror_dir());
    let texts: Vec<&[u8]> = first.iter().map(|(_, b)| b.as_slice()).collect();
    assert!(texts.contains(&b"eins".as_slice()) && texts.contains(&b"zwei".as_slice()));
    t.reconcile_all_forced();
    let paths = |v: Vec<(String, Vec<u8>)>| {
        let mut p: Vec<String> = v.into_iter().map(|(p, _)| p).collect();
        p.sort();
        p
    };
    assert_eq!(
        paths(first),
        paths(all_mirror_bytes(&t.mirror_dir())),
        "the same names on a second pass"
    );
}

#[test]
fn names_that_sanitize_alike_get_a_stable_suffix_on_any_file_system() {
    // Two source names the engine maps to one token: the second mirror name
    // carries `~xxxx` before the extension (no case-sensitive file system
    // is needed, unlike the test above).
    let t = TestMirror::new(engine(), Arc::new(MemManifest::default()));
    std::fs::write(t.source().join("Zyxwuria Quolnath.txt"), "eins").unwrap();
    std::fs::write(t.source().join("Zyxwuria_Quolnath.txt"), "zwei").unwrap();
    let files = |t: &TestMirror| {
        let mut v: Vec<(String, Vec<u8>)> = all_mirror_bytes(&t.mirror_dir())
            .into_iter()
            .filter(|(p, _)| p.ends_with(".txt"))
            .collect();
        v.sort();
        v
    };
    // `<stem>~abcd.txt`: four lowercase hex digits after a tilde.
    let suffixed = |name: &str| {
        let Some(stem) = name.strip_suffix(".txt") else {
            return false;
        };
        let (head, tail) = stem.split_at(stem.len().saturating_sub(5));
        !head.is_empty()
            && tail.starts_with('~')
            && tail[1..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    t.reconcile_all();
    let first = files(&t);
    assert_eq!(first.len(), 2, "both files mirrored: {first:?}");
    let texts: Vec<&[u8]> = first.iter().map(|(_, b)| b.as_slice()).collect();
    assert!(texts.contains(&b"eins".as_slice()) && texts.contains(&b"zwei".as_slice()));
    assert_eq!(
        first.iter().filter(|(p, _)| suffixed(p)).count(),
        1,
        "exactly one name carries the suffix: {first:?}"
    );
    assert_no_original(&t.mirror_dir(), &[NAME, "Quolnath"]);
    assert!(t.claims_balanced());
    t.reconcile_all_forced();
    assert_eq!(first, files(&t), "the same names after a forced pass");
    assert!(t.claims_balanced());
    let t2 = t.restart();
    t2.reconcile_all_forced();
    assert_eq!(first, files(&t2), "the same names after a restart");
    assert!(t2.claims_balanced());
}

#[test]
fn no_extended_attribute_of_the_source_reaches_the_mirror() {
    // Spec §6.3, §16.1 item 3: contents are written from sanitized bytes only.
    let t = TestMirror::new(engine(), Arc::new(MemManifest::default()));
    let p = t.source().join("brief.txt");
    std::fs::write(&p, "Hallo\n").unwrap();
    if !xattr::set(&p, "user.inumaki-probe", NAME.as_bytes()) {
        return; // the file system has no user xattrs (some tmpfs): nothing to test here
    }
    t.reconcile_all();
    let m = t.mirror_dir().join("brief.txt");
    assert!(m.exists());
    assert!(
        !xattr::has(&m, "user.inumaki-probe"),
        "an extended attribute was copied"
    );
}

#[test]
fn a_polling_reader_never_sees_a_partial_or_empty_file() {
    // Spec §6.3, §16.1 item 3: 200 changes while a reader polls the mirror file.
    let t = TestMirror::new(engine(), Arc::new(MemManifest::default()));
    let p = t.source().join("brief.txt");
    std::fs::write(&p, format!("Fassung 0 {}\n", "x".repeat(4000))).unwrap();
    assert_eq!(t.process("brief.txt"), StepKind::Done);
    let target = t.mirror_dir().join("brief.txt");
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let (stop, target) = (Arc::clone(&stop), target.clone());
        std::thread::spawn(move || {
            let mut reads = 0u32;
            while !stop.load(Ordering::Relaxed) {
                let s = std::fs::read_to_string(&target).expect("the mirror file is always there");
                assert!(
                    s.starts_with("Fassung ") && s.ends_with('\n') && s.len() > 4000,
                    "partial read: {} bytes",
                    s.len()
                );
                reads += 1;
            }
            reads
        })
    };
    for i in 1..=200usize {
        // The size changes every time, so the manifest shortcut never applies.
        std::fs::write(&p, format!("Fassung {i} {}\n", "x".repeat(4000 + i))).unwrap();
        assert_eq!(t.process("brief.txt"), StepKind::Done);
    }
    stop.store(true, Ordering::Relaxed);
    assert!(reader.join().unwrap() > 0);
}

/// Extended attributes through libc (no extra crate).
mod xattr {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    fn c(p: &Path) -> CString {
        CString::new(p.as_os_str().as_bytes()).unwrap()
    }

    /// `true` when the attribute was set.
    pub fn set(p: &Path, name: &str, value: &[u8]) -> bool {
        let (p, n) = (c(p), CString::new(name).unwrap());
        // SAFETY: NUL-terminated strings and a valid buffer outlive the call.
        #[cfg(target_os = "macos")]
        let r = unsafe {
            libc::setxattr(
                p.as_ptr(),
                n.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        };
        // SAFETY: as above.
        #[cfg(target_os = "linux")]
        let r = unsafe {
            libc::setxattr(
                p.as_ptr(),
                n.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        r == 0
    }

    /// Whether the attribute exists.
    pub fn has(p: &Path, name: &str) -> bool {
        let (p, n) = (c(p), CString::new(name).unwrap());
        // SAFETY: a size query with a null buffer.
        #[cfg(target_os = "macos")]
        let r = unsafe { libc::getxattr(p.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
        // SAFETY: as above.
        #[cfg(target_os = "linux")]
        let r = unsafe { libc::getxattr(p.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
        r >= 0
    }
}

#[test]
fn an_oversized_block_withholds_the_whole_file() {
    // A block over `MAX_BLOCK_BYTES` (one huge JSON string value) or a
    // verification block over it (an object of two large values) never
    // reaches the engine: the whole file is withheld as blocked.
    let e = engine();
    let t = TestMirror::new(e.clone(), Arc::new(MemManifest::default()));
    let cap = inumaki_mirror::MirrorConfig::MAX_BLOCK_BYTES;
    let value = format!("{NAME} {}", "x".repeat(cap));
    std::fs::write(
        t.source().join("gross.json"),
        format!("{{\"note\": \"{value}\"}}"),
    )
    .unwrap();
    let half = format!("{NAME} {}", "y".repeat(cap / 2));
    std::fs::write(
        t.source().join("objekt.json"),
        format!("{{\"a\": \"{half}\", \"b\": \"{half}\"}}"),
    )
    .unwrap();
    t.reconcile_all();
    for f in ["gross.json", "objekt.json"] {
        assert!(!t.mirror_dir().join(f).exists(), "{f} mirrored");
        let ph = std::fs::read_to_string(t.mirror_dir().join(format!("{f}.inumaki-blocked.txt")))
            .unwrap();
        assert!(ph.contains("Reason: blocked."), "{ph}");
    }
    assert_no_original(&t.mirror_dir(), &[NAME, "Quolnath"]);
    assert!(
        *e.largest_block.lock().unwrap() <= cap,
        "the engine received an oversized block"
    );
    assert_eq!(t.snapshot().files.blocked, 2);
    let records = e.records.lock().unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|a| a.verdict == inumaki_mirror::ActivityVerdict::Blocked && a.kinds.is_empty())
    );
}
