//! M5 spec §6.3, §6.4: no symlink is followed, atomic writes leave no
//! partial or temporary file, no-replace writes never overwrite, and a tree
//! is deleted only behind its marker.

use std::ffi::OsStr;
use std::os::unix::fs::{PermissionsExt, symlink};

use inumaki_mirror::fsops::{
    DeleteFault, Dir, Kind, MARKER, TMP_PREFIX, check_name, delete_mirror_tree,
    inject_delete_fault, inject_noreplace_unsupported, write_marker,
};

#[test]
fn symlinks_are_never_followed() {
    let t = tempfile::tempdir().unwrap();
    let outside = t.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), "Zyxwuria Quolnath").unwrap();
    let root = t.path().join("root");
    std::fs::create_dir(&root).unwrap();
    symlink(&outside, root.join("link-dir")).unwrap();
    symlink(outside.join("secret.txt"), root.join("link-file")).unwrap();
    let d = Dir::open_root(&root).unwrap();
    assert!(d.child(OsStr::new("link-dir")).is_err());
    assert!(d.read_file(OsStr::new("link-file"), 1024).is_err());
    assert_eq!(d.stat(OsStr::new("link-file")).unwrap().kind, Kind::Symlink);
    assert!(d.walk(b"link-dir/secret.txt").is_err());
    // A symlink root is refused.
    symlink(&root, t.path().join("root-link")).unwrap();
    assert!(Dir::open_root(&t.path().join("root-link")).is_err());
    // A mirror-side symlink is replaced, never written through.
    d.write_atomic(OsStr::new("link-file"), b"<PERSON_a1b2c3>", 0o444, None)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(outside.join("secret.txt")).unwrap(),
        "Zyxwuria Quolnath"
    );
    assert_eq!(d.stat(OsStr::new("link-file")).unwrap().kind, Kind::File);
    let sub = d.ensure_dir(OsStr::new("link-dir"), 0o755).unwrap();
    sub.write_atomic(OsStr::new("x.txt"), b"x", 0o444, None)
        .unwrap();
    assert!(!outside.join("x.txt").exists());
}

#[test]
fn atomic_writes_leave_no_partial_or_temporary_file() {
    let t = tempfile::tempdir().unwrap();
    let d = Dir::open_root(t.path()).unwrap();
    d.write_atomic(
        OsStr::new("a.txt"),
        b"first",
        0o444,
        Some((1_700_000_000, 0)),
    )
    .unwrap();
    d.write_atomic(
        OsStr::new("a.txt"),
        b"second",
        0o444,
        Some((1_700_000_001, 0)),
    )
    .unwrap();
    assert_eq!(std::fs::read(t.path().join("a.txt")).unwrap(), b"second");
    let md = std::fs::metadata(t.path().join("a.txt")).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o444);
    use std::os::unix::fs::MetadataExt;
    assert_eq!(md.mtime(), 1_700_000_001);
    let names: Vec<_> = std::fs::read_dir(t.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        names
            .iter()
            .all(|n| !n.to_string_lossy().starts_with(TMP_PREFIX)),
        "{names:?}"
    );
    assert!(
        d.write_atomic(OsStr::new("../x"), b"x", 0o444, None)
            .is_err()
    );
    assert!(
        d.write_atomic(OsStr::new("a/b"), b"x", 0o444, None)
            .is_err()
    );
}

#[test]
fn write_new_never_overwrites() {
    let t = tempfile::tempdir().unwrap();
    let d = Dir::open_root(t.path()).unwrap();
    d.write_new(OsStr::new("reply.txt"), b"one", 0o600).unwrap();
    let e = d
        .write_new(OsStr::new("reply.txt"), b"two", 0o600)
        .unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(t.path().join("reply.txt")).unwrap(), b"one");
    let names: Vec<_> = std::fs::read_dir(t.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "no temporary file left: {names:?}");
}

#[test]
fn a_tree_is_deleted_only_behind_its_marker() {
    let t = tempfile::tempdir().unwrap();
    let root = Dir::open_root(t.path()).unwrap();
    let m = root
        .ensure_dir(OsStr::new("d1b2c3d4e5f60718"), 0o755)
        .unwrap();
    write_marker(&m, "d1b2c3d4e5f60718").unwrap();
    m.ensure_dir(OsStr::new("sub"), 0o755)
        .unwrap()
        .write_atomic(OsStr::new("f.txt"), b"x", 0o444, None)
        .unwrap();
    std::fs::create_dir(t.path().join("user-dir")).unwrap();
    std::fs::write(t.path().join("user-dir").join(MARKER), "other-label").unwrap();
    assert!(
        !delete_mirror_tree(&root, "user-dir").unwrap(),
        "a foreign marker: nothing deleted, nothing to retry"
    );
    assert!(t.path().join("user-dir").join(MARKER).exists());
    assert!(delete_mirror_tree(&root, "d1b2c3d4e5f60718").unwrap());
    assert!(!t.path().join("d1b2c3d4e5f60718").exists());
    assert!(
        !delete_mirror_tree(&root, "d1b2c3d4e5f60718").unwrap(),
        "absent is false"
    );
}

#[test]
fn open_or_create_never_removes_what_is_in_the_way() {
    let t = tempfile::tempdir().unwrap();
    let outside = t.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let root = t.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("a-file"), "Zyxwuria Quolnath").unwrap();
    symlink(&outside, root.join("a-link")).unwrap();
    let d = Dir::open_root(&root).unwrap();
    for name in ["a-file", "a-link"] {
        let e = d.open_or_create(OsStr::new(name), 0o700).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "{name}");
    }
    assert_eq!(
        std::fs::read_to_string(root.join("a-file")).unwrap(),
        "Zyxwuria Quolnath"
    );
    assert!(
        std::fs::symlink_metadata(root.join("a-link"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let fresh = d.open_or_create(OsStr::new("fresh"), 0o700).unwrap();
    fresh.write_new(OsStr::new("x.txt"), b"x", 0o600).unwrap();
    let again = d.open_or_create(OsStr::new("fresh"), 0o700).unwrap();
    assert_eq!(again.stat(OsStr::new("x.txt")).unwrap().kind, Kind::File);
    assert_eq!(
        std::fs::metadata(root.join("fresh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

fn names(p: &std::path::Path) -> Vec<std::ffi::OsString> {
    let mut v: Vec<_> = std::fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    v.sort();
    v
}

#[test]
fn check_name_refuses_anything_but_one_component() {
    use std::os::unix::ffi::OsStrExt;
    for bad in [&b""[..], b".", b"..", b"a\0b", b"../x", b"a/b", b"/"] {
        assert!(check_name(OsStr::from_bytes(bad)).is_err(), "{bad:?}");
    }
    for good in ["a.txt", "...", ".hidden", "Zyxwuria Quolnath.txt"] {
        assert!(check_name(OsStr::new(good)).is_ok(), "{good}");
    }
    // Length is the kernel's call: a long non-ASCII name is not refused here.
    assert!(check_name(OsStr::new(&"\u{e4}".repeat(200))).is_ok());
}

#[test]
fn delete_refuses_a_tree_without_its_own_marker() {
    let t = tempfile::tempdir().unwrap();
    let root = Dir::open_root(t.path()).unwrap();
    let label = "d1b2c3d4e5f60718";
    // (a) No marker at all: an empty directory goes, one with content is
    // left untouched and reported as "nothing deleted" (review m7).
    std::fs::create_dir(t.path().join(label)).unwrap();
    assert!(delete_mirror_tree(&root, label).unwrap());
    assert!(!t.path().join(label).exists());
    std::fs::create_dir(t.path().join(label)).unwrap();
    std::fs::write(t.path().join(label).join("f.txt"), "x").unwrap();
    assert!(!delete_mirror_tree(&root, label).unwrap());
    assert_eq!(
        std::fs::read_to_string(t.path().join(label).join("f.txt")).unwrap(),
        "x"
    );
    // (b) The marker is a symlink to a file that holds the label.
    let elsewhere = t.path().join("elsewhere");
    std::fs::write(&elsewhere, label).unwrap();
    symlink(&elsewhere, t.path().join(label).join(MARKER)).unwrap();
    let e = delete_mirror_tree(&root, label).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(t.path().join(label).join("f.txt").exists());
    assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), label);
}

#[test]
fn delete_never_follows_a_symlink_out_of_the_tree() {
    let t = tempfile::tempdir().unwrap();
    let outside = t.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("keep.txt"), "Zyxwuria Quolnath").unwrap();
    let root_path = t.path().join("root");
    std::fs::create_dir(&root_path).unwrap();
    let root = Dir::open_root(&root_path).unwrap();
    let label = "d1b2c3d4e5f60718";
    let m = root.ensure_dir(OsStr::new(label), 0o755).unwrap();
    write_marker(&m, label).unwrap();
    let sub = m.ensure_dir(OsStr::new("sub"), 0o755).unwrap();
    symlink(&outside, root_path.join(label).join("sub").join("out")).unwrap();
    symlink(
        outside.join("keep.txt"),
        root_path.join(label).join("out-file"),
    )
    .unwrap();
    drop(sub);
    assert!(delete_mirror_tree(&root, label).unwrap());
    assert!(!root_path.join(label).exists());
    assert_eq!(
        std::fs::read_to_string(outside.join("keep.txt")).unwrap(),
        "Zyxwuria Quolnath"
    );
}

#[test]
fn a_failed_delete_keeps_the_marker_and_can_be_retried() {
    let t = tempfile::tempdir().unwrap();
    let root = Dir::open_root(t.path()).unwrap();
    let label = "d1b2c3d4e5f60718";
    let tree = t.path().join(label);
    for fault in [DeleteFault::BeforeMarker, DeleteFault::FinalRmdir] {
        let m = root.ensure_dir(OsStr::new(label), 0o755).unwrap();
        write_marker(&m, label).unwrap();
        for n in ["a", "z"] {
            m.ensure_dir(OsStr::new(n), 0o755)
                .unwrap()
                .write_atomic(OsStr::new("f.txt"), b"x", 0o444, None)
                .unwrap();
        }
        inject_delete_fault(Some(fault));
        let r = delete_mirror_tree(&root, label);
        inject_delete_fault(None);
        assert!(r.is_err(), "{fault:?}");
        assert_eq!(
            std::fs::read_to_string(tree.join(MARKER)).unwrap(),
            label,
            "{fault:?}: the marker survives"
        );
        assert_eq!(
            names(&tree),
            vec![std::ffi::OsString::from(MARKER)],
            "{fault:?}"
        );
        assert!(
            delete_mirror_tree(&root, label).unwrap(),
            "{fault:?}: retry"
        );
        assert!(!tree.exists(), "{fault:?}");
    }
}

#[test]
fn write_new_refuses_a_dangling_symlink_on_both_paths() {
    let t = tempfile::tempdir().unwrap();
    let outside = t.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let dest = t.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    symlink(outside.join("planted.txt"), dest.join("reply.txt")).unwrap();
    let d = Dir::open_root(&dest).unwrap();
    for fallback in [false, true] {
        inject_noreplace_unsupported(fallback);
        let e = d
            .write_new(OsStr::new("reply.txt"), b"Zyxwuria Quolnath", 0o600)
            .unwrap_err();
        inject_noreplace_unsupported(false);
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "{fallback}");
        assert!(!outside.join("planted.txt").exists(), "{fallback}");
        assert_eq!(names(&dest), vec![std::ffi::OsString::from("reply.txt")]);
    }
}

#[test]
fn the_o_excl_fallback_never_overwrites() {
    let t = tempfile::tempdir().unwrap();
    let d = Dir::open_root(t.path()).unwrap();
    inject_noreplace_unsupported(true);
    d.write_new(OsStr::new("reply.txt"), b"one", 0o600).unwrap();
    let e = d
        .write_new(OsStr::new("reply.txt"), b"two", 0o600)
        .unwrap_err();
    inject_noreplace_unsupported(false);
    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(t.path().join("reply.txt")).unwrap(), b"one");
    let md = std::fs::metadata(t.path().join("reply.txt")).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o600);
    assert_eq!(names(t.path()), vec![std::ffi::OsString::from("reply.txt")]);
}
