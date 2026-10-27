//! M5 through the daemon: validation (spec §12.3), the folder registry the
//! hook reads, add and remove before the mirror service starts (the M6-3
//! check sweep does it), and the hook's path cap. With the service running
//! (Task 8b): a folder dataset mirrors and re-mirrors after a rotation with
//! the previous epoch's names carried, deleting the dataset removes its
//! folder, and an outbox destination replaced by a symlink is not followed.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::mirror::{start_mirror, start_state_only, start_state_with};
use hyper::Method;
use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumakid::folders::{AddError, Refusal, ValidateCtx, validate};
use inumakid::hook::{FolderRegistry, HookInput, MAX_HOOK_PATHS, run_hook};
use serde_json::json;

fn check(c: &ValidateCtx, src: &Path, dest: Option<&Path>) -> Result<(), Refusal> {
    validate(src, std::fs::metadata(src), dest, c).map(|_| ())
}

#[test]
fn eperm_on_the_source_is_accepted_as_not_permitted() {
    let ctx = ValidateCtx::for_test(
        "/Users/qwxzvk",
        "/Users/qwxzvk/Inumaki",
        "/Users/qwxzvk/Library/Inumaki",
    );
    let meta = Err(std::io::Error::from_raw_os_error(1)); // EPERM
    let r = validate(Path::new("/Users/qwxzvk/Documents/Akten"), meta, None, &ctx);
    let (source, _, root_id) = r.expect("accepted");
    assert_eq!(source, PathBuf::from("/Users/qwxzvk/Documents/Akten"));
    assert_eq!(root_id, None, "learned at the first successful open");
    // Any other error is "not an existing directory".
    let meta = Err(std::io::Error::from_raw_os_error(2));
    let r = validate(Path::new("/Users/qwxzvk/Documents/Akten"), meta, None, &ctx);
    assert_eq!(r.unwrap_err(), Refusal::SourceNotDirectory);
}

#[test]
fn validation_refuses_with_the_spec_messages_in_both_overlap_directions() {
    let t = tempfile::tempdir().unwrap();
    let b = std::fs::canonicalize(t.path()).unwrap();
    let (home, root, data) = (b.join("home"), b.join("home/Inumaki"), b.join("data"));
    for d in [
        &home,
        &root,
        &data,
        &b.join("home/a/b"),
        &b.join("elsewhere"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(b.join("file"), b"x").unwrap();
    let ctx = || {
        ValidateCtx::for_test(
            home.to_str().unwrap(),
            root.to_str().unwrap(),
            data.to_str().unwrap(),
        )
    };
    let c = ctx();
    assert_eq!(
        check(&c, Path::new("rel"), None),
        Err(Refusal::SourceNotAbsolute)
    );
    assert_eq!(
        check(&c, &b.join("file"), None),
        Err(Refusal::SourceNotDirectory)
    );
    assert_eq!(
        check(&c, &b.join("nope"), None),
        Err(Refusal::SourceNotDirectory)
    );
    assert_eq!(check(&c, &home, None), Err(Refusal::SourceIsHome));
    assert_eq!(check(&c, &root, None), Err(Refusal::SourceInsideProtected));
    assert_eq!(check(&c, &data, None), Err(Refusal::SourceInsideProtected));
    assert_eq!(check(&c, &b, None), Err(Refusal::SourceContainsProtected));
    assert_eq!(
        check(&c, Path::new("/"), None),
        Err(Refusal::SourceContainsProtected)
    );
    // The message table is the spec's, literally.
    assert_eq!(
        Refusal::SourceContainsProtected.message(),
        "source must not contain the mirror root, the data directory, or the home directory"
    );
    assert_eq!(
        Refusal::DestNotDirectory.message(),
        "outbox_destination must be a directory"
    );
    // Another folder's source, in both directions.
    let o = ctx().with_others(vec![home.join("a")]);
    assert_eq!(
        check(&o, &home.join("a/b"), None),
        Err(Refusal::SourceOverlaps)
    );
    assert_eq!(check(&o, &home, None), Err(Refusal::SourceIsHome));
    let o = ctx().with_others(vec![home.join("a/b")]);
    assert_eq!(
        check(&o, &home.join("a"), None),
        Err(Refusal::SourceOverlaps)
    );
    assert!(check(&o, &b.join("elsewhere"), None).is_ok());
    // Destination: absolute, not inside the protected roots, not a file;
    // symlinks are resolved before the comparison.
    let src = b.join("elsewhere");
    assert_eq!(
        check(&c, &src, Some(Path::new("out"))),
        Err(Refusal::DestNotAbsolute)
    );
    assert_eq!(
        check(&c, &src, Some(&root.join("out"))),
        Err(Refusal::DestInsideProtected)
    );
    assert_eq!(
        check(&c, &src, Some(&b.join("file"))),
        Err(Refusal::DestNotDirectory)
    );
    std::os::unix::fs::symlink(&root, b.join("link")).unwrap();
    assert_eq!(
        check(&c, &src, Some(&b.join("link/x"))),
        Err(Refusal::DestInsideProtected)
    );
    let (_, resolved, _) =
        validate(&src, std::fs::metadata(&src), Some(&b.join("new/deep")), &c).unwrap();
    assert_eq!(
        resolved,
        b.join("new/deep"),
        "a missing destination is accepted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_registers_for_the_hook_and_refuses_wrong_kind_overlap_and_a_second_folder() {
    let m = start_state_only().await;
    let f = Arc::clone(m.state.mirror.get().unwrap());
    let st = Arc::clone(&m.state);
    let (a, a_sub, other) = (m.base.join("A"), m.base.join("A/sub"), m.base.join("B"));
    for d in [&a_sub, &other] {
        std::fs::create_dir_all(d).unwrap();
    }
    let outbox = m.base.join("Outbox");
    tokio::task::spawn_blocking(move || {
        st.vault
            .create_dataset(&inumaki_vault::DatasetSpec::new("g-qwxzvk", "G", "offline"))
            .unwrap();
        let mut spec = inumaki_vault::DatasetSpec::new("f-qwxzvk", "F", "offline");
        spec.kind = inumaki_vault::DatasetKind::Folder;
        st.vault.create_dataset(&spec).unwrap();
        let mut spec = inumaki_vault::DatasetSpec::new("h-qwxzvk", "H", "offline");
        spec.kind = inumaki_vault::DatasetKind::Folder;
        st.vault.create_dataset(&spec).unwrap();
        let src = a.to_str().unwrap();
        assert!(matches!(
            f.add(&st, "nope", src, None),
            Err(AddError::UnknownDataset)
        ));
        assert!(matches!(
            f.add(&st, "g-qwxzvk", src, None),
            Err(AddError::WrongKind)
        ));
        let info = f.add(&st, "f-qwxzvk", src, None).unwrap();
        assert_eq!(
            PathBuf::from(&info.outbox_destination),
            outbox.join(&info.label),
            "the default destination"
        );
        assert!(
            !format!("{info:?}").contains(&info.source),
            "Debug never prints a path"
        );
        assert!(matches!(
            f.add(&st, "f-qwxzvk", other.to_str().unwrap(), None),
            Err(AddError::Exists)
        ));
        assert!(matches!(
            f.add(&st, "h-qwxzvk", a_sub.to_str().unwrap(), None),
            Err(AddError::Refused(Refusal::SourceOverlaps))
        ));
        assert!(
            st.vault.folder("h-qwxzvk").unwrap().is_none(),
            "a refused folder stores nothing"
        );
        // The hook's registry sees the folder, whatever its state.
        let reg: &dyn FolderRegistry = &*f;
        assert_eq!(
            reg.source_roots(),
            vec![("f-qwxzvk".to_string(), a.clone())]
        );
        assert_eq!(reg.outbox_destinations().len(), 1);
        assert_eq!(reg.mirror_root(), Some(f.mirror_root().to_path_buf()));
        assert_eq!(f.list().len(), 1);
        assert!(
            f.list()[0].1.is_none(),
            "no snapshot before the service starts"
        );
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_before_the_mirror_starts_removes_the_tree_and_the_rows() {
    // Spec §7.2 step 2, §12.2, §16.1 item 9 (review I11).
    let m = start_state_only().await;
    assert!(
        m.root.join("README.txt").exists(),
        "the root exists from AppState::start (spec §7.2 step 1)"
    );
    let f = Arc::clone(m.state.mirror.get().unwrap());
    let st = Arc::clone(&m.state);
    let src = m.base.join("Akten");
    std::fs::create_dir_all(&src).unwrap();
    let root = m.root.clone();
    tokio::task::spawn_blocking(move || {
        let mut spec = inumaki_vault::DatasetSpec::new("check-qwxzvk", "Check", "offline");
        spec.kind = inumaki_vault::DatasetKind::Folder;
        st.vault.create_dataset(&spec).unwrap();
        let info = f
            .add(&st, "check-qwxzvk", src.to_str().unwrap(), None)
            .unwrap();
        // A tree left by an earlier run, behind its marker.
        let mirror = PathBuf::from(&info.mirror);
        std::fs::create_dir_all(mirror.join("x")).unwrap();
        std::fs::write(mirror.join(".inumaki-mirror"), &info.label).unwrap();
        assert!(f.remove(&st, "check-qwxzvk").unwrap());
        assert!(!mirror.exists(), "the tree went");
        assert!(
            st.vault.folder("check-qwxzvk").unwrap().is_none(),
            "the rows went"
        );
        assert!(f.source_roots().is_empty(), "the hook no longer guards it");
        assert!(
            !f.remove(&st, "check-qwxzvk").unwrap(),
            "absent the second time"
        );
        assert!(root.exists(), "the root itself stays");
        assert!(src.exists(), "the source is never touched");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_request_with_too_many_paths_is_refused_when_folders_exist() {
    let m = start_state_only().await;
    let f = Arc::clone(m.state.mirror.get().unwrap());
    let st = Arc::clone(&m.state);
    let src = m.base.join("Akten");
    std::fs::create_dir_all(&src).unwrap();
    tokio::task::spawn_blocking(move || {
        let input = |n: usize| HookInput {
            cwd: PathBuf::from("/"),
            paths: (0..n).map(|i| format!("/nonexistent-qwxzvk/{i}")).collect(),
            texts: vec!["Zyxwuria Quolnath".to_string()],
        };
        // No folder yet: no path is resolved, the count is irrelevant.
        assert!(run_hook(&st, &input(MAX_HOOK_PATHS + 1)).is_ok());
        let mut spec = inumaki_vault::DatasetSpec::new("f-qwxzvk", "F", "offline");
        spec.kind = inumaki_vault::DatasetKind::Folder;
        st.vault.create_dataset(&spec).unwrap();
        f.add(&st, "f-qwxzvk", src.to_str().unwrap(), None).unwrap();
        assert!(run_hook(&st, &input(MAX_HOOK_PATHS)).is_ok());
        let e = run_hook(&st, &input(MAX_HOOK_PATHS + 1)).expect_err("refused, never passed");
        assert!(matches!(
            e,
            inumakid::service::ServiceError::Unsupported("hook_paths")
        ));
    })
    .await
    .unwrap();
}

fn folder_dataset(st: &inumakid::AppState, id: &str) {
    let mut spec = inumaki_vault::DatasetSpec::new(id, "F", "offline");
    spec.kind = inumaki_vault::DatasetKind::Folder;
    st.vault.create_dataset(&spec).unwrap();
}

/// Review I4 (a), (b): the stored folders are in the registry before
/// anything is served, and a row the daemon cannot read stops the start
/// (skipping it would leave its source unguarded).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_guards_stored_folders_and_refuses_an_unreadable_row() {
    let m = start_state_only().await;
    let src = m.base.join("Akten");
    std::fs::create_dir_all(&src).unwrap();
    let (f, st, s2) = (
        Arc::clone(m.state.mirror.get().unwrap()),
        Arc::clone(&m.state),
        src.clone(),
    );
    tokio::task::spawn_blocking(move || {
        folder_dataset(&st, "f-qwxzvk");
        f.add(&st, "f-qwxzvk", s2.to_str().unwrap(), None).unwrap();
    })
    .await
    .unwrap();
    let (r, t) = m.restart(None).await;
    let state = Arc::new(r.expect("restart"));
    let reg = state.folders.get().expect("set before anything is served");
    assert_eq!(
        reg.source_roots(),
        vec![("f-qwxzvk".to_string(), src.clone())]
    );
    assert_eq!(reg.outbox_destinations().len(), 1);
    // Garbage under a valid seal: the next start fails closed.
    let st = Arc::clone(&state);
    tokio::task::spawn_blocking(move || {
        folder_dataset(&st, "g-qwxzvk");
        st.vault.create_folder("g-qwxzvk", b"not json").unwrap();
    })
    .await
    .unwrap();
    // Reuse the temp dir by hand: the helper consumes a `MirrorState`.
    drop(state);
    let base = std::fs::canonicalize(t.path()).unwrap();
    let opts = inumakid::StartOptions {
        config: Some(base.join("inumaki.toml")),
        data_dir: Some(base.join("data")),
        socket: Some(common::short_socket_path("m")),
        models_dir: Some(base.join("no-models")),
        clock: None,
    };
    let e = tokio::task::spawn_blocking(move || inumakid::AppState::start(&opts))
        .await
        .unwrap()
        .expect_err("refused");
    assert!(matches!(e, inumakid::StartError::Config(_)), "{e}");
}

/// Review I2: a mirror root edited to hold a stored source stops the start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_root_that_now_holds_a_stored_source_stops_the_start() {
    let m = start_state_only().await;
    let src = m.base.join("work/Akten");
    std::fs::create_dir_all(&src).unwrap();
    let (f, st, s2) = (
        Arc::clone(m.state.mirror.get().unwrap()),
        Arc::clone(&m.state),
        src.clone(),
    );
    tokio::task::spawn_blocking(move || {
        folder_dataset(&st, "f-qwxzvk");
        f.add(&st, "f-qwxzvk", s2.to_str().unwrap(), None).unwrap();
    })
    .await
    .unwrap();
    let holder = m.base.join("work");
    let (r, _t) = m.restart(Some(holder)).await;
    let e = r.expect_err("refused");
    assert!(matches!(e, inumakid::StartError::Config(_)), "{e}");
}

/// 8a re-review n1: a root moved inside a stored source stops the start
/// before anything is created there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_root_inside_a_stored_source_is_never_created() {
    let m = start_state_only().await;
    let src = m.base.join("Akten");
    std::fs::create_dir_all(&src).unwrap();
    let (f, st, s2) = (
        Arc::clone(m.state.mirror.get().unwrap()),
        Arc::clone(&m.state),
        src.clone(),
    );
    tokio::task::spawn_blocking(move || {
        folder_dataset(&st, "f-qwxzvk");
        f.add(&st, "f-qwxzvk", s2.to_str().unwrap(), None).unwrap();
    })
    .await
    .unwrap();
    let inside = src.join("Inumaki");
    let (r, _t) = m.restart(Some(inside.clone())).await;
    assert!(matches!(r, Err(inumakid::StartError::Config(_))));
    assert!(!inside.exists(), "no root, marker, or README in the source");
}

/// Review I1, C1: a root that cannot be prepared (a symlink, a foreign
/// directory) is neither followed nor written, and the daemon still starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unusable_root_is_not_followed_and_not_written() {
    let m = start_state_with(|base, root| {
        std::fs::create_dir_all(base.join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(base.join("elsewhere"), root).unwrap();
    })
    .await;
    let f = m.state.mirror.get().unwrap();
    assert_eq!(
        f.mirror_root(),
        m.root,
        "the symlink itself, not its target"
    );
    assert!(!m.base.join("elsewhere/README.txt").exists());
    let m = start_state_with(|_, root| {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join("mine.txt"), "x").unwrap();
    })
    .await;
    assert!(
        !m.root.join("README.txt").exists(),
        "a foreign directory gets nothing"
    );
    assert!(!m.root.join(".inumaki-root").exists());
}

/// Review I4 (c) and m7, final review A-M6: a marker that holds another label
/// is not ours (rows and entry go, the tree stays untouched); a marker that is
/// not a plain file refuses the removal and keeps everything; no marker at all
/// lets the removal finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_with_a_foreign_marker_leaves_the_tree_and_a_symlinked_marker_refuses() {
    let m = start_state_only().await;
    let (f, st) = (
        Arc::clone(m.state.mirror.get().unwrap()),
        Arc::clone(&m.state),
    );
    let base = m.base.clone();
    tokio::task::spawn_blocking(move || {
        for (i, id) in ["a-qwxzvk", "b-qwxzvk", "c-qwxzvk", "d-qwxzvk"]
            .into_iter()
            .enumerate()
        {
            let src = base.join(format!("src{i}"));
            std::fs::create_dir_all(&src).unwrap();
            folder_dataset(&st, id);
            let info = f.add(&st, id, src.to_str().unwrap(), None).unwrap();
            let tree = PathBuf::from(&info.mirror);
            std::fs::create_dir_all(&tree).unwrap();
            match i {
                0 => std::fs::write(tree.join(".inumaki-mirror"), "cccccccccccccccc").unwrap(),
                1 => std::fs::write(tree.join("kept.txt"), "x").unwrap(),
                3 => {
                    std::os::unix::fs::symlink(base.join("elsewhere"), tree.join(".inumaki-mirror"))
                        .unwrap()
                }
                _ => {}
            }
            let removed = f.remove(&st, id);
            match i {
                0 => {
                    assert!(
                        removed.unwrap(),
                        "a foreign marker does not wedge the folder"
                    );
                    assert_eq!(
                        std::fs::read_to_string(tree.join(".inumaki-mirror")).unwrap(),
                        "cccccccccccccccc",
                        "the tree stays untouched"
                    );
                    assert!(st.vault.folder(id).unwrap().is_none() && f.get(id).is_none());
                }
                3 => {
                    assert!(
                        removed.is_err(),
                        "a marker that is no plain file is refused"
                    );
                    assert!(
                        tree.join(".inumaki-mirror").symlink_metadata().is_ok(),
                        "the tree stays"
                    );
                    assert!(st.vault.folder(id).unwrap().is_some(), "the row stays");
                    assert!(f.get(id).is_some(), "the registry entry stays");
                }
                1 => {
                    assert!(removed.unwrap());
                    assert!(
                        tree.join("kept.txt").exists(),
                        "unmarked content is left untouched"
                    );
                    assert!(st.vault.folder(id).unwrap().is_none() && f.get(id).is_none());
                }
                _ => {
                    assert!(removed.unwrap());
                    assert!(!tree.exists(), "an empty unmarked directory is removed");
                    assert!(st.vault.folder(id).unwrap().is_none() && f.get(id).is_none());
                }
            }
        }
    })
    .await
    .unwrap();
}

const NAME: &str = "Zyxwuria Quolnath";

async fn wait_file(p: &Path, within: Duration, pred: impl Fn(&str) -> bool) -> Option<String> {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if let Ok(s) = std::fs::read_to_string(p) {
            if pred(&s) {
                return Some(s);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_folder_dataset_mirrors_and_rotation_re_mirrors() {
    // The name is known only as a seeded entity (the offline profile has no
    // NER), so the re-mirror after the rotation tokenizes it only because
    // the previous epoch's known originals were carried (review Cr2).
    let m = start_mirror().await;
    let (code, body) =
        m.d.call(
            Method::POST,
            "/v1/datasets",
            Some(json!({"id": "x-qwxzvk", "name": "X", "kind": "nope"})),
        )
        .await;
    assert_eq!(code, 400);
    assert_eq!(
        body["error"]["message"],
        "kind must be generic, mailbox, or folder"
    );
    let (code, _) = m
        .d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({"id": "qwxzvk-akten", "name": "Akten", "profile": "offline", "kind": "folder"})),
        )
        .await;
    assert_eq!(code, 201);
    let s = Arc::clone(&m.d.state);
    tokio::task::spawn_blocking(move || {
        s.namespace("qwxzvk-akten")
            .unwrap()
            .lock()
            .unwrap()
            .token_for(&EntityKind::Person, NAME)
            .unwrap();
    })
    .await
    .unwrap();
    let src = m.base.join("Akten");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("brief.txt"),
        format!("Sehr geehrter Herr {NAME}\n"),
    )
    .unwrap();
    // The control API is Task 10's; connect through `Folders::add` (review I9).
    let (f, st, s2) = (
        Arc::clone(m.d.state.mirror.get().unwrap()),
        Arc::clone(&m.d.state),
        src.clone(),
    );
    let info = tokio::task::spawn_blocking(move || {
        f.add(&st, "qwxzvk-akten", s2.to_str().unwrap(), None)
            .unwrap()
    })
    .await
    .unwrap();
    let mirror = PathBuf::from(&info.mirror);
    assert!(
        mirror.starts_with(&m.root) && !mirror.to_string_lossy().contains("qwxzvk"),
        "label, not slug"
    );
    let first = wait_file(&mirror.join("brief.txt"), Duration::from_secs(20), |s| {
        s.contains("<PERSON_")
    })
    .await
    .expect("mirrored");
    assert!(!first.contains(NAME));
    let (code, _) =
        m.d.call(Method::POST, "/v1/datasets/qwxzvk-akten/rotate", None)
            .await;
    assert_eq!(code, 200);
    let second = wait_file(&mirror.join("brief.txt"), Duration::from_secs(40), |s| {
        s.contains("<PERSON_") && s != first
    })
    .await
    .expect("re-mirrored with a new-epoch token");
    assert!(!second.contains(NAME));
    let reg = m.d.state.folders.get().unwrap();
    assert_eq!(reg.source_roots().len(), 1);
    assert_eq!(reg.mirror_root(), Some(m.root.clone()));
    let (code, _) =
        m.d.call(Method::DELETE, "/v1/datasets/qwxzvk-akten", None)
            .await;
    assert_eq!(code, 204);
    assert!(!mirror.exists(), "the dataset's folder went with it");
    assert!(src.join("brief.txt").exists());
    assert!(reg.source_roots().is_empty());
    m.d.stop().await;
}

/// Task 7 ruling: the destination is resolved once, at add. A destination
/// an agent replaces by a symlink afterwards is refused at write time, and
/// nothing is written through the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outbox_destination_replaced_by_a_symlink_is_not_followed() {
    let m = start_mirror().await;
    let (code, _) =
        m.d.call(
            Method::POST,
            "/v1/datasets",
            Some(json!({"id": "qwxzvk-out", "name": "O", "kind": "folder"})),
        )
        .await;
    assert_eq!(code, 201);
    let (src, dest, elsewhere) = (
        m.base.join("Akten"),
        m.base.join("Antworten"),
        m.base.join("elsewhere"),
    );
    for d in [&src, &dest, &elsewhere] {
        std::fs::create_dir_all(d).unwrap();
    }
    let (f, st) = (
        Arc::clone(m.d.state.mirror.get().unwrap()),
        Arc::clone(&m.d.state),
    );
    let (s2, d2) = (src.clone(), dest.clone());
    let info = tokio::task::spawn_blocking(move || {
        f.add(
            &st,
            "qwxzvk-out",
            s2.to_str().unwrap(),
            Some(d2.to_str().unwrap()),
        )
        .unwrap()
    })
    .await
    .unwrap();
    let outbox = PathBuf::from(&info.outbox);
    let until = Instant::now() + Duration::from_secs(20);
    while !outbox.is_dir() && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(outbox.is_dir(), "the outbox exists");
    std::fs::remove_dir(&dest).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &dest).unwrap();
    std::fs::write(outbox.join("reply.txt"), "Antwort ohne Namen\n").unwrap();
    let f = Arc::clone(m.d.state.mirror.get().unwrap());
    let until = Instant::now() + Duration::from_secs(30);
    let mut refused = false;
    while Instant::now() < until {
        let unwritable = f.list().iter().any(|(_, snap)| {
            snap.as_ref()
                .is_some_and(|s| s.error == Some(inumaki_mirror::FolderError::OutboxUnwritable))
        });
        if unwritable {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(refused, "the write was attempted and refused");
    assert_eq!(
        std::fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "nothing written through the link"
    );
    assert!(
        std::fs::symlink_metadata(&dest)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link itself is left alone"
    );
    m.d.stop().await;
}

/// 5c review I2 / 6b M5: a root id adopted by the running service (the
/// folder was added while its root was unreadable) is stored in the sealed
/// folder config, which `Folders::load` passes as `Folder::root_id`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_adopted_root_id_is_stored_in_the_folder_config() {
    use inumakid::folders::FolderConfig;
    use std::os::unix::fs::MetadataExt;
    let m = start_state_only().await;
    let src = m.base.join("Akten");
    std::fs::create_dir_all(&src).unwrap();
    let md = std::fs::metadata(&src).unwrap();
    let want = (md.dev(), md.ino());
    let (f, st, s2) = (
        Arc::clone(m.state.mirror.get().unwrap()),
        Arc::clone(&m.state),
        src.clone(),
    );
    tokio::task::spawn_blocking(move || {
        folder_dataset(&st, "f-qwxzvk");
        f.add(&st, "f-qwxzvk", s2.to_str().unwrap(), None).unwrap();
        // As if added under EPERM: no id stored.
        let (bytes, _) = st.vault.folder("f-qwxzvk").unwrap().unwrap();
        let mut c: FolderConfig = serde_json::from_slice(&bytes).unwrap();
        c.root_id = None;
        let out = serde_json::to_vec(&c).unwrap();
        assert!(st.vault.update_folder_config("f-qwxzvk", &out).unwrap());
    })
    .await
    .unwrap();
    let (r, _t) = m.restart(None).await;
    let state = Arc::new(r.expect("restart"));
    let (f, st) = (Arc::clone(state.mirror.get().unwrap()), Arc::clone(&state));
    tokio::task::spawn_blocking(move || f.start(&st))
        .await
        .unwrap();
    let stored = |s: &inumakid::AppState| {
        let (bytes, _) = s.vault.folder("f-qwxzvk").unwrap().unwrap();
        serde_json::from_slice::<FolderConfig>(&bytes)
            .unwrap()
            .root_id
    };
    let until = Instant::now() + Duration::from_secs(20);
    while stored(&state) != Some(want) && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(stored(&state), Some(want), "the adopted id is stored");
    let f = Arc::clone(state.mirror.get().unwrap());
    tokio::task::spawn_blocking(move || f.stop()).await.unwrap();
}
