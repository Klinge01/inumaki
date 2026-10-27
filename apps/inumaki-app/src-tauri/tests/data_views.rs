//! Email and Folders (spec §6.4, §6.5): degrade to "not available yet"
//! before a lane merges (Review Focus 2), send the app password once and
//! keep it nowhere, reveal only inside the mirror root, and report the
//! harnesses a data change could not update (review C2c).

mod common;

use std::path::Path;

use common::{Fail, FakeOps, ctx_with};
use inumaki_app_lib::commands::{email, folders};
use inumaki_client::mock::{Canned, MockDaemon};
use inumaki_client::{HarnessId, MailboxPreset};
use serde_json::json;

fn no_route() -> Canned {
    Canned::error(404, "not_found", "no such route", &[])
}

#[tokio::test]
async fn views_degrade_when_lane_routes_are_missing() {
    let m = MockDaemon::start().await;
    let mut status: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("status")).unwrap();
    status.as_object_mut().unwrap().remove("mailboxes");
    m.set("GET", "/v1/status", Canned::json(200, status));
    m.set("GET", "/v1/folders", no_route());
    m.set("GET", "/v1/proxy", no_route());
    let (ctx, _dir, _) = ctx_with(&m, vec![FakeOps::new(HarnessId::ClaudeCode)]);
    assert_eq!(
        email::mailboxes(&ctx).await.unwrap_err().kind,
        "not_available"
    );
    assert_eq!(
        folders::folders(&ctx).await.unwrap_err().kind,
        "not_available"
    );
    let v = inumaki_app_lib::commands::overview::overview(&ctx)
        .await
        .unwrap();
    assert!(
        v.reachable && v.cards.len() == 1,
        "the Overview still renders"
    );
}

/// The user's own paths (source, mirror, outbox, outbox destination) are for
/// the UI only: not in `Debug` of the row or of the view (they would reach a
/// log through a stray `{:?}`).
#[tokio::test]
async fn a_folder_row_debug_omits_the_source_path() {
    let m = MockDaemon::start().await;
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let v = folders::folders(&ctx).await.unwrap();
    let row = &v.folders[0];
    assert_eq!(row.source, "/Users/qwxzvk/Akten", "the UI still gets it");
    assert_eq!(row.mirror, "/Users/qwxzvk/Inumaki/d1b2c3d4e5f60718");
    assert_eq!(row.outbox, "/Users/qwxzvk/Inumaki/d1b2c3d4e5f60718/outbox");
    assert_eq!(row.outbox_destination, "/Users/qwxzvk/Inumaki Outbox/Akten");
    for dbg in [format!("{row:?}"), format!("{v:?}")] {
        for s in [
            "qwxzvk",
            "Akten",
            "/Users",
            "Inumaki",
            "d1b2c3d4e5f60718",
            "outbox",
            "Outbox",
        ] {
            assert!(!dbg.contains(s), "{s} in {dbg}");
        }
    }
}

/// "Show restored files" reveals only the destination the daemon reports
/// for the dataset, and only an existing directory that is not a symlink.
#[tokio::test]
async fn outbox_target_reveals_only_an_existing_destination() {
    let m = MockDaemon::start().await;
    let mut f: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("folders")).unwrap();
    let ds = f["folders"][0]["dataset"].as_str().unwrap().to_string();
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    // Nothing restored yet: the fixture's destination does not exist.
    assert_eq!(
        folders::outbox_target(&ctx, &ds).await.unwrap_err().kind,
        "open_failed"
    );
    assert_eq!(
        folders::outbox_target(&ctx, "qwxzvk-nirgends")
            .await
            .unwrap_err()
            .kind,
        "not_found"
    );
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("Ausgang");
    std::fs::create_dir_all(&dest).unwrap();
    f["folders"][0]["outbox_destination"] = json!(dest.to_str().unwrap());
    m.set("GET", "/v1/folders", Canned::json(200, f.clone()));
    assert_eq!(
        folders::outbox_target(&ctx, &ds).await.unwrap(),
        std::fs::canonicalize(&dest).unwrap()
    );
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&dest, &link).unwrap();
    f["folders"][0]["outbox_destination"] = json!(link.to_str().unwrap());
    m.set("GET", "/v1/folders", Canned::json(200, f.clone()));
    assert_eq!(
        folders::outbox_target(&ctx, &ds).await.unwrap_err().kind,
        "open_failed"
    );
    for bad in ["", "relative/Ausgang", "/Users/../etc"] {
        f["folders"][0]["outbox_destination"] = json!(bad);
        m.set("GET", "/v1/folders", Canned::json(200, f.clone()));
        assert_eq!(
            folders::outbox_target(&ctx, &ds).await.unwrap_err().kind,
            "bad_response",
            "{bad}"
        );
    }
}

#[tokio::test]
async fn mailbox_password_is_sent_once_and_kept_nowhere() {
    let m = MockDaemon::start().await;
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    inumaki_app_lib::applog::init(&ctx.paths.log_file);
    let form: email::MailboxForm = serde_json::from_value(json!({
        "preset": "gmail", "username": "office@qwxzvk.example", "password": "hunter2-qwxzvk", "display_name": "Qwxzvk Office"
    }))
    .unwrap();
    assert!(!format!("{form:?}").contains("hunter2"));
    let added = email::add_mailbox(&ctx, form).await.unwrap();
    assert_eq!(added.reconnect_failures, 0);
    let sent = m
        .requests()
        .into_iter()
        .find(|r| r.route == "/v1/datasets/{id}/mailbox" && r.method == "POST")
        .unwrap();
    assert_eq!(sent.body.unwrap()["password"], "hunter2-qwxzvk");
    let created = m
        .requests()
        .into_iter()
        .find(|r| r.route == "/v1/datasets" && r.method == "POST")
        .unwrap()
        .body
        .unwrap();
    assert_eq!(created["kind"], "mailbox");
    assert!(
        created["id"].as_str().unwrap().starts_with("mail-"),
        "never named after the mailbox"
    );
    // The card the UI gets never carries the vault secret's name.
    assert!(
        !serde_json::to_string(&added.card)
            .unwrap()
            .contains("password")
    );
    for f in [&ctx.paths.log_file, &ctx.paths.state_file] {
        let t = std::fs::read_to_string(f).unwrap_or_default();
        assert!(!t.contains("hunter2") && !t.contains("qwxzvk"), "{t}");
    }
    assert_eq!(
        email::help_url(MailboxPreset::Gmail),
        Some("https://support.google.com/accounts/answer/185833")
    );
}

#[tokio::test]
async fn reveal_only_inside_the_mirror_root() {
    let m = MockDaemon::start().await;
    let mut f: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("folders")).unwrap();
    let ds = f["folders"][0]["dataset"].as_str().unwrap().to_string();
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    assert!(
        folders::reveal_target(&ctx, &ds).await.is_ok(),
        "the fixture's mirror is under its root"
    );
    f["folders"][0]["mirror"] = json!("/etc");
    m.set("GET", "/v1/folders", Canned::json(200, f.clone()));
    assert_eq!(
        folders::reveal_target(&ctx, &ds).await.unwrap_err().kind,
        "outside_mirror_root"
    );
    f["folders"][0]["mirror"] = json!(format!("{}/../../etc", f["mirror_root"].as_str().unwrap()));
    m.set("GET", "/v1/folders", Canned::json(200, f));
    assert_eq!(
        folders::reveal_target(&ctx, &ds).await.unwrap_err().kind,
        "outside_mirror_root"
    );
}

#[tokio::test]
async fn reveal_refuses_a_mirror_that_is_a_symlink_out_of_the_root() {
    let m = MockDaemon::start().await;
    let mut f: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("folders")).unwrap();
    let ds = f["folders"][0]["dataset"].as_str().unwrap().to_string();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    f["mirror_root"] = json!(root.to_str().unwrap());
    f["folders"][0]["mirror"] = json!(root.join("link").to_str().unwrap());
    m.set("GET", "/v1/folders", Canned::json(200, f));
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    assert_eq!(
        folders::reveal_target(&ctx, &ds).await.unwrap_err().kind,
        "outside_mirror_root"
    );
}

#[tokio::test]
async fn data_changes_report_harnesses_they_could_not_update() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    *f.fail_apply.lock().unwrap() = Some(Fail::Io);
    // Connected: the adapter holds an active backup.
    *f.active.lock().unwrap() = Some("000000000001-000000000".into());
    let idle = FakeOps::new(HarnessId::ClaudeCode);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone(), idle.clone()]);
    ctx.update_state(|s| {
        s.backups.insert("codex".into(), vec!["backup-0".into()]);
    })
    .unwrap();
    let change = folders::add_folder(&ctx, "/Users/qwxzvk/Akten".into())
        .await
        .unwrap();
    assert_eq!(change.reconnect_failures, 1);
    assert_eq!(change.failed_harnesses, vec!["codex"]);
    assert!(
        ctx.state().reconnect_failed.contains("codex"),
        "and the tray turns red"
    );
    // The preview came first and the apply failed: the revert had run.
    assert_eq!(*f.previews.lock().unwrap(), 1);
    assert_eq!(f.reverted.lock().unwrap().len(), 1);
    // A harness that is not connected is not touched.
    assert_eq!(*idle.previews.lock().unwrap(), 0);
    assert!(idle.applied.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_refused_preview_changes_no_harness_and_is_counted() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    f.refuse_preview
        .store(true, std::sync::atomic::Ordering::SeqCst);
    *f.active.lock().unwrap() = Some("000000000001-000000000".into());
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let change = folders::remove_folder(&ctx, "qwxzvk-akten").await.unwrap();
    assert_eq!(change.reconnect_failures, 1);
    assert!(
        f.reverted.lock().unwrap().is_empty(),
        "preview before revert"
    );
    assert!(
        !ctx.state().reconnect_failed.contains("codex"),
        "nothing was reverted: still connected"
    );
}

#[tokio::test]
async fn a_removed_mailbox_is_not_written_back_to_a_harness() {
    let m = MockDaemon::start().await;
    // The daemon's status no longer lists the mailbox after the delete.
    let mut status: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("status")).unwrap();
    status["datasets"] = json!([]);
    m.set("GET", "/v1/status", Canned::json(200, status));
    let f = FakeOps::new(HarnessId::Codex);
    *f.active.lock().unwrap() = Some("000000000001-000000000".into());
    let mut e = FakeOps::stdio("inumaki-mail", "/bin/true", &[]);
    e.gateway_dataset = Some("qwxzvk-mail".into());
    f.servers.lock().unwrap().push(e);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let change = email::remove_mailbox(&ctx, "qwxzvk-mail").await.unwrap();
    assert_eq!(change.reconnect_failures, 0);
    let applied = f.applied.lock().unwrap().clone();
    assert_eq!(applied.len(), 1);
    assert!(
        applied[0]
            .iter()
            .all(|(_, url, _)| !url.contains("qwxzvk-mail")),
        "the removed mailbox's entry is gone"
    );
}

#[tokio::test]
async fn folder_rows_carry_a_fixed_error_not_the_daemons_words() {
    let m = MockDaemon::start().await;
    let mut f: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("folders")).unwrap();
    f["folders"][0]["state"] = json!("failed");
    f["folders"][0]["error"] = json!("source_unreadable");
    m.set("GET", "/v1/folders", Canned::json(200, f));
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let v = folders::folders(&ctx).await.unwrap();
    let e = v.folders[0].error.expect("an error row");
    assert_eq!(e.code, "folder_source_unreadable");
    assert_eq!(
        e.text,
        folders::error_reason(Some(inumaki_client::FolderError::SourceUnreadable)).text
    );
    // The mirror, outbox, and destination paths reach the UI on purpose
    // (redesign spec §9.1, local user only); `Debug` still omits them
    // (`a_folder_row_debug_omits_the_source_path`).
}

#[tokio::test]
async fn a_pending_folder_has_no_error_row_even_with_a_stale_error() {
    let m = MockDaemon::start().await;
    let mut f: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("folders")).unwrap();
    f["folders"][0]["state"] = json!("pending");
    f["folders"][0]["error"] = json!("source_unreadable");
    m.set("GET", "/v1/folders", Canned::json(200, f));
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let v = folders::folders(&ctx).await.unwrap();
    assert_eq!(v.folders[0].state, inumaki_client::FolderState::Pending);
    assert!(v.folders[0].error.is_none());
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"state\":\"pending\""), "{json}");
}

#[tokio::test]
async fn a_busy_removal_keeps_the_folder_and_says_so() {
    let m = MockDaemon::start().await;
    let busy = || {
        Canned::error(
            409,
            "conflict",
            "the folder is busy; try again in a moment",
            &[],
        )
    };
    m.set("DELETE", "/v1/datasets/{id}/folder", busy());
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let e = folders::remove_folder(&ctx, "qwxzvk-akten")
        .await
        .unwrap_err();
    assert_eq!(e.kind, "folder_busy");
    assert_eq!(e.status, Some(409));
    // Only the folder call ran: the dataset and its vault namespace were not touched.
    assert_eq!(deletes(&m), vec!["/v1/datasets/qwxzvk-akten/folder"]);
    // The folder call passes but the dataset delete is busy: the same answer.
    m.set("DELETE", "/v1/datasets/{id}/folder", Canned::empty(204));
    m.set("DELETE", "/v1/datasets/{id}", busy());
    let e = folders::remove_folder(&ctx, "qwxzvk-akten")
        .await
        .unwrap_err();
    assert_eq!(e.kind, "folder_busy");
}

#[tokio::test]
async fn a_409_of_another_kind_is_not_a_busy_folder() {
    let m = MockDaemon::start().await;
    let other = |kind: &str| Canned::error(409, kind, "something else", &[]);
    // The dataset delete answers 409 with another type: reported as itself.
    m.set("DELETE", "/v1/datasets/{id}/folder", Canned::empty(204));
    m.set("DELETE", "/v1/datasets/{id}", other("already_exists"));
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let e = folders::remove_folder(&ctx, "qwxzvk-akten")
        .await
        .unwrap_err();
    assert_ne!(e.kind, "folder_busy");
    // A 409 without the documented error shape is not busy either.
    m.set("DELETE", "/v1/datasets/{id}", Canned::empty(409));
    let e = folders::remove_folder(&ctx, "qwxzvk-akten")
        .await
        .unwrap_err();
    assert_ne!(e.kind, "folder_busy");
    // Another type on the folder call: the removal goes on to the dataset.
    m.set(
        "DELETE",
        "/v1/datasets/{id}/folder",
        other("already_exists"),
    );
    m.set("DELETE", "/v1/datasets/{id}", Canned::empty(204));
    let _ = folders::remove_folder(&ctx, "qwxzvk-akten").await;
    assert_eq!(
        deletes(&m).last().map(String::as_str),
        Some("/v1/datasets/qwxzvk-akten")
    );
}

#[test]
fn folders_macos_protects_get_a_fixed_warning_code() {
    let home = Path::new("/Users/qwxzvk");
    for p in [
        "/Users/qwxzvk/Desktop/Akten",
        "/Users/qwxzvk/documents",
        "/Users/qwxzvk/Downloads",
        "/Users/qwxzvk/Library/Mobile Documents/com~apple~CloudDocs/Akten",
        "/Volumes/Extern/Akten",
    ] {
        assert_eq!(
            folders::access_warning(Path::new(p), home),
            Some("folder_needs_access"),
            "{p}"
        );
    }
    for p in [
        "/Users/qwxzvk/Akten",
        "/Users/qwxzvk/Library/Caches",
        "/srv/x",
    ] {
        assert_eq!(folders::access_warning(Path::new(p), home), None, "{p}");
    }
}

fn deletes(m: &MockDaemon) -> Vec<String> {
    m.requests()
        .into_iter()
        .filter(|r| r.method == "DELETE")
        .map(|r| r.path)
        .collect()
}

#[tokio::test]
async fn removal_only_touches_datasets_of_its_own_kind() {
    let m = MockDaemon::start().await;
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    // `qwxzvk-kunde` is a wrapped-server (generic) dataset in the fixture.
    assert_eq!(
        email::remove_mailbox(&ctx, "qwxzvk-kunde")
            .await
            .unwrap_err()
            .kind,
        "not_a_mailbox"
    );
    assert_eq!(
        folders::remove_folder(&ctx, "qwxzvk-kunde")
            .await
            .unwrap_err()
            .kind,
        "not_a_folder"
    );
    assert_eq!(
        folders::remove_folder(&ctx, "qwxzvk-mail")
            .await
            .unwrap_err()
            .kind,
        "not_a_folder"
    );
    assert!(
        deletes(&m).is_empty(),
        "nothing was deleted: {:?}",
        deletes(&m)
    );
}

#[tokio::test]
async fn a_failed_create_deletes_the_dataset_again() {
    let m = MockDaemon::start().await;
    m.set(
        "POST",
        "/v1/datasets/{id}/mailbox",
        Canned::error(400, "bad_request", "bad host", &[]),
    );
    m.set(
        "POST",
        "/v1/datasets/{id}/folder",
        Canned::error(400, "bad_request", "bad source", &[]),
    );
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let form: email::MailboxForm = serde_json::from_value(json!({
        "preset": "gmail", "username": "u@qwxzvk.example", "password": "pw", "display_name": "Qwxzvk"
    }))
    .unwrap();
    assert_eq!(
        email::add_mailbox(&ctx, form).await.unwrap_err().kind,
        "bad_request"
    );
    assert_eq!(deletes(&m), ["/v1/datasets/mail-1"]);
    assert_eq!(
        folders::add_folder(&ctx, "/Users/qwxzvk/Akten".into())
            .await
            .unwrap_err()
            .kind,
        "bad_request"
    );
    assert_eq!(
        deletes(&m),
        ["/v1/datasets/mail-1", "/v1/datasets/folder-1"]
    );
}

#[tokio::test]
async fn a_revert_that_ran_meanwhile_is_not_undone_by_the_refresh() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    *f.active.lock().unwrap() = Some("000000000001-000000000".into());
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    // A Revert holds the harness while the folder is added.
    let held = ctx.harness_lock(HarnessId::Codex).lock_owned().await;
    let c = ctx.clone();
    let add =
        tokio::spawn(async move { folders::add_folder(&c, "/Users/qwxzvk/Akten".into()).await });
    // The folder is created; the refresh now waits for the lock.
    for _ in 0..200 {
        if m.requests()
            .iter()
            .any(|r| r.route == "/v1/datasets/{id}/folder" && r.method == "POST")
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    *f.active.lock().unwrap() = None; // the Revert finished
    drop(held);
    let change = add.await.unwrap().unwrap();
    assert_eq!(change.reconnect_failures, 0);
    assert!(
        f.applied.lock().unwrap().is_empty(),
        "no apply after the revert"
    );
    assert_eq!(*f.previews.lock().unwrap(), 0);
}

#[tokio::test]
async fn a_refused_refresh_revokes_the_token_it_minted() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    f.refuse_preview
        .store(true, std::sync::atomic::Ordering::SeqCst);
    *f.active.lock().unwrap() = Some("000000000001-000000000".into());
    // A gateway entry carries a token, so one is minted.
    let mut e = FakeOps::stdio("inumaki-mail", "/bin/true", &[]);
    e.gateway_dataset = Some("qwxzvk-mail".into());
    f.servers.lock().unwrap().push(e);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let change = folders::remove_folder(&ctx, "qwxzvk-akten").await.unwrap();
    assert_eq!(change.reconnect_failures, 1);
    let minted = m
        .requests()
        .iter()
        .any(|r| r.route == "/v1/gateway/tokens" && r.method == "POST");
    assert!(minted, "the request carried a gateway entry");
    let created_id = serde_json::from_str::<serde_json::Value>(inumaki_client::contract::fixture(
        "token_created",
    ))
    .unwrap()["id"]
        .to_string();
    assert!(
        deletes(&m).contains(&format!("/v1/gateway/tokens/{created_id}")),
        "{:?}",
        deletes(&m)
    );
}
