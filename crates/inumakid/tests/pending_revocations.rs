//! Pending gateway token revocations (offline Revert spec D2, D3, D6, D7):
//! a label-only record written while the service is down is applied before
//! the service serves; a bad record revokes every `app:` token; a
//! `revocations` path that cannot be listed stops the start.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use common::{open_vault, serve_result_in, start_in, start_with};
use inumaki_client::HarnessId;
use inumaki_client::revocations::{self, record};
use inumaki_vault::Vault;
use inumakid::StartError;
use inumakid::revocations::apply_pending;

fn labels(vault: &Vault) -> Vec<String> {
    vault
        .gateway_tokens()
        .unwrap()
        .into_iter()
        .map(|t| t.label)
        .collect()
}

fn mint(vault: &Vault, label: &str) -> String {
    let (_, token) = vault.create_gateway_token(label).unwrap();
    token.to_string()
}

fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_written_while_the_service_was_down_is_applied_before_it_serves() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let data = dir.join("data");
    let codex = {
        let vault = open_vault(dir);
        let a = mint(&vault, "app:codex");
        let b = mint(&vault, "app:codex");
        mint(&vault, "app:claude-code");
        mint(&vault, "mine");
        vec![a, b]
    };
    record(&data, HarnessId::Codex).unwrap();
    let file = data.join(revocations::DIR).join("codex.json");
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"{\"version\":1,\"label\":\"app:codex\"}\n"
    );
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(&data.join(revocations::DIR)), 0o700);

    let d = start_in(dir, "").await;
    assert_eq!(labels(&d.state.vault), vec!["app:claude-code", "mine"]);
    for t in &codex {
        assert!(matches!(d.state.vault.verify_gateway_token(t), Ok(None)));
    }
    assert!(!file.exists());
    d.stop().await;
}

/// One unreadable case: mint the app tokens again, plant the entry, apply,
/// and check that every `app:` token went, the check token stayed, and the
/// directory is empty.
fn unreadable_case(vault: &Vault, revs: &Path, plant: impl FnOnce(&Path)) {
    for l in ["app:codex", "app:hermes", "app:other"] {
        mint(vault, l);
    }
    plant(revs);
    let data = revs.parent().unwrap();
    assert_eq!(apply_pending(vault, data).unwrap(), 3);
    assert_eq!(labels(vault), vec!["check:0123456789ab"]);
    assert!(entries(revs).is_empty(), "{:?}", entries(revs));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_record_revokes_every_app_token_and_nothing_else() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let vault = open_vault(dir);
    mint(&vault, "check:0123456789ab");
    let revs = dir.join("data").join(revocations::DIR);
    std::fs::create_dir_all(&revs).unwrap();
    let hermes = b"{\"version\":1,\"label\":\"app:hermes\"}\n";

    unreadable_case(&vault, &revs, |r| {
        std::fs::write(r.join("codex.json"), "not json").unwrap();
        std::fs::write(r.join(".codex.json.tmp"), hermes).unwrap();
    });
    unreadable_case(&vault, &revs, |r| {
        std::fs::write(
            r.join("codex.json"),
            "{\"version\":2,\"label\":\"app:codex\"}\n",
        )
        .unwrap();
    });
    unreadable_case(&vault, &revs, |r| {
        std::fs::write(
            r.join("codex.json"),
            "{\"version\":1,\"label\":\"app:codex\",\"id\":7}\n",
        )
        .unwrap();
    });
    unreadable_case(&vault, &revs, |r| {
        std::fs::write(
            r.join("codex.json"),
            "{\"version\":1,\"label\":\"app:nobody\"}\n",
        )
        .unwrap();
    });
    unreadable_case(&vault, &revs, |r| {
        std::fs::write(r.join("codex.json"), hermes).unwrap();
    });
    let target = dir.join("elsewhere.json");
    std::fs::write(&target, "{\"version\":1,\"label\":\"app:claude-code\"}\n").unwrap();
    unreadable_case(&vault, &revs, |r| {
        std::os::unix::fs::symlink(&target, r.join("claude-code.json")).unwrap();
    });
    assert!(target.exists(), "the link's target is never touched");

    // A leftover temp record alone is removed and never applied.
    mint(&vault, "app:hermes");
    std::fs::write(revs.join(".hermes.json.tmp"), hermes).unwrap();
    assert_eq!(apply_pending(&vault, &dir.join("data")).unwrap(), 0);
    assert_eq!(labels(&vault), vec!["check:0123456789ab", "app:hermes"]);
    assert!(entries(&revs).is_empty(), "{:?}", entries(&revs));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocations_path_that_cannot_be_listed_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let vault = open_vault(dir);
    mint(&vault, "app:codex");
    let data = dir.join("data");
    let revs = data.join(revocations::DIR);
    let no_path = |e: &revocations::RevocationError| {
        let s = e.to_string();
        assert!(!s.contains("revocations/"), "{s}");
        assert!(!s.contains(&*dir.to_string_lossy()), "{s}");
    };

    // (a) a regular file
    std::fs::write(&revs, "x").unwrap();
    let e = apply_pending(&vault, &data).unwrap_err();
    no_path(&e);
    std::fs::remove_file(&revs).unwrap();

    // (b) a symbolic link to a real directory holding a valid record
    let real = dir.join("real");
    std::fs::create_dir_all(&real).unwrap();
    let rec = real.join("codex.json");
    std::fs::write(&rec, "{\"version\":1,\"label\":\"app:codex\"}\n").unwrap();
    std::os::unix::fs::symlink(&real, &revs).unwrap();
    let e = apply_pending(&vault, &data).unwrap_err();
    no_path(&e);
    assert!(rec.exists());
    assert_eq!(labels(&vault), vec!["app:codex"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocations_path_that_cannot_be_listed_stops_the_start() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let data = dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join(revocations::DIR), "x").unwrap();
    let (state, socket, r) = serve_result_in(dir).await;
    assert!(matches!(r, Err(StartError::Revocations(_))), "{r:?}");
    assert!(!socket.exists());
    assert!(state.gateway_listen.lock().unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_written_while_the_service_runs_is_applied_by_the_sweeper() {
    let d = start_with("", "", Duration::from_millis(100), None).await;
    mint(&d.state.vault, "app:codex");
    record(&d.state.data_dir, HarnessId::Codex).unwrap();
    let file = d.state.data_dir.join(revocations::DIR).join("codex.json");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let gone = !labels(&d.state.vault).iter().any(|l| l == "app:codex");
        if gone && !file.exists() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the sweeper did not apply the record"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    d.stop().await;
}

/// Spec D7: an entry the sweep cannot remove (a directory named
/// `codex.json`) stops a running service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entry_the_sweep_cannot_remove_stops_the_service() {
    let d = start_with("", "", Duration::from_millis(100), None).await;
    let revs = d.state.data_dir.join(revocations::DIR);
    std::fs::create_dir_all(revs.join("codex.json")).unwrap();
    let mut rx = d.state.shutdown.subscribe();
    // `wait_for`'s guard holds the watch's read lock: drop it inside, or
    // `stop`'s `send_replace` would wait for it forever.
    let stopped = tokio::time::timeout(Duration::from_secs(5), async {
        rx.wait_for(|v| *v).await.is_ok()
    })
    .await;
    assert!(
        matches!(stopped, Ok(true)),
        "the service did not stop within 5 s"
    );
    d.stop().await;
}
