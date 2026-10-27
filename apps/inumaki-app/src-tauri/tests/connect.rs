//! Connect, Revert, Reconnect (spec §4.2, §4.5; Review Focus 3; review C1,
//! C2): tokens are labelled per harness; a refusal keeps the token that is
//! in the manual snippet, every other failure revokes it; Reconnect refuses
//! before writing and reports a failure after its revert as a disconnect.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use common::{Fail, FakeOps, ctx_with};
use inumaki_app_lib::appstate::{CheckMemo, last_check_summary};
use inumaki_app_lib::harness::ops::HarnessOps;
use inumaki_app_lib::harness::{connect, harness_key};
use inumaki_client::mock::{Canned, MockDaemon};
use inumaki_client::{CheckReport, HarnessId, PathStatus};
use serde_json::json;

fn created() -> (i64, String) {
    let v: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("token_created")).unwrap();
    (
        v["id"].as_i64().unwrap(),
        v["token"].as_str().unwrap().to_string(),
    )
}

fn deleted(m: &MockDaemon) -> Vec<String> {
    m.requests()
        .into_iter()
        .filter(|r| r.method == "DELETE" && r.route == "/v1/gateway/tokens/{id}")
        .map(|r| r.path.rsplit('/').next().unwrap().to_string())
        .collect()
}

fn minted(m: &MockDaemon) -> Vec<serde_json::Value> {
    m.requests()
        .into_iter()
        .filter(|r| r.method == "POST" && r.route == "/v1/gateway/tokens")
        .map(|r| r.body.unwrap()["label"].clone())
        .collect()
}

fn tokens(list: &[(i64, &str)]) -> Canned {
    Canned::json(
        200,
        json!(
            list.iter()
                .map(|(id, label)| json!({ "id": id, "label": label, "created_at": 1, "last_used": null }))
                .collect::<Vec<_>>()
        ),
    )
}

/// A gateway entry the harness already has (connected by hand, or a
/// protected server), so the request carries a token.
fn routed(f: &FakeOps) {
    let mut e = FakeOps::stdio("crm", "/usr/local/bin/crm", &[]);
    e.gateway_dataset = Some("qwxzvk-kunde".into());
    f.servers.lock().unwrap().push(e);
}

/// A passed check memo (the fixture report with every path passed).
fn memo() -> CheckMemo {
    let mut r = serde_json::from_str(inumaki_client::contract::fixture("check_report"))
        .map(|r: CheckReport| r.results)
        .unwrap();
    r.gateway.status = PathStatus::Passed;
    r.mirror.status = PathStatus::Passed;
    r.proxy.status = PathStatus::Passed;
    CheckMemo { at: 1, results: r }
}

fn state_bytes(ctx: &inumaki_app_lib::ctx::Ctx) -> String {
    std::fs::read_to_string(&ctx.paths.state_file).unwrap_or_default()
}

#[tokio::test]
async fn a_refusal_keeps_the_token_that_is_in_the_snippet() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    *f.fail_apply.lock().unwrap() = Some(Fail::Refuse);
    let (ctx, _dir, notes) = ctx_with(&m, vec![f.clone()]);
    let e = connect::connect(&ctx, HarnessId::Codex).await.unwrap_err();
    assert_eq!(e.kind, "cannot_edit_safely");
    let (_, token) = created();
    assert!(
        e.snippet.as_deref().unwrap().contains(&token),
        "the manual fallback needs the live token"
    );
    assert!(
        deleted(&m).is_empty(),
        "the token in the snippet must keep working"
    );
    assert_eq!(minted(&m), [json!("app:codex")]);
    assert!(
        !format!("{e:?}").contains(&token),
        "Debug never prints the snippet"
    );
    assert!(!state_bytes(&ctx).contains(&token));
    assert!(notes.sent().iter().all(|n| !n.contains(&token)));
}

#[tokio::test]
async fn any_other_failure_revokes_the_new_token_at_once() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    *f.fail_apply.lock().unwrap() = Some(Fail::Io);
    let (ctx, _dir, _) = ctx_with(&m, vec![f]);
    let e = connect::connect(&ctx, HarnessId::Codex).await.unwrap_err();
    assert_eq!(e.kind, "file_unwritable");
    assert!(e.snippet.is_none());
    assert_eq!(deleted(&m), [created().0.to_string()]);
    assert!(
        ctx.state()
            .backups
            .get("codex")
            .is_none_or(|b| b.is_empty())
    );
}

#[tokio::test]
async fn connect_writes_protected_servers_and_mailboxes_with_one_token() {
    let m = MockDaemon::start().await;
    let mut status: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("status")).unwrap();
    let ds = |id: &str, kind: &str| json!({ "id": id, "label": "0123456789abcdef", "name": "x", "profile": "offline", "rotation_days": 30, "grace_days": 7, "epoch_id": 1, "epoch_started_at": 1, "entries": 0, "kind": kind });
    status["datasets"] = json!([
        ds("mail-2", "mailbox"),
        ds("mcp-crm", "generic"),
        ds("mail-1", "mailbox")
    ]);
    m.set("GET", "/v1/status", Canned::json(200, status.clone()));
    let f = FakeOps::new(HarnessId::ClaudeCode);
    let mut crm = FakeOps::stdio("crm", "/usr/local/bin/crm", &[]);
    crm.gateway_dataset = Some("mcp-crm".into());
    f.servers.lock().unwrap().push(crm);
    f.servers
        .lock()
        .unwrap()
        .push(FakeOps::stdio("left-alone", "/bin/x", &[]));
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    connect::connect(&ctx, HarnessId::ClaudeCode).await.unwrap();
    assert_eq!(*f.previews.lock().unwrap(), 1, "previewed before writing");
    let applied = f.applied.lock().unwrap()[0].clone();
    let listen = status["gateway"]["listen"].as_str().unwrap();
    assert_eq!(
        applied
            .iter()
            .map(|(n, u, _)| (n.as_str(), u.as_str()))
            .collect::<Vec<_>>(),
        [
            ("crm", format!("http://{listen}/mcp/mcp-crm").as_str()),
            (
                "inumaki-mail",
                format!("http://{listen}/mcp/mail-1").as_str()
            ),
            (
                "inumaki-mail-2",
                format!("http://{listen}/mcp/mail-2").as_str()
            ),
        ]
    );
    assert!(
        applied.iter().all(|(_, _, t)| t == &applied[0].2),
        "one token per harness"
    );
    assert_eq!(ctx.state().backups["claude-code"].len(), 1);
    // The proxy's client header goes into the request, as `inumaki connect` does.
    let proxy: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("proxy")).unwrap();
    assert_eq!(
        f.headers.lock().unwrap()[0].as_deref(),
        proxy["client_header"]["value"].as_str()
    );
    // Neither the token nor the header reaches state.json.
    let st = state_bytes(&ctx);
    assert!(!st.contains(&applied[0].2));
    assert!(!st.contains(proxy["client_header"]["value"].as_str().unwrap()));
}

#[tokio::test]
async fn reconnect_refuses_before_writing_and_revokes_the_old_token_only_after_apply() {
    let m = MockDaemon::start().await;
    m.set(
        "GET",
        "/v1/gateway/tokens",
        tokens(&[(7, "app:codex"), (8, "app:claude-code")]),
    );
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    *f.active.lock().unwrap() = Some("backup-0".into());
    // A refusal at preview: nothing reverted, the old token untouched.
    f.fail_preview.store(true, Ordering::SeqCst);
    assert!(connect::reconnect(&ctx, HarnessId::Codex).await.is_err());
    assert!(
        f.reverted.lock().unwrap().is_empty(),
        "no write before the preview passed"
    );
    assert!(!deleted(&m).contains(&"7".to_string()));
    assert_eq!(f.active.lock().unwrap().as_deref(), Some("backup-0"));
    f.fail_preview.store(false, Ordering::SeqCst);
    let before = deleted(&m).len();
    connect::reconnect(&ctx, HarnessId::Codex).await.unwrap();
    assert_eq!(
        *f.reverted.lock().unwrap(),
        ["backup-0"],
        "revert to the original first"
    );
    assert_eq!(f.applied.lock().unwrap().len(), 1);
    assert_eq!(
        deleted(&m)[before..],
        ["7"],
        "only this harness's old token, after the apply"
    );
    assert_eq!(ctx.state().backups["codex"].len(), 1);
    assert_ne!(ctx.state().backups["codex"][0], "backup-0");
}

/// D9: a user Revert removes the check memo of the connection it ended, and
/// only that harness's memo (never the direct run's, never another harness's).
#[tokio::test]
async fn a_revert_forgets_the_harness_check_memo_and_keeps_the_others() {
    let m = MockDaemon::start().await;
    m.set("GET", "/v1/gateway/tokens", tokens(&[(7, "app:codex")]));
    let f = FakeOps::new(HarnessId::Codex);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    *f.active.lock().unwrap() = Some("backup-0".into());
    ctx.update_state(|s| {
        s.backups.insert("codex".into(), vec!["backup-0".into()]);
        for k in ["codex", "claude-code", "direct"] {
            s.last_check.insert(k.into(), memo());
        }
    })
    .unwrap();
    connect::revert(&ctx, HarnessId::Codex).await.unwrap();
    let s = ctx.state();
    assert!(!s.last_check.contains_key("codex"));
    assert!(s.last_check.contains_key("claude-code") && s.last_check.contains_key("direct"));
    // With only the harness's own memo, nothing is left to summarise.
    ctx.update_state(|s| {
        s.last_check.clear();
        s.last_check.insert("codex".into(), memo());
    })
    .unwrap();
    connect::revert(&ctx, HarnessId::Codex).await.unwrap();
    assert!(last_check_summary(&ctx.state()).is_none());
}

/// Review C2 (b): an apply failure after the revert is a disconnect, loudly.
#[tokio::test]
async fn a_reconnect_failure_after_the_revert_is_reported_as_disconnected() {
    let m = MockDaemon::start().await;
    m.set("GET", "/v1/gateway/tokens", tokens(&[(7, "app:codex")]));
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    *f.active.lock().unwrap() = Some("backup-0".into());
    *f.fail_apply.lock().unwrap() = Some(Fail::Io);
    ctx.update_state(|s| {
        s.last_check.insert("codex".into(), memo());
    })
    .unwrap();
    let e = connect::reconnect(&ctx, HarnessId::Codex)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "reconnect_failed_disconnected");
    let d = deleted(&m);
    assert!(
        d.contains(&created().0.to_string()) && d.contains(&"7".to_string()),
        "no file uses either token now: {d:?}"
    );
    let s = ctx.state();
    assert!(s.reconnect_failed.contains("codex"));
    assert!(
        !s.last_check.contains_key("codex"),
        "the check proved a connection that is gone"
    );
    assert!(s.backups.get("codex").is_none_or(|b| b.is_empty()));
    // The next successful Connect clears the flag.
    *f.fail_apply.lock().unwrap() = None;
    connect::connect(&ctx, HarnessId::Codex).await.unwrap();
    assert!(!ctx.state().reconnect_failed.contains("codex"));
}

/// A refusal after the revert drops its snippet: the token in it is revoked.
#[tokio::test]
async fn a_refusal_after_the_revert_shows_no_snippet() {
    let m = MockDaemon::start().await;
    m.set("GET", "/v1/gateway/tokens", tokens(&[(7, "app:codex")]));
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    *f.active.lock().unwrap() = Some("000000000001-000000000".into());
    *f.fail_apply.lock().unwrap() = Some(Fail::Refuse);
    let e = connect::connect(&ctx, HarnessId::Codex).await.unwrap_err();
    assert_eq!(e.kind, "reconnect_failed_disconnected");
    assert!(e.snippet.is_none());
    assert!(deleted(&m).contains(&created().0.to_string()));
}

#[tokio::test]
async fn revert_revokes_every_token_of_the_harness_even_without_a_backup() {
    let m = MockDaemon::start().await;
    m.set(
        "GET",
        "/v1/gateway/tokens",
        tokens(&[
            (7, "app:codex"),
            (8, "app:claude-code"),
            (9, "app:codex"),
            (10, "check:0123456789ab"),
        ]),
    );
    let f = FakeOps::new(HarnessId::Codex);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    *f.active.lock().unwrap() = Some("backup-0".into());
    ctx.update_state(|s| {
        s.backups.insert("codex".into(), vec!["backup-0".into()]);
        s.reconnect_failed.insert("codex".into());
    })
    .unwrap();
    let r = connect::revert(&ctx, HarnessId::Codex).await.unwrap();
    assert!(r.reverted);
    assert!(!r.client_header_left);
    assert!(!r.revocation_pending, "the service revoked the tokens");
    assert!(
        !ctx.paths.data_dir.join("revocations").exists(),
        "an online Revert writes no record"
    );
    assert_eq!(*f.reverted.lock().unwrap(), ["backup-0"]);
    assert_eq!(deleted(&m), ["7", "9"]);
    assert!(
        ctx.state()
            .backups
            .get("codex")
            .is_none_or(|b| b.is_empty())
    );
    assert!(!ctx.state().reconnect_failed.contains("codex"));
    // A harness connected by hand (the snippet) has no backup: Revert still revokes.
    let r = connect::revert(&ctx, HarnessId::Codex).await.unwrap();
    assert!(!r.reverted);
    assert!(!r.revocation_pending);
    assert_eq!(deleted(&m), ["7", "9", "7", "9"]);
}

fn record_path(ctx: &inumaki_app_lib::ctx::Ctx, key: &str) -> std::path::PathBuf {
    ctx.paths
        .data_dir
        .join("revocations")
        .join(format!("{key}.json"))
}

/// Offline Revert (spec D1, D5): with the service not running the files are
/// restored and a label-only record names the token to revoke.
#[tokio::test]
async fn revert_with_the_service_down_records_the_revocation_and_restores_the_files() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    *f.active.lock().unwrap() = Some("backup-0".into());
    ctx.update_state(|s| {
        s.backups.insert("codex".into(), vec!["backup-0".into()]);
    })
    .unwrap();
    m.stop().await;
    let r = connect::revert(&ctx, HarnessId::Codex).await.unwrap();
    assert!(r.reverted && r.revocation_pending);
    assert_eq!(*f.reverted.lock().unwrap(), ["backup-0"]);
    assert_eq!(
        std::fs::read(record_path(&ctx, "codex")).unwrap(),
        b"{\"version\":1,\"label\":\"app:codex\"}\n",
        "the record holds the label only"
    );
    assert!(!state_bytes(&ctx).contains("inumaki-gw-"));
    assert!(!ctx.state().backups.contains_key("codex"));
    // Without a backup: nothing to revert, the revocation is still pending.
    let r = connect::revert(&ctx, HarnessId::Codex).await.unwrap();
    assert!(!r.reverted && r.revocation_pending);
    assert!(record_path(&ctx, "codex").exists());
}

/// Review R1: the offline Revert that leaves the client header has its own kind.
#[tokio::test]
async fn an_offline_revert_that_leaves_the_client_header_reports_it_with_the_pending_revocation() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.header_left.store(true, Ordering::SeqCst);
    *f.active.lock().unwrap() = Some("000000000001-000000000".into());
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    m.stop().await;
    let e = connect::revert(&ctx, HarnessId::ClaudeCode)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "client_header_left_pending");
    assert_eq!(e.reason, Some(connect::CLIENT_HEADER_LEFT));
    assert_eq!(f.reverted.lock().unwrap().len(), 1);
    assert!(record_path(&ctx, "claude-code").exists());
}

/// Spec D3, §4: a record that cannot be written (here `revocations` is a
/// symbolic link, which the writer refuses) changes nothing.
#[tokio::test]
async fn an_unwritable_revocation_record_changes_nothing() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    let (ctx, dir, _) = ctx_with(&m, vec![f.clone()]);
    *f.active.lock().unwrap() = Some("backup-0".into());
    let target = dir.path().join("elsewhere");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&ctx.paths.data_dir).unwrap();
    std::os::unix::fs::symlink(&target, ctx.paths.data_dir.join("revocations")).unwrap();
    m.stop().await;
    let e = connect::revert(&ctx, HarnessId::Codex).await.unwrap_err();
    assert_eq!(e.kind, "revocation_store");
    assert!(
        f.reverted.lock().unwrap().is_empty(),
        "no harness file touched"
    );
    assert_eq!(
        std::fs::read_dir(&target).unwrap().count(),
        0,
        "nothing written through the link"
    );
}

/// Review Focus 4 (spec D5): a configuration error or a timeout is not
/// "offline": today's error, no record, no file touched.
#[tokio::test]
async fn revert_with_a_config_error_or_a_timeout_writes_no_record() {
    // (a) The config file that names the socket does not parse.
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("inumaki.toml"), "this is [ not toml").unwrap();
    let paths = inumaki_app_lib::paths::AppPaths::under(&data, &dir.path().join("home"));
    assert!(paths.config_error.is_some());
    let client = inumaki_client::Client::new(&paths.socket);
    let f = FakeOps::new(HarnessId::Codex);
    *f.active.lock().unwrap() = Some("backup-0".into());
    let (ctx, _) = inumaki_app_lib::ctx::Ctx::for_tests(paths, client);
    let ctx = ctx.with_harnesses(vec![f.clone() as Arc<dyn HarnessOps>]);
    let e = connect::revert(&ctx, HarnessId::Codex).await.unwrap_err();
    assert!(
        ["config_error", "service_unreachable"].contains(&e.kind),
        "{}",
        e.kind
    );
    assert!(!data.join("revocations").exists());
    assert!(f.reverted.lock().unwrap().is_empty());

    // (b) The service accepts the connection but does not answer in time.
    let m = MockDaemon::start().await;
    m.set(
        "GET",
        "/v1/gateway/tokens",
        tokens(&[(7, "app:codex")]).delayed(std::time::Duration::from_secs(3)),
    );
    let dir = tempfile::tempdir().unwrap();
    let f = FakeOps::new(HarnessId::Codex);
    *f.active.lock().unwrap() = Some("backup-0".into());
    let (ctx, _) = inumaki_app_lib::ctx::Ctx::for_tests(
        inumaki_app_lib::paths::AppPaths::under(&dir.path().join("data"), &dir.path().join("home")),
        m.client()
            .with_timeout(std::time::Duration::from_millis(200)),
    );
    let ctx = ctx.with_harnesses(vec![f.clone() as Arc<dyn HarnessOps>]);
    let e = connect::revert(&ctx, HarnessId::Codex).await.unwrap_err();
    assert_eq!(e.kind, "timeout");
    assert!(!ctx.paths.data_dir.join("revocations").exists());
    assert!(f.reverted.lock().unwrap().is_empty());
}

/// Review Focus 5 (spec D6): a lingering record is settled before the new
/// token exists, so a later sweep cannot revoke the new token.
#[tokio::test]
async fn a_connect_settles_a_pending_revocation_before_minting() {
    let m = MockDaemon::start().await;
    m.set("GET", "/v1/gateway/tokens", tokens(&[(7, "app:codex")]));
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    inumaki_client::revocations::record(&ctx.paths.data_dir, HarnessId::Codex).unwrap();
    connect::connect(&ctx, HarnessId::Codex).await.unwrap();
    let reqs = m.requests();
    let revoked = reqs
        .iter()
        .position(|r| r.method == "DELETE" && r.path == "/v1/gateway/tokens/7")
        .expect("the old token was revoked");
    let mint = reqs
        .iter()
        .position(|r| r.method == "POST" && r.route == "/v1/gateway/tokens")
        .expect("a token was minted");
    assert!(revoked < mint, "revoked before the new token was minted");
    assert!(!record_path(&ctx, "codex").exists());
    assert_eq!(f.applied.lock().unwrap().len(), 1);
}

/// The record's label is the label the app and the CLI mint (review O6).
#[test]
fn the_record_names_the_label_the_app_and_the_cli_mint() {
    let mut labels: Vec<String> = [
        HarnessId::ClaudeCode,
        HarnessId::Codex,
        HarnessId::Hermes,
        HarnessId::Openclaw,
    ]
    .into_iter()
    .map(|h| {
        let l = inumaki_client::revocations::label(h);
        assert_eq!(l, connect::token_label(h));
        l
    })
    .collect();
    labels.sort();
    let mut cli: Vec<String> = inumaki_adapters::HarnessId::ALL
        .into_iter()
        .map(|h| h.token_label())
        .collect();
    cli.sort();
    assert_eq!(labels, cli);
}

/// Only the user's Revert is the final one (it removes Codex's trust record
/// for the hook); the revert inside a Reconnect keeps it.
#[tokio::test]
async fn only_the_user_revert_is_final() {
    let m = MockDaemon::start().await;
    m.set("GET", "/v1/gateway/tokens", tokens(&[(7, "app:codex")]));
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    *f.active.lock().unwrap() = Some("000000000001-000000000".into());
    connect::reconnect(&ctx, HarnessId::Codex).await.unwrap();
    assert_eq!(
        f.reverted.lock().unwrap().len(),
        1,
        "the reconnect reverted first"
    );
    assert!(
        f.reverted_final.lock().unwrap().is_empty(),
        "a reconnect's revert is not final"
    );
    connect::revert(&ctx, HarnessId::Codex).await.unwrap();
    assert_eq!(f.reverted.lock().unwrap().len(), 2);
    assert_eq!(f.reverted_final.lock().unwrap().len(), 1);
}

/// M6-1 §4.2: a header left in the file is an error, as `inumaki connect revert` exits 2.
#[tokio::test]
async fn revert_with_the_client_header_left_is_an_error() {
    let m = MockDaemon::start().await;
    m.set(
        "GET",
        "/v1/gateway/tokens",
        tokens(&[(7, "app:claude-code")]),
    );
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.header_left.store(true, Ordering::SeqCst);
    *f.active.lock().unwrap() = Some("000000000001-000000000".into());
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let e = connect::revert(&ctx, HarnessId::ClaudeCode)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "client_header_left");
    let r = e.reason.unwrap();
    assert!(r.text.contains("X-Inumaki-Client"));
    let proxy: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("proxy")).unwrap();
    let value = proxy["client_header"]["value"].as_str().unwrap();
    assert!(
        !serde_json::to_string(&e).unwrap().contains(value),
        "no value in the error"
    );
    // Revoked and cleared before the error.
    assert_eq!(deleted(&m), ["7"]);
    assert_eq!(f.reverted.lock().unwrap().len(), 1);
    assert!(!ctx.state().backups.contains_key("claude-code"));
}

/// Review I2: a backup id in state.json without an active adapter backup is
/// stale (an outside revert): it never locks the harness out.
#[tokio::test]
async fn a_stale_backup_id_is_cleared_and_never_blocks() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let stale = || {
        ctx.update_state(|s| {
            s.backups
                .insert("codex".into(), vec!["000000000001-000000000".into()]);
        })
        .unwrap()
    };
    stale();
    let r = connect::revert(&ctx, HarnessId::Codex).await.unwrap();
    assert!(!r.reverted);
    assert!(f.reverted.lock().unwrap().is_empty());
    assert!(!ctx.state().backups.contains_key("codex"));
    stale();
    connect::connect(&ctx, HarnessId::Codex).await.unwrap();
    assert!(f.reverted.lock().unwrap().is_empty(), "a fresh connect");
    assert_eq!(f.applied.lock().unwrap().len(), 1);
    assert_ne!(ctx.state().backups["codex"], ["000000000001-000000000"]);
}

/// Review I1: two Connect clicks on one harness run one after the other.
/// The second sees the first's backup and reconnects: it reverts that
/// backup before applying (no chained backup over inumaki's entries), and
/// revokes the first token only after its own apply. (The mock mints a
/// distinct token each time and keeps the live ones, so exactly one live
/// token must remain: the second's.)
#[tokio::test]
async fn two_concurrent_connects_on_one_harness_are_serialized() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let (a, b) = tokio::join!(
        connect::connect(&ctx, HarnessId::Codex),
        connect::connect(&ctx, HarnessId::Codex)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(f.applied.lock().unwrap().len(), 2);
    let first = format!("{:012}-{:09}", 1_790_000_001, 0);
    assert_eq!(
        *f.reverted.lock().unwrap(),
        [first],
        "the second reverted the first"
    );
    // Every revocation precedes the last mint or follows the last apply;
    // none lands between the second mint and its apply.
    let reqs = m.requests();
    let last_post = reqs
        .iter()
        .rposition(|r| r.method == "POST" && r.route == "/v1/gateway/tokens")
        .unwrap();
    let posts = reqs
        .iter()
        .filter(|r| r.method == "POST" && r.route == "/v1/gateway/tokens")
        .count();
    assert_eq!(posts, 2);
    assert!(
        reqs[..last_post]
            .iter()
            .filter(|r| r.method == "POST" && r.route == "/v1/gateway/tokens")
            .count()
            == 1
    );
    assert_eq!(ctx.state().backups["codex"].len(), 1);
    // The first connect's token was revoked: one live token, the second mint.
    let live = m.live_tokens();
    assert_eq!(live.len(), 1, "exactly one live token: {live:?}");
    let applied = f.applied.lock().unwrap();
    assert_ne!(applied[0][0].2, applied[1][0].2, "each mint is distinct");
}

/// Rule 5 when state.json cannot be written: the tray still turns red.
#[tokio::test]
async fn a_disconnect_shows_even_when_the_state_cannot_be_written() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    *f.active.lock().unwrap() = Some("backup-0".into());
    *f.fail_apply.lock().unwrap() = Some(Fail::Io);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    // A directory in the state file's place: every save fails.
    std::fs::create_dir_all(ctx.paths.state_file.join("block")).unwrap();
    let e = connect::reconnect(&ctx, HarnessId::Codex)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "reconnect_failed_disconnected");
    assert!(ctx.state().reconnect_failed.contains("codex"));
    let tray = |ctx: &inumaki_app_lib::ctx::Ctx| {
        let snap = inumaki_app_lib::poll::Snapshot {
            reachable: true,
            ..Default::default()
        };
        let cards = inumaki_app_lib::harness::cards::cards(ctx, &snap);
        let input = inumaki_app_lib::harness::tray_input_from(&snap, &cards);
        inumaki_app_lib::tray::color(&input, &ctx.state())
    };
    assert_eq!(tray(&ctx), inumaki_app_lib::tray::TrayColor::Red);
}

/// Re-review N1: a failed apply after the revert can leave an active backup
/// (some files written before a later write failed). The harness is
/// half-written with revoked tokens: the card and the tray stay red.
#[tokio::test]
async fn a_half_written_reconnect_stays_red() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    *f.active.lock().unwrap() = Some("backup-0".into());
    *f.fail_apply.lock().unwrap() = Some(Fail::Io);
    f.partial_apply.store(true, Ordering::SeqCst);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let e = connect::reconnect(&ctx, HarnessId::Codex)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "reconnect_failed_disconnected");
    assert!(
        f.active.lock().unwrap().is_some(),
        "the partial backup exists"
    );
    let snap = inumaki_app_lib::poll::Snapshot {
        reachable: true,
        ..Default::default()
    };
    for _ in 0..2 {
        let cards = inumaki_app_lib::harness::cards::cards(&ctx, &snap);
        assert!(cards[0].disconnected, "the card says disconnected");
        let input = inumaki_app_lib::harness::tray_input_from(&snap, &cards);
        assert_eq!(
            inumaki_app_lib::tray::color(&input, &ctx.state()),
            inumaki_app_lib::tray::TrayColor::Red
        );
    }
    assert!(ctx.state().reconnect_failed.contains("codex"));
}

/// The preview's placeholder token is dead: a refusal there shows no snippet.
#[tokio::test]
async fn a_preview_refusal_shows_no_snippet() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    f.refuse_preview.store(true, Ordering::SeqCst);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let e = connect::preview(&ctx, HarnessId::Codex).await.unwrap_err();
    assert_eq!(e.kind, "cannot_edit_safely");
    assert!(e.snippet.is_none());
    assert!(e.reason.unwrap().text.contains("Press Connect"));
    assert!(minted(&m).is_empty());
}

/// New mailbox entries skip every name in use, also an `inumaki-mail`
/// that points at another mailbox.
#[tokio::test]
async fn a_new_mailbox_never_takes_a_name_in_use() {
    let m = MockDaemon::start().await;
    let mut status: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("status")).unwrap();
    status["datasets"] = json!([{ "id": "mail-1", "label": "0123456789abcdef", "name": "x", "profile": "offline", "rotation_days": 30, "grace_days": 7, "epoch_id": 1, "epoch_started_at": 1, "entries": 0, "kind": "mailbox" }]);
    m.set("GET", "/v1/status", Canned::json(200, status));
    let f = FakeOps::new(HarnessId::Codex);
    let mut old = FakeOps::stdio("inumaki-mail", "/bin/x", &[]);
    old.gateway_dataset = Some("mail-9".into());
    f.servers.lock().unwrap().push(old);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    connect::connect(&ctx, HarnessId::Codex).await.unwrap();
    let names: Vec<String> = f.applied.lock().unwrap()[0]
        .iter()
        .map(|(n, _, _)| n.clone())
        .collect();
    assert_eq!(names, ["inumaki-mail", "inumaki-mail-2"]);
}

/// An unreadable backup is not "nothing to revert" (as `inumaki connect revert`).
#[tokio::test]
async fn revert_with_an_unreadable_backup_fails_after_revoking() {
    let m = MockDaemon::start().await;
    m.set("GET", "/v1/gateway/tokens", tokens(&[(7, "app:codex")]));
    let f = FakeOps::new(HarnessId::Codex);
    f.unreadable.store(true, Ordering::SeqCst);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let e = connect::revert(&ctx, HarnessId::Codex).await.unwrap_err();
    assert_eq!(e.kind, "backup_unreadable");
    assert_eq!(deleted(&m), ["7"]);
}

#[tokio::test]
async fn other_client_reuses_an_existing_token() {
    let m = MockDaemon::start().await;
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    m.set("GET", "/v1/gateway/tokens", tokens(&[(4, "app:codex")]));
    let first = connect::other_client(&ctx).await.unwrap();
    assert_eq!(first.token.as_deref(), Some(created().1.as_str()));
    // The status fixture's served dataset is named "Qwxzvk Kunde GmbH": a
    // display name is model-visible as an entry name, so it is never one.
    assert!(!first.gateway.is_empty());
    assert!(first.gateway.iter().all(|g| !g.name.contains("Qwxzvk")));
    assert_eq!(first.gateway[0].name, "inumaki-mcp");
    let proxy: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("proxy")).unwrap();
    let value = proxy["client_header"]["value"].as_str().unwrap();
    assert_eq!(
        first.client_header.as_deref(),
        Some(format!("X-Inumaki-Client: {value}").as_str())
    );
    let dbg = format!("{first:?}");
    assert!(!dbg.contains(value) && !dbg.contains(&created().1));
    assert_eq!(minted(&m), [json!("app:other")]);
    m.set("GET", "/v1/gateway/tokens", tokens(&[(5, "app:other")]));
    let again = connect::other_client(&ctx).await.unwrap();
    assert!(again.token.is_none(), "a token is shown once");
    assert_eq!(minted(&m).len(), 1, "no token per click");
    connect::revoke_other_client(&ctx).await.unwrap();
    assert_eq!(deleted(&m), ["5"]);
}

/// Nothing to route through the gateway: no token is created that no file holds.
#[tokio::test]
async fn connect_without_gateway_entries_mints_no_token() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Hermes);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    connect::connect(&ctx, HarnessId::Hermes).await.unwrap();
    assert!(minted(&m).is_empty());
    assert_eq!(f.applied.lock().unwrap().len(), 1);
}

/// A proxy that is not Running owns no address the harness may be pointed
/// at: whatever else holds 127.0.0.1:8787 would receive the raw conversation
/// and the harness's credentials. The route and the client header are read
/// from the status fetched at apply time and skipped otherwise.
#[tokio::test]
async fn a_proxy_that_is_not_running_gets_no_chat_route() {
    for state in ["bind_failed", "disabled"] {
        let m = MockDaemon::start().await;
        let mut proxy: serde_json::Value =
            serde_json::from_str(inumaki_client::contract::fixture("proxy")).unwrap();
        proxy["state"] = json!(state);
        m.set("GET", "/v1/proxy", Canned::json(200, proxy));
        let f = FakeOps::new(HarnessId::ClaudeCode);
        let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
        let out = connect::connect(&ctx, HarnessId::ClaudeCode).await.unwrap();
        assert_eq!(
            *f.chat_routes.lock().unwrap(),
            [false],
            "{state}: no base URL"
        );
        assert_eq!(
            *f.headers.lock().unwrap(),
            [None],
            "{state}: no client header"
        );
        let w = out.warning.expect("the skipped route is surfaced");
        assert!(w.starts_with("the proxy is ") && w.ends_with("the chat route is skipped"));
        assert!(
            !w.contains("8787") && !w.contains("127.0.0.1"),
            "no address in the text"
        );
    }
}

/// The status is read per apply, not remembered: a proxy that came up (or
/// died) since the last call changes the next apply.
#[tokio::test]
async fn a_running_proxy_gets_the_chat_route_and_no_warning() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::ClaudeCode);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let out = connect::connect(&ctx, HarnessId::ClaudeCode).await.unwrap();
    assert_eq!(*f.chat_routes.lock().unwrap(), [true]);
    assert!(f.headers.lock().unwrap()[0].is_some());
    assert!(out.warning.is_none());
}

/// The "Other client" card follows the same rule as Connect: a proxy that is
/// not Running owns no address to paste into another client, so the card
/// shows no base URL and no client header, only the fixed warning. The state
/// is read on each open.
#[tokio::test]
async fn other_client_shows_no_proxy_details_unless_it_runs() {
    for state in ["bind_failed", "disabled"] {
        let m = MockDaemon::start().await;
        let mut proxy: serde_json::Value =
            serde_json::from_str(inumaki_client::contract::fixture("proxy")).unwrap();
        proxy["state"] = json!(state);
        m.set("GET", "/v1/proxy", Canned::json(200, proxy));
        let (ctx, _dir, _) = ctx_with(&m, vec![]);
        let o = connect::other_client(&ctx).await.unwrap();
        assert!(o.proxy.is_empty(), "{state}: no base URL");
        assert!(o.client_header.is_none(), "{state}: no client header");
        assert!(
            !o.gateway.is_empty(),
            "{state}: the gateway part is unchanged"
        );
        let w = o.proxy_warning.expect("the warning is returned");
        assert!(w.starts_with("the proxy is ") && w.ends_with("the chat route is skipped"));
        assert!(!w.contains("8787") && !w.contains("127.0.0.1"));
    }
    let m = MockDaemon::start().await;
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let o = connect::other_client(&ctx).await.unwrap();
    assert!(!o.proxy.is_empty() && o.client_header.is_some());
    assert!(o.proxy_warning.is_none());
}

/// Integrator ruling 2026-10-10: the adapter's fixed warnings about the
/// harness's own settings (Codex `approval_policy = "never"`) reach the
/// outcome of Connect and Reconnect as closed codes with fixed text, next
/// to (not instead of) the skipped-chat-route warning; none when the
/// adapter reports none.
#[tokio::test]
async fn harness_warnings_reach_the_connect_and_reconnect_outcome() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    routed(&f);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let out = connect::connect(&ctx, HarnessId::Codex).await.unwrap();
    assert!(out.harness_warnings.is_empty());
    let v = serde_json::to_value(&out).unwrap();
    assert_eq!(v["harness_warnings"], json!([]));

    let w = inumaki_adapters::ConnectWarning::CodexApprovalNever;
    f.warnings
        .lock()
        .unwrap()
        .push(inumaki_app_lib::harness::ops::Reason {
            code: w.code(),
            text: w.sentence(),
        });
    // Connected already: this is a Reconnect.
    let out = connect::connect(&ctx, HarnessId::Codex).await.unwrap();
    assert_eq!(out.harness_warnings.len(), 1);
    assert!(out.warning.is_none(), "the chat-route slot is untouched");
    let v = serde_json::to_value(&out).unwrap();
    assert_eq!(
        v["harness_warnings"],
        json!([{ "code": "codex_approval_never", "text": w.sentence() }])
    );
    let out = connect::reconnect(&ctx, HarnessId::Codex).await.unwrap();
    assert_eq!(out.harness_warnings[0].code, "codex_approval_never");
    // No token or dataset in the text.
    let (_, token) = created();
    let text = v.to_string();
    assert!(!text.contains(&token) && !text.contains("qwxzvk"), "{text}");
}

/// Follow-up ruling (lane L5, 2026-10-10): Reconnect reverts before it
/// re-applies, so the user's own `default_tools_approval_mode` on a gateway
/// entry is read with the servers before the revert and carried in the
/// request; a new mailbox entry carries none (the app never invents one).
#[tokio::test]
async fn reconnect_carries_the_users_approval_mode_through_the_revert() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    let mut e = FakeOps::stdio("crm", "/usr/local/bin/crm", &[]);
    e.gateway_dataset = Some("qwxzvk-kunde".into());
    e.approval_mode = Some("approve".into());
    f.servers.lock().unwrap().push(e);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    connect::connect(&ctx, HarnessId::Codex).await.unwrap();
    connect::reconnect(&ctx, HarnessId::Codex).await.unwrap();
    assert_eq!(
        f.reverted.lock().unwrap().len(),
        1,
        "the reconnect reverted first"
    );
    for apply in f.approvals.lock().unwrap().iter() {
        for (name, mode) in apply {
            if name == "crm" {
                assert_eq!(
                    mode.as_ref().and_then(|v| v.as_str()),
                    Some("approve"),
                    "{name}"
                );
            } else {
                assert_eq!(mode, &None, "{name}: never invented");
            }
        }
    }
    assert_eq!(f.approvals.lock().unwrap().len(), 2);
}

/// D6: the user's Revert starts the harness's chat choice over, in every
/// outcome (no backup, success, and the `client_header_left` error), for
/// every harness, and leaves the other harnesses' choices alone. It writes
/// the prefs directly: the setter would reconnect.
/// On the `backup_unreadable` and failed-revert returns the prefs stay as
/// they were, by design: that Revert did not complete.
#[tokio::test]
async fn a_user_revert_clears_the_chat_choices() {
    let m = MockDaemon::start().await;
    m.set("GET", "/v1/gateway/tokens", tokens(&[]));
    let all = [
        HarnessId::ClaudeCode,
        HarnessId::Codex,
        HarnessId::Hermes,
        HarnessId::Openclaw,
    ];
    let fakes: Vec<_> = all.iter().map(|h| FakeOps::new(*h)).collect();
    let (ctx, _dir, _) = ctx_with(&m, fakes.clone());
    let choice = |h: HarnessId| ctx.state().prefs.chat_opt_in.get(harness_key(h)).copied();
    let set_all = |on: bool| {
        ctx.update_state(|s| {
            for h in all {
                s.prefs.chat_opt_in.insert(harness_key(h).into(), on);
            }
        })
        .unwrap();
    };

    for (i, (h, f)) in all.iter().zip(&fakes).enumerate() {
        // No backup (`reverted: false`).
        set_all(true);
        let r = connect::revert(&ctx, *h).await.unwrap();
        assert!(!r.reverted);
        assert_eq!(choice(*h), None, "{h:?}");
        for o in all.iter().filter(|o| *o != h) {
            assert_eq!(choice(*o), Some(true), "{o:?} is not {h:?}");
        }

        // Success.
        set_all(false);
        *f.active.lock().unwrap() = Some(format!("00000000000{}-000000000", i + 1));
        connect::revert(&ctx, *h).await.unwrap();
        assert_eq!(choice(*h), None, "{h:?}");
    }

    // The `client_header_left` error is returned after the prefs are cleared.
    let claude = &fakes[0];
    set_all(true);
    claude.header_left.store(true, Ordering::SeqCst);
    *claude.active.lock().unwrap() = Some("000000000009-000000000".into());
    let e = connect::revert(&ctx, HarnessId::ClaudeCode)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "client_header_left");
    assert_eq!(choice(HarnessId::ClaudeCode), None);

    // None of it reconnected anything.
    for f in &fakes {
        assert!(f.applied.lock().unwrap().is_empty());
    }
}
