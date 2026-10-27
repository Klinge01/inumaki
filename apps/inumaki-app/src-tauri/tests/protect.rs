//! The Protect switch (spec §4.5; Review Focus 4): dataset ids, secret
//! split, never merging two accounts of one server, Unprotect keeping a
//! dataset another harness uses, no server name in state.json, the
//! per-harness lock, and failing closed without the state key.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{FakeOps, ctx_with};
use inumaki_app_lib::ctx::Ctx;
use inumaki_app_lib::harness::ops::{HarnessOps, Scope};
use inumaki_app_lib::harness::{adapt, naming, protect};
use inumaki_app_lib::paths::AppPaths;
use inumaki_client::HarnessId;
use inumaki_client::mock::{Canned, MockDaemon};
use serde_json::json;

/// The id the MCP servers view gives a user-scope entry.
fn uid(ctx: &Ctx, h: HarnessId, name: &str) -> String {
    naming::server_key(ctx, h, name, &Scope::User).unwrap()
}

#[test]
fn dataset_ids_follow_the_rule() {
    let none = BTreeSet::new();
    assert_eq!(naming::dataset_id("@scope/x", &none), "mcp-scope-x");
    assert_eq!(
        naming::dataset_id("Kunde Müller GmbH", &none),
        "mcp-kunde-m-ller-gmbh"
    );
    // M6-1's rule; the app only delegates. The properties below are what the app relies on.
    let taken: BTreeSet<String> = ["mcp-crm".to_string(), "mcp-crm-2".to_string()].into();
    assert_eq!(naming::dataset_id("CRM", &taken), "mcp-crm-3");
    let long = "a".repeat(100);
    let id = naming::dataset_id(&long, &BTreeSet::from([naming::dataset_id(&long, &none)]));
    assert!(id.len() <= 64 && id.ends_with("-2"), "{id}");
    for name in [
        "@scope/x",
        "Kunde Müller GmbH",
        "check-me",
        "CHECK",
        &long,
        "a/../b",
        "x y\tz",
        "---",
    ] {
        let id = naming::dataset_id(name, &none);
        assert!(
            id.len() <= 64
                && !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "{id}"
        );
        // M6-1 trims a trailing `-`: a name with no usable character ("---")
        // gives the bare `mcp`, still in the alphabet and never `check-`.
        assert!(
            (id == "mcp" || id.starts_with("mcp-")) && !id.starts_with("check-"),
            "{id}"
        );
        let u = naming::upstream_name(name);
        assert!(
            u.len() <= 64
                && u.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'_'),
            "{u}"
        );
    }
    assert!(
        naming::credential_like("GITHUB_TOKEN")
            && naming::credential_like("Authorization")
            && naming::credential_like("x-api-key")
    );
    assert!(!naming::credential_like("LOG_LEVEL") && !naming::credential_like("PATH"));
}

/// `GET /v1/datasets` answers `list`; `POST /v1/datasets` answers `post`;
/// `GET /v1/status` lists both (connect maps labels to ids from status).
fn daemon_datasets(m: &MockDaemon, list: &[(&str, &str)], post: (&str, &str)) {
    let ds = |id: &str, label: &str| json!({ "id": id, "label": label, "name": "x", "profile": "offline", "rotation_days": 30, "grace_days": 7, "epoch_id": 1, "epoch_started_at": 1, "entries": 0, "kind": "generic" });
    m.set(
        "GET",
        "/v1/datasets",
        Canned::json(
            200,
            json!(list.iter().map(|(i, l)| ds(i, l)).collect::<Vec<_>>()),
        ),
    );
    m.set(
        "POST",
        "/v1/datasets",
        Canned::json(201, ds(post.0, post.1)),
    );
    let mut all: Vec<serde_json::Value> = list.iter().map(|(i, l)| ds(i, l)).collect();
    if !list.contains(&post) {
        all.push(ds(post.0, post.1));
    }
    let mut status: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("status")).unwrap();
    status["datasets"] = json!(all);
    status["profiles"] =
        json!([{ "name": "offline", "available": true }, { "name": "strict", "available": true }]);
    m.set("GET", "/v1/status", Canned::json(200, status));
}

fn posts(m: &MockDaemon, route: &'static str) -> Vec<serde_json::Value> {
    m.requests()
        .into_iter()
        .filter(|r| r.method == "POST" && r.route == route)
        .filter_map(|r| r.body)
        .collect()
}

#[tokio::test]
async fn protect_moves_secrets_to_the_vault_and_keeps_names_out_of_state() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-qwxzvk-crm", "aaaaaaaaaaaaaaaa"));
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.servers.lock().unwrap().push(FakeOps::stdio(
        "qwxzvk-crm",
        "/bin/sh",
        &[("GITHUB_TOKEN", "hunter2-qwxzvk"), ("LOG_LEVEL", "debug")],
    ));
    let (ctx, _dir, notes) = ctx_with(&m, vec![f.clone()]);
    let out = protect::protect(
        &ctx,
        HarnessId::ClaudeCode,
        &uid(&ctx, HarnessId::ClaudeCode, "qwxzvk-crm"),
    )
    .await
    .unwrap();
    assert!(!out.reused);
    assert!(out.warning.is_none());
    let dbg = format!("{out:?}");
    assert!(!dbg.contains("qwxzvk"), "{dbg}");
    let ds = posts(&m, "/v1/datasets");
    assert_eq!(ds[0]["id"], "mcp-qwxzvk-crm");
    assert_eq!(
        ds[0]["name"], "qwxzvk-crm",
        "display name = server name (local only)"
    );
    assert_eq!(
        ds[0]["profile"],
        protect::WRAPPED_SERVER_PROFILE,
        "spec §4.5: the wrapped-server default"
    );
    let up = posts(&m, "/v1/datasets/{id}/upstreams");
    assert_eq!(up[0]["command"], "/bin/sh");
    assert_eq!(up[0]["secret_env"]["GITHUB_TOKEN"], "hunter2-qwxzvk");
    assert_eq!(up[0]["env"]["LOG_LEVEL"], "debug");
    assert!(
        up[0]["env"]["PATH"].is_string(),
        "the login-shell PATH is recorded (spec §4.5 step 1)"
    );
    assert!(up[0]["env"].get("GITHUB_TOKEN").is_none());
    let applied = f.applied.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        applied[0].0, "qwxzvk-crm",
        "tool names seen by the agent do not change"
    );
    assert!(applied[0].1.ends_with("/mcp/mcp-qwxzvk-crm"));
    let state = std::fs::read_to_string(&ctx.paths.state_file).unwrap();
    assert!(
        !state.contains("qwxzvk") && !state.contains("hunter2"),
        "{state}"
    );
    let rows = protect::servers(&ctx).await.unwrap();
    assert!(rows[0].protected && !rows[0].pending);
    assert_eq!(rows[0].id, uid(&ctx, HarnessId::ClaudeCode, "qwxzvk-crm"));
    assert!(!format!("{:?}", rows[0]).contains("qwxzvk"));
    assert!(notes.sent().iter().all(|n| !n.contains("qwxzvk")));
}

#[tokio::test]
async fn same_definition_different_secrets_never_merge() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
    let a = FakeOps::new(HarnessId::ClaudeCode);
    let b = FakeOps::new(HarnessId::Codex);
    let c = FakeOps::new(HarnessId::Hermes);
    a.servers.lock().unwrap().push(FakeOps::stdio(
        "crm",
        "/bin/sh",
        &[("CRM_TOKEN", "account-one")],
    ));
    b.servers.lock().unwrap().push(FakeOps::stdio(
        "crm",
        "/bin/sh",
        &[("CRM_TOKEN", "account-one")],
    ));
    c.servers.lock().unwrap().push(FakeOps::stdio(
        "crm",
        "/bin/sh",
        &[("CRM_TOKEN", "account-two")],
    ));
    let (ctx, _dir, _) = ctx_with(&m, vec![a.clone(), b.clone(), c.clone()]);
    assert!(
        !protect::protect(
            &ctx,
            HarnessId::ClaudeCode,
            &uid(&ctx, HarnessId::ClaudeCode, "crm")
        )
        .await
        .unwrap()
        .reused
    );
    daemon_datasets(
        &m,
        &[("mcp-crm", "aaaaaaaaaaaaaaaa")],
        ("mcp-crm", "aaaaaaaaaaaaaaaa"),
    );
    assert!(
        protect::protect(&ctx, HarnessId::Codex, &uid(&ctx, HarnessId::Codex, "crm"))
            .await
            .unwrap()
            .reused,
        "identical definition joins the dataset"
    );
    assert_eq!(posts(&m, "/v1/datasets").len(), 1);
    daemon_datasets(
        &m,
        &[("mcp-crm", "aaaaaaaaaaaaaaaa")],
        ("mcp-crm-2", "bbbbbbbbbbbbbbbb"),
    );
    let out = protect::protect(
        &ctx,
        HarnessId::Hermes,
        &uid(&ctx, HarnessId::Hermes, "crm"),
    )
    .await
    .unwrap();
    assert!(
        !out.reused,
        "another account of the same server never merges"
    );
    assert_eq!(posts(&m, "/v1/datasets").last().unwrap()["id"], "mcp-crm-2");
    assert!(
        c.applied.lock().unwrap().last().unwrap()[0]
            .1
            .ends_with("/mcp/mcp-crm-2")
    );
    let s = |e: &common::FakeOps| e.servers.lock().unwrap()[0].clone();
    let dd = &ctx.paths.data_dir;
    assert_ne!(
        naming::definition_id(dd, &s(&a)).unwrap(),
        naming::definition_id(dd, &s(&c)).unwrap()
    );
    assert_eq!(
        naming::definition_id(dd, &s(&a)).unwrap(),
        naming::definition_id(dd, &s(&b)).unwrap()
    );
}

#[tokio::test]
async fn unprotect_keeps_a_dataset_another_harness_uses() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
    let a = FakeOps::new(HarnessId::ClaudeCode);
    let b = FakeOps::new(HarnessId::Codex);
    for f in [&a, &b] {
        f.servers
            .lock()
            .unwrap()
            .push(FakeOps::stdio("crm", "/bin/sh", &[]));
    }
    let (ctx, _dir, _) = ctx_with(&m, vec![a.clone(), b.clone()]);
    protect::protect(
        &ctx,
        HarnessId::ClaudeCode,
        &uid(&ctx, HarnessId::ClaudeCode, "crm"),
    )
    .await
    .unwrap();
    daemon_datasets(
        &m,
        &[("mcp-crm", "aaaaaaaaaaaaaaaa")],
        ("mcp-crm", "aaaaaaaaaaaaaaaa"),
    );
    protect::protect(&ctx, HarnessId::Codex, &uid(&ctx, HarnessId::Codex, "crm"))
        .await
        .unwrap();
    // The files now point both entries at the gateway: Unprotect must drop
    // the entry from the new apply, not carry it over as "already routed".
    assert!(a.servers.lock().unwrap()[0].gateway_dataset.is_some());
    let out = protect::unprotect(
        &ctx,
        HarnessId::ClaudeCode,
        &uid(&ctx, HarnessId::ClaudeCode, "crm"),
    )
    .await
    .unwrap();
    assert_eq!(out.unreferenced_dataset, None);
    assert_eq!(
        a.reverted.lock().unwrap().len(),
        1,
        "reverted to the original first"
    );
    assert!(
        a.applied
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .iter()
            .all(|(n, _, _)| n != "crm"),
        "the original entry is back"
    );
    assert_eq!(
        protect::remove_dataset(&ctx, "mcp-crm")
            .await
            .unwrap_err()
            .kind,
        "still_in_use"
    );
    let out = protect::unprotect(&ctx, HarnessId::Codex, &uid(&ctx, HarnessId::Codex, "crm"))
        .await
        .unwrap();
    assert_eq!(out.unreferenced_dataset.as_deref(), Some("mcp-crm"));
    protect::remove_dataset(&ctx, "mcp-crm").await.unwrap();
    assert!(m.requests().iter().any(|r| r.method == "DELETE"
        && r.route == "/v1/datasets/{id}"
        && r.path.ends_with("/mcp-crm")));
}

/// Task 5 hand-off: Protect holds the harness lock and calls only the
/// `*_held` variants, so it never deadlocks on its own lock, and two
/// Protects on one harness run one after the other (the second reverts the
/// first's backup and writes both servers).
#[tokio::test]
async fn two_concurrent_protects_on_one_harness_serialize() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-alpha", "aaaaaaaaaaaaaaaa"));
    let f = FakeOps::new(HarnessId::ClaudeCode);
    for n in ["alpha", "beta"] {
        f.servers
            .lock()
            .unwrap()
            .push(FakeOps::stdio(n, "/bin/sh", &[]));
    }
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let (ia, ib) = (
        uid(&ctx, HarnessId::ClaudeCode, "alpha"),
        uid(&ctx, HarnessId::ClaudeCode, "beta"),
    );
    let (x, y) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            protect::protect(&ctx, HarnessId::ClaudeCode, &ia),
            protect::protect(&ctx, HarnessId::ClaudeCode, &ib)
        )
    })
    .await
    .expect("Protect must not hang on the harness lock");
    x.unwrap();
    y.unwrap();
    assert_eq!(f.applied.lock().unwrap().len(), 2);
    let first = format!("{:012}-{:09}", 1_790_000_001, 0);
    assert_eq!(
        *f.reverted.lock().unwrap(),
        [first],
        "the second reverted the first"
    );
    let last: BTreeSet<String> = f.applied.lock().unwrap()[1]
        .iter()
        .map(|(n, _, _)| n.clone())
        .collect();
    assert_eq!(last, BTreeSet::from(["alpha".into(), "beta".into()]));
    assert_eq!(ctx.state().backups["claude-code"].len(), 1);
    // A Connect after a Protect is not blocked either.
    tokio::time::timeout(
        Duration::from_secs(30),
        inumaki_app_lib::harness::connect::connect(&ctx, HarnessId::ClaudeCode),
    )
    .await
    .expect("the lock is released")
    .unwrap();
}

/// No state key: nothing can be recorded, so nothing is created or written.
#[tokio::test]
async fn protect_without_a_state_key_creates_nothing() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.servers.lock().unwrap().push(FakeOps::stdio(
        "crm",
        "/bin/sh",
        &[("CRM_TOKEN", "account-one")],
    ));
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(&dir.path().join("data"), &dir.path().join("home"));
    // A directory where the key file belongs: it can be neither read nor created.
    std::fs::create_dir_all(&paths.state_key).unwrap();
    let (ctx, _) = Ctx::for_tests(paths, m.client());
    let ctx = Arc::new(ctx.with_harnesses(vec![f.clone() as Arc<dyn HarnessOps>]));
    // Any id: without the key no entry's id can even be computed.
    let e = protect::protect(&ctx, HarnessId::ClaudeCode, &"a".repeat(64))
        .await
        .unwrap_err();
    assert_eq!(e.kind, "state_unwritable");
    assert!(posts(&m, "/v1/datasets").is_empty());
    assert!(posts(&m, "/v1/datasets/{id}/upstreams").is_empty());
    assert!(f.applied.lock().unwrap().is_empty());
    assert!(ctx.state().protected.is_empty());
}

/// Spec §4.5 amendment: the split is by name, so a credential in an
/// argument or the URL stays in the non-secret fields; Protect warns.
#[tokio::test]
async fn a_credential_in_an_argument_or_url_is_flagged() {
    let flagged: &[&[&str]] = &[
        &["--api-key", "sk-qwxzvk"],
        &["--token=sk-qwxzvk"],
        &["run", "-e", "GITHUB_TOKEN=sk-qwxzvk", "image"],
        &["mcp-remote", "--header", "Authorization: Bearer sk-qwxzvk"],
        &["mcp-remote", "https://u:sk-qwxzvk@example.test/mcp"],
        &["API_KEY=sk-qwxzvk"],
    ];
    let clean: &[&[&str]] = &[
        &["--stdio"],
        &["run", "-e", "GITHUB_TOKEN", "image"],
        &[
            "--port",
            "8080",
            "LOG_LEVEL=debug",
            "http://localhost:8080/mcp",
        ],
    ];
    for (args, want) in flagged
        .iter()
        .map(|a| (a, true))
        .chain(clean.iter().map(|a| (a, false)))
    {
        let m = MockDaemon::start().await;
        daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
        let f = FakeOps::new(HarnessId::ClaudeCode);
        let mut e = FakeOps::stdio("crm", "/bin/sh", &[]);
        e.args = args.iter().map(|a| a.to_string()).collect();
        f.servers.lock().unwrap().push(e);
        let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
        let id = uid(&ctx, HarnessId::ClaudeCode, "crm");
        let out = protect::protect(&ctx, HarnessId::ClaudeCode, &id)
            .await
            .unwrap();
        assert_eq!(
            out.warning.map(|w| w.code),
            want.then_some("secret_outside_credential_names"),
            "{args:?}"
        );
        assert!(!format!("{out:?}").contains("qwxzvk"));
        assert!(!serde_json::to_string(&out).unwrap().contains("qwxzvk"));
    }
}

/// Review C1: Claude Code lists one name once per scope, often with
/// another account. Each entry is its own server: Protect and Unprotect
/// touch only the entry they were given, and the datasets differ.
#[tokio::test]
async fn one_name_in_two_scopes_is_two_accounts() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
    let f = FakeOps::new(HarnessId::ClaudeCode);
    let user = FakeOps::stdio("crm", "/bin/sh", &[("CRM_TOKEN", "account-one")]);
    let mut local = FakeOps::stdio("crm", "/bin/sh", &[("CRM_TOKEN", "account-two")]);
    local.scope = Scope::Local("/home/fake/qwxzvk-project".into());
    f.servers.lock().unwrap().extend([user, local]);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let rows = protect::servers(&ctx).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].id, rows[1].id, "one id per (name, scope)");
    let (user_id, local_id) = (rows[0].id.clone(), rows[1].id.clone());
    protect::protect(&ctx, HarnessId::ClaudeCode, &user_id)
        .await
        .unwrap();
    {
        let s = f.servers.lock().unwrap();
        assert_eq!(s[0].gateway_dataset.as_deref(), Some("mcp-crm"));
        assert!(
            s[1].gateway_dataset.is_none(),
            "the other account's entry stays as is"
        );
    }
    assert_eq!(f.applied.lock().unwrap().last().unwrap().len(), 1);
    daemon_datasets(
        &m,
        &[("mcp-crm", "aaaaaaaaaaaaaaaa")],
        ("mcp-crm-2", "bbbbbbbbbbbbbbbb"),
    );
    let out = protect::protect(&ctx, HarnessId::ClaudeCode, &local_id)
        .await
        .unwrap();
    assert!(
        !out.reused,
        "the second account never joins the first's dataset"
    );
    assert_eq!(out.dataset, "mcp-crm-2");
    let urls: BTreeSet<String> = f
        .applied
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .iter()
        .map(|(_, u, _)| u.rsplit('/').next().unwrap().to_string())
        .collect();
    assert_eq!(urls, BTreeSet::from(["mcp-crm".into(), "mcp-crm-2".into()]));
    // Unprotect the user-scope entry: only it gets its original back.
    let out = protect::unprotect(&ctx, HarnessId::ClaudeCode, &user_id)
        .await
        .unwrap();
    {
        let s = f.servers.lock().unwrap();
        assert!(s[0].gateway_dataset.is_none());
        assert_eq!(s[1].gateway_dataset.as_deref(), Some("mcp-crm-2"));
    }
    let last = f.applied.lock().unwrap().last().unwrap().clone();
    assert_eq!(last.len(), 1);
    assert!(last[0].1.ends_with("/mcp/mcp-crm-2"));
    assert_eq!(out.unreferenced_dataset.as_deref(), Some("mcp-crm"));
    let state = std::fs::read_to_string(&ctx.paths.state_file).unwrap();
    assert!(
        !state.contains("qwxzvk") && !state.contains("crm"),
        "{state}"
    );
}

/// A Protect whose connect wrote nothing leaves the state as it was,
/// "leave unprotected" included.
#[tokio::test]
async fn a_protect_that_wrote_nothing_restores_the_state() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.servers
        .lock()
        .unwrap()
        .push(FakeOps::stdio("crm", "/bin/sh", &[]));
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let id = uid(&ctx, HarnessId::ClaudeCode, "crm");
    protect::leave_unprotected(&ctx, HarnessId::ClaudeCode, &id, true)
        .await
        .unwrap();
    f.fail_preview.store(true, Ordering::SeqCst);
    let e = protect::protect(&ctx, HarnessId::ClaudeCode, &id)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "changed_meanwhile");
    let st = ctx.state();
    assert!(st.protected.is_empty(), "no pending protection shown");
    assert!(st.leave_unprotected.contains(&id));
    assert!(f.applied.lock().unwrap().is_empty());
}

/// A failed upstream create deletes the dataset it just made: no orphan,
/// nothing recorded.
#[tokio::test]
async fn a_failed_upstream_create_leaves_no_dataset() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
    m.set(
        "POST",
        "/v1/datasets/{id}/upstreams",
        Canned::error(400, "bad_request", "upstream rejected", &[]),
    );
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.servers.lock().unwrap().push(FakeOps::stdio(
        "crm",
        "/bin/sh",
        &[("CRM_TOKEN", "account-one")],
    ));
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let e = protect::protect(
        &ctx,
        HarnessId::ClaudeCode,
        &uid(&ctx, HarnessId::ClaudeCode, "crm"),
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind, "bad_request");
    assert!(m.requests().iter().any(|r| r.method == "DELETE"
        && r.route == "/v1/datasets/{id}"
        && r.path.ends_with("/mcp-crm")));
    assert!(
        adapt::defined_datasets(&ctx.paths.data_dir)
            .unwrap()
            .is_empty()
    );
    assert!(ctx.state().protected.is_empty());
    assert!(f.applied.lock().unwrap().is_empty());
}

/// Data loss: only a dataset Protect made can be removed here, never a
/// mailbox's, a folder's, or one the user made by hand.
#[tokio::test]
async fn remove_dataset_refuses_what_protect_did_not_make() {
    let m = MockDaemon::start().await;
    let ds = |id: &str, kind: &str| json!({ "id": id, "label": "0123456789abcdef", "name": "x", "profile": "offline", "rotation_days": 30, "grace_days": 7, "epoch_id": 1, "epoch_started_at": 1, "entries": 0, "kind": kind });
    let mut status: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("status")).unwrap();
    status["datasets"] = json!([
        ds("mail-1", "mailbox"),
        ds("folder-1", "folder"),
        ds("mcp-notes", "generic")
    ]);
    m.set("GET", "/v1/status", Canned::json(200, status));
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    for id in ["mail-1", "folder-1", "mcp-notes"] {
        let e = protect::remove_dataset(&ctx, id).await.unwrap_err();
        assert_eq!(e.kind, "not_a_wrapped_server", "{id}");
    }
    assert!(!m.requests().iter().any(|r| r.method == "DELETE"));
}

/// An Unprotect whose Reconnect wrote nothing keeps the protection recorded.
#[tokio::test]
async fn an_unprotect_that_wrote_nothing_keeps_the_mapping() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.servers
        .lock()
        .unwrap()
        .push(FakeOps::stdio("crm", "/bin/sh", &[]));
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let id = uid(&ctx, HarnessId::ClaudeCode, "crm");
    protect::protect(&ctx, HarnessId::ClaudeCode, &id)
        .await
        .unwrap();
    f.fail_preview.store(true, Ordering::SeqCst);
    let e = protect::unprotect(&ctx, HarnessId::ClaudeCode, &id)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "changed_meanwhile");
    assert!(ctx.state().protected["claude-code"].contains_key(&id));
    assert!(f.reverted.lock().unwrap().is_empty(), "nothing reverted");
    assert_eq!(f.applied.lock().unwrap().len(), 1);
}

/// An apply that did not route the entry (its dataset left out) is no
/// protection: `not_routed`, and the state is put back.
#[tokio::test]
async fn an_apply_that_does_not_route_the_entry_is_not_routed() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.servers
        .lock()
        .unwrap()
        .push(FakeOps::stdio("crm", "/bin/sh", &[]));
    *f.no_route.lock().unwrap() = Some("crm".into());
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let id = uid(&ctx, HarnessId::ClaudeCode, "crm");
    let e = protect::protect(&ctx, HarnessId::ClaudeCode, &id)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "not_routed");
    assert!(ctx.state().protected.is_empty());
    assert_eq!(f.applied.lock().unwrap().len(), 1);
    let rows = protect::servers(&ctx).await.unwrap();
    assert!(!rows[0].protected && !rows[0].pending);
    assert_eq!(rows[0].scope, "user");
}

/// Fail closed: the file cannot be read back between apply and check. The
/// command returns a fixed failure kind, never an outcome, and the server is
/// not reported as protected while the file cannot be read.
#[tokio::test]
async fn a_read_error_after_apply_is_a_failure_not_a_protection() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.servers
        .lock()
        .unwrap()
        .push(FakeOps::stdio("crm", "/bin/sh", &[]));
    f.read_fails_after_apply.store(true, Ordering::SeqCst);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let id = uid(&ctx, HarnessId::ClaudeCode, "crm");
    let r = protect::protect(&ctx, HarnessId::ClaudeCode, &id).await;
    assert_eq!(f.applied.lock().unwrap().len(), 1, "the apply happened");
    let e = r.expect_err("a failed re-read is never a protection");
    assert_eq!(e.kind, "file_unwritable");
    assert!(e.snippet.is_none() && e.reason.is_none());
    // Nothing reads as protected: no row while the file cannot be read.
    let rows = protect::servers(&ctx).await.unwrap();
    assert!(rows.iter().all(|r| !r.protected));
    // Once the file reads again, the row follows the file, not the state.
    f.read_fails_after_apply.store(false, Ordering::SeqCst);
    f.servers.lock().unwrap()[0].gateway_dataset = None;
    let rows = protect::servers(&ctx).await.unwrap();
    assert!(!rows[0].protected);
}

/// Review I1: an entry the file points at the gateway with no `state.json`
/// record (protected by `inumaki connect --protect`, or a record lost with a
/// corrupt state or a regenerated state key) is listed as protected, and
/// Unprotect restores it from the backup instead of failing `not_protected`.
#[tokio::test]
async fn unprotect_without_a_record_restores_a_gateway_entry() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-crm", "aaaaaaaaaaaaaaaa"));
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.servers
        .lock()
        .unwrap()
        .push(FakeOps::stdio("crm", "/bin/sh", &[]));
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let id = uid(&ctx, HarnessId::ClaudeCode, "crm");
    protect::protect(&ctx, HarnessId::ClaudeCode, &id)
        .await
        .unwrap();
    // The record is gone; the file still routes the entry.
    ctx.update_state(|s| s.protected.clear()).unwrap();
    let rows = protect::servers(&ctx).await.unwrap();
    assert!(rows[0].protected && rows[0].id == id);
    let out = protect::unprotect(&ctx, HarnessId::ClaudeCode, &id)
        .await
        .unwrap();
    assert_eq!(
        f.reverted.lock().unwrap().len(),
        1,
        "restored from the backup"
    );
    assert!(f.servers.lock().unwrap()[0].gateway_dataset.is_none());
    assert_eq!(
        out.unreferenced_dataset.as_deref(),
        Some("mcp-crm"),
        "the label comes from the status by dataset id"
    );
    // An entry not pointing at the gateway is still `not_protected`.
    let e = protect::unprotect(&ctx, HarnessId::ClaudeCode, &id)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "not_protected");
    // A mailbox's gateway entry is no wrapped server: not Unprotect's.
    let mut status: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("status")).unwrap();
    status["datasets"] = json!([{ "id": "mail-1", "label": "cccccccccccccccc", "name": "x", "profile": "offline", "rotation_days": 30, "grace_days": 7, "epoch_id": 1, "epoch_started_at": 1, "entries": 0, "kind": "mailbox" }]);
    m.set("GET", "/v1/status", Canned::json(200, status));
    let mut mail = FakeOps::stdio("inumaki-mail", "/bin/sh", &[]);
    mail.gateway_dataset = Some("mail-1".into());
    f.servers.lock().unwrap().push(mail);
    let reverted = f.reverted.lock().unwrap().len();
    let e = protect::unprotect(
        &ctx,
        HarnessId::ClaudeCode,
        &uid(&ctx, HarnessId::ClaudeCode, "inumaki-mail"),
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind, "not_protected");
    assert_eq!(
        f.reverted.lock().unwrap().len(),
        reverted,
        "nothing reverted"
    );
}

/// Review I1 (connect ruling 2026-10-10): Protect often writes a harness's
/// first gateway entry, so the connect's fixed harness warnings
/// (`codex_approval_never`) come back in its outcome, as codes and fixed
/// text only.
#[tokio::test]
async fn protect_returns_the_connects_harness_warnings() {
    let m = MockDaemon::start().await;
    daemon_datasets(&m, &[], ("mcp-qwxzvk-crm", "aaaaaaaaaaaaaaaa"));
    let f = FakeOps::new(HarnessId::Codex);
    // The user approved their own server's tools; that setting is theirs
    // and is not lent to inumaki's entry (review follow-up 2026-10-10).
    let mut own = FakeOps::stdio("qwxzvk-crm", "/bin/sh", &[]);
    own.approval_mode = Some("approve".into());
    f.servers.lock().unwrap().push(own);
    let w = inumaki_adapters::ConnectWarning::CodexApprovalNever;
    f.warnings
        .lock()
        .unwrap()
        .push(inumaki_app_lib::harness::ops::Reason {
            code: w.code(),
            text: w.sentence(),
        });
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let out = protect::protect(
        &ctx,
        HarnessId::Codex,
        &uid(&ctx, HarnessId::Codex, "qwxzvk-crm"),
    )
    .await
    .unwrap();
    assert_eq!(out.harness_warnings.len(), 1);
    assert_eq!(out.harness_warnings[0].code, "codex_approval_never");
    let v = serde_json::to_value(&out).unwrap();
    assert_eq!(v["harness_warnings"][0]["text"], w.sentence());
    let dbg = format!("{out:?}");
    assert!(
        dbg.contains("codex_approval_never") && !dbg.contains("qwxzvk"),
        "{dbg}"
    );
    let carried = f.approvals.lock().unwrap();
    assert!(
        carried
            .iter()
            .flatten()
            .all(|(name, mode)| name != "qwxzvk-crm" || mode.is_none()),
        "the user's own entry lends no approval mode"
    );
    assert!(
        carried
            .iter()
            .flatten()
            .any(|(name, _)| name == "qwxzvk-crm")
    );
}
