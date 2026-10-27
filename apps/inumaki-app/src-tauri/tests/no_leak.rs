//! Spec §11 (app): every command, driven against the mock daemon whose
//! answers carry canary values everywhere (the fixtures' `qwxzvk` marker in
//! dataset ids and names, upstream names, hosts, usernames, paths, journal
//! payloads, entity originals, the gateway token, and the proxy client
//! header; plus error messages naming a slug, a value, and a privacy
//! block), leaves the app log, the state file, every notification, and the
//! `Debug` and serialization of every `CmdError` (and the `Debug` of the
//! app's own views) free of them (Review Focus 5).
//!
//! Canaries the app itself is handed: a mailbox password (Add, Replace
//! password), an MCP server's env secret (Protect: it goes to the upstream
//! create only), a server name and a project directory (the opaque
//! `ServerRow.id`, `state.json`), and a value typed into Forget.

mod common;

use std::fmt::Debug;
use std::future::Future;
use std::path::PathBuf;

use common::{FakeOps, ctx_with};
use inumaki_app_lib::applog::{self, logged};
use inumaki_app_lib::commands::{activity, email, folders, inspect, mcp, overview, settings};
use inumaki_app_lib::ctx::Ctx;
use inumaki_app_lib::error::CmdError;
use inumaki_app_lib::harness::ops::{PathKind, Scope};
use inumaki_app_lib::harness::{connect, naming};
use inumaki_client::mock::{Canned, MockDaemon};
use inumaki_client::{HarnessId, Redaction, RedactionAction, Secret};
use serde_json::json;

/// `qwxzvk` is in every fixture's sensitive field and every canary below;
/// `zyxwuria` is the fixtures' surname; `hunter2` starts every secret;
/// `at61 1904` is the fixtures' IBAN.
const MARKERS: [&str; 4] = ["qwxzvk", "zyxwuria", "hunter2", "at61 1904"];

const ENV_SECRET: &str = "hunter2-envsecret-qwxzvk";
const MAIL_PASSWORD: &str = "hunter2-mailpw-qwxzvk";
const MAIL_PASSWORD_2: &str = "hunter2-mailpw2-qwxzvk";
const PROJECT_DIR: &str = "/Users/qwxzvk/projects/qwxzvk-app";

fn clean(what: &str, text: &str) {
    let l = text.to_lowercase();
    for m in MARKERS {
        assert!(!l.contains(m), "{what} contains {m}: {text}");
    }
}

/// `snippet` (a `cannot_edit_safely` refusal's lines, with the harness
/// token) is exempt by design: it is an IPC answer to the local user who
/// pressed Connect, never a sink (see tests/connect.rs). No refusal path runs
/// here, so this check does not cover it.
fn clean_err(what: &str, e: &CmdError) {
    clean(
        &format!("{what}: CmdError"),
        &format!("{e:?} {}", serde_json::to_string(e).unwrap()),
    );
}

/// Run a command as its IPC wrapper does (through `logged`); an error's
/// `Debug` and serialization must be clean.
async fn run<T>(
    name: &'static str,
    f: impl Future<Output = Result<T, CmdError>>,
) -> Result<T, CmdError> {
    let r = logged(name, f).await;
    if let Err(e) = &r {
        clean_err(name, e);
    }
    r
}

/// [`run`], and the answer's `Debug` (an app type) must be clean too.
async fn run_dbg<T: Debug>(
    name: &'static str,
    f: impl Future<Output = Result<T, CmdError>>,
) -> Result<T, CmdError> {
    let r = run(name, f).await;
    if let Ok(v) = &r {
        clean(&format!("{name}: Debug"), &format!("{v:?}"));
    }
    r
}

/// The three sinks: `app.log`, `state.json`, the notifications sent so far.
fn sinks_clean(ctx: &Ctx, sent: &[String]) {
    for n in sent {
        clean("notification", n);
    }
    clean(
        "app.log",
        &std::fs::read_to_string(&ctx.paths.log_file).unwrap(),
    );
    // unwrap: a state save that failed (`state_unwritable` is swallowed in
    // places) must not pass as a clean, empty file.
    clean(
        "state.json",
        &std::fs::read_to_string(&ctx.paths.state_file).unwrap(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_canary_reaches_log_state_or_notifications() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::ClaudeCode);
    let user = FakeOps::stdio(
        "qwxzvk-crm",
        "/bin/sh",
        &[("QWXZVK_TOKEN", ENV_SECRET), ("LOG_LEVEL", "qwxzvk-debug")],
    );
    let mut project = FakeOps::stdio("qwxzvk-wiki", "/bin/sh", &[]);
    project.scope = Scope::Local(PROJECT_DIR.into());
    f.servers.lock().unwrap().extend([user, project]);
    *f.backups.lock().unwrap() = vec!["001790000000-000000001".into()];
    let (ctx, dir, notes) = ctx_with(&m, vec![f.clone()]);
    applog::init(&ctx.paths.log_file);
    // Fixture datasets: a generic one, a mailbox, a folder.
    let (ds, mail, folder) = ("qwxzvk-kunde", "qwxzvk-mail", "qwxzvk-akten");
    let rec = |id: char, dataset: &str, verdict: &str| {
        json!({ "id": id.to_string().repeat(32), "at": 4_000_000_000i64, "dataset": dataset,
        "front_door": "gateway", "upstream": "qwxzvk-crm", "direction": "result", "verdict": verdict, "checks": ["Leak"],
        "kinds": [{ "kind": "PERSON", "count": 1 }, { "kind": "qwxzvk zyxwuria", "count": 1 }], "tripwire": true, "bytes": 10, "released": null })
    };
    m.set(
        "GET",
        "/v1/activity",
        Canned::json(
            200,
            json!({ "records": [rec('1', ds, "blocked"), rec('2', folder, "released")] }),
        ),
    );

    // Every command once, logged as the IPC wrappers log it.
    let _ = run_dbg("overview", overview::overview(&ctx)).await;
    let _ = run_dbg("refresh", overview::refresh(&ctx)).await;
    let _ = run(
        "acknowledge",
        overview::acknowledge(&ctx, HarnessId::ClaudeCode, PathKind::Chat),
    )
    .await;
    let _ = run_dbg(
        "preview_connect",
        connect::preview(&ctx, HarnessId::ClaudeCode),
    )
    .await;
    run_dbg("connect", connect::connect(&ctx, HarnessId::ClaudeCode))
        .await
        .unwrap();
    run_dbg("reconnect", connect::reconnect(&ctx, HarnessId::ClaudeCode))
        .await
        .unwrap();
    let other = run_dbg("other_client", connect::other_client(&ctx))
        .await
        .unwrap();
    assert!(
        other.token.is_some() && other.client_header.is_some(),
        "the token and the client header are exercised"
    );
    let _ = run("revoke_other_client", connect::revoke_other_client(&ctx)).await;

    // MCP servers: the ids are opaque (no name, no project directory).
    let rows = run_dbg("mcp_servers", mcp::servers(&ctx)).await.unwrap();
    assert_eq!(rows.len(), 2);
    for r in &rows {
        clean("ServerRow.id", &r.id);
        assert!(r.id.len() == 64 && !r.id.contains("projects"));
    }
    let (crm, wiki) = (rows[0].id.clone(), rows[1].id.clone());
    assert_eq!(rows[1].scope, "project");
    let out = run_dbg("protect", mcp::protect(&ctx, HarnessId::ClaudeCode, &crm))
        .await
        .unwrap();
    assert!(!ctx.state().protected.is_empty(), "Protect recorded");
    run(
        "leave_unprotected",
        mcp::leave_unprotected(&ctx, HarnessId::ClaudeCode, &wiki, true),
    )
    .await
    .unwrap();
    assert!(
        ctx.state().leave_unprotected.contains(&wiki),
        "leave unprotected recorded"
    );
    // The state now holds both entries: no name, path, or secret in it.
    sinks_clean(&ctx, &notes.sent());
    let on_disk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ctx.paths.state_file).unwrap()).unwrap();
    assert!(
        on_disk["leave_unprotected"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x == wiki.as_str())),
        "the file, not only memory, holds leave_unprotected: {on_disk}"
    );
    assert!(
        on_disk["protected"]["claude-code"]
            .as_object()
            .is_some_and(|m| !m.is_empty()),
        "the file, not only memory, holds the protection: {on_disk}"
    );
    let _ = run_dbg("mcp_servers", mcp::servers(&ctx)).await;
    let _ = run("accept_schema", mcp::accept_schema(&ctx, ds, "qwxzvk-crm")).await;
    let _ = run_dbg(
        "unprotect",
        mcp::unprotect(&ctx, HarnessId::ClaudeCode, &crm),
    )
    .await;
    let _ = run(
        "remove_protected_dataset",
        mcp::remove_dataset(&ctx, &out.dataset),
    )
    .await;
    let _ = run_dbg("revert", connect::revert(&ctx, HarnessId::ClaudeCode)).await;
    // The env secret went to the upstream create and nowhere else.
    let mut sent_secret = 0;
    for r in m.requests() {
        let body = r.body.map(|b| b.to_string()).unwrap_or_default();
        let query = r.query.unwrap_or_default();
        if body.contains("envsecret") {
            sent_secret += 1;
            assert!(
                r.method == "POST" && r.route == "/v1/datasets/{id}/upstreams",
                "the env secret reached {} {}",
                r.method,
                r.route
            );
        }
        assert!(!r.path.contains("envsecret") && !query.contains("envsecret"));
    }
    assert!(
        sent_secret >= 1,
        "Protect sent the env secret to the upstream create"
    );
    for applied in f.applied.lock().unwrap().iter() {
        for (_, url, _) in applied {
            assert!(!url.contains("envsecret"));
        }
    }

    // Email.
    let _ = run_dbg("mailboxes", email::mailboxes(&ctx)).await;
    let form: email::MailboxForm = serde_json::from_value(json!({ "preset": "generic", "username": "office@qwxzvk.example",
        "password": MAIL_PASSWORD, "imap_host": "imap.qwxzvk.example", "imap_port": 993, "display_name": "Qwxzvk Office" }))
    .unwrap();
    clean("MailboxForm Debug", &format!("{form:?}"));
    let _ = run_dbg("add_mailbox", email::add_mailbox(&ctx, form)).await;
    let _ = run("check_mailbox", email::check_mailbox(&ctx, mail)).await;
    run(
        "replace_mailbox_password",
        email::replace_password(&ctx, mail, Secret::new(MAIL_PASSWORD_2)),
    )
    .await
    .unwrap();
    let _ = run_dbg("remove_mailbox", email::remove_mailbox(&ctx, mail)).await;
    let pw: Vec<_> = m
        .requests()
        .into_iter()
        .filter(|r| {
            r.body
                .as_ref()
                .is_some_and(|b| b.to_string().contains("mailpw"))
        })
        .map(|r| (r.method, r.route))
        .collect();
    assert_eq!(
        pw,
        [
            ("POST".to_string(), "/v1/datasets/{id}/mailbox"),
            ("POST".to_string(), "/v1/datasets/{id}/mailbox")
        ],
        "the password is sent once per Add and Replace, to the mailbox route only"
    );

    // Folders.
    let _ = run_dbg("folders", folders::folders(&ctx)).await;
    let _ = run_dbg(
        "add_folder",
        folders::add_folder(&ctx, PathBuf::from("/Users/qwxzvk/Akten")),
    )
    .await;
    let _ = run("rescan_folder", folders::rescan(&ctx, folder)).await;
    let _ = run("reveal_mirror", folders::reveal_target(&ctx, folder)).await;
    let _ = run("reveal_outbox", folders::outbox_target(&ctx, folder)).await;
    let _ = run_dbg("remove_folder", folders::remove_folder(&ctx, folder)).await;

    // Activity, journal, entities, forget.
    let _ = run(
        "activity",
        activity::activity(&ctx, Some(ds.into()), Some(10)),
    )
    .await;
    let _ = run("verify_activity", activity::verify(&ctx)).await;
    let _ = run("journal", activity::journal(&ctx, ds, None)).await;
    // The success paths carry the originals: they must run, not fail quietly.
    run(
        "journal_record",
        activity::journal_record(&ctx, ds, &"0".repeat(32), true),
    )
    .await
    .unwrap();
    run("entities", activity::entities(&ctx, ds, true))
        .await
        .unwrap();
    let _ = run_dbg(
        "forget_token",
        activity::forget_token(&ctx, ds, "<PERSON_qwxzvk1>"),
    )
    .await;
    let _ = run_dbg(
        "forget_value",
        activity::forget_value(&ctx, ds, "Qwxzvk Zyxwuria".into()),
    )
    .await;

    // Inspect.
    run_dbg(
        "inspect_text",
        inspect::inspect(
            &ctx,
            ds,
            "Kunde Qwxzvk Zyxwuria, IBAN AT61 1904 3002 3457 3201".into(),
            true,
        ),
    )
    .await
    .unwrap();
    let spans = vec![Redaction {
        start: 6,
        end: 21,
        kind: "PERSON".into(),
        action: RedactionAction::Tokenize,
    }];
    let _ = run(
        "sanitize_with",
        inspect::sanitize_with(&ctx, ds, "Kunde Qwxzvk Zyxwuria".into(), spans),
    )
    .await;
    let file = dir.path().join("qwxzvk.txt");
    std::fs::write(&file, "Qwxzvk Zyxwuria").unwrap();
    let _ = run("open_text_file", async { inspect::read_text_file(&file) }).await;
    let _ = run("open_text_file", async {
        inspect::read_text_file(&dir.path().join("qwxzvk-missing.txt"))
    })
    .await;

    // Settings.
    let _ = run("service_info", settings::service_info(&ctx)).await;
    let _ = run("models_status", settings::models_status(&ctx)).await;
    let v = run_dbg("settings", settings::settings(&ctx)).await.unwrap();
    assert!(!v.backups.is_empty(), "the backups view is exercised");
    clean("BackupRow Debug", &format!("{:?}", v.backups));
    let _ = run(
        "delete_backup",
        settings::delete_backup(&ctx, HarnessId::ClaudeCode, "qwxzvk-backup"),
    )
    .await;
    let _ = run("set_first_run_done", async {
        settings::set_first_run_done(&ctx)
    })
    .await;
    let _ = run_dbg(
        "set_chat_opt_in",
        settings::set_chat_opt_in(&ctx, HarnessId::Codex, true),
    )
    .await;
    let _ = run_dbg("prefs", settings::prefs(&ctx)).await;
    let _ = run("datasets", settings::datasets(&ctx)).await;

    // The same routes failing with messages that name the slug or a value.
    for (method, route) in [
        ("GET", "/v1/datasets/{id}/mailbox"),
        ("GET", "/v1/datasets/{id}/journal"),
        ("POST", "/v1/inspect"),
        ("GET", "/v1/folders"),
        ("GET", "/v1/datasets"),
    ] {
        m.set(
            method,
            route,
            Canned::error(404, "not_found", "dataset qwxzvk-kunde not found", &[]),
        );
    }
    m.set(
        "POST",
        "/v1/sanitize",
        Canned::error(
            451,
            "privacy_block",
            "qwxzvk Zyxwuria remained",
            &["PERSON", "qwxzvk zyxwuria", "AT61 1904"],
        ),
    );
    m.set(
        "POST",
        "/v1/datasets/{id}/entities/forget",
        Canned::error(400, "qwxzvk_kind", "no entity Qwxzvk Zyxwuria", &[]),
    );
    m.set(
        "POST",
        "/v1/datasets/{id}/upstreams",
        Canned::error(400, "bad_request", "upstream qwxzvk-crm rejected", &[]),
    );
    let mut errs = vec![
        run("journal", activity::journal(&ctx, ds, None))
            .await
            .unwrap_err(),
        run(
            "inspect_text",
            inspect::inspect(&ctx, ds, "Qwxzvk".into(), false),
        )
        .await
        .unwrap_err(),
        run(
            "sanitize_with",
            inspect::sanitize_with(&ctx, ds, "Qwxzvk".into(), vec![]),
        )
        .await
        .unwrap_err(),
        run("folders", folders::folders(&ctx)).await.unwrap_err(),
        run(
            "forget_value",
            activity::forget_value(&ctx, ds, "Qwxzvk Zyxwuria".into()),
        )
        .await
        .unwrap_err(),
        run(
            "replace_mailbox_password",
            email::replace_password(&ctx, mail, Secret::new(MAIL_PASSWORD_2)),
        )
        .await
        .unwrap_err(),
    ];
    // Protect of a new definition whose upstream create fails (the secret
    // was sent; the error message names the server).
    m.reset("GET", "/v1/datasets");
    f.servers.lock().unwrap().push(FakeOps::stdio(
        "qwxzvk-erp",
        "/bin/sh",
        &[("ERP_TOKEN", ENV_SECRET)],
    ));
    let erp = naming::server_key(&ctx, HarnessId::ClaudeCode, "qwxzvk-erp", &Scope::User).unwrap();
    errs.push(
        run("protect", mcp::protect(&ctx, HarnessId::ClaudeCode, &erp))
            .await
            .unwrap_err(),
    );
    assert_eq!(errs.last().unwrap().kind, "bad_request");
    assert_eq!(errs[2].kinds, ["PERSON"], "only kind-shaped labels pass");
    assert_eq!(
        errs[4].kind, "error",
        "an unknown daemon kind is not passed on"
    );
    for e in &errs {
        clean_err("failure", e);
    }

    // Notifications from the poller.
    inumaki_app_lib::poll::tick(&ctx).await;
    let sent = notes.sent();
    assert!(!sent.is_empty(), "the blocked record notifies");
    sinks_clean(&ctx, &sent);
    // A log that was never written (a failed `applog::init`) is no evidence.
    let log = std::fs::read_to_string(&ctx.paths.log_file).unwrap();
    assert!(
        log.lines()
            .any(|l| l.contains("cmd=protect ") && l.contains("outcome=ok")),
        "{log}"
    );
    assert!(log.contains("cmd=inspect_text "), "{log}");
}
