//! Activity, Inspect, Settings (spec §6.4): degrade before lane 2b merges,
//! hide check datasets, hash the NFC text for redactions, embed measured
//! numbers, and show backups with their times; originals reach no log or
//! Debug; deleting a backup never leaves the backup directory or removes the
//! live one; the Codex opt-in reconnects through the harness lock.

mod common;

use common::{FakeOps, ctx_with};
use inumaki_app_lib::commands::{activity, inspect, settings};
use inumaki_app_lib::harness::ops::*;
use inumaki_app_lib::harness::{adapt, harness_key};
use inumaki_app_lib::paths::AppPaths;
use inumaki_client::mock::{Canned, MockDaemon};
use inumaki_client::{HarnessId, Redaction, RedactionAction};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn no_route() -> Canned {
    Canned::error(404, "not_found", "no such route", &[])
}

#[tokio::test]
async fn journal_and_entities_degrade_before_plan_2b() {
    let m = MockDaemon::start().await;
    for route in ["/v1/datasets/{id}/journal", "/v1/datasets/{id}/entities"] {
        m.set("GET", route, no_route());
    }
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    assert_eq!(
        activity::journal(&ctx, "kunde", None)
            .await
            .unwrap_err()
            .kind,
        "not_available"
    );
    assert_eq!(
        activity::entities(&ctx, "kunde", false)
            .await
            .unwrap_err()
            .kind,
        "not_available"
    );
}

#[tokio::test]
async fn a_missing_dataset_on_an_existing_route_is_an_ordinary_error() {
    let m = MockDaemon::start().await;
    m.set(
        "GET",
        "/v1/datasets/{id}/journal",
        Canned::error(404, "not_found", "no such dataset", &[]),
    );
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let e = activity::journal(&ctx, "kunde", None).await.unwrap_err();
    assert_eq!(e.kind, "not_found", "not 'not_available'");
}

#[tokio::test]
async fn activity_hides_check_datasets() {
    let m = MockDaemon::start().await;
    let rec = |dataset: &str| {
        json!({ "id": "0".repeat(32), "at": 1, "dataset": dataset, "front_door": "gateway", "upstream": null,
        "direction": "result", "verdict": "released", "checks": [], "kinds": [], "tripwire": false, "bytes": 1, "released": null })
    };
    m.set(
        "GET",
        "/v1/activity",
        Canned::json(
            200,
            json!({ "records": [rec("kunde"), rec("check-0123456789ab"), rec("check-0123456789ab-f")] }),
        ),
    );
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let list = activity::activity(&ctx, None, Some(50)).await.unwrap();
    assert_eq!(list.records.len(), 1);
    assert_eq!(list.records[0].dataset, "kunde");
}

#[tokio::test]
async fn redactions_hash_the_nfc_text() {
    let m = MockDaemon::start().await;
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let text = "Cafe\u{301} Qwxzvk".to_string();
    let spans = vec![Redaction {
        start: 6,
        end: 12,
        kind: "PERSON".into(),
        action: RedactionAction::Tokenize,
    }];
    inspect::sanitize_with(&ctx, "kunde", text, spans)
        .await
        .unwrap();
    let body = m
        .requests()
        .into_iter()
        .find(|r| r.route == "/v1/sanitize")
        .unwrap()
        .body
        .unwrap();
    let want: String = Sha256::digest("Café Qwxzvk".as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(body["redactions"]["input_sha256"], want);
    assert_eq!(
        body["text"], "Café Qwxzvk",
        "the NFC text is what the offsets refer to"
    );
}

#[tokio::test]
async fn inspect_asks_for_originals_only_when_told_to() {
    let m = MockDaemon::start().await;
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    inspect::inspect(&ctx, "kunde", "Qwxzvk".into(), false)
        .await
        .unwrap();
    inspect::inspect(&ctx, "kunde", "Qwxzvk".into(), true)
        .await
        .unwrap();
    let sent: Vec<bool> = m
        .requests()
        .into_iter()
        .filter(|r| r.route == "/v1/inspect")
        .map(|r| r.body.unwrap()["show_values"].as_bool().unwrap())
        .collect();
    assert_eq!(sent, [false, true]);
    // `show_values` travels in the query string (the recorded `path` has none).
    let calls = |reveal: bool| {
        let want = format!("show_values={reveal}");
        m.requests()
            .into_iter()
            .filter(|r| {
                r.query
                    .as_deref()
                    .is_some_and(|q| q.split('&').any(|p| p == want))
            })
            .count()
    };
    activity::entities(&ctx, "kunde", false).await.ok();
    activity::journal_record(&ctx, "kunde", &"0".repeat(32), false)
        .await
        .ok();
    assert_eq!(calls(true), 0, "no reveal without an explicit request");
    assert_eq!(calls(false), 2);
    // The explicit reveal does ask, once per click.
    activity::entities(&ctx, "kunde", true).await.ok();
    activity::journal_record(&ctx, "kunde", &"0".repeat(32), true)
        .await
        .ok();
    assert_eq!(calls(true), 2, "a reveal sends show_values=true");
}

/// The daemon's span offsets are UTF-8 bytes of the NFC text: the command
/// normalizes before sending and hands that exact text back for the UI to
/// slice, so a decomposed character before a span cannot shift it.
#[tokio::test]
async fn inspect_offsets_index_into_the_returned_nfc_text() {
    let m = MockDaemon::start().await;
    // "Café " is 6 bytes in NFC (é = 2 bytes), 7 decomposed (e + U+0301).
    m.set(
        "POST",
        "/v1/inspect",
        Canned::json(
            200,
            json!({ "label": "local diagnostic output — not approved for transmission", "outcome": "pass",
                "profile": "offline", "retried": false,
                "spans": [{ "start": 6, "end": 12, "kind": "PERSON", "action": "tokenize", "source": "Known" }],
                "reasons": [], "replacements": 1, "limitations": [],
                "expiry": { "rotation_days": 30, "grace_days": 7, "epoch_started_at": 1_790_000_000 } }),
        ),
    );
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let v = inspect::inspect(&ctx, "kunde", "Cafe\u{301} Qwxzvk".into(), false)
        .await
        .unwrap();
    assert_eq!(v.text, "Caf\u{e9} Qwxzvk");
    let s = &v.body.spans[0];
    assert_eq!(&v.text[s.start as usize..s.end as usize], "Qwxzvk");
    let sent = m
        .requests()
        .into_iter()
        .find(|r| r.route == "/v1/inspect")
        .unwrap()
        .body
        .unwrap();
    assert_eq!(
        sent["text"], "Caf\u{e9} Qwxzvk",
        "the daemon gets the NFC text"
    );
    assert!(!format!("{v:?}").contains("Qwxzvk"), "no text in Debug");
}

#[test]
fn measured_is_not_empty() {
    let m = inumaki_app_lib::measured::measured();
    assert!(
        !m.is_empty(),
        "build.rs found no report in docs/quality: the Settings view would show no numbers"
    );
    assert!(
        m.iter()
            .all(|r| r.docs > 0 && r.evaluated_at > 1_700_000_000),
        "unix seconds, parsed as integers"
    );
    let mut profiles: Vec<&str> = m.iter().map(|r| r.profile.as_str()).collect();
    profiles.sort();
    profiles.dedup();
    assert_eq!(profiles.len(), m.len(), "one row per profile");
}

#[tokio::test]
async fn backups_show_their_time_and_which_one_revert_uses() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    *f.backups.lock().unwrap() = vec![
        "001790000000-000000001".into(),
        "001790000100-000000002".into(),
        "000000000000-000000003".into(),
    ];
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    ctx.update_state(|s| {
        s.backups
            .insert("codex".into(), vec!["001790000100-000000002".into()]);
    })
    .unwrap();
    // Review M6: without an active backup the recorded id is stale (an
    // outside revert): not live, and cleared, as Connect clears it.
    let v = settings::settings(&ctx).await.unwrap();
    let rows = serde_json::to_value(&v.backups).unwrap();
    assert!(rows.as_array().unwrap().iter().all(|r| r["live"] == false));
    assert!(!ctx.state().backups.contains_key("codex"));
    ctx.update_state(|s| {
        s.backups
            .insert("codex".into(), vec!["001790000100-000000002".into()]);
    })
    .unwrap();
    *f.active.lock().unwrap() = Some("001790000100-000000002".into());
    let v = settings::settings(&ctx).await.unwrap();
    let rows = serde_json::to_value(&v.backups).unwrap();
    assert_eq!(rows[0]["backup"]["created_at"], 1_790_000_000);
    assert_eq!(rows[1]["live"], true);
    assert_eq!(rows[0]["live"], false);
    assert!(
        rows[2]["backup"]["created_at"].is_null(),
        "time 0 is unknown, not 1970"
    );
    assert_eq!(
        settings::delete_backup(&ctx, HarnessId::Codex, "001790000100-000000002")
            .await
            .unwrap_err()
            .kind,
        "backup_in_use"
    );
    assert_eq!(f.backups.lock().unwrap().len(), 3, "the live one stays");
    settings::delete_backup(&ctx, HarnessId::Codex, "001790000000-000000001")
        .await
        .unwrap();
    assert_eq!(f.backups.lock().unwrap().len(), 2);
    // The adapter's active backup is live too, whatever `state.json` holds.
    *f.active.lock().unwrap() = Some("000000000000-000000003".into());
    assert_eq!(
        settings::delete_backup(&ctx, HarnessId::Codex, "000000000000-000000003")
            .await
            .unwrap_err()
            .kind,
        "backup_in_use"
    );
}

#[tokio::test]
async fn debug_of_views_prints_no_id_path_or_count_of_content() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    *f.backups.lock().unwrap() = vec!["001790000000-000000001".into()];
    let (ctx, _dir, _) = ctx_with(&m, vec![f]);
    let v = settings::settings(&ctx).await.unwrap();
    let s = format!("{v:?} {:?}", v.backups);
    assert!(!s.contains("001790000000"), "{s}");
    assert!(
        !s.contains(ctx.paths.log_file.to_str().unwrap()),
        "the log path stays out of Debug"
    );
}

/// The real adapter: a backup id names a directory that is removed
/// recursively, so nothing but a backup id may reach `remove_dir_all`.
#[test]
fn delete_backup_never_leaves_the_backup_store() {
    const ORIGINAL: &str =
        r#"{ "mcpServers": { "crm": { "command": "/bin/sh", "args": ["-c", "true"] } } }"#;
    const BASE: &str = "http://127.0.0.1:8789";
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(home.join(".claude.json"), ORIGINAL).unwrap();
    let paths = AppPaths::under(&dir.path().join("data"), &home);
    let ops = adapt::for_tests(&paths, &home)
        .into_iter()
        .find(|o| o.id() == HarnessId::ClaudeCode)
        .unwrap();
    ops.refresh();
    let req = ConnectRequest {
        gateway_base: BASE.into(),
        gateway: vec![GatewayEntry {
            name: "crm".into(),
            scope: Scope::User,
            url: format!("{BASE}/mcp/mcp-crm"),
            token: Zeroizing::new("inumaki_gw_test".into()),
            approval_mode: None,
        }],
        mirror_root: None,
        outboxes: Vec::new(),
        proxy: ProxyUrls::default(),
        hook_command: None,
        chat: false,
        client_header: None,
    };
    let id = ops.apply(&req).unwrap();
    let listed = ops.backups();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, id);
    assert!(listed[0].created_at.is_some_and(|t| t > 1_700_000_000));

    // A directory next to the store with a manifest: an `..` id must not reach it.
    let outside = paths.data_dir.join("adapters").join("victim");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("manifest.json"), "{}").unwrap();
    for bad in ["../../victim", "..", "", "/", "000000000001-00000000/../x"] {
        assert!(
            matches!(
                ops.delete_backup(bad),
                Err(OpError::Failed("backup_unreadable"))
            ),
            "{bad:?}"
        );
    }
    assert!(outside.join("manifest.json").exists());

    // A second apply chains onto the first: the older backup is no longer
    // the active one, and deleting it leaves the active one alone.
    let newer = ops.apply(&req).unwrap();
    assert_ne!(newer, id);
    ops.delete_backup(&id).unwrap();
    let left: Vec<String> = ops.backups().into_iter().map(|b| b.id).collect();
    assert_eq!(left, std::slice::from_ref(&newer));
    assert_eq!(ops.active_backup().as_deref(), Some(newer.as_str()));
    // A clean revert removes its backup itself.
    ops.revert(&newer).unwrap();
    assert!(ops.backups().is_empty());
}

#[tokio::test]
async fn forgetting_while_the_purge_is_pending_is_a_success_with_a_note() {
    let m = MockDaemon::start().await;
    m.set(
        "DELETE",
        "/v1/datasets/{id}/entities/{token}",
        Canned::error(503, "vault_busy", "purge pending", &[]),
    );
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let out = activity::forget_token(&ctx, "kunde", "<PERSON_a7f2>")
        .await
        .unwrap();
    assert!(out.purge_pending);
    m.set(
        "DELETE",
        "/v1/datasets/{id}/entities/{token}",
        Canned::error(503, "unavailable", "down", &[]),
    );
    let e = activity::forget_token(&ctx, "kunde", "<PERSON_a7f2>")
        .await
        .unwrap_err();
    assert_eq!(e.status, Some(503), "any other 503 stays an error");
}

#[test]
fn the_file_view_opens_small_text_files_only() {
    let dir = tempfile::tempdir().unwrap();
    let ok = dir.path().join("a.txt");
    std::fs::write(&ok, "Grüße Qwxzvk").unwrap();
    assert_eq!(inspect::read_text_file(&ok).unwrap(), "Grüße Qwxzvk");
    let big = dir.path().join("big.txt");
    std::fs::write(&big, vec![b'a'; (1 << 20) + 1]).unwrap();
    assert_eq!(
        inspect::read_text_file(&big).unwrap_err().kind,
        "file_too_large"
    );
    let bin = dir.path().join("b.bin");
    std::fs::write(&bin, [0xff, 0xfe, 0x00]).unwrap();
    assert_eq!(
        inspect::read_text_file(&bin).unwrap_err().kind,
        "file_not_text"
    );
    assert_eq!(
        inspect::read_text_file(dir.path()).unwrap_err().kind,
        "file_not_text",
        "a directory is no text"
    );
    assert_eq!(
        inspect::read_text_file(&dir.path().join("none"))
            .unwrap_err()
            .kind,
        "file_unreadable"
    );
}

/// Every harness's chat switch (M9 Task 6): the choice is saved, the view
/// reads it back, and only that harness is reconnected.
#[tokio::test]
async fn each_chat_opt_in_persists_and_reconnects_its_harness_only() {
    let all = [
        HarnessId::ClaudeCode,
        HarnessId::Codex,
        HarnessId::Hermes,
        HarnessId::Openclaw,
    ];
    for h in all {
        let m = MockDaemon::start().await;
        let fakes: Vec<_> = all.iter().map(|id| FakeOps::new(*id)).collect();
        for (i, f) in fakes.iter().enumerate() {
            *f.active.lock().unwrap() = Some(format!("00000000000{}-000000000", i + 1));
        }
        let (ctx, _dir, _) = ctx_with(&m, fakes.clone());
        let me = fakes.iter().find(|f| f.id == h).unwrap();
        let key = harness_key(h);
        let others = || {
            fakes
                .iter()
                .filter(|f| f.id != h)
                .map(|f| f.applied.lock().unwrap().len() + *f.previews.lock().unwrap())
                .sum::<usize>()
        };

        // No choice and no route in the backup: the effective value is off.
        // "Off" is saved as an explicit choice but reconnects nothing.
        assert!(!settings::prefs(&ctx).await.unwrap().chat_effective[key]);
        settings::set_chat_opt_in(&ctx, h, false).await.unwrap();
        assert_eq!(ctx.state().prefs.chat_opt_in.get(key), Some(&false));
        assert!(me.applied.lock().unwrap().is_empty());

        let c = settings::set_chat_opt_in(&ctx, h, true).await.unwrap();
        assert_eq!(c.reconnect_failures, 0);
        assert_eq!(ctx.state().prefs.chat_opt_in.get(key), Some(&true));
        let p = settings::prefs(&ctx).await.unwrap();
        assert!(p.chat_effective[key]);
        assert_eq!(
            serde_json::to_value(&p).unwrap()["chat_opt_in"][key],
            true,
            "the answer carries the stored choice and the effective value"
        );
        assert!(
            settings::settings(&ctx).await.unwrap().prefs.chat_opt_in[key],
            "the Settings view reads the choice back"
        );
        assert_eq!(me.applied.lock().unwrap().len(), 1, "{key} followed");
        assert_eq!(others(), 0, "{key}: no other harness");

        // Unchanged: nothing is touched.
        settings::set_chat_opt_in(&ctx, h, true).await.unwrap();
        assert_eq!(me.applied.lock().unwrap().len(), 1);

        // A failing reconnect is reported; the choice stays.
        *me.fail_apply.lock().unwrap() = Some(common::Fail::Io);
        *me.active.lock().unwrap() = Some("000000000009-000000000".into());
        let c = settings::set_chat_opt_in(&ctx, h, false).await.unwrap();
        assert_eq!(c.failed_harnesses, vec![key]);
        assert_eq!(ctx.state().prefs.chat_opt_in.get(key), Some(&false));
        assert_eq!(others(), 0, "{key}: no other harness");
    }
}

/// M9 Task 6: the chat choices of older `state.json` files are folded into
/// the per-harness map on load (Claude Code's `Some`/`None`; Codex's
/// ChatGPT opt-in only when `true`, since `false` was also the default of a
/// routed API-key login), a newer entry wins, and the old fields are never
/// written back.
#[test]
fn older_chat_prefs_are_migrated_on_load() {
    use inumaki_app_lib::appstate;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("state.json");
    let load = |prefs: serde_json::Value| {
        std::fs::write(&f, json!({ "version": 1, "prefs": prefs }).to_string()).unwrap();
        appstate::load(&f).prefs
    };

    let p = load(
        json!({ "first_run_done": true, "claude_code_chat_opt_in": false, "codex_chatgpt_opt_in": true }),
    );
    assert!(p.first_run_done);
    assert_eq!(p.chat_opt_in.get("claude-code"), Some(&false));
    assert_eq!(p.chat_opt_in.get("codex"), Some(&true));
    assert!(p.chat_migration_pending, "a pre-M9 file");

    let p = load(json!({ "claude_code_chat_opt_in": null, "codex_chatgpt_opt_in": false }));
    assert!(p.chat_opt_in.is_empty(), "no choice was made");
    assert!(p.chat_migration_pending);

    let p =
        load(json!({ "claude_code_chat_opt_in": true, "chat_opt_in": { "claude-code": false } }));
    assert_eq!(
        p.chat_opt_in.get("claude-code"),
        Some(&false),
        "the newer entry wins"
    );
    assert!(!p.chat_migration_pending, "an M9 file");

    let mut st = appstate::load(&f);
    st.prefs = load(json!({ "claude_code_chat_opt_in": true, "codex_chatgpt_opt_in": true }));
    appstate::save(&f, &st).unwrap();
    let text = std::fs::read_to_string(&f).unwrap();
    assert!(
        !text.contains("claude_code_chat_opt_in") && !text.contains("codex_chatgpt_opt_in"),
        "{text}"
    );
    let back = appstate::load(&f).prefs;
    assert_eq!(back.chat_opt_in.get("claude-code"), Some(&true));
    assert_eq!(back.chat_opt_in.get("codex"), Some(&true));
}

#[tokio::test]
async fn first_run_done_is_saved() {
    let m = MockDaemon::start().await;
    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    assert!(!ctx.state().prefs.first_run_done);
    settings::set_first_run_done(&ctx).unwrap();
    assert!(ctx.state().prefs.first_run_done);
}
