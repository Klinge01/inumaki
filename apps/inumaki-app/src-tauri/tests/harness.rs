//! Overview cards (spec §4.1, §4.6, §6.4): path states with reasons,
//! counts instead of names, acknowledgement of red-by-design paths only,
//! and server keys that do not reveal a name.

mod common;

use std::collections::BTreeSet;

use common::{FakeOps, ctx_with};
use inumaki_adapters::ReasonCode;
use inumaki_app_lib::commands::overview;
use inumaki_app_lib::ctx::Ctx;
use inumaki_app_lib::harness::reason::{code, reason};
use inumaki_app_lib::harness::{self, ops::*};
use inumaki_app_lib::paths::AppPaths;
use inumaki_client::HarnessId;
use inumaki_client::mock::MockDaemon;

#[tokio::test]
async fn cards_carry_states_reasons_and_counts_never_names() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Openclaw);
    f.servers.lock().unwrap().push(FakeOps::stdio(
        "qwxzvk-crm",
        "qwxzvk-server",
        &[("QWXZVK_TOKEN", "hunter2-qwxzvk")],
    ));
    f.status.lock().unwrap().paths = vec![
        PathInfo {
            path: PathKind::Mcp,
            state: PathState::Connected,
            reason: None,
            detail: Some(Detail::Protected {
                protected: 1,
                total: 2,
            }),
        },
        PathInfo {
            path: PathKind::Files,
            state: PathState::Connected,
            reason: Some(Reason {
                code: "openclaw_docker_binds_only",
                text: "OpenClaw sees the mirror through its Docker sandbox only.",
            }),
            detail: None,
        },
        PathInfo {
            path: PathKind::Chat,
            state: PathState::Unsupported,
            reason: Some(Reason {
                code: "openclaw_subscription_bridge",
                text: "OpenClaw's Claude or ChatGPT subscription login runs through a command-line bridge that has no base-URL setting, so chat text is not filtered. Use an API key, or keep sensitive data in connected sources.",
            }),
            detail: None,
        },
    ];
    let (ctx, _dir, _) = ctx_with(&m, vec![f]);
    inumaki_app_lib::poll::tick(&ctx).await;
    let v = overview::overview(&ctx).await.unwrap();
    let json = serde_json::to_string(&v).unwrap();
    assert!(
        !json.contains("qwxzvk"),
        "no server name, command, or value in a card: {json}"
    );
    let card = &v.cards[0];
    assert_eq!(
        card.paths[0].detail,
        Some(Detail::Protected {
            protected: 1,
            total: 2
        })
    );
    assert_eq!(
        card.paths[2].reason.as_ref().unwrap().code,
        "openclaw_subscription_bridge"
    );
    assert!(!card.paths[2].acknowledged);
    assert_eq!(card.paths[2].state, PathState::Unsupported);
    overview::acknowledge(&ctx, HarnessId::Openclaw, PathKind::Chat)
        .await
        .unwrap();
    let v = overview::overview(&ctx).await.unwrap();
    assert!(v.cards[0].paths[2].acknowledged);
    // Acknowledge greys the card; the path stays unsupported with its reason.
    assert_eq!(v.cards[0].paths[2].state, PathState::Unsupported);
    assert!(v.cards[0].paths[2].reason.is_some());
    assert!(ctx.state().acknowledged.contains("openclaw/chat"));
}

/// The manual-setup lines (home paths, local URLs) are never on a card: the
/// card's JSON has no such field, and they come only from the on-demand command.
#[tokio::test]
async fn manual_setup_lines_are_on_demand_and_never_on_a_card() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Hermes);
    *f.manual.lock().unwrap() = Some(ManualSetupView {
        lines: "qwxzvk-lines".into(),
        note: "A fixed note.",
    });
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let card = serde_json::to_string(&overview::overview(&ctx).await.unwrap()).unwrap();
    assert!(!card.contains("qwxzvk-lines"), "{card}");
    let got = overview::manual_setup(&ctx, HarnessId::Hermes)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.lines, "qwxzvk-lines");
    // A harness without any answers none; so does an unknown one.
    *f.manual.lock().unwrap() = None;
    assert!(
        overview::manual_setup(&ctx, HarnessId::Hermes)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        overview::manual_setup(&ctx, HarnessId::Codex)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn only_red_by_design_paths_can_be_acknowledged() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    f.status.lock().unwrap().paths[0] = PathInfo {
        path: PathKind::Mcp,
        state: PathState::Broken,
        reason: Some(Reason {
            code: "changed_outside_inumaki",
            text: "The configuration was changed outside inumaki. Reconnect to restore it.",
        }),
        detail: None,
    };
    let (ctx, _dir, _) = ctx_with(&m, vec![f]);
    let e = overview::acknowledge(&ctx, HarnessId::Codex, PathKind::Mcp)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "not_acknowledgeable");
}

/// M6 spec §6.6 amendment (state.key): a server key is keyed per install.
#[tokio::test]
async fn server_keys_are_keyed_per_install() {
    let m = MockDaemon::start().await;
    let (a, _da, _) = ctx_with(&m, vec![]);
    let (b, _db, _) = ctx_with(&m, vec![]);
    let ka = harness::server_key(&a, HarnessId::Codex, "crm", &Scope::User).unwrap();
    assert_eq!(ka.len(), 64);
    assert_eq!(
        ka,
        harness::server_key(&a, HarnessId::Codex, "crm", &Scope::User).unwrap()
    );
    assert_ne!(
        ka,
        harness::server_key(&b, HarnessId::Codex, "crm", &Scope::User).unwrap(),
        "another install's key differs"
    );
    assert_ne!(
        ka,
        harness::server_key(&a, HarnessId::ClaudeCode, "crm", &Scope::User).unwrap()
    );
    // One name in two scopes is two entries (often two accounts).
    assert_ne!(
        ka,
        harness::server_key(&a, HarnessId::Codex, "crm", &Scope::Local("/p".into())).unwrap()
    );
}

/// No state key: no server key, so nothing is recorded under a weak one.
#[tokio::test]
async fn server_key_fails_closed_without_a_state_key() {
    let m = MockDaemon::start().await;
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(&dir.path().join("data"), dir.path());
    std::fs::create_dir_all(paths.state_key.parent().unwrap().parent().unwrap()).unwrap();
    std::fs::write(paths.state_key.parent().unwrap(), "x").unwrap();
    let (ctx, _) = Ctx::for_tests(paths, m.client());
    let e = harness::server_key(&ctx, HarnessId::Codex, "crm", &Scope::User).unwrap_err();
    assert_eq!(e.kind, "state_unwritable");
}

/// Harness ids are the client's serde names, written out.
#[test]
fn harness_keys_are_the_serde_names() {
    for h in [
        HarnessId::ClaudeCode,
        HarnessId::Codex,
        HarnessId::Hermes,
        HarnessId::Openclaw,
    ] {
        let j = serde_json::to_value(h).unwrap();
        assert_eq!(j.as_str().unwrap(), harness::harness_key(h));
    }
}

/// Every adapter reason maps to a distinct fixed code and the adapter's sentence;
/// the three M6-1 amendments are covered.
#[test]
fn reasons_map_explicitly() {
    use ReasonCode::*;
    let all = [
        OpenclawSubscriptionBridge,
        CodexNoReadScope,
        OpenclawDockerBindsOnly,
        OpenclawNoDockerSandbox,
        HermesFilesUnconfirmed,
        HermesOauthNoOverride,
        CodexChatgptUnverified,
        ChatNotProtected,
        RouteFailing,
        ChangedOutsideInumaki,
        NoFolderConnected,
        NoTrafficYet,
        UpstreamNotRunning,
        HookBinaryMissing,
        HookOutdated,
        HermesHooksFailOpen,
        OpenclawHookNotFiring,
        ProxyUnavailable,
        MirrorUnavailable,
        ServiceDown,
        LoginUnknown,
        ChatProviderNotRouted,
        CodexProfileOverride,
        ChatTokensOnly,
        CodexHookNeedsTrust,
    ];
    let codes: BTreeSet<_> = all.iter().map(|r| code(*r)).collect();
    assert_eq!(codes.len(), all.len(), "codes are distinct");
    for r in all {
        assert_eq!(reason(r).text, r.sentence());
        assert!(
            code(r).bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "a code is snake_case words"
        );
    }
    assert_eq!(code(ChatTokensOnly), "chat_tokens_only");
    assert_eq!(code(CodexHookNeedsTrust), "codex_hook_needs_trust");
    assert_eq!(code(HookOutdated), "hook_outdated");
}

/// A pending hook shows its fixed reason code on the card.
#[tokio::test]
async fn a_pending_hook_carries_its_reason_code() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    f.status.lock().unwrap().hook = HookState::Pending {
        reason: reason(ReasonCode::CodexHookNeedsTrust),
    };
    let (ctx, _dir, _) = ctx_with(&m, vec![f]);
    let v = overview::overview(&ctx).await.unwrap();
    let j = serde_json::to_value(&v).unwrap();
    assert_eq!(j["cards"][0]["hook"]["state"], "pending");
    assert_eq!(
        j["cards"][0]["hook"]["reason"]["code"],
        "codex_hook_needs_trust"
    );
    assert_eq!(
        j["cards"][0]["hook"]["reason"]["text"],
        ReasonCode::CodexHookNeedsTrust.sentence()
    );
    assert!(j["cards"][0]["grant"].is_null());
}

/// A broken hook keeps the adapter's reason: missing and outdated differ.
#[tokio::test]
async fn a_broken_hook_carries_its_reason_code() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::ClaudeCode);
    f.status.lock().unwrap().hook = HookState::Broken {
        reason: reason(ReasonCode::HookOutdated),
    };
    let (ctx, _dir, _) = ctx_with(&m, vec![f]);
    let j = serde_json::to_value(overview::overview(&ctx).await.unwrap()).unwrap();
    assert_eq!(j["cards"][0]["hook"]["state"], "broken");
    assert_eq!(j["cards"][0]["hook"]["reason"]["code"], "hook_outdated");
    assert_eq!(
        j["cards"][0]["hook"]["reason"]["text"],
        ReasonCode::HookOutdated.sentence()
    );
}

/// Debug of types that carry a snippet, an entry, or a path prints no value.
#[test]
fn debug_prints_kinds_and_counts_only() {
    let secret = "qwxzvk-canary";
    let err = OpError::CannotEditSafely {
        snippet: zeroize::Zeroizing::new(format!("Bearer {secret}")),
    };
    let entry = FakeOps::stdio(secret, secret, &[("K", secret)]);
    let change = FileChange {
        path: format!("/home/{secret}/x.json").into(),
        keys: vec![format!("mcpServers.{secret}")],
    };
    let req = ConnectRequest {
        gateway_base: format!("http://{secret}"),
        gateway: vec![GatewayEntry {
            name: secret.into(),
            scope: Scope::Local(secret.into()),
            url: format!("http://{secret}/mcp/x"),
            token: zeroize::Zeroizing::new(secret.into()),
            approval_mode: None,
        }],
        mirror_root: Some(secret.into()),
        outboxes: vec![secret.into()],
        proxy: ProxyUrls::default(),
        hook_command: Some(secret.into()),
        chat: false,
        client_header: Some(zeroize::Zeroizing::new(secret.into())),
    };
    for d in [
        format!("{err:?}"),
        format!("{entry:?}"),
        format!("{change:?}"),
        format!("{req:?}"),
        format!("{:?}", Scope::Local(secret.into())),
        format!(
            "{:?}",
            ProxyUrls {
                anthropic: Some(format!("http://{secret}")),
                ..ProxyUrls::default()
            }
        ),
    ] {
        assert!(!d.contains(secret), "Debug leaked: {d}");
    }
}

/// The menu shows product names and fixed words: no server, dataset, or path.
#[tokio::test]
async fn tray_menu_lines_hold_names_of_products_only() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Codex);
    f.servers
        .lock()
        .unwrap()
        .push(FakeOps::stdio("qwxzvk-crm", "qwxzvk-server", &[]));
    f.status.lock().unwrap().paths[2].state = PathState::Unsupported;
    let (ctx, _dir, _) = ctx_with(&m, vec![f]);
    let v = overview::overview(&ctx).await.unwrap();
    let lines = inumaki_app_lib::tray::menu_lines(&v.cards);
    assert_eq!(lines, vec!["Fake harness: a path is not protected"]);
}

/// An unsupported path is red on the card with its reason, yellow on the
/// tray, and still greys on the card after Acknowledge (D4, 2026-10-12).
#[tokio::test]
async fn an_unsupported_path_is_red_on_the_card_and_not_on_the_tray() {
    use inumaki_app_lib::tray::{self, TrayColor};
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::Hermes);
    {
        let mut st = f.status.lock().unwrap();
        st.paths[1].state = PathState::Unsupported;
        st.paths[1].reason = Some(reason(ReasonCode::HermesFilesUnconfirmed));
    }
    let (ctx, _dir, _) = ctx_with(&m, vec![f]);
    let snap = inumaki_app_lib::poll::Snapshot {
        reachable: true,
        ..Default::default()
    };
    let tray_color = |ctx: &Ctx| {
        let cards = harness::cards::cards(ctx, &snap);
        tray::color(&harness::tray_input_from(&snap, &cards), &ctx.state())
    };
    let cards = harness::cards::cards(&ctx, &snap);
    let files = &cards[0].paths[1];
    assert_eq!(files.state, PathState::Unsupported);
    assert!(files.reason.is_some() && !files.acknowledged);
    assert_eq!(tray_color(&ctx), TrayColor::Yellow);
    assert_eq!(
        tray::menu_lines(&cards),
        vec!["Fake harness: a path is not protected"]
    );
    overview::acknowledge(&ctx, HarnessId::Hermes, PathKind::Files)
        .await
        .unwrap();
    let cards = harness::cards::cards(&ctx, &snap);
    assert!(cards[0].paths[1].acknowledged, "the card greys");
    assert_eq!(cards[0].paths[1].state, PathState::Unsupported);
    assert_eq!(tray_color(&ctx), TrayColor::Yellow);
}

/// The daemon facts adapters get match their contract and `inumaki connect`
/// (review 4b): a dataset runs with at least one running upstream, only
/// watching folders' outboxes are listed, and the hook program is the
/// service's `bin_dir` one, for status and for Connect alike.
#[tokio::test]
async fn system_view_matches_the_adapter_contract() {
    use inumaki_client::mock::Canned;
    use serde_json::json;
    use std::path::PathBuf;
    let m = MockDaemon::start().await;
    let mut st: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("status")).unwrap();
    let up = st["gateway"]["datasets"][0]["upstreams"][0].clone();
    let mut stopped = up.clone();
    stopped["name"] = "second".into();
    stopped["state"] = "stopped".into();
    st["gateway"]["datasets"][0]["upstreams"] = json!([up, stopped.clone()]);
    let mut down = st["gateway"]["datasets"][0].clone();
    down["id"] = "mcp-down".into();
    down["upstreams"] = json!([stopped]);
    st["gateway"]["datasets"].as_array_mut().unwrap().push(down);
    m.set("GET", "/v1/status", Canned::json(200, st));
    let mut f: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("folders")).unwrap();
    // The fixture grows with the folder cases; only watching folders count.
    let watching_outboxes: Vec<PathBuf> = f["folders"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["state"] == "watching")
        .map(|x| PathBuf::from(x["outbox"].as_str().unwrap()))
        .collect();
    assert!(!watching_outboxes.is_empty());
    let mut paused = f["folders"][0].clone();
    paused["dataset"] = "folder-paused".into();
    paused["outbox"] = "/Users/qwxzvk/Inumaki/paused/outbox".into();
    paused["state"] = "stopped".into();
    f["folders"].as_array_mut().unwrap().push(paused);
    m.set("GET", "/v1/folders", Canned::json(200, f));
    let svc: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("service")).unwrap();
    let hook = PathBuf::from(svc["bin_dir"].as_str().unwrap()).join("inumaki-hook");

    let (ctx, _dir, _) = ctx_with(&m, vec![]);
    let snap = inumaki_app_lib::poll::tick(&ctx).await;
    let v = harness::system_view(&ctx, &snap);
    assert_eq!(
        v.running_datasets,
        BTreeSet::from(["qwxzvk-kunde".to_string()]),
        "one running upstream is enough; none is not"
    );
    assert_eq!(v.folders_watching, watching_outboxes.len());
    assert_eq!(v.outboxes, watching_outboxes);
    assert_eq!(v.hook_command.as_ref(), Some(&hook));
    assert_eq!(harness::hook_command(&ctx, HarnessId::Codex), Some(hook));
    assert_eq!(harness::hook_command(&ctx, HarnessId::Hermes), None);
}

/// Re-review: the adapters drop a left-alone server from `total` by name.
/// Leaving only the user-scope `crm` must not hide the project-scope `crm`
/// (another account): a name is left alone only when every entry of it is.
#[tokio::test]
async fn leave_unprotected_names_need_every_scope_of_the_name() {
    let m = MockDaemon::start().await;
    let f = FakeOps::new(HarnessId::ClaudeCode);
    let mut local = FakeOps::stdio("crm", "/bin/sh", &[]);
    local.scope = Scope::Local("/home/fake/project".into());
    f.servers.lock().unwrap().extend([
        FakeOps::stdio("crm", "/bin/sh", &[]),
        local,
        FakeOps::stdio("notes", "/bin/sh", &[]),
    ]);
    let (ctx, _dir, _) = ctx_with(&m, vec![f.clone()]);
    let key = |n: &str, s: &Scope| harness::server_key(&ctx, HarnessId::ClaudeCode, n, s).unwrap();
    let (user_crm, local_crm, notes) = (
        key("crm", &Scope::User),
        key("crm", &Scope::Local("/home/fake/project".into())),
        key("notes", &Scope::User),
    );
    ctx.update_state(|s| {
        s.leave_unprotected.insert(user_crm);
        s.leave_unprotected.insert(notes);
    })
    .unwrap();
    let snap = inumaki_app_lib::poll::Snapshot::default();
    let v = harness::system_view(&ctx, &snap);
    assert_eq!(
        v.leave_unprotected["claude-code"],
        BTreeSet::from(["notes".to_string()]),
        "the project-scope crm still counts in total"
    );
    ctx.update_state(|s| {
        s.leave_unprotected.insert(local_crm);
    })
    .unwrap();
    let v = harness::system_view(&ctx, &snap);
    assert_eq!(
        v.leave_unprotected["claude-code"],
        BTreeSet::from(["crm".to_string(), "notes".to_string()])
    );
}
