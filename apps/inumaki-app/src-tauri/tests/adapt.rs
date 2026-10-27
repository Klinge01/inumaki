//! The seam against the real adapter crate (review C3): a Claude Code
//! configuration in a temporary home is listed, previewed, applied, and
//! reverted through `HarnessOps`; Debug and card data carry no value. The
//! real home and harness configs are never touched (`adapt::for_tests`).

use std::collections::BTreeSet;
use std::path::Path;

use inumaki_app_lib::harness::ops::*;
use inumaki_app_lib::harness::{adapt, client_harness, harness_key, route_name};
use inumaki_app_lib::paths::AppPaths;
use inumaki_client::{ClientKind, HarnessId, RoutePrefix};
use zeroize::Zeroizing;

const ORIGINAL: &str = r#"{
  "mcpServers": {
    "crm": { "command": "/bin/sh", "args": ["-c", "true"], "env": { "CRM_TOKEN": "hunter2-qwxzvk", "LOG_LEVEL": "debug" } }
  }
}
"#;
const BASE: &str = "http://127.0.0.1:8789";
const ANTHROPIC: &str = "http://127.0.0.1:8790/anthropic";

fn claude(root: &Path) -> (std::sync::Arc<dyn HarnessOps>, AppPaths) {
    let home = root.join("home");
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(home.join(".claude.json"), ORIGINAL).unwrap();
    let paths = AppPaths::under(&root.join("data"), &home);
    let ops = adapt::for_tests(&paths, &home)
        .into_iter()
        .find(|o| o.id() == HarnessId::ClaudeCode)
        .unwrap();
    // Detection is cached: nothing is known until `refresh`.
    assert!(ops.install().is_none());
    assert!(matches!(ops.servers(BASE), Err(OpError::NotInstalled)));
    ops.refresh();
    (ops, paths)
}

fn request() -> ConnectRequest {
    ConnectRequest {
        gateway_base: BASE.into(),
        gateway: Vec::new(),
        mirror_root: None,
        outboxes: Vec::new(),
        proxy: ProxyUrls::default(),
        hook_command: None,
        chat: false,
        client_header: None,
    }
}

#[test]
fn claude_code_round_trip_through_the_seam() {
    let dir = tempfile::tempdir().unwrap();
    let (ops, paths) = claude(dir.path());
    assert!(
        ops.install().is_some(),
        "configured without a binary is still detected"
    );
    let servers = ops.servers(BASE).unwrap();
    assert_eq!(servers.len(), 1);
    let crm = &servers[0];
    assert_eq!(crm.name, "crm");
    assert_eq!(crm.scope, Scope::User);
    assert!(
        crm.env
            .iter()
            .any(|(k, v)| k == "CRM_TOKEN" && v.as_str() == "hunter2-qwxzvk")
    );
    assert!(
        !format!("{crm:?}").contains("hunter2") && !format!("{crm:?}").contains("crm\""),
        "{crm:?}"
    );
    assert!(!ops.status(&SystemView::default()).grant);

    let req = ConnectRequest {
        gateway: vec![GatewayEntry {
            name: "crm".into(),
            scope: Scope::User,
            url: format!("{BASE}/mcp/mcp-crm"),
            token: Zeroizing::new("inumaki_gw_test".into()),
            approval_mode: None,
        }],
        ..request()
    };
    let preview = ops.preview(&req).unwrap();
    assert!(
        preview
            .iter()
            .any(|c| c.keys.iter().any(|k| k.contains("crm"))),
        "preview names the owned key"
    );
    assert_eq!(
        std::fs::read_to_string(paths.home.join(".claude.json")).unwrap(),
        ORIGINAL,
        "preview writes nothing"
    );

    let backup = ops.apply(&req).unwrap();
    assert!(
        backup.split('-').next().unwrap().parse::<i64>().is_ok(),
        "backup ids start with unix seconds: {backup}"
    );
    let written = std::fs::read_to_string(paths.home.join(".claude.json")).unwrap();
    assert!(
        written.contains("/mcp/mcp-crm") && !written.contains("hunter2"),
        "{written}"
    );
    assert_eq!(ops.active_backup().as_deref(), Some(backup.as_str()));
    let back = ops.servers(BASE).unwrap();
    assert_eq!(back[0].gateway_dataset.as_deref(), Some("mcp-crm"));

    // A backup id is a directory name: anything else is refused.
    assert!(matches!(
        ops.revert("../../../etc"),
        Err(OpError::Failed("backup_unreadable"))
    ));
    let r = ops.revert(&backup).unwrap();
    assert!(r.reverted && !r.client_header_left);
    let restored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(paths.home.join(".claude.json")).unwrap())
            .unwrap();
    assert_eq!(
        restored,
        serde_json::from_str::<serde_json::Value>(ORIGINAL).unwrap()
    );
    assert_eq!(ops.active_backup(), None);
}

#[test]
fn definition_ids_are_keyed_and_never_merge_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let (ops, paths) = claude(dir.path());
    let mut e = ops.servers(BASE).unwrap().remove(0);
    let a = adapt::definition_id(&paths.data_dir, &e).unwrap();
    assert_eq!(
        a,
        adapt::definition_id(&paths.data_dir, &e).unwrap(),
        "stable with the same key"
    );
    e.env.iter_mut().find(|(k, _)| k == "CRM_TOKEN").unwrap().1 =
        Zeroizing::new("another-account".into());
    assert_ne!(
        a,
        adapt::definition_id(&paths.data_dir, &e).unwrap(),
        "another account is another definition"
    );
    adapt::record_definition(&paths.data_dir, a.clone(), "mcp-crm".into()).unwrap();
    assert_eq!(
        adapt::definition_dataset(&paths.data_dir, &a)
            .unwrap()
            .as_deref(),
        Some("mcp-crm")
    );
    assert_eq!(
        adapt::dataset_id("@scope/x", &BTreeSet::new()),
        "mcp-scope-x"
    );
    assert_eq!(
        adapt::mail_entry_name(1, &BTreeSet::new()),
        "inumaki-mail-2"
    );
}

/// One server, one definition id: an env value that is not a string has no
/// value in the app's entry, but its name is part of the id exactly as in
/// `inumaki connect --protect` (otherwise the two mint different ids for the
/// same entry and Protect makes duplicate datasets).
#[test]
fn a_non_string_env_value_gives_the_cli_definition_id() {
    use inumaki_adapters as ad;
    let dir = tempfile::tempdir().unwrap();
    let (ops, paths) = claude(dir.path());
    std::fs::write(
        dir.path().join("home").join(".claude.json"),
        r#"{ "mcpServers": { "crm": { "command": "/bin/sh", "args": ["-c", "true"],
             "env": { "CRM_TOKEN": "hunter2-qwxzvk", "PORT": 8080, "DEBUG": true } } } }"#,
    )
    .unwrap();
    let e = ops.servers(BASE).unwrap().remove(0);
    assert_eq!(e.env.len(), 1, "only the string value is carried");
    let mut unvalued = e.unvalued_env.clone();
    unvalued.sort();
    assert_eq!(unvalued, ["DEBUG", "PORT"]);
    let app = adapt::definition_id(&paths.data_dir, &e).unwrap();
    // The CLI hashes the adapter's entry: every name, only string values.
    let cli_entry = ad::McpServerEntry {
        name: "crm".into(),
        scope: ad::Scope::User,
        transport: ad::Transport::Stdio {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), "true".into()],
            cwd: None,
        },
        env_names: vec!["CRM_TOKEN".into(), "PORT".into(), "DEBUG".into()],
        header_names: Vec::new(),
        values: [(
            "env:CRM_TOKEN".to_string(),
            Zeroizing::new("hunter2-qwxzvk".to_string()),
        )]
        .into_iter()
        .collect(),
        gateway: false,
        needs_oauth: false,
        approval_mode: None,
    };
    let cli = ad::protect::DefinitionIndex::load(&paths.data_dir)
        .unwrap()
        .id_for(&cli_entry);
    assert_eq!(app, cli, "the app never mints an id the CLI would not");
    assert!(
        !format!("{e:?}").contains("PORT"),
        "Debug stays counts only"
    );
}

#[test]
fn login_path_ignores_banners() {
    use inumaki_app_lib::harness::shell::extract;
    assert_eq!(
        extract("Welcome!\n__INUMAKI_PATH_START__/opt/homebrew/bin:/usr/bin__INUMAKI_PATH_END__")
            .as_deref(),
        Some("/opt/homebrew/bin:/usr/bin")
    );
    assert_eq!(extract("no sentinel"), None);
}

/// The app's route and client strings (`harness::route_name`,
/// `harness::client_harness`) are the ones the adapters understand.
#[test]
fn route_and_client_names_reach_the_adapter() {
    for (k, h) in [
        (ClientKind::ClaudeCode, HarnessId::ClaudeCode),
        (ClientKind::Codex, HarnessId::Codex),
        (ClientKind::Hermes, HarnessId::Hermes),
        (ClientKind::Openclaw, HarnessId::Openclaw),
    ] {
        let s = client_harness(k).unwrap();
        assert_eq!(s, harness_key(h));
        assert_eq!(
            inumaki_adapters::HarnessId::parse(s).map(|x| x.as_str()),
            Some(s)
        );
    }
    assert_eq!(client_harness(ClientKind::Other), None);

    let dir = tempfile::tempdir().unwrap();
    let (ops, _paths) = claude(dir.path());
    let req = ConnectRequest {
        proxy: ProxyUrls {
            anthropic: Some(ANTHROPIC.into()),
            ..ProxyUrls::default()
        },
        client_header: Some(Zeroizing::new("hdr-canary-zyx".into())),
        chat: true,
        ..request()
    };
    ops.apply(&req).unwrap();
    let chat = |sys: &SystemView| {
        ops.status(sys)
            .paths
            .into_iter()
            .find(|p| p.path == PathKind::Chat)
            .unwrap()
    };
    let mut sys = SystemView {
        service_up: true,
        gateway_listen: Some("127.0.0.1:8789".into()),
        proxy: ProxyUrls {
            anthropic: Some(ANTHROPIC.into()),
            ..ProxyUrls::default()
        },
        ..SystemView::default()
    };
    sys.failing_routes
        .insert(route_name(RoutePrefix::Anthropic).into());
    let failing = chat(&sys);
    assert_eq!(failing.state, PathState::Broken);
    assert_eq!(failing.reason.map(|r| r.code), Some("route_failing"));

    sys.failing_routes.clear();
    assert_eq!(
        chat(&sys).reason.map(|r| r.code),
        Some("no_traffic_yet"),
        "no client seen yet"
    );
    sys.proxy_clients
        .insert(client_harness(ClientKind::ClaudeCode).unwrap().into());
    let seen = chat(&sys);
    assert_eq!(seen.state, PathState::Connected);
    assert_eq!(seen.reason, None);
}

/// Only macOS withholding a grant (`EPERM`) shows the grant card; a file
/// mode or owner (`EACCES`, e.g. root-owned after `sudo`) does not, since
/// System Settings cannot fix it.
#[test]
fn only_a_withheld_grant_asks_for_the_grant() {
    use std::os::unix::fs::PermissionsExt;
    assert!(adapt::grant_needed(&std::io::Error::from_raw_os_error(1)));
    assert!(!adapt::grant_needed(&std::io::Error::from_raw_os_error(13)));
    let dir = tempfile::tempdir().unwrap();
    let (ops, paths) = claude(dir.path());
    let f = paths.home.join(".claude.json");
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
    let grant = ops.status(&SystemView::default()).grant;
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!grant, "EACCES is no grant problem");
}

#[test]
fn login_path_values_must_read_as_a_path() {
    use inumaki_app_lib::harness::shell::extract;
    let w = |p: &str| format!("__INUMAKI_PATH_START__{p}__INUMAKI_PATH_END__");
    assert_eq!(extract(&w("/usr/bin")).as_deref(), Some("/usr/bin"));
    assert_eq!(
        extract(&w("/My Tools/bin:/usr/bin")).as_deref(),
        Some("/My Tools/bin:/usr/bin")
    );
    for bad in [
        "",
        "usr/bin",
        "/a /b",
        "/usr/bin:relative",
        "Unknown option -lc",
    ] {
        assert_eq!(extract(&w(bad)), None, "{bad}");
    }
}

/// Integrator ruling 2026-10-10: the real Codex adapter behind the seam
/// reports `approval_policy = "never"` as the fixed `codex_approval_never`
/// reason when the request writes a gateway entry, and nothing otherwise.
/// The text holds no value or path from the file.
#[test]
fn codex_approval_never_reaches_the_app_as_a_fixed_reason() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    let cfg = home.join(".codex/config.toml");
    std::fs::write(
        &cfg,
        "approval_policy = \"never\"\n\n[mcp_servers.crm]\ncommand = \"/opt/qwxzvk-crm\"\n",
    )
    .unwrap();
    let paths = AppPaths::under(&dir.path().join("data"), &home);
    let ops = adapt::for_tests(&paths, &home)
        .into_iter()
        .find(|o| o.id() == HarnessId::Codex)
        .unwrap();
    ops.refresh();
    let gw = ConnectRequest {
        gateway: vec![GatewayEntry {
            name: "crm".into(),
            scope: Scope::User,
            url: format!("{BASE}/mcp/mcp-crm"),
            token: Zeroizing::new("inumaki_gw_test".into()),
            approval_mode: None,
        }],
        ..request()
    };
    let w = ops.connect_warnings(&gw);
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].code, "codex_approval_never");
    for leak in ["qwxzvk", "crm", "/opt", &*home.to_string_lossy()] {
        assert!(!w[0].text.contains(leak), "{leak}");
    }
    assert!(
        ops.connect_warnings(&request()).is_empty(),
        "no gateway entry"
    );
    std::fs::write(&cfg, "approval_policy = \"untrusted\"\n").unwrap();
    assert!(ops.connect_warnings(&gw).is_empty());
}

/// Follow-up ruling (lane L5, 2026-10-10) through the real Codex adapter:
/// the user's `default_tools_approval_mode` on an applied gateway entry is
/// listed with the server, survives the app's revert-then-apply when the
/// request carries it, leaves the MCP path connected, and suppresses the
/// approval warning.
#[test]
fn codex_user_approval_mode_survives_the_apps_reconnect() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    let cfg = home.join(".codex/config.toml");
    std::fs::write(
        &cfg,
        "approval_policy = \"never\"\n\n[mcp_servers.crm]\ncommand = \"/opt/crm\"\n",
    )
    .unwrap();
    let paths = AppPaths::under(&dir.path().join("data"), &home);
    let ops = adapt::for_tests(&paths, &home)
        .into_iter()
        .find(|o| o.id() == HarnessId::Codex)
        .unwrap();
    ops.refresh();
    let req = |mode: Option<serde_json::Value>| ConnectRequest {
        gateway: vec![GatewayEntry {
            name: "crm".into(),
            scope: Scope::User,
            url: format!("{BASE}/mcp/mcp-crm"),
            token: Zeroizing::new("inumaki_gw_test".into()),
            approval_mode: mode,
        }],
        ..request()
    };
    let b = ops.apply(&req(None)).unwrap();
    let t = std::fs::read_to_string(&cfg).unwrap();
    assert!(!t.contains("default_tools_approval_mode"));
    std::fs::write(
        &cfg,
        t.replace(
            "startup_timeout_sec = 30\n",
            "startup_timeout_sec = 30\ndefault_tools_approval_mode = \"approve\"\n",
        ),
    )
    .unwrap();
    // Read before the revert, as `build` does.
    let mode = ops.servers(BASE).unwrap()[0].approval_mode.clone();
    assert_eq!(mode.as_ref().and_then(|v| v.as_str()), Some("approve"));
    assert!(ops.connect_warnings(&req(mode.clone())).is_empty());
    let r = ops.revert(&b).unwrap();
    assert_eq!(r.conflicts, 0, "the user's key goes with the entry");
    assert!(!std::fs::read_to_string(&cfg).unwrap().contains("approve"));
    ops.apply(&req(mode)).unwrap();
    let t = std::fs::read_to_string(&cfg).unwrap();
    assert!(
        t.contains("default_tools_approval_mode = \"approve\""),
        "{t}"
    );
    let mut sys = SystemView {
        gateway_listen: Some("127.0.0.1:8789".into()),
        service_up: true,
        ..SystemView::default()
    };
    sys.running_datasets.insert("mcp-crm".into());
    let st = ops.status(&sys);
    assert_eq!(st.paths[0].state, PathState::Connected, "{:?}", st.paths[0]);
}

const OPENAI: &str = "http://127.0.0.1:8790/openai";
const CODEX: &str = "http://127.0.0.1:8790/codex";

/// The harnesses whose chat is an opt-in in the app: all four.
const ALL: [HarnessId; 4] = [
    HarnessId::ClaudeCode,
    HarnessId::Codex,
    HarnessId::Hermes,
    HarnessId::Openclaw,
];

/// A home with `h` configured for an API-key login whose selected provider
/// has a proxy route (Claude Code: the shared `.claude.json`).
fn configure(h: HarnessId, home: &Path) {
    let write = |rel: &str, body: &str| {
        let f = home.join(rel);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, body).unwrap();
    };
    match h {
        HarnessId::ClaudeCode => {
            std::fs::create_dir_all(home.join(".claude")).unwrap();
            write(".claude.json", ORIGINAL);
        }
        HarnessId::Codex => {
            write(
                ".codex/auth.json",
                "{\"OPENAI_API_KEY\": \"sk-qwxzvk\", \"tokens\": null}",
            );
            write(".codex/config.toml", "model = \"gpt-5-codex\"\n");
        }
        HarnessId::Hermes => {
            write(
                ".hermes/config.yaml",
                "model:\n  provider: openai\n  default: gpt-5\n",
            );
            write(".hermes/.env", "OPENAI_API_KEY=sk-qwxzvk\n");
        }
        HarnessId::Openclaw => write(
            ".openclaw/openclaw.json",
            "{ agents: { defaults: { model: { primary: 'openai/gpt-5' } } }, models: { providers: { openai: { apiKey: '${OPENAI_API_KEY}' } } } }\n",
        ),
    }
}

/// The file `h`'s chat route is written to.
fn chat_file(h: HarnessId, home: &Path) -> String {
    let rel = match h {
        HarnessId::ClaudeCode => ".claude/settings.json",
        HarnessId::Codex => ".codex/config.toml",
        HarnessId::Hermes => ".hermes/config.yaml",
        HarnessId::Openclaw => ".openclaw/openclaw.json",
    };
    std::fs::read_to_string(home.join(rel)).unwrap_or_default()
}

/// `text` (the chat file) routes chat through a proxy at `base` (no
/// trailing slash) and carries the client header `header`.
fn routes(text: &str, base: &str, header: &str) -> bool {
    text.contains(base) && text.contains(header)
}

/// `h`'s `HarnessOps` over the real adapter in `home`, detected.
fn real_ops(h: HarnessId, root: &Path) -> (std::sync::Arc<dyn HarnessOps>, AppPaths) {
    let home = root.join("home");
    configure(h, &home);
    let paths = AppPaths::under(&root.join("data"), &home);
    let ops = adapt::for_tests(&paths, &home)
        .into_iter()
        .find(|o| o.id() == h)
        .unwrap();
    ops.refresh();
    (ops, paths)
}

/// The real adapters (a FakeOps cannot fail here): chat is an opt-in for
/// every harness. Without it Connect writes neither the chat route nor the
/// client header line; with it, both, and the backup it makes is the one
/// the derived switch reads.
#[test]
fn chat_is_written_only_when_opted_in() {
    let req = |on: bool| ConnectRequest {
        proxy: ProxyUrls {
            anthropic: Some(ANTHROPIC.into()),
            openai: Some(OPENAI.into()),
            codex: Some(CODEX.into()),
        },
        client_header: Some(Zeroizing::new("hdr-canary-zyx".into())),
        chat: on,
        ..request()
    };
    for h in ALL {
        let dir = tempfile::tempdir().unwrap();
        let (ops, paths) = real_ops(h, dir.path());
        let backup = ops.apply(&req(false)).unwrap();
        let off = chat_file(h, &paths.home);
        assert!(!off.contains("127.0.0.1:8790"), "{h:?}: {off}");
        assert!(!off.contains("hdr-canary-zyx"), "{h:?}: {off}");
        assert!(!ops.chat_route_in_backup(), "{h:?}");
        assert!(
            ops.connect_warnings(&req(false)).is_empty(),
            "{h:?}: no chat warning without chat"
        );
        ops.revert(&backup).unwrap();

        let w = ops.connect_warnings(&req(true));
        assert_eq!(
            w.len(),
            1,
            "{h:?}: {:?}",
            w.iter().map(|r| r.code).collect::<Vec<_>>()
        );
        assert!(w[0].code.ends_with("_chat_live"), "{h:?}: {}", w[0].code);
        let backup = ops.apply(&req(true)).unwrap();
        let on = chat_file(h, &paths.home);
        assert!(
            routes(&on, "http://127.0.0.1:8790/", "hdr-canary-zyx"),
            "{h:?}: {on}"
        );
        assert!(ops.chat_route_in_backup(), "{h:?}");
        ops.revert(&backup).unwrap();
    }

    // Codex with a ChatGPT login: the same switch gates the codex route.
    let dir = tempfile::tempdir().unwrap();
    let (ops, paths) = real_ops(HarnessId::Codex, dir.path());
    std::fs::write(
        paths.home.join(".codex/auth.json"),
        "{\"OPENAI_API_KEY\": null, \"tokens\": {\"id_token\": \"x\"}}",
    )
    .unwrap();
    ops.refresh();
    assert!(matches!(ops.install().unwrap().login, Login::Oauth));
    let b = ops.apply(&req(false)).unwrap();
    assert!(!chat_file(HarnessId::Codex, &paths.home).contains(CODEX));
    ops.revert(&b).unwrap();
    let b = ops.apply(&req(true)).unwrap();
    let on = chat_file(HarnessId::Codex, &paths.home);
    assert!(routes(&on, CODEX, "hdr-canary-zyx"), "{on}");
    ops.revert(&b).unwrap();
}

/// A `Ctx` over the real adapters in a temporary home with `h` configured.
fn real_ctx(
    h: HarnessId,
    root: &Path,
    m: &inumaki_client::mock::MockDaemon,
) -> (inumaki_app_lib::ctx::Ctx, AppPaths) {
    let home = root.join("home");
    configure(h, &home);
    let paths = AppPaths::under(&root.join("data"), &home);
    let (ctx, _) = inumaki_app_lib::ctx::Ctx::for_tests(paths.clone(), m.client());
    (ctx.with_harnesses(adapt::for_tests(&paths, &home)), paths)
}

/// The proxy fixture's base URL and client header value.
const PROXY: &str = "http://127.0.0.1:8787/";
const HEADER: &str = "inumaki_client_qwxzvk";

/// With no choice made (`None`), a harness that already routes chat (a
/// route written before the pref existed, or by the CLI) keeps it through
/// Reconnect; a choice of `Some(false)` drops it.
#[tokio::test]
async fn reconnect_keeps_a_chat_route_the_files_already_hold() {
    use inumaki_app_lib::harness::connect;
    use inumaki_client::mock::MockDaemon;

    for h in ALL {
        let m = MockDaemon::start().await;
        let dir = tempfile::tempdir().unwrap();
        let (ctx, paths) = real_ctx(h, dir.path(), &m);
        let key = harness_key(h);
        let routed = || routes(&chat_file(h, &paths.home), PROXY, HEADER);
        let set = |on: Option<bool>| {
            ctx.update_state(|s| match on {
                Some(on) => {
                    s.prefs.chat_opt_in.insert(key.into(), on);
                }
                None => {
                    s.prefs.chat_opt_in.remove(key);
                }
            })
            .unwrap();
        };
        let effective = || async {
            inumaki_app_lib::commands::settings::prefs(&ctx)
                .await
                .unwrap()
                .chat_effective[key]
        };

        // The CLI's default: a chat route with no pref in `state.json`.
        set(Some(true));
        connect::connect(&ctx, h).await.unwrap();
        assert!(routed(), "{h:?}: {}", chat_file(h, &paths.home));
        set(None);
        assert!(
            effective().await,
            "{h:?}: the switch shows the route the files hold"
        );

        connect::reconnect(&ctx, h).await.unwrap();
        assert!(routed(), "{h:?}: {}", chat_file(h, &paths.home));
        assert_eq!(
            ctx.state().prefs.chat_opt_in.get(key),
            Some(&true),
            "{h:?}: the apply saved the choice the backup stood for"
        );
        set(None);

        // The proxy down must not turn the effective value off: it is read
        // from the active backup, not from the chat path's status.
        m.set(
            "GET",
            "/v1/proxy",
            inumaki_client::mock::Canned::error(503, "unavailable", "down", &[]),
        );
        assert!(effective().await, "{h:?}: the backup holds the route");

        // An explicit "off" removes it on the next Reconnect.
        set(Some(false));
        m.set(
            "GET",
            "/v1/proxy",
            inumaki_client::mock::Canned::json(
                200,
                serde_json::from_str(inumaki_client::contract::fixture("proxy")).unwrap(),
            ),
        );
        connect::reconnect(&ctx, h).await.unwrap();
        let after = chat_file(h, &paths.home);
        assert!(
            !after.contains(PROXY) && !after.contains(HEADER),
            "{h:?}: {after}"
        );

        // No choice and a backup without the route: effective is off.
        set(None);
        assert!(!effective().await, "{h:?}: the backup holds no route");
    }
}

/// With no choice made, a refresh while the proxy is not running skips the
/// chat route, and the backup it makes holds none. The apply saves the
/// choice first, so the route comes back on the next Reconnect with the
/// proxy running instead of being lost for good.
#[tokio::test]
async fn an_apply_with_the_proxy_down_does_not_lose_the_chat_route() {
    use inumaki_app_lib::harness::connect;
    use inumaki_client::mock::{Canned, MockDaemon};

    for h in ALL {
        let m = MockDaemon::start().await;
        let dir = tempfile::tempdir().unwrap();
        let (ctx, paths) = real_ctx(h, dir.path(), &m);
        let key = harness_key(h);
        let routed = || chat_file(h, &paths.home).contains(PROXY);
        let running: serde_json::Value =
            serde_json::from_str(inumaki_client::contract::fixture("proxy")).unwrap();

        // A route in the backup and no choice in `state.json`.
        ctx.update_state(|s| {
            s.prefs.chat_opt_in.insert(key.into(), true);
        })
        .unwrap();
        connect::connect(&ctx, h).await.unwrap();
        assert!(routed(), "{h:?}");
        ctx.update_state(|s| {
            s.prefs.chat_opt_in.remove(key);
        })
        .unwrap();

        // A data-change refresh while the proxy failed to bind: the route is skipped.
        let mut down = running.clone();
        down["state"] = serde_json::json!("bind_failed");
        m.set("GET", "/v1/proxy", Canned::json(200, down));
        assert!(connect::refresh_connected(&ctx).await.is_empty(), "{h:?}");
        assert!(!routed(), "{h:?}: {}", chat_file(h, &paths.home));
        assert_eq!(ctx.state().prefs.chat_opt_in.get(key), Some(&true), "{h:?}");

        // The proxy is back: a Reconnect writes the route again.
        m.set("GET", "/v1/proxy", Canned::json(200, running));
        connect::reconnect(&ctx, h).await.unwrap();
        assert!(routed(), "{h:?}: {}", chat_file(h, &paths.home));
        assert_eq!(ctx.state().prefs.chat_opt_in.get(key), Some(&true), "{h:?}");
    }
}

/// Integrator ruling (Task 6 fix round 1): the app before M9 routed the
/// chat of an API-key Codex on every Connect. A `state.json` from then (no
/// `chat_opt_in`) whose last apply ran with the proxy down holds a backup
/// without the chat record; the migration saves the choice "on" once the
/// login kind is known, so the next Reconnect writes the route again.
#[tokio::test]
async fn a_pre_m9_state_keeps_an_api_key_codex_chat_route() {
    use inumaki_app_lib::ctx::Ctx;
    use inumaki_app_lib::harness::connect;
    use inumaki_client::mock::MockDaemon;

    let m = MockDaemon::start().await;
    let dir = tempfile::tempdir().unwrap();
    let h = HarnessId::Codex;
    let (ctx, paths) = real_ctx(h, dir.path(), &m);
    // The last pre-upgrade apply wrote no chat route.
    ctx.update_state(|s| {
        s.prefs.chat_opt_in.insert("codex".into(), false);
    })
    .unwrap();
    connect::connect(&ctx, h).await.unwrap();
    assert!(!chat_file(h, &paths.home).contains(PROXY));
    let codex = ctx.harnesses.iter().find(|o| o.id() == h).unwrap();
    assert!(!codex.chat_route_in_backup());

    // The same state.json as the app before M9 wrote it.
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&paths.state_file).unwrap()).unwrap();
    v["prefs"] = serde_json::json!({ "first_run_done": true, "codex_chatgpt_opt_in": false });
    std::fs::write(&paths.state_file, v.to_string()).unwrap();
    let (ctx, _) = Ctx::for_tests(paths.clone(), m.client());
    let ctx = ctx.with_harnesses(adapt::for_tests(&paths, &paths.home));
    assert!(ctx.state().prefs.chat_migration_pending);
    assert!(ctx.state().prefs.chat_opt_in.is_empty());

    // Start-up detection (the poller) knows the login kind: the choice is saved.
    ctx.harnesses.iter().for_each(|o| o.refresh());
    connect::migrate_pre_m9_chat(&ctx, true);
    assert!(!ctx.state().prefs.chat_migration_pending);
    assert_eq!(ctx.state().prefs.chat_opt_in.get("codex"), Some(&true));
    assert!(
        inumaki_app_lib::commands::settings::prefs(&ctx)
            .await
            .unwrap()
            .chat_effective["codex"]
    );

    connect::reconnect(&ctx, h).await.unwrap();
    let after = chat_file(h, &paths.home);
    assert!(routes(&after, PROXY, HEADER), "{after}");

    // Saved once: a later state.json is not migrated again.
    let st = inumaki_app_lib::appstate::load(&paths.state_file);
    assert!(!st.prefs.chat_migration_pending);
}

/// A real adapter in a temporary home, detected.
fn harness_in(
    root: &Path,
    id: HarnessId,
    files: &[(&str, &str)],
) -> std::sync::Arc<dyn HarnessOps> {
    let home = root.join("home");
    for (rel, body) in files {
        let p = home.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    let paths = AppPaths::under(&root.join("data"), &home);
    let ops = adapt::for_tests(&paths, &home)
        .into_iter()
        .find(|o| o.id() == id)
        .unwrap();
    ops.refresh();
    ops
}

/// The manual-setup lines come from the seam on demand: Hermes with a
/// subscription login gets the Codex route and the fixed note; no value of
/// the client header appears; without a proxy route there is nothing.
#[test]
fn hermes_manual_setup_comes_on_demand_without_the_header() {
    let dir = tempfile::tempdir().unwrap();
    let ops = harness_in(
        dir.path(),
        HarnessId::Hermes,
        &[
            (".hermes/config.yaml", "model:\n  provider: openai-codex\n"),
            (
                ".hermes/auth.json",
                "{\"active_provider\": \"openai-codex\"}",
            ),
        ],
    );
    let sys = SystemView {
        service_up: true,
        proxy: ProxyUrls {
            codex: Some("http://127.0.0.1:8787/codex".into()),
            ..Default::default()
        },
        client_header: Some(Zeroizing::new("inumaki_client_qwxzvk".into())),
        ..Default::default()
    };
    let m = ops
        .manual_setup(&sys)
        .expect("lines for a subscription login");
    assert!(
        m.lines
            .contains("HERMES_CODEX_BASE_URL=http://127.0.0.1:8787/codex"),
        "{}",
        m.lines
    );
    assert_eq!(
        m.note,
        "Hermes OAuth sends no client header, so only session tokens are restored."
    );
    assert!(!m.lines.contains("qwxzvk") && !m.note.contains("qwxzvk"));
    // The card itself carries no path or URL.
    let status = serde_json::to_string(&ops.status(&sys).paths).unwrap();
    assert!(
        !status.contains("8787") && !status.contains(".hermes"),
        "{status}"
    );
    assert!(ops.manual_setup(&SystemView::default()).is_none());
}

/// OpenClaw: a Docker sandbox with the mirror outside the workspace roots
/// gets the bind line; inside a root, or without a mirror, nothing.
#[test]
fn openclaw_manual_setup_is_the_bind_outside_the_workspace_roots() {
    let dir = tempfile::tempdir().unwrap();
    let ops = harness_in(
        dir.path(),
        HarnessId::Openclaw,
        &[(
            ".openclaw/openclaw.json",
            r#"{ agents: { defaults: { workspace: "/work/agents", sandbox: { docker: {} } } } }"#,
        )],
    );
    let sys = |mirror: &str| SystemView {
        service_up: true,
        mirror_root: Some(mirror.into()),
        folders_watching: 1,
        ..Default::default()
    };
    let m = ops.manual_setup(&sys("/mirror/root")).expect("bind lines");
    assert!(
        m.lines.contains("/mirror/root:/mirror/root:ro"),
        "{}",
        m.lines
    );
    assert!(
        m.note
            .contains("dangerouslyAllowExternalBindSources is true")
    );
    assert!(ops.manual_setup(&sys("/work/agents/mirror")).is_none());
    assert!(ops.manual_setup(&SystemView::default()).is_none());
}

/// Ruling L97 through the real adapters: a Connect whose request installs
/// the hook (the app sets `hook_command` for Claude Code and Codex, see
/// `harness::hook_command`) carries the fixed `hook_blocks_when_stopped`
/// reason into the connect outcome's `harness_warnings`; Hermes Agent and
/// OpenClaw install no hook and get none. The text names no path.
#[test]
fn the_hook_warning_reaches_the_app_exactly_when_the_hook_is_installed() {
    for h in ALL {
        let dir = tempfile::tempdir().unwrap();
        let (ops, paths) = real_ops(h, dir.path());
        let hook = paths.bin_dir.join("inumaki-hook");
        let req = ConnectRequest {
            hook_command: Some(hook.clone()),
            ..request()
        };
        let w = ops.connect_warnings(&req);
        let codes: Vec<&str> = w.iter().map(|r| r.code).collect();
        match h {
            HarnessId::ClaudeCode | HarnessId::Codex => {
                assert_eq!(codes, ["hook_blocks_when_stopped"], "{h:?}");
                assert_eq!(
                    w[0].text,
                    inumaki_adapters::ConnectWarning::HookBlocksWhenStopped.sentence()
                );
                assert!(!w[0].text.contains(&*hook.to_string_lossy()));
                assert!(!w[0].text.contains('/'), "{}", w[0].text);
            }
            HarnessId::Hermes | HarnessId::Openclaw => assert!(codes.is_empty(), "{h:?}"),
        }
        assert!(
            ops.connect_warnings(&request()).is_empty(),
            "{h:?}: no hook"
        );
    }
}
