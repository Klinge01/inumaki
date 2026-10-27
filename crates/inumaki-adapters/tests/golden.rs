//! Golden files (spec §11): per harness, login kind, and path selection,
//! apply to the inputs, compare with the expected values and bytes, then
//! revert and compare with the inputs. `INUMAKI_BLESS=1` writes missing
//! `*.expected` files; a reviewer reads every blessed file against spec §4.3.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use inumaki_adapters::edit::parse_standard;
use inumaki_adapters::*;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Case {
    harness: String,
    /// Role (snake_case) → input file in the case directory.
    files: BTreeMap<String, String>,
    /// Extra files relative to the home (auth.json, .env, credentials).
    #[serde(default)]
    home_files: BTreeMap<String, String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    plan: PlanSpec,
    #[serde(default)]
    expect: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize, Default)]
struct PlanSpec {
    gateway: Option<GatewaySpec>,
    files: Option<FilesSpec>,
    chat: Option<ChatSpec>,
    hook: Option<HookSpec>,
    /// `GET /v1/proxy` `client_header` (a fake value in the cases).
    proxy_client_header: Option<String>,
}
#[derive(Deserialize)]
struct GatewaySpec {
    token: String,
    entries: Vec<EntrySpec>,
}
#[derive(Deserialize)]
struct EntrySpec {
    name: String,
    #[serde(default)]
    project: Option<String>,
    url: String,
}
#[derive(Deserialize)]
struct FilesSpec {
    mirror_root: PathBuf,
    #[serde(default)]
    outboxes: Vec<PathBuf>,
}
#[derive(Deserialize)]
struct ChatSpec {
    anthropic: Option<String>,
    openai: Option<String>,
    codex: Option<String>,
    #[serde(default)]
    codex_chatgpt: bool,
}
#[derive(Deserialize)]
struct HookSpec {
    command: PathBuf,
    socket: PathBuf,
}

fn plan(spec: &PlanSpec, data_dir: &Path) -> ConnectPlan {
    ConnectPlan {
        data_dir: data_dir.to_path_buf(),
        gateway_base: "http://127.0.0.1:8789".to_string(),
        gateway: spec.gateway.as_ref().map(|g| GatewayPlan {
            token: Zeroizing::new(g.token.clone()),
            entries: g
                .entries
                .iter()
                .map(|e| GatewayEntry {
                    name: e.name.clone(),
                    scope: e.project.clone().map_or(Scope::User, Scope::Project),
                    url: e.url.clone(),
                    approval_mode: None,
                })
                .collect(),
        }),
        files: spec.files.as_ref().map(|f| FilesPlan {
            mirror_root: f.mirror_root.clone(),
            outboxes: f.outboxes.clone(),
        }),
        chat: spec.chat.as_ref().map(|c| ChatPlan {
            anthropic: c.anthropic.clone(),
            openai: c.openai.clone(),
            codex: c.codex.clone(),
            codex_chatgpt: c.codex_chatgpt,
        }),
        hook: spec.hook.as_ref().map(|h| HookPlan {
            command: h.command.clone(),
            socket: h.socket.clone(),
        }),
        proxy_client_header: spec
            .proxy_client_header
            .as_ref()
            .map(|v| ClientHeader::new(Zeroizing::new(v.clone()))),
    }
}

fn role_name(r: FileRole) -> String {
    serde_json::to_value(r)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn run_case(dir: &Path) {
    let case: Case =
        serde_json::from_str(&std::fs::read_to_string(dir.join("case.json")).unwrap()).unwrap();
    let h = HarnessId::parse(&case.harness).unwrap();
    let ad = adapter(h);
    let home = tempfile::tempdir().unwrap();
    let mut env = ProbeEnv::for_tests(home.path());
    env.env = case.env.clone();
    for (rel, src) in &case.home_files {
        let p = home.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::copy(dir.join(src), p).unwrap();
    }
    let mut inputs: BTreeMap<FileRole, (PathBuf, Option<Vec<u8>>)> = BTreeMap::new();
    for f in ad.config_files(&env) {
        let input = case
            .files
            .get(&role_name(f.role))
            .map(|src| std::fs::read(dir.join(src)).unwrap());
        if let Some(bytes) = &input {
            std::fs::create_dir_all(f.path.parent().unwrap()).unwrap();
            std::fs::write(&f.path, bytes).unwrap();
        }
        inputs.insert(f.role, (f.path.clone(), input));
    }
    let inst = ad
        .detect(&env)
        .unwrap_or_else(|| panic!("{}: not detected", dir.display()));
    if let Some(l) = &case.login {
        assert_eq!(
            format!("{:?}", inst.login).to_lowercase(),
            l.replace('_', ""),
            "{}: login kind",
            dir.display()
        );
    }
    let data = home.path().join("data");
    // Read before the write, as the CLI and the app do.
    let warnings = ad.connect_warnings(&inst, &plan(&case.plan, &data));
    let result = ad.apply(&inst, &plan(&case.plan, &data));
    if let Some(err) = &case.error {
        let e = result
            .err()
            .unwrap_or_else(|| panic!("{}: expected {err}", dir.display()));
        assert!(
            matches!(e, AdapterError::CannotEditSafely { .. }) || err != "cannot_edit_safely",
            "{}: {e}",
            dir.display()
        );
        for (path, input) in inputs.values() {
            assert_eq!(
                std::fs::read(path).ok(),
                *input,
                "{}: a refused apply wrote nothing",
                dir.display()
            );
        }
        return;
    }
    let backup = result.unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    // Ruling L97: the fail-closed hook warning is given exactly when the
    // apply installs the hook (no input holds a hook entry before).
    let hook_written = inst
        .config_files
        .iter()
        .any(|f| std::fs::read_to_string(&f.path).is_ok_and(|t| t.contains(harness::HOOK_MARKER)));
    assert_eq!(
        warnings.contains(&ConnectWarning::HookBlocksWhenStopped),
        hook_written,
        "{}: hook warning {warnings:?}",
        dir.display()
    );
    for f in &inst.config_files {
        let name = role_name(f.role);
        let Some(expected) = case.expect.get(&name) else {
            continue;
        };
        let out = std::fs::read_to_string(&f.path).unwrap();
        assert_eq!(
            &parse_standard(f.format, &out).unwrap(),
            expected,
            "{}: {name} value",
            dir.display()
        );
        let golden = dir.join(format!("{name}.expected"));
        match std::fs::read_to_string(&golden) {
            Ok(g) => assert_eq!(out, g, "{}: {name} bytes", dir.display()),
            Err(_) if std::env::var_os("INUMAKI_BLESS").is_some() => {
                std::fs::write(&golden, &out).unwrap()
            }
            Err(_) => panic!(
                "{}: missing {name}.expected; run with INUMAKI_BLESS=1 and review it",
                dir.display()
            ),
        }
    }
    ad.revert(&inst, &backup).unwrap();
    for (role, (path, input)) in &inputs {
        let now = std::fs::read(path).ok();
        if *role == FileRole::ClaudeJson {
            // No full copy of ~/.claude.json exists (spec §4.2): revert is
            // key-level, so the value is identical and the bytes may differ.
            let f = inst.file(*role).unwrap();
            let v = |b: &Option<Vec<u8>>| {
                b.as_ref()
                    .map(|b| parse_standard(f.format, std::str::from_utf8(b).unwrap()).unwrap())
            };
            assert_eq!(
                v(&now),
                v(input),
                "{}: claude_json value after revert",
                dir.display()
            );
        } else {
            assert_eq!(
                now,
                *input,
                "{}: {role:?} bytes after revert",
                dir.display()
            );
        }
    }
}

fn cases(harness: &str) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(harness);
    let mut v: Vec<PathBuf> = std::fs::read_dir(root)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("case.json").exists())
        .collect();
    v.sort();
    v
}

#[test]
fn claude_code_golden_files() {
    for c in cases("claude-code") {
        run_case(&c);
    }
}

#[test]
fn codex_golden_files() {
    for c in cases("codex") {
        run_case(&c);
    }
}

#[test]
fn hermes_golden_files() {
    for c in cases("hermes") {
        run_case(&c);
    }
}

#[test]
fn openclaw_golden_files() {
    for c in cases("openclaw") {
        run_case(&c);
    }
}

/// Review I2: a name defined at both user scope and one project's local
/// scope is not a case where the user-scope entry should disappear. Every
/// *other* project (and no project at all) still connects to it, so it
/// must stay listed, and it must stay eligible for its own protection.
#[test]
fn a_name_shadowed_in_one_project_still_lists_and_protects_the_user_scope_entry() {
    let home = tempfile::tempdir().unwrap();
    let claude_json = serde_json::json!({
        "mcpServers": {"crm": {"command": "/opt/homebrew/bin/crm-mcp"}},
        "projects": {"/Users/qwxzvk/other-proj": {"mcpServers": {"crm": {"command": "/usr/local/bin/other-crm-mcp"}}}}
    });
    std::fs::write(
        home.path().join(".claude.json"),
        serde_json::to_string_pretty(&claude_json).unwrap(),
    )
    .unwrap();
    let ad = adapter(HarnessId::ClaudeCode);
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();

    let servers = ad.mcp_servers(&inst, "http://127.0.0.1:8789").unwrap();
    let crm: Vec<&McpServerEntry> = servers.iter().filter(|s| s.name == "crm").collect();
    assert_eq!(
        crm.len(),
        2,
        "both scopes are listed even though the names collide"
    );
    assert!(
        crm.iter().any(|s| s.scope == Scope::User),
        "the user-scope entry is not dropped"
    );
    assert!(
        crm.iter()
            .any(|s| matches!(&s.scope, Scope::Project(d) if d == "/Users/qwxzvk/other-proj"))
    );

    let plan = ConnectPlan {
        data_dir: home.path().join("data"),
        gateway_base: "http://127.0.0.1:8789".to_string(),
        gateway: Some(GatewayPlan {
            token: Zeroizing::new("inumaki_gw_shadow".to_string()),
            entries: vec![GatewayEntry {
                name: "crm".to_string(),
                scope: Scope::User,
                url: "http://127.0.0.1:8789/mcp/mcp-crm".to_string(),
                approval_mode: None,
            }],
        }),
        files: None,
        chat: None,
        hook: None,
        proxy_client_header: None,
    };
    let edits = ad.plan_edits(&inst, &plan).unwrap();
    let cj_edits = &edits[0].1;
    assert!(
        cj_edits.iter().any(|e| matches!(e, Edit::Set { path, .. } if path.len() == 2 && path[0] == "mcpServers" && path[1] == "crm")),
        "the user-scope entry is still protectable despite the name collision"
    );
}

#[test]
fn mcp_server_entries_print_no_values() {
    let home = tempfile::tempdir().unwrap();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/claude-code/api-key-all");
    std::fs::copy(dir.join("claude.json"), home.path().join(".claude.json")).unwrap();
    let ad = adapter(HarnessId::ClaudeCode);
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    let servers = ad.mcp_servers(&inst, "http://127.0.0.1:8789").unwrap();
    assert!(
        servers
            .iter()
            .any(|s| s.values.values().any(|v| v.contains("qwxzvk"))),
        "the value is available to Protect"
    );
    let shown = format!("{servers:?} {inst:?}");
    assert!(
        !shown.contains("qwxzvk") && !shown.contains("crm"),
        "{shown}"
    );
}

const CLIENT_VALUE: &str = "inumaki_client_golden";

fn chat_plan(data_dir: &Path) -> ConnectPlan {
    ConnectPlan {
        data_dir: data_dir.to_path_buf(),
        gateway_base: "http://127.0.0.1:8789".to_string(),
        gateway: None,
        files: None,
        chat: Some(ChatPlan {
            anthropic: Some("http://127.0.0.1:8787/anthropic".to_string()),
            openai: None,
            codex: None,
            codex_chatgpt: false,
        }),
        hook: None,
        proxy_client_header: Some(ClientHeader::new(Zeroizing::new(CLIENT_VALUE.to_string()))),
    }
}

fn custom_headers(settings: &Path) -> Option<String> {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(settings).unwrap()).unwrap();
    v["env"]
        .get("ANTHROPIC_CUSTOM_HEADERS")
        .and_then(|x| x.as_str())
        .map(str::to_string)
}

/// Rewrite settings.json as a user would: `f` edits the parsed value.
fn user_edits(settings: &Path, f: impl FnOnce(&mut serde_json::Value)) {
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(settings).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(settings, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

/// Spec §4.3 amendment: inumaki owns one line of
/// `env.ANTHROPIC_CUSTOM_HEADERS`. A key-level revert restores the user's
/// own lines exactly; a value the user changed after apply is a reported
/// conflict and is never clobbered; drift is our line missing or changed,
/// not another line of the user's.
#[test]
fn the_client_header_line_reverts_without_clobbering_user_lines() {
    let home = tempfile::tempdir().unwrap();
    let case =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/claude-code/chat-custom-headers");
    let settings = home.path().join(".claude/settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = std::fs::read(case.join("settings.json")).unwrap();
    let before = "X-Team: blue\nx-inumaki-client: inumaki_client_stale\n";
    let ad = adapter(HarnessId::ClaudeCode);
    let env = ProbeEnv::for_tests(home.path());
    let data = home.path().join("data");

    // (a) Another key changed since apply: revert is key-level and gives
    // back the user's header lines exactly.
    std::fs::write(&settings, &original).unwrap();
    let inst = ad.detect(&env).unwrap();
    let b = ad.apply(&inst, &chat_plan(&data)).unwrap();
    assert_eq!(
        custom_headers(&settings).as_deref(),
        Some("X-Team: blue\nX-Inumaki-Client: inumaki_client_golden\n")
    );
    user_edits(&settings, |v| v["model"] = "opus".into());
    let r = ad.revert(&inst, &b).unwrap();
    assert!(
        r.key_level.contains(&FileRole::ClaudeSettings) && r.conflicts.is_empty(),
        "{r:?}"
    );
    assert_eq!(custom_headers(&settings).as_deref(), Some(before));

    // (b) The key did not exist before: a key-level revert removes it.
    std::fs::write(&settings, "{\"env\": {\"DISABLE_TELEMETRY\": \"1\"}}\n").unwrap();
    let b = ad.apply(&inst, &chat_plan(&data)).unwrap();
    assert_eq!(
        custom_headers(&settings).as_deref(),
        Some("X-Inumaki-Client: inumaki_client_golden")
    );
    user_edits(&settings, |v| v["model"] = "opus".into());
    ad.revert(&inst, &b).unwrap();
    assert_eq!(
        custom_headers(&settings),
        None,
        "the key inumaki created is gone"
    );

    // (c) The user added a line after apply: not drift (our line is
    // intact); revert removes our line and keeps the user's lines (review
    // I1: our secret line must not stay once the base URL is reverted).
    std::fs::write(&settings, &original).unwrap();
    let b = ad.apply(&inst, &chat_plan(&data)).unwrap();
    user_edits(&settings, |v| {
        let s = v["env"]["ANTHROPIC_CUSTOM_HEADERS"]
            .as_str()
            .unwrap()
            .to_string();
        v["env"]["ANTHROPIC_CUSTOM_HEADERS"] = format!("{s}X-Other: 1\n").into();
    });
    let edited = custom_headers(&settings);
    let sys = SystemState {
        service_up: true,
        proxy: Some(ProxyInfo {
            routes: vec![RouteInfo {
                route: Route::Anthropic,
                base_url: "http://127.0.0.1:8787/anthropic".to_string(),
                failing: false,
            }],
            client_header: Some(ClientHeader::new(Zeroizing::new(CLIENT_VALUE.to_string()))),
            ..Default::default()
        }),
        applied: Some(b.clone()),
        ..Default::default()
    };
    let st = ad.status(&inst, &sys);
    assert!(
        st.drift.is_empty(),
        "another user line is not drift: {:?}",
        st.drift
    );
    assert!(
        matches!(st.paths[2].1, PathState::Connected { .. }),
        "{:?}",
        st.paths[2]
    );
    assert!(edited.as_deref().is_some_and(|v| v.contains("X-Other: 1")));
    let r = ad.revert(&inst, &b).unwrap();
    let path = vec!["env".to_string(), "ANTHROPIC_CUSTOM_HEADERS".to_string()];
    assert!(
        !r.conflicts.iter().any(|c| c.path == path) && !r.client_header_left,
        "{r:?}"
    );
    assert_eq!(
        custom_headers(&settings).as_deref(),
        Some("X-Team: blue\nX-Other: 1\n"),
        "the user's lines stay, ours is gone"
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert!(v["env"].get("ANTHROPIC_BASE_URL").is_none());

    // (c2) Only our line left after the user's edit: the key goes.
    std::fs::write(&settings, "{\"env\": {}}\n").unwrap();
    let b = ad.apply(&inst, &chat_plan(&data)).unwrap();
    user_edits(&settings, |v| {
        v["env"]["ANTHROPIC_CUSTOM_HEADERS"] = "X-Inumaki-Client: inumaki_client_golden\n\n".into()
    });
    let r = ad.revert(&inst, &b).unwrap();
    assert!(r.conflicts.is_empty() && !r.client_header_left, "{r:?}");
    assert_eq!(custom_headers(&settings), None);

    // (c3) Our value where the line edit cannot reach it: the report says
    // the secret is still in the file.
    std::fs::write(&settings, &original).unwrap();
    let b = ad.apply(&inst, &chat_plan(&data)).unwrap();
    user_edits(&settings, |v| {
        v["env"]["ANTHROPIC_CUSTOM_HEADERS"] =
            serde_json::json!(["X-Inumaki-Client: inumaki_client_golden"])
    });
    let r = ad.revert(&inst, &b).unwrap();
    assert!(
        r.client_header_left && r.conflicts.iter().any(|c| c.path == path),
        "{r:?}"
    );

    // (d) Our line removed, or a stale value: drift, and Chat is broken.
    std::fs::write(&settings, &original).unwrap();
    let b = ad.apply(&inst, &chat_plan(&data)).unwrap();
    user_edits(&settings, |v| {
        v["env"]["ANTHROPIC_CUSTOM_HEADERS"] = "X-Team: blue\n".into()
    });
    let sys = SystemState {
        applied: Some(b.clone()),
        ..sys
    };
    let st = ad.status(&inst, &sys);
    assert!(st.drift.iter().any(|d| d.path == path), "{:?}", st.drift);
    assert_eq!(
        st.paths[2].1,
        PathState::Broken {
            reason: ReasonCode::ChangedOutsideInumaki
        }
    );
    let stale = SystemState {
        applied: None,
        ..sys.clone()
    };
    user_edits(&settings, |v| {
        v["env"]["ANTHROPIC_CUSTOM_HEADERS"] = "X-Inumaki-Client: inumaki_client_old".into()
    });
    assert_eq!(
        ad.status(&inst, &stale).paths[2].1,
        PathState::Broken {
            reason: ReasonCode::ChangedOutsideInumaki
        }
    );
}

/// The client header value is a secret like the gateway token: no `Debug`
/// prints it.
#[test]
fn debug_never_prints_the_client_header_or_the_token() {
    let mut plan = chat_plan(Path::new("/Users/qwxzvk/data"));
    plan.gateway = Some(GatewayPlan {
        token: Zeroizing::new("inumaki_gw_golden".to_string()),
        entries: vec![GatewayEntry {
            name: "crm".to_string(),
            scope: Scope::User,
            url: "http://127.0.0.1:8789/mcp/mcp-crm".to_string(),
            approval_mode: None,
        }],
    });
    let shown = format!("{plan:?} {:?}", plan.proxy_client_header);
    assert!(
        shown.contains("X-Inumaki-Client"),
        "the name is shown: {shown}"
    );
    for secret in [
        CLIENT_VALUE,
        "inumaki_gw_golden",
        "qwxzvk",
        "crm",
        "127.0.0.1",
    ] {
        assert!(!shown.contains(secret), "{secret} leaked: {shown}");
    }
}

fn executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// docs/harness-adapters.md CX-HOOK "Hook trust": the adapter appends its
/// group after the user's, never writes a trust record (config.toml is not
/// touched at all), and reports the hook as needing trust until Codex has a
/// `trusted_hash` under our key. A re-apply leaves a trusted entry in place.
#[test]
fn the_codex_hook_is_never_trusted_by_inumaki_and_reports_needs_trust() {
    let home = tempfile::tempdir().unwrap();
    let codex = home.path().join(".codex");
    std::fs::create_dir_all(&codex).unwrap();
    let config = "# mine\nmodel = \"gpt-5-codex\"\n";
    std::fs::write(codex.join("config.toml"), config).unwrap();
    let user_group = serde_json::json!({"matcher": "^Bash$", "hooks": [{"type": "command", "command": "~/bin/audit.sh"}]});
    std::fs::write(
        codex.join("hooks.json"),
        serde_json::to_string_pretty(
            &serde_json::json!({"hooks": {"PostToolUse": [user_group.clone()]}}),
        )
        .unwrap(),
    )
    .unwrap();
    let ad = adapter(HarnessId::Codex);
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    let bin = home.path().join("bin/inumaki-hook");
    executable(&bin);
    let plan = ConnectPlan {
        data_dir: home.path().join("data"),
        gateway_base: "http://127.0.0.1:8789".to_string(),
        gateway: None,
        files: None,
        chat: None,
        hook: Some(HookPlan {
            command: bin.clone(),
            socket: home.path().join("inumakid.sock"),
        }),
        proxy_client_header: None,
    };
    let b = ad.apply(&inst, &plan).unwrap();
    assert_eq!(
        std::fs::read_to_string(codex.join("config.toml")).unwrap(),
        config,
        "no trust record, no config.toml edit"
    );
    let hooks: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(codex.join("hooks.json")).unwrap()).unwrap();
    let groups = hooks["hooks"]["PostToolUse"].as_array().unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0], user_group, "the user's group keeps index 0");
    assert!(
        groups[1].to_string().contains("inumaki-hook"),
        "ours is appended last"
    );

    let sys = SystemState {
        hook_binary: Some(bin.clone()),
        applied: Some(b),
        ..Default::default()
    };
    assert_eq!(
        ad.status(&inst, &sys).hook,
        HookState::Pending {
            reason: ReasonCode::CodexHookNeedsTrust
        }
    );

    // The user trusts it in Codex's /hooks; Codex records the hash.
    let hooks_path = inst
        .file(FileRole::CodexHooks)
        .unwrap()
        .path
        .to_string_lossy()
        .into_owned();
    let trusted = format!(
        "{config}\n[hooks.state.\"{hooks_path}:post_tool_use:1:0\"]\ntrusted_hash = \"sha256:0123abcd\"\n"
    );
    std::fs::write(codex.join("config.toml"), &trusted).unwrap();
    assert_eq!(ad.status(&inst, &sys).hook, HookState::Installed);

    // A re-apply of the same hook moves nothing and keeps the trust record.
    let hooks_before = std::fs::read(codex.join("hooks.json")).unwrap();
    ad.apply(&inst, &plan).unwrap();
    assert_eq!(
        std::fs::read(codex.join("hooks.json")).unwrap(),
        hooks_before
    );
    assert_eq!(
        std::fs::read_to_string(codex.join("config.toml")).unwrap(),
        trusted
    );
    assert_eq!(ad.status(&inst, &sys).hook, HookState::Installed);
}

/// docs/harness-adapters.md CX-PROFILES: `[profiles.*]` in config.toml is
/// ignored since Codex 0.134; a profile file `<name>.config.toml` with
/// another `model_provider` bypasses inumaki's provider.
#[test]
fn a_codex_profile_file_with_another_provider_is_an_override() {
    let home = tempfile::tempdir().unwrap();
    let codex = home.path().join(".codex");
    std::fs::create_dir_all(&codex).unwrap();
    std::fs::write(
        codex.join("config.toml"),
        "model_provider = \"inumaki\"\n\n[model_providers.inumaki]\nname = \"inumaki\"\nbase_url = \"http://127.0.0.1:8787/openai/v1\"\nwire_api = \"responses\"\nenv_key = \"OPENAI_API_KEY\"\n\n[profiles.fast]\nmodel_provider = \"openai\"\n",
    )
    .unwrap();
    let mut env = ProbeEnv::for_tests(home.path());
    env.env.insert("OPENAI_API_KEY".to_string(), String::new());
    let ad = adapter(HarnessId::Codex);
    let inst = ad.detect(&env).unwrap();
    let sys = SystemState {
        service_up: true,
        proxy: Some(ProxyInfo {
            routes: vec![RouteInfo {
                route: Route::Openai,
                base_url: "http://127.0.0.1:8787/openai".to_string(),
                failing: false,
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let chat = |ad: &dyn HarnessAdapter| ad.status(&inst, &sys).paths[2].1;
    assert!(
        matches!(chat(&*ad), PathState::Connected { .. }),
        "[profiles.fast] is inert: {:?}",
        chat(&*ad)
    );
    std::fs::write(
        codex.join("work.config.toml"),
        "model_provider = \"inumaki\"\n",
    )
    .unwrap();
    assert!(
        matches!(chat(&*ad), PathState::Connected { .. }),
        "a profile on our provider is fine"
    );
    std::fs::write(
        codex.join("fast.config.toml"),
        "model = \"gpt-5-mini\"\nmodel_provider = \"openai\"\n",
    )
    .unwrap();
    assert_eq!(
        chat(&*ad),
        PathState::NotConnected {
            reason: Some(ReasonCode::CodexProfileOverride)
        }
    );
}

/// Review M5: a stale inumaki entry next to an identical one is pulled, so
/// exactly one inumaki group is left (appended last).
#[test]
fn a_stale_codex_hook_entry_is_replaced_even_next_to_an_identical_one() {
    let home = tempfile::tempdir().unwrap();
    let codex = home.path().join(".codex");
    std::fs::create_dir_all(&codex).unwrap();
    let bin = home.path().join("bin/inumaki-hook");
    let sock = home.path().join("inumakid.sock");
    let ad = adapter(HarnessId::Codex);
    let plan = ConnectPlan {
        data_dir: home.path().join("data"),
        gateway_base: "http://127.0.0.1:8789".to_string(),
        gateway: None,
        files: None,
        chat: None,
        hook: Some(HookPlan {
            command: bin.clone(),
            socket: sock.clone(),
        }),
        proxy_client_header: None,
    };
    std::fs::write(codex.join("config.toml"), "").unwrap();
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    ad.apply(&inst, &plan).unwrap();
    let read = || -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(codex.join("hooks.json")).unwrap()).unwrap()
    };
    let current = read()["hooks"]["PostToolUse"][0].clone();
    let mut stale = current.clone();
    stale["hooks"][0]["command"] = "'/old/inumaki-hook' codex --socket '/old/inumakid.sock'".into();
    let user = serde_json::json!({"matcher": "^Bash$", "hooks": [{"type": "command", "command": "~/bin/audit.sh"}]});
    let doc = serde_json::json!({"hooks": {"PostToolUse": [stale, user.clone(), current.clone()]}});
    std::fs::write(
        codex.join("hooks.json"),
        serde_json::to_string_pretty(&doc).unwrap(),
    )
    .unwrap();
    ad.apply(&inst, &plan).unwrap();
    assert_eq!(
        read()["hooks"]["PostToolUse"],
        serde_json::json!([user, current])
    );
}

/// A tempdir home with the case's files in place, and the adapter's
/// installation over it.
fn install(
    harness: &str,
    case: &str,
    files: &[(&str, &str)],
) -> (tempfile::TempDir, Installation, Box<dyn HarnessAdapter>) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(harness)
        .join(case);
    let home = tempfile::tempdir().unwrap();
    for (src, rel) in files {
        let p = home.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::copy(dir.join(src), p).unwrap();
    }
    let ad = adapter(HarnessId::parse(harness).unwrap());
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    (home, inst, ad)
}

fn chat_sys(
    route: Route,
    base: &str,
    header: Option<&str>,
    applied: Option<Backup>,
) -> SystemState {
    SystemState {
        service_up: true,
        proxy: Some(ProxyInfo {
            routes: vec![RouteInfo {
                route,
                base_url: base.to_string(),
                failing: false,
            }],
            client_header: header.map(|h| ClientHeader::new(Zeroizing::new(h.to_string()))),
            ..Default::default()
        }),
        applied,
        ..Default::default()
    }
}

fn openai_chat_plan(data_dir: &Path, header: Option<&str>) -> ConnectPlan {
    ConnectPlan {
        data_dir: data_dir.to_path_buf(),
        gateway_base: "http://127.0.0.1:8789".to_string(),
        gateway: None,
        files: None,
        chat: Some(ChatPlan {
            anthropic: None,
            openai: Some("http://127.0.0.1:8787/openai".to_string()),
            codex: None,
            codex_chatgpt: false,
        }),
        hook: None,
        proxy_client_header: header.map(|h| ClientHeader::new(Zeroizing::new(h.to_string()))),
    }
}

/// Spec §4.3 amendment for the harnesses whose provider config can carry a
/// header (Hermes `extra_headers`, OpenClaw `headers`): written beside the
/// base URL, absent when the plan has none, and a changed or stale value is
/// drift that turns Chat red. The value never shows in a `Debug`.
#[test]
fn hermes_and_openclaw_send_the_client_header_and_report_drift() {
    for (harness, case, files, key) in [
        (
            "hermes",
            "api-key-all",
            vec![
                ("config.yaml", ".hermes/config.yaml"),
                ("env", ".hermes/.env"),
            ],
            "extra_headers",
        ),
        (
            "openclaw",
            "api-key-docker",
            vec![("openclaw.json", ".openclaw/openclaw.json")],
            "headers",
        ),
    ] {
        let route = Route::Openai;
        let base = "http://127.0.0.1:8787/openai";
        let (home, inst, ad) = install(harness, case, &files);
        let cfg = &inst.config_files[0].path;
        let data = home.path().join("data");

        // No header in the plan: none in the file.
        let b = ad.apply(&inst, &openai_chat_plan(&data, None)).unwrap();
        assert!(
            !std::fs::read_to_string(cfg).unwrap().contains(CLIENT_VALUE),
            "{harness}"
        );
        assert!(
            !std::fs::read_to_string(cfg)
                .unwrap()
                .contains("X-Inumaki-Client"),
            "{harness}"
        );
        ad.revert(&inst, &b).unwrap();

        // With it: written, and status is Connected.
        let b = ad
            .apply(&inst, &openai_chat_plan(&data, Some(CLIENT_VALUE)))
            .unwrap();
        let text = std::fs::read_to_string(cfg).unwrap();
        assert!(
            text.contains(key) && text.contains(CLIENT_VALUE),
            "{harness}"
        );
        let sys = chat_sys(route, base, Some(CLIENT_VALUE), Some(b.clone()));
        let st = ad.status(&inst, &sys);
        assert!(
            matches!(st.paths[2].1, PathState::Connected { .. }),
            "{harness}: {:?}",
            st.paths[2]
        );
        assert!(st.drift.is_empty(), "{harness}: {:?}", st.drift);
        let shown = format!("{st:?} {b:?} {inst:?}");
        assert!(
            !shown.contains(CLIENT_VALUE) && !shown.contains("inumaki_gw_golden"),
            "{harness}: {shown}"
        );

        // The daemon rotated its header: our file is stale.
        let rotated = chat_sys(route, base, Some("inumaki_client_rotated"), None);
        assert_eq!(
            ad.status(&inst, &rotated).paths[2].1,
            PathState::Broken {
                reason: ReasonCode::ChangedOutsideInumaki
            },
            "{harness}"
        );

        // The user changed or removed our header: drift against the backup.
        std::fs::write(cfg, text.replace(CLIENT_VALUE, "inumaki_client_edited")).unwrap();
        let st = ad.status(&inst, &sys);
        assert_eq!(
            st.paths[2].1,
            PathState::Broken {
                reason: ReasonCode::ChangedOutsideInumaki
            },
            "{harness}"
        );
        assert!(!st.drift.is_empty(), "{harness}");
    }
}

/// Hermes: a subscription login is `Unverified` and nothing is written for
/// chat (its override lives in `.env`, outside the editors); the manual
/// snippet names the environment variable.
#[test]
fn a_hermes_subscription_login_is_unverified_and_writes_nothing_for_chat() {
    let (home, _, ad) = install(
        "hermes",
        "api-key-all",
        &[("config.yaml", ".hermes/config.yaml")],
    );
    std::fs::write(
        home.path().join(".hermes/auth.json"),
        "{\"active_provider\": \"openai-codex\"}",
    )
    .unwrap();
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    assert_eq!(inst.login, LoginKind::Oauth);
    let mut plan = openai_chat_plan(&home.path().join("data"), Some(CLIENT_VALUE));
    plan.chat.as_mut().unwrap().codex = Some("http://127.0.0.1:8787/codex".to_string());
    let edits = ad.plan_edits(&inst, &plan).unwrap();
    assert!(
        edits[0].1.is_empty(),
        "no chat edit for a subscription login"
    );
    let sys = chat_sys(
        Route::Openai,
        "http://127.0.0.1:8787/openai",
        Some(CLIENT_VALUE),
        None,
    );
    assert_eq!(
        ad.status(&inst, &sys).paths[2].1,
        PathState::Unverified {
            reason: ReasonCode::HermesOauthNoOverride
        }
    );
    let snippet =
        inumaki_adapters::harness::hermes::Hermes::oauth_chat_snippet(plan.chat.as_ref().unwrap())
            .unwrap();
    assert!(
        snippet.contains("HERMES_CODEX_BASE_URL=http://127.0.0.1:8787/codex"),
        "{snippet}"
    );
    assert!(!snippet.contains(CLIENT_VALUE));
    // The on-demand view: the Codex route from the daemon's facts, the fixed
    // note, and no header value.
    let mut sys = chat_sys(
        Route::Codex,
        "http://127.0.0.1:8787/codex",
        Some(CLIENT_VALUE),
        None,
    );
    let st = ad.status(&inst, &sys);
    let setup = ad
        .manual_setup(&st, &sys)
        .expect("manual setup for Hermes OAuth");
    assert!(
        setup
            .lines
            .contains("HERMES_CODEX_BASE_URL=http://127.0.0.1:8787/codex"),
        "{}",
        setup.lines
    );
    assert_eq!(
        setup.note,
        "Hermes OAuth sends no client header, so only session tokens are restored."
    );
    assert!(!setup.lines.contains(CLIENT_VALUE) && !setup.note.contains(CLIENT_VALUE));
    // Without a proxy route there is nothing to write down.
    sys.proxy = None;
    assert!(ad.manual_setup(&ad.status(&inst, &sys), &sys).is_none());
}

/// OpenClaw docker bind (ruling): written only inside an agent workspace
/// root; otherwise nothing is written (no `dangerously*` flag, ever), Files
/// is `Unsupported`, and the manual snippet carries the bind.
#[test]
fn an_openclaw_bind_outside_the_workspace_roots_is_never_written() {
    let (home, inst, ad) = install(
        "openclaw",
        "api-key-docker",
        &[("openclaw.json", ".openclaw/openclaw.json")],
    );
    let cfg = &inst.config_files[0].path;
    let moved = std::fs::read_to_string(cfg).unwrap().replace(
        "workspace: '/Users/qwxzvk'",
        "workspace: '/Users/qwxzvk/work'",
    );
    std::fs::write(cfg, moved).unwrap();
    let files = FilesPlan {
        mirror_root: PathBuf::from("/Users/qwxzvk/Inumaki"),
        outboxes: vec![],
    };
    let mut plan = openai_chat_plan(&home.path().join("data"), None);
    plan.chat = None;
    plan.files = Some(FilesPlan {
        mirror_root: files.mirror_root.clone(),
        outboxes: vec![],
    });
    ad.apply(&inst, &plan).unwrap();
    let after = std::fs::read_to_string(cfg).unwrap();
    assert!(
        !after.contains("Inumaki") && !after.contains("dangerously"),
        "{after}"
    );
    let sys = SystemState {
        folders: Some(FolderInfo {
            mirror_root: files.mirror_root.clone(),
            watching: 1,
            outboxes: vec![],
        }),
        ..Default::default()
    };
    assert_eq!(
        ad.status(&inst, &sys).paths[1].1,
        PathState::Unsupported {
            reason: ReasonCode::OpenclawDockerBindsOnly
        }
    );
    let snippet = inumaki_adapters::harness::openclaw::Openclaw::docker_bind_snippet(&files);
    assert!(
        snippet.contains("/Users/qwxzvk/Inumaki:/Users/qwxzvk/Inumaki:ro"),
        "{snippet}"
    );
    let st = ad.status(&inst, &sys);
    let setup = ad
        .manual_setup(&st, &sys)
        .expect("manual setup for the bind");
    assert_eq!(setup.lines, snippet);
    assert!(
        setup
            .note
            .contains("dangerouslyAllowExternalBindSources is true"),
        "{}",
        setup.note
    );
}

/// Spec §4.2: a refused file shows the manual snippet, including when the
/// file does not parse at all (the dry run, not `plan_edits`, refuses it).
#[test]
fn refusals_carry_the_manual_snippet() {
    for (harness, case, file, rel) in [
        (
            "hermes",
            "refuse-flow",
            "config.yaml",
            ".hermes/config.yaml",
        ),
        (
            "openclaw",
            "refuse-edge",
            "openclaw.json",
            ".openclaw/openclaw.json",
        ),
    ] {
        let (home, inst, ad) = install(harness, case, &[(file, rel)]);
        let mut plan = openai_chat_plan(&home.path().join("data"), Some(CLIENT_VALUE));
        plan.gateway = Some(GatewayPlan {
            token: Zeroizing::new("inumaki_gw_golden".to_string()),
            entries: vec![GatewayEntry {
                name: "tickets".to_string(),
                scope: Scope::User,
                url: "http://127.0.0.1:8789/mcp/mcp-tickets".to_string(),
                approval_mode: None,
            }],
        });
        let e = ad.apply(&inst, &plan).unwrap_err();
        let snippet = e.snippet().unwrap_or_else(|| panic!("{harness}: {e}"));
        assert!(
            snippet.contains("http://127.0.0.1:8789/mcp/mcp-tickets"),
            "{harness}: {snippet:?}"
        );
        let shown = format!("{e} {e:?}");
        assert!(
            !shown.contains("inumaki_gw_golden") && !shown.contains("tickets"),
            "{harness}: {shown}"
        );
    }
}
