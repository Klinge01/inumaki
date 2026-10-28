//! Spec §4.1, §4.5, §4.6: drift turns a path red; red-by-design rows hold;
//! Protect ids and identities.

use std::collections::{BTreeMap, BTreeSet};

use inumaki_adapters::protect::{
    credential_like, dataset_id_for, definition_id, mail_entry_name, split,
};
use inumaki_adapters::*;
use zeroize::Zeroizing;

#[test]
fn drift_turns_the_path_red_and_red_by_design_rows_hold() {
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("data");
    std::fs::write(
        home.path().join(".claude.json"),
        "{\"mcpServers\": {\"crm\": {\"command\": \"/bin/crm\"}}}\n",
    )
    .unwrap();
    let ad = adapter(HarnessId::ClaudeCode);
    let env = ProbeEnv::for_tests(home.path());
    let inst = ad.detect(&env).unwrap();
    let plan = ConnectPlan {
        data_dir: data.clone(),
        gateway_base: "http://127.0.0.1:8789".into(),
        gateway: Some(GatewayPlan {
            token: Zeroizing::new("t".into()),
            entries: vec![GatewayEntry {
                name: "crm".into(),
                scope: Scope::User,
                url: "http://127.0.0.1:8789/mcp/mcp-crm".into(),
                approval_mode: None,
            }],
        }),
        files: None,
        chat: None,
        hook: None,
        proxy_client_header: None,
    };
    let b = ad.apply(&inst, &plan).unwrap();
    let mut sys = SystemState {
        service_up: true,
        gateway_base: "http://127.0.0.1:8789".into(),
        applied: Some(b),
        ..Default::default()
    };
    sys.datasets_running.insert("mcp-crm".into());
    assert!(matches!(
        ad.status(&inst, &sys).paths[0].1,
        PathState::Connected { .. }
    ));
    // A running session writes back an older copy: drift.
    std::fs::write(
        home.path().join(".claude.json"),
        "{\"mcpServers\": {\"crm\": {\"command\": \"/bin/crm\"}}}\n",
    )
    .unwrap();
    assert_eq!(
        ad.status(&inst, &sys).paths[0].1,
        PathState::Broken {
            reason: ReasonCode::ChangedOutsideInumaki
        }
    );
    // Red by design, regardless of files.
    let hermes_home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(hermes_home.path().join(".hermes")).unwrap();
    std::fs::write(
        hermes_home.path().join(".hermes/config.yaml"),
        "model:\n  provider: x\n",
    )
    .unwrap();
    let h = adapter(HarnessId::Hermes);
    let hi = h.detect(&ProbeEnv::for_tests(hermes_home.path())).unwrap();
    let hs = h.status(&hi, &SystemState::default());
    assert_eq!(
        hs.paths[1].1,
        PathState::Unsupported {
            reason: ReasonCode::HermesFilesUnconfirmed
        }
    );
    assert_eq!(
        hs.paths[2].1,
        PathState::NotConnected {
            reason: Some(ReasonCode::ChatProviderNotRouted)
        },
        "provider x has no route: chat is left alone"
    );
    assert_eq!(
        hs.hook,
        HookState::NotSupported {
            reason: ReasonCode::HermesHooksFailOpen
        }
    );
}

#[test]
fn protect_ids_identities_and_names() {
    let taken: BTreeSet<String> = ["mcp-scope-x".to_string()].into();
    assert_eq!(dataset_id_for("@scope/x", &BTreeSet::new()), "mcp-scope-x");
    assert_eq!(dataset_id_for("@scope/x", &taken), "mcp-scope-x-2");
    assert!(dataset_id_for(&"a".repeat(200), &BTreeSet::new()).len() <= 64);
    for n in [
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "Authorization",
        "DB_PASSWORD",
    ] {
        assert!(credential_like(n), "{n}");
    }
    assert!(!credential_like("PATH"));
    let entry = |secret: &str| McpServerEntry {
        name: "crm".into(),
        scope: Scope::User,
        transport: Transport::Stdio {
            command: "crm-mcp".into(),
            args: vec![],
            cwd: None,
        },
        env_names: vec!["CRM_TOKEN".into(), "CRM_URL".into()],
        header_names: vec![],
        values: BTreeMap::from([
            (
                "env:CRM_TOKEN".to_string(),
                Zeroizing::new(secret.to_string()),
            ),
            (
                "env:CRM_URL".to_string(),
                Zeroizing::new("https://crm".to_string()),
            ),
        ]),
        gateway: false,
        needs_oauth: false,
        approval_mode: None,
    };
    let k = [7u8; 32];
    assert_ne!(
        definition_id(&entry("a"), &k),
        definition_id(&entry("b"), &k),
        "two accounts never merge"
    );
    assert_eq!(
        definition_id(&entry("a"), &k),
        definition_id(&entry("a"), &k)
    );
    assert_ne!(
        definition_id(&entry("a"), &k),
        definition_id(&entry("a"), &[8u8; 32]),
        "keyed per install"
    );
    let parts = split(&entry("s3cret-qwxzvk"), Some("/usr/bin:/bin"));
    assert!(parts.secret_env.contains_key("CRM_TOKEN") && parts.env.contains_key("CRM_URL"));
    assert_eq!(
        parts.env.get("PATH").map(String::as_str),
        Some("/usr/bin:/bin")
    );
    assert!(!format!("{parts:?}").contains("qwxzvk"));
    let used: BTreeSet<String> = ["inumaki-mail".to_string()].into();
    assert_eq!(mail_entry_name(0, &BTreeSet::new()), "inumaki-mail");
    assert_eq!(
        mail_entry_name(0, &used),
        "inumaki-mail-2",
        "a user entry of that name is never overwritten"
    );
    assert_eq!(mail_entry_name(1, &BTreeSet::new()), "inumaki-mail-2");
}

#[test]
fn the_secret_split_never_copies_a_credential_like_value_into_a_plain_field() {
    // Credential-like names in either table (env or header) go to the
    // secret maps; the value appears in no plain field, whatever the case.
    let secret = "s3cret-qwxzvk";
    let entry = McpServerEntry {
        name: "crm".into(),
        scope: Scope::User,
        transport: Transport::Http {
            url: "https://crm.example/mcp".into(),
        },
        env_names: vec!["Api_Key".into()],
        header_names: vec![
            "Authorization".into(),
            "X-Api-Key".into(),
            "X-Tenant".into(),
        ],
        values: BTreeMap::from([
            (
                "env:Api_Key".to_string(),
                Zeroizing::new(secret.to_string()),
            ),
            (
                "header:Authorization".to_string(),
                Zeroizing::new(format!("Bearer {secret}")),
            ),
            (
                "header:X-Api-Key".to_string(),
                Zeroizing::new(secret.to_string()),
            ),
            (
                "header:X-Tenant".to_string(),
                Zeroizing::new("acme".to_string()),
            ),
        ]),
        gateway: false,
        needs_oauth: false,
        approval_mode: None,
    };
    let parts = split(&entry, None);
    assert_eq!(parts.kind, "http");
    assert_eq!(parts.secret_env.len(), 1);
    assert_eq!(parts.secret_headers.len(), 2);
    assert_eq!(
        parts.headers.get("X-Tenant").map(String::as_str),
        Some("acme")
    );
    let plain: Vec<&String> = parts
        .env
        .values()
        .chain(parts.headers.values())
        .chain(parts.args.iter())
        .chain(parts.url.iter())
        .chain(parts.command.iter())
        .collect();
    assert!(
        plain.iter().all(|v| !v.contains("qwxzvk")),
        "no plain field holds a credential value"
    );
    assert!(!format!("{entry:?}").contains("qwxzvk"));
}

#[test]
fn the_client_header_value_never_shows_in_debug() {
    let header = ClientHeader::new(Zeroizing::new("inumaki_client_qwxzvk".to_string()));
    let plan = ConnectPlan {
        data_dir: "/data".into(),
        gateway_base: "http://127.0.0.1:8789".into(),
        gateway: None,
        files: None,
        chat: None,
        hook: None,
        proxy_client_header: Some(header.clone()),
    };
    for shown in [format!("{header:?}"), format!("{plan:?}")] {
        assert!(!shown.contains("qwxzvk"), "{shown}");
        assert!(shown.contains("X-Inumaki-Client"), "{shown}");
    }
}

#[test]
fn the_definition_index_persists_with_a_private_key() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let entry = McpServerEntry {
        name: "crm".into(),
        scope: Scope::User,
        transport: Transport::Http {
            url: "https://crm.example/mcp".into(),
        },
        env_names: vec![],
        header_names: vec![],
        values: BTreeMap::new(),
        gateway: false,
        needs_oauth: false,
        approval_mode: None,
    };
    let mut idx = inumaki_adapters::protect::DefinitionIndex::load(dir.path()).unwrap();
    let def = idx.id_for(&entry);
    idx.insert(def.clone(), "mcp-crm".into());
    idx.save().unwrap();
    let again = inumaki_adapters::protect::DefinitionIndex::load(dir.path()).unwrap();
    assert_eq!(again.id_for(&entry), def, "the key is stable across loads");
    assert_eq!(again.get(&def), Some("mcp-crm"));
    for f in ["definition.key", "definitions.json"] {
        let mode = std::fs::metadata(dir.path().join("adapters").join(f))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{f}");
    }
}

#[test]
fn a_corrupt_index_or_key_is_an_error_never_overwritten() {
    use inumaki_adapters::protect::DefinitionIndex;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let adapters = dir.path().join("adapters");
    std::fs::create_dir_all(&adapters).unwrap();
    std::fs::set_permissions(&adapters, std::fs::Permissions::from_mode(0o755)).unwrap();
    DefinitionIndex::load(dir.path()).unwrap();
    let mode = std::fs::metadata(&adapters).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o700,
        "an existing loose directory is tightened"
    );
    // A corrupt index is refused and left as it is.
    std::fs::write(adapters.join("definitions.json"), b"{not json").unwrap();
    assert!(DefinitionIndex::load(dir.path()).is_err());
    assert_eq!(
        std::fs::read(adapters.join("definitions.json")).unwrap(),
        b"{not json"
    );
    std::fs::remove_file(adapters.join("definitions.json")).unwrap();
    // A key of the wrong length is refused and left as it is.
    std::fs::write(adapters.join("definition.key"), b"short").unwrap();
    assert!(DefinitionIndex::load(dir.path()).is_err());
    assert_eq!(
        std::fs::read(adapters.join("definition.key")).unwrap(),
        b"short"
    );
}

fn executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Final review I1: status reads the program and socket the registered
/// hook command names, not where inumaki's binaries are now. A command
/// that names a missing program is broken even when the current one exists.
#[test]
fn hook_status_checks_the_program_the_registered_command_runs() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".claude")).unwrap();
    let ad = adapter(HarnessId::ClaudeCode);
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    let current = home.path().join("bin/inumaki-hook");
    executable(&current);
    let sock = home.path().join("inumakid.sock");
    let apply_with = |command: std::path::PathBuf, socket: std::path::PathBuf| {
        let plan = ConnectPlan {
            data_dir: home.path().join("data"),
            gateway_base: "http://127.0.0.1:8789".into(),
            gateway: None,
            files: None,
            chat: None,
            hook: Some(HookPlan { command, socket }),
            proxy_client_header: None,
        };
        ad.apply(&inst, &plan).unwrap()
    };
    let sys_for = |b| SystemState {
        hook_binary: Some(current.clone()),
        hook_socket: Some(sock.clone()),
        applied: Some(b),
        ..Default::default()
    };
    // The file names a program that does not exist; the current one does.
    let b = apply_with(home.path().join("moved/inumaki-hook"), sock.clone());
    assert_eq!(
        ad.status(&inst, &sys_for(b)).hook,
        HookState::Broken {
            reason: ReasonCode::HookBinaryMissing
        }
    );
    // Another program that runs, or another socket: reconnect.
    let old = home.path().join("old/inumaki-hook");
    executable(&old);
    let b = apply_with(old, sock.clone());
    assert_eq!(
        ad.status(&inst, &sys_for(b)).hook,
        HookState::Broken {
            reason: ReasonCode::HookOutdated
        }
    );
    let b = apply_with(current.clone(), home.path().join("other.sock"));
    assert_eq!(
        ad.status(&inst, &sys_for(b)).hook,
        HookState::Broken {
            reason: ReasonCode::HookOutdated
        }
    );
    let b = apply_with(current.clone(), sock.clone());
    assert_eq!(ad.status(&inst, &sys_for(b)).hook, HookState::Installed);
}

fn codex_gateway_plan(data: &std::path::Path) -> ConnectPlan {
    ConnectPlan {
        data_dir: data.to_path_buf(),
        gateway_base: "http://127.0.0.1:8789".into(),
        gateway: Some(GatewayPlan {
            token: Zeroizing::new("tok-qwxzvk".into()),
            entries: vec![GatewayEntry {
                name: "docs".into(),
                scope: Scope::User,
                url: "http://127.0.0.1:8789/mcp/mcp-docs".into(),
                approval_mode: None,
            }],
        }),
        files: None,
        chat: None,
        hook: None,
        proxy_client_header: None,
    }
}

/// Integrator ruling 2026-10-10: a Codex gateway entry gets `required = true`
/// and `startup_timeout_sec = 30`, and reads as connected. A config connected
/// before the ruling (the entry and the backup's record without the two
/// keys) still reads as connected, not as changed outside inumaki: the
/// next connect rewrites the entry with them.
#[test]
fn codex_gateway_entries_wait_for_the_gateway_and_older_entries_stay_connected() {
    let home = tempfile::tempdir().unwrap();
    let codex = home.path().join(".codex");
    std::fs::create_dir_all(&codex).unwrap();
    let cfg = codex.join("config.toml");
    let original =
        "model = \"gpt-5-codex\"\n\n[mcp_servers.docs]\ncommand = \"/usr/local/bin/docs-mcp\"\n";
    std::fs::write(&cfg, original).unwrap();
    let ad = adapter(HarnessId::Codex);
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    let b = ad
        .apply(&inst, &codex_gateway_plan(&home.path().join("data")))
        .unwrap();
    let v: toml::Value = toml::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    let docs = &v["mcp_servers"]["docs"];
    assert_eq!(docs["required"].as_bool(), Some(true));
    assert_eq!(docs["startup_timeout_sec"].as_integer(), Some(30));
    assert!(
        docs.get("default_tools_approval_mode").is_none(),
        "tool approval stays the user's decision"
    );
    let connected = |b: &Backup| {
        let mut sys = SystemState {
            service_up: true,
            gateway_base: "http://127.0.0.1:8789".into(),
            applied: Some(b.clone()),
            ..Default::default()
        };
        sys.datasets_running.insert("mcp-docs".into());
        matches!(
            ad.status(&inst, &sys).paths[0].1,
            PathState::Connected { .. }
        )
    };
    assert!(connected(&b));
    // Revert restores the original bytes: the new keys go with the entry.
    ad.revert(&inst, &b).unwrap();
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), original);

    // The same connect as written before the ruling: entry and record
    // without the two keys.
    let mut b = ad
        .apply(&inst, &codex_gateway_plan(&home.path().join("data")))
        .unwrap();
    let old = std::fs::read_to_string(&cfg)
        .unwrap()
        .replace("required = true\nstartup_timeout_sec = 30\n", "");
    assert!(!old.contains("required"));
    std::fs::write(&cfg, &old).unwrap();
    for f in &mut b.files {
        for r in &mut f.records {
            if let inumaki_adapters::backup::EditRecord::Set { path, after, .. } = r
                && path.first().map(String::as_str) == Some("mcp_servers")
            {
                let m = after.as_object_mut().unwrap();
                m.remove("required");
                m.remove("startup_timeout_sec");
            }
        }
    }
    assert!(connected(&b), "an older connect is not reported as broken");

    // Stored as such (the manifest an older inumaki wrote), a reconnect
    // over it adds both keys, and revert still gives the original bytes.
    for f in &mut b.files {
        if f.role == FileRole::CodexConfig {
            f.sha_after = inumaki_adapters::fsio::sha256_hex(old.as_bytes());
        }
    }
    std::fs::write(
        b.dir.join("manifest.json"),
        serde_json::to_vec_pretty(&b).unwrap(),
    )
    .unwrap();
    let b2 = ad
        .apply(&inst, &codex_gateway_plan(&home.path().join("data")))
        .unwrap();
    let v: toml::Value = toml::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    assert_eq!(v["mcp_servers"]["docs"]["required"].as_bool(), Some(true));
    assert_eq!(
        v["mcp_servers"]["docs"]["startup_timeout_sec"].as_integer(),
        Some(30)
    );
    assert!(connected(&b2));
    ad.revert(&inst, &b2).unwrap();
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), original);
}

/// Integrator ruling 2026-10-10: `approval_policy = "never"` in Codex's
/// `config.toml` makes Codex refuse the inumaki tool calls; connect reports
/// one fixed warning (no value, no path) when it writes a gateway entry, and
/// nothing when the policy is absent or another value, the file cannot be
/// read or parsed, or no gateway entry is written.
#[test]
fn codex_approval_never_gives_one_fixed_warning() {
    let home = tempfile::tempdir().unwrap();
    let codex = home.path().join(".codex");
    std::fs::create_dir_all(&codex).unwrap();
    let cfg = codex.join("config.toml");
    let ad = adapter(HarnessId::Codex);
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    let plan = codex_gateway_plan(&home.path().join("data"));
    let warnings = |body: &str, plan: &ConnectPlan| {
        std::fs::write(&cfg, body).unwrap();
        ad.connect_warnings(&inst, plan)
    };
    let never = "model = \"gpt-5-codex\"\napproval_policy = \"never\"\n\n[mcp_servers.docs]\ncommand = \"/opt/qwxzvk-secret-mcp\"\n";
    assert_eq!(
        warnings(never, &plan),
        vec![ConnectWarning::CodexApprovalNever]
    );
    let w = ConnectWarning::CodexApprovalNever;
    assert_eq!(w.code(), "codex_approval_never");
    let text = w.sentence();
    assert!(text.contains("approval_policy = never"));
    assert!(text.contains("default_tools_approval_mode"));
    for leak in [
        "qwxzvk",
        "/",
        "gpt-5",
        "docs",
        &*home.path().to_string_lossy(),
    ] {
        assert!(!text.contains(leak), "{leak}");
    }
    // Absent, another value, another shape.
    for body in [
        "model = \"gpt-5-codex\"\n",
        "approval_policy = \"on-request\"\n",
        "approval_policy = { granular = { mcp_elicitations = false } }\n",
        "[profiles.fast]\napproval_policy = \"never\"\n",
    ] {
        assert!(warnings(body, &plan).is_empty(), "{body}");
    }
    // Unparseable, unreadable, missing.
    assert!(warnings("approval_policy = \"never\"\n[[[", &plan).is_empty());
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&cfg, never).unwrap();
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = std::fs::read(&cfg).is_err();
        let got = ad.connect_warnings(&inst, &plan);
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
        if unreadable {
            assert!(got.is_empty(), "an unreadable config gives no warning");
        }
    }
    std::fs::remove_file(&cfg).unwrap();
    assert!(ad.connect_warnings(&inst, &plan).is_empty());
    // No gateway entry written: no inumaki tool to refuse.
    let no_gateway = ConnectPlan {
        gateway: None,
        ..codex_gateway_plan(&home.path().join("data"))
    };
    assert!(warnings(never, &no_gateway).is_empty());
    // Other harnesses report none.
    assert!(
        adapter(HarnessId::ClaudeCode)
            .connect_warnings(&inst, &plan)
            .is_empty()
    );
}

/// Follow-up ruling (lane L5, 2026-10-10): `default_tools_approval_mode` on
/// an inumaki gateway entry is the user's. Added by hand it is not drift,
/// any re-apply carries it (from the file, or from the plan when the app
/// reverted first), inumaki never invents it, revert takes it away with the
/// entry without a conflict, and once set the approval warning is not shown.
#[test]
fn codex_user_approval_mode_is_kept_ignored_by_drift_and_reverted_with_the_entry() {
    let home = tempfile::tempdir().unwrap();
    let codex = home.path().join(".codex");
    std::fs::create_dir_all(&codex).unwrap();
    let cfg = codex.join("config.toml");
    let original = "approval_policy = \"never\"\n\n[mcp_servers.docs]\ncommand = \"/usr/local/bin/docs-mcp\"\n";
    std::fs::write(&cfg, original).unwrap();
    let ad = adapter(HarnessId::Codex);
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    let data = home.path().join("data");
    let plan = codex_gateway_plan(&data);
    let read = || std::fs::read_to_string(&cfg).unwrap();
    let mode = || -> Option<String> {
        let v: toml::Value = toml::from_str(&read()).unwrap();
        v["mcp_servers"]["docs"]
            .get("default_tools_approval_mode")
            .and_then(|m| m.as_str())
            .map(str::to_string)
    };
    let mcp = |b: &Backup| {
        let mut sys = SystemState {
            service_up: true,
            gateway_base: "http://127.0.0.1:8789".into(),
            applied: Some(b.clone()),
            ..Default::default()
        };
        sys.datasets_running.insert("mcp-docs".into());
        ad.status(&inst, &sys).paths[0].1
    };
    let add_mode = |v: &str| {
        let t = read().replace(
            "startup_timeout_sec = 30\n",
            &format!("startup_timeout_sec = 30\ndefault_tools_approval_mode = \"{v}\"\n"),
        );
        std::fs::write(&cfg, t).unwrap();
    };
    assert_eq!(
        ad.connect_warnings(&inst, &plan),
        vec![ConnectWarning::CodexApprovalNever]
    );
    let b = ad.apply(&inst, &plan).unwrap();
    assert_eq!(mode(), None, "never invented");

    // The user follows the warning: still connected, no warning.
    add_mode("approve");
    assert!(
        matches!(mcp(&b), PathState::Connected { .. }),
        "{:?}",
        mcp(&b)
    );
    assert!(ad.connect_warnings(&inst, &plan).is_empty());
    // Anything else in the entry is still drift.
    let saved = read();
    std::fs::write(&cfg, saved.replace("/mcp/mcp-docs", "/mcp/other")).unwrap();
    assert_eq!(
        mcp(&b),
        PathState::Broken {
            reason: ReasonCode::ChangedOutsideInumaki
        }
    );
    std::fs::write(&cfg, &saved).unwrap();

    // A re-apply over the file (the CLI) keeps the value.
    let b = ad.apply(&inst, &plan).unwrap();
    assert_eq!(mode().as_deref(), Some("approve"));
    assert!(matches!(mcp(&b), PathState::Connected { .. }));
    // Revert: the entry goes, the user's key with it, no conflict.
    let r = ad.revert(&inst, &b).unwrap();
    assert!(r.conflicts.is_empty());
    let back: toml::Value = toml::from_str(&read()).unwrap();
    assert_eq!(back, toml::from_str::<toml::Value>(original).unwrap());

    // The app reverts before it re-applies: the plan carries the value.
    let b = ad.apply(&inst, &plan).unwrap();
    add_mode("prompt");
    let r = ad.revert(&inst, &b).unwrap();
    assert!(r.conflicts.is_empty());
    let mut carried = codex_gateway_plan(&data);
    carried.gateway.as_mut().unwrap().entries[0].approval_mode = Some("prompt".into());
    assert!(ad.connect_warnings(&inst, &carried).is_empty());
    let b = ad.apply(&inst, &carried).unwrap();
    assert_eq!(mode().as_deref(), Some("prompt"));
    assert!(matches!(mcp(&b), PathState::Connected { .. }));
    ad.revert(&inst, &b).unwrap();
    assert_eq!(read(), original, "unchanged since apply: byte for byte");
}

/// Review follow-up (2026-10-10): the approval mode is carried only from
/// inumaki's own entry, the one being rewritten (same name, same gateway
/// URL), and raw. A user's own server entry of the same name (being
/// protected) or a stale inumaki entry for another dataset lends nothing,
/// and the warning still shows; a non-string value is kept as it is.
#[test]
fn codex_approval_mode_is_carried_only_from_inumakis_own_entry_and_raw() {
    let home = tempfile::tempdir().unwrap();
    let codex = home.path().join(".codex");
    std::fs::create_dir_all(&codex).unwrap();
    let cfg = codex.join("config.toml");
    let ad = adapter(HarnessId::Codex);
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    let data = home.path().join("data");
    let plan = codex_gateway_plan(&data);
    let entry = |path: &std::path::Path| -> toml::Value {
        let v: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v["mcp_servers"]["docs"].clone()
    };

    // The user's own server, approved by them, is being protected.
    let own = "approval_policy = \"never\"\n\n[mcp_servers.docs]\ncommand = \"/usr/local/bin/docs-mcp\"\ndefault_tools_approval_mode = \"approve\"\n";
    std::fs::write(&cfg, own).unwrap();
    assert_eq!(
        ad.connect_warnings(&inst, &plan),
        vec![ConnectWarning::CodexApprovalNever]
    );
    let b = ad.apply(&inst, &plan).unwrap();
    assert!(entry(&cfg).get("default_tools_approval_mode").is_none());
    ad.revert(&inst, &b).unwrap();
    assert_eq!(
        std::fs::read_to_string(&cfg).unwrap(),
        own,
        "theirs comes back"
    );

    // A stale inumaki entry of that name for another dataset.
    std::fs::write(
        &cfg,
        "approval_policy = \"never\"\n\n[mcp_servers.docs]\nurl = \"http://127.0.0.1:8789/mcp/mcp-old\"\ndefault_tools_approval_mode = \"approve\"\n",
    )
    .unwrap();
    assert_eq!(
        ad.connect_warnings(&inst, &plan),
        vec![ConnectWarning::CodexApprovalNever]
    );

    // Inumaki's own entry with a non-string value: carried raw.
    std::fs::write(
        &cfg,
        "approval_policy = \"never\"\n\n[mcp_servers.docs]\nurl = \"http://127.0.0.1:8789/mcp/mcp-docs\"\ndefault_tools_approval_mode = true\n",
    )
    .unwrap();
    assert!(ad.connect_warnings(&inst, &plan).is_empty());
    ad.apply(&inst, &plan).unwrap();
    assert_eq!(
        entry(&cfg).get("default_tools_approval_mode"),
        Some(&toml::Value::Boolean(true))
    );
}

fn proxy_sys(route: Route, base_url: &str) -> SystemState {
    SystemState {
        service_up: true,
        proxy: Some(ProxyInfo {
            routes: vec![RouteInfo {
                route,
                base_url: base_url.into(),
                failing: false,
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// F1: a chat path that is not routed through the proxy says so in a fixed
/// sentence, never a bare grey. Claude Code with no chat keys, and Codex with
/// a ChatGPT login and no provider written, are both `NotConnected` with a
/// reason that begins "Chat is not protected".
#[test]
fn chat_that_is_not_routed_states_why() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".claude")).unwrap();
    std::fs::write(home.path().join(".claude/settings.json"), "{}\n").unwrap();
    let cc = adapter(HarnessId::ClaudeCode);
    let inst = cc.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    let sys = proxy_sys(Route::Anthropic, "http://127.0.0.1:8787/anthropic");
    assert_eq!(
        cc.status(&inst, &sys).paths[2].1,
        PathState::NotConnected {
            reason: Some(ReasonCode::ChatNotProtected)
        }
    );
    assert_eq!(
        ReasonCode::ChatNotProtected.sentence(),
        "Chat is not protected: it goes straight to the provider, and inumaki does not see it."
    );

    // Codex, ChatGPT login, not opted in: not routed, with its own reason.
    let codex_home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(codex_home.path().join(".codex")).unwrap();
    std::fs::write(codex_home.path().join(".codex/config.toml"), "").unwrap();
    let cx = adapter(HarnessId::Codex);
    let mut ci = cx.detect(&ProbeEnv::for_tests(codex_home.path())).unwrap();
    ci.login = LoginKind::Oauth;
    let cs = proxy_sys(Route::Codex, "http://127.0.0.1:8787/codex");
    assert_eq!(
        cx.status(&ci, &cs).paths[2].1,
        PathState::NotConnected {
            reason: Some(ReasonCode::CodexChatgptUnverified)
        }
    );
    assert!(
        ReasonCode::CodexChatgptUnverified
            .sentence()
            .starts_with("Chat is not protected: Codex with a ChatGPT login")
    );
}

/// F4: Claude Code's chat route lives in the user-level settings, so
/// connecting it warns (once, with a fixed sentence) exactly when the plan
/// carries an anthropic route.
#[test]
fn claude_code_chat_connect_warns_that_every_window_is_affected() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".claude")).unwrap();
    std::fs::write(home.path().join(".claude/settings.json"), "{}\n").unwrap();
    let ad = adapter(HarnessId::ClaudeCode);
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    let plan = |chat: Option<ChatPlan>| ConnectPlan {
        chat,
        ..codex_gateway_plan(&home.path().join("data"))
    };
    let chat = |anthropic: Option<&str>| {
        Some(ChatPlan {
            anthropic: anthropic.map(str::to_string),
            openai: None,
            codex: None,
            codex_chatgpt: false,
        })
    };
    assert_eq!(
        ad.connect_warnings(&inst, &plan(chat(Some("http://127.0.0.1:8787/anthropic")))),
        vec![ConnectWarning::ClaudeCodeChatLive]
    );
    assert!(ad.connect_warnings(&inst, &plan(None)).is_empty());
    assert!(ad.connect_warnings(&inst, &plan(chat(None))).is_empty());
    let w = ConnectWarning::ClaudeCodeChatLive;
    assert_eq!(w.code(), "claude_code_chat_live");
    assert_eq!(
        w.sentence(),
        "Every open Claude Code window now sends chat through inumaki, including other projects; with the support-email or strict profile its chat requests are refused today."
    );
}

/// M9 Task 6: an apply that writes Codex's, Hermes', or OpenClaw's chat
/// route warns with that harness's fixed sentence (the CLI prints it, the
/// app shows it), and the backup it makes is recognized as holding the
/// route. A plan without chat, or with no route the harness can use,
/// neither warns nor records it.
#[test]
fn every_harness_warns_when_its_chat_route_is_written() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let write = |rel: &str, body: &str| {
        let f = h.join(rel);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, body).unwrap();
    };
    write(
        ".codex/auth.json",
        "{\"OPENAI_API_KEY\": \"sk-qwxzvk\", \"tokens\": null}",
    );
    write(".codex/config.toml", "model = \"gpt-5-codex\"\n");
    write(
        ".hermes/config.yaml",
        "model:\n  provider: openai\n  default: gpt-5\n",
    );
    write(".hermes/.env", "OPENAI_API_KEY=sk-qwxzvk\n");
    write(
        ".openclaw/openclaw.json",
        "{ agents: { defaults: { model: { primary: 'openai/gpt-5' } } }, models: { providers: { openai: { apiKey: '${OPENAI_API_KEY}' } } } }\n",
    );
    let env = ProbeEnv::for_tests(h);
    let chat = |openai: Option<&str>| {
        Some(ChatPlan {
            anthropic: None,
            openai: openai.map(str::to_string),
            codex: None,
            codex_chatgpt: false,
        })
    };
    for (id, want) in [
        (HarnessId::Codex, ConnectWarning::CodexChatLive),
        (HarnessId::Hermes, ConnectWarning::HermesChatLive),
        (HarnessId::Openclaw, ConnectWarning::OpenclawChatLive),
    ] {
        let ad = adapter(id);
        let inst = ad.detect(&env).unwrap();
        assert_eq!(inst.login, LoginKind::ApiKey, "{id:?}");
        let plan = |c: Option<ChatPlan>| ConnectPlan {
            gateway: None,
            chat: c,
            ..codex_gateway_plan(&h.join("data"))
        };
        let on = plan(chat(Some("http://127.0.0.1:8787/openai")));
        assert_eq!(ad.connect_warnings(&inst, &on), vec![want], "{id:?}");
        assert_eq!(ConnectWarning::chat_live(id), want);
        assert!(ad.connect_warnings(&inst, &plan(None)).is_empty(), "{id:?}");
        assert!(
            ad.connect_warnings(&inst, &plan(chat(None))).is_empty(),
            "{id:?}: no route for the selected provider"
        );

        let b = ad.apply(&inst, &on).unwrap();
        assert!(harness::backup_has_chat_route(ad.as_ref(), &b), "{id:?}");
        ad.revert(&inst, &b).unwrap();
        let b = ad.apply(&inst, &plan(None)).unwrap();
        assert!(!harness::backup_has_chat_route(ad.as_ref(), &b), "{id:?}");
        ad.revert(&inst, &b).unwrap();
    }
    for w in [
        ConnectWarning::CodexChatLive,
        ConnectWarning::HermesChatLive,
        ConnectWarning::OpenclawChatLive,
    ] {
        assert!(w.sentence().contains("next session"), "{w:?}");
        assert!(
            !w.sentence().contains("open "),
            "{w:?}: no hot-reload claim"
        );
    }
    assert!(
        ConnectWarning::CodexChatLive
            .sentence()
            .contains("restart Codex"),
        "the warning says Codex needs a restart"
    );
    assert!(
        !ConnectWarning::CodexChatLive.sentence().contains("refused"),
        "Codex chat is not refused any more"
    );
    for w in [
        ConnectWarning::HermesChatLive,
        ConnectWarning::OpenclawChatLive,
    ] {
        assert!(w.sentence().contains("not measured"), "{w:?}");
    }

    // Codex with a ChatGPT login: the codex route is written only on request.
    write(
        ".codex/auth.json",
        "{\"OPENAI_API_KEY\": null, \"tokens\": {\"id_token\": \"x\"}}",
    );
    let ad = adapter(HarnessId::Codex);
    let inst = ad.detect(&env).unwrap();
    assert_eq!(inst.login, LoginKind::Oauth);
    let oauth = |chatgpt: bool| ConnectPlan {
        gateway: None,
        chat: Some(ChatPlan {
            anthropic: None,
            openai: Some("http://127.0.0.1:8787/openai".into()),
            codex: Some("http://127.0.0.1:8787/codex".into()),
            codex_chatgpt: chatgpt,
        }),
        ..codex_gateway_plan(&h.join("data"))
    };
    assert_eq!(
        ad.connect_warnings(&inst, &oauth(true)),
        vec![ConnectWarning::CodexChatLive]
    );
    assert!(ad.connect_warnings(&inst, &oauth(false)).is_empty());
}

/// Ruling L97: the hook fails closed while the service is down, so an
/// apply that installs it warns with one fixed, content-free sentence.
/// Claude Code and Codex install the hook; Hermes Agent and OpenClaw never
/// do, so a hook in the plan gives them no warning (the goldens pin that
/// the warning matches what each apply writes).
#[test]
fn the_hook_warning_is_given_exactly_when_the_hook_is_installed() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let write = |rel: &str, body: &str| {
        let f = h.join(rel);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, body).unwrap();
    };
    write(".claude/settings.json", "{}\n");
    write(".codex/config.toml", "model = \"gpt-5-codex\"\n");
    write(
        ".hermes/config.yaml",
        "model:\n  provider: openai\n  default: gpt-5\n",
    );
    write(
        ".openclaw/openclaw.json",
        "{ agents: { defaults: { model: { primary: 'openai/gpt-5' } } } }\n",
    );
    let env = ProbeEnv::for_tests(h);
    let hook = |on: bool| ConnectPlan {
        gateway: None,
        hook: on.then(|| HookPlan {
            command: h.join("bin/inumaki-hook"),
            socket: h.join("data/qwxzvk.sock"),
        }),
        ..codex_gateway_plan(&h.join("data"))
    };
    for (id, installs) in [
        (HarnessId::ClaudeCode, true),
        (HarnessId::Codex, true),
        (HarnessId::Hermes, false),
        (HarnessId::Openclaw, false),
    ] {
        let ad = adapter(id);
        let inst = ad.detect(&env).unwrap();
        let want: Vec<ConnectWarning> = if installs {
            vec![ConnectWarning::HookBlocksWhenStopped]
        } else {
            Vec::new()
        };
        assert_eq!(ad.connect_warnings(&inst, &hook(true)), want, "{id:?}");
        assert!(
            ad.connect_warnings(&inst, &hook(false)).is_empty(),
            "{id:?}"
        );
    }
    let w = ConnectWarning::HookBlocksWhenStopped;
    assert_eq!(w.code(), "hook_blocks_when_stopped");
    assert_eq!(
        w.sentence(),
        "While inumaki is stopped, tool output in every connected session is blocked. Start the service to recover; Revert also needs it running."
    );
}

/// A Codex re-apply of an identical hook entry writes nothing new to
/// `hooks.json`, but the hook is still installed, so the warning is still
/// given.
#[test]
fn a_codex_reapply_of_an_identical_hook_still_warns() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    std::fs::create_dir_all(h.join(".codex")).unwrap();
    std::fs::write(h.join(".codex/config.toml"), "model = \"gpt-5-codex\"\n").unwrap();
    let env = ProbeEnv::for_tests(h);
    let plan = ConnectPlan {
        gateway: None,
        hook: Some(HookPlan {
            command: h.join("bin/inumaki-hook"),
            socket: h.join("data/qwxzvk.sock"),
        }),
        ..codex_gateway_plan(&h.join("data"))
    };
    let ad = adapter(HarnessId::Codex);
    let inst = ad.detect(&env).unwrap();
    ad.apply(&inst, &plan).unwrap();
    let inst = ad.detect(&env).unwrap();
    let hooks = std::fs::read_to_string(h.join(".codex/hooks.json")).unwrap();
    assert!(hooks.contains("inumaki-hook"), "{hooks}");
    assert_eq!(
        ad.connect_warnings(&inst, &plan),
        vec![ConnectWarning::HookBlocksWhenStopped]
    );
    ad.apply(&inst, &plan).unwrap();
    assert_eq!(
        std::fs::read_to_string(h.join(".codex/hooks.json")).unwrap(),
        hooks
    );
    assert_eq!(
        ad.connect_warnings(&inst, &plan),
        vec![ConnectWarning::HookBlocksWhenStopped]
    );
}
