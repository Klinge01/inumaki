//! Codex hook trust on Revert (docs/harness-adapters.md CX-HOOK "Hook
//! trust"): the user's Revert removes the one trust record Codex wrote for
//! inumaki's hook and nothing else; a Reconnect (`revert`) keeps it.

use std::path::{Path, PathBuf};

use inumaki_adapters::*;
use zeroize::Zeroizing;

/// The user already has an MCP server, so `[mcp_servers]` exists before
/// Connect. The tests below that need a table inumaki creates use
/// `FIRST_TIME` and `EMPTY_TABLE` instead.
const CONFIG: &str =
    "# mine\nmodel = \"gpt-5-codex\"\n\n[mcp_servers.docs]\nurl = \"https://docs.example/mcp\"\n";
/// A first-time user: no `mcp_servers` and no `hooks` table.
const FIRST_TIME: &str = "# mine\nmodel = \"gpt-5-codex\"\n";
/// `[mcp_servers]` exists before Connect and holds nothing.
const EMPTY_TABLE: &str = "# mine\nmodel = \"gpt-5-codex\"\n\n[mcp_servers]\n";
/// Written by Codex after the user connected, unrelated to inumaki.
const UNRELATED: &str = "\n[projects.\"/work/app\"]\ntrust_level = \"trusted\"\n";

struct Setup {
    _home: tempfile::TempDir,
    codex: PathBuf,
    ad: Box<dyn HarnessAdapter>,
    inst: Installation,
    backup: Backup,
}

impl Setup {
    fn config(&self) -> String {
        std::fs::read_to_string(self.codex.join("config.toml")).unwrap()
    }
    fn hooks_path(&self) -> String {
        self.codex.join("hooks.json").to_string_lossy().into_owned()
    }
    fn append(&self, text: &str) {
        let mut c = self.config();
        c.push_str(text);
        std::fs::write(self.codex.join("config.toml"), c).unwrap();
    }
}

fn trust_table(key: &str) -> String {
    format!("\n[hooks.state.\"{key}\"]\ntrusted_hash = \"sha256:0123abcd\"\n")
}

/// Connect Codex in a synthetic home: a user hook group at index 0, our hook
/// at index 1 (`gateway`: also a gateway entry, so `config.toml` is in the
/// backup).
fn connect(gateway: bool) -> Setup {
    connect_with(CONFIG, gateway)
}

fn connect_with(config: &str, gateway: bool) -> Setup {
    connect_outbox(config, gateway, false)
}

/// [`connect_with`]; `outbox`: the plan also lists a connected outbox, which
/// Codex gets as a `writable_roots` entry.
fn connect_outbox(config: &str, gateway: bool, outbox: bool) -> Setup {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let codex = home.path().join(".codex");
    std::fs::create_dir_all(&codex).unwrap();
    std::fs::write(codex.join("config.toml"), config).unwrap();
    let user_group = serde_json::json!({"matcher": "^Bash$", "hooks": [{"type": "command", "command": "~/bin/audit.sh"}]});
    std::fs::write(
        codex.join("hooks.json"),
        serde_json::to_string_pretty(&serde_json::json!({"hooks": {"PostToolUse": [user_group]}}))
            .unwrap(),
    )
    .unwrap();
    let bin = home.path().join("bin/inumaki-hook");
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    std::fs::write(&bin, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let ad = adapter(HarnessId::Codex);
    let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
    let base = "http://127.0.0.1:8789".to_string();
    let plan = ConnectPlan {
        data_dir: home.path().join("data"),
        gateway: gateway.then(|| GatewayPlan {
            token: Zeroizing::new("tok".to_string()),
            entries: vec![GatewayEntry {
                name: "inumaki-crm".to_string(),
                scope: Scope::User,
                url: format!("{base}/mcp/crm"),
                approval_mode: None,
            }],
        }),
        gateway_base: base,
        files: outbox.then(|| FilesPlan {
            mirror_root: home.path().join("mirror"),
            outboxes: vec![PathBuf::from("/inumaki/outbox")],
        }),
        chat: None,
        hook: Some(HookPlan {
            command: bin,
            socket: home.path().join("inumakid.sock"),
        }),
        proxy_client_header: None,
    };
    let backup = ad.apply(&inst, &plan).unwrap();
    Setup {
        _home: home,
        codex,
        ad,
        inst,
        backup,
    }
}

fn canonical(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

#[test]
fn revert_final_removes_exactly_our_trust_record_and_nothing_else() {
    let s = connect(true);
    s.append(&trust_table(&format!(
        "{}:post_tool_use:1:0",
        s.hooks_path()
    )));
    s.append(UNRELATED);
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(!r.codex_trust_left, "{r:?}");
    assert_eq!(
        s.config(),
        format!("{CONFIG}{UNRELATED}"),
        "the record and the emptied [hooks] are gone; Codex's own key stays"
    );
}

#[test]
fn revert_final_removes_the_record_under_the_canonical_path() {
    let s = connect(true);
    let canon = canonical(&s.codex.join("hooks.json"));
    s.append(&trust_table(&format!("{canon}:post_tool_use:1:0")));
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(!r.codex_trust_left, "{r:?}");
    assert_eq!(s.config(), CONFIG);
}

#[test]
fn other_positions_files_and_projects_keep_their_records() {
    let s = connect(true);
    let ours = format!("{}:post_tool_use:1:0", s.hooks_path());
    let same_file_other_position = format!("{}:post_tool_use:1:1", s.hooks_path());
    let user_group = format!("{}:post_tool_use:0:0", s.hooks_path());
    let other_project = "/other/project/.codex/hooks.json:post_tool_use:1:0";
    s.append(&trust_table(&ours));
    for k in [&same_file_other_position, &user_group, other_project] {
        s.append(&trust_table(k));
    }
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(!r.codex_trust_left, "{r:?}");
    let cfg = s.config();
    assert!(!cfg.contains(&format!("\"{ours}\"")), "{cfg}");
    for k in [&same_file_other_position, &user_group, other_project] {
        assert!(
            cfg.contains(&format!(
                "[hooks.state.\"{k}\"]\ntrusted_hash = \"sha256:0123abcd\""
            )),
            "{k} must survive: {cfg}"
        );
    }
}

#[test]
fn without_a_trust_record_config_toml_is_restored_byte_for_byte() {
    let s = connect(true);
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(!r.codex_trust_left && r.conflicts.is_empty(), "{r:?}");
    assert_eq!(s.config(), CONFIG);
}

/// The Reconnect path: `revert` then `apply` must not make the user trust
/// the hook again.
#[test]
fn plain_revert_keeps_the_trust_record() {
    let s = connect(true);
    let table = trust_table(&format!("{}:post_tool_use:1:0", s.hooks_path()));
    s.append(&table);
    let r = s.ad.revert(&s.inst, &s.backup).unwrap();
    assert!(!r.codex_trust_left);
    assert!(s.config().contains(table.trim_start()), "{}", s.config());
}

/// The revert stands when the record cannot be removed: the flag is set and
/// the result is still `Ok`.
#[test]
fn a_record_that_cannot_be_removed_sets_the_flag_and_the_revert_stands() {
    // Hook only: `config.toml` is not in the backup, so the revert does not
    // touch it, and the step that removes the record finds it unparsable.
    let s = connect(false);
    assert!(s.backup.file(FileRole::CodexConfig).is_none());
    s.append(&trust_table(&format!(
        "{}:post_tool_use:1:0",
        s.hooks_path()
    )));
    s.append("\nthis = is not [valid toml\n");
    let before = s.config();
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(r.codex_trust_left, "{r:?}");
    assert_eq!(s.config(), before, "an unreadable file is not rewritten");
    let hooks = std::fs::read_to_string(s.codex.join("hooks.json")).unwrap();
    assert!(!hooks.contains("inumaki-hook"), "the revert itself stands");
}

/// A first-time user's Revert: Connect created `[mcp_servers]`, Codex then
/// appended a key and the trust record. The table inumaki created goes with
/// its entry; the key Codex wrote stays.
#[test]
fn revert_removes_the_table_connect_created_and_keeps_codexs_own_key() {
    let s = connect_with(FIRST_TIME, true);
    assert!(s.config().contains("[mcp_servers.inumaki-crm]"));
    s.append(UNRELATED);
    s.append(&trust_table(&format!(
        "{}:post_tool_use:1:0",
        s.hooks_path()
    )));
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(!r.codex_trust_left && r.conflicts.is_empty(), "{r:?}");
    let cfg = s.config();
    assert!(
        !cfg.contains("mcp_servers") && !cfg.contains("hooks"),
        "{cfg}"
    );
    assert!(cfg.contains(UNRELATED.trim_start()), "{cfg}");
    assert!(cfg.starts_with(FIRST_TIME), "{cfg}");
}

/// A table that existed before Connect is never removed, even empty.
#[test]
fn a_table_that_existed_before_connect_stays_after_revert() {
    let s = connect_with(EMPTY_TABLE, true);
    s.append(UNRELATED);
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(r.conflicts.is_empty(), "{r:?}");
    let cfg = s.config();
    assert!(cfg.contains("[mcp_servers]"), "{cfg}");
    assert!(!cfg.contains("inumaki-crm"), "{cfg}");
    assert!(cfg.contains(UNRELATED.trim_start()), "{cfg}");
}

/// A table Connect created but another key now shares stays with that key.
#[test]
fn a_created_table_holding_another_key_stays() {
    let s = connect_with(FIRST_TIME, true);
    s.append("\n[mcp_servers.theirs]\nurl = \"https://theirs.example/mcp\"\n");
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(r.conflicts.is_empty(), "{r:?}");
    let cfg = s.config();
    assert!(
        cfg.contains("[mcp_servers.theirs]") && !cfg.contains("inumaki-crm"),
        "{cfg}"
    );
}

/// The outbox goes into `sandbox_workspace_write.writable_roots`. A first-time
/// user has neither the table nor the key: Revert removes both. Codex wrote its own record in
/// between, so the file is edited key by key, not restored from the copy.
#[test]
fn revert_removes_the_writable_roots_table_connect_created() {
    let s = connect_outbox(FIRST_TIME, true, true);
    assert!(s.config().contains("/inumaki/outbox"), "{}", s.config());
    s.append(UNRELATED);
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(r.conflicts.is_empty(), "{r:?}");
    assert_eq!(s.config(), format!("{FIRST_TIME}{UNRELATED}"));
}

/// A list the user already had keeps their entries and nothing else.
#[test]
fn revert_leaves_the_users_writable_roots_entries() {
    let cfg = format!("{FIRST_TIME}\n[sandbox_workspace_write]\nwritable_roots = [\"/a\"]\n");
    let s = connect_outbox(&cfg, true, true);
    assert!(s.config().contains("/inumaki/outbox"), "{}", s.config());
    s.append(UNRELATED);
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(r.conflicts.is_empty(), "{r:?}");
    let v: toml::Value = toml::from_str(&s.config()).unwrap();
    let roots = &v["sandbox_workspace_write"]["writable_roots"];
    assert_eq!(roots.to_string(), "[\"/a\"]", "{}", s.config());
    assert!(s.config().contains(UNRELATED.trim_start()));
}

/// A table the user had, without the key: the table stays, the key goes.
#[test]
fn revert_keeps_the_users_sandbox_table_but_removes_the_key_it_added() {
    let cfg = format!("{FIRST_TIME}\n[sandbox_workspace_write]\nnetwork_access = true\n");
    let s = connect_outbox(&cfg, true, true);
    s.append(UNRELATED);
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(r.conflicts.is_empty(), "{r:?}");
    let c = s.config();
    assert!(c.contains("[sandbox_workspace_write]") && c.contains("network_access = true"));
    assert!(!c.contains("writable_roots"), "{c}");
    let empty = format!("{FIRST_TIME}\n[sandbox_workspace_write]\n");
    let s = connect_outbox(&empty, true, true);
    s.append(UNRELATED);
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(r.conflicts.is_empty(), "{r:?}");
    let c = s.config();
    assert!(c.contains("[sandbox_workspace_write]"), "{c}");
    assert!(!c.contains("writable_roots"), "{c}");
}

/// Data-loss guard: the user adds their own element to the array Connect
/// created. Revert pulls only ours; the array and its table stay with theirs.
#[test]
fn revert_keeps_an_element_the_user_added_to_the_array_connect_created() {
    let s = connect_outbox(FIRST_TIME, true, true);
    let before = s.config();
    assert!(before.contains("/inumaki/outbox"), "{before}");
    let edited = before.replacen("writable_roots = [", "writable_roots = [\"/mine\", ", 1);
    assert_ne!(edited, before, "{before}");
    std::fs::write(s.codex.join("config.toml"), edited).unwrap();
    let r = s.ad.revert_final(&s.inst, &s.backup).unwrap();
    assert!(r.conflicts.is_empty(), "{r:?}");
    let v: toml::Value = toml::from_str(&s.config()).unwrap();
    let roots = &v["sandbox_workspace_write"]["writable_roots"];
    assert_eq!(roots.to_string(), "[\"/mine\"]", "{}", s.config());
}
