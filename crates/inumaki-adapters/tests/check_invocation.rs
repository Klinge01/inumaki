//! The check's harness runs are isolated (M6 spec §8.2): empty working
//! directory, temporary configuration directory, only the check's gateway
//! entry, the check route as base URL, a dummy credential, no other traffic.

use std::path::{Path, PathBuf};
use std::time::Duration;

use inumaki_adapters::CheckPlan;
use inumaki_adapters::check;
use zeroize::Zeroizing;

const TOKEN: &str = "inumaki_gw_qwxzvkTOKEN000000000000000";
const SOURCE: &str = "/private/var/folders/x/T/inumaki-check-0a1b2c3d-Xy9z/source";

fn plan(root: &Path, routes: &[(&str, &str)], hook: bool) -> CheckPlan {
    CheckPlan {
        workdir: root.join("work"),
        config_dir: root.join("config"),
        gateway_url: "http://127.0.0.1:8789/mcp/check-0123456789ab".into(),
        gateway_token: Zeroizing::new(TOKEN.into()),
        server: "inumaki-check-012345".into(),
        mirror_file: Some(PathBuf::from("/Users/x/Inumaki/d1b2/canary.txt")),
        source_dir: Some(PathBuf::from(SOURCE)),
        routes: routes
            .iter()
            .map(|(u, b)| (u.to_string(), b.to_string()))
            .collect(),
        path_env: "/opt/homebrew/bin:/usr/bin:/bin".into(),
        hook_command: hook.then(|| {
            PathBuf::from("/Users/x/Library/Application Support/inumaki/bin/inumaki-hook")
        }),
        socket: PathBuf::from("/Users/x/Library/Application Support/inumaki/inumakid.sock"),
    }
}

fn env<'a>(inv: &'a inumaki_adapters::Invocation, k: &str) -> Option<&'a str> {
    inv.env
        .iter()
        .find(|(n, _)| n == k)
        .map(|(_, v)| v.as_str())
}

#[test]
fn claude_code_runs_only_with_the_check_config() {
    let root = Path::new("/tmp/inumaki-check-test");
    let base = "http://127.0.0.1:8787/check/0123456789abcdef0123456789abcdef/anthropic";
    let inv = check::claude_code(
        Path::new("/opt/homebrew/bin/claude"),
        &plan(root, &[("anthropic", base)], false),
    )
    .unwrap();
    let a = &inv.args;
    assert_eq!(a[0], "-p");
    assert!(
        a.windows(2)
            .any(|w| w[0] == "--mcp-config" && Path::new(&w[1]).starts_with(root.join("config")))
    );
    assert!(a.contains(&"--strict-mcp-config".to_string()));
    let allowed = a
        .windows(2)
        .find(|w| w[0] == "--allowedTools")
        .map(|w| w[1].clone())
        .unwrap();
    assert!(
        allowed.contains("mcp__inumaki-check-012345__lookup_record") && allowed.contains("Read")
    );
    assert!(
        !allowed.contains("Bash"),
        "without the hook, Bash stays denied"
    );
    assert!(
        a.windows(2)
            .any(|w| w[0] == "--add-dir" && w[1] == "/Users/x/Inumaki/d1b2")
    );
    assert_eq!(inv.cwd, root.join("work"));
    assert_eq!(
        env(&inv, "CLAUDE_CONFIG_DIR"),
        Some(root.join("config").to_str().unwrap())
    );
    assert_eq!(
        env(&inv, "HOME"),
        Some(root.join("config").to_str().unwrap())
    );
    assert_eq!(env(&inv, "ANTHROPIC_BASE_URL"), Some(base));
    assert_eq!(
        env(&inv, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"),
        Some("1")
    );
    assert!(env(&inv, "ANTHROPIC_API_KEY").is_some_and(|k| k.starts_with("inumaki-check-")));
    assert!(
        inv.files
            .iter()
            .all(|(p, _)| p.starts_with(root.join("config")))
    );
    let mcp: serde_json::Value = serde_json::from_str(
        &inv.files
            .iter()
            .find(|(p, _)| p.ends_with("check-mcp.json"))
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(
        mcp["mcpServers"]["inumaki-check-012345"]["headers"]["Authorization"],
        format!("Bearer {TOKEN}")
    );
    assert!(inv.timeout <= Duration::from_secs(180));
    assert!(
        !format!("{inv:?}").contains(TOKEN),
        "Invocation Debug prints no token"
    );
}

#[test]
fn claude_code_with_the_hook_allows_bash_and_installs_the_hook() {
    let root = Path::new("/tmp/inumaki-check-test");
    let inv = check::claude_code(
        Path::new("/usr/local/bin/claude"),
        &plan(root, &[("anthropic", "http://x/check/a/anthropic")], true),
    )
    .unwrap();
    let allowed = inv
        .args
        .windows(2)
        .find(|w| w[0] == "--allowedTools")
        .map(|w| w[1].clone())
        .unwrap();
    assert!(allowed.contains("Bash"));
    let settings: serde_json::Value = serde_json::from_str(
        &inv.files
            .iter()
            .find(|(p, _)| p.ends_with("settings.json"))
            .unwrap()
            .1,
    )
    .unwrap();
    // Review C2: the bin directory has a space, and HOME is the temporary
    // config directory during a check, so the hook must be told its socket.
    assert_eq!(
        settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
        "'/Users/x/Library/Application Support/inumaki/bin/inumaki-hook' claude-code --socket '/Users/x/Library/Application Support/inumaki/inumakid.sock'"
    );
}

#[test]
fn codex_uses_its_own_home_and_the_check_provider() {
    let root = Path::new("/tmp/inumaki-check-test");
    let inv = check::codex(
        Path::new("/opt/homebrew/bin/codex"),
        &plan(
            root,
            &[("openai", "http://127.0.0.1:8787/check/ab/openai")],
            false,
        ),
    )
    .unwrap();
    assert_eq!(&inv.args[..2], ["exec", "--skip-git-repo-check"]);
    assert_eq!(
        env(&inv, "CODEX_HOME"),
        Some(root.join("config").to_str().unwrap())
    );
    let cfg: toml::Value = toml::from_str(
        &inv.files
            .iter()
            .find(|(p, _)| p.ends_with("config.toml"))
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(cfg["model_provider"].as_str(), Some("inumaki-check"));
    assert_eq!(
        cfg["model_providers"]["inumaki-check"]["base_url"].as_str(),
        Some("http://127.0.0.1:8787/check/ab/openai/v1")
    );
    assert_eq!(
        cfg["mcp_servers"]["inumaki-check-012345"]["url"].as_str(),
        Some("http://127.0.0.1:8789/mcp/check-0123456789ab")
    );
    // Recorded from Codex 0.159.2 (M8 spec §20 amendment 2026-10-10):
    // without `required` the first request has no MCP tools (startup race),
    // and without the approval mode a call is refused under
    // `approval_policy = "never"`.
    let srv = &cfg["mcp_servers"]["inumaki-check-012345"];
    assert_eq!(srv["required"].as_bool(), Some(true));
    assert_eq!(srv["default_tools_approval_mode"].as_str(), Some("approve"));
    assert_eq!(srv["startup_timeout_sec"].as_integer(), Some(30));
    assert_eq!(cfg["approval_policy"].as_str(), Some("never"));
    assert_eq!(
        cfg["check_for_update_on_startup"].as_bool(),
        Some(false),
        "no other traffic"
    );
    assert!(!format!("{inv:?}").contains(TOKEN));
}

#[test]
fn no_route_means_no_harness_run() {
    let root = Path::new("/tmp/inumaki-check-test");
    assert!(
        check::claude_code(
            Path::new("/bin/claude"),
            &plan(root, &[("openai", "http://x")], false)
        )
        .is_none()
    );
    assert!(
        check::codex(
            Path::new("/bin/codex"),
            &plan(root, &[("anthropic", "http://x")], false)
        )
        .is_none()
    );
}

#[test]
fn hermes_uses_its_own_home_and_values_that_need_escaping_are_refused() {
    let root = Path::new("/tmp/inumaki-check-test");
    let mut p = plan(
        root,
        &[("openai", "http://127.0.0.1:8787/check/ab/openai")],
        false,
    );
    let inv = check::hermes(Path::new("/opt/homebrew/bin/hermes"), &p).unwrap();
    assert_eq!(
        env(&inv, "HERMES_HOME"),
        Some(root.join("config").to_str().unwrap())
    );
    let cfg: serde_yaml_ng::Value = serde_yaml_ng::from_str(&inv.files[0].1).unwrap();
    assert_eq!(
        cfg["mcp_servers"]["inumaki-check-012345"]["headers"]["Authorization"].as_str(),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert!(!format!("{inv:?}").contains(TOKEN) && !format!("{p:?}").contains(TOKEN));
    // Fail closed: a value that would need quoting in the generated TOML/YAML is not written.
    p.server = "bad\"name".into();
    assert!(check::hermes(Path::new("/bin/hermes"), &p).is_none());
    assert!(check::codex(Path::new("/bin/codex"), &p).is_none());
}

#[test]
fn no_run_leaks_the_token_or_inherits_the_environment() {
    let root = Path::new("/tmp/inumaki-check-test");
    let routes = [
        ("anthropic", "http://x/check/a/anthropic"),
        ("openai", "http://x/check/a/openai"),
    ];
    let runs = [
        check::claude_code(Path::new("/bin/claude"), &plan(root, &routes, false)).unwrap(),
        check::claude_code(Path::new("/bin/claude"), &plan(root, &routes, true)).unwrap(),
        check::codex(Path::new("/bin/codex"), &plan(root, &routes, false)).unwrap(),
        check::hermes(Path::new("/bin/hermes"), &plan(root, &routes, false)).unwrap(),
    ];
    const ALLOWED: &[&str] = &[
        "HOME",
        "PATH",
        "LANG",
        "CLAUDE_CONFIG_DIR",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        "DISABLE_AUTOUPDATER",
        "CODEX_HOME",
        "HERMES_HOME",
        "INUMAKI_CHECK_KEY",
    ];
    for inv in &runs {
        assert!(
            inv.args.iter().all(|a| !a.contains(TOKEN)),
            "token in an argument"
        );
        assert!(
            inv.env.iter().all(|(_, v)| !v.contains(TOKEN)),
            "token in the environment"
        );
        assert!(
            inv.env.iter().all(|(k, _)| ALLOWED.contains(&k.as_str())),
            "unexpected environment variable"
        );
        assert!(
            !inv.files.is_empty()
                && inv
                    .files
                    .iter()
                    .all(|(p, _)| p.starts_with(root.join("config")))
        );
        assert_eq!(inv.cwd, root.join("work"));
    }
}

#[test]
fn a_server_name_outside_the_strict_set_is_refused_everywhere() {
    let root = Path::new("/tmp/inumaki-check-test");
    let routes = [
        ("anthropic", "http://x/check/a/anthropic"),
        ("openai", "http://x/check/a/openai"),
    ];
    for bad in ["a b", "a.b", "a]", "", "x\"y"] {
        let mut p = plan(root, &routes, false);
        p.server = bad.into();
        assert!(
            check::claude_code(Path::new("/bin/claude"), &p).is_none(),
            "claude {bad:?}"
        );
        assert!(
            check::codex(Path::new("/bin/codex"), &p).is_none(),
            "codex {bad:?}"
        );
        assert!(
            check::hermes(Path::new("/bin/hermes"), &p).is_none(),
            "hermes {bad:?}"
        );
    }
}

fn add_dirs(inv: &inumaki_adapters::Invocation) -> Vec<&str> {
    inv.args
        .windows(2)
        .filter(|w| w[0] == "--add-dir")
        .map(|w| w[1].as_str())
        .collect()
}

/// M6 spec §9.7 amendment 2026-10-10: the scripted `Bash` `cat` reads the
/// check's source directory, so Claude Code gets it as `--add-dir`, but only
/// with the hook (without it Bash is denied, Task 8a), and only when it has
/// the shape of the daemon's temporary source directory.
#[test]
fn claude_code_adds_the_source_dir_only_with_the_hook() {
    let root = Path::new("/tmp/inumaki-check-test");
    let routes = [("anthropic", "http://x/check/a/anthropic")];
    let claude = |p: &CheckPlan| check::claude_code(Path::new("/bin/claude"), p).unwrap();
    let with_hook = claude(&plan(root, &routes, true));
    assert_eq!(add_dirs(&with_hook), ["/Users/x/Inumaki/d1b2", SOURCE]);
    // `--allowedTools` only pre-approves: read-only Grep and Glob run inside
    // added directories without approval, so the hook covers them too.
    let settings: serde_json::Value = serde_json::from_str(
        &with_hook
            .files
            .iter()
            .find(|(p, _)| p.ends_with("settings.json"))
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(
        settings["hooks"]["PostToolUse"][0]["matcher"],
        "Bash|Read|Grep|Glob"
    );
    let without = claude(&plan(root, &routes, false));
    assert_eq!(
        add_dirs(&without),
        ["/Users/x/Inumaki/d1b2"],
        "no source dir without the hook"
    );
    let mut p = plan(root, &routes, true);
    p.source_dir = None;
    assert_eq!(add_dirs(&claude(&p)), ["/Users/x/Inumaki/d1b2"]);
    for bad in [
        "relative/inumaki-check-0a1b-Xy9z/source",
        "/tmp/inumaki-check-0a1b-Xy9z/../source",
        "/tmp/inumaki-check-0a1b-Xy9z/./source",
        "/tmp/inumaki-check-0a1b-Xy9z/source/..",
        "/tmp/inumaki-check-0a\nb/source",
        "/tmp/inumaki-check-0a\u{7}b/source",
        "/tmp/other-0a1b/source",
        "/tmp/inumaki-check-/source",
        "/tmp/inumaki-check-0a1b-Xy9z/outbox",
        "/Users/x",
        "/",
    ] {
        assert!(!check::source_dir_ok(Path::new(bad)), "{bad:?}");
        let mut p = plan(root, &routes, true);
        p.source_dir = Some(PathBuf::from(bad));
        assert_eq!(add_dirs(&claude(&p)), ["/Users/x/Inumaki/d1b2"], "{bad:?}");
    }
    assert!(check::source_dir_ok(Path::new(SOURCE)));
    // Codex and Hermes read no mirror or source file: unchanged.
    let routes = [("openai", "http://x/check/a/openai")];
    let p = plan(root, &routes, true);
    for inv in [
        check::codex(Path::new("/bin/codex"), &p).unwrap(),
        check::hermes(Path::new("/bin/hermes"), &p).unwrap(),
    ] {
        assert!(
            inv.args
                .iter()
                .all(|a| !a.contains("inumaki-check-0a1b2c3d"))
        );
    }
    assert!(
        !format!("{p:?}").contains("inumaki-check-0a1b2c3d"),
        "Debug prints no path"
    );
}
