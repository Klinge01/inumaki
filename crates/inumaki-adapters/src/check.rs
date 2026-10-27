//! Non-interactive harness runs for the end-to-end check (M6 spec §8.2).
//! Each run gets an empty working directory and a temporary configuration
//! directory (both created and deleted by the app), only the check's
//! gateway entry, the check route as base URL, a dummy credential, and the
//! harness's switches for "no other network traffic". The user's own
//! configuration is never read or written.

use std::path::Path;
use std::time::Duration;

use crate::harness::sh_quote;
use crate::model::{CheckPlan, Invocation};

/// The prompt; the scripted upstream decides the tool calls anyway.
pub const PROMPT: &str =
    "Call the lookup_record tool, read any file you are given, then repeat the results verbatim.";
const DUMMY_KEY: &str = "inumaki-check-dummy-credential";
const TIMEOUT: Duration = Duration::from_secs(120);

fn route<'a>(plan: &'a CheckPlan, upstream: &str) -> Option<&'a str> {
    plan.routes
        .iter()
        .find(|(u, _)| u == upstream)
        .map(|(_, b)| b.as_str())
}

/// Values written into TOML or YAML by `format!` must not need escaping.
fn plain(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '\'' | '\\' | '`' | '$'))
}

/// The MCP server name ends up in `--allowedTools` (space-separated), in TOML
/// table headers, and in YAML keys: only `[A-Za-z0-9_-]+` is accepted.
fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

fn base_env(plan: &CheckPlan) -> Vec<(String, String)> {
    let d = plan.config_dir.display().to_string();
    vec![
        ("HOME".into(), d),
        ("PATH".into(), plan.path_env.clone()),
        ("LANG".into(), "C.UTF-8".into()),
    ]
}

/// The check's `PostToolUse` matcher: every tool that can read the mirror
/// or the source directory (an exact-string list, hooks.md matcher table).
pub const CHECK_HOOK_MATCHER: &str = "Bash|Read|Grep|Glob";

/// The prefix of the daemon's temporary check directories.
const TMP_PREFIX: &str = "inumaki-check-";

/// Whether `dir` has the shape of the check's own source directory,
/// `<temp>/inumaki-check-<tag>-<random>/source`: absolute, no `.` or `..`
/// segment, no control characters, named `source`, inside an
/// `inumaki-check-` directory. Anything else is never handed to a harness
/// as an allowed directory.
pub fn source_dir_ok(dir: &Path) -> bool {
    let Some(s) = dir.to_str() else {
        return false;
    };
    let parent_ok = dir
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.len() > TMP_PREFIX.len() && n.starts_with(TMP_PREFIX));
    dir.is_absolute()
        // On the string: `Path::components` drops an inner `.`.
        && !s.split('/').any(|seg| seg == "." || seg == "..")
        && !s.chars().any(char::is_control)
        && dir.file_name().is_some_and(|n| n == "source")
        && parent_ok
}

/// `claude -p` with `--mcp-config FILE --strict-mcp-config` (spec §8.2).
///
/// `--no-session-persistence` and the space-separated `--allowedTools` list
/// are the forms the 2026-09-28 smoke run used with Claude Code 2.1.283
/// (`docs/smoke-claude-code.md`); M6-1's verification record (2.1.284) does
/// not cover them, so the installed `claude --help` has not been compared.
pub fn claude_code(binary: &Path, plan: &CheckPlan) -> Option<Invocation> {
    let base = route(plan, "anthropic")?;
    if !name_ok(&plan.server) {
        return None;
    }
    let cfg = &plan.config_dir;
    let mcp = serde_json::json!({ "mcpServers": { plan.server.clone(): {
        "type": "http", "url": plan.gateway_url,
        "headers": { "Authorization": format!("Bearer {}", plan.gateway_token.as_str()) } } } });
    let mut files = vec![(cfg.join("check-mcp.json"), mcp.to_string())];
    let mut allowed = vec![
        format!("mcp__{}__lookup_record", plan.server),
        "Read".to_string(),
    ];
    if let Some(hook) = &plan.hook_command {
        allowed.push("Bash".into());
        let command = format!(
            "{} claude-code --socket {}",
            sh_quote(hook),
            sh_quote(&plan.socket)
        );
        // `--allowedTools` pre-approves; it does not restrict. Grep and Glob
        // are read-only and run without approval inside the working and
        // added directories, so they are hooked too: with the source
        // directory added, the hook stays the single control on its text.
        let settings = serde_json::json!({ "hooks": { "PostToolUse": [{ "matcher": CHECK_HOOK_MATCHER,
            "hooks": [{ "type": "command", "command": command, "timeout": 30 }] }] } });
        files.push((cfg.join("settings.json"), settings.to_string()));
    }
    let mut args = vec![
        "-p".to_string(),
        PROMPT.into(),
        "--mcp-config".into(),
        cfg.join("check-mcp.json").display().to_string(),
        "--strict-mcp-config".into(),
        "--allowedTools".into(),
        allowed.join(" "),
        "--output-format".into(),
        "text".into(),
        "--max-turns".into(),
        "6".into(),
        "--no-session-persistence".into(),
    ];
    if let Some(dir) = plan.mirror_file.as_ref().and_then(|f| f.parent()) {
        args.extend(["--add-dir".to_string(), dir.display().to_string()]);
    }
    // The scripted `Bash` call `cat`s the canary in the check's source
    // directory, outside the working directory. In the 9b run 4 (Claude
    // Code 2.1.296) that call came back as an error and no Bash hook ran;
    // the likely cause is Bash's path constraint to the working and added
    // directories (not yet confirmed by a real run with this argument).
    // Only with the hook: without it Bash stays denied (Task 8a), and so
    // does the source directory.
    if plan.hook_command.is_some()
        && let Some(dir) = plan.source_dir.as_deref().filter(|d| source_dir_ok(d))
    {
        args.extend(["--add-dir".to_string(), dir.display().to_string()]);
    }
    let mut env = base_env(plan);
    env.extend([
        ("CLAUDE_CONFIG_DIR".to_string(), cfg.display().to_string()),
        ("ANTHROPIC_BASE_URL".into(), base.to_string()),
        ("ANTHROPIC_API_KEY".into(), DUMMY_KEY.into()),
        (
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".into(),
            "1".into(),
        ),
        ("DISABLE_AUTOUPDATER".into(), "1".into()),
    ]);
    Some(Invocation {
        program: binary.to_path_buf(),
        args,
        env,
        cwd: plan.workdir.clone(),
        files,
        timeout: TIMEOUT,
    })
}

/// `codex exec` with `CODEX_HOME` = the temporary directory. Its "no other
/// traffic" switch is `check_for_update_on_startup = false`.
///
/// The gateway entry carries three keys recorded from Codex 0.159.2 (M8
/// spec §20, amendment 2026-10-10): `required = true`, because `codex exec`
/// otherwise starts the turn before MCP servers are up and the first request
/// advertises no MCP tools; `startup_timeout_sec = 30`, the wait that
/// `required` bounds; and `default_tools_approval_mode = "approve"`, because
/// under `approval_policy = "never"` an MCP call is otherwise refused with
/// "MCP tool call requires approval, but approval policy is never". The
/// approval applies to the check's own gateway entry only, in a throwaway
/// `CODEX_HOME`.
pub fn codex(binary: &Path, plan: &CheckPlan) -> Option<Invocation> {
    let base = route(plan, "openai")?;
    let token = plan.gateway_token.as_str();
    if !name_ok(&plan.server)
        || ![base, plan.gateway_url.as_str(), token]
            .iter()
            .all(|v| plain(v))
    {
        return None;
    }
    let config = format!(
        "model = \"inumaki-check\"\nmodel_provider = \"inumaki-check\"\napproval_policy = \"never\"\ncheck_for_update_on_startup = false\n\n\
         [model_providers.inumaki-check]\nname = \"inumaki check\"\nbase_url = \"{base}/v1\"\nwire_api = \"responses\"\nenv_key = \"INUMAKI_CHECK_KEY\"\n\n\
         [mcp_servers.{server}]\nurl = \"{url}\"\nhttp_headers = {{ Authorization = \"Bearer {token}\" }}\n\
         required = true\nstartup_timeout_sec = 30\ndefault_tools_approval_mode = \"approve\"\n",
        server = plan.server,
        url = plan.gateway_url,
    );
    let mut env = base_env(plan);
    env.extend([
        (
            "CODEX_HOME".to_string(),
            plan.config_dir.display().to_string(),
        ),
        ("INUMAKI_CHECK_KEY".into(), DUMMY_KEY.into()),
    ]);
    Some(Invocation {
        program: binary.to_path_buf(),
        args: vec![
            "exec".into(),
            "--skip-git-repo-check".into(),
            "--cd".into(),
            plan.workdir.display().to_string(),
            "--sandbox".into(),
            "read-only".into(),
            PROMPT.into(),
        ],
        env,
        cwd: plan.workdir.clone(),
        files: vec![(plan.config_dir.join("config.toml"), config)],
        timeout: TIMEOUT,
    })
}

/// Hermes one-shot. `HERMES_HOME` is verified for v2026.9.24
/// (`docs/harness-adapters.md`); the one-shot spelling `chat -q` is not in
/// that record, so it is unverified against the installed version. Hermes has
/// no documented switch for "no other traffic" (no update-check or telemetry
/// key appears in the verified configuration reference), so none is set; the
/// check's isolation (temporary `HERMES_HOME`, cleared environment) is the
/// only containment there.
pub fn hermes(binary: &Path, plan: &CheckPlan) -> Option<Invocation> {
    let base = route(plan, "openai")?;
    let token = plan.gateway_token.as_str();
    if !name_ok(&plan.server)
        || ![base, plan.gateway_url.as_str(), token]
            .iter()
            .all(|v| plain(v))
    {
        return None;
    }
    let config = format!(
        "model:\n  provider: inumaki-check\n  default: inumaki-check\nproviders:\n  inumaki-check:\n    base_url: \"{base}/v1\"\n    key_env: INUMAKI_CHECK_KEY\n\
         mcp_servers:\n  {server}:\n    url: \"{url}\"\n    headers:\n      Authorization: \"Bearer {token}\"\n",
        server = plan.server,
        url = plan.gateway_url,
    );
    let mut env = base_env(plan);
    env.extend([
        (
            "HERMES_HOME".to_string(),
            plan.config_dir.display().to_string(),
        ),
        ("INUMAKI_CHECK_KEY".into(), DUMMY_KEY.into()),
    ]);
    Some(Invocation {
        program: binary.to_path_buf(),
        args: vec!["chat".into(), "-q".into(), PROMPT.into()],
        env,
        cwd: plan.workdir.clone(),
        files: vec![(plan.config_dir.join("config.yaml"), config)],
        timeout: TIMEOUT,
    })
}
