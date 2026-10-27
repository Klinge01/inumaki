//! Claude Code (spec §4.3, docs/harness-adapters.md rows CC-*):
//! `~/.claude.json` holds MCP servers (user scope, and local scope under
//! `projects.<dir>.mcpServers`); `~/.claude/settings.json` holds Files,
//! Chat (with the proxy client header line in `env.ANTHROPIC_CUSTOM_HEADERS`),
//! and the `PostToolUse` hook.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;
use zeroize::Zeroizing;

use super::{EntryKeys, HOOK_MARKER, HarnessAdapter, bearer, entry_from_json, p, sh_quote};
use crate::backup::{Backup, BackupStore, EditRecord, FileRecord, RevertReport};
use crate::detect::{ProbeEnv, find_binary, keychain_item_exists, version, version_in};
use crate::engine::{self, current_value};
use crate::model::*;
use crate::node::{Edit, Format, Node, value_at};
use crate::status::{chat_state, drifted, files_state, hook_state, mcp_state};

/// Version range of the golden files (docs/harness-adapters.md §1, "Tested
/// version ranges"): the 2.1.284 binary whose tool schemas and hook
/// handling were inspected to build this adapter.
pub const TESTED_MIN: &str = "2.1.284";
/// Upper end of the range.
pub const TESTED_MAX: &str = "2.1.284";
const MCP: &str = "mcpServers";
const PROJECTS: &str = "projects";
const DIRS: [&str; 2] = ["permissions", "additionalDirectories"];
const BASE_URL: [&str; 2] = ["env", "ANTHROPIC_BASE_URL"];
/// Newline-separated `Name: value` lines (spec §4.3 amendment 2026-09-29).
const CUSTOM_HEADERS: [&str; 2] = ["env", "ANTHROPIC_CUSTOM_HEADERS"];
const HOOKS: [&str; 2] = ["hooks", "PostToolUse"];
/// Built-in tools with process or file output whose `updatedToolOutput`
/// Claude Code honors (docs/harness-adapters.md §5 and §7 deviation 1):
/// `MultiEdit` is absent from 2.1.284 (legacy) and `BashOutput` does not
/// exist (background output is read back through `Read`); `PowerShell`
/// and `ReadMcpResourceTool` are added.
const HOOK_TOOLS: &str = "Bash|PowerShell|Read|Grep|Glob|Edit|WebFetch|ReadMcpResourceTool";
const HOOK_TIMEOUT_S: i64 = 30;
const KEYS: EntryKeys = EntryKeys {
    url: "url",
    env: "env",
    headers: "headers",
    approval: None,
};
const OWNED: &[(FileRole, &[&str])] = &[
    (FileRole::ClaudeJson, &[MCP, "*"]),
    (FileRole::ClaudeJson, &[PROJECTS, "*", MCP, "*"]),
    (FileRole::ClaudeSettings, &DIRS),
    (FileRole::ClaudeSettings, &BASE_URL),
    (FileRole::ClaudeSettings, &CUSTOM_HEADERS),
    (FileRole::ClaudeSettings, &HOOKS),
];

/// The Claude Code adapter.
pub struct ClaudeCode;

/// A server name as Claude Code puts it into its MCP tool names
/// (`mcp__<name>__<tool>`): every character outside `[A-Za-z0-9_-]`
/// becomes `_` (final review I2: the 2.1.289 binary applies
/// `name.replace(/[^a-zA-Z0-9_-]/g, "_")`). That replace works on UTF-16
/// code units, so a character outside the Basic Multilingual Plane becomes
/// two `_`. The result holds only `[A-Za-z0-9_-]`, so it needs no escaping
/// in a regular expression.
pub fn tool_name_part(server: &str) -> String {
    let mut out = String::with_capacity(server.len());
    for c in server.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
        } else {
            for _ in 0..c.len_utf16() {
                out.push('_');
            }
        }
    }
    out
}

/// The hook matcher (final review I2, spec §4.3 amendment): the listed
/// built-in tools, and every MCP tool except those of the servers that point
/// at the gateway after this apply: `^(…)$|^mcp__(?!(<g1>|<g2>|…)__).*`,
/// or `^(…)$|^mcp__.*` when no server is gateway-routed. `<gN>` are the
/// gateway-routed names in Claude Code's tool-name form
/// ([`tool_name_part`]). Excluding instead of listing covers every MCP
/// server inumaki does not see or that appears later: project-scope
/// `.mcp.json`, plugin servers (`mcp__plugin_…`), hand-named entries, and
/// servers added after apply. A gateway-routed name is not excluded when a
/// server that is not gateway-routed has the same tool-name form or one
/// that starts with `<gN>__` (recall first: such a server's tools would
/// otherwise match the exclusion). A gateway-routed server needs no
/// tripwire hook: its output is already tokens, and a second round-trip
/// would cost latency for nothing. Anchored, so the built-in half never
/// matches `ReadMcpResourceDirTool` (on `ReadMcpResourceTool`) or
/// `NotebookEdit` (on `Edit`).
pub fn matcher(gateway_routed: &[String], other_servers: &[String]) -> String {
    let others: BTreeSet<String> = other_servers.iter().map(|n| tool_name_part(n)).collect();
    let excluded: BTreeSet<String> = gateway_routed
        .iter()
        .map(|n| tool_name_part(n))
        .filter(|g| {
            !g.is_empty()
                && !others
                    .iter()
                    .any(|o| o == g || o.starts_with(&format!("{g}__")))
        })
        .collect();
    if excluded.is_empty() {
        format!("^({HOOK_TOOLS})$|^mcp__.*")
    } else {
        let names: Vec<&str> = excluded.iter().map(String::as_str).collect();
        format!("^({HOOK_TOOLS})$|^mcp__(?!({})__).*", names.join("|"))
    }
}

/// The value of the `name` line of an `ANTHROPIC_CUSTOM_HEADERS` value
/// (names compare case-insensitively, as HTTP header names do).
fn header_line_value<'a>(lines: &'a str, name: &str) -> Option<&'a str> {
    lines.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// The lines of a header value (without line endings), the line ending to
/// write (`\r\n` when the value uses it anywhere, else `\n`), and whether
/// the value ends with one. A value with mixed endings is rewritten with
/// the one chosen.
fn split_lines(s: &str) -> (Vec<&str>, &'static str, bool) {
    let eol = if s.contains("\r\n") { "\r\n" } else { "\n" };
    let trailing = s.ends_with('\n');
    let body = s
        .strip_suffix('\n')
        .map_or(s, |b| b.strip_suffix('\r').unwrap_or(b));
    (
        body.split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .collect(),
        eol,
        trailing,
    )
}

fn join_lines(lines: &[&str], eol: &str, trailing: bool) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "{}{}",
        lines.join(eol),
        if trailing { eol } else { "" }
    ))
}

/// `line` is a `name:` line (any case).
fn is_named(line: &str, name: &str) -> bool {
    line.split_once(':')
        .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name))
}

/// `existing` with the line `<name>: <value>`: every other line stays as it
/// is, the first line of the same name (any case) is replaced in place and
/// any further one dropped, else the line is appended. The value's line
/// ending and a trailing one are kept.
fn with_header_line(existing: Option<&str>, h: &ClientHeader) -> Zeroizing<String> {
    let ours = Zeroizing::new(format!("{}: {}", h.name, h.value.as_str()));
    let Some(existing) = existing.filter(|s| !s.is_empty()) else {
        return ours;
    };
    let (lines, eol, trailing) = split_lines(existing);
    let mut out: Vec<&str> = Vec::new();
    let mut placed = false;
    for line in lines {
        if !is_named(line, h.name) {
            out.push(line);
        } else if !placed {
            out.push(ours.as_str());
            placed = true;
        }
    }
    if !placed {
        out.push(ours.as_str());
    }
    join_lines(&out, eol, trailing)
}

/// `existing` without inumaki's lines: every client header line whose value
/// is one of `ours`. `None`: nothing changes; `Some(None)`: no line is
/// left, so the key goes; `Some(Some(v))`: the user's other lines.
fn without_our_lines(
    existing: &str,
    ours: &[Zeroizing<String>],
) -> Option<Option<Zeroizing<String>>> {
    let (lines, eol, trailing) = split_lines(existing);
    let mine = |l: &str| {
        is_named(l, CLIENT_HEADER_NAME)
            && header_line_value(l, CLIENT_HEADER_NAME)
                .is_some_and(|v| ours.iter().any(|o| o.as_str() == v))
    };
    if !lines.iter().any(|l| mine(l)) {
        return None;
    }
    let kept: Vec<&str> = lines.into_iter().filter(|l| !mine(l)).collect();
    Some((!kept.iter().all(|l| l.trim().is_empty())).then(|| join_lines(&kept, eol, trailing)))
}

/// Every client header value inumaki wrote into this file's
/// `ANTHROPIC_CUSTOM_HEADERS`, newest first (chained applies keep all).
fn applied_header_values(f: &FileRecord) -> Vec<Zeroizing<String>> {
    let path = p(&CUSTOM_HEADERS);
    f.records
        .iter()
        .rev()
        .filter_map(|r| match r {
            EditRecord::Set {
                path: at, after, ..
            } if *at == path => after
                .as_str()
                .and_then(|s| header_line_value(s, CLIENT_HEADER_NAME))
                .map(|v| Zeroizing::new(v.to_string())),
            _ => None,
        })
        .collect()
}

/// Our header line's value as the active backup's latest apply wrote it.
fn applied_header_value(sys: &SystemState) -> Option<Zeroizing<String>> {
    applied_header_values(sys.applied.as_ref()?.file(FileRole::ClaudeSettings)?)
        .into_iter()
        .next()
}

fn gateway_node(url: &str, token: &str) -> Node {
    Node::obj([
        ("type", Node::s("http")),
        ("url", Node::s(url)),
        (
            "headers",
            Node::obj([("Authorization", Node::s(bearer(token)))]),
        ),
    ])
}

impl ClaudeCode {
    fn dir(env: &ProbeEnv) -> PathBuf {
        env.var("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| env.home.join(".claude"))
    }

    /// `<config dir>` (`CLAUDE_CONFIG_DIR`, or the home directory) plus
    /// `.claude.json`, or its legacy name `.config.json` when that file
    /// exists there (docs/harness-adapters.md §2 and §7 deviation 6).
    fn claude_json_path(env: &ProbeEnv) -> PathBuf {
        let base = env
            .var("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| env.home.clone());
        let legacy = base.join(".config.json");
        if legacy.exists() {
            legacy
        } else {
            base.join(".claude.json")
        }
    }

    /// The installed MCP server names split by where they point once
    /// `plan` is applied: `(gateway_routed, others)`. Gateway-routed: already
    /// pointing at the gateway, or named (with a matching scope) in
    /// `plan.gateway`'s entries (which also adds new entries such as
    /// `inumaki-mail`). A name can be in both lists when one scope is routed
    /// and another is not.
    fn servers_by_route(
        &self,
        inst: &Installation,
        plan: &ConnectPlan,
    ) -> (Vec<String>, Vec<String>) {
        let servers = self
            .mcp_servers(inst, &plan.gateway_base)
            .unwrap_or_default();
        let will_protect: BTreeSet<(Scope, String)> = plan
            .gateway
            .as_ref()
            .map(|g| {
                g.entries
                    .iter()
                    .map(|e| (e.scope.clone(), e.name.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let mut routed: BTreeSet<String> = will_protect.iter().map(|(_, n)| n.clone()).collect();
        let mut others = BTreeSet::new();
        for s in &servers {
            if s.gateway || will_protect.contains(&(s.scope.clone(), s.name.clone())) {
                routed.insert(s.name.clone());
            } else {
                others.insert(s.name.clone());
            }
        }
        (routed.into_iter().collect(), others.into_iter().collect())
    }
}

impl HarnessAdapter for ClaudeCode {
    fn id(&self) -> HarnessId {
        HarnessId::ClaudeCode
    }

    fn owned(&self) -> &'static [(FileRole, &'static [&'static str])] {
        OWNED
    }

    fn config_files(&self, env: &ProbeEnv) -> Vec<ConfigFile> {
        vec![
            ConfigFile {
                role: FileRole::ClaudeJson,
                path: Self::claude_json_path(env),
                format: Format::Json,
                full_copy: false,
            },
            ConfigFile {
                role: FileRole::ClaudeSettings,
                path: Self::dir(env).join("settings.json"),
                format: Format::Json,
                full_copy: true,
            },
        ]
    }

    fn detect(&self, env: &ProbeEnv) -> Option<Installation> {
        let files = self.config_files(env);
        let binary = find_binary(
            env,
            "claude",
            &[Self::dir(env).join("local").join("claude")],
        );
        if binary.is_none() && !files[0].path.exists() && !Self::dir(env).exists() {
            return None;
        }
        let version = binary.as_deref().and_then(|b| version(env, b));
        let tested = version
            .as_deref()
            .is_some_and(|v| version_in(v, TESTED_MIN, TESTED_MAX));
        let settings = current_value(&files[1]).unwrap_or(Value::Null);
        let login = if env.has("ANTHROPIC_API_KEY")
            || settings.get("apiKeyHelper").is_some()
            || value_at(&settings, &p(&["env", "ANTHROPIC_API_KEY"])).is_some()
        {
            LoginKind::ApiKey
        } else if Self::dir(env).join(".credentials.json").exists()
            || keychain_item_exists(env, "Claude Code-credentials")
        {
            LoginKind::Oauth
        } else {
            LoginKind::Unknown
        };
        Some(Installation {
            harness: HarnessId::ClaudeCode,
            binary,
            version,
            tested,
            config_files: files,
            login,
        })
    }

    fn mcp_servers(
        &self,
        inst: &Installation,
        gateway_base: &str,
    ) -> Result<Vec<McpServerEntry>, AdapterError> {
        let Some(f) = inst.file(FileRole::ClaudeJson) else {
            return Ok(Vec::new());
        };
        let v = current_value(f)?;
        let mut out = Vec::new();
        // Every scope is listed, even when a name repeats across them.
        // Claude Code's local-scope-shadows-user-scope precedence
        // (docs/harness-adapters.md mcp.md quote) holds only inside the
        // one project that defines the local-scope entry: the user-scope
        // entry is exactly what Claude Code connects to in every other
        // project, so dropping it here would hide a server that is still
        // live and (un)protected everywhere else (review C1).
        if let Some(m) = v.get(MCP).and_then(Value::as_object) {
            out.extend(
                m.iter()
                    .map(|(n, d)| entry_from_json(n, Scope::User, d, &KEYS, gateway_base)),
            );
        }
        if let Some(projects) = v.get(PROJECTS).and_then(Value::as_object) {
            for (dir, proj) in projects {
                if let Some(m) = proj.get(MCP).and_then(Value::as_object) {
                    out.extend(m.iter().map(|(n, d)| {
                        entry_from_json(n, Scope::Project(dir.clone()), d, &KEYS, gateway_base)
                    }));
                }
            }
        }
        Ok(out)
    }

    fn chat_key(&self) -> (FileRole, &'static [&'static str]) {
        (FileRole::ClaudeSettings, &BASE_URL)
    }

    fn plan_edits(
        &self,
        inst: &Installation,
        plan: &ConnectPlan,
    ) -> Result<Vec<(ConfigFile, Vec<Edit>)>, AdapterError> {
        let cj = inst
            .file(FileRole::ClaudeJson)
            .cloned()
            .ok_or(AdapterError::Backup)?;
        let st = inst
            .file(FileRole::ClaudeSettings)
            .cloned()
            .ok_or(AdapterError::Backup)?;
        let mut cj_edits = Vec::new();
        let mut st_edits = Vec::new();
        if let Some(g) = &plan.gateway {
            for e in &g.entries {
                let path = match &e.scope {
                    Scope::User => vec![MCP.to_string(), e.name.clone()],
                    Scope::Project(d) => vec![
                        PROJECTS.to_string(),
                        d.clone(),
                        MCP.to_string(),
                        e.name.clone(),
                    ],
                };
                cj_edits.push(Edit::Set {
                    path,
                    value: gateway_node(&e.url, &g.token),
                });
            }
        }
        if let Some(f) = &plan.files {
            st_edits.push(Edit::Push {
                path: p(&DIRS),
                value: Node::s(f.mirror_root.to_string_lossy()),
            });
        }
        if let Some(url) = plan.chat.as_ref().and_then(|c| c.anthropic.as_ref()) {
            st_edits.push(Edit::Set {
                path: p(&BASE_URL),
                value: Node::s(url.as_str()),
            });
            if let Some(h) = &plan.proxy_client_header {
                // The user's other header lines stay; an unparsable file is
                // refused (with the full snippet) by apply's dry run.
                let cur = current_value(&st).unwrap_or(Value::Null);
                let existing = match value_at(&cur, &p(&CUSTOM_HEADERS)) {
                    None => None,
                    Some(Value::String(s)) => Some(s.as_str()),
                    Some(_) => {
                        let ours = Edit::Set {
                            path: p(&CUSTOM_HEADERS),
                            value: Node::s(with_header_line(None, h).as_str()),
                        };
                        return Err(AdapterError::cannot(
                            FileRole::ClaudeSettings,
                            Refusal::TypeConflict,
                            &[ours],
                        ));
                    }
                };
                st_edits.push(Edit::Set {
                    path: p(&CUSTOM_HEADERS),
                    value: Node::s(with_header_line(existing, h).as_str()),
                });
            }
        }
        if let Some(h) = &plan.hook {
            let (routed, others) = self.servers_by_route(inst, plan);
            let entry = Node::obj([
                ("matcher", Node::s(matcher(&routed, &others))),
                (
                    "hooks",
                    Node::Arr(vec![Node::obj([
                        ("type", Node::s("command")),
                        (
                            "command",
                            Node::s(format!(
                                "{} claude-code --socket {}",
                                sh_quote(&h.command),
                                sh_quote(&h.socket)
                            )),
                        ),
                        ("timeout", Node::Int(HOOK_TIMEOUT_S)),
                    ])]),
                ),
            ]);
            st_edits.push(Edit::PullMatching {
                path: p(&HOOKS),
                marker: HOOK_MARKER.to_string(),
            });
            st_edits.push(Edit::Push {
                path: p(&HOOKS),
                value: entry,
            });
        }
        Ok(vec![(cj, cj_edits), (st, st_edits)])
    }

    /// The engine's revert, then (spec §4.3 amendment: inumaki owns only its
    /// line of `ANTHROPIC_CUSTOM_HEADERS`) when the user changed that value
    /// after apply, the engine reports a conflict and keeps it whole: our
    /// line is removed from it here, the user's lines stay, and the key goes
    /// when nothing is left. Otherwise the client header secret would go to
    /// the provider once `ANTHROPIC_BASE_URL` is reverted. The write goes
    /// through the engine's owned-key check, semantic guard, and
    /// compare-and-rename. If our line cannot be removed, the conflict
    /// stays and `client_header_left` is set.
    fn revert(&self, _inst: &Installation, b: &Backup) -> Result<RevertReport, AdapterError> {
        let mut report = engine::revert(&BackupStore::of_backup(b), b)?;
        let path = p(&CUSTOM_HEADERS);
        let is_ours = |c: &DriftItem| c.role == FileRole::ClaudeSettings && c.path == path;
        let Some(rec) = b.file(FileRole::ClaudeSettings) else {
            return Ok(report);
        };
        if !report.conflicts.iter().any(is_ours) {
            return Ok(report);
        }
        let ours = applied_header_values(rec);
        let file = ConfigFile {
            role: rec.role,
            path: rec.path.clone(),
            format: rec.format,
            full_copy: rec.full_copy,
        };
        let strip = |cur: &Value| -> Vec<Edit> {
            match value_at(cur, &path)
                .and_then(Value::as_str)
                .and_then(|s| without_our_lines(s, &ours))
            {
                None => Vec::new(),
                Some(None) => vec![Edit::Remove { path: path.clone() }],
                Some(Some(v)) => vec![Edit::Set {
                    path: path.clone(),
                    value: Node::s(v.as_str()),
                }],
            }
        };
        let _ = engine::rewrite_owned(OWNED, &file, &strip);
        // Verify on the bytes now on disk: no line of ours may be left.
        let left = match current_value(&file) {
            Ok(cur) => match value_at(&cur, &path) {
                None => false,
                Some(Value::String(s)) => without_our_lines(s, &ours).is_some(),
                Some(other) => ours.iter().any(|o| other.to_string().contains(o.as_str())),
            },
            Err(_) => true,
        };
        if left {
            report.client_header_left = true;
        } else {
            report.conflicts.retain(|c| !is_ours(c));
        }
        Ok(report)
    }

    /// [`ConnectWarning::ClaudeCodeChatLive`] when the plan writes the chat
    /// route: `ANTHROPIC_BASE_URL` goes into the user-level `settings.json`,
    /// so every Claude Code window sends chat through inumaki, not only the
    /// project the user connected from. Then
    /// [`ConnectWarning::HookBlocksWhenStopped`] when the plan installs the
    /// hook, which fails closed while the service is down.
    fn connect_warnings(&self, _inst: &Installation, plan: &ConnectPlan) -> Vec<ConnectWarning> {
        plan.chat
            .as_ref()
            .is_some_and(|c| c.anthropic.is_some())
            .then_some(ConnectWarning::ClaudeCodeChatLive)
            .into_iter()
            .chain(
                plan.hook
                    .is_some()
                    .then_some(ConnectWarning::HookBlocksWhenStopped),
            )
            .collect()
    }

    fn status(&self, inst: &Installation, sys: &SystemState) -> HarnessStatus {
        let settings = inst
            .file(FileRole::ClaudeSettings)
            .and_then(|f| current_value(f).ok())
            .unwrap_or(Value::Null);
        let headers = value_at(&settings, &p(&CUSTOM_HEADERS)).and_then(Value::as_str);
        let line = |name: &str| headers.and_then(|v| header_line_value(v, name));
        // We own one line of `ANTHROPIC_CUSTOM_HEADERS`: another line the
        // user added is not drift, a missing or changed line of ours is.
        let ours_intact =
            applied_header_value(sys).is_some_and(|v| line(CLIENT_HEADER_NAME) == Some(v.as_str()));
        let mut drift = sys.applied.as_ref().map(engine::drift).unwrap_or_default();
        drift.retain(|d| {
            !(ours_intact && d.role == FileRole::ClaudeSettings && d.path == p(&CUSTOM_HEADERS))
        });
        let servers = self
            .mcp_servers(inst, &sys.gateway_base)
            .unwrap_or_default();
        let mcp_drift = drift.iter().any(|d| d.role == FileRole::ClaudeJson);
        let mirror_listed = sys.folders.as_ref().is_some_and(|f| {
            value_at(&settings, &p(&DIRS))
                .and_then(Value::as_array)
                .is_some_and(|a| {
                    a.iter()
                        .any(|x| x.as_str() == Some(&*f.mirror_root.to_string_lossy()))
                })
        });
        let base = value_at(&settings, &p(&BASE_URL)).and_then(Value::as_str);
        // Chat routed through the proxy without the current client header
        // line (missing, changed, or stale after the daemon's value changed).
        let routed = base
            .zip(sys.proxy.as_ref().and_then(|x| x.route(Route::Anthropic)))
            .is_some_and(|(b, r)| b.starts_with(r.base_url.as_str()));
        let header_drift = routed
            && sys
                .proxy
                .as_ref()
                .and_then(|x| x.client_header.as_ref())
                .is_some_and(|h| line(h.name) != Some(h.value.as_str()));
        let chat_drift = header_drift
            || drifted(&drift, FileRole::ClaudeSettings, &p(&BASE_URL))
            || drifted(&drift, FileRole::ClaudeSettings, &p(&CUSTOM_HEADERS));
        HarnessStatus {
            paths: [
                (ProtectionPath::Mcp, mcp_state(&servers, sys, mcp_drift)),
                (
                    ProtectionPath::Files,
                    files_state(
                        mirror_listed,
                        sys,
                        drifted(&drift, FileRole::ClaudeSettings, &p(&DIRS)),
                        None,
                    ),
                ),
                (
                    ProtectionPath::Chat,
                    chat_state(
                        HarnessId::ClaudeCode,
                        base,
                        Route::Anthropic,
                        sys,
                        chat_drift,
                    ),
                ),
            ],
            hook: if drifted(&drift, FileRole::ClaudeSettings, &p(&HOOKS)) {
                HookState::Broken {
                    reason: ReasonCode::ChangedOutsideInumaki,
                }
            } else {
                hook_state(value_at(&settings, &p(&HOOKS)), HarnessId::ClaudeCode, sys)
            },
            drift,
            level: Level::Easy,
        }
    }

    fn check_invocation(&self, inst: &Installation, c: &CheckPlan) -> Option<Invocation> {
        inst.binary
            .as_deref()
            .and_then(|b| crate::check::claude_code(b, c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Final review I2: every MCP tool is hooked except the gateway-routed
    /// servers', whose names take Claude Code's tool-name form.
    #[test]
    fn the_matcher_excludes_only_gateway_routed_servers() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let builtin = format!("^({HOOK_TOOLS})$");
        assert_eq!(matcher(&[], &[]), format!("{builtin}|^mcp__.*"));
        assert_eq!(
            matcher(&[], &s(&["notes"])),
            format!("{builtin}|^mcp__.*"),
            "no gateway-routed server: every MCP tool is hooked"
        );
        assert_eq!(
            matcher(&s(&["crm.intern", "acme crm", "db"]), &s(&["notes"])),
            format!("{builtin}|^mcp__(?!(acme_crm|crm_intern|db)__).*")
        );
        assert_eq!(tool_name_part("a/b\u{1F600}"), "a_b__", "UTF-16 code units");
        // A server that is not routed and shares the tool-name form, or
        // whose form starts with `<routed>__`, keeps the routed name hooked.
        assert_eq!(
            matcher(&s(&["crm.intern", "db", "x"]), &s(&["crm_intern", "db__2"])),
            format!("{builtin}|^mcp__(?!(x)__).*")
        );
        assert_eq!(
            matcher(&s(&["crm"]), &s(&["crm"])),
            format!("{builtin}|^mcp__.*"),
            "a name routed in one scope and not in another stays hooked"
        );
        let m = matcher(&s(&["crm.intern", "acme crm"]), &[]);
        let names = m.split("(?!(").nth(1).unwrap().split(")__").next().unwrap();
        assert!(
            names
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '|'),
            "{names}"
        );
    }

    /// Review M4: a CRLF value keeps CRLF for our line, on merge and removal.
    #[test]
    fn crlf_header_values_keep_their_line_endings() {
        let h = ClientHeader::new(Zeroizing::new("v1".to_string()));
        let merged = with_header_line(
            Some("X-Team: blue\r\nx-inumaki-client: old\r\nX-B: 2\r\n"),
            &h,
        );
        assert_eq!(
            merged.as_str(),
            "X-Team: blue\r\nX-Inumaki-Client: v1\r\nX-B: 2\r\n"
        );
        let appended = with_header_line(Some("X-Team: blue\r\nX-B: 2"), &h);
        assert_eq!(
            appended.as_str(),
            "X-Team: blue\r\nX-B: 2\r\nX-Inumaki-Client: v1"
        );
        let ours = [Zeroizing::new("v1".to_string())];
        let removed = without_our_lines(merged.as_str(), &ours).unwrap().unwrap();
        assert_eq!(removed.as_str(), "X-Team: blue\r\nX-B: 2\r\n");
        assert!(
            without_our_lines("X-Inumaki-Client: someone-else\r\n", &ours).is_none(),
            "another value is not ours"
        );
    }
}
