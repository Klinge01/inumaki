//! Codex CLI (spec §4.3, docs/harness-adapters.md rows CX-*):
//! `$CODEX_HOME/config.toml` holds MCP servers, the writable outbox roots,
//! and the model provider (with the proxy client header in its
//! `http_headers`); `$CODEX_HOME/hooks.json` holds the `PostToolUse` hook.
//!
//! Hook trust (docs/harness-adapters.md CX-HOOK, §7 deviation 7): Codex runs
//! a new or changed user hook only after the user trusts it in `/hooks`.
//! The adapter appends its matcher group after every existing group, so the
//! user's group indexes (and with them their trust records) never shift,
//! and it never writes a `trusted_hash`: until one exists for our hook, the
//! hook state is [`HookState::Pending`] with
//! [`ReasonCode::CodexHookNeedsTrust`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::de::IgnoredAny;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{
    EntryKeys, HOOK_MARKER, HarnessAdapter, bearer, chat_live_warning, entry_from_json, p, sh_quote,
};
use crate::backup::{Backup, FileRecord, RevertReport};
use crate::detect::{ProbeEnv, find_binary, version, version_in};
use crate::engine::{self, current_value};
use crate::model::*;
use crate::node::{Edit, Format, Node, value_at};
use crate::status::{chat_state, drifted, files_state, hook_state, mcp_state};

/// Version range of the golden files (docs/harness-adapters.md §1, "Tested
/// version ranges"): the `rust-v0.158.0` source tag read in Task 1. The
/// gateway-entry keys `required`, `startup_timeout_sec` and the user's
/// `default_tools_approval_mode` were recorded on 0.159.2, outside this
/// range; do not raise `TESTED_MAX` without goldens for that version.
pub const TESTED_MIN: &str = "0.158.0";
/// Upper end of the range.
pub const TESTED_MAX: &str = "0.158.0";
pub(crate) const MCP: &str = "mcp_servers";
/// Codex's per-server tool approval. A user-owned sub-key of a gateway
/// entry ([`super::user_subkeys`]): never written by inumaki on its own,
/// carried over when the entry is rewritten, ignored by drift.
pub(crate) const APPROVAL_KEY: &str = "default_tools_approval_mode";
const WRITABLE: [&str; 2] = ["sandbox_workspace_write", "writable_roots"];
const PROVIDER: &str = "model_provider";
const PROVIDERS: &str = "model_providers";
const ID: &str = "inumaki";
const HOOKS: [&str; 2] = ["hooks", "PostToolUse"];
/// Codex 0.158.0 reports every shell tool (`exec_command`, `write_stdin`)
/// to hooks as `Bash` (docs/harness-adapters.md CX-HOOK, §7 deviation 10).
const BASH_MATCHER: &str = "^Bash$";
const HOOK_TIMEOUT_S: i64 = 30;
/// `startup_timeout_sec` of a gateway entry (docs/harness-adapters.md
/// CX-MCP): with `required = true`, `codex exec` waits for the gateway this
/// long before its first turn, and fails visibly instead of running the
/// session without the inumaki tools (Codex 0.159.2 starts the first turn
/// before MCP servers are up). The gateway answers in milliseconds; 30 s
/// covers a service still starting at login.
const MCP_STARTUP_TIMEOUT_S: i64 = 30;
/// Appended to the `/openai` route's base URL (docs/harness-adapters.md §3).
const OPENAI_SUFFIX: &str = "/v1";
/// Suffix of a profile file `$CODEX_HOME/<name>.config.toml` (CX-PROFILES).
const PROFILE_SUFFIX: &str = ".config.toml";
const KEYS: EntryKeys = EntryKeys {
    url: "url",
    env: "env",
    headers: "http_headers",
    approval: Some(APPROVAL_KEY),
};
/// `mcp_servers.*` is owned whole, except the user-owned
/// [`APPROVAL_KEY`] inside it (see [`super::user_subkeys`]).
const OWNED: &[(FileRole, &[&str])] = &[
    (FileRole::CodexConfig, &[MCP, "*"]),
    (FileRole::CodexConfig, &WRITABLE),
    (FileRole::CodexConfig, &[PROVIDER]),
    (FileRole::CodexConfig, &[PROVIDERS, ID]),
    (FileRole::CodexHooks, &HOOKS),
];

/// The Codex adapter.
pub struct Codex;

impl Codex {
    fn dir(env: &ProbeEnv) -> PathBuf {
        env.var("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| env.home.join(".codex"))
    }

    /// Names in `auth.json`, values skipped unread (`null` → `None`).
    fn auth_keys(env: &ProbeEnv) -> BTreeMap<String, Option<IgnoredAny>> {
        std::fs::read(Self::dir(env).join("auth.json"))
            .ok()
            .map(Zeroizing::new)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// The hook entry: one matcher group with one command handler.
    fn hook_entry(h: &HookPlan) -> Node {
        Node::obj([
            ("matcher", Node::s(BASH_MATCHER)),
            (
                "hooks",
                Node::Arr(vec![Node::obj([
                    ("type", Node::s("command")),
                    (
                        "command",
                        Node::s(format!(
                            "{} codex --socket {}",
                            sh_quote(&h.command),
                            sh_quote(&h.socket)
                        )),
                    ),
                    ("timeout", Node::Int(HOOK_TIMEOUT_S)),
                ])]),
            ),
        ])
    }
}

/// `http_headers` with the proxy client header, when the plan has one.
fn with_client_header(mut pairs: Vec<(&'static str, Node)>, h: Option<&ClientHeader>) -> Node {
    if let Some(h) = h {
        pairs.push((
            "http_headers",
            Node::obj([(h.name, Node::s(h.value.as_str()))]),
        ));
    }
    Node::obj(pairs)
}

/// A profile file `$CODEX_HOME/<name>.config.toml` selects another model
/// provider (docs/harness-adapters.md CX-PROFILES: `[profiles.<name>]` in
/// `config.toml` is ignored from Codex 0.134, the profile file is what
/// `--profile <name>` overlays). Only `model_provider` is kept from each
/// file; no other value is read into a field.
fn profile_overrides(dir: &Path) -> bool {
    #[derive(serde::Deserialize)]
    struct Profile {
        model_provider: Option<String>,
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    rd.flatten().any(|e| {
        let name = e.file_name();
        let is_profile = name
            .to_str()
            .and_then(|n| n.strip_suffix(PROFILE_SUFFIX))
            .is_some_and(|n| !n.is_empty());
        is_profile
            && std::fs::read_to_string(e.path())
                .ok()
                .map(Zeroizing::new)
                .and_then(|t| toml::from_str::<Profile>(&t).ok())
                .and_then(|pr| pr.model_provider)
                .is_some_and(|m| m != ID)
    })
}

/// The user's `default_tools_approval_mode` for gateway entry `e`, raw:
/// the one the plan carries (read before an app Reconnect reverted the
/// file), else the one in `cur` (the file as it is now) on the entry of that
/// name, but only when that entry is inumaki's own and the one being
/// rewritten (its `url` is `e.url`). A user's own server entry of the same
/// name, or a stale entry for another dataset, gives nothing.
fn approval_of(e: &GatewayEntry, cur: Option<&Value>) -> Option<Value> {
    e.approval_mode.clone().or_else(|| {
        let def = cur.and_then(|v| v.get(MCP)).and_then(|m| m.get(&e.name))?;
        (def.get("url").and_then(Value::as_str) == Some(e.url.as_str()))
            .then(|| def.get(APPROVAL_KEY).cloned())
            .flatten()
    })
}

/// `config.toml` sets the top-level `approval_policy = "never"`. Only that
/// key is read into a field; any other shape of it (a table, a number), an
/// unreadable file, or invalid TOML is `false`. Profile files are not read:
/// the warning covers the main configuration only.
fn approval_never(config: &Path) -> bool {
    #[derive(serde::Deserialize)]
    struct Top {
        approval_policy: Option<toml::Value>,
    }
    std::fs::read_to_string(config)
        .ok()
        .map(Zeroizing::new)
        .and_then(|t| toml::from_str::<Top>(&t).ok())
        .and_then(|t| t.approval_policy)
        .is_some_and(|v| v.as_str() == Some("never"))
}

/// Where our hook handler sits in `hooks.json`: the matcher group index and
/// the handler index inside it, which Codex puts into the key of its trust
/// record. The first handler carrying [`HOOK_MARKER`].
fn our_hook_position(hooks: &Value) -> Option<(usize, usize)> {
    let groups = value_at(hooks, &p(&HOOKS)).and_then(Value::as_array)?;
    groups.iter().enumerate().find_map(|(gi, g)| {
        let handlers = g.get("hooks")?.as_array()?;
        handlers
            .iter()
            .position(|h| h.to_string().contains(HOOK_MARKER))
            .map(|hi| (gi, hi))
    })
}

/// The keys under `[hooks.state]` Codex may have used for the handler at
/// `g:h` of `hooks_path`: the path as written, and its canonical form when
/// the file exists (symlinks, `/private` on macOS), without repeats.
/// Canonicalizing needs the file, so a revert that can delete it asks first.
fn trust_keys(hooks_path: &Path, g: usize, h: usize) -> Vec<String> {
    let mut sources = vec![hooks_path.to_string_lossy().into_owned()];
    if let Ok(c) = std::fs::canonicalize(hooks_path) {
        let c = c.to_string_lossy().into_owned();
        if !sources.contains(&c) {
            sources.push(c);
        }
    }
    sources
        .iter()
        .map(|s| format!("{s}:post_tool_use:{g}:{h}"))
        .collect()
}

/// Codex has a trust record for our hook handler: `config.toml` has
/// `[hooks.state."<hooks.json path>:post_tool_use:<group>:<handler>"]`
/// with a `trusted_hash` (docs/harness-adapters.md CX-HOOK "Hook trust",
/// `hooks/src/lib.rs::hook_key`). The hash is Codex's own and is never
/// computed or compared here; its presence is all that is checked.
fn hook_trusted(cfg: &Value, hooks: &Value, hooks_path: &Path) -> bool {
    let Some((gi, hi)) = our_hook_position(hooks) else {
        return false;
    };
    let Some(state) = hook_state_table(cfg) else {
        return false;
    };
    trust_keys(hooks_path, gi, hi).iter().any(|k| {
        state
            .get(k)
            .and_then(|e| e.get("trusted_hash"))
            .and_then(Value::as_str)
            .is_some_and(|h| !h.is_empty())
    })
}

/// `[hooks.state]` of a parsed `config.toml`.
fn hook_state_table(cfg: &Value) -> Option<&serde_json::Map<String, Value>> {
    cfg.get("hooks")?.get("state")?.as_object()
}

/// What [`remove_trust`] may touch: the trust record tables, and the two
/// parents when removing the records leaves them empty (`toml_edit` drops an
/// empty implicit table, which the semantic check would refuse).
const TRUST_OWNED: &[(FileRole, &[&str])] = &[
    (FileRole::CodexConfig, &["hooks", "state", "*"]),
    (FileRole::CodexConfig, &["hooks", "state"]),
    (FileRole::CodexConfig, &["hooks"]),
];

/// Remove exactly the `[hooks.state."<key>"]` tables named by `keys`, and
/// `[hooks.state]` and `[hooks]` only when this removal empties them. Every
/// other record (another position, file, or project) stays. Returns whether
/// a record is still there afterwards: the write failed or was refused, the
/// file changed under us, or it cannot be read.
fn remove_trust(file: &ConfigFile, keys: &[String]) -> bool {
    let plan = |cur: &Value| -> Vec<Edit> {
        let Some(state) = hook_state_table(cur) else {
            return Vec::new();
        };
        let state_path = p(&["hooks", "state"]);
        let mut edits: Vec<Edit> = keys
            .iter()
            .filter(|k| state.contains_key(*k))
            .map(|k| Edit::Remove {
                path: [state_path.clone(), vec![k.clone()]].concat(),
            })
            .collect();
        if edits.is_empty() {
            return edits;
        }
        if state.keys().all(|k| keys.contains(k)) {
            edits.push(Edit::Remove { path: state_path });
            let only_state = cur
                .get("hooks")
                .and_then(Value::as_object)
                .is_some_and(|h| h.len() == 1);
            if only_state {
                edits.push(Edit::Remove {
                    path: p(&["hooks"]),
                });
            }
        }
        edits
    };
    let _ = engine::rewrite_owned(TRUST_OWNED, file, &plan);
    match current_value(file) {
        Ok(cur) => hook_state_table(&cur).is_some_and(|s| keys.iter().any(|k| s.contains_key(k))),
        Err(_) => true,
    }
}

impl HarnessAdapter for Codex {
    fn id(&self) -> HarnessId {
        HarnessId::Codex
    }

    fn owned(&self) -> &'static [(FileRole, &'static [&'static str])] {
        OWNED
    }

    fn config_files(&self, env: &ProbeEnv) -> Vec<ConfigFile> {
        let d = Self::dir(env);
        vec![
            ConfigFile {
                role: FileRole::CodexConfig,
                path: d.join("config.toml"),
                format: Format::Toml,
                full_copy: true,
            },
            ConfigFile {
                role: FileRole::CodexHooks,
                path: d.join("hooks.json"),
                format: Format::Json,
                full_copy: true,
            },
        ]
    }

    fn detect(&self, env: &ProbeEnv) -> Option<Installation> {
        let binary = find_binary(env, "codex", &[]);
        if binary.is_none() && !Self::dir(env).exists() {
            return None;
        }
        let version = binary.as_deref().and_then(|b| version(env, b));
        let tested = version
            .as_deref()
            .is_some_and(|v| version_in(v, TESTED_MIN, TESTED_MAX));
        let keys = Self::auth_keys(env);
        // `OPENAI_API_KEY` is always serialized, `null` for ChatGPT logins
        // (docs/harness-adapters.md §4): presence of a value, not of the key.
        let login =
            if matches!(keys.get("OPENAI_API_KEY"), Some(Some(_))) || env.has("OPENAI_API_KEY") {
                LoginKind::ApiKey
            } else if matches!(keys.get("tokens"), Some(Some(_))) {
                LoginKind::Oauth
            } else {
                LoginKind::Unknown
            };
        Some(Installation {
            harness: HarnessId::Codex,
            binary,
            version,
            tested,
            config_files: self.config_files(env),
            login,
        })
    }

    fn mcp_servers(
        &self,
        inst: &Installation,
        gateway_base: &str,
    ) -> Result<Vec<McpServerEntry>, AdapterError> {
        let Some(f) = inst.file(FileRole::CodexConfig) else {
            return Ok(Vec::new());
        };
        let v = current_value(f)?;
        Ok(v.get(MCP)
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(n, d)| entry_from_json(n, Scope::User, d, &KEYS, gateway_base))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn chat_key(&self) -> (FileRole, &'static [&'static str]) {
        (FileRole::CodexConfig, &[PROVIDERS, ID])
    }

    fn plan_edits(
        &self,
        inst: &Installation,
        plan: &ConnectPlan,
    ) -> Result<Vec<(ConfigFile, Vec<Edit>)>, AdapterError> {
        let cfg = inst
            .file(FileRole::CodexConfig)
            .cloned()
            .ok_or(AdapterError::Backup)?;
        let hooks = inst
            .file(FileRole::CodexHooks)
            .cloned()
            .ok_or(AdapterError::Backup)?;
        let mut c = Vec::new();
        let mut hk = Vec::new();
        if let Some(g) = &plan.gateway {
            let cur = current_value(&cfg).ok();
            for e in g.entries.iter().filter(|e| e.scope == Scope::User) {
                let mut pairs = vec![
                    ("url", Node::s(&e.url)),
                    (
                        "http_headers",
                        Node::obj([("Authorization", Node::s(bearer(&g.token)))]),
                    ),
                    ("required", Node::Bool(true)),
                    ("startup_timeout_sec", Node::Int(MCP_STARTUP_TIMEOUT_S)),
                ];
                // The user's own approval setting goes along; never one of ours.
                if let Some(m) = approval_of(e, cur.as_ref()) {
                    pairs.push((APPROVAL_KEY, engine::json_node(&m)));
                }
                c.push(Edit::Set {
                    path: vec![MCP.to_string(), e.name.clone()],
                    value: Node::obj(pairs),
                });
            }
        }
        if let Some(f) = &plan.files {
            for o in &f.outboxes {
                c.push(Edit::Push {
                    path: p(&WRITABLE),
                    value: Node::s(o.to_string_lossy()),
                });
            }
        }
        if let Some(chat) = &plan.chat {
            let header = plan.proxy_client_header.as_ref();
            let provider = match inst.login {
                LoginKind::ApiKey => chat.openai.as_ref().map(|u| {
                    with_client_header(
                        vec![
                            ("name", Node::s(ID)),
                            ("base_url", Node::s(format!("{u}{OPENAI_SUFFIX}"))),
                            ("wire_api", Node::s("responses")),
                            ("env_key", Node::s("OPENAI_API_KEY")),
                        ],
                        header,
                    )
                }),
                // `supports_websockets = false` (spec §4.3 amendment) is not
                // written: 0.159.2 accepts the key (user-gated run
                // 2026-10-10, M8 spec §13 amendment), 0.158.0 is unrecorded
                // (docs/harness-adapters.md CX-CHAT-CHATGPT); the proxy
                // answers an upgrade with 501 either way.
                LoginKind::Oauth if chat.codex_chatgpt => chat.codex.as_ref().map(|u| {
                    with_client_header(
                        vec![
                            ("name", Node::s(ID)),
                            ("base_url", Node::s(u.as_str())),
                            ("wire_api", Node::s("responses")),
                            ("requires_openai_auth", Node::Bool(true)),
                        ],
                        header,
                    )
                }),
                _ => None,
            };
            if let Some(node) = provider {
                c.push(Edit::Set {
                    path: vec![PROVIDER.to_string()],
                    value: Node::s(ID),
                });
                c.push(Edit::Set {
                    path: vec![PROVIDERS.to_string(), ID.to_string()],
                    value: node,
                });
            }
        }
        if let Some(h) = &plan.hook {
            let entry = Self::hook_entry(h);
            // An identical entry already in place, and the only inumaki
            // entry, stays where it is: moving it would change its index,
            // and with it Codex's trust record. Any other inumaki entry
            // (a stale one) means pull them all and append one.
            let cur = current_value(&hooks).unwrap_or(Value::Null);
            let ours: Vec<&Value> = value_at(&cur, &p(&HOOKS))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter(|x| x.to_string().contains(HOOK_MARKER))
                        .collect()
                })
                .unwrap_or_default();
            let in_place = ours.len() == 1 && *ours[0] == entry.to_json();
            if !in_place {
                // Ours is appended after every existing group (never earlier:
                // that would shift the user's group indexes and turn their
                // trusted hooks into modified, skipped ones).
                hk.push(Edit::PullMatching {
                    path: p(&HOOKS),
                    marker: HOOK_MARKER.to_string(),
                });
                hk.push(Edit::Push {
                    path: p(&HOOKS),
                    value: entry,
                });
            }
        }
        Ok(vec![(cfg, c), (hooks, hk)])
    }

    /// [`ConnectWarning::CodexApprovalNever`] when the plan writes a gateway
    /// entry without the user's own `default_tools_approval_mode` (any
    /// value: once set, the user has decided) and `config.toml` sets
    /// `approval_policy = "never"`. inumaki never writes the approval mode
    /// itself: auto-approving tool calls is the user's decision
    /// (docs/harness-adapters.md CX-MCP). Then
    /// [`ConnectWarning::CodexChatLive`] when the plan writes the chat
    /// provider (an API-key login's openai route, or a ChatGPT login's codex
    /// route). Then [`ConnectWarning::HookBlocksWhenStopped`] when the plan
    /// installs the hook (also when an identical entry is already in place:
    /// the hook stays installed), which fails closed while the service is
    /// down.
    fn connect_warnings(&self, inst: &Installation, plan: &ConnectPlan) -> Vec<ConnectWarning> {
        let cfg = inst.file(FileRole::CodexConfig);
        let cur = cfg.and_then(|f| current_value(f).ok());
        let undecided = plan.gateway.as_ref().is_some_and(|g| {
            g.entries
                .iter()
                .any(|e| e.scope == Scope::User && approval_of(e, cur.as_ref()).is_none())
        });
        let never = undecided && cfg.is_some_and(|f| approval_never(&f.path));
        never
            .then_some(ConnectWarning::CodexApprovalNever)
            .into_iter()
            .chain(chat_live_warning(self, inst, plan))
            .chain(
                plan.hook
                    .is_some()
                    .then_some(ConnectWarning::HookBlocksWhenStopped),
            )
            .collect()
    }

    fn status(&self, inst: &Installation, sys: &SystemState) -> HarnessStatus {
        let drift = sys.applied.as_ref().map(engine::drift).unwrap_or_default();
        let servers = self
            .mcp_servers(inst, &sys.gateway_base)
            .unwrap_or_default();
        let cfg = inst
            .file(FileRole::CodexConfig)
            .and_then(|f| current_value(f).ok())
            .unwrap_or(Value::Null);
        let hooks_file = inst.file(FileRole::CodexHooks);
        let hooks = hooks_file
            .and_then(|f| current_value(f).ok())
            .unwrap_or(Value::Null);
        let roots = value_at(&cfg, &p(&WRITABLE))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let outboxes_listed = sys.folders.as_ref().is_some_and(|f| {
            !f.outboxes.is_empty()
                && f.outboxes.iter().all(|o| {
                    roots
                        .iter()
                        .any(|r| r.as_str() == Some(&*o.to_string_lossy()))
                })
        });
        let ours = cfg.get(PROVIDER).and_then(Value::as_str) == Some(ID);
        let provider = value_at(&cfg, &[PROVIDERS.to_string(), ID.to_string()]);
        let base = if ours {
            provider
                .and_then(|v| v.get("base_url"))
                .and_then(Value::as_str)
        } else {
            None
        };
        // The provider must send the daemon's current client header.
        let header_drift = ours
            && sys
                .proxy
                .as_ref()
                .and_then(|x| x.client_header.as_ref())
                .is_some_and(|h| {
                    provider
                        .and_then(|v| v.get("http_headers"))
                        .and_then(|v| v.get(h.name))
                        .and_then(Value::as_str)
                        != Some(h.value.as_str())
                });
        let chat_drift = header_drift
            || drifted(&drift, FileRole::CodexConfig, &[PROVIDER.to_string()])
            || drifted(&drift, FileRole::CodexConfig, &[PROVIDERS.to_string()]);
        let profile_override = inst
            .file(FileRole::CodexConfig)
            .and_then(|f| f.path.parent())
            .is_some_and(profile_overrides);
        let chat = match inst.login {
            _ if profile_override => PathState::NotConnected {
                reason: Some(ReasonCode::CodexProfileOverride),
            },
            LoginKind::Oauth
                if base.is_none()
                    && !sys.proxy.as_ref().is_some_and(|x| x.codex_chatgpt_verified) =>
            {
                PathState::NotConnected {
                    reason: Some(ReasonCode::CodexChatgptUnverified),
                }
            }
            LoginKind::Oauth => chat_state(HarnessId::Codex, base, Route::Codex, sys, chat_drift),
            _ => chat_state(HarnessId::Codex, base, Route::Openai, sys, chat_drift),
        };
        let trusted = hooks_file.is_some_and(|f| hook_trusted(&cfg, &hooks, &f.path));
        let hook = if drifted(&drift, FileRole::CodexHooks, &p(&HOOKS)) {
            HookState::Broken {
                reason: ReasonCode::ChangedOutsideInumaki,
            }
        } else {
            match hook_state(value_at(&hooks, &p(&HOOKS)), HarnessId::Codex, sys) {
                HookState::Installed if !trusted => HookState::Pending {
                    reason: ReasonCode::CodexHookNeedsTrust,
                },
                s => s,
            }
        };
        HarnessStatus {
            paths: [
                (
                    ProtectionPath::Mcp,
                    mcp_state(
                        &servers,
                        sys,
                        drifted(&drift, FileRole::CodexConfig, &[MCP.to_string()]),
                    ),
                ),
                (
                    ProtectionPath::Files,
                    files_state(
                        outboxes_listed,
                        sys,
                        drifted(&drift, FileRole::CodexConfig, &p(&WRITABLE)),
                        Some(ReasonCode::CodexNoReadScope),
                    ),
                ),
                (ProtectionPath::Chat, chat),
            ],
            hook,
            drift,
            level: Level::Easy,
        }
    }

    /// The engine's revert, then the trust record Codex wrote for our hook
    /// (`[hooks.state."<hooks.json>:post_tool_use:<g>:<h>"]`) is removed: the
    /// hook is gone, and a record left behind would trust whatever hook the
    /// user later puts at that position. Only that record, at the position
    /// our hook had and under the path as written or in its canonical form;
    /// an emptied `[hooks.state]` and `[hooks]` go too. The position and the
    /// canonical path are read before the revert, which may delete
    /// `hooks.json`. If the record cannot be removed the revert stands and
    /// `codex_trust_left` is set. Not part of [`revert`](HarnessAdapter::revert):
    /// a Reconnect reverts and applies again, and keeps the record, so the
    /// user does not have to trust the hook again.
    fn revert_final(&self, inst: &Installation, b: &Backup) -> Result<RevertReport, AdapterError> {
        let file_of = |rec: &FileRecord| ConfigFile {
            role: rec.role,
            path: rec.path.clone(),
            format: rec.format,
            full_copy: rec.full_copy,
        };
        let keys = b.file(FileRole::CodexHooks).map(file_of).and_then(|f| {
            let (g, h) = our_hook_position(&current_value(&f).ok()?)?;
            Some(trust_keys(&f.path, g, h))
        });
        let cfg = b
            .file(FileRole::CodexConfig)
            .map(file_of)
            .or_else(|| inst.file(FileRole::CodexConfig).cloned());
        let mut report = self.revert(inst, b)?;
        if let (Some(keys), Some(cfg)) = (keys, cfg) {
            report.codex_trust_left = remove_trust(&cfg, &keys);
        }
        Ok(report)
    }

    fn check_invocation(&self, inst: &Installation, c: &CheckPlan) -> Option<Invocation> {
        inst.binary
            .as_deref()
            .and_then(|b| crate::check::codex(b, c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_file(dir: &Path, text: &str) -> ConfigFile {
        let path = dir.join("config.toml");
        std::fs::write(&path, text).unwrap();
        ConfigFile {
            role: FileRole::CodexConfig,
            path,
            format: Format::Toml,
            full_copy: true,
        }
    }

    /// A record we cannot prove gone is reported as left, never as removed.
    #[test]
    fn remove_trust_on_an_unparsable_file_reports_the_record_left() {
        let d = tempfile::tempdir().unwrap();
        let f = config_file(d.path(), "[hooks.state\"k\"\ntrusted_hash = \n");
        assert!(remove_trust(&f, &["k".to_string()]));
    }

    #[test]
    fn remove_trust_on_a_missing_record_or_file_is_not_left() {
        let d = tempfile::tempdir().unwrap();
        let f = config_file(d.path(), "model = \"x\"\n");
        assert!(!remove_trust(&f, &["k".to_string()]));
        std::fs::remove_file(&f.path).unwrap();
        assert!(!remove_trust(&f, &["k".to_string()]));
        assert!(!f.path.exists(), "a missing file is never created");
    }
}
