//! OpenClaw (spec §4.3, docs/harness-adapters.md rows OC-*):
//! `~/.openclaw/openclaw.json` (JSON5) holds MCP servers, the Docker
//! sandbox binds, and model providers. Subscription chat is red by design;
//! no hook (openclaw#60209).
//!
//! The Docker bind is written only when the mirror root lies inside an
//! agent workspace root: a bind source outside them needs
//! `dangerouslyAllowExternalBindSources`, which Easy mode never writes
//! (§7 item 14). Otherwise Files is `Unsupported` and
//! [`Openclaw::docker_bind_snippet`] gives the manual lines.
//!
//! The proxy client header goes in `models.providers.inumaki.headers`
//! (`types.models.ts`: `headers?: Record<string, SecretInput>`).

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{EntryKeys, HarnessAdapter, bearer, chat_live_warning, entry_from_json, p};
use crate::detect::{ProbeEnv, find_binary, version, version_in};
use crate::engine::{self, current_value};
use crate::model::*;
use crate::node::{Edit, Format, Node, value_at};
use crate::status::{chat_state, drifted, files_state, mcp_state};

/// Version range of the golden files (docs/harness-adapters.md §1).
pub const TESTED_MIN: &str = "2026.9.6";
/// Upper end of the range.
pub const TESTED_MAX: &str = "2026.9.6";
const MCP: [&str; 2] = ["mcp", "servers"];
const DOCKER: [&str; 4] = ["agents", "defaults", "sandbox", "docker"];
const BINDS: [&str; 5] = ["agents", "defaults", "sandbox", "docker", "binds"];
const PROVIDER: [&str; 3] = ["models", "providers", "inumaki"];
const PROVIDER_BASE: [&str; 4] = ["models", "providers", "inumaki", "baseUrl"];
const PROVIDER_HEADERS: [&str; 4] = ["models", "providers", "inumaki", "headers"];
/// `agents.defaults.model`: a string, or `{primary, fallbacks}` (OC-CHAT-KEY).
const MODEL: [&str; 3] = ["agents", "defaults", "model"];
/// The selection key when `model` is an object.
const SELECT: [&str; 4] = ["agents", "defaults", "model", "primary"];
/// Provider API kinds per route (docs/harness-adapters.md OC-CHAT-KEY).
const API_OPENAI: &str = "openai-completions";
const API_ANTHROPIC: &str = "anthropic-messages";
const OPENAI_SUFFIX: &str = "/v1";
const ID: &str = "inumaki";
const KEYS: EntryKeys = EntryKeys {
    url: "url",
    env: "env",
    headers: "headers",
    approval: None,
};
const OWNED: &[(FileRole, &[&str])] = &[
    (FileRole::OpenclawConfig, &["mcp", "servers", "*"]),
    (FileRole::OpenclawConfig, &BINDS),
    (FileRole::OpenclawConfig, &PROVIDER),
    (FileRole::OpenclawConfig, &MODEL),
    (FileRole::OpenclawConfig, &SELECT),
];

/// The OpenClaw adapter.
pub struct Openclaw;

/// The selected model: the key that holds it, its provider, and its model id
/// (`openai/gpt-5` → `("openai", "gpt-5")`).
fn selected(v: &Value) -> Option<(Vec<String>, String, String)> {
    let (path, m) = match value_at(v, &p(&MODEL))? {
        Value::String(s) => (p(&MODEL), s.as_str()),
        Value::Object(o) => (p(&SELECT), o.get("primary")?.as_str()?),
        _ => return None,
    };
    let (provider, model) = m.split_once('/')?;
    Some((path, provider.to_string(), model.to_string()))
}

/// The route of the selected provider. Chat is rewritten only when the
/// selected provider has a matching route (review minor item).
fn chat_route(v: &Value) -> Option<Route> {
    let (_, provider, _) = selected(v)?;
    match provider.as_str() {
        "openai" => Some(Route::Openai),
        "anthropic" => Some(Route::Anthropic),
        ID => {
            let base = value_at(v, &p(&PROVIDER_BASE)).and_then(Value::as_str);
            Some(if base.is_some_and(|b| b.contains("/anthropic")) {
                Route::Anthropic
            } else {
                Route::Openai
            })
        }
        _ => None,
    }
}

/// The key reference of a provider: its existing `${ENV}` reference, kept,
/// else the harness's usual variable. A literal key is never copied.
fn api_key_ref(v: &Value, provider: &str, route: Route) -> String {
    value_at(v, &p(&["models", "providers", provider, "apiKey"]))
        .and_then(Value::as_str)
        .filter(|s| s.starts_with("${") && s.ends_with('}'))
        .map(str::to_string)
        .unwrap_or_else(|| {
            match route {
                Route::Anthropic => "${ANTHROPIC_API_KEY}",
                _ => "${OPENAI_API_KEY}",
            }
            .to_string()
        })
}

/// The agent workspace roots the config names (`agents.defaults.workspace`
/// and each `agents.list[].workspace`): the roots a Docker bind source may
/// lie under without `dangerouslyAllowExternalBindSources`. Only absolute
/// paths count (a `~` path is not expanded: the answer errs toward "outside").
fn workspace_roots(v: &Value) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut add = |x: Option<&Value>| {
        if let Some(s) = x
            .and_then(Value::as_str)
            .filter(|s| Path::new(s).is_absolute())
        {
            out.push(PathBuf::from(s));
        }
    };
    add(value_at(v, &p(&["agents", "defaults", "workspace"])));
    if let Some(list) = value_at(v, &p(&["agents", "list"])).and_then(Value::as_array) {
        for a in list {
            add(a.get("workspace"));
        }
    }
    out
}

fn has_docker(v: &Value) -> bool {
    value_at(v, &p(&DOCKER)).is_some_and(Value::is_object)
}

fn bind_entry(mirror: &Path) -> String {
    let m = mirror.to_string_lossy();
    format!("{m}:{m}:ro")
}

/// `oauth` among the auth profiles' `mode` values (docs/harness-adapters.md
/// §4) → subscription; `api_key` or `token`, or an `apiKey` on a provider →
/// API key. Only names and modes are looked at.
fn login_of(v: &Value) -> LoginKind {
    let modes: Vec<&str> = value_at(v, &p(&["auth", "profiles"]))
        .and_then(Value::as_object)
        .map(|m| {
            m.values()
                .filter_map(|x| x.get("mode").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let provider_key = value_at(v, &p(&["models", "providers"]))
        .and_then(Value::as_object)
        .is_some_and(|m| m.values().any(|x| x.get("apiKey").is_some()));
    if modes.contains(&"oauth") {
        LoginKind::Oauth
    } else if modes.iter().any(|m| matches!(*m, "api_key" | "token")) || provider_key {
        LoginKind::ApiKey
    } else {
        LoginKind::Unknown
    }
}

impl Openclaw {
    /// `openclaw.json`: `OPENCLAW_CONFIG_PATH` (the file), else under
    /// `OPENCLAW_STATE_DIR`, else `<home>/.openclaw[-<profile>]` where the
    /// home is `OPENCLAW_HOME` or the user's (docs/harness-adapters.md §2;
    /// the profile directory name is not confirmed there).
    fn config_path(env: &ProbeEnv) -> PathBuf {
        if let Some(f) = env.var("OPENCLAW_CONFIG_PATH") {
            return PathBuf::from(f);
        }
        if let Some(d) = env.var("OPENCLAW_STATE_DIR") {
            return Path::new(d).join("openclaw.json");
        }
        let home = env
            .var("OPENCLAW_HOME")
            .map_or_else(|| env.home.clone(), PathBuf::from);
        let dir = match env.var("OPENCLAW_PROFILE") {
            Some(prof) => format!(".openclaw-{prof}"),
            None => ".openclaw".to_string(),
        };
        home.join(dir).join("openclaw.json")
    }

    /// The manual line for a mirror that cannot be bound without a
    /// `dangerously*` flag (Easy mode writes none): the bind. The flag is
    /// the user's own decision and is named in [`ManualSetup::note`].
    pub fn docker_bind_snippet(files: &FilesPlan) -> String {
        crate::edit::snippet(&[Edit::Push {
            path: p(&BINDS),
            value: Node::s(bind_entry(&files.mirror_root)),
        }])
    }
}

impl HarnessAdapter for Openclaw {
    fn id(&self) -> HarnessId {
        HarnessId::Openclaw
    }

    fn owned(&self) -> &'static [(FileRole, &'static [&'static str])] {
        OWNED
    }

    fn config_files(&self, env: &ProbeEnv) -> Vec<ConfigFile> {
        vec![ConfigFile {
            role: FileRole::OpenclawConfig,
            path: Self::config_path(env),
            format: Format::Json5,
            full_copy: true,
        }]
    }

    fn detect(&self, env: &ProbeEnv) -> Option<Installation> {
        let files = self.config_files(env);
        let binary = find_binary(env, "openclaw", &[]);
        if binary.is_none() && !files[0].path.exists() {
            return None;
        }
        let version = binary.as_deref().and_then(|b| version(env, b));
        let tested = version
            .as_deref()
            .is_some_and(|v| version_in(v, TESTED_MIN, TESTED_MAX));
        let login = current_value(&files[0])
            .map(|v| login_of(&v))
            .unwrap_or(LoginKind::Unknown);
        Some(Installation {
            harness: HarnessId::Openclaw,
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
        let v = current_value(&inst.config_files[0])?;
        Ok(value_at(&v, &p(&MCP))
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(n, d)| entry_from_json(n, Scope::User, d, &KEYS, gateway_base))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// The bind line for a mirror outside the workspace roots
    /// (`OpenclawDockerBindsOnly`).
    fn manual_setup(&self, status: &HarnessStatus, sys: &SystemState) -> Option<ManualSetup> {
        let (_, files) = &status.paths[1];
        if *files
            != (PathState::Unsupported {
                reason: ReasonCode::OpenclawDockerBindsOnly,
            })
        {
            return None;
        }
        let folders = sys.folders.as_ref()?;
        Some(ManualSetup {
            lines: Self::docker_bind_snippet(&FilesPlan {
                mirror_root: folders.mirror_root.clone(),
                outboxes: Vec::new(),
            }),
            note: "OpenClaw also blocks a bind outside its workspace roots unless agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources is true. That flag widens what the sandbox may mount, so inumaki never writes it; adding it is your decision.",
        })
    }

    fn chat_key(&self) -> (FileRole, &'static [&'static str]) {
        (FileRole::OpenclawConfig, &PROVIDER)
    }

    fn plan_edits(
        &self,
        inst: &Installation,
        plan: &ConnectPlan,
    ) -> Result<Vec<(ConfigFile, Vec<Edit>)>, AdapterError> {
        let f = inst.config_files[0].clone();
        // An unparsable file still gets its gateway edits: `apply_files`'
        // dry run then refuses with the full snippet (spec §4.2). Files and
        // chat are skipped for it.
        let cur = current_value(&f).unwrap_or(Value::Null);
        let mut e = Vec::new();
        if let Some(g) = &plan.gateway {
            for x in g.entries.iter().filter(|x| x.scope == Scope::User) {
                let mut path = p(&MCP);
                path.push(x.name.clone());
                e.push(Edit::Set {
                    path,
                    value: Node::obj([
                        ("url", Node::s(&x.url)),
                        ("transport", Node::s("streamable-http")),
                        (
                            "headers",
                            Node::obj([("Authorization", Node::s(bearer(&g.token)))]),
                        ),
                    ]),
                });
            }
        }
        if let Some(files) = &plan.files
            && has_docker(&cur)
            && workspace_roots(&cur)
                .iter()
                .any(|r| files.mirror_root.starts_with(r))
        {
            e.push(Edit::Push {
                path: p(&BINDS),
                value: Node::s(bind_entry(&files.mirror_root)),
            });
        }
        if let (Some(chat), LoginKind::ApiKey, Some(route), Some((select, from, model))) =
            (&plan.chat, inst.login, chat_route(&cur), selected(&cur))
        {
            let provider = match route {
                Route::Openai => chat
                    .openai
                    .as_ref()
                    .map(|u| (format!("{u}{OPENAI_SUFFIX}"), API_OPENAI)),
                Route::Anthropic => chat.anthropic.as_ref().map(|u| (u.clone(), API_ANTHROPIC)),
                Route::Codex => None,
            };
            if let Some((base, api)) = provider {
                let mut pairs = vec![
                    ("baseUrl", Node::s(base)),
                    ("api", Node::s(api)),
                    ("apiKey", Node::s(api_key_ref(&cur, &from, route))),
                    (
                        "models",
                        Node::Arr(vec![Node::obj([
                            ("id", Node::s(&model)),
                            ("name", Node::s(&model)),
                        ])]),
                    ),
                ];
                // The proxy restores dataset tokens in the answer only for
                // requests that carry this header (spec §4.3 amendment).
                if let Some(h) = &plan.proxy_client_header {
                    pairs.push(("headers", Node::obj([(h.name, Node::s(h.value.as_str()))])));
                }
                e.push(Edit::Set {
                    path: p(&PROVIDER),
                    value: Node::obj(pairs),
                });
                e.push(Edit::Set {
                    path: select,
                    value: Node::s(format!("{ID}/{model}")),
                });
            }
        }
        Ok(vec![(f, e)])
    }

    /// [`ConnectWarning::OpenclawChatLive`] when the plan writes the chat
    /// provider (the selected provider has a route the plan carries).
    fn connect_warnings(&self, inst: &Installation, plan: &ConnectPlan) -> Vec<ConnectWarning> {
        chat_live_warning(self, inst, plan).into_iter().collect()
    }

    fn status(&self, inst: &Installation, sys: &SystemState) -> HarnessStatus {
        let drift = sys.applied.as_ref().map(engine::drift).unwrap_or_default();
        let servers = self
            .mcp_servers(inst, &sys.gateway_base)
            .unwrap_or_default();
        let v = current_value(&inst.config_files[0]).unwrap_or(Value::Null);
        let binds_drift = drifted(&drift, FileRole::OpenclawConfig, &p(&BINDS));
        let files = if !has_docker(&v) {
            PathState::Unsupported {
                reason: ReasonCode::OpenclawNoDockerSandbox,
            }
        } else {
            let listed = sys.folders.as_ref().is_some_and(|f| {
                let want = bind_entry(&f.mirror_root);
                value_at(&v, &p(&BINDS))
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(&want)))
            });
            let outside = sys.folders.as_ref().is_some_and(|f| {
                !workspace_roots(&v)
                    .iter()
                    .any(|r| f.mirror_root.starts_with(r))
            });
            if !listed && !binds_drift && outside {
                // Easy mode writes no `dangerously*` flag (§7 item 14).
                PathState::Unsupported {
                    reason: ReasonCode::OpenclawDockerBindsOnly,
                }
            } else {
                files_state(
                    listed,
                    sys,
                    binds_drift,
                    Some(ReasonCode::OpenclawDockerBindsOnly),
                )
            }
        };
        let chat = match inst.login {
            LoginKind::Oauth => PathState::Unsupported {
                reason: ReasonCode::OpenclawSubscriptionBridge,
            },
            _ => match chat_route(&v) {
                None => PathState::NotConnected {
                    reason: Some(ReasonCode::ChatProviderNotRouted),
                },
                Some(route) => {
                    let ours = selected(&v).is_some_and(|(_, prov, _)| prov == ID);
                    let base = ours
                        .then(|| value_at(&v, &p(&PROVIDER_BASE)).and_then(Value::as_str))
                        .flatten();
                    // The provider must send the daemon's current client header.
                    let header_drift = ours
                        && sys
                            .proxy
                            .as_ref()
                            .and_then(|x| x.client_header.as_ref())
                            .is_some_and(|h| {
                                value_at(&v, &p(&PROVIDER_HEADERS))
                                    .and_then(|x| x.get(h.name))
                                    .and_then(Value::as_str)
                                    != Some(h.value.as_str())
                            });
                    let chat_drift = header_drift
                        || drifted(&drift, FileRole::OpenclawConfig, &p(&PROVIDER))
                        || drifted(&drift, FileRole::OpenclawConfig, &p(&MODEL));
                    chat_state(HarnessId::Openclaw, base, route, sys, chat_drift)
                }
            },
        };
        HarnessStatus {
            paths: [
                (
                    ProtectionPath::Mcp,
                    mcp_state(
                        &servers,
                        sys,
                        drifted(&drift, FileRole::OpenclawConfig, &p(&MCP)),
                    ),
                ),
                (ProtectionPath::Files, files),
                (ProtectionPath::Chat, chat),
            ],
            hook: HookState::NotSupported {
                reason: ReasonCode::OpenclawHookNotFiring,
            },
            drift,
            level: Level::Easy,
        }
    }
}
