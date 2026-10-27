//! Hermes Agent (spec §4.3, docs/harness-adapters.md rows HM-*):
//! `~/.hermes/config.yaml` holds MCP servers and providers. No Files path
//! (unconfirmed) and no hook (Hermes runs hooks fail-open).
//!
//! Chat is written only for an API-key login whose selected provider has a
//! proxy route, as `providers.inumaki` (+ `model.provider: inumaki`). The
//! proxy client header goes in that provider's `extra_headers`
//! (`runtime_provider_custom.py::_match_new_style_provider` reads it, HM-CHAT-KEY).
//! A subscription login is `Unverified` and nothing is written: its base
//! URL is an environment variable in `.env` (`HERMES_CODEX_BASE_URL`), which
//! no editor here touches; [`Hermes::oauth_chat_snippet`] gives the lines.

use std::path::{Path, PathBuf};

use serde_json::Value;
use zeroize::Zeroizing;

use super::{EntryKeys, HarnessAdapter, bearer, chat_live_warning, entry_from_json, p};
use crate::detect::{ProbeEnv, find_binary, version, version_in};
use crate::engine::{self, current_value};
use crate::model::*;
use crate::node::{Edit, Format, Node, value_at};
use crate::status::{chat_state, drifted, mcp_state};

/// Version range of the golden files (docs/harness-adapters.md §1).
pub const TESTED_MIN: &str = "2026.9.24";
/// Upper end of the range.
pub const TESTED_MAX: &str = "2026.9.24";
const MCP: &str = "mcp_servers";
const PROVIDERS: &str = "providers";
const ID: &str = "inumaki";
/// The provider selection key (HM-CHAT-KEY).
const SELECT: [&str; 2] = ["model", "provider"];
/// Header table key of an MCP entry (HM-MCP).
const HEADERS: &str = "headers";
/// The custom provider's extra request headers (HM-CHAT-KEY).
const EXTRA_HEADERS: &str = "extra_headers";
const OPENAI_SUFFIX: &str = "/v1";
const KEYS: EntryKeys = EntryKeys {
    url: "url",
    env: "env",
    headers: HEADERS,
    approval: None,
};
const OWNED: &[(FileRole, &[&str])] = &[
    (FileRole::HermesConfig, &[MCP, "*"]),
    (FileRole::HermesConfig, &[PROVIDERS, ID]),
    (FileRole::HermesConfig, &SELECT),
];

/// The Hermes adapter.
pub struct Hermes;

/// Key names in the `.env` of `dir`; values are read into a zeroized buffer
/// and dropped, never kept (login detection and the route check need names
/// only). A missing or unreadable file has none.
fn env_key_names(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join(".env"))
        .map(Zeroizing::new)
        .map(|t| {
            t.lines()
                .filter_map(|l| {
                    let l = l.trim();
                    let l = l.strip_prefix("export ").unwrap_or(l);
                    (!l.starts_with('#'))
                        .then(|| l.split_once('=').map(|(k, _)| k.trim().to_string()))
                        .flatten()
                        .filter(|k| !k.is_empty())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The directory of an installation's `config.yaml`.
fn dir_of(config: &ConfigFile) -> &Path {
    config.path.parent().unwrap_or(Path::new("."))
}

/// The route our provider entry points at.
fn route_of_base(base: Option<&str>) -> Route {
    if base.is_some_and(|b| b.contains("/anthropic")) {
        Route::Anthropic
    } else {
        Route::Openai
    }
}

impl Hermes {
    fn dir(env: &ProbeEnv) -> PathBuf {
        env.var("HERMES_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| env.home.join(".hermes"))
    }

    /// The route of the provider the user selected, and its key variable.
    /// Chat is rewritten only when the selected provider has a matching
    /// route (review minor item): a user on OpenRouter keeps OpenRouter.
    fn chat_route(
        login: LoginKind,
        cfg: &Value,
        env_keys: &[String],
    ) -> Option<(Route, &'static str)> {
        if login != LoginKind::ApiKey {
            return None;
        }
        let selected = value_at(cfg, &p(&SELECT)).and_then(Value::as_str)?;
        let route = match selected {
            "openai" => Route::Openai,
            "anthropic" => Route::Anthropic,
            s if s == ID => route_of_base(
                value_at(cfg, &p(&[PROVIDERS, ID, "base_url"])).and_then(Value::as_str),
            ),
            _ => return None,
        };
        let key = if route == Route::Anthropic {
            "ANTHROPIC_API_KEY"
        } else {
            "OPENAI_API_KEY"
        };
        env_keys.iter().any(|k| k == key).then_some((route, key))
    }

    /// What a subscription login needs, by hand (nothing is written for it):
    /// the `.env` line for the ChatGPT/Codex login, and the `model` keys for
    /// the Anthropic login (HM-CHAT-OAUTH). `None` when the plan has no route.
    pub fn oauth_chat_snippet(chat: &ChatPlan) -> Option<String> {
        let mut out = String::new();
        if let Some(u) = &chat.codex {
            out.push_str(&format!(
                "ChatGPT or Codex login, in ~/.hermes/.env: HERMES_CODEX_BASE_URL={u}\n"
            ));
        }
        if let Some(u) = &chat.anthropic {
            out.push_str(&format!(
                "Anthropic login, in config.yaml, with model.provider anthropic: set model.base_url to {u}\n"
            ));
        }
        (!out.is_empty()).then_some(out)
    }
}

impl HarnessAdapter for Hermes {
    fn id(&self) -> HarnessId {
        HarnessId::Hermes
    }

    fn owned(&self) -> &'static [(FileRole, &'static [&'static str])] {
        OWNED
    }

    fn config_files(&self, env: &ProbeEnv) -> Vec<ConfigFile> {
        vec![ConfigFile {
            role: FileRole::HermesConfig,
            path: Self::dir(env).join("config.yaml"),
            format: Format::Yaml,
            full_copy: true,
        }]
    }

    fn detect(&self, env: &ProbeEnv) -> Option<Installation> {
        let files = self.config_files(env);
        if !files[0].path.exists() {
            return None; // Hermes writes config.yaml on setup; without it there is nothing to connect.
        }
        let binary = find_binary(env, "hermes", &[]);
        let version = binary.as_deref().and_then(|b| version(env, b));
        let tested = version
            .as_deref()
            .is_some_and(|v| version_in(v, TESTED_MIN, TESTED_MAX));
        let dir = Self::dir(env);
        let login = if env_key_names(&dir).iter().any(|k| k.ends_with("_API_KEY")) {
            LoginKind::ApiKey
        } else if dir.join("auth.json").exists() {
            LoginKind::Oauth
        } else {
            LoginKind::Unknown
        };
        Some(Installation {
            harness: HarnessId::Hermes,
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
        (FileRole::HermesConfig, &[PROVIDERS, ID])
    }

    fn plan_edits(
        &self,
        inst: &Installation,
        plan: &ConnectPlan,
    ) -> Result<Vec<(ConfigFile, Vec<Edit>)>, AdapterError> {
        let f = inst.config_files[0].clone();
        let mut e = Vec::new();
        if let Some(g) = &plan.gateway {
            for x in g.entries.iter().filter(|x| x.scope == Scope::User) {
                e.push(Edit::Set {
                    path: vec![MCP.to_string(), x.name.clone()],
                    value: Node::obj([
                        ("url", Node::s(&x.url)),
                        (
                            HEADERS,
                            Node::obj([("Authorization", Node::s(bearer(&g.token)))]),
                        ),
                    ]),
                });
            }
        }
        if let Some(chat) = &plan.chat {
            // An unparsable file still gets its gateway edits: `apply_files`'
            // dry run then refuses with the full snippet (spec §4.2).
            let cur = current_value(&f).unwrap_or(Value::Null);
            if let Some((route, key_env)) =
                Self::chat_route(inst.login, &cur, &env_key_names(dir_of(&f)))
            {
                let base = match route {
                    Route::Openai => chat.openai.as_ref().map(|u| format!("{u}{OPENAI_SUFFIX}")),
                    Route::Anthropic => chat.anthropic.clone(),
                    Route::Codex => None,
                };
                if let Some(base) = base {
                    let mut pairs =
                        vec![("base_url", Node::s(base)), ("key_env", Node::s(key_env))];
                    // The proxy restores dataset tokens in the answer only for
                    // requests that carry this header (spec §4.3 amendment).
                    if let Some(h) = &plan.proxy_client_header {
                        pairs.push((
                            EXTRA_HEADERS,
                            Node::obj([(h.name, Node::s(h.value.as_str()))]),
                        ));
                    }
                    e.push(Edit::Set {
                        path: vec![PROVIDERS.to_string(), ID.to_string()],
                        value: Node::obj(pairs),
                    });
                    e.push(Edit::Set {
                        path: p(&SELECT),
                        value: Node::s(ID),
                    });
                }
            }
        }
        // Files and the hook: nothing to write (spec §4.3).
        Ok(vec![(f, e)])
    }

    /// [`ConnectWarning::HermesChatLive`] when the plan writes the chat
    /// provider (the selected provider has a route the plan carries).
    fn connect_warnings(&self, inst: &Installation, plan: &ConnectPlan) -> Vec<ConnectWarning> {
        chat_live_warning(self, inst, plan).into_iter().collect()
    }

    fn status(&self, inst: &Installation, sys: &SystemState) -> HarnessStatus {
        let drift = sys.applied.as_ref().map(engine::drift).unwrap_or_default();
        let servers = self
            .mcp_servers(inst, &sys.gateway_base)
            .unwrap_or_default();
        let file = &inst.config_files[0];
        let v = current_value(file).unwrap_or(Value::Null);
        let ours = value_at(&v, &p(&SELECT)).and_then(Value::as_str) == Some(ID);
        let provider = value_at(&v, &p(&[PROVIDERS, ID]));
        let base = if ours {
            provider
                .and_then(|x| x.get("base_url"))
                .and_then(Value::as_str)
        } else {
            None
        };
        let route = route_of_base(base);
        let routable = Self::chat_route(inst.login, &v, &env_key_names(dir_of(file))).is_some();
        // The provider must send the daemon's current client header.
        let header_drift = ours
            && sys
                .proxy
                .as_ref()
                .and_then(|x| x.client_header.as_ref())
                .is_some_and(|h| {
                    provider
                        .and_then(|x| x.get(EXTRA_HEADERS))
                        .and_then(|x| x.get(h.name))
                        .and_then(Value::as_str)
                        != Some(h.value.as_str())
                });
        let chat_drift = header_drift
            || drifted(&drift, FileRole::HermesConfig, &[PROVIDERS.to_string()])
            || drifted(&drift, FileRole::HermesConfig, &p(&SELECT));
        let chat = match inst.login {
            // Not written, and not provable: the override lives outside the
            // editors (docs/harness-adapters.md §7 item 12).
            LoginKind::Oauth if !ours => PathState::Unverified {
                reason: ReasonCode::HermesOauthNoOverride,
            },
            _ if !ours && !routable => PathState::NotConnected {
                reason: Some(ReasonCode::ChatProviderNotRouted),
            },
            _ => chat_state(HarnessId::Hermes, base, route, sys, chat_drift),
        };
        HarnessStatus {
            paths: [
                (
                    ProtectionPath::Mcp,
                    mcp_state(
                        &servers,
                        sys,
                        drifted(&drift, FileRole::HermesConfig, &[MCP.to_string()]),
                    ),
                ),
                (
                    ProtectionPath::Files,
                    PathState::Unsupported {
                        reason: ReasonCode::HermesFilesUnconfirmed,
                    },
                ),
                (ProtectionPath::Chat, chat),
            ],
            hook: HookState::NotSupported {
                reason: ReasonCode::HermesHooksFailOpen,
            },
            drift,
            level: Level::Easy,
        }
    }

    /// The base-URL lines for a subscription login (`HermesOauthNoOverride`).
    fn manual_setup(&self, status: &HarnessStatus, sys: &SystemState) -> Option<ManualSetup> {
        let (_, chat) = &status.paths[2];
        if *chat
            != (PathState::Unverified {
                reason: ReasonCode::HermesOauthNoOverride,
            })
        {
            return None;
        }
        let proxy = sys.proxy.as_ref()?;
        let url = |r| proxy.route(r).map(|x| x.base_url.clone());
        let lines = Self::oauth_chat_snippet(&ChatPlan {
            anthropic: url(Route::Anthropic),
            openai: None,
            codex: url(Route::Codex),
            codex_chatgpt: false,
        })?;
        Some(ManualSetup {
            lines,
            note: "Hermes OAuth sends no client header, so only session tokens are restored.",
        })
    }

    fn check_invocation(&self, inst: &Installation, c: &CheckPlan) -> Option<Invocation> {
        inst.binary
            .as_deref()
            .and_then(|b| crate::check::hermes(b, c))
    }
}
