//! The adapter contract's types (M6 spec §4.1). `Debug` of every type here
//! prints roles, kinds, counts, and reason codes only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::node::{Edit, Format};

/// A harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HarnessId {
    /// Claude Code.
    ClaudeCode,
    /// Codex CLI.
    Codex,
    /// Hermes Agent.
    Hermes,
    /// OpenClaw.
    Openclaw,
}

impl HarnessId {
    /// Every harness, in card order.
    pub const ALL: [HarnessId; 4] = [
        HarnessId::ClaudeCode,
        HarnessId::Codex,
        HarnessId::Hermes,
        HarnessId::Openclaw,
    ];

    /// `claude-code`, `codex`, `hermes`, `openclaw` (the contract's `HarnessId`).
    pub fn as_str(self) -> &'static str {
        match self {
            HarnessId::ClaudeCode => "claude-code",
            HarnessId::Codex => "codex",
            HarnessId::Hermes => "hermes",
            HarnessId::Openclaw => "openclaw",
        }
    }

    /// Parse [`HarnessId::as_str`].
    pub fn parse(s: &str) -> Option<HarnessId> {
        HarnessId::ALL.into_iter().find(|h| h.as_str() == s)
    }

    /// The gateway token label of this harness (spec §4.5).
    pub fn token_label(self) -> String {
        format!("app:{}", self.as_str())
    }
}

/// Which harness file.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FileRole {
    /// `~/.claude.json` (rewritten by Claude Code; manifest only, never copied).
    ClaudeJson,
    /// `~/.claude/settings.json`.
    ClaudeSettings,
    /// `~/.codex/config.toml`.
    CodexConfig,
    /// `~/.codex/hooks.json`.
    CodexHooks,
    /// `~/.hermes/config.yaml`.
    HermesConfig,
    /// `~/.openclaw/openclaw.json`.
    OpenclawConfig,
}

/// One harness file.
#[derive(Clone)]
pub struct ConfigFile {
    /// Role.
    pub role: FileRole,
    /// Path (may be a symlink).
    pub path: PathBuf,
    /// Syntax.
    pub format: Format,
    /// A backup keeps a full copy (user-edited files only).
    pub full_copy: bool,
}

impl std::fmt::Debug for ConfigFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigFile")
            .field("role", &self.role)
            .field("format", &self.format)
            .field("full_copy", &self.full_copy)
            .finish_non_exhaustive()
    }
}

/// Login kind, from file and key presence only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginKind {
    /// Subscription or ChatGPT login.
    Oauth,
    /// API key.
    ApiKey,
    /// Neither found.
    Unknown,
}

/// A detected harness.
#[derive(Clone)]
pub struct Installation {
    /// Harness.
    pub harness: HarnessId,
    /// Binary, if found.
    pub binary: Option<PathBuf>,
    /// `--version` output's version, if any.
    pub version: Option<String>,
    /// The version is inside the range the golden files were recorded against.
    pub tested: bool,
    /// Its configuration files (existing or to be created).
    pub config_files: Vec<ConfigFile>,
    /// Login kind.
    pub login: LoginKind,
}

impl Installation {
    /// The file with `role`.
    pub fn file(&self, role: FileRole) -> Option<&ConfigFile> {
        self.config_files.iter().find(|f| f.role == role)
    }
}

impl std::fmt::Debug for Installation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Installation")
            .field("harness", &self.harness)
            .field("has_binary", &self.binary.is_some())
            .field("version", &self.version)
            .field("tested", &self.tested)
            .field("files", &self.config_files)
            .field("login", &self.login)
            .finish()
    }
}

/// A protection path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtectionPath {
    /// MCP through the gateway.
    Mcp,
    /// Files through the mirror.
    Files,
    /// Chat through the proxy.
    Chat,
}

/// Why a path has its state: a closed set with one fixed sentence each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReasonCode {
    /// OpenClaw subscription login.
    OpenclawSubscriptionBridge,
    /// Codex has no read-scope setting.
    CodexNoReadScope,
    /// OpenClaw Files through Docker binds only.
    OpenclawDockerBindsOnly,
    /// OpenClaw without a Docker sandbox.
    OpenclawNoDockerSandbox,
    /// Hermes Files unconfirmed.
    HermesFilesUnconfirmed,
    /// Hermes subscription login: the override (an environment variable, or
    /// `model.base_url`) is not written by inumaki; chat is `Unverified`.
    HermesOauthNoOverride,
    /// Codex ChatGPT login: chat goes to ChatGPT directly, and routing it
    /// through inumaki is a separate opt-in that is refused today.
    CodexChatgptUnverified,
    /// Chat is not routed through inumaki: the harness sends it straight to
    /// the provider, and inumaki does not see it.
    ChatNotProtected,
    /// The proxy route is failing.
    RouteFailing,
    /// The configuration changed outside inumaki.
    ChangedOutsideInumaki,
    /// No folder connected.
    NoFolderConnected,
    /// No proxy traffic seen yet.
    NoTrafficYet,
    /// A gateway entry's dataset has no running upstream.
    UpstreamNotRunning,
    /// The hook binary the registered hook command names is missing or not
    /// executable, or the command cannot be read.
    HookBinaryMissing,
    /// The registered hook command names another hook binary or service
    /// socket than this inumaki uses now (it moved, or the service runs
    /// from elsewhere): reconnect to rewrite it.
    HookOutdated,
    /// Hermes hooks fail open.
    HermesHooksFailOpen,
    /// OpenClaw's tool-result hook does not fire (openclaw#60209).
    OpenclawHookNotFiring,
    /// The model-API proxy is not available in this build.
    ProxyUnavailable,
    /// The folder mirror is not available in this build.
    MirrorUnavailable,
    /// The service is not running.
    ServiceDown,
    /// The login kind is unknown.
    LoginUnknown,
    /// The harness's selected chat provider has no matching proxy route.
    ChatProviderNotRouted,
    /// A Codex profile sets its own `model_provider`.
    CodexProfileOverride,
    /// Chat is filtered, but the harness cannot send the proxy client
    /// header (spec §4.3 amendment 2026-09-29).
    ChatTokensOnly,
    /// Codex runs a new or changed user hook only after the user trusts it
    /// in `/hooks` (docs/harness-adapters.md §7 deviation 7).
    CodexHookNeedsTrust,
}

impl ReasonCode {
    /// The fixed English sentence (spec §4.1, §4.3).
    pub fn sentence(self) -> &'static str {
        match self {
            ReasonCode::OpenclawSubscriptionBridge => {
                "OpenClaw's Claude or ChatGPT subscription login runs through a command-line bridge that has no base-URL setting, so chat text is not filtered. Use an API key, or keep sensitive data in connected sources."
            }
            ReasonCode::CodexNoReadScope => {
                "Codex has no setting that limits which folders it reads; inumaki can only make the outbox writable."
            }
            ReasonCode::OpenclawDockerBindsOnly => {
                "OpenClaw sees the mirror through its Docker sandbox only."
            }
            ReasonCode::OpenclawNoDockerSandbox => {
                "OpenClaw has no Docker sandbox configured, so the mirror cannot be mounted."
            }
            ReasonCode::HermesFilesUnconfirmed => {
                "The mirror exists, but Hermes has no confirmed setting that restricts it to the mirror."
            }
            ReasonCode::HermesOauthNoOverride => {
                "Hermes can route this login through inumaki only with a base-URL setting that inumaki does not write yet; chat text is not filtered until you add it by hand."
            }
            ReasonCode::CodexChatgptUnverified => {
                "Chat is not protected: Codex with a ChatGPT login talks to ChatGPT directly. Routing it through inumaki is a separate opt-in, and it is refused today (privacy_block)."
            }
            ReasonCode::ChatNotProtected => {
                "Chat is not protected: it goes straight to the provider, and inumaki does not see it."
            }
            ReasonCode::RouteFailing => "Recent requests through this route failed.",
            ReasonCode::ChangedOutsideInumaki => {
                "The configuration was changed outside inumaki. Reconnect to restore it."
            }
            ReasonCode::NoFolderConnected => "No folder is connected.",
            ReasonCode::NoTrafficYet => "No traffic seen yet.",
            ReasonCode::UpstreamNotRunning => "A protected server is not running.",
            ReasonCode::HookBinaryMissing => {
                "The inumaki hook program is missing or cannot be run."
            }
            ReasonCode::HookOutdated => {
                "The hook names an inumaki program or service socket that this inumaki no longer uses. Reconnect to update it."
            }
            ReasonCode::HermesHooksFailOpen => {
                "Hermes runs hooks fail-open, so inumaki installs none."
            }
            ReasonCode::OpenclawHookNotFiring => {
                "OpenClaw's tool-result hook does not fire in embedded runs (openclaw#60209), so inumaki installs none."
            }
            ReasonCode::ProxyUnavailable => "The chat proxy is not available in this version.",
            ReasonCode::MirrorUnavailable => "The folder mirror is not available in this version.",
            ReasonCode::ServiceDown => "The inumaki service is not running.",
            ReasonCode::LoginUnknown => "The login kind could not be determined.",
            ReasonCode::ChatProviderNotRouted => {
                "The selected model provider has no inumaki route, so chat was left unchanged."
            }
            ReasonCode::CodexProfileOverride => {
                "A Codex profile sets its own model provider; chat in that profile does not go through inumaki."
            }
            ReasonCode::ChatTokensOnly => {
                "Chat is filtered, but this harness cannot send inumaki's client header, so values from connected sources appear as tokens in chat answers."
            }
            ReasonCode::CodexHookNeedsTrust => {
                "Codex runs the inumaki hook only after you trust it: open /hooks in Codex and trust it."
            }
        }
    }
}

/// A fact of the harness's own configuration that limits what a connect
/// can do, or a consequence of what the connect installs, reported with the
/// connect outcome (CLI and app alike). A closed set with one fixed
/// sentence each: never a value from the file, never a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnectWarning {
    /// Codex's `config.toml` sets `approval_policy = "never"` while the
    /// connect writes gateway entries: Codex refuses every MCP tool call
    /// that needs approval, so the inumaki tools fail
    /// (docs/harness-adapters.md CX-MCP).
    CodexApprovalNever,
    /// Claude Code's chat route is written to the user-level
    /// `settings.json`, which every Claude Code window reads, not only the
    /// project the user connected from.
    ClaudeCodeChatLive,
    /// Codex's chat route (`model_provider`) is written: its next session
    /// sends chat through inumaki, which the support-email and strict
    /// profiles refuse today.
    CodexChatLive,
    /// Hermes Agent's chat route is written. Whether the support-email and
    /// strict profiles refuse its chat requests is not measured.
    HermesChatLive,
    /// OpenClaw's chat route is written. Whether the support-email and
    /// strict profiles refuse its chat requests is not measured.
    OpenclawChatLive,
    /// The connect installs the tool-result hook (Claude Code, Codex). The
    /// hook fails closed (ruling L97): while the service is stopped or
    /// unreachable, every hooked tool result in every session of that
    /// harness that runs the hook is replaced by a block.
    HookBlocksWhenStopped,
}

impl ConnectWarning {
    /// Stable code for the app's UI and tests.
    pub fn code(self) -> &'static str {
        match self {
            ConnectWarning::CodexApprovalNever => "codex_approval_never",
            ConnectWarning::ClaudeCodeChatLive => "claude_code_chat_live",
            ConnectWarning::CodexChatLive => "codex_chat_live",
            ConnectWarning::HermesChatLive => "hermes_chat_live",
            ConnectWarning::OpenclawChatLive => "openclaw_chat_live",
            ConnectWarning::HookBlocksWhenStopped => "hook_blocks_when_stopped",
        }
    }

    /// The fixed English sentence.
    pub fn sentence(self) -> &'static str {
        match self {
            ConnectWarning::CodexApprovalNever => {
                "Codex is set to approval_policy = never and will refuse the inumaki tool calls; to allow them, set default_tools_approval_mode on the inumaki server entry in Codex's config."
            }
            ConnectWarning::ClaudeCodeChatLive => {
                "Every open Claude Code window now sends chat through inumaki, including other projects; with the support-email or strict profile its chat requests are refused today."
            }
            ConnectWarning::CodexChatLive => {
                "Codex sends chat through inumaki from its next session; with the support-email or strict profile its chat requests are refused today."
            }
            ConnectWarning::HermesChatLive => {
                "Hermes Agent sends chat through inumaki at the latest from its next session; whether the support-email or strict profile refuses its chat requests is not measured."
            }
            ConnectWarning::OpenclawChatLive => {
                "OpenClaw sends chat through inumaki at the latest from its next session; whether the support-email or strict profile refuses its chat requests is not measured."
            }
            ConnectWarning::HookBlocksWhenStopped => {
                "While inumaki is stopped, tool output in every connected session is blocked. Start the service to recover; Revert also needs it running."
            }
        }
    }

    /// The warning of an apply that writes `h`'s chat route.
    pub fn chat_live(h: HarnessId) -> ConnectWarning {
        match h {
            HarnessId::ClaudeCode => ConnectWarning::ClaudeCodeChatLive,
            HarnessId::Codex => ConnectWarning::CodexChatLive,
            HarnessId::Hermes => ConnectWarning::HermesChatLive,
            HarnessId::Openclaw => ConnectWarning::OpenclawChatLive,
        }
    }
}

/// Counts for a connected path; never names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detail {
    /// Protected items (servers, folders); 0 when not counted.
    pub protected: u32,
    /// All items.
    pub total: u32,
    /// A qualifying note.
    pub note: Option<ReasonCode>,
}

/// State of one path (spec §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Grey.
    NotConnected {
        /// Why, when there is something to say.
        reason: Option<ReasonCode>,
    },
    /// Yellow in Easy mode.
    Connected {
        /// Counts.
        detail: Detail,
    },
    /// Yellow, labeled unverified.
    Unverified {
        /// Why.
        reason: ReasonCode,
    },
    /// Red by design, acknowledgeable.
    Unsupported {
        /// Why.
        reason: ReasonCode,
    },
    /// Red.
    Broken {
        /// Why.
        reason: ReasonCode,
    },
}

/// State of the hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookState {
    /// Not installed.
    NotInstalled,
    /// Installed and executable.
    Installed,
    /// Yellow: installed and executable, but the harness does not run it
    /// yet (Codex: not trusted in `/hooks`).
    Pending {
        /// Why.
        reason: ReasonCode,
    },
    /// No hook for this harness in the MVP.
    NotSupported {
        /// Why.
        reason: ReasonCode,
    },
    /// Installed but broken.
    Broken {
        /// Why.
        reason: ReasonCode,
    },
}

/// An owned key whose value is no longer the one inumaki wrote.
#[derive(Clone, PartialEq, Eq)]
pub struct DriftItem {
    /// File.
    pub role: FileRole,
    /// Key path (can contain a server name: not in `Debug`).
    pub path: Vec<String>,
}

impl std::fmt::Debug for DriftItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriftItem")
            .field("role", &self.role)
            .field("depth", &self.path.len())
            .finish()
    }
}

/// Protection level (Easy only in M6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Easy mode.
    Easy,
}

/// A harness's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessStatus {
    /// MCP, Files, Chat, in that order.
    pub paths: [(ProtectionPath, PathState); 3],
    /// The hook.
    pub hook: HookState,
    /// Drifted owned keys.
    pub drift: Vec<DriftItem>,
    /// Level.
    pub level: Level,
}

/// How an MCP server is reached.
#[derive(Clone, PartialEq, Eq)]
pub enum Transport {
    /// A child process.
    Stdio {
        /// Program.
        command: String,
        /// Arguments.
        args: Vec<String>,
        /// Working directory.
        cwd: Option<String>,
    },
    /// Streamable HTTP.
    Http {
        /// URL.
        url: String,
    },
}

/// Where an entry lives.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// User scope.
    User,
    /// Claude Code local scope: `projects.<dir>.mcpServers`.
    Project(String),
}

/// One MCP server entry of a harness.
#[derive(Clone)]
pub struct McpServerEntry {
    /// Name (model-visible).
    pub name: String,
    /// Scope.
    pub scope: Scope,
    /// Transport.
    pub transport: Transport,
    /// Environment variable names.
    pub env_names: Vec<String>,
    /// Header names.
    pub header_names: Vec<String>,
    /// Values by `env:NAME` / `header:NAME`, for the Protect switch only.
    pub values: BTreeMap<String, Zeroizing<String>>,
    /// Already points at the gateway.
    pub gateway: bool,
    /// Needs the MCP OAuth flow ("cannot protect yet").
    pub needs_oauth: bool,
    /// The user's own tool-approval setting on this entry (Codex
    /// `default_tools_approval_mode`; `None` for other harnesses), as the
    /// file holds it (a non-string value is kept as it is). A user-owned
    /// sub-key: a connect carries it into the rewritten entry.
    pub approval_mode: Option<serde_json::Value>,
}

impl std::fmt::Debug for McpServerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServerEntry")
            .field("stdio", &matches!(self.transport, Transport::Stdio { .. }))
            .field("env", &self.env_names.len())
            .field("headers", &self.header_names.len())
            .field("gateway", &self.gateway)
            .field("needs_oauth", &self.needs_oauth)
            .finish_non_exhaustive()
    }
}

/// The name of the proxy client header (spec §4.3 amendment 2026-09-29).
pub const CLIENT_HEADER_NAME: &str = "X-Inumaki-Client";

/// The proxy client header: with it, the proxy restores dataset tokens in a
/// model's answer (M8 spec §8). The value is a per-install secret as
/// sensitive as a gateway token; `Debug` prints the name only.
#[derive(Clone)]
pub struct ClientHeader {
    /// Always [`CLIENT_HEADER_NAME`].
    pub name: &'static str,
    /// `GET /v1/proxy` `client_header`.
    pub value: Zeroizing<String>,
}

impl ClientHeader {
    /// The header with `value`.
    pub fn new(value: Zeroizing<String>) -> Self {
        ClientHeader {
            name: CLIENT_HEADER_NAME,
            value,
        }
    }
}

impl std::fmt::Debug for ClientHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHeader")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Whether connect writes the chat (proxy) route by default. True now that
/// the proxy streams (plan M8-2): Messages, Responses, Chat Completions, and
/// the Codex route are all served, `stream: true` included. Codex with a
/// ChatGPT login is still routed only on request (`--chatgpt`) until the
/// proxy's own verification.
///
/// The CLI (`inumaki connect apply`, where `--chat` and `--no-chat` override
/// it) reads this constant. The desktop app does not: there Chat is an
/// explicit opt-in per harness, off until the user turns it on (M9 Task 6).
pub const CHAT_ROUTE_DEFAULT: bool = true;

/// Resolved values an apply writes (spec §3.1); the caller got them from the daemon.
/// `Debug` prints which parts are present and counts only: never the data
/// directory, a URL, a token, or the client header's value.
pub struct ConnectPlan {
    /// `<data_dir>` for backups.
    pub data_dir: PathBuf,
    /// `http://<gateway listen>` from `GET /v1/status`; every gateway entry's
    /// URL must start with `<gateway_base>/mcp/`.
    pub gateway_base: String,
    /// Gateway entries.
    pub gateway: Option<GatewayPlan>,
    /// Files path.
    pub files: Option<FilesPlan>,
    /// Chat path.
    pub chat: Option<ChatPlan>,
    /// Hook.
    pub hook: Option<HookPlan>,
    /// The proxy client header, written wherever a Chat base URL is written
    /// (`None`: nothing is written for it).
    pub proxy_client_header: Option<ClientHeader>,
}

impl std::fmt::Debug for ConnectPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectPlan")
            .field(
                "gateway_entries",
                &self.gateway.as_ref().map(|g| g.entries.len()),
            )
            .field("files", &self.files.is_some())
            .field("chat", &self.chat.is_some())
            .field("hook", &self.hook.is_some())
            .field("proxy_client_header", &self.proxy_client_header)
            .finish_non_exhaustive()
    }
}

/// Gateway entries with the harness's token.
pub struct GatewayPlan {
    /// Bearer token (`app:<harness>`).
    pub token: Zeroizing<String>,
    /// Entries to write (replacing an entry of the same name and scope).
    pub entries: Vec<GatewayEntry>,
}

/// One gateway entry.
#[derive(Clone)]
pub struct GatewayEntry {
    /// Entry name (the protected server's name, or `inumaki-mail`, …).
    pub name: String,
    /// Scope.
    pub scope: Scope,
    /// `http://127.0.0.1:8789/mcp/<dataset>`.
    pub url: String,
    /// The user's own tool-approval setting of the inumaki entry this one
    /// rewrites (Codex `default_tools_approval_mode`, raw, read before the
    /// connect; the app reverts before it re-applies, so the plan carries
    /// it). Callers set it only from an entry that already points at the
    /// gateway, never from the user's own server entry of the same name.
    /// `None` takes the value of the file's entry with this name and this
    /// same gateway URL, if any. inumaki never invents one.
    pub approval_mode: Option<serde_json::Value>,
}

/// Files path values.
pub struct FilesPlan {
    /// `GET /v1/folders` `mirror_root`.
    pub mirror_root: PathBuf,
    /// Connected outboxes (`FolderStatus.outbox`).
    pub outboxes: Vec<PathBuf>,
}

/// Chat path values: proxy route base URLs (`GET /v1/proxy`).
pub struct ChatPlan {
    /// `/anthropic` route.
    pub anthropic: Option<String>,
    /// `/openai` route.
    pub openai: Option<String>,
    /// `/codex` route.
    pub codex: Option<String>,
    /// The user opted in to Codex ChatGPT-login chat, or the build verified it.
    pub codex_chatgpt: bool,
}

/// Hook values.
pub struct HookPlan {
    /// `<bin>/inumaki-hook`.
    pub command: PathBuf,
    /// The control socket the hook calls (`--socket`), so the hook and the
    /// app always talk to the same service.
    pub socket: PathBuf,
}

/// Lines the user adds to a harness's own files by hand, for a path inumaki
/// does not write itself (the manual-setup view, `inumaki connect status`).
/// The lines hold a home-directory path or a local URL, so a card never
/// carries them and there is no `Debug`. Neither the lines nor the note hold
/// a token or the client-header value.
#[derive(Clone, PartialEq, Eq)]
pub struct ManualSetup {
    /// What to add, one edit per line (the part to copy).
    pub lines: String,
    /// A fixed sentence to read next to the lines: what they do not do, or
    /// what adding them decides.
    pub note: &'static str,
}

/// What the caller knows from the control API (spec §4.1).
#[derive(Clone, Default)]
pub struct SystemState {
    /// The service answers.
    pub service_up: bool,
    /// `http://<gateway listen>`: an entry is a gateway entry only when its
    /// URL starts with `<gateway_base>/mcp/`.
    pub gateway_base: String,
    /// Dataset ids with at least one running upstream.
    pub datasets_running: BTreeSet<String>,
    /// Folders (`None` before M5).
    pub folders: Option<FolderInfo>,
    /// Proxy (`None` before M8).
    pub proxy: Option<ProxyInfo>,
    /// `<bin>/inumaki-hook` of the running inumaki (`GET /v1/service`
    /// `bin_dir`): a registered hook command that names another program is
    /// [`ReasonCode::HookOutdated`].
    pub hook_binary: Option<PathBuf>,
    /// The control socket (absolute) this inumaki answers on: a registered
    /// hook command whose `--socket` differs is [`ReasonCode::HookOutdated`].
    pub hook_socket: Option<PathBuf>,
    /// Server names the user chose to leave unprotected.
    pub leave_unprotected: BTreeSet<String>,
    /// The active backup of this harness, if connected.
    pub applied: Option<crate::backup::Backup>,
}

/// Folder facts.
#[derive(Clone)]
pub struct FolderInfo {
    /// Mirror root.
    pub mirror_root: PathBuf,
    /// Folder datasets in state `watching`.
    pub watching: u32,
    /// Their outboxes.
    pub outboxes: Vec<PathBuf>,
}

/// A proxy route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `/anthropic`.
    Anthropic,
    /// `/openai`.
    Openai,
    /// `/codex`.
    Codex,
}

/// One route's facts.
#[derive(Clone)]
pub struct RouteInfo {
    /// Route.
    pub route: Route,
    /// Base URL.
    pub base_url: String,
    /// State `failing`.
    pub failing: bool,
}

/// Proxy facts.
#[derive(Clone, Default)]
pub struct ProxyInfo {
    /// Routes.
    pub routes: Vec<RouteInfo>,
    /// Harnesses seen in `clients`.
    pub clients_seen: BTreeSet<HarnessId>,
    /// `oauth.codex_chatgpt.verified_in_build`.
    pub codex_chatgpt_verified: bool,
    /// `client_header`: the value a connected harness must send.
    pub client_header: Option<ClientHeader>,
}

impl ProxyInfo {
    /// The route's info.
    pub fn route(&self, r: Route) -> Option<&RouteInfo> {
        self.routes.iter().find(|x| x.route == r)
    }
}

/// What the app prepared for one end-to-end check run (M6 spec §8.2).
/// `Debug` prints counts only: the plan holds a bearer token and paths.
pub struct CheckPlan {
    /// Empty working directory.
    pub workdir: PathBuf,
    /// Temporary configuration directory.
    pub config_dir: PathBuf,
    /// The check's gateway URL.
    pub gateway_url: String,
    /// The check's temporary bearer token.
    pub gateway_token: Zeroizing<String>,
    /// MCP server name for the entry.
    pub server: String,
    /// The mirrored canary file, when the mirror path is available.
    pub mirror_file: Option<PathBuf>,
    /// The check's own temporary source directory, which the scripted `Bash`
    /// call reads (M6 spec §9.7 amendment 2026-10-10). Set only when it
    /// passes [`crate::check::source_dir_ok`]; the Claude Code run adds it
    /// with `--add-dir` only when the hook is connected.
    pub source_dir: Option<PathBuf>,
    /// Check routes: (upstream, base URL).
    pub routes: Vec<(String, String)>,
    /// The user's login-shell `PATH` (harnesses are often Node scripts).
    pub path_env: String,
    /// `<bin>/inumaki-hook` when the harness has the hook connected.
    pub hook_command: Option<PathBuf>,
    /// The control socket the hook calls (`--socket`): HOME is the temporary
    /// configuration directory during a check, so the hook cannot find the
    /// default socket by itself.
    pub socket: PathBuf,
}

impl std::fmt::Debug for CheckPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckPlan")
            .field("routes", &self.routes.len())
            .field("mirror", &self.mirror_file.is_some())
            .field("source_dir", &self.source_dir.is_some())
            .finish_non_exhaustive()
    }
}

/// One process to run. `Debug` (ruling F1, privacy) prints the program's
/// file name and counts only: arguments, environment, and file contents hold
/// paths, server names, and the bearer token.
pub struct Invocation {
    /// Absolute program path.
    pub program: PathBuf,
    /// Arguments.
    pub args: Vec<String>,
    /// The complete environment (the runner clears everything else).
    pub env: Vec<(String, String)>,
    /// Working directory.
    pub cwd: PathBuf,
    /// Files to write (0600) before the run, inside `config_dir`.
    pub files: Vec<(PathBuf, String)>,
    /// Kill after this long.
    pub timeout: std::time::Duration,
}

impl std::fmt::Debug for Invocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invocation")
            .field("program", &self.program.file_name())
            .field("args", &self.args.len())
            .field("env", &self.env.len())
            .field("files", &self.files.len())
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Why a file cannot be edited safely (spec §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The standard parser rejects the file.
    #[error("the file does not parse")]
    Syntax,
    /// The editor does not print the file back byte-identical.
    #[error("the file uses syntax the editor cannot keep")]
    RoundTrip,
    /// A key on the path holds a different type.
    #[error("a key holds an unexpected type")]
    TypeConflict,
    /// A flow-style YAML mapping on the path.
    #[error("flow-style YAML")]
    FlowStyle,
    /// A YAML anchor, alias, or merge key.
    #[error("YAML anchors or aliases")]
    Anchor,
    /// YAML editing is not available (Task 1 decision).
    #[error("YAML editing is not available")]
    YamlUnsupported,
    /// The edited file would differ in more than the owned keys.
    #[error("the edit would change more than inumaki's keys")]
    SemanticDiff,
    /// A value the format cannot hold (`null` in TOML).
    #[error("a value the format cannot hold")]
    Unrepresentable,
    /// The document is not an object or mapping.
    #[error("the file is not an object")]
    NotAnObject,
    /// An internal inconsistency.
    #[error("internal")]
    Internal,
}

/// Adapter errors. `Display` and `Debug` name the file role, never a path;
/// the snippet is available through [`AdapterError::snippet`] only.
#[derive(thiserror::Error)]
pub enum AdapterError {
    /// The file cannot be edited safely; the user adds `snippet` by hand.
    #[error("{role:?} cannot be edited safely: {reason}")]
    CannotEditSafely {
        /// File.
        role: FileRole,
        /// Why.
        reason: Refusal,
        /// What to add by hand (contains the gateway token).
        snippet: Zeroizing<String>,
    },
    /// The harness kept writing the file; nothing was written.
    #[error("{role:?} kept changing while inumaki edited it; nothing was written")]
    Changed {
        /// File.
        role: FileRole,
    },
    /// An I/O error.
    #[error("{role:?}: {kind:?}")]
    Io {
        /// File.
        role: FileRole,
        /// Kind.
        kind: std::io::ErrorKind,
    },
    /// The backup is missing or unreadable.
    #[error("the backup cannot be read")]
    Backup,
    /// The plan asks for something this harness cannot do.
    #[error("not supported: {0:?}")]
    Unsupported(ReasonCode),
    /// A plan's gateway entry does not point at `<gateway_base>/mcp/`.
    #[error("a gateway entry does not point at this inumaki gateway")]
    NotOurGateway,
}

impl std::fmt::Debug for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AdapterError({self})")
    }
}

impl AdapterError {
    /// `CannotEditSafely` for `role` with the snippet of `edits`.
    pub fn cannot(role: FileRole, reason: Refusal, edits: &[Edit]) -> Self {
        AdapterError::CannotEditSafely {
            role,
            reason,
            snippet: Zeroizing::new(crate::edit::snippet(edits)),
        }
    }

    /// The manual snippet, if any.
    pub fn snippet(&self) -> Option<&str> {
        match self {
            AdapterError::CannotEditSafely { snippet, .. } => Some(snippet.as_str()),
            _ => None,
        }
    }
}
