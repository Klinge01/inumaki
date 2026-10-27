//! The app's view of a harness adapter (M6 spec §4.1), so the app and its
//! tests do not depend on the adapter crate's internals. `adapt.rs`
//! (Task 4b) implements it for `inumaki-adapters`; tests implement a fake.
//! Types that hold names, paths, or values have no `Debug`, or one that
//! prints counts only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use inumaki_client::HarnessId;
use serde::Serialize;
use zeroize::Zeroizing;

/// Login kind, from file and key presence only (spec §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Login {
    /// Subscription login.
    Oauth,
    /// API key.
    ApiKey,
    /// Not determined.
    Unknown,
}

/// A detected installation (no `Debug`: the binary path is under the home directory).
#[derive(Clone)]
pub struct InstallInfo {
    /// Absolute binary path, if found.
    pub binary: Option<PathBuf>,
    /// Version.
    pub version: Option<String>,
    /// Within the golden files' tested range.
    pub tested: bool,
    /// Login kind.
    pub login: Login,
    /// A configuration file exists.
    pub configured: bool,
}

/// Configuration scope of a server entry. The project directory of a
/// local-scope entry is opaque to the app: written back as read, never
/// printed, never stored in `state.json`.
#[derive(Clone, PartialEq, Eq)]
pub enum Scope {
    /// User scope.
    User,
    /// Local scope of one project directory.
    Local(String),
}

impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scope::User => "User",
            Scope::Local(_) => "Local(..)",
        })
    }
}

/// Transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Child process on stdio.
    Stdio,
    /// Streamable HTTP.
    Http,
}

/// One MCP server entry of a harness, with its values (for the Protect switch).
#[derive(Clone)]
pub struct ServerEntry {
    /// Entry name (model-visible).
    pub name: String,
    /// Scope.
    pub scope: Scope,
    /// Transport.
    pub transport: Transport,
    /// `stdio`: command as written.
    pub command: Option<String>,
    /// `stdio`: arguments.
    pub args: Vec<String>,
    /// `stdio`: working directory.
    pub cwd: Option<String>,
    /// `http`: URL.
    pub url: Option<String>,
    /// Environment, every value.
    pub env: Vec<(String, Zeroizing<String>)>,
    /// Headers, every value.
    pub headers: Vec<(String, Zeroizing<String>)>,
    /// Environment names whose configured value is not a string. They carry
    /// no value here, but the definition id covers them exactly as the CLI's
    /// does (one server, one id in the app and in `inumaki connect`).
    pub unvalued_env: Vec<String>,
    /// Header names whose configured value is not a string (see `unvalued_env`).
    pub unvalued_headers: Vec<String>,
    /// The dataset when the entry already points at the gateway.
    pub gateway_dataset: Option<String>,
    /// HTTP server that needs the MCP OAuth flow ("cannot protect yet").
    pub needs_oauth: bool,
    /// The user's own tool-approval setting on the entry (Codex
    /// `default_tools_approval_mode`, raw), carried into a rewritten
    /// inumaki entry.
    pub approval_mode: Option<serde_json::Value>,
}

impl std::fmt::Debug for ServerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerEntry")
            .field("scope", &self.scope)
            .field("transport", &self.transport)
            .field("env", &self.env.len())
            .field("headers", &self.headers.len())
            .field("protected", &self.gateway_dataset.is_some())
            .finish_non_exhaustive()
    }
}

/// A protection path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// MCP tools through the gateway.
    Mcp,
    /// Files through the mirror.
    Files,
    /// Chat through the proxy.
    Chat,
}

impl PathKind {
    /// `mcp`, `files`, `chat`.
    pub fn as_str(self) -> &'static str {
        match self {
            PathKind::Mcp => "mcp",
            PathKind::Files => "files",
            PathKind::Chat => "chat",
        }
    }
}

/// Spec §4.1 `PathState`, without payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathState {
    /// Grey.
    NotConnected,
    /// Yellow in Easy mode.
    Connected,
    /// Yellow, labeled "unverified".
    Unverified,
    /// Red by design, acknowledgeable.
    Unsupported,
    /// Red: drift, service down, failing route.
    Broken,
}

/// A closed reason code and its fixed English sentence (spec §4.1 `ReasonCode`).
/// Never a free string from an adapter: both fields are `'static`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Reason {
    /// `openclaw_subscription_bridge`, `route_failing`, …
    pub code: &'static str,
    /// The fixed sentence.
    pub text: &'static str,
}

/// The card state for a harness whose files macOS no longer lets the app read.
/// Ad-hoc signing means a file-access grant (TCC) can be lost on upgrade. No
/// adapter reports it yet: `cards` leaves `HarnessCard::grant` empty until a
/// later task detects it, and the UI (Task 8) renders it when set.
pub const GRANT_NEEDED: Reason = Reason {
    code: "grant_needed",
    text: "macOS may have withdrawn inumaki's access to this harness's files, for example after an update. Grant access again in System Settings, then refresh.",
};

/// Counts, never names (spec §4.1 `Detail`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Detail {
    /// "k of n servers protected".
    Protected {
        /// Protected.
        protected: u32,
        /// Total.
        total: u32,
    },
}

/// One path of a card.
#[derive(Debug, Clone, Serialize)]
pub struct PathInfo {
    /// Path.
    pub path: PathKind,
    /// State.
    pub state: PathState,
    /// Reason.
    pub reason: Option<Reason>,
    /// Counts.
    pub detail: Option<Detail>,
}

/// Lines to add to a harness's own files by hand, for a path inumaki does
/// not write (spec §6.4 manual setup). They hold a home-directory path or a
/// local URL, so they never ride on a card: the UI asks for them on demand.
/// No `Debug`; neither field holds a token or the client-header value.
#[derive(Clone, Serialize)]
pub struct ManualSetupView {
    /// What to add (the part to copy).
    pub lines: String,
    /// A fixed sentence to read next to the lines.
    pub note: &'static str,
}

/// The tool-result hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HookState {
    /// No hook for this harness in the MVP.
    NotApplicable,
    /// Not installed.
    NotInstalled,
    /// Installed and executable.
    Installed,
    /// Installed and executable, but the harness does not run it yet
    /// (Codex: not trusted in `/hooks`). The reason is a fixed code.
    Pending {
        /// Why.
        reason: Reason,
    },
    /// Missing, not executable, or naming another program or socket than
    /// this inumaki uses; the reason is a fixed code (`hook_binary_missing`,
    /// `hook_outdated`).
    Broken {
        /// Why.
        reason: Reason,
    },
}

/// A harness's status.
#[derive(Debug, Clone)]
pub struct CardStatus {
    /// MCP, Files, Chat, in that order.
    pub paths: Vec<PathInfo>,
    /// Hook.
    pub hook: HookState,
    /// Owned keys changed outside inumaki.
    pub drift: usize,
    /// A configuration file of this harness exists but the app may not
    /// read it (permission denied: a macOS file-access grant lost after an
    /// update, or a file mode). The card shows `GRANT_NEEDED`.
    pub grant: bool,
}

/// What the adapters need to know about the daemon (spec §4.1 `SystemState`).
/// No `Debug`: it holds server names.
#[derive(Clone, Default)]
pub struct SystemView {
    /// Gateway listen address.
    pub gateway_listen: Option<String>,
    /// Dataset ids with running upstreams.
    pub running_datasets: BTreeSet<String>,
    /// Dataset ids that exist.
    pub datasets: BTreeSet<String>,
    /// Mirror root (`GET /v1/folders`).
    pub mirror_root: Option<PathBuf>,
    /// Folders in state `watching`.
    pub folders_watching: usize,
    /// Outbox directories.
    pub outboxes: Vec<PathBuf>,
    /// Proxy base URLs.
    pub proxy: ProxyUrls,
    /// Proxy route names currently `failing` (`anthropic`, `openai`, `codex`).
    pub failing_routes: BTreeSet<String>,
    /// Harness ids the proxy has seen (`claude-code`, `codex`, …).
    pub proxy_clients: BTreeSet<String>,
    /// M8 verified the Codex ChatGPT-login path in this build.
    pub codex_chatgpt_verified: bool,
    /// The service answers.
    pub service_up: bool,
    /// `<bin>/inumaki-hook`.
    pub hook_command: Option<PathBuf>,
    /// Harness id → names of its servers the user left unprotected.
    pub leave_unprotected: BTreeMap<String, BTreeSet<String>>,
    /// `GET /v1/proxy` `client_header` value: what a connected harness
    /// must send (a per-install secret, as sensitive as a gateway token).
    pub client_header: Option<Zeroizing<String>>,
}

/// Proxy route base URLs from `GET /v1/proxy`. `Debug` prints which routes exist only.
#[derive(Clone, Default)]
pub struct ProxyUrls {
    /// `/anthropic`.
    pub anthropic: Option<String>,
    /// `/openai`.
    pub openai: Option<String>,
    /// `/codex`.
    pub codex: Option<String>,
}

impl std::fmt::Debug for ProxyUrls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyUrls")
            .field("anthropic", &self.anthropic.is_some())
            .field("openai", &self.openai.is_some())
            .field("codex", &self.codex.is_some())
            .finish()
    }
}

/// One gateway entry to write.
pub struct GatewayEntry {
    /// Entry name: the original server name, or `inumaki-mail`, `inumaki-mail-2`, …
    pub name: String,
    /// Scope (the protected entry's own; data sources: user scope).
    pub scope: Scope,
    /// `http://<gateway>/mcp/<dataset>`.
    pub url: String,
    /// This harness's bearer token.
    pub token: Zeroizing<String>,
    /// The user's tool-approval setting of the entry this one rewrites, read
    /// before Reconnect reverts the file (Codex `default_tools_approval_mode`,
    /// raw). Only from an entry that already points at the gateway; `None`
    /// for a new entry or a server being protected. Never set by the app on
    /// its own.
    pub approval_mode: Option<serde_json::Value>,
}

/// What Connect writes (spec §4.1 `ConnectPlan`).
pub struct ConnectRequest {
    /// `http://<gateway listen>`; every entry's URL starts with `<gateway_base>/mcp/`.
    pub gateway_base: String,
    /// Gateway entries.
    pub gateway: Vec<GatewayEntry>,
    /// Mirror root, known before any folder exists.
    pub mirror_root: Option<PathBuf>,
    /// Connected outboxes (Codex `writable_roots`).
    pub outboxes: Vec<PathBuf>,
    /// Proxy base URLs.
    pub proxy: ProxyUrls,
    /// Hook command (Claude Code, Codex).
    pub hook_command: Option<PathBuf>,
    /// This harness's chat route is wanted: the effective value of its
    /// `Prefs::chat_opt_in` entry. Without it Connect writes no chat route
    /// and no client header (Claude Code's `ANTHROPIC_BASE_URL`, the
    /// `inumaki` provider of the others). For Codex it is also the
    /// ChatGPT-login opt-in: one switch, whichever login.
    pub chat: bool,
    /// `GET /v1/proxy` `client_header` value, written wherever a Chat base
    /// URL is written (M6-1 spec §4.3 amendment 2026-09-29); `None` writes
    /// no header line.
    pub client_header: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for ConnectRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectRequest")
            .field("gateway", &self.gateway.len())
            .field("outboxes", &self.outboxes.len())
            .finish_non_exhaustive()
    }
}

/// One file and the owned keys an apply changes (shown to the local user
/// before writing, spec §6.3). `Debug` prints the key count only: the path
/// is under the home directory and a key can contain a server name.
#[derive(Clone, Serialize)]
pub struct FileChange {
    /// The file.
    pub path: PathBuf,
    /// Key paths.
    pub keys: Vec<String>,
}

impl std::fmt::Debug for FileChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileChange")
            .field("keys", &self.keys.len())
            .finish_non_exhaustive()
    }
}

/// Result of a revert.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RevertSummary {
    /// A backup was restored (false: nothing to revert; tokens were still
    /// revoked, or their revocation recorded, see `revocation_pending`).
    pub reverted: bool,
    /// Restored byte for byte.
    pub exact: bool,
    /// Owned keys someone else changed since apply, left alone.
    pub conflicts: usize,
    /// inumaki's proxy client header line could not be removed: the secret
    /// is still in the harness file and goes to the provider. The UI warns
    /// and tells the user to remove it by hand.
    pub client_header_left: bool,
    /// Codex: the trust record for inumaki's hook could not be removed from
    /// `config.toml` (only the final revert tries). The revert stands; the
    /// UI tells the user to remove the record in Codex's `/hooks`.
    pub codex_trust_left: bool,
    /// The service was not running, so the harness's gateway tokens could
    /// not be revoked: a pending-revocation record names them, and the
    /// service revokes them before it serves anything at its next start, or
    /// within a sweep if it is running after all (offline Revert spec D1).
    /// Set only by the app's Revert; every adapter answers `false`.
    pub revocation_pending: bool,
}

/// One adapter backup (Settings, spec §6.4). `Debug` prints nothing of
/// the id: it names a directory under the user's data directory.
#[derive(Clone, Serialize)]
pub struct BackupInfo {
    /// Opaque id (`<unix-seconds:012>-<nanos:09>`, M6-1).
    pub id: String,
    /// Unix seconds, from the id's prefix; `None` when it cannot be read
    /// (shown as "unknown").
    pub created_at: Option<i64>,
}

impl BackupInfo {
    /// The info of backup `id`; the time is its prefix, `None` when the
    /// prefix is not a positive number of seconds (`0` is "unknown").
    pub fn from_id(id: String) -> BackupInfo {
        let created_at = id
            .split('-')
            .next()
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|t| *t > 0);
        BackupInfo { id, created_at }
    }
}

impl std::fmt::Debug for BackupInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupInfo")
            .field("dated", &self.created_at.is_some())
            .finish_non_exhaustive()
    }
}

/// Adapter failure.
pub enum OpError {
    /// The file cannot be edited safely; add this snippet by hand (it
    /// carries the harness's token: shown locally, never logged).
    CannotEditSafely {
        /// The snippet (wiped when dropped).
        snippet: Zeroizing<String>,
    },
    /// The harness is not installed.
    NotInstalled,
    /// The request asks for something this harness cannot do; the fixed reason says why.
    Unsupported(Reason),
    /// Anything else, by class.
    Failed(&'static str),
}

impl std::fmt::Debug for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpError::CannotEditSafely { snippet } => {
                write!(f, "CannotEditSafely({} bytes)", snippet.len())
            }
            OpError::NotInstalled => f.write_str("NotInstalled"),
            OpError::Unsupported(r) => write!(f, "Unsupported({})", r.code),
            OpError::Failed(k) => write!(f, "Failed({k})"),
        }
    }
}

impl From<OpError> for crate::error::CmdError {
    fn from(e: OpError) -> Self {
        match e {
            // Moved out, not copied: the one copy goes to the local UI.
            OpError::CannotEditSafely { mut snippet } => crate::error::CmdError {
                snippet: Some(std::mem::take(&mut *snippet)),
                ..crate::error::CmdError::new("cannot_edit_safely")
            },
            OpError::NotInstalled => crate::error::CmdError::new("harness_not_installed"),
            OpError::Unsupported(r) => crate::error::CmdError {
                reason: Some(r),
                ..crate::error::CmdError::new("not_supported")
            },
            OpError::Failed(k) => crate::error::CmdError::new(k),
        }
    }
}

/// One harness, as the app uses it.
pub trait HarnessOps: Send + Sync {
    /// Id.
    fn id(&self) -> HarnessId;
    /// Display name ("Claude Code").
    fn name(&self) -> &'static str;
    /// Detect again (binary, version, login kind). Spawns processes: call at
    /// start, on Refresh, before Connect, and when the window is shown —
    /// never on the poll tick.
    fn refresh(&self);
    /// The cached detection; `None` when neither a binary nor a configuration exists.
    fn install(&self) -> Option<InstallInfo>;
    /// The adapter's active backup (a Connect made by the app or by `inumaki connect`).
    fn active_backup(&self) -> Option<String>;
    /// The active backup holds a `Set` record of this harness's chat key
    /// (Claude Code's `env.ANTHROPIC_BASE_URL`, the `inumaki` provider entry
    /// of the others): the last Connect wrote the chat route. Read from the
    /// backup, so the answer does not depend on the proxy running. `false`
    /// without a backup. File reads only.
    fn chat_route_in_backup(&self) -> bool {
        false
    }
    /// A backup of this harness exists whose manifest does not load. With no
    /// active backup this is not "nothing to revert": the files may still
    /// hold inumaki's entries, so Revert fails instead of reporting success.
    fn backup_unreadable(&self) -> bool {
        false
    }
    /// User- and local-scope MCP server entries; `gateway_base` is
    /// `http://<gateway listen>`, how gateway entries are recognized.
    fn servers(&self, gateway_base: &str) -> Result<Vec<ServerEntry>, OpError>;
    /// Path states from the files and `sys` (file reads only).
    fn status(&self, sys: &SystemView) -> CardStatus;
    /// The lines to add by hand for a path that needs them (Hermes with a
    /// subscription login, OpenClaw's Docker bind outside the workspace
    /// roots); `None` when no path of this harness does. File reads only.
    fn manual_setup(&self, _sys: &SystemView) -> Option<ManualSetupView> {
        None
    }
    /// The files and owned keys `apply(req)` would change; refusals happen here, before any write.
    fn preview(&self, req: &ConnectRequest) -> Result<Vec<FileChange>, OpError>;
    /// Fixed warnings for applying `req`: settings of the harness's own that
    /// make part of it ineffective (Codex: `approval_policy = "never"`
    /// refuses the gateway's tool calls). File reads only; an unreadable
    /// file gives none. Codes and sentences come from the adapter's closed
    /// set (`inumaki_adapters::ConnectWarning`), never from the file.
    fn connect_warnings(&self, _req: &ConnectRequest) -> Vec<Reason> {
        Vec::new()
    }
    /// Write `req` with a backup; returns the backup id.
    fn apply(&self, req: &ConnectRequest) -> Result<String, OpError>;
    /// Revert the apply that made `backup`.
    fn revert(&self, backup: &str) -> Result<RevertSummary, OpError>;
    /// The user's own Revert, which is not followed by an apply: [`revert`](Self::revert)
    /// plus what a harness keeps for the connection (Codex's trust record for
    /// the hook, which a Reconnect, a refresh, and the setters keep).
    fn revert_final(&self, backup: &str) -> Result<RevertSummary, OpError> {
        self.revert(backup)
    }
    /// Every backup of this harness the app can revert or delete, oldest
    /// first (reads the backup directory: call from a blocking thread).
    fn backups(&self) -> Vec<BackupInfo>;
    /// Delete one backup. The caller refuses the live one; an id that is
    /// not a backup id (it names a directory) is refused here.
    fn delete_backup(&self, backup: &str) -> Result<(), OpError>;
    /// The end-to-end check's non-interactive run (M6-3 Task 8a fills M6-1's types).
    fn check_invocation(
        &self,
        _plan: &inumaki_adapters::CheckPlan,
    ) -> Option<inumaki_adapters::Invocation> {
        None
    }
}
