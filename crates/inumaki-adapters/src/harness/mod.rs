//! The adapter contract (spec §4.1) and helpers shared by the four adapters.
//! `owned`, `config_files`, and `plan_edits` are added to the spec's trait,
//! and `mcp_servers` takes the gateway base URL (Task 9 records the
//! deviations): the golden runner and the app need a harness's
//! file paths before detection, and the edits before writing them (the
//! Connect dialog shows exactly which keys change).

pub mod claude_code;
pub mod codex;
pub mod hermes;
pub mod openclaw;

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::backup::{Backup, BackupStore, RevertReport};
use crate::detect::ProbeEnv;
use crate::engine;
use crate::model::*;
use crate::node::Edit;

/// Every hook entry inumaki writes contains this; it is how a re-apply
/// finds and replaces its own earlier entry.
pub const HOOK_MARKER: &str = "inumaki-hook";

/// One harness (spec §4.1).
pub trait HarnessAdapter {
    /// Id.
    fn id(&self) -> HarnessId;
    /// The key-path patterns this adapter may edit, per file (`*` matches one
    /// segment); `engine::apply_files` refuses any other path.
    fn owned(&self) -> &'static [(FileRole, &'static [&'static str])];
    /// The configuration files, existing or not.
    fn config_files(&self, env: &ProbeEnv) -> Vec<ConfigFile>;
    /// The installation, if the binary or its configuration exists.
    fn detect(&self, env: &ProbeEnv) -> Option<Installation>;
    /// Its MCP servers (user and local scope).
    fn mcp_servers(
        &self,
        inst: &Installation,
        gateway_base: &str,
    ) -> Result<Vec<McpServerEntry>, AdapterError>;
    /// The edits `plan` makes, per file (shown before writing).
    fn plan_edits(
        &self,
        inst: &Installation,
        plan: &ConnectPlan,
    ) -> Result<Vec<(ConfigFile, Vec<Edit>)>, AdapterError>;
    /// The key whose write is the chat route (a `Set` of it in a backup:
    /// that apply routed chat through the proxy). One per harness: Claude
    /// Code's `env.ANTHROPIC_BASE_URL`, the `inumaki` provider entry of the
    /// others.
    fn chat_key(&self) -> (FileRole, &'static [&'static str]);
    /// Path states from the files and `sys`.
    fn status(&self, inst: &Installation, sys: &SystemState) -> HarnessStatus;
    /// Fixed warnings for applying `plan`: settings of the harness's own
    /// that make part of the plan ineffective (file reads only, nothing is
    /// written; an unreadable file gives none). Shared by the CLI and the
    /// app so both report the same closed set.
    fn connect_warnings(&self, _inst: &Installation, _plan: &ConnectPlan) -> Vec<ConnectWarning> {
        Vec::new()
    }
    /// Apply `plan` with a backup.
    fn apply(&self, inst: &Installation, plan: &ConnectPlan) -> Result<Backup, AdapterError> {
        if plan.gateway.as_ref().is_some_and(|g| {
            g.entries
                .iter()
                .any(|e| !is_gateway_url(&e.url, &plan.gateway_base))
        }) {
            return Err(AdapterError::NotOurGateway);
        }
        let edits = self.plan_edits(inst, plan)?;
        engine::apply_files(
            &BackupStore::new(&plan.data_dir),
            self.id(),
            self.owned(),
            edits,
        )
    }
    /// Revert `b`.
    fn revert(&self, _inst: &Installation, b: &Backup) -> Result<RevertReport, AdapterError> {
        engine::revert(&BackupStore::of_backup(b), b)
    }
    /// The user's own Revert, the last one for this connection (not a step
    /// of a Reconnect, a refresh, or a setting change, which revert and then
    /// apply again). The same as [`revert`](Self::revert), plus whatever a
    /// harness wrote itself because of what inumaki installed and the
    /// user would otherwise be left with: Codex's trust record for the
    /// hook, which a Reconnect keeps.
    fn revert_final(&self, inst: &Installation, b: &Backup) -> Result<RevertReport, AdapterError> {
        self.revert(inst, b)
    }
    /// The lines to add by hand for a path `status` reports as needing them
    /// (nothing is written for it), computed on demand from the same
    /// `status` and `sys`. `None` when no path of this harness needs any.
    fn manual_setup(&self, _status: &HarnessStatus, _sys: &SystemState) -> Option<ManualSetup> {
        None
    }
    /// The non-interactive command line for the end-to-end check (M6-3).
    fn check_invocation(&self, _inst: &Installation, _c: &CheckPlan) -> Option<Invocation> {
        None
    }
}

/// `edits` set `ad`'s chat key: applying them routes chat through the proxy.
pub fn edits_write_chat(ad: &dyn HarnessAdapter, edits: &[(ConfigFile, Vec<Edit>)]) -> bool {
    let (role, key) = ad.chat_key();
    edits
        .iter()
        .filter(|(f, _)| f.role == role)
        .flat_map(|(_, e)| e)
        .any(|e| matches!(e, Edit::Set { path, .. } if path.iter().map(String::as_str).eq(key.iter().copied())))
}

/// `b` holds a `Set` record of `ad`'s chat key: the apply that made it
/// wrote the chat route. Read from the backup, so the answer does not
/// depend on the proxy running now.
pub fn backup_has_chat_route(ad: &dyn HarnessAdapter, b: &Backup) -> bool {
    use crate::backup::EditRecord;
    let (role, key) = ad.chat_key();
    b.files
        .iter()
        .filter(|f| f.role == role)
        .flat_map(|f| &f.records)
        .any(|r| {
            matches!(r, EditRecord::Set { path, .. }
                if path.iter().map(String::as_str).eq(key.iter().copied()))
        })
}

/// [`ConnectWarning::chat_live`] when applying `plan` writes `ad`'s chat
/// route (the plan carries chat and the harness has a route for it);
/// nothing when the edits cannot be planned.
pub fn chat_live_warning(
    ad: &dyn HarnessAdapter,
    inst: &Installation,
    plan: &ConnectPlan,
) -> Option<ConnectWarning> {
    (plan.chat.is_some()
        && ad
            .plan_edits(inst, plan)
            .is_ok_and(|e| edits_write_chat(ad, &e)))
    .then(|| ConnectWarning::chat_live(ad.id()))
}

/// The adapter of `h`.
pub fn adapter(h: HarnessId) -> Box<dyn HarnessAdapter> {
    match h {
        HarnessId::ClaudeCode => Box::new(claude_code::ClaudeCode),
        HarnessId::Codex => Box::new(codex::Codex),
        HarnessId::Hermes => Box::new(hermes::Hermes),
        HarnessId::Openclaw => Box::new(openclaw::Openclaw),
    }
}

/// All four, in card order.
pub fn all_adapters() -> Vec<Box<dyn HarnessAdapter>> {
    HarnessId::ALL.into_iter().map(adapter).collect()
}

/// A key path.
pub fn p(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|k| (*k).to_string()).collect()
}

/// POSIX single-quoting (hook commands run through a shell; the bin
/// directory is under "Application Support" on macOS).
pub fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
}

/// `Bearer <token>`.
pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// `url` is an entry of this inumaki's gateway: it starts with
/// `<gateway_base>/mcp/` (review I6: any other loopback `/mcp/` server is
/// someone else's and stays unprotected).
pub fn is_gateway_url(url: &str, gateway_base: &str) -> bool {
    let base = gateway_base.trim_end_matches('/');
    !base.is_empty()
        && url
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with("/mcp/") && rest.len() > 5)
}

/// The dataset id of a gateway URL.
pub fn dataset_of_url(url: &str, gateway_base: &str) -> Option<String> {
    is_gateway_url(url, gateway_base)
        .then(|| url.rsplit('/').next().map(str::to_string))
        .flatten()
}

/// Key names of an MCP entry in one harness's format.
pub struct EntryKeys {
    /// URL key.
    pub url: &'static str,
    /// Environment table key.
    pub env: &'static str,
    /// Headers table key.
    pub headers: &'static str,
    /// The user-owned tool-approval key of an entry, if the harness has one.
    pub approval: Option<&'static str>,
}

/// User-owned sub-keys inside an owned key path: inumaki writes the whole
/// entry, but these keys are the user's decision. Drift ignores them,
/// revert removes them with the entry instead of counting a conflict, and a
/// connect carries them into the rewritten entry. The only one is Codex's
/// `default_tools_approval_mode` on `mcp_servers.<name>`
/// (docs/harness-adapters.md CX-MCP).
pub fn user_subkeys(role: FileRole, path: &[String]) -> &'static [&'static str] {
    match (role, path) {
        (FileRole::CodexConfig, [first, _]) if first == codex::MCP => &[codex::APPROVAL_KEY],
        _ => &[],
    }
}

/// An `McpServerEntry` from a parsed definition.
pub fn entry_from_json(
    name: &str,
    scope: Scope,
    def: &Value,
    keys: &EntryKeys,
    gateway_base: &str,
) -> McpServerEntry {
    let s = |k: &str| def.get(k).and_then(Value::as_str).map(str::to_string);
    let transport = match s(keys.url) {
        Some(url) => Transport::Http { url },
        None => Transport::Stdio {
            command: s("command").unwrap_or_default(),
            args: def
                .get("args")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            cwd: s("cwd"),
        },
    };
    let mut values = BTreeMap::new();
    let mut names = |table: &str, prefix: &str| -> Vec<String> {
        let mut out = Vec::new();
        if let Some(m) = def.get(table).and_then(Value::as_object) {
            for (k, v) in m {
                out.push(k.clone());
                if let Some(v) = v.as_str() {
                    values.insert(format!("{prefix}:{k}"), Zeroizing::new(v.to_string()));
                }
            }
        }
        out
    };
    let env_names = names(keys.env, "env");
    let header_names = names(keys.headers, "header");
    let gateway =
        matches!(&transport, Transport::Http { url } if is_gateway_url(url, gateway_base));
    let needs_oauth =
        def.get("auth").and_then(Value::as_str) == Some("oauth") || def.get("oauth").is_some();
    let approval_mode = keys.approval.and_then(|k| def.get(k).cloned());
    McpServerEntry {
        name: name.to_string(),
        scope,
        transport,
        env_names,
        header_names,
        values,
        gateway,
        needs_oauth,
        approval_mode,
    }
}
