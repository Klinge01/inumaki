//! `HarnessOps` for the adapters of `inumaki-adapters` (M6-1), and the
//! Protect switch's pure helpers from its `protect` module. This is the one
//! file that names adapter-crate types; when M6-1's API changes, only this
//! file changes. Detection (which runs `--version` and may ask the login
//! shell) is cached per harness and repeated only by `refresh`; `status`
//! and everything else read files only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use inumaki_adapters as ad;
use inumaki_client::{HarnessId, RoutePrefix, UpstreamCreate};
use zeroize::Zeroizing;

use super::ops::*;
use super::reason::reason;
use crate::error::CmdError;
use crate::paths::AppPaths;

enum Probe {
    /// The user's environment (`ProbeEnv::from_process`).
    Process,
    /// A test home (`ProbeEnv::for_tests`: runs no binaries).
    Home(PathBuf),
}

/// One harness. The adapter is built per call (`ad::adapter(h)` boxes a
/// unit struct), so this type is `Send + Sync`.
struct AdapterOps {
    h: ad::HarnessId,
    probe: Probe,
    data_dir: PathBuf,
    /// The control socket the hook calls and status compares against.
    socket: PathBuf,
    /// `<bin>/inumaki-hook` of this app.
    hook_binary: PathBuf,
    inst: RwLock<Option<ad::Installation>>,
}

fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

fn wrap(paths: &AppPaths, probe: impl Fn() -> Probe) -> Vec<Arc<dyn HarnessOps>> {
    ad::HarnessId::ALL
        .into_iter()
        .map(|h| {
            Arc::new(AdapterOps {
                h,
                probe: probe(),
                data_dir: absolute(&paths.data_dir),
                socket: absolute(&paths.socket),
                hook_binary: absolute(&paths.bin_dir.join("inumaki-hook")),
                inst: RwLock::new(None),
            }) as Arc<dyn HarnessOps>
        })
        .collect()
}

/// Every adapter M6-1 ships, probing the real environment.
pub fn all(paths: &AppPaths) -> Vec<Arc<dyn HarnessOps>> {
    wrap(paths, || Probe::Process)
}

/// Every adapter over a test home (`ProbeEnv::for_tests`: runs no binaries).
pub fn for_tests(paths: &AppPaths, home: &Path) -> Vec<Arc<dyn HarnessOps>> {
    wrap(paths, || Probe::Home(home.to_path_buf()))
}

fn client_id(h: ad::HarnessId) -> HarnessId {
    match h {
        ad::HarnessId::ClaudeCode => HarnessId::ClaudeCode,
        ad::HarnessId::Codex => HarnessId::Codex,
        ad::HarnessId::Hermes => HarnessId::Hermes,
        ad::HarnessId::Openclaw => HarnessId::Openclaw,
    }
}

/// The client's route prefix of an adapter route, so the failing-route
/// names come from one table (`harness::route_name`).
fn prefix(r: ad::Route) -> RoutePrefix {
    match r {
        ad::Route::Anthropic => RoutePrefix::Anthropic,
        ad::Route::Openai => RoutePrefix::Openai,
        ad::Route::Codex => RoutePrefix::Codex,
    }
}

fn path_info(p: ad::ProtectionPath, s: &ad::PathState) -> PathInfo {
    let path = match p {
        ad::ProtectionPath::Mcp => PathKind::Mcp,
        ad::ProtectionPath::Files => PathKind::Files,
        ad::ProtectionPath::Chat => PathKind::Chat,
    };
    let (state, r, detail) = match *s {
        ad::PathState::NotConnected { reason: r } => (PathState::NotConnected, r, None),
        ad::PathState::Connected { detail } => (
            PathState::Connected,
            detail.note,
            (detail.total > 0).then_some(Detail::Protected {
                protected: detail.protected,
                total: detail.total,
            }),
        ),
        ad::PathState::Unverified { reason: r } => (PathState::Unverified, Some(r), None),
        ad::PathState::Unsupported { reason: r } => (PathState::Unsupported, Some(r), None),
        ad::PathState::Broken { reason: r } => (PathState::Broken, Some(r), None),
    };
    PathInfo {
        path,
        state,
        reason: r.map(reason),
        detail,
    }
}

fn hook_state(h: ad::HookState) -> HookState {
    match h {
        ad::HookState::NotInstalled => HookState::NotInstalled,
        ad::HookState::Installed => HookState::Installed,
        ad::HookState::Pending { reason: r } => HookState::Pending { reason: reason(r) },
        ad::HookState::NotSupported { .. } => HookState::NotApplicable,
        ad::HookState::Broken { reason: r } => HookState::Broken { reason: reason(r) },
    }
}

/// An adapter error by class; the snippet (it carries the token) only in
/// `CannotEditSafely`. Exhaustive: a new adapter error does not compile
/// until it has a class here.
fn op_error(e: ad::AdapterError) -> OpError {
    match e {
        ad::AdapterError::CannotEditSafely { snippet, .. } => OpError::CannotEditSafely { snippet },
        ad::AdapterError::Changed { .. } => OpError::Failed("changed_meanwhile"),
        ad::AdapterError::Io { .. } => OpError::Failed("file_unwritable"),
        ad::AdapterError::Backup => OpError::Failed("backup_unreadable"),
        ad::AdapterError::Unsupported(r) => OpError::Unsupported(reason(r)),
        ad::AdapterError::NotOurGateway => OpError::Failed("not_our_gateway"),
    }
}

fn scope_in(s: ad::Scope) -> Scope {
    match s {
        ad::Scope::User => Scope::User,
        ad::Scope::Project(dir) => Scope::Local(dir),
    }
}

fn scope_out(s: &Scope) -> ad::Scope {
    match s {
        Scope::User => ad::Scope::User,
        Scope::Local(dir) => ad::Scope::Project(dir.clone()),
    }
}

/// The app's entry for an adapter entry. A name whose value is not a string
/// has no value in the adapter entry (`values`); it is kept as an unvalued
/// name so [`entry`] gives back the same name lists (and so the same
/// definition id) the CLI sees.
fn server(e: ad::McpServerEntry, gateway_base: &str) -> ServerEntry {
    let pick = |table: &str, names: &[String]| -> Vec<(String, Zeroizing<String>)> {
        names
            .iter()
            .filter_map(|n| {
                e.values
                    .get(&format!("{table}:{n}"))
                    .map(|v| (n.clone(), v.clone()))
            })
            .collect()
    };
    let (transport, command, args, cwd, url) = match &e.transport {
        ad::Transport::Stdio { command, args, cwd } => (
            Transport::Stdio,
            Some(command.clone()),
            args.clone(),
            cwd.clone(),
            None,
        ),
        ad::Transport::Http { url } => (Transport::Http, None, Vec::new(), None, Some(url.clone())),
    };
    let gateway_dataset = if e.gateway {
        url.as_deref()
            .and_then(|u| ad::harness::dataset_of_url(u, gateway_base))
    } else {
        None
    };
    let unvalued = |table: &str, names: &[String]| -> Vec<String> {
        names
            .iter()
            .filter(|n| !e.values.contains_key(&format!("{table}:{n}")))
            .cloned()
            .collect()
    };
    ServerEntry {
        env: pick("env", &e.env_names),
        headers: pick("header", &e.header_names),
        unvalued_env: unvalued("env", &e.env_names),
        unvalued_headers: unvalued("header", &e.header_names),
        name: e.name,
        scope: scope_in(e.scope),
        transport,
        command,
        args,
        cwd,
        url,
        gateway_dataset,
        needs_oauth: e.needs_oauth,
        approval_mode: e.approval_mode,
    }
}

/// The adapter-crate entry for an app entry (for the `protect` helpers).
fn entry(e: &ServerEntry) -> ad::McpServerEntry {
    let mut values = BTreeMap::new();
    for (k, v) in &e.env {
        values.insert(format!("env:{k}"), v.clone());
    }
    for (k, v) in &e.headers {
        values.insert(format!("header:{k}"), v.clone());
    }
    ad::McpServerEntry {
        name: e.name.clone(),
        scope: scope_out(&e.scope),
        transport: match e.transport {
            Transport::Stdio => ad::Transport::Stdio {
                command: e.command.clone().unwrap_or_default(),
                args: e.args.clone(),
                cwd: e.cwd.clone(),
            },
            Transport::Http => ad::Transport::Http {
                url: e.url.clone().unwrap_or_default(),
            },
        },
        env_names: e
            .env
            .iter()
            .map(|(k, _)| k.clone())
            .chain(e.unvalued_env.iter().cloned())
            .collect(),
        header_names: e
            .headers
            .iter()
            .map(|(k, _)| k.clone())
            .chain(e.unvalued_headers.iter().cloned())
            .collect(),
        values,
        gateway: e.gateway_dataset.is_some(),
        needs_oauth: e.needs_oauth,
        approval_mode: e.approval_mode.clone(),
    }
}

fn index(data_dir: &Path) -> Result<ad::protect::DefinitionIndex, CmdError> {
    ad::protect::DefinitionIndex::load(data_dir).map_err(|_| CmdError::new("state_unwritable"))
}

/// Keyed definition identity (spec §4.5 step 3), shared with `inumaki connect`
/// (M6-1's `DefinitionIndex` key in `<data_dir>/adapters/definition.key`).
pub fn definition_id(data_dir: &Path, e: &ServerEntry) -> Result<String, CmdError> {
    Ok(index(data_dir)?.id_for(&entry(e)))
}

/// Every dataset id the definition index records (the wrapped servers the
/// app and `inumaki connect --protect` created). The index API has no
/// listing, so the file is read after `DefinitionIndex::load` validated it.
pub fn defined_datasets(data_dir: &Path) -> Result<BTreeSet<String>, CmdError> {
    index(data_dir)?;
    let fail = || CmdError::new("state_unwritable");
    match std::fs::read(data_dir.join("adapters").join("definitions.json")) {
        Ok(b) => serde_json::from_slice::<BTreeMap<String, String>>(&b)
            .map(|m| m.into_values().collect())
            .map_err(|_| fail()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(_) => Err(fail()),
    }
}

/// The dataset recorded for a definition.
pub fn definition_dataset(data_dir: &Path, def: &str) -> Result<Option<String>, CmdError> {
    Ok(index(data_dir)?.get(def).map(str::to_string))
}

/// Record a definition's dataset in `<data_dir>/adapters/definitions.json`.
pub fn record_definition(data_dir: &Path, def: String, dataset: String) -> Result<(), CmdError> {
    let mut i = index(data_dir)?;
    i.insert(def, dataset);
    i.save().map_err(|_| CmdError::new("state_unwritable"))
}

/// The upstream to create for `e` (credential split, command resolved with
/// the login-shell `PATH`, `PATH` recorded; spec §4.5 steps 1–2).
pub fn upstream_create(e: &ServerEntry, login_path: Option<&str>) -> UpstreamCreate {
    let parts = ad::protect::split(&entry(e), login_path);
    let name = ad::protect::upstream_name(&e.name);
    let mut u = if parts.kind == "http" {
        UpstreamCreate::http(name, parts.url.clone().unwrap_or_default())
    } else {
        UpstreamCreate::stdio(name, parts.command.clone().unwrap_or_default())
    };
    u.args = parts.args.clone();
    u.cwd = parts.cwd.clone();
    u.env = parts.env.clone();
    u.headers = parts.headers.clone();
    for (k, v) in &parts.secret_env {
        u.secret_env.insert(k.clone(), v.as_str());
    }
    for (k, v) in &parts.secret_headers {
        u.secret_headers.insert(k.clone(), v.as_str());
    }
    u
}

/// `mcp-…` dataset id (spec §4.5 step 3).
pub fn dataset_id(server: &str, taken: &BTreeSet<String>) -> String {
    ad::protect::dataset_id_for(server, taken)
}

/// Upstream name for a server name (`[a-z0-9_-]{1,64}`).
pub fn upstream_name(server: &str) -> String {
    ad::protect::upstream_name(server)
}

/// `inumaki-mail`, `inumaki-mail-2`, … skipping names in `taken`.
pub fn mail_entry_name(index: usize, taken: &BTreeSet<String>) -> String {
    ad::protect::mail_entry_name(index, taken)
}

/// The credential rule shared with the CLI.
pub fn credential_like(name: &str) -> bool {
    ad::protect::credential_like(name)
}

/// A backup id as M6-1 makes them (`{secs:012}-{nanos:09}`): the id names a
/// directory under the backup store, so nothing else (`..`, `/`) is accepted.
fn backup_id_ok(id: &str) -> bool {
    id.split_once('-').is_some_and(|(s, n)| {
        s.len() == 12
            && n.len() == 9
            && s.bytes().all(|b| b.is_ascii_digit())
            && n.bytes().all(|b| b.is_ascii_digit())
    })
}

/// `e` is macOS withholding a file-access grant: `EPERM` (1), which TCC
/// returns. `EACCES` (a file mode or owner, e.g. a root-owned file after
/// `sudo`) is not: System Settings cannot fix it, so no grant card.
pub fn grant_needed(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(1)
}

fn denied(p: &Path) -> bool {
    std::fs::File::open(p).is_err_and(|e| grant_needed(&e))
}

impl AdapterOps {
    /// The probe environment. `with_login_path` fills the login-shell PATH,
    /// which may start the login shell the first time: only detection
    /// (`refresh`) asks for it, so a revert spawns nothing.
    fn env(&self, with_login_path: bool) -> Option<ad::ProbeEnv> {
        match &self.probe {
            // The login-shell PATH lets `codex --version` find `node` when the
            // app was started from Finder. Only a successful ask is cached; a
            // failed one is repeated per harness, bounded by the 3 s limit.
            // Detection already starts the login shell, so this adds no new
            // blocking.
            Probe::Process => ad::ProbeEnv::from_process().map(|mut e| {
                if with_login_path {
                    e.login_path = crate::harness::shell::login_path();
                }
                e
            }),
            Probe::Home(h) => Some(ad::ProbeEnv::for_tests(h)),
        }
    }

    /// The cached installation; `NotInstalled` until `refresh` found one
    /// (never detects here, so the poll tick spawns no process).
    fn inst(&self) -> Result<ad::Installation, OpError> {
        self.inst
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(OpError::NotInstalled)
    }

    /// For a revert: the cached installation, else one built from the
    /// adapter's file locations (no process spawn). A harness uninstalled
    /// since Connect can still be reverted; the adapters' revert works from
    /// the backup's own records.
    fn inst_for_revert(&self) -> Result<ad::Installation, OpError> {
        if let Ok(i) = self.inst() {
            return Ok(i);
        }
        let env = self.env(false).ok_or(OpError::NotInstalled)?;
        Ok(ad::Installation {
            harness: self.h,
            binary: None,
            version: None,
            tested: false,
            config_files: ad::adapter(self.h).config_files(&env),
            login: ad::LoginKind::Unknown,
        })
    }

    fn store(&self) -> ad::BackupStore {
        ad::BackupStore::new(&self.data_dir)
    }

    fn system_state(&self, sys: &SystemView) -> ad::SystemState {
        let route = |r: ad::Route, url: &Option<String>| {
            url.as_ref().map(|u| ad::RouteInfo {
                route: r,
                base_url: u.clone(),
                failing: sys.failing_routes.contains(super::route_name(prefix(r))),
            })
        };
        let any_route = sys.proxy.anthropic.is_some()
            || sys.proxy.openai.is_some()
            || sys.proxy.codex.is_some();
        ad::SystemState {
            service_up: sys.service_up,
            gateway_base: sys
                .gateway_listen
                .as_ref()
                .map(|l| format!("http://{l}"))
                .unwrap_or_default(),
            datasets_running: sys.running_datasets.clone(),
            folders: sys.mirror_root.as_ref().map(|m| ad::FolderInfo {
                mirror_root: m.clone(),
                watching: u32::try_from(sys.folders_watching).unwrap_or(u32::MAX),
                outboxes: sys.outboxes.clone(),
            }),
            proxy: any_route.then(|| ad::ProxyInfo {
                routes: [
                    route(ad::Route::Anthropic, &sys.proxy.anthropic),
                    route(ad::Route::Openai, &sys.proxy.openai),
                    route(ad::Route::Codex, &sys.proxy.codex),
                ]
                .into_iter()
                .flatten()
                .collect(),
                clients_seen: sys
                    .proxy_clients
                    .iter()
                    .filter_map(|c| ad::HarnessId::parse(c))
                    .collect(),
                codex_chatgpt_verified: sys.codex_chatgpt_verified,
                client_header: sys.client_header.clone().map(ad::ClientHeader::new),
            }),
            // Always filled (M6-1 consumer item): a registered hook that
            // names another program or socket is `hook_outdated`.
            hook_binary: Some(
                sys.hook_command
                    .clone()
                    .unwrap_or_else(|| self.hook_binary.clone()),
            ),
            hook_socket: Some(self.socket.clone()),
            leave_unprotected: sys
                .leave_unprotected
                .get(self.h.as_str())
                .cloned()
                .unwrap_or_default(),
            applied: self.store().active(self.h),
        }
    }

    /// The adapter plan for `req`. Every gateway entry of one harness
    /// carries the same token (`app:<harness>`); entries with different
    /// tokens are a caller error and write nothing.
    fn plan(&self, req: &ConnectRequest) -> Result<ad::ConnectPlan, OpError> {
        let gateway = match req.gateway.first() {
            None => None,
            Some(first) => {
                if req.gateway.iter().any(|g| g.token != first.token) {
                    return Err(OpError::Failed("adapter_failed"));
                }
                Some(ad::GatewayPlan {
                    token: first.token.clone(),
                    entries: req
                        .gateway
                        .iter()
                        .map(|g| ad::GatewayEntry {
                            name: g.name.clone(),
                            scope: scope_out(&g.scope),
                            url: g.url.clone(),
                            approval_mode: g.approval_mode.clone(),
                        })
                        .collect(),
                })
            }
        };
        let p = &req.proxy;
        // Chat is an explicit opt-in for every harness in the app (M9
        // Task 6): the CLI's default (`CHAT_ROUTE_DEFAULT`) does not apply.
        // For Codex the switch is also the ChatGPT-login opt-in.
        let any_route =
            req.chat && (p.anthropic.is_some() || p.openai.is_some() || p.codex.is_some());
        let chat = any_route.then(|| ad::ChatPlan {
            anthropic: p.anthropic.clone(),
            openai: p.openai.clone(),
            codex: p.codex.clone(),
            codex_chatgpt: true,
        });
        Ok(ad::ConnectPlan {
            data_dir: self.data_dir.clone(),
            gateway_base: req.gateway_base.clone(),
            gateway,
            files: req.mirror_root.clone().map(|m| ad::FilesPlan {
                mirror_root: m,
                outboxes: req.outboxes.clone(),
            }),
            proxy_client_header: req
                .client_header
                .clone()
                // Written only where a chat route is (as the CLI does):
                // nothing carries the header while this harness's chat is None.
                .filter(|h| chat.is_some() && !h.is_empty())
                .map(ad::ClientHeader::new),
            chat,
            hook: req.hook_command.clone().map(|c| ad::HookPlan {
                command: c,
                socket: self.socket.clone(),
            }),
        })
    }

    /// Revert `backup`; `final_`: the user's own Revert (the adapter's
    /// `revert_final`), else a step of Reconnect, a refresh, or a setter.
    fn revert_with(&self, backup: &str, final_: bool) -> Result<RevertSummary, OpError> {
        if !backup_id_ok(backup) {
            return Err(OpError::Failed("backup_unreadable"));
        }
        let i = self.inst_for_revert()?;
        let b = self.store().load(self.h, backup).map_err(op_error)?;
        let ad = ad::adapter(self.h);
        let r = if final_ {
            ad.revert_final(&i, &b)
        } else {
            ad.revert(&i, &b)
        }
        .map_err(op_error)?;
        Ok(RevertSummary {
            reverted: true,
            exact: r.key_level.is_empty(),
            conflicts: r.conflicts.len(),
            client_header_left: r.client_header_left,
            codex_trust_left: r.codex_trust_left,
            revocation_pending: false,
        })
    }
}

impl HarnessOps for AdapterOps {
    fn id(&self) -> HarnessId {
        client_id(self.h)
    }

    fn name(&self) -> &'static str {
        match self.h {
            ad::HarnessId::ClaudeCode => "Claude Code",
            ad::HarnessId::Codex => "Codex",
            ad::HarnessId::Hermes => "Hermes Agent",
            ad::HarnessId::Openclaw => "OpenClaw",
        }
    }

    fn refresh(&self) {
        let found = self
            .env(true)
            .and_then(|env| ad::adapter(self.h).detect(&env));
        *self.inst.write().unwrap_or_else(PoisonError::into_inner) = found;
    }

    fn install(&self) -> Option<InstallInfo> {
        let i = self.inst().ok()?;
        Some(InstallInfo {
            configured: i.config_files.iter().any(|f| f.path.exists()),
            binary: i.binary,
            version: i.version,
            tested: i.tested,
            login: match i.login {
                ad::LoginKind::Oauth => Login::Oauth,
                ad::LoginKind::ApiKey => Login::ApiKey,
                ad::LoginKind::Unknown => Login::Unknown,
            },
        })
    }

    fn active_backup(&self) -> Option<String> {
        self.store().active(self.h).map(|b| b.id)
    }

    fn chat_route_in_backup(&self) -> bool {
        self.store()
            .active(self.h)
            .is_some_and(|b| ad::harness::backup_has_chat_route(ad::adapter(self.h).as_ref(), &b))
    }

    fn backup_unreadable(&self) -> bool {
        let store = self.store();
        store
            .list(self.h)
            .iter()
            .any(|id| store.load(self.h, id).is_err())
    }

    fn servers(&self, gateway_base: &str) -> Result<Vec<ServerEntry>, OpError> {
        let i = self.inst()?;
        let list = ad::adapter(self.h)
            .mcp_servers(&i, gateway_base)
            .map_err(op_error)?;
        Ok(list.into_iter().map(|e| server(e, gateway_base)).collect())
    }

    fn status(&self, sys: &SystemView) -> CardStatus {
        let Ok(i) = self.inst() else {
            return CardStatus {
                paths: Vec::new(),
                hook: HookState::NotApplicable,
                drift: 0,
                grant: false,
            };
        };
        let st = ad::adapter(self.h).status(&i, &self.system_state(sys));
        CardStatus {
            paths: st.paths.iter().map(|(p, s)| path_info(*p, s)).collect(),
            hook: hook_state(st.hook),
            drift: st.drift.len(),
            grant: i.config_files.iter().any(|f| denied(&f.path)),
        }
    }

    fn manual_setup(&self, sys: &SystemView) -> Option<ManualSetupView> {
        let i = self.inst().ok()?;
        let adapter = ad::adapter(self.h);
        let sys = self.system_state(sys);
        let m = adapter.manual_setup(&adapter.status(&i, &sys), &sys)?;
        Some(ManualSetupView {
            lines: m.lines,
            note: m.note,
        })
    }

    fn preview(&self, req: &ConnectRequest) -> Result<Vec<FileChange>, OpError> {
        let i = self.inst()?;
        let edits = ad::adapter(self.h)
            .plan_edits(&i, &self.plan(req)?)
            .map_err(op_error)?;
        Ok(edits
            .into_iter()
            .filter(|(_, es)| !es.is_empty())
            .map(|(f, es)| FileChange {
                path: f.path.clone(),
                keys: es
                    .iter()
                    .map(|e| match e {
                        ad::Edit::Set { path, .. }
                        | ad::Edit::Remove { path }
                        | ad::Edit::Push { path, .. }
                        | ad::Edit::Pull { path, .. }
                        | ad::Edit::PullMatching { path, .. } => path.join("."),
                    })
                    .collect(),
            })
            .collect())
    }

    fn connect_warnings(&self, req: &ConnectRequest) -> Vec<Reason> {
        let (Ok(i), Ok(plan)) = (self.inst(), self.plan(req)) else {
            return Vec::new();
        };
        ad::adapter(self.h)
            .connect_warnings(&i, &plan)
            .into_iter()
            .map(|w| Reason {
                code: w.code(),
                text: w.sentence(),
            })
            .collect()
    }

    fn apply(&self, req: &ConnectRequest) -> Result<String, OpError> {
        let i = self.inst()?;
        let b = ad::adapter(self.h)
            .apply(&i, &self.plan(req)?)
            .map_err(op_error)?;
        Ok(b.id)
    }

    fn revert(&self, backup: &str) -> Result<RevertSummary, OpError> {
        self.revert_with(backup, false)
    }

    fn revert_final(&self, backup: &str) -> Result<RevertSummary, OpError> {
        self.revert_with(backup, true)
    }

    fn backups(&self) -> Vec<BackupInfo> {
        // Only ids the app can revert or delete (`backup_id_ok`).
        self.store()
            .list(self.h)
            .into_iter()
            .filter(|id| backup_id_ok(id))
            .map(BackupInfo::from_id)
            .collect()
    }

    fn delete_backup(&self, backup: &str) -> Result<(), OpError> {
        // The id names a directory that is removed recursively.
        if !backup_id_ok(backup) {
            return Err(OpError::Failed("backup_unreadable"));
        }
        let store = self.store();
        let b = store.load(self.h, backup).map_err(op_error)?;
        store.delete(&b).map_err(op_error)
    }

    fn check_invocation(&self, plan: &ad::CheckPlan) -> Option<ad::Invocation> {
        let i = self.inst().ok()?;
        ad::adapter(self.h).check_invocation(&i, plan)
    }
}
