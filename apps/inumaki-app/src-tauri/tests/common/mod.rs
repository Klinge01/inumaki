#![allow(dead_code)]
//! A fake harness for app tests: records what the app asked for, answers
//! what the test set. No harness file is touched.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use inumaki_app_lib::ctx::{Ctx, RecordingNotifier};
use inumaki_app_lib::harness::ops::*;
use inumaki_app_lib::paths::AppPaths;
use inumaki_client::HarnessId;
use inumaki_client::mock::MockDaemon;
use zeroize::Zeroizing;

/// How `apply` fails.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fail {
    /// `CannotEditSafely`, with this apply's token in the snippet.
    Refuse,
    /// Any other failure.
    Io,
}

/// (entry name, carried approval mode) of one applied gateway entry.
pub type Carried = (String, Option<serde_json::Value>);

pub struct FakeOps {
    pub id: HarnessId,
    pub servers: Mutex<Vec<ServerEntry>>,
    pub status: Mutex<CardStatus>,
    pub applied: Mutex<Vec<Vec<(String, String, String)>>>, // (name, url, token) per apply
    pub reverted: Mutex<Vec<String>>,
    /// The subset of `reverted` that went through `revert_final` (the user's Revert).
    pub reverted_final: Mutex<Vec<String>>,
    pub previews: Mutex<usize>,
    pub fail_apply: Mutex<Option<Fail>>,
    pub fail_preview: AtomicBool,
    /// `preview` refuses with `CannotEditSafely`, its token in the snippet.
    pub refuse_preview: AtomicBool,
    pub active: Mutex<Option<String>>,
    /// `revert` reports the proxy client header as left in the file.
    pub header_left: AtomicBool,
    /// A backup manifest that does not load exists.
    pub unreadable: AtomicBool,
    /// The client header of each successful apply.
    pub headers: Mutex<Vec<Option<String>>>,
    /// Whether each successful apply carried any proxy base URL.
    pub chat_routes: Mutex<Vec<bool>>,
    /// Entries (name, scope) the applies pointed at the gateway; a revert
    /// gives them back their original (as a real adapter's backup does).
    pub routed_by_apply: Mutex<Vec<(String, Scope)>>,
    /// An apply that leaves the entry of this name as it was (a dataset the
    /// adapter did not write).
    pub no_route: Mutex<Option<String>>,
    /// Backup ids `backups()` lists.
    pub backups: Mutex<Vec<String>>,
    /// A failing `Fail::Io` apply wrote some files first and keeps an
    /// active backup of them (M6-1 `apply_files_with`).
    pub partial_apply: AtomicBool,
    /// `servers()` fails with a read error once an apply has been recorded
    /// (the file cannot be read back between apply and check).
    pub read_fails_after_apply: AtomicBool,
    /// What `connect_warnings` answers (the adapter's fixed reasons).
    pub warnings: Mutex<Vec<Reason>>,
    /// Each successful apply's (entry name, carried approval mode).
    pub approvals: Mutex<Vec<Vec<Carried>>>,
    /// What `manual_setup` answers.
    pub manual: Mutex<Option<ManualSetupView>>,
}

impl FakeOps {
    pub fn new(id: HarnessId) -> Arc<FakeOps> {
        Arc::new(FakeOps {
            id,
            servers: Mutex::new(Vec::new()),
            status: Mutex::new(CardStatus {
                paths: [PathKind::Mcp, PathKind::Files, PathKind::Chat]
                    .into_iter()
                    .map(|path| PathInfo {
                        path,
                        state: PathState::NotConnected,
                        reason: None,
                        detail: None,
                    })
                    .collect(),
                hook: HookState::NotApplicable,
                drift: 0,
                grant: false,
            }),
            applied: Mutex::new(Vec::new()),
            reverted: Mutex::new(Vec::new()),
            reverted_final: Mutex::new(Vec::new()),
            previews: Mutex::new(0),
            fail_apply: Mutex::new(None),
            fail_preview: AtomicBool::new(false),
            refuse_preview: AtomicBool::new(false),
            active: Mutex::new(None),
            header_left: AtomicBool::new(false),
            unreadable: AtomicBool::new(false),
            headers: Mutex::new(Vec::new()),
            chat_routes: Mutex::new(Vec::new()),
            routed_by_apply: Mutex::new(Vec::new()),
            no_route: Mutex::new(None),
            backups: Mutex::new(Vec::new()),
            partial_apply: AtomicBool::new(false),
            read_fails_after_apply: AtomicBool::new(false),
            warnings: Mutex::new(Vec::new()),
            approvals: Mutex::new(Vec::new()),
            manual: Mutex::new(None),
        })
    }

    pub fn stdio(name: &str, command: &str, env: &[(&str, &str)]) -> ServerEntry {
        ServerEntry {
            name: name.into(),
            scope: Scope::User,
            transport: Transport::Stdio,
            command: Some(command.into()),
            args: vec!["--stdio".into()],
            cwd: None,
            url: None,
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
                .collect(),
            headers: Vec::new(),
            unvalued_env: Vec::new(),
            unvalued_headers: Vec::new(),
            gateway_dataset: None,
            needs_oauth: false,
            approval_mode: None,
        }
    }
}

impl HarnessOps for FakeOps {
    fn id(&self) -> HarnessId {
        self.id
    }
    fn name(&self) -> &'static str {
        "Fake harness"
    }
    fn refresh(&self) {}
    fn install(&self) -> Option<InstallInfo> {
        Some(InstallInfo {
            binary: Some("/opt/fake/bin/fake".into()),
            version: Some("1.0.0".into()),
            tested: true,
            login: Login::ApiKey,
            configured: true,
        })
    }
    fn active_backup(&self) -> Option<String> {
        self.active.lock().unwrap().clone()
    }
    fn backup_unreadable(&self) -> bool {
        self.unreadable.load(Ordering::SeqCst)
    }
    fn servers(&self, _gateway_base: &str) -> Result<Vec<ServerEntry>, OpError> {
        if self.read_fails_after_apply.load(Ordering::SeqCst)
            && !self.applied.lock().unwrap().is_empty()
        {
            return Err(OpError::Failed("file_unwritable"));
        }
        Ok(self.servers.lock().unwrap().clone())
    }
    fn status(&self, _sys: &SystemView) -> CardStatus {
        self.status.lock().unwrap().clone()
    }
    fn preview(&self, req: &ConnectRequest) -> Result<Vec<FileChange>, OpError> {
        *self.previews.lock().unwrap() += 1;
        if self.fail_preview.load(Ordering::SeqCst) {
            return Err(OpError::Failed("changed_meanwhile"));
        }
        if self.refuse_preview.load(Ordering::SeqCst) {
            let token = req
                .gateway
                .first()
                .map(|g| g.token.to_string())
                .unwrap_or_default();
            return Err(OpError::CannotEditSafely {
                snippet: Zeroizing::new(format!("\"Authorization\": \"Bearer {token}\"")),
            });
        }
        Ok(vec![FileChange {
            path: "/home/fake/.fake.json".into(),
            keys: req
                .gateway
                .iter()
                .map(|g| format!("mcpServers.{}", g.name))
                .collect(),
        }])
    }
    fn manual_setup(&self, _sys: &SystemView) -> Option<ManualSetupView> {
        self.manual.lock().unwrap().clone()
    }

    fn connect_warnings(&self, _req: &ConnectRequest) -> Vec<Reason> {
        self.warnings.lock().unwrap().clone()
    }
    fn apply(&self, req: &ConnectRequest) -> Result<String, OpError> {
        match *self.fail_apply.lock().unwrap() {
            // M6-1's snippet is the edit the user adds by hand, token included.
            Some(Fail::Refuse) => {
                let token = req
                    .gateway
                    .first()
                    .map(|g| g.token.to_string())
                    .unwrap_or_default();
                return Err(OpError::CannotEditSafely {
                    snippet: Zeroizing::new(format!("\"Authorization\": \"Bearer {token}\"")),
                });
            }
            Some(Fail::Io) => {
                if self.partial_apply.load(Ordering::SeqCst) {
                    *self.active.lock().unwrap() = Some("partial-backup".into());
                }
                return Err(OpError::Failed("file_unwritable"));
            }
            None => {}
        }
        self.headers
            .lock()
            .unwrap()
            .push(req.client_header.as_ref().map(|h| h.to_string()));
        self.chat_routes.lock().unwrap().push(
            req.proxy.anthropic.is_some()
                || req.proxy.openai.is_some()
                || req.proxy.codex.is_some(),
        );
        // The written entries now point at the gateway, as the adapter
        // reports them on the next read (matched by name and scope).
        {
            let mut servers = self.servers.lock().unwrap();
            let mut routed = self.routed_by_apply.lock().unwrap();
            let skip = self.no_route.lock().unwrap().clone();
            for g in req
                .gateway
                .iter()
                .filter(|g| skip.as_deref() != Some(g.name.as_str()))
            {
                let ds = g.url.rsplit_once("/mcp/").map(|(_, d)| d.to_string());
                for s in servers
                    .iter_mut()
                    .filter(|s| s.name == g.name && s.scope == g.scope)
                {
                    if s.gateway_dataset.is_none() {
                        routed.push((s.name.clone(), s.scope.clone()));
                    }
                    s.gateway_dataset = ds.clone();
                }
            }
        }
        self.approvals.lock().unwrap().push(
            req.gateway
                .iter()
                .map(|g| (g.name.clone(), g.approval_mode.clone()))
                .collect(),
        );
        self.applied.lock().unwrap().push(
            req.gateway
                .iter()
                .map(|g| (g.name.clone(), g.url.clone(), g.token.to_string()))
                .collect(),
        );
        let id = format!(
            "{:012}-{:09}",
            1_790_000_000 + self.applied.lock().unwrap().len(),
            0
        );
        *self.active.lock().unwrap() = Some(id.clone());
        Ok(id)
    }
    fn revert(&self, backup: &str) -> Result<RevertSummary, OpError> {
        self.reverted.lock().unwrap().push(backup.into());
        let mut servers = self.servers.lock().unwrap();
        for (n, sc) in self.routed_by_apply.lock().unwrap().drain(..) {
            for s in servers.iter_mut().filter(|s| s.name == n && s.scope == sc) {
                s.gateway_dataset = None;
            }
        }
        drop(servers);
        *self.active.lock().unwrap() = None;
        Ok(RevertSummary {
            reverted: true,
            exact: true,
            conflicts: 0,
            client_header_left: self.header_left.load(Ordering::SeqCst),
            codex_trust_left: false,
            revocation_pending: false,
        })
    }
    fn revert_final(&self, backup: &str) -> Result<RevertSummary, OpError> {
        self.reverted_final.lock().unwrap().push(backup.into());
        self.revert(backup)
    }
    fn backups(&self) -> Vec<BackupInfo> {
        self.backups
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .map(BackupInfo::from_id)
            .collect()
    }
    fn delete_backup(&self, backup: &str) -> Result<(), OpError> {
        self.backups.lock().unwrap().retain(|b| b != backup);
        Ok(())
    }
}

pub fn ctx_with(
    m: &MockDaemon,
    fakes: Vec<Arc<FakeOps>>,
) -> (Arc<Ctx>, tempfile::TempDir, Arc<RecordingNotifier>) {
    let dir = tempfile::tempdir().unwrap();
    let (ctx, notes) = Ctx::for_tests(
        AppPaths::under(&dir.path().join("data"), &dir.path().join("home")),
        m.client(),
    );
    let ops: Vec<Arc<dyn HarnessOps>> = fakes
        .into_iter()
        .map(|f| f as Arc<dyn HarnessOps>)
        .collect();
    (Arc::new(ctx.with_harnesses(ops)), dir, notes)
}
