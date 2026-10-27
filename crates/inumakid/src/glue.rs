//! What the gateway needs from the daemon: the engine behind `Blocks` and
//! the built-in upstreams (the mail connector of a mailbox dataset, with
//! its credentials and handle store over the vault). Both hold a
//! `Weak<AppState>` so the gateway, which the state owns, does not keep the
//! state alive.

use std::sync::{Arc, Weak};

use inumaki_core::policy::Profile;
use inumaki_gateway::upstream::{
    BoxFut, BuiltinUpstreams, Running, ServerGuard, UpstreamClient, UpstreamError,
    connect_in_process,
};
use inumaki_gateway::{BlockOutcome, BlockResult, Blocks, BlocksError, FieldHint, TextBlock};
use inumaki_mail::{
    MailAccount, MailCredentials, MailError, MailHandles, MailServer, MessageRef, Preset, Resolved,
    UPSTREAM_NAME,
};
use inumaki_vault::{MailHandleKind, MailHandleRef, Vault, VaultError};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::cache::CachedOutcome;
use crate::engines::EngineError;
use crate::service::{self, BlockInput, RehydrateMode, ServiceError};
use crate::state::AppState;

fn vault_err(e: &VaultError) -> BlocksError {
    match e {
        VaultError::DatasetNotFound(_) | VaultError::Closed => BlocksError::DatasetNotFound,
        _ => BlocksError::VaultUnavailable,
    }
}

fn engine_err(e: &EngineError) -> BlocksError {
    match e {
        EngineError::Unavailable { .. } => BlocksError::ModelUnavailable,
        EngineError::Config(_) => BlocksError::Internal("profile"),
    }
}

fn map_err(e: ServiceError) -> BlocksError {
    match e {
        ServiceError::Vault(v) => vault_err(&v),
        ServiceError::Store(_) => BlocksError::VaultUnavailable,
        ServiceError::Engine(e) => engine_err(&e),
        ServiceError::Unresolved { unknown, removed } => {
            BlocksError::Unresolved { unknown, removed }
        }
        ServiceError::Redaction(_) => BlocksError::Unsupported("redactions"),
        ServiceError::Unsupported(c) => BlocksError::Unsupported(c),
    }
}

/// The engine, through the daemon's service module.
pub struct BlocksHandle(pub Weak<AppState>);

impl BlocksHandle {
    fn state(&self) -> Result<Arc<AppState>, BlocksError> {
        self.0
            .upgrade()
            .ok_or(BlocksError::Internal("daemon_stopped"))
    }
}

impl Blocks for BlocksHandle {
    fn sanitize_blocks(
        &self,
        dataset: &str,
        blocks: Vec<TextBlock>,
    ) -> Result<Vec<BlockResult>, BlocksError> {
        let s = self.state()?;
        let mut results: Vec<Option<BlockResult>> = vec![None; blocks.len()];
        let mut inputs: Vec<BlockInput> = Vec::new();
        let mut slots: Vec<usize> = Vec::new();
        // The dataset's current mailbox fingerprint, read once per batch.
        let mut fingerprint: Option<String> = None;
        for (i, b) in blocks.into_iter().enumerate() {
            let hint = match b.hint {
                FieldHint::Handle => {
                    // Provenance, not shape (M4 spec §6.2): the vault minted
                    // this value for this dataset's current mailbox. The
                    // text never reaches the engine and comes back unchanged.
                    if fingerprint.is_none() {
                        fingerprint = Some(
                            s.vault
                                .mailbox(dataset)
                                .map_err(|e| vault_err(&e))?
                                .ok_or(BlocksError::Unsupported("handle_provenance"))?
                                .fingerprint,
                        );
                    }
                    let fp = fingerprint.as_deref().unwrap_or_default();
                    if !s
                        .vault
                        .mail_handle_known(dataset, fp, &b.text)
                        .map_err(|e| vault_err(&e))?
                    {
                        return Err(BlocksError::Unsupported("handle_provenance"));
                    }
                    results[i] = Some(BlockResult {
                        outcome: BlockOutcome::Pass,
                        text: b.text,
                        replacements: 0,
                        kinds: Vec::new(),
                        reasons: Vec::new(),
                        cached: false,
                    });
                    continue;
                }
                FieldHint::FreeText => service::FieldHint::FreeText,
                FieldHint::Identifier(k) => service::FieldHint::Identifier(k),
                FieldHint::Metadata => service::FieldHint::Metadata,
            };
            slots.push(i);
            // Gateway blocks carry no redactions (`TextBlock` has none), so
            // the engine's trust in validated redactions is never reached
            // from here.
            inputs.push(BlockInput {
                text: b.text,
                hint,
                redactions: Vec::new(),
            });
        }
        if !inputs.is_empty() {
            let out = service::sanitize_blocks(&s, dataset, None, inputs).map_err(map_err)?;
            if out.len() != slots.len() {
                return Err(BlocksError::Internal("block count"));
            }
            for (slot, r) in slots.into_iter().zip(out) {
                results[slot] = Some(BlockResult {
                    outcome: match r.outcome {
                        CachedOutcome::Pass => BlockOutcome::Pass,
                        CachedOutcome::PassUncertain => BlockOutcome::PassUncertain,
                        CachedOutcome::Blocked => BlockOutcome::Blocked,
                    },
                    text: r.text,
                    replacements: r.replacements,
                    kinds: r.kinds,
                    reasons: r.reasons,
                    cached: r.cached,
                });
            }
        }
        results
            .into_iter()
            .map(|r| r.ok_or(BlocksError::Internal("block slot")))
            .collect()
    }

    fn rehydrate_strict(
        &self,
        dataset: &str,
        blocks: Vec<String>,
    ) -> Result<Vec<String>, BlocksError> {
        let s = self.state()?;
        let inputs = blocks.into_iter().map(BlockInput::text).collect();
        let out = service::rehydrate_blocks(&s, dataset, inputs, RehydrateMode::Strict)
            .map_err(map_err)?;
        Ok(out.into_iter().map(|r| r.text).collect())
    }

    fn profile(&self, dataset: &str) -> Result<Arc<Profile>, BlocksError> {
        let s = self.state()?;
        let name = s
            .vault
            .dataset_profile(dataset)
            .map_err(|e| vault_err(&e))?;
        s.engines.policy(&name).map_err(|e| engine_err(&e))
    }

    fn scan_clear(
        &self,
        dataset: &str,
        texts: &[String],
    ) -> Result<Vec<(String, u32)>, BlocksError> {
        let s = self.state()?;
        let out = service::scan_clear(&s, dataset, texts).map_err(map_err)?;
        Ok(out
            .into_iter()
            .map(|(k, n)| (k.label().to_string(), n))
            .collect())
    }

    fn scan_names(&self, dataset: &str, names: &[String]) -> Result<u32, BlocksError> {
        let s = self.state()?;
        service::scan_names(&s, dataset, names).map_err(map_err)
    }
}

/// The account of a mailbox dataset, read fresh from the vault: the row
/// plus the app password from the secrets table. Classes only on failure.
pub fn mailbox_account(vault: &Vault, dataset: &str) -> Result<MailAccount, MailError> {
    let row = vault
        .mailbox(dataset)
        .map_err(|_| MailError::Credentials("vault"))?
        .ok_or(MailError::Credentials("no_mailbox"))?;
    let secret = vault
        .get_secret(&row.spec.password_secret)
        .map_err(|_| MailError::Credentials("vault"))?
        .ok_or(MailError::Credentials("no_password"))?;
    // Borrowed, then copied once into a zeroizing string.
    let password = std::str::from_utf8(&secret)
        .map(|p| Zeroizing::new(p.to_owned()))
        .map_err(|_| MailError::Credentials("password_encoding"))?;
    Ok(MailAccount {
        preset: Preset::parse(&row.spec.preset).unwrap_or(Preset::Generic),
        host: row.spec.imap_host,
        port: row.spec.imap_port,
        tls: row.spec.imap_tls,
        username: Zeroizing::new(row.spec.username),
        password,
        drafts_folder: row.spec.drafts_folder,
        from_address: row.spec.from_address,
    })
}

/// [`MailCredentials`] over the vault: re-read at every (re)connect, so a
/// replaced password is picked up without a restart.
pub struct VaultCredentials {
    /// The vault.
    pub vault: Vault,
    /// Dataset id.
    pub dataset: String,
}

impl MailCredentials for VaultCredentials {
    fn account(&self) -> Result<MailAccount, MailError> {
        mailbox_account(&self.vault, &self.dataset)
    }
}

/// [`MailHandles`] over the vault's `mail_handles` table, scoped to one
/// dataset and the mailbox fingerprint the connector was started for: a
/// connector left over from a replaced mailbox can neither mint nor resolve.
pub struct VaultMailHandles {
    /// The vault.
    pub vault: Vault,
    /// Dataset id.
    pub dataset: String,
    /// Mailbox fingerprint at start.
    pub fingerprint: String,
}

fn store_err(_: VaultError) -> MailError {
    MailError::Handles("store")
}

impl MailHandles for VaultMailHandles {
    fn folder_handle(&self, folder: &str) -> Result<String, MailError> {
        self.vault
            .mail_handle(
                &self.dataset,
                &self.fingerprint,
                &MailHandleRef::folder(folder),
            )
            .map_err(store_err)
    }

    fn message_handle(&self, r: &MessageRef) -> Result<String, MailError> {
        self.vault
            .mail_handle(
                &self.dataset,
                &self.fingerprint,
                &MailHandleRef::message(&r.folder, r.uid_validity, r.uid),
            )
            .map_err(store_err)
    }

    fn resolve(&self, handle: &str) -> Result<Option<Resolved>, MailError> {
        Ok(self
            .vault
            .resolve_mail_handle(&self.dataset, &self.fingerprint, handle)
            .map_err(store_err)?
            .map(|(kind, r)| match kind {
                MailHandleKind::Folder => Resolved::Folder(r.folder),
                MailHandleKind::Message => Resolved::Message(MessageRef {
                    folder: r.folder,
                    uid_validity: r.uid_validity,
                    uid: r.uid,
                }),
            }))
    }

    fn invalidate_folder(&self, folder: &str) -> Result<usize, MailError> {
        self.vault
            .invalidate_mail_folder(&self.dataset, &self.fingerprint, folder)
            .map_err(store_err)
    }
}

/// Logs the mail session out when the upstream is dropped (dataset
/// removed, mailbox replaced, daemon shutdown).
struct LogoutOnDrop(MailServer);

impl Drop for LogoutOnDrop {
    fn drop(&mut self) {
        let server = self.0.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move { server.shutdown().await });
        }
    }
}

/// Built-in upstreams: the mail connector of a mailbox dataset.
pub struct DaemonBuiltins {
    /// The daemon.
    pub state: Weak<AppState>,
}

impl BuiltinUpstreams for DaemonBuiltins {
    /// Start the mail connector for the `mail` upstream of a mailbox
    /// dataset, with credentials and handles read from the vault. Without a
    /// mailbox row it fails closed (`failed(no_mailbox)`); any other name
    /// is `failed(unknown_builtin)`.
    fn connect(
        &self,
        dataset: &str,
        upstream: &str,
        client: UpstreamClient,
    ) -> BoxFut<Result<(Running, ServerGuard), UpstreamError>> {
        let state = self.state.upgrade();
        let (dataset, upstream) = (dataset.to_string(), upstream.to_string());
        Box::pin(async move {
            let Some(state) = state else {
                return Err(UpstreamError::Builtin("daemon_stopped"));
            };
            if upstream != UPSTREAM_NAME {
                return Err(UpstreamError::Builtin("unknown_builtin"));
            }
            let vault = state.vault.clone();
            let ds = dataset.clone();
            let row = tokio::task::spawn_blocking(move || vault.mailbox(&ds))
                .await
                .map_err(|_| UpstreamError::Builtin("worker"))?;
            let fingerprint = match row {
                Ok(Some(r)) => r.fingerprint,
                Ok(None) => return Err(UpstreamError::Builtin("no_mailbox")),
                Err(_) => return Err(UpstreamError::Builtin("vault")),
            };
            let server = MailServer::start(
                Arc::new(VaultCredentials {
                    vault: state.vault.clone(),
                    dataset: dataset.clone(),
                }),
                Arc::new(VaultMailHandles {
                    vault: state.vault.clone(),
                    dataset: dataset.clone(),
                    fingerprint,
                }),
                state.cfg.mail_config(),
                &state.vault.opaque_id(&dataset),
            );
            let ct = CancellationToken::new();
            let (running, guard) = connect_in_process(server.clone(), client, ct.clone()).await?;
            let guard: ServerGuard = Box::new((guard, ct.drop_guard(), LogoutOnDrop(server)));
            Ok((running, guard))
        })
    }
}
