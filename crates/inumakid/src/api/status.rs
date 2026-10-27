//! `GET /v1/status`.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use inumaki_models::assemble::LoadedModelInfo;
use serde::Serialize;

use super::{ApiError, blocking};
use crate::cache::CacheStats;
use crate::engines::ProfileStatus;
use crate::state::AppState;

/// One dataset in the status body. No `Debug`: it carries the display name.
#[derive(Serialize)]
pub struct DatasetBody {
    /// Slug.
    pub id: String,
    /// The opaque dataset label (the one logs and the gateway's
    /// `server_info` use). Suggested client configuration names the MCP
    /// server after it: harnesses show the server name to the model (Claude
    /// Code prefixes it to every tool name), and the slug is a customer
    /// name as often as not.
    pub label: String,
    /// Display name.
    pub name: String,
    /// Profile.
    pub profile: String,
    /// Epoch length in days.
    pub rotation_days: u32,
    /// Grace period in days.
    pub grace_days: u32,
    /// Current epoch id.
    pub epoch_id: i64,
    /// Current epoch start, unix seconds.
    pub epoch_started_at: i64,
    /// Entries in the current epoch.
    pub entries: u64,
    /// `generic` or `mailbox`.
    pub kind: String,
}

impl DatasetBody {
    /// The body of `d`, labelled by `vault`.
    pub fn new(d: inumaki_vault::Dataset, vault: &inumaki_vault::Vault) -> Self {
        DatasetBody {
            label: vault.opaque_id(&d.id),
            id: d.id,
            name: d.name,
            profile: d.profile,
            rotation_days: d.rotation_days,
            grace_days: d.grace_days,
            epoch_id: d.epoch_id,
            epoch_started_at: d.epoch_started_at,
            entries: d.entries,
            kind: d.kind.as_str().to_string(),
        }
    }
}

/// One configured mailbox. No user name: the account's login is local
/// configuration `GET …/mailbox` answers, not status. `Debug` prints the
/// preset, port, TLS, and handle count only (the dataset id is a slug and
/// the host can name a customer).
#[derive(Serialize)]
pub struct MailboxStatus {
    /// Dataset id.
    pub dataset: String,
    /// Preset.
    pub preset: String,
    /// IMAP host.
    pub imap_host: String,
    /// IMAP port.
    pub imap_port: u16,
    /// Implicit TLS.
    pub imap_tls: bool,
    /// Mail handles held.
    pub handles: u64,
}

impl std::fmt::Debug for MailboxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailboxStatus")
            .field("preset", &self.preset)
            .field("imap_port", &self.imap_port)
            .field("imap_tls", &self.imap_tls)
            .field("handles", &self.handles)
            .finish()
    }
}

/// The status body.
#[derive(Serialize)]
pub struct StatusBody {
    /// Crate version.
    pub version: &'static str,
    /// Seconds since start.
    pub uptime_s: u64,
    /// Data directory.
    pub data_dir: String,
    /// Socket path.
    pub socket: String,
    /// `keyring` or `file`.
    pub key_source: &'static str,
    /// Loaded models.
    pub models: Vec<LoadedModelInfo>,
    /// Profiles and availability.
    pub profiles: Vec<ProfileStatus>,
    /// Datasets.
    pub datasets: Vec<DatasetBody>,
    /// Live session contexts.
    pub sessions: usize,
    /// Sanitization cache counters.
    pub cache: CacheStats,
    /// Sum of pool waits over all models (spec §9.3).
    pub pool_waits: u64,
    /// The gateway block.
    pub gateway: inumaki_gateway::GatewayStatus,
    /// Configured mailboxes (plan 3; last, so earlier clients still parse).
    pub mailboxes: Vec<MailboxStatus>,
    /// `embedded`, or the path of the configuration file in use (never its
    /// content). Additive, after `mailboxes`.
    pub config_source: String,
}

/// Handler.
pub async fn status(State(state): State<Arc<AppState>>) -> Result<Json<StatusBody>, ApiError> {
    let s = Arc::clone(&state);
    let (datasets, tokens, mailboxes) = blocking(move || {
        // The proxy's reserved chat dataset is not a user dataset (M8 spec
        // §9): `GET /v1/datasets` lists it, the status does not.
        let datasets: Vec<_> = s
            .vault
            .datasets()?
            .into_iter()
            .filter(|d| d.kind != inumaki_vault::DatasetKind::Chat)
            .collect();
        let mut mailboxes = Vec::new();
        for d in datasets
            .iter()
            .filter(|d| d.kind == inumaki_vault::DatasetKind::Mailbox)
        {
            if let Some(m) = s.vault.mailbox(&d.id)? {
                mailboxes.push(MailboxStatus {
                    dataset: d.id.clone(),
                    preset: m.spec.preset,
                    imap_host: m.spec.imap_host,
                    imap_port: m.spec.imap_port,
                    imap_tls: m.spec.imap_tls,
                    handles: s.vault.mail_handle_count(&d.id)?,
                });
            }
        }
        Ok((datasets, s.vault.gateway_tokens()?.len(), mailboxes))
    })
    .await?;
    let mut gateway = state.gateway_status(tokens).await;
    // A restarted daemon's gateway loads the chat dataset like any other
    // (it has no upstreams and serves nothing); it is not listed.
    gateway
        .datasets
        .retain(|d| d.id != inumaki_vault::CHAT_DATASET);
    let models = state.engines.models();
    Ok(Json(StatusBody {
        version: env!("CARGO_PKG_VERSION"),
        uptime_s: state.uptime().as_secs(),
        data_dir: state.data_dir.display().to_string(),
        socket: state.socket_path.display().to_string(),
        key_source: state.vault.key_source(),
        pool_waits: models.iter().map(|m| m.pool_waits).sum(),
        models,
        profiles: state.profiles(),
        datasets: datasets
            .into_iter()
            .map(|d| DatasetBody::new(d, &state.vault))
            .collect(),
        sessions: state.sessions.len(),
        cache: state.cache.stats(),
        gateway,
        mailboxes,
        config_source: state.config_source.label(),
    }))
}
