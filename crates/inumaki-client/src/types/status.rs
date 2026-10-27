//! `GET /v1/status` (`inumakid/src/api/status.rs`, `inumaki-gateway/src/status.rs`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::datasets::DatasetBody;
use super::mailbox::MailboxStatus;

/// Where the vault key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySource {
    /// The OS keyring.
    Keyring,
    /// A key file.
    File,
}

/// The status body.
#[derive(Clone, Serialize, Deserialize)]
pub struct StatusBody {
    /// Daemon version.
    pub version: String,
    /// Seconds since start.
    pub uptime_s: u64,
    /// Data directory (a path: not in `Debug`).
    pub data_dir: String,
    /// Socket path (not in `Debug`).
    pub socket: String,
    /// Key source.
    pub key_source: KeySource,
    /// Loaded models.
    pub models: Vec<ModelInfo>,
    /// Profiles.
    pub profiles: Vec<ProfileStatus>,
    /// Datasets.
    pub datasets: Vec<DatasetBody>,
    /// Live session contexts.
    pub sessions: u64,
    /// Sanitization cache.
    pub cache: CacheStats,
    /// Pool waits over all models.
    pub pool_waits: u64,
    /// Gateway block.
    pub gateway: GatewayStatus,
    /// Plan 3 (§9.4); absent until plan 3 merges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailboxes: Option<Vec<MailboxStatus>>,
    /// `embedded`, or the path of the daemon's configuration file (not in
    /// `Debug`); absent from daemons that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_source: Option<String>,
}

debug_fields!(StatusBody {
    version,
    uptime_s,
    key_source,
    models,
    profiles,
    datasets,
    sessions,
    cache,
    pool_waits,
    gateway,
    mailboxes
});

/// One loaded model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Manifest name.
    pub name: String,
    /// Intra-op threads per session.
    pub threads: u64,
    /// Pooled sessions.
    pub sessions: u64,
    /// Calls that found every session busy.
    pub pool_waits: u64,
}

/// One profile.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProfileStatus {
    /// Name.
    pub name: String,
    /// Its engine can be built.
    pub available: bool,
    /// Why not (can name a path): not in `Debug`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

debug_fields!(ProfileStatus { name, available });

/// Sanitization cache counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Hits.
    pub hits: u64,
    /// Misses.
    pub misses: u64,
    /// Bytes charged.
    pub bytes: u64,
    /// Evictions.
    pub evictions: u64,
    /// Entries.
    pub entries: u64,
}

/// Contract state of an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractState {
    /// Bound to the current schema.
    Ready,
    /// No contract stored.
    None,
    /// The stored policy is invalid.
    Invalid,
    /// The schema no longer matches the reviewed fingerprint.
    Drift,
}

/// Kind of an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamKind {
    /// Child process on stdio.
    Stdio,
    /// Streamable HTTP.
    Http,
    /// The built-in mail connector.
    Mail,
}

/// Gateway block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayStatus {
    /// Bound listen address.
    pub listen: String,
    /// Datasets with a gateway handler.
    pub datasets: Vec<GatewayDataset>,
    /// Gateway tokens.
    pub tokens: u64,
    /// Check ids on withheld uncertain results.
    pub uncertain_checks: BTreeMap<String, u64>,
    /// `unqualified` until plan 4c.
    pub qualification: String,
    /// Activity records dropped.
    pub activity_dropped: u64,
    /// Plan 2b (§9.3); absent until plan 2b merges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_dropped: Option<u64>,
}

/// One dataset served by the gateway. `id` is the slug: not in `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct GatewayDataset {
    /// Slug.
    pub id: String,
    /// Upstreams.
    pub upstreams: Vec<UpstreamStatus>,
    /// Calls served.
    pub calls: u64,
    /// Blocked results.
    pub blocked: u64,
    /// Withheld uncertain results.
    pub uncertain: u64,
    /// Refused for unresolved placeholders.
    pub unresolved: u64,
    /// `unsupported_content`.
    pub unsupported: u64,
    /// `resource_limit`.
    pub limited: u64,
    /// Clear-value tripwire hits.
    pub clear_value_hits: u64,
}

debug_fields!(GatewayDataset {
    upstreams,
    calls,
    blocked,
    uncertain,
    unresolved,
    unsupported,
    limited,
    clear_value_hits
});

/// One upstream's runtime state. `name` is a server name: not in `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpstreamStatus {
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: UpstreamKind,
    /// `running`, `starting`, `stopped`, or `failed(<class>)`.
    pub state: String,
    /// Restarts since start.
    pub restarts: u32,
    /// Child stderr bytes discarded.
    pub stderr_bytes: u64,
    /// Contract state.
    pub contract: ContractState,
    /// Current schema fingerprint, `null` before the first listing.
    pub schema_fingerprint: Option<String>,
}

debug_fields!(UpstreamStatus {
    kind,
    state,
    restarts,
    stderr_bytes,
    contract,
    schema_fingerprint
});
