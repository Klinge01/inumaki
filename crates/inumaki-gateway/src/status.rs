//! What `GET /v1/status` shows for the gateway (M4 spec §8). Counts,
//! names, and classes only.

use std::collections::BTreeMap;

/// Whether an upstream's field contract can be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractState {
    /// Parsed and bound to the upstream's current schema.
    Ready,
    /// No contract stored (`{}`): text-only tools work, structured content is rejected.
    None,
    /// The stored policy does not parse or violates a rule.
    Invalid,
    /// The upstream's schema no longer matches the reviewed fingerprint.
    Drift,
}

impl ContractState {
    /// The status string.
    pub fn as_str(self) -> &'static str {
        match self {
            ContractState::Ready => "ready",
            ContractState::None => "none",
            ContractState::Invalid => "invalid",
            ContractState::Drift => "drift",
        }
    }
}

/// One upstream of a dataset.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UpstreamStatus {
    /// Upstream name.
    pub name: String,
    /// `stdio`, `http`, or `mail`.
    pub kind: String,
    /// `running`, `starting`, `stopped`, or `failed(<class>)`.
    pub state: String,
    /// Restarts since the daemon started.
    pub restarts: u32,
    /// Bytes of child stderr read and discarded.
    pub stderr_bytes: u64,
    /// Contract readiness (`ContractState::as_str`).
    pub contract: String,
    /// The running upstream's current schema fingerprint (`sha256:…`), set by the
    /// gateway after the first successful listing; `None` until then.
    pub schema_fingerprint: Option<String>,
}

/// One dataset served by the gateway.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DatasetStatus {
    /// Dataset id.
    pub id: String,
    /// Its upstreams in creation order.
    pub upstreams: Vec<UpstreamStatus>,
    /// `tools/call`, `resources/read`, and `prompts/get` served.
    pub calls: u64,
    /// Results discarded as `Blocked`.
    pub blocked: u64,
    /// Results withheld as `PassUncertain`.
    pub uncertain: u64,
    /// Requests refused before dispatch for unresolved placeholders.
    pub unresolved: u64,
    /// Results or listings rejected as `unsupported_content`.
    pub unsupported: u64,
    /// Requests refused with `resource_limit`.
    pub limited: u64,
    /// Clear-value tripwire hits (M4 spec §16.1): a known original or a
    /// validated identifier found in clear in model-written arguments.
    pub clear_value_hits: u64,
}

/// The gateway block of the status body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GatewayStatus {
    /// Bound listen address.
    pub listen: String,
    /// Datasets with a gateway handler.
    pub datasets: Vec<DatasetStatus>,
    /// Gateway tokens in the vault.
    pub tokens: usize,
    /// Verifier check ids seen on withheld uncertain results, with counts.
    pub uncertain_checks: BTreeMap<String, u64>,
    /// `unqualified` until plan 4 records a passing §13.1 run.
    pub qualification: String,
    /// Activity records lost to a full queue or a failed write (M4 spec §16.4).
    pub activity_dropped: u64,
    /// Journal entries dropped (in-flight cap, refused or failed write, or
    /// a dropped record; M4 spec §16.3).
    pub journal_dropped: u64,
}
