//! `/v1/check*` (M6 spec §8, §9.7). Canary values never appear in these
//! bodies except the harness output the app forwards (lengths in `Debug`).

use serde::{Deserialize, Serialize};

use crate::secret::Secret;

/// Harness id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessId {
    /// Claude Code.
    ClaudeCode,
    /// Codex.
    Codex,
    /// Hermes Agent.
    Hermes,
    /// OpenClaw.
    Openclaw,
}

/// A protection path of the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckPath {
    /// MCP gateway.
    Gateway,
    /// Folder mirror.
    Mirror,
    /// Model-API proxy.
    Proxy,
}

/// `POST /v1/check` body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckCreate {
    /// Paths to prepare; all when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<CheckPath>>,
}

/// Why a path is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailReason {
    /// M5 is not present.
    MirrorUnavailable,
    /// M8 is not present.
    ProxyUnavailable,
}

/// Availability of one path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathAvail {
    /// Available.
    pub available: bool,
    /// Why not.
    pub reason: Option<AvailReason>,
}

/// Availability per path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckPaths {
    /// Gateway.
    pub gateway: PathAvail,
    /// Mirror.
    pub mirror: PathAvail,
    /// Proxy.
    pub proxy: PathAvail,
}

/// The check's gateway entry.
#[derive(Clone, Serialize, Deserialize)]
pub struct CheckGateway {
    /// Gateway URL of the check dataset.
    pub url: String,
    /// Temporary bearer token.
    pub token: Secret,
    /// MCP server name for the harness entry.
    pub server: String,
}

debug_fields!(CheckGateway {});

/// The check's mirror. `Debug` prints no field: both are paths.
#[derive(Clone, Serialize, Deserialize)]
pub struct CheckMirror {
    /// Mirrored canary file.
    pub path: String,
    /// The check's own temporary source directory, which the scripted `Bash`
    /// call reads (M6 spec §9.7 amendment 2026-10-10). The daemon creates it
    /// (`<temp>/inumaki-check-<tag>-<random>/source`); it is never a user
    /// path. Absent from daemons older than the amendment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_dir: Option<String>,
}

debug_fields!(CheckMirror {});

/// One check route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckProxyRoute {
    /// Upstream name.
    pub upstream: String,
    /// Base URL of the check route.
    pub base_url: String,
}

/// The check's proxy routes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckProxy {
    /// Routes.
    pub routes: Vec<CheckProxyRoute>,
}

/// `POST /v1/check` answer (201).
#[derive(Clone, Serialize, Deserialize)]
pub struct CheckCreated {
    /// 128-bit random id, hex.
    pub id: String,
    /// Expiry.
    pub expires_at: i64,
    /// Gateway entry.
    pub gateway: Option<CheckGateway>,
    /// Mirror.
    pub mirror: Option<CheckMirror>,
    /// Proxy.
    pub proxy: Option<CheckProxy>,
    /// Availability.
    pub paths: CheckPaths,
}

debug_fields!(CheckCreated {
    id,
    expires_at,
    proxy,
    paths
});

/// `POST /v1/check/{id}/harness` body. `output` holds synthetic canary text.
#[derive(Clone, Serialize, Deserialize)]
pub struct CheckHarnessRequest {
    /// Harness.
    pub harness: HarnessId,
    /// The harness's stdout.
    pub output: String,
    /// Its exit code.
    pub exit_code: i64,
}

impl std::fmt::Debug for CheckHarnessRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckHarnessRequest")
            .field("harness", &self.harness)
            .field("output_len", &self.output.len())
            .field("exit_code", &self.exit_code)
            .finish()
    }
}

/// Verdict of a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStatus {
    /// Passed.
    Passed,
    /// Failed.
    Failed,
    /// Not checked.
    NotChecked,
}

/// Reason of a path verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathReason {
    /// M5 not present.
    MirrorUnavailable,
    /// M8 not present.
    ProxyUnavailable,
    /// The harness's chat does not go through the proxy.
    ChatNotRouted,
    /// A canary value reached the scripted upstream.
    CanaryInUpstream,
    /// No tokens in the tool result or mirrored file.
    NoTokens,
    /// The output lacked the rehydrated canary.
    NotRehydrated,
    /// Timeout.
    Timeout,
    /// The harness run failed.
    HarnessFailed,
}

/// Result of one path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathResult {
    /// Status.
    pub status: PathStatus,
    /// Reason.
    pub reason: Option<PathReason>,
    /// Requests the scripted upstream recorded.
    pub upstream_requests: u64,
    /// A canary value was in an upstream request.
    pub canary_in_upstream: bool,
    /// Tokens were seen.
    pub tokens_seen: bool,
    /// The output had the canary after rehydration.
    pub rehydrated_in_output: bool,
}

/// Results per path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResults {
    /// Gateway.
    pub gateway: PathResult,
    /// Mirror.
    pub mirror: PathResult,
    /// Proxy.
    pub proxy: PathResult,
}

/// `CheckReport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckReport {
    /// Check id.
    pub id: String,
    /// Harness, for a harness run.
    pub harness: Option<HarnessId>,
    /// Results.
    pub results: CheckResults,
}
