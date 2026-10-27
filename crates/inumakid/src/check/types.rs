//! Bodies of `/v1/check*` (M6 spec §9.7). Field order is the contract's
//! (`inumaki_client::{CheckCreated, CheckReport, …}`). The only text-bearing
//! request, [`CheckHarnessBody`], prints lengths in `Debug`.

use serde::{Deserialize, Serialize};

/// A protection path.
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
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckCreate {
    /// Paths to prepare; all when absent.
    #[serde(default)]
    pub paths: Option<Vec<CheckPath>>,
}

/// Why a path is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailReason {
    /// M5 does not answer.
    MirrorUnavailable,
    /// M8 does not answer.
    ProxyUnavailable,
}

/// Availability of one path.
#[derive(Debug, Clone, Serialize)]
pub struct PathAvail {
    /// Available.
    pub available: bool,
    /// Why not.
    pub reason: Option<AvailReason>,
}

impl PathAvail {
    /// Available.
    pub fn yes() -> Self {
        PathAvail {
            available: true,
            reason: None,
        }
    }
    /// Unavailable for `r`.
    pub fn no(r: AvailReason) -> Self {
        PathAvail {
            available: false,
            reason: Some(r),
        }
    }
}

/// Availability per path.
#[derive(Debug, Clone, Serialize)]
pub struct CheckPaths {
    /// Gateway.
    pub gateway: PathAvail,
    /// Mirror.
    pub mirror: PathAvail,
    /// Proxy.
    pub proxy: PathAvail,
}

/// The check's gateway entry; `token` is shown to the local user once.
#[derive(Clone, Serialize)]
pub struct GatewayEntry {
    /// `http://<gateway>/mcp/<check dataset>`.
    pub url: String,
    /// Temporary bearer token.
    pub token: String,
    /// MCP server name for a harness entry.
    pub server: String,
}

/// The mirrored canary file, and the check's own source directory (M6 spec
/// §9.7 amendment 2026-10-10). Neither is a user path: the source directory
/// is `<temp>/inumaki-check-<tag>-<random>/source`, created by
/// `check::mirror::prepare`. No `Debug`: both are paths.
#[derive(Clone, Serialize)]
pub struct MirrorEntry {
    /// Absolute path inside the mirror.
    pub path: String,
    /// Absolute path of the check's temporary source directory, which the
    /// scripted `Bash` call reads (Claude Code needs it as `--add-dir`).
    pub source_dir: String,
}

/// One check route.
#[derive(Clone, Serialize)]
pub struct ProxyRouteEntry {
    /// `anthropic`, `openai`, `openai-codex`.
    pub upstream: String,
    /// Base URL under `/check/<id>/`.
    pub base_url: String,
}

/// The upstream only: the base URL holds the route id, the route's capability.
impl std::fmt::Debug for ProxyRouteEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyRouteEntry")
            .field("upstream", &self.upstream)
            .finish_non_exhaustive()
    }
}

/// The check's proxy routes; `Debug` prints upstreams only.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyEntry {
    /// Routes.
    pub routes: Vec<ProxyRouteEntry>,
}

/// `POST /v1/check` answer.
#[derive(Clone, Serialize)]
pub struct CheckCreated {
    /// 32 lowercase hex.
    pub id: String,
    /// Unix seconds.
    pub expires_at: i64,
    /// Gateway entry.
    pub gateway: Option<GatewayEntry>,
    /// Mirror.
    pub mirror: Option<MirrorEntry>,
    /// Proxy.
    pub proxy: Option<ProxyEntry>,
    /// Availability.
    pub paths: CheckPaths,
}

/// Harness id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// `POST /v1/check/{id}/harness` body: synthetic canary text, compared in memory.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckHarnessBody {
    /// Harness.
    pub harness: HarnessId,
    /// Its stdout.
    pub output: String,
    /// Its exit code.
    pub exit_code: i64,
}

impl std::fmt::Debug for CheckHarnessBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckHarnessBody")
            .field("harness", &self.harness)
            .field("output_len", &self.output.len())
            .field("exit_code", &self.exit_code)
            .finish()
    }
}

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStatus {
    /// Passed.
    Passed,
    /// Failed.
    Failed,
    /// Not checked.
    NotChecked,
}

/// Reason of a verdict (closed set, spec §9.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathReason {
    /// M5 does not answer.
    MirrorUnavailable,
    /// M8 does not answer.
    ProxyUnavailable,
    /// The harness's chat did not go through the check route.
    ChatNotRouted,
    /// A canary value reached the model side.
    CanaryInUpstream,
    /// No tokens where tokens were expected.
    NoTokens,
    /// The canary was not restored in the output.
    NotRehydrated,
    /// A step did not finish in time.
    Timeout,
    /// The harness run failed.
    HarnessFailed,
}

/// Result of one path; booleans and counts only.
#[derive(Debug, Clone, Serialize)]
pub struct PathResult {
    /// Status.
    pub status: PathStatus,
    /// Reason.
    pub reason: Option<PathReason>,
    /// Requests the model side recorded.
    pub upstream_requests: u64,
    /// A canary value was on the model side.
    pub canary_in_upstream: bool,
    /// Tokens were seen.
    pub tokens_seen: bool,
    /// The output had the canary after rehydration.
    pub rehydrated_in_output: bool,
}

/// Results per path.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResults {
    /// Gateway.
    pub gateway: PathResult,
    /// Mirror.
    pub mirror: PathResult,
    /// Proxy.
    pub proxy: PathResult,
}

/// `CheckReport`.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    /// Check id.
    pub id: String,
    /// Harness of a harness run; `null` for the direct run.
    pub harness: Option<HarnessId>,
    /// Results.
    pub results: CheckResults,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The route id is a capability: never in `Debug`.
    #[test]
    fn route_debug_prints_no_route_id() {
        let id = "0123456789abcdef0123456789abcdef";
        let entry = ProxyEntry {
            routes: vec![ProxyRouteEntry {
                upstream: "anthropic".into(),
                base_url: format!("http://127.0.0.1:8787/check/{id}/anthropic"),
            }],
        };
        let d = format!("{entry:?}");
        assert!(!d.contains(id) && !d.contains("/check/"), "{d}");
        assert!(d.contains("anthropic"), "{d}");
    }
}
