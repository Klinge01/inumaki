//! `GET /v1/proxy` (M6 spec §9.6, M8). Nothing here is user data: the
//! User-Agent is reduced to a closed client enum by the daemon.

use serde::{Deserialize, Serialize};

/// Proxy listener state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyState {
    /// Serving.
    Running,
    /// Disabled.
    Disabled,
    /// The listener could not bind, or stopped serving.
    BindFailed,
}

impl ProxyState {
    /// Why a proxy in this state owns no address a harness may be pointed
    /// at, as fixed text; `None` while it is serving. A base URL written for
    /// a proxy that is not running sends the conversation and the harness's
    /// credentials to whatever holds the address. No port, PID or process
    /// name is ever part of the text.
    pub const fn chat_route_blocker(self) -> Option<&'static str> {
        match self {
            ProxyState::Running => None,
            ProxyState::Disabled => Some("disabled"),
            ProxyState::BindFailed => Some("not listening"),
        }
    }

    /// The fixed sentence shown (CLI warning, app note) when the default
    /// apply skips the chat route because the proxy is not running.
    pub const fn chat_route_skipped(self) -> Option<&'static str> {
        match self {
            ProxyState::Running => None,
            ProxyState::Disabled => Some("the proxy is disabled; the chat route is skipped"),
            ProxyState::BindFailed => Some("the proxy is not listening; the chat route is skipped"),
        }
    }

    /// The fixed sentence shown when the end-to-end check does not run its
    /// harnesses because the proxy is not running: the check's proxy URLs
    /// would send the test conversation and the harness's credentials to
    /// whatever holds the address. No port, PID or process name.
    pub const fn check_route_skipped(self) -> Option<&'static str> {
        match self {
            ProxyState::Running => None,
            ProxyState::Disabled => {
                Some("the proxy is disabled; the harness chat check is skipped")
            }
            ProxyState::BindFailed => {
                Some("the proxy is not listening; the harness chat check is skipped")
            }
        }
    }
}

/// Route prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutePrefix {
    /// Anthropic Messages.
    #[serde(rename = "/anthropic")]
    Anthropic,
    /// OpenAI Responses and Chat Completions.
    #[serde(rename = "/openai")]
    Openai,
    /// Codex backend.
    #[serde(rename = "/codex")]
    Codex,
}

/// Route upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyUpstream {
    /// `anthropic`.
    #[serde(rename = "anthropic")]
    Anthropic,
    /// `openai`.
    #[serde(rename = "openai")]
    Openai,
    /// `openai-codex`.
    #[serde(rename = "openai-codex")]
    OpenaiCodex,
}

/// Route state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteState {
    /// Recent requests succeeded.
    Ok,
    /// No traffic yet.
    Idle,
    /// Recent requests failed.
    Failing,
}

/// Proxy error class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyError {
    /// Upstream unreachable.
    UpstreamUnreachable,
    /// Upstream refused the credential.
    UpstreamAuth,
    /// Upstream rate limit.
    UpstreamRateLimited,
    /// Upstream 5xx.
    #[serde(rename = "upstream_5xx")]
    Upstream5xx,
    /// Blocked by verification.
    PrivacyBlock,
    /// A resource limit.
    ResourceLimit,
    /// Stream aborted.
    StreamAborted,
    /// Bad request.
    BadRequest,
    /// Anything else.
    Internal,
}

/// Last error of a route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteError {
    /// Class.
    pub class: ProxyError,
    /// Upstream HTTP status.
    pub status: Option<u64>,
    /// Unix seconds.
    pub at: i64,
}

/// One route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRoute {
    /// Prefix.
    pub prefix: RoutePrefix,
    /// Upstream.
    pub upstream: ProxyUpstream,
    /// Root a harness is configured with.
    pub base_url: String,
    /// Served paths, relative to `base_url`.
    pub paths: Vec<String>,
    /// State.
    pub state: RouteState,
    /// Requests.
    pub requests: u64,
    /// Blocked.
    pub blocked: u64,
    /// Uncertain.
    pub uncertain: u64,
    /// Last request.
    pub last_request_at: Option<i64>,
    /// Last error.
    pub last_error: Option<RouteError>,
}

/// Client kind, from the User-Agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// Claude Code.
    ClaudeCode,
    /// Codex.
    Codex,
    /// Hermes.
    Hermes,
    /// OpenClaw.
    Openclaw,
    /// Anything else.
    Other,
}

/// Traffic per client kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyClient {
    /// Client.
    pub client: ClientKind,
    /// Requests.
    pub requests: u64,
    /// Last request.
    pub last_at: i64,
}

/// Anthropic subscription traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicOauth {
    /// Requests.
    pub requests: u64,
    /// Translated requests.
    pub translated: u64,
    /// Last error.
    pub last_error: Option<ProxyError>,
}

/// Codex ChatGPT-login traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodexChatgpt {
    /// M8's verification passed in this build.
    pub verified_in_build: bool,
    /// Requests.
    pub requests: u64,
    /// Last success.
    pub last_ok_at: Option<i64>,
    /// Last error.
    pub last_error: Option<ProxyError>,
}

/// OAuth traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyOauth {
    /// Anthropic.
    pub anthropic: AnthropicOauth,
    /// Codex ChatGPT login.
    pub codex_chatgpt: CodexChatgpt,
}

/// Incremental sanitization cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalCache {
    /// Hits.
    pub hits: u64,
    /// Misses.
    pub misses: u64,
    /// Entries.
    pub entries: u64,
}

/// The per-install client header adapters write into a harness's chat
/// configuration (M6 spec §4.3 amendment). The value is as sensitive as a
/// gateway token: `Debug` prints the name only.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientHeaderBody {
    /// Header name (`X-Inumaki-Client`).
    pub name: String,
    /// Header value.
    pub value: String,
}

impl std::fmt::Debug for ClientHeaderBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHeaderBody")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// One request's local and provider time, in whole milliseconds (M6 spec
/// §9.6 amendment 2026-10-12). Durations only; `provider_ms` and
/// `first_byte_ms` are `null` for a request that was not forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyTiming {
    /// Arrival to the end of the response.
    pub total_ms: u64,
    /// Read, queue, scan, engine, closure and restore.
    pub local_ms: u64,
    /// The upstream's time, without the proxy's own restore work.
    pub provider_ms: Option<u64>,
    /// Send to the upstream's response headers.
    pub first_byte_ms: Option<u64>,
    /// Reading and decoding the body.
    pub read_ms: u64,
    /// Blocking-pool wait.
    pub queue_ms: u64,
    /// Walk, session, cache lookups and edits.
    pub scan_ms: u64,
    /// Detection, policy, sanitize and verification.
    pub engine_ms: u64,
    /// Closure projection (step 6b).
    pub closure_ms: u64,
    /// The projections inside `closure_ms`.
    pub project_ms: u64,
    /// Answer-side local work.
    pub restore_ms: u64,
}

/// The `timing` object of `GET /v1/proxy`: the latest sample and its
/// nearest-rank percentiles over the last `window` samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProxyTimingSummary {
    /// Samples held, at most 64.
    pub window: u64,
    /// Unix seconds of the latest sample.
    pub last_at: Option<i64>,
    /// The latest sample.
    pub last: Option<ProxyTiming>,
    /// Median per field.
    pub p50: Option<ProxyTiming>,
    /// 95th percentile per field.
    pub p95: Option<ProxyTiming>,
}

/// The cross-session static-prompt NER cache's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StaticCacheBody {
    /// On in the configuration and the daemon provides a memo.
    pub enabled: bool,
    /// Eligible NER calls answered from the cache.
    pub hits: u64,
    /// Eligible NER calls that ran the model.
    pub misses: u64,
    /// Entries held.
    pub entries: u64,
    /// Clears caused by a change of the datasets the proxy sees.
    pub clears: u64,
}

/// `GET /v1/proxy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyBody {
    /// Enabled (status only).
    pub enabled: bool,
    /// Listen address.
    pub listen: String,
    /// State.
    pub state: ProxyState,
    /// Routes.
    pub routes: Vec<ProxyRoute>,
    /// Clients seen.
    pub clients: Vec<ProxyClient>,
    /// OAuth traffic.
    pub oauth: ProxyOauth,
    /// Live sessions.
    pub sessions: u64,
    /// Incremental cache.
    pub incremental_cache: IncrementalCache,
    /// Live check routes.
    pub check_routes: u64,
    /// The client header to write into harness chat configuration.
    pub client_header: ClientHeaderBody,
    /// Where each request's time goes. Absent from a daemon older than the
    /// 2026-10-12 amendment.
    #[serde(default)]
    pub timing: ProxyTimingSummary,
    /// The static-prompt cache. Absent from a daemon older than the
    /// 2026-10-12 amendment.
    #[serde(default)]
    pub static_cache: StaticCacheBody,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::fixture;

    /// A daemon from before the 2026-10-12 amendment sends neither object:
    /// the body still decodes, with an empty window and a disabled cache.
    #[test]
    fn a_body_without_timing_and_static_cache_still_decodes() {
        let mut v: serde_json::Value = serde_json::from_str(fixture("proxy")).unwrap();
        let o = v.as_object_mut().unwrap();
        assert!(o.remove("timing").is_some() && o.remove("static_cache").is_some());
        let b: ProxyBody = serde_json::from_value(v).expect("an older daemon's body decodes");
        assert_eq!(b.timing, ProxyTimingSummary::default());
        assert_eq!(b.timing.window, 0);
        assert_eq!(b.static_cache, StaticCacheBody::default());
        assert!(!b.static_cache.enabled);
    }

    /// The fixture's samples: `last`, `p50` and `p95` are set, and the p95
    /// has one `null` provider time.
    #[test]
    fn the_fixture_carries_the_split_with_one_null_provider() {
        let b: ProxyBody = serde_json::from_str(fixture("proxy")).unwrap();
        assert!(b.timing.last.is_some() && b.timing.p50.is_some());
        assert_eq!(b.timing.p95.unwrap().provider_ms, None);
        assert!(b.static_cache.enabled);
    }
}
