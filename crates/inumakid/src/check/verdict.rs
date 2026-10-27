//! Evidence → verdict (M6 spec §8.3). Passed when no canary value reached
//! the model side, tokens were seen where the path must tokenize, and the
//! output carried the canary after rehydration. Checked in that order, so
//! a leak is always reported as a leak.

use super::types::{PathReason, PathResult, PathStatus};

/// What one path produced.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    /// Requests or calls on the model side.
    pub upstream_requests: u64,
    /// A canary value was on the model side.
    pub canary_in_upstream: bool,
    /// Tokens were on the model side.
    pub tokens_seen: bool,
    /// The canary came back after rehydration.
    pub rehydrated_in_output: bool,
    /// A step hit its deadline.
    pub timed_out: bool,
    /// The harness exited non-zero or produced nothing.
    pub harness_failed: bool,
    /// Harness runs only: the harness sent nothing through the check route.
    pub chat_not_routed: bool,
}

/// A `not_checked` result.
pub fn not_checked(reason: Option<PathReason>) -> PathResult {
    PathResult {
        status: PathStatus::NotChecked,
        reason,
        upstream_requests: 0,
        canary_in_upstream: false,
        tokens_seen: false,
        rehydrated_in_output: false,
    }
}

/// The verdict for `e`.
pub fn verdict(e: &Evidence) -> PathResult {
    let reason = if e.canary_in_upstream {
        Some(PathReason::CanaryInUpstream)
    } else if e.harness_failed {
        Some(PathReason::HarnessFailed)
    } else if e.timed_out {
        Some(PathReason::Timeout)
    } else if e.chat_not_routed {
        Some(PathReason::ChatNotRouted)
    } else if !e.tokens_seen {
        Some(PathReason::NoTokens)
    } else if !e.rehydrated_in_output {
        Some(PathReason::NotRehydrated)
    } else {
        None
    };
    PathResult {
        status: if reason.is_none() {
            PathStatus::Passed
        } else {
            PathStatus::Failed
        },
        reason,
        upstream_requests: e.upstream_requests,
        canary_in_upstream: e.canary_in_upstream,
        tokens_seen: e.tokens_seen,
        rehydrated_in_output: e.rehydrated_in_output,
    }
}
