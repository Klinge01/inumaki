//! `POST /v1/inspect` (M4 spec §8, §9.1): local diagnostic inspection over
//! the control socket only. Never mounted on the gateway's TCP router.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use inumaki_core::redact::RedactionFile;
use serde::{Deserialize, Serialize};

use super::sanitize::ReasonBody;
use super::{ApiError, blocking};
use crate::cache::CachedOutcome;
use crate::service::{InspectSpan, inspect};
use crate::state::AppState;

/// The fixed label every inspection carries.
pub const DIAGNOSTIC_LABEL: &str = "local diagnostic output — not approved for transmission";

/// Request body. `Debug` prints lengths only.
#[derive(Deserialize)]
pub struct InspectRequest {
    /// Dataset id.
    pub dataset: String,
    /// Profile override.
    pub profile: Option<String>,
    /// The text (extracted locally by the user; never fetched).
    pub text: String,
    /// Optional redactions to apply before verification.
    pub redactions: Option<RedactionFile>,
    /// Include the candidate text and original excerpts.
    #[serde(default)]
    pub show_values: bool,
}

impl std::fmt::Debug for InspectRequest {
    /// `dataset` is a user-chosen slug (M4 spec §5.4) and is not printed;
    /// only whether it was set, the way `SanitizeRequest` does.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectRequest")
            .field("dataset", &"…")
            .field("profile", &self.profile)
            .field("text_len", &self.text.len())
            .field(
                "redactions",
                &self.redactions.as_ref().map(|r| r.spans.len()),
            )
            .field("show_values", &self.show_values)
            .finish()
    }
}

/// Response body.
#[derive(Serialize)]
pub struct InspectBody {
    /// Always [`DIAGNOSTIC_LABEL`].
    pub label: &'static str,
    /// Outcome.
    pub outcome: CachedOutcome,
    /// Profile that settled it.
    pub profile: String,
    /// Settled by the retry profile.
    pub retried: bool,
    /// Spans (NFC byte offsets).
    pub spans: Vec<InspectSpan>,
    /// Document-level reasons.
    pub reasons: Vec<ReasonBody>,
    /// Replacement count.
    pub replacements: usize,
    /// Candidate text; only with `show_values`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<String>,
    /// Known limitations.
    pub limitations: Vec<String>,
    /// Expiry information.
    pub expiry: ExpiryBody,
}

/// When mappings expire.
#[derive(Serialize)]
pub struct ExpiryBody {
    /// Rotation period, days.
    pub rotation_days: u32,
    /// Grace period, days.
    pub grace_days: u32,
    /// Current epoch start, unix seconds.
    pub epoch_started_at: i64,
}

/// Handler.
pub async fn inspect_handler(
    State(state): State<Arc<AppState>>,
    body: Result<Json<InspectRequest>, JsonRejection>,
) -> Result<Json<InspectBody>, ApiError> {
    let Json(req) = body?;
    let i = blocking(move || {
        Ok(inspect(
            &state,
            &req.dataset,
            req.profile.as_deref(),
            &req.text,
            req.redactions.as_ref(),
            req.show_values,
        )?)
    })
    .await?;
    tracing::info!(outcome = ?i.outcome, spans = i.spans.len(), reasons = i.reasons.len(), show_values = i.candidate.is_some(), "inspected");
    Ok(Json(InspectBody {
        label: DIAGNOSTIC_LABEL,
        outcome: i.outcome,
        profile: i.profile,
        retried: i.retried,
        spans: i.spans,
        reasons: i
            .reasons
            .iter()
            .map(|x| ReasonBody {
                kind: x.kind.label().to_string(),
                check: format!("{:?}", x.check),
            })
            .collect(),
        replacements: i.replacements,
        candidate: i.candidate,
        limitations: i.limitations,
        expiry: ExpiryBody {
            rotation_days: i.rotation_days,
            grace_days: i.grace_days,
            epoch_started_at: i.epoch_started_at,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix round 1, finding 1(b): `dataset` is a user-chosen slug (M4 spec
    /// §5.4) and must never appear in `Debug`.
    #[test]
    fn debug_omits_the_dataset_slug() {
        let req = InspectRequest {
            dataset: "qwxzvk-canary-slug".to_string(),
            profile: None,
            text: "Zyxwuria Quolnath".to_string(),
            redactions: None,
            show_values: false,
        };
        let d = format!("{req:?}");
        assert!(!d.contains("qwxzvk"), "{d}");
    }
}
