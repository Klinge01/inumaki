//! `POST /v1/sanitize` (spec §10.3, §6, §12).

use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use inumaki_core::engine::normalize_input;
use inumaki_core::redact::{RedactionFile, validate_redactions};
use inumaki_core::token::ContextId;
use serde::{Deserialize, Serialize};

use super::{ApiError, blocking};
use crate::cache::CachedOutcome;
use crate::service::{BlockInput, BlockResult, FieldHint};
use crate::state::AppState;

/// Request body. `Debug` prints lengths only.
#[derive(Deserialize)]
pub struct SanitizeRequest {
    /// Dataset id (namespace); exactly one of `dataset`/`session`.
    pub dataset: Option<String>,
    /// Session id; exactly one of `dataset`/`session`.
    pub session: Option<String>,
    /// Profile; defaults to the dataset's profile or `[daemon] default_profile`.
    pub profile: Option<String>,
    /// The text.
    pub text: String,
    /// Mandatory transformations to apply before verification (M4 spec §9.1).
    pub redactions: Option<RedactionFile>,
}

impl std::fmt::Debug for SanitizeRequest {
    /// `dataset` is a user-chosen slug (M4 spec §5.4) and is not printed;
    /// only whether it was set.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanitizeRequest")
            .field("dataset", &self.dataset.as_ref().map(|_| "…"))
            .field("session", &self.session.as_ref().map(|_| "…"))
            .field("profile", &self.profile)
            .field("text_len", &self.text.len())
            .field(
                "redactions",
                &self.redactions.as_ref().map(|r| r.spans.len()),
            )
            .finish()
    }
}

/// One reason in the response.
#[derive(Debug, Serialize)]
pub struct ReasonBody {
    /// Kind label.
    pub kind: String,
    /// Check id.
    pub check: String,
}

/// Response body for `pass` and `pass_uncertain`.
#[derive(Serialize)]
pub struct SanitizeResponse {
    /// `pass` or `pass_uncertain`.
    pub outcome: CachedOutcome,
    /// Sanitized text.
    pub text: String,
    /// Replacement count.
    pub replacements: usize,
    /// Kind labels of tokenized or removed spans.
    pub kinds: Vec<String>,
    /// Reasons when uncertain.
    pub reasons: Vec<ReasonBody>,
    /// Served from the cache.
    pub cached: bool,
    /// Wall time of this request, milliseconds.
    pub latency_ms: f64,
}

impl std::fmt::Debug for SanitizeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanitizeResponse")
            .field("outcome", &self.outcome)
            .field("len", &self.text.len())
            .field("replacements", &self.replacements)
            .field("cached", &self.cached)
            .finish()
    }
}

fn respond(r: BlockResult, t0: Instant) -> Result<Json<SanitizeResponse>, ApiError> {
    let cached = r.cached;
    if r.outcome == CachedOutcome::Blocked {
        tracing::info!(
            kinds = r.kinds.len(),
            checks = r.reasons.len(),
            cached,
            "blocked"
        );
        return Err(ApiError::privacy_block(&r.kinds, &r.reasons));
    }
    tracing::info!(outcome = ?r.outcome, replacements = r.replacements, cached, latency_ms = t0.elapsed().as_millis() as u64, "sanitized");
    Ok(Json(SanitizeResponse {
        outcome: r.outcome,
        text: r.text,
        replacements: r.replacements,
        kinds: r.kinds.iter().map(|k| k.label().to_string()).collect(),
        reasons: r
            .reasons
            .iter()
            .map(|x| ReasonBody {
                kind: x.kind.label().to_string(),
                check: format!("{:?}", x.check),
            })
            .collect(),
        cached,
        latency_ms: (t0.elapsed().as_secs_f64() * 10_000.0).round() / 10.0,
    }))
}

/// Handler.
pub async fn sanitize(
    State(state): State<Arc<AppState>>,
    body: Result<Json<SanitizeRequest>, JsonRejection>,
) -> Result<Json<SanitizeResponse>, ApiError> {
    let Json(req) = body?;
    let t0 = Instant::now();
    let nfc = normalize_input(&req.text).into_owned();
    // Review Focus 8: redactions are validated against the NFC input before
    // anything is transformed, whichever path (dataset or session) dispatches.
    let reds = match &req.redactions {
        Some(f) => {
            validate_redactions(&nfc, f).map_err(|e| ApiError::bad_request(e.to_string()))?
        }
        None => Vec::new(),
    };
    match (req.dataset, req.session) {
        (Some(dataset), None) => sanitize_dataset(state, dataset, req.profile, nfc, reds, t0).await,
        (None, Some(session)) => sanitize_session(state, session, req.profile, nfc, reds, t0).await,
        _ => Err(ApiError::bad_request(
            "exactly one of dataset or session is required",
        )),
    }
}

async fn sanitize_dataset(
    state: Arc<AppState>,
    dataset: String,
    profile: Option<String>,
    text: String,
    redactions: Vec<inumaki_core::redact::Redaction>,
    t0: Instant,
) -> Result<Json<SanitizeResponse>, ApiError> {
    // The service opens the namespace and may load a model: blocking pool only (M3 review I3).
    let result = blocking(move || {
        super::datasets::refuse_chat(&state, &dataset)?;
        let mut v = crate::service::sanitize_blocks(
            &state,
            &dataset,
            profile.as_deref(),
            vec![BlockInput {
                text,
                hint: FieldHint::FreeText,
                redactions,
            }],
        )?;
        Ok(v.pop().expect("one block in, one block out"))
    })
    .await?;
    respond(result, t0)
}

async fn sanitize_session(
    state: Arc<AppState>,
    session: String,
    profile: Option<String>,
    text: String,
    redactions: Vec<inumaki_core::redact::Redaction>,
    t0: Instant,
) -> Result<Json<SanitizeResponse>, ApiError> {
    let profile = profile.unwrap_or_else(|| state.cfg.daemon.default_profile.clone());
    // Fix round 1, finding 1 (service.rs `sanitize_blocks`) applies here
    // too: a session's primary profile is never a metadata profile, since
    // this path never goes through `sanitize_blocks`. Fails closed, no
    // profile name or text in the error.
    if state.engines.core().is_metadata_profile(&profile) {
        return Err(crate::service::ServiceError::Unsupported("metadata_profile").into());
    }
    let s = Arc::clone(&state);
    // `engines.engine` moved into the blocking closure (review I3): it can
    // build detectors or load a model, and must not run on an async worker.
    let result = blocking(move || {
        let engine = s.engines.engine(&profile, None)?;
        let mut ctx = s.sessions.get_or_create(&ContextId(session)).map_err(|e| {
            ApiError::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "session_cap",
                e.to_string(),
            )
        })?;
        let outcome = engine
            .process_with(&text, &mut *ctx, &redactions)
            .map_err(ApiError::from)?;
        Ok(crate::service::block_result(
            crate::service::to_result(outcome),
            false,
        ))
    })
    .await?;
    respond(result, t0)
}
