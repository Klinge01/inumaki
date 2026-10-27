//! `POST /v1/rehydrate`.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use inumaki_core::rehydrate::RehydrateError;
use inumaki_core::token::ContextId;
use serde::{Deserialize, Serialize};

use super::{ApiError, blocking};
use crate::state::AppState;

/// Request body. `Debug` prints lengths only.
#[derive(Deserialize)]
pub struct RehydrateRequest {
    /// Dataset id.
    pub dataset: Option<String>,
    /// Session id.
    pub session: Option<String>,
    /// Text with tokens.
    pub text: String,
    /// Fail with `unresolved_token` instead of leaving placeholders (M4 spec §8).
    #[serde(default)]
    pub strict: bool,
}

impl std::fmt::Debug for RehydrateRequest {
    /// `dataset` is a user-chosen slug (M4 spec §5.4) and is not printed;
    /// only whether it was set.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RehydrateRequest")
            .field("dataset", &self.dataset.as_ref().map(|_| "…"))
            .field("text_len", &self.text.len())
            .field("strict", &self.strict)
            .finish()
    }
}

/// Response body.
#[derive(Serialize)]
pub struct RehydrateResponse {
    /// Rehydrated text.
    pub text: String,
    /// Tokens left as-is because the store does not know them.
    pub unknown_tokens: usize,
    /// Removed-value markers left as-is (permissive mode).
    pub removed_markers: usize,
}

/// Handler.
pub async fn rehydrate(
    State(state): State<Arc<AppState>>,
    body: Result<Json<RehydrateRequest>, JsonRejection>,
) -> Result<Json<RehydrateResponse>, ApiError> {
    let Json(req) = body?;
    let strict = req.strict;
    let mode = if strict {
        crate::service::RehydrateMode::Strict
    } else {
        crate::service::RehydrateMode::Permissive
    };
    let (text, unknown_tokens, removed_markers) = match (req.dataset, req.session) {
        (Some(dataset), None) => {
            let s = Arc::clone(&state);
            blocking(move || {
                super::datasets::refuse_chat(&s, &dataset)?;
                let mut v = crate::service::rehydrate_blocks(
                    &s,
                    &dataset,
                    vec![crate::service::BlockInput::text(req.text)],
                    mode,
                )?;
                let r = v.pop().expect("one block in, one block out");
                Ok((r.text, r.unknown_tokens, r.removed_markers))
            })
            .await?
        }
        (None, Some(session)) => {
            let s = Arc::clone(&state);
            blocking(move || {
                // Never `get_or_create`: a missing or expired session is an
                // error, not a fresh empty context (M4 spec §5.3, §8).
                let mut ctx = s
                    .sessions
                    .get(&ContextId(session))
                    .ok_or_else(ApiError::context_unavailable)?;
                match mode {
                    crate::service::RehydrateMode::Strict => {
                        let text = s
                            .session_rehydrator
                            .rehydrate_strict(&req.text, &mut *ctx)
                            .map_err(|e| match e {
                                RehydrateError::Unresolved { unknown, removed } => {
                                    ApiError::unresolved(unknown, removed)
                                }
                                RehydrateError::Store(st) => ApiError::from(st),
                            })?;
                        Ok((text, 0, 0))
                    }
                    crate::service::RehydrateMode::Permissive => {
                        let removed = s
                            .session_rehydrator
                            .tokens_in(&req.text)
                            .iter()
                            .filter(|t| t.contains("_REMOVED"))
                            .count();
                        let (text, unknown) = s.session_rehydrator.rehydrate(&req.text, &*ctx);
                        Ok((text, unknown, removed))
                    }
                }
            })
            .await?
        }
        _ => {
            return Err(ApiError::bad_request(
                "exactly one of dataset or session is required",
            ));
        }
    };
    tracing::info!(unknown_tokens, removed_markers, strict, "rehydrated");
    Ok(Json(RehydrateResponse {
        text,
        unknown_tokens,
        removed_markers,
    }))
}
