//! `GET /v1/datasets/{id}/journal` and `GET /v1/datasets/{id}/journal/{record}`
//! (M4 spec §16.3), control socket only. The listing is metadata; `show`
//! returns the released payload as sent (tokens) and, with
//! `show_values=true`, rehydrated locally for the user who asked. Nothing
//! from a payload, no dataset id, and no query string reaches a log line
//! or an error body.
//!
//! A rehydrated payload is the released JSON with tokens replaced as
//! text: an original containing `"` or `\` makes it invalid JSON, so a
//! client shows it as text and never parses it.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use inumaki_vault::{RecordId, valid_dataset_id};
use serde::{Deserialize, Serialize};

use super::{ApiError, blocking};
use crate::service::{BlockInput, RehydrateMode, rehydrate_blocks};
use crate::state::AppState;

/// Label on a payload shown as sent.
pub const JOURNAL_TOKENS_LABEL: &str = "released payload as sent (tokens)";
/// Label on a payload rehydrated for the local user.
pub const JOURNAL_VALUES_LABEL: &str = "originals revealed locally — not for transmission";

/// Listing query.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Only entries at or after this unix time.
    pub since: Option<i64>,
    /// At most this many (newest first); default 100, capped at 10 000.
    pub limit: Option<usize>,
}

/// `show` query.
#[derive(Debug, Deserialize, Default)]
pub struct ShowQuery {
    /// Rehydrate the payload locally.
    #[serde(default)]
    pub show_values: bool,
}

/// One entry in the listing.
#[derive(Debug, Serialize)]
pub struct JournalEntryBody {
    /// Activity record id.
    pub id: String,
    /// Unix seconds.
    pub at: i64,
    /// Payload length.
    pub bytes: u64,
    /// The activity record's digest of the payload.
    pub released: String,
}

/// The `show` body.
#[derive(Serialize)]
pub struct JournalShowBody {
    /// Activity record id.
    pub id: String,
    /// Unix seconds.
    pub at: i64,
    /// Payload length as released.
    pub bytes: u64,
    /// Digest as released.
    pub released: String,
    /// The payload: as sent, or rehydrated when `show_values`.
    pub payload: String,
    /// Whether `payload` carries originals.
    pub show_values: bool,
    /// Placeholders left in place (forgotten, expired, or removed values).
    pub unresolved: usize,
    /// Fixed label.
    pub label: &'static str,
}

impl std::fmt::Debug for JournalShowBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalShowBody")
            .field("bytes", &self.bytes)
            .field("show_values", &self.show_values)
            .field("unresolved", &self.unresolved)
            .finish()
    }
}

/// A dataset id the vault can hold, checked before any lookup (fixed 400).
pub(super) fn check_dataset(id: &str) -> Result<(), ApiError> {
    if valid_dataset_id(id) {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "dataset id must match [a-z0-9-]{1,64}",
        ))
    }
}

/// `GET /v1/datasets/{id}/journal?since=&limit=`: `{entries: [{id, at,
/// bytes, released}]}`, newest first. A malformed query is a fixed `400`.
pub async fn list(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    q: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Ok(Query(q)) = q else {
        return Err(ApiError::bad_request(
            "query must be since=SECONDS, limit=N",
        ));
    };
    check_dataset(&id)?;
    let entries = blocking(move || {
        state
            .vault
            .journal(&id, q.since, q.limit.unwrap_or(100))
            .map_err(ApiError::from)
    })
    .await?;
    tracing::info!(entries = entries.len(), "journal listed");
    let entries: Vec<JournalEntryBody> = entries
        .into_iter()
        .map(|e| JournalEntryBody {
            id: e.id.as_str().to_string(),
            at: e.at,
            bytes: e.bytes,
            released: e.released.as_str().to_string(),
        })
        .collect();
    Ok(Json(serde_json::json!({ "entries": entries })))
}

/// `GET /v1/datasets/{id}/journal/{record}?show_values=`: one entry with
/// its payload, opened and checked against the record's digest (a failed
/// check is a fixed `500 journal_record`, never content).
pub async fn show(
    State(state): State<Arc<AppState>>,
    Path((id, record)): Path<(String, String)>,
    q: Result<Query<ShowQuery>, QueryRejection>,
) -> Result<Json<JournalShowBody>, ApiError> {
    let Ok(Query(q)) = q else {
        return Err(ApiError::bad_request(
            "the show_values query parameter must be true or false",
        ));
    };
    check_dataset(&id)?;
    let record = RecordId::try_from(record)
        .map_err(|_| ApiError::bad_request("record id must be 32 lowercase hex characters"))?;
    let show_values = q.show_values;
    let body = blocking(move || {
        let (entry, payload) = state
            .vault
            .journal_payload(&id, &record)?
            .ok_or_else(|| ApiError::not_found("no journal entry with that id in this dataset"))?;
        let text = String::from_utf8_lossy(&payload).into_owned();
        let (payload, unresolved) =
            if show_values && state.vault.dataset_kind(&id)? == inumaki_vault::DatasetKind::Chat {
                // M8 spec §9: dataset tokens through their namespaces; session
                // tokens show as unresolved.
                crate::chat::reveal(&state, &text)
            } else if show_values {
                let mut out = rehydrate_blocks(
                    &state,
                    &id,
                    vec![BlockInput::text(text)],
                    RehydrateMode::Permissive,
                )?;
                let r = out
                    .pop()
                    .ok_or_else(|| ApiError::internal("empty rehydration"))?;
                (r.text, r.unknown_tokens + r.removed_markers)
            } else {
                (text, 0)
            };
        Ok(JournalShowBody {
            id: entry.id.as_str().to_string(),
            at: entry.at,
            bytes: entry.bytes,
            released: entry.released.as_str().to_string(),
            payload,
            show_values,
            unresolved,
            label: if show_values {
                JOURNAL_VALUES_LABEL
            } else {
                JOURNAL_TOKENS_LABEL
            },
        })
    })
    .await?;
    tracing::info!(
        reveal = show_values,
        bytes = body.bytes,
        unresolved = body.unresolved,
        "journal entry shown"
    );
    Ok(Json(body))
}
