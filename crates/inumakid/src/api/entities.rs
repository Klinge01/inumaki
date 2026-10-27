//! `GET /v1/datasets/{id}/entities`, `DELETE /v1/datasets/{id}/entities/{token}`,
//! `POST /v1/datasets/{id}/entities/forget` (M4 spec §16.3), control socket
//! only. Originals appear in a response only with `show_values=true`; the
//! value in a forget body is never logged or echoed. Log lines carry
//! counts only: no dataset id, token, value, or query string.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use inumaki_vault::{EntityInfo, Forgotten};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::journal::check_dataset;
use super::{ApiError, blocking};
use crate::state::{AppState, ForgetTarget};

/// Listing query.
#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    /// Include the originals.
    #[serde(default)]
    pub show_values: bool,
    /// At most this many (most recently used first); default 1 000.
    pub limit: Option<usize>,
}

/// One entity. `Debug` prints no token or value.
#[derive(Serialize)]
pub struct EntityBody {
    /// The token.
    pub token: String,
    /// Kind label.
    pub kind: String,
    /// Mint time, unix seconds.
    pub first_use: i64,
    /// Last store use, unix seconds.
    pub last_use: i64,
    /// Store-level uses.
    pub uses: u64,
    /// Epoch row id.
    pub epoch_id: i64,
    /// The epoch is the current one.
    pub current_epoch: bool,
    /// Surface-form rows of the entity (other spellings, bare parts, alias variants).
    pub surface_forms: usize,
    /// The original, only with `show_values`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
}

impl std::fmt::Debug for EntityBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityBody")
            .field("kind", &self.kind)
            .field("uses", &self.uses)
            .field("has_original", &self.original.is_some())
            .finish()
    }
}

impl From<EntityInfo> for EntityBody {
    fn from(e: EntityInfo) -> Self {
        EntityBody {
            token: e.token,
            kind: e.kind.label().to_string(),
            first_use: e.first_use,
            last_use: e.last_use,
            uses: e.uses,
            epoch_id: e.epoch_id,
            current_epoch: e.current_epoch,
            surface_forms: e.surface_forms,
            original: e.original.map(|z| z.to_string()),
        }
    }
}

/// `POST …/forget` body. `Debug` prints the length only.
#[derive(Deserialize)]
pub struct ForgetBody {
    /// The original to forget.
    pub value: String,
}

impl std::fmt::Debug for ForgetBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgetBody")
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// What a forget removed.
#[derive(Debug, Serialize)]
pub struct ForgottenBody {
    /// Kind labels of the removed mappings.
    pub kinds: Vec<String>,
    /// Tokens that pointed at the entity, across epochs.
    pub tokens: usize,
    /// Rows deleted.
    pub rows: usize,
}

impl From<Forgotten> for ForgottenBody {
    fn from(f: Forgotten) -> Self {
        ForgottenBody {
            kinds: f.kinds.iter().map(|k| k.label().to_string()).collect(),
            tokens: f.tokens.len(),
            rows: f.rows,
        }
    }
}

/// `GET /v1/datasets/{id}/entities?show_values=&limit=`: `{entities:
/// [{token, kind, first_use, last_use, uses, epoch_id, current_epoch,
/// original?}]}`, most recently used first. A malformed query is a fixed
/// `400`.
pub async fn list(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    q: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Ok(Query(q)) = q else {
        return Err(ApiError::bad_request(
            "query must be show_values (true or false) and limit (a number)",
        ));
    };
    check_dataset(&id)?;
    let show_values = q.show_values;
    let rows = blocking(move || {
        state
            .vault
            .entities(&id, q.limit.unwrap_or(1_000), show_values)
            .map_err(ApiError::from)
    })
    .await?;
    tracing::info!(
        entities = rows.len(),
        reveal = show_values,
        "entities listed"
    );
    let entities: Vec<EntityBody> = rows.into_iter().map(EntityBody::from).collect();
    Ok(Json(serde_json::json!({ "entities": entities })))
}

/// `DELETE /v1/datasets/{id}/entities/{token}` → 200 `{kinds, tokens,
/// rows}`; `404 not_found` when no entity has that token.
pub async fn forget_token(
    State(state): State<Arc<AppState>>,
    Path((id, token)): Path<(String, String)>,
) -> Result<Json<ForgottenBody>, ApiError> {
    check_dataset(&id)?;
    let f = blocking(move || {
        super::datasets::refuse_chat(&state, &id)?;
        state
            .forget_entity(&id, &ForgetTarget::Token(token))
            .map_err(ApiError::from)
    })
    .await?;
    Ok(Json(ForgottenBody::from(f)))
}

/// `POST /v1/datasets/{id}/entities/forget` `{value}` → 200 `{kinds,
/// tokens, rows}`; `404 not_found` when the value is unknown; `400` for an
/// empty value or a malformed body (fixed messages, the value is never
/// echoed).
pub async fn forget_value(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Result<Json<ForgetBody>, JsonRejection>,
) -> Result<Json<ForgottenBody>, ApiError> {
    let Json(b) = body?;
    let value = Zeroizing::new(b.value);
    if value.trim().is_empty() {
        return Err(ApiError::bad_request("value must not be empty"));
    }
    check_dataset(&id)?;
    let f = blocking(move || {
        super::datasets::refuse_chat(&state, &id)?;
        state
            .forget_entity(&id, &ForgetTarget::Value(value))
            .map_err(ApiError::from)
    })
    .await?;
    Ok(Json(ForgottenBody::from(f)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_no_token_or_value() {
        let b: ForgetBody = serde_json::from_str(r#"{"value":"Zyxwuria Quolnath"}"#).unwrap();
        assert_eq!(format!("{b:?}"), "ForgetBody { value_len: 17 }");
        let e = EntityBody {
            token: "<PERSON_abc123>".into(),
            kind: "PERSON".into(),
            first_use: 1,
            last_use: 2,
            uses: 3,
            epoch_id: 4,
            current_epoch: true,
            surface_forms: 0,
            original: Some("Zyxwuria Quolnath".into()),
        };
        let d = format!("{e:?}");
        assert!(!d.contains("abc123") && !d.contains("Zyxwuria"), "{d}");
    }
}
