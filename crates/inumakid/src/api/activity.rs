//! `GET /v1/activity` and `GET /v1/activity/verify` (M4 spec §16.4),
//! control socket only. Records carry opaque labels; this endpoint maps
//! dataset labels back to local dataset ids for the local user.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use inumaki_vault::{ActivityFilter, valid_dataset_id};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ApiError, blocking};
use crate::state::AppState;

/// Query of `GET /v1/activity`. No `Debug`: the dataset id is user-chosen.
#[derive(Deserialize)]
pub struct ActivityQuery {
    /// Only this dataset (its local id).
    pub dataset: Option<String>,
    /// Only records at or after this time (unix seconds).
    pub since: Option<i64>,
    /// At most this many, newest first (default 100, capped at 10 000).
    pub limit: Option<usize>,
}

/// `GET /v1/activity?dataset=&since=&limit=`: records newest first, each
/// dataset label replaced by the local id when the dataset still exists.
/// A malformed query is `400` with a fixed message (never the value).
pub async fn list(
    State(state): State<Arc<AppState>>,
    q: Result<Query<ActivityQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Ok(Query(q)) = q else {
        return Err(ApiError::bad_request(
            "query must be dataset=ID, since=SECONDS, limit=N",
        ));
    };
    if q.dataset.as_deref().is_some_and(|d| !valid_dataset_id(d)) {
        return Err(ApiError::bad_request(
            "dataset id must match [a-z0-9-]{1,64}",
        ));
    }
    let s = Arc::clone(&state);
    let (records, datasets) = blocking(move || {
        let filter = ActivityFilter {
            dataset: q.dataset.as_deref().map(|d| s.vault.opaque_ref(d)),
            since: q.since,
            limit: q.limit.unwrap_or(100),
        };
        Ok((s.vault.activity(&filter)?, s.vault.datasets()?))
    })
    .await?;
    let names: HashMap<String, String> = datasets
        .into_iter()
        .map(|d| (state.vault.opaque_id(&d.id), d.id))
        .collect();
    let records: Vec<Value> = records
        .into_iter()
        .map(|r| {
            let mut v = serde_json::to_value(&r).unwrap_or(Value::Null);
            if let Some(id) = names.get(r.dataset.as_str()) {
                v["dataset"] = Value::String(id.clone());
            }
            v
        })
        .collect();
    Ok(Json(json!({ "records": records })))
}

/// `GET /v1/activity/verify`: recompute the record chain from the oldest
/// kept row; `{records, ok}` or a `500` naming the first bad row.
pub async fn verify(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let s = Arc::clone(&state);
    let n = blocking(move || Ok(s.vault.verify_activity_chain()?)).await?;
    Ok(Json(json!({ "records": n, "ok": true })))
}
