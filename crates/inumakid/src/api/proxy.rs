//! `GET /v1/proxy` (M6 spec §9.6 with the M8 amendment). Control socket only.
//!
//! The body carries the per-install `X-Inumaki-Client` value, as sensitive as
//! a gateway token; it is never logged and the body type has no `Debug`.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;

use super::ApiError;
use crate::state::AppState;

/// The proxy's state, counters, and the client header for adapters.
pub async fn status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<inumaki_proxy::status::ProxyStatusBody>, ApiError> {
    let p = state
        .proxy
        .get()
        .ok_or_else(|| ApiError::internal("proxy not started"))?;
    Ok(Json(p.status()))
}
