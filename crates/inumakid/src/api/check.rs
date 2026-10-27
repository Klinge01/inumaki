//! `/v1/check*` (M6 spec §8, §9.7): control socket only. Path ids are
//! validated (32 lowercase hex) and never logged; bodies use fixed messages.
//!
//! Every handler runs its runner call on its own task ([`detached`]): hyper
//! drops a handler's future when the client disconnects, and a prepare or a
//! removal cancelled half way would leave a `check-` dataset with the seeded
//! canary, a running canary upstream, and a `check:` token behind until the
//! next start. A prepare that finishes after its caller left becomes the
//! live check and expires with its TTL.

use std::future::Future;
use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::api::ApiError;
use crate::check::runner;
use crate::check::types::{CheckCreate, CheckCreated, CheckHarnessBody, CheckReport};
use crate::state::AppState;

/// Run `fut` to completion on its own task, whether or not the caller waits.
async fn detached<T: Send + 'static>(
    fut: impl Future<Output = Result<T, ApiError>> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::spawn(fut)
        .await
        .unwrap_or_else(|_| Err(ApiError::internal("check worker failed")))
}

/// `POST /v1/check` → 201, `409` while one is live. An empty body is `{}`.
pub async fn create(
    State(state): State<Arc<AppState>>,
    body: Result<Json<CheckCreate>, JsonRejection>,
) -> Result<(StatusCode, Json<CheckCreated>), ApiError> {
    let b = match body {
        Ok(Json(b)) => b,
        Err(JsonRejection::MissingJsonContentType(_)) => CheckCreate::default(),
        Err(e) => return Err(e.into()),
    };
    let created = detached(async move { runner::prepare(&state, b).await }).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

/// `POST /v1/check/{id}/direct`.
pub async fn direct(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<CheckReport>, ApiError> {
    Ok(Json(
        detached(async move { runner::direct(&state, &id).await }).await?,
    ))
}

/// `POST /v1/check/{id}/harness`.
pub async fn harness(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Result<Json<CheckHarnessBody>, JsonRejection>,
) -> Result<Json<CheckReport>, ApiError> {
    let Json(b) = body?;
    Ok(Json(
        detached(async move { runner::harness(&state, &id, b).await }).await?,
    ))
}

/// `GET /v1/check/{id}`.
pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<CheckReport>, ApiError> {
    Ok(Json(
        detached(async move { runner::report(&state, &id).await }).await?,
    ))
}

/// `DELETE /v1/check/{id}` → 204.
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    detached(async move { runner::remove(&state, &id).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}
