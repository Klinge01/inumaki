//! Dataset endpoints.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use inumaki_vault::{DatasetKind, DatasetSpec};
use serde::Deserialize;

use super::status::DatasetBody;
use super::{ApiError, blocking};
use crate::folders::{AddError, RemoveDatasetError};
use crate::state::AppState;

/// `POST /v1/datasets` body.
#[derive(Deserialize)]
pub struct CreateBody {
    /// Slug.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Profile; defaults to `[daemon] default_profile`.
    pub profile: Option<String>,
    /// Epoch length; default 30.
    pub rotation_days: Option<u32>,
    /// Grace period; default 7.
    pub grace_days: Option<u32>,
    /// `generic` (default), `mailbox`, or `folder`.
    pub kind: Option<String>,
    /// Not supported; any value (including `false`) is refused.
    pub allow_binary: Option<bool>,
}

impl std::fmt::Debug for CreateBody {
    /// Omits the display name (review M1: it can be a customer name).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateBody")
            .field("id", &self.id)
            .field("name_len", &self.name.len())
            .field("profile", &self.profile)
            .field("rotation_days", &self.rotation_days)
            .field("grace_days", &self.grace_days)
            .field("kind", &self.kind)
            .field("allow_binary", &self.allow_binary)
            .finish()
    }
}

/// Refuse the proxy's reserved chat dataset on endpoints that take a
/// dataset id (M8 spec §9). Fixed message: no slug in the error. Blocking
/// pool only; a missing dataset keeps its usual not-found error.
pub(crate) fn refuse_chat(state: &AppState, id: &str) -> Result<(), ApiError> {
    if state.vault.dataset_kind(id)? == DatasetKind::Chat {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "reserved",
            "the chat dataset cannot be used here",
        ));
    }
    Ok(())
}

/// `GET /v1/datasets`.
pub async fn list(State(state): State<Arc<AppState>>) -> Result<Json<Vec<DatasetBody>>, ApiError> {
    let s = Arc::clone(&state);
    let datasets = blocking(move || Ok(s.vault.datasets()?)).await?;
    Ok(Json(
        datasets
            .into_iter()
            .map(|d| DatasetBody::new(d, &state.vault))
            .collect(),
    ))
}

/// `POST /v1/datasets` → 201.
pub async fn create(
    State(state): State<Arc<AppState>>,
    internal: Option<axum::Extension<crate::check::Internal>>,
    body: Result<Json<CreateBody>, JsonRejection>,
) -> Result<(StatusCode, Json<DatasetBody>), ApiError> {
    let Json(b) = body?;
    // M8 spec §9: the proxy owns `inumaki-` ids and the `chat` kind.
    if b.id.starts_with(inumaki_vault::RESERVED_PREFIX) || b.kind.as_deref() == Some("chat") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "reserved",
            "dataset ids starting with inumaki- and the kind chat are reserved",
        ));
    }
    // M6 spec §8.4: `check-` ids belong to the end-to-end check.
    if internal.is_none() && b.id.starts_with(crate::check::CHECK_PREFIX) {
        return Err(ApiError::bad_request(
            "dataset ids starting with check- are reserved",
        ));
    }
    let profile = b
        .profile
        .unwrap_or_else(|| state.cfg.daemon.default_profile.clone());
    state
        .engines
        .core()
        .resolve_dataset_profile(&profile)
        .map_err(|_| ApiError::bad_request(format!("unknown profile {profile}")))?;
    if b.allow_binary.is_some() {
        return Err(ApiError::bad_request("allow_binary is not supported"));
    }
    let kind = match b.kind.as_deref() {
        None => DatasetKind::Generic,
        Some(k) => DatasetKind::parse(k)
            .ok_or_else(|| ApiError::bad_request("kind must be generic, mailbox, or folder"))?,
    };
    let mut spec = DatasetSpec::new(&b.id, &b.name, &profile);
    spec.kind = kind;
    if let Some(r) = b.rotation_days {
        spec.rotation_days = r;
    }
    if let Some(g) = b.grace_days {
        spec.grace_days = g;
    }
    let s = Arc::clone(&state);
    let d = blocking(move || Ok(s.vault.create_dataset(&spec)?)).await?;
    state.gateway_reload(&d.id).await;
    Ok((StatusCode::CREATED, Json(DatasetBody::new(d, &state.vault))))
}

/// `DELETE /v1/datasets/{id}` → 204.
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if id == inumaki_vault::CHAT_DATASET {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "reserved",
            "the chat dataset is managed by the proxy",
        ));
    }
    // M5 spec §11: a folder dataset loses its folder (watchers, mirror
    // tree, manifest) and then the dataset, under one hold of the folders
    // mutex; the dataset stays when the folder cannot be removed.
    let (s, dataset) = (Arc::clone(&state), id.clone());
    blocking(move || match s.mirror.get() {
        Some(f) => f.remove_dataset(&s, &dataset).map_err(|e| match e {
            RemoveDatasetError::Folder(AddError::Mirror(inumaki_mirror::FolderError::Busy)) => {
                super::folders::busy()
            }
            RemoveDatasetError::Folder(e) => {
                // Only a fixed class is logged: the error wraps paths and ids.
                let class = match e {
                    AddError::Vault(_) => "vault",
                    AddError::Mirror(e) => e.as_str(),
                    _ => "folder",
                };
                tracing::warn!(class, "folder removal failed");
                ApiError::internal("folder removal failed")
            }
            RemoveDatasetError::Dataset(e) => e.into(),
        }),
        None => Ok(s.delete_dataset(&dataset)?),
    })
    .await?;
    state.gateway_remove(&id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/datasets/{id}/rotate`.
pub async fn rotate(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rot = blocking(move || {
        // M8 spec §9: the proxy manages the chat dataset.
        refuse_chat(&state, &id)?;
        Ok(state.rotate_dataset(&id)?)
    })
    .await?;
    Ok(Json(serde_json::json!({
        "dataset": rot.dataset_id,
        "old_epoch": rot.old_epoch,
        "new_epoch": rot.new_epoch,
        "epoch_started_at": rot.started_at,
    })))
}
