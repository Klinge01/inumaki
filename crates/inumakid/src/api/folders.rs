//! Folder endpoints (M5 spec §12; M6 spec §9.5 as amended). Control socket
//! only. Bodies serialize from structs in the client's field order
//! (`inumaki_client::{FolderBody, FoldersBody, RescanBody}`); every error
//! body is one of the fixed messages of spec §12.3, never a path or a slug.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use inumaki_mirror::FolderError;
use inumaki_vault::VaultError;
use serde::{Deserialize, Serialize};

use super::blocking;
use super::error::ApiError;
use crate::folders::{AddError, FolderInfo, Folders};
use crate::state::AppState;

/// `POST /v1/datasets/{id}/folder` body. No `Debug` of the paths.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFolder {
    source: String,
    outbox_destination: Option<String>,
}

impl std::fmt::Debug for CreateFolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CreateFolder")
    }
}

/// `inumaki_client::FolderBody`. No `Debug`: it carries paths.
#[derive(Serialize)]
pub struct FolderBody {
    dataset: String,
    label: String,
    source: String,
    mirror: String,
    outbox: String,
    outbox_destination: String,
    created_at: i64,
}

impl From<FolderInfo> for FolderBody {
    fn from(i: FolderInfo) -> Self {
        FolderBody {
            dataset: i.dataset,
            label: i.label,
            source: i.source,
            mirror: i.mirror,
            outbox: i.outbox,
            outbox_destination: i.outbox_destination,
            created_at: i.created_at,
        }
    }
}

#[derive(Serialize)]
struct Files {
    source: u64,
    mirrored: u64,
    blocked: u64,
    unsupported: u64,
    pending: u64,
}

#[derive(Serialize)]
struct OutboxFiles {
    rehydrated: u64,
    with_unresolved: u64,
    pending: u64,
}

/// `inumaki_client::FolderStatus`.
#[derive(Serialize)]
struct FolderStatus {
    dataset: String,
    label: String,
    source: String,
    mirror: String,
    outbox: String,
    outbox_destination: String,
    state: &'static str,
    error: Option<&'static str>,
    files: Files,
    last_mirrored_at: Option<i64>,
    epoch_id: i64,
    remirror_pending: bool,
    outbox_files: OutboxFiles,
}

/// `inumaki_client::FoldersBody`.
#[derive(Serialize)]
pub struct FoldersBody {
    mirror_root: String,
    folders: Vec<FolderStatus>,
}

/// `inumaki_client::RescanBody`.
#[derive(Debug, Serialize)]
pub struct RescanBody {
    queued: u64,
}

fn not_configured() -> ApiError {
    ApiError::not_found("folder not configured")
}

/// `404`: `unknown dataset` when the dataset does not exist, else `folder
/// not configured` (spec §12.3). Blocking (one vault read).
fn missing(state: &AppState, id: &str) -> ApiError {
    match state.vault.dataset_kind(id) {
        Err(VaultError::DatasetNotFound(_)) => ApiError::not_found("unknown dataset"),
        Ok(_) => not_configured(),
        Err(_) => {
            tracing::warn!(class = "vault", "folder request failed");
            ApiError::internal("vault error")
        }
    }
}

/// Every error becomes a fixed body. The `Debug` of an [`AddError`] wraps
/// vault and mirror errors (ids, paths): it is never formatted, only the
/// fixed class goes to the log.
fn map(e: AddError) -> ApiError {
    match e {
        AddError::Refused(r) => ApiError::bad_request(r.message()),
        AddError::Reserved => ApiError::new(
            StatusCode::BAD_REQUEST,
            "reserved",
            "the chat dataset cannot be used here",
        ),
        AddError::WrongKind => ApiError::bad_request("dataset kind must be folder"),
        AddError::Exists => ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "a folder is already connected; delete it first",
        ),
        AddError::UnknownDataset => ApiError::not_found("unknown dataset"),
        AddError::Vault(_) => {
            tracing::warn!(class = "vault", "folder request failed");
            ApiError::internal("vault error")
        }
        AddError::Mirror(FolderError::Busy) => busy(),
        AddError::Mirror(e) => {
            tracing::warn!(class = e.as_str(), "folder request failed");
            ApiError::internal("mirror error")
        }
    }
}

/// `409`: the folder's job in flight did not end within the removal
/// deadline (a first open waiting on a macOS privacy prompt). The folder
/// stays fenced; the same request again finishes the removal.
pub(crate) fn busy() -> ApiError {
    tracing::warn!(
        class = FolderError::Busy.as_str(),
        "folder removal deferred"
    );
    ApiError::new(
        StatusCode::CONFLICT,
        "conflict",
        "the folder is busy; try again in a moment",
    )
}

fn folders(state: &AppState) -> Result<Arc<Folders>, ApiError> {
    state
        .mirror
        .get()
        .cloned()
        .ok_or_else(|| ApiError::internal("mirror unavailable"))
}

/// `POST /v1/datasets/{id}/folder` → 201.
pub async fn create(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Result<Json<CreateFolder>, JsonRejection>,
) -> Result<(StatusCode, Json<FolderBody>), ApiError> {
    let Json(b) = body.map_err(|_| ApiError::bad_request("unknown or invalid folder field"))?;
    let info = blocking(move || {
        folders(&state)?
            .add(&state, &id, &b.source, b.outbox_destination.as_deref())
            .map_err(map)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(info.into())))
}

/// `GET /v1/datasets/{id}/folder`.
pub async fn show(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<FolderBody>, ApiError> {
    let info = blocking(move || {
        folders(&state)?
            .get(&id)
            .ok_or_else(|| missing(&state, &id))
    })
    .await?;
    Ok(Json(info.into()))
}

/// `DELETE /v1/datasets/{id}/folder` → 204.
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    blocking(move || {
        if folders(&state)?.remove(&state, &id).map_err(map)? {
            Ok(())
        } else {
            Err(missing(&state, &id))
        }
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/datasets/{id}/folder/rescan` → 202.
pub async fn rescan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<RescanBody>), ApiError> {
    let queued = blocking(move || {
        folders(&state)?
            .rescan(&id)
            .map_err(map)?
            .ok_or_else(|| missing(&state, &id))
    })
    .await?;
    Ok((StatusCode::ACCEPTED, Json(RescanBody { queued })))
}

fn state_str(s: inumaki_mirror::FolderState) -> &'static str {
    match s {
        inumaki_mirror::FolderState::Scanning => "scanning",
        inumaki_mirror::FolderState::Watching => "watching",
        inumaki_mirror::FolderState::Stopped => "stopped",
        inumaki_mirror::FolderState::Failed => "failed",
        inumaki_mirror::FolderState::Pending => "pending",
    }
}

/// `GET /v1/folders`. A folder without a snapshot (the service has not
/// started) is `stopped` with zero counts and the dataset's current epoch.
pub async fn list(State(state): State<Arc<AppState>>) -> Result<Json<FoldersBody>, ApiError> {
    let f = folders(&state)?;
    // A folder without a snapshot (the service has not started) still
    // reports its dataset's current epoch.
    let rows = {
        let (f, s) = (Arc::clone(&f), Arc::clone(&state));
        blocking(move || {
            Ok(f.list()
                .into_iter()
                .map(|(i, snap)| {
                    let epoch = s.vault.dataset_state(&i.dataset).map_or(0, |(_, e)| e);
                    (i, snap, epoch)
                })
                .collect::<Vec<_>>())
        })
        .await?
    };
    let folders = rows
        .into_iter()
        .map(|(i, snap, epoch)| {
            let snap = snap.unwrap_or(inumaki_mirror::Snapshot {
                state: inumaki_mirror::FolderState::Stopped,
                error: None,
                files: Default::default(),
                last_mirrored_at: None,
                epoch_id: epoch,
                remirror_pending: false,
                outbox: Default::default(),
            });
            FolderStatus {
                dataset: i.dataset,
                label: i.label,
                source: i.source,
                mirror: i.mirror,
                outbox: i.outbox,
                outbox_destination: i.outbox_destination,
                state: state_str(snap.state),
                error: snap.error.map(|e| e.as_str()),
                files: Files {
                    source: snap.files.source,
                    mirrored: snap.files.mirrored,
                    blocked: snap.files.blocked,
                    unsupported: snap.files.unsupported,
                    pending: snap.files.pending,
                },
                last_mirrored_at: snap.last_mirrored_at,
                epoch_id: snap.epoch_id,
                remirror_pending: snap.remirror_pending,
                outbox_files: OutboxFiles {
                    rehydrated: snap.outbox.rehydrated,
                    with_unresolved: snap.outbox.with_unresolved,
                    pending: snap.outbox.pending,
                },
            }
        })
        .collect();
    Ok(Json(FoldersBody {
        mirror_root: f.mirror_root().display().to_string(),
        folders,
    }))
}
