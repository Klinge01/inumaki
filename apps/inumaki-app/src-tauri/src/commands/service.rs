//! Service and model commands (M6 spec §6.3 steps 1–2, §6.4 Settings).

use std::path::PathBuf;
use std::time::Duration;

use inumaki_client::{ManagedBy, ModelsJob, ModelsPull};
use serde::Serialize;

use crate::ctx::Ctx;
use crate::error::CmdError;
use crate::service;

/// The directory of the app's executable: the bundle's helpers sit next to
/// it (Tauri sidecars in `Contents/MacOS`).
fn bundle_dir() -> Result<PathBuf, CmdError> {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.to_path_buf()))
        .ok_or_else(|| CmdError::new("helper_missing"))
}

/// Install and start the login service.
pub async fn service_install(ctx: &Ctx) -> Result<(), CmdError> {
    service::install(ctx, &bundle_dir()?, Duration::from_secs(20)).await
}

/// Stop and unregister it.
pub async fn service_remove(ctx: &Ctx) -> Result<(), CmdError> {
    service::remove(ctx).await
}

/// Restart it.
pub async fn service_restart(ctx: &Ctx) -> Result<(), CmdError> {
    service::restart(ctx, Duration::from_secs(20)).await
}

/// Start the model download.
pub async fn models_pull_start(ctx: &Ctx) -> Result<ModelsJob, CmdError> {
    Ok(ctx.client.start_models_pull(&ModelsPull::default()).await?)
}

/// One poll: the job, whether the app restarted the service for it, and who
/// must restart it otherwise. No `Debug`: the job's files carry paths.
#[derive(Serialize)]
pub struct ModelsPoll {
    /// The job.
    pub job: ModelsJob,
    /// The app restarted the service.
    pub restarted: bool,
    /// Manager of the service, for the "restart it yourself" hint.
    pub restart_by: Option<ManagedBy>,
}

/// Poll the job and restart the app's service when it finished.
pub async fn models_pull_poll(ctx: &Ctx) -> Result<ModelsPoll, CmdError> {
    let job = ctx.client.models_pull().await?;
    let restarted = service::after_models_poll(ctx, &job).await?;
    let restart_by = ctx.client.service().await.ok().map(|s| s.managed_by);
    Ok(ModelsPoll {
        job,
        restarted,
        restart_by,
    })
}
