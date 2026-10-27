//! `GET /v1/service` (M6 spec §7.1, §9.7): who runs this daemon and where
//! its helper binaries are. Paths are answered to the local user only.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::state::AppState;

/// The variable the login service, the formula, and the `.deb` unit set.
pub const MANAGED_BY_ENV: &str = "INUMAKI_MANAGED_BY";

/// Who installed the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ManagedBy {
    /// The app's LaunchAgent or systemd user unit.
    App,
    /// `brew services`.
    Homebrew,
    /// The `.deb`'s user unit.
    Deb,
    /// Anything else, including a daemon started by hand.
    Manual,
}

/// `INUMAKI_MANAGED_BY`'s value → [`ManagedBy`]; unknown or absent is `Manual`.
pub fn managed_by_from(v: Option<&str>) -> ManagedBy {
    match v {
        Some("app") => ManagedBy::App,
        Some("homebrew") => ManagedBy::Homebrew,
        Some("deb") => ManagedBy::Deb,
        _ => ManagedBy::Manual,
    }
}

/// `<prefix>/Cellar/inumaki/<version>/bin/inumakid` → `<prefix>/opt/inumaki/bin`.
pub fn homebrew_bin_dir(exe: &std::path::Path) -> Option<std::path::PathBuf> {
    let s = exe.to_str()?;
    let i = s.find("/Cellar/inumaki/")?;
    Some(std::path::PathBuf::from(format!(
        "{}/opt/inumaki/bin",
        &s[..i]
    )))
}

/// Field order is the contract's (`inumaki_client::ServiceBody`).
#[derive(Serialize)]
pub struct ServiceBody {
    version: &'static str,
    pid: u32,
    started_at: i64,
    exe: String,
    bin_dir: String,
    managed_by: ManagedBy,
    restart_required: bool,
}

/// `GET /v1/service`.
pub async fn service(State(state): State<Arc<AppState>>) -> Json<ServiceBody> {
    let managed_by = managed_by_from(std::env::var(MANAGED_BY_ENV).ok().as_deref());
    let exe = std::env::current_exe().unwrap_or_default();
    // The app's service runs from <data_dir>/bin (spec §7.1); Homebrew's
    // stable `opt` link survives upgrades, the versioned Cellar path does
    // not; any other install keeps its helpers next to its executable.
    let bin_dir = match managed_by {
        ManagedBy::App => state.data_dir.join("bin"),
        ManagedBy::Homebrew => homebrew_bin_dir(&exe)
            .unwrap_or_else(|| exe.parent().map(|p| p.to_path_buf()).unwrap_or_default()),
        _ => exe.parent().map(|p| p.to_path_buf()).unwrap_or_default(),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    Json(ServiceBody {
        version: env!("CARGO_PKG_VERSION"),
        pid: std::process::id(),
        started_at: now - state.started.elapsed().as_secs() as i64,
        exe: exe.display().to_string(),
        bin_dir: bin_dir.display().to_string(),
        managed_by,
        restart_required: state.models_job.restart_required(),
    })
}
