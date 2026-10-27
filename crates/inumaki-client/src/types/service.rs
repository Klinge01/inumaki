//! `GET /v1/service`, `POST/GET /v1/models/pull` (M6 spec §9.7).

use serde::{Deserialize, Serialize};

/// Who installed the service (`INUMAKI_MANAGED_BY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ManagedBy {
    /// The app's login service.
    App,
    /// Homebrew.
    Homebrew,
    /// The `.deb`.
    Deb,
    /// Started by hand.
    Manual,
}

/// `GET /v1/service`. `exe` and `bin_dir` are paths: not in `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceBody {
    /// Version.
    pub version: String,
    /// Process id.
    pub pid: u64,
    /// Unix seconds.
    pub started_at: i64,
    /// Executable path.
    pub exe: String,
    /// Directory of the helper binaries.
    pub bin_dir: String,
    /// Manager.
    pub managed_by: ManagedBy,
    /// A restart is needed (after a model download).
    pub restart_required: bool,
}

debug_fields!(ServiceBody {
    version,
    pid,
    started_at,
    managed_by,
    restart_required
});

/// `POST /v1/models/pull` body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelsPull {
    /// Models; the manifest's defaults when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<String>>,
}

/// Job state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    /// No job.
    Idle,
    /// Downloading.
    Running,
    /// Finished.
    Done,
    /// Failed.
    Failed,
}

/// Job error class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobError {
    /// Network.
    Network,
    /// A file fails its pinned hash.
    HashMismatch,
    /// Disk.
    Disk,
    /// The manifest.
    Manifest,
}

/// One file of the job. `path` is not in `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ModelFile {
    /// Model.
    pub model: String,
    /// Destination path.
    pub path: String,
    /// Bytes done.
    pub bytes_done: u64,
    /// Bytes total.
    pub bytes_total: u64,
    /// Hash verified.
    pub verified: bool,
}

debug_fields!(ModelFile {
    model,
    bytes_done,
    bytes_total,
    verified
});

/// `ModelsJob`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelsJob {
    /// State.
    pub state: JobState,
    /// Start.
    pub started_at: Option<i64>,
    /// Files.
    pub files: Vec<ModelFile>,
    /// Error class.
    pub error: Option<JobError>,
    /// The service must restart to load the models.
    pub restart_required: bool,
}
