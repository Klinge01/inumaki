//! The model download job (M6 spec §7.2, §9.7): `POST /v1/models/pull`
//! starts one download of the pinned manifest's models inside the daemon,
//! `GET` reports it. The daemon does not hot-reload models: a finished job
//! sets `restart_required`, and the app restarts the service. Logs carry
//! model names (public) and error classes, never a URL or a path.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use inumaki_models::manifest::{self, FetchError, FileStatus, HF_BASE, Manifest, ModelEntry};
use serde::{Deserialize, Serialize};

use crate::api::ApiError;
use crate::state::AppState;

/// `POST /v1/models/pull` body.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PullBody {
    /// Model names; the manifest's defaults when absent.
    #[serde(default)]
    models: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum JobState {
    Idle,
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum JobError {
    Network,
    HashMismatch,
    Disk,
    Manifest,
}

/// One file; field order is the contract's (`inumaki_client::ModelFile`).
#[derive(Clone, Serialize)]
struct FileView {
    model: String,
    path: String,
    bytes_done: u64,
    bytes_total: u64,
    verified: bool,
}

/// The job; field order is the contract's (`inumaki_client::ModelsJob`).
#[derive(Clone, Serialize)]
pub struct JobView {
    state: JobState,
    started_at: Option<i64>,
    files: Vec<FileView>,
    error: Option<JobError>,
    restart_required: bool,
}

impl Default for JobView {
    fn default() -> Self {
        JobView {
            state: JobState::Idle,
            started_at: None,
            files: Vec::new(),
            error: None,
            restart_required: false,
        }
    }
}

/// Manifest and download base URL; tests point them at a local server.
struct Source {
    manifest: Manifest,
    base_url: String,
}

/// The daemon's one job.
pub struct ModelsJobSlot {
    job: Arc<Mutex<JobView>>,
    source: Mutex<Source>,
    /// Set by a finished job, cleared only by a new process: models load at start.
    restart: Arc<AtomicBool>,
}

impl Default for ModelsJobSlot {
    fn default() -> Self {
        ModelsJobSlot {
            job: Arc::new(Mutex::new(JobView::default())),
            source: Mutex::new(Source {
                manifest: Manifest::embedded(),
                base_url: HF_BASE.to_string(),
            }),
            restart: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ModelsJobSlot {
    /// Replace the manifest and base URL (tests).
    pub fn set_source(&self, manifest: Manifest, base_url: String) {
        *self.source.lock().unwrap_or_else(PoisonError::into_inner) = Source { manifest, base_url };
    }

    /// A finished job is waiting for a restart (until this process exits).
    pub fn restart_required(&self) -> bool {
        self.restart.load(Ordering::SeqCst)
    }

    fn view(&self) -> JobView {
        self.job
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn class(e: &FetchError) -> JobError {
    match e {
        FetchError::Http(_) => JobError::Network,
        FetchError::Checksum(_) => JobError::HashMismatch,
        FetchError::Io(_) => JobError::Disk,
        FetchError::Manifest(_) => JobError::Manifest,
    }
}

/// `GET /v1/models/pull`.
pub async fn get(State(state): State<Arc<AppState>>) -> Json<JobView> {
    Json(state.models_job.view())
}

/// `POST /v1/models/pull` → 202, `400` for an unknown model, `409` while a job runs.
pub async fn start(
    State(state): State<Arc<AppState>>,
    body: Result<Json<PullBody>, JsonRejection>,
) -> Result<(StatusCode, Json<JobView>), ApiError> {
    let Json(b) = body?;
    let (entries, base_url) = {
        let src = state
            .models_job
            .source
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let entries: Vec<ModelEntry> = match &b.models {
            None => src.manifest.defaults().into_iter().cloned().collect(),
            Some(names) => {
                let mut v = Vec::new();
                for n in names {
                    // Fixed message: the name is user input.
                    v.push(
                        src.manifest
                            .get(n)
                            .cloned()
                            .ok_or_else(|| ApiError::bad_request("unknown model name"))?,
                    );
                }
                v
            }
        };
        (entries, src.base_url.clone())
    };
    let root: PathBuf = state.engines.models_dir().to_path_buf();
    {
        let mut job = state
            .models_job
            .job
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if job.state == JobState::Running {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "conflict",
                "a model download is running",
            ));
        }
        *job = JobView {
            state: JobState::Running,
            started_at: Some(now()),
            files: entries
                .iter()
                .flat_map(|e| {
                    e.files.iter().map(|f| FileView {
                        model: e.name.clone(),
                        path: root.join(&e.name).join(&f.path).display().to_string(),
                        bytes_done: 0,
                        bytes_total: f.size,
                        verified: false,
                    })
                })
                .collect(),
            error: None,
            restart_required: state.models_job.restart_required(),
        };
    }
    let job = Arc::clone(&state.models_job.job);
    let restart = Arc::clone(&state.models_job.restart);
    std::thread::spawn(move || run_job(&job, &restart, &root, &entries, &base_url));
    Ok((StatusCode::ACCEPTED, Json(state.models_job.view())))
}

fn run_job(
    job: &Mutex<JobView>,
    restart: &AtomicBool,
    root: &std::path::Path,
    entries: &[ModelEntry],
    base_url: &str,
) {
    for e in entries {
        tracing::info!(model = %e.name, "model download started");
        let r = manifest::pull(root, e, base_url, &mut |path, done, _total| {
            let mut j = job.lock().unwrap_or_else(PoisonError::into_inner);
            let suffix = std::path::Path::new(&e.name).join(path);
            if let Some(f) = j
                .files
                .iter_mut()
                .find(|f| f.model == e.name && f.path.ends_with(&*suffix.to_string_lossy()))
            {
                f.bytes_done = done;
            }
        });
        let mut j = job.lock().unwrap_or_else(PoisonError::into_inner);
        match r {
            Ok(()) => {
                for ((name, st), f) in manifest::verify(root, e)
                    .into_iter()
                    .zip(j.files.iter_mut().filter(|f| f.model == e.name))
                {
                    let _ = name;
                    f.verified = st == FileStatus::Ok;
                    if f.verified {
                        f.bytes_done = f.bytes_total;
                    }
                }
                tracing::info!(model = %e.name, "model download finished");
            }
            Err(err) => {
                // FetchError's Display carries a URL or a path: log the class only.
                let c = class(&err);
                tracing::warn!(model = %e.name, error = ?c, "model download failed");
                j.state = JobState::Failed;
                j.error = Some(c);
                return;
            }
        }
    }
    restart.store(true, Ordering::SeqCst);
    let mut j = job.lock().unwrap_or_else(PoisonError::into_inner);
    j.state = JobState::Done;
    j.restart_required = true;
}
