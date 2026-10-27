//! Folders view (spec §6.4): one card per folder dataset (`folder-N`).
//! "Reveal mirror" opens only paths under the mirror root; "Show restored
//! files" opens only the folder's outbox destination as the daemon reports
//! it. Both take the dataset id, never a path from the UI. A row carries a
//! fixed error code and sentence, never the daemon's wording.

use std::path::{Component, Path, PathBuf};

use inumaki_client::{
    ClientError, CreateDataset, DatasetKind, FolderCreate, FolderError, FolderFiles, FolderState,
    OutboxFiles, RescanBody,
};
use serde::Serialize;

use crate::ctx::Ctx;
use crate::error::CmdError;
pub use crate::harness::connect::DataChange;
use crate::harness::connect::refresh_connected;
use crate::harness::ops::Reason;

/// Serializes the choice of the next `folder-N`.
static NAMING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The warning code of a source inside a folder macOS protects (Desktop,
/// Documents, Downloads, iCloud Drive, external volumes): the system asks
/// the user to allow access, and the daemon's first scan fails until then.
pub const FOLDER_NEEDS_ACCESS: &str = "folder_needs_access";

/// One folder card. Shown to the local user only; `Debug` omits every path.
#[derive(Serialize)]
pub struct FolderRow {
    /// Dataset id (`folder-N`).
    pub dataset: String,
    /// The source directory.
    pub source: String,
    /// The sanitized mirror directory.
    pub mirror: String,
    /// The agent-writable outbox inside the mirror.
    pub outbox: String,
    /// Where restored outbox files go; empty when the daemon does not say
    /// (older daemons), which the UI treats as unknown.
    pub outbox_destination: String,
    /// State.
    pub state: FolderState,
    /// Fixed error code and sentence of a failed folder.
    pub error: Option<Reason>,
    /// File counts.
    pub files: FolderFiles,
    /// Outbox counts.
    pub outbox_files: OutboxFiles,
    /// Last mirrored file, unix seconds.
    pub last_mirrored_at: Option<i64>,
    /// A re-mirror after a key rotation is pending.
    pub remirror_pending: bool,
}

impl std::fmt::Debug for FolderRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderRow")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// The Folders view. `Debug` prints the folder count.
#[derive(Serialize)]
pub struct FoldersView {
    /// Where mirrors live.
    pub mirror_root: String,
    /// Folder cards.
    pub folders: Vec<FolderRow>,
}

impl std::fmt::Debug for FoldersView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FoldersView")
            .field("folders", &self.folders.len())
            .finish_non_exhaustive()
    }
}

/// The fixed code and sentence of a folder error class.
pub fn error_reason(e: Option<FolderError>) -> Reason {
    let (code, text) = match e {
        Some(FolderError::SourceMissing) => (
            "folder_source_missing",
            "The folder no longer exists at its path.",
        ),
        Some(FolderError::SourceNotPermitted) => (
            "folder_source_not_permitted",
            "macOS did not allow inumaki to read this folder. Allow access when macOS asks, or in System Settings under Privacy & Security, Files and Folders or Full Disk Access.",
        ),
        Some(FolderError::SourceUnreadable) => (
            "folder_source_unreadable",
            "inumaki cannot read this folder. If it is in Desktop, Documents, Downloads, iCloud Drive, or an external volume, allow access when macOS asks, or in System Settings under Privacy & Security.",
        ),
        Some(FolderError::MirrorUnwritable) => (
            "folder_mirror_unwritable",
            "inumaki cannot write the sanitized copy of this folder.",
        ),
        Some(FolderError::WatchFailed) => (
            "folder_watch_failed",
            "Watching this folder for changes stopped. Rescan to retry.",
        ),
        Some(FolderError::VaultUnavailable) => {
            ("folder_vault_unavailable", "The vault is not available.")
        }
        Some(FolderError::ModelUnavailable) => (
            "folder_model_unavailable",
            "A detection model is not available yet.",
        ),
        Some(FolderError::OutboxUnwritable) => (
            "folder_outbox_unwritable",
            "inumaki cannot write files from the outbox to the destination folder. The files stay in the outbox until the destination is writable.",
        ),
        Some(FolderError::Internal) | None => {
            ("folder_failed", "This folder failed. Rescan to retry.")
        }
    };
    Reason { code, text }
}

/// `GET /v1/folders` without check datasets; `not_available` before M5.
pub async fn folders(ctx: &Ctx) -> Result<FoldersView, CmdError> {
    let f = ctx.client.folders().await?;
    Ok(FoldersView {
        mirror_root: f.mirror_root,
        folders: f
            .folders
            .into_iter()
            .filter(|x| !x.dataset.starts_with("check-"))
            .map(|x| FolderRow {
                // `pending` shows its own sentence in the app, not a stale reason.
                error: (x.state != FolderState::Pending
                    && (x.state == FolderState::Failed || x.error.is_some()))
                .then(|| error_reason(x.error)),
                dataset: x.dataset,
                source: x.source,
                mirror: x.mirror,
                outbox: x.outbox,
                outbox_destination: x.outbox_destination,
                state: x.state,
                files: x.files,
                outbox_files: x.outbox_files,
                last_mirrored_at: x.last_mirrored_at,
                remirror_pending: x.remirror_pending,
            })
            .collect(),
    })
}

/// `FOLDER_NEEDS_ACCESS` when `source` is in a place macOS protects behind
/// a consent prompt, judged from the lexical path (case-insensitive, as the
/// file system is) under `home`. The path itself is never returned.
pub fn access_warning(source: &Path, home: &Path) -> Option<&'static str> {
    let lower = |p: &Path| -> Vec<String> {
        let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        canon
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let (p, h) = (lower(source), lower(home));
    let rel: &[String] = if p.len() > h.len() && p[..h.len()] == h[..] {
        &p[h.len()..]
    } else {
        &[]
    };
    let at = |i: usize| rel.get(i).map(String::as_str);
    let in_home = matches!(at(0), Some("desktop" | "documents" | "downloads"))
        || (at(0) == Some("library") && at(1) == Some("mobile documents"));
    let volume = p.len() >= 2 && p[0] == "/" && p[1] == "volumes";
    (in_home || volume).then_some(FOLDER_NEEDS_ACCESS)
}

/// Connect `source` as `folder-N`; connected harnesses learn the new mirror by Reconnect.
pub async fn add_folder(ctx: &Ctx, source: PathBuf) -> Result<DataChange, CmdError> {
    if !source.is_absolute() {
        return Err(CmdError::new("bad_request"));
    }
    {
        let _naming = NAMING.lock().await;
        let taken = ctx.client.datasets().await?;
        let n = taken
            .iter()
            .filter_map(|d| {
                d.id.strip_prefix("folder-")
                    .and_then(|n| n.parse::<u64>().ok())
            })
            .max()
            .unwrap_or(0)
            + 1;
        let id = format!("folder-{n}");
        let display = source
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| id.clone());
        let mut create = CreateDataset::new(id.clone(), display);
        create.kind = Some(DatasetKind::Folder);
        ctx.client.create_dataset(&create).await?;
        let body = FolderCreate {
            source: source.display().to_string(),
            outbox_destination: None,
        };
        if let Err(e) = ctx.client.set_folder(&id, &body).await {
            // No dataset without a folder.
            let _ = ctx.client.delete_dataset(&id).await;
            return Err(e.into());
        }
    }
    let mut change = DataChange::from_failed(refresh_connected(ctx).await);
    // `canonicalize` touches the file system (a network volume can stall).
    let home = ctx.paths.home.clone();
    change.warning = tokio::task::spawn_blocking(move || access_warning(&source, &home))
        .await
        .ok()
        .flatten();
    Ok(change)
}

/// Rescan.
pub async fn rescan(ctx: &Ctx, id: &str) -> Result<RescanBody, CmdError> {
    Ok(ctx.client.rescan_folder(id).await?)
}

/// Stop watching, delete the mirror tree (never the source), delete the
/// dataset, then update the connected harnesses.
pub async fn remove_folder(ctx: &Ctx, id: &str) -> Result<DataChange, CmdError> {
    // Only a folder dataset: never a wrapped server's or a mailbox's.
    if !ctx
        .client
        .folders()
        .await?
        .folders
        .iter()
        .any(|f| f.dataset == id)
    {
        return Err(CmdError::new("not_a_folder"));
    }
    // A parked first read (the macOS privacy prompt) makes the daemon answer
    // 409 on both calls; the folder stays and a retry finishes the removal.
    match ctx.client.delete_folder(id).await {
        Err(e) if is_busy(&e) => return Err(busy()),
        _ => {}
    }
    match ctx.client.delete_dataset(id).await {
        Err(e) if is_busy(&e) => return Err(busy()),
        r => r?,
    }
    Ok(DataChange::from_failed(refresh_connected(ctx).await))
}

/// The daemon's `busy()` answer: 409 with the `conflict` error type. A 409
/// of any other type is some other refusal, not a parked folder.
fn is_busy(e: &ClientError) -> bool {
    e.status() == Some(409) && e.detail().is_some_and(|d| d.kind == "conflict")
}

fn busy() -> CmdError {
    CmdError {
        status: Some(409),
        ..CmdError::new("folder_busy")
    }
}

/// `path` is inside `root`, lexically, with no `..` component.
pub fn under_root(path: &Path, root: &Path) -> bool {
    path.is_absolute()
        && root.is_absolute()
        && !path.components().any(|c| c == Component::ParentDir)
        && path.starts_with(root)
}

/// The mirror directory of `id`, if it is inside the mirror root (also
/// after symlinks, when the directory exists).
pub async fn reveal_target(ctx: &Ctx, id: &str) -> Result<PathBuf, CmdError> {
    let f = ctx.client.folders().await?;
    let x = f
        .folders
        .iter()
        .find(|x| x.dataset == id)
        .ok_or_else(|| CmdError::new("not_found"))?;
    let (p, root) = (PathBuf::from(&x.mirror), PathBuf::from(&f.mirror_root));
    if !under_root(&p, &root) {
        return Err(CmdError::new("outside_mirror_root"));
    }
    // The directory is opened as the canonical path that was checked.
    if let (Ok(cp), Ok(cr)) = (std::fs::canonicalize(&p), std::fs::canonicalize(&root)) {
        return if cp.starts_with(&cr) {
            Ok(cp)
        } else {
            Err(CmdError::new("outside_mirror_root"))
        };
    }
    Ok(p)
}

/// The outbox destination of `id`, as the daemon reports it (never a path
/// from the UI), canonicalized for the reveal. `not_found` for an unknown
/// dataset; `bad_response` for an empty, relative, or `..` path; and
/// `open_failed` when the destination is a symlink or not an existing
/// directory (nothing has been restored yet). The symlink refusal covers the
/// last path component only; `canonicalize` resolves symlinked ancestors,
/// which matches the contract (the daemon is trusted and there is no root to
/// contain the path in).
pub async fn outbox_target(ctx: &Ctx, id: &str) -> Result<PathBuf, CmdError> {
    let f = ctx.client.folders().await?;
    let x = f
        .folders
        .iter()
        .find(|x| x.dataset == id)
        .ok_or_else(|| CmdError::new("not_found"))?;
    let p = PathBuf::from(&x.outbox_destination);
    if x.outbox_destination.is_empty()
        || !p.is_absolute()
        || p.components().any(|c| c == Component::ParentDir)
    {
        return Err(CmdError::new("bad_response"));
    }
    // The file system can stall (a network volume): off the async runtime.
    tokio::task::spawn_blocking(move || {
        let open_failed = || CmdError::new("open_failed");
        let meta = std::fs::symlink_metadata(&p).map_err(|_| open_failed())?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(open_failed());
        }
        std::fs::canonicalize(&p).map_err(|_| open_failed())
    })
    .await
    .map_err(|_| CmdError::new("open_failed"))?
}
