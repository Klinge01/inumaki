//! The mirror path of the check (M6 spec §8.1–8.2), driven entirely through
//! the §9.5 folders contract on the control router, in process: it needs no
//! M5 internals and reports `mirror_unavailable` while `GET /v1/folders`
//! is not served. The source and outbox destination live in a temporary
//! directory outside the data directory (M5 refuses folders inside it),
//! named `inumaki-check-<data-dir tag>-<random>`, removed on cleanup and by
//! this data directory's startup sweep (never another daemon's).
//!
//! Only the `201` of `POST …/folder` and its `mirror` and `outbox` strings
//! are read; any other answer (whatever error class M5 reports) leaves the
//! path `mirror_unavailable`.

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::Method;
use serde_json::json;

use super::runner::{LiveCheck, rehydrate, seed};
use super::types::{MirrorEntry, PathAvail, PathReason, PathResult};
use super::verdict::{Evidence, not_checked, verdict};
use super::{TMP_PREFIX, internal, tmp_tag};
use crate::state::AppState;

const FILE: &str = "canary.txt";
const REPLY: &str = "reply.txt";

/// What `prepare` created. `Debug` prints nothing: the paths lie under the
/// home directory and name the check's dataset.
pub struct MirrorSetup {
    /// The folder dataset, `check-<12 hex>-f`.
    pub dataset: String,
    /// `<temp>/inumaki-check-<tag>-<random>`.
    pub tmp_root: PathBuf,
    /// Agent-readable mirror directory.
    pub mirror: PathBuf,
    /// Agent-writable outbox.
    pub outbox: PathBuf,
    /// Where rehydrated outbox files land.
    pub outbox_destination: PathBuf,
}

impl MirrorSetup {
    /// `<tmp_root>/source`: the check's own source directory, which holds
    /// the canary file the scripted `Bash` call reads.
    pub fn source_dir(&self) -> PathBuf {
        self.tmp_root.join("source")
    }
}

impl std::fmt::Debug for MirrorSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MirrorSetup(..)")
    }
}

/// Create `p` as 0700 from the first instant (never readable by others in between).
fn mkdir_private(p: &Path) -> Option<()> {
    std::fs::DirBuilder::new().mode(0o700).create(p).ok()
}

/// `<temp>/inumaki-check-<tag>-<random>/{source,outbox}`, every directory
/// 0700 from creation. Returns the root, kept on purpose: `cleanup` and the
/// startup sweep remove it.
///
/// The root is the canonical path (on macOS `$TMPDIR` is under `/var`, a
/// symlink to `/private/var`), so the scripted `cat`, Claude Code's
/// `--add-dir`, M5's folder source, and the hook's resolved path all name
/// the same real directory. The sweep matches by file name, which
/// canonicalization keeps.
fn create_tmp_root(data_dir: &Path) -> Option<PathBuf> {
    let tmp = tempfile::Builder::new()
        .prefix(&format!("{TMP_PREFIX}{}-", tmp_tag(data_dir)))
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .ok()?;
    let kept = tmp.keep();
    let Ok(root) = kept.canonicalize() else {
        let _ = std::fs::remove_dir_all(&kept);
        return None;
    };
    if mkdir_private(&root.join("source")).is_none()
        || mkdir_private(&root.join("outbox")).is_none()
    {
        let _ = std::fs::remove_dir_all(&root);
        return None;
    }
    Some(root)
}

/// Remove every regular file directly under `dir` (a previous run's reply).
fn clear_files(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.filter_map(Result::ok) {
            if e.file_type().is_ok_and(|t| t.is_file()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Prepare the mirror path; on any failure the path stays unavailable and
/// whatever was created is removed (the folder dataset with the check).
pub async fn prepare(state: &Arc<AppState>, live: &mut LiveCheck) {
    match internal(state, Method::GET, "/v1/folders", None).await {
        Some((200, _)) => {}
        _ => return,
    }
    let dataset = format!("{}{}", live.dataset, super::MIRROR_DATASET_SUFFIX);
    let Some(tmp_root) = create_tmp_root(&state.data_dir) else {
        tracing::warn!("the check could not prepare the mirror path");
        return;
    };
    let (source, dest) = (tmp_root.join("source"), tmp_root.join("outbox"));
    let mut folder_created = false;
    let prepared = async {
        let c = &live.canary;
        std::fs::write(
            source.join(FILE),
            format!(
                "Record: {}, IBAN {}, email {}\n",
                c.full_name(),
                c.iban,
                c.email
            ),
        )
        .ok()?;
        let (code, _) = internal(
            state,
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": dataset, "name": "check", "profile": "offline", "kind": "folder" })),
        )
        .await?;
        if code != 201 {
            return None;
        }
        live.datasets.push(dataset.clone());
        let (s, ds, canary) = (Arc::clone(state), dataset.clone(), live.canary.clone());
        crate::api::blocking(move || seed(&s, &ds, &canary))
            .await
            .ok()?;
        let (code, body) = internal(
            state,
            Method::POST,
            &format!("/v1/datasets/{dataset}/folder"),
            Some(json!({
                "source": source.display().to_string(),
                "outbox_destination": dest.display().to_string(),
            })),
        )
        .await?;
        if code != 201 {
            return None;
        }
        folder_created = true;
        Some(MirrorSetup {
            dataset: dataset.clone(),
            tmp_root: tmp_root.clone(),
            mirror: PathBuf::from(body["mirror"].as_str()?),
            outbox: PathBuf::from(body["outbox"].as_str()?),
            outbox_destination: dest.clone(),
        })
    }
    .await;
    match prepared {
        Some(m) => {
            live.mirror = Some(m);
            live.paths.mirror = PathAvail::yes();
        }
        None => {
            tracing::warn!("the check could not prepare the mirror path");
            if folder_created {
                // M5 stops watching before the dataset goes with the check.
                let _ = internal(
                    state,
                    Method::DELETE,
                    &format!("/v1/datasets/{dataset}/folder"),
                    None,
                )
                .await;
            }
            let _ = std::fs::remove_dir_all(&tmp_root);
        }
    }
}

/// The mirrored canary file handed to the app.
pub fn entry(live: &LiveCheck) -> Option<MirrorEntry> {
    live.mirror.as_ref().map(|m| MirrorEntry {
        path: m.mirror.join(FILE).display().to_string(),
        source_dir: m.source_dir().display().to_string(),
    })
}

/// A file M5 writes beside the content and the check must never read as
/// the mirrored text: the marker and temporary files (`.…`) and the
/// placeholder sidecars (`*.inumaki-<reason>.txt`).
fn is_bookkeeping(name: &str) -> bool {
    name.starts_with('.') || (name.contains(".inumaki-") && name.ends_with(".txt"))
}

/// The first regular content file under `dir` (mirrored names may be sanitized).
pub(crate) fn first_file(dir: &Path) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| !is_bookkeeping(&e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .find(|p| p.is_file())
}

/// Wait until `dir/name` (or, failing that, the first content file) holds
/// text; `None` after `within`, which the caller reports as `timeout`.
pub(crate) async fn wait_file(dir: &Path, name: &str, within: Duration) -> Option<String> {
    let until = Instant::now() + within;
    loop {
        let p = dir.join(name);
        let p = if p.is_file() {
            Some(p)
        } else {
            first_file(dir)
        };
        if let Some(text) = p
            .and_then(|p| std::fs::read_to_string(p).ok())
            .filter(|t| !t.is_empty())
        {
            return Some(text);
        }
        if Instant::now() >= until {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The mirrored canary file's text, if it is there.
pub fn mirrored_text(live: &LiveCheck) -> Option<String> {
    let m = live.mirror.as_ref()?;
    std::fs::read_to_string(m.mirror.join(FILE))
        .ok()
        .or_else(|| first_file(&m.mirror).and_then(|p| std::fs::read_to_string(p).ok()))
}

/// Read the mirrored file (must hold tokens, no canary), write it back
/// through the outbox, read the rehydrated result (must hold the canary).
pub async fn direct(state: &Arc<AppState>, live: &LiveCheck) -> PathResult {
    let Some(m) = &live.mirror else {
        return not_checked(Some(PathReason::MirrorUnavailable));
    };
    let wait = state.check.path_wait();
    let Some(mirrored) = wait_file(&m.mirror, FILE, wait).await else {
        return verdict(&Evidence {
            timed_out: true,
            ..Evidence::default()
        });
    };
    // A store error restores nothing and shows no tokens.
    let restored = rehydrate(state, &m.dataset, mirrored.clone()).await;
    let mut e = Evidence {
        upstream_requests: 1,
        canary_in_upstream: live.canary.appears_in(&mirrored),
        tokens_seen: restored.is_some_and(|r| r != mirrored),
        ..Evidence::default()
    };
    // A previous direct run's reply must not answer for this one.
    let _ = std::fs::remove_file(m.outbox.join(REPLY));
    clear_files(&m.outbox_destination);
    if std::fs::write(m.outbox.join(REPLY), &mirrored).is_err() {
        return verdict(&e);
    }
    match wait_file(&m.outbox_destination, REPLY, wait).await {
        Some(out) => e.rehydrated_in_output = live.canary.restored_in(&out),
        None => e.timed_out = true,
    }
    verdict(&e)
}

/// Remove the temporary source and outbox destination. The folder itself
/// goes with its dataset (`Folders::remove_dataset`, in `remove_live`),
/// which stops watching and deletes the mirror tree first.
pub fn cleanup(live: &LiveCheck) {
    if let Some(m) = &live.mirror {
        let _ = std::fs::remove_dir_all(&m.tmp_root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M5 §9/§10 notes: the marker, temporary files, and placeholder
    /// sidecars are never read as the mirrored text, and a wait that sees
    /// nothing ends (the `timeout` verdict), it never hangs.
    #[tokio::test]
    async fn waits_skip_bookkeeping_files_and_end_on_time() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            ".inumaki-mirror",
            ".inumaki-tmp-1a2b",
            "x.inumaki-blocked.txt",
        ] {
            std::fs::write(dir.path().join(name), "not the content").unwrap();
        }
        let started = Instant::now();
        assert_eq!(
            wait_file(dir.path(), FILE, Duration::from_millis(200)).await,
            None
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        std::fs::write(dir.path().join("renamed.txt"), "content").unwrap();
        assert_eq!(
            wait_file(dir.path(), FILE, Duration::from_millis(200))
                .await
                .as_deref(),
            Some("content")
        );
    }

    /// The temporary source and outbox destination are private from creation.
    #[test]
    fn the_temporary_root_is_private() {
        let data = tempfile::tempdir().unwrap();
        let root = create_tmp_root(data.path()).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let modes = [
            mode(&root),
            mode(&root.join("source")),
            mode(&root.join("outbox")),
        ];
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(modes, [0o700; 3]);
    }

    /// The root is canonical (no `/var` symlink on macOS) and keeps the
    /// sweep's `inumaki-check-<tag>-` file-name prefix. The canonical part
    /// only bites where `$TMPDIR` has a symlink in it (macOS); elsewhere
    /// (Linux CI) it passes either way. No process-global `TMPDIR` change is
    /// made to force it.
    #[test]
    fn the_temporary_root_is_canonical() {
        let data = tempfile::tempdir().unwrap();
        let root = create_tmp_root(data.path()).unwrap();
        let canonical = root.canonicalize().unwrap();
        let name = root.file_name().unwrap().to_string_lossy().into_owned();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(root, canonical);
        assert!(name.starts_with(&format!("{TMP_PREFIX}{}-", tmp_tag(data.path()))));
    }
}
