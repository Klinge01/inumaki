//! The debounced watcher (M5 spec §6.1). Events are hints: the worker
//! `lstat`s every path it is given and never trusts an event's content.
//! `notify` errors carry paths in their `Display`, so they are never
//! formatted or kept: any error means a full reconcile.

use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::RecursiveMode;
use notify_debouncer_full::{DebounceEventResult, Debouncer, NoCache, new_debouncer_opt};

/// What the watcher reports.
pub(crate) enum Signal {
    /// Paths that changed.
    Paths(Vec<PathBuf>),
    /// Events were lost or the backend failed: reconcile everything.
    Rescan,
}

/// Keeps the watcher alive. Dropping it only sets the debouncer's stop flag
/// (it does not join the thread), so the sink can still be called once after
/// the drop: a sink must tolerate a late call.
pub(crate) struct Watch {
    // `NoCache`, not `RecommendedCache`: on macOS and Windows that is a
    // `FileIdMap`, which walks the tree with `follow_links(true)` on `watch()`
    // and on every rescan, so a symlink inside the folder would be walked and
    // stat'ed. Events are hints and the worker `lstat`s every path, so losing
    // the rename-id stitching only costs an extra scan.
    _d: Debouncer<notify::RecommendedWatcher, NoCache>,
}

/// Watch `path` recursively without following symlinks. `Err(())` when the
/// backend cannot be set up; the error is deliberately classless because
/// `notify::Error` can hold paths. The caller validates `path` (no symlinked
/// root) before calling.
///
/// The sink runs on the debouncer thread: it must be cheap and non-blocking
/// (push to a queue or channel and return), and it must tolerate a call
/// shortly after the [`Watch`] is dropped.
pub(crate) fn watch(
    path: &Path,
    debounce: Duration,
    sink: impl Fn(Signal) + Send + 'static,
) -> Result<Watch, ()> {
    let config = notify::Config::default().with_follow_symlinks(false);
    let mut d = new_debouncer_opt::<_, notify::RecommendedWatcher, NoCache>(
        debounce,
        None,
        move |r: DebounceEventResult| match r {
            Ok(events) => {
                let mut paths = Vec::new();
                let mut rescan = false;
                for e in events {
                    rescan |= e.need_rescan();
                    paths.extend(e.paths.iter().cloned());
                }
                if rescan {
                    sink(Signal::Rescan);
                }
                paths.sort();
                paths.dedup();
                if !paths.is_empty() {
                    sink(Signal::Paths(paths));
                }
            }
            // The errors are dropped unread: they may name paths.
            Err(_) => sink(Signal::Rescan),
        },
        NoCache::new(),
        config,
    )
    .map_err(|_| ())?;
    d.watch(path, RecursiveMode::Recursive).map_err(|_| ())?;
    Ok(Watch { _d: d })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn a_new_file_is_signalled() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (tx, rx) = mpsc::channel();
        let _w = watch(&root, Duration::from_millis(50), move |_| {
            let _ = tx.send(());
        })
        .unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        rx.recv_timeout(Duration::from_secs(30)).unwrap();
    }
}
