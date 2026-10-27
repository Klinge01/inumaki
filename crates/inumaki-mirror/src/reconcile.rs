//! Reconcile (M5 spec §7.2 step 3, §6.2, §7.6): walk the source through
//! handles, remove entries whose source is gone, sweep the mirror of
//! everything the manifest does not name, then name directories and queue
//! stale files. Never deletes anything when the root is missing, replaced,
//! or not permitted, nor below a subdirectory it cannot read. Deletions and
//! the sweep run before any engine call, so they continue under
//! `model_unavailable` (review I4).

use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::PoisonError;

use crate::folder::{FileState, FolderRt, OpenSide, Reason};
use crate::fsops::{Dir, IoClass, Kind, MARKER, Meta, TMP_PREFIX, map_errno};
use crate::names::{OUTBOX, casefold, ignored};
use crate::pipeline::{
    Ctx, checked_dir_components, ensure_carried, ensure_mirror_dirs, mirror_file_present,
    open_source_root, remove_entry,
};
use crate::queue::{Job, Priority};
use crate::status::FolderError;

fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.is_empty() {
        b.to_vec()
    } else {
        [a, b"/", b].concat()
    }
}

/// `r` is `base` or lies below it (`base` empty: everything).
fn within(r: &[u8], base: &[u8]) -> bool {
    base.is_empty() || r == base || (r.starts_with(base) && r.get(base.len()) == Some(&b'/'))
}

/// Reconcile `subtree` (empty: the whole folder). `full` also retries every
/// file that is not mirrored (placeholders) with the manifest shortcut off.
/// Returns the files queued. A directory whose name or mirror directory
/// fails is skipped and the rest continues; the first such error is
/// returned at the end (spec §9: the folder continues).
pub(crate) fn run(
    ctx: &Ctx,
    rt: &FolderRt,
    subtree: &[u8],
    full: bool,
) -> Result<u64, FolderError> {
    let ds = rt.folder.dataset.clone();
    if subtree.split(|b| *b == b'/').any(ignored) {
        return Ok(0); // never mirrored (spec §4.2)
    }
    // The outbox does not depend on the source: it is walked first, so a
    // missing or not permitted source never holds it up (7 review M4).
    let outbox_queued = if subtree.is_empty() {
        crate::outbox::walk(ctx, rt)
    } else {
        0
    };
    // A missing, replaced, or not permitted root is an error here, before
    // anything is deleted (spec §6.2, §9). A root not known to be the one
    // mirrored deletes nothing (5c review I2).
    let root = open_source_root(ctx, rt)?;
    let may_delete = root.may_delete;
    let start = if subtree.is_empty() {
        root.dir
    } else {
        match root.dir.walk(subtree) {
            Ok(d) => d,
            Err(e) if matches!(map_errno(&e), IoClass::NotFound | IoClass::Symlink) => {
                // Gone, a file now, or behind a link: what was mirrored
                // below it goes; the path itself runs through the pipeline,
                // which mirrors a file or a link placeholder in its place.
                if !may_delete {
                    return Ok(0);
                }
                remove_entry(ctx, rt, subtree)?;
                ctx.queue.push(
                    Job::Source {
                        dataset: ds,
                        rel: subtree.to_vec(),
                        force: false,
                    },
                    Priority::Live,
                );
                return Ok(1);
            }
            Err(_) => return Ok(0), // unreadable: what is mirrored stays
        }
    };

    // 1. Walk (no engine). Only NotFound and ELOOP count as gone; an
    //    unreadable directory (EACCES, EPERM, EIO) keeps everything below it.
    //    The stack holds paths, not handles: each directory is reopened
    //    from `start` when it is listed (`O_NOFOLLOW` per component), so the
    //    walk holds a few descriptors however wide the tree is (5c review
    //    I1; a daemon's limit is 256 on macOS).
    let below = |rel: &[u8]| -> Vec<u8> {
        let r = &rel[subtree.len()..];
        r.strip_prefix(b"/").unwrap_or(r).to_vec()
    };
    let mut files: Vec<(Vec<u8>, Option<Meta>)> = Vec::new();
    let mut dirs: Vec<Vec<u8>> = Vec::new();
    let mut unreadable: Vec<Vec<u8>> = Vec::new();
    let mut stack: Vec<Vec<u8>> = vec![subtree.to_vec()];
    while let Some(rel) = stack.pop() {
        let is_start = rel.as_slice() == subtree;
        let dir = match start.walk(&below(&rel)) {
            Ok(d) => d,
            Err(e) if !is_start && map_errno(&e) == IoClass::NotFound => continue,
            // Swapped for a link since the listing: never followed; the
            // pipeline gives it a link placeholder.
            Err(e) if !is_start && map_errno(&e) == IoClass::Symlink => {
                files.push((rel, None));
                continue;
            }
            Err(e) => {
                if is_start && subtree.is_empty() {
                    return Err(FolderError::from_source_io(&e));
                }
                dirs.push(rel.clone());
                unreadable.push(rel);
                continue;
            }
        };
        // The subtree's own directory is named too (a new, empty one
        // included).
        if !rel.is_empty() {
            dirs.push(rel.clone());
        }
        // The root's listing may be the first access a macOS prompt
        // blocks: `pending` while it waits.
        let listed = {
            let _opening = is_start.then(|| rt.begin_open(OpenSide::Source));
            dir.entries()
        };
        if listed.is_ok() {
            rt.opened(OpenSide::Source);
        }
        let entries = match listed {
            Ok(e) => e,
            Err(e) => {
                // The whole folder's root listed nothing: a failure, not
                // an empty folder (5c review I3). `NotFound` here is a
                // child that vanished during the listing: retried.
                if is_start && subtree.is_empty() {
                    return Err(match map_errno(&e) {
                        IoClass::NotFound => FolderError::Internal,
                        _ => FolderError::from_source_io(&e),
                    });
                }
                unreadable.push(rel);
                continue;
            }
        };
        for (name, kind) in entries {
            let nb = name.as_bytes();
            if ignored(nb) {
                continue;
            }
            let child = join(&rel, nb);
            match kind {
                Kind::Dir => stack.push(child),
                Kind::File | Kind::Symlink => match dir.stat(&name) {
                    Ok(m) => files.push((child, Some(m))),
                    Err(e) if map_errno(&e) == IoClass::NotFound => {}
                    Err(_) => files.push((child, None)),
                },
                Kind::Other => {}
            }
        }
    }

    // 2. Deletions (no engine). A record goes only when its source was not
    //    seen and no unreadable directory could be hiding it, and only
    //    under a root known to be the one mirrored.
    let (gone_files, gone_dirs) = if !may_delete {
        (Vec::new(), Vec::new())
    } else {
        let seen_files: HashSet<&[u8]> = files.iter().map(|(r, _)| r.as_slice()).collect();
        let seen_dirs: HashSet<&[u8]> = dirs.iter().map(Vec::as_slice).collect();
        let kept = |r: &[u8]| unreadable.iter().any(|u| within(r, u));
        let ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
        let mut gone_dirs: Vec<Vec<u8>> = ix
            .dirs
            .keys()
            .filter(|r| {
                within(r, subtree)
                    && r.as_slice() != subtree
                    && !seen_dirs.contains(r.as_slice())
                    && !kept(r)
            })
            .cloned()
            .collect();
        // `remove_entry` on a directory takes everything below it, so only
        // the topmost gone directories and the files outside them are needed.
        gone_dirs.sort();
        let mut top: Vec<Vec<u8>> = Vec::new();
        for d in gone_dirs {
            if !top.last().is_some_and(|t| within(&d, t)) {
                top.push(d);
            }
        }
        let gone_files: Vec<Vec<u8>> = ix
            .files
            .keys()
            .filter(|r| {
                within(r, subtree)
                    && !seen_files.contains(r.as_slice())
                    && !kept(r)
                    && !top.iter().any(|t| within(r, t))
            })
            .cloned()
            .collect();
        (gone_files, top)
    };
    for r in gone_dirs.iter().chain(&gone_files) {
        remove_entry(ctx, rt, r)?;
    }

    // 3. Whole folder: sweep orphans and crash leftovers (no engine). It
    //    removes only what the manifest does not name, whatever the source.
    if subtree.is_empty() {
        sweep_orphans(ctx, rt)?;
    }

    // 4. Names and queueing (engine).
    let st = ctx
        .engine
        .state(&ds)
        .map_err(|e| FolderError::from_engine(&e))?;
    ensure_carried(ctx, rt, &st)?;
    let mut failed: Option<FolderError> = None;
    for d in &dirs {
        let r = checked_dir_components(ctx, rt, d, st.epoch_id, st.fingerprint)
            .and_then(|comps| ensure_mirror_dirs(ctx, rt, &comps));
        if let Err(e) = r {
            failed.get_or_insert(e);
        }
    }
    let mut queued = outbox_queued;
    for (rel, meta) in &files {
        if let Some(force) = needs_work(ctx, rt, rel, *meta, st.epoch_id, st.fingerprint, full) {
            ctx.queue.push(
                Job::Source {
                    dataset: ds.clone(),
                    rel: rel.clone(),
                    force,
                },
                Priority::Background,
            );
            queued += 1;
        }
    }

    if subtree.is_empty() {
        let mut s = rt.status.lock().unwrap_or_else(PoisonError::into_inner);
        s.source_files = files
            .iter()
            .filter(|(_, m)| m.is_some_and(|m| m.kind == Kind::File))
            .count() as u64;
        if failed.is_none() {
            s.succeed();
        }
    }
    match failed {
        Some(e) => Err(e),
        None => Ok(queued),
    }
}

/// Whether `rel` goes through the pipeline (`Some`), and with the manifest
/// shortcut off (`Some(true)`).
fn needs_work(
    ctx: &Ctx,
    rt: &FolderRt,
    rel: &[u8],
    meta: Option<Meta>,
    epoch: i64,
    fp: [u8; 32],
    full: bool,
) -> Option<bool> {
    let Some(m) = meta else {
        return Some(full);
    };
    let r = rt
        .index
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .files
        .get(rel)
        .cloned();
    let Some(r) = r else {
        return Some(full);
    };
    // An unreadable placeholder is retried at every reconcile (spec §6.2).
    if r.state == FileState::Pending
        || r.epoch_id != epoch
        || r.fingerprint != fp
        || r.reason == Some(Reason::Unreadable)
    {
        return Some(full);
    }
    if full && r.state != FileState::Mirrored {
        return Some(true);
    }
    if m.size != r.size || m.mtime != r.mtime {
        return Some(full);
    }
    // The mirror file itself must still be there; if it is not, the
    // manifest shortcut would skip the rewrite.
    (!mirror_file_present(ctx, rt, &r.mirror_rel)).then_some(true)
}

/// Mirror paths the manifest names, NFC and case-folded (the mirror's file
/// system may ignore case): every file, and every directory that is a
/// directory record or an ancestor of a named path.
struct Named {
    files: HashSet<String>,
    dirs: HashSet<String>,
}

fn fold(b: &[u8]) -> String {
    casefold(&String::from_utf8_lossy(b))
}

/// Delete everything under the mirror directory the manifest does not name,
/// except the marker and the top-level `outbox/`, and every temporary file.
/// Files and links are unlinked one by one; a directory goes only once
/// empty (never a recursive delete below the folder's mirror directory).
/// Skipped, as an error, unless the mirror directory's marker holds this
/// folder's label (spec §4.1: a tree is cleared only when its marker
/// matches).
fn sweep_orphans(ctx: &Ctx, rt: &FolderRt) -> Result<(), FolderError> {
    let label = &rt.folder.label;
    let mdir = ctx
        .root
        .child(OsStr::new(label))
        .map_err(|e| FolderError::from_mirror_io(&e))?;
    match mdir.read_file(OsStr::new(MARKER), 64) {
        Ok((b, _, _)) if b == label.as_bytes() => {}
        _ => return Err(FolderError::MirrorUnwritable),
    }
    fn ancestors(mut p: &[u8], dirs: &mut HashSet<String>) {
        while let Some(i) = p.iter().rposition(|b| *b == b'/') {
            p = &p[..i];
            dirs.insert(fold(p));
        }
    }
    let named = {
        let ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
        let mut n = Named {
            files: HashSet::new(),
            dirs: HashSet::new(),
        };
        for r in ix.files.values() {
            n.files.insert(fold(&r.mirror_rel));
            ancestors(&r.mirror_rel, &mut n.dirs);
        }
        for d in ix.dirs.values() {
            n.dirs.insert(fold(&d.mirror_rel));
            ancestors(&d.mirror_rel, &mut n.dirs);
        }
        n
    };
    sweep(&mdir, b"", &named);
    Ok(())
}

/// Depth first through handles (`O_NOFOLLOW`); a directory that cannot be
/// read is left as it is.
fn sweep(dir: &Dir, rel: &[u8], named: &Named) {
    let Ok(entries) = dir.entries() else { return };
    for (name, kind) in entries {
        let nb = name.as_bytes();
        if rel.is_empty() && (nb == MARKER.as_bytes() || nb == OUTBOX.as_bytes()) {
            continue;
        }
        let child = join(rel, nb);
        match kind {
            Kind::Dir => match dir.child(&name) {
                Ok(d) => {
                    sweep(&d, &child, named);
                    if !named.dirs.contains(&fold(&child)) {
                        let _ = dir.remove_empty_dir(&name);
                    }
                }
                // Swapped for a link since the listing: the link goes.
                Err(e) if map_errno(&e) == IoClass::Symlink => {
                    let _ = dir.unlink(&name);
                }
                Err(_) => {}
            },
            // A link or a special file is never a mirror file (spec §6.4).
            Kind::File
                if named.files.contains(&fold(&child))
                    && !nb.starts_with(TMP_PREFIX.as_bytes()) => {}
            _ => {
                let _ = dir.unlink(&name);
            }
        }
    }
}
