//! Outbox (M5 spec §8): settle, refuse links and non-text, strict
//! restoration of content and names, a no-replace write into the
//! destination with ` (2)` … ` (999)` on clashes, sidecars with counts
//! only, and the walk the whole-folder reconcile runs. Nothing in the
//! user's destination is ever removed except inumaki's own stale temporary
//! files, and nothing there is ever overwritten.
//!
//! The outbox side is read through the mirror root's handle, one component
//! at a time with `O_NOFOLLOW`; the destination is opened `O_NOFOLLOW` at
//! its root and walked the same way. A symlink on either side is never
//! followed.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::sync::PoisonError;
use std::time::{Duration, SystemTime};

use crate::config::MirrorConfig;
use crate::engine::{Activity, ActivityDirection, ActivityVerdict, EngineError};
use crate::folder::{FolderRt, OpenSide, OutboxOutcome, OutboxRecord};
use crate::fsops::{self, Dir, IoClass, Kind, Meta, TMP_PREFIX, map_errno};
use crate::names::{self, OUTBOX};
use crate::pipeline::{Ctx, split_rel};
use crate::queue::{Job, Priority};
use crate::status::FolderError;

const UNRESOLVED: &str = ".inumaki-unresolved.txt";
const REFUSED: &str = ".inumaki-refused.txt";
/// A temporary file older than this in a destination is a crash leftover;
/// a younger one may be another worker's write in progress.
const STALE_TMP: Duration = Duration::from_secs(60);
/// Longest file name written (spec §8 step 6).
const NAME_MAX: usize = 255;

/// inumaki's own sidecars: never processed, never queued.
fn is_own(name: &[u8]) -> bool {
    name.ends_with(UNRESOLVED.as_bytes()) || name.ends_with(REFUSED.as_bytes())
}

fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.is_empty() {
        b.to_vec()
    } else {
        [a, b"/", b].concat()
    }
}

/// `<root>/<label>/outbox` through the root handle.
fn outbox_dir(ctx: &Ctx, rt: &FolderRt) -> io::Result<Dir> {
    ctx.root
        .child(OsStr::new(&rt.folder.label))
        .and_then(|d| d.child(OsStr::new(OUTBOX)))
}

/// Write the sidecar `<name><suffix>` (counts and fixed text only) and drop
/// the other kind, so one file never carries two contradicting notes. Best
/// effort: a sidecar that cannot be written changes nothing else.
fn note(dir: &Dir, name: &[u8], suffix: &str, text: &str) {
    let mut n = name.to_vec();
    n.extend_from_slice(suffix.as_bytes());
    let _ = dir.write_atomic(OsStr::from_bytes(&n), text.as_bytes(), 0o644, None);
    let other = if suffix == UNRESOLVED {
        REFUSED
    } else {
        UNRESOLVED
    };
    let mut o = name.to_vec();
    o.extend_from_slice(other.as_bytes());
    let _ = dir.unlink(OsStr::from_bytes(&o));
}

/// Remove both sidecars of `name` (it was written).
fn clear_notes(dir: &Dir, name: &[u8]) {
    for suffix in [UNRESOLVED, REFUSED] {
        let mut n = name.to_vec();
        n.extend_from_slice(suffix.as_bytes());
        // `unlink` never removes a directory and never follows a link.
        let _ = dir.unlink(OsStr::from_bytes(&n));
    }
}

fn refuse(dir: &Dir, name: &[u8], why: &str) {
    note(
        dir,
        name,
        REFUSED,
        &format!("inumaki did not save this file: {why}.\n"),
    );
}

fn requeue(ctx: &Ctx, rt: &FolderRt, rel: &[u8]) {
    ctx.queue.push(
        Job::Outbox {
            dataset: rt.folder.dataset.clone(),
            rel: rel.to_vec(),
        },
        Priority::Outbox,
    );
}

/// Why a destination directory could not be had.
enum DestError {
    /// Missing and not creatable, not writable, a symlink, `EPERM`: the
    /// file stays pending and is retried (spec §9).
    Unwritable,
    /// A file or symlink is where a directory belongs: refused with a
    /// sidecar, never removed (review I6).
    InTheWay,
}

/// Open the destination root (`O_NOFOLLOW`: a symlink there is refused).
/// A missing destination is created 0700 only where inumaki owns the place:
/// below the default outbox parent the whole path, elsewhere only the last
/// component, so a destination on an unplugged drive stays missing (spec
/// §9) instead of being recreated on the system disk.
fn destination_root(ctx: &Ctx, rt: &FolderRt) -> Result<Dir, DestError> {
    let dest = &rt.folder.outbox_destination;
    match Dir::open_root(dest) {
        Ok(d) => return Ok(d),
        Err(e) if map_errno(&e) == IoClass::NotFound => {}
        Err(_) => return Err(DestError::Unwritable),
    }
    let parent = &ctx.cfg.outbox_root;
    let ours = !parent.as_os_str().is_empty() && dest.starts_with(parent);
    match std::fs::DirBuilder::new()
        .recursive(ours)
        .mode(0o700)
        .create(dest)
    {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(DestError::Unwritable),
    }
    Dir::open_root(dest).map_err(|_| DestError::Unwritable)
}

/// Open `<destination>/<parents>`, creating missing directories 0700,
/// without removing or following anything in the user's destination.
fn destination_dir(ctx: &Ctx, rt: &FolderRt, parents: &[String]) -> Result<Dir, DestError> {
    // A first open of a protected destination may wait on a macOS prompt:
    // `pending` while it does.
    let _opening = rt.begin_open(OpenSide::Destination);
    let mut d = destination_root(ctx, rt)?;
    rt.opened(OpenSide::Destination);
    for c in parents {
        d = match d.open_or_create(OsStr::new(c), 0o700) {
            Ok(x) => x,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(DestError::InTheWay),
            Err(_) => return Err(DestError::Unwritable),
        };
    }
    remove_stale_tmp(&d);
    Ok(d)
}

/// Remove inumaki's own crash leftovers in a destination directory: regular
/// files named `.inumaki-tmp-<16 hex>` older than a minute. `unlink` only:
/// a directory of that name is never removed.
fn remove_stale_tmp(d: &Dir) {
    let Ok(entries) = d.entries() else { return };
    for (name, kind) in entries {
        let nb = name.as_bytes();
        let ours = kind == Kind::File
            && nb.len() == TMP_PREFIX.len() + 16
            && nb.starts_with(TMP_PREFIX.as_bytes())
            && nb[TMP_PREFIX.len()..].iter().all(u8::is_ascii_hexdigit);
        if !ours {
            continue;
        }
        let stale = d.stat(&name).is_ok_and(|m| {
            m.kind == Kind::File && {
                let at = SystemTime::UNIX_EPOCH
                    + Duration::new(
                        m.mtime.0.max(0) as u64,
                        m.mtime.1.clamp(0, 999_999_999) as u32,
                    );
                at.elapsed().is_ok_and(|age| age > STALE_TMP)
            }
        });
        if stale {
            let _ = d.unlink(&name);
        }
    }
}

/// `name` with `suffix` before its kept extension (files only; directory
/// names are never split), the stem shortened at a character boundary so
/// the whole fits in 255 bytes.
fn fitted(name: &str, suffix: &str, is_dir: bool) -> String {
    let (stem, ext) = names::split_name(name, is_dir);
    let tail = match ext {
        Some(e) => format!("{suffix}.{e}"),
        None => suffix.to_string(),
    };
    let mut cut = stem.len().min(NAME_MAX.saturating_sub(tail.len()));
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{tail}", &stem[..cut])
}

/// Spec §8 step 6: `/` and NUL become `_`; `None` for an empty, `.`, or `..`
/// component; shortened to 255 bytes before the extension.
fn restored_component(s: &str, is_dir: bool) -> Option<String> {
    let c: String = s
        .chars()
        .map(|ch| if ch == '/' || ch == '\0' { '_' } else { ch })
        .collect();
    if c.is_empty() || c == "." || c == ".." {
        return None;
    }
    let c = if c.len() > NAME_MAX {
        fitted(&c, "", is_dir)
    } else {
        c
    };
    names::valid_component(&c).then_some(c)
}

/// The open file and its path still hold the version read.
fn unchanged(dir: &Dir, name: &OsStr, f: &std::fs::File, read: &Meta) -> bool {
    let fd = fsops::fstat_file(f).is_ok_and(|m| m.same_version(read));
    let path = dir.stat(name).is_ok_and(|m| m.same_version(read));
    fd && path
}

/// Process one outbox path. A path that met an unwritable destination is
/// kept in `pending_outbox`, which the poller requeues when the backoff
/// fires (spec §9, review I5); any other outcome clears it.
/// `outbox_unwritable` follows that set: it is set (by the worker's `fail`)
/// while some path is pending and cleared once none is, whether the last
/// one was written, refused, or deleted (7 review I1).
pub(crate) fn process(ctx: &Ctx, rt: &FolderRt, rel: &[u8]) -> Result<(), FolderError> {
    let r = process_inner(ctx, rt, rel);
    let mut s = rt.status.lock().unwrap_or_else(PoisonError::into_inner);
    if r == Err(FolderError::OutboxUnwritable) {
        s.pending_outbox.insert(rel.to_vec());
    } else {
        s.pending_outbox.remove(rel);
        if s.pending_outbox.is_empty() {
            s.errors.remove(&FolderError::OutboxUnwritable);
        }
    }
    r
}

thread_local! {
    static SETTLE_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test seam (this thread only): runs between the two `lstat`s of the
/// settle check, as a writer still at work would.
pub(crate) fn set_settle_hook(f: Option<Box<dyn FnMut()>>) {
    SETTLE_HOOK.with(|h| *h.borrow_mut() = f);
}

fn process_inner(ctx: &Ctx, rt: &FolderRt, rel: &[u8]) -> Result<(), FolderError> {
    let ds = rt.folder.dataset.clone();
    let (parent_rel, name) = split_rel(rel);
    if name.is_empty() || is_own(name) || rel.split(|b| *b == b'/').any(names::ignored) {
        return Ok(());
    }
    // Gone: its record goes too. Behind a link or unreadable: nothing to
    // do, and the record stays.
    let dir = match outbox_dir(ctx, rt).and_then(|d| d.walk(parent_rel)) {
        Ok(d) => d,
        Err(e) if map_errno(&e) == IoClass::NotFound => return forget(ctx, rt, rel),
        Err(_) => return Ok(()),
    };
    let n = OsStr::from_bytes(name);
    let first = match dir.stat(n) {
        Ok(m) => m,
        Err(e) if map_errno(&e) == IoClass::NotFound => return forget(ctx, rt, rel),
        Err(_) => return Ok(()),
    };
    match first.kind {
        Kind::File if first.nlink <= 1 => {}
        Kind::Dir => {
            // A directory moved in whole may arrive as one event. A file of
            // that name is gone.
            forget(ctx, rt, rel)?;
            walk_from(ctx, rt, rel);
            return Ok(());
        }
        Kind::File => {
            refuse(&dir, name, "it has more than one hard link");
            return Ok(());
        }
        Kind::Symlink | Kind::Other => {
            refuse(&dir, name, "links and special files are not processed");
            return Ok(());
        }
    }
    if first.size > ctx.cfg.max_file_bytes {
        refuse(&dir, name, "it exceeds the size limit");
        return Ok(());
    }

    // 1. Settle: a half-written file is never copied (spec §8 step 1).
    std::thread::sleep(MirrorConfig::SETTLE);
    SETTLE_HOOK.with(|h| {
        if let Some(f) = h.borrow_mut().as_mut() {
            f();
        }
    });
    let Ok(second) = dir.stat(n) else {
        return Ok(());
    };
    if !second.same_version(&first) {
        requeue(ctx, rt, rel);
        return Ok(());
    }
    let (bytes, opened, file) = match dir.read_file(n, ctx.cfg.max_file_bytes) {
        Ok(x) => x,
        Err(e) => {
            match map_errno(&e) {
                IoClass::NotFound => return forget(ctx, rt, rel),
                // Grown past the limit or swapped for a link since the
                // check: it changed; the next run decides.
                IoClass::Symlink => requeue(ctx, rt, rel),
                _ if e.kind() == io::ErrorKind::FileTooLarge => requeue(ctx, rt, rel),
                _ if e.kind() == io::ErrorKind::InvalidInput => requeue(ctx, rt, rel),
                _ => refuse(&dir, name, "inumaki could not read it"),
            }
            return Ok(());
        }
    };
    if opened.nlink > 1 {
        refuse(&dir, name, "it has more than one hard link");
        return Ok(());
    }
    if !opened.same_version(&second) {
        requeue(ctx, rt, rel);
        return Ok(());
    }

    // 3. The same content as recorded: nothing to do (no duplicate after a
    //    restart).
    let mac = ctx.manifest.mac("mirror:outbox", &bytes);
    let prev_mac = rt
        .index
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .outbox
        .get(rel)
        .map(|r| r.content_mac);
    if prev_mac == Some(mac) {
        return Ok(());
    }
    let record = |outcome: OutboxOutcome, destination_rel: Option<Vec<u8>>| {
        rt.put_outbox(
            &*ctx.manifest,
            OutboxRecord {
                rel: rel.to_vec(),
                content_mac: mac,
                destination_rel,
                outcome,
            },
        )
        .map_err(|e| FolderError::from_engine(&e))
    };
    // 2. UTF-8 text and UTF-8 names only. Refusals that depend on the
    //    content are recorded, so an unchanged file is not refused again.
    let Ok(text) = String::from_utf8(bytes) else {
        refuse(&dir, name, "only UTF-8 text is restored");
        return record(OutboxOutcome::Refused, None);
    };
    let Ok(comps) = rel
        .split(|b| *b == b'/')
        .map(|c| std::str::from_utf8(c).map(str::to_string))
        .collect::<Result<Vec<String>, _>>()
    else {
        refuse(&dir, name, "only UTF-8 names are restored");
        return record(OutboxOutcome::Refused, None);
    };

    // 4. Tripwire: a known original in clear in model-written text is
    //    recorded, not blocked (the destination is local).
    let tripwire = ctx
        .engine
        .scan_clear(&ds, std::slice::from_ref(&text))
        .is_ok_and(|v| !v.is_empty());

    // 5. Strict restoration of the content and every path component.
    let text_len = text.len() as u64;
    let mut blocks = Vec::with_capacity(comps.len() + 1);
    blocks.push(text);
    blocks.extend(comps.iter().cloned());
    let restored = match ctx.engine.rehydrate_strict(&ds, blocks) {
        Ok(r) if r.len() == comps.len() + 1 => r,
        Ok(_) => return Err(FolderError::Internal),
        Err(EngineError::Unresolved { unknown, removed }) => {
            note(
                &dir,
                name,
                UNRESOLVED,
                &format!(
                    "inumaki did not save this file: it contains {unknown} token(s) inumaki \
                     cannot restore and {removed} removed value(s). Removed values (secrets) \
                     are never restored. Edit the file to fix it; inumaki will try again.\n"
                ),
            );
            record(OutboxOutcome::Unresolved, None)?;
            ctx.engine.record(Activity {
                dataset: ds,
                direction: ActivityDirection::Arguments,
                verdict: ActivityVerdict::Unresolved,
                kinds: Vec::new(),
                tripwire,
                bytes: text_len,
            });
            return Ok(());
        }
        Err(e) => return Err(FolderError::from_engine(&e)),
    };

    // 6. Restored names stay single components inside the destination.
    let last = comps.len() - 1;
    let mut out = Vec::with_capacity(comps.len());
    for (i, c) in restored[1..].iter().enumerate() {
        match restored_component(c, i < last) {
            Some(x) => out.push(x),
            None => {
                refuse(&dir, name, "a restored name is empty or not a valid name");
                return record(OutboxOutcome::Refused, None);
            }
        }
    }

    // Changed during restoration: never write a version that is not the
    // one on disk now (spec §5.1 step 8 applied to the outbox).
    if !unchanged(&dir, n, &file, &opened) {
        requeue(ctx, rt, rel);
        return Ok(());
    }

    // 7. A no-replace write; an existing destination file is never
    //    overwritten.
    let (parents, base) = out.split_at(last);
    let base = &base[0];
    let dest = match destination_dir(ctx, rt, parents) {
        Ok(d) => d,
        Err(DestError::InTheWay) => {
            // Not recorded: the walk retries it once the obstacle is gone.
            refuse(
                &dir,
                name,
                "a file or link at the destination is in the way of a folder",
            );
            return Ok(());
        }
        Err(DestError::Unwritable) => return Err(FolderError::OutboxUnwritable),
    };
    let content = restored[0].as_bytes();
    let mut written = None;
    for i in 1..=999u32 {
        let candidate = if i == 1 {
            base.clone()
        } else {
            fitted(base, &format!(" ({i})"), false)
        };
        match dest.write_new(OsStr::new(&candidate), content, 0o600) {
            Ok(()) => {
                written = Some(candidate);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            // The destination file system refuses the name itself (not a
            // failed write or `fsync`, which is retried).
            Err(e) if fsops::is_name_rejected(&e) => {
                refuse(
                    &dir,
                    name,
                    "the destination does not accept the restored name",
                );
                return record(OutboxOutcome::Refused, None);
            }
            Err(_) => return Err(FolderError::OutboxUnwritable),
        }
    }
    let Some(written) = written else {
        return Err(FolderError::OutboxUnwritable);
    };
    let mut dest_rel = parents.join("/");
    if !dest_rel.is_empty() {
        dest_rel.push('/');
    }
    dest_rel.push_str(&written);
    record(OutboxOutcome::Rehydrated, Some(dest_rel.into_bytes()))?;
    clear_notes(&dir, name);
    ctx.engine.record(Activity {
        dataset: ds,
        direction: ActivityDirection::Arguments,
        verdict: ActivityVerdict::Released,
        kinds: Vec::new(),
        tripwire,
        bytes: content.len() as u64,
    });
    Ok(())
}

/// Drop the record of an outbox file that is gone, so the counts
/// (`with_unresolved`, `rehydrated`) describe the outbox as it is and a
/// file written again under that name is processed as new. What was
/// written to the destination stays there.
fn forget(ctx: &Ctx, rt: &FolderRt, rel: &[u8]) -> Result<(), FolderError> {
    let known = rt
        .index
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .outbox
        .contains_key(rel);
    if known {
        rt.drop_outbox(&*ctx.manifest, rel)
            .map_err(|e| FolderError::from_engine(&e))?;
    }
    Ok(())
}

/// Queue every outbox file whose content differs from its record (spec §8
/// step 3; review I5): files written while the daemon was down, events the
/// watcher dropped, and the poll reconcile under `watch_failed`. A file
/// that cannot be read as a candidate (a link, too large, hard-linked) is
/// queued only while it has no refusal note. A record whose file was not
/// seen is queued too; processing drops it when the file is gone. Returns
/// the jobs queued.
pub(crate) fn walk(ctx: &Ctx, rt: &FolderRt) -> u64 {
    walk_from(ctx, rt, b"")
}

/// [`walk`] below `subtree` of the outbox. The stack holds paths, not
/// handles: each directory is reopened from the outbox handle
/// (`O_NOFOLLOW` per component), so the walk holds a few descriptors
/// however wide the tree is.
fn walk_from(ctx: &Ctx, rt: &FolderRt, subtree: &[u8]) -> u64 {
    let Ok(top) = outbox_dir(ctx, rt) else {
        return 0;
    };
    let known: HashMap<Vec<u8>, [u8; 32]> = rt
        .index
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .outbox
        .iter()
        .map(|(k, r)| (k.clone(), r.content_mac))
        .collect();
    let max = ctx.cfg.max_file_bytes;
    let mut queued = 0;
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut stack: Vec<Vec<u8>> = vec![subtree.to_vec()];
    while let Some(rel) = stack.pop() {
        let Ok(dir) = top.walk(&rel) else { continue };
        let Ok(entries) = dir.entries() else { continue };
        let present: HashSet<&[u8]> = entries.iter().map(|(n, _)| n.as_bytes()).collect();
        for (name, kind) in &entries {
            let nb = name.as_bytes();
            if names::ignored(nb) || is_own(nb) {
                continue;
            }
            let child = join(&rel, nb);
            seen.insert(child.clone());
            let noted = present.contains([nb, REFUSED.as_bytes()].concat().as_slice());
            let due = match kind {
                Kind::Dir => {
                    stack.push(child);
                    continue;
                }
                Kind::File => match dir.stat(name) {
                    Ok(m) if m.kind == Kind::File && m.nlink <= 1 && m.size <= max => {
                        match dir.read_file(name, max) {
                            Ok((bytes, meta, _)) if meta.nlink <= 1 => {
                                known.get(&child)
                                    != Some(&ctx.manifest.mac("mirror:outbox", &bytes))
                            }
                            _ => !noted,
                        }
                    }
                    Ok(_) => !noted,
                    Err(_) => false,
                },
                Kind::Symlink | Kind::Other => !noted,
            };
            if due {
                requeue(ctx, rt, &child);
                queued += 1;
            }
        }
    }
    let below = |r: &[u8]| {
        subtree.is_empty() || (r.starts_with(subtree) && r.get(subtree.len()) == Some(&b'/'))
    };
    for rel in known.keys() {
        if below(rel) && !seen.contains(rel) {
            requeue(ctx, rt, rel);
            queued += 1;
        }
    }
    queued
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restored_names_are_one_component_and_fit() {
        assert_eq!(
            restored_component("a/b\0c", false).as_deref(),
            Some("a_b_c")
        );
        assert_eq!(restored_component("..", false), None);
        assert_eq!(restored_component("", true), None);
        let long = format!("{}.txt", "ä".repeat(200));
        let c = restored_component(&long, false).unwrap();
        assert!(c.len() <= NAME_MAX && c.ends_with(".txt"), "{}", c.len());
        let two = fitted(&c, " (999)", false);
        assert!(two.len() <= NAME_MAX && two.ends_with(" (999).txt"));
        assert_eq!(fitted("reply.txt", " (2)", false), "reply (2).txt");
    }
}
