//! Release check, tripwire pass, removal of confirmed originals (M5 spec
//! §5.4, §7.4, §7.5). Everything here reads and changes the mirror only,
//! through handles; nothing depends on the source, so a removal runs under
//! an untrusted or missing root too (it deletes a clear copy the mirror
//! wrote, not an entry whose source is gone).

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::PoisonError;

use crate::config::MirrorConfig;
use crate::engine::{Activity, ActivityDirection, ActivityVerdict};
use crate::folder::{DirRecord, FileState, FolderRt, SourceRecord};
use crate::fsops::{IoClass, Kind, map_errno};
use crate::names::{self, PlaceholderClass};
use crate::pipeline::{Ctx, Reservation, eng, mirror_dir, prune_mirror_dirs, split_rel};
use crate::queue::{Job, Priority};
use crate::status::FolderError;

/// The release check's answer.
pub(crate) enum ReleaseCheck {
    /// No known original in the text or the mirror path.
    Clean,
    /// A known original in clear: in the content, and/or in these mirror
    /// path components (indexes into the components checked).
    Hit {
        content: bool,
        components: Vec<usize>,
    },
}

/// The window `known_in_clear` gets of a long text: one call holds the
/// namespace lock, so no call gets more than one block's worth.
const WINDOW: usize = MirrorConfig::MAX_BLOCK_BYTES;
/// Windows start this far apart, so they overlap by half: an original up to
/// half a window long lies whole inside one of them.
const STEP: usize = WINDOW / 2;

/// `text` as overlapping windows of at most [`WINDOW`] bytes, cut at
/// character boundaries. Empty text: none.
fn windows(text: &str) -> Vec<&str> {
    if text.len() <= WINDOW {
        return if text.is_empty() { vec![] } else { vec![text] };
    }
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        let mut end = (start + WINDOW).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        out.push(&text[start..end]);
        if end == text.len() {
            return out;
        }
        let mut next = start + STEP;
        while !text.is_char_boundary(next) {
            next -= 1;
        }
        start = next;
    }
}

/// `known_in_clear` over `text` and every component in `comps` (spec §5.4;
/// the service checks each as written and spaced). One file per call, never
/// a batch of files: the components and the first window go in one call, a
/// text longer than [`WINDOW`] continues in one call per window. A result
/// count that does not match is an error (fail closed).
pub(crate) fn release_check(
    ctx: &Ctx,
    rt: &FolderRt,
    text: &str,
    comps: &[String],
) -> Result<ReleaseCheck, FolderError> {
    let ds = &rt.folder.dataset;
    let mut rest = windows(text).into_iter();
    let mut texts: Vec<String> = comps.to_vec();
    texts.extend(rest.next().map(str::to_string));
    if texts.is_empty() {
        return Ok(ReleaseCheck::Clean);
    }
    let hits = ctx.engine.known_in_clear(ds, &texts).map_err(eng)?;
    if hits.len() != texts.len() {
        return Err(FolderError::Internal);
    }
    let components: Vec<usize> = hits[..comps.len()]
        .iter()
        .enumerate()
        .filter(|(_, h)| h.is_some())
        .map(|(i, _)| i)
        .collect();
    let mut content = hits[comps.len()..].iter().any(Option::is_some);
    for w in rest {
        if content {
            break;
        }
        let h = ctx
            .engine
            .known_in_clear(ds, &[w.to_string()])
            .map_err(eng)?;
        if h.len() != 1 {
            return Err(FolderError::Internal);
        }
        content = h[0].is_some();
    }
    Ok(if content || !components.is_empty() {
        ReleaseCheck::Hit {
            content,
            components,
        }
    } else {
        ReleaseCheck::Clean
    })
}

/// What the last component checked is.
#[derive(Clone, Copy)]
pub(crate) enum Last<'a> {
    /// A directory, like the others.
    Dir,
    /// A file name, decorated like `mirror_components` does it.
    File {
        suffix: Option<&'a str>,
        placeholder: Option<PlaceholderClass>,
    },
}

/// Replace the components in `hits` with opaque names (spec §4.3 rule 3,
/// §7.5 step 1). A directory component is renamed in the mirror, which
/// moves its subtree in one rename, and its record is written under
/// `epoch` and the policy fingerprint `fp`, so the directory-name cache
/// keeps the opaque name for this epoch and policy (5b review I1). A file
/// name gets the opaque name of its source path, decorated as `last` says;
/// `commit` claims it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn opaque_components(
    ctx: &Ctx,
    rt: &FolderRt,
    rel: &[u8],
    epoch: i64,
    fp: [u8; 32],
    mut comps: Vec<String>,
    hits: &[usize],
    last: Last<'_>,
) -> Result<Vec<String>, FolderError> {
    let parts: Vec<&[u8]> = rel
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() || parts.len() != comps.len() {
        return Err(FolderError::Internal);
    }
    let ndirs = match last {
        Last::Dir => parts.len(),
        Last::File { .. } => parts.len() - 1,
    };
    let mut hits = hits.to_vec();
    hits.sort_unstable();
    hits.dedup();
    // Parents first: a directory renamed moves what lies below it, and the
    // components after it are resolved under its new name.
    for i in hits {
        if i >= parts.len() {
            return Err(FolderError::Internal);
        }
        let prefix = parts[..=i].join(&b'/');
        if i < ndirs {
            comps[i] = rename_dir(ctx, rt, &prefix, &comps[..i], &comps[i], epoch, fp)?;
            continue;
        }
        let Last::File {
            suffix,
            placeholder,
        } = last
        else {
            unreachable!("every component of a directory path is a directory");
        };
        let ds = &rt.folder.dataset;
        let ext = std::str::from_utf8(parts[i])
            .ok()
            .and_then(|n| names::split_name(n, false).1);
        let mut name = names::opaque_name(&*ctx.manifest, ds, epoch, rel, ext);
        if let Some(s) = suffix {
            name.push_str(s);
        }
        if let Some(p) = placeholder {
            name = names::placeholder_name(&name, p);
        }
        let full = [comps[..i].join("/"), name.clone()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        let taken = rt
            .index
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .mirror_taken(&names::casefold(&full), rel);
        // Taken only by a source entry literally named like the opaque name:
        // fail closed, as `mirror_components` does (5b review N1).
        if !names::valid_component(&name) || taken {
            return Err(FolderError::Internal);
        }
        comps[i] = name;
    }
    Ok(comps)
}

/// Rename the mirror directory `parents/old` (the source directory
/// `prefix`) to an opaque name and move the mirror paths of every file and
/// directory record below it. Returns the new component. The directory's
/// own record is written when it names `old_path` (or there is none), so it
/// is never created under the old name again (review I3); a record that
/// already names another path (a newer epoch's) is left alone and only the
/// records below `old_path` move (5d review minor 3). Only the renamed
/// directory and a leftover at the target name are touched: a link or a
/// file under the old name is unlinked, an empty directory at the target
/// removed with one `REMOVEDIR`; nothing is removed recursively. A target
/// that holds something (a non-empty directory) is skipped for the next
/// candidate name, so the clear name always leaves the disk (5d review
/// minor 2).
fn rename_dir(
    ctx: &Ctx,
    rt: &FolderRt,
    prefix: &[u8],
    parents: &[String],
    old: &str,
    epoch: i64,
    fp: [u8; 32],
) -> Result<String, FolderError> {
    let ds = &rt.folder.dataset;
    let m = &*ctx.manifest;
    let parent_path = parents.join("/");
    let full = |c: &str| {
        if parent_path.is_empty() {
            c.to_string()
        } else {
            format!("{parent_path}/{c}")
        }
    };
    let old_path = full(old).into_bytes();
    let base = names::opaque_name(m, ds, epoch, prefix, None);
    let candidates = (0..RENAME_CANDIDATES).map(|n| match n {
        0 => base.clone(),
        1 => names::with_suffix(&base, &names::collision_suffix(m, ds, epoch, prefix), None),
        n => names::opaque_name(m, ds, epoch, &[prefix, &[0, n][..]].concat(), None),
    });
    let mut chosen = None;
    for c in candidates {
        // Choose and claim the name under one index lock (5b review M3).
        let reservation = {
            let mut ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
            let mirror_rel = full(&c).into_bytes();
            if ix.mirror_taken(&names::casefold(&full(&c)), prefix)
                || !ix.reserve(&mirror_rel, prefix)
            {
                continue;
            }
            Reservation {
                rt,
                mirror_rel,
                rel: prefix.to_vec(),
            }
        };
        if reservation.mirror_rel == old_path
            || move_on_disk(ctx, rt, parent_path.as_bytes(), old, &c)?
        {
            chosen = Some((c, reservation));
            break;
        }
    }
    // Every candidate taken or occupied: fail, the job is retried.
    let Some((new, reservation)) = chosen else {
        return Err(FolderError::MirrorUnwritable);
    };
    let new_path = reservation.mirror_rel.clone();
    let own = rt
        .index
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .dirs
        .get(prefix)
        .map(|d| d.mirror_rel.clone());
    if own.is_none_or(|o| o == old_path) {
        rt.put_dir(
            m,
            DirRecord {
                rel: prefix.to_vec(),
                epoch_id: epoch,
                fingerprint: fp,
                component: new.clone(),
                mirror_rel: new_path.clone(),
            },
        )
        .map_err(eng)?;
    }
    drop(reservation);
    if new_path == old_path {
        return Ok(new);
    }
    let below = |p: &[u8]| p.starts_with(&old_path) && p.get(old_path.len()) == Some(&b'/');
    let moved = |p: &[u8]| [new_path.as_slice(), &p[old_path.len()..]].concat();
    let (files, dirs): (Vec<SourceRecord>, Vec<DirRecord>) = {
        let ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
        (
            ix.files
                .values()
                .filter(|f| below(&f.mirror_rel))
                .cloned()
                .collect(),
            ix.dirs
                .values()
                .filter(|d| below(&d.mirror_rel))
                .cloned()
                .collect(),
        )
    };
    for mut f in files {
        f.mirror_rel = moved(&f.mirror_rel);
        rt.put_file(m, f).map_err(eng)?;
    }
    for mut d in dirs {
        d.mirror_rel = moved(&d.mirror_rel);
        rt.put_dir(m, d).map_err(eng)?;
    }
    Ok(new)
}

/// Opaque names tried for one directory: its own, the collision-suffixed
/// one, then derived ones.
const RENAME_CANDIDATES: u8 = 8;

/// `parent/old` → `parent/new` in the mirror, then `fsync` the parent; a
/// clear name moved or removed is a tripwire activity record (spec §7.5).
/// Not there (or behind a link): nothing to move. `false` when something
/// that cannot be cleared without a recursive delete holds `new`.
fn move_on_disk(
    ctx: &Ctx,
    rt: &FolderRt,
    parent: &[u8],
    old: &str,
    new: &str,
) -> Result<bool, FolderError> {
    let io = |e: std::io::Error| FolderError::from_mirror_io(&e);
    let p = match mirror_dir(ctx, rt)?.walk(parent) {
        Ok(p) => p,
        Err(e) if matches!(map_errno(&e), IoClass::NotFound | IoClass::Symlink) => {
            return Ok(true);
        }
        Err(e) => return Err(io(e)),
    };
    match p.stat(OsStr::new(old)) {
        Ok(meta) if meta.kind == Kind::Dir => {
            // Nothing the manifest names is at `new` (it is reserved): what
            // is there is a leftover, removed the way the sweep would.
            if names::casefold(old) != names::casefold(new) {
                match p.stat(OsStr::new(new)) {
                    Ok(t) if t.kind == Kind::Dir => {
                        let _ = p.remove_empty_dir(OsStr::new(new));
                    }
                    Ok(_) => p.unlink(OsStr::new(new)).map_err(io)?,
                    Err(_) => {}
                }
            }
            if let Err(e) = p.rename(OsStr::new(old), &p, OsStr::new(new)) {
                return match e.raw_os_error() {
                    Some(libc::ENOTEMPTY | libc::EEXIST | libc::EISDIR | libc::ENOTDIR) => {
                        Ok(false)
                    }
                    _ => Err(io(e)),
                };
            }
        }
        // A link or a file under a name that holds an original: not the
        // mirror's directory; it goes.
        Ok(_) => p.unlink(OsStr::new(old)).map_err(io)?,
        Err(e) if map_errno(&e) == IoClass::NotFound => return Ok(true),
        Err(e) => return Err(io(e)),
    }
    p.sync().map_err(io)?;
    record_removal(ctx, rt);
    Ok(true)
}

/// Unlink the mirror file `mirror_rel` (never through a link) and `fsync`
/// its directory (a tripwire activity record, spec §7.5); prune its parent if that is now an empty directory no
/// entry names. A directory in its place goes only if empty. Absent: done.
fn unlink_copy(ctx: &Ctx, rt: &FolderRt, mirror_rel: &[u8]) -> Result<(), FolderError> {
    let (parent, name) = split_rel(mirror_rel);
    if name.is_empty() {
        return Ok(());
    }
    let io = |e: std::io::Error| FolderError::from_mirror_io(&e);
    let p = match mirror_dir(ctx, rt)?.walk(parent) {
        Ok(p) => p,
        Err(e) if matches!(map_errno(&e), IoClass::NotFound | IoClass::Symlink) => return Ok(()),
        Err(e) => return Err(io(e)),
    };
    let name = OsStr::from_bytes(name);
    match p.stat(name) {
        Ok(m) if m.kind == Kind::Dir => p.remove_empty_dir(name).map_err(io)?,
        Ok(_) => p.unlink(name).map_err(io)?,
        Err(e) if map_errno(&e) == IoClass::NotFound => return Ok(()),
        Err(e) => return Err(io(e)),
    }
    p.sync().map_err(io)?;
    record_removal(ctx, rt);
    prune_mirror_dirs(ctx, rt, parent);
    Ok(())
}

/// Unlink `rel`'s existing mirror copy and record it `pending` (spec §7.5
/// steps 1 and 2): the startup reconcile then never sees a manifest row
/// that names the removed copy. Used before a second release-check hit's
/// placeholder (spec §5.4) and by [`remove_confirmed`].
pub(crate) fn remove_confirmed_copy(
    ctx: &Ctx,
    rt: &FolderRt,
    rel: &[u8],
) -> Result<(), FolderError> {
    let prev = rt
        .index
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .files
        .get(rel)
        .cloned();
    if let Some(mut r) = prev {
        unlink_copy(ctx, rt, &r.mirror_rel)?;
        if r.state != FileState::Pending {
            r.state = FileState::Pending;
            rt.put_file(&*ctx.manifest, r).map_err(eng)?;
        }
    }
    Ok(())
}

/// The components of a mirror path.
fn components(mirror_rel: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(mirror_rel)
        .split('/')
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect()
}

/// A mirror file's text as the tripwire sees it.
enum MirrorText {
    /// Nothing there (or not a regular file): no content to leak.
    Absent,
    Text(String),
    /// There, but not readable as the text the mirror wrote: treated as a
    /// hit (fail closed).
    Unreadable,
}

/// Read the mirror file `mirror_rel` through handles, never through a link.
/// The cap leaves room for sanitized text longer than its source (tokens
/// are longer than most names, `.md` rendering adds markup).
fn read_mirror(ctx: &Ctx, rt: &FolderRt, mirror_rel: &[u8]) -> Result<MirrorText, FolderError> {
    let (parent, name) = split_rel(mirror_rel);
    let p = match mirror_dir(ctx, rt)?.walk(parent) {
        Ok(p) => p,
        Err(e) if matches!(map_errno(&e), IoClass::NotFound | IoClass::Symlink) => {
            return Ok(MirrorText::Absent);
        }
        Err(_) => return Ok(MirrorText::Unreadable),
    };
    let name = OsStr::from_bytes(name);
    // Only an entry that is not there, or that is a directory, fifo, or
    // socket, holds no text; every other failure is a hit (5d review).
    match p.stat(name) {
        Ok(m) if matches!(m.kind, Kind::Dir | Kind::Other) => return Ok(MirrorText::Absent),
        Ok(_) => {}
        Err(e) if map_errno(&e) == IoClass::NotFound => return Ok(MirrorText::Absent),
        Err(_) => return Ok(MirrorText::Unreadable),
    }
    let cap = ctx.cfg.max_file_bytes.saturating_mul(8);
    Ok(match p.read_file(name, cap) {
        Ok((b, _, _)) => match String::from_utf8(b) {
            Ok(s) => MirrorText::Text(s),
            Err(_) => MirrorText::Unreadable,
        },
        Err(_) => MirrorText::Unreadable,
    })
}

/// Check one file record: its mirror path and, when it is mirrored content,
/// its text. `None` when clean; else whether the content hit and which
/// components did.
fn check_file(
    ctx: &Ctx,
    rt: &FolderRt,
    r: &SourceRecord,
) -> Result<Option<(bool, Vec<usize>)>, FolderError> {
    let comps = components(&r.mirror_rel);
    // A placeholder's text is fixed; only mirrored content can hold an
    // original.
    let (text, unreadable) = if r.state == FileState::Mirrored {
        match read_mirror(ctx, rt, &r.mirror_rel)? {
            MirrorText::Text(t) => (t, false),
            MirrorText::Absent => (String::new(), false),
            MirrorText::Unreadable => (String::new(), true),
        }
    } else {
        (String::new(), false)
    };
    Ok(match release_check(ctx, rt, &text, &comps)? {
        ReleaseCheck::Clean if !unreadable => None,
        ReleaseCheck::Clean => Some((true, Vec::new())),
        ReleaseCheck::Hit {
            content,
            components,
        } => Some((content || unreadable, components)),
    })
}

fn record_removal(ctx: &Ctx, rt: &FolderRt) {
    ctx.engine.record(Activity {
        dataset: rt.folder.dataset.clone(),
        direction: ActivityDirection::Result,
        verdict: ActivityVerdict::Blocked,
        kinds: Vec::new(),
        tripwire: true,
        bytes: 0,
    });
}

/// A confirmed original (spec §7.5), for a file or a directory record
/// (an empty directory has no file to carry it): re-checked first, so a
/// job whose original an earlier removal already took does nothing. Then:
/// 1. every directory component that hit is renamed to its opaque name
///    (one subtree move) and its record written; a file whose content or
///    name hit is unlinked; 2. the file is recorded `pending`; 3. it is
///    requeued at live priority, where the known-entity detector now
///    tokenizes the name. Each directory moved and each copy removed is a
///    tripwire activity record. This removes a clear copy from the mirror, so it
///    runs whatever the source root's state (an untrusted root only stops
///    deletions based on a source not being seen). Errors propagate: the
///    worker keeps the job for the poller's retry (review Cr1).
pub(crate) fn remove_confirmed(ctx: &Ctx, rt: &FolderRt, rel: &[u8]) -> Result<(), FolderError> {
    let ds = &rt.folder.dataset;
    let (file, dir) = {
        let ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
        (
            ix.files.get(rel).cloned(),
            ix.dirs.get(rel).map(|d| d.mirror_rel.clone()),
        )
    };
    let Some(r) = file else {
        let Some(mirror_rel) = dir else {
            return Ok(());
        };
        let comps = components(&mirror_rel);
        let ReleaseCheck::Hit { components, .. } = release_check(ctx, rt, "", &comps)? else {
            return Ok(());
        };
        let st = ctx.engine.state(ds).map_err(eng)?;
        opaque_components(
            ctx,
            rt,
            rel,
            st.epoch_id,
            st.fingerprint,
            comps,
            &components,
            Last::Dir,
        )?;
        return Ok(());
    };
    let Some((content, hits)) = check_file(ctx, rt, &r)? else {
        return Ok(());
    };
    let last = components(&r.mirror_rel).len().saturating_sub(1);
    let dir_hits: Vec<usize> = hits.iter().copied().filter(|i| *i < last).collect();
    let file_hit = content || hits.contains(&last);
    if !dir_hits.is_empty() {
        let st = ctx.engine.state(ds).map_err(eng)?;
        opaque_components(
            ctx,
            rt,
            rel,
            st.epoch_id,
            st.fingerprint,
            components(&r.mirror_rel),
            &dir_hits,
            Last::File {
                suffix: None,
                placeholder: None,
            },
        )?;
    }
    if file_hit {
        // The record's mirror path as moved by the renames above.
        remove_confirmed_copy(ctx, rt, rel)?;
        ctx.queue.push(
            Job::Source {
                dataset: ds.clone(),
                rel: rel.to_vec(),
                force: true,
            },
            Priority::Live,
        );
    }
    Ok(())
}

/// Re-check every mirrored file, file name, and directory name of a folder
/// (spec §7.4; directories too, review I3) with `known_in_clear`, one file
/// or directory per call. Reads the mirror, never the source. Each hit
/// becomes a `Job::Confirmed` at removal priority. On completion the
/// generation the pass started from is stored, so a change made during the
/// pass triggers another one (review Cr1); a pass that fails stores
/// nothing and is run again. Returns the hits.
pub(crate) fn tripwire_pass(ctx: &Ctx, rt: &FolderRt) -> Result<u32, FolderError> {
    let ds = &rt.folder.dataset;
    let generation = ctx.engine.state(ds).map_err(eng)?.entries_generation;
    if *rt
        .tripwire_generation
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        == Some(generation)
    {
        return Ok(0); // nothing learned since the last completed pass
    }
    let (files, dirs): (Vec<SourceRecord>, Vec<DirRecord>) = {
        let ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
        (
            ix.files.values().cloned().collect(),
            ix.dirs.values().cloned().collect(),
        )
    };
    let mut hits = 0;
    let mut confirmed = |rel: Vec<u8>| {
        hits += 1;
        ctx.queue.push(
            Job::Confirmed {
                dataset: ds.clone(),
                rel,
            },
            Priority::Removal,
        );
    };
    for r in files {
        if check_file(ctx, rt, &r)?.is_some() {
            confirmed(r.rel);
        }
    }
    for d in dirs {
        if let ReleaseCheck::Hit { .. } = release_check(ctx, rt, "", &components(&d.mirror_rel))? {
            confirmed(d.rel);
        }
    }
    *rt.tripwire_generation
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(generation);
    *rt.last_tripwire
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(std::time::Instant::now());
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_overlap_by_half_and_cover_the_text() {
        assert!(windows("").is_empty());
        assert_eq!(windows("abc"), vec!["abc"]);
        // Multi-byte characters across the boundaries.
        let text: String = "äöü x".repeat(WINDOW / 3);
        let w = windows(&text);
        assert!(w.len() > 2);
        assert!(w.iter().all(|s| s.len() <= WINDOW));
        assert!(text.starts_with(w[0]) && text.ends_with(w[w.len() - 1]));
        // Any span up to half a window lies whole inside one window.
        let needle = "Qwxzvk Yolandir";
        for at in [STEP - 3, STEP, WINDOW - 7, 2 * STEP + 1] {
            let mut t = "a".repeat(3 * WINDOW);
            t.replace_range(at..at + needle.len(), needle);
            assert!(windows(&t).iter().any(|s| s.contains(needle)), "{at}");
        }
    }
}
