//! One source file through the pipeline (M5 spec §5.1). All helpers return
//! [`FolderError`] classes; nothing here formats a path, a name, or content.
//! Deletions come before any engine call (review I4); a new epoch is carried
//! before anything is sanitized in it (review Cr2); a directory is created
//! only from release-checked components (review I3).

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use inumaki_core::span::EntityKind;

use crate::config::MirrorConfig;
use crate::engine::{
    Activity, ActivityDirection, ActivityVerdict, Block, DatasetState, EngineError, ManifestStore,
    MirrorEngine, Outcome,
};
use crate::folder::{DirRecord, FileState, FolderRt, OpenSide, Reason, RootIdentity, SourceRecord};
use crate::formats::{self, Redo};
use crate::fsops::{self, Dir, IoClass, Kind, Meta, map_errno};
use crate::guard::{self, Last, ReleaseCheck};
use crate::names::{self, PlaceholderClass};
use crate::queue::{Job, Priority, WorkQueue};
use crate::status::FolderError;

/// Shared context of the workers.
pub(crate) struct Ctx {
    pub cfg: MirrorConfig,
    pub engine: Arc<dyn MirrorEngine>,
    pub manifest: Arc<dyn ManifestStore>,
    pub root: Dir,
    pub queue: WorkQueue,
    /// Test seam: runs between reading and the step-8 comparison.
    pub before_commit: Mutex<Option<Box<dyn Fn() + Send>>>,
    /// Test seam: what an open of the source root meets ([`SourceFault`]).
    pub source_fault: Mutex<Option<SourceFault>>,
}

/// Test seam of [`open_source_root`]; `None` in production.
#[derive(Clone)]
pub(crate) enum SourceFault {
    /// Fail with this errno (spec §16.1 item 9 simulates `EPERM` this way).
    Errno(i32),
    /// Wait until the gate opens, then open: a first open that a macOS
    /// privacy prompt blocks (TCC spike finding 2).
    Hold(Arc<crate::testing::Gate>),
}

/// What the worker does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Done,
    Requeue,
    Subtree,
}

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

pub(crate) fn eng(e: EngineError) -> FolderError {
    FolderError::from_engine(&e)
}

/// Split `a/b/c` into (`a/b`, `c`).
pub(crate) fn split_rel(rel: &[u8]) -> (&[u8], &[u8]) {
    match rel.iter().rposition(|b| *b == b'/') {
        Some(i) => (&rel[..i], &rel[i + 1..]),
        None => (&[], rel),
    }
}

/// The opened source root.
pub(crate) struct SourceRoot {
    pub dir: Dir,
    /// The root is known to be the one mirrored ([`RootId::trusted`]): a
    /// source entry that is not seen may be deleted from the mirror.
    pub may_delete: bool,
}

/// Open the source root and check it is the directory that was added
/// (device, inode, and the generation where the filesystem has one; see
/// spec §6.2 for the removable-disk limitation). A stored id without a
/// generation learns it here and stores it like an adopted id. A
/// folder added while its root could not be read adopts the first root it
/// opens; adopted before anything was mirrored, that id is trusted and
/// persisted (retried until it is stored); adopted over a non-empty
/// manifest (after a restart that lost an unpersisted id) it is only
/// compared against, and nothing is deleted (5c review I2).
pub(crate) fn open_source_root(ctx: &Ctx, rt: &FolderRt) -> Result<SourceRoot, FolderError> {
    // A first open may wait on a macOS prompt: `pending` while it does.
    let _opening = rt.begin_open(OpenSide::Source);
    let fault = ctx
        .source_fault
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    match fault {
        Some(SourceFault::Errno(errno)) => {
            return Err(FolderError::from_source_io(
                &std::io::Error::from_raw_os_error(errno),
            ));
        }
        Some(SourceFault::Hold(gate)) => gate.wait(),
        None => {}
    }
    let d = Dir::open_root(&rt.folder.source).map_err(|e| FolderError::from_source_io(&e))?;
    let m = d.meta().map_err(|e| FolderError::from_source_io(&e))?;
    let seen = RootIdentity {
        dev: m.dev,
        ino: m.ino,
        generation: d.generation(),
    };
    let empty = {
        let ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
        ix.files.is_empty() && ix.dirs.is_empty()
    };
    let id = {
        let mut id = rt.root_id.lock().unwrap_or_else(PoisonError::into_inner);
        match id.id {
            Some(x) if !x.matches(&seen) => return Err(FolderError::SourceMissing),
            // Stored before generations were recorded: the same (device,
            // inode) is this root, so its generation is learned and stored.
            Some(x) if x.generation.is_none() && seen.generation.is_some() => {
                id.id = Some(seen);
                id.persisted = false;
            }
            Some(_) => {}
            None => {
                id.id = Some(seen);
                id.trusted = empty;
            }
        }
        *id
    };
    if id.trusted && !id.persisted && ctx.manifest.put_root_id(&rt.folder.dataset, seen).is_ok() {
        let mut id = rt.root_id.lock().unwrap_or_else(PoisonError::into_inner);
        if id.id == Some(seen) {
            id.persisted = true;
        }
    }
    Ok(SourceRoot {
        dir: d,
        may_delete: id.trusted,
    })
}

/// Spec §7.3 (amended 2026-10-04, review Cr2): before anything is
/// sanitized in an epoch this folder has not seen, the previous epoch's
/// known originals are registered in it, so known-entity detection
/// survives the rotation. Idempotent; after a restart it runs once.
pub(crate) fn ensure_carried(
    ctx: &Ctx,
    rt: &FolderRt,
    st: &DatasetState,
) -> Result<(), FolderError> {
    let mut carried = rt
        .carried_epoch
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if *carried == Some(st.epoch_id) {
        return Ok(());
    }
    ctx.engine.carry_known(&rt.folder.dataset).map_err(eng)?;
    *carried = Some(st.epoch_id);
    Ok(())
}

pub(crate) fn mirror_dir(ctx: &Ctx, rt: &FolderRt) -> Result<Dir, FolderError> {
    ctx.root
        .child(OsStr::new(&rt.folder.label))
        .map_err(|e| FolderError::from_mirror_io(&e))
}

fn is_ignored_path(rel: &[u8]) -> bool {
    rel.split(|b| *b == b'/').any(names::ignored)
}

/// The mirror name of each component of `rel` (directories from the
/// component table, the last one as a file or directory name), creating
/// missing directory records. A component whose mirror path another entry
/// already owns gets a collision suffix (spec §4.3 rule 4), directories
/// included. `suffix` (`.md` for rendered formats) and `placeholder` are
/// appended to the last component of a file; a name that is then invalid
/// falls back to the opaque name. A name the engine did not pass (`Blocked`,
/// `Uncertain`) is never used, not even tokenized: it is the opaque name
/// too (spec §4.3 rule 3). Directory names are reused only when recorded
/// under this epoch and policy fingerprint `fp` (5b review I1).
#[allow(clippy::too_many_arguments)]
pub(crate) fn mirror_components(
    ctx: &Ctx,
    rt: &FolderRt,
    rel: &[u8],
    last_is_dir: bool,
    epoch: i64,
    fp: [u8; 32],
    suffix: Option<&str>,
    placeholder: Option<PlaceholderClass>,
) -> Result<Vec<String>, FolderError> {
    let ds = &rt.folder.dataset;
    let m = &*ctx.manifest;
    let parts: Vec<&[u8]> = rel
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        return Err(FolderError::Internal);
    }
    let ndirs = parts.len().saturating_sub(usize::from(!last_is_dir));
    let mut comps: Vec<Option<String>> = vec![None; parts.len()];
    // Known directory components of this epoch and fingerprint.
    {
        let ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
        for (i, c) in comps.iter_mut().enumerate().take(ndirs) {
            let prefix = parts[..=i].join(&b'/');
            if let Some(d) = ix
                .dirs
                .get(&prefix)
                .filter(|d| d.epoch_id == epoch && d.fingerprint == fp)
            {
                *c = Some(d.component.clone());
            }
        }
    }
    let recorded: Vec<bool> = comps.iter().map(Option::is_some).collect();
    // Sanitize the rest in one batch.
    let mut want: Vec<(usize, String, Option<String>)> = Vec::new(); // (index, stem, ext)
    for (i, p) in parts.iter().enumerate() {
        if comps[i].is_some() {
            continue;
        }
        let is_dir = i + 1 < parts.len() || last_is_dir;
        let Ok(name) = std::str::from_utf8(p) else {
            comps[i] = Some(names::opaque_name(
                m,
                ds,
                epoch,
                &parts[..=i].join(&b'/'),
                None,
            ));
            continue;
        };
        if i == 0 && names::casefold(name) == names::OUTBOX {
            comps[i] = Some(names::OUTBOX_RENAMED.to_string());
            continue;
        }
        let (stem, ext) = names::split_name(name, is_dir);
        want.push((i, stem.to_string(), ext.map(str::to_string)));
    }
    if !want.is_empty() {
        let out = ctx
            .engine
            .sanitize_names(ds, want.iter().map(|(_, s, _)| s.clone()).collect())
            .map_err(eng)?;
        if out.len() != want.len() {
            // One answer per stem or nothing is named (fail closed).
            return Err(FolderError::Internal);
        }
        for ((i, _, ext), b) in want.into_iter().zip(out) {
            let prefix = parts[..=i].join(&b'/');
            let name = match (b.outcome, &ext) {
                (Outcome::Pass, Some(e)) => format!("{}.{e}", b.text),
                (Outcome::Pass, None) => b.text,
                _ => names::opaque_name(m, ds, epoch, &prefix, ext.as_deref()),
            };
            let name = if names::valid_component(&name) {
                name
            } else {
                names::opaque_name(m, ds, epoch, &prefix, ext.as_deref())
            };
            comps[i] = Some(name);
        }
    }
    let mut comps: Vec<String> = comps.into_iter().map(Option::unwrap_or_default).collect();
    // Record new directory components, each with its full mirror path.
    for i in 0..ndirs {
        if recorded[i] {
            continue;
        }
        let prefix = parts[..=i].join(&b'/');
        let parent = comps[..i].join("/");
        let full = |c: &str| {
            if parent.is_empty() {
                c.to_string()
            } else {
                format!("{parent}/{c}")
            }
        };
        // Choose and claim the name under one index lock (5b review M3).
        let (reservation, old) = {
            let mut ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
            let old = ix.dirs.get(&prefix).map(|d| d.mirror_rel.clone());
            let taken = |ix: &crate::folder::Index, c: &str| {
                ix.mirror_taken(&names::casefold(&full(c)), &prefix)
            };
            if taken(&ix, &comps[i]) {
                let s = names::collision_suffix(m, ds, epoch, &prefix);
                let c = names::with_suffix(&comps[i], &s, None);
                comps[i] = if names::valid_component(&c) && !taken(&ix, &c) {
                    c
                } else {
                    names::with_suffix(&names::opaque_name(m, ds, epoch, &prefix, None), &s, None)
                };
            }
            let mirror_rel = full(&comps[i]).into_bytes();
            if !ix.reserve(&mirror_rel, &prefix) {
                return Err(FolderError::Internal);
            }
            (
                Reservation {
                    rt,
                    mirror_rel,
                    rel: prefix.clone(),
                },
                old,
            )
        };
        let record = DirRecord {
            rel: prefix,
            epoch_id: epoch,
            fingerprint: fp,
            component: comps[i].clone(),
            mirror_rel: reservation.mirror_rel.clone(),
        };
        let new = record.mirror_rel.clone();
        rt.put_dir(m, record).map_err(eng)?;
        drop(reservation);
        // The directory under its previous name (an older epoch's tokens, or
        // a name an older policy left in clear) goes once its files have
        // moved (spec §7.3, 5b review M2); an empty one goes now.
        if let Some(old) = old.filter(|o| *o != new) {
            prune_mirror_dirs(ctx, rt, &old);
        }
    }
    if last_is_dir {
        return Ok(comps);
    }
    // The last component of a file: suffix, placeholder, validity, collision.
    let decorate = |base: &str| {
        let mut n = base.to_string();
        if let Some(s) = suffix {
            n.push_str(s);
        }
        match placeholder {
            Some(p) => names::placeholder_name(&n, p),
            None => n,
        }
    };
    let ext = std::str::from_utf8(parts[parts.len() - 1])
        .ok()
        .and_then(|n| names::split_name(n, false).1);
    let opaque = || decorate(&names::opaque_name(m, ds, epoch, rel, ext));
    let mut last = decorate(&comps[comps.len() - 1]);
    if !names::valid_component(&last) {
        last = opaque();
    }
    let dirs = comps[..comps.len() - 1].join("/");
    let full = |n: &str| {
        if dirs.is_empty() {
            n.to_string()
        } else {
            format!("{dirs}/{n}")
        }
    };
    // `commit` claims the name before writing; a name taken meanwhile by
    // another worker is a requeue there (5b review M3).
    let ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
    let taken = |n: &str| ix.mirror_taken(&names::casefold(&full(n)), rel);
    if taken(&last) {
        let s = names::collision_suffix(m, ds, epoch, rel);
        let with = |n: &str| names::with_suffix(n, &s, formats::kept_extension(n));
        let c = with(&last);
        last = if names::valid_component(&c) && !taken(&c) {
            c
        } else {
            // A taken fallback would requeue forever in `commit`: fail
            // closed, as directories do (5b review N1).
            let o = with(&opaque());
            if !names::valid_component(&o) || taken(&o) {
                return Err(FolderError::Internal);
            }
            o
        };
    }
    drop(ix);
    let n = comps.len();
    comps[n - 1] = last;
    Ok(comps)
}

/// A directory's mirror components after the release check (spec §5.4): a
/// component that hits is replaced by its opaque name before any directory
/// is created (review I3).
pub(crate) fn checked_dir_components(
    ctx: &Ctx,
    rt: &FolderRt,
    rel: &[u8],
    epoch: i64,
    fp: [u8; 32],
) -> Result<Vec<String>, FolderError> {
    let comps = mirror_components(ctx, rt, rel, true, epoch, fp, None, None)?;
    match guard::release_check(ctx, rt, "", &comps)? {
        ReleaseCheck::Clean => Ok(comps),
        ReleaseCheck::Hit { components, .. } => {
            guard::opaque_components(ctx, rt, rel, epoch, fp, comps, &components, Last::Dir)
        }
    }
}

/// Create the mirror directories `comps` (0755), through handles. Callers
/// pass release-checked components only (review I3).
pub(crate) fn ensure_mirror_dirs(
    ctx: &Ctx,
    rt: &FolderRt,
    comps: &[String],
) -> Result<Dir, FolderError> {
    let mut d = mirror_dir(ctx, rt)?;
    for c in comps {
        d = d
            .ensure_dir(OsStr::new(c), 0o755)
            .map_err(|e| FolderError::from_mirror_io(&e))?;
    }
    Ok(d)
}

/// Whether the mirror directory lists `a` and `b` (same parent) as two
/// separate entries: false on a case-insensitive file system, where one
/// entry answers to both.
fn both_spellings_exist(ctx: &Ctx, rt: &FolderRt, a: &[u8], b: &[u8]) -> bool {
    let (parent, a_name) = split_rel(a);
    let (b_parent, b_name) = split_rel(b);
    if parent != b_parent {
        return false;
    }
    let Ok(m) = mirror_dir(ctx, rt) else {
        return false;
    };
    let Ok(entries) = m.walk(parent).and_then(|d| d.entries()) else {
        return false;
    };
    let has = |n: &[u8]| entries.iter().any(|(e, _)| e.as_bytes() == n);
    has(a_name) && has(b_name)
}

/// Unlink the mirror file `mirror_rel` (never a directory, never through a
/// symlink), then prune its parent if that is now an empty directory no
/// entry names.
fn unlink_mirror(ctx: &Ctx, rt: &FolderRt, mirror_rel: &[u8]) {
    let (parent, name) = split_rel(mirror_rel);
    if name.is_empty() {
        return;
    }
    if let Ok(m) = mirror_dir(ctx, rt) {
        if let Ok(p) = m.walk(parent) {
            let _ = p.unlink(OsStr::from_bytes(name));
        }
    }
    prune_mirror_dirs(ctx, rt, parent);
}

/// Remove the mirror directory `mirror_rel`, then each parent in turn,
/// while it is empty and no record or reservation holds its path (5b review
/// M2). Never recursive and never through a symlink: a directory that still
/// holds anything stays, for its files to move or for the orphan sweep. The
/// folder's mirror directory and its `outbox/` are never removed.
pub(crate) fn prune_mirror_dirs(ctx: &Ctx, rt: &FolderRt, mirror_rel: &[u8]) {
    let Ok(m) = mirror_dir(ctx, rt) else { return };
    let mut p = mirror_rel;
    while !p.is_empty() && !p.eq_ignore_ascii_case(names::OUTBOX.as_bytes()) {
        if rt
            .index
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .claimed(p)
        {
            return;
        }
        let (parent, name) = split_rel(p);
        let Ok(d) = m.walk(parent) else { return };
        if d.remove_empty_dir(OsStr::from_bytes(name)).is_err() {
            return;
        }
        p = parent;
    }
}

/// `r` is `rel` or lies below it.
fn within(r: &[u8], rel: &[u8]) -> bool {
    r == rel || (r.starts_with(rel) && r.get(rel.len()) == Some(&b'/'))
}

/// The source entry is gone: remove its mirror file or subtree and its
/// records. Needs no engine (spec §7.6: deletions continue under
/// `model_unavailable`); every file and directory record below `rel` is
/// unlinked by its own mirror path, so subtrees still on an older epoch's
/// names go too (review I4). Directories go deepest first and only once
/// empty; anything else left in one (an agent's file) is the orphan
/// sweep's (spec §7.2).
pub(crate) fn remove_entry(ctx: &Ctx, rt: &FolderRt, rel: &[u8]) -> Result<(), FolderError> {
    let (files, mut dirs): (Vec<SourceRecord>, Vec<DirRecord>) = {
        let ix = rt.index.lock().unwrap_or_else(PoisonError::into_inner);
        (
            ix.files
                .values()
                .filter(|f| within(&f.rel, rel))
                .cloned()
                .collect(),
            ix.dirs
                .values()
                .filter(|d| within(&d.rel, rel))
                .cloned()
                .collect(),
        )
    };
    for f in files {
        unlink_mirror(ctx, rt, &f.mirror_rel);
        rt.drop_file(&*ctx.manifest, &f.rel).map_err(eng)?;
    }
    dirs.sort_by_key(|d| std::cmp::Reverse(d.rel.iter().filter(|b| **b == b'/').count()));
    for d in dirs {
        rt.drop_dir(&*ctx.manifest, &d.rel).map_err(eng)?;
        prune_mirror_dirs(ctx, rt, &d.mirror_rel);
    }
    Ok(())
}

fn placeholder_text(r: Reason, max: u64) -> String {
    let head = "This file exists in the source folder and was not mirrored by inumaki.\n";
    let why = match r {
        Reason::UnsupportedFormat => "Reason: unsupported_format. inumaki mirrors text, Markdown, YAML, CSV, TSV, JSON, e-mail (.eml), and HTML files.\n".to_string(),
        Reason::TooLarge => format!("Reason: too_large. The limit is {max} bytes.\n"),
        Reason::Unreadable => "Reason: unreadable. inumaki could not read the file (for example, it is stored only in the cloud).\n".to_string(),
        Reason::SymbolicLink => "Reason: symbolic_link. Links are not followed.\n".to_string(),
        Reason::Blocked => "Reason: blocked. The file was withheld by verification.\n".to_string(),
        Reason::Uncertain => "Reason: uncertain. The file was withheld because verification was uncertain.\n".to_string(),
    };
    format!("{head}{why}")
}

fn family(r: Reason) -> (PlaceholderClass, FileState) {
    match r {
        Reason::Blocked | Reason::Uncertain => (PlaceholderClass::Blocked, FileState::Blocked),
        _ => (PlaceholderClass::Unsupported, FileState::Unsupported),
    }
}

/// A mirror path claimed in the index for one source entry until the
/// record is written or the write abandoned; released on drop (5b review
/// M3).
pub(crate) struct Reservation<'a> {
    pub(crate) rt: &'a FolderRt,
    pub(crate) mirror_rel: Vec<u8>,
    pub(crate) rel: Vec<u8>,
}

impl<'a> Reservation<'a> {
    /// `None` when another entry owns `mirror_rel`.
    fn take(rt: &'a FolderRt, mirror_rel: Vec<u8>, rel: &[u8]) -> Option<Reservation<'a>> {
        let ok = rt
            .index
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reserve(&mirror_rel, rel);
        ok.then(|| Reservation {
            rt,
            mirror_rel,
            rel: rel.to_vec(),
        })
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.rt
            .index
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unreserve(&self.mirror_rel, &self.rel);
    }
}

/// Run `rel` again later, at live priority.
fn requeue(ctx: &Ctx, rt: &FolderRt, rel: &[u8]) {
    ctx.queue.push(
        Job::Source {
            dataset: rt.folder.dataset.clone(),
            rel: rel.to_vec(),
            force: false,
        },
        Priority::Live,
    );
}

struct Seen {
    meta: Meta,
    mac: [u8; 32],
}

/// Spec §5.1 step 9: write, delete the previous mirror path if it differs,
/// upsert the manifest row.
#[allow(clippy::too_many_arguments)]
fn commit(
    ctx: &Ctx,
    rt: &FolderRt,
    rel: &[u8],
    comps: Vec<String>,
    bytes: &[u8],
    seen: &Seen,
    epoch: i64,
    fp: [u8; 32],
    state: FileState,
    reason: Option<Reason>,
) -> Result<Step, FolderError> {
    let mirror_rel = comps.join("/").into_bytes();
    // Claim the name before writing (5b review M3): with several workers,
    // another file may have taken it since `mirror_components` chose it.
    let Some(_reservation) = Reservation::take(rt, mirror_rel.clone(), rel) else {
        requeue(ctx, rt, rel);
        return Ok(Step::Requeue);
    };
    let (dirs, last) = comps.split_at(comps.len() - 1);
    let d = ensure_mirror_dirs(ctx, rt, dirs)?;
    d.write_atomic(OsStr::new(&last[0]), bytes, 0o444, Some(seen.meta.mtime))
        .map_err(|e| FolderError::from_mirror_io(&e))?;
    let prev = rt
        .index
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .files
        .get(rel)
        .map(|r| r.mirror_rel.clone());
    if let Some(p) = prev.filter(|p| *p != mirror_rel) {
        // On a case-insensitive file system a previous name equal to the new
        // one (NFC, case-folded) is the entry just written: unlink it only
        // when the directory holds both spellings as separate entries.
        if names::casefold(&String::from_utf8_lossy(&p))
            != names::casefold(&String::from_utf8_lossy(&mirror_rel))
            || both_spellings_exist(ctx, rt, &p, &mirror_rel)
        {
            unlink_mirror(ctx, rt, &p);
        }
    }
    rt.put_file(
        &*ctx.manifest,
        SourceRecord {
            rel: rel.to_vec(),
            mirror_rel,
            size: seen.meta.size,
            mtime: seen.meta.mtime,
            content_mac: seen.mac,
            epoch_id: epoch,
            fingerprint: fp,
            state,
            reason,
            mirrored_at: now(),
        },
    )
    .map_err(eng)?;
    let mut s = rt.status.lock().unwrap_or_else(PoisonError::into_inner);
    s.last_mirrored_at = Some(now());
    s.succeed();
    Ok(Step::Done)
}

/// A placeholder (spec §5.5); its name goes through steps 6 and 7 like a
/// mirror file's. Withheld files (`blocked`, `uncertain`) get an activity
/// record with the kinds; the placeholder itself never names them.
#[allow(clippy::too_many_arguments)]
fn write_placeholder(
    ctx: &Ctx,
    rt: &FolderRt,
    rel: &[u8],
    seen: &Seen,
    st: &DatasetState,
    reason: Reason,
    suffix: Option<&str>,
    kinds: Vec<EntityKind>,
) -> Result<Step, FolderError> {
    let (fam, state) = family(reason);
    let comps = mirror_components(
        ctx,
        rt,
        rel,
        false,
        st.epoch_id,
        st.fingerprint,
        suffix,
        Some(fam),
    )?;
    let comps = match guard::release_check(ctx, rt, "", &comps)? {
        ReleaseCheck::Clean => comps,
        ReleaseCheck::Hit { components, .. } => guard::opaque_components(
            ctx,
            rt,
            rel,
            st.epoch_id,
            st.fingerprint,
            comps,
            &components,
            Last::File {
                suffix,
                placeholder: Some(fam),
            },
        )?,
    };
    let step = commit(
        ctx,
        rt,
        rel,
        comps,
        placeholder_text(reason, ctx.cfg.max_file_bytes).as_bytes(),
        seen,
        st.epoch_id,
        st.fingerprint,
        state,
        Some(reason),
    )?;
    if step != Step::Done {
        return Ok(step);
    }
    if matches!(reason, Reason::Blocked | Reason::Uncertain) {
        ctx.engine.record(Activity {
            dataset: rt.folder.dataset.clone(),
            direction: ActivityDirection::Result,
            verdict: if reason == Reason::Blocked {
                ActivityVerdict::Blocked
            } else {
                ActivityVerdict::Uncertain
            },
            kinds: kinds.into_iter().map(|k| (k, 1)).collect(),
            tripwire: false,
            bytes: 0,
        });
    }
    Ok(Step::Done)
}

/// The mirror file `mirror_rel` exists as a regular file (through
/// handles, never through a link).
pub(crate) fn mirror_file_present(ctx: &Ctx, rt: &FolderRt, mirror_rel: &[u8]) -> bool {
    let (parent, file) = split_rel(mirror_rel);
    mirror_dir(ctx, rt)
        .and_then(|d| d.walk(parent).map_err(|e| FolderError::from_mirror_io(&e)))
        .and_then(|d| {
            d.stat(OsStr::from_bytes(file))
                .map_err(|e| FolderError::from_mirror_io(&e))
        })
        .is_ok_and(|m| m.kind == Kind::File)
}

/// A placeholder decided before the content is read (link, dataless, too
/// large, unreadable). If the manifest already holds this placeholder for
/// this version of the entry, under this epoch and policy, and its mirror
/// file is there, nothing is written, forced or not: the bytes and the name
/// would be the same, and a rewrite would only replace the inode, which the
/// watcher and sync clients see as a change.
fn source_placeholder(
    ctx: &Ctx,
    rt: &FolderRt,
    rel: &[u8],
    seen: &Seen,
    st: &DatasetState,
    reason: Reason,
) -> Result<Step, FolderError> {
    let prev = rt
        .index
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .files
        .get(rel)
        .cloned();
    let unchanged = prev.is_some_and(|r| {
        r.reason == Some(reason)
            && r.state == family(reason).1
            && r.epoch_id == st.epoch_id
            && r.fingerprint == st.fingerprint
            && r.size == seen.meta.size
            && r.mtime == seen.meta.mtime
            && mirror_file_present(ctx, rt, &r.mirror_rel)
    });
    if unchanged {
        return Ok(Step::Done);
    }
    write_placeholder(ctx, rt, rel, seen, st, reason, None, vec![])
}

enum Sanitized {
    Text {
        text: String,
        kinds: Vec<EntityKind>,
    },
    Withheld(Reason, Vec<EntityKind>),
}

fn add_kinds(into: &mut Vec<EntityKind>, kinds: Vec<EntityKind>) {
    for k in kinds {
        if !into.contains(&k) {
            into.push(k);
        }
    }
}

/// Send `blocks` to the engine in adaptive sub-batches (spec §5.1 step 5):
/// about [`MirrorConfig::SUB_BATCH_BYTES`] each, the target halved after a
/// call that took longer than [`MirrorConfig::SUB_BATCH_BUDGET`], so no
/// single call holds the namespace lock for long (the daemon's adapter
/// does not split a batch). `each` gets every sub-batch's inputs and
/// results in order and returns `false` to stop. A result count that does
/// not match its inputs is an error (fail closed).
fn sub_batches(
    ctx: &Ctx,
    ds: &str,
    blocks: &[String],
    mut each: impl FnMut(&[String], Vec<Block>) -> bool,
) -> Result<(), FolderError> {
    let mut target = MirrorConfig::SUB_BATCH_BYTES;
    let mut i = 0;
    while i < blocks.len() {
        let mut j = i;
        let mut size = 0;
        while j < blocks.len() && (j == i || size + blocks[j].len() <= target) {
            size += blocks[j].len();
            j += 1;
        }
        let started = Instant::now();
        let res = ctx
            .engine
            .sanitize(ds, blocks[i..j].to_vec())
            .map_err(eng)?;
        // Numbers only: the longest a single call held the namespace lock.
        tracing::debug!(
            batch_ms = started.elapsed().as_millis() as u64,
            bytes = size as u64,
            "mirror sub-batch"
        );
        if started.elapsed() > MirrorConfig::SUB_BATCH_BUDGET {
            target = (target / 2).max(1024);
        }
        if res.len() != j - i {
            return Err(FolderError::Internal);
        }
        if !each(&blocks[i..j], res) {
            return Ok(());
        }
        i = j;
    }
    Ok(())
}

/// Sanitized content blocks and their kinds, or why the file is withheld.
type BlockOutcome = Result<(Vec<String>, Vec<EntityKind>), (Reason, Vec<EntityKind>)>;

/// Content blocks → sanitized blocks, or why the file is withheld. A
/// `Blocked` block wins over an `Uncertain` one in the same sub-batch; the
/// first sub-batch with either stops the file.
fn sanitize_blocks(ctx: &Ctx, ds: &str, blocks: &[String]) -> Result<BlockOutcome, FolderError> {
    let mut out = Vec::with_capacity(blocks.len());
    let mut kinds: Vec<EntityKind> = Vec::new();
    let mut withheld: Option<Reason> = None;
    sub_batches(ctx, ds, blocks, |_, res| {
        for b in res {
            add_kinds(&mut kinds, b.kinds);
            match b.outcome {
                Outcome::Pass => out.push(b.text),
                Outcome::Blocked => withheld = Some(Reason::Blocked),
                Outcome::Uncertain => {
                    withheld.get_or_insert(Reason::Uncertain);
                }
            }
        }
        withheld.is_none()
    })?;
    Ok(match withheld {
        Some(r) => Err((r, kinds)),
        None => Ok((out, kinds)),
    })
}

/// Blocks → assembled text, with the object-level check (spec §5.2). A
/// block or verification block over [`MirrorConfig::MAX_BLOCK_BYTES`]
/// withholds the whole file before the engine sees it.
fn sanitize_doc(ctx: &Ctx, ds: &str, mut doc: formats::Doc) -> Result<Sanitized, FolderError> {
    for _ in 0..3 {
        if formats::oversized(doc.blocks()) {
            return Ok(Sanitized::Withheld(Reason::Blocked, Vec::new()));
        }
        let (out, mut kinds) = match sanitize_blocks(ctx, ds, doc.blocks())? {
            Ok(x) => x,
            Err((r, k)) => return Ok(Sanitized::Withheld(r, k)),
        };
        match doc.assemble(&out) {
            Ok(a) => {
                if formats::oversized(&a.verify) {
                    return Ok(Sanitized::Withheld(Reason::Blocked, Vec::new()));
                }
                // Released only if every verification block comes back
                // `Pass` with no new replacement.
                let mut clean = true;
                sub_batches(ctx, ds, &a.verify, |inputs, res| {
                    for (b, input) in res.into_iter().zip(inputs) {
                        if b.outcome != Outcome::Pass || b.text != *input {
                            clean = false;
                        }
                        add_kinds(&mut kinds, b.kinds);
                    }
                    clean
                })?;
                if !clean {
                    return Ok(Sanitized::Withheld(Reason::Uncertain, kinds));
                }
                return Ok(Sanitized::Text {
                    text: a.text,
                    kinds,
                });
            }
            Err(Redo::AsText(d)) | Err(Redo::Records(d)) => doc = d,
        }
    }
    Ok(Sanitized::Withheld(Reason::Uncertain, Vec::new()))
}

/// Process one source path (spec §5.1).
pub(crate) fn process_source(
    ctx: &Ctx,
    rt: &FolderRt,
    rel: &[u8],
    force: bool,
) -> Result<Step, FolderError> {
    let ds = rt.folder.dataset.clone();
    if rel.is_empty() || is_ignored_path(rel) {
        return Ok(Step::Done);
    }
    // Step 1. Deletions first: they need no engine (spec §7.6, review I4).
    // A root that is not known to be the mirrored one deletes nothing.
    let src = open_source_root(ctx, rt)?;
    let (parent_rel, name) = split_rel(rel);
    let name = OsStr::from_bytes(name);
    let parent = match src.dir.walk(parent_rel) {
        Ok(p) => p,
        Err(e) if matches!(map_errno(&e), IoClass::NotFound | IoClass::Symlink) => {
            if src.may_delete {
                remove_entry(ctx, rt, rel)?;
            }
            return Ok(Step::Done);
        }
        Err(_) => return Ok(Step::Done),
    };
    let stat = match parent.stat(name) {
        Err(e) if map_errno(&e) == IoClass::NotFound => {
            if src.may_delete {
                remove_entry(ctx, rt, rel)?;
            }
            return Ok(Step::Done);
        }
        other => other,
    };
    let st = ctx.engine.state(&ds).map_err(eng)?;
    ensure_carried(ctx, rt, &st)?;
    let meta = match stat {
        Ok(m) => m,
        Err(_) => {
            let seen = Seen {
                meta: Meta {
                    kind: Kind::File,
                    size: 0,
                    mtime: (0, 0),
                    ctime: (0, 0),
                    dev: 0,
                    ino: 0,
                    nlink: 1,
                    dataless: false,
                },
                mac: [0; 32],
            };
            return source_placeholder(ctx, rt, rel, &seen, &st, Reason::Unreadable);
        }
    };
    let blank = Seen { meta, mac: [0; 32] };
    match meta.kind {
        Kind::Dir => return Ok(Step::Subtree),
        Kind::Other => return Ok(Step::Done),
        Kind::Symlink => {
            return source_placeholder(ctx, rt, rel, &blank, &st, Reason::SymbolicLink);
        }
        Kind::File => {}
    }
    if meta.dataless {
        return source_placeholder(ctx, rt, rel, &blank, &st, Reason::Unreadable);
    }
    if meta.size > ctx.cfg.max_file_bytes {
        return source_placeholder(ctx, rt, rel, &blank, &st, Reason::TooLarge);
    }
    // Step 2: the manifest shortcut.
    let prev = rt
        .index
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .files
        .get(rel)
        .cloned();
    let current = |r: &SourceRecord| {
        // An unreadable placeholder is not final: a chmod or a cloud
        // download keeps size and mtime (5b review M1).
        r.epoch_id == st.epoch_id
            && r.fingerprint == st.fingerprint
            && r.state != FileState::Pending
            && r.reason != Some(Reason::Unreadable)
            // Past the link and size checks above, a link or too-large
            // record means the entry changed kind or the limit was raised.
            && r.reason != Some(Reason::SymbolicLink)
            && r.reason != Some(Reason::TooLarge)
    };
    if let Some(r) = &prev {
        if !force && current(r) && r.size == meta.size && r.mtime == meta.mtime {
            return Ok(Step::Done);
        }
    }
    // Step 3: read through the handle; the same content: update the mtime.
    let read = {
        let _opening = rt.begin_open(OpenSide::Source);
        parent.read_file(name, ctx.cfg.max_file_bytes)
    };
    let (bytes, opened, file) = match read {
        Ok(x) => {
            rt.opened(OpenSide::Source);
            x
        }
        Err(e) => {
            // The file grew past the limit after the `lstat` (5b review M5).
            let reason = if e.kind() == std::io::ErrorKind::FileTooLarge {
                Reason::TooLarge
            } else {
                Reason::Unreadable
            };
            return source_placeholder(ctx, rt, rel, &blank, &st, reason);
        }
    };
    let mac = ctx.manifest.mac("mirror:content", &bytes);
    if let Some(r) = &prev {
        if !force && r.content_mac == mac && current(r) {
            let mut r = r.clone();
            r.mtime = opened.mtime;
            r.size = opened.size;
            rt.put_file(&*ctx.manifest, r).map_err(eng)?;
            return Ok(Step::Done);
        }
    }
    let seen = Seen { meta: opened, mac };
    // Step 4: classify, decode, split.
    let format = formats::classify(name.as_bytes());
    let suffix = formats::mirror_suffix(format);
    let doc = match formats::prepare(format, &bytes) {
        Ok(d) => d,
        Err(_) => {
            return write_placeholder(
                ctx,
                rt,
                rel,
                &seen,
                &st,
                Reason::UnsupportedFormat,
                None,
                vec![],
            );
        }
    };
    // Steps 5-7: content, names, file-level release check (one redo).
    let sanitize_started = Instant::now();
    let mut attempt = 0;
    let (text, kinds, comps) = loop {
        let (text, kinds) = match sanitize_doc(ctx, &ds, doc.clone())? {
            Sanitized::Text { text, kinds } => (text, kinds),
            Sanitized::Withheld(r, k) => {
                return write_placeholder(ctx, rt, rel, &seen, &st, r, suffix, k);
            }
        };
        let comps = mirror_components(
            ctx,
            rt,
            rel,
            false,
            st.epoch_id,
            st.fingerprint,
            suffix,
            None,
        )?;
        let (content, hits) = match guard::release_check(ctx, rt, &text, &comps)? {
            ReleaseCheck::Clean => break (text, kinds, comps),
            ReleaseCheck::Hit {
                content,
                components,
            } => (content, components),
        };
        // A directory component that hit is renamed to its opaque name now
        // (spec §7.5), which needs no redo: the file's own text and name
        // are what a redo could fix.
        let last = comps.len() - 1;
        let dir_hits: Vec<usize> = hits.iter().copied().filter(|i| *i < last).collect();
        let comps = if dir_hits.is_empty() {
            comps
        } else {
            guard::opaque_components(
                ctx,
                rt,
                rel,
                st.epoch_id,
                st.fingerprint,
                comps,
                &dir_hits,
                Last::File {
                    suffix,
                    placeholder: None,
                },
            )?
        };
        if !content && !hits.contains(&last) {
            break (text, kinds, comps);
        }
        if attempt == 0 {
            attempt += 1;
            continue;
        }
        // A second hit is a confirmed original (spec §5.4): any existing
        // copy goes first, then the file is withheld.
        guard::remove_confirmed_copy(ctx, rt, rel)?;
        return write_placeholder(ctx, rt, rel, &seen, &st, Reason::Blocked, suffix, kinds);
    };
    // Step 8: the file must still be the version that was read.
    if let Some(hook) = ctx
        .before_commit
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
    {
        hook();
    }
    let now_fd = fsops::fstat_file(&file).map_err(|_| FolderError::Internal)?;
    let now_path = parent.stat(name).ok();
    if !now_fd.same_version(&opened) || now_path.is_none_or(|p| !p.same_version(&opened)) {
        requeue(ctx, rt, rel);
        return Ok(Step::Requeue);
    }
    // Step 9.
    let sanitize_ms = sanitize_started.elapsed().as_millis() as u64;
    let write_started = Instant::now();
    let step = commit(
        ctx,
        rt,
        rel,
        comps,
        text.as_bytes(),
        &seen,
        st.epoch_id,
        st.fingerprint,
        FileState::Mirrored,
        None,
    )?;
    if step != Step::Done {
        return Ok(step);
    }
    tracing::debug!(
        sanitize_ms,
        write_ms = write_started.elapsed().as_millis() as u64,
        bytes = text.len() as u64,
        "mirror file"
    );
    ctx.engine.record(Activity {
        dataset: rt.folder.dataset.clone(),
        direction: ActivityDirection::Result,
        verdict: ActivityVerdict::Released,
        kinds: kinds.into_iter().map(|k| (k, 1)).collect(),
        tripwire: false,
        bytes: text.len() as u64,
    });
    Ok(Step::Done)
}
