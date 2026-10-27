//! The tool-result hook's daemon side (M6 spec §5.2, §9.7 as amended
//! 2026-09-29). One request carries every text of one tool result. The
//! hook sanitizes only when the tool input references a connected source
//! folder or outbox destination, or the texts contain a known original of
//! two or more words or of an identifier kind (plan 2c's rule,
//! [`service::scan_known_names`]). Otherwise it passes the output through.
//! After sanitizing, every known-entity span of every dataset is checked
//! again, at any confidence and single words included
//! ([`service::known_left`]); one left over is a block.

use std::path::{Component, Path, PathBuf};

use inumaki_core::span::EntityKind;
use inumaki_core::verify::Reason;

use crate::cache::CachedOutcome;
use crate::pathcmp;
use crate::service::{self, BlockInput, ServiceError, sanitize_blocks};
use crate::state::AppState;

/// Connected source folders, their outbox destinations, and the mirror
/// root. M5 implements this and sets `AppState::folders` inside
/// `AppState::start`, before the server accepts requests; until it merges,
/// `folders` is unset and [`NoFolders`] applies.
pub trait FolderRegistry: Send + Sync {
    /// `(dataset id, source directory)` of each connected folder.
    fn source_roots(&self) -> Vec<(String, PathBuf)>;
    /// `(dataset id, outbox destination)` of each connected folder: the
    /// rehydrated files there hold originals (review I9).
    fn outbox_destinations(&self) -> Vec<(String, PathBuf)>;
    /// The mirror root, if the mirror is available.
    fn mirror_root(&self) -> Option<PathBuf>;
}

/// Most paths one hook request may reference when folders are connected.
/// Each path is resolved against the filesystem, so the count is bounded;
/// a request over it is refused, not truncated (see [`run_hook`]).
pub const MAX_HOOK_PATHS: usize = 4096;

/// No folders (before M5).
pub struct NoFolders;

impl FolderRegistry for NoFolders {
    fn source_roots(&self) -> Vec<(String, PathBuf)> {
        Vec::new()
    }
    fn outbox_destinations(&self) -> Vec<(String, PathBuf)> {
        Vec::new()
    }
    fn mirror_root(&self) -> Option<PathBuf> {
        None
    }
}

/// One hook request: all texts of one tool result. `Debug` prints counts.
pub struct HookInput {
    /// The tool call's working directory.
    pub cwd: PathBuf,
    /// Paths the tool input references.
    pub paths: Vec<String>,
    /// Keys, strings, and numbers of the tool output, in the hook's order.
    pub texts: Vec<String>,
}

impl std::fmt::Debug for HookInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookInput")
            .field("paths", &self.paths.len())
            .field("texts", &self.texts.len())
            .field("bytes", &self.texts.iter().map(String::len).sum::<usize>())
            .finish_non_exhaustive()
    }
}

/// What the hook answers. `Debug` prints counts and flags, never text or
/// the dataset.
pub enum HookOutcome {
    /// Pass the output unchanged.
    Pass,
    /// Replace the texts with their sanitized versions.
    Replace {
        /// Sanitized texts, same length and order as the input.
        texts: Vec<String>,
        /// Kinds replaced.
        kinds: Vec<EntityKind>,
        /// Dataset used.
        dataset: String,
        /// The tripwire found a known original.
        tripwire: bool,
    },
    /// Block it.
    Block {
        /// Kinds.
        kinds: Vec<EntityKind>,
        /// Reasons.
        reasons: Vec<Reason>,
        /// Dataset used.
        dataset: String,
        /// The tripwire found a known original.
        tripwire: bool,
    },
}

impl std::fmt::Debug for HookOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookOutcome::Pass => f.write_str("Pass"),
            HookOutcome::Replace {
                texts,
                kinds,
                tripwire,
                ..
            } => f
                .debug_struct("Replace")
                .field("texts", &texts.len())
                .field("kinds", &kinds.len())
                .field("tripwire", tripwire)
                .finish_non_exhaustive(),
            HookOutcome::Block {
                kinds,
                reasons,
                tripwire,
                ..
            } => f
                .debug_struct("Block")
                .field("kinds", &kinds.len())
                .field("reasons", &reasons.len())
                .field("tripwire", tripwire)
                .finish_non_exhaustive(),
        }
    }
}

fn push_kind(kinds: &mut Vec<EntityKind>, k: EntityKind) {
    if !kinds.contains(&k) {
        kinds.push(k);
    }
}

/// Every dataset the hook scans: all but the proxy's reserved chat
/// dataset, whose namespace holds no entities by design (M8 spec §9) and
/// whose profile is the proxy's, not one a hook result should depend on.
fn hook_datasets(state: &AppState) -> Result<Vec<inumaki_vault::Dataset>, ServiceError> {
    Ok(state
        .vault
        .datasets()?
        .into_iter()
        .filter(|d| d.kind != inumaki_vault::DatasetKind::Chat)
        .collect())
}

/// The trigger over every dataset: `(dataset id, hits)` for each dataset
/// with at least one known original under plan 2c's rule. No NER.
fn trigger_hits(state: &AppState, texts: &[String]) -> Result<Vec<(String, u32)>, ServiceError> {
    let mut out = Vec::new();
    for d in hook_datasets(state)? {
        let hits: u32 = service::scan_known_names(state, &d.id, texts)?
            .iter()
            .map(|(_, n)| *n)
            .sum();
        if hits > 0 {
            out.push((d.id, hits));
        }
    }
    Ok(out)
}

/// `path` against `cwd`, symlinks resolved. A path that does not exist (a
/// file an Edit creates) is normalized lexically (`.` and `..` removed),
/// and its longest existing ancestor is canonicalized, so a new file under
/// a symlinked folder still resolves into that folder.
fn resolve(cwd: &Path, path: &str) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let p = match (path.strip_prefix("~/"), home) {
        (Some(rest), Some(h)) => h.join(rest),
        _ if Path::new(path).is_absolute() => PathBuf::from(path),
        _ => cwd.join(path),
    };
    if let Ok(c) = std::fs::canonicalize(&p) {
        return c;
    }
    let mut lexical = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::ParentDir => {
                lexical.pop();
            }
            Component::Normal(x) => lexical.push(x),
            _ => {}
        }
    }
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let mut base = lexical.clone();
    loop {
        if let Ok(c) = std::fs::canonicalize(&base) {
            return rest.iter().rev().fold(c, |acc, x| acc.join(x));
        }
        match base.file_name() {
            Some(name) => {
                rest.push(name.to_os_string());
                base.pop();
            }
            None => return lexical,
        }
    }
}

/// Closed-set facts about one hook request for its log line (M6-3 Task
/// 9b): flags only, never a path, a dataset, or text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HookTrace {
    /// A referenced path resolved under a connected source folder or
    /// outbox destination (the folder rule picked the dataset).
    pub root_match: bool,
    /// A referenced path resolved under the mirror before any root match
    /// (exempt from the folder rule).
    pub mirror_match: bool,
}

/// Spec §5.2 steps 1–4. Blocking: call from the blocking pool. Any error
/// (vault, store, model, detector) is returned, never a pass: the caller
/// withholds the output (fail closed).
pub fn run_hook(state: &AppState, input: &HookInput) -> Result<HookOutcome, ServiceError> {
    run_hook_traced(state, input, &mut HookTrace::default())
}

/// [`run_hook`], filling `trace` as far as it got (also on an error).
pub fn run_hook_traced(
    state: &AppState,
    input: &HookInput,
    trace: &mut HookTrace,
) -> Result<HookOutcome, ServiceError> {
    let none = NoFolders;
    let reg: &dyn FolderRegistry = match state.folders.get() {
        Some(r) => r.as_ref(),
        None => &none,
    };
    let canon = |p: PathBuf| std::fs::canonicalize(&p).unwrap_or(p);
    let roots: Vec<(String, PathBuf)> = reg
        .source_roots()
        .into_iter()
        .chain(reg.outbox_destinations())
        .map(|(d, r)| (d, canon(r)))
        .collect();
    // The mirror exemption holds only for a real directory (an agent that
    // replaced the root with a symlink to a source must not exempt that
    // source) and only when no folder root holds or sits in it (M5 review
    // I1). It stays an exact match: no case folding.
    let mirror = reg
        .mirror_root()
        .filter(|m| std::fs::symlink_metadata(m).is_ok_and(|md| md.is_dir()))
        .map(canon)
        .filter(|m| !roots.iter().any(|(_, r)| pathcmp::overlap(m, r)));
    // More paths than the cap cannot all be checked against the roots, and
    // ignoring the excess could pass a source folder's content: refuse, so
    // the caller withholds the output (fail closed). Without roots no path
    // is resolved, so the count costs nothing and the request goes on.
    if !roots.is_empty() && input.paths.len() > MAX_HOOK_PATHS {
        return Err(ServiceError::Unsupported("hook_paths"));
    }
    // The first referenced path under a connected folder picks its dataset;
    // the deepest root wins. Paths under the mirror are exempt from this
    // rule only: the tripwire still runs on their output. With no folder
    // root (`NoFolders`) no path can match, so none is resolved.
    let paths: &[String] = if roots.is_empty() { &[] } else { &input.paths };
    let by_path = paths
        .iter()
        .map(|p| resolve(&input.cwd, p))
        .filter(|p| {
            let under = mirror.as_ref().is_some_and(|m| p.starts_with(m));
            trace.mirror_match |= under;
            !under
        })
        .find_map(|p| {
            roots
                .iter()
                .filter(|(_, r)| pathcmp::starts_with(&p, r))
                .max_by_key(|(_, r)| r.components().count())
                .map(|(d, _)| d.clone())
        });
    trace.root_match = by_path.is_some();
    let hits = trigger_hits(state, &input.texts)?;
    let tripwire = !hits.is_empty();
    let dataset = match by_path {
        Some(d) => d,
        // Most hits; on a tie the smallest id (datasets come sorted by id).
        None => match hits
            .iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        {
            Some((d, _)) => d.clone(),
            None => return Ok(HookOutcome::Pass),
        },
    };
    // One batch: every text of the tool result in one namespace lock, with
    // the dataset's own profile.
    let results = sanitize_blocks(
        state,
        &dataset,
        None,
        input
            .texts
            .iter()
            .map(|t| BlockInput::text(t.clone()))
            .collect(),
    )?;
    if results.len() != input.texts.len() {
        return Err(ServiceError::Unsupported("hook_batch"));
    }
    let mut kinds: Vec<EntityKind> = Vec::new();
    let mut reasons: Vec<Reason> = Vec::new();
    let mut blocked = false;
    for r in &results {
        // Blocked, or uncertain (the gateway withholds those too).
        blocked |= r.outcome != CachedOutcome::Pass;
        for k in &r.kinds {
            push_kind(&mut kinds, k.clone());
        }
        reasons.extend(r.reasons.iter().cloned());
    }
    if blocked {
        return Ok(HookOutcome::Block {
            kinds,
            reasons,
            dataset,
            tripwire,
        });
    }
    let texts: Vec<String> = results.into_iter().map(|r| r.text).collect();
    // The re-scan: every dataset, every known-entity span at any confidence.
    let mut left: Vec<Reason> = Vec::new();
    for d in hook_datasets(state)? {
        left.extend(service::known_left(state, &d.id, &texts)?);
    }
    if !left.is_empty() {
        let mut kinds: Vec<EntityKind> = Vec::new();
        for r in &left {
            push_kind(&mut kinds, r.kind.clone());
        }
        return Ok(HookOutcome::Block {
            kinds,
            reasons: left,
            dataset,
            tripwire,
        });
    }
    Ok(HookOutcome::Replace {
        texts,
        kinds,
        dataset,
        tripwire,
    })
}
