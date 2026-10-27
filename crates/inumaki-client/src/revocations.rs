//! Pending gateway token revocations (offline Revert spec D2, D3, D4, D7).
//!
//! When the app reverts a harness while the service is not running, it
//! cannot revoke the harness's gateway token: the token's row id lives in
//! the vault, which only the service opens. It writes a record instead,
//! `<data dir>/revocations/<harness-key>.json`, holding exactly
//! `{"version":1,"label":"app:<harness-key>"}` and a newline: no token, no
//! id, no hash, no time, no path. The service applies every record after it
//! binds its control socket and before its gateway listens, and on every
//! sweep, by revoking every token with that label.
//!
//! This module owns the format: the writer the app uses and the reader the
//! service uses, so there is one parser for a fail-closed security record.
//! The reader fails closed: a record it cannot trust is reported as
//! [`Pending::Unreadable`], and the service then revokes every `app:` token.
//!
//! Symbolic links are never followed: a `revocations` path that is a link
//! is refused by the writer and is "not listable" for the reader, and an
//! entry that is a link is unreadable (the link is removed, its target is
//! never touched). Errors carry fixed stage words only, never a path.
#![deny(missing_docs)]

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::HarnessId;

/// The directory under the data directory that holds the records.
pub const DIR: &str = "revocations";

/// The only record version this module writes and accepts.
const VERSION: u32 = 1;

/// A record larger than this is unreadable (a valid one is under 64 bytes).
const MAX_RECORD: u64 = 1024;

/// Every harness, for mapping a file stem back to its harness. The unit
/// test `every_harness_is_listed_with_its_label_and_file_stem` takes the
/// variants from the derived `Deserialize` and fails unless this list holds
/// each exactly once, in the order of the test's exhaustive `index` match
/// (which stops compiling on a new variant). A variant missing here would
/// make its records unreadable (over-revoke, fail closed).
const HARNESSES: [HarnessId; 4] = [
    HarnessId::ClaudeCode,
    HarnessId::Codex,
    HarnessId::Hermes,
    HarnessId::Openclaw,
];

/// Why a record could not be written, listed, or removed. The payload is a
/// fixed stage word (`"create dir"`, `"write"`, `"sync"`, `"rename"`,
/// `"list"`, `"inspect"`, `"remove"`, and `"vault"` from the service),
/// never a path, a label, or an OS error text.
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    /// A file system step failed.
    #[error("pending revocations: {0}")]
    Io(&'static str),
}

/// What a record in the directory asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pending {
    /// Revoke every gateway token with this label (one of the four
    /// `app:<harness-key>` labels, matching the record's file name).
    Label(String),
    /// The record cannot be trusted: revoke every token whose label starts
    /// with `app:`.
    Unreadable,
}

/// The record's exact shape; any other key makes it unreadable.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    label: String,
}

/// The harness's key in labels and file names.
fn harness_key(h: HarnessId) -> &'static str {
    match h {
        HarnessId::ClaudeCode => "claude-code",
        HarnessId::Codex => "codex",
        HarnessId::Hermes => "hermes",
        HarnessId::Openclaw => "openclaw",
    }
}

/// The gateway token label of a harness: `"app:<harness-key>"`. Equal to
/// the app's `connect::token_label`.
pub fn label(h: HarnessId) -> String {
    format!("app:{}", harness_key(h))
}

fn dir_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DIR)
}

fn file_name(h: HarnessId) -> String {
    format!("{}.json", harness_key(h))
}

fn temp_name(h: HarnessId) -> String {
    format!(".{}.json.tmp", harness_key(h))
}

/// `fsync` a directory so a rename or a removal in it is durable.
fn sync_dir(dir: &Path) -> Result<(), RevocationError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|_| RevocationError::Io("sync"))
}

/// Remove a file or link; a missing one is fine.
fn remove_if_present(path: &Path) -> Result<(), RevocationError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RevocationError::Io("remove")),
    }
}

/// Whether the directory exists; a symbolic link is refused (`inspect`).
fn dir_exists(dir: &Path) -> Result<bool, RevocationError> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => Err(RevocationError::Io("inspect")),
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(RevocationError::Io("inspect")),
    }
}

/// Make sure the directory exists and is a real directory, not a link.
/// A directory this call creates gets mode 0700 (so do missing parents);
/// an existing one keeps its mode.
fn ensure_dir(dir: &Path) -> Result<(), RevocationError> {
    if dir_exists(dir)? {
        return Ok(());
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| RevocationError::Io("create dir"))?;
    // A link planted in between is refused like one found above.
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => {}
        _ => return Err(RevocationError::Io("inspect")),
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| RevocationError::Io("create dir"))
}

/// Write the record of `h` atomically (spec D3): create the directory
/// (0700) when missing, remove a leftover temporary file, write
/// `.<harness-key>.json.tmp` with `create_new` (0600), `fsync` it, rename it
/// to `<harness-key>.json`, and `fsync` the directory. Returns only after
/// the directory `fsync`, so a success is durable. A `revocations` path
/// that is a symbolic link is refused.
pub fn record(data_dir: &Path, h: HarnessId) -> Result<(), RevocationError> {
    let dir = dir_path(data_dir);
    ensure_dir(&dir)?;
    let tmp = dir.join(temp_name(h));
    // A leftover (or planted link) is removed so `create_new` never follows it.
    remove_if_present(&tmp)?;
    let body = serde_json::to_string(&Record {
        version: VERSION,
        label: label(h),
    })
    .map_err(|_| RevocationError::Io("write"))?;
    let written = write_temp(&tmp, format!("{body}\n").as_bytes()).and_then(|()| {
        std::fs::rename(&tmp, dir.join(file_name(h))).map_err(|_| RevocationError::Io("rename"))
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(&dir)
}

fn write_temp(tmp: &Path, bytes: &[u8]) -> Result<(), RevocationError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .map_err(|_| RevocationError::Io("write"))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| RevocationError::Io("write"))?;
    f.write_all(bytes)
        .map_err(|_| RevocationError::Io("write"))?;
    f.sync_all().map_err(|_| RevocationError::Io("sync"))
}

/// Whether a record of `h` is present (whatever it holds). The entry is
/// inspected without following a link; a `revocations` path that is a
/// symbolic link is an error.
pub fn is_pending(data_dir: &Path, h: HarnessId) -> Result<bool, RevocationError> {
    let dir = dir_path(data_dir);
    if !dir_exists(&dir)? {
        return Ok(false);
    }
    match std::fs::symlink_metadata(dir.join(file_name(h))) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(RevocationError::Io("inspect")),
    }
}

/// Remove the record of `h`; a missing one is fine. A `revocations` path
/// that is a symbolic link is an error (see [`remove`]).
pub fn clear(data_dir: &Path, h: HarnessId) -> Result<(), RevocationError> {
    remove(&dir_path(data_dir).join(file_name(h)))
}

/// Remove one entry [`scan`] returned (a link itself, never its target),
/// then `fsync` its directory. A missing entry (or directory) is fine; a
/// directory that is a symbolic link is an error (`inspect`), so nothing is
/// removed through it.
pub fn remove(path: &Path) -> Result<(), RevocationError> {
    if let Some(dir) = path.parent()
        && !dir_exists(dir)?
    {
        return Ok(());
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(RevocationError::Io("remove")),
    }
    match path.parent() {
        Some(dir) => sync_dir(dir),
        None => Ok(()),
    }
}

/// Every record in the directory, by file name, with what it asks for.
///
/// - A missing directory: no records.
/// - A `revocations` path that is a symbolic link, is not a directory, or
///   cannot be listed: `Err` (the service must not serve).
/// - `.<name>.json.tmp` leftovers: removed (an unfinished write the app
///   reported nothing for) and not returned.
/// - `<name>.json`: [`Pending::Label`] only when it is a regular file of at
///   most 1 KiB that parses as exactly `{"version":1,"label":…}` and the
///   label is `label(h)` of the harness `<name>` names; anything else
///   (an unknown name, a link, a directory, another version, an extra key,
///   another label) is [`Pending::Unreadable`].
/// - Other names are ignored.
pub fn scan(data_dir: &Path) -> Result<Vec<(PathBuf, Pending)>, RevocationError> {
    let dir = dir_path(data_dir);
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(RevocationError::Io("list")),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(RevocationError::Io("list")),
    }
    let mut out = Vec::new();
    let mut leftovers = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|_| RevocationError::Io("list"))? {
        let entry = entry.map_err(|_| RevocationError::Io("list"))?;
        let name = entry.file_name();
        let bytes = name.as_bytes();
        if bytes.starts_with(b".") && bytes.ends_with(b".json.tmp") {
            leftovers.push(entry.path());
        } else if let Some(stem) = bytes.strip_suffix(b".json") {
            let path = entry.path();
            let pending = read_record(&path, stem);
            out.push((path, pending));
        }
    }
    let removed = !leftovers.is_empty();
    for tmp in leftovers {
        remove_if_present(&tmp)?;
    }
    if removed {
        sync_dir(&dir)?;
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// What the entry at `path`, whose name is `<stem>.json`, asks for.
fn read_record(path: &Path, stem: &[u8]) -> Pending {
    let Some(h) = HARNESSES
        .into_iter()
        .find(|h| harness_key(*h).as_bytes() == stem)
    else {
        return Pending::Unreadable;
    };
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => {}
        _ => return Pending::Unreadable,
    }
    let Ok(f) = File::open(path) else {
        return Pending::Unreadable;
    };
    // The entry may have been swapped between the check and the open.
    match f.metadata() {
        Ok(m) if m.is_file() => {}
        _ => return Pending::Unreadable,
    }
    let mut buf = Vec::new();
    if f.take(MAX_RECORD + 1).read_to_end(&mut buf).is_err() || buf.len() as u64 > MAX_RECORD {
        return Pending::Unreadable;
    }
    match serde_json::from_slice::<Record>(&buf) {
        Ok(r) if r.version == VERSION && r.label == label(h) => Pending::Label(r.label),
        _ => Pending::Unreadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant's serde name, read from the derived `Deserialize`:
    /// serde's "unknown variant" error lists all of them, so this list is
    /// never written by hand and cannot go stale.
    fn every_variant_name() -> Vec<String> {
        let e = serde_json::from_str::<HarnessId>("\"\"")
            .unwrap_err()
            .to_string();
        let (_, expected) = e.split_once("expected").expect("serde names the variants");
        expected
            .split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect()
    }

    /// The number of `HarnessId` variants; `index` maps them onto `0..COUNT`.
    const COUNT: usize = 4;

    /// No `_` arm: a new `HarnessId` variant fails to compile here.
    fn index(h: HarnessId) -> usize {
        match h {
            HarnessId::ClaudeCode => 0,
            HarnessId::Codex => 1,
            HarnessId::Hermes => 2,
            HarnessId::Openclaw => 3,
        }
    }

    /// L112: `HARNESSES` holds every variant exactly once, at `index(h)`,
    /// and each variant's label and file stem use its serde name. A stale
    /// `COUNT`, `index`, or `HARNESSES` fails here.
    #[test]
    fn every_harness_is_listed_with_its_label_and_file_stem() {
        let names = every_variant_name();
        assert_eq!(names.len(), COUNT, "{names:?}");
        assert_eq!(HARNESSES.len(), COUNT);
        for name in names {
            let h: HarnessId = serde_json::from_value(serde_json::json!(name)).unwrap();
            assert!(index(h) < COUNT, "{name}");
            assert_eq!(HARNESSES[index(h)], h, "{name}");
            assert_eq!(harness_key(h), name);
            assert_eq!(label(h), format!("app:{name}"));
            assert_eq!(file_name(h), format!("{name}.json"));
        }
    }

    /// L110.2: a `revocations` path that is a symbolic link is refused by
    /// the writer, `is_pending`, and `clear`; nothing goes through it. A
    /// missing directory is "not pending" and clears fine.
    #[test]
    fn a_linked_directory_is_refused_and_a_missing_one_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        std::fs::create_dir(&data).unwrap();
        assert!(!is_pending(&data, HarnessId::Codex).unwrap());
        clear(&data, HarnessId::Codex).unwrap();

        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let held = real.join("codex.json");
        std::fs::write(&held, "{\"version\":1,\"label\":\"app:codex\"}\n").unwrap();
        std::os::unix::fs::symlink(&real, data.join(DIR)).unwrap();
        let inspect = |r: Result<(), RevocationError>| {
            assert_eq!(r.unwrap_err().to_string(), "pending revocations: inspect");
        };
        inspect(record(&data, HarnessId::Hermes));
        inspect(is_pending(&data, HarnessId::Codex).map(|_| ()));
        inspect(clear(&data, HarnessId::Codex));
        let mut left: Vec<_> = std::fs::read_dir(&real)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(
            left,
            ["codex.json"],
            "nothing written or removed through the link"
        );
    }
}
