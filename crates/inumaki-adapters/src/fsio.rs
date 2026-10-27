//! Reading and writing harness files: compare-and-rename, the original
//! mode, symlinks edited at their target (spec §4.2).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

/// Lower-case hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A file as read: the path actually edited (a symlink's target), its bytes
/// and hash (`None` when missing), and its mode.
#[derive(Clone)]
pub struct Snapshot {
    /// The resolved target.
    pub target: PathBuf,
    /// Bytes, `None` when the file does not exist.
    pub bytes: Option<Vec<u8>>,
    /// SHA-256 of `bytes`.
    pub sha: Option<String>,
    /// Permission bits.
    pub mode: Option<u32>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("exists", &self.bytes.is_some())
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// Read `path`, resolving a symlink to its target.
pub fn read(path: &Path) -> io::Result<Snapshot> {
    let target = match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    match fs::read(&target) {
        Ok(b) => {
            let mode = fs::metadata(&target)?.permissions().mode() & 0o7777;
            Ok(Snapshot {
                sha: Some(sha256_hex(&b)),
                bytes: Some(b),
                mode: Some(mode),
                target,
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Snapshot {
            target,
            bytes: None,
            sha: None,
            mode: None,
        }),
        Err(e) => Err(e),
    }
}

/// Why a write did not happen.
#[derive(Debug)]
pub enum WriteError {
    /// The target changed since it was read.
    Changed,
    /// An I/O error.
    Io(io::ErrorKind),
}

impl From<io::Error> for WriteError {
    fn from(e: io::Error) -> Self {
        WriteError::Io(e.kind())
    }
}

fn current_sha(target: &Path) -> io::Result<Option<String>> {
    match fs::read(target) {
        Ok(b) => Ok(Some(sha256_hex(&b))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Replace the target with `new` if it still has the snapshot's hash.
pub fn write_if_unchanged(snap: &Snapshot, new: &[u8]) -> Result<(), WriteError> {
    write_if_unchanged_with(snap, new, &|| {})
}

/// [`write_if_unchanged`] with a callback between writing the temporary
/// file and comparing (tests simulate a harness writing there).
pub(crate) fn write_if_unchanged_with(
    snap: &Snapshot,
    new: &[u8],
    before_compare: &dyn Fn(),
) -> Result<(), WriteError> {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = snap
        .target
        .parent()
        .ok_or(WriteError::Io(io::ErrorKind::InvalidInput))?;
    fs::create_dir_all(dir)?;
    let name = snap
        .target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let tmp = dir.join(format!(
        ".{name}.inumaki-{}-{}.tmp",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let mode = snap.mode.unwrap_or(0o600);
    let written = (|| -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(new)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    before_compare();
    match current_sha(&snap.target) {
        Ok(now) if now == snap.sha => {}
        Ok(_) => {
            let _ = fs::remove_file(&tmp);
            return Err(WriteError::Changed);
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
    }
    fs::rename(&tmp, &snap.target).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        WriteError::from(e)
    })
}

/// Delete the target if it still has the snapshot's hash (revert of a file inumaki created).
pub fn remove_if_unchanged(snap: &Snapshot) -> Result<(), WriteError> {
    if current_sha(&snap.target)? != snap.sha {
        return Err(WriteError::Changed);
    }
    fs::remove_file(&snap.target)?;
    Ok(())
}
