//! `<data dir>/app/check-tmp/<check id>-<harness>/{work,config}`, 0700,
//! removed when a run ends (`Drop`) and at every app start (a crash).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::CmdError;
use crate::paths::AppPaths;

/// The directory all runs live under.
pub fn root(paths: &AppPaths) -> PathBuf {
    paths.app_dir.join("check-tmp")
}

/// Remove every leftover run directory.
pub fn sweep(paths: &AppPaths) {
    let _ = std::fs::remove_dir_all(root(paths));
}

/// One run's directories; removed on drop.
pub struct CheckDirs {
    /// `<root>/<id>-<harness>`.
    pub root: PathBuf,
    /// Empty working directory.
    pub work: PathBuf,
    /// Temporary configuration directory.
    pub config: PathBuf,
}

impl std::fmt::Debug for CheckDirs {
    /// The paths live under the user's data directory: not printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckDirs(..)")
    }
}

impl Drop for CheckDirs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn private(p: &Path) -> Result<(), CmdError> {
    std::fs::create_dir_all(p).map_err(|_| CmdError::new("check_tmp_unwritable"))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| CmdError::new("check_tmp_unwritable"))
}

/// A path component made of `[a-z0-9-]` only: the check id (hex from the
/// daemon) and the harness key never steer the directory elsewhere.
fn component_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Create the directories of one run.
pub fn create(paths: &AppPaths, check_id: &str, harness: &str) -> Result<CheckDirs, CmdError> {
    if !component_ok(check_id) || !component_ok(harness) {
        return Err(CmdError::new("bad_response"));
    }
    private(&root(paths))?;
    let r = root(paths).join(format!("{check_id}-{harness}"));
    // A leftover of the same name (it cannot be a live run: one check at a time).
    let _ = std::fs::remove_dir_all(&r);
    let dirs = CheckDirs {
        work: r.join("work"),
        config: r.join("config"),
        root: r,
    };
    private(&dirs.root)?;
    private(&dirs.work)?;
    private(&dirs.config)?;
    Ok(dirs)
}
