//! Data directory: `--data-dir`, else `INUMAKI_DATA_DIR`, else
//! `<platform data dir>/inumaki` (spec §10.1). The models directory keeps
//! its own resolution in `inumaki-models`.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Environment variable overriding the data directory.
pub const DATA_DIR_ENV: &str = "INUMAKI_DATA_DIR";

/// See the module docs; `env` is the value of [`DATA_DIR_ENV`].
pub fn resolve_data_dir_with(cli: Option<&Path>, env: Option<&OsStr>) -> PathBuf {
    if let Some(p) = cli {
        return p.to_path_buf();
    }
    if let Some(e) = env.filter(|e| !e.is_empty()) {
        return PathBuf::from(e);
    }
    dirs::data_dir().map_or_else(|| PathBuf::from("inumaki-data"), |d| d.join("inumaki"))
}

/// [`resolve_data_dir_with`] reading the process environment.
pub fn resolve_data_dir(cli: Option<&Path>) -> PathBuf {
    resolve_data_dir_with(cli, std::env::var_os(DATA_DIR_ENV).as_deref())
}

/// A configured path, relative to the data directory unless absolute.
pub fn resolve_in(data_dir: &Path, configured: &Path) -> PathBuf {
    if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        data_dir.join(configured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_is_cli_then_env_then_platform() {
        let cli = Path::new("/tmp/cli");
        assert_eq!(
            resolve_data_dir_with(Some(cli), Some(OsStr::new("/tmp/env"))),
            PathBuf::from("/tmp/cli")
        );
        assert_eq!(
            resolve_data_dir_with(None, Some(OsStr::new("/tmp/env"))),
            PathBuf::from("/tmp/env")
        );
        assert_eq!(
            resolve_data_dir_with(None, Some(OsStr::new(""))),
            resolve_data_dir_with(None, None)
        );
        let platform = resolve_data_dir_with(None, None);
        assert!(
            platform.ends_with("inumaki") || platform.ends_with("inumaki-data"),
            "{platform:?}"
        );
    }

    #[test]
    fn relative_paths_join_the_data_dir() {
        let d = Path::new("/data");
        assert_eq!(
            resolve_in(d, Path::new("inumakid.sock")),
            PathBuf::from("/data/inumakid.sock")
        );
        assert_eq!(
            resolve_in(d, Path::new("/run/x.sock")),
            PathBuf::from("/run/x.sock")
        );
    }
}
