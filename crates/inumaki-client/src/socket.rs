//! Where the daemon's control socket is: one resolver for every program that
//! is not the daemon (the app, the MCP shim, the hook). It follows the
//! daemon's own rule (`inumakid::config::config_path`, `dirs::resolve_in`):
//!
//! 1. an explicit `--socket`;
//! 2. else `[daemon] socket` in `<data dir>/inumaki.toml` when that file
//!    exists (a relative value is relative to the data directory);
//! 3. else `<data dir>/inumakid.sock`.
//!
//! It fails closed like the daemon: only a definite "not found" falls back
//! to the default. A file that cannot be inspected, read, or parsed (a
//! dangling symlink, a directory, bad TOML) is an error that names the file
//! and never prints its content. A daemon started with `--config` elsewhere
//! is not followed: clients have no way to know that file.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The config file inside the data directory.
const CONFIG_FILE: &str = "inumaki.toml";
/// The default socket inside the data directory.
const SOCKET_FILE: &str = "inumakid.sock";

/// The config file could not give an answer. The text names the file and why
/// in fixed words; it never carries the file's content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("config file {}: {why}", file.display())]
pub struct SocketError {
    file: PathBuf,
    why: String,
}

/// The keys of the daemon's `[daemon]` table. The daemon refuses any other
/// key, so this resolver does too: a file the daemon would not start with is
/// not trusted to name the socket. `inumakid` has a test that fails when this
/// list and its `DaemonSection` differ.
pub const DAEMON_KEYS: &[&str] = &[
    "socket",
    "cache_bytes",
    "session_ttl",
    "session_cap",
    "default_profile",
    "session_suffix_len",
];

impl SocketError {
    /// The config file the error is about.
    pub fn file(&self) -> &Path {
        &self.file
    }
}

/// A key is printed only when it is a plain name, as the daemon does; a
/// quoted or odd key could be anything the user typed.
fn printable(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The data directory as the daemon resolves it with no `--data-dir`:
/// `env` (the value of `INUMAKI_DATA_DIR`) when non-empty, else
/// `<platform data dir>/inumaki`.
pub fn default_data_dir_with(env: Option<&OsStr>) -> PathBuf {
    match env.filter(|e| !e.is_empty()) {
        Some(e) => PathBuf::from(e),
        None => {
            dirs::data_dir().map_or_else(|| PathBuf::from("inumaki-data"), |d| d.join("inumaki"))
        }
    }
}

/// [`default_data_dir_with`] reading the process environment.
pub fn default_data_dir() -> PathBuf {
    default_data_dir_with(std::env::var_os("INUMAKI_DATA_DIR").as_deref())
}

/// The control socket for `data_dir`; see the module docs for the order.
pub fn resolve_socket(flag: Option<&Path>, data_dir: &Path) -> Result<PathBuf, SocketError> {
    if let Some(s) = flag {
        return Ok(s.to_path_buf());
    }
    let file = data_dir.join(CONFIG_FILE);
    let fail = |why: String| SocketError {
        file: file.clone(),
        why,
    };
    match std::fs::symlink_metadata(&file) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(data_dir.join(SOCKET_FILE));
        }
        Err(_) => return Err(fail("cannot inspect".into())),
    }
    // The file exists (or is a dangling link): from here every failure is an
    // error, including a `NotFound` while reading.
    let text = std::fs::read_to_string(&file).map_err(|_| fail("cannot read".into()))?;
    let parsed: toml::Table = text.parse().map_err(|_| fail("is not valid TOML".into()))?;
    let configured = match parsed.get("daemon") {
        None => PathBuf::from(SOCKET_FILE),
        Some(toml::Value::Table(d)) => {
            if let Some(k) = d.keys().find(|k| !DAEMON_KEYS.contains(&k.as_str())) {
                return Err(fail(if printable(k) {
                    format!("[daemon] has an unknown key `{k}`")
                } else {
                    "[daemon] has an unknown key".into()
                }));
            }
            match d.get("socket") {
                None => PathBuf::from(SOCKET_FILE),
                Some(toml::Value::String(s)) => PathBuf::from(s),
                Some(_) => return Err(fail("[daemon] socket is not a string".into())),
            }
        }
        Some(_) => return Err(fail("[daemon] is not a table".into())),
    };
    Ok(if configured.is_absolute() {
        configured
    } else {
        data_dir.join(configured)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(config: Option<&str>) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        if let Some(c) = config {
            std::fs::write(d.path().join(CONFIG_FILE), c).unwrap();
        }
        d
    }

    #[test]
    fn flag_wins_even_over_a_broken_file() {
        let d = dir_with(Some("not = [valid"));
        let s = resolve_socket(Some(Path::new("/run/x.sock")), d.path()).unwrap();
        assert_eq!(s, PathBuf::from("/run/x.sock"));
    }

    #[test]
    fn absolute_and_relative_values_follow_the_daemon() {
        let d = dir_with(Some("[daemon]\nsocket = \"/run/inumaki/x.sock\"\n"));
        assert_eq!(
            resolve_socket(None, d.path()).unwrap(),
            PathBuf::from("/run/inumaki/x.sock")
        );
        let d = dir_with(Some("[daemon]\nsocket = \"run/x.sock\"\n"));
        assert_eq!(
            resolve_socket(None, d.path()).unwrap(),
            d.path().join("run/x.sock")
        );
    }

    #[test]
    fn a_file_without_the_key_or_no_file_gives_the_default() {
        for config in [None, Some(""), Some("[daemon]\ncache_bytes = 1\n")] {
            let d = dir_with(config);
            assert_eq!(
                resolve_socket(None, d.path()).unwrap(),
                d.path().join(SOCKET_FILE)
            );
        }
    }

    #[test]
    fn an_invalid_file_is_an_error_naming_the_file_without_its_content() {
        let secret = "SECRET-CONTENT";
        for bad in [
            format!("{secret} = = ["),
            format!("[daemon]\nsocket = 5 # {secret}\n"),
        ] {
            let d = dir_with(Some(&bad));
            let e = resolve_socket(None, d.path()).unwrap_err();
            let shown = format!("{e} / {e:?}");
            assert_eq!(e.file(), d.path().join(CONFIG_FILE));
            assert!(shown.contains("inumaki.toml"), "{shown}");
            assert!(!shown.contains(secret), "{shown}");
        }
    }

    #[test]
    fn a_dangling_symlink_or_a_directory_is_an_error_not_the_default() {
        let d = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(d.path().join("missing"), d.path().join(CONFIG_FILE)).unwrap();
        assert!(resolve_socket(None, d.path()).is_err());
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join(CONFIG_FILE)).unwrap();
        assert!(resolve_socket(None, d.path()).is_err());
    }

    #[test]
    fn an_unknown_daemon_key_is_an_error_naming_the_key_not_the_value() {
        let d = dir_with(Some("[daemon]\nsocekt = \"SECRET-VALUE\"\n"));
        let e = resolve_socket(None, d.path()).unwrap_err().to_string();
        assert!(e.contains("inumaki.toml") && e.contains("`socekt`"), "{e}");
        assert!(!e.contains("SECRET-VALUE"), "{e}");
        let d = dir_with(Some("[daemon]\n\"odd key\" = 1\n"));
        let e = resolve_socket(None, d.path()).unwrap_err().to_string();
        assert!(!e.contains("odd"), "{e}");
        // Every key the daemon knows is accepted.
        for k in DAEMON_KEYS.iter().filter(|k| **k != "socket") {
            let d = dir_with(Some(&format!("[daemon]\n{k} = 1\n")));
            assert!(resolve_socket(None, d.path()).is_ok(), "{k}");
        }
    }

    #[test]
    fn data_dir_prefers_a_non_empty_env() {
        assert_eq!(
            default_data_dir_with(Some(OsStr::new("/tmp/env"))),
            PathBuf::from("/tmp/env")
        );
        assert_eq!(
            default_data_dir_with(Some(OsStr::new(""))),
            default_data_dir_with(None)
        );
    }
}
