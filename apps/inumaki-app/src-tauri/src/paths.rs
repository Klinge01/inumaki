//! Where the app reads and writes (M6 spec §6.6, §7.1). The data directory is
//! the daemon's default; the socket is the one the daemon derives from that
//! directory's `inumaki.toml` (`inumaki_client::resolve_socket`). The data
//! directory is resolved first, and the socket never moves state, logs, or
//! helper binaries. A daemon started with `--config` elsewhere is not followed.

use std::path::{Path, PathBuf};

/// The app's paths.
#[derive(Clone)]
pub struct AppPaths {
    /// `INUMAKI_DATA_DIR`, else `<platform data dir>/inumaki`.
    pub data_dir: PathBuf,
    /// The daemon's socket: `[daemon] socket` of `<data_dir>/inumaki.toml`,
    /// else `<data_dir>/inumakid.sock`. When `config_error` is set this is only
    /// a placeholder nothing listens on.
    pub socket: PathBuf,
    /// The config file could not be read or parsed: a fixed sentence naming the
    /// file, never its content. The app shows it and does not talk to a daemon.
    pub config_error: Option<String>,
    /// `<data_dir>/app` (0700).
    pub app_dir: PathBuf,
    /// `<data_dir>/app/state.json` (0600).
    pub state_file: PathBuf,
    /// `<data_dir>/app/state.key` (0600): HMAC key for server names in `state.json`.
    pub state_key: PathBuf,
    /// `<data_dir>/logs/app.log` (0600).
    pub log_file: PathBuf,
    /// `<data_dir>/bin`: helper binaries (M6-3).
    pub bin_dir: PathBuf,
    /// The user's home directory (harness files live under it).
    pub home: PathBuf,
}

impl std::fmt::Debug for AppPaths {
    /// Every field is under the home directory: nothing is printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppPaths(..)")
    }
}

impl AppPaths {
    /// The real locations.
    pub fn system() -> AppPaths {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
        Self::build(inumaki_client::default_data_dir(), home)
    }

    /// Everything under `data_dir`, harness files under `home` (tests).
    pub fn under(data_dir: &Path, home: &Path) -> AppPaths {
        Self::build(data_dir.to_path_buf(), home.to_path_buf())
    }

    fn build(data_dir: PathBuf, home: PathBuf) -> AppPaths {
        let (socket, config_error) = match inumaki_client::resolve_socket(None, &data_dir) {
            Ok(s) => (s, None),
            // Not the default socket: a daemon that is still running there is
            // not necessarily the one the file describes. Nothing listens on
            // this name, and `poll::fetch` does not even try.
            Err(e) => (data_dir.join("config-invalid.sock"), Some(e.to_string())),
        };
        AppPaths {
            config_error,
            app_dir: data_dir.join("app"),
            state_file: data_dir.join("app").join("state.json"),
            state_key: data_dir.join("app").join("state.key"),
            log_file: data_dir.join("logs").join("app.log"),
            bin_dir: data_dir.join("bin"),
            socket,
            data_dir,
            home,
        }
    }
}
