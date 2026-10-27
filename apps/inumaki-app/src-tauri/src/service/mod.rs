//! Login service and model download (M6 spec §7): install, remove, and
//! restart the LaunchAgent or systemd user unit for a service the app
//! manages; never touch one that Homebrew, the `.deb`, or the user runs
//! (`managed_by` ≠ `app`), running or stopped. Only a service file that
//! carries the app's `INUMAKI_MANAGED_BY=app` marker is ever rewritten,
//! unloaded, restarted, disabled, or deleted. Removing never deletes the
//! data directory.

pub mod bin;
pub mod launchd;
pub mod runner;
pub mod systemd;

use std::io::ErrorKind;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::PoisonError;
use std::time::{Duration, Instant};

use inumaki_client::{ClientError, JobState, ManagedBy, ModelsJob};

use crate::ctx::Ctx;
use crate::error::CmdError;

/// Restart-guard key of a finished job the daemon reports without a start time.
const NO_START: i64 = i64::MIN;

/// Binaries the bundle carries and `<data dir>/bin` receives.
pub const HELPERS: [&str; 4] = ["inumakid", "inumaki", "inumaki-mcp", "inumaki-hook"];

/// The `.deb`'s user unit.
pub const DEB_UNIT: &str = "/usr/lib/systemd/user/inumakid.service";

/// Service files of other installers outside the home directory, any one of
/// which makes the app refuse to install (Review Focus 4): the `.deb`'s
/// user unit, an administrator's user unit, and `sudo brew services`'s
/// LaunchDaemon.
pub const SYSTEM_FILES: [&str; 3] = [
    DEB_UNIT,
    "/etc/systemd/user/inumakid.service",
    "/Library/LaunchDaemons/homebrew.mxcl.inumaki.plist",
];

/// Write `bytes` to `path` through a temporary file in the same directory.
/// A stale temporary (or a symlink planted there) is removed first and the
/// new one is created exclusively, so the write never follows a link.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), CmdError> {
    let dir = path
        .parent()
        .ok_or_else(|| CmdError::new("service_file_unwritable"))?;
    std::fs::create_dir_all(dir).map_err(|_| CmdError::new("service_file_unwritable"))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|_| CmdError::new("service_file_unwritable"))?;
        f.write_all(bytes)
            .map_err(|_| CmdError::new("service_file_unwritable"))?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
        .map_err(|_| CmdError::new("service_file_unwritable"))?;
    std::fs::rename(&tmp, path).map_err(|_| CmdError::new("service_file_unwritable"))
}

/// What answers on the socket.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Nothing listens.
    Nobody,
    /// A service that names its manager.
    Manager(ManagedBy),
    /// Something answers but does not say who runs it (a daemon older than
    /// `GET /v1/service`, or one that timed out): never replaced.
    Unknown,
}

/// A path with a control character (a newline, a tab) would break the
/// line-based unit file or end up raw in the plist: refused before rendering.
pub(crate) fn printable_path(p: &Path) -> Result<(), CmdError> {
    if p.as_os_str()
        .as_encoded_bytes()
        .iter()
        .any(|b| *b < 0x20 || *b == 0x7f)
    {
        Err(CmdError::new("service_file_unwritable"))
    } else {
        Ok(())
    }
}

async fn answer(ctx: &Ctx) -> Answer {
    match ctx.client.service().await {
        Ok(s) => Answer::Manager(s.managed_by),
        // Nothing at the path, or nothing listening. Any other connect
        // error (a socket owned by someone else) is not "nobody".
        Err(ClientError::Connect(ErrorKind::NotFound | ErrorKind::ConnectionRefused)) => {
            Answer::Nobody
        }
        Err(_) => Answer::Unknown,
    }
}

async fn wait_up(ctx: &Ctx, within: Duration) -> Result<(), CmdError> {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if matches!(answer(ctx).await, Answer::Manager(_)) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(CmdError::new("service_did_not_start"))
}

/// The app's own service file: `Some(true)` when it exists and carries the
/// app's marker, `Some(false)` when something else wrote it, `None` when absent.
fn ours(home: &Path) -> Option<bool> {
    let (path, marker) = if cfg!(target_os = "macos") {
        (
            launchd::plist_path(home),
            "<key>INUMAKI_MANAGED_BY</key><string>app</string>",
        )
    } else {
        (
            systemd::unit_path(home),
            "Environment=INUMAKI_MANAGED_BY=app",
        )
    };
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        // A symlink at the app's path was not written by the app.
        Ok(m) if !m.file_type().is_file() => return Some(false),
        _ => {}
    }
    match std::fs::read_to_string(path) {
        Ok(t) => Some(t.contains(marker)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => Some(false),
    }
}

/// Another installer's service exists, running or not (Review Focus 4):
/// Homebrew's LaunchAgent (or its systemd unit on Linux), the `.deb`'s unit,
/// an administrator's user unit, or a file at the app's own path without
/// the app's marker.
fn foreign(home: &Path, system_files: &[&Path]) -> bool {
    home.join("Library/LaunchAgents/homebrew.mxcl.inumaki.plist")
        .exists()
        || home
            .join(".config/systemd/user/homebrew.inumaki.service")
            .exists()
        || system_files.iter().any(|p| p.exists())
        || ours(home) == Some(false)
}

/// Install and start the app's login service with the helpers from `src_dir`.
pub async fn install(ctx: &Ctx, src_dir: &Path, wait: Duration) -> Result<(), CmdError> {
    let system: Vec<&Path> = SYSTEM_FILES.iter().map(Path::new).collect();
    install_with(ctx, src_dir, wait, &system).await
}

/// [`install`] with the system service files injected (tests).
pub async fn install_with(
    ctx: &Ctx,
    src_dir: &Path,
    wait: Duration,
    system_files: &[&Path],
) -> Result<(), CmdError> {
    let _one = ctx.service_lock.lock().await;
    match answer(ctx).await {
        Answer::Manager(ManagedBy::App) => return Ok(()),
        Answer::Manager(_) | Answer::Unknown => return Err(CmdError::new("managed_elsewhere")),
        Answer::Nobody => {}
    }
    if foreign(&ctx.paths.home, system_files) {
        return Err(CmdError::new("managed_elsewhere"));
    }
    let replace_own = ours(&ctx.paths.home) == Some(true);
    let r = ctx.runner.as_ref();
    bin::install_helpers(r, src_dir, &ctx.paths.bin_dir)?;
    if cfg!(target_os = "macos") {
        let logs = ctx.paths.data_dir.join("logs");
        let log = logs.join("inumakid.log");
        std::fs::create_dir_all(&logs).map_err(|_| CmdError::new("service_file_unwritable"))?;
        // launchd opens the log with its own umask: create it 0600 first.
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log)
            .and_then(|_| std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)))
            .map_err(|_| CmdError::new("service_file_unwritable"))?;
        launchd::install(r, &ctx.paths.home, &ctx.paths.bin_dir, &log, replace_own)?;
    } else {
        systemd::install(r, &ctx.paths.home, &ctx.paths.bin_dir)?;
    }
    wait_up(ctx, wait).await
}

/// Stop and unregister the app's service. Vault, models, and backups stay.
/// Only a service file the app wrote is ever unloaded or deleted.
pub async fn remove(ctx: &Ctx) -> Result<(), CmdError> {
    let _one = ctx.service_lock.lock().await;
    let a = answer(ctx).await;
    if matches!(a, Answer::Manager(m) if m != ManagedBy::App) {
        return Err(CmdError::new("managed_elsewhere"));
    }
    match ours(&ctx.paths.home) {
        Some(true) => {}
        Some(false) => return Err(CmdError::new("managed_elsewhere")),
        // A daemon that says the app runs it, but the app's service file
        // is gone (removed by hand, or another user's): nothing here can
        // stop it, and "removed" would be untrue.
        None if matches!(a, Answer::Manager(ManagedBy::App)) => {
            return Err(CmdError::new("service_not_installed_by_app"));
        }
        None => return Ok(()),
    }
    let r = ctx.runner.as_ref();
    if cfg!(target_os = "macos") {
        launchd::remove(r, &ctx.paths.home)
    } else {
        systemd::remove(r, &ctx.paths.home)
    }
}

/// Restart the app's service and wait for it.
pub async fn restart(ctx: &Ctx, wait: Duration) -> Result<(), CmdError> {
    let _one = ctx.service_lock.lock().await;
    restart_locked(ctx, wait).await
}

/// [`restart`] with `ctx.service_lock` already held.
async fn restart_locked(ctx: &Ctx, wait: Duration) -> Result<(), CmdError> {
    if matches!(answer(ctx).await, Answer::Manager(m) if m != ManagedBy::App) {
        return Err(CmdError::new("managed_elsewhere"));
    }
    if ours(&ctx.paths.home) != Some(true) {
        return Err(CmdError::new("managed_elsewhere"));
    }
    let r = ctx.runner.as_ref();
    if cfg!(target_os = "macos") {
        launchd::restart(r, &ctx.paths.home)?
    } else {
        systemd::restart(r)?
    }
    wait_up(ctx, wait).await
}

/// After a poll of the model job: restart the app's service once per
/// finished job (spec §7.2). `Ok(true)` when it restarted. A service the
/// app did not install is left alone (the UI shows who must restart it).
pub async fn after_models_poll(ctx: &Ctx, job: &ModelsJob) -> Result<bool, CmdError> {
    if job.state != JobState::Done {
        // A job that is not (or no longer) done: the next finished job may
        // restart again, even one the daemon reports without a start time.
        *ctx.restart_guard
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        return Ok(false);
    }
    if !job.restart_required {
        return Ok(false);
    }
    // A job without a start time gets a sentinel no real start time takes
    // (not 0); the reset above lets the next such job restart once too.
    let key = job.started_at.unwrap_or(NO_START);
    // Compare and set under one lock, before any await: of two overlapping
    // polls of the same job only one goes on (the guard is a std mutex and
    // is never held across an await).
    {
        let mut g = ctx
            .restart_guard
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *g == Some(key) {
            return Ok(false);
        }
        *g = Some(key);
    }
    let release = || {
        let mut g = ctx
            .restart_guard
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *g == Some(key) {
            *g = None;
        }
    };
    if answer(ctx).await != Answer::Manager(ManagedBy::App) || ours(&ctx.paths.home) != Some(true) {
        // Not the app's service: nothing restarted, nothing to remember.
        release();
        return Ok(false);
    }
    match restart(ctx, Duration::from_secs(20)).await {
        Ok(()) => Ok(true),
        // The restart went out; a slow start is reported by the poller, not retried.
        Err(e) if e.kind == "service_did_not_start" => Ok(true),
        Err(e) => {
            // Nothing restarted: the next poll may try again.
            release();
            Err(e)
        }
    }
}

/// At app start: when the app manages the service and the bundle's helpers
/// differ from the installed copies (an app update), refresh and restart.
pub async fn refresh_on_start(ctx: &Ctx) {
    let Some(src) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    else {
        return;
    };
    let _one = ctx.service_lock.lock().await;
    if answer(ctx).await != Answer::Manager(ManagedBy::App) || ours(&ctx.paths.home) != Some(true) {
        return;
    }
    if !HELPERS.iter().any(|h| {
        src.join(h).is_file() && bin::needs_refresh(&src.join(h), &ctx.paths.bin_dir.join(h))
    }) {
        return;
    }
    match bin::install_helpers(ctx.runner.as_ref(), &src, &ctx.paths.bin_dir) {
        Ok(_) => {
            if restart_locked(ctx, Duration::from_secs(20)).await.is_err() {
                crate::applog::event("helper_refresh_restart_failed");
            }
        }
        Err(_) => crate::applog::event("helper_refresh_failed"),
    }
}
