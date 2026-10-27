//! `<data_dir>/logs/app.log` (M6 spec §6.6): command name, duration,
//! outcome, HTTP status, and counts. The functions take `&'static str` and
//! integers only, so no request, response, path, name, or token can be
//! passed in at runtime. The panic hook writes the panic's file name and
//! line only: panic messages can contain `Debug` output of values, and a
//! dependency's full source path contains the home directory.

use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, Once, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::error::CmdError;

static FILE: Mutex<Option<File>> = Mutex::new(None);
static HOOK: Once = Once::new();

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn write(line: std::fmt::Arguments<'_>) {
    if let Some(f) = FILE.lock().unwrap_or_else(PoisonError::into_inner).as_mut() {
        let _ = writeln!(f, "ts={} {line}", now());
    }
}

/// Open (append) `path`, 0600 in a 0700 directory.
pub fn init(path: &Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .ok();
    // `mode` applies on create only: an existing log keeps its old mode otherwise.
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    *FILE.lock().unwrap_or_else(PoisonError::into_inner) = f;
}

/// Replace the panic hook with one that logs the location only (once).
/// `run()` calls it; tests do not, except the one that checks it, so a
/// failing test still prints its assertion message.
pub fn install_panic_hook() {
    HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let at = info.location().map(|l| {
                let file = Path::new(l.file())
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                format!("{file}:{}", l.line())
            });
            write(format_args!(
                "panic at={}",
                at.as_deref().unwrap_or("unknown")
            ));
        }));
    });
}

/// One command: name, duration, outcome (`ok` or an error kind), HTTP status.
pub fn command(name: &'static str, ms: u64, outcome: &'static str, status: Option<u16>) {
    match status {
        Some(s) => write(format_args!(
            "cmd={name} ms={ms} outcome={outcome} status={s}"
        )),
        None => write(format_args!(
            "cmd={name} ms={ms} outcome={outcome} status=-"
        )),
    }
}

/// A count attached to a command.
pub fn count(name: &'static str, key: &'static str, n: u64) {
    write(format_args!("cmd={name} {key}={n}"));
}

/// A fixed event (`poll_failed`, `state_unreadable`, …).
pub fn event(what: &'static str) {
    write(format_args!("event={what}"));
}

/// Run `f` and log its name, duration, and outcome (never an argument or a
/// result). Every IPC wrapper logs through this; public so tests log
/// exactly as the wrappers do.
pub async fn logged<T>(
    name: &'static str,
    f: impl Future<Output = Result<T, CmdError>>,
) -> Result<T, CmdError> {
    let t = Instant::now();
    let r = f.await;
    let (outcome, status) = match &r {
        Ok(_) => ("ok", None),
        Err(e) => (e.kind, e.status),
    };
    command(name, t.elapsed().as_millis() as u64, outcome, status);
    r
}
