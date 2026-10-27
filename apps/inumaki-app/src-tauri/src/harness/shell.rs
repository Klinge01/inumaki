//! The user's login-shell `PATH` (spec §4.4, §4.5): a GUI app on macOS does
//! not inherit the shell's `PATH`. Asked with a 3 s limit; a value is
//! cached for the app's lifetime, a failure is not (the next call asks
//! again, e.g. after a slow first login shell). The value is wrapped in
//! sentinels, because shell start-up files may print banners or other
//! text. `Ctx` holds this function behind its login-`PATH` source, so tests
//! inject a fixed value and never start a shell.
//!
//! Limits: on timeout only the shell itself is killed, not processes its
//! start-up files started; and a reader thread whose pipe such a process
//! keeps open stays blocked until it closes (at most one per failed ask).

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

static PATH: Mutex<Option<String>> = Mutex::new(None);
const START: &str = "__INUMAKI_PATH_START__";
const END: &str = "__INUMAKI_PATH_END__";
const LIMIT: Duration = Duration::from_secs(3);
/// More than any `PATH`; start-up files that print more are cut off.
const MAX_OUTPUT: u64 = 256 * 1024;

/// The text between the sentinels, if it reads as a `PATH`: `:`-separated
/// absolute directories. fish's space-joined list (`/a /b`), a relative
/// value, or an error message is `None`.
pub fn extract(out: &str) -> Option<String> {
    let (_, rest) = out.split_once(START)?;
    let (p, _) = rest.split_once(END)?;
    let dirs: Vec<&str> = p.split(':').filter(|d| !d.is_empty()).collect();
    let ok = !dirs.is_empty()
        && dirs.iter().all(|d| d.starts_with('/'))
        && (p.contains(':') || !p.contains(" /"));
    ok.then(|| p.to_string())
}

fn ask() -> Option<String> {
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| s.starts_with('/'))
        .unwrap_or_else(|| "/bin/zsh".into());
    let mut child = Command::new(shell)
        .args([
            "-lc",
            &format!("printf '%s%s%s' '{START}' \"$PATH\" '{END}'"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Read on another thread, and only up to the end sentinel: a start-up
    // file that leaves a background process holding stdout open must not
    // block past the limit.
    let out = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = out.take(MAX_OUTPUT);
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match out.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    bytes.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&bytes).contains(END) {
                        break;
                    }
                }
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&bytes).into_owned());
    });
    let got = rx.recv_timeout(LIMIT).ok();
    // The value is in (or the limit passed): the shell has nothing more to say.
    let until = Instant::now() + Duration::from_millis(200);
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    if matches!(child.try_wait(), Ok(None)) {
        let _ = child.kill();
    }
    let _ = child.wait();
    extract(&got?)
}

/// The login shell's `PATH`, or `None` when it could not be read. Blocks up
/// to 3 s until a value is cached: call from a blocking thread. Concurrent
/// callers wait for one ask instead of starting a shell each.
pub fn login_path() -> Option<String> {
    let mut g = PATH.lock().unwrap_or_else(PoisonError::into_inner);
    if g.is_none() {
        *g = ask();
    }
    g.clone()
}
