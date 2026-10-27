//! macOS LaunchAgent `inumaki.inumakid` (M6 spec §7.1): rendered from
//! `packaging/launchd/inumaki.inumakid.plist.in`, loaded with
//! `launchctl bootstrap gui/<uid>`, restarted with `kickstart -k`,
//! removed with `bootout`.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::runner::Runner;
use super::write_atomic;
use crate::error::CmdError;

/// The agent's label.
pub const LABEL: &str = "inumaki.inumakid";
const LAUNCHCTL: &str = "/bin/launchctl";
const TEMPLATE: &str = include_str!("../../../../../packaging/launchd/inumaki.inumakid.plist.in");

/// XML text escape. `@` is escaped too, so a rendered path can never form
/// (or be mistaken for) a placeholder.
fn xml_escape(p: &Path) -> String {
    p.display()
        .to_string()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('@', "&#64;")
}

/// The plist for `bin_dir/inumakid`, logging to `log_file`.
pub fn render(bin_dir: &Path, log_file: &Path) -> String {
    TEMPLATE
        .replace("@PROGRAM@", &xml_escape(&bin_dir.join("inumakid")))
        .replace("@LOG@", &xml_escape(log_file))
}

/// `~/Library/LaunchAgents/inumaki.inumakid.plist`.
pub fn plist_path(home: &Path) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

/// `gui/<uid>`; the uid is the home directory's owner (the user running the app).
fn domain(home: &Path) -> Result<String, CmdError> {
    let uid = std::fs::metadata(home)
        .map_err(|_| CmdError::new("home_unreadable"))?
        .uid();
    Ok(format!("gui/{uid}"))
}

fn launchctl(r: &dyn Runner, args: &[String]) -> Result<bool, CmdError> {
    r.run(Path::new(LAUNCHCTL), args)
        .map(|o| o.ok())
        .map_err(|_| CmdError::new("launchctl_failed"))
}

/// Write the plist and bootstrap it. `replace_own` is true only when the
/// app's own plist was already there: then a stale registration of the
/// app's label is booted out first. Without it nothing is booted out, so a
/// job the app did not register is never unloaded.
pub fn install(
    r: &dyn Runner,
    home: &Path,
    bin_dir: &Path,
    log_file: &Path,
    replace_own: bool,
) -> Result<(), CmdError> {
    super::printable_path(bin_dir)?;
    super::printable_path(log_file)?;
    let plist = plist_path(home);
    let d = domain(home)?;
    write_atomic(&plist, render(bin_dir, log_file).as_bytes(), 0o644)?;
    if replace_own {
        let _ = launchctl(r, &["bootout".into(), format!("{d}/{LABEL}")]);
    }
    if !launchctl(r, &["bootstrap".into(), d, plist.display().to_string()])? {
        return Err(CmdError::new("service_install_failed"));
    }
    Ok(())
}

/// Boot the agent out and delete the plist. The caller checked that the
/// plist is the app's own.
pub fn remove(r: &dyn Runner, home: &Path) -> Result<(), CmdError> {
    let d = domain(home)?;
    let _ = launchctl(r, &["bootout".into(), format!("{d}/{LABEL}")]);
    match std::fs::remove_file(plist_path(home)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CmdError::new("service_remove_failed")),
    }
}

/// `launchctl kickstart -k gui/<uid>/inumaki.inumakid`.
pub fn restart(r: &dyn Runner, home: &Path) -> Result<(), CmdError> {
    let d = domain(home)?;
    if !launchctl(
        r,
        &["kickstart".into(), "-k".into(), format!("{d}/{LABEL}")],
    )? {
        return Err(CmdError::new("service_restart_failed"));
    }
    Ok(())
}
