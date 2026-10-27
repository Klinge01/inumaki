//! Linux systemd user unit (M6 spec §7.1): the `.deb`'s unit with
//! `ExecStart` pointing at `<data dir>/bin/inumakid` and
//! `INUMAKI_MANAGED_BY=app`. `loginctl enable-linger` is explained in the
//! UI and never run here.

use std::path::{Path, PathBuf};

use super::runner::Runner;
use super::write_atomic;
use crate::error::CmdError;

const TEMPLATE: &str = include_str!("../../../../../packaging/systemd/inumakid.service");
const UNIT: &str = "inumakid";

fn systemctl() -> &'static Path {
    if Path::new("/usr/bin/systemctl").exists() {
        Path::new("/usr/bin/systemctl")
    } else {
        Path::new("/bin/systemctl")
    }
}

/// Quote for `ExecStart=`: `%` (specifier) and `$` (variable) doubled;
/// double quotes when a space, a quote, or a backslash is present.
fn exec_path(p: &Path) -> String {
    let s = p
        .display()
        .to_string()
        .replace('%', "%%")
        .replace('$', "$$");
    if s.contains([' ', '\t', '"', '\'', '\\']) {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s
    }
}

/// The unit for `bin_dir/inumakid`.
pub fn render(bin_dir: &Path) -> String {
    let mut out = String::new();
    for line in TEMPLATE.lines() {
        match line {
            "ExecStart=/usr/bin/inumakid" => {
                out.push_str("ExecStart=");
                out.push_str(&exec_path(&bin_dir.join("inumakid")));
            }
            "Environment=INUMAKI_MANAGED_BY=deb" => {
                out.push_str("Environment=INUMAKI_MANAGED_BY=app")
            }
            l => out.push_str(l),
        }
        out.push('\n');
    }
    out
}

/// `~/.config/systemd/user/inumakid.service`.
pub fn unit_path(home: &Path) -> PathBuf {
    home.join(".config")
        .join("systemd")
        .join("user")
        .join(format!("{UNIT}.service"))
}

fn user(r: &dyn Runner, args: &[&str]) -> Result<bool, CmdError> {
    let mut v = vec!["--user".to_string()];
    v.extend(args.iter().map(|s| s.to_string()));
    r.run(systemctl(), &v)
        .map(|o| o.ok())
        .map_err(|_| CmdError::new("systemctl_failed"))
}

/// Write the unit, reload, enable and start it.
pub fn install(r: &dyn Runner, home: &Path, bin_dir: &Path) -> Result<(), CmdError> {
    super::printable_path(bin_dir)?;
    write_atomic(&unit_path(home), render(bin_dir).as_bytes(), 0o644)?;
    user(r, &["daemon-reload"])?;
    if !user(r, &["enable", "--now", UNIT])? {
        return Err(CmdError::new("service_install_failed"));
    }
    Ok(())
}

/// Disable, stop, delete, reload. The caller checked that the unit file is
/// the app's own: a unit the app did not write is never disabled.
pub fn remove(r: &dyn Runner, home: &Path) -> Result<(), CmdError> {
    let _ = user(r, &["disable", "--now", UNIT]);
    match std::fs::remove_file(unit_path(home)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(CmdError::new("service_remove_failed")),
    }
    user(r, &["daemon-reload"]).map(|_| ())
}

/// `systemctl --user restart inumakid`.
pub fn restart(r: &dyn Runner) -> Result<(), CmdError> {
    if !user(r, &["restart", UNIT])? {
        return Err(CmdError::new("service_restart_failed"));
    }
    Ok(())
}
