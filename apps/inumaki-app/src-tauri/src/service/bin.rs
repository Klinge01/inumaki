//! Helper binaries in `<data dir>/bin` (M6 spec §7.1): copied from the app
//! bundle, mode 0755, and on macOS stripped of extended attributes
//! (`com.apple.quarantine`) and re-signed ad hoc, so launchd and the
//! harnesses can run them. A copy is refreshed when its SHA-256 differs.

use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};

use super::HELPERS;
use super::runner::Runner;
use crate::error::CmdError;

fn digest(p: &Path) -> Option<[u8; 32]> {
    let mut f = std::fs::File::open(p).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().into())
}

/// `<dir>/.<helper>.sha256`: the bundle's digest and the installed copy's
/// digest after re-signing (64 bytes). Re-signing on macOS can change the
/// copy's bytes; without this record every app start would see a
/// difference, copy again, and restart the service.
fn stamp_path(to: &Path) -> std::path::PathBuf {
    let name = to
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    to.with_file_name(format!(".{name}.sha256"))
}

fn stamp(to: &Path) -> Option<([u8; 32], [u8; 32])> {
    let b = std::fs::read(stamp_path(to)).ok()?;
    let (s, d) = (b.get(..32)?, b.get(32..64)?);
    Some((s.try_into().ok()?, d.try_into().ok()?))
}

/// `to` is missing or differs from `from` (a copy re-signed from exactly
/// this `from` counts as the same).
pub fn needs_refresh(from: &Path, to: &Path) -> bool {
    let (Some(a), Some(b)) = (digest(from), digest(to)) else {
        return true;
    };
    a != b && stamp(to) != Some((a, b))
}

/// Copy every helper from `src` to `dst` that is missing or different;
/// returns how many were copied. `helper_missing` when the bundle lacks one.
pub fn install_helpers(r: &dyn Runner, src: &Path, dst: &Path) -> Result<usize, CmdError> {
    for h in HELPERS {
        if !src.join(h).is_file() {
            return Err(CmdError::new("helper_missing"));
        }
    }
    std::fs::create_dir_all(dst).map_err(|_| CmdError::new("bin_dir_unwritable"))?;
    let mut copied = 0;
    for h in HELPERS {
        let (from, to) = (src.join(h), dst.join(h));
        if !needs_refresh(&from, &to) {
            continue;
        }
        let tmp = dst.join(format!(".{h}.tmp"));
        // A stale temporary (or a symlink planted there) is removed, and the
        // new one is created exclusively, so a write never follows a link.
        let _ = std::fs::remove_file(&tmp);
        {
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o755)
                .open(&tmp)
                .map_err(|_| CmdError::new("bin_dir_unwritable"))?;
            let mut inp =
                std::fs::File::open(&from).map_err(|_| CmdError::new("helper_missing"))?;
            std::io::copy(&mut inp, &mut out).map_err(|_| CmdError::new("bin_dir_unwritable"))?;
        }
        if std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(CmdError::new("bin_dir_unwritable"));
        }
        // The temporary is cleared and signed before it replaces anything:
        // a failure leaves the previous, working copy where launchd and the
        // harness hooks expect it (a missing hook binary would fail open).
        if cfg!(target_os = "macos") {
            let p = tmp.display().to_string();
            let cleared = r
                .run(Path::new("/usr/bin/xattr"), &["-c".into(), p.clone()])
                .is_ok_and(|o| o.ok());
            let signed = cleared
                && r.run(
                    Path::new("/usr/bin/codesign"),
                    &[
                        "--force".into(),
                        "-s".into(),
                        "-".into(),
                        "-i".into(),
                        h.into(),
                        p,
                    ],
                )
                .is_ok_and(|o| o.ok());
            if !signed {
                let _ = std::fs::remove_file(&tmp);
                return Err(CmdError::new("sign_failed"));
            }
        }
        if std::fs::rename(&tmp, &to).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(CmdError::new("bin_dir_unwritable"));
        }
        if let (Some(a), Some(b)) = (digest(&from), digest(&to)) {
            let mut rec = a.to_vec();
            rec.extend_from_slice(&b);
            // Without the record the next start copies again: harmless.
            let _ = super::write_atomic(&stamp_path(&to), &rec, 0o644);
        }
        copied += 1;
    }
    crate::applog::count("install_helpers", "copied", copied as u64);
    Ok(copied)
}
