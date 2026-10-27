//! `[mirror]` (M5 spec §13). Errors name the key, never the value.

use std::path::{Path, PathBuf};
use std::time::Duration;

use inumaki_core::Error;
use inumaki_mirror::MirrorConfig;
use serde::Deserialize;

use crate::config::{parse_bytes, parse_duration};

/// `[mirror]` table.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MirrorSection {
    /// Mirror root; `~/` expands to the service user's home.
    pub root: String,
    /// Parent of default outbox destinations.
    pub outbox_root: String,
    /// Watcher debounce, e.g. `500ms` (up to `10s`).
    pub debounce: String,
    /// Largest file mirrored or restored, e.g. `1MiB` (up to `16MiB`).
    pub max_file_bytes: String,
    /// Worker threads (1 to 8).
    pub workers: usize,
    /// Period of the full reconcile, e.g. `1h`.
    pub rescan_interval: String,
}

/// The roots are home paths (they carry the user name): counts only.
impl std::fmt::Debug for MirrorSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MirrorSection")
            .field("workers", &self.workers)
            .finish_non_exhaustive()
    }
}

impl Default for MirrorSection {
    fn default() -> Self {
        MirrorSection {
            root: "~/Inumaki Mirror".into(),
            outbox_root: "~/Inumaki Outbox".into(),
            debounce: "500ms".into(),
            max_file_bytes: "1MiB".into(),
            workers: 1,
            rescan_interval: "1h".into(),
        }
    }
}

fn invalid(key: &str) -> Error {
    Error::ConfigInvalid(format!("mirror.{key}"))
}

fn expand(s: &str, key: &str) -> Result<PathBuf, Error> {
    let p = match s.strip_prefix("~/") {
        Some(rest) => dirs::home_dir().ok_or_else(|| invalid(key))?.join(rest),
        None => PathBuf::from(s),
    };
    if !p.is_absolute() {
        return Err(invalid(key));
    }
    Ok(p)
}

/// `500ms`, or any form [`parse_duration`] reads.
fn parse_debounce(s: &str) -> Option<Duration> {
    match s.trim().strip_suffix("ms") {
        Some(n) => n.parse().ok().map(Duration::from_millis),
        None => parse_duration(s),
    }
}

fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Validate `[mirror]` into the mirror crate's settings. `root` and
/// `outbox_root` must not contain each other; that `root` is not inside the
/// data directory is checked where the data directory is known
/// (`Folders::load`).
pub fn parse(m: &MirrorSection) -> Result<MirrorConfig, Error> {
    let root = expand(&m.root, "root")?;
    let outbox_root = expand(&m.outbox_root, "outbox_root")?;
    if overlap(&root, &outbox_root) {
        return Err(invalid("outbox_root"));
    }
    let debounce = parse_debounce(&m.debounce)
        .filter(|d| !d.is_zero() && *d <= Duration::from_secs(10))
        .ok_or_else(|| invalid("debounce"))?;
    let max_file_bytes = parse_bytes(&m.max_file_bytes)
        .map(|b| b as u64)
        .filter(|b| *b > 0 && *b <= MirrorConfig::MAX_FILE_BYTES_CEILING)
        .ok_or_else(|| invalid("max_file_bytes"))?;
    if !(1..=8).contains(&m.workers) {
        return Err(invalid("workers"));
    }
    let rescan_interval = parse_duration(&m.rescan_interval)
        .filter(|d| !d.is_zero())
        .ok_or_else(|| invalid("rescan_interval"))?;
    Ok(MirrorConfig {
        root,
        outbox_root,
        debounce,
        max_file_bytes,
        workers: m.workers,
        rescan_interval,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(f: impl FnOnce(&mut MirrorSection)) -> Result<MirrorConfig, Error> {
        let mut m = MirrorSection {
            root: "/srv/qwxzvk-root".into(),
            outbox_root: "/srv/qwxzvk-outbox".into(),
            ..MirrorSection::default()
        };
        f(&mut m);
        parse(&m)
    }

    #[test]
    fn the_defaults_parse_and_the_shipped_config_needs_no_table() {
        assert!(parse(&MirrorSection::default()).is_ok() || dirs::home_dir().is_none());
        assert!(crate::config::DaemonConfig::embedded().mirror_cfg.workers >= 1);
    }

    /// The default root must not be the same directory as a checkout at
    /// `~/inumaki` on a case-insensitive volume, nor the outbox root.
    #[test]
    fn the_default_root_does_not_collide_with_a_checkout_or_the_outbox() {
        let Some(home) = dirs::home_dir() else { return };
        let cfg = parse(&MirrorSection::default()).unwrap();
        assert_eq!(cfg.root.file_name().unwrap(), "Inumaki Mirror");
        let fold = |p: &Path| p.to_string_lossy().to_ascii_lowercase();
        assert_ne!(fold(&cfg.root), fold(&cfg.outbox_root));
        assert_ne!(fold(&cfg.root), fold(&home.join("inumaki")));
        let checkout = fold(&home.join("inumaki"));
        assert!(!Path::new(&fold(&cfg.root)).starts_with(&checkout));
    }

    #[test]
    fn debounce_reads_milliseconds_and_seconds() {
        let d = |v: &str| section(|m| m.debounce = v.into()).map(|c| c.debounce);
        assert_eq!(d("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(d("2s").unwrap(), Duration::from_secs(2));
        assert!(d("0ms").is_err() && d("ms").is_err() && d("-5ms").is_err());
    }

    #[test]
    fn root_and_outbox_root_must_not_contain_each_other() {
        assert!(section(|m| m.outbox_root = "/srv/qwxzvk-root/out".into()).is_err());
        assert!(section(|m| m.root = "/srv/qwxzvk-outbox/in".into()).is_err());
        assert!(section(|m| m.outbox_root = m.root.clone()).is_err());
    }

    #[test]
    fn a_bad_value_is_named_by_key_and_never_echoed() {
        let e = section(|m| m.root = "relative/qwxzvk".into()).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("mirror.root"), "{msg}");
        assert!(!msg.contains("qwxzvk"), "{msg}");
        for (f, key) in [
            (
                Box::new(|m: &mut MirrorSection| m.debounce = "11s".into())
                    as Box<dyn Fn(&mut MirrorSection)>,
                "debounce",
            ),
            (
                Box::new(|m| m.max_file_bytes = "17MiB".into()),
                "max_file_bytes",
            ),
            (Box::new(|m| m.workers = 0), "workers"),
            (
                Box::new(|m| m.rescan_interval = "0s".into()),
                "rescan_interval",
            ),
        ] {
            let e = section(|m| f(m)).unwrap_err().to_string();
            assert!(e.contains(&format!("mirror.{key}")), "{e}");
        }
    }
}
