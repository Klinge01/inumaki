//! Mirror names (M5 spec §4.3): which suffix is an extension, validity,
//! opaque fallback, collision suffixes, placeholders. Sanitizing a stem is
//! the engine's job (`MirrorEngine::sanitize_names`); this module decides
//! what goes in and what a result may look like.

use unicode_normalization::UnicodeNormalization;

use crate::engine::ManifestStore;
use crate::formats::kept_extension;

/// Names never mirrored and never counted (spec §4.2): dotfiles and
/// dot-directories, editor and office lock or swap files, partial
/// downloads, `Thumbs.db`, `desktop.ini`.
pub fn ignored(name: &[u8]) -> bool {
    let ends =
        |s: &[u8]| name.len() >= s.len() && name[name.len() - s.len()..].eq_ignore_ascii_case(s);
    name.first() == Some(&b'.')
        || name.last() == Some(&b'~')
        || (name.len() > 1 && name.first() == Some(&b'#') && name.last() == Some(&b'#'))
        || name.starts_with(b"~$")
        || ends(b".swp")
        || ends(b".swx")
        || ends(b".part")
        || ends(b".crdownload")
        || ends(b".tmp")
        || name.eq_ignore_ascii_case(b"Thumbs.db")
        || name.eq_ignore_ascii_case(b"desktop.ini")
}

/// The reserved top-level directory.
pub const OUTBOX: &str = "outbox";
/// What a top-level source entry named `outbox` is mirrored as.
pub const OUTBOX_RENAMED: &str = "outbox~source";

/// Stem and kept extension. Directory names are never split.
pub fn split_name(name: &str, is_dir: bool) -> (&str, Option<&str>) {
    if is_dir {
        return (name, None);
    }
    match kept_extension(name) {
        Some(ext) => (&name[..name.len() - ext.len() - 1], Some(ext)),
        None => (name, None),
    }
}

/// A name the mirror may write.
pub fn valid_component(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.contains('/')
        && !s.contains('\0')
        && s.len() <= 255
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `f-<10 hex>[.ext]`, keyed by dataset, epoch, relative path.
pub fn opaque_name(
    m: &dyn ManifestStore,
    dataset: &str,
    epoch: i64,
    rel: &[u8],
    ext: Option<&str>,
) -> String {
    let mac = m.mac(&format!("mirror:opaque:{dataset}:{epoch}"), rel);
    let base = format!("f-{}", &hex(&mac)[..10]);
    match ext {
        Some(e) => format!("{base}.{e}"),
        None => base,
    }
}

/// `~<4 hex>`, keyed by dataset, epoch, relative path.
pub fn collision_suffix(m: &dyn ManifestStore, dataset: &str, epoch: i64, rel: &[u8]) -> String {
    let mac = m.mac(&format!("mirror:collision:{dataset}:{epoch}"), rel);
    format!("~{}", &hex(&mac)[..4])
}

/// Insert `suffix` before the kept extension (appended when `name` does not
/// end with `.ext`).
pub fn with_suffix(name: &str, suffix: &str, ext: Option<&str>) -> String {
    match ext.and_then(|e| name.strip_suffix(&format!(".{e}"))) {
        Some(stem) if !stem.is_empty() => {
            format!("{stem}{suffix}.{}", &name[stem.len() + 1..])
        }
        _ => format!("{name}{suffix}"),
    }
}

/// NFC plus lower case: the collision key (APFS is case-insensitive).
pub fn casefold(s: &str) -> String {
    s.nfc().collect::<String>().to_lowercase()
}

/// Placeholder families (spec §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderClass {
    /// `.inumaki-unsupported.txt`.
    Unsupported,
    /// `.inumaki-blocked.txt`.
    Blocked,
}

/// `<mirror name>.inumaki-<family>.txt`. The result can exceed 255 bytes for a
/// long mirror name: the caller checks [`valid_component`] and falls back to
/// the opaque name.
pub fn placeholder_name(mirror_name: &str, c: PlaceholderClass) -> String {
    match c {
        PlaceholderClass::Unsupported => format!("{mirror_name}.inumaki-unsupported.txt"),
        PlaceholderClass::Blocked => format!("{mirror_name}.inumaki-blocked.txt"),
    }
}
