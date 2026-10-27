//! Path comparison that matches how the file system does (M5 review I3).
//!
//! APFS is case- and normalization-insensitive. `canonicalize` returns the
//! on-disk case for what exists, but a path the daemon cannot resolve (an
//! `EPERM` source, a destination not created yet, a hook path inside a
//! folder it has no grant for) keeps the case it was typed in. Comparing
//! such a tail byte for byte would let `.../akten/x` miss the source
//! `.../Akten`, so folder matching folds case and normalization (macOS
//! only) component by component. Use it where over-matching is the safe
//! direction: validation refusals and the hook's source and outbox match.
//! The hook's mirror-root exemption stays exact.

use std::ffi::OsStr;
use std::path::Path;

use unicode_normalization::UnicodeNormalization;

/// Case folding from std alone: lowercase of the uppercase. Plain
/// lowercasing is not case folding (`ς` and `σ`, `ſ` and `s` stay
/// apart); through the uppercase they meet, as do `ß` and `ss`.
/// Over-matching is the safe direction here.
fn fold_component(c: &OsStr, fold: bool) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    match c.to_str() {
        Some(s) if fold => s
            .nfc()
            .collect::<String>()
            .to_uppercase()
            .to_lowercase()
            .nfc()
            .collect::<String>()
            .into_bytes(),
        _ => c.as_bytes().to_vec(),
    }
}

/// `path` is `base` or below it, component-wise. `fold` selects case and
/// normalization folding.
pub fn starts_with_fold(path: &Path, base: &Path, fold: bool) -> bool {
    let mut p = path.components();
    base.components().all(|b| {
        p.next().is_some_and(|c| {
            fold_component(c.as_os_str(), fold) == fold_component(b.as_os_str(), fold)
        })
    })
}

/// [`starts_with_fold`] with this platform's file-system rule.
pub fn starts_with(path: &Path, base: &Path) -> bool {
    starts_with_fold(path, base, cfg!(target_os = "macos"))
}

/// Same directory, by name.
pub fn same(a: &Path, b: &Path) -> bool {
    starts_with(a, b) && starts_with(b, a)
}

/// One contains the other, or they are the same.
pub fn overlap(a: &Path, b: &Path) -> bool {
    starts_with(a, b) || starts_with(b, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folding_matches_case_and_normalization_component_wise() {
        let p = |s: &str| std::path::PathBuf::from(s);
        assert!(starts_with_fold(
            &p("/u/Documents/akten/x"),
            &p("/u/documents/Akten"),
            true
        ));
        assert!(!starts_with_fold(
            &p("/u/Documents/akten/x"),
            &p("/u/documents/Akten"),
            false
        ));
        // NFD "u" + combining diaeresis against NFC "\u{fc}".
        assert!(starts_with_fold(
            &p("/u/Sch\u{fc}ler"),
            &p("/u/schu\u{308}ler"),
            true
        ));
        // Component-wise: a longer name sharing a prefix is not below.
        assert!(!starts_with_fold(
            &p("/u/Aktenschrank"),
            &p("/u/akten"),
            true
        ));
        assert!(starts_with_fold(&p("/u/akten"), &p("/u/Akten/"), true));
        // Case folding, not lowercasing (8a re-review n3).
        assert!(starts_with_fold(&p("/u/\u{3c3}x"), &p("/u/\u{3c2}x"), true));
        assert!(starts_with_fold(&p("/u/x\u{3c3}"), &p("/u/x\u{3c2}"), true));
        assert!(starts_with_fold(&p("/u/\u{17f}ache"), &p("/u/Sache"), true));
        assert!(!starts_with_fold(&p("/u"), &p("/u/akten"), true));
    }
}
