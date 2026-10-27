//! DACH first-name gazetteer (engine spec §6.1 amendment): supporting
//! evidence for the anchor detector and the linker, never a detector.
//!
//! Data: `data/first_names_dach.txt`, built by `scripts/first-names/build.sh`
//! from Statistik Austria `OGDEXT_VORNAMEN_1` (CC BY 4.0) and Berlin
//! `haeufige-vornamen-berlin` (CC BY 3.0 DE); attribution in `NOTICE`.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::token::normalize;

const DATA: &str = include_str!("../data/first_names_dach.txt");

/// German ASCII transliteration of `ü`/`ö`/`ä` as `ue`/`oe`/`ae`: many people
/// write "Juergen" for "Jürgen" when umlauts are not available. `normalize`
/// only strips the diacritic (`ü` -> `u`), so the gazetteer indexes this
/// spelling as an alternate key alongside the diacritic-stripped one.
/// Returns `None` when `line` has no umlaut to expand.
fn ascii_umlaut_variant(line: &str) -> Option<String> {
    if !line.contains(['ü', 'ö', 'ä', 'Ü', 'Ö', 'Ä']) {
        return None;
    }
    let mut out = String::with_capacity(line.len() + 4);
    for c in line.chars() {
        match c {
            'ü' => out.push_str("ue"),
            'ö' => out.push_str("oe"),
            'ä' => out.push_str("ae"),
            'Ü' => out.push_str("Ue"),
            'Ö' => out.push_str("Oe"),
            'Ä' => out.push_str("Ae"),
            _ => out.push(c),
        }
    }
    Some(out)
}

static SET: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    for l in DATA
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        set.insert(normalize(l).as_str().to_string());
        if let Some(v) = ascii_umlaut_variant(l) {
            set.insert(normalize(&v).as_str().to_string());
        }
    }
    set
});

/// True when `word` is a DACH first name after normalization (case,
/// diacritics, `ß`). Three characters minimum; the stoplist wins.
pub fn is_first_name(word: &str) -> bool {
    let w = word.trim();
    if w.chars().count() < 3 || crate::stoplist::is_common_word(w) {
        return false;
    }
    SET.contains(normalize(w).as_str())
}

/// Number of normalized lookup keys in the gazetteer: one per distinct
/// spelling in the data file, plus one more for each name that has an
/// `ascii_umlaut_variant`, so this overcounts the number of distinct names.
pub fn len() -> usize {
    SET.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_dach_and_international_first_names_are_known() {
        for n in [
            "Sarah", "Jürgen", "juergen", "JÜRGEN", "Ayşe", "Ayse", "Zeynep", "Bojan", "Hüseyin",
            "Noah", "Eva", "Elif", "Milan", "Thomas",
        ] {
            assert!(is_first_name(n), "{n}");
        }
    }

    #[test]
    fn surnames_words_and_short_strings_are_not() {
        for n in [
            "Leitner",
            "Gruber",
            "und",
            "the",
            "Team",
            "Damen",
            "Neubaugasse",
            "GmbH",
            "Al",
            "x",
            "",
        ] {
            assert!(!is_first_name(n), "{n}");
        }
    }

    #[test]
    fn the_data_file_is_well_formed() {
        assert!(len() >= 10_000, "{}", len());
        for line in DATA.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            assert_eq!(line, line.trim());
            assert!(unicode_normalization::is_nfc(line), "{line}");
            assert!(line.chars().count() >= 3, "{line}");
            assert!(
                line.chars()
                    .all(|c| c.is_alphabetic() || c == '-' || c == '\''),
                "{line}"
            );
            assert!(
                !crate::stoplist::is_common_word(line),
                "stoplisted word in the gazetteer: {line}"
            );
        }
        assert!(
            DATA.lines().next().unwrap().starts_with("# "),
            "attribution header"
        );
        assert!(DATA.contains("CC BY 4.0") && DATA.contains("CC BY 3.0 DE"));
    }
}
