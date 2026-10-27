//! Identifying residue in accepted output (spec §13.1): the exact value, a
//! normalized variant (case, whitespace, Unicode, transliteration), or an
//! identifying component (a name part, a street name, a mail local part)
//! that survived into the sanitized text. Independent of the verifier: it
//! never consults a verdict, only the gold span and the output text.

use inumaki_core::detect::dictionary::word_bounded;
use inumaki_core::stoplist::{is_common_word, name_parts};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

/// A whole value shorter than this (in characters) is never residue; it
/// would match too much ordinary text (mirrors the verifier's floor).
pub const MIN_CHARS: usize = 3;
/// A component (name part, street name, local part) needs this many characters.
pub const MIN_COMPONENT_CHARS: usize = 4;
/// A numeric value needs this many digits before its digit string counts.
pub const MIN_DIGITS: usize = 7;

/// What survived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Residue {
    /// The whole value, as written or in a normalized variant.
    Full,
    /// An identifying component only (surname, first name, street name, local part).
    Partial,
}

/// Street words that identify nothing on their own.
const STREET_STOP: &[&str] = &[
    "straße",
    "strasse",
    "str.",
    "str",
    "gasse",
    "weg",
    "platz",
    "allee",
    "ring",
    "ufer",
    "damm",
    "markt",
    "zeile",
    "hof",
    "promenade",
    "am",
    "an",
    "der",
    "die",
    "das",
    "im",
    "in",
    "auf",
    "zum",
    "zur",
    "lange",
    "obere",
    "untere",
    "neue",
    "alte",
    "kurze",
    "große",
    "grosse",
    "kleine",
];

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn transliterate(s: &str) -> String {
    s.replace('ä', "ae")
        .replace('ö', "oe")
        .replace('ü', "ue")
        .replace('ß', "ss")
        .replace('Ä', "Ae")
        .replace('Ö', "Oe")
        .replace('Ü', "Ue")
}

fn fold(s: &str) -> String {
    s.nfd().filter(|c| !is_combining_mark(*c)).collect()
}

fn digits(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Every maximal run of digits separated by single spaces, hyphens, slashes
/// or dots in `text`, as its digit string. Runs never merge across other
/// characters, so a date next to a phone number does not become one number.
fn digit_runs(text: &str) -> Vec<String> {
    let mut runs = Vec::new();
    let mut cur = String::new();
    let mut prev_sep = false;
    for c in text.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
            prev_sep = false;
        } else if matches!(c, ' ' | '-' | '/' | '.') && !cur.is_empty() && !prev_sep {
            prev_sep = true;
        } else {
            if !cur.is_empty() {
                runs.push(std::mem::take(&mut cur));
            }
            prev_sep = false;
        }
    }
    if !cur.is_empty() {
        runs.push(cur);
    }
    runs
}

fn contains_bounded(hay: &str, needle: &str) -> bool {
    !needle.is_empty()
        && hay
            .match_indices(needle)
            .any(|(i, _)| word_bounded(hay, i, i + needle.len()))
}

/// The three haystack forms a needle is searched in: lower-cased,
/// lower-cased and transliterated, lower-cased and diacritic-folded.
struct Hay {
    lower: String,
    tl: String,
    folded: String,
}

impl Hay {
    fn new(output: &str) -> Self {
        let lower = collapse(output).to_lowercase();
        Hay {
            tl: transliterate(&lower),
            folded: fold(&lower),
            lower,
        }
    }

    fn has(&self, needle: &str) -> bool {
        let n = collapse(needle).to_lowercase();
        contains_bounded(&self.lower, &n)
            || contains_bounded(&self.tl, &transliterate(&n))
            || contains_bounded(&self.folded, &fold(&n))
    }
}

/// Components that identify on their own.
fn components(kind: &str, value: &str) -> Vec<String> {
    match kind {
        "PERSON" => name_parts(value).map(str::to_string).collect(),
        "STREET_ADDRESS" => value
            .split_whitespace()
            .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
            .filter(|w| {
                w.chars().count() >= MIN_COMPONENT_CHARS
                    && w.chars().any(char::is_alphabetic)
                    && !STREET_STOP.contains(&w.to_lowercase().as_str())
                    && !is_common_word(w)
            })
            .map(str::to_string)
            .collect(),
        "EMAIL" => value
            .split('@')
            .next()
            .filter(|l| l.chars().count() >= MIN_COMPONENT_CHARS && !is_common_word(l))
            .map(str::to_string)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// Residue of the gold `value` of `kind` in the sanitized `output`, if any.
///
/// `Full` when the whole value survives as written or after case,
/// whitespace, Unicode, or transliteration normalization, or (for values
/// with at least [`MIN_DIGITS`] digits) as the same digit string inside one
/// digit run of the output. `Partial` when an identifying component
/// survives on its own. Components that identify nothing (a street suffix,
/// a bare house number, a common-word name part) are never residue.
pub fn find_residue(kind: &str, value: &str, output: &str) -> Option<Residue> {
    if value.chars().count() < MIN_CHARS {
        return None;
    }
    let hay = Hay::new(output);
    if hay.has(value) {
        return Some(Residue::Full);
    }
    let d = digits(value);
    if d.len() >= MIN_DIGITS && digit_runs(output).iter().any(|run| run.contains(&d)) {
        return Some(Residue::Full);
    }
    if components(kind, value).iter().any(|c| hay.has(c)) {
        return Some(Residue::Partial);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_normalized_full_values_are_full_residue() {
        let cases = [
            ("PERSON", "Sarah Leitner", "Hallo Sarah Leitner, danke."),
            ("PERSON", "Sarah Leitner", "hallo sarah leitner"),
            ("PERSON", "Sarah Leitner", "Bitte an Sarah\n  Leitner"),
            ("PERSON", "Jörg Müller", "JOERG MUELLER rief an"),
            ("PERSON", "Jörg Müller", "Jorg Muller rief an"),
            (
                "STREET_ADDRESS",
                "Neubaugasse 22",
                "wohnt in Neubaugasse\n22.",
            ),
            (
                "IBAN",
                "AT61 1904 3002 3457 3201",
                "Konto AT611904300234573201 bitte",
            ),
            ("PHONE", "+43 660 1234567", "Tel 0043-660-1234567"),
        ];
        for (kind, value, out) in cases {
            assert_eq!(
                find_residue(kind, value, out),
                Some(Residue::Full),
                "{kind} {value:?} in {out:?}"
            );
        }
    }

    #[test]
    fn components_are_partial_residue() {
        assert_eq!(
            find_residue("PERSON", "Sarah Leitner", "Frau Leitner kam."),
            Some(Residue::Partial)
        );
        assert_eq!(
            find_residue("PERSON", "Sarah Leitner", "sarah hat angerufen"),
            Some(Residue::Partial)
        );
        assert_eq!(
            find_residue("PERSON", "Jörg Müller", "Herr Mueller kam."),
            Some(Residue::Partial)
        );
        assert_eq!(
            find_residue(
                "STREET_ADDRESS",
                "Mariahilfer Straße 7",
                "in der Mariahilfer <STREET_ADDRESS_a1b2c3>"
            ),
            Some(Residue::Partial)
        );
        assert_eq!(
            find_residue("STREET_ADDRESS", "Neubaugasse 22", "Neubaugasse <X_0000>"),
            Some(Residue::Partial)
        );
        assert_eq!(
            find_residue(
                "EMAIL",
                "sarah.leitner@gmx.at",
                "mail von sarah.leitner an uns"
            ),
            Some(Residue::Partial)
        );
    }

    #[test]
    fn incidental_substrings_house_numbers_and_common_words_are_not_residue() {
        assert_eq!(
            find_residue("STREET_ADDRESS", "Neubaugasse 22", "Bestellung 22 Stück"),
            None
        );
        assert_eq!(
            find_residue(
                "STREET_ADDRESS",
                "Lange Gasse 12",
                "die lange Gasse hinter dem Haus"
            ),
            None
        );
        assert_eq!(
            find_residue("PERSON", "Thomas May", "Im May haben wir Pause"),
            None
        );
        assert_eq!(
            find_residue("PERSON", "Sarah Leitner", "Leitnerstraße 5"),
            None,
            "word boundary"
        );
        assert_eq!(
            find_residue("PERSON", "Eva Leitner", "Eva ist nett"),
            None,
            "three-letter part"
        );
        assert_eq!(
            find_residue("IBAN", "AT61 1904 3002 3457 3201", "Ref 3457 3201 und 1904"),
            None
        );
        assert_eq!(
            find_residue("CUSTOMER_ID", "K-928174", "Kunde <CUSTOMER_ID_a1b2c3>"),
            None
        );
        assert_eq!(
            find_residue("PERSON", "X1", "X1 X1"),
            None,
            "below MIN_CHARS"
        );
    }

    #[test]
    fn full_wins_over_partial_when_both_are_present() {
        assert_eq!(
            find_residue("PERSON", "Sarah Leitner", "Sarah Leitner und Leitner"),
            Some(Residue::Full)
        );
    }
}
