//! Hand-written cases in TOML; spans are given by their text.

use serde::Deserialize;
use unicode_normalization::UnicodeNormalization;

use crate::corpus::{Doc, EvalError, GoldSpan, default_sensitive};

#[derive(Deserialize)]
struct File {
    case: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    lang: String,
    #[serde(default)]
    why: Option<String>,
    text: String,
    #[serde(default)]
    spans: Vec<SpanSpec>,
}

#[derive(Deserialize)]
struct SpanSpec {
    text: String,
    kind: String,
    /// 1-based occurrence; all occurrences when absent.
    occurrence: Option<usize>,
    sensitive: Option<bool>,
    /// Gold entity id: spans naming the same person share one (coreference
    /// and wrong-link metrics).
    entity: Option<String>,
}

/// 1-based `(line, column)` of byte offset `at` in `src`. Used only to locate a syntax
/// error in a cases *file* (never in case or span text, which the caller already has).
fn line_col(src: &str, at: usize) -> (usize, usize) {
    let at = at.min(src.len());
    let mut line = 1;
    let mut col = 1;
    for c in src[..at].chars() {
        if c == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Parse one cases file. Span texts are located in the (NFC) case text.
pub fn parse_cases(file_name: &str, toml_src: &str) -> Result<Vec<Doc>, EvalError> {
    let f: File = toml::from_str(toml_src).map_err(|e| {
        // `toml::de::Error::span()` locates the syntax error in `toml_src` (the cases
        // *file*, never a hand-written case's text); keep line/column when it is available
        // instead of collapsing every parse failure to just the file name, which made two
        // different syntax errors in the same file indistinguishable.
        let where_ = e.span().map(|span| {
            let (line, col) = line_col(toml_src, span.start);
            format!(":{line}:{col}")
        });
        EvalError::Parse(format!(
            "{file_name}{}: {}",
            where_.unwrap_or_default(),
            e.message()
        ))
    })?;
    let mut out = Vec::new();
    for c in f.case {
        let text: String = c.text.nfc().collect();
        let mut spans = Vec::new();
        for (i, s) in c.spans.iter().enumerate() {
            let needle: String = s.text.nfc().collect();
            let starts: Vec<usize> = text
                .match_indices(needle.as_str())
                .map(|(p, _)| p)
                .collect();
            let chosen: Vec<usize> = match s.occurrence {
                Some(n) => starts.get(n.wrapping_sub(1)).copied().into_iter().collect(),
                None => starts,
            };
            if chosen.is_empty() {
                return Err(EvalError::Invalid(format!(
                    "{file_name}: case {} span {i} not found",
                    c.id
                )));
            }
            for p in chosen {
                spans.push(GoldSpan {
                    start: p,
                    end: p + needle.len(),
                    kind: s.kind.clone(),
                    sensitive: s.sensitive.unwrap_or_else(|| default_sensitive(&s.kind)),
                    entity: s.entity.clone(),
                });
            }
        }
        spans.sort_by_key(|s| s.start);
        let doc = Doc {
            id: c.id,
            lang: c.lang,
            text,
            spans,
            why: c.why,
        };
        doc.validate()?;
        out.push(doc);
    }
    Ok(out)
}

const FILES: &[(&str, &str)] = &[
    ("signatures.toml", include_str!("../cases/signatures.toml")),
    ("threads.toml", include_str!("../cases/threads.toml")),
    (
        "names_and_places.toml",
        include_str!("../cases/names_and_places.toml"),
    ),
    (
        "identifiers_and_negatives.toml",
        include_str!("../cases/identifiers_and_negatives.toml"),
    ),
    ("m4_safety.toml", include_str!("../cases/m4_safety.toml")),
    ("linking.toml", include_str!("../cases/linking.toml")),
    (
        "name_shapes.toml",
        include_str!("../cases/name_shapes.toml"),
    ),
    (
        "structured_positions.toml",
        include_str!("../cases/structured_positions.toml"),
    ),
];

/// All shipped cases, compiled into the binary.
pub fn embedded_cases() -> Vec<Doc> {
    FILES
        .iter()
        .flat_map(|(name, src)| parse_cases(name, src).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_resolve_by_text_and_occurrence() {
        let t = r#"
            [[case]]
            id = "x"
            lang = "de"
            why = "test"
            text = "Anna Berger schrieb. Gruß, Anna"
            spans = [
              { text = "Anna Berger", kind = "PERSON" },
              { text = "Anna", kind = "PERSON", occurrence = 2 },
            ]
        "#;
        let docs = parse_cases("t.toml", t).unwrap();
        let d = &docs[0];
        let got: Vec<&str> = d.spans.iter().map(|s| &d.text[s.start..s.end]).collect();
        assert_eq!(got, vec!["Anna Berger", "Anna"]);
        assert_eq!(d.spans[1].start, 28);
    }

    #[test]
    fn malformed_toml_error_carries_line_and_column() {
        // Line 2 has an unterminated string.
        let t = "[[case]]\nid = \"y\n";
        let e = parse_cases("bad.toml", t).unwrap_err();
        let msg = format!("{e}");
        assert!(msg.contains("bad.toml:2:"), "{msg}");
    }

    #[test]
    fn missing_span_text_is_an_error_naming_the_case() {
        let t = "[[case]]\nid = \"y\"\nlang = \"en\"\ntext = \"hello\"\nspans = [ { text = \"Bob\", kind = \"PERSON\" } ]\n";
        let e = parse_cases("t.toml", t).unwrap_err();
        assert!(format!("{e}").contains("y"), "{e}");
    }

    /// Spec §13.1: the held-out lists are disjoint from the tuning corpus, and
    /// the built-in cases are part of the tuning corpus (they are folded into
    /// every full-corpus eval alongside the 2 000 generated documents). A
    /// held-out first name, last name, street, or city leaking into a case's
    /// text would let that case's calibration see held-out material, which is
    /// exactly what `held_out_lists_are_disjoint_from_tuning_lists`
    /// (`generate.rs`) guards against for the generator's own lists.
    #[test]
    fn embedded_cases_contain_no_held_out_identities() {
        use inumaki_core::detect::dictionary::word_bounded;

        fn contains_word(text: &str, word: &str) -> bool {
            text.match_indices(word)
                .any(|(i, _)| word_bounded(text, i, i + word.len()))
        }

        let mut words: Vec<&str> = Vec::new();
        words.extend(crate::data_held_out::FIRST_NAMES.iter().copied());
        words.extend(crate::data_held_out::LAST_NAMES.iter().copied());
        for (zip, city) in crate::data_held_out::CITIES {
            words.push(zip);
            words.push(city);
        }

        for d in embedded_cases() {
            for w in &words {
                assert!(
                    !contains_word(&d.text, w),
                    "case {} contains held-out entry {w:?}: {:?}",
                    d.id,
                    d.text
                );
            }
            for street in crate::data_held_out::STREETS {
                assert!(
                    !d.text.contains(street),
                    "case {} contains held-out street {street:?}: {:?}",
                    d.id,
                    d.text
                );
            }
        }
    }

    #[test]
    fn shipped_cases_load_and_are_valid() {
        let docs = embedded_cases();
        assert!(docs.len() >= 67, "{}", docs.len());
        let mut ids: Vec<&str> = docs.iter().map(|d| d.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), docs.len(), "case ids must be unique");
        for d in &docs {
            d.validate().unwrap_or_else(|e| panic!("{}: {e}", d.id));
        }
        assert!(docs.iter().any(|d| d.spans.is_empty()), "negatives present");
    }
}
