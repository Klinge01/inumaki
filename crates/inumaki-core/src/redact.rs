//! Explicit redactions (M4 spec §9.1): spans a user marks as mandatory
//! transformations on the NFC input. A redaction only adds coverage and
//! strengthens the action taken over the range it overlaps (see
//! `engine::merge_redaction`); it never evicts a detected span, never
//! weakens a policy block, and never marks text safe — verification runs
//! unchanged.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::span::{DetectorId, EntityKind, Span};

/// What a redaction does to its span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactionAction {
    /// Replace with a token of `kind`.
    Tokenize,
    /// Replace with the `_REMOVED` marker; never restorable.
    Remove,
}

/// One user-marked span. Offsets are bytes into the NFC-normalized input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redaction {
    /// First byte.
    pub start: usize,
    /// One past the last byte.
    pub end: usize,
    /// Entity kind label (`PERSON`, `CUSTOMER_ID`, a custom label).
    pub kind: String,
    /// Action.
    pub action: RedactionAction,
}

/// The redactions file: `{input_sha256, spans}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionFile {
    /// SHA-256 (lower-case hex) of the NFC input the spans refer to.
    pub input_sha256: String,
    /// The spans.
    pub spans: Vec<Redaction>,
}

/// Why a redactions file was refused. Carries indexes, never text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RedactionError {
    /// `input_sha256` is not the digest of the input.
    #[error("redactions: input digest does not match")]
    Digest,
    /// A span is empty or outside the input.
    #[error("redactions: span {0} is empty or out of range")]
    Range(usize),
    /// A span offset is not on a char boundary.
    #[error("redactions: span {0} is not on a char boundary")]
    Boundary(usize),
    /// A span overlaps an earlier one.
    #[error("redactions: span {0} overlaps another")]
    Overlap(usize),
    /// A kind label, upper-cased, is not `[A-Z][A-Z_]{0,31}`.
    #[error("redactions: span {0} has an invalid kind")]
    Kind(usize),
}

/// Lower-case hex SHA-256 of `text`.
pub fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The kind, upper-cased, has the one kind-label shape `[A-Z][A-Z_]{0,31}`
/// ([`crate::span::valid_kind_label`]).
fn valid_kind(k: &str) -> bool {
    crate::span::valid_kind_label(&k.to_ascii_uppercase())
}

/// Check `file` against `nfc_text` and return its spans sorted by start.
pub fn validate_redactions(
    nfc_text: &str,
    file: &RedactionFile,
) -> Result<Vec<Redaction>, RedactionError> {
    if file.input_sha256 != sha256_hex(nfc_text) {
        return Err(RedactionError::Digest);
    }
    for (i, r) in file.spans.iter().enumerate() {
        if r.start >= r.end || r.end > nfc_text.len() {
            return Err(RedactionError::Range(i));
        }
        if !nfc_text.is_char_boundary(r.start) || !nfc_text.is_char_boundary(r.end) {
            return Err(RedactionError::Boundary(i));
        }
        if !valid_kind(&r.kind) {
            return Err(RedactionError::Kind(i));
        }
    }
    let mut order: Vec<usize> = (0..file.spans.len()).collect();
    order.sort_by_key(|&i| file.spans[i].start);
    let mut prev_end = 0usize;
    for &i in &order {
        if file.spans[i].start < prev_end {
            return Err(RedactionError::Overlap(i));
        }
        prev_end = file.spans[i].end;
    }
    Ok(order.into_iter().map(|i| file.spans[i].clone()).collect())
}

/// Spans for the resolver: source `Redaction`, confidence 1.0.
pub fn redaction_spans(reds: &[Redaction]) -> Vec<Span> {
    reds.iter()
        .map(|r| {
            Span::new(
                r.start,
                r.end,
                EntityKind::from_label(&r.kind),
                1.0,
                DetectorId::Redaction,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(text: &str, spans: Vec<Redaction>) -> RedactionFile {
        RedactionFile {
            input_sha256: sha256_hex(text),
            spans,
        }
    }

    fn r(start: usize, end: usize) -> Redaction {
        Redaction {
            start,
            end,
            kind: "PERSON".into(),
            action: RedactionAction::Tokenize,
        }
    }

    /// Review Focus 8.
    #[test]
    fn redactions_are_validated_before_use() {
        let text = "Hallo Sarah Leitner, Müller kam.";
        let ok = validate_redactions(text, &file(text, vec![r(21, 27), r(6, 19)])).unwrap();
        assert_eq!(
            ok.iter().map(|x| x.start).collect::<Vec<_>>(),
            [6, 21],
            "sorted"
        );
        let mut stale = file(text, vec![r(6, 19)]);
        stale.input_sha256 = sha256_hex("other text");
        assert_eq!(
            validate_redactions(text, &stale),
            Err(RedactionError::Digest)
        );
        assert_eq!(
            validate_redactions(text, &file(text, vec![r(6, 6)])),
            Err(RedactionError::Range(0))
        );
        assert_eq!(
            validate_redactions(text, &file(text, vec![r(6, 999)])),
            Err(RedactionError::Range(0))
        );
        assert_eq!(
            validate_redactions(text, &file(text, vec![r(23, 27)])),
            Err(RedactionError::Boundary(0)),
            "inside ü"
        );
        assert_eq!(
            validate_redactions(text, &file(text, vec![r(6, 19), r(10, 27)])),
            Err(RedactionError::Overlap(1))
        );
        for k in ["not a label", "IBAN_AT611904300234573201", "büro"] {
            let mut bad_kind = r(6, 19);
            bad_kind.kind = k.into();
            assert_eq!(
                validate_redactions(text, &file(text, vec![bad_kind])),
                Err(RedactionError::Kind(0)),
                "{k}"
            );
        }
        let spans = redaction_spans(&ok);
        assert_eq!(spans[0].source, crate::span::DetectorId::Redaction);
        assert_eq!(spans[0].kind, crate::span::EntityKind::Person);
        assert!((spans[0].confidence - 1.0).abs() < 1e-6);
    }

    #[test]
    fn file_round_trips_through_json() {
        let text = "x";
        let f = file(
            text,
            vec![Redaction {
                start: 0,
                end: 1,
                kind: "CUSTOMER_ID".into(),
                action: RedactionAction::Remove,
            }],
        );
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.contains("\"action\":\"remove\""));
        assert_eq!(serde_json::from_str::<RedactionFile>(&j).unwrap(), f);
    }
}
