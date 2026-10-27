//! Documents with gold spans, JSONL I/O, and validation.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

/// Errors in evaluation input. Messages name files, lines, and case ids, never text.
#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    /// File could not be read or written.
    #[error("file error: {0}")]
    Io(String),
    /// Input could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),
    /// A document or case is inconsistent.
    #[error("invalid: {0}")]
    Invalid(String),
}

/// A gold entity span. Byte offsets into [`Doc::text`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoldSpan {
    /// Byte offset of the first byte.
    pub start: usize,
    /// Byte offset one past the last byte.
    pub end: usize,
    /// Entity kind label, e.g. `PERSON`.
    pub kind: String,
    /// Whether the value must not reach the model under the default policy.
    pub sensitive: bool,
    /// Gold entity id linking spans that name the same person across
    /// blocks of one document (plan 4a Task 5's referential-consistency
    /// checks). Not serialized: a corpus digest pinned before this field
    /// existed stays valid, and the id is a generator-internal detail, not
    /// part of the evaluated corpus's identity.
    #[serde(skip)]
    pub entity: Option<String>,
}

/// One evaluation document.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Doc {
    /// Unique id.
    pub id: String,
    /// `de`, `en`, or `mixed`.
    pub lang: String,
    /// NFC text.
    pub text: String,
    /// Non-overlapping gold spans, sorted by start.
    pub spans: Vec<GoldSpan>,
    /// Why the case exists (hand-written cases).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

impl std::fmt::Debug for Doc {
    /// Hand-written: `text` is corpus/case input and must never reach a log or panic
    /// message. Prints `id`, `lang`, the text's length, and the span count, not the
    /// text or the spans themselves (a span's `kind` alone is harmless, but printing
    /// only some fields of a struct next to fields it always hides invites a future
    /// `{d.spans:?}` debug print elsewhere that leaks offsets into surrounding text).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Doc")
            .field("id", &self.id)
            .field("lang", &self.lang)
            .field("text_len", &self.text.len())
            .field("spans", &self.spans.len())
            .finish()
    }
}

/// Kinds the default profiles preserve are not sensitive; everything else is.
pub fn default_sensitive(kind: &str) -> bool {
    !matches!(
        kind,
        "CITY" | "POSTAL_CODE" | "COUNTRY" | "ORGANIZATION" | "URL" | "DATE"
    )
}

impl Doc {
    /// Offsets in range, on char boundaries, non-empty, sorted, and non-overlapping.
    pub fn validate(&self) -> Result<(), EvalError> {
        let bad = |why: &str| EvalError::Invalid(format!("{}: {why}", self.id));
        let mut prev_end = 0usize;
        for (i, s) in self.spans.iter().enumerate() {
            if s.start >= s.end || s.end > self.text.len() {
                return Err(bad(&format!("span {i} out of range")));
            }
            if !self.text.is_char_boundary(s.start) || !self.text.is_char_boundary(s.end) {
                return Err(bad(&format!("span {i} not on a char boundary")));
            }
            if i > 0 && s.start < prev_end {
                return Err(bad(&format!("span {i} overlaps or is out of order")));
            }
            prev_end = s.end;
        }
        Ok(())
    }
}

/// Read one [`Doc`] per line.
pub fn read_jsonl(path: &Path) -> Result<Vec<Doc>, EvalError> {
    let f = std::fs::File::open(path).map_err(|_| EvalError::Io(path.display().to_string()))?;
    let mut out = Vec::new();
    for (n, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|_| EvalError::Io(path.display().to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        let d: Doc = serde_json::from_str(&line)
            .map_err(|_| EvalError::Parse(format!("{}:{}", path.display(), n + 1)))?;
        // The engine NFC-normalizes input, so gold offsets are only meaningful on NFC text.
        if d.text.nfc().collect::<String>() != d.text {
            return Err(EvalError::Invalid(format!(
                "{}:{}: text is not NFC",
                path.display(),
                n + 1
            )));
        }
        d.validate()?;
        out.push(d);
    }
    Ok(out)
}

/// Write one [`Doc`] per line.
pub fn write_jsonl(path: &Path, docs: &[Doc]) -> Result<(), EvalError> {
    let mut f =
        std::fs::File::create(path).map_err(|_| EvalError::Io(path.display().to_string()))?;
    for d in docs {
        // Serializing a `Doc` we built ourselves failing is an I/O-shaped surprise (an
        // out-of-memory allocation, say), not a parse error in caller-supplied input, so it
        // is reported against the destination path like every other failure in this
        // function, not against the document id (`EvalError::Parse` is for input we read).
        let line =
            serde_json::to_string(d).map_err(|_| EvalError::Io(path.display().to_string()))?;
        writeln!(f, "{line}").map_err(|_| EvalError::Io(path.display().to_string()))?;
    }
    Ok(())
}

/// Lower-case hex SHA-256 over the JSONL serialization of `docs`, in order.
/// Pins a corpus in reports and baselines (spec §13.1).
pub fn digest(docs: &[Doc]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for d in docs {
        h.update(
            serde_json::to_string(d)
                .expect("a Doc serializes")
                .as_bytes(),
        );
        h.update(b"\n");
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Doc {
        Doc {
            id: "d1".into(),
            lang: "de".into(),
            text: "Frau Müller wohnt in Wien.".into(),
            spans: vec![
                GoldSpan {
                    start: 5,
                    end: 12,
                    kind: "PERSON".into(),
                    sensitive: true,
                    entity: None,
                },
                GoldSpan {
                    start: 22,
                    end: 26,
                    kind: "CITY".into(),
                    sensitive: false,
                    entity: None,
                },
            ],
            why: None,
        }
    }

    #[test]
    fn valid_doc_passes_and_bad_offsets_fail() {
        assert!(doc().validate().is_ok());
        let mut d = doc();
        d.spans[0].start = 7; // "Frau " is 5 bytes, 'M' is byte 5, 'ü' is bytes 6..8
        assert!(d.validate().is_err(), "offset inside ü");
        let mut d = doc();
        d.spans[1].start = 10;
        assert!(d.validate().is_err(), "overlap");
    }

    #[test]
    fn jsonl_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.jsonl");
        write_jsonl(&p, &[doc(), doc()]).unwrap();
        let back = read_jsonl(&p).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].spans, doc().spans);
    }

    #[test]
    fn jsonl_rejects_non_nfc_text() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nfd.jsonl");
        // "Mu" + combining diaeresis: NFD form of "Mü".
        std::fs::write(
            &p,
            "{\"id\":\"n\",\"lang\":\"de\",\"text\":\"Mu\\u0308ller\",\"spans\":[]}\n",
        )
        .unwrap();
        let e = read_jsonl(&p).unwrap_err();
        assert!(format!("{e}").contains("NFC"), "{e}");
    }

    #[test]
    fn digest_is_stable_and_order_sensitive() {
        let a = digest(&[doc(), doc()]);
        assert_eq!(a, digest(&[doc(), doc()]));
        assert_eq!(a.len(), 64);
        let mut d2 = doc();
        d2.id = "d2".into();
        assert_ne!(digest(&[doc(), d2.clone()]), digest(&[d2, doc()]));
    }

    #[test]
    fn sensitivity_defaults() {
        assert!(default_sensitive("PERSON"));
        assert!(default_sensitive("SECRET"));
        assert!(default_sensitive("LOCATION"), "unknown kinds are sensitive");
        assert!(!default_sensitive("CITY"));
        assert!(!default_sensitive("DATE"));
    }
}
