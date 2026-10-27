//! Detector trait and parallel fan-out.

use std::sync::Arc;

use rayon::prelude::*;

use crate::lang::{Language, detect_language};
use crate::span::{DetectorId, Span};
use crate::{Error, Result};

pub mod anchor;
pub mod dictionary;
pub mod domain;
pub mod path_names;
pub mod plausible;
pub mod regex;
pub mod secrets;
pub mod surname;
pub mod technical;
pub mod validate;

/// Per-request context shared by all detectors.
#[derive(Debug, Clone)]
pub struct DetectCtx {
    /// Language hint for the text.
    pub language: Language,
}

impl DetectCtx {
    /// Build a context by detecting the language of `text`.
    pub fn for_text(text: &str) -> Self {
        DetectCtx {
            language: detect_language(text),
        }
    }
}

/// A source of candidate spans.
pub trait Detector: Send + Sync {
    /// Identity, used for overlap priority.
    fn id(&self) -> DetectorId;
    /// Return candidate spans. Offsets must be char boundaries of `text`.
    ///
    /// An `Err` means the detector could not examine the text (for example a
    /// model backend failed). The engine treats that as a block, never as
    /// "nothing found". Errors must not carry input text.
    fn detect(&self, text: &str, ctx: &DetectCtx) -> Result<Vec<Span>>;
}

/// `Ok` when `span` lies inside `text` with both offsets on char boundaries
/// and `start <= end`; [`Error::InvalidUtf8Boundary`] otherwise.
pub fn validate_span(text: &str, span: &Span) -> Result<()> {
    if span.start <= span.end
        && span.end <= text.len()
        && text.is_char_boundary(span.start)
        && text.is_char_boundary(span.end)
    {
        Ok(())
    } else {
        Err(Error::InvalidUtf8Boundary)
    }
}

/// Run every detector in parallel and concatenate the results.
///
/// Fails when any detector fails, or when any returned span is not a valid
/// range of `text` (see [`validate_span`]).
pub fn run_all(detectors: &[Arc<dyn Detector>], text: &str, ctx: &DetectCtx) -> Result<Vec<Span>> {
    let per: Vec<Vec<Span>> = detectors
        .par_iter()
        .map(|d| d.detect(text, ctx))
        .collect::<Result<_>>()?;
    let spans: Vec<Span> = per.into_iter().flatten().collect();
    for s in &spans {
        validate_span(text, s)?;
    }
    Ok(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::{DetectorId, EntityKind, Span};
    use std::sync::Arc;

    struct Fixed(Vec<Span>);
    impl Detector for Fixed {
        fn id(&self) -> DetectorId {
            DetectorId::Ner
        }
        fn detect(&self, _: &str, _: &DetectCtx) -> crate::Result<Vec<Span>> {
            Ok(self.0.clone())
        }
    }

    struct Failing;
    impl Detector for Failing {
        fn id(&self) -> DetectorId {
            DetectorId::Ner
        }
        fn detect(&self, _: &str, _: &DetectCtx) -> crate::Result<Vec<Span>> {
            Err(crate::Error::ModelUnavailable("test backend".into()))
        }
    }

    #[test]
    fn run_all_propagates_a_detector_error() {
        let ds: Vec<Arc<dyn Detector>> = vec![Arc::new(Fixed(vec![])), Arc::new(Failing)];
        let err = run_all(&ds, "abc", &DetectCtx::for_text("abc")).unwrap_err();
        assert!(matches!(err, crate::Error::ModelUnavailable(_)));
    }

    #[test]
    fn run_all_rejects_spans_outside_text_or_off_char_boundaries() {
        for (text, start, end) in [("abc", 0, 10), ("abc", 4, 5), ("äb", 1, 3), ("äb", 0, 1)] {
            let ds: Vec<Arc<dyn Detector>> = vec![Arc::new(Fixed(vec![Span {
                start,
                end,
                kind: EntityKind::Person,
                confidence: 0.9,
                source: DetectorId::Ner,
                crossed_line_break: false,
            }]))];
            let err = run_all(&ds, text, &DetectCtx::for_text(text)).unwrap_err();
            assert!(
                matches!(err, crate::Error::InvalidUtf8Boundary),
                "{start}..{end}"
            );
        }
        // start > end is rejected too
        let ds: Vec<Arc<dyn Detector>> = vec![Arc::new(Fixed(vec![Span {
            start: 2,
            end: 1,
            kind: EntityKind::Person,
            confidence: 0.9,
            source: DetectorId::Ner,
            crossed_line_break: false,
        }]))];
        assert!(run_all(&ds, "abc", &DetectCtx::for_text("abc")).is_err());
    }

    #[test]
    fn run_all_concatenates_every_detector() {
        let a = Arc::new(Fixed(vec![Span::new(
            0,
            1,
            EntityKind::Person,
            0.9,
            DetectorId::Ner,
        )]));
        let b = Arc::new(Fixed(vec![Span::new(
            2,
            3,
            EntityKind::City,
            0.9,
            DetectorId::Ner,
        )]));
        let ds: Vec<Arc<dyn Detector>> = vec![a, b];
        let out = run_all(&ds, "abc", &DetectCtx::for_text("abc")).unwrap();
        assert_eq!(out.len(), 2);
    }
}
