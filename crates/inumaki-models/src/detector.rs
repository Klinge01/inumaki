//! Adapter from a [`NerBackend`] to the core [`Detector`] trait.

use std::collections::HashMap;
use std::sync::Arc;

use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::span::{DetectorId, EntityKind, Span};

use crate::backend::{ModelError, NerBackend, RawEntity};
use crate::chunk::chunks;

/// One model label, the entity kind it maps to, and its minimum score.
#[derive(Debug, Clone, PartialEq)]
pub struct NerLabelSpec {
    /// Label text given to the model (GLiNER) or model type name (`PER`, `LOC`…).
    pub label: String,
    /// Entity kind emitted for this label.
    pub kind: EntityKind,
    /// Minimum score for this label.
    pub threshold: f32,
}

/// Runs a [`NerBackend`] over chunks of the text and emits core spans.
pub struct NerDetector {
    backend: Arc<dyn NerBackend>,
    labels: Vec<NerLabelSpec>,
    max_chunk_bytes: usize,
    overlap_bytes: usize,
}

impl std::fmt::Debug for NerDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NerDetector")
            .field("backend", &self.backend.id())
            .field("labels", &self.labels.len())
            .finish()
    }
}

const MIN_SPLIT_BYTES: usize = 64;
const MAX_SPLIT_DEPTH: u32 = 8;

impl NerDetector {
    /// Detector with chunks of `3 × max_input_tokens` bytes and 200 bytes of overlap.
    ///
    /// A factor of 4 (roughly one sub-word token per byte for English) routinely
    /// undercounts German and other non-English text, where compounds and
    /// diacritics push the sub-word count per byte higher; a chunk sized at that
    /// factor could tokenize past `max_input_tokens` and hit the `InputTooLong`
    /// split path (`predict_into`) on ordinary input. 3 leaves enough headroom
    /// that the reference long email thread (`tests/gliner.rs`) needs no split.
    pub fn new(backend: Arc<dyn NerBackend>, labels: Vec<NerLabelSpec>) -> Self {
        let max_chunk_bytes = backend.max_input_tokens().saturating_mul(3).max(256);
        NerDetector {
            backend,
            labels,
            max_chunk_bytes,
            overlap_bytes: 200,
        }
    }

    /// Override chunk size and overlap (bytes).
    #[must_use]
    pub fn with_chunking(mut self, max_chunk_bytes: usize, overlap_bytes: usize) -> Self {
        self.max_chunk_bytes = max_chunk_bytes;
        self.overlap_bytes = overlap_bytes;
        self
    }

    /// The chunk size (bytes) this detector splits text into, as configured by
    /// [`NerDetector::new`] or [`NerDetector::with_chunking`]. Exposed for tests
    /// that want to check a chunk fits the backend without triggering the
    /// `InputTooLong` split path.
    pub fn chunk_bytes(&self) -> usize {
        self.max_chunk_bytes
    }

    fn unavailable(&self) -> inumaki_core::Error {
        inumaki_core::Error::ModelUnavailable(self.backend.id().to_string())
    }

    fn predict_into(
        &self,
        text: &str,
        offset: usize,
        names: &[String],
        thresholds: &[f32],
        depth: u32,
        out: &mut Vec<RawEntity>,
    ) -> inumaki_core::Result<()> {
        match self.backend.predict(text, names, thresholds) {
            Ok(found) => {
                out.extend(found.into_iter().map(|mut e| {
                    e.start += offset;
                    e.end += offset;
                    e
                }));
                Ok(())
            }
            Err(ModelError::InputTooLong)
                if text.len() > MIN_SPLIT_BYTES && depth < MAX_SPLIT_DEPTH =>
            {
                let half = text.len() / 2 + 1;
                for c in chunks(text, half, (self.overlap_bytes).min(half / 2)) {
                    self.predict_into(
                        c.text,
                        offset + c.offset,
                        names,
                        thresholds,
                        depth + 1,
                        out,
                    )?;
                }
                Ok(())
            }
            Err(_) => Err(self.unavailable()),
        }
    }
}

impl Detector for NerDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Ner
    }

    fn detect(&self, text: &str, _ctx: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        if self.labels.is_empty() || text.trim().is_empty() {
            return Ok(Vec::new());
        }
        let names: Vec<String> = self.labels.iter().map(|l| l.label.clone()).collect();
        let thresholds: Vec<f32> = self.labels.iter().map(|l| l.threshold).collect();
        let mut raw = Vec::new();
        for c in chunks(text, self.max_chunk_bytes, self.overlap_bytes) {
            self.predict_into(c.text, c.offset, &names, &thresholds, 0, &mut raw)?;
        }
        let by_label: HashMap<&str, &NerLabelSpec> =
            self.labels.iter().map(|l| (l.label.as_str(), l)).collect();
        let mut best: HashMap<(usize, usize, String), Span> = HashMap::new();
        for e in raw {
            let Some(spec) = by_label.get(e.label.as_str()) else {
                continue;
            };
            if e.score < spec.threshold || e.start >= e.end {
                continue;
            }
            let key = (e.start, e.end, spec.kind.label().to_string());
            let span = Span::new(e.start, e.end, spec.kind.clone(), e.score, DetectorId::Ner);
            match best.get(&key) {
                Some(prev) if prev.confidence >= span.confidence => {}
                _ => {
                    best.insert(key, span);
                }
            }
        }
        // `best` is a `HashMap`, whose default `RandomState` hasher gives
        // `into_values()` a different iteration order on every construction
        // (not just every process run). The output order must not depend on
        // that: sort on a total order over every field two spans could
        // otherwise tie on (position, then kind label, then confidence) so
        // the result is the same regardless of the input order this run
        // happened to produce.
        let mut spans: Vec<Span> = best.into_values().collect();
        // The `.then(...)` confidence tie-break below never actually triggers: `best`'s key
        // is `(start, end, kind.label())`, the same triple this sort orders by first, so no
        // two spans in `best.into_values()` can tie on it. Kept as a documented, harmless
        // total order rather than relying on an implicit assumption about `best`'s keys.
        spans.sort_by(|a, b| {
            (a.start, a.end, a.kind.label())
                .cmp(&(b.start, b.end, b.kind.label()))
                .then(b.confidence.total_cmp(&a.confidence))
        });
        Ok(spans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use inumaki_core::detect::{DetectCtx, Detector, run_all};

    /// Finds fixed strings; rejects inputs longer than `limit` bytes.
    struct Mock {
        names: Vec<(&'static str, &'static str, f32)>,
        limit: usize,
        calls: AtomicUsize,
        fail: bool,
        bad_offsets: bool,
    }

    impl Mock {
        fn new(limit: usize) -> Self {
            Mock {
                names: vec![
                    ("Sarah Leitner", "person", 0.9),
                    ("Neubaugasse 22", "street address", 0.7),
                    ("Wien", "city", 0.35),
                ],
                limit,
                calls: AtomicUsize::new(0),
                fail: false,
                bad_offsets: false,
            }
        }
    }

    impl NerBackend for Mock {
        fn id(&self) -> &str {
            "mock"
        }
        fn supports_dynamic_labels(&self) -> bool {
            true
        }
        fn predict(
            &self,
            text: &str,
            labels: &[String],
            thresholds: &[f32],
        ) -> Result<Vec<RawEntity>, ModelError> {
            assert_eq!(labels.len(), thresholds.len(), "caller must pair them");
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(ModelError::Inference);
            }
            if text.len() > self.limit {
                return Err(ModelError::InputTooLong);
            }
            let mut out = Vec::new();
            for (needle, label, score) in &self.names {
                let Some(idx) = labels.iter().position(|l| l == label) else {
                    continue;
                };
                if *score < thresholds[idx] {
                    continue;
                }
                for (i, _) in text.match_indices(needle) {
                    let (start, end) = if self.bad_offsets {
                        (i + 1, i + needle.len())
                    } else {
                        (i, i + needle.len())
                    };
                    out.push(RawEntity {
                        start,
                        end,
                        label: (*label).to_string(),
                        score: *score,
                    });
                }
            }
            Ok(out)
        }
        fn max_input_tokens(&self) -> usize {
            self.limit / 4
        }
    }

    fn labels() -> Vec<NerLabelSpec> {
        vec![
            NerLabelSpec {
                label: "person".into(),
                kind: EntityKind::Person,
                threshold: 0.5,
            },
            NerLabelSpec {
                label: "street address".into(),
                kind: EntityKind::StreetAddress,
                threshold: 0.5,
            },
            NerLabelSpec {
                label: "city".into(),
                kind: EntityKind::City,
                threshold: 0.5,
            },
        ]
    }

    fn found(d: &NerDetector, text: &str) -> Vec<(EntityKind, String)> {
        let mut v: Vec<_> = d
            .detect(text, &DetectCtx::for_text(text))
            .unwrap()
            .into_iter()
            .map(|s| (s.kind.clone(), s.slice(text).to_string()))
            .collect();
        v.sort_by(|a, b| a.1.cmp(&b.1));
        v
    }

    #[test]
    fn maps_labels_to_kinds_and_applies_per_label_thresholds() {
        // Genuinely different thresholds per label (Task 3 deferred minor,
        // closed together with I2): city's bar (0.3) is lower than person's
        // (0.5) and street address's (0.6), so Wien (mock score 0.35) is
        // kept only because its own label's threshold is low, not because
        // every label shares one threshold.
        let per_label = vec![
            NerLabelSpec {
                label: "person".into(),
                kind: EntityKind::Person,
                threshold: 0.5,
            },
            NerLabelSpec {
                label: "street address".into(),
                kind: EntityKind::StreetAddress,
                threshold: 0.6,
            },
            NerLabelSpec {
                label: "city".into(),
                kind: EntityKind::City,
                threshold: 0.3,
            },
        ];
        let d = NerDetector::new(Arc::new(Mock::new(10_000)), per_label);
        let v = found(&d, "Sarah Leitner wohnt in der Neubaugasse 22 in Wien.");
        assert_eq!(
            v,
            vec![
                (EntityKind::StreetAddress, "Neubaugasse 22".to_string()),
                (EntityKind::Person, "Sarah Leitner".to_string()),
                (EntityKind::City, "Wien".to_string()),
            ],
            "Wien scores 0.35, above city's own 0.3 threshold though below the others'"
        );
        let spans = d.detect("Sarah Leitner", &DetectCtx::for_text("")).unwrap();
        assert_eq!(spans[0].source, DetectorId::Ner);
    }

    /// I2: a candidate that would later be dropped for its own label's
    /// threshold must not be allowed to win an overlap against a different
    /// label's candidate that clears its own threshold. Reproduces the
    /// final review's scenario: organization scores 0.55 against its own
    /// 0.6 threshold (fails), person scores 0.52 against its own 0.5
    /// threshold (passes), both over the same span.
    #[test]
    fn per_label_threshold_is_applied_before_overlap_resolution() {
        struct OverlapMock;
        impl NerBackend for OverlapMock {
            fn id(&self) -> &str {
                "overlap-mock"
            }
            fn supports_dynamic_labels(&self) -> bool {
                true
            }
            fn predict(
                &self,
                text: &str,
                labels: &[String],
                thresholds: &[f32],
            ) -> Result<Vec<RawEntity>, ModelError> {
                assert_eq!(labels.len(), thresholds.len());
                let start = text.find("Leitner").expect("fixture contains Leitner");
                let end = start + "Leitner".len();
                let raw = [("organization", 0.55f32), ("person", 0.52f32)];
                // Filter by each label's own threshold first, as a correct
                // backend must (§7, amended for I2), then greedily keep the
                // highest-scoring survivor over the shared span.
                let mut survivors: Vec<(usize, f32)> = raw
                    .iter()
                    .filter_map(|(label, score)| {
                        let idx = labels.iter().position(|l| l == label)?;
                        (*score >= thresholds[idx]).then_some((idx, *score))
                    })
                    .collect();
                survivors.sort_by(|a, b| b.1.total_cmp(&a.1));
                Ok(survivors
                    .into_iter()
                    .take(1)
                    .map(|(idx, score)| RawEntity {
                        start,
                        end,
                        label: labels[idx].clone(),
                        score,
                    })
                    .collect())
            }
            fn max_input_tokens(&self) -> usize {
                1_000
            }
        }

        let labels = vec![
            NerLabelSpec {
                label: "organization".into(),
                kind: EntityKind::Organization,
                threshold: 0.6,
            },
            NerLabelSpec {
                label: "person".into(),
                kind: EntityKind::Person,
                threshold: 0.5,
            },
        ];
        let d = NerDetector::new(Arc::new(OverlapMock), labels);
        let text = "Leitner rief an.";
        let spans = d.detect(text, &DetectCtx::for_text(text)).unwrap();
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(spans[0].kind, EntityKind::Person, "{spans:?}");
    }

    /// Fix round 1 finding: two candidates at the exact same position that
    /// tie on every field `rank`-equivalent criteria could use (here: same
    /// span, same confidence, different kind) must still come out in a
    /// fixed order, not whatever order the internal `HashMap` happened to
    /// hand them back this run.
    #[test]
    fn ties_at_the_same_position_break_deterministically_by_kind_label() {
        let mut m = Mock::new(10_000);
        m.names = vec![("Ana", "person", 0.9), ("Ana", "city", 0.9)];
        let d = NerDetector::new(Arc::new(m), labels());
        let spans = d.detect("Ana ist da.", &DetectCtx::for_text("")).unwrap();
        assert_eq!(spans.len(), 2, "{spans:?}");
        assert_eq!(spans[0].start, spans[1].start);
        assert_eq!(spans[0].end, spans[1].end);
        // "CITY" < "PERSON" lexically; this must hold on every run.
        assert_eq!(
            spans.iter().map(|s| s.kind.label()).collect::<Vec<_>>(),
            vec!["CITY", "PERSON"]
        );
    }

    #[test]
    fn long_text_is_chunked_and_offsets_are_global() {
        let filler = "Das ist ein ganz normaler Satz ohne Namen. ".repeat(30);
        let text = format!("{filler}Sarah Leitner kam. {filler}Neubaugasse 22 ist neu. {filler}");
        let d = NerDetector::new(Arc::new(Mock::new(300)), labels()).with_chunking(250, 60);
        let spans = d.detect(&text, &DetectCtx::for_text("")).unwrap();
        let texts: Vec<&str> = spans.iter().map(|s| s.slice(&text)).collect();
        assert_eq!(
            texts.iter().filter(|t| **t == "Sarah Leitner").count(),
            1,
            "{texts:?}"
        );
        assert_eq!(
            texts.iter().filter(|t| **t == "Neubaugasse 22").count(),
            1,
            "{texts:?}"
        );
    }

    #[test]
    fn entity_across_chunk_boundary_found_once() {
        // Place the name so a 100-byte chunk would cut through it.
        let text = format!(
            "{}Sarah Leitner rief an. {}",
            "a ".repeat(46),
            "b ".repeat(80)
        );
        let d = NerDetector::new(Arc::new(Mock::new(10_000)), labels()).with_chunking(100, 40);
        let spans = d.detect(&text, &DetectCtx::for_text("")).unwrap();
        let persons: Vec<&Span> = spans
            .iter()
            .filter(|s| s.kind == EntityKind::Person)
            .collect();
        assert_eq!(persons.len(), 1, "{spans:?}");
        assert_eq!(persons[0].slice(&text), "Sarah Leitner");
    }

    #[test]
    fn input_too_long_is_split_until_it_fits() {
        let text = format!("{} Sarah Leitner. {}", "c ".repeat(200), "d ".repeat(200));
        // Chunking allows 600 bytes but the backend only takes 120.
        let d = NerDetector::new(Arc::new(Mock::new(120)), labels()).with_chunking(600, 50);
        let v = found(&d, &text);
        assert!(
            v.contains(&(EntityKind::Person, "Sarah Leitner".into())),
            "{v:?}"
        );
    }

    #[test]
    fn backend_failure_is_an_error_not_an_empty_result() {
        let mut m = Mock::new(10_000);
        m.fail = true;
        let d = NerDetector::new(Arc::new(m), labels());
        let err = d
            .detect("Sarah Leitner", &DetectCtx::for_text(""))
            .unwrap_err();
        assert!(matches!(err, inumaki_core::Error::ModelUnavailable(ref id) if id == "mock"));
        assert!(!format!("{err}").contains("Sarah"));
    }

    #[test]
    fn bad_backend_offsets_block() {
        // The mock finds "üller" at byte 1 of "Müller" and, with bad_offsets,
        // returns start 2, which is inside 'ü' (bytes 1..3).
        let mut m = Mock::new(10_000);
        m.names = vec![("üller", "person", 0.9)];
        m.bad_offsets = true;
        let d: Arc<dyn Detector> = Arc::new(NerDetector::new(Arc::new(m), labels()));
        let text = "Müller";
        let r = run_all(&[d], text, &DetectCtx::for_text(text));
        assert!(
            matches!(r, Err(inumaki_core::Error::InvalidUtf8Boundary)),
            "{r:?}"
        );
    }

    #[test]
    fn ner_detector_is_usable_from_many_threads() {
        let d = Arc::new(NerDetector::new(Arc::new(Mock::new(10_000)), labels()));
        let text = "Sarah Leitner wohnt in der Neubaugasse 22.";
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let d = Arc::clone(&d);
                std::thread::spawn(move || {
                    d.detect(text, &DetectCtx::for_text(text)).unwrap().len()
                })
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), 2);
        }
    }

    #[test]
    fn empty_labels_or_blank_text_do_not_call_the_backend() {
        let m = Arc::new(Mock::new(10_000));
        let d = NerDetector::new(m.clone(), vec![]);
        assert!(
            d.detect("Sarah Leitner", &DetectCtx::for_text(""))
                .unwrap()
                .is_empty()
        );
        let d = NerDetector::new(m.clone(), labels());
        assert!(
            d.detect("   \n ", &DetectCtx::for_text(""))
                .unwrap()
                .is_empty()
        );
        assert_eq!(m.calls.load(Ordering::SeqCst), 0);
    }
}
