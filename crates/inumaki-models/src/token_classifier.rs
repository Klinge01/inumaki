//! BERT-style token-classification backend (fixed BIO label set) on ONNX Runtime.

use std::borrow::Cow;
use std::path::Path;

use ndarray::Array2;
use ort::session::{Session, SessionInputValue};
use ort::value::Tensor;
use tokenizers::{PostProcessor, Tokenizer};

use crate::backend::{ModelError, NerBackend, RawEntity, build_sessions, load_tokenizer};
use crate::pool::SessionPool;

/// A model input this backend knows how to fill.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Feed {
    InputIds,
    AttentionMask,
    TokenTypeIds,
}

/// Which output tensor holds the token logits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputSelect {
    /// By name.
    Named(&'static str),
}

/// Two adjacent entities (only whitespace between them) become one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeRule {
    /// Label of the entity ending the gap.
    pub left: &'static str,
    /// Label of the entity starting after the gap.
    pub right: &'static str,
    /// Label of the merged entity.
    pub merged: &'static str,
}

/// Kiji's split labels merged into the shapes inumaki maps to kinds.
pub const KIJI_MERGES: &[MergeRule] = &[
    MergeRule {
        left: "FIRSTNAME",
        right: "SURNAME",
        merged: "NAME",
    },
    MergeRule {
        left: "SURNAME",
        right: "FIRSTNAME",
        merged: "NAME",
    },
    MergeRule {
        left: "NAME",
        right: "SURNAME",
        merged: "NAME",
    },
    MergeRule {
        left: "FIRSTNAME",
        right: "NAME",
        merged: "NAME",
    },
    MergeRule {
        left: "STREET",
        right: "BUILDINGNUM",
        merged: "ADDRESS",
    },
];

/// `pii.id2label` of a Kiji `label_mappings.json`, dense and in id order,
/// ignoring the `-100` sentinel; positions are DistilBERT's 512.
pub fn read_kiji_mappings(path: &Path) -> Result<(Vec<String>, usize), ModelError> {
    let load_err = |reason: &str| ModelError::Load(format!("{}: {reason}", path.display()));
    let raw = std::fs::read_to_string(path).map_err(|e| load_err(&e.to_string()))?;
    let json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| load_err(&e.to_string()))?;
    let map = json
        .pointer("/pii/id2label")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| load_err("missing pii.id2label"))?;
    let mut pairs: Vec<(usize, String)> = Vec::new();
    for (k, v) in map {
        let Ok(idx) = k.parse::<usize>() else {
            if k.starts_with('-') {
                continue; // `-100: IGNORE`
            }
            return Err(load_err("non-numeric id2label key"));
        };
        pairs.push((
            idx,
            v.as_str()
                .ok_or_else(|| load_err("non-string label"))?
                .to_owned(),
        ));
    }
    pairs.sort_by_key(|(i, _)| *i);
    if pairs.is_empty() || pairs.iter().enumerate().any(|(n, (i, _))| n != *i) {
        return Err(load_err("sparse pii.id2label"));
    }
    Ok((pairs.into_iter().map(|(_, l)| l).collect(), 512))
}

/// Apply `rules` left to right over entities sorted by start; the merged
/// entity spans both and scores the minimum of the two.
pub(crate) fn merge_adjacent(
    text: &str,
    mut ents: Vec<RawEntity>,
    rules: &[MergeRule],
) -> Vec<RawEntity> {
    ents.sort_by_key(|e| e.start);
    let mut out: Vec<RawEntity> = Vec::with_capacity(ents.len());
    for e in ents {
        if let Some(prev) = out.last_mut() {
            let gap = &text[prev.end.min(e.start)..e.start.max(prev.end)];
            let adjacent =
                prev.end <= e.start && !gap.is_empty() && gap.chars().all(char::is_whitespace);
            if adjacent {
                if let Some(rule) = rules
                    .iter()
                    .find(|r| r.left == prev.label && r.right == e.label)
                {
                    prev.end = e.end;
                    prev.label = rule.merged.to_owned();
                    prev.score = prev.score.min(e.score);
                    continue;
                }
            }
        }
        out.push(e);
    }
    out
}

/// Token classifier such as `bert-base-multilingual-cased-ner-hrl` exported to ONNX.
///
/// Labels are the model's entity type names (`PER`, `ORG`, `LOC`, `DATE`, ...), taken from
/// `id2label` with the `B-`/`I-` prefix removed.
pub struct TokenClassifierBackend {
    id: String,
    session: SessionPool<Session>,
    tokenizer: Tokenizer,
    /// `id2label` in class-index order, e.g. `["O", "B-DATE", "I-DATE", ...]`.
    tags: Vec<String>,
    /// Declared model inputs, in declaration order.
    inputs: Vec<Feed>,
    /// `max_position_embeddings` (special tokens included).
    max_positions: usize,
    /// Special tokens the tokenizer adds to a single sequence (`[CLS]`, `[SEP]`).
    num_special: usize,
    /// Which output tensor holds the logits.
    output: OutputSelect,
    /// Adjacent-entity merge rules applied before label filtering.
    merges: &'static [MergeRule],
}

impl TokenClassifierBackend {
    /// Loads the ONNX model, `tokenizer.json` and the Hugging Face `config.json`
    /// (`id2label`, `max_position_embeddings`).
    ///
    /// `threads == 0` selects [`crate::backend::default_threads`].
    pub fn load(
        model_path: &Path,
        tokenizer_path: &Path,
        config_path: &Path,
        threads: usize,
        sessions: usize,
    ) -> Result<Self, ModelError> {
        let (tags, max_positions) = read_config(config_path)?;
        Self::load_with_tags(
            model_path,
            tokenizer_path,
            tags,
            max_positions,
            threads,
            sessions,
        )
    }

    /// Loads the Kiji PII model: DistilBERT token classifier with the label
    /// list in `label_mappings.json` and the logits in `pii_logits`.
    pub fn load_kiji(
        model_path: &Path,
        tokenizer_path: &Path,
        mappings_path: &Path,
        threads: usize,
        sessions: usize,
    ) -> Result<Self, ModelError> {
        let (tags, max_positions) = read_kiji_mappings(mappings_path)?;
        let mut b = Self::load_with_tags(
            model_path,
            tokenizer_path,
            tags,
            max_positions,
            threads,
            sessions,
        )?;
        b.id = "kiji".to_owned();
        b.output = OutputSelect::Named("pii_logits");
        b.merges = KIJI_MERGES;
        Ok(b)
    }

    /// Shared load body once the label list and position limit are known
    /// (from either `config.json`'s `id2label` or Kiji's `label_mappings.json`).
    fn load_with_tags(
        model_path: &Path,
        tokenizer_path: &Path,
        tags: Vec<String>,
        max_positions: usize,
        threads: usize,
        sessions: usize,
    ) -> Result<Self, ModelError> {
        let tokenizer = load_tokenizer(tokenizer_path)?;
        let num_special = tokenizer
            .get_post_processor()
            .map_or(0, |p| p.added_tokens(false));
        let sessions = build_sessions(model_path, threads, sessions)?;
        let inputs = sessions[0]
            .inputs()
            .iter()
            .map(|i| match i.name() {
                "input_ids" => Ok(Feed::InputIds),
                "attention_mask" => Ok(Feed::AttentionMask),
                "token_type_ids" => Ok(Feed::TokenTypeIds),
                other => Err(ModelError::Load(format!(
                    "{}: unsupported input {other}",
                    model_path.display()
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            id: "token-classifier".to_owned(),
            session: SessionPool::new(sessions),
            tokenizer,
            tags,
            inputs,
            max_positions,
            num_special,
            output: OutputSelect::Named("logits"),
            merges: &[],
        })
    }

    /// Replaces the backend identifier returned by [`NerBackend::id`].
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Runs the model and returns, per token, the arg-max class and its softmax probability.
    fn run(&self, encoding: &tokenizers::Encoding) -> Result<Vec<(usize, f32)>, ModelError> {
        let n = encoding.len();
        let to_array = |values: &[u32]| {
            Array2::from_shape_vec((1, n), values.iter().map(|&v| i64::from(v)).collect())
                .map_err(|_| ModelError::Inference)
                .and_then(|a| Tensor::from_array(a).map_err(|_| ModelError::Inference))
        };
        let mut feed: Vec<(Cow<'_, str>, SessionInputValue<'_>)> =
            Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            let (name, values) = match input {
                Feed::InputIds => ("input_ids", encoding.get_ids()),
                Feed::AttentionMask => ("attention_mask", encoding.get_attention_mask()),
                Feed::TokenTypeIds => ("token_type_ids", encoding.get_type_ids()),
            };
            feed.push((Cow::Borrowed(name), to_array(values)?.into()));
        }
        let mut session = self.session.acquire();
        let outputs = session.run(feed).map_err(|_| ModelError::Inference)?;
        // Prefer the named output; fall back to whatever the model actually exported
        // (Kiji's export names have not been confirmed against the README).
        let OutputSelect::Named(name) = self.output;
        let logits_value = outputs
            .get(name)
            .or_else(|| outputs.keys().next().and_then(|k| outputs.get(k)))
            .ok_or(ModelError::Inference)?;
        let (shape, logits) = logits_value
            .try_extract_tensor::<f32>()
            .map_err(|_| ModelError::Inference)?;
        let num_tags = self.tags.len();
        if shape.len() != 3
            || shape[0] != 1
            || usize::try_from(shape[1]) != Ok(n)
            || usize::try_from(shape[2]) != Ok(num_tags)
        {
            return Err(ModelError::Inference);
        }
        Ok(logits.chunks_exact(num_tags).map(softmax_argmax).collect())
    }
}

impl NerBackend for TokenClassifierBackend {
    fn id(&self) -> &str {
        &self.id
    }

    fn supports_dynamic_labels(&self) -> bool {
        false
    }

    fn predict(
        &self,
        text: &str,
        labels: &[String],
        thresholds: &[f32],
    ) -> Result<Vec<RawEntity>, ModelError> {
        if thresholds.len() != labels.len() {
            return Err(ModelError::Inference);
        }
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|_| ModelError::Inference)?;
        if encoding.len() > self.max_positions {
            return Err(ModelError::InputTooLong);
        }
        if encoding.get_word_ids().iter().all(Option::is_none) {
            return Ok(Vec::new());
        }
        // Empty `labels` means "unfiltered": every entity passes, regardless of score.
        // Otherwise an entity's own label must be requested and must clear that label's
        // own threshold, not the threshold of some other requested label.
        let preds = self.run(&encoding)?;
        let entities = decode_bio(
            &self.tags,
            &preds,
            encoding.get_word_ids(),
            encoding.get_offsets(),
        );
        Ok(merge_adjacent(text, entities, self.merges)
            .into_iter()
            .filter(|e| {
                labels.is_empty()
                    || labels
                        .iter()
                        .zip(thresholds)
                        .any(|(l, &t)| *l == e.label && e.score >= t)
            })
            .collect())
    }

    fn max_input_tokens(&self) -> usize {
        self.max_positions.saturating_sub(self.num_special)
    }

    fn pool_waits(&self) -> u64 {
        self.session.waits()
    }
}

/// Reads `id2label` (as a dense, index-ordered list) and `max_position_embeddings` (default 512).
fn read_config(path: &Path) -> Result<(Vec<String>, usize), ModelError> {
    let load_err = |reason: &str| ModelError::Load(format!("{}: {reason}", path.display()));
    let raw = std::fs::read_to_string(path).map_err(|e| load_err(&e.to_string()))?;
    let json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| load_err(&e.to_string()))?;
    let map = json
        .get("id2label")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| load_err("missing id2label"))?;
    if map.is_empty() {
        return Err(load_err("empty id2label"));
    }
    let mut tags = vec![None; map.len()];
    for (key, value) in map {
        let idx: usize = key
            .parse()
            .map_err(|_| load_err("non-numeric id2label key"))?;
        let slot = tags
            .get_mut(idx)
            .ok_or_else(|| load_err("sparse id2label"))?;
        *slot = Some(
            value
                .as_str()
                .ok_or_else(|| load_err("non-string label"))?
                .to_owned(),
        );
    }
    let tags = tags
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| load_err("duplicate id2label key"))?;
    let max_positions = json
        .get("max_position_embeddings")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(512);
    Ok((tags, max_positions))
}

/// Index and probability of the most likely class for one token's logits.
fn softmax_argmax(logits: &[f32]) -> (usize, f32) {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let sum: f32 = logits.iter().map(|&l| (l - max).exp()).sum();
    let (idx, &best) = logits
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.total_cmp(b.1))
        .unwrap_or((0, &max));
    (idx, (best - max).exp() / sum)
}

/// Splits a BIO tag into `(is_begin, type)`; `None` for `O`. Un-prefixed tags count as `I-`.
fn parse_tag(tag: &str) -> Option<(bool, &str)> {
    match tag {
        "O" => None,
        t => Some(match (t.strip_prefix("B-"), t.strip_prefix("I-")) {
            (Some(ty), _) => (true, ty),
            (_, Some(ty)) => (false, ty),
            _ => (false, t),
        }),
    }
}

/// Entity being assembled from consecutive words.
struct Open<'a> {
    ty: &'a str,
    start: usize,
    end: usize,
    score_sum: f32,
    tokens: usize,
}

impl Open<'_> {
    fn finish(self) -> RawEntity {
        #[allow(clippy::cast_precision_loss)] // token counts are < 2^24
        let score = self.score_sum / self.tokens as f32;
        RawEntity {
            start: self.start,
            end: self.end,
            label: self.ty.to_owned(),
            score,
        }
    }
}

/// Decodes per-token `(class, probability)` predictions into entities.
///
/// Sub-word pieces (`##` continuations) are merged into their word via `word_ids`; a word
/// takes the tag of its first piece. `B-X` starts an entity, `I-X` extends an open `X`
/// entity (or starts one), `O` closes it. The score is the mean max-probability over all
/// tokens of the entity. Offsets are byte offsets from the tokenizer.
fn decode_bio(
    tags: &[String],
    preds: &[(usize, f32)],
    word_ids: &[Option<u32>],
    offsets: &[(usize, usize)],
) -> Vec<RawEntity> {
    let mut entities = Vec::new();
    let mut open: Option<Open<'_>> = None;
    let mut prev_word: Option<u32> = None;
    for ((&(class, prob), &word), &(start, end)) in preds.iter().zip(word_ids).zip(offsets) {
        let Some(word) = word else {
            prev_word = None;
            continue;
        };
        if prev_word == Some(word) {
            // Continuation piece: extend the current word (and entity, if any).
            if let Some(e) = open.as_mut() {
                e.end = end;
                e.score_sum += prob;
                e.tokens += 1;
            }
            continue;
        }
        prev_word = Some(word);
        match parse_tag(tags.get(class).map_or("O", String::as_str)) {
            None => entities.extend(open.take().map(Open::finish)),
            Some((begin, ty)) => match open.as_mut() {
                Some(e) if !begin && e.ty == ty => {
                    e.end = end;
                    e.score_sum += prob;
                    e.tokens += 1;
                }
                _ => {
                    entities.extend(open.take().map(Open::finish));
                    open = Some(Open {
                        ty,
                        start,
                        end,
                        score_sum: prob,
                        tokens: 1,
                    });
                }
            },
        }
    }
    entities.extend(open.map(Open::finish));
    entities
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags() -> Vec<String> {
        ["O", "B-PER", "I-PER", "B-LOC", "I-LOC"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    /// Logits that make `class` the arg-max with a clear margin.
    fn logits_for(class: usize) -> Vec<f32> {
        (0..5).map(|c| if c == class { 4.0 } else { 0.0 }).collect()
    }

    #[test]
    fn softmax_argmax_picks_max() {
        let (idx, p) = softmax_argmax(&[0.0, 2.0, 0.0]);
        assert_eq!(idx, 1);
        let expected = 2f32.exp() / (2f32.exp() + 2.0);
        assert!((p - expected).abs() < 1e-6);
    }

    #[test]
    fn merges_subwords_and_bio_runs() {
        // "[CLS] Jür ##gen Müller aus Köln [SEP]" on "Jürgen Müller aus Köln"
        let classes = [0, 1, 0, 2, 0, 3, 0];
        let preds: Vec<(usize, f32)> = classes
            .iter()
            .map(|&c| softmax_argmax(&logits_for(c)))
            .enumerate()
            .map(|(i, (c, p))| (c, if i == 2 { 0.5 } else { p }))
            .collect();
        let word_ids = [None, Some(0), Some(0), Some(1), Some(2), Some(3), None];
        let offsets = [(0, 0), (0, 4), (4, 7), (8, 15), (16, 19), (20, 25), (0, 0)];
        let e = decode_bio(&tags(), &preds, &word_ids, &offsets);
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].start, e[0].end, e[0].label.as_str()), (0, 15, "PER"));
        // Continuation "##gen" (tagged O) still belongs to the word and counts in the mean.
        let p = preds[1].1;
        assert!((e[0].score - (p + 0.5 + p) / 3.0).abs() < 1e-6);
        assert_eq!((e[1].start, e[1].end, e[1].label.as_str()), (20, 25, "LOC"));
    }

    #[test]
    fn begin_splits_and_type_change_splits() {
        // B-PER B-PER I-LOC I-LOC O I-PER
        let preds: Vec<(usize, f32)> = [1, 1, 4, 4, 0, 2].iter().map(|&c| (c, 0.9)).collect();
        let word_ids: Vec<Option<u32>> = (0..6).map(Some).collect();
        let offsets: Vec<(usize, usize)> = (0..6).map(|i| (i * 2, i * 2 + 1)).collect();
        let e = decode_bio(&tags(), &preds, &word_ids, &offsets);
        let spans: Vec<(usize, usize, &str)> = e
            .iter()
            .map(|e| (e.start, e.end, e.label.as_str()))
            .collect();
        assert_eq!(
            spans,
            [(0, 1, "PER"), (2, 3, "PER"), (4, 7, "LOC"), (10, 11, "PER")]
        );
    }

    #[test]
    fn read_config_rejects_empty_id2label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"id2label": {}}"#).unwrap();
        let err = read_config(&path).unwrap_err();
        let ModelError::Load(msg) = err else {
            panic!("expected Load, got {err:?}");
        };
        assert!(msg.contains("empty id2label"), "{msg}");
    }

    #[test]
    fn parses_tags() {
        assert_eq!(parse_tag("O"), None);
        assert_eq!(parse_tag("B-ORG"), Some((true, "ORG")));
        assert_eq!(parse_tag("I-ORG"), Some((false, "ORG")));
        assert_eq!(parse_tag("MISC"), Some((false, "MISC")));
    }

    /// Review Focus 8: the Kiji label file parses despite `-100: IGNORE`, and
    /// FIRSTNAME + SURNAME separated by one space merge into NAME while two
    /// persons separated by a comma stay two.
    #[test]
    fn kiji_label_mappings_parse_and_names_merge() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("label_mappings.json");
        std::fs::write(&path, r#"{"pii":{"label2id":{"O":0},"id2label":{"0":"O","1":"B-SURNAME","2":"I-SURNAME","3":"B-FIRSTNAME","4":"I-FIRSTNAME","5":"B-STREET","6":"B-BUILDINGNUM","-100":"IGNORE"}},"coref":{"id2label":{"0":"NO_COREF"}}}"#).unwrap();
        let (tags, max) = read_kiji_mappings(&path).unwrap();
        assert_eq!(
            tags,
            [
                "O",
                "B-SURNAME",
                "I-SURNAME",
                "B-FIRSTNAME",
                "I-FIRSTNAME",
                "B-STREET",
                "B-BUILDINGNUM"
            ]
        );
        assert_eq!(max, 512);
        // "Sarah Leitner, Max Gruber" → FIRSTNAME SURNAME , FIRSTNAME SURNAME
        let text = "Sarah Leitner, Max Gruber wohnt Neubaugasse 22";
        let ents = vec![
            RawEntity {
                start: 0,
                end: 5,
                label: "FIRSTNAME".into(),
                score: 0.9,
            },
            RawEntity {
                start: 6,
                end: 13,
                label: "SURNAME".into(),
                score: 0.8,
            },
            RawEntity {
                start: 15,
                end: 18,
                label: "FIRSTNAME".into(),
                score: 0.9,
            },
            RawEntity {
                start: 19,
                end: 25,
                label: "SURNAME".into(),
                score: 0.9,
            },
            RawEntity {
                start: 32,
                end: 43,
                label: "STREET".into(),
                score: 0.7,
            },
            RawEntity {
                start: 44,
                end: 46,
                label: "BUILDINGNUM".into(),
                score: 0.6,
            },
        ];
        let merged = merge_adjacent(text, ents, KIJI_MERGES);
        let got: Vec<(&str, &str)> = merged
            .iter()
            .map(|e| (&text[e.start..e.end], e.label.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("Sarah Leitner", "NAME"),
                ("Max Gruber", "NAME"),
                ("Neubaugasse 22", "ADDRESS")
            ]
        );
        assert!(
            (merged[0].score - 0.8).abs() < 1e-6,
            "the merged score is the minimum of its parts"
        );
        // a lone surname keeps its label
        let ents = vec![RawEntity {
            start: 6,
            end: 13,
            label: "SURNAME".into(),
            score: 0.8,
        }];
        assert_eq!(merge_adjacent(text, ents, KIJI_MERGES)[0].label, "SURNAME");
    }
}
