//! GLiNER span-mode backend (flat NER, zero-shot labels) on ONNX Runtime.
//!
//! Portions derived from gline-rs (<https://github.com/fbilhaut/gline-rs>), Apache-2.0:
//! the word-splitter regex (`text/splitter.rs`), the prompt layout and per-word
//! sub-word encoding with `words_mask` construction (`model/input/{prompt,encoded}.rs`),
//! the span tensor layout (`model/input/tensors/span.rs`) and span scoring
//! (`model/output/decoded/span.rs`). Greedy decoding follows the reference Python
//! GLiNER (score-ordered) instead of gline-rs' offset-ordered scan; see `greedy_flat`.

use std::path::Path;

use ndarray::{Array2, Array3};
use ort::session::Session;
use ort::value::Tensor;
use regex::Regex;
use tokenizers::Tokenizer;

use crate::backend::{ModelError, NerBackend, RawEntity, build_sessions, load_tokenizer};
use crate::pool::SessionPool;

/// Word splitter used by gline-rs (and GLiNER's `WhitespaceTokenSplitter`).
const WORD_REGEX: &str = r"\w+(?:[-_]\w+)*|\S";
/// Sequence start id hard-coded by gline-rs (DeBERTa `[CLS]`; `</s>` in mT5 vocabularies).
const START_TOKEN_ID: i64 = 1;
/// Sequence end id hard-coded by gline-rs (DeBERTa `[SEP]`; `<unk>` in mT5 vocabularies).
const END_TOKEN_ID: i64 = 2;

/// Pre/post-processing parameters, mirroring `gliner_config.json`.
#[derive(Debug, Clone, PartialEq)]
pub struct GlinerConfig {
    /// Maximum span width in words (`max_width`, default 12).
    pub max_width: usize,
    /// Maximum prompt length in sub-word tokens, framing tokens included (default 512).
    pub max_length: usize,
    /// Entity marker token (`ent_token`, default `<<ENT>>`).
    pub ent_token: String,
    /// Label/text separator token (`sep_token`, default `<<SEP>>`).
    pub sep_token: String,
}

impl Default for GlinerConfig {
    fn default() -> Self {
        Self {
            max_width: 12,
            max_length: 512,
            ent_token: "<<ENT>>".to_owned(),
            sep_token: "<<SEP>>".to_owned(),
        }
    }
}

impl GlinerConfig {
    /// Reads `max_width`, `ent_token` and `sep_token` from a `gliner_config.json`;
    /// missing keys keep their defaults. `max_length` is not read (`max_len` there counts words).
    pub fn from_file(path: &Path) -> Result<Self, ModelError> {
        let load_err = |reason: String| ModelError::Load(format!("{}: {reason}", path.display()));
        let raw = std::fs::read_to_string(path).map_err(|e| load_err(e.to_string()))?;
        let json: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| load_err(e.to_string()))?;
        let mut config = Self::default();
        if let Some(w) = json.get("max_width").and_then(serde_json::Value::as_u64) {
            config.max_width = usize::try_from(w).map_err(|e| load_err(e.to_string()))?;
        }
        if let Some(t) = json.get("ent_token").and_then(serde_json::Value::as_str) {
            config.ent_token = t.to_owned();
        }
        if let Some(t) = json.get("sep_token").and_then(serde_json::Value::as_str) {
            config.sep_token = t.to_owned();
        }
        if config.max_width == 0 {
            return Err(load_err("max_width must be > 0".to_owned()));
        }
        Ok(config)
    }
}

/// GLiNER span-mode model (e.g. `knowledgator/gliner-x-small`) exported to ONNX.
pub struct GlinerBackend {
    id: String,
    session: SessionPool<Session>,
    tokenizer: Tokenizer,
    splitter: Regex,
    config: GlinerConfig,
}

impl GlinerBackend {
    /// Loads the ONNX model and `tokenizer.json` with [`GlinerConfig::default`].
    ///
    /// `threads == 0` selects [`crate::backend::default_threads`].
    pub fn load(
        model_path: &Path,
        tokenizer_path: &Path,
        threads: usize,
        sessions: usize,
    ) -> Result<Self, ModelError> {
        Self::load_with_config(
            model_path,
            tokenizer_path,
            GlinerConfig::default(),
            threads,
            sessions,
        )
    }

    /// Loads the ONNX model and `tokenizer.json` with an explicit configuration.
    pub fn load_with_config(
        model_path: &Path,
        tokenizer_path: &Path,
        config: GlinerConfig,
        threads: usize,
        sessions: usize,
    ) -> Result<Self, ModelError> {
        if config.max_width == 0 {
            return Err(ModelError::Load(format!(
                "{}: max_width must be > 0",
                model_path.display()
            )));
        }
        let tokenizer = load_tokenizer(tokenizer_path)?;
        let sessions = build_sessions(model_path, threads, sessions)?;
        let splitter = Regex::new(WORD_REGEX).map_err(|e| ModelError::Load(e.to_string()))?;
        Ok(Self {
            id: "gliner".to_owned(),
            session: SessionPool::new(sessions),
            tokenizer,
            splitter,
            config,
        })
    }

    /// Replaces the backend identifier returned by [`NerBackend::id`].
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Sub-word ids of one prompt word, without special tokens (as gline-rs does).
    fn encode_word(&self, word: &str) -> Result<Vec<u32>, ModelError> {
        let encoding = self
            .tokenizer
            .encode(word, false)
            .map_err(|_| ModelError::Inference)?;
        Ok(encoding.get_ids().to_vec())
    }

    /// Runs the model and returns the flat `logits` of shape `(num_words, max_width, num_labels)`.
    fn run(
        &self,
        prompt: &EncodedPrompt,
        num_words: usize,
        num_labels: usize,
    ) -> Result<Vec<f32>, ModelError> {
        let max_width = self.config.max_width;
        let seq_len = prompt.input_ids.len();
        let (span_idx, span_mask) = span_tensors(num_words, max_width);
        let err = |_| ModelError::Inference;
        let input_ids =
            Array2::from_shape_vec((1, seq_len), prompt.input_ids.clone()).map_err(err)?;
        let attention_mask = Array2::<i64>::ones((1, seq_len));
        let words_mask =
            Array2::from_shape_vec((1, seq_len), prompt.words_mask.clone()).map_err(err)?;
        let text_lengths = Array2::from_elem((1, 1), to_i64(num_words));
        let span_idx =
            Array3::from_shape_vec((1, num_words * max_width, 2), span_idx).map_err(err)?;
        let span_mask =
            Array2::from_shape_vec((1, num_words * max_width), span_mask).map_err(err)?;
        let inputs = ort::inputs![
            "input_ids" => Tensor::from_array(input_ids).map_err(|_| ModelError::Inference)?,
            "attention_mask" => Tensor::from_array(attention_mask).map_err(|_| ModelError::Inference)?,
            "words_mask" => Tensor::from_array(words_mask).map_err(|_| ModelError::Inference)?,
            "text_lengths" => Tensor::from_array(text_lengths).map_err(|_| ModelError::Inference)?,
            "span_idx" => Tensor::from_array(span_idx).map_err(|_| ModelError::Inference)?,
            "span_mask" => Tensor::from_array(span_mask).map_err(|_| ModelError::Inference)?,
        ];
        let mut session = self.session.acquire();
        let outputs = session.run(inputs).map_err(|_| ModelError::Inference)?;
        let (shape, logits) = outputs["logits"]
            .try_extract_tensor::<f32>()
            .map_err(|_| ModelError::Inference)?;
        let expected = [1, to_i64(num_words), to_i64(max_width), to_i64(num_labels)];
        if shape[..] != expected[..] {
            return Err(ModelError::Inference);
        }
        Ok(logits.to_vec())
    }
}

impl NerBackend for GlinerBackend {
    fn id(&self) -> &str {
        &self.id
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
        if thresholds.len() != labels.len() {
            return Err(ModelError::Inference);
        }
        let words = split_words(&self.splitter, text);
        if words.is_empty() || labels.is_empty() {
            return Ok(Vec::new());
        }
        let mut label_part = Vec::with_capacity(labels.len() * 2 + 1);
        for label in labels {
            label_part.push(self.encode_word(&self.config.ent_token)?);
            label_part.push(self.encode_word(label)?);
        }
        label_part.push(self.encode_word(&self.config.sep_token)?);

        // Format characters (ZWJ, ZWNJ, LRM, BOM, ...) are their own `\S` word under
        // `WORD_REGEX` but the tokenizer encodes them to zero sub-word ids. Leaving such a
        // word in would add nothing to `input_ids`/`words_mask` while `text_lengths` and the
        // span tensors still counted it, desyncing every later word index from its tensor
        // position. Drop these words from both the offset table and the encoded text so
        // `kept` and `text_part` stay in lock-step.
        let mut kept: Vec<(usize, usize)> = Vec::with_capacity(words.len());
        let mut text_part: Vec<Vec<u32>> = Vec::with_capacity(words.len());
        for &(start, end) in &words {
            let ids = self.encode_word(&text[start..end])?;
            if ids.is_empty() {
                continue;
            }
            kept.push((start, end));
            text_part.push(ids);
        }
        if kept.is_empty() {
            return Ok(Vec::new());
        }

        let prompt = encode_prompt(&label_part, &text_part);
        if prompt.input_ids.len() > self.config.max_length {
            return Err(ModelError::InputTooLong);
        }
        let logits = self.run(&prompt, kept.len(), labels.len())?;
        let candidates = decode_spans(&logits, kept.len(), self.config.max_width, thresholds);
        Ok(greedy_flat(candidates)
            .into_iter()
            .map(|c| RawEntity {
                start: kept[c.start].0,
                end: kept[c.end].1,
                label: labels[c.label].clone(),
                score: c.score,
            })
            .collect())
    }

    fn max_input_tokens(&self) -> usize {
        // The label prompt (`<<ENT>> label ... <<SEP>>`) also counts against this budget.
        self.config.max_length.saturating_sub(2)
    }

    fn pool_waits(&self) -> u64 {
        self.session.waits()
    }
}

/// Model input for one prompt.
#[derive(Debug, PartialEq)]
struct EncodedPrompt {
    input_ids: Vec<i64>,
    /// 1-based word index on the first sub-word of each text word, 0 elsewhere.
    words_mask: Vec<i64>,
}

/// A scored span over word indices (`end` inclusive).
#[derive(Debug, Clone, PartialEq)]
struct Candidate {
    start: usize,
    end: usize,
    label: usize,
    score: f32,
}

/// Splits `text` into words, returning byte ranges.
fn split_words(splitter: &Regex, text: &str) -> Vec<(usize, usize)> {
    splitter
        .find_iter(text)
        .map(|m| (m.start(), m.end()))
        .collect()
}

/// Flattens `[start] label_part text_part [end]` and builds the matching `words_mask`.
fn encode_prompt(label_part: &[Vec<u32>], text_part: &[Vec<u32>]) -> EncodedPrompt {
    let total = 2 + label_part
        .iter()
        .chain(text_part)
        .map(Vec::len)
        .sum::<usize>();
    let mut input_ids = Vec::with_capacity(total);
    let mut words_mask = Vec::with_capacity(total);
    input_ids.push(START_TOKEN_ID);
    for word in label_part {
        input_ids.extend(word.iter().map(|&id| i64::from(id)));
    }
    words_mask.resize(input_ids.len(), 0);
    for (word_idx, word) in text_part.iter().enumerate() {
        for (piece_idx, &id) in word.iter().enumerate() {
            input_ids.push(i64::from(id));
            words_mask.push(if piece_idx == 0 {
                to_i64(word_idx + 1)
            } else {
                0
            });
        }
    }
    input_ids.push(END_TOKEN_ID);
    words_mask.push(0);
    EncodedPrompt {
        input_ids,
        words_mask,
    }
}

/// Flat `span_idx` (`num_words * max_width * 2`) and `span_mask` (`num_words * max_width`).
///
/// Slot `start * max_width + width` holds `[start, start + width]` when it fits in the text;
/// other slots are `[0, 0]` and masked out.
fn span_tensors(num_words: usize, max_width: usize) -> (Vec<i64>, Vec<bool>) {
    let mut idx = vec![0i64; num_words * max_width * 2];
    let mut mask = vec![false; num_words * max_width];
    for start in 0..num_words {
        for width in 0..max_width.min(num_words - start) {
            let slot = start * max_width + width;
            idx[slot * 2] = to_i64(start);
            idx[slot * 2 + 1] = to_i64(start + width);
            mask[slot] = true;
        }
    }
    (idx, mask)
}

/// Spans whose sigmoid score reaches their own label's threshold (`thresholds[label]`), from
/// flat logits `(num_words, max_width, thresholds.len())`.
///
/// Filtering here, before `greedy_flat`'s overlap resolution, matters: a candidate that would
/// later be dropped for scoring under its own label's threshold must not be allowed to win an
/// overlap against a different label's candidate that clears its own (final review I2).
fn decode_spans(
    logits: &[f32],
    num_words: usize,
    max_width: usize,
    thresholds: &[f32],
) -> Vec<Candidate> {
    let num_labels = thresholds.len();
    let mut out = Vec::new();
    for start in 0..num_words {
        for width in 0..max_width.min(num_words - start) {
            for label in 0..num_labels {
                let score = sigmoid(logits[(start * max_width + width) * num_labels + label]);
                if score >= thresholds[label] {
                    out.push(Candidate {
                        start,
                        end: start + width,
                        label,
                        score,
                    });
                }
            }
        }
    }
    out
}

/// Flat greedy decoding as in Python GLiNER: take spans by descending score, drop any that
/// overlaps an accepted one, return in text order.
///
/// gline-rs 1.1.0 instead scans offset-sorted spans comparing each only with its predecessor,
/// which can drop a span that overlaps nothing accepted (A < B < C chained overlaps keep only C).
fn greedy_flat(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score));
    let mut accepted: Vec<Candidate> = Vec::new();
    for c in candidates {
        if accepted.iter().all(|a| c.end < a.start || a.end < c.start) {
            accepted.push(c);
        }
    }
    accepted.sort_by_key(|c| (c.start, c.end));
    accepted
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Index to tensor element; indices here are bounded by `max_length`, far below `i64::MAX`.
fn to_i64(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn splitter() -> Regex {
        Regex::new(WORD_REGEX).unwrap()
    }

    #[test]
    fn splits_words_with_byte_offsets() {
        let text = "Jürgen Müller-Lüdenscheid, Wien 1010.";
        let words: Vec<&str> = split_words(&splitter(), text)
            .iter()
            .map(|&(s, e)| &text[s..e])
            .collect();
        assert_eq!(
            words,
            ["Jürgen", "Müller-Lüdenscheid", ",", "Wien", "1010", "."]
        );
        assert_eq!(split_words(&splitter(), text)[1], (8, 28));
    }

    #[test]
    fn splits_like_gline_rs() {
        let words = split_words(&splitter(), "This is an oh-yeah test");
        assert_eq!(words.len(), 5);
        assert_eq!(words[3], (11, 18));
    }

    #[test]
    fn encodes_prompt_with_first_subword_mask() {
        // [<<ENT>>] [name] [<<SEP>>] | "1a" -> 2 pieces, "John", "Doe"
        let labels = vec![vec![100], vec![7], vec![101]];
        let text = vec![vec![11, 12], vec![13], vec![14]];
        let p = encode_prompt(&labels, &text);
        assert_eq!(p.input_ids, [1, 100, 7, 101, 11, 12, 13, 14, 2]);
        // Same mask as gline-rs `test_words_mask_multi_token_first_word`.
        assert_eq!(p.words_mask, [0, 0, 0, 0, 1, 0, 2, 3, 0]);
    }

    #[test]
    fn span_tensors_layout() {
        let (idx, mask) = span_tensors(3, 2);
        assert_eq!(idx, [0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 0, 0]);
        assert_eq!(mask, [true, true, true, true, true, false]);
    }

    #[test]
    fn decodes_spans_above_threshold_within_text() {
        // num_words = 2, max_width = 2, num_labels = 1; slot (1, width 1) is out of text.
        let logits = [2.0, -2.0, 0.0, 9.0];
        let c = decode_spans(&logits, 2, 2, &[0.5]);
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].start, c[0].end), (0, 0));
        assert!((c[0].score - sigmoid(2.0)).abs() < 1e-6);
        assert_eq!((c[1].start, c[1].end), (1, 1));
        assert!((c[1].score - 0.5).abs() < 1e-6);
    }

    /// I2: a candidate below its own label's threshold is not emitted, even
    /// when a lower threshold would have let it through for another label.
    #[test]
    fn decode_spans_applies_each_labels_own_threshold() {
        // num_words = 1, max_width = 1, 2 labels: label 0 threshold 0.6, label 1 threshold 0.5.
        // Single slot (start 0, width 0): label 0 scores sigmoid(0.2) ~= 0.55 (below its own
        // 0.6 threshold), label 1 scores sigmoid(0.6) ~= 0.65 (above its 0.5 threshold).
        let logits = [0.2, 0.6];
        let c = decode_spans(&logits, 1, 1, &[0.6, 0.5]);
        assert_eq!(c.len(), 1, "{c:?}");
        assert_eq!(c[0].label, 1);
        assert!((c[0].score - sigmoid(0.6)).abs() < 1e-6);
    }

    #[test]
    fn greedy_keeps_best_non_overlapping() {
        let cand = |start, end, score| Candidate {
            start,
            end,
            label: 0,
            score,
        };
        let out = greedy_flat(vec![
            cand(0, 1, 0.5),
            cand(1, 2, 0.6),
            cand(2, 3, 0.7),
            cand(5, 5, 0.4),
        ]);
        assert_eq!(out, vec![cand(0, 1, 0.5), cand(2, 3, 0.7), cand(5, 5, 0.4)]);
    }

    #[test]
    fn greedy_rejects_nested_and_same_span_other_label() {
        let a = Candidate {
            start: 0,
            end: 2,
            label: 0,
            score: 0.9,
        };
        let b = Candidate {
            start: 1,
            end: 1,
            label: 1,
            score: 0.8,
        };
        let c = Candidate {
            start: 0,
            end: 2,
            label: 1,
            score: 0.7,
        };
        assert_eq!(greedy_flat(vec![b, c, a.clone()]), vec![a]);
    }

    fn write_config(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gliner_config.json");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    #[test]
    fn from_file_partial_keys_keep_other_defaults() {
        let (_dir, path) = write_config(r#"{"max_width": 8}"#);
        let config = GlinerConfig::from_file(&path).unwrap();
        assert_eq!(config.max_width, 8);
        assert_eq!(config.ent_token, GlinerConfig::default().ent_token);
        assert_eq!(config.sep_token, GlinerConfig::default().sep_token);
        assert_eq!(config.max_length, GlinerConfig::default().max_length);
    }

    #[test]
    fn from_file_all_keys_override_all_fields() {
        let (_dir, path) =
            write_config(r#"{"max_width": 4, "ent_token": "<<E>>", "sep_token": "<<S>>"}"#);
        let config = GlinerConfig::from_file(&path).unwrap();
        assert_eq!(config.max_width, 4);
        assert_eq!(config.ent_token, "<<E>>");
        assert_eq!(config.sep_token, "<<S>>");
        // max_length is never read from the file.
        assert_eq!(config.max_length, GlinerConfig::default().max_length);
    }

    #[test]
    fn from_file_zero_max_width_is_rejected_without_leaking_contents() {
        let (_dir, path) = write_config(r#"{"max_width": 0}"#);
        let err = GlinerConfig::from_file(&path).unwrap_err();
        let ModelError::Load(msg) = err else {
            panic!("expected Load, got {err:?}");
        };
        assert!(msg.contains(&path.display().to_string()), "{msg}");
        assert!(!msg.contains("max_width\": 0"), "{msg}");
    }

    #[test]
    fn load_with_config_rejects_zero_max_width() {
        let config = GlinerConfig {
            max_width: 0,
            ..GlinerConfig::default()
        };
        // `GlinerBackend` has no `Debug` impl (it holds no printable state worth exposing),
        // so match the `Result` by hand instead of `.unwrap_err()`.
        let result = GlinerBackend::load_with_config(
            Path::new("/nonexistent/model.onnx"),
            Path::new("/nonexistent/tokenizer.json"),
            config,
            1,
            1,
        );
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected an error for max_width = 0"),
        };
        let ModelError::Load(msg) = err else {
            panic!("expected Load, got {err:?}");
        };
        assert!(msg.contains("max_width"), "{msg}");
    }

    #[test]
    fn from_file_empty_object_is_default() {
        let (_dir, path) = write_config("{}");
        let config = GlinerConfig::from_file(&path).unwrap();
        assert_eq!(config, GlinerConfig::default());
    }
}
