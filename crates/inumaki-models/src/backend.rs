//! Shared types for NER model backends.

use std::path::Path;

use ort::session::{Session, builder::GraphOptimizationLevel};

/// A detected entity from a model. Byte offsets into the input text.
#[derive(Debug, Clone, PartialEq)]
pub struct RawEntity {
    /// Byte offset of the first byte of the entity.
    pub start: usize,
    /// Byte offset one past the last byte of the entity.
    pub end: usize,
    /// Entity label (the requested label for dynamic backends, the model's type name otherwise).
    pub label: String,
    /// Confidence in `[0, 1]`.
    pub score: f32,
}

/// Model errors never carry input text.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    /// Loading the model, tokenizer or config failed. Carries a file path or reason, never input text.
    #[error("model load failed: {0}")]
    Load(String),
    /// Tokenization or inference failed.
    #[error("inference failed")]
    Inference,
    /// The input does not fit into a single model call; the caller must chunk it.
    #[error("input too long")]
    InputTooLong,
}

/// A named-entity-recognition model.
pub trait NerBackend: Send + Sync {
    /// Stable identifier of the backend instance.
    fn id(&self) -> &str;
    /// Whether `predict` honours arbitrary labels (zero-shot) or only filters fixed ones.
    fn supports_dynamic_labels(&self) -> bool;
    /// Entities in `text` for the given labels (ignored by fixed-label backends), filtered
    /// per label by `thresholds`.
    ///
    /// `thresholds[i]` is the minimum score for `labels[i]`; `thresholds.len()` must equal
    /// `labels.len()`, or the call fails with [`ModelError::Inference`]. A backend applies
    /// each entity's own label's threshold, not the minimum or maximum over all of them, so
    /// a low-threshold label cannot suppress a high-threshold label's valid span (or the
    /// reverse) during overlap resolution. Fixed-label backends filter every entity by the
    /// threshold of its matching label; when `labels` is empty they return every entity found,
    /// unfiltered (as if compared against `f32::MIN`).
    fn predict(
        &self,
        text: &str,
        labels: &[String],
        thresholds: &[f32],
    ) -> Result<Vec<RawEntity>, ModelError>;
    /// Max text length the backend accepts in one call, in model tokens.
    fn max_input_tokens(&self) -> usize;
    /// Times a call found every pooled session busy (0 for backends without a pool).
    fn pool_waits(&self) -> u64 {
        0
    }
}

/// Default intra-op thread count: `min(4, available_parallelism)`.
pub fn default_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(4))
}

/// Builds an ONNX Runtime session with full graph optimisation.
///
/// `threads == 0` selects [`default_threads`].
pub(crate) fn build_session(model_path: &Path, threads: usize) -> Result<Session, ModelError> {
    let threads = if threads == 0 {
        default_threads()
    } else {
        threads
    };
    let load_err = |e: ort::Error| ModelError::Load(format!("{}: {e}", model_path.display()));
    Session::builder()
        .map_err(load_err)?
        .with_optimization_level(GraphOptimizationLevel::All)
        .map_err(|e| load_err(e.into()))?
        .with_intra_threads(threads)
        .map_err(|e| load_err(e.into()))?
        .commit_from_file(model_path)
        .map_err(load_err)
}

/// `sessions` independent sessions of the same model (see [`crate::pool::SessionPool`]).
pub(crate) fn build_sessions(
    model_path: &Path,
    threads: usize,
    sessions: usize,
) -> Result<Vec<Session>, ModelError> {
    (0..sessions.max(1))
        .map(|_| build_session(model_path, threads))
        .collect()
}

/// Loads a Hugging Face `tokenizer.json` with truncation and padding disabled.
///
/// Input length is checked by each backend (`ModelError::InputTooLong`); a
/// `tokenizer.json` that carries its own truncation setting would otherwise
/// silently drop the tail of a long text.
pub(crate) fn load_tokenizer(path: &Path) -> Result<tokenizers::Tokenizer, ModelError> {
    let load_err = |reason: String| ModelError::Load(format!("{}: {reason}", path.display()));
    let mut tokenizer =
        tokenizers::Tokenizer::from_file(path).map_err(|e| load_err(e.to_string()))?;
    tokenizer
        .with_truncation(None)
        .map_err(|e| load_err(e.to_string()))?;
    tokenizer.with_padding(None);
    Ok(tokenizer)
}
