//! ONNX named-entity-recognition backends for inumaki.
//!
//! [`NerBackend`] is the model interface; [`NerDetector`] adapts any backend to
//! the core [`inumaki_core::detect::Detector`] trait, handling chunking and the
//! mapping from model labels to entity kinds.
#![deny(missing_docs)]

pub mod assemble;
pub mod backend;
pub mod chunk;
pub mod detector;
pub mod gliner;
pub mod manifest;
pub mod pool;
pub mod token_classifier;

pub use assemble::{
    AssembleError, BackendCache, LoadedModelInfo, NerPair, ner_for_profile, ner_for_profile_with,
};
pub use backend::{ModelError, NerBackend, RawEntity};
pub use detector::{NerDetector, NerLabelSpec};
pub use gliner::{GlinerBackend, GlinerConfig};
pub use manifest::{FetchError, FileStatus, Manifest, ModelEntry, resolve_models_dir};
pub use pool::SessionPool;
pub use token_classifier::TokenClassifierBackend;
