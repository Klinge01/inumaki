//! Build sanitizer and verifier NER detectors for a profile from the `[ner]` config.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use inumaki_core::config::{CoreConfig, NerSectionConfig};
use inumaki_core::detect::Detector;
use inumaki_core::policy::Profile;
use inumaki_core::span::EntityKind;

use crate::backend::{ModelError, NerBackend, default_threads};
use crate::detector::{NerDetector, NerLabelSpec};
use crate::gliner::{GlinerBackend, GlinerConfig};
use crate::manifest::{Manifest, ModelEntry, quick_check};
use crate::token_classifier::TokenClassifierBackend;

/// Detectors for one profile. The two are always distinct instances.
pub struct NerPair {
    /// Detector added to the sanitizer's stack.
    pub sanitizer: Option<Arc<dyn Detector>>,
    /// Detector used by the verifier's independent re-scan.
    pub verifier: Option<Arc<dyn Detector>>,
}

/// Why NER detectors could not be built.
#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    /// Model files are not in the models directory.
    #[error("model '{name}' is not installed in {dir}; run `inumaki models pull {name}`")]
    Missing {
        /// Model name.
        name: String,
        /// Models directory searched.
        dir: String,
    },
    /// The config names a model that is not in the manifest, or one of the wrong kind.
    #[error("model '{name}' at {key} is unknown or not a {kind} model; see `inumaki models list`")]
    Unknown {
        /// Model name from the config.
        name: String,
        /// Config key path.
        key: String,
        /// Expected model kind.
        kind: String,
    },
    /// The model failed to load.
    #[error(transparent)]
    Model(#[from] ModelError),
}

fn expected_kind(section: &str) -> &'static str {
    match section {
        "token_classifier" => "token_classifier",
        "kiji" => "kiji",
        _ => "gliner",
    }
}

fn load(
    entry: &ModelEntry,
    root: &Path,
    threads: usize,
    sessions: usize,
) -> Result<Arc<dyn NerBackend>, AssembleError> {
    if !quick_check(root, entry) {
        return Err(AssembleError::Missing {
            name: entry.name.clone(),
            dir: root.display().to_string(),
        });
    }
    let file = |role: &str| entry.path(root, role).expect("manifest lists every role");
    Ok(match entry.kind.as_str() {
        "gliner" => {
            let cfg = GlinerConfig::from_file(&file("config"))?;
            Arc::new(
                GlinerBackend::load_with_config(
                    &file("model"),
                    &file("tokenizer"),
                    cfg,
                    threads,
                    sessions,
                )?
                .with_id(entry.name.clone()),
            )
        }
        "kiji" => Arc::new(
            TokenClassifierBackend::load_kiji(
                &file("model"),
                &file("tokenizer"),
                &file("config"),
                threads,
                sessions,
            )?
            .with_id(entry.name.clone()),
        ),
        _ => Arc::new(
            TokenClassifierBackend::load(
                &file("model"),
                &file("tokenizer"),
                &file("config"),
                threads,
                sessions,
            )?
            .with_id(entry.name.clone()),
        ),
    })
}

fn labels(sec: &NerSectionConfig) -> Vec<NerLabelSpec> {
    sec.labels
        .iter()
        .map(|l| NerLabelSpec {
            label: l.label.clone(),
            kind: EntityKind::from_label(&l.kind),
            threshold: l.threshold.unwrap_or(sec.threshold),
        })
        .collect()
}

/// A backend loaded once, with the settings it was loaded with.
struct LoadedModel {
    backend: Arc<dyn NerBackend>,
    threads: usize,
    sessions: usize,
}

/// What `status` reports per loaded model.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LoadedModelInfo {
    /// Manifest name.
    pub name: String,
    /// Intra-op threads per session.
    pub threads: usize,
    /// Pooled sessions.
    pub sessions: usize,
    /// Calls that found every pooled session busy.
    pub pool_waits: u64,
}

/// Backends by manifest name, shared across every profile and engine of a
/// process so each model file is loaded once.
#[derive(Default)]
pub struct BackendCache {
    map: Mutex<HashMap<String, LoadedModel>>,
}

impl std::fmt::Debug for BackendCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self
            .map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("BackendCache").field("models", &n).finish()
    }
}

impl BackendCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loaded models, sorted by name.
    pub fn loaded(&self) -> Vec<LoadedModelInfo> {
        let map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        let mut v: Vec<LoadedModelInfo> = map
            .iter()
            .map(|(name, m)| LoadedModelInfo {
                name: name.clone(),
                threads: m.threads,
                sessions: m.sessions,
                pool_waits: m.backend.pool_waits(),
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    fn get_or_load(
        &self,
        entry: &ModelEntry,
        root: &Path,
        threads: usize,
        sessions: usize,
    ) -> Result<Arc<dyn NerBackend>, AssembleError> {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(m) = map.get(&entry.name) {
            return Ok(Arc::clone(&m.backend));
        }
        let backend = load(entry, root, threads, sessions)?;
        map.insert(
            entry.name.clone(),
            LoadedModel {
                backend: Arc::clone(&backend),
                threads: if threads == 0 {
                    default_threads()
                } else {
                    threads
                },
                sessions: sessions.max(1),
            },
        );
        Ok(backend)
    }
}

/// Build the profile's sanitizer and verifier detectors, loading each model
/// through `cache` (once per process). The two detectors stay separate
/// instances with their own labels and thresholds.
pub fn ner_for_profile_with(
    cfg: &CoreConfig,
    profile: &Profile,
    models_dir: &Path,
    cache: &BackendCache,
) -> Result<NerPair, AssembleError> {
    let manifest = Manifest::embedded();
    let build = |which: &Option<String>| -> Result<Option<Arc<dyn Detector>>, AssembleError> {
        let Some(which) = which.as_deref() else {
            return Ok(None);
        };
        let sec = cfg
            .ner
            .section(which)
            .expect("resolve_profile checked the section exists");
        let kind = expected_kind(which);
        let entry = manifest
            .get(&sec.model)
            .filter(|e| e.kind == kind)
            .ok_or_else(|| AssembleError::Unknown {
                name: sec.model.clone(),
                key: format!("ner.{which}.model"),
                kind: kind.to_string(),
            })?;
        let backend = cache.get_or_load(entry, models_dir, cfg.ner.threads, cfg.ner.sessions)?;
        Ok(Some(
            Arc::new(NerDetector::new(backend, labels(sec))) as Arc<dyn Detector>
        ))
    };
    let sanitizer = build(&profile.ner_sanitizer)?;
    let verifier = build(&profile.ner_verifier)?;
    Ok(NerPair {
        sanitizer,
        verifier,
    })
}

/// [`ner_for_profile_with`] with a cache that lives for this call only.
pub fn ner_for_profile(
    cfg: &CoreConfig,
    profile: &Profile,
    models_dir: &Path,
) -> Result<NerPair, AssembleError> {
    ner_for_profile_with(cfg, profile, models_dir, &BackendCache::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use inumaki_core::config::CoreConfig;

    fn cfg() -> CoreConfig {
        CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap()
    }

    #[test]
    fn offline_profile_loads_nothing() {
        let c = cfg();
        let p = c.resolve_profile("offline").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pair = ner_for_profile(&c, &p, dir.path()).unwrap();
        assert!(pair.sanitizer.is_none() && pair.verifier.is_none());
    }

    #[test]
    fn backend_cache_starts_empty_and_offline_loads_nothing() {
        let cache = BackendCache::new();
        assert!(cache.loaded().is_empty());
        let c = cfg();
        let p = c.resolve_profile("offline").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pair = ner_for_profile_with(&c, &p, dir.path(), &cache).unwrap();
        assert!(pair.sanitizer.is_none() && pair.verifier.is_none());
        assert!(cache.loaded().is_empty());
        assert_eq!(format!("{cache:?}"), "BackendCache { models: 0 }");
    }

    #[test]
    fn missing_model_names_the_pull_command() {
        let c = cfg();
        let p = c.resolve_profile("support-email").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let err = ner_for_profile(&c, &p, dir.path()).err().unwrap();
        let msg = format!("{err}");
        assert!(msg.contains("inumaki models pull gliner-x-small"), "{msg}");
    }

    #[test]
    fn unknown_model_name_is_reported_with_its_key() {
        let mut c = cfg();
        c.ner.gliner.as_mut().unwrap().model = "nope".into();
        let p = c.resolve_profile("support-email").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let msg = format!("{}", ner_for_profile(&c, &p, dir.path()).err().unwrap());
        assert!(
            msg.contains("nope") && msg.contains("ner.gliner.model"),
            "{msg}"
        );
    }
}
