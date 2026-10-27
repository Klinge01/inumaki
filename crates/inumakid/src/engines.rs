//! Engines per profile and dataset, over models loaded once.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use inumaki_core::config::CoreConfig;
use inumaki_core::detect::Detector;
use inumaki_core::engine::Engine;
use inumaki_core::policy::Profile;
use inumaki_models::assemble::{BackendCache, LoadedModelInfo, NerPair, ner_for_profile_with};
use inumaki_proxy::memo::{NerMemo, NerRole};

/// Whether a profile can be served.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProfileStatus {
    /// Profile name.
    pub name: String,
    /// True when its engine can be built (models loaded).
    pub available: bool,
    /// Why not, when unavailable (paths and names, never text).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Why an engine could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The profile's models are not loaded.
    #[error("profile {profile} is unavailable: {reason}")]
    Unavailable {
        /// Profile name.
        profile: String,
        /// Reason (names the pull command when a model is missing).
        reason: String,
    },
    /// The profile does not exist or is misconfigured.
    #[error(transparent)]
    Config(#[from] inumaki_core::Error),
}

type EngineKey = (String, Option<String>);

/// A proxy engine: its profile, the memo whose wrappers it holds (kept
/// alive here and compared by `Arc` identity), and the engine. An entry
/// lives for the process; a daemon has one `DaemonHost`, so one memo and at
/// most one engine per profile. A process that builds many hosts (tests)
/// keeps every memo and engine it built.
type ProxyEntry = (String, Arc<NerMemo>, Arc<Engine>);

/// Engine cache keyed by `(profile, dataset)`; models shared underneath.
pub struct Engines {
    core: CoreConfig,
    models_dir: PathBuf,
    backends: BackendCache,
    pairs: Mutex<HashMap<String, Arc<NerPair>>>,
    engines: Mutex<HashMap<EngineKey, Arc<Engine>>>,
    /// The model-API proxy's engines ([`Engines::proxy_engine`]), apart
    /// from `engines` so the gateway, the mirror and the hook never get a
    /// memo-wrapped detector.
    proxy_engines: Mutex<Vec<ProxyEntry>>,
    policies: Mutex<HashMap<String, Arc<Profile>>>,
    metadata: Mutex<HashMap<String, String>>,
}

impl std::fmt::Debug for Engines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self
            .engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("Engines").field("engines", &n).finish()
    }
}

impl Engines {
    /// Empty cache over `core` and `models_dir`.
    pub fn new(core: CoreConfig, models_dir: PathBuf) -> Self {
        Engines {
            core,
            models_dir,
            backends: BackendCache::new(),
            pairs: Mutex::new(HashMap::new()),
            engines: Mutex::new(HashMap::new()),
            proxy_engines: Mutex::new(Vec::new()),
            policies: Mutex::new(HashMap::new()),
            metadata: Mutex::new(HashMap::new()),
        }
    }

    /// The engine configuration.
    pub fn core(&self) -> &CoreConfig {
        &self.core
    }

    /// The models directory.
    pub fn models_dir(&self) -> &std::path::Path {
        &self.models_dir
    }

    /// A profile's resolved policy, without its models: available even when
    /// the profile's engine is not. Cached; configuration is fixed for the
    /// daemon's lifetime.
    pub fn policy(&self, profile: &str) -> Result<Arc<Profile>, EngineError> {
        if let Some(p) = self
            .policies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(profile)
        {
            return Ok(Arc::clone(p));
        }
        let p = Arc::new(self.core.resolve_profile(profile)?);
        self.policies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(profile.to_string(), Arc::clone(&p));
        Ok(p)
    }

    /// The metadata profile of `profile`
    /// ([`CoreConfig::metadata_profile_for`]), cached like
    /// [`Engines::policy`]: configuration is fixed for the daemon's lifetime.
    pub fn metadata_profile(&self, profile: &str) -> Result<String, EngineError> {
        if let Some(m) = self
            .metadata
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(profile)
        {
            return Ok(m.clone());
        }
        let m = self.core.metadata_profile_for(profile)?;
        self.metadata
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(profile.to_string(), m.clone());
        Ok(m)
    }

    fn profile_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .core
            .profiles
            .keys()
            .filter(|n| !self.core.is_metadata_profile(n))
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// A success is cached forever (models do not vanish once loaded); a
    /// failure is never cached, so the next call retries the assembly. The
    /// underlying check (`quick_check` in `crate::manifest`, via
    /// `ner_for_profile_with`) is a file-size check, not a reload, so
    /// retrying an unavailable profile on every request is cheap and picks
    /// up `inumaki models pull` run after the daemon started, without a
    /// restart (review ruling, task 10).
    fn pair(&self, profile: &str) -> Result<Arc<NerPair>, EngineError> {
        if let Some(p) = self
            .pairs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(profile)
        {
            return Ok(Arc::clone(p));
        }
        let p = self.core.resolve_profile(profile)?;
        let built = ner_for_profile_with(&self.core, &p, &self.models_dir, &self.backends)
            .map(Arc::new)
            .map_err(|e| e.to_string());
        if let Ok(pair) = &built {
            self.pairs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(profile.to_string(), Arc::clone(pair));
        }
        built.map_err(|reason| EngineError::Unavailable {
            profile: profile.to_string(),
            reason,
        })
    }

    /// Load every profile's models (spec §10.2 step 2). Profiles whose
    /// models are missing are reported, not fatal.
    pub fn preload(&self) -> Vec<ProfileStatus> {
        self.profile_names()
            .into_iter()
            .map(|name| match self.pair(&name) {
                Ok(_) => ProfileStatus {
                    name,
                    available: true,
                    reason: None,
                },
                Err(e) => {
                    let reason = match e {
                        EngineError::Unavailable { reason, .. } => reason,
                        EngineError::Config(c) => c.to_string(),
                    };
                    ProfileStatus {
                        name,
                        available: false,
                        reason: Some(reason),
                    }
                }
            })
            .collect()
    }

    /// Current availability per profile (cached results of [`Engines::preload`]).
    pub fn profiles(&self) -> Vec<ProfileStatus> {
        self.preload()
    }

    /// Engine for `profile`, with a dataset's detector added when given.
    pub fn engine(
        &self,
        profile: &str,
        dataset: Option<(&str, Arc<dyn Detector>)>,
    ) -> Result<Arc<Engine>, EngineError> {
        let key: EngineKey = (
            profile.to_string(),
            dataset.as_ref().map(|(id, _)| (*id).to_string()),
        );
        if let Some(e) = self
            .engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return Ok(Arc::clone(e));
        }
        let pair = self.pair(profile)?;
        let mut engine = Engine::from_config(
            &self.core,
            profile,
            pair.sanitizer.clone(),
            pair.verifier.clone(),
        )?;
        if let Some((_, det)) = dataset {
            engine = engine.with_detector(det);
        }
        let engine = Arc::new(engine);
        self.engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, Arc::clone(&engine));
        Ok(engine)
    }

    /// The model-API proxy's engine for `profile` (M8 spec §20, amendment
    /// 2026-10-12): the configuration of [`Engines::engine`] with no
    /// dataset, its sanitizer and verifier NER detectors each wrapped by
    /// `memo` ([`NerMemo::wrap`]), nothing else different. Cached apart from
    /// [`Engines::engine`]'s engines, per profile and memo (a daemon has one
    /// memo; a second host over the same state gets its own engine rather
    /// than one wrapped by another host's memo).
    ///
    /// Refuses with [`EngineError::Config`] when the profile's sanitizer and
    /// verifier NER are the same `Arc` (S6): two wraps of one `Arc` would
    /// pass core's verifier-independence check in `Engine::from_config`.
    pub fn proxy_engine(
        &self,
        profile: &str,
        memo: &Arc<NerMemo>,
    ) -> Result<Arc<Engine>, EngineError> {
        let mine = |(p, m, _): &ProxyEntry| p == profile && Arc::ptr_eq(m, memo);
        if let Some((_, _, e)) = self
            .proxy_engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|e| mine(e))
        {
            return Ok(Arc::clone(e));
        }
        let pair = self.pair(profile)?;
        if let (Some(a), Some(b)) = (&pair.sanitizer, &pair.verifier)
            && Arc::ptr_eq(a, b)
        {
            return Err(EngineError::Config(inumaki_core::Error::ConfigInvalid(
                "verifier_ner must differ from sanitizer_ner".into(),
            )));
        }
        let wrap = |d: &Option<Arc<dyn Detector>>, role| d.clone().map(|d| memo.wrap(d, role));
        let engine = Arc::new(Engine::from_config(
            &self.core,
            profile,
            wrap(&pair.sanitizer, NerRole::Sanitizer),
            wrap(&pair.verifier, NerRole::Verifier),
        )?);
        let mut cached = self
            .proxy_engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // A concurrent first call may have built one meanwhile: keep that one.
        if let Some((_, _, e)) = cached.iter().find(|e| mine(e)) {
            return Ok(Arc::clone(e));
        }
        cached.push((profile.to_string(), Arc::clone(memo), Arc::clone(&engine)));
        Ok(engine)
    }

    /// Use `pair` as `profile`'s NER pair, as if its models had loaded
    /// (tests: fake detectors without model files).
    #[cfg(test)]
    pub(crate) fn insert_pair(&self, profile: &str, pair: NerPair) {
        self.pairs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(profile.to_string(), Arc::new(pair));
    }

    /// Forget every engine built for `dataset_id` (dataset deleted).
    pub fn drop_dataset(&self, dataset_id: &str) {
        self.engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(_, d), _| d.as_deref() != Some(dataset_id));
    }

    /// Loaded models for `status`.
    pub fn models(&self) -> Vec<LoadedModelInfo> {
        self.backends.loaded()
    }
}

/// Test helpers shared with `proxy_host`'s tests: a fake NER model and a
/// long, finding-free text.
#[cfg(test)]
pub(crate) mod fake {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use inumaki_core::detect::{DetectCtx, Detector};
    use inumaki_core::span::{DetectorId, Span};
    use inumaki_proxy::memo::STATIC_MIN_BYTES;

    /// A NER model that finds nothing and counts its calls on inputs the
    /// memo could serve (at least `STATIC_MIN_BYTES`).
    #[derive(Default)]
    pub(crate) struct CountingNer(AtomicUsize);

    impl CountingNer {
        pub(crate) fn long(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Detector for CountingNer {
        fn id(&self) -> DetectorId {
            DetectorId::Ner
        }
        fn detect(&self, text: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
            if text.len() >= STATIC_MIN_BYTES {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            Ok(Vec::new())
        }
    }

    /// An ASCII text of at least 4 KiB that no detector flags.
    pub(crate) fn long_text() -> String {
        let mut s = String::new();
        while s.len() < 4096 {
            s.push_str("Answer in short paragraphs and keep a calm tone. ");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{CountingNer, long_text};
    use super::*;
    use inumaki_core::detect::{DetectCtx, Detector};
    use inumaki_core::span::{DetectorId, EntityKind, Span};
    use inumaki_core::token::{Context, ContextId};
    use inumaki_proxy::memo::{MemoStats, STATIC_MEMO_BYTES, STATIC_MEMO_ENTRIES};

    fn core() -> CoreConfig {
        CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap()
    }

    struct Gruber;
    impl Detector for Gruber {
        fn id(&self) -> DetectorId {
            DetectorId::Dictionary
        }
        fn detect(&self, text: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
            Ok(text
                .find("Gruber")
                .map(|i| {
                    vec![Span::new(
                        i,
                        i + 6,
                        EntityKind::Person,
                        0.97,
                        DetectorId::Dictionary,
                    )]
                })
                .unwrap_or_default())
        }
    }

    #[test]
    fn offline_profile_is_available_without_models_and_engines_are_cached() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engines::new(core(), dir.path().to_path_buf());
        let status = e.preload();
        let offline = status.iter().find(|p| p.name == "offline").unwrap();
        assert!(offline.available && offline.reason.is_none());
        let se = status.iter().find(|p| p.name == "support-email").unwrap();
        assert!(!se.available);
        assert!(
            se.reason
                .as_deref()
                .unwrap()
                .contains("inumaki models pull"),
            "{:?}",
            se.reason
        );
        let a = e.engine("offline", None).unwrap();
        let b = e.engine("offline", None).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "same engine on the second call");
        assert!(e.models().is_empty());
        assert_eq!(e.profiles(), status);
    }

    #[test]
    fn unavailable_profile_is_an_engine_error_never_a_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engines::new(core(), dir.path().to_path_buf());
        let err = e.engine("support-email", None).unwrap_err();
        assert!(
            matches!(err, EngineError::Unavailable { ref profile, .. } if profile == "support-email"),
            "{err}"
        );
        let err = e.engine("nope", None).unwrap_err();
        assert!(matches!(err, EngineError::Config(_)), "{err}");
    }

    /// Review ruling (task 10): a profile whose model load failed earlier
    /// must retry the assembly on the next request, not repeat the cached
    /// failure forever, so `inumaki models pull` after the daemon started
    /// is picked up without a restart. `quick_check` is a file-size check,
    /// so files of the right size (garbage content) make it pass and force
    /// the retry into the real loader, which then fails differently
    /// (invalid config, not "not installed") — proof the second call did
    /// not just replay the first call's cached error.
    #[test]
    fn unavailable_profile_is_retried_not_cached_as_permanently_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engines::new(core(), dir.path().to_path_buf());
        let first = e.engine("support-email", None).unwrap_err();
        let EngineError::Unavailable { reason, .. } = &first else {
            panic!("{first}");
        };
        assert!(reason.contains("inumaki models pull"), "{reason}");

        let manifest = inumaki_models::manifest::Manifest::embedded();
        let entry = manifest.get("gliner-x-small").unwrap();
        for f in &entry.files {
            let p = dir.path().join("gliner-x-small").join(&f.path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, vec![0u8; f.size as usize]).unwrap();
        }

        let second = e.engine("support-email", None).unwrap_err();
        let EngineError::Unavailable { reason, .. } = &second else {
            panic!("{second}");
        };
        assert!(
            !reason.contains("is not installed"),
            "second call should have retried the load, not repeated the missing-file error: {reason}"
        );
    }

    #[test]
    fn dataset_engines_carry_their_detector_and_are_dropped_per_dataset() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engines::new(core(), dir.path().to_path_buf());
        let plain = e.engine("offline", None).unwrap();
        let det: Arc<dyn Detector> = Arc::new(Gruber);
        let ds = e.engine("offline", Some(("mail", det))).unwrap();
        assert!(!Arc::ptr_eq(&plain, &ds));
        // No honorific: the anchor detector would find `Herr Gruber` itself.
        assert!(plain.detect("Rechnung an Gruber").unwrap().is_empty());
        assert_eq!(ds.detect("Rechnung an Gruber").unwrap().len(), 1);
        let det2: Arc<dyn Detector> = Arc::new(Gruber);
        let again = e.engine("offline", Some(("mail", det2))).unwrap();
        assert!(Arc::ptr_eq(&ds, &again), "cached per (profile, dataset)");
        e.drop_dataset("mail");
        let det3: Arc<dyn Detector> = Arc::new(Gruber);
        let rebuilt = e.engine("offline", Some(("mail", det3))).unwrap();
        assert!(!Arc::ptr_eq(&ds, &rebuilt));
        assert!(
            Arc::ptr_eq(&plain, &e.engine("offline", None).unwrap()),
            "profile engine untouched"
        );
    }

    fn memo() -> Arc<NerMemo> {
        NerMemo::new(
            "support-email",
            [0; 32],
            STATIC_MEMO_ENTRIES,
            STATIC_MEMO_BYTES,
        )
    }

    /// Engines whose `support-email` pair is two counting fakes.
    fn with_fakes() -> (
        Engines,
        Arc<CountingNer>,
        Arc<CountingNer>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let e = Engines::new(core(), dir.path().to_path_buf());
        let (s, v) = (
            Arc::new(CountingNer::default()),
            Arc::new(CountingNer::default()),
        );
        e.insert_pair(
            "support-email",
            NerPair {
                sanitizer: Some(s.clone() as Arc<dyn Detector>),
                verifier: Some(v.clone() as Arc<dyn Detector>),
            },
        );
        (e, s, v, dir)
    }

    /// One whole engine pass (sanitizer NER on the text, verifier NER on
    /// the candidate) in a fresh context.
    fn run(engine: &Engine, text: &str) {
        let mut ctx = Context::new(
            ContextId("t".into()),
            std::time::Duration::from_secs(60),
            engine.token_settings().clone(),
        );
        engine.process(text, &mut ctx).unwrap();
    }

    /// P4 (plan Task 3): the engine the gateway, the mirror and the hook use
    /// (`Engines::engine`) runs both NER models on every call, even inside
    /// an open memo scope on the same text and after the proxy engine has
    /// filled the memo: its detectors are the pair's own, unwrapped. The
    /// proxy engine (`proxy_engine`) is a separate engine whose second pass
    /// on the same text is answered by the memo. Core has no accessor for
    /// an engine's NER detectors, so this checks the behavior, not `ptr_eq`.
    #[test]
    fn the_shared_engine_stays_unwrapped_and_only_the_proxy_engine_uses_the_memo() {
        let (e, s, v, _dir) = with_fakes();
        let m = memo();
        let text = long_text();
        let plain = e.engine("support-email", None).unwrap();
        let wrapped = e.proxy_engine("support-email", &m).unwrap();
        assert!(!Arc::ptr_eq(&plain, &wrapped), "a separate engine");
        assert!(Arc::ptr_eq(
            &wrapped,
            &e.proxy_engine("support-email", &m).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &plain,
            &e.engine("support-email", None).unwrap()
        ));
        let other = memo();
        assert!(
            !Arc::ptr_eq(&wrapped, &e.proxy_engine("support-email", &other).unwrap()),
            "an engine per memo"
        );

        let scope = m.scope(&text);
        run(&plain, &text);
        run(&plain, &text);
        assert_eq!((s.long(), v.long()), (2, 2), "both models ran each time");
        assert_eq!(
            m.stats(),
            MemoStats::default(),
            "the memo was never touched"
        );

        run(&wrapped, &text);
        run(&wrapped, &text);
        assert_eq!((s.long(), v.long()), (3, 3), "the second pass ran no model");
        let st = m.stats();
        assert_eq!((st.hits, st.misses), (2, 2));

        run(&plain, &text);
        assert_eq!(
            (s.long(), v.long()),
            (4, 4),
            "still unwrapped with a full memo"
        );
        assert_eq!(m.stats().hits, 2);
        drop(scope);
    }

    /// S6 (plan Task 3): one `Arc` in both NER roles is refused before
    /// wrapping; two wraps of it would pass core's independence check.
    #[test]
    fn proxy_engine_refuses_one_ner_arc_in_both_roles() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engines::new(core(), dir.path().to_path_buf());
        let one: Arc<dyn Detector> = Arc::new(CountingNer::default());
        e.insert_pair(
            "support-email",
            NerPair {
                sanitizer: Some(Arc::clone(&one)),
                verifier: Some(one),
            },
        );
        let err = e.proxy_engine("support-email", &memo()).unwrap_err();
        assert!(matches!(err, EngineError::Config(_)), "{err}");
        assert!(e.proxy_engines.lock().unwrap().is_empty(), "nothing cached");
    }
}
