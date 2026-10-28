//! Engines per profile and dataset, over models loaded once.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use inumaki_core::config::CoreConfig;
use inumaki_core::detect::Detector;
use inumaki_core::engine::{Engine, EngineOptions};
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
/// alive here and compared by `Arc` identity), the logins it preserves, and
/// the engine. An entry
/// lives for the process; a daemon has one `DaemonHost`, so one memo and at
/// most one engine per profile. A process that builds many hosts (tests)
/// keeps every memo and engine it built.
type ProxyEntry = (String, Arc<NerMemo>, Vec<String>, Arc<Engine>);

/// A chat engine's cache key: profile, whether it runs without NER models,
/// and the logins it preserves.
type ChatKey = (String, bool, Vec<String>);

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
    /// The proxy's engines that differ from the shared one by an
    /// [`EngineOptions`] ([`Engines::chat_engine`]), keyed by profile,
    /// `no_ner` and the preserved logins.
    chat_engines: Mutex<HashMap<ChatKey, Arc<Engine>>>,
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
            chat_engines: Mutex::new(HashMap::new()),
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
        self.proxy_engine_with(profile, memo, &[])
    }

    /// [`Engines::proxy_engine`] with `preserved` logins
    /// ([`EngineOptions::preserved_logins`]). A host passes the same list
    /// for its whole lifetime, so the cache is keyed by profile and memo.
    pub fn proxy_engine_with(
        &self,
        profile: &str,
        memo: &Arc<NerMemo>,
        preserved: &[String],
    ) -> Result<Arc<Engine>, EngineError> {
        let mine = |(p, m, l, _): &ProxyEntry| {
            p == profile && Arc::ptr_eq(m, memo) && l.as_slice() == preserved
        };
        if let Some((_, _, _, e)) = self
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
        let engine = Arc::new(Engine::from_config_with(
            &self.core,
            profile,
            wrap(&pair.sanitizer, NerRole::Sanitizer),
            wrap(&pair.verifier, NerRole::Verifier),
            EngineOptions {
                preserved_logins: preserved.to_vec(),
                harness_envelopes: true,
                ..EngineOptions::default()
            },
        )?);
        let mut cached = self
            .proxy_engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // A concurrent first call may have built one meanwhile: keep that one.
        if let Some((_, _, _, e)) = cached.iter().find(|e| mine(e)) {
            return Ok(Arc::clone(e));
        }
        cached.push((
            profile.to_string(),
            Arc::clone(memo),
            preserved.to_vec(),
            Arc::clone(&engine),
        ));
        Ok(engine)
    }

    /// The proxy's engine for `profile` that is not the memo engine: a
    /// cached one built with those [`EngineOptions`] and the proxy's own
    /// (`harness_envelopes`), never the shared engine of the gateway, the
    /// mirror and the hook. With `no_ner` no model is loaded: the engine
    /// exists whether or not the profile's models are installed.
    pub fn chat_engine(
        &self,
        profile: &str,
        preserved: &[String],
        no_ner: bool,
    ) -> Result<Arc<Engine>, EngineError> {
        let key = (profile.to_string(), no_ner, preserved.to_vec());
        if let Some(e) = self
            .chat_engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return Ok(Arc::clone(e));
        }
        let (sanitizer, verifier) = if no_ner {
            (None, None)
        } else {
            let pair = self.pair(profile)?;
            (pair.sanitizer.clone(), pair.verifier.clone())
        };
        let engine = Arc::new(Engine::from_config_with(
            &self.core,
            profile,
            sanitizer,
            verifier,
            EngineOptions {
                no_ner,
                preserved_logins: preserved.to_vec(),
                harness_envelopes: true,
            },
        )?);
        // A concurrent first call may have built one meanwhile: keep that one.
        let mut cached = self
            .chat_engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Ok(Arc::clone(cached.entry(key).or_insert(engine)))
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
    /// The proxy's model-free engine exists with no model installed (the
    /// `support-email` profile is otherwise unavailable), and the plain and
    /// preserved-login variants are cached apart from the shared engine.
    #[test]
    fn chat_engine_without_models_preserved_logins_and_its_own_cache() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engines::new(core(), dir.path().to_path_buf());
        // No models: the full engine is unavailable, the model-free one is not.
        assert!(e.chat_engine("support-email", &[], false).is_err());
        let a = e.chat_engine("support-email", &[], true).unwrap();
        let b = e.chat_engine("support-email", &[], true).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "cached");
        assert!(a.profile().ner_sanitizer.is_none() && a.profile().ner_verifier.is_none());

        // With a pair installed: the proxy's engines are never the shared
        // one, and each variant is built once.
        e.insert_pair(
            "support-email",
            NerPair {
                sanitizer: Some(Arc::new(CountingNer::default())),
                verifier: Some(Arc::new(CountingNer::default())),
            },
        );
        let shared = e.engine("support-email", None).unwrap();
        // The proxy's engine is its own even with no option set, so the
        // gateway's shared engine never carries the proxy's protected ranges.
        let own = e.chat_engine("support-email", &[], false).unwrap();
        assert!(!Arc::ptr_eq(&shared, &own));
        assert!(Arc::ptr_eq(
            &own,
            &e.chat_engine("support-email", &[], false).unwrap()
        ));
        let keep = ["gruber".to_string()];
        let p1 = e.chat_engine("support-email", &keep, false).unwrap();
        let p2 = e.chat_engine("support-email", &keep, false).unwrap();
        assert!(Arc::ptr_eq(&p1, &p2));
        assert!(
            !Arc::ptr_eq(&p1, &shared),
            "the shared engine keeps tokenizing"
        );

        // The shared engine tokenizes the login in a path; the preserved
        // one leaves it, and leaves another login tokenized.
        let run = |eng: &Engine, text: &str| {
            let mut c = Context::new(
                ContextId("t".into()),
                std::time::Duration::from_secs(60),
                eng.token_settings().clone(),
            );
            match eng.process(text, &mut c).unwrap() {
                inumaki_core::engine::Outcome::Pass { sanitized } => sanitized.text.to_string(),
                _ => panic!("not passed"),
            }
        };
        let text = "ls /Users/gruber/app /home/huber/app";
        let shared_out = run(&shared, text);
        assert!(!shared_out.contains("gruber") && !shared_out.contains("huber"));
        let kept_out = run(&p1, text);
        assert!(kept_out.contains("/Users/gruber/app"), "{kept_out}");
        assert!(!kept_out.contains("huber"), "{kept_out}");
    }
}
