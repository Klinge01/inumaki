//! A fake host: one dataset "ds" with a known entity, an offline-style
//! engine, recorded events. Canary values are synthetic. Used by the unit
//! tests of this and later tasks, so some items are unused here.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use inumaki_core::config::CoreConfig;
use inumaki_core::detect::dictionary::DictionaryDetector;
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::engine::Engine;
use inumaki_core::policy::Profile;
use inumaki_core::span::{DetectorId, EntityKind, Span};
use zeroize::Zeroizing;

use crate::host::{HostBlock, HostError, ProxyEvent, ProxyHost, Scope};
use crate::memo::{NerMemo, NerRole, STATIC_MEMO_BYTES, STATIC_MEMO_ENTRIES, STATIC_MIN_BYTES};

pub const NAME: &str = "Zyxwuria Quolnath";
pub const EMAIL: &str = "zyx.quolnath@example.invalid";
pub const IBAN: &str = "AT61 1904 3002 3457 3201";
pub const DS_TOKEN: &str = "<PERSON_a1b2c3>";

/// The check dataset (check routes, M8 spec §12.3) and its known values.
pub const CHECK_DS: &str = "check-ab";
pub const CHECK_NAME: &str = "Vexmira Thwarnquix";
pub const CHECK_EMAIL: &str = "vexmira@example.invalid";
pub const CHECK_TOKEN: &str = "<PERSON_c4c4c4>";
pub const CHECK_EMAIL_TOKEN: &str = "<EMAIL_e5e5e5>";

pub const CFG: &str = r#"
    [profiles.fast]
    default_action = "tokenize"
    default_min_confidence = 0.5
    escalate_below = 0.5
    [profiles.fast.entities.DATE]
    action = "preserve"
    min_confidence = 0.0
    [profiles.fast.entities.URL]
    action = "preserve"
    min_confidence = 0.0
    [profiles.fast.entities.SECRET]
    action = "remove"
    min_confidence = 0.0
    [profiles.fast.verifier]
    on_uncertain = "block"
    allow_no_ner = true
"#;

/// [`CFG`], plus ORGANIZATION preserved: an identifier-shaped ORGANIZATION
/// (such as a customer number) is still never treated as preserved (I2).
pub const CFG_ORG_PRESERVED: &str = r#"
    [profiles.fast]
    default_action = "tokenize"
    default_min_confidence = 0.5
    escalate_below = 0.5
    [profiles.fast.entities.DATE]
    action = "preserve"
    min_confidence = 0.0
    [profiles.fast.entities.URL]
    action = "preserve"
    min_confidence = 0.0
    [profiles.fast.entities.ORGANIZATION]
    action = "preserve"
    min_confidence = 0.0
    [profiles.fast.entities.SECRET]
    action = "remove"
    min_confidence = 0.0
    [profiles.fast.verifier]
    on_uncertain = "block"
    allow_no_ner = true
"#;

/// Flags every `needle` as a PERSON at the given confidence; `None` fails like a broken model.
pub struct Word(pub &'static str, pub Option<f32>);

impl Detector for Word {
    fn id(&self) -> DetectorId {
        DetectorId::Ner
    }
    fn detect(&self, text: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        let Some(c) = self.1 else {
            return Err(inumaki_core::Error::ModelUnavailable("test".into()));
        };
        Ok(text
            .match_indices(self.0)
            .map(|(i, w)| Span::new(i, i + w.len(), EntityKind::Person, c, DetectorId::Ner))
            .collect())
    }
}

/// A detector that counts its calls: a full-engine (re-)run calls it once
/// per pass; a projection never does.
pub struct Counting(pub Arc<std::sync::atomic::AtomicUsize>);

impl Detector for Counting {
    fn id(&self) -> DetectorId {
        DetectorId::RegexSyntax
    }
    fn detect(&self, _: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Vec::new())
    }
}

/// A synthetic name the fake NER detectors ([`CountingNer`]) flag as a
/// PERSON wherever it appears (the static-prompt memo tests).
pub const MEMO_NAME: &str = "Quilbert Xandover";
/// A synthetic surname the fake NER detectors flag as a PERSON only right
/// after `Mr. `: a static text can hold it in clear while a user text
/// mints it.
pub const MEMO_V: &str = "Pemberton";
/// A synthetic word the fake NER detectors flag as `FORBIDDEN`, a kind
/// [`CFG_NER`] blocks: a text holding it is refused.
pub const MEMO_FORBIDDEN: &str = "Brimvault";

/// The word the origin host's sanitizer NER flags as a PERSON at 0.6: a
/// lowercase vocabulary surname, dropped only in harness-static text (L98).
pub const ORIGIN_WORD: &str = "rust";
/// The word the origin host's verifier NER flags as a PERSON at 0.99:
/// accepted only in harness-static text (L103).
pub const ORIGIN_PRODUCT: &str = "Claude";

/// [`CFG`] with both NER roles named (sections are never loaded: the fake
/// host hands the engine its detectors), so the engine has a sanitizer NER
/// and an independent verifier NER, as `support-email` does.
pub const CFG_NER: &str = r#"
    [ner.gliner]
    model = "m"
    threshold = 0.5
    labels = [ { label = "person", kind = "PERSON" } ]
    [ner.token_classifier]
    model = "t"
    threshold = 0.5
    labels = [ { label = "PER", kind = "PERSON" } ]
    [profiles.fast]
    default_action = "tokenize"
    default_min_confidence = 0.5
    escalate_below = 0.5
    ner_sanitizer = "gliner"
    ner_verifier = "token_classifier"
    [profiles.fast.entities.DATE]
    action = "preserve"
    min_confidence = 0.0
    [profiles.fast.entities.URL]
    action = "preserve"
    min_confidence = 0.0
    [profiles.fast.entities.SECRET]
    action = "remove"
    min_confidence = 0.0
    [profiles.fast.entities.FORBIDDEN]
    action = "block"
    min_confidence = 0.0
    [profiles.fast.verifier]
    on_uncertain = "block"
"#;

/// A fake NER model that counts its calls, split at [`STATIC_MIN_BYTES`]
/// (only the long calls are ones the memo could serve). It flags every
/// [`MEMO_NAME`], and [`MEMO_V`] right after `Mr. `, as a PERSON, and
/// [`MEMO_FORBIDDEN`] as `FORBIDDEN`; with
/// `fail` set it fails like a broken model on the long inputs (so a short
/// leaf of the same request cannot fail first).
#[derive(Default)]
pub struct CountingNer {
    pub long: AtomicUsize,
    pub short: AtomicUsize,
    pub fail: AtomicBool,
}

impl CountingNer {
    /// Calls on inputs of at least [`STATIC_MIN_BYTES`].
    pub fn long(&self) -> usize {
        self.long.load(Ordering::SeqCst)
    }
    /// Every call.
    pub fn calls(&self) -> usize {
        self.long() + self.short.load(Ordering::SeqCst)
    }
}

impl Detector for CountingNer {
    fn id(&self) -> DetectorId {
        DetectorId::Ner
    }
    fn detect(&self, text: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        if text.len() >= STATIC_MIN_BYTES {
            self.long.fetch_add(1, Ordering::SeqCst);
        } else {
            self.short.fetch_add(1, Ordering::SeqCst);
        }
        if self.fail.load(Ordering::SeqCst) && text.len() >= STATIC_MIN_BYTES {
            return Err(inumaki_core::Error::ModelUnavailable("test".into()));
        }
        let person =
            |i: usize, len: usize| Span::new(i, i + len, EntityKind::Person, 0.95, DetectorId::Ner);
        let mut out: Vec<Span> = text
            .match_indices(MEMO_NAME)
            .map(|(i, w)| person(i, w.len()))
            .collect();
        let mr = format!("Mr. {MEMO_V}");
        out.extend(
            text.match_indices(mr.as_str())
                .map(|(i, _)| person(i + 4, MEMO_V.len())),
        );
        out.extend(text.match_indices(MEMO_FORBIDDEN).map(|(i, w)| {
            Span::new(
                i,
                i + w.len(),
                EntityKind::custom("FORBIDDEN"),
                0.95,
                DetectorId::Ner,
            )
        }));
        out.sort_by_key(|s| s.start);
        Ok(out)
    }
}

/// The fake host's NER models and its two engines (the memo tests).
pub struct NerFake {
    /// The sanitizer role's model.
    pub sanitizer: Arc<CountingNer>,
    /// The verifier role's model.
    pub verifier: Arc<CountingNer>,
    /// `engine_unmemoized`: the same configuration, the models unwrapped.
    pub plain: Arc<Engine>,
}

/// Which engine the fake host hands out (review I1, I2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    /// "Grauzone" is a PERSON at low confidence under `on_uncertain = "pass"`: `PassUncertain`.
    Uncertain,
    /// "Sperrwort" is a PERSON the policy blocks: `Blocked` by the policy.
    Block,
    /// Every text hits a detector error: `Blocked` with `CheckId::DetectorError`.
    DetectorError,
}

/// `Profile::action_for` escalates a span whose confidence is below the
/// kind's `min_confidence` and at or above `escalate_below`; so the
/// minimum sits above 0.3 and `escalate_below` below it.
const CFG_UNCERTAIN: &str = r#"
    [profiles.fast]
    default_action = "tokenize"
    default_min_confidence = 0.5
    escalate_below = 0.2
    [profiles.fast.entities.SECRET]
    action = "remove"
    min_confidence = 0.0
    [profiles.fast.verifier]
    on_uncertain = "pass"
    allow_no_ner = true
"#;

const CFG_BLOCK: &str = r#"
    [profiles.fast]
    default_action = "tokenize"
    default_min_confidence = 0.5
    escalate_below = 0.5
    [profiles.fast.entities.PERSON]
    action = "block"
    min_confidence = 0.0
    [profiles.fast.entities.SECRET]
    action = "remove"
    min_confidence = 0.0
    [profiles.fast.verifier]
    on_uncertain = "block"
    allow_no_ner = true
"#;

fn build(cfg: &str, d: Word) -> Arc<Engine> {
    let cfg = CoreConfig::from_toml(cfg).unwrap();
    Arc::new(
        Engine::from_config(&cfg, "fast", None, None)
            .unwrap()
            .with_detector(Arc::new(d)),
    )
}

/// The dataset content a stored dictionary was built from:
/// `(token, kind label, original)`, sorted.
pub type DictKey = Vec<(String, String, String)>;

pub struct FakeHost {
    pub mode: Mutex<Mode>,
    pub engine: Arc<Engine>,
    pub policy: Arc<Profile>,
    pub dataset: Mutex<HashMap<String, (EntityKind, String)>>, // token → (kind, original)
    /// The dictionary `dictionary()` returns, with the dataset content it
    /// was built from: the same `Arc` until that content changes (P2), or
    /// until [`FakeHost::set_dictionary`] swaps it.
    pub dict_arc: Mutex<Option<(DictKey, Arc<dyn Detector>)>>,
    /// The static-prompt NER memo `ner_memo()` returns.
    pub memo: Option<Arc<NerMemo>>,
    /// NER models and the unwrapped engine (hosts built by `with_ner`).
    pub ner: Option<NerFake>,
    /// When set, the next `dictionary()` read still returns the stored
    /// dictionary, then a fresh `Arc` of the same content replaces it: the
    /// request that read it holds a dictionary that is no longer current
    /// (a change while it is in flight).
    pub swap_after_next_read: AtomicBool,
    /// The check dataset [`CHECK_DS`]: token → (kind, original).
    pub check: Mutex<HashMap<String, (EntityKind, String)>>,
    pub identity: Vec<(EntityKind, String)>,
    pub events: Mutex<Vec<ProxyEvent>>,
    pub fail_engine: Mutex<bool>,
    pub fail_vault: Mutex<bool>,
    pub resolve_calls: Mutex<usize>,
    /// SHA-256 digests of blocks another front door released (spec §14).
    pub released: Mutex<Vec<[u8; 32]>>,
}

impl FakeHost {
    pub fn new() -> Arc<FakeHost> {
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let engine = Arc::new(Engine::from_config(&cfg, "fast", None, None).unwrap());
        let policy = Arc::new(cfg.resolve_profile("fast").unwrap());
        let mut ds = HashMap::new();
        ds.insert(DS_TOKEN.to_string(), (EntityKind::Person, NAME.to_string()));
        let mut check = HashMap::new();
        check.insert(
            CHECK_TOKEN.to_string(),
            (EntityKind::Person, CHECK_NAME.to_string()),
        );
        check.insert(
            CHECK_EMAIL_TOKEN.to_string(),
            (EntityKind::Email, CHECK_EMAIL.to_string()),
        );
        Arc::new(FakeHost {
            mode: Mutex::new(Mode::Normal),
            engine,
            policy,
            dataset: Mutex::new(ds),
            dict_arc: Mutex::new(None),
            memo: None,
            ner: None,
            swap_after_next_read: AtomicBool::new(false),
            check: Mutex::new(check),
            identity: Vec::new(),
            events: Mutex::new(Vec::new()),
            fail_engine: Mutex::new(false),
            fail_vault: Mutex::new(false),
            resolve_calls: Mutex::new(0),
            released: Mutex::new(Vec::new()),
        })
    }
    /// A host whose engine has counting NER models in both roles
    /// ([`CFG_NER`]); with `memo`, a static-prompt memo wraps them in
    /// `engine()`, and `engine_unmemoized()` returns the unwrapped twin.
    pub fn with_ner(memo: bool) -> Arc<FakeHost> {
        let mut h = Arc::into_inner(FakeHost::new()).unwrap();
        let cfg = CoreConfig::from_toml(CFG_NER).unwrap();
        let sanitizer = Arc::new(CountingNer::default());
        let verifier = Arc::new(CountingNer::default());
        let s: Arc<dyn Detector> = sanitizer.clone();
        let v: Arc<dyn Detector> = verifier.clone();
        let build = |s: Arc<dyn Detector>, v: Arc<dyn Detector>| {
            Arc::new(Engine::from_config(&cfg, "fast", Some(s), Some(v)).unwrap())
        };
        let plain = build(Arc::clone(&s), Arc::clone(&v));
        h.memo =
            memo.then(|| NerMemo::new("fast", [0; 32], STATIC_MEMO_ENTRIES, STATIC_MEMO_BYTES));
        h.engine = match &h.memo {
            Some(m) => build(m.wrap(s, NerRole::Sanitizer), m.wrap(v, NerRole::Verifier)),
            None => Arc::clone(&plain),
        };
        h.policy = Arc::new(cfg.resolve_profile("fast").unwrap());
        h.ner = Some(NerFake {
            sanitizer,
            verifier,
            plain,
        });
        Arc::new(h)
    }
    /// A host whose engine reads the text origin: [`CFG_NER`] with
    /// `Word(ORIGIN_WORD, Some(0.6))` as the sanitizer NER and
    /// `Word(ORIGIN_PRODUCT, Some(0.99))` as the verifier NER. No memo.
    pub fn with_origin_ner() -> Arc<FakeHost> {
        let mut h = Arc::into_inner(FakeHost::new()).unwrap();
        let cfg = CoreConfig::from_toml(CFG_NER).unwrap();
        let s: Arc<dyn Detector> = Arc::new(Word(ORIGIN_WORD, Some(0.6)));
        let v: Arc<dyn Detector> = Arc::new(Word(ORIGIN_PRODUCT, Some(0.99)));
        h.engine = Arc::new(Engine::from_config(&cfg, "fast", Some(s), Some(v)).unwrap());
        h.policy = Arc::new(cfg.resolve_profile("fast").unwrap());
        h.memo = None;
        h.ner = None;
        Arc::new(h)
    }
    /// Replace the dictionary `dictionary()` returns by `d` (a dictionary
    /// change, P2), kept until the dataset content changes.
    pub fn set_dictionary(&self, d: Arc<dyn Detector>) {
        *self.dict_arc.lock().unwrap() = Some((self.dict_key(), d));
    }
    /// The dataset content, sorted: what the stored dictionary was built from.
    fn dict_key(&self) -> DictKey {
        let mut k: DictKey = self
            .dataset
            .lock()
            .unwrap()
            .iter()
            .map(|(t, (kind, v))| (t.clone(), kind.label().to_string(), v.clone()))
            .collect();
        k.sort();
        k
    }
    pub fn with_identity(name: &str, email: &str) -> Arc<FakeHost> {
        let mut h = Arc::into_inner(FakeHost::new()).unwrap();
        h.identity = vec![
            (EntityKind::Person, name.into()),
            (EntityKind::Email, email.into()),
        ];
        Arc::new(h)
    }
    /// Record `text` as released by another front door (its SHA-256).
    pub fn release(&self, text: &str) {
        use sha2::Digest;
        self.released
            .lock()
            .unwrap()
            .push(sha2::Sha256::digest(text.as_bytes()).into());
    }
    pub fn forget(&self, token: &str) {
        self.dataset.lock().unwrap().remove(token);
    }
    fn dict(&self) -> DictionaryDetector {
        DictionaryDetector::from_entries(
            self.dataset
                .lock()
                .unwrap()
                .values()
                .map(|(k, v)| (k.clone(), v.clone())),
        )
        .unwrap()
    }
}

impl ProxyHost for FakeHost {
    fn engine(&self, _: &str) -> Result<Arc<Engine>, HostError> {
        if *self.fail_engine.lock().unwrap() {
            return Err(HostError::ModelUnavailable);
        }
        Ok(match *self.mode.lock().unwrap() {
            Mode::Normal => Arc::clone(&self.engine),
            Mode::Uncertain => build(CFG_UNCERTAIN, Word("Grauzone", Some(0.3))),
            Mode::Block => build(CFG_BLOCK, Word("Sperrwort", Some(0.95))),
            Mode::DetectorError => build(CFG, Word("x", None)),
        })
    }
    fn policy(&self, _: &str) -> Result<Arc<Profile>, HostError> {
        Ok(Arc::clone(&self.policy))
    }
    /// The same `Arc` until the dataset content changes (P2).
    fn dictionary(&self) -> Result<Arc<dyn Detector>, HostError> {
        let key = self.dict_key();
        let mut slot = self.dict_arc.lock().unwrap();
        let d = match slot.as_ref() {
            Some((k, d)) if *k == key => Arc::clone(d),
            _ => {
                let d: Arc<dyn Detector> = Arc::new(self.dict());
                *slot = Some((key.clone(), Arc::clone(&d)));
                d
            }
        };
        if self.swap_after_next_read.swap(false, Ordering::SeqCst) {
            *slot = Some((key, Arc::new(self.dict())));
        }
        Ok(d)
    }
    fn ner_memo(&self) -> Option<Arc<NerMemo>> {
        self.memo.clone()
    }
    /// The unwrapped twin for a `with_ner` host in `Mode::Normal`; else
    /// `engine()`, which wraps nothing on other hosts.
    fn engine_unmemoized(&self, p: &str) -> Result<Arc<Engine>, HostError> {
        match &self.ner {
            Some(n) if *self.mode.lock().unwrap() == Mode::Normal => {
                if *self.fail_engine.lock().unwrap() {
                    return Err(HostError::ModelUnavailable);
                }
                Ok(Arc::clone(&n.plain))
            }
            _ => self.engine(p),
        }
    }
    /// One row per kind found, for the one fake dataset `ds`.
    fn scan_known(&self, texts: &[String]) -> Result<Vec<(String, EntityKind, u32)>, HostError> {
        let d = self.dict();
        let mut rows: Vec<(String, EntityKind, u32)> = Vec::new();
        for t in texts {
            for s in d
                .detect(t, &DetectCtx::for_text(t))
                .map_err(|_| HostError::Internal)?
            {
                match rows.iter_mut().find(|r| r.1 == s.kind) {
                    Some(r) => r.2 += 1,
                    None => rows.push(("ds".into(), s.kind, 1)),
                }
            }
        }
        Ok(rows)
    }
    fn identity(&self) -> Vec<(EntityKind, Zeroizing<String>)> {
        self.identity
            .iter()
            .map(|(k, v)| (k.clone(), Zeroizing::new(v.clone())))
            .collect()
    }
    /// Matches case-insensitively, like the vault; returns the canonical original.
    fn dataset_token(
        &self,
        kind: &EntityKind,
        value: &str,
    ) -> Result<Option<(String, Zeroizing<String>)>, HostError> {
        if *self.fail_vault.lock().unwrap() {
            return Err(HostError::VaultUnavailable);
        }
        Ok(self
            .dataset
            .lock()
            .unwrap()
            .iter()
            .find(|(_, (k, v))| k == kind && v.eq_ignore_ascii_case(value))
            .map(|(t, (_, v))| (t.clone(), Zeroizing::new(v.clone()))))
    }
    /// Scope-aware: normal routes see "ds", a check route only its dataset.
    fn resolve(
        &self,
        tokens: &[String],
        scope: &Scope,
    ) -> Result<Vec<(String, EntityKind, Zeroizing<String>)>, HostError> {
        if *self.fail_vault.lock().unwrap() {
            return Err(HostError::VaultUnavailable);
        }
        *self.resolve_calls.lock().unwrap() += 1;
        let map = match scope {
            Scope::Datasets => self.dataset.lock().unwrap().clone(),
            Scope::Check(ds) if ds == CHECK_DS => self.check.lock().unwrap().clone(),
            Scope::Check(_) => HashMap::new(),
        };
        Ok(tokens
            .iter()
            .filter_map(|t| {
                map.get(t)
                    .map(|(k, v)| (t.clone(), k.clone(), Zeroizing::new(v.clone())))
            })
            .collect())
    }
    fn released(&self, d: &[u8; 32]) -> bool {
        self.released.lock().unwrap().contains(d)
    }
    fn scan_definitions(&self, texts: &[String]) -> Result<Vec<(EntityKind, u32)>, HostError> {
        let hits: u32 = texts
            .iter()
            .filter(|t| t.contains(NAME) || t.contains(EMAIL))
            .count() as u32;
        Ok(if hits > 0 {
            vec![(EntityKind::Person, hits)]
        } else {
            vec![]
        })
    }
    /// The check dataset: its known values become its tokens; `BLOCK-ME` is blocked.
    fn sanitize_dataset(&self, ds: &str, blocks: Vec<String>) -> Result<Vec<HostBlock>, HostError> {
        if ds != CHECK_DS {
            return Err(HostError::VaultUnavailable);
        }
        let check = self.check.lock().unwrap();
        Ok(blocks
            .into_iter()
            .map(|t| {
                if t.contains("BLOCK-ME") {
                    return HostBlock {
                        text: String::new(),
                        blocked: true,
                        uncertain: false,
                        kinds: vec![EntityKind::Person],
                        checks: vec!["Leak".into()],
                    };
                }
                let (mut text, mut kinds) = (t, Vec::new());
                for (tok, (k, v)) in check.iter() {
                    if text.contains(v.as_str()) {
                        text = text.replace(v.as_str(), tok);
                        kinds.push(k.clone());
                    }
                }
                HostBlock {
                    text,
                    blocked: false,
                    uncertain: false,
                    kinds,
                    checks: Vec::new(),
                }
            })
            .collect())
    }
    fn record(&self, e: ProxyEvent) {
        self.events.lock().unwrap().push(e);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use inumaki_core::config::TokenSettings;
    use inumaki_core::engine::Outcome;
    use inumaki_core::token::{Context, ContextId};

    use super::*;

    /// Later tasks rely on each mode's verdict; pin them here.
    #[test]
    fn fake_modes_yield_their_verdicts() {
        let host = FakeHost::new();
        let run = |mode: Mode, text: &str| {
            *host.mode.lock().unwrap() = mode;
            let mut c = Context::new(
                ContextId(String::new()),
                Duration::from_secs(60),
                TokenSettings::default(),
            );
            host.engine("fast").unwrap().process(text, &mut c).unwrap()
        };
        assert!(matches!(
            run(Mode::Normal, "hello there"),
            Outcome::Pass { .. }
        ));
        assert!(matches!(
            run(Mode::Uncertain, "ask Grauzone today"),
            Outcome::PassUncertain { .. }
        ));
        assert!(matches!(
            run(Mode::Block, "ask Sperrwort today"),
            Outcome::Blocked { .. }
        ));
        assert!(matches!(
            run(Mode::DetectorError, "anything"),
            Outcome::Blocked { .. }
        ));
    }
}
