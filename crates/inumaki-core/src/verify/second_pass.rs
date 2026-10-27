//! Deterministic second pass: leak check, regex re-scan, home-folder login
//! check (ruling L127, `verify::home_login`), independent NER re-scan,
//! combination heuristic.
//!
//! In a text the caller marks harness-static, the NER re-scan does not fail on
//! a hit that is exactly a listed product name (ruling L103).

use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::ops::Range;
use std::sync::{Arc, LazyLock};

use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;
use zeroize::Zeroizing;

use super::{CheckId, Reason, Verdict, Verifier};
use crate::collapse::{Collapsed, collapse_pattern};
use crate::config::TokenSettings;
use crate::detect::dictionary::word_bounded;
use crate::detect::plausible::is_greeting_only_value;
use crate::detect::regex::RegexDetector;
use crate::detect::{DetectCtx, Detector, validate_span};
use crate::origin::TextOrigin;
use crate::policy::{Action, VerifierSettings};
use crate::sanitize::Sanitized;
use crate::span::{EntityKind, Span};
use crate::stoplist::{is_role_or_label_word, is_salutation_word, name_parts};
use crate::token::TokenStore;
use crate::{Error, Result};

/// Minimum length, in characters, of a full original or removed value used
/// as a leak pattern. Shorter values would match too much ordinary text.
const MIN_ORIGINAL_CHARS: usize = 3;
/// Minimum length, in characters, of a single person name part used as a
/// leak pattern (together with the common-word stoplist).
const MIN_NAME_PART_CHARS: usize = 4;

/// v1 verifier. See module docs.
pub struct SecondPassVerifier {
    regex: RegexDetector,
    ner: Option<Arc<dyn Detector>>,
    combination_threshold: usize,
}

impl std::fmt::Debug for SecondPassVerifier {
    /// Hand-written: `dyn Detector` carries no `Debug` bound, and this never
    /// prints text in any case.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecondPassVerifier")
            .field("has_ner", &self.ner.is_some())
            .field("combination_threshold", &self.combination_threshold)
            .finish()
    }
}

/// ASCII transliteration of German umlauts and `ß`. The proxy's leak closure
/// uses this; one definition, so they cannot drift.
pub fn transliterate(s: &str) -> String {
    s.replace('ä', "ae")
        .replace('ö', "oe")
        .replace('ü', "ue")
        .replace('ß', "ss")
        .replace('Ä', "Ae")
        .replace('Ö', "Oe")
        .replace('Ü', "Ue")
}

/// NFC form. Engine input is NFC already; this covers originals a caller
/// put into the context directly.
fn nfc(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    s.nfc().collect()
}

/// Strip combining marks after NFD. The proxy's leak closure uses this; one
/// definition, so they cannot drift.
pub fn fold_diacritics(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    use unicode_normalization::char::is_combining_mark;
    s.nfd().filter(|c| !is_combining_mark(*c)).collect()
}

/// `sanitized.text` with every `Tokenize` replacement's random hex suffix
/// overwritten with `x` characters, same length.
///
/// A token's suffix (`<PERSON_a7f2>`'s `a7f2`) is opaque and per-context
/// random by design (spec: tokens are "opaque, random, per-context"). The
/// regex and NER re-scans below exist to judge whether the *candidate text*
/// is safe to send, not to react to which random hex a token happened to
/// get this run — a token is never itself a leak (`is_inside_token`/
/// `is_exempt` already treat any `Tokenize` output range as handled). But an
/// NER model has no notion of "this run of hex is exempt": it scores
/// whatever bytes are in front of it, so two sanitizations of the same
/// input that differ only in their tokens' random suffixes can get
/// different verdicts from a model that is otherwise deterministic. That
/// breaks both determinism of `verify()` for identical input and the eval
/// gate's baseline (`inumaki eval`), which must be reproducible. Masking the
/// suffix to a fixed filler removes that source of variance while leaving
/// every byte offset — and so every `is_exempt`/`is_inside_token` check made
/// against the unmasked `sanitized` — unchanged, since the replacement is
/// the same length. The leak check runs on the original, unmasked text
/// instead: it never treats a token's own text as a leak hit in the first
/// place, so masking would only cost precision there for no benefit.
///
/// Protected tokens (`sanitized.protected`, M8 spec decision 11) are masked
/// the same way: they were in the input already and resolve in the store,
/// so they are tokens, not text to judge. The surface component of a
/// surface-form token is random too and is masked with the suffix.
fn mask_token_suffixes(sanitized: &Sanitized, settings: &TokenSettings) -> String {
    let mut text = sanitized.text.clone();
    for r in &sanitized.replacements {
        if r.action == Action::Tokenize {
            crate::protect::mask_token(&mut text, r.out_range.clone(), settings);
        }
    }
    for r in &sanitized.protected {
        crate::protect::mask_token(&mut text, r.clone(), settings);
    }
    // Callers apply offsets found in the masked text to `sanitized.text`;
    // that holds only while masking keeps the byte length (lengths only in
    // the message, never text).
    debug_assert_eq!(
        text.len(),
        sanitized.text.len(),
        "token masking must keep the byte length"
    );
    text
}

/// The leak patterns of one store value, passed to `push` as
/// `(form, kind, minimum characters)` before whitespace collapse and case
/// variants ([`leak_variants`]). An entry yields its original, its NFC,
/// transliterated, and diacritic-folded forms, and for a PERSON each name
/// part in the same forms; a greeting-only entry yields nothing (Task 7d).
/// A removed value yields itself and itself without a trailing sentence
/// mark. One definition for [`SecondPassVerifier::leak_patterns`] and
/// [`LeakLayer::build`], so they cannot drift.
fn push_leak_forms(
    kind: &EntityKind,
    value: &str,
    removed: bool,
    push: &mut dyn FnMut(&str, &EntityKind, usize),
) {
    if removed {
        // Removed values (secrets) are never rehydrated, but another copy of
        // one must not be sent either. A trailing sentence punctuation
        // variant covers a rule that captured the `.` ending the sentence.
        push(value, kind, MIN_ORIGINAL_CHARS);
        push(
            value.trim_end_matches(['.', ',', ';', ':', '!', '?', ')']),
            kind,
            MIN_ORIGINAL_CHARS,
        );
        return;
    }
    // Task 7d (ruling L56): a whole stored value that is only
    // greeting vocabulary (`Hello`, `Best`) identifies no one, so a
    // later clear copy of it is no leak. `Hallo Anna` still is.
    if is_greeting_only_value(kind, value) {
        return;
    }
    push(value, kind, MIN_ORIGINAL_CHARS);
    for v in [
        Zeroizing::new(nfc(value)),
        Zeroizing::new(transliterate(value)),
        Zeroizing::new(fold_diacritics(value)),
    ] {
        push(&v, kind, MIN_ORIGINAL_CHARS);
    }
    if *kind == EntityKind::Person {
        for part in name_parts(value) {
            push(part, kind, MIN_NAME_PART_CHARS);
            // Exact NFC leg, independent of the shared normalizers.
            push(&Zeroizing::new(nfc(part)), kind, MIN_NAME_PART_CHARS);
            push(
                &Zeroizing::new(transliterate(part)),
                kind,
                MIN_NAME_PART_CHARS,
            );
            push(
                &Zeroizing::new(fold_diacritics(part)),
                kind,
                MIN_NAME_PART_CHARS,
            );
        }
    }
}

/// The searched patterns of one form: whitespace-collapsed, then as is,
/// `to_lowercase()` and `to_uppercase()` (`ascii_case_insensitive` does not
/// fold non-ASCII case pairs such as `Ü`/`ü`); nothing below `min_chars`.
fn leak_variants(form: &str, min_chars: usize, mut f: impl FnMut(Zeroizing<String>)) {
    // The candidate is searched in whitespace-collapsed form.
    let s = Zeroizing::new(collapse_pattern(form));
    if s.chars().count() < min_chars {
        return;
    }
    for variant in [
        Zeroizing::new(s.to_string()),
        Zeroizing::new(s.to_lowercase()),
        Zeroizing::new(s.to_uppercase()),
    ] {
        f(variant);
    }
}

/// Process-wide count of leak checks whose store-owned index did not cover
/// the store and fell back to the per-call build (Task 5, Q1). A count only.
static LEAK_INDEX_STALE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many leak checks found the store's index stale and built their own
/// patterns instead (Task 5, Q1): a write path that forgot to tell the
/// store's cache costs latency, never a leak. A count only.
pub fn leak_index_stale_count() -> u64 {
    LEAK_INDEX_STALE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Process-wide count of store leak indexes whose build failed (Task 5
/// review): the leak check then built its own patterns. A count only.
static LEAK_INDEX_FAILED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many store leak-index builds failed, each answered by the per-call
/// build instead: a persistent failure costs latency and shows here. A
/// count only.
pub fn leak_index_failed_count() -> u64 {
    LEAK_INDEX_FAILED.load(std::sync::atomic::Ordering::Relaxed)
}

/// `ctx`'s own leak index for this call ([`TokenStore::leak_index`]), or
/// `None` when the store keeps none or its build failed. A failure is
/// counted ([`leak_index_failed_count`]); the verifier then builds its own
/// patterns, never skipping the leak check.
pub fn store_leak_index(ctx: &mut dyn TokenStore) -> Option<LeakIndex> {
    match ctx.leak_index(None)? {
        Ok(idx) => Some(idx),
        Err(_) => {
            LEAK_INDEX_FAILED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
    }
}

#[cfg(test)]
thread_local! {
    /// [`leak_index_stale_count`] on this thread only (tests run in
    /// parallel; F17).
    static STALE_HERE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Test hook: stale leak indexes met on this thread.
#[cfg(test)]
pub(crate) fn stale_on_this_thread() -> u64 {
    STALE_HERE.with(std::cell::Cell::get)
}

/// One compiled set of leak patterns over a list of store values (Task 5,
/// Phase B): the patterns ([`push_leak_forms`], [`leak_variants`]), each
/// deduplicated within the layer, the store values ("owners") behind each
/// pattern, and one Aho-Corasick automaton (`Standard`,
/// `ascii_case_insensitive`, as the per-call check always built).
///
/// Owners are numbered from `first_ordinal`: the entries in order (an alias
/// variant shares its entry's number), then the removed values. Every
/// owner's keyed `(removed, kind, value)` hash is kept for
/// [`LeakIndex::covers`], whether or not it yields a pattern (F12).
///
/// Privacy: the patterns are originals, held in `Zeroizing`; the automaton
/// keeps its own copy of the pattern bytes, which cannot be wiped. A layer
/// lives in a store's [`StoreDictCache`](crate::consistency::StoreDictCache)
/// or within one call. `Debug` prints counts only.
pub struct LeakLayer {
    pats: Vec<Zeroizing<String>>,
    /// The first (lowest) owner of each pattern, by local owner index.
    owner: Vec<usize>,
    /// Further owners of a pattern several values share, ascending.
    more_owners: HashMap<usize, Vec<usize>>,
    /// Each local owner's kind.
    owner_kinds: Vec<EntityKind>,
    /// Local owners below this are entries; the rest removed values.
    entries: usize,
    first_ordinal: usize,
    /// Keyed `(removed, kind, value)` hash → local owners (the kind itself,
    /// not its label: `Custom("PERSON")` and `Person` never collide).
    by_hash: HashMap<u64, Vec<usize>>,
    ac: Option<AhoCorasick>,
}

impl std::fmt::Debug for LeakLayer {
    /// Counts only, never a pattern.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeakLayer")
            .field("patterns", &self.pats.len())
            .field("owners", &self.owner_kinds.len())
            .finish()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for LeakLayer {
    fn drop(&mut self) {
        crate::consistency::leak_layer_live(-1);
    }
}

impl LeakLayer {
    /// A layer over `entries` and `removed`, each value followed by its
    /// alias variants when `aliases` is given (what
    /// [`Aliased`](crate::alias::Aliased) reports for the same store), with
    /// owners numbered from `first_ordinal`.
    pub fn build<'a>(
        entries: impl Iterator<Item = (&'a EntityKind, &'a str)>,
        removed: impl Iterator<Item = (&'a EntityKind, &'a str)>,
        aliases: Option<&crate::alias::AliasTable>,
        first_ordinal: usize,
    ) -> crate::Result<LeakLayer> {
        #[cfg(any(test, feature = "test-support"))]
        crate::consistency::leak_build_counted();
        let key = crate::consistency::hash_key();
        let variants = |kind: &EntityKind, value: &str| -> &[String] {
            aliases.map_or(&[][..], |t| t.variants_of(kind, value))
        };
        let mut pats: Vec<Zeroizing<String>> = Vec::new();
        let mut owner: Vec<usize> = Vec::new();
        let mut more_owners: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut owner_kinds: Vec<EntityKind> = Vec::new();
        let mut by_hash: HashMap<u64, Vec<usize>> = HashMap::new();
        // Dedup index: hash of a pattern -> positions in `pats` with that
        // hash (compared by value on a hit). Holds no plaintext itself.
        let hasher = RandomState::new();
        let mut seen: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut add = |o: usize, kind: &EntityKind, value: &str, removed: bool| {
            let slot = by_hash
                .entry(key.hash_one((removed, kind, value)))
                .or_default();
            if slot.last() != Some(&o) {
                slot.push(o);
            }
            push_leak_forms(kind, value, removed, &mut |form, _, min_chars| {
                leak_variants(form, min_chars, |variant| {
                    let slot = seen.entry(hasher.hash_one(variant.as_str())).or_default();
                    match slot.iter().find(|&&i| pats[i].as_str() == variant.as_str()) {
                        Some(&i) => {
                            if owner[i] != o {
                                let more = more_owners.entry(i).or_default();
                                if more.last() != Some(&o) {
                                    more.push(o);
                                }
                            }
                        }
                        None => {
                            slot.push(pats.len());
                            pats.push(variant);
                            owner.push(o);
                        }
                    }
                });
            });
        };
        for (kind, value) in entries {
            let o = owner_kinds.len();
            owner_kinds.push(kind.clone());
            for v in std::iter::once(value).chain(variants(kind, value).iter().map(String::as_str))
            {
                add(o, kind, v, false);
            }
        }
        let n_entries = owner_kinds.len();
        for (kind, value) in removed {
            let o = owner_kinds.len();
            owner_kinds.push(kind.clone());
            for v in std::iter::once(value).chain(variants(kind, value).iter().map(String::as_str))
            {
                add(o, kind, v, true);
            }
        }
        let ac = if pats.is_empty() {
            None
        } else {
            // `Standard` + `find_overlapping_iter`: see `LeakIndex::reasons`.
            Some(
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::Standard)
                    .build(pats.iter().map(|p| p.as_bytes()))
                    .map_err(|_| Error::ConfigInvalid("leak patterns".into()))?,
            )
        };
        #[cfg(any(test, feature = "test-support"))]
        crate::consistency::leak_layer_live(1);
        Ok(LeakLayer {
            pats,
            owner,
            more_owners,
            owner_kinds,
            entries: n_entries,
            first_ordinal,
            by_hash,
            ac,
        })
    }

    /// The ordinal after this layer's last owner.
    pub fn end_ordinal(&self) -> usize {
        self.first_ordinal + self.owner_kinds.len()
    }

    /// Every local owner of pattern `p`, ascending.
    fn owners_of(&self, p: usize) -> impl Iterator<Item = usize> + '_ {
        std::iter::once(self.owner[p])
            .chain(self.more_owners.get(&p).into_iter().flatten().copied())
    }

    /// Fresh-build order of a local owner: every entry before every
    /// removed value (as the per-call build pushes them), then by ordinal.
    fn rank(&self, o: usize) -> (bool, usize) {
        (o >= self.entries, self.first_ordinal + o)
    }
}

/// A store's leak patterns as layers (Task 5, Phase B): the layers with
/// their automata, the base layer's dead entries (a working set's LRU
/// evictions since the base was built, by ordinal), and the owners' keyed
/// hashes for the freshness check. Built from a store's own cache
/// ([`TokenStore::leak_index`]) or per call; held only within a call (it
/// keeps `Arc`s of the cache's layers, which must not outlive the cache's
/// `clear()`). `Debug`: pattern and layer counts.
pub struct LeakIndex {
    layers: Vec<Arc<LeakLayer>>,
    /// Owners of `layers[0]` no longer in the store (by ordinal).
    dead: Arc<std::collections::HashSet<usize>>,
}

impl std::fmt::Debug for LeakIndex {
    /// Counts only, never a pattern.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeakIndex")
            .field(
                "patterns",
                &self.layers.iter().map(|l| l.pats.len()).sum::<usize>(),
            )
            .field("layers", &self.layers.len())
            .field("dead", &self.dead.len())
            .finish()
    }
}

impl LeakIndex {
    /// `layers` (the first one's dead owners `dead`).
    pub(crate) fn new(
        layers: Vec<Arc<LeakLayer>>,
        dead: Arc<std::collections::HashSet<usize>>,
    ) -> LeakIndex {
        LeakIndex { layers, dead }
    }

    /// One layer built for this call (the per-call path).
    pub(crate) fn single(layer: LeakLayer) -> LeakIndex {
        LeakIndex::new(vec![Arc::new(layer)], Arc::default())
    }

    /// This index plus `layer`: values a store view holds beside the store
    /// it caches for (the proxy's request-scoped dataset values).
    pub fn with_layer(mut self, layer: Arc<LeakLayer>) -> LeakIndex {
        self.layers.push(layer);
        self
    }

    /// Number of layers.
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// The ordinal after the last owner of every layer.
    pub fn end_ordinal(&self) -> usize {
        self.layers
            .iter()
            .map(|l| l.end_ordinal())
            .max()
            .unwrap_or(0)
    }

    /// Whether local owner `o` of layer `l` is still in the store.
    fn live(&self, l: usize, layer: &LeakLayer, o: usize) -> bool {
        l != 0 || self.dead.is_empty() || !self.dead.contains(&(layer.first_ordinal + o))
    }

    /// Whether every entry and removed value of `ctx` has a live owner here
    /// (Q1): one keyed hash lookup per value, no pattern building. A miss
    /// means the store changed without telling its cache.
    pub fn covers(&self, ctx: &dyn TokenStore) -> bool {
        let key = crate::consistency::hash_key();
        let has = |removed: bool, kind: &EntityKind, value: &str| {
            let h = key.hash_one((removed, kind, value));
            self.layers.iter().enumerate().any(|(l, layer)| {
                layer
                    .by_hash
                    .get(&h)
                    .is_some_and(|os| os.iter().any(|&o| self.live(l, layer, o)))
            })
        };
        ctx.entries().all(|(k, v)| has(false, k, v))
            && ctx.removed_entries().all(|(k, v)| has(true, k, v))
    }

    /// The `Leak` reasons for `s`, one per kind, sorted by (first match
    /// start, end, kind label) (Q3).
    ///
    /// Every layer is searched with `find_overlapping_iter` over the
    /// whitespace-collapsed view (any whitespace run in the candidate
    /// matches a single space in a pattern). `Standard` +
    /// `find_overlapping_iter` (rather than `LeftmostLongest` + `find_iter`)
    /// so that when the longest match at a position is rejected (e.g.
    /// "Sarah Leitner" inside "Sarah Leitners", rejected for failing
    /// `word_bounded`), shorter or later-starting patterns whose bytes it
    /// would otherwise have consumed are still examined. A match counts when
    /// it is word-bounded, outside every token, and its pattern has a live
    /// owner. The same pattern string at the same span is one match across
    /// layers, attributed to its lowest live owner in fresh-build order
    /// (Q4), so a value two layers share is reported under the kind a fresh
    /// build reports.
    pub fn reasons(&self, s: &Sanitized) -> Vec<Reason> {
        let view = Collapsed::new(&s.text);
        let t = view.text();
        // (start, end, pattern) -> (rank of the lowest live owner, its kind)
        type Hits<'a> = HashMap<(usize, usize, &'a str), ((bool, usize), &'a EntityKind)>;
        let mut hits: Hits<'_> = HashMap::new();
        for (l, layer) in self.layers.iter().enumerate() {
            let Some(ac) = &layer.ac else { continue };
            for m in ac.find_overlapping_iter(t) {
                let (a, b) = (m.start(), m.end());
                if !t.is_char_boundary(a) || !t.is_char_boundary(b) {
                    continue;
                }
                if !word_bounded(t, a, b) {
                    continue;
                }
                if s.is_inside_token(view.to_original(a), view.to_original(b)) {
                    continue;
                }
                let p = m.pattern().as_usize();
                let Some(o) = layer
                    .owners_of(p)
                    .filter(|&o| self.live(l, layer, o))
                    .min_by_key(|&o| layer.rank(o))
                else {
                    continue;
                };
                let hit = (layer.rank(o), &layer.owner_kinds[o]);
                hits.entry((a, b, layer.pats[p].as_str()))
                    .and_modify(|h| {
                        if hit.0 < h.0 {
                            *h = hit;
                        }
                    })
                    .or_insert(hit);
            }
        }
        // One reason per leaked kind, at its first match.
        let mut first: HashMap<&EntityKind, (usize, usize)> = HashMap::new();
        for ((a, b, _), (_, kind)) in hits {
            first
                .entry(kind)
                .and_modify(|at| *at = (*at).min((a, b)))
                .or_insert((a, b));
        }
        let mut by_pos: Vec<((usize, usize), &EntityKind)> =
            first.into_iter().map(|(k, at)| (at, k)).collect();
        by_pos.sort_by(|x, y| (x.0, x.1.label()).cmp(&(y.0, y.1.label())));
        by_pos
            .into_iter()
            .map(|(_, kind)| Reason {
                kind: kind.clone(),
                check: CheckId::Leak,
            })
            .collect()
    }
}

/// Today's leak check (before Task 5), kept for the equality tests and the
/// `leak-crosscheck` build (F8): `leak_patterns` and one automaton per
/// call, reasons in match order.
#[cfg(any(test, feature = "leak-crosscheck"))]
pub(crate) fn legacy_check_leak(s: &Sanitized, ctx: &dyn TokenStore) -> Vec<Reason> {
    LegacyLeak::build(ctx).check(s)
}

/// [`legacy_check_leak`]'s patterns and automaton, built once (tests
/// search many probes with one build).
#[cfg(any(test, feature = "leak-crosscheck"))]
pub(crate) struct LegacyLeak {
    kinds: Vec<EntityKind>,
    ac: Option<AhoCorasick>,
}

#[cfg(any(test, feature = "leak-crosscheck"))]
impl LegacyLeak {
    pub(crate) fn build(ctx: &dyn TokenStore) -> LegacyLeak {
        let (pats, kinds) = SecondPassVerifier::leak_patterns(ctx);
        if pats.is_empty() {
            return LegacyLeak { kinds, ac: None };
        }
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(pats.iter().map(|p| p.as_bytes()))
            .expect("patterns are plain strings");
        LegacyLeak {
            kinds,
            ac: Some(ac),
        }
    }

    pub(crate) fn check(&self, s: &Sanitized) -> Vec<Reason> {
        let Some(ac) = &self.ac else {
            return Vec::new();
        };
        let kinds = &self.kinds;
        let view = Collapsed::new(&s.text);
        let t = view.text();
        let mut reasons = Vec::new();
        let mut seen: std::collections::HashSet<EntityKind> = std::collections::HashSet::new();
        for m in ac.find_overlapping_iter(t) {
            let (a, b) = (m.start(), m.end());
            if !t.is_char_boundary(a) || !t.is_char_boundary(b) {
                continue;
            }
            if !word_bounded(t, a, b) {
                continue;
            }
            if s.is_inside_token(view.to_original(a), view.to_original(b)) {
                continue;
            }
            let kind = kinds[m.pattern().as_usize()].clone();
            if seen.insert(kind.clone()) {
                reasons.push(Reason {
                    kind,
                    check: CheckId::Leak,
                });
            }
        }
        reasons
    }
}

/// `leak-crosscheck` builds (Step 6, F14): compare the leak reasons with
/// today's check by verdict (leak or not) and kind set; each difference is
/// one stderr line with kind labels only, never text.
#[cfg(feature = "leak-crosscheck")]
#[allow(clippy::print_stderr)]
fn crosscheck(reasons: &[Reason], s: &Sanitized, ctx: &dyn TokenStore) {
    let legacy = legacy_check_leak(s, ctx);
    let set = |r: &[Reason]| -> std::collections::BTreeSet<String> {
        r.iter().map(|x| x.kind.label().to_string()).collect()
    };
    if reasons.is_empty() != legacy.is_empty() || set(reasons) != set(&legacy) {
        eprintln!(
            "leak-crosscheck: difference check=Leak index={:?} legacy={:?}",
            set(reasons),
            set(&legacy)
        );
    }
}

impl SecondPassVerifier {
    /// Build. Without an NER detector, `settings.allow_no_ner` must be true.
    pub fn new(
        regex: RegexDetector,
        ner: Option<Arc<dyn Detector>>,
        settings: &VerifierSettings,
    ) -> Result<Self> {
        if ner.is_none() && !settings.allow_no_ner {
            return Err(Error::ModelUnavailable("ner".into()));
        }
        Ok(SecondPassVerifier {
            regex,
            ner,
            combination_threshold: settings.combination_threshold,
        })
    }

    /// Leak patterns and the kind each one belongs to. Full originals and
    /// removed values need at least [`MIN_ORIGINAL_CHARS`] characters, name
    /// parts [`MIN_NAME_PART_CHARS`]. For every base variant
    /// (original, transliterated, diacritic-folded, and — for persons — each
    /// name part's own variants, plus every value a `Remove` action took out) both `to_lowercase()` and `to_uppercase()`
    /// forms are added too, since `ascii_case_insensitive` does not fold
    /// non-ASCII case pairs such as `Ü`/`ü`. Patterns are deduplicated.
    ///
    /// Every returned pattern is plaintext-equivalent and zeroized on drop.
    pub fn leak_patterns(ctx: &dyn TokenStore) -> (Vec<Zeroizing<String>>, Vec<EntityKind>) {
        // Every pattern string (and every intermediate variant) is
        // plaintext-equivalent, so it lives in `Zeroizing` and is wiped on
        // drop. The Aho-Corasick automaton built from them in `check_leak`
        // keeps its own internal copy of the pattern bytes, which cannot be
        // wiped; it is dropped at the end of that call.
        let mut pats: Vec<Zeroizing<String>> = Vec::new();
        let mut kinds = Vec::new();
        // Dedup index: hash of a pattern -> positions in `pats` with that
        // hash (compared by value on a hit). Holds no plaintext itself.
        let hasher = RandomState::new();
        let mut seen: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut push = |s: &str, k: &EntityKind, min_chars: usize| {
            leak_variants(s, min_chars, |variant| {
                let slot = seen.entry(hasher.hash_one(variant.as_str())).or_default();
                if !slot.iter().any(|&i| pats[i].as_str() == variant.as_str()) {
                    slot.push(pats.len());
                    pats.push(variant);
                    kinds.push(k.clone());
                }
            });
        };
        for (kind, original) in ctx.entries() {
            push_leak_forms(kind, original, false, &mut push);
        }
        for (kind, removed) in ctx.removed_entries() {
            push_leak_forms(kind, removed, true, &mut push);
        }
        (pats, kinds)
    }

    /// The per-call leak check: one layer over `ctx`'s current values,
    /// built now (the store-less path, and the fallback when a store's
    /// index is stale). A build failure is a bug, never a silent empty list
    /// (F11).
    fn check_leak(&self, s: &Sanitized, ctx: &dyn TokenStore) -> Vec<Reason> {
        let layer = LeakLayer::build(ctx.entries(), ctx.removed_entries(), None, 0)
            .expect("patterns are plain strings");
        LeakIndex::single(layer).reasons(s)
    }

    /// The leak check answered by `leak` when it covers `ctx` (Q1);
    /// otherwise, or without one, by the per-call build (a stale index is
    /// counted).
    fn check_leak_with(
        &self,
        s: &Sanitized,
        ctx: &dyn TokenStore,
        leak: Option<&LeakIndex>,
    ) -> Vec<Reason> {
        let reasons = match leak {
            Some(idx) if idx.covers(ctx) => idx.reasons(s),
            Some(_) => {
                LEAK_INDEX_STALE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                #[cfg(test)]
                STALE_HERE.with(|c| c.set(c.get() + 1));
                self.check_leak(s, ctx)
            }
            None => self.check_leak(s, ctx),
        };
        #[cfg(feature = "leak-crosscheck")]
        crosscheck(&reasons, s, ctx);
        reasons
    }

    /// `masked` is `text` with token suffixes replaced (see
    /// [`mask_token_suffixes`]); offsets are unaffected since it is the same
    /// length, so `s.is_exempt` (keyed on `s`'s own, unmasked ranges) still
    /// applies directly to spans found in it.
    fn check_regex(&self, s: &Sanitized, masked: &str) -> Result<Vec<Reason>> {
        let ctx = DetectCtx::for_text(masked);
        let mut reasons: Vec<Reason> = self
            .regex
            .detect(masked, &ctx)?
            .into_iter()
            .filter(|sp| !s.is_exempt(sp.start, sp.end, &sp.kind))
            .map(|sp| Reason {
                kind: sp.kind,
                check: CheckId::Regex,
            })
            .collect();
        // An unlabeled identifier-shaped word (`K-482913`) that survived
        // sanitization: no rule above matches it without a label, and the
        // sanitizer must not be the only line of defence against a model
        // mislabelling it (a preserved ORGANIZATION). Tokens, protected
        // tokens, and a value policy deliberately kept as a contract number
        // or postal code are exempt.
        if bare_identifiers(masked).any(|(a, b)| {
            !s.is_exempt(a, b, &EntityKind::ContractId)
                && !s.is_exempt(a, b, &EntityKind::PostalCode)
        }) {
            reasons.push(Reason {
                kind: EntityKind::ContractId,
                check: CheckId::Regex,
            });
        }
        Ok(reasons)
    }

    /// See [`Self::check_regex`] on `masked`.
    fn check_ner(&self, s: &Sanitized, masked: &str, origin: TextOrigin) -> Result<Vec<Reason>> {
        let Some(ner) = &self.ner else {
            return Ok(Vec::new());
        };
        let ctx = DetectCtx::for_text(masked);
        let spans = ner.detect(masked, &ctx)?;
        for sp in &spans {
            validate_span(masked, sp)?;
        }
        Ok(spans
            .into_iter()
            .filter(|sp| matches!(sp.kind, EntityKind::Person | EntityKind::StreetAddress))
            // The model reads a greeting, a role noun, or a field label as
            // a name when a placeholder sits next to it
            // (`<PERSON_ab12>\nHallo,`, `Meine Nachbarin <PERSON_ab12>`,
            // `Kundennummer <CUSTOMER_ID_ab12>`). Only there is a PERSON hit
            // made only of such words dropped; the same words with no token
            // beside them, or with any other word in the hit, still fail.
            .filter(|sp| {
                !(sp.kind == EntityKind::Person
                    && masked
                        .get(sp.start..sp.end)
                        .is_some_and(is_all_salutation_or_role)
                    && is_next_to_token(s, sp.start, sp.end))
            })
            .filter(|sp| !is_preserved_place(s, sp.start, sp.end, &sp.kind))
            .filter(|sp| !is_harness_product_name(origin, s, masked, sp))
            .filter(|sp| !s.is_exempt(sp.start, sp.end, &sp.kind))
            .map(|sp| Reason {
                kind: sp.kind,
                check: CheckId::Ner,
            })
            .collect())
    }

    /// Byte offset of the start of each sentence, in ascending order,
    /// always including `0`.
    ///
    /// `.`, `!`, `?` end a sentence only when followed by whitespace or the
    /// end of the text, so dates like `01.02.2020` are not split apart.
    /// `\n` always ends a sentence.
    fn sentence_bounds(text: &str) -> Vec<usize> {
        let mut bounds: Vec<usize> = vec![0];
        for (i, ch) in text.char_indices() {
            match ch {
                '\n' => bounds.push(i + ch.len_utf8()),
                '.' | '!' | '?' => {
                    let end = i + ch.len_utf8();
                    let splits = text[end..].chars().next().is_none_or(|c| c.is_whitespace());
                    if splits {
                        bounds.push(end);
                    }
                }
                _ => {}
            }
        }
        bounds
    }

    fn check_combination(&self, s: &Sanitized) -> Vec<Reason> {
        let bounds = Self::sentence_bounds(&s.text);
        let sentence_of = |off: usize| bounds.iter().rposition(|b| *b <= off).unwrap_or(0);
        let mut per_sentence: Vec<Vec<EntityKind>> = vec![Vec::new(); bounds.len()];
        for r in &s.replacements {
            if !matches!(r.action, Action::Preserve | Action::Escalate) {
                continue;
            }
            let quasi = matches!(
                r.span.kind,
                EntityKind::City
                    | EntityKind::PostalCode
                    | EntityKind::Organization
                    | EntityKind::Date
                    | EntityKind::Custom(_)
            );
            if !quasi {
                continue;
            }
            let idx = sentence_of(r.out_range.start);
            if !per_sentence[idx].contains(&r.span.kind) {
                per_sentence[idx].push(r.span.kind.clone());
            }
        }
        // `!is_empty()` keeps a threshold of 0 (settings built in code;
        // configuration rejects < 2) from indexing an empty bucket.
        per_sentence
            .into_iter()
            .filter(|kinds| !kinds.is_empty() && kinds.len() >= self.combination_threshold)
            .map(|kinds| Reason {
                kind: kinds[0].clone(),
                check: CheckId::Combination,
            })
            .collect()
    }
}

/// Byte ranges of words (delimited by whitespace or JSON punctuation,
/// `"{}[](),;:=<>|`; surrounding punctuation trimmed) shaped like a bare
/// identifier: one to three ASCII capitals, an
/// optional hyphen, and at least five digits (`K-482913`, `V12345678`).
/// Four-digit tails (`ISO-9001`) and anything with a longer prefix do not
/// match.
fn bare_identifiers(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    // Compact JSON has no whitespace around a value (`"subject":"x K-099731"},`),
    // so quotes, brackets, and separators break words too.
    const WORD_BREAKS: &str = "\"{}[](),;:=<>|";
    let mut words = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        match (c.is_whitespace() || WORD_BREAKS.contains(c), start) {
            (false, None) => start = Some(i),
            (true, Some(st)) => {
                words.push((st, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(st) = start {
        words.push((st, text.len()));
    }
    words.into_iter().filter_map(move |(a, b)| {
        let w = &text[a..b];
        let t = w.trim_start_matches(|c: char| !c.is_alphanumeric());
        let a = a + (w.len() - t.len());
        let t = t.trim_end_matches(|c: char| !c.is_alphanumeric());
        let letters = t.bytes().take_while(u8::is_ascii_uppercase).count();
        let rest = &t[letters..];
        let digits = rest.strip_prefix('-').unwrap_or(rest);
        let shaped = (1..=3).contains(&letters)
            && digits.len() >= 5
            && digits.bytes().all(|d| d.is_ascii_digit());
        shaped.then_some((a, a + t.len()))
    })
}

/// Exact product names of the agent harnesses the proxy serves (ruling
/// L103, R18). A verifier NER `PERSON` hit whose whole text is one of these
/// (case-sensitive) is the product, but only in a harness-static text (see
/// [`is_harness_product_name`]). `Claude` is the only one that is also a
/// first name; it is the measured hit (`Claude never …` in a Claude Code
/// system prompt, confidence 1.00).
const HARNESS_PRODUCT_NAMES: &[&str] = &["Claude", "Codex", "Opus", "Sonnet", "Haiku"];

/// Ruling L103, the verifier's own product cue (not the sanitizer's
/// `detect::technical` rule, and no filter shared with it): in a
/// [`TextOrigin::HarnessStatic`] text, a `PERSON` hit whose text is exactly
/// a [`HARNESS_PRODUCT_NAMES`] entry is not a failure. It never applies to
/// [`TextOrigin::Free`]. A hit with any other word in it (`Claude Dubois`,
/// `Thanks, Claude`), another casing (`claude`, `CLAUDE`), or another kind
/// still fails. So does a hit that is part of a longer word (a letter, digit,
/// `-`, or `_` directly before or after it: `Jean-Claude`, `ClaudeX`), and a
/// hit next to one of the sanitizer's placeholders (`Claude <PERSON_ab12>`):
/// there the sanitizer split a name and tokenized only the rest, so the cue
/// would fail together with the sanitizer's. Residual (threat model): a
/// person named exactly like a product, standing alone in a system prompt,
/// is not flagged here.
fn is_harness_product_name(origin: TextOrigin, s: &Sanitized, masked: &str, sp: &Span) -> bool {
    let glued = |c: char| c.is_alphanumeric() || c == '-' || c == '_';
    origin == TextOrigin::HarnessStatic
        && sp.kind == EntityKind::Person
        && masked
            .get(sp.start..sp.end)
            .is_some_and(|t| HARNESS_PRODUCT_NAMES.contains(&t))
        && !masked[..sp.start].chars().next_back().is_some_and(glued)
        && !masked[sp.end..].chars().next().is_some_and(glued)
        && !is_next_to_token(s, sp.start, sp.end)
}

/// True when every word of `hit` (split on whitespace, trimmed of
/// non-alphanumerics) is a salutation or group word (`Hallo`, `Liebes
/// Support-Team`) or a role noun or field label (`Nachbarin`, `Kundennummer`,
/// `Tel.`, `E-Mail`, see [`is_role_or_label_word`]). A hyphenated word
/// counts when it is such a word whole (`E-Mail`) or every part is
/// (`Support-Team`). A hit with no word at all does not count.
fn is_all_salutation_or_role(hit: &str) -> bool {
    let ok = |w: &str| is_salutation_word(w) || is_role_or_label_word(w);
    let mut any = false;
    for w in hit
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| !w.is_empty())
    {
        let parts_ok = || {
            let mut parts = w.split('-').filter(|p| !p.is_empty()).peekable();
            parts.peek().is_some() && parts.all(ok)
        };
        if !(ok(w) || parts_ok()) {
            return false;
        }
        any = true;
    }
    any
}

/// True when an NER hit is a place the sanitizer already preserved and
/// that carries no street word (Task 9, ruling L48):
/// - a STREET_ADDRESS hit whose every non-whitespace byte lies inside
///   `Preserve` replacements of kind POSTAL_CODE, CITY, or COUNTRY
///   (`6020 Innsbruck`);
/// - a PERSON hit lying inside one `Preserve` CITY replacement that is the
///   regex town span ([`crate::detect::regex::is_town_span`], with its
///   address-line narrowing) and directly follows a postal code
///   replacement on the same line (`6020 Innsbruck`, the model reading the
///   town as a name). A CITY from any other source (the sanitizer's NER, a
///   dictionary or store copy) gets no such trust: `Bestellung 20231 Hall`
///   with a model CITY over a surname still fails.
///
/// A hit containing a street word (`TOWN_NOT_STREET` in the regex
/// detector, as a substring: `Neubaugasse`, `Hauptstr.`) is never a
/// place here: preserving the outer value never licensed sending a street
/// the sanitizer mislabelled as a city. Out-of-range or non-boundary
/// offsets are never a place (fail closed).
fn is_preserved_place(s: &Sanitized, start: usize, end: usize, kind: &EntityKind) -> bool {
    let Some(hit) = s.text.get(start..end) else {
        return false;
    };
    let lower = hit.to_lowercase();
    if crate::detect::regex::TOWN_NOT_STREET
        .iter()
        .any(|w| lower.contains(w))
    {
        return false;
    }
    let preserved = |r: &&crate::sanitize::Replacement, kinds: &[EntityKind]| {
        r.action == Action::Preserve && kinds.contains(&r.span.kind)
    };
    match kind {
        EntityKind::StreetAddress => {
            let places = [
                EntityKind::PostalCode,
                EntityKind::City,
                EntityKind::Country,
            ];
            let mut any = false;
            for (i, c) in hit.char_indices().filter(|(_, c)| !c.is_whitespace()) {
                let (a, b) = (start + i, start + i + c.len_utf8());
                let inside = s
                    .replacements
                    .iter()
                    .filter(|r| preserved(r, &places))
                    .any(|r| r.out_range.start <= a && b <= r.out_range.end);
                if !inside {
                    return false;
                }
                any = true;
            }
            any
        }
        EntityKind::Person => s
            .replacements
            .iter()
            .filter(|r| preserved(r, &[EntityKind::City]))
            .filter(|r| crate::detect::regex::is_town_span(&r.span))
            .filter(|r| r.out_range.start <= start && end <= r.out_range.end)
            .any(|city| {
                s.replacements.iter().any(|p| {
                    p.span.kind == EntityKind::PostalCode
                        && p.out_range.end < city.out_range.start
                        && s.text
                            .get(p.out_range.end..city.out_range.start)
                            .is_some_and(|g| g.bytes().all(|b| b == b' ' || b == b'\t'))
                })
            }),
        _ => false,
    }
}

/// Whitespace and punctuation only (ASCII punctuation or Unicode `P*`);
/// the empty string counts. [`is_next_to_token`] also caps its line breaks.
static SEPARATOR_GAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[\s\p{P}[:punct:]]*\z").unwrap());

/// At most one blank line between a placeholder and the hit: the diagnosed
/// shape is `<PERSON_ab12>\nHallo,`, and a wider gap gains nothing.
const MAX_GAP_LINE_BREAKS: usize = 2;

/// Line breaks in `gap`; `\r\n` counts once. Over-counting only narrows
/// adjacency (fail closed).
fn line_breaks(gap: &str) -> usize {
    let mut n = 0;
    let mut chars = gap.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' | '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}' => n += 1,
            _ => {}
        }
    }
    n
}

/// True when `start..end` of `s.text` sits next to one of the sanitizer's
/// own placeholders, with only whitespace or punctuation between them and at
/// most [`MAX_GAP_LINE_BREAKS`] line breaks.
///
/// Placeholders are the output ranges of `Tokenize` and `Remove`
/// replacements and the protected tokens: tokens by construction. A
/// token-shaped string in the text that is neither (a forged one) does not
/// count. Out-of-range or non-boundary offsets are never adjacent (fail
/// closed).
fn is_next_to_token(s: &Sanitized, start: usize, end: usize) -> bool {
    is_next_to_ranges(
        &s.text,
        start,
        end,
        s.replacements
            .iter()
            .filter(|r| matches!(r.action, Action::Tokenize | Action::Remove))
            .map(|r| &r.out_range)
            .chain(s.protected.iter()),
    )
}

/// True when `start..end` of `text` sits next to one of `ranges`, with only
/// whitespace or punctuation between and at most [`MAX_GAP_LINE_BREAKS`]
/// line breaks. Out-of-range or non-boundary offsets are never adjacent.
pub(crate) fn is_next_to_ranges<'a>(
    text: &str,
    start: usize,
    end: usize,
    ranges: impl IntoIterator<Item = &'a Range<usize>>,
) -> bool {
    let gap_ok = |a: usize, b: usize| {
        text.get(a..b)
            .is_some_and(|g| SEPARATOR_GAP.is_match(g) && line_breaks(g) <= MAX_GAP_LINE_BREAKS)
    };
    ranges.into_iter().any(|t| {
        (t.end <= start && gap_ok(t.end, start)) || (end <= t.start && gap_ok(end, t.start))
    })
}

/// `Fail` with a single `DetectorError` reason. The error is logged by its
/// `Display`, which never carries input text.
pub(crate) fn detector_failure(e: &Error) -> Verdict {
    tracing::warn!(error = %e, "verifier re-scan failed");
    Verdict::Fail(vec![Reason {
        kind: EntityKind::custom("DETECTOR"),
        check: CheckId::DetectorError,
    }])
}

impl Verifier for SecondPassVerifier {
    fn verify(&self, sanitized: &Sanitized, ctx: &dyn TokenStore) -> Verdict {
        self.verify_with_leak(sanitized, ctx, None)
    }

    fn verify_with(
        &self,
        sanitized: &Sanitized,
        ctx: &dyn TokenStore,
        leak: Option<&LeakIndex>,
    ) -> Verdict {
        self.verify_with_leak(sanitized, ctx, leak)
    }

    fn verify_at(
        &self,
        sanitized: &Sanitized,
        ctx: &dyn TokenStore,
        origin: TextOrigin,
    ) -> Verdict {
        self.verify_with_at(sanitized, ctx, None, origin)
    }

    /// The leak check answered by `leak` when it
    /// [`covers`](LeakIndex::covers) `ctx`, otherwise by the per-call build
    /// (counted as stale when `leak` was given). Only the NER re-scan sees
    /// the origin (rulings L103, L3-18); the leak check, the regex re-scan,
    /// the home-folder login check (ruling L127, `verify::home_login`) and
    /// the combination heuristic do not.
    fn verify_with_at(
        &self,
        sanitized: &Sanitized,
        ctx: &dyn TokenStore,
        leak: Option<&LeakIndex>,
        origin: TextOrigin,
    ) -> Verdict {
        let leaks = self.check_leak_with(sanitized, ctx, leak);
        if !leaks.is_empty() {
            return Verdict::Fail(leaks);
        }
        // Token suffixes are random and must not sway the re-scans below;
        // see `mask_token_suffixes`. Masking clones the whole candidate text, so skip it
        // when there is nothing to mask and nothing that would notice: no NER re-scan will
        // run (`self.ner` is `None`), and neither a `Tokenize` replacement nor a
        // protected token put a random suffix there (`mask_token_suffixes` would be
        // a no-op on the regex re-scan's `masked` input either way).
        let has_tokenize = !sanitized.protected.is_empty()
            || sanitized
                .replacements
                .iter()
                .any(|r| r.action == Action::Tokenize);
        let masked: Cow<'_, str> = if self.ner.is_none() && !has_tokenize {
            Cow::Borrowed(sanitized.text.as_str())
        } else {
            Cow::Owned(mask_token_suffixes(sanitized, ctx.settings()))
        };
        // A re-scan that cannot run is a failure, never a silent pass.
        let regex = match self.check_regex(sanitized, &masked) {
            Ok(r) => r,
            Err(e) => return detector_failure(&e),
        };
        if !regex.is_empty() {
            return Verdict::Fail(regex);
        }
        // Ruling L127: a home-folder login in clear, for every origin. The
        // check is the verifier's own (`verify::home_login`), sharing no
        // code with the sanitizer's path detector (S12).
        let home = super::home_login::check_home_logins(sanitized);
        if !home.is_empty() {
            return Verdict::Fail(home);
        }
        let ner = match self.check_ner(sanitized, &masked, origin) {
            Ok(r) => r,
            Err(e) => return detector_failure(&e),
        };
        if !ner.is_empty() {
            return Verdict::Fail(ner);
        }
        let combo = self.check_combination(sanitized);
        if !combo.is_empty() {
            return Verdict::Uncertain(combo);
        }
        Verdict::Pass
    }
}

impl SecondPassVerifier {
    /// [`Verifier::verify`], the leak check answered by `leak` when it
    /// [`covers`](LeakIndex::covers) `ctx`; otherwise the per-call build
    /// (counted as stale when `leak` was given). Judges the text as
    /// [`TextOrigin::Free`].
    pub fn verify_with_leak(
        &self,
        sanitized: &Sanitized,
        ctx: &dyn TokenStore,
        leak: Option<&LeakIndex>,
    ) -> Verdict {
        self.verify_with_at(sanitized, ctx, leak, TextOrigin::Free)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokenSettings;
    use crate::detect::regex::RegexDetector;
    use crate::detect::{DetectCtx, Detector};
    use crate::origin::TextOrigin;
    use crate::policy::{Action, Decision, VerifierSettings};
    use crate::sanitize::{sanitize, sanitize_linked};
    use crate::span::{DetectorId as D, EntityKind as K, Span};
    use crate::token::{Context, ContextId};
    use std::sync::Arc;
    use std::time::Duration;

    fn settings() -> VerifierSettings {
        VerifierSettings {
            allow_no_ner: true,
            ..Default::default()
        }
    }
    fn ctx() -> Context {
        Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        )
    }
    fn verifier() -> SecondPassVerifier {
        SecondPassVerifier::new(RegexDetector::new(), None, &settings()).unwrap()
    }
    fn dec(s: usize, e: usize, k: K, a: Action) -> Decision {
        Decision {
            span: Span::new(s, e, k, 0.9, D::Ner),
            action: a,
        }
    }

    #[test]
    fn requires_explicit_opt_out_of_ner() {
        let err = SecondPassVerifier::new(RegexDetector::new(), None, &VerifierSettings::default())
            .unwrap_err();
        assert!(matches!(err, crate::Error::ModelUnavailable(_)));
    }

    #[test]
    fn clean_candidate_passes() {
        let text = "Sarah Leitner moved.";
        let mut c = ctx();
        let s = sanitize(text, &[dec(0, 13, K::Person, Action::Tokenize)], &mut c).unwrap();
        assert_eq!(verifier().verify(&s, &c), Verdict::Pass);
    }

    /// Ruling L127: a home-folder login the sanitizer left in clear fails
    /// the verifier in every origin (one `PERSON`/`Regex` reason, no text);
    /// the same path with the login tokenized passes.
    #[test]
    fn a_clear_home_login_fails_in_every_origin() {
        let text = "cwd /Users/mhuber/projekte/app";
        for origin in [
            TextOrigin::Free,
            TextOrigin::HarnessStatic,
            TextOrigin::FileName,
        ] {
            let mut c = ctx();
            let clear = sanitize(text, &[], &mut c).unwrap();
            assert_eq!(
                verifier().verify_at(&clear, &c, origin),
                Verdict::Fail(vec![Reason {
                    kind: K::Person,
                    check: CheckId::Regex
                }]),
                "{origin:?}"
            );
            let tokenized =
                sanitize(text, &[dec(11, 17, K::Person, Action::Tokenize)], &mut c).unwrap();
            assert_eq!(verifier().verify_at(&tokenized, &c, origin), Verdict::Pass);
        }
    }

    /// Independent line of defence: a bare identifier-shaped word that the
    /// sanitizer left in clear fails the regex re-scan; four-digit tails,
    /// tokens, and policy-kept postal codes do not.
    #[test]
    fn bare_identifier_left_in_clear_fails_the_regex_rescan() {
        let mut c = ctx();
        let text = "Bitte Ticket K-482913. bearbeiten";
        let s = sanitize(text, &[], &mut c).unwrap();
        assert_eq!(
            verifier().verify(&s, &c),
            Verdict::Fail(vec![Reason {
                kind: K::ContractId,
                check: CheckId::Regex
            }])
        );
        for ok in [
            "Norm ISO-9001 gilt, Ticket ABCD-482913 offen",
            "Version v2024 und Nr 12345 ohne Praefix",
        ] {
            let s = sanitize(ok, &[], &mut c).unwrap();
            assert_eq!(verifier().verify(&s, &c), Verdict::Pass, "{ok}");
        }
        // tokenized: the token is not a word of that shape
        let text = "Ticket V-482913 offen";
        let s = sanitize(text, &[dec(7, 15, K::ContractId, Action::Tokenize)], &mut c).unwrap();
        assert!(s.text.contains("<CONTRACT_ID_"), "{}", s.text);
        assert_eq!(verifier().verify(&s, &c), Verdict::Pass);
        // a postal code the policy keeps (`D-10115`) is not a finding
        let text = "Sitz D-10115 Berlin";
        let s = sanitize(text, &[dec(5, 12, K::PostalCode, Action::Preserve)], &mut c).unwrap();
        assert_eq!(verifier().verify(&s, &c), Verdict::Pass);
    }

    #[test]
    fn bare_identifier_inside_compact_json_fails_the_regex_rescan() {
        let mut c = ctx();
        let text =
            r#"{"messages":[{"subject":"Adressänderung K-099731"},{"id":"mm_1"}],"total":1}"#;
        let s = sanitize(text, &[], &mut c).unwrap();
        assert_eq!(
            verifier().verify(&s, &c),
            Verdict::Fail(vec![Reason {
                kind: K::ContractId,
                check: CheckId::Regex
            }])
        );
        for ok in [
            r#"{"norm":"ISO-9001","ticket":"ABCD-482913"}"#,
            r#"{"version":"v2024","nr":12345}"#,
        ] {
            let s = sanitize(ok, &[], &mut c).unwrap();
            assert_eq!(verifier().verify(&s, &c), Verdict::Pass, "{ok}");
        }
    }

    #[test]
    fn leaked_original_fails() {
        let text = "Sarah Leitner moved. Call Sarah Leitner.";
        let mut c = ctx();
        // only the first mention was tokenized
        let s = sanitize(text, &[dec(0, 13, K::Person, Action::Tokenize)], &mut c).unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => {
                assert!(
                    r.iter()
                        .any(|x| x.check == CheckId::Leak && x.kind == K::Person)
                )
            }
            v => panic!("expected Fail, got {v:?}"),
        }
    }

    #[test]
    fn leaked_surname_alone_fails_but_common_word_part_does_not() {
        let text = "Thomas May moved. Frau May und Herr Thomas kamen.";
        let mut c = ctx();
        let s = sanitize(text, &[dec(0, 10, K::Person, Action::Tokenize)], &mut c).unwrap();
        // "May" is a common word, "Thomas" is a name part >= 4 chars -> Thomas leaks
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => assert!(r.iter().any(|x| x.check == CheckId::Leak)),
            v => panic!("{v:?}"),
        }
        let text2 = "Thomas May moved. Frau May kam.";
        let mut c2 = ctx();
        let s2 = sanitize(text2, &[dec(0, 10, K::Person, Action::Tokenize)], &mut c2).unwrap();
        assert_eq!(verifier().verify(&s2, &c2), Verdict::Pass);
    }

    /// M2: full originals of 3 characters are leak-checked too.
    #[test]
    fn three_char_original_repeated_fails() {
        let text = "Kunde X12 und nochmal X12.";
        let mut c = ctx();
        let s = sanitize(text, &[dec(6, 9, K::CustomerId, Action::Tokenize)], &mut c).unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => assert!(
                r.iter()
                    .any(|x| x.check == CheckId::Leak && x.kind == K::CustomerId),
                "{r:?}"
            ),
            v => panic!("expected Fail, got {v:?}"),
        }
    }

    /// M2: the 4-character floor still applies to name parts.
    #[test]
    fn three_char_name_part_alone_is_not_a_leak() {
        let text = "Eva Leitner kam. Eva ist nett.";
        let mut c = ctx();
        let s = sanitize(text, &[dec(0, 11, K::Person, Action::Tokenize)], &mut c).unwrap();
        assert_eq!(verifier().verify(&s, &c), Verdict::Pass);
    }

    #[test]
    fn leak_check_folds_case_and_diacritics() {
        let text = "Jörg Müller here. JOERG MUELLER again.";
        let mut c = ctx();
        let s = sanitize(text, &[dec(0, 13, K::Person, Action::Tokenize)], &mut c).unwrap();
        assert!(matches!(verifier().verify(&s, &c), Verdict::Fail(_)));
    }

    /// The leak check keeps an exact NFC leg (`nfc(original)` and
    /// `nfc(name part)`) next to the transliterated and diacritic-folded
    /// legs, so a bug in the normalizers shared with the consistency pass
    /// cannot blind both the sanitizer and the verifier. The original is
    /// stored decomposed (a caller may put any form into the context); the
    /// candidate carries the composed copy in clear. The assertions are on
    /// the pattern set itself, so they hold with `transliterate` and
    /// `fold_diacritics` replaced by the identity.
    #[test]
    fn leak_check_has_an_exact_nfc_leg_independent_of_the_normalizers() {
        use unicode_normalization::UnicodeNormalization;
        let nfd_original: String = "Jürgen Müller".nfd().collect();
        assert_ne!(nfd_original, "Jürgen Müller");
        let mut c = ctx();
        c.token_for(&K::Person, &nfd_original).unwrap();
        let (pats, _) = SecondPassVerifier::leak_patterns(&c);
        for exact in ["Jürgen Müller", "Müller"] {
            assert!(
                pats.iter().any(|p| p.as_str() == exact),
                "no exact NFC pattern for {exact}"
            );
        }
        for leaked in ["Bitte Jürgen Müller anrufen.", "Bitte Müller anrufen."] {
            let s = sanitize(leaked, &[], &mut c).unwrap();
            match verifier().verify(&s, &c) {
                Verdict::Fail(r) => assert!(
                    r.iter()
                        .any(|x| x.check == CheckId::Leak && x.kind == K::Person),
                    "{leaked}: {r:?}"
                ),
                v => panic!("{leaked}: expected Fail, got {v:?}"),
            }
        }
    }

    /// R6: patterns must also cover raw case-folded (non-ASCII) forms, since
    /// `ascii_case_insensitive` does not fold `Ü`/`ü`.
    #[test]
    fn leak_check_folds_non_ascii_case() {
        let text = "Jörg Müller here. JÖRG MÜLLER again.";
        let mut c = ctx();
        let s = sanitize(text, &[dec(0, 13, K::Person, Action::Tokenize)], &mut c).unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => assert!(r.iter().any(|x| x.check == CheckId::Leak)),
            v => panic!("expected Fail, got {v:?}"),
        }
    }

    /// Fix round 1 finding: a rejected longest match must not hide a
    /// shorter, word-bounded pattern it happened to overlap with — here
    /// "Sarah Leitner" is rejected (trailing genitive "s"), but the bare
    /// "Sarah" that immediately follows in the automaton's search space
    /// must still be examined and flagged.
    #[test]
    fn leaked_name_part_hidden_by_rejected_longest_match_fails() {
        let text = "Sarah Leitner kam. Sarah Leitners Hund bellte.";
        let mut c = ctx();
        let s = sanitize(text, &[dec(0, 13, K::Person, Action::Tokenize)], &mut c).unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => {
                assert!(
                    r.iter()
                        .any(|x| x.check == CheckId::Leak && x.kind == K::Person)
                )
            }
            v => panic!("expected Fail, got {v:?}"),
        }
    }

    /// Fix round 1 finding: a rejected longest match starting *earlier* must
    /// not hide a different, later-starting pattern whose bytes it
    /// consumed — here "Anna Berg" is rejected (trailing "m" of
    /// "Bergmann"), but "Bergmann" (a name part of the unrelated "Karl
    /// Bergmann" entry) overlaps it and must still be found.
    #[test]
    fn leaked_surname_hidden_behind_a_different_rejected_longest_match_fails() {
        let text = "Anna Berg und Karl Bergmann kamen. Dann Anna Bergmann.";
        let mut c = ctx();
        let anna_berg = text.find("Anna Berg").unwrap();
        let karl_bergmann = text.find("Karl Bergmann").unwrap();
        let s = sanitize(
            text,
            &[
                dec(
                    anna_berg,
                    anna_berg + "Anna Berg".len(),
                    K::Person,
                    Action::Tokenize,
                ),
                dec(
                    karl_bergmann,
                    karl_bergmann + "Karl Bergmann".len(),
                    K::Person,
                    Action::Tokenize,
                ),
            ],
            &mut c,
        )
        .unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => {
                assert!(
                    r.iter()
                        .any(|x| x.check == CheckId::Leak && x.kind == K::Person)
                )
            }
            v => panic!("expected Fail, got {v:?}"),
        }
    }

    /// C3: a removed secret is recorded for the leak check, so a second,
    /// undetected copy of it fails verification.
    #[test]
    fn second_copy_of_removed_secret_fails_leak_check() {
        let text = "api_key: 9f8e7d6c5b4a3210ffee. Bitte teste mit 9f8e7d6c5b4a3210ffee im Header.";
        let mut c = ctx();
        let s = sanitize(
            text,
            &[dec(
                9,
                29,
                K::Secret(crate::span::SecretKind::Generic),
                Action::Remove,
            )],
            &mut c,
        )
        .unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => assert!(
                r.iter()
                    .any(|x| x.check == CheckId::Leak && x.kind.is_secret()),
                "{r:?}"
            ),
            v => panic!("expected Fail, got {v:?}"),
        }
    }

    /// I9: a known value wrapped across lines still counts as a leak.
    #[test]
    fn leak_check_matches_across_whitespace_runs() {
        let mut c = ctx();
        c.token_for(&K::StreetAddress, "Neubaugasse 22").unwrap();
        let s = sanitize("Wohnt in Neubaugasse\n  22.", &[], &mut c).unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => assert!(
                r.iter()
                    .any(|x| x.check == CheckId::Leak && x.kind == K::StreetAddress),
                "{r:?}"
            ),
            v => panic!("expected Fail, got {v:?}"),
        }
        // an original stored with irregular whitespace matches a single space
        let mut c = ctx();
        c.token_for(&K::StreetAddress, "Neubaugasse\t22").unwrap();
        let s = sanitize("Wohnt in Neubaugasse 22.", &[], &mut c).unwrap();
        assert!(matches!(verifier().verify(&s, &c), Verdict::Fail(_)));
    }

    #[test]
    fn regex_rescan_catches_missed_structured_ids() {
        let text = "IBAN AT61 1904 3002 3457 3201 bitte";
        let mut c = ctx();
        let s = sanitize(text, &[], &mut c).unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => {
                assert!(
                    r.iter()
                        .any(|x| x.check == CheckId::Regex && x.kind == K::Iban)
                )
            }
            v => panic!("{v:?}"),
        }
    }

    /// C1: the re-scan shares the regex detector, so an IBAN or card that
    /// the greedy pattern used to over-extend must now be caught here too.
    #[test]
    fn regex_rescan_catches_iban_and_card_followed_by_more_text() {
        for (text, kind) in [
            ("IBAN AT61 1904 3002 3457 3201 BIC BKAUATWW", K::Iban),
            ("Karte 4111 1111 1111 1111 123 gueltig", K::CreditCard),
        ] {
            let mut c = ctx();
            let s = sanitize(text, &[], &mut c).unwrap();
            match verifier().verify(&s, &c) {
                Verdict::Fail(r) => assert!(
                    r.iter()
                        .any(|x| x.check == CheckId::Regex && x.kind == kind),
                    "{r:?}"
                ),
                v => panic!("expected Fail, got {v:?}"),
            }
        }
    }

    #[test]
    fn preserved_span_seen_by_sanitizer_is_not_a_regex_failure() {
        let text = "Termin am 24.09.2026";
        let mut c = ctx();
        let s = sanitize(text, &[dec(10, 20, K::Date, Action::Preserve)], &mut c).unwrap();
        assert_eq!(verifier().verify(&s, &c), Verdict::Pass);
    }

    /// C2: a preserved URL must not exempt an email (a different kind) that
    /// the re-scan finds inside it; a same-kind hit stays exempt.
    #[test]
    fn preserved_range_exempts_only_same_kind_hits() {
        let text = "https://portal.example.at/kunden?email=sarah.leitner@example.at";
        let mut c = ctx();
        let s = sanitize(
            text,
            &[dec(0, text.len(), K::Url, Action::Preserve)],
            &mut c,
        )
        .unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => assert!(
                r.iter()
                    .any(|x| x.check == CheckId::Regex && x.kind == K::Email),
                "{r:?}"
            ),
            v => panic!("expected Fail, got {v:?}"),
        }
        let text = "Siehe https://example.at/x bitte";
        let mut c = ctx();
        let s = sanitize(text, &[dec(6, 26, K::Url, Action::Preserve)], &mut c).unwrap();
        assert_eq!(verifier().verify(&s, &c), Verdict::Pass);
    }

    #[test]
    fn ner_hit_inside_preserved_range_of_other_kind_fails() {
        struct PersonInOrg;
        impl Detector for PersonInOrg {
            fn id(&self) -> D {
                D::Ner
            }
            fn detect(&self, text: &str, _: &DetectCtx) -> crate::Result<Vec<Span>> {
                Ok(text
                    .find("Gruber")
                    .map(|i| vec![Span::new(i, i + 6, K::Person, 0.9, D::Ner)])
                    .unwrap_or_default())
            }
        }
        let v = SecondPassVerifier::new(
            RegexDetector::new(),
            Some(Arc::new(PersonInOrg)),
            &VerifierSettings::default(),
        )
        .unwrap();
        let text = "Bei Gruber Bau GmbH angerufen.";
        let mut c = ctx();
        let s = sanitize(
            text,
            &[dec(4, 19, K::Organization, Action::Preserve)],
            &mut c,
        )
        .unwrap();
        match v.verify(&s, &c) {
            Verdict::Fail(r) => assert!(r.iter().any(|x| x.check == CheckId::Ner)),
            o => panic!("expected Fail, got {o:?}"),
        }
    }

    /// I5: a failing verifier NER backend fails verification.
    #[test]
    fn failing_verifier_ner_fails() {
        struct Broken;
        impl Detector for Broken {
            fn id(&self) -> D {
                D::Ner
            }
            fn detect(&self, _: &str, _: &DetectCtx) -> crate::Result<Vec<Span>> {
                Err(crate::Error::ModelUnavailable("test backend".into()))
            }
        }
        struct OutOfBounds;
        impl Detector for OutOfBounds {
            fn id(&self) -> D {
                D::Ner
            }
            fn detect(&self, _: &str, _: &DetectCtx) -> crate::Result<Vec<Span>> {
                Ok(vec![Span::new(0, 999, K::Person, 0.9, D::Ner)])
            }
        }
        let backends: [Arc<dyn Detector>; 2] = [Arc::new(Broken), Arc::new(OutOfBounds)];
        for ner in backends {
            let v = SecondPassVerifier::new(
                RegexDetector::new(),
                Some(ner),
                &VerifierSettings::default(),
            )
            .unwrap();
            let mut c = ctx();
            let s = sanitize("Herr Gruber kam.", &[], &mut c).unwrap();
            match v.verify(&s, &c) {
                Verdict::Fail(r) => assert!(r.iter().any(|x| x.check == CheckId::DetectorError)),
                o => panic!("expected Fail, got {o:?}"),
            }
        }
    }

    #[test]
    fn ner_rescan_uses_injected_detector() {
        struct AlwaysPerson;
        impl Detector for AlwaysPerson {
            fn id(&self) -> D {
                D::Ner
            }
            fn detect(&self, text: &str, _: &DetectCtx) -> crate::Result<Vec<Span>> {
                Ok(text
                    .find("Gruber")
                    .map(|i| vec![Span::new(i, i + 6, K::Person, 0.9, D::Ner)])
                    .unwrap_or_default())
            }
        }
        let v = SecondPassVerifier::new(
            RegexDetector::new(),
            Some(Arc::new(AlwaysPerson)),
            &VerifierSettings::default(),
        )
        .unwrap();
        let text = "Herr Gruber kam.";
        let mut c = ctx();
        let s = sanitize(text, &[], &mut c).unwrap();
        match v.verify(&s, &c) {
            Verdict::Fail(r) => assert!(r.iter().any(|x| x.check == CheckId::Ner)),
            o => panic!("{o:?}"),
        }
    }

    /// Fix round 1 finding: the NER re-scan must not see the token's random
    /// hex suffix, so two sanitizations of the same input that only differ
    /// in which random hex their tokens got produce the same verdict.
    #[test]
    fn ner_rescan_sees_masked_token_suffixes_not_random_hex() {
        struct RecordingNer(std::sync::Mutex<Option<String>>);
        impl Detector for RecordingNer {
            fn id(&self) -> D {
                D::Ner
            }
            fn detect(&self, text: &str, _: &DetectCtx) -> crate::Result<Vec<Span>> {
                *self.0.lock().unwrap() = Some(text.to_string());
                Ok(Vec::new())
            }
        }
        let recorder = Arc::new(RecordingNer(std::sync::Mutex::new(None)));
        let ner: Arc<dyn Detector> = recorder.clone();
        let v = SecondPassVerifier::new(
            RegexDetector::new(),
            Some(ner),
            &VerifierSettings::default(),
        )
        .unwrap();
        let text = "Sarah Leitner rief an. Auch Karl Gruber war da.";
        let sarah = text.find("Sarah Leitner").unwrap();
        let karl = text.find("Karl Gruber").unwrap();
        let mut c = ctx();
        let s = sanitize(
            text,
            &[
                dec(
                    sarah,
                    sarah + "Sarah Leitner".len(),
                    K::Person,
                    Action::Tokenize,
                ),
                dec(
                    karl,
                    karl + "Karl Gruber".len(),
                    K::Person,
                    Action::Tokenize,
                ),
            ],
            &mut c,
        )
        .unwrap();
        let _ = v.verify(&s, &c);
        let seen = recorder
            .0
            .lock()
            .unwrap()
            .clone()
            .expect("ner detector was called");

        // (b) masking does not change length.
        assert_eq!(seen.len(), s.text.len());

        // (a) no hex digits survive between the last `_` and the closing
        // delimiter inside any token; every such run is masked to `x`.
        let close = &c.settings().close;
        for r in &s.replacements {
            assert_eq!(r.action, Action::Tokenize);
            let tok = &seen[r.out_range.clone()];
            let close_start = tok.len() - close.len();
            let sep = tok[..close_start]
                .rfind('_')
                .expect("token has a label/suffix separator");
            let suffix = &tok[sep + 1..close_start];
            assert!(!suffix.is_empty());
            assert!(suffix.chars().all(|ch| ch == 'x'), "{suffix}");
        }

        // (c) text outside tokens is byte-identical to the unmasked text.
        let mut cursor = 0;
        for r in &s.replacements {
            assert_eq!(
                &seen[cursor..r.out_range.start],
                &s.text[cursor..r.out_range.start]
            );
            cursor = r.out_range.end;
        }
        assert_eq!(&seen[cursor..], &s.text[cursor..]);
    }

    #[test]
    fn combination_of_preserved_kinds_is_uncertain() {
        let text = "Elektriker bei Example GmbH in Wien seit 01.02.2020.";
        let mut c = ctx();
        let gmbh = text.find("Example GmbH").unwrap();
        let wien = text.find("Wien").unwrap();
        let date = text.find("01.02.2020").unwrap();
        let s = sanitize(
            text,
            &[
                dec(gmbh, gmbh + 12, K::Organization, Action::Preserve),
                dec(wien, wien + 4, K::City, Action::Preserve),
                dec(date, date + 10, K::Date, Action::Preserve),
            ],
            &mut c,
        )
        .unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Uncertain(r) => assert_eq!(r[0].check, CheckId::Combination),
            o => panic!("{o:?}"),
        }
    }

    /// I7: a threshold of 0 (possible when settings are built in code) must
    /// not panic on sentences without preserved kinds.
    #[test]
    fn combination_threshold_zero_does_not_panic() {
        let v = SecondPassVerifier::new(
            RegexDetector::new(),
            None,
            &VerifierSettings {
                allow_no_ner: true,
                combination_threshold: 0,
                ..Default::default()
            },
        )
        .unwrap();
        let mut c = ctx();
        let s = sanitize("hello world", &[], &mut c).unwrap();
        assert_eq!(v.verify(&s, &c), Verdict::Pass);
    }

    /// R5: a date's internal periods must not split the sentence, or a
    /// preserved span after the date would be miscounted as a separate
    /// sentence and the combination check would miss it.
    #[test]
    fn combination_across_custom_date_and_postal_in_one_sentence_is_uncertain() {
        let text = "Elektriker seit 01.02.2020 in 1010 Wien.";
        let mut c = ctx();
        let prof = text.find("Elektriker").unwrap();
        let date = text.find("01.02.2020").unwrap();
        let postal = text.find("1010").unwrap();
        // The regex detector reads `Wien` after the postal code as a CITY
        // (Task 7b), so the sanitizer holds a decision for it too.
        let city = text.find("Wien").unwrap();
        let s = sanitize(
            text,
            &[
                dec(prof, prof + 10, K::custom("profession"), Action::Preserve),
                dec(date, date + 10, K::Date, Action::Preserve),
                dec(postal, postal + 4, K::PostalCode, Action::Preserve),
                dec(city, city + 4, K::City, Action::Preserve),
            ],
            &mut c,
        )
        .unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Uncertain(r) => assert!(r.iter().any(|x| x.check == CheckId::Combination)),
            o => panic!("expected Uncertain(Combination), got {o:?}"),
        }
    }

    /// Spec §13.1: the verifier's regex re-scan catches a street address the
    /// sanitizer never saw (an NER miss), so it can no longer leave in clear.
    #[test]
    fn regex_rescan_catches_missed_street_address() {
        let text = "Bitte liefern Sie an Neubaugasse 22, danke.";
        let mut c = ctx();
        let s = sanitize(text, &[], &mut c).unwrap();
        match verifier().verify(&s, &c) {
            Verdict::Fail(r) => assert!(
                r.iter()
                    .any(|x| x.check == CheckId::Regex && x.kind == K::StreetAddress),
                "{r:?}"
            ),
            v => panic!("expected Fail, got {v:?}"),
        }
    }

    /// Plan 4a: masking covers the hex suffix and the random surface
    /// component, so the re-scans see `<PERSON_xxxxxx_xx>` and never a random
    /// byte.
    #[test]
    fn masking_handles_variant_tokens() {
        let text = "Sarah Leitner kam. LG Sarah";
        let mut c = ctx();
        let full_end = "Sarah Leitner".len();
        let sarah = text.rfind("Sarah").unwrap();
        let mut links = crate::link::Links::empty();
        links.insert(sarah, "Sarah Leitner", crate::link::LinkTier::Document);
        let s = sanitize_linked(
            text,
            &[
                dec(0, full_end, K::Person, Action::Tokenize),
                dec(sarah, sarah + 5, K::Person, Action::Tokenize),
            ],
            &links,
            &mut c,
        )
        .unwrap();
        let masked = mask_token_suffixes(&s, c.settings());
        assert_eq!(masked.len(), s.text.len());
        let toks: Vec<&str> = masked
            .split_whitespace()
            .filter(|w| w.starts_with('<'))
            .collect();
        assert_eq!(toks.len(), 2, "{masked}");
        assert_eq!(toks[0], "<PERSON_xxxx>", "{masked}");
        assert_eq!(toks[1], "<PERSON_xxxx_xx>", "{masked}");
    }

    /// M8 decision 11: a protected token is masked and exempt like a minted one.
    #[test]
    fn protected_tokens_are_masked_and_exempt() {
        struct TokenLooksLikeAName;
        impl crate::detect::Detector for TokenLooksLikeAName {
            fn id(&self) -> D {
                D::Ner
            }
            fn detect(&self, text: &str, _: &crate::detect::DetectCtx) -> crate::Result<Vec<Span>> {
                // Flags "PERSON_" plus six following bytes when they are not masked.
                Ok(text
                    .match_indices("PERSON_")
                    .filter(|(i, _)| !text[i + 7..].starts_with("xxxx"))
                    .map(|(i, _)| Span::new(i, i + 13, K::Person, 0.9, D::Ner))
                    .collect())
            }
        }
        let mut c = ctx();
        let t = c.token_for(&K::Person, "Zyxwuria Quolnath").unwrap();
        let text = format!("Bitte {} anrufen.", t.as_str());
        let mut s = sanitize(&text, &[], &mut c).unwrap();
        let v = SecondPassVerifier::new(
            RegexDetector::new(),
            Some(Arc::new(TokenLooksLikeAName)),
            &settings(),
        )
        .unwrap();
        assert!(
            matches!(v.verify(&s, &c), Verdict::Fail(_)),
            "unprotected, the token's bytes are judged like any text"
        );
        let start = text.find(t.as_str()).unwrap();
        s.protected.push(start..start + t.as_str().len());
        assert_eq!(
            mask_token_suffixes(&s, c.settings()),
            "Bitte <PERSON_xxxx> anrufen."
        );
        assert_eq!(v.verify(&s, &c), Verdict::Pass);
    }

    /// Review Focus 3.
    #[test]
    fn all_salutation_person_hits_are_not_failures_but_mixed_ones_are() {
        struct Flags(&'static [&'static str]);
        impl Detector for Flags {
            fn id(&self) -> D {
                D::Ner
            }
            fn detect(&self, text: &str, _: &DetectCtx) -> crate::Result<Vec<Span>> {
                Ok(self
                    .0
                    .iter()
                    .filter_map(|w| {
                        text.find(w)
                            .map(|i| Span::new(i, i + w.len(), K::Person, 0.9, D::Ner))
                    })
                    .collect())
            }
        }
        let v = |w: &'static [&'static str]| {
            SecondPassVerifier::new(
                RegexDetector::new(),
                Some(Arc::new(Flags(w))),
                &VerifierSettings::default(),
            )
            .unwrap()
        };
        let mut c = ctx();
        // a greeting on the line after a sign-off token: dropped (RED today)
        let text = "Viele Grüße\nQuolnath\nHallo,\n\nbitte prüfen.";
        let q = text.find("Quolnath").unwrap();
        let s = sanitize(text, &[dec(q, q + 8, K::Person, Action::Tokenize)], &mut c).unwrap();
        assert_eq!(v(&["Hallo"]).verify(&s, &c), Verdict::Pass);
        let text = "Viele Grüße\nQuolnath\nLiebes Support-Team,\nbitte prüfen.";
        let q = text.find("Quolnath").unwrap();
        let s = sanitize(text, &[dec(q, q + 8, K::Person, Action::Tokenize)], &mut c).unwrap();
        assert_eq!(v(&["Liebes Support-Team"]).verify(&s, &c), Verdict::Pass);
        // guard: the same greeting with no token next to it still fails
        let s = sanitize("Danke.\n\nHallo,\n\nbitte prüfen.", &[], &mut c).unwrap();
        assert!(
            matches!(v(&["Hallo"]).verify(&s, &c), Verdict::Fail(r) if r.iter().any(|x| x.check == CheckId::Ner))
        );
        // guard: a word between the token and the greeting breaks adjacency
        let text = "Quolnath sagt Hallo,\nbitte prüfen.";
        let s = sanitize(text, &[dec(0, 8, K::Person, Action::Tokenize)], &mut c).unwrap();
        assert!(
            matches!(v(&["Hallo"]).verify(&s, &c), Verdict::Fail(r) if r.iter().any(|x| x.check == CheckId::Ner))
        );
        // guard: more than two line breaks between token and greeting
        let text = "Quolnath\n\n\nHallo,\nbitte prüfen.";
        let s = sanitize(text, &[dec(0, 8, K::Person, Action::Tokenize)], &mut c).unwrap();
        assert!(
            matches!(v(&["Hallo"]).verify(&s, &c), Verdict::Fail(r) if r.iter().any(|x| x.check == CheckId::Ner))
        );
        // two line breaks (one blank line) are still adjacent
        let text = "Quolnath\r\n\r\nHallo,\nbitte prüfen.";
        let s = sanitize(text, &[dec(0, 8, K::Person, Action::Tokenize)], &mut c).unwrap();
        assert_eq!(v(&["Hallo"]).verify(&s, &c), Verdict::Pass);
        // guard: a greeting mixed with a name fails even right after a token
        let text = "Viele Grüße\nQuolnath\nHallo Sarah,\nbitte prüfen.";
        let q = text.find("Quolnath").unwrap();
        let s = sanitize(text, &[dec(q, q + 8, K::Person, Action::Tokenize)], &mut c).unwrap();
        assert!(
            matches!(v(&["Hallo Sarah"]).verify(&s, &c), Verdict::Fail(r) if r.iter().any(|x| x.check == CheckId::Ner))
        );
        let s = sanitize("Hallo Sarah,\nbitte prüfen.", &[], &mut c).unwrap();
        assert!(
            matches!(v(&["Hallo Sarah"]).verify(&s, &c), Verdict::Fail(r) if r.iter().any(|x| x.check == CheckId::Ner))
        );
        let s = sanitize("Viele Grüße\nRose", &[], &mut c).unwrap();
        assert!(
            matches!(v(&["Rose"]).verify(&s, &c), Verdict::Fail(r) if r.iter().any(|x| x.check == CheckId::Ner))
        );
    }

    /// NER test double: flags each listed word, with its kind, at its first
    /// occurrence.
    struct FlagsK(&'static [(&'static str, K)]);
    impl Detector for FlagsK {
        fn id(&self) -> D {
            D::Ner
        }
        fn detect(&self, text: &str, _: &DetectCtx) -> crate::Result<Vec<Span>> {
            Ok(self
                .0
                .iter()
                .filter_map(|(w, k)| {
                    text.find(w)
                        .map(|i| Span::new(i, i + w.len(), k.clone(), 0.9, D::Ner))
                })
                .collect())
        }
    }

    fn flags_k(w: &'static [(&'static str, K)]) -> SecondPassVerifier {
        SecondPassVerifier::new(
            RegexDetector::new(),
            Some(Arc::new(FlagsK(w))),
            &VerifierSettings::default(),
        )
        .unwrap()
    }

    fn fails_ner(v: Verdict) -> bool {
        matches!(v, Verdict::Fail(r) if r.iter().any(|x| x.check == CheckId::Ner))
    }

    /// Task 9 (brief).
    #[test]
    fn role_label_and_preserved_place_hits_are_not_failures_but_streets_and_names_are() {
        let v = flags_k;
        let mut c = ctx();
        let text = "Kundennummer K-482913 siehe oben.";
        let s = sanitize(
            text,
            &[dec(13, 21, K::CustomerId, Action::Tokenize)],
            &mut c,
        )
        .unwrap();
        assert_eq!(
            v(&[("Kundennummer", K::Person)]).verify(&s, &c),
            Verdict::Pass
        );
        // guard: a role/label word with no token next to it still fails
        let s = sanitize("Kundennummer siehe oben.", &[], &mut c).unwrap();
        assert!(fails_ner(v(&[("Kundennummer", K::Person)]).verify(&s, &c)));
        let text = "Ich wohne in 6020 Innsbruck.";
        let s = sanitize(
            text,
            &[
                dec(13, 17, K::PostalCode, Action::Preserve),
                dec(18, 27, K::City, Action::Preserve),
            ],
            &mut c,
        )
        .unwrap();
        assert_eq!(
            v(&[("6020 Innsbruck", K::StreetAddress)]).verify(&s, &c),
            Verdict::Pass
        );
        let s = sanitize("Ich wohne in der Neubaugasse 22.", &[], &mut c).unwrap();
        assert!(matches!(
            v(&[("Neubaugasse 22", K::StreetAddress)]).verify(&s, &c),
            Verdict::Fail(_)
        ));
        let s = sanitize("Mein Nachbar Huber ruft an.", &[], &mut c).unwrap();
        assert!(fails_ner(v(&[("Nachbar Huber", K::Person)]).verify(&s, &c)));
        // I4: a street the sanitizer mislabelled (CITY over the name,
        // POSTAL_CODE over the number) still fails
        let text = "Ich wohne in der Neubaugasse 22.";
        let s = sanitize(
            text,
            &[
                dec(17, 28, K::City, Action::Preserve),
                dec(29, 31, K::PostalCode, Action::Preserve),
            ],
            &mut c,
        )
        .unwrap();
        assert!(matches!(
            v(&[("Neubaugasse 22", K::StreetAddress)]).verify(&s, &c),
            Verdict::Fail(_)
        ));
        // the same, where only the NER re-scan can see it: a street word
        // in a fully preserved hit
        let text = "Ich wohne in 6020 Hauptplatz.";
        let s = sanitize(
            text,
            &[
                dec(13, 17, K::PostalCode, Action::Preserve),
                dec(18, 28, K::City, Action::Preserve),
            ],
            &mut c,
        )
        .unwrap();
        assert!(fails_ner(
            v(&[("6020 Hauptplatz", K::StreetAddress)]).verify(&s, &c)
        ));
    }

    /// Task 9 rulings 1-3: contact labels next to a token, `Account
    /// holder`, and a PERSON hit inside a preserved town right after a
    /// postal code are dropped; a label word that is also a surname, a
    /// town with no postal code before it, and a hit reaching past the
    /// town still fail.
    #[test]
    fn contact_labels_and_town_persons_are_dropped_only_in_their_shape() {
        let v = flags_k;
        let mut c = ctx();
        let tok = |text: &str, c: &mut Context| {
            let q = text.find("Quolnath").unwrap();
            sanitize(text, &[dec(q, q + 8, K::Person, Action::Tokenize)], c).unwrap()
        };
        let s = tok("Quolnath\nWeb: siehe oben", &mut c);
        assert_eq!(v(&[("Web", K::Person)]).verify(&s, &c), Verdict::Pass);
        let s = tok("Quolnath\nUID siehe oben", &mut c);
        assert_eq!(v(&[("UID", K::Person)]).verify(&s, &c), Verdict::Pass);
        let s = tok("Quolnath\nE-Mail: siehe oben", &mut c);
        assert_eq!(v(&[("E-Mail", K::Person)]).verify(&s, &c), Verdict::Pass);
        // guard: words that are also names are never dropped next to a
        // token (fix round 1: `Holder`, `Nachbar`, `Iban`, `Bic` left the
        // lists)
        let names: [(&str, &'static [(&'static str, K)]); 6] = [
            ("Quolnath Handy ruft an.", &[("Handy", K::Person)]),
            ("Quolnath Holder ruft an.", &[("Holder", K::Person)]),
            ("Account holder: Quolnath", &[("Account holder", K::Person)]),
            ("Quolnath\nNachbar", &[("Nachbar", K::Person)]),
            ("Quolnath Iban ruft an.", &[("Iban", K::Person)]),
            ("Quolnath Bic ruft an.", &[("Bic", K::Person)]),
        ];
        for (text, w) in names {
            let s = tok(text, &mut c);
            assert!(fails_ner(v(w).verify(&s, &c)), "{text:?}");
        }
        // M1: a role word plus a name next to a token still fails
        let s = tok("Quolnath\nTechniker Huber", &mut c);
        assert!(fails_ner(
            v(&[("Techniker Huber", K::Person)]).verify(&s, &c)
        ));
        // The regex town span (7b) is the only CITY the PERSON rule trusts.
        let town = |a: usize, b: usize, src: D| Decision {
            span: Span::new(a, b, K::City, 0.85, src),
            action: Action::Preserve,
        };
        let postal = |a: usize, b: usize| Decision {
            span: Span::new(a, b, K::PostalCode, 0.85, D::RegexSyntax),
            action: Action::Preserve,
        };
        // a town after a postal code, read as a name: dropped
        let text = "Ich wohne in 6020 Innsbruck.";
        let pc_city = [postal(13, 17), town(18, 27, D::RegexSyntax)];
        let s = sanitize(text, &pc_city, &mut c).unwrap();
        assert_eq!(v(&[("Innsbruck", K::Person)]).verify(&s, &c), Verdict::Pass);
        // guard: the hit reaches past the town
        let text = "Ich wohne in 6020 Innsbruck Huber.";
        let s = sanitize(text, &pc_city, &mut c).unwrap();
        assert!(fails_ner(
            v(&[("Innsbruck Huber", K::Person)]).verify(&s, &c)
        ));
        // guard: a preserved town with no postal code before it
        let s = sanitize(
            "Ich wohne in Innsbruck.",
            &[town(13, 22, D::RegexSyntax)],
            &mut c,
        )
        .unwrap();
        assert!(fails_ner(v(&[("Innsbruck", K::Person)]).verify(&s, &c)));
        // guard: the postal code is on the line before
        let text = "Ich wohne in 6020\nInnsbruck.";
        let s = sanitize(
            text,
            &[postal(13, 17), town(18, 27, D::RegexSyntax)],
            &mut c,
        )
        .unwrap();
        assert!(fails_ner(v(&[("Innsbruck", K::Person)]).verify(&s, &c)));
        // guard: a street word in the preserved town
        let text = "Ich wohne in 6020 Hauptplatz.";
        let s = sanitize(
            text,
            &[postal(13, 17), town(18, 28, D::RegexSyntax)],
            &mut c,
        )
        .unwrap();
        assert!(fails_ner(v(&[("Hauptplatz", K::Person)]).verify(&s, &c)));
        // I1 guard: a CITY from the model, a dictionary, or a store copy
        // over a surname after an order number is not the regex town
        let text = "Bestellung 20231 Hall";
        for src in [D::Ner, D::Dictionary, D::Redaction] {
            let s = sanitize(text, &[postal(11, 16), town(17, 21, src)], &mut c).unwrap();
            assert!(
                fails_ner(v(&[("Hall", K::Person)]).verify(&s, &c)),
                "{src:?}"
            );
        }
    }

    /// Ruling L103: the verifier's product cue. Under `HarnessStatic` a
    /// PERSON hit that is exactly a listed product name is not a failure.
    /// Under `Free`, and through `verify`, it still fails. A hit with any
    /// other word, another casing, another kind, or a non-product name fails
    /// under both origins, and the leak check is untouched.
    #[test]
    fn product_cue_discards_exact_product_names_only_in_harness_static_text() {
        let hs = TextOrigin::HarnessStatic;
        let run = |text: &str, flags: &'static [(&'static str, K)], origin: TextOrigin| {
            let mut c = ctx();
            let s = sanitize(text, &[], &mut c).unwrap();
            flags_k(flags).verify_at(&s, &c, origin)
        };
        let claude: &'static [(&'static str, K)] = &[("Claude", K::Person)];
        let cc = "You are Claude Code. Claude never guesses file contents.";
        assert_eq!(run(cc, claude, hs), Verdict::Pass);
        assert!(fails_ner(run(cc, claude, TextOrigin::Free)));
        {
            let mut c = ctx();
            let s = sanitize(cc, &[], &mut c).unwrap();
            assert!(fails_ner(flags_k(claude).verify(&s, &c)), "verify is Free");
        }
        assert_eq!(
            run(
                "You are Codex, a coding agent.",
                &[("Codex", K::Person)],
                hs
            ),
            Verdict::Pass
        );
        // decided and pinned (exact-span rule): a bare `Claude` hit in a
        // harness-static text is the product, even after `Thanks,`
        // (threat-model residual); a hit with another word in it is not
        assert_eq!(
            run("Thanks, Claude, for the form.", claude, hs),
            Verdict::Pass
        );
        assert!(fails_ner(run(
            "Thanks, Claude, for the form.",
            &[("Thanks, Claude", K::Person)],
            hs
        )));
        assert!(fails_ner(run(
            "Anfrage von Claude Dubois.",
            &[("Claude Dubois", K::Person)],
            hs
        )));
        assert!(fails_ner(run(
            "Anfrage von Claude Dubois.",
            &[("Claude", K::Person), ("Dubois", K::Person)],
            hs
        )));
        // other casings, glued words, other kinds, other names
        assert!(fails_ner(run(
            "ask claude today",
            &[("claude", K::Person)],
            hs
        )));
        assert!(fails_ner(run(
            "you are CLAUDE",
            &[("CLAUDE", K::Person)],
            hs
        )));
        assert!(fails_ner(run(
            "ClaudeBot runs",
            &[("ClaudeBot", K::Person)],
            hs
        )));
        assert!(fails_ner(run(
            "Claude Street 5",
            &[("Claude", K::StreetAddress)],
            hs
        )));
        assert!(fails_ner(run(
            "Herr Huber ruft an",
            &[("Huber", K::Person)],
            hs
        )));
        // the leak check runs first and is not touched by the origin
        let mut c = ctx();
        let s = sanitize(
            "Claude hat angerufen. Claude.",
            &[dec(0, 6, K::Person, Action::Tokenize)],
            &mut c,
        )
        .unwrap();
        assert!(matches!(
            flags_k(claude).verify_at(&s, &c, hs),
            Verdict::Fail(r) if r.iter().any(|x| x.check == CheckId::Leak)
        ));
    }

    /// R18: the list holds exact, capitalized product names; only `Claude`
    /// is also a first name.
    #[test]
    fn harness_product_names_are_exact_names() {
        for n in HARNESS_PRODUCT_NAMES {
            assert!(
                n.chars().next().is_some_and(char::is_uppercase)
                    && n.chars().skip(1).all(|c| c.is_ascii_lowercase()),
                "{n}"
            );
            if *n != "Claude" {
                assert!(!crate::gazetteer::is_first_name(n), "{n} is a first name");
            }
        }
    }

    /// Fix round 1 (security review of 6c): the product cue applies only to
    /// a whole word that sits next to no placeholder. `Claude` beside a
    /// tokenized surname is a given name the sanitizer split off (its C3
    /// cue dropped `Claude`, the surname was tokenized), and `Claude` inside
    /// `Jean-Claude` or glued to other letters is part of another word.
    #[test]
    fn product_cue_needs_a_whole_word_away_from_any_token() {
        let hs = TextOrigin::HarnessStatic;
        let claude: &'static [(&'static str, K)] = &[("Claude", K::Person)];
        let run_with = |text: &str, decs: &[Decision], origin: TextOrigin| {
            let mut c = ctx();
            let s = sanitize(text, decs, &mut c).unwrap();
            flags_k(claude).verify_at(&s, &c, origin)
        };
        // next to a tokenized surname, on either side
        let t = "Anfrage von Claude Dubois.";
        assert!(fails_ner(run_with(
            t,
            &[dec(19, 25, K::Person, Action::Tokenize)],
            hs
        )));
        let t = "Anfrage von Dubois Claude.";
        assert!(fails_ner(run_with(
            t,
            &[dec(12, 18, K::Person, Action::Tokenize)],
            hs
        )));
        let t = "Dubois,\nClaude";
        assert!(fails_ner(run_with(
            t,
            &[dec(0, 6, K::Person, Action::Tokenize)],
            hs
        )));
        // a token far away (another word between) does not block the cue
        let t = "Claude never asks Herr Dubois.";
        assert_eq!(
            run_with(t, &[dec(23, 29, K::Person, Action::Tokenize)], hs),
            Verdict::Pass
        );
        // part of a longer word
        for t in [
            "Bonjour Jean-Claude, merci.",
            "Bonjour Claude-Henri.",
            "ClaudeX runs",
            "XClaude runs",
            "Claude2 runs",
            "le_Claude",
        ] {
            assert!(fails_ner(run_with(t, &[], hs)), "{t}");
        }
        // a whole word with punctuation around it, or at either end of the text
        for t in [
            "(Claude) helps.",
            "Claude.",
            "use Claude",
            "\"Claude\" never guesses",
            "Claude's answer",
        ] {
            assert_eq!(run_with(t, &[], hs), Verdict::Pass, "{t}");
        }
    }
}
