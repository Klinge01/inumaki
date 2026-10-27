//! Referential consistency over the whole token store (engine spec §6.4,
//! concept §24): every clear copy of a value the store already holds is
//! tokenized with that value's existing entity before verification.
//!
//! The forms searched are the verifier's leak-check forms
//! ([`SecondPassVerifier::leak_patterns`](crate::verify::SecondPassVerifier::leak_patterns)):
//! each original with its transliterated and diacritic-folded forms, each
//! PERSON's name parts in the same three forms, and each removed value with
//! and without a trailing sentence mark. Every store value counts, of every
//! kind, preserved kinds included (plan ruling C1): a preserved-kind value
//! is in the store only because something tokenized it, and a later clear
//! copy would undo that. A whole value that is only greeting vocabulary
//! (`Hello`; Task 7d,
//! [`is_greeting_only_value`](crate::detect::plausible::is_greeting_only_value))
//! is a form here too, though the leak check skips it: left in clear, the
//! verifier's NER re-scan tags such a word as a PERSON and refuses the
//! text. The leak check stays the backstop.
//!
//! Privacy: the forms are originals. Every copy made here is held in
//! `Zeroizing` and wiped on drop; the automata keep their own copy of the
//! pattern bytes, which cannot be wiped. `Debug` prints counts only.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::ops::Range;
use std::sync::{Arc, OnceLock};

use zeroize::Zeroizing;

use crate::alias::AliasTable;
use crate::detect::dictionary::{DictionaryDetector, PatternOrigins};
use crate::detect::validate_span;
use crate::policy::{Action, Decision};
use crate::redact::{Redaction, RedactionAction};
use crate::span::{EntityKind, Span};
use crate::stoplist::name_parts;
use crate::token::{NormKey, TokenStore, normalize};
use crate::verify::second_pass::{LeakIndex, LeakLayer, fold_diacritics, transliterate};

/// Shorter forms are not searched (the leak check's minimum for originals
/// and removed values; name parts are at least four characters already).
const MIN_FORM_CHARS: usize = 3;

/// The store's values as dictionaries in the leak check's forms
/// (`SecondPassVerifier::leak_patterns`): each original with its
/// transliterated and diacritic-folded forms, each PERSON's
/// `stoplist::name_parts` in the same three forms, and each removed value
/// with and without a trailing sentence mark; at least 3 characters after
/// whitespace collapse. Case variants and whitespace runs are
/// `DictionaryDetector::from_entries`'s own. `Debug`: counts only.
///
/// Task 7e (ruling L62): one or more layers, each over part of the store's
/// values. A store that keeps a [`StoreDictCache`] hands out its cached
/// base layer, its middle tier, and a small top layer over the values
/// written since (Task 6), so a large store is not compiled again for
/// every text. Together the layers find
/// the same spans as one dictionary over the store's current values: a
/// working set's entry evicted since the base was built is a dead entry
/// there, its forms still in the automaton but matched only where a live
/// entry shares them. The kind reported for a span can differ from a fresh
/// build's when a form is shared across kinds: a pattern keeps the kind of
/// its highest-confidence entry, which may be a dead one, and two layers
/// can report one span under two kinds. Cloning shares the
/// layers.
#[derive(Clone)]
pub struct StoreDict {
    layers: Vec<Arc<Layer>>,
    /// Entries of `layers[0]` no longer in the store (by entry ordinal).
    dead: Arc<HashSet<usize>>,
}

/// One compiled dictionary over a list of store values. Its forms are
/// `Zeroizing`; the automata keep their own copy of the pattern bytes.
struct Layer {
    originals: Option<DictionaryDetector>,
    /// The forms (indices into `forms`) behind each pattern of `originals`.
    origins: PatternOrigins,
    removed: Option<DictionaryDetector>,
    /// Form entries (before case variants) in each dictionary, for `Debug`.
    counts: (usize, usize),
    /// Every original, by index (the source index's values): each store
    /// entry's value, then its alias variants when built through aliases.
    sources: Vec<Zeroizing<String>>,
    /// The store entry (its ordinal in this layer's input) behind each
    /// source: an alias variant shares its canonical's.
    owner: Vec<usize>,
    /// Each store entry's kind and the index of its own value in `sources`.
    entries: Vec<(EntityKind, usize)>,
    /// Every original form (before case variants) with the index of the
    /// original that produced it; the source index is built from these.
    forms: Vec<(EntityKind, Zeroizing<String>, usize)>,
    /// `(kind, token::normalize(form))` → the indices of the originals of
    /// that kind that produced the form (N1). Built on the first original
    /// match only: most texts match nothing, and normalizing every form of
    /// a large store would cost O(store) per pass for nothing. A cached
    /// layer builds it once for its whole life.
    by_form: OnceLock<HashMap<(EntityKind, NormKey), Vec<usize>>>,
    /// Keyed hash of `(kind, value)` → entry ordinals, for an eviction to
    /// find its entry; built on the first eviction only.
    by_entry: OnceLock<HashMap<u64, Vec<usize>>>,
}

impl fmt::Debug for StoreDict {
    /// Counts only, never a value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sum = |g: fn(&Layer) -> usize| self.layers.iter().map(|l| g(l)).sum::<usize>();
        f.debug_struct("StoreDict")
            .field("originals", &sum(|l| l.counts.0))
            .field("removed", &sum(|l| l.counts.1))
            .field("sources", &sum(|l| l.sources.len()))
            .field("layers", &self.layers.len())
            .field("dead", &self.dead.len())
            .finish()
    }
}

/// One clear copy of a store value. `Debug` prints kind and range only.
pub struct StoreMatch {
    /// What to fold into the pass's decisions: `Tokenize` with the match's
    /// kind label for an original, `Remove` for a removed value.
    pub redaction: Redaction,
    /// The store original this match is a form of, when the matched form
    /// (by `token::normalize` key) belongs to exactly one store original
    /// of that kind; `None` when two or more originals share the form
    /// (e.g. the surname of two people) or for removed values.
    pub source: Option<Zeroizing<String>>,
}

impl fmt::Debug for StoreMatch {
    /// Kind, range, action, and whether a source is known; never text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreMatch")
            .field("kind", &self.redaction.kind)
            .field("range", &(self.redaction.start..self.redaction.end))
            .field("action", &self.redaction.action)
            .field("linked", &self.source.is_some())
            .finish()
    }
}

/// Whether `form` is long enough, counted in whitespace-collapsed form
/// without another copy.
fn long_enough(form: &str) -> bool {
    let (words, chars) = form
        .split_whitespace()
        .fold((0usize, 0usize), |(w, c), x| (w + 1, c + x.chars().count()));
    chars + words.saturating_sub(1) >= MIN_FORM_CHARS
}

/// One dictionary over `entries`; `None` when there are none.
fn dictionary<'a>(
    entries: impl ExactSizeIterator<Item = (&'a EntityKind, &'a Zeroizing<String>)>,
) -> crate::Result<Option<DictionaryDetector>> {
    if entries.len() == 0 {
        return Ok(None);
    }
    // `from_entries` borrows; the automaton keeps its own pattern bytes.
    DictionaryDetector::from_entries(entries.map(|(k, v)| (k.clone(), v.as_str()))).map(Some)
}

/// The per-process random key for the value hashes below (no stable
/// digest of an original exists).
pub(crate) fn hash_key() -> &'static RandomState {
    static KEY: OnceLock<RandomState> = OnceLock::new();
    KEY.get_or_init(RandomState::new)
}

#[cfg(test)]
thread_local! {
    /// Test hook: make [`StoreDict::build`] fail on this thread, so the
    /// engine's fail-closed path can be exercised (no store value makes
    /// `DictionaryDetector::from_entries` fail).
    static FAIL_BUILD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// What a [`StoreDict`] over `store` depends on: every entry and removed
/// value, each hashed with a per-process random key (no stable digest of an
/// original exists), summed so the store's order does not matter, with the
/// count (Task 7d; the scheme of inumakid's re-check fingerprint, Task 7c).
/// Two stores holding the same values give the same fingerprint; any write
/// that adds a value changes it. The engine compares it only within one
/// call, against the same store before and after a pass (ruling L58), for a
/// store that keeps no [`StoreDictCache`]. A collision there (about 2^-64,
/// unpredictable without the key) would reuse the dictionary from before
/// the pass's mints, so it could miss a value minted in between; the leak
/// check, built from the store itself, still refuses that value's clear
/// copy.
pub fn store_fingerprint(store: &dyn TokenStore) -> (u64, usize) {
    let key = hash_key();
    let (mut sum, mut count) = (0u64, 0usize);
    for (tag, (kind, value)) in store
        .entries()
        .map(|e| (0u8, e))
        .chain(store.removed_entries().map(|e| (1u8, e)))
    {
        sum = sum.wrapping_add(key.hash_one((tag, kind, value)));
        count += 1;
    }
    (sum, count)
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    /// Layers alive that were built on this thread (test hook below).
    static LIVE: std::cell::Cell<isize> = const { std::cell::Cell::new(0) };
}

/// Test hook (Task 7e): the dictionary layers built on this thread that are
/// still alive, net of those dropped on it. Lets a test see a store's
/// cached forms go with the store. Built only for this crate's tests and
/// with the `test-support` feature (other crates' tests); not an API.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn live_layers_on_this_thread() -> isize {
    LIVE.with(std::cell::Cell::get)
}

#[cfg(test)]
thread_local! {
    /// Test hook: how many [`StoreDict`] layer builds ran on this thread.
    static BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test hook: the number of [`StoreDict`] layer builds on this thread
/// (a full build or a cache's layer over the values written since).
#[cfg(test)]
pub(crate) fn builds_on_this_thread() -> usize {
    BUILDS.with(std::cell::Cell::get)
}

#[cfg(test)]
thread_local! {
    /// Test hooks (Task 6): how many base and middle-tier builds a
    /// [`StoreDictCache`] ran on this thread.
    static BASE_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static MID_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test hook (Task 6): the [`StoreDictCache`] base builds on this thread
/// (dictionary and leak base together count once).
#[cfg(test)]
pub(crate) fn base_builds_on_this_thread() -> usize {
    BASE_BUILDS.with(std::cell::Cell::get)
}

/// Test hook (Task 6): the [`StoreDictCache`] middle-tier builds on this
/// thread (dictionary and leak layer together count once).
#[cfg(test)]
pub(crate) fn mid_builds_on_this_thread() -> usize {
    MID_BUILDS.with(std::cell::Cell::get)
}

/// Test hook: while `on`, every [`StoreDict`] layer build on this thread
/// fails.
#[cfg(test)]
pub(crate) fn fail_builds_on_this_thread(on: bool) {
    FAIL_BUILD.with(|f| f.set(on));
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    /// Leak layers alive that were built on this thread (test hook below).
    static LIVE_LEAK: std::cell::Cell<isize> = const { std::cell::Cell::new(0) };
}

/// Test hook (Task 5, F13): the leak-check layers
/// ([`LeakLayer`]) built on this thread that are still alive, net of those
/// dropped on it. Lets a test see a store's cached leak patterns go with the
/// store. Built only for this crate's tests and with the `test-support`
/// feature (other crates' tests); not an API.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn live_leak_layers_on_this_thread() -> isize {
    LIVE_LEAK.with(std::cell::Cell::get)
}

/// A [`LeakLayer`] was built (`1`) or dropped (`-1`) on this thread.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn leak_layer_live(delta: isize) {
    LIVE_LEAK.with(|l| l.set(l.get() + delta));
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    /// Test hook: how many [`LeakLayer`] builds ran on this thread.
    static LEAK_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test hook: the number of [`LeakLayer`] builds on this thread (a cache's
/// base or top layer, or a per-call build). Built only for this crate's
/// tests and with the `test-support` feature; not an API.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn leak_builds_on_this_thread() -> usize {
    LEAK_BUILDS.with(std::cell::Cell::get)
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn leak_build_counted() {
    LEAK_BUILDS.with(|b| b.set(b.get() + 1));
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for Layer {
    fn drop(&mut self) {
        LIVE.with(|l| l.set(l.get() - 1));
    }
}

impl Layer {
    /// A layer over `entries` and `removed`, each value followed by its
    /// alias variants when `aliases` is given (what
    /// [`Aliased`](crate::alias::Aliased) reports for the same store).
    fn build<'a>(
        entries: impl Iterator<Item = (&'a EntityKind, &'a str)>,
        removed: impl Iterator<Item = (&'a EntityKind, &'a str)>,
        aliases: Option<&AliasTable>,
    ) -> crate::Result<Layer> {
        #[cfg(test)]
        BUILDS.with(|b| b.set(b.get() + 1));
        #[cfg(test)]
        if FAIL_BUILD.with(std::cell::Cell::get) {
            return Err(crate::Error::ConfigInvalid("store dictionary".into()));
        }
        let variants = |kind: &EntityKind, value: &str| -> Vec<&str> {
            aliases.map_or_else(Vec::new, |t| {
                t.variants_of(kind, value)
                    .iter()
                    .map(String::as_str)
                    .collect()
            })
        };
        let mut sources: Vec<Zeroizing<String>> = Vec::new();
        let mut owner: Vec<usize> = Vec::new();
        let mut store_entries: Vec<(EntityKind, usize)> = Vec::new();
        let mut forms: Vec<(EntityKind, Zeroizing<String>, usize)> = Vec::new();
        for (kind, value) in entries {
            let e = store_entries.len();
            store_entries.push((kind.clone(), sources.len()));
            for original in std::iter::once(value).chain(variants(kind, value)) {
                let i = sources.len();
                sources.push(Zeroizing::new(original.to_string()));
                owner.push(e);
                let mut push = |form: Zeroizing<String>| {
                    if long_enough(&form) {
                        forms.push((kind.clone(), form, i));
                    }
                };
                push(Zeroizing::new(original.to_string()));
                push(Zeroizing::new(transliterate(original)));
                push(Zeroizing::new(fold_diacritics(original)));
                if *kind == EntityKind::Person {
                    for part in name_parts(original) {
                        push(Zeroizing::new(part.to_string()));
                        push(Zeroizing::new(transliterate(part)));
                        push(Zeroizing::new(fold_diacritics(part)));
                    }
                }
            }
        }
        let mut removed_forms: Vec<(EntityKind, Zeroizing<String>)> = Vec::new();
        for (kind, value) in removed {
            for v in std::iter::once(value).chain(variants(kind, value)) {
                for form in [v, v.trim_end_matches(['.', ',', ';', ':', '!', '?', ')'])] {
                    if long_enough(form) {
                        removed_forms.push((kind.clone(), Zeroizing::new(form.to_string())));
                    }
                }
            }
        }
        let (originals, origins) = if forms.is_empty() {
            (None, PatternOrigins::default())
        } else {
            // `from_entries_traced` borrows; the automaton keeps its own
            // pattern bytes.
            let (d, o) = DictionaryDetector::from_entries_traced(
                forms.iter().map(|(k, f, _)| (k.clone(), f.as_str())),
            )?;
            (Some(d), o)
        };
        let removed_dict = dictionary(removed_forms.iter().map(|(k, f)| (k, f)))?;
        #[cfg(any(test, feature = "test-support"))]
        LIVE.with(|l| l.set(l.get() + 1));
        Ok(Layer {
            originals,
            origins,
            removed: removed_dict,
            counts: (forms.len(), removed_forms.len()),
            sources,
            owner,
            entries: store_entries,
            forms,
            by_form: OnceLock::new(),
            by_entry: OnceLock::new(),
        })
    }

    /// Whether some entry behind `pattern` of `originals` is not in `dead`.
    fn live_pattern(&self, pattern: usize, dead: &HashSet<usize>) -> bool {
        self.origins
            .of(pattern)
            .any(|f| !dead.contains(&self.owner[self.forms[f].2]))
    }

    fn by_form(&self) -> &HashMap<(EntityKind, NormKey), Vec<usize>> {
        self.by_form.get_or_init(|| {
            let mut m: HashMap<(EntityKind, NormKey), Vec<usize>> = HashMap::new();
            for (k, form, i) in &self.forms {
                let ids = m.entry((k.clone(), normalize(form))).or_default();
                if !ids.contains(i) {
                    ids.push(*i);
                }
            }
            m
        })
    }

    /// The ordinal of an entry of `kind` whose value is exactly `value`
    /// and that is not in `dead`.
    fn live_entry(&self, kind: &EntityKind, value: &str, dead: &HashSet<usize>) -> Option<usize> {
        let key = hash_key();
        let by_entry = self.by_entry.get_or_init(|| {
            let mut m: HashMap<u64, Vec<usize>> = HashMap::new();
            for (e, (k, i)) in self.entries.iter().enumerate() {
                m.entry(key.hash_one((k, self.sources[*i].as_str())))
                    .or_default()
                    .push(e);
            }
            m
        });
        by_entry
            .get(&key.hash_one((kind, value)))?
            .iter()
            .copied()
            .find(|&e| {
                !dead.contains(&e)
                    && self.entries[e].0 == *kind
                    && self.sources[self.entries[e].1].as_str() == value
            })
    }
}

impl StoreDict {
    /// Every entry and removed value of `store`, all kinds.
    pub fn build(store: &dyn TokenStore) -> crate::Result<StoreDict> {
        StoreDict::build_aliased(store, None)
    }

    /// [`StoreDict::build`] over `store` as seen through `aliases`: every
    /// value followed by its alias variants, as
    /// [`Aliased`](crate::alias::Aliased) reports them.
    pub fn build_aliased(
        store: &dyn TokenStore,
        aliases: Option<&AliasTable>,
    ) -> crate::Result<StoreDict> {
        let layer = Layer::build(store.entries(), store.removed_entries(), aliases)?;
        Ok(StoreDict {
            layers: vec![Arc::new(layer)],
            dead: Arc::default(),
        })
    }

    /// This dictionary plus a layer over `entries` (through `aliases`):
    /// values a store view holds beside the store it caches for (the
    /// proxy's request-scoped dataset values). No layer when there are none.
    pub fn with_values<'a>(
        mut self,
        entries: impl Iterator<Item = (&'a EntityKind, &'a str)>,
        aliases: Option<&AliasTable>,
    ) -> crate::Result<StoreDict> {
        let mut entries = entries.peekable();
        if entries.peek().is_some() {
            let layer = Layer::build(entries, std::iter::empty(), aliases)?;
            self.layers.push(Arc::new(layer));
        }
        Ok(self)
    }

    /// Number of layers (tests).
    #[cfg(test)]
    pub(crate) fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Redactions for every word-bounded match in `text` (all overlapping
    /// matches, `DictionaryDetector::detect_all`, deduplicated by
    /// (start, end, kind) across layers) that is not entirely inside a
    /// `Tokenize`/`Remove` decision or a protected range:
    /// `RedactionAction::Tokenize` with the match's kind label for
    /// originals, `RedactionAction::Remove` for removed values. Overlapping
    /// matches are all returned; the caller's `merge_redaction` unions
    /// them, so a longer match cannot hide a shorter clear copy (handoff R3
    /// (7)). A form only dead entries produce is no match.
    ///
    /// A match outside the text or off a char boundary is an error (fail
    /// closed), as for any detector.
    pub fn redactions(
        &self,
        text: &str,
        decisions: &[Decision],
        protected: &[Range<usize>],
    ) -> crate::Result<Vec<StoreMatch>> {
        let inside = |s: &Span| {
            protected
                .iter()
                .any(|p| p.start <= s.start && s.end <= p.end)
                || decisions.iter().any(|d| {
                    matches!(d.action, Action::Tokenize | Action::Remove)
                        && d.span.start <= s.start
                        && s.end <= d.span.end
                })
        };
        let mut out = Vec::new();
        // One occurrence comes back once per case variant and per layer:
        // keep one, counted only once it is a live match.
        let mut seen = HashSet::new();
        for (l, layer) in self.layers.iter().enumerate() {
            let Some(dict) = &layer.originals else {
                continue;
            };
            let spans = dict.detect_all_traced(text)?;
            for (s, _) in &spans {
                validate_span(text, s)?;
            }
            for (s, pattern) in spans {
                if s.start >= s.end || !self.live(l, pattern) {
                    continue;
                }
                if !seen.insert((s.start, s.end, s.kind.clone())) || inside(&s) {
                    continue;
                }
                let source = self.source_of(&s.kind, s.slice(text));
                out.push(StoreMatch {
                    redaction: Redaction {
                        start: s.start,
                        end: s.end,
                        kind: s.kind.label().to_string(),
                        action: RedactionAction::Tokenize,
                    },
                    source,
                });
            }
        }
        let mut seen = HashSet::new();
        for layer in &self.layers {
            let Some(dict) = &layer.removed else { continue };
            let spans = dict.detect_all(text)?;
            for s in &spans {
                validate_span(text, s)?;
            }
            for s in spans {
                if s.start >= s.end || !seen.insert((s.start, s.end, s.kind.clone())) || inside(&s)
                {
                    continue;
                }
                out.push(StoreMatch {
                    redaction: Redaction {
                        start: s.start,
                        end: s.end,
                        kind: s.kind.label().to_string(),
                        action: RedactionAction::Remove,
                    },
                    source: None,
                });
            }
        }
        Ok(out)
    }

    /// The kind of the first word-bounded match of a store form in `text`
    /// (an original's form or a removed value, every kind) that lies
    /// outside every range `covered` accepts (`covered(start, end)`);
    /// `None` when there is none. The service asks this of sanitized text
    /// (a cache hit, a batch's blocks): a clear copy of a value the store
    /// holds now is one a fresh pass would tokenize. Builds no redactions
    /// and links no source. A match outside the text or off a char boundary
    /// is an error (fail closed), as for any detector.
    pub fn uncovered_match(
        &self,
        text: &str,
        covered: impl Fn(usize, usize) -> bool,
    ) -> crate::Result<Option<EntityKind>> {
        for (l, layer) in self.layers.iter().enumerate() {
            let Some(dict) = &layer.originals else {
                continue;
            };
            for (s, pattern) in dict.detect_all_traced(text)? {
                validate_span(text, &s)?;
                if s.start < s.end && !covered(s.start, s.end) && self.live(l, pattern) {
                    return Ok(Some(s.kind));
                }
            }
        }
        for layer in &self.layers {
            let Some(dict) = &layer.removed else { continue };
            for s in dict.detect_all(text)? {
                validate_span(text, &s)?;
                if s.start < s.end && !covered(s.start, s.end) {
                    return Ok(Some(s.kind));
                }
            }
        }
        Ok(None)
    }

    /// Whether `pattern` of layer `l`'s originals has an entry still in
    /// the store (only the base layer has dead entries).
    fn live(&self, l: usize, pattern: usize) -> bool {
        l != 0 || self.dead.is_empty() || self.layers[0].live_pattern(pattern, &self.dead)
    }

    /// The single live original of `kind` whose forms include `matched`
    /// (by normalized key), across layers; `None` when none or several do.
    fn source_of(&self, kind: &EntityKind, matched: &str) -> Option<Zeroizing<String>> {
        let key = (kind.clone(), normalize(matched));
        let mut live = None;
        for (l, layer) in self.layers.iter().enumerate() {
            let Some(ids) = layer.by_form().get(&key) else {
                continue;
            };
            for &i in ids {
                if l == 0 && self.dead.contains(&layer.owner[i]) {
                    continue;
                }
                if live.is_some() {
                    return None;
                }
                live = Some((l, i));
            }
        }
        live.map(|(l, i)| Zeroizing::new(self.layers[l].sources[i].to_string()))
    }
}

/// A store's own cache of the [`StoreDict`] over its values (Task 7e,
/// integrator ruling L62). It is a field of the store whose originals it
/// copies, so its forms never outlive the store: dropped with it (a
/// session's end or TTL sweep, a namespace handle's close), and cleared by
/// every path that drops or resets the store's mappings
/// ([`StoreDictCache::clear`]: rotation, forget, delete, expiry, and a
/// working set's eviction of an entry that expires). No engine field or
/// static holds forms.
///
/// The store reports each write: a value added ([`StoreDictCache::note_entry`],
/// [`StoreDictCache::note_removed`]) or a working-set entry evicted
/// ([`StoreDictCache::note_evicted`]). [`StoreDictCache::get`] compiles the
/// whole store once (the base layer) and keeps three tiers (Task 6, ruling
/// L2-07):
///
/// - the **top** layer over the values written since the last merge,
///   rebuilt when they change;
/// - the **middle** tier: when the top's values exceed [`TOP_MAX`] they
///   merge into it, and it is rebuilt over its own values plus those;
/// - the **base**, compiled again (every tier with it) when there is a dead
///   entry and the dead entries plus the writes since the first one exceed
///   [`churn_limit`] (Q2), or when the middle tier's values exceed
///   [`mid_limit`]. A store that only grows has no dead entry, so its full
///   builds are amortized over the middle tier.
///
/// An evicted entry of the top or middle tier is removed from that tier's
/// values at once, its layers dropped (the middle tier's take the top's
/// with them, whose leak ordinals follow it); an evicted base entry is a
/// dead entry of the base, never matched, and its forms leave the cache
/// within [`churn_limit`] writes of any kind after the first dead entry:
/// the write that passes the limit drops every tier (7e's bound). An entry
/// that expires is cleared at eviction instead. A different alias table
/// (by [`AliasTable::fingerprint`]) compiles again too.
///
/// Privacy: the values of the top and middle tiers are copied here
/// (`Zeroizing`, at most [`TOP_MAX`] + [`mid_limit`] of them) to compile
/// their layers. `Debug` prints counts only.
///
/// Task 5 (Phase B, L69): the cache also holds the verifier's leak-check
/// layers ([`LeakLayer`], served by [`StoreDictCache::leak`]), one per tier:
/// a leak base built in the same rebuild as the dictionary's base, from the
/// same enumeration (so the dead entries apply to both), a middle and a top
/// leak layer built and dropped exactly where the tier's dictionary layer
/// is. Owner ordinals continue across `[base, middle, top]`, so the first
/// live owner is a fresh build's. They live and go with the rest of the
/// state: every write invalidates the top layers, and `clear` (forget,
/// rotation, expiry, a closed epoch entry's eviction, close) and the
/// store's drop take every tier.
#[derive(Default)]
pub struct StoreDictCache {
    state: Option<Cached>,
}

struct Cached {
    aliases: u64,
    base: Arc<Layer>,
    dead: Arc<HashSet<usize>>,
    /// The middle tier's entries and removed values (merged top values).
    mid_values: Vec<(EntityKind, Zeroizing<String>)>,
    mid_removed: Vec<(EntityKind, Zeroizing<String>)>,
    /// The layer over the middle tier's values; `None` when stale or empty.
    mid: Option<Arc<Layer>>,
    /// The top's entries and removed values (written since the last merge).
    added: Vec<(EntityKind, Zeroizing<String>)>,
    removed: Vec<(EntityKind, Zeroizing<String>)>,
    /// The layer over `added` and `removed`; `None` when stale or empty.
    delta: Option<Arc<Layer>>,
    /// The leak-check base, over the same values as `base` (same entry
    /// ordinals, so `dead` applies to it too).
    leak_base: Arc<LeakLayer>,
    /// The leak-check layer over the middle tier; `None` exactly where
    /// `mid` is.
    leak_mid: Option<Arc<LeakLayer>>,
    /// The leak-check layer over `added` and `removed`; `None` exactly
    /// where `delta` is.
    leak_top: Option<Arc<LeakLayer>>,
    /// Writes (`note_*`) since the first dead entry (Q2); 0 while none.
    writes_since_first_dead: usize,
}

impl Cached {
    /// Whether every tier must go and the base be compiled again: a dead
    /// entry with the dead entries plus the writes since the first one past
    /// [`churn_limit`] (7e's bound, Q2), or a middle tier past
    /// [`mid_limit`].
    fn needs_base(&self) -> bool {
        let base = self.base.entries.len();
        (!self.dead.is_empty()
            && self.dead.len() + self.writes_since_first_dead > churn_limit(base))
            || self.mid_values.len() + self.mid_removed.len() > mid_limit(base)
    }

    /// One more write: counted once there is a dead entry.
    fn count_write(&mut self) {
        if !self.dead.is_empty() {
            self.writes_since_first_dead += 1;
        }
    }

    /// A write since the top layers were built: both go.
    fn stale_top(&mut self) {
        self.delta = None;
        self.leak_top = None;
    }

    /// The middle tier changed: its layers go, and the top's with them
    /// (the top's leak ordinals follow the middle tier's).
    fn stale_mid(&mut self) {
        self.mid = None;
        self.leak_mid = None;
        self.stale_top();
    }

    /// Past [`TOP_MAX`], the top's values move into the middle tier.
    fn merge_top(&mut self) {
        if self.added.len() + self.removed.len() > TOP_MAX {
            self.mid_values.append(&mut self.added);
            self.mid_removed.append(&mut self.removed);
            self.stale_mid();
        }
    }
}

/// Dead entries plus writes since the first dead entry (Task 6, Q2) after
/// which every tier of a [`StoreDictCache`] goes and the next call compiles
/// the whole store again: a sixteenth of the base's entries, at least 256
/// and at most 1024. This bounds how long an LRU-evicted base value's forms
/// and leak patterns stay (never matched meanwhile): at most this many
/// writes of any kind. A store with no dead entry is not rebuilt by it.
pub fn churn_limit(base_entries: usize) -> usize {
    (base_entries / 16).clamp(256, 1024)
}

/// Values in a [`StoreDictCache`]'s top layer above which they merge into
/// the middle tier (Task 6). The proxy's session dictionary uses the same
/// bound for its delta segment.
pub const TOP_MAX: usize = 256;

/// Values in the middle tier above which the base is compiled again: a
/// quarter of the base's entries, at least 1024 (Task 6). Above it a full
/// build is amortized over that many writes.
pub fn mid_limit(base_entries: usize) -> usize {
    (base_entries / 4).max(1024)
}

impl fmt::Debug for StoreDictCache {
    /// Counts only, never a value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("StoreDictCache");
        if let Some(c) = &self.state {
            d.field("base", &c.base.entries.len())
                .field("mid", &(c.mid_values.len() + c.mid_removed.len()))
                .field("added", &c.added.len())
                .field("removed", &c.removed.len())
                .field("dead", &c.dead.len());
        }
        d.finish()
    }
}

impl StoreDictCache {
    /// The store gained the entry `value` of `kind` (a mint, a surface
    /// form, a working-set load).
    pub fn note_entry(&mut self, kind: &EntityKind, value: &str) {
        if let Some(c) = &mut self.state {
            c.count_write();
            c.added
                .push((kind.clone(), Zeroizing::new(value.to_string())));
            c.stale_top();
            c.merge_top();
        }
        self.drop_when_stale();
    }

    /// The store gained the removed value `value` of `kind`.
    pub fn note_removed(&mut self, kind: &EntityKind, value: &str) {
        if let Some(c) = &mut self.state {
            c.count_write();
            c.removed
                .push((kind.clone(), Zeroizing::new(value.to_string())));
            c.stale_top();
            c.merge_top();
        }
        self.drop_when_stale();
    }

    /// The entry `value` of `kind` left the store (a working set's LRU
    /// eviction): removed from the top, else from the middle tier (whose
    /// layers go at once), else a dead entry of the base. A value the
    /// cache cannot place clears it (never guess). Forget, rotation,
    /// expiry, and the eviction of an entry that expires call
    /// [`StoreDictCache::clear`] instead: their values' forms must go at
    /// once.
    pub fn note_evicted(&mut self, kind: &EntityKind, value: &str) {
        let Some(c) = &mut self.state else { return };
        c.count_write();
        let at = |values: &[(EntityKind, Zeroizing<String>)]| {
            values
                .iter()
                .rposition(|(k, v)| k == kind && v.as_str() == value)
        };
        if let Some(p) = at(&c.added) {
            drop(c.added.remove(p));
            c.stale_top();
        } else if let Some(p) = at(&c.mid_values) {
            drop(c.mid_values.remove(p));
            c.stale_mid();
        } else {
            match c.base.live_entry(kind, value, &c.dead) {
                Some(e) => {
                    Arc::make_mut(&mut c.dead).insert(e);
                }
                None => self.state = None,
            }
        }
        self.drop_when_stale();
    }

    /// Drops every tier at the write that passes the base rule
    /// ([`Cached::needs_base`]), so an evicted value's forms do not wait
    /// for the next read.
    fn drop_when_stale(&mut self) {
        if self.state.as_ref().is_some_and(Cached::needs_base) {
            self.state = None;
        }
    }

    /// Drop every cached form and leak pattern now.
    pub fn clear(&mut self) {
        self.state = None;
    }

    /// True when nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.state.is_none()
    }

    /// The base's dead entries, `None` when nothing is cached (tests).
    #[cfg(test)]
    pub(crate) fn dead_len(&self) -> Option<usize> {
        self.state.as_ref().map(|c| c.dead.len())
    }

    /// The values in the top and middle tiers, `None` when nothing is
    /// cached (tests: the next write merges when the top holds `TOP_MAX`).
    #[cfg(test)]
    pub(crate) fn tier_sizes(&self) -> Option<(usize, usize)> {
        self.state.as_ref().map(|c| {
            (
                c.added.len() + c.removed.len(),
                c.mid_values.len() + c.mid_removed.len(),
            )
        })
    }

    /// The dictionary over `store`'s values (through `aliases` when
    /// given). `store` must be the store this cache belongs to, which has
    /// reported every write since the cache was last cleared. A failed
    /// build leaves nothing new cached; the next call tries again.
    pub fn get(
        &mut self,
        store: &dyn TokenStore,
        aliases: Option<&AliasTable>,
    ) -> crate::Result<StoreDict> {
        let c = self.current(store, aliases)?;
        let mut layers = vec![Arc::clone(&c.base)];
        layers.extend(c.mid.iter().cloned());
        layers.extend(c.delta.iter().cloned());
        Ok(StoreDict {
            layers,
            dead: Arc::clone(&c.dead),
        })
    }

    /// The verifier's leak-check index over `store`'s values (through
    /// `aliases` when given), from the same state as [`StoreDictCache::get`]
    /// (Task 5, Phase B). The caller holds it only for the current call (Q5)
    /// and checks it against the store before use
    /// ([`LeakIndex::covers`], Q1). Same contract and failure handling as
    /// `get`.
    pub fn leak(
        &mut self,
        store: &dyn TokenStore,
        aliases: Option<&AliasTable>,
    ) -> crate::Result<LeakIndex> {
        let c = self.current(store, aliases)?;
        let mut layers = vec![Arc::clone(&c.leak_base)];
        layers.extend(c.leak_mid.iter().cloned());
        layers.extend(c.leak_top.iter().cloned());
        Ok(LeakIndex::new(layers, Arc::clone(&c.dead)))
    }

    /// The cached state for `store`, compiled again when stale (another
    /// alias table, or the base rule of [`Cached::needs_base`]), its middle
    /// and top layers built when missing.
    fn current(
        &mut self,
        store: &dyn TokenStore,
        aliases: Option<&AliasTable>,
    ) -> crate::Result<&mut Cached> {
        let key = aliases.map_or(0, AliasTable::fingerprint);
        if self
            .state
            .as_ref()
            .is_some_and(|c| c.aliases != key || c.needs_base())
        {
            // Dropped before the build: one cached copy of the forms at a time.
            self.state = None;
        }
        let c = match self.state.take() {
            Some(c) => c,
            None => {
                // One enumeration order for both bases: entry ordinals, and
                // so the dead entries, mean the same in each.
                #[cfg(test)]
                BASE_BUILDS.with(|b| b.set(b.get() + 1));
                let base = Layer::build(store.entries(), store.removed_entries(), aliases)?;
                let leak_base =
                    LeakLayer::build(store.entries(), store.removed_entries(), aliases, 0)?;
                Cached {
                    aliases: key,
                    base: Arc::new(base),
                    dead: Arc::default(),
                    mid_values: Vec::new(),
                    mid_removed: Vec::new(),
                    mid: None,
                    added: Vec::new(),
                    removed: Vec::new(),
                    delta: None,
                    leak_base: Arc::new(leak_base),
                    leak_mid: None,
                    leak_top: None,
                    writes_since_first_dead: 0,
                }
            }
        };
        let c = self.state.insert(c);
        if c.mid.is_none() && (!c.mid_values.is_empty() || !c.mid_removed.is_empty()) {
            #[cfg(test)]
            MID_BUILDS.with(|b| b.set(b.get() + 1));
            let mid = Layer::build(
                c.mid_values.iter().map(|(k, v)| (k, v.as_str())),
                c.mid_removed.iter().map(|(k, v)| (k, v.as_str())),
                aliases,
            )?;
            let leak_mid = LeakLayer::build(
                c.mid_values.iter().map(|(k, v)| (k, v.as_str())),
                c.mid_removed.iter().map(|(k, v)| (k, v.as_str())),
                aliases,
                c.leak_base.end_ordinal(),
            )?;
            c.mid = Some(Arc::new(mid));
            c.leak_mid = Some(Arc::new(leak_mid));
            // Defensive: every path that leaves the middle tier unbuilt
            // dropped the top already (`stale_mid`), so the top is built
            // after it and its leak ordinals follow the middle tier's.
            c.stale_top();
        }
        if c.delta.is_none() && (!c.added.is_empty() || !c.removed.is_empty()) {
            let first = c
                .leak_mid
                .as_ref()
                .map_or(c.leak_base.end_ordinal(), |m| m.end_ordinal());
            let delta = Layer::build(
                c.added.iter().map(|(k, v)| (k, v.as_str())),
                c.removed.iter().map(|(k, v)| (k, v.as_str())),
                aliases,
            )?;
            let top = LeakLayer::build(
                c.added.iter().map(|(k, v)| (k, v.as_str())),
                c.removed.iter().map(|(k, v)| (k, v.as_str())),
                aliases,
                first,
            )?;
            c.delta = Some(Arc::new(delta));
            c.leak_top = Some(Arc::new(top));
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokenSettings;
    use crate::redact::RedactionAction;
    use crate::token::{Context, ContextId};
    use crate::verify::SecondPassVerifier;
    use std::time::Duration;

    fn store() -> Context {
        let mut c = Context::new(
            ContextId(String::new()),
            Duration::from_secs(60),
            TokenSettings::default(),
        );
        c.token_for(&EntityKind::Person, "Jürgen Müßig-Weiß")
            .unwrap();
        c.token_for(&EntityKind::Person, "İlker Yılmaz").unwrap();
        c.token_for(&EntityKind::City, "Wien").unwrap();
        c.token_for(&EntityKind::Organization, "Muster  GmbH")
            .unwrap();
        c.record_removed(&EntityKind::custom("SECRET"), "hunter2pw.");
        c
    }

    /// Parity with the leak check: every leak-check pattern, standing alone
    /// in a text, is found by the store dictionary. The consistency pass
    /// must never miss a form the verifier would refuse.
    #[test]
    fn every_leak_pattern_is_found() {
        let c = store();
        let d = StoreDict::build(&c).unwrap();
        let (pats, _) = SecondPassVerifier::leak_patterns(&c);
        assert!(!pats.is_empty());
        for (i, p) in pats.iter().enumerate() {
            let text = format!("Text: {} ende", p.as_str());
            let found = d.redactions(&text, &[], &[]).unwrap();
            let (a, b) = (6, 6 + p.len());
            assert!(
                found
                    .iter()
                    .any(|m| m.redaction.start == a && m.redaction.end == b),
                "leak pattern #{i} not found"
            );
        }
    }

    /// Task 7c: a name part, a folded form, and a removed value each count
    /// when uncovered; a match inside a covered range does not.
    #[test]
    fn uncovered_matches_are_found_and_covered_ones_are_not() {
        let c = store();
        let d = StoreDict::build(&c).unwrap();
        let none = |_: usize, _: usize| false;
        for text in [
            "Gruss an Jurgen heute",
            "Herr Yilmaz kommt",
            "das Passwort hunter2pw ist alt",
            "Treffen in Wien",
        ] {
            assert!(
                d.uncovered_match(text, none).unwrap().is_some(),
                "{}",
                text.len()
            );
        }
        assert!(
            d.uncovered_match("nichts Bekanntes hier", none)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            d.uncovered_match("Treffen in Wien", none).unwrap(),
            Some(EntityKind::City)
        );
        let text = "Treffen in Wien";
        let at = text.find("Wien").unwrap();
        let inside = |s: usize, e: usize| at <= s && e <= at + 4;
        assert!(d.uncovered_match(text, inside).unwrap().is_none());
    }

    /// Every match of `d` in `text` as comparable plain data (test only).
    fn found(d: &StoreDict, text: &str) -> Vec<(usize, usize, String, bool, Option<String>)> {
        let mut v: Vec<_> = d
            .redactions(text, &[], &[])
            .unwrap()
            .into_iter()
            .map(|m| {
                (
                    m.redaction.start,
                    m.redaction.end,
                    m.redaction.kind.clone(),
                    m.redaction.action == RedactionAction::Remove,
                    m.source.map(|s| s.to_string()),
                )
            })
            .collect();
        v.sort();
        v
    }

    const PROBES: [&str; 6] = [
        "Gruss an Jurgen und Herrn Yilmaz aus Wien.",
        "Frau Berger und Anna Berger, Muster GmbH",
        "das Passwort hunter2pw. und geheim42x!",
        "Kurt Berger trifft Lena Quorvik in Graz",
        "HP Gruber und Hans-Peter Gruber, Hansi",
        "nichts Bekanntes hier",
    ];

    fn cached(c: &mut Context) -> StoreDict {
        TokenStore::store_dict(c, None).unwrap().unwrap()
    }

    /// Task 7e (ruling L62): a context keeps its dictionary; an unchanged
    /// context builds once, and a value minted after the build is found by
    /// the next dictionary, linked to its source.
    #[test]
    fn a_context_reuses_its_dict_until_a_write() {
        let mut c = store();
        let b = builds_on_this_thread();
        let first = cached(&mut c);
        let again = cached(&mut c);
        assert_eq!(builds_on_this_thread() - b, 1);
        assert_eq!(found(&first, PROBES[0]), found(&again, PROBES[0]));
        c.token_for(&EntityKind::Person, "Zyxwuria Quolnath")
            .unwrap();
        let d = cached(&mut c);
        let m = d.redactions("Gruss an Zyxwuria heute", &[], &[]).unwrap();
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(
            m[0].source.as_ref().map(|s| s.as_str()),
            Some("Zyxwuria Quolnath")
        );
        assert_eq!(builds_on_this_thread() - b, 2, "one small layer");
        assert_eq!(d.layer_count(), 2);
        drop(cached(&mut c));
        assert_eq!(builds_on_this_thread() - b, 2, "reused again");
    }

    /// Task 7e: base plus the layer over later writes finds what a fresh
    /// dictionary over the same store finds, shared name parts across the
    /// layers (an ambiguous source) and removed values included (no form
    /// here is shared across kinds, so kinds agree too).
    #[test]
    fn a_layered_dict_answers_as_a_fresh_build() {
        let mut c = store();
        c.token_for(&EntityKind::Person, "Anna Berger").unwrap();
        drop(cached(&mut c));
        c.token_for(&EntityKind::Person, "Kurt Berger").unwrap();
        c.token_for(&EntityKind::Person, "Lena Quorvik").unwrap();
        c.token_for(&EntityKind::City, "Graz").unwrap();
        c.record_removed(&EntityKind::custom("SECRET"), "geheim42x!");
        let layered = cached(&mut c);
        assert_eq!(layered.layer_count(), 2);
        let fresh = StoreDict::build(&c).unwrap();
        for text in PROBES {
            assert_eq!(found(&layered, text), found(&fresh, text), "{}", text.len());
        }
        let berger = found(&layered, PROBES[3]);
        assert!(
            berger.iter().any(|m| m.4.is_none() && m.1 - m.0 == 6),
            "Berger is shared, so unlinked: {berger:?}"
        );
        drop((layered, fresh));
        // Task 6 (L2-07, F21; fix round L2-19): three tiers. 1 300 values
        // minted one at a time into the context and reported to a cache of
        // this test's own cross three top-to-middle merges, one base
        // rebuild (the fourth merge passes `mid_limit`), and one more
        // merge. Each transition is checked right before and right after
        // the write that causes it.
        let mut cache = StoreDictCache::default();
        drop(cache.get(&c, None).unwrap());
        let (mut checks, mut three, mut merges, mut rebuilds) = (0, false, 0, 0);
        for i in 0..1300 {
            let merging = cache.tier_sizes().is_some_and(|(top, _)| top == TOP_MAX);
            if merging {
                three |= tier_check(&mut c, &mut cache, i, &mut checks);
            }
            let (b, m) = (base_builds_on_this_thread(), mid_builds_on_this_thread());
            match tier_value(i) {
                (k, v, true) => {
                    c.record_removed(&k, &v);
                    cache.note_removed(&k, &v);
                }
                (k, v, false) => {
                    c.token_for(&k, &v).unwrap();
                    cache.note_entry(&k, &v);
                }
            }
            if merging {
                three |= tier_check(&mut c, &mut cache, i + 1, &mut checks);
                let (rebuilt, merged) = (
                    base_builds_on_this_thread() - b,
                    mid_builds_on_this_thread() - m,
                );
                assert_eq!(rebuilt + merged, 1, "write {i}: one transition");
                rebuilds += rebuilt;
                merges += merged;
            }
        }
        assert_eq!((merges, rebuilds), (4, 1));
        assert_eq!(checks, 10);
        assert!(three, "base, middle tier, and top at once");
    }

    /// Task 6: one checkpoint of the three-tier test after `n` mints: 20
    /// probe texts find in `cache`'s dictionary what a fresh build of `c`
    /// finds, and at every second checkpoint the leak index answers as the
    /// per-call check (with two full per-call spot checks when this read
    /// rebuilt the base). Whether the dictionary had three layers.
    fn tier_check(
        c: &mut Context,
        cache: &mut StoreDictCache,
        n: usize,
        checks: &mut usize,
    ) -> bool {
        let texts = tier_probes(n);
        assert_eq!(texts.len(), 20);
        let b = base_builds_on_this_thread();
        let layered = cache.get(c, None).unwrap();
        let rebuilt = base_builds_on_this_thread() != b;
        let fresh = StoreDict::build(c).unwrap();
        for t in &texts {
            assert_eq!(found(&layered, t), found(&fresh, t), "{n} {}", t.len());
        }
        let three = layered.layer_count() == 3;
        drop((layered, fresh));
        if *checks % 2 == 0 || rebuilt {
            let mut probes = leak_probes(c);
            probes.extend(texts.iter().map(|t| cand(t, Vec::new())));
            let idx = cache.leak(c, None).unwrap();
            assert_leak_answers(c, &idx, &probes, if rebuilt { 2 } else { 0 });
        }
        *checks += 1;
        three
    }

    /// Task 6: value `i` of the tiered fixture, by `i % 10`: a person, an
    /// organization, a removed value, and cities otherwise (few forms
    /// each, so a fresh build stays cheap); no form is shared across kinds.
    fn tier_value(i: usize) -> (EntityKind, String, bool) {
        match i % 10 {
            0 => (
                EntityKind::Person,
                format!("Vorname{i} Familienname{i}"),
                false,
            ),
            3 => (EntityKind::Organization, format!("Firma{i} Handel"), false),
            6 => (EntityKind::custom("SECRET"), format!("geheim{i}x!"), true),
            _ => (EntityKind::City, format!("Ortschaft{i}"), false),
        }
    }

    /// 20 probe texts after `n` mints: `PROBES` plus 14 texts naming
    /// values spread over the whole store (base, middle tier, top), the
    /// latest ones, and some not minted yet.
    fn tier_probes(n: usize) -> Vec<String> {
        let mut out: Vec<String> = PROBES.iter().map(|s| s.to_string()).collect();
        for k in 0..14 {
            let a = (k * n / 13) / 10;
            out.push(format!(
                "Gruss an Vorname{} und Herrn Familienname{}, aus Ortschaft{}; \
                 Firma{} Handel, Passwort geheim{}x! und Ortschaft{} ende",
                10 * a,
                10 * a,
                10 * a + 1,
                10 * a + 3,
                10 * a + 6,
                n.saturating_sub(k + 1),
            ));
        }
        out
    }

    fn ctx() -> Context {
        Context::new(
            ContextId(String::new()),
            Duration::from_secs(60),
            TokenSettings::default(),
        )
    }

    /// Task 6: a store that only grows merges into the middle tier. With
    /// 4 096 base entries, 7e's rule (`churn_limit` 256) rebuilt the base
    /// every 257 writes, 7 times in 2 000; the tiers rebuild it exactly
    /// once, at the fourth merge (1 028 middle values past
    /// `mid_limit(4096)` = 1 024), and the merges after it fit the new
    /// base's limit. Driven through `note_entry`, read right after each
    /// merge.
    #[test]
    fn base_rebuilds_are_rare_on_a_growing_store() {
        let n = 4096;
        assert_eq!(churn_limit(n), 256);
        let base = persons_then_cities(0, None, 0..n);
        // The store as of the rebuild (the cache reads it only then).
        let at_rebuild = persons_then_cities(0, None, 0..n + 4 * (TOP_MAX + 1));
        let mut cache = StoreDictCache::default();
        drop(cache.get(&base, None).unwrap());
        let (b, m) = (base_builds_on_this_thread(), mid_builds_on_this_thread());
        for i in n..n + 2000 {
            let merging = cache.tier_sizes().is_some_and(|(top, _)| top == TOP_MAX);
            cache.note_entry(&EntityKind::City, &format!("Ortschaft{i}"));
            if merging {
                drop(cache.get(&at_rebuild, None).unwrap());
            }
        }
        assert_eq!(base_builds_on_this_thread() - b, 1, "one base rebuild");
        assert_eq!(
            mid_builds_on_this_thread() - m,
            6,
            "seven merges, one a rebuild"
        );
        let d = cache.get(&at_rebuild, None).unwrap();
        assert_eq!(d.layer_count(), 3, "base, middle tier, top");
        let text = format!("Gruss aus Ortschaft7 und Ortschaft{}", n + 1999);
        assert_eq!(d.redactions(&text, &[], &[]).unwrap().len(), 2);
    }

    /// `n` persons, `skip` left out, then `cities` cities: a store after
    /// an eviction and writes (Task 6).
    fn persons_then_cities(n: usize, skip: Option<usize>, cities: Range<usize>) -> Context {
        let mut c = ctx();
        for i in (0..n).filter(|&i| Some(i) != skip) {
            c.token_for(&EntityKind::Person, &format!("Vorname{i} Familienname{i}"))
                .unwrap();
        }
        for i in cities {
            c.token_for(&EntityKind::City, &format!("Ortschaft{i}"))
                .unwrap();
        }
        c
    }

    /// Task 6 (Q2): an LRU-evicted base value's forms and leak patterns
    /// leave within `churn_limit(base)` writes of any kind: one write
    /// short of it the base is kept (dead entry and all), at it the base
    /// goes, and the next call compiles it again with no dead entry. The
    /// writes cross a top-to-middle merge.
    #[test]
    fn an_evicted_base_value_leaves_within_churn_limit_writes() {
        let n = 4800;
        let limit = churn_limit(n);
        assert!(limit > TOP_MAX, "the writes cross a merge");
        let before = persons_then_cities(n, None, 0..0);
        let after = persons_then_cities(n, Some(7), 0..limit);
        let (live, live_leak) = (
            live_layers_on_this_thread(),
            live_leak_layers_on_this_thread(),
        );
        let mut cache = StoreDictCache::default();
        drop(cache.get(&before, None).unwrap());
        cache.note_evicted(&EntityKind::Person, "Vorname7 Familienname7");
        assert_eq!(cache.dead_len(), Some(1));
        for i in 0..limit - 1 {
            cache.note_entry(&EntityKind::City, &format!("Ortschaft{i}"));
            if i == limit - 2 {
                // Middle and top layers to drop later, built from `after`
                // (the cache reads the store only for a base build).
                drop(cache.get(&after, None).unwrap());
                drop(cache.leak(&after, None).unwrap());
            }
        }
        assert_eq!(cache.dead_len(), Some(1), "one write short: base kept");
        assert_eq!(live_layers_on_this_thread() - live, 3, "base, middle, top");
        assert_eq!(live_leak_layers_on_this_thread() - live_leak, 3);
        let b = base_builds_on_this_thread();
        cache.note_entry(&EntityKind::City, &format!("Ortschaft{}", limit - 1));
        assert!(cache.is_empty(), "at churn_limit writes the base goes");
        assert_eq!(
            live_layers_on_this_thread() - live,
            0,
            "old dict layers gone"
        );
        assert_eq!(
            live_leak_layers_on_this_thread() - live_leak,
            0,
            "old leak layers gone"
        );
        let d = cache.get(&after, None).unwrap();
        let idx = cache.leak(&after, None).unwrap();
        assert_eq!(base_builds_on_this_thread() - b, 1, "base rebuilt");
        assert_eq!(cache.dead_len(), Some(0));
        assert_eq!((d.layer_count(), idx.layer_count()), (1, 1));
        assert_eq!(live_layers_on_this_thread() - live, 1);
        assert_eq!(live_leak_layers_on_this_thread() - live_leak, 1);
        assert!(idx.covers(&after));
        let gone = "Gruss an Vorname7 und Familienname7";
        assert!(d.uncovered_match(gone, |_, _| false).unwrap().is_none());
        assert!(idx.reasons(&cand(gone, Vec::new())).is_empty());
        let text = "Gruss an Vorname8 aus Ortschaft3";
        assert_eq!(
            found(&d, text),
            found(&StoreDict::build(&after).unwrap(), text)
        );
    }

    /// Task 6: evicting a middle-tier value removes its copy and drops the
    /// middle tier's dictionary and leak layers at once (the top layers
    /// with them: their leak ordinals follow the middle tier's); the next
    /// call builds the tier without it. `clear` drops every tier.
    #[test]
    fn an_evicted_middle_tier_value_leaves_with_the_tier() {
        let before = persons_then_cities(20, None, 0..0);
        let after = {
            let mut c = persons_then_cities(20, None, 0..5);
            for i in 6..300 {
                c.token_for(&EntityKind::City, &format!("Ortschaft{i}"))
                    .unwrap();
            }
            c
        };
        let (live, live_leak) = (
            live_layers_on_this_thread(),
            live_leak_layers_on_this_thread(),
        );
        let mut cache = StoreDictCache::default();
        drop(cache.get(&before, None).unwrap());
        for i in 0..300 {
            cache.note_entry(&EntityKind::City, &format!("Ortschaft{i}"));
        }
        let m = mid_builds_on_this_thread();
        drop(cache.get(&after, None).unwrap());
        drop(cache.leak(&after, None).unwrap());
        assert_eq!(mid_builds_on_this_thread() - m, 1);
        assert_eq!(live_layers_on_this_thread() - live, 3, "base, middle, top");
        assert_eq!(live_leak_layers_on_this_thread() - live_leak, 3);
        cache.note_evicted(&EntityKind::City, "Ortschaft5");
        assert!(!cache.is_empty());
        assert_eq!(
            cache.dead_len(),
            Some(0),
            "no dead entry for a middle value"
        );
        assert_eq!(live_layers_on_this_thread() - live, 1, "middle tier gone");
        assert_eq!(
            live_leak_layers_on_this_thread() - live_leak,
            1,
            "leak_mid gone"
        );
        let d = cache.get(&after, None).unwrap();
        let idx = cache.leak(&after, None).unwrap();
        assert_eq!(mid_builds_on_this_thread() - m, 2);
        assert_eq!((d.layer_count(), idx.layer_count()), (3, 3));
        assert!(idx.covers(&after));
        let fresh = StoreDict::build(&after).unwrap();
        for text in [
            "Treffen in Ortschaft5 und Ortschaft6",
            "Gruss an Vorname3, Ortschaft299 und Ortschaft4",
        ] {
            assert_eq!(found(&d, text), found(&fresh, text), "{}", text.len());
        }
        assert!(
            idx.reasons(&cand("in Ortschaft5 heute", Vec::new()))
                .is_empty()
        );
        drop((d, idx, fresh));
        cache.clear();
        assert_eq!(live_layers_on_this_thread() - live, 0);
        assert_eq!(live_leak_layers_on_this_thread() - live_leak, 0);
    }

    /// Task 7e: an evicted entry is dead in the base (its forms match no
    /// more) and an entry added then evicted leaves the small layer; the
    /// result finds what a fresh build over the store after the changes
    /// finds.
    #[test]
    fn an_evicted_entry_is_dead_in_the_cached_dict() {
        let before = store();
        let mut after = Context::new(
            ContextId(String::new()),
            Duration::from_secs(60),
            TokenSettings::default(),
        );
        after
            .token_for(&EntityKind::Person, "Jürgen Müßig-Weiß")
            .unwrap();
        after.token_for(&EntityKind::City, "Wien").unwrap();
        after
            .token_for(&EntityKind::Organization, "Muster  GmbH")
            .unwrap();
        after
            .token_for(&EntityKind::Person, "Lena Quorvik")
            .unwrap();
        after.record_removed(&EntityKind::custom("SECRET"), "hunter2pw.");
        let mut cache = StoreDictCache::default();
        drop(cache.get(&before, None).unwrap());
        cache.note_entry(&EntityKind::Person, "Kurt Berger");
        cache.note_entry(&EntityKind::Person, "Lena Quorvik");
        cache.note_evicted(&EntityKind::Person, "İlker Yılmaz");
        cache.note_evicted(&EntityKind::Person, "Kurt Berger");
        assert!(!cache.is_empty());
        let d = cache.get(&after, None).unwrap();
        let fresh = StoreDict::build(&after).unwrap();
        for text in PROBES {
            assert_eq!(found(&d, text), found(&fresh, text), "{}", text.len());
        }
        assert!(
            d.uncovered_match("Herr Yilmaz kommt", |_, _| false)
                .unwrap()
                .is_none()
        );
        assert!(
            d.uncovered_match("Gruss an Jurgen", |_, _| false)
                .unwrap()
                .is_some()
        );
        // A value the cache cannot place clears it.
        cache.note_evicted(&EntityKind::Person, "Niemand Bekannt");
        assert!(cache.is_empty());
    }

    /// Task 7e: the cached forms go with the context.
    #[test]
    fn a_contexts_dict_drops_with_the_context() {
        let live = live_layers_on_this_thread();
        let mut c = store();
        drop(cached(&mut c));
        assert_eq!(
            live_layers_on_this_thread() - live,
            1,
            "cached on the context"
        );
        c.token_for(&EntityKind::City, "Graz").unwrap();
        drop(cached(&mut c));
        assert_eq!(
            live_layers_on_this_thread() - live,
            2,
            "base and small layer"
        );
        drop(c);
        assert_eq!(live_layers_on_this_thread() - live, 0);
    }

    /// Task 7e, as amended by Task 6: a store that grows past [`TOP_MAX`]
    /// writes merges them into the middle tier (base kept, empty top), and
    /// another alias table is never served a dictionary built through the
    /// first.
    #[test]
    fn churn_and_alias_changes_rebuild() {
        let mut c = store();
        drop(cached(&mut c));
        let b = base_builds_on_this_thread();
        for i in 0..=TOP_MAX {
            c.token_for(&EntityKind::City, &format!("Ortschaft{i}"))
                .unwrap();
        }
        assert_eq!(cached(&mut c).layer_count(), 2, "base and middle tier");
        assert_eq!(base_builds_on_this_thread(), b, "no dead entry: base kept");
        let table = AliasTable::build([crate::alias::AliasGroup {
            kind: EntityKind::Person,
            names: vec!["Hans-Peter Gruber".into(), "HP Gruber".into()],
        }])
        .unwrap();
        assert_ne!(table.fingerprint(), 0);
        c.token_for(&EntityKind::Person, "Hans-Peter Gruber")
            .unwrap();
        let b = builds_on_this_thread();
        let through = TokenStore::store_dict(&mut c, Some(&table))
            .unwrap()
            .unwrap();
        assert_eq!(builds_on_this_thread() - b, 1);
        assert_eq!(through.layer_count(), 1);
        let mut aliased = crate::alias::Aliased::new(&mut c, &table);
        let fresh = StoreDict::build(&aliased).unwrap();
        assert_eq!(found(&through, PROBES[4]), found(&fresh, PROBES[4]));
        assert!(
            found(&through, PROBES[4])
                .iter()
                .any(|m| m.0 == 0 && m.1 == 9)
        );
        let b = builds_on_this_thread();
        let via = TokenStore::store_dict(&mut aliased, None).unwrap().unwrap();
        assert_eq!(found(&via, PROBES[4]), found(&fresh, PROBES[4]));
        assert_eq!(builds_on_this_thread() - b, 0, "the aliased view shares it");
        drop(cached(&mut c));
        assert_eq!(builds_on_this_thread() - b, 1, "no alias view: rebuilt");
    }

    /// `Debug` prints counts, never a value.
    #[test]
    fn debug_prints_counts_only() {
        let c = store();
        let d = StoreDict::build(&c).unwrap();
        let s = format!("{d:?}");
        assert!(s.contains("originals"), "{s}");
        let m = d.redactions("Gruss aus Wien", &[], &[]).unwrap();
        let s = format!("{s} {m:?}");
        for secret in ["Jürgen", "Wien", "Muster", "hunter2", "Yılmaz"] {
            assert!(!s.contains(secret), "{s}");
        }
    }

    fn one_person(value: &str) -> Context {
        let mut c = Context::new(
            ContextId(String::new()),
            Duration::from_secs(60),
            TokenSettings::default(),
        );
        c.token_for(&EntityKind::Person, value).unwrap();
        c
    }

    fn verifier() -> SecondPassVerifier {
        let settings = crate::policy::VerifierSettings {
            allow_no_ner: true,
            ..Default::default()
        };
        SecondPassVerifier::new(crate::detect::regex::RegexDetector::new(), None, &settings)
            .unwrap()
    }

    /// Task 7d (A, ruling on the measured refusals): a stored PERSON value
    /// that is only a greeting word is no leak pattern, so a clear copy
    /// left in a text passes the leak check. It stays a consistency form:
    /// a new text's clear copy is still tokenized, because the verifier's
    /// NER re-scan tags a clear greeting word as a PERSON and refuses.
    #[test]
    fn a_greeting_only_store_value_is_a_form_but_no_leak() {
        let c = one_person("Hello");
        let text = "Hello again, the invoice is attached.";
        let d = StoreDict::build(&c).unwrap();
        assert!(
            d.redactions(text, &[], &[])
                .unwrap()
                .iter()
                .any(|m| m.redaction.start == 0 && m.redaction.end == 5)
        );
        let (pats, _) = SecondPassVerifier::leak_patterns(&c);
        assert!(pats.is_empty(), "{}", pats.len());
        let mut c = c;
        let s = crate::sanitize::sanitize(text, &[], &mut c).unwrap();
        assert_eq!(
            crate::verify::Verifier::verify(&verifier(), &s, &c),
            crate::verify::Verdict::Pass
        );
    }

    /// Task 7d (A): a greeting next to a name is a real value: its clear
    /// copy is a consistency match and a leak when left in clear.
    #[test]
    fn a_greeting_with_a_name_stays_a_form_and_a_leak() {
        let c = one_person("Hallo Anna");
        let text = "Nochmals Hallo Anna, wie besprochen.";
        let d = StoreDict::build(&c).unwrap();
        let at = text.find("Hallo Anna").unwrap();
        assert!(
            d.redactions(text, &[], &[])
                .unwrap()
                .iter()
                .any(|m| m.redaction.start == at && m.redaction.end == at + 10)
        );
        let mut c = c;
        let s = crate::sanitize::sanitize(text, &[], &mut c).unwrap();
        match crate::verify::Verifier::verify(&verifier(), &s, &c) {
            crate::verify::Verdict::Fail(r) => {
                assert!(r.iter().any(
                    |x| x.check == crate::verify::CheckId::Leak && x.kind == EntityKind::Person
                ))
            }
            v => panic!("expected a leak, got {v:?}"),
        }
    }

    // --- Task 5 (Phase B): the leak index lives on the store ---

    use crate::sanitize::Sanitized;
    use crate::verify::second_pass::{
        LeakIndex, leak_index_stale_count, legacy_check_leak,
        stale_on_this_thread as leak_stale_here,
    };
    use crate::verify::{CheckId, Reason, Verdict};

    /// A candidate with no replacements, `protected` as its token ranges.
    fn cand(text: &str, protected: Vec<Range<usize>>) -> Sanitized {
        Sanitized {
            text: text.to_string(),
            replacements: Vec::new(),
            blocked: Vec::new(),
            escalated: Vec::new(),
            protected,
        }
    }

    fn leak_index(store: &mut dyn TokenStore) -> LeakIndex {
        store.leak_index(None).unwrap().unwrap()
    }

    fn leak_kinds(v: &Verdict) -> Vec<EntityKind> {
        match v {
            Verdict::Fail(r) => r
                .iter()
                .filter(|x| x.check == CheckId::Leak)
                .map(|x| x.kind.clone())
                .collect(),
            _ => Vec::new(),
        }
    }

    fn kind_set(r: &[Reason]) -> HashSet<EntityKind> {
        r.iter().map(|x| x.kind.clone()).collect()
    }

    /// `store()` plus a greeting-only value, a removed value with a
    /// trailing `.`, two overlapping values, a value that is a token label,
    /// and 300 more persons.
    fn leak_store() -> Context {
        let mut c = store();
        for (k, v) in [
            (EntityKind::Person, "Hello"),
            (EntityKind::Person, "Anna Berger"),
            (EntityKind::Organization, "Berger Bau"),
            (EntityKind::custom("CODE"), "CITY"),
        ] {
            c.token_for(&k, v).unwrap();
        }
        c.record_removed(&EntityKind::custom("SECRET"), "geheim42x.");
        for i in 0..300 {
            c.token_for(&EntityKind::Person, &format!("Vorname{i} Familienname{i}"))
                .unwrap();
        }
        c
    }

    /// Probe texts: every leak pattern of the fixture's own values (not
    /// the 300 fillers) standing alone, two overlapping values, a value
    /// inside a real token, a value across a whitespace run, and `Wien`.
    fn leak_probes(c: &mut Context) -> Vec<Sanitized> {
        let (pats, _) = SecondPassVerifier::leak_patterns(&leak_store_small());
        let mut out: Vec<Sanitized> = pats
            .iter()
            .map(|p| cand(&format!("Text: {} ende", p.as_str()), Vec::new()))
            .collect();
        out.push(cand("Gruss an Anna Berger Bau heute", Vec::new()));
        let t = c.token_for(&EntityKind::City, "Wien").unwrap();
        let text = format!("Siehe {} heute", t.as_str());
        let at = text.find(t.as_str()).unwrap();
        let range = at..at + t.as_str().len();
        out.push(cand(&text, std::iter::once(range).collect()));
        out.push(cand("Treffen mit Jürgen \n\t Müßig-Weiß heute", Vec::new()));
        out.push(cand("Treffen in Wien", Vec::new()));
        out.push(cand("nichts Bekanntes hier", Vec::new()));
        out
    }

    /// The fixture's own values without the 300 fillers (probe source).
    fn leak_store_small() -> Context {
        let mut c = store();
        c.token_for(&EntityKind::Person, "Anna Berger").unwrap();
        c.token_for(&EntityKind::Organization, "Berger Bau")
            .unwrap();
        c.token_for(&EntityKind::custom("CODE"), "CITY").unwrap();
        c.record_removed(&EntityKind::custom("SECRET"), "geheim42x.");
        c
    }

    /// Every probe: the index answers as the per-call build (verdict and
    /// reason order), with the reason set of today's `check_leak`, and the
    /// index is never stale. The per-call build and today's check are each
    /// built once per call here (the same code `check_leak` and
    /// `legacy_check_leak` run per probe), so the 300 fillers stay cheap.
    fn assert_index_answers(store: &mut dyn TokenStore, probes: &[Sanitized]) {
        assert_index_answers_spot(store, probes, true);
    }

    /// [`assert_index_answers`], the per-call spot checks only when `spot`
    /// (each builds the store's patterns again: slow on a large store in a
    /// debug build).
    fn assert_index_answers_spot(store: &mut dyn TokenStore, probes: &[Sanitized], spot: bool) {
        let idx = leak_index(store);
        assert_leak_answers(store, &idx, probes, if spot { 5 } else { 0 });
    }

    /// [`assert_index_answers_spot`] with a given index over `store` and
    /// `spots` per-call spot checks.
    fn assert_leak_answers(
        store: &dyn TokenStore,
        idx: &LeakIndex,
        probes: &[Sanitized],
        spots: usize,
    ) {
        use crate::verify::second_pass::{LeakLayer, LegacyLeak};
        let v = verifier();
        let stale = leak_stale_here();
        let per_call = LeakIndex::single(
            LeakLayer::build(store.entries(), store.removed_entries(), None, 0).unwrap(),
        );
        let legacy = LegacyLeak::build(store);
        for (i, s) in probes.iter().enumerate() {
            let with = v.verify_with_leak(s, store, Some(idx));
            let fresh = per_call.reasons(s);
            if fresh.is_empty() {
                assert!(leak_kinds(&with).is_empty(), "probe #{i}");
            } else {
                assert_eq!(with, Verdict::Fail(fresh), "probe #{i}");
            }
            assert_eq!(
                leak_kinds(&with).into_iter().collect::<HashSet<_>>(),
                kind_set(&legacy.check(s)),
                "probe #{i}"
            );
        }
        // The full per-call path, spot-checked.
        for s in probes.iter().rev().take(spots) {
            assert_eq!(
                v.verify_with_leak(s, store, Some(idx)),
                v.verify_with_leak(s, store, None)
            );
            assert_eq!(
                kind_set(&legacy_check_leak(s, store)),
                kind_set(&legacy.check(s))
            );
        }
        assert_eq!(leak_stale_here(), stale, "the index covered the store");
    }

    /// Task 5 (Q1, Q3, Q4): base, base plus top, and a rebuilt base each
    /// answer as the per-call check; `Wien`, a CITY in the base and a
    /// PERSON in the top layer, is reported once, as the CITY a fresh
    /// build reports.
    #[test]
    fn a_leak_index_answers_as_check_leak() {
        let mut c = leak_store();
        let probes = leak_probes(&mut c);
        assert!(probes.len() > 20);
        assert_index_answers(&mut c, &probes);
        c.token_for(&EntityKind::Person, "Wien").unwrap();
        assert_eq!(leak_index(&mut c).layer_count(), 2, "Wien in the top");
        assert_index_answers(&mut c, &probes);
        let wien = probes.iter().rposition(|s| s.text == "Treffen in Wien");
        let wien = &probes[wien.unwrap()];
        let idx = leak_index(&mut c);
        assert_eq!(
            leak_kinds(&verifier().verify_with_leak(wien, &c, Some(&idx))),
            vec![EntityKind::City]
        );
        drop(idx);
        for i in 0..50 {
            c.token_for(&EntityKind::City, &format!("Kleinort{i}"))
                .unwrap();
        }
        assert_index_answers(&mut c, &probes);
        for i in 0..=churn_limit(0) {
            c.token_for(&EntityKind::City, &format!("Grossort{i}"))
                .unwrap();
        }
        assert_eq!(
            leak_index(&mut c).layer_count(),
            3,
            "base, middle tier, top (Task 6)"
        );
        assert_index_answers(&mut c, &probes);
    }

    /// Task 5 (Q6 b): the same through `Aliased`, `run_pass`'s path.
    #[test]
    fn a_leak_index_through_aliases_answers_as_check_leak() {
        let table = AliasTable::build([crate::alias::AliasGroup {
            kind: EntityKind::Person,
            names: vec!["Hans-Peter Gruber".into(), "HP Gruber".into()],
        }])
        .unwrap();
        let mut c = leak_store();
        c.token_for(&EntityKind::Person, "Hans-Peter Gruber")
            .unwrap();
        let mut probes = leak_probes(&mut c);
        probes.push(cand(PROBES[4], Vec::new()));
        probes.push(cand("Gruss an HP Gruber", Vec::new()));
        let mut aliased = crate::alias::Aliased::new(&mut c, &table);
        assert_index_answers(&mut aliased, &probes);
        let idx = leak_index(&mut aliased);
        assert_eq!(
            leak_kinds(&verifier().verify_with_leak(
                &cand("Gruss an HP Gruber", Vec::new()),
                &aliased,
                Some(&idx)
            )),
            vec![EntityKind::Person],
            "a variant is a leak"
        );
        drop(idx);
        aliased
            .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
            .unwrap();
        assert_index_answers(&mut aliased, &probes);
    }

    /// Task 5 (Q1): a write no `note_*` reported makes the index stale; the
    /// per-call build still refuses the value's clear copy.
    #[test]
    fn a_write_the_cache_never_saw_is_still_a_leak() {
        let mut c = store();
        drop(leak_index(&mut c));
        c.push_entry_unnoted_for_test(&EntityKind::Person, "Zyxwuria Quolnath");
        let idx = leak_index(&mut c);
        let s = cand("Gruss an Zyxwuria Quolnath", Vec::new());
        let (here, total) = (leak_stale_here(), leak_index_stale_count());
        let v = verifier().verify_with_leak(&s, &c, Some(&idx));
        assert_eq!(leak_kinds(&v), vec![EntityKind::Person], "{v:?}");
        assert_eq!(leak_stale_here() - here, 1);
        assert!(leak_index_stale_count() - total >= 1);
    }

    /// Task 5 (Q6 a): a failed index build is never a pass without a leak
    /// check: `run_pass`'s call falls back to the per-call build.
    #[test]
    fn a_failed_index_build_still_checks_leaks() {
        let mut c = store();
        fail_builds_on_this_thread(true);
        let r = c.leak_index(None).unwrap();
        let failed = crate::verify::second_pass::leak_index_failed_count();
        let leak = crate::verify::second_pass::store_leak_index(&mut c);
        fail_builds_on_this_thread(false);
        assert!(r.is_err());
        assert!(leak.is_none());
        assert!(
            crate::verify::second_pass::leak_index_failed_count() - failed >= 1,
            "a failed build is counted"
        );
        let s = cand("Gruss an Jurgen und Herrn Yilmaz", Vec::new());
        let v = crate::verify::Verifier::verify_with(&verifier(), &s, &c, leak.as_ref());
        assert_eq!(leak_kinds(&v), vec![EntityKind::Person], "{v:?}");
    }

    /// Task 5: an unchanged store builds its leak index once (a greeting-
    /// only value, which yields no pattern, still counts as covered, F12);
    /// a mint builds only the top layer.
    #[test]
    fn the_leak_index_is_built_once_while_the_store_is_unchanged() {
        let mut c = store();
        c.token_for(&EntityKind::Person, "Hello").unwrap();
        let (b, stale) = (leak_builds_on_this_thread(), leak_stale_here());
        let first = leak_index(&mut c);
        let again = leak_index(&mut c);
        assert_eq!(leak_builds_on_this_thread() - b, 1);
        assert_eq!(first.layer_count(), 1);
        let s = cand("Hello, Gruss aus Wien", Vec::new());
        let v = verifier().verify_with_leak(&s, &c, Some(&again));
        assert_eq!(leak_kinds(&v), vec![EntityKind::City]);
        assert_eq!(leak_stale_here(), stale, "covered");
        drop((first, again));
        c.token_for(&EntityKind::City, "Graz").unwrap();
        let idx = leak_index(&mut c);
        assert_eq!(leak_builds_on_this_thread() - b, 2, "only the top layer");
        assert_eq!(idx.layer_count(), 2);
        let s = cand("von Graz nach Wien", Vec::new());
        let v = verifier().verify_with_leak(&s, &c, Some(&idx));
        assert_eq!(leak_kinds(&v), vec![EntityKind::City]);
        assert_eq!(leak_stale_here(), stale, "covered");
    }

    /// Task 5 (L69): the leak patterns go with the context.
    #[test]
    fn a_contexts_leak_index_drops_with_the_context() {
        let live = live_leak_layers_on_this_thread();
        let mut c = store();
        drop(leak_index(&mut c));
        assert_eq!(
            live_leak_layers_on_this_thread() - live,
            1,
            "on the context"
        );
        c.token_for(&EntityKind::City, "Graz").unwrap();
        drop(leak_index(&mut c));
        assert_eq!(live_leak_layers_on_this_thread() - live, 2, "base and top");
        drop(c);
        assert_eq!(live_leak_layers_on_this_thread() - live, 0);
    }

    /// Task 5: `Debug` of the index prints counts, never a value.
    #[test]
    fn leak_index_debug_prints_counts_only() {
        let mut c = store();
        let idx = leak_index(&mut c);
        let s = format!("{idx:?}");
        assert!(s.contains("patterns"), "{s}");
        for secret in [
            "Jürgen", "Jurgen", "Wien", "WIEN", "Muster", "hunter2", "Yılmaz",
        ] {
            assert!(!s.contains(secret), "{s}");
        }
    }
}
