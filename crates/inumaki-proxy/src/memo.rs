//! The cross-session static-prompt NER memo (M8 spec §20, amendment of
//! 2026-10-12, part 1).
//!
//! A [`NerMemo`] remembers the span lists the NER models returned for long
//! system texts, so a new session does not pay the model again for text
//! another session already sent. It memoizes model inference only: a value
//! is the model's `Vec<Span>` (offsets, kinds, scores, detector id), never
//! text, a token or an original. Every other engine step still runs.
//!
//! The engine's sanitizer NER detector and its verifier NER detector are
//! each wrapped with [`NerMemo::wrap`]. A wrapper reads or writes the memo
//! only while a [`Scope`] for the leaf is open:
//!
//! - the sanitizer role, which core runs on the rayon pool, needs the keyed
//!   digest of its input in the scope's allow set;
//! - the verifier role, which core runs on the calling thread, needs the
//!   calling thread's mark.
//!
//! Each wrapper has its own random id and the role is in the key, so the
//! two roles never share an entry (the verifier stays independent). Every
//! [`NerMemo::clear`] bumps a generation; a scope opened before a clear
//! neither reads nor writes afterwards. A poisoned lock, a lost signal or
//! an input below [`STATIC_MIN_BYTES`] only costs a miss: the model runs.
//!
//! Nothing here prints an entry, a key or a digest: every `Debug` prints
//! counts only, and no type derives `Serialize`.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use hmac::{Hmac, Mac};
use inumaki_core::{DetectCtx, Detector, DetectorId, EntityKind, Span};
use sha2::Sha256;

/// The smallest input, in bytes, that the memo serves (spec: 2 KiB).
pub const STATIC_MIN_BYTES: usize = 2048;
/// The most entries the memo holds before it evicts the least recent.
pub const STATIC_MEMO_ENTRIES: usize = 256;
/// The most bytes (by entry weight) the memo holds before it evicts.
pub const STATIC_MEMO_BYTES: usize = 8 << 20;

/// Fixed per-entry overhead in the weight, beside the key and the spans.
const ENTRY_OVERHEAD: usize = 64;

/// Source of process-unique memo ids for the thread mark (0 means none).
static NEXT_MEMO_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// The calling thread's scope mark: which memo, how many nested scopes
    /// of it, and the generation the outermost one captured.
    static MARK: Cell<Mark> = const { Cell::new(Mark::NONE) };
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Mark {
    memo: u64,
    depth: u32,
    generation: u64,
}

impl Mark {
    const NONE: Mark = Mark {
        memo: 0,
        depth: 0,
        generation: 0,
    };
}

/// Which side of the engine a wrapper serves. Part of the memo key, so the
/// two never share an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NerRole {
    /// The sanitizer's NER pass over the leaf (runs on the rayon pool).
    Sanitizer,
    /// The verifier's NER re-scan of the candidate (runs on the caller).
    Verifier,
}

impl NerRole {
    fn tag(self) -> &'static [u8] {
        match self {
            NerRole::Sanitizer => b"sanitizer",
            NerRole::Verifier => b"verifier",
        }
    }
}

/// The memo's counters. Counts only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoStats {
    /// Eligible NER calls answered from the memo.
    pub hits: u64,
    /// Eligible NER calls that ran the model and stored its result.
    pub misses: u64,
    /// Entries held now.
    pub entries: u64,
    /// Clears since the memo was built.
    pub clears: u64,
}

/// One stored span list.
struct Slot {
    spans: Arc<[Span]>,
    weight: usize,
    tick: u64,
}

/// A hand-rolled LRU: the map, plus recency order by a monotonic tick.
#[derive(Default)]
struct Lru {
    map: HashMap<[u8; 32], Slot>,
    order: BTreeMap<u64, [u8; 32]>,
    tick: u64,
    bytes: usize,
}

impl Lru {
    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    /// The entry for `k`, made most recent.
    fn get(&mut self, k: &[u8; 32]) -> Option<Arc<[Span]>> {
        let tick = self.next_tick();
        let slot = self.map.get_mut(k)?;
        self.order.remove(&slot.tick);
        slot.tick = tick;
        self.order.insert(tick, *k);
        Some(Arc::clone(&slot.spans))
    }

    fn remove(&mut self, k: &[u8; 32]) {
        if let Some(old) = self.map.remove(k) {
            self.order.remove(&old.tick);
            self.bytes = self.bytes.saturating_sub(old.weight);
        }
    }

    /// Insert `spans` under `k`, evicting the least recent entries until
    /// both caps hold. An entry that alone exceeds a cap is not stored.
    fn insert(&mut self, k: [u8; 32], spans: Arc<[Span]>, max_entries: usize, max_bytes: usize) {
        let weight = weight(&spans);
        if max_entries == 0 || weight > max_bytes {
            return;
        }
        self.remove(&k);
        while self.map.len() >= max_entries || self.bytes + weight > max_bytes {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            if let Some(old) = self.map.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(old.weight);
            }
        }
        let tick = self.next_tick();
        self.order.insert(tick, k);
        self.map.insert(
            k,
            Slot {
                spans,
                weight,
                tick,
            },
        );
        self.bytes += weight;
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
        self.bytes = 0;
    }
}

/// An entry's weight: its key, its spans, any custom kind labels, and a
/// fixed overhead.
fn weight(spans: &[Span]) -> usize {
    let labels: usize = spans
        .iter()
        .map(|s| match &s.kind {
            EntityKind::Custom(l) => l.len(),
            _ => 0,
        })
        .sum();
    32 + std::mem::size_of_val(spans) + labels + ENTRY_OVERHEAD
}

/// An allow-set entry: how many open scopes hold the digest, per
/// generation they opened at. The sanitizer side uses the smallest (the
/// conservative one), which recovers as soon as the pre-clear scopes close.
type Allow = BTreeMap<u64, u32>;

/// The static-prompt NER memo. Shared by every trusted client of the proxy
/// listener; memory only. `Debug` prints counts.
pub struct NerMemo {
    key: [u8; 32],
    profile: String,
    fingerprint: [u8; 32],
    max_entries: usize,
    max_bytes: usize,
    /// Process-unique id, so a thread mark of one memo never opens another.
    id: u64,
    lru: Mutex<Lru>,
    /// Keyed digests of the NFC texts of open scopes (sanitizer side).
    allowed: Mutex<HashMap<[u8; 32], Allow>>,
    /// The dictionary last adopted; a `Weak`, so the memo never keeps a
    /// forgotten entity's original alive (S4).
    adopted: Mutex<Option<Weak<dyn Detector>>>,
    /// Bumped by every clear (S5).
    generation: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    clears: AtomicU64,
}

impl fmt::Debug for NerMemo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.stats();
        f.debug_struct("NerMemo")
            .field("entries", &s.entries)
            .field("hits", &s.hits)
            .field("misses", &s.misses)
            .field("clears", &s.clears)
            .finish()
    }
}

impl NerMemo {
    /// A memo for `profile` under the configuration `fingerprint`, holding
    /// at most `entries` entries and `bytes` bytes, with a fresh random key.
    pub fn new(profile: &str, fingerprint: [u8; 32], entries: usize, bytes: usize) -> Arc<NerMemo> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("the OS random source works");
        Arc::new(NerMemo::with_key(key, profile, fingerprint, entries, bytes))
    }

    fn with_key(
        key: [u8; 32],
        profile: &str,
        fingerprint: [u8; 32],
        entries: usize,
        bytes: usize,
    ) -> NerMemo {
        NerMemo {
            key,
            profile: profile.to_string(),
            fingerprint,
            max_entries: entries,
            max_bytes: bytes,
            id: NEXT_MEMO_ID.fetch_add(1, Ordering::Relaxed),
            lru: Mutex::new(Lru::default()),
            allowed: Mutex::new(HashMap::new()),
            adopted: Mutex::new(None),
            generation: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            clears: AtomicU64::new(0),
        }
    }

    /// HMAC over length-prefixed parts, exactly as `cache::KeyMaker::mac`,
    /// so part boundaries cannot shift.
    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("any key length");
        for p in parts {
            m.update(&(p.len() as u64).to_be_bytes());
            m.update(p);
        }
        m.finalize().into_bytes().into()
    }

    /// The allow-set digest of a text.
    fn text_digest(&self, text: &str) -> [u8; 32] {
        self.mac(&[b"text", text.as_bytes()])
    }

    /// The memo key of one wrapper's call.
    ///
    /// Invariant (ruling L122 item 1a): the key holds no text origin, and
    /// it need not. A memo value is a raw NER result, and the origin acts
    /// only after NER (the sanitizer's technical-person filter and the
    /// verifier's product cue), so a value is the same under either origin.
    /// Only harness-static leaves are memo-eligible; a `Free` leaf never
    /// reads or writes the memo, it runs on `engine_unmemoized`
    /// (`memo_tests::free_leaves_never_read_a_harness_static_entry` pins
    /// that and must stay a hard test). If the origin ever reaches
    /// `DetectCtx` (an origin-dependent NER call), that change must add it
    /// to this key; the exhaustive destructuring below makes such a field a
    /// compile error here.
    fn entry_key(
        &self,
        wrapper: &[u8; 16],
        role: NerRole,
        ctx: &DetectCtx,
        text: &str,
    ) -> [u8; 32] {
        // Exhaustive, so a new `DetectCtx` field is a compile error here
        // rather than a context the key silently leaves out.
        let DetectCtx { language } = ctx;
        let lang = format!("{language:?}");
        self.mac(&[
            wrapper,
            role.tag(),
            self.profile.as_bytes(),
            &self.fingerprint,
            lang.as_bytes(),
            text.as_bytes(),
        ])
    }

    /// Wrap `inner` for `role`. The wrapper reports `inner`'s id and
    /// forwards every `Detector` method; it has its own random id, which is
    /// part of every key it makes.
    pub fn wrap(self: &Arc<Self>, inner: Arc<dyn Detector>, role: NerRole) -> Arc<dyn Detector> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("the OS random source works");
        Arc::new(Memoized {
            inner,
            role,
            id,
            memo: Arc::clone(self),
        })
    }

    /// Open a scope for a leaf whose NFC text is `nfc`: the sanitizer side
    /// may use the memo for exactly that text, and the verifier side may use
    /// it on this thread, until the guard drops.
    pub fn scope(&self, nfc: &str) -> Scope<'_> {
        let generation = self.generation.load(Ordering::Acquire);
        let digest = self.text_digest(nfc);
        let allowed = match self.allowed.lock() {
            Ok(mut set) => {
                let refs = set
                    .entry(digest)
                    .or_default()
                    .entry(generation)
                    .or_insert(0);
                *refs = refs.saturating_add(1);
                true
            }
            Err(_) => false,
        };
        let marked = MARK.with(|m| {
            let cur = m.get();
            if cur.depth == 0 {
                m.set(Mark {
                    memo: self.id,
                    depth: 1,
                    generation,
                });
                true
            } else if cur.memo == self.id {
                // Nested: keep the outer (older or equal) generation.
                m.set(Mark {
                    depth: cur.depth.saturating_add(1),
                    ..cur
                });
                true
            } else {
                // Another memo's scope owns this thread: this memo's
                // verifier side misses.
                false
            }
        });
        Scope {
            memo: self,
            digest: allowed.then_some((digest, generation)),
            marked,
            _not_send: PhantomData,
        }
    }

    /// Adopt the request's dictionary. When it is the host's `current` one
    /// and not the dictionary adopted before, clear the memo and adopt it.
    /// The first adoption clears too (entries made before it belong to an
    /// unknown dictionary) and bumps the generation, but is not counted as
    /// a clear (ruling L2-39).
    pub fn adopt(&self, dict: &Arc<dyn Detector>, current: bool) {
        if !current {
            return;
        }
        let mut adopted = self.adopted.lock().unwrap_or_else(PoisonError::into_inner);
        let same = adopted
            .as_ref()
            .is_some_and(|w| std::ptr::addr_eq(w.as_ptr(), Arc::as_ptr(dict)));
        if !same {
            self.clear_inner(adopted.is_some());
            *adopted = Some(Arc::downgrade(dict));
        }
    }

    /// Drop every entry, bump the generation and count a clear. Works on a
    /// poisoned lock too: dropping entries is always safe.
    pub fn clear(&self) {
        self.clear_inner(true);
    }

    /// Drop every entry and bump the generation; count a clear if `count`.
    fn clear_inner(&self, count: bool) {
        let mut lru = self.lru.lock().unwrap_or_else(PoisonError::into_inner);
        lru.clear();
        self.generation.fetch_add(1, Ordering::AcqRel);
        if count {
            self.clears.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The counters.
    pub fn stats(&self) -> MemoStats {
        let entries = self
            .lru
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map
            .len() as u64;
        MemoStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entries,
            clears: self.clears.load(Ordering::Relaxed),
        }
    }

    /// The generation the sanitizer side may use for `text`, if an open
    /// scope allows it. `None` on an empty set (without hashing), on a
    /// digest not allowed, or on a poisoned lock.
    fn sanitizer_generation(&self, text: &str) -> Option<u64> {
        {
            let set = self.allowed.lock().ok()?;
            if set.is_empty() {
                return None;
            }
        }
        let d = self.text_digest(text);
        let set = self.allowed.lock().ok()?;
        set.get(&d).and_then(|gens| gens.keys().next().copied())
    }

    /// The generation the verifier side may use on this thread, if marked.
    fn verifier_generation(&self) -> Option<u64> {
        let m = MARK.with(Cell::get);
        (m.depth > 0 && m.memo == self.id).then_some(m.generation)
    }

    #[cfg(test)]
    fn allowed_len(&self) -> usize {
        self.allowed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// A scope guard from [`NerMemo::scope`]. `!Send` (S7), so it drops on the
/// thread that opened it. `Debug` prints flags only.
pub struct Scope<'a> {
    memo: &'a NerMemo,
    /// The digest this scope added to the allow set, if it could, and the
    /// generation it added it under.
    digest: Option<([u8; 32], u64)>,
    /// Whether this scope counted in the thread mark.
    marked: bool,
    _not_send: PhantomData<*const ()>,
}

impl fmt::Debug for Scope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scope")
            .field("allowed", &self.digest.is_some())
            .field("marked", &self.marked)
            .finish()
    }
}

impl Drop for Scope<'_> {
    fn drop(&mut self) {
        if let Some((d, generation)) = self.digest.take() {
            // Recover a poisoned lock: a stale allow entry must not outlive
            // its scope.
            let mut set = self
                .memo
                .allowed
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(gens) = set.get_mut(&d) {
                if let Some(refs) = gens.get_mut(&generation) {
                    *refs = refs.saturating_sub(1);
                    if *refs == 0 {
                        gens.remove(&generation);
                    }
                }
                if gens.is_empty() {
                    set.remove(&d);
                }
            }
        }
        if self.marked {
            let id = self.memo.id;
            MARK.with(|m| {
                let cur = m.get();
                if cur.memo == id {
                    debug_assert!(cur.depth > 0, "the thread mark is held");
                    let depth = cur.depth.saturating_sub(1);
                    m.set(if depth == 0 {
                        Mark::NONE
                    } else {
                        Mark { depth, ..cur }
                    });
                }
            });
        }
    }
}

/// A NER detector behind the memo. `Debug` prints the role and inner id.
struct Memoized {
    inner: Arc<dyn Detector>,
    role: NerRole,
    id: [u8; 16],
    memo: Arc<NerMemo>,
}

impl fmt::Debug for Memoized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Memoized")
            .field("role", &self.role)
            .field("inner", &self.inner.id())
            .finish_non_exhaustive()
    }
}

impl Detector for Memoized {
    fn id(&self) -> DetectorId {
        self.inner.id()
    }

    fn detect(&self, text: &str, ctx: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        if text.len() < STATIC_MIN_BYTES {
            return self.inner.detect(text, ctx);
        }
        let memo = &*self.memo;
        let generation = match self.role {
            NerRole::Sanitizer => memo.sanitizer_generation(text),
            NerRole::Verifier => memo.verifier_generation(),
        };
        let Some(generation) = generation else {
            return self.inner.detect(text, ctx);
        };
        let key = memo.entry_key(&self.id, self.role, ctx, text);
        {
            let Ok(mut lru) = memo.lru.lock() else {
                return self.inner.detect(text, ctx);
            };
            if memo.generation.load(Ordering::Acquire) != generation {
                drop(lru);
                return self.inner.detect(text, ctx);
            }
            if let Some(spans) = lru.get(&key) {
                drop(lru);
                memo.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(spans.to_vec());
            }
        }
        let spans = self.inner.detect(text, ctx)?;
        if let Ok(mut lru) = memo.lru.lock()
            && memo.generation.load(Ordering::Acquire) == generation
        {
            lru.insert(
                key,
                Arc::from(spans.as_slice()),
                memo.max_entries,
                memo.max_bytes,
            );
            drop(lru);
            memo.misses.fetch_add(1, Ordering::Relaxed);
        }
        Ok(spans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inumaki_core::Error;
    use inumaki_core::lang::Language;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    /// A fake NER detector that counts its calls. Spans depend on the
    /// input's length, carry a custom kind label, and use odd offsets, so
    /// the `Debug` test can look for them.
    struct Counting {
        calls: AtomicUsize,
        fail: bool,
    }

    impl Counting {
        fn new() -> Arc<Counting> {
            Arc::new(Counting {
                calls: AtomicUsize::new(0),
                fail: false,
            })
        }
        fn failing() -> Arc<Counting> {
            Arc::new(Counting {
                calls: AtomicUsize::new(0),
                fail: true,
            })
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Detector for Counting {
        fn id(&self) -> DetectorId {
            DetectorId::Ner
        }
        fn detect(&self, text: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(Error::ModelUnavailable("fake".into()));
            }
            Ok(vec![
                Span::new(1237, 1291, EntityKind::Person, 0.75, DetectorId::Ner),
                Span::new(
                    0,
                    text.len() % 997,
                    EntityKind::custom("CANARY_KIND"),
                    0.5,
                    DetectorId::Ner,
                ),
            ])
        }
    }

    fn ctx() -> DetectCtx {
        DetectCtx {
            language: Language::En,
        }
    }

    /// A long text with a canary, distinct per `seed`.
    fn long(seed: &str) -> String {
        let mut s = format!("CANARY-Sarah-Leitner {seed} ");
        while s.len() < 3000 {
            s.push_str("system prompt text. ");
        }
        s
    }

    fn memo() -> Arc<NerMemo> {
        NerMemo::new(
            "support-email",
            [7u8; 32],
            STATIC_MEMO_ENTRIES,
            STATIC_MEMO_BYTES,
        )
    }

    fn as_dyn(c: &Arc<Counting>) -> Arc<dyn Detector> {
        Arc::clone(c) as Arc<dyn Detector>
    }

    #[test]
    fn memo_hit_returns_identical_spans_and_runs_inner_once() {
        let m = memo();
        let c = Counting::new();
        let w = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let text = long("a");
        let _s = m.scope(&text);
        let first = w.detect(&text, &ctx()).unwrap();
        let second = w.detect(&text, &ctx()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first, c.detect(&text, &ctx()).unwrap());
        assert_eq!(c.calls(), 2, "the wrapper ran the model once");
        assert_eq!(w.id(), DetectorId::Ner);
        let st = m.stats();
        assert_eq!((st.hits, st.misses, st.entries), (1, 1, 1));
    }

    #[test]
    fn memo_roles_have_separate_namespaces() {
        for verifier_first in [false, true] {
            let m = memo();
            let cs = Counting::new();
            let cv = Counting::new();
            let s = m.wrap(as_dyn(&cs), NerRole::Sanitizer);
            let v = m.wrap(as_dyn(&cv), NerRole::Verifier);
            let text = long("ns");
            let _g = m.scope(&text);
            if verifier_first {
                v.detect(&text, &ctx()).unwrap();
                s.detect(&text, &ctx()).unwrap();
            } else {
                s.detect(&text, &ctx()).unwrap();
                v.detect(&text, &ctx()).unwrap();
            }
            assert_eq!((cs.calls(), cv.calls()), (1, 1), "no cross-role answer");
            s.detect(&text, &ctx()).unwrap();
            v.detect(&text, &ctx()).unwrap();
            assert_eq!((cs.calls(), cv.calls()), (1, 1), "each hits its own entry");
            assert_eq!(m.stats().entries, 2);
        }
        // One inner detector under both roles: still two model runs.
        let m = memo();
        let c = Counting::new();
        let s = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let v = m.wrap(as_dyn(&c), NerRole::Verifier);
        let text = long("shared");
        let _g = m.scope(&text);
        s.detect(&text, &ctx()).unwrap();
        v.detect(&text, &ctx()).unwrap();
        s.detect(&text, &ctx()).unwrap();
        v.detect(&text, &ctx()).unwrap();
        assert_eq!(c.calls(), 2);
    }

    #[test]
    fn memo_keys_differ_by_wrapper_language_byte_profile_and_fingerprint() {
        // Two wraps of one detector.
        let m = memo();
        let c = Counting::new();
        let w1 = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let w2 = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let text = long("k");
        let _g = m.scope(&text);
        w1.detect(&text, &ctx()).unwrap();
        w2.detect(&text, &ctx()).unwrap();
        assert_eq!(c.calls(), 2, "wrapper id is in the key");

        // Language hint.
        let de = DetectCtx {
            language: Language::De,
        };
        w1.detect(&text, &de).unwrap();
        assert_eq!(c.calls(), 3, "language is in the key");
        w1.detect(&text, &de).unwrap();
        assert_eq!(c.calls(), 3);

        // One changed byte.
        let mut other = text.clone().into_bytes();
        let last = other.len() - 1;
        other[last] = b'!';
        let other = String::from_utf8(other).unwrap();
        let _g2 = m.scope(&other);
        w1.detect(&other, &ctx()).unwrap();
        assert_eq!(c.calls(), 4, "every input byte is in the key");

        // Profile and fingerprint, under one memo key.
        let id = [3u8; 16];
        let a = NerMemo::with_key([9; 32], "support-email", [1; 32], 8, 1 << 20);
        let b = NerMemo::with_key([9; 32], "fast", [1; 32], 8, 1 << 20);
        let f = NerMemo::with_key([9; 32], "support-email", [2; 32], 8, 1 << 20);
        let same = NerMemo::with_key([9; 32], "support-email", [1; 32], 8, 1 << 20);
        let k = |m: &NerMemo| m.entry_key(&id, NerRole::Sanitizer, &ctx(), &text);
        assert_eq!(k(&a), k(&same));
        assert_ne!(k(&a), k(&b), "profile is in the key");
        assert_ne!(k(&a), k(&f), "fingerprint is in the key");
        assert_ne!(
            k(&a),
            a.entry_key(&id, NerRole::Verifier, &ctx(), &text),
            "role is in the key"
        );
    }

    #[test]
    fn memo_outside_a_scope_delegates_and_stores_nothing() {
        let m = memo();
        let c = Counting::new();
        let s = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let v = m.wrap(as_dyn(&c), NerRole::Verifier);
        let text = long("out");
        for _ in 0..2 {
            s.detect(&text, &ctx()).unwrap();
            v.detect(&text, &ctx()).unwrap();
        }
        assert_eq!(c.calls(), 4);
        assert_eq!(m.stats(), MemoStats::default());
        // And after a scope closes, the same.
        drop(m.scope(&text));
        s.detect(&text, &ctx()).unwrap();
        v.detect(&text, &ctx()).unwrap();
        assert_eq!(c.calls(), 6);
        assert_eq!(m.stats(), MemoStats::default());
    }

    #[test]
    fn memo_sanitizer_needs_the_digest_and_verifier_needs_the_thread_mark() {
        let m = memo();
        let c = Counting::new();
        let s = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let v = m.wrap(as_dyn(&c), NerRole::Verifier);
        let text = long("allowed");
        let other = long("not allowed");
        let _g = m.scope(&text);

        // Sanitizer: a text whose digest is not allowed delegates.
        s.detect(&other, &ctx()).unwrap();
        s.detect(&other, &ctx()).unwrap();
        assert_eq!(c.calls(), 2);
        assert_eq!(m.stats().entries, 0);

        std::thread::scope(|ts| {
            ts.spawn(|| {
                // Verifier on an unmarked thread delegates.
                v.detect(&text, &ctx()).unwrap();
                v.detect(&text, &ctx()).unwrap();
                // Sanitizer on another thread (the rayon pool's case) uses
                // the allowed digest.
                s.detect(&text, &ctx()).unwrap();
                s.detect(&text, &ctx()).unwrap();
            });
        });
        assert_eq!(c.calls(), 5, "verifier twice, sanitizer once");
        assert_eq!(m.stats().entries, 1);

        // On the marked thread the verifier uses the memo.
        v.detect(&text, &ctx()).unwrap();
        v.detect(&text, &ctx()).unwrap();
        assert_eq!(c.calls(), 6);
        assert_eq!(m.stats().entries, 2);

        // A scope of another memo does not mark the thread for this one.
        drop(_g);
        let m2 = memo();
        let _g2 = m2.scope(&text);
        v.detect(&text, &ctx()).unwrap();
        assert_eq!(c.calls(), 7);
    }

    #[test]
    fn memo_never_stores_errors_or_short_inputs() {
        let m = memo();
        let bad = Counting::failing();
        let s = m.wrap(as_dyn(&bad), NerRole::Sanitizer);
        let v = m.wrap(as_dyn(&bad), NerRole::Verifier);
        let text = long("err");
        let _g = m.scope(&text);
        for _ in 0..2 {
            assert!(matches!(
                s.detect(&text, &ctx()),
                Err(Error::ModelUnavailable(_))
            ));
            assert!(matches!(
                v.detect(&text, &ctx()),
                Err(Error::ModelUnavailable(_))
            ));
        }
        assert_eq!(bad.calls(), 4);
        assert_eq!(m.stats(), MemoStats::default());

        let c = Counting::new();
        let s = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let v = m.wrap(as_dyn(&c), NerRole::Verifier);
        let short = "s".repeat(STATIC_MIN_BYTES - 1);
        let _g = m.scope(&short);
        for _ in 0..2 {
            s.detect(&short, &ctx()).unwrap();
            v.detect(&short, &ctx()).unwrap();
        }
        assert_eq!(c.calls(), 4);
        assert_eq!(m.stats().entries, 0);

        let edge = "s".repeat(STATIC_MIN_BYTES);
        let _g = m.scope(&edge);
        s.detect(&edge, &ctx()).unwrap();
        s.detect(&edge, &ctx()).unwrap();
        assert_eq!(c.calls(), 5, "exactly the minimum is served");
    }

    /// Run `texts` through a sanitizer wrapper in order; true per text when
    /// the inner detector did not run (a hit).
    fn hits(m: &Arc<NerMemo>, w: &Arc<dyn Detector>, c: &Counting, texts: &[&str]) -> Vec<bool> {
        texts
            .iter()
            .map(|t| {
                let before = c.calls();
                let _g = m.scope(t);
                w.detect(t, &ctx()).unwrap();
                c.calls() == before
            })
            .collect()
    }

    #[test]
    fn memo_entry_cap_and_byte_cap_evict_lru_and_a_hit_refreshes() {
        let (a, b, cc) = (long("A"), long("B"), long("C"));
        let one = weight(&Counting::new().detect(&a, &ctx()).unwrap());
        for (entries, bytes) in [(2, STATIC_MEMO_BYTES), (STATIC_MEMO_ENTRIES, 2 * one)] {
            let m = NerMemo::new("p", [0; 32], entries, bytes);
            let c = Counting::new();
            let w = m.wrap(as_dyn(&c), NerRole::Sanitizer);
            // A, B stored; A hit (refreshed); C evicts B, the least recent.
            assert_eq!(
                hits(&m, &w, &c, &[&a, &b, &a, &cc]),
                [false, false, true, false]
            );
            assert_eq!(m.stats().entries, 2);
            assert_eq!(hits(&m, &w, &c, &[&a, &cc, &b]), [true, true, false]);
        }
        // An entry heavier than the byte cap is not stored.
        let m = NerMemo::new("p", [0; 32], 8, one - 1);
        let c = Counting::new();
        let w = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        assert_eq!(hits(&m, &w, &c, &[&a, &a]), [false, false]);
    }

    #[test]
    fn memo_adopt_clears_only_on_a_new_current_dictionary() {
        let m = memo();
        let c = Counting::new();
        let w = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let text = long("adopt");
        let fill = || {
            let _g = m.scope(&text);
            w.detect(&text, &ctx()).unwrap();
        };
        let d1: Arc<dyn Detector> = Counting::new();
        // The first adoption bumps the generation (a scope opened before it
        // misses afterwards) but is not counted as a clear (L2-39).
        let before = m.scope(&text);
        m.adopt(&d1, true);
        assert_eq!(m.stats().clears, 0);
        w.detect(&text, &ctx()).unwrap();
        w.detect(&text, &ctx()).unwrap();
        assert_eq!(c.calls(), 2, "the pre-adoption scope runs the model");
        assert_eq!(m.stats().entries, 0, "and stores nothing");
        drop(before);
        fill();
        assert_eq!(m.stats().entries, 1);

        m.adopt(&Arc::clone(&d1), true);
        assert_eq!(
            (m.stats().entries, m.stats().clears),
            (1, 0),
            "same Arc keeps"
        );

        let d2: Arc<dyn Detector> = Counting::new();
        m.adopt(&d2, false);
        assert_eq!(
            (m.stats().entries, m.stats().clears),
            (1, 0),
            "not current keeps"
        );

        m.adopt(&d2, true);
        assert_eq!(
            (m.stats().entries, m.stats().clears),
            (0, 1),
            "new Arc clears and counts"
        );
        fill();
        m.adopt(&d1, false);
        assert_eq!(m.stats().entries, 1, "no ping-pong back to a stale one");
    }

    #[test]
    fn memo_adopt_keeps_no_dictionary_alive() {
        struct Dict(Arc<AtomicBool>);
        impl Drop for Dict {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        impl Detector for Dict {
            fn id(&self) -> DetectorId {
                DetectorId::Dictionary
            }
            fn detect(&self, _: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
                Ok(Vec::new())
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let m = memo();
        let a: Arc<dyn Detector> = Arc::new(Dict(Arc::clone(&dropped)));
        let a2 = Arc::clone(&a);
        m.adopt(&a, true);
        drop(a);
        assert!(!dropped.load(Ordering::SeqCst));
        drop(a2);
        assert!(dropped.load(Ordering::SeqCst), "the memo holds only a Weak");
    }

    #[test]
    fn memo_scope_opened_before_a_clear_neither_reads_nor_inserts() {
        let m = memo();
        let c = Counting::new();
        let s = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let v = m.wrap(as_dyn(&c), NerRole::Verifier);
        let text = long("gen");
        let g = m.scope(&text);
        s.detect(&text, &ctx()).unwrap();
        v.detect(&text, &ctx()).unwrap();
        assert_eq!((c.calls(), m.stats().entries), (2, 2));
        m.clear();
        for _ in 0..2 {
            s.detect(&text, &ctx()).unwrap();
            v.detect(&text, &ctx()).unwrap();
        }
        assert_eq!(c.calls(), 6, "the stale scope runs the model");
        assert_eq!(m.stats().entries, 0, "and stores nothing");
        drop(g);
        // A scope opened after the clear works again.
        let _g = m.scope(&text);
        s.detect(&text, &ctx()).unwrap();
        s.detect(&text, &ctx()).unwrap();
        assert_eq!(c.calls(), 7);
    }

    #[test]
    fn memo_clear_during_the_model_call_stores_nothing() {
        /// Clears the memo while "the model runs": a concurrent clear that
        /// lands between the lookup and the insert.
        struct ClearsMidway(Arc<NerMemo>);
        impl Detector for ClearsMidway {
            fn id(&self) -> DetectorId {
                DetectorId::Ner
            }
            fn detect(&self, _: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
                self.0.clear();
                Ok(vec![Span::new(
                    0,
                    1,
                    EntityKind::Person,
                    0.9,
                    DetectorId::Ner,
                )])
            }
        }
        let m = memo();
        let inner: Arc<dyn Detector> = Arc::new(ClearsMidway(Arc::clone(&m)));
        let text = long("midway");
        let _g = m.scope(&text);
        for role in [NerRole::Sanitizer, NerRole::Verifier] {
            let w = m.wrap(Arc::clone(&inner), role);
            assert_eq!(w.detect(&text, &ctx()).unwrap().len(), 1);
            assert_eq!(m.stats().entries, 0, "{role:?}: no insert after a clear");
            assert_eq!(m.stats().misses, 0);
        }
    }

    #[test]
    fn memo_allow_generation_recovers_when_pre_clear_scopes_close() {
        let m = memo();
        let c = Counting::new();
        let w = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let text = long("recover");
        // Run the sanitizer side on another thread, as the rayon pool does,
        // so only the allow set (not this thread's mark) decides.
        let run = || std::thread::scope(|ts| ts.spawn(|| w.detect(&text, &ctx())).join());
        let old = m.scope(&text);
        m.clear();
        let new = m.scope(&text);
        run().unwrap().unwrap();
        run().unwrap().unwrap();
        assert_eq!(c.calls(), 2, "the pre-clear scope holds the minimum");
        assert_eq!(m.stats().entries, 0);
        drop(old);
        run().unwrap().unwrap();
        run().unwrap().unwrap();
        assert_eq!(c.calls(), 3, "the post-clear scope's generation takes over");
        assert_eq!(m.stats().hits, 1);
        drop(new);
        assert_eq!(m.allowed_len(), 0);
    }

    #[test]
    fn memo_poisoned_locks_delegate() {
        fn poison<T>(lock: &Mutex<T>) {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _g = lock.lock().unwrap_or_else(PoisonError::into_inner);
                std::panic::resume_unwind(Box::new(()));
            }));
            assert!(lock.is_poisoned());
        }

        // A poisoned LRU: both roles return Ok, run the model on every
        // call, and count no hit.
        let m = memo();
        let c = Counting::new();
        let s = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        let v = m.wrap(as_dyn(&c), NerRole::Verifier);
        let text = long("poison");
        poison(&m.lru);
        let g = m.scope(&text);
        for _ in 0..2 {
            assert!(s.detect(&text, &ctx()).is_ok());
            assert!(v.detect(&text, &ctx()).is_ok());
        }
        assert_eq!(c.calls(), 4);
        assert_eq!(m.stats().hits, 0);
        drop(g);

        // A poisoned allow set: the scope allows nothing, the sanitizer
        // delegates, and the drop does not panic.
        let m = memo();
        let c = Counting::new();
        let s = m.wrap(as_dyn(&c), NerRole::Sanitizer);
        poison(&m.allowed);
        let g = m.scope(&text);
        assert_eq!(format!("{g:?}"), "Scope { allowed: false, marked: true }");
        for _ in 0..2 {
            assert!(s.detect(&text, &ctx()).is_ok());
        }
        assert_eq!(c.calls(), 2);
        assert_eq!((m.stats().hits, m.stats().entries), (0, 0));
        drop(g);
    }

    #[test]
    fn memo_scope_dropped_by_a_panic_leaves_nothing() {
        let m = memo();
        let text = long("panic");
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _outer = m.scope(&text);
            let _inner = m.scope(&text);
            assert_eq!(m.allowed_len(), 1);
            assert_eq!(MARK.with(Cell::get).depth, 2);
            // No panic hook runs, so the test output stays clean.
            std::panic::resume_unwind(Box::new(()));
        }));
        assert!(r.is_err());
        assert_eq!(m.allowed_len(), 0);
        assert!(MARK.with(Cell::get) == Mark::NONE);
        assert!(m.verifier_generation().is_none());
    }

    /// `Scope` is `!Send` (S7): the impl below is ambiguous, and fails to
    /// compile, exactly when `Scope` is `Send`.
    #[allow(dead_code)]
    trait AmbiguousIfSend<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    #[allow(dead_code)]
    struct IsSend;
    impl<T: ?Sized + Send> AmbiguousIfSend<IsSend> for T {}
    const _: fn() = || {
        let _ = <Scope<'static> as AmbiguousIfSend<_>>::check;
    };

    #[test]
    fn memo_debug_prints_counts_only() {
        let m = memo();
        let c = Counting::new();
        let w = Memoized {
            inner: as_dyn(&c),
            role: NerRole::Sanitizer,
            id: [0xab; 16],
            memo: Arc::clone(&m),
        };
        let text = long("debug");
        let g = m.scope(&text);
        w.detect(&text, &ctx()).unwrap();
        w.detect(&text, &ctx()).unwrap();

        let dm = format!("{m:?}");
        let dw = format!("{w:?}");
        let dg = format!("{g:?}");
        let ds = format!("{:?}", m.stats());
        assert_eq!(dm, "NerMemo { entries: 1, hits: 1, misses: 1, clears: 0 }");
        assert_eq!(dw, "Memoized { role: Sanitizer, inner: Ner, .. }");
        assert_eq!(dg, "Scope { allowed: true, marked: true }");

        // The wrapper id (0xab bytes), in decimal and in hex.
        let wrapper_dec = format!("{:?}", &w.id[..4]);
        let wrapper_hex: String = w.id[..4].iter().map(|b| format!("{b:02x}")).collect();
        let key_hex: String = m.key[..4].iter().map(|b| format!("{b:02x}")).collect();
        let key_dec = format!("{:?}", &m.key[..4]);
        let digest = m.text_digest(&text);
        let digest_dec = format!("{:?}", &digest[..4]);
        for d in [&dm, &dw, &dg, &ds] {
            for needle in [
                "CANARY",
                "Leitner",
                "1237",
                "1291",
                wrapper_dec.as_str(),
                wrapper_hex.as_str(),
                key_hex.as_str(),
                key_dec.as_str(),
                digest_dec.as_str(),
            ] {
                assert!(!d.contains(needle), "Debug leaks {needle}");
            }
        }
    }
}
