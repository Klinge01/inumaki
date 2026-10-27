//! Per-session leaf cache keys and values (M8 spec §5.6). Keys are keyed
//! hashes with a random per-process key; values hold sanitized text only.
//!
//! A hit is only valid while the tokens it carries still resolve in the
//! request's scope; the caller checks that (spec §5.6) and treats a hit
//! whose tokens no longer resolve as a miss.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use inumaki_core::TextOrigin;
use sha2::Sha256;

use crate::closure::Gen;
use crate::routes::Wire;
use crate::walk::Class;

/// A keyed hash of one leaf: wire format, leaf class, text origin, profile,
/// config fingerprint, and leaf bytes. `Debug` prints the type name only.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafKey(pub [u8; 32]);

impl fmt::Debug for LeafKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LeafKey")
    }
}

/// Makes cache keys and digests under a random per-process key, so a key
/// says nothing about the text without that key, and nothing survives a
/// restart. `Debug` never prints the key.
pub struct KeyMaker {
    key: [u8; 32],
    profile: String,
    fingerprint: [u8; 32],
}

impl fmt::Debug for KeyMaker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyMaker")
    }
}

impl KeyMaker {
    /// A key maker for `profile` under the configuration `fingerprint`,
    /// with a fresh random process key.
    pub fn new(profile: &str, fingerprint: [u8; 32]) -> KeyMaker {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("the OS random source works");
        KeyMaker {
            key,
            profile: profile.to_string(),
            fingerprint,
        }
    }

    /// The per-process key (also keys session ids, §5.1).
    pub fn process_key(&self) -> &[u8; 32] {
        &self.key
    }

    /// HMAC over length-prefixed parts, so part boundaries cannot shift.
    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("any key length");
        for p in parts {
            m.update(&(p.len() as u64).to_be_bytes());
            m.update(p);
        }
        m.finalize().into_bytes().into()
    }

    /// The cache key of a leaf.
    pub fn leaf(&self, wire: Wire, class: Class, origin: TextOrigin, bytes: &[u8]) -> LeafKey {
        LeafKey(self.mac(&[
            format!("{wire:?}/{class:?}/{}", origin.label()).as_bytes(),
            self.profile.as_bytes(),
            &self.fingerprint,
            bytes,
        ]))
    }

    /// A keyed digest under `tag` (memo keys, reasoning digests).
    pub fn digest(&self, tag: &str, bytes: &[u8]) -> [u8; 32] {
        self.mac(&[tag.as_bytes(), bytes])
    }
}

/// A cached sanitized leaf and the tokens it contains. `Debug` prints lengths.
#[derive(Clone)]
pub struct Cached {
    /// The sanitized text as forwarded.
    pub text: String,
    /// The tokens in `text`, checked to still resolve on a hit.
    pub tokens: Vec<String>,
}

impl fmt::Debug for Cached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cached")
            .field("len", &self.text.len())
            .field("tokens", &self.tokens.len())
            .finish()
    }
}

/// Fixed per-entry overhead counted against the byte budget.
const ENTRY_OVERHEAD: usize = 64;

/// One cache entry: the value, the stamps it was verified up to, and its
/// revision (step 6b, plan Task 4a).
///
/// - `generation`: the session logs' prefix the text was verified against. A hit
///   is scanned only against entries at or past it.
/// - `ds`: keyed digests of the dataset tokens it was verified against,
///   sorted and deduplicated (`pipeline::ds_digest`). A hit is re-scanned
///   only against the request's dataset values whose digest is missing.
/// - `rev`: unique per insert for the cache's lifetime, so a commit can
///   only vouch for the text it actually checked (never for a replacement).
struct Slot {
    value: Cached,
    generation: Gen,
    ds: Arc<[u64]>,
    rev: u64,
}

/// Bytes counted for a slot: the text, its tokens, the dataset digests
/// (counted per slot, shared or not: conservative), and a fixed overhead.
fn weight(s: &Slot) -> usize {
    s.value.text.len()
        + s.value.tokens.iter().map(String::len).sum::<usize>()
        + 8 * s.ds.len()
        + ENTRY_OVERHEAD
}

/// The sorted union of two sorted, deduplicated digest sets. Shares an
/// input when it already holds the other, so a commit allocates one set.
pub(crate) fn union(old: &Arc<[u64]>, new: &Arc<[u64]>) -> Arc<[u64]> {
    let has = |a: &[u64], b: &[u64]| b.iter().all(|x| a.binary_search(x).is_ok());
    if has(new, old) {
        return Arc::clone(new);
    }
    if has(old, new) {
        return Arc::clone(old);
    }
    let mut v: Vec<u64> = old.iter().chain(new.iter()).copied().collect();
    v.sort_unstable();
    v.dedup();
    v.into()
}

/// The sorted intersection of two sorted, deduplicated digest sets (a
/// seed stamp merged with another never gains coverage). Shares an input
/// when it is already the intersection.
pub(crate) fn intersect(a: &Arc<[u64]>, b: &Arc<[u64]>) -> Arc<[u64]> {
    let v: Vec<u64> = a
        .iter()
        .copied()
        .filter(|x| b.binary_search(x).is_ok())
        .collect();
    if v.len() == a.len() {
        Arc::clone(a)
    } else if v.len() == b.len() {
        Arc::clone(b)
    } else {
        v.into()
    }
}

/// A cache hit: the value, its stamps, and the revision a commit must match
/// to advance them. `Debug` prints lengths and positions only.
#[derive(Clone)]
pub struct Hit {
    /// The cached sanitized leaf.
    pub cached: Cached,
    /// The logs' prefix the text was verified against.
    pub generation: Gen,
    /// Digests of the dataset tokens it was verified against.
    pub ds: Arc<[u64]>,
    /// The entry's revision.
    pub rev: u64,
}

impl fmt::Debug for Hit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hit")
            .field("cached", &self.cached)
            .field("generation", &self.generation)
            .field("ds", &self.ds.len())
            .finish_non_exhaustive()
    }
}

/// One session's leaf cache. `Debug` prints counts.
#[derive(Default)]
pub struct LeafCache {
    map: HashMap<LeafKey, Slot>,
    bytes: usize,
    /// The next insert's revision. Monotonic for the cache's lifetime:
    /// `clear` and `remove` never reset it, so a revision never recurs (an
    /// old revision can never match a later entry, I4).
    next_rev: u64,
}

impl fmt::Debug for LeafCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeafCache")
            .field("entries", &self.map.len())
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl LeafCache {
    /// The entry for `k`, with its stamps and revision.
    pub fn get(&self, k: &LeafKey) -> Option<Hit> {
        self.map.get(k).map(|s| Hit {
            cached: s.value.clone(),
            generation: s.generation,
            ds: Arc::clone(&s.ds),
            rev: s.rev,
        })
    }

    /// Whether `k` has an entry (no copy of the value).
    pub fn contains(&self, k: &LeafKey) -> bool {
        self.map.contains_key(k)
    }

    /// Insert or replace, verified up to `generation` and `ds`, under a new
    /// revision.
    pub fn insert(&mut self, k: LeafKey, v: Cached, generation: Gen, ds: Arc<[u64]>) {
        debug_assert!(
            ds.windows(2).all(|w| w[0] < w[1]),
            "dataset digests are sorted and deduplicated"
        );
        let rev = self.next_rev;
        // 2^64 inserts never happen; wrapping keeps every revision unique
        // until then, where saturating would repeat one.
        self.next_rev = self.next_rev.wrapping_add(1);
        let slot = Slot {
            value: v,
            generation,
            ds,
            rev,
        };
        let add = weight(&slot);
        if let Some(old) = self.map.insert(k, slot) {
            self.bytes = self.bytes.saturating_sub(weight(&old));
        }
        self.bytes += add;
    }

    /// Advance `k`'s stamps to at least `g` and `ds`, only while it is
    /// still the entry of revision `rev` (the text the caller verified):
    /// the component-wise maximum and the set union, so a stamp never
    /// drops. False when the entry is gone or was replaced.
    pub fn bump(&mut self, k: &LeafKey, rev: u64, g: Gen, ds: &Arc<[u64]>) -> bool {
        debug_assert!(
            ds.windows(2).all(|w| w[0] < w[1]),
            "dataset digests are sorted and deduplicated"
        );
        let Some(s) = self.map.get_mut(k).filter(|s| s.rev == rev) else {
            return false;
        };
        let was = weight(s);
        s.generation = s.generation.max(g);
        s.ds = union(&s.ds, ds);
        let now = weight(s);
        self.bytes = self.bytes.saturating_sub(was) + now;
        true
    }

    /// Drop `k`'s entry, if any.
    pub fn remove(&mut self, k: &LeafKey) {
        if let Some(old) = self.map.remove(k) {
            self.bytes = self.bytes.saturating_sub(weight(&old));
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Approximate bytes held.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Drop every entry. The revision counter is kept (never reset).
    pub fn clear(&mut self) {
        self.map.clear();
        self.bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> Arc<[u64]> {
        Arc::from([])
    }

    fn val(s: &str) -> Cached {
        Cached {
            text: s.into(),
            tokens: vec!["<PERSON_abcdef>".into()],
        }
    }

    /// I4 (Review Focus 2): a commit vouches only for the text it checked.
    /// A bump under a replaced entry's revision fails; a bump takes the
    /// component-wise maximum; a revision never recurs after `clear()`, so
    /// an old one cannot match a later entry (ABA); `remove` drops the
    /// entry and its bytes.
    #[test]
    fn a_bump_never_marks_replaced_text_verified() {
        let mut c = LeafCache::default();
        let k = LeafKey([7; 32]);
        let five = Gen {
            entries: 5,
            removed: 0,
        };
        c.insert(k, val("a"), Gen::ZERO, empty());
        let old = c.get(&k).unwrap().rev;
        c.insert(k, val("b"), Gen::ZERO, empty()); // a concurrent replace
        assert!(!c.bump(&k, old, five, &empty()), "replaced text");
        assert_eq!(c.get(&k).unwrap().generation, Gen::ZERO);

        let rev = c.get(&k).unwrap().rev;
        let g = |entries, removed| Gen { entries, removed };
        assert!(c.bump(&k, rev, g(5, 1), &empty()));
        assert!(c.bump(&k, rev, g(3, 2), &empty()));
        assert_eq!(c.get(&k).unwrap().generation, g(5, 2), "component-wise max");

        // ABA: after `clear()`, no later insert reuses the revision.
        let rev = c.get(&k).unwrap().rev;
        c.clear();
        for n in 0..rev + 2 {
            c.insert(k, val("c"), Gen::ZERO, empty());
            assert!(!c.bump(&k, rev, five, &empty()), "insert {n} after clear");
        }
        assert_eq!(c.get(&k).unwrap().generation, Gen::ZERO);

        c.insert(LeafKey([6; 32]), val("dd"), Gen::ZERO, empty());
        let both = c.bytes();
        c.remove(&k);
        assert!(!c.contains(&k));
        assert_eq!(c.len(), 1);
        assert!(c.bytes() < both && c.bytes() > 0, "its bytes went too");
        c.remove(&LeafKey([6; 32]));
        assert_eq!((c.len(), c.bytes()), (0, 0));
    }

    /// A changed profile, configuration, wire format, leaf class, or text
    /// origin must never hit an entry made under another one; nor may
    /// another process.
    #[test]
    fn keys_separate_every_input_and_process() {
        let k = KeyMaker::new("fast", [1; 32]);
        let base = k.leaf(Wire::Messages, Class::Text, TextOrigin::Free, b"hello");
        assert_eq!(
            base,
            k.leaf(Wire::Messages, Class::Text, TextOrigin::Free, b"hello")
        );
        assert_ne!(
            base,
            k.leaf(Wire::Messages, Class::Text, TextOrigin::Free, b"hello!")
        );
        assert_ne!(
            base,
            k.leaf(Wire::Chat, Class::Text, TextOrigin::Free, b"hello")
        );
        assert_ne!(
            base,
            k.leaf(
                Wire::Messages,
                Class::ToolResult,
                TextOrigin::Free,
                b"hello"
            )
        );
        assert_ne!(
            base,
            k.leaf(
                Wire::Messages,
                Class::Text,
                TextOrigin::HarnessStatic,
                b"hello"
            )
        );
        let other_cfg = KeyMaker {
            key: k.key,
            profile: "fast".into(),
            fingerprint: [2; 32],
        };
        assert_ne!(
            base,
            other_cfg.leaf(Wire::Messages, Class::Text, TextOrigin::Free, b"hello")
        );
        let other_profile = KeyMaker {
            key: k.key,
            profile: "strict".into(),
            fingerprint: [1; 32],
        };
        assert_ne!(
            base,
            other_profile.leaf(Wire::Messages, Class::Text, TextOrigin::Free, b"hello")
        );
        assert_ne!(
            base,
            KeyMaker::new("fast", [1; 32]).leaf(
                Wire::Messages,
                Class::Text,
                TextOrigin::Free,
                b"hello"
            )
        );
        assert_ne!(k.digest("memo", b"x"), k.digest("seed", b"x"));
    }

    #[test]
    fn bytes_track_replacement_and_clear() {
        let mut c = LeafCache::default();
        let k = LeafKey([9; 32]);
        let v = |s: &str| Cached {
            text: s.into(),
            tokens: vec!["<PERSON_abcdef>".into()],
        };
        c.insert(k, v("aaaa"), Gen::ZERO, empty());
        let one = c.bytes();
        c.insert(k, v("aaaa"), Gen::ZERO, empty());
        assert_eq!(
            (c.len(), c.bytes()),
            (1, one),
            "a replacement is not counted twice"
        );
        c.insert(LeafKey([8; 32]), v("bb"), Gen::ZERO, empty());
        assert_eq!(c.len(), 2);
        c.insert(k, v("Zyxwuria"), Gen::ZERO, Arc::from([7u64]));
        let hit = format!("{:?}", c.get(&k).unwrap());
        assert!(
            !hit.contains("Zyxwuria") && !hit.contains("PERSON"),
            "{hit}"
        );
        c.clear();
        assert_eq!((c.len(), c.bytes()), (0, 0));
        assert!(c.get(&k).is_none());
        let dbg = format!(
            "{:?} {:?} {k:?}",
            v("Zyxwuria"),
            KeyMaker::new("fast", [0; 32])
        );
        assert!(
            !dbg.contains("Zyxwuria") && !dbg.contains("PERSON"),
            "{dbg}"
        );
    }
}
