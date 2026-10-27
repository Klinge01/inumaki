//! Sanitization cache (spec §6): `(namespace, epoch, profile, configuration
//! fingerprint, sha256(NFC text))` → the sanitized result. Exact within an
//! epoch because tokens are deterministic given the namespace and the engine
//! is deterministic given the text and the configuration (M4 spec §5.3).

use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use inumaki_core::span::EntityKind;
use inumaki_core::verify::Reason;
use inumaki_vault::lru::Lru;
use sha2::{Digest, Sha256};

use crate::service::ReplacedSpan;

/// Cache key. `text_sha` is SHA-256 of the NFC-normalized request text.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Dataset id.
    pub namespace: String,
    /// Epoch row id at request time.
    pub epoch: i64,
    /// Profile name.
    pub profile: String,
    /// Configuration fingerprint at request time.
    pub config_rev: [u8; 32],
    /// SHA-256 of the text.
    pub text_sha: [u8; 32],
    /// Which transformation of `nfc_text` this key covers: `text` for a
    /// plain free-text block, `redact:<sha256 of the redaction spans>` when
    /// redactions applied. Typed identifier blocks are never cached.
    pub variant: String,
}

impl std::fmt::Debug for CacheKey {
    /// Omits `namespace` (M4 spec §5.4: a user-chosen dataset slug), and
    /// `text_sha`/`config_rev`, which reveal nothing on their own but add no
    /// diagnostic value here.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheKey")
            .field("epoch", &self.epoch)
            .field("profile", &self.profile)
            .finish()
    }
}

impl CacheKey {
    /// Key for `nfc_text` (already NFC-normalized).
    pub fn new(
        namespace: &str,
        epoch: i64,
        profile: &str,
        config_rev: &[u8; 32],
        nfc_text: &str,
    ) -> Self {
        CacheKey {
            namespace: namespace.to_string(),
            epoch,
            profile: profile.to_string(),
            config_rev: *config_rev,
            text_sha: Sha256::digest(nfc_text.as_bytes()).into(),
            variant: "text".into(),
        }
    }

    /// Key for a transformation variant of `nfc_text` (redactions, plan 2).
    pub fn with_variant(
        namespace: &str,
        epoch: i64,
        profile: &str,
        config_rev: &[u8; 32],
        variant: &str,
        nfc_text: &str,
    ) -> Self {
        let mut k = Self::new(namespace, epoch, profile, config_rev, nfc_text);
        k.variant = variant.to_string();
        k
    }
}

/// Which outcome the engine produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CachedOutcome {
    /// Safe to send.
    Pass,
    /// Safe to send, flagged.
    PassUncertain,
    /// Must not be sent (the API answers 451).
    Blocked,
}

/// A cached engine result. `text` is empty for `Blocked`.
#[derive(Clone)]
pub struct CachedResult {
    /// Outcome kind.
    pub outcome: CachedOutcome,
    /// Sanitized text.
    pub text: String,
    /// Replacement count.
    pub replacements: usize,
    /// Entity kinds involved (replacements, or the block's kinds).
    pub kinds: Vec<EntityKind>,
    /// Reasons (uncertain or blocked).
    pub reasons: Vec<Reason>,
    /// Tokens present in `text`, for the disagreement check.
    pub tokens: Vec<String>,
    /// The applied decisions (offsets only), returned with every hit.
    pub replaced: Vec<ReplacedSpan>,
    /// Output ranges of tokens that were already in the input and resolve
    /// in the store; the release check treats text inside them as covered.
    pub protected: Vec<Range<usize>>,
    /// A link was decided from state outside the text (the batch or the
    /// recency window). Such a result is never inserted (plan 4a decision
    /// 7); a cached hit is `false` by construction.
    pub cross_request: bool,
}

impl std::fmt::Debug for CachedResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedResult")
            .field("outcome", &self.outcome)
            .field("len", &self.text.len())
            .field("replacements", &self.replacements)
            .field("tokens", &self.tokens.len())
            .finish()
    }
}

impl CachedResult {
    /// Bytes charged against the capacity: the sanitized text plus a fixed
    /// per-entry overhead so blocked results (empty text) count too.
    fn weight(&self) -> usize {
        self.text.len() + 64 + self.replaced.len() * 64 + self.protected.len() * 16
    }
}

/// Counters for `GET /v1/status`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct CacheStats {
    /// Lookups that returned a result.
    pub hits: u64,
    /// Lookups that did not (including dropped stale entries).
    pub misses: u64,
    /// Bytes currently charged.
    pub bytes: u64,
    /// Entries evicted or refused for size.
    pub evictions: u64,
    /// Entries stored.
    pub entries: u64,
}

/// The daemon-wide sanitization cache.
pub struct SanitizeCache {
    lru: Mutex<Lru<CacheKey, CachedResult>>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl std::fmt::Debug for SanitizeCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanitizeCache")
            .field("stats", &self.stats())
            .finish()
    }
}

impl SanitizeCache {
    /// Cache holding at most `capacity_bytes` of sanitized text (plus overhead).
    pub fn new(capacity_bytes: u64) -> Self {
        SanitizeCache {
            lru: Mutex::new(Lru::new(
                usize::try_from(capacity_bytes).unwrap_or(usize::MAX),
            )),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Lru<CacheKey, CachedResult>> {
        self.lru.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Cached result, marking it recently used.
    pub fn get(&self, key: &CacheKey) -> Option<CachedResult> {
        let r = self.lock().get(key).cloned();
        match &r {
            Some(_) => self.hits.fetch_add(1, Ordering::Relaxed),
            None => self.misses.fetch_add(1, Ordering::Relaxed),
        };
        r
    }

    /// Like [`SanitizeCache::get`], but the entry is dropped (and counted as
    /// a miss) when `check` rejects it: the cache and the vault disagree
    /// (spec §12), which can only happen after a crash between the cache
    /// write and the vault commit.
    pub fn get_verified(
        &self,
        key: &CacheKey,
        check: impl FnOnce(&CachedResult) -> bool,
    ) -> Option<CachedResult> {
        let r = self.lock().get(key).cloned();
        match r {
            Some(r) if check(&r) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(r)
            }
            Some(_) => {
                // The dataset id is not logged here (M4 spec §5.4); `epoch`
                // is a row id, not user-chosen data.
                tracing::warn!(
                    epoch = key.epoch,
                    "cached result disagrees with the vault; dropped"
                );
                self.lock().remove(key);
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Store a result.
    pub fn insert(&self, key: CacheKey, result: CachedResult) {
        let weight = result.weight();
        let (evicted, refused) = {
            let mut lru = self.lock();
            let refused = weight > lru.capacity();
            (lru.insert(key.clone(), result, weight), refused)
        };
        // A replaced value under the same key is not an eviction; a refused
        // oversized entry counts as one.
        let n = evicted.iter().filter(|(k, _)| *k != key).count() + usize::from(refused);
        if n > 0 {
            self.evictions.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    /// Remove one entry.
    pub fn remove(&self, key: &CacheKey) {
        self.lock().remove(key);
    }

    /// Drop every entry of `(namespace, epoch)`; returns how many.
    pub fn invalidate_epoch(&self, namespace: &str, epoch: i64) -> usize {
        self.lock()
            .retain(|k, _| !(k.namespace == namespace && k.epoch == epoch))
            .len()
    }

    /// Drop every entry of `namespace`; returns how many.
    pub fn invalidate_namespace(&self, namespace: &str) -> usize {
        self.lock().retain(|k, _| k.namespace != namespace).len()
    }

    /// Counters.
    pub fn stats(&self) -> CacheStats {
        let lru = self.lock();
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            bytes: lru.weight() as u64,
            evictions: self.evictions.load(Ordering::Relaxed),
            entries: lru.len() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inumaki_core::span::EntityKind;

    fn result(text: &str, tokens: &[&str]) -> CachedResult {
        CachedResult {
            outcome: CachedOutcome::Pass,
            text: text.to_string(),
            replacements: tokens.len(),
            kinds: vec![EntityKind::Person],
            reasons: Vec::new(),
            tokens: tokens.iter().map(|t| (*t).to_string()).collect(),
            replaced: Vec::new(),
            protected: Vec::new(),
            cross_request: false,
        }
    }

    #[test]
    fn miss_then_hit_with_stats() {
        let c = SanitizeCache::new(1 << 20);
        let k = CacheKey::new("mail", 1, "offline", &[0u8; 32], "Hallo Sarah");
        assert!(c.get(&k).is_none());
        c.insert(
            k.clone(),
            result("Hallo <PERSON_a1b2c3>", &["<PERSON_a1b2c3>"]),
        );
        let r = c.get(&k).unwrap();
        assert_eq!(r.text, "Hallo <PERSON_a1b2c3>");
        let s = c.stats();
        assert_eq!((s.hits, s.misses, s.entries, s.evictions), (1, 1, 1, 0));
        assert!(s.bytes >= "Hallo <PERSON_a1b2c3>".len() as u64);
    }

    #[test]
    fn key_depends_on_namespace_epoch_profile_and_exact_text() {
        let base = CacheKey::new("mail", 1, "offline", &[0u8; 32], "Hallo Sarah");
        assert_eq!(
            base,
            CacheKey::new("mail", 1, "offline", &[0u8; 32], "Hallo Sarah")
        );
        assert_ne!(
            base,
            CacheKey::new("mail2", 1, "offline", &[0u8; 32], "Hallo Sarah")
        );
        assert_ne!(
            base,
            CacheKey::new("mail", 2, "offline", &[0u8; 32], "Hallo Sarah")
        );
        assert_ne!(
            base,
            CacheKey::new("mail", 1, "strict", &[0u8; 32], "Hallo Sarah")
        );
        assert_ne!(
            base,
            CacheKey::new("mail", 1, "offline", &[0u8; 32], "Hallo  Sarah")
        );
        assert_ne!(
            base,
            CacheKey::new("mail", 1, "offline", &[0u8; 32], "hallo sarah")
        );
        assert_ne!(
            base,
            CacheKey::new("mail", 1, "offline", &[1u8; 32], "Hallo Sarah")
        );
        assert_ne!(
            base,
            CacheKey::with_variant(
                "mail",
                1,
                "offline",
                &[0u8; 32],
                "redact:abc",
                "Hallo Sarah"
            )
        );
    }

    #[test]
    fn evicts_by_bytes_least_recently_used_first() {
        // weight() is text.len() + 64: a and b weigh 164 each, so 400 holds
        // two of them (328) and the third insert evicts the oldest (review I2)
        let c = SanitizeCache::new(400);
        let a = CacheKey::new("mail", 1, "offline", &[0u8; 32], "a");
        let b = CacheKey::new("mail", 1, "offline", &[0u8; 32], "b");
        let d = CacheKey::new("mail", 1, "offline", &[0u8; 32], "d");
        c.insert(a.clone(), result(&"x".repeat(100), &[]));
        c.insert(b.clone(), result(&"y".repeat(100), &[]));
        c.get(&a); // a is recent, b is the oldest
        c.insert(d.clone(), result(&"z".repeat(100), &[]));
        assert!(c.get(&b).is_none(), "b evicted");
        assert!(c.get(&a).is_some() && c.get(&d).is_some());
        assert_eq!(c.stats().evictions, 1);
        // an entry larger than the whole cache is never stored
        c.insert(
            CacheKey::new("mail", 1, "offline", &[0u8; 32], "big"),
            result(&"q".repeat(400), &[]),
        );
        assert_eq!(c.stats().evictions, 2);
        assert!(
            c.get(&CacheKey::new("mail", 1, "offline", &[0u8; 32], "big"))
                .is_none()
        );
    }

    #[test]
    fn invalidation_by_epoch_and_namespace() {
        let c = SanitizeCache::new(1 << 20);
        c.insert(
            CacheKey::new("mail", 1, "offline", &[0u8; 32], "a"),
            result("a", &[]),
        );
        c.insert(
            CacheKey::new("mail", 1, "strict", &[0u8; 32], "b"),
            result("b", &[]),
        );
        c.insert(
            CacheKey::new("mail", 2, "offline", &[0u8; 32], "c"),
            result("c", &[]),
        );
        c.insert(
            CacheKey::new("files", 7, "offline", &[0u8; 32], "d"),
            result("d", &[]),
        );
        assert_eq!(c.invalidate_epoch("mail", 1), 2);
        assert_eq!(c.stats().entries, 2);
        assert!(
            c.get(&CacheKey::new("mail", 2, "offline", &[0u8; 32], "c"))
                .is_some()
        );
        assert_eq!(c.invalidate_namespace("mail"), 1);
        assert_eq!(c.stats().entries, 1);
        assert!(
            c.get(&CacheKey::new("files", 7, "offline", &[0u8; 32], "d"))
                .is_some()
        );
        c.remove(&CacheKey::new("files", 7, "offline", &[0u8; 32], "d"));
        assert_eq!(c.stats().entries, 0);
    }

    /// Review Focus 5 (cache side): a cached result whose tokens the namespace
    /// no longer knows is dropped and counted as a miss.
    #[test]
    fn stale_entry_with_unknown_tokens_is_dropped() {
        let c = SanitizeCache::new(1 << 20);
        let k = CacheKey::new("mail", 1, "offline", &[0u8; 32], "Hallo Sarah");
        c.insert(
            k.clone(),
            result("Hallo <PERSON_a1b2c3>", &["<PERSON_a1b2c3>"]),
        );
        let known: Vec<String> = Vec::new();
        assert!(
            c.get_verified(&k, |r| r.tokens.iter().all(|t| known.contains(t)))
                .is_none()
        );
        assert_eq!(c.stats().entries, 0, "dropped");
        assert_eq!((c.stats().hits, c.stats().misses), (0, 1));
        c.insert(
            k.clone(),
            result("Hallo <PERSON_a1b2c3>", &["<PERSON_a1b2c3>"]),
        );
        let known = ["<PERSON_a1b2c3>".to_string()];
        assert!(
            c.get_verified(&k, |r| r.tokens.iter().all(|t| known.contains(t)))
                .is_some()
        );
        assert_eq!((c.stats().hits, c.stats().misses), (1, 1));
    }

    #[test]
    fn debug_and_stats_carry_no_text() {
        let c = SanitizeCache::new(1 << 20);
        let k = CacheKey::new("mail", 1, "offline", &[0u8; 32], "Hallo Sarah Leitner");
        let r = result("Hallo <PERSON_a1b2c3>", &["<PERSON_a1b2c3>"]);
        let d = format!("{c:?} {k:?} {r:?} {:?}", c.stats());
        assert!(
            !d.contains("Sarah") && !d.contains("a1b2c3") && !d.contains("Hallo"),
            "{d}"
        );
        let json = serde_json::to_string(&CachedOutcome::PassUncertain).unwrap();
        assert_eq!(json, "\"pass_uncertain\"");
    }
}
