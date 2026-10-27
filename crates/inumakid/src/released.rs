//! Keyed digests of blocks `sanitize_blocks` released (gateway, mirror,
//! hook), so the proxy can skip detection for a tool result that already
//! passed (M8 spec §14, review I10). In memory only; the stored value is
//! `HMAC(per-process key, SHA-256(text))`, never the text or its plain
//! digest; bounded at [`CAPACITY`] entries, each valid for [`TTL`].
//!
//! The proxy still re-checks a released block deterministically before it
//! skips the engine (`inumaki_proxy::pipeline`); a digest here is a hint,
//! never a verdict.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// At most this many digests are held; the oldest goes first.
pub const CAPACITY: usize = 65_536;
/// A digest older than this no longer counts.
pub const TTL: Duration = Duration::from_secs(3600);

/// The released blocks' keyed digests. `Debug` prints the count only.
pub struct ReleasedDigests {
    key: [u8; 32],
    map: Mutex<HashMap<[u8; 32], Instant>>,
}

impl std::fmt::Debug for ReleasedDigests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleasedDigests")
            .field("entries", &self.len())
            .finish()
    }
}

impl Default for ReleasedDigests {
    fn default() -> Self {
        Self::new()
    }
}

impl ReleasedDigests {
    /// An empty set with a fresh per-process key.
    pub fn new() -> ReleasedDigests {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("the OS random source works");
        ReleasedDigests {
            key,
            map: Mutex::new(HashMap::new()),
        }
    }

    fn keyed(&self, sha: &[u8; 32]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("any key length");
        m.update(sha);
        m.finalize().into_bytes().into()
    }

    /// Record a released block's text (as `sanitize_blocks` returns it).
    pub fn insert(&self, text: &str) {
        let k = self.keyed(&Sha256::digest(text.as_bytes()).into());
        let now = Instant::now();
        let mut m = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if m.len() >= CAPACITY && !m.contains_key(&k) {
            m.retain(|_, t| now.duration_since(*t) < TTL);
            if m.len() >= CAPACITY
                && let Some(oldest) = m.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k)
            {
                m.remove(&oldest);
            }
        }
        m.insert(k, now);
    }

    /// Whether a block with this SHA-256 was released within the TTL.
    pub fn contains(&self, sha: &[u8; 32]) -> bool {
        let k = self.keyed(sha);
        let m = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        m.get(&k).is_some_and(|t| t.elapsed() < TTL)
    }

    /// Digests held (expired ones included until evicted).
    pub fn len(&self) -> usize {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn released_digests_are_keyed_bounded_and_quiet() {
        let r = ReleasedDigests::new();
        r.insert("Kunde <PERSON_a1b2c3> hat bestellt");
        let d: [u8; 32] = Sha256::digest("Kunde <PERSON_a1b2c3> hat bestellt".as_bytes()).into();
        assert!(r.contains(&d));
        assert!(!r.contains(&Sha256::digest(b"other").into()));
        assert_eq!(format!("{r:?}"), "ReleasedDigests { entries: 1 }");
        for i in 0..CAPACITY + 10 {
            r.insert(&format!("block {i}"));
        }
        assert!(r.len() <= CAPACITY);
    }
}
