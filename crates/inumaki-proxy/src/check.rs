//! Check routes (M8 spec §12.2; M6 spec §9.6 as the M6-3 plan consumes
//! it). A registration ties a 128-bit route id to a check dataset, a
//! script, and an expiry, and keeps the request bodies the scripted
//! upstream received, in arrival order. Bodies only: the check route never
//! copies a request header into the scripted upstream's request, so
//! `authorization`, `x-api-key`, `cookie`, `chatgpt-account-id`, and
//! `x-inumaki-client` never enter. The id is a capability: it is never
//! logged and `Debug` does not print it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use inumaki_core::config::TokenSettings;
use sha2::{Digest, Sha256};

use crate::routes::UpstreamId;
use crate::scripted::Script;
use crate::session::{Session, SessionKey, SessionStore};

/// Most bodies kept per id (spec §12.2).
pub const MAX_RECORDED: usize = 256;
/// Largest body kept.
pub const MAX_RECORDED_BYTES: usize = 4 << 20;

/// A check route id: 16 random bytes, 32 lowercase hex characters on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckId([u8; 16]);

impl std::fmt::Debug for CheckId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckId")
    }
}

impl CheckId {
    /// Exactly 32 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<CheckId> {
        if s.len() != 32 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(CheckId(out))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// One body the scripted upstream received, as sanitized by the pipeline.
#[derive(Clone)]
pub struct RecordedRequest {
    /// `anthropic`, `openai`, or `openai-codex`.
    pub upstream: &'static str,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for RecordedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordedRequest")
            .field("upstream", &self.upstream)
            .field("len", &self.body.len())
            .finish()
    }
}

struct Registration {
    dataset: String,
    script: Script,
    expires: Instant,
    /// Shared, so `recorded` copies pointers under the lock, not bodies.
    recorded: Vec<(&'static str, Arc<[u8]>)>,
    dropped: u64,
    session: Arc<Session>,
}

impl Registration {
    /// Bodies this registration lost or refused if it went away now.
    fn lost(&self) -> u64 {
        self.dropped + self.recorded.len() as u64
    }
}

/// How long the drop count of an expired registration stays readable: one
/// hour from when the expiry is noticed.
const TOMBSTONE: Duration = Duration::from_secs(3600);

/// Longest registration lifetime; a longer `ttl` is clamped to it.
const MAX_TTL: Duration = Duration::from_secs(3600);

/// Makes every registration's session key unique without randomness.
static REGISTRATIONS: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct Table {
    live: HashMap<CheckId, Registration>,
    /// Expired registrations that lost bodies: their drop count, kept so a
    /// reader that counted bodies before the expiry fails closed.
    gone: HashMap<CheckId, (u64, Instant)>,
}

impl Table {
    /// The drop count kept for `id` after an expiry, unless it is older than
    /// [`TOMBSTONE`].
    fn gone_count(&self, id: &CheckId, now: Instant) -> u64 {
        match self.gone.get(id) {
            Some((n, at)) if now.saturating_duration_since(*at) < TOMBSTONE => *n,
            _ => 0,
        }
    }

    /// Move `id` to `gone` when it has expired; `true` when it is live.
    fn is_live(&mut self, id: &CheckId, now: Instant) -> bool {
        match self.live.get(id) {
            Some(r) if r.expires > now => true,
            Some(_) => {
                let r = self.live.remove(id).expect("present");
                if r.lost() > 0 {
                    self.gone.insert(*id, (r.lost(), now));
                }
                false
            }
            None => false,
        }
    }
}

/// The live check routes.
pub struct CheckRoutes {
    table: Mutex<Table>,
    sessions: SessionStore,
}

impl std::fmt::Debug for CheckRoutes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckRoutes")
            .field("live", &self.len())
            .finish()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl CheckRoutes {
    pub fn new(settings: TokenSettings) -> CheckRoutes {
        CheckRoutes {
            table: Mutex::new(Table::default()),
            sessions: SessionStore::new(Duration::from_secs(3600), 64, settings, 1 << 20),
        }
    }

    /// Register `id` (replacing any registration of it) for `ttl`, clamped
    /// to one hour. Bodies a replaced or expired registration of the same id
    /// held are not carried over; they count as dropped. Every registration
    /// gets a fresh session, so a check never inherits token mappings.
    pub fn register(&self, id: CheckId, dataset: &str, script: Script, ttl: Duration) {
        let mut h = Sha256::new();
        h.update(b"inumaki-check\0");
        h.update(id.0);
        h.update(REGISTRATIONS.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        let session = self.sessions.get(SessionKey(h.finalize().into()));
        let now = Instant::now();
        let expires = now.checked_add(ttl.min(MAX_TTL)).unwrap_or(now);
        let mut t = lock(&self.table);
        let carried = t.live.get(&id).map_or(0, Registration::lost) + t.gone_count(&id, now);
        t.gone.remove(&id);
        t.live.insert(
            id,
            Registration {
                dataset: dataset.to_string(),
                script,
                expires,
                recorded: Vec::new(),
                dropped: carried,
                session,
            },
        );
    }

    /// Bodies recorded for `id`, in arrival order. The store only appends:
    /// a body that is not kept is counted in [`CheckRoutes::dropped`].
    pub fn recorded(&self, id: &CheckId) -> Vec<RecordedRequest> {
        let shared = {
            let mut t = lock(&self.table);
            if !t.is_live(id, Instant::now()) {
                return Vec::new();
            }
            t.live[id].recorded.clone()
        };
        // The bodies are copied after the lock is released.
        shared
            .into_iter()
            .map(|(upstream, body)| RecordedRequest {
                upstream,
                body: body.to_vec(),
            })
            .collect()
    }

    /// Bodies for `id` that `recorded` does not return: refused over the
    /// caps, or discarded by a re-registration or an expiry. A check fails
    /// closed when this is above zero (M6-3's `ProxyCheckRoutes::dropped`).
    /// `0` after `remove`, which ends the check deliberately.
    pub fn dropped(&self, id: &CheckId) -> u64 {
        let mut t = lock(&self.table);
        let now = Instant::now();
        if t.is_live(id, now) {
            t.live[id].dropped
        } else {
            t.gone_count(id, now)
        }
    }

    /// End a check: its registration, bodies, and drop count go.
    pub fn remove(&self, id: &CheckId) {
        let mut t = lock(&self.table);
        t.live.remove(id);
        t.gone.remove(id);
    }

    pub fn len(&self) -> usize {
        let now = Instant::now();
        lock(&self.table)
            .live
            .values()
            .filter(|r| r.expires > now)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop expired registrations with their bodies (their drop counts stay
    /// readable for an hour); returns how many registrations expired.
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let mut t = lock(&self.table);
        let expired: Vec<CheckId> = t
            .live
            .iter()
            .filter(|(_, r)| r.expires <= now)
            .map(|(k, _)| *k)
            .collect();
        for id in &expired {
            t.is_live(id, now);
        }
        t.gone
            .retain(|_, (_, at)| now.duration_since(*at) < TOMBSTONE);
        expired.len()
    }

    /// Dataset, script, and session of a live registration.
    pub(crate) fn lookup(&self, id: &CheckId) -> Option<(String, Script, Arc<Session>)> {
        let mut t = lock(&self.table);
        if !t.is_live(id, Instant::now()) {
            return None;
        }
        let r = &t.live[id];
        Some((r.dataset.clone(), r.script.clone(), Arc::clone(&r.session)))
    }

    /// Keep one body the scripted upstream received, or count it as dropped.
    pub(crate) fn record(&self, id: &CheckId, up: UpstreamId, body: &[u8]) {
        // Copied before the lock is taken; an oversized body is never copied.
        let kept: Option<Arc<[u8]>> = (body.len() <= MAX_RECORDED_BYTES).then(|| Arc::from(body));
        let mut t = lock(&self.table);
        let now = Instant::now();
        let known = t.live.contains_key(id);
        if !t.is_live(id, now) {
            if known {
                // Expired before this body arrived: the body is lost, so count
                // it, and a check that counted bodies fails closed.
                let n = t.gone_count(id, now) + 1;
                t.gone.insert(*id, (n, now));
            }
            return;
        }
        let r = t.live.get_mut(id).expect("live");
        match kept {
            Some(b) if r.recorded.len() < MAX_RECORDED => r.recorded.push((up.id(), b)),
            _ => r.dropped += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripted::Step;

    const HEX: &str = "0123456789abcdef0123456789abcdef";

    fn routes() -> CheckRoutes {
        CheckRoutes::new(TokenSettings::default())
    }

    /// Review Focus 4; M6-3 relies on these exact rules.
    #[test]
    fn registry_contract() {
        let id = CheckId::from_hex(HEX).unwrap();
        assert_eq!(id.to_hex(), HEX);
        for bad in [
            "0123456789ABCDEF0123456789abcdef",
            &HEX[..31],
            &format!("{HEX}0"),
            "g123456789abcdef0123456789abcdef",
            "",
        ] {
            assert!(CheckId::from_hex(bad).is_none(), "{} chars", bad.len());
        }
        assert_eq!(format!("{id:?}"), "CheckId");
        let r = routes();
        r.register(
            id,
            "check-ab",
            Script(vec![Step::EchoUserText]),
            Duration::from_secs(60),
        );
        assert_eq!(r.len(), 1);
        r.record(&id, UpstreamId::Anthropic, b"first");
        r.record(&id, UpstreamId::OpenaiCodex, b"second");
        let rec = r.recorded(&id);
        assert_eq!(
            rec.iter()
                .map(|x| (x.upstream, x.body.as_slice()))
                .collect::<Vec<_>>(),
            vec![
                ("anthropic", &b"first"[..]),
                ("openai-codex", &b"second"[..])
            ]
        );
        assert_eq!(
            format!("{:?}", rec[0]),
            "RecordedRequest { upstream: \"anthropic\", len: 5 }"
        );
        r.register(
            id,
            "check-ab",
            Script(vec![Step::EchoUserText]),
            Duration::from_secs(60),
        );
        assert!(
            r.recorded(&id).is_empty(),
            "re-registering starts a new record"
        );
        assert_eq!(
            r.dropped(&id),
            2,
            "the replaced registration's bodies count as dropped"
        );
        r.record(&id, UpstreamId::Anthropic, b"x");
        r.remove(&id);
        assert!(r.lookup(&id).is_none() && r.recorded(&id).is_empty());
        assert_eq!(r.dropped(&id), 0, "remove ends the check deliberately");
        r.register(id, "check-ab", Script::default(), Duration::ZERO);
        assert_eq!(r.len(), 0, "expired at once");
        assert_eq!(r.sweep(), 1, "the sweep drops it");
        r.register(id, "check-ab", Script::default(), Duration::ZERO);
        assert!(r.lookup(&id).is_none(), "expired");
        assert!(r.recorded(&id).is_empty());
        assert_eq!(
            r.dropped(&id),
            0,
            "an expiry that lost no body drops nothing"
        );
    }

    /// Integrator addition (M6-3 `ProxyCheckRoutes::dropped`): any body not
    /// returned by `recorded` counts, so a check that counted bodies fails closed.
    #[test]
    fn an_expiry_that_discards_bodies_counts_them_as_dropped() {
        let id = CheckId::from_hex(HEX).unwrap();
        let r = routes();
        r.register(id, "check-ab", Script::default(), Duration::from_millis(50));
        r.record(&id, UpstreamId::Anthropic, b"one");
        std::thread::sleep(Duration::from_millis(80));
        assert!(r.recorded(&id).is_empty(), "expired with its bodies");
        assert_eq!(r.dropped(&id), 1, "the discarded body is a drop");
        assert_eq!(r.sweep(), 0, "already expired on read");
        assert_eq!(r.dropped(&id), 1, "still readable after the sweep");
        r.register(id, "check-ab", Script::default(), Duration::from_secs(60));
        assert_eq!(r.dropped(&id), 1, "carried into a re-registration");
    }

    /// Fail closed: a body arriving after the expiry is counted, a body for an
    /// id that was never registered or was removed is not.
    #[test]
    fn a_body_after_expiry_is_counted_but_unknown_ids_stay_zero() {
        let id = CheckId::from_hex(HEX).unwrap();
        let r = routes();
        r.register(id, "check-ab", Script::default(), Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(80));
        r.record(&id, UpstreamId::Anthropic, b"late");
        assert!(r.recorded(&id).is_empty());
        assert_eq!(r.dropped(&id), 1);
        r.remove(&id);
        r.record(&id, UpstreamId::Anthropic, b"unknown");
        assert_eq!(r.dropped(&id), 0, "removed id");
        let other = CheckId::from_hex("ffffffffffffffffffffffffffffffff").unwrap();
        r.record(&other, UpstreamId::Anthropic, b"unknown");
        assert_eq!(r.dropped(&other), 0, "never registered");
    }

    /// A check never inherits token mappings, and a huge ttl does not expire at once.
    #[test]
    fn each_registration_gets_a_fresh_session_and_a_huge_ttl_is_clamped() {
        let id = CheckId::from_hex(HEX).unwrap();
        let r = routes();
        r.register(id, "check-ab", Script::default(), Duration::MAX);
        assert_eq!(r.len(), 1, "clamped, not expired");
        let first = r.lookup(&id).expect("live").2;
        r.register(id, "check-ab", Script::default(), Duration::from_secs(60));
        let second = r.lookup(&id).expect("live").2;
        assert!(!Arc::ptr_eq(&first, &second));
    }

    /// Over the caps: refused and counted, never evicted (more than 256 bodies ⇒ dropped > 0).
    #[test]
    fn recording_is_bounded_append_only_and_counted() {
        let id = CheckId::from_hex(HEX).unwrap();
        let r = routes();
        r.register(id, "check-ab", Script::default(), Duration::from_secs(60));
        r.record(&id, UpstreamId::Openai, &vec![b'a'; MAX_RECORDED_BYTES + 1]);
        assert!(r.recorded(&id).is_empty(), "an oversized body is not kept");
        assert_eq!(r.dropped(&id), 1);
        for i in 0..MAX_RECORDED + 5 {
            r.record(&id, UpstreamId::Openai, i.to_string().as_bytes());
        }
        let rec = r.recorded(&id);
        assert_eq!(rec.len(), MAX_RECORDED);
        assert_eq!(rec[0].body, b"0", "no eviction: the first body stays first");
        assert_eq!(
            rec[MAX_RECORDED - 1].body,
            (MAX_RECORDED - 1).to_string().into_bytes()
        );
        assert_eq!(r.dropped(&id), 6, "1 oversized + 5 over the count");
    }
}
