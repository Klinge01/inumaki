//! Sessions (M8 spec §5.1) and the per-request store the engine sees (§5.3).
//!
//! A [`Session`] is one conversation: a core [`Context`] holding the
//! session's own tokens, its leaf cache, its memo (blocked-verdict
//! placeholders and the keys of binary parts already sent), and its
//! seeded reasoning digests, all in memory and dropped (originals zeroized)
//! when the session expires or is evicted. A [`SessionView`] is the
//! per-request [`TokenStore`] over a session: it adds dataset tokens from
//! the host without ever copying them into the session (decision 12), and
//! it locks the session only inside minting calls, never during detection.
//!
//! # Locking rules
//!
//! - Lock order: the store's map, then a session's cache (`entries`,
//!   `enforce_budget`). Never call a [`SessionStore`] method while holding
//!   a [`Session::cache`] guard: those methods take the map lock.
//! - [`Session::originals`] takes the originals lock, then the context
//!   lock. [`Session::closure_dict`] takes the session-dictionary lock,
//!   then the context lock. Nothing takes the context lock first and then
//!   either of those, and the two are never held together. The session's
//!   `Debug` reads the dictionary's pattern count before it takes the
//!   context lock, and releases it in between.
//! - Closures passed to [`Session::with_context`] must not panic, and must
//!   not format the session's `Debug` (it takes the context lock again and
//!   would deadlock). Every lock here recovers from poisoning with
//!   `PoisonError::into_inner`. That is acceptable because the `Context`
//!   methods called under the lock push a whole entry and its indexes, or
//!   return an error before changing anything. A panic can only come from a
//!   bug in the caller's closure, and the worst outcome of recovering is a
//!   token minted again. Nothing leaks, and one failed request does not
//!   take every request on the session down with it.
//! - The memo (blocked-verdict placeholders and binary part keys share one
//!   FIFO) and the seeded-digest set are bounded per session
//!   ([`MEMO_CAP`], [`SEEDED_CAP`]); the oldest entry goes first.
//!   Losing an entry is fail-closed: a memo miss runs the engine again
//!   (same input, same verdict) or counts a resent binary part again, and
//!   a seed miss means a reasoning block
//!   that holds a known original in clear is refused rather than forwarded.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use inumaki_core::config::TokenSettings;
use inumaki_core::consistency::{TOP_MAX, mid_limit};
use inumaki_core::detect::dictionary::DictionaryDetector;
use inumaki_core::span::EntityKind;
use inumaki_core::token::{Context, ContextId, StoreError, Token, TokenStore};
use inumaki_core::verify::LeakIndex;
use inumaki_core::verify::second_pass::LeakLayer;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::cache::{LeafCache, intersect, union};
use crate::closure::{ClosureDict, Gen, Segment, SessionDict};
use crate::host::{HostError, ProxyHost, Scope};

/// Whether the request carried the client header (decision 23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientMode {
    /// The client header matched: dataset tokens may be restored.
    Trusted,
    /// No or a wrong client header: only session tokens are restored.
    Restricted,
}

/// A session's key: an HMAC under the per-process key. In memory only;
/// `Debug` prints the type name only.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey(pub [u8; 32]);

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey")
    }
}

/// Resolve a request's session key in integration spec §8.2 order:
/// `X-Inumaki-Session`, `x-claude-code-session-id`, Codex's `session-id`
/// (alias `session_id`), else the first system and first user text. Scoped by route prefix and
/// client mode, so the two modes never share a session.
pub fn session_key(
    pk: &[u8; 32],
    prefix: &str,
    mode: ClientMode,
    headers: &http::HeaderMap,
    first_system: Option<&str>,
    first_user: Option<&str>,
) -> SessionKey {
    let header = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
    };
    let (tag, value): (&str, Zeroizing<Vec<u8>>) = if let Some(v) = header("x-inumaki-session") {
        ("inumaki", Zeroizing::new(v.as_bytes().to_vec()))
    } else if let Some(v) = header("x-claude-code-session-id") {
        ("claude", Zeroizing::new(v.as_bytes().to_vec()))
    } else if let Some(v) = header("session-id").or_else(|| header("session_id")) {
        // Codex 0.159.2 sends `session-id`; `session_id` stays an alias
        // (spec §5.1 amendment 2026-10-10). One tag: both spellings of one
        // id are one session.
        ("codex", Zeroizing::new(v.as_bytes().to_vec()))
    } else {
        // The content fallback holds request text: wiped after hashing.
        let mut b = Zeroizing::new(first_system.unwrap_or("").as_bytes().to_vec());
        b.push(0);
        b.extend_from_slice(first_user.unwrap_or("").as_bytes());
        ("content", b)
    };
    let mode_tag: &[u8] = if mode == ClientMode::Trusted {
        b"t"
    } else {
        b"r"
    };
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(pk).expect("any key length");
    for p in [
        prefix.as_bytes(),
        mode_tag,
        tag.as_bytes(),
        value.as_slice(),
    ] {
        m.update(&(p.len() as u64).to_be_bytes());
        m.update(p);
    }
    SessionKey(m.finalize().into_bytes().into())
}

struct Originals {
    built_at: usize,
    det: Option<Arc<DictionaryDetector>>,
}

/// Memo entries kept per session, blocked-verdict placeholders and binary
/// part keys together in one FIFO (oldest evicted first).
pub const MEMO_CAP: usize = 1024;
/// Seeded reasoning digests kept per session (oldest evicted first).
pub const SEEDED_CAP: usize = 4096;

/// A map of digests bounded to `cap` entries, oldest inserted first out.
struct Fifo<V> {
    map: HashMap<[u8; 32], V>,
    order: VecDeque<[u8; 32]>,
    cap: usize,
}

impl<V> Fifo<V> {
    fn new(cap: usize) -> Fifo<V> {
        Fifo {
            map: HashMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    fn get(&self, k: &[u8; 32]) -> Option<&V> {
        self.map.get(k)
    }

    fn get_mut(&mut self, k: &[u8; 32]) -> Option<&mut V> {
        self.map.get_mut(k)
    }

    fn insert(&mut self, k: [u8; 32], v: V) {
        if self.map.insert(k, v).is_none() {
            self.order.push_back(k);
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

/// What a seeded scanned leaf (provider-written reasoning or citation
/// text) was checked against (plan Task 4b, ruling I1).
///
/// - `generation`: the logs' prefix the text needs no check for. At
///   seeding it is the producing request's claim (`Prepared::claim`): the
///   provider saw that request's values only as tokens. Never the logs'
///   length when the answer arrives (a value minted meanwhile, N1).
/// - `ds`: keyed digests of the dataset tokens it needs no check for,
///   sorted and deduplicated (`pipeline::ds_digest`).
///
/// Step 2 checks a seeded leaf against the session values past
/// `generation` and the request's dataset values missing from `ds`. The
/// field is `generation` because `gen` is reserved in edition 2024.
/// `Debug` prints positions and counts only.
#[derive(Clone)]
pub struct SeedStamp {
    /// The logs' prefix already covered.
    pub generation: Gen,
    /// Digests of the dataset tokens already covered.
    pub ds: Arc<[u64]>,
}

impl SeedStamp {
    /// Nothing covered: the text is checked against everything.
    pub fn unverified() -> SeedStamp {
        SeedStamp {
            generation: Gen::ZERO,
            ds: Arc::from([]),
        }
    }
}

impl fmt::Debug for SeedStamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeedStamp")
            .field("generation", &self.generation)
            .field("ds", &self.ds.len())
            .finish()
    }
}

/// Which segment a session-dictionary rebuild builds (Task 6), with the
/// segments it keeps.
enum Plan {
    /// The base over `[0, now)`, alone.
    Base,
    /// The middle segment over `[base.to, now)`, after the kept base.
    Mid(Arc<Segment>),
    /// The delta over `[mid.to, now)` (or `[base.to, now)` with no middle
    /// segment), after the kept base and middle segment.
    Delta(Arc<Segment>, Option<Arc<Segment>>),
}

impl Plan {
    /// Where the new segment starts.
    fn from(&self) -> Gen {
        match self {
            Plan::Base => Gen::ZERO,
            Plan::Mid(b) => b.to,
            Plan::Delta(b, m) => m.as_ref().map_or(b.to, |m| m.to),
        }
    }
}

/// The rebuild for logs at `now` after `cached` (Task 6): a delta while it
/// holds at most `TOP_MAX` entries, else a middle segment while it holds at
/// most `mid_limit(base entries)`, else the base.
fn plan_segments(cached: Option<&SessionDict>, now: Gen) -> Plan {
    let span =
        |from: Gen| (now.entries - from.entries) as usize + (now.removed - from.removed) as usize;
    let Some(b) = cached.and_then(|d| d.base()).filter(|b| now.covers(b.to)) else {
        return Plan::Base;
    };
    let m = cached
        .and_then(|d| d.mid())
        .filter(|m| now.covers(m.to))
        .cloned();
    let m_to = m.as_ref().map_or(b.to, |m| m.to);
    if span(m_to) <= TOP_MAX {
        Plan::Delta(Arc::clone(b), m)
    } else if span(b.to) <= mid_limit(b.to.entries as usize) {
        Plan::Mid(Arc::clone(b))
    } else {
        Plan::Base
    }
}

/// One conversation. `Debug` prints counts only.
pub struct Session {
    ctx: Mutex<Context>,
    cache: Mutex<LeafCache>,
    memo: Mutex<Fifo<String>>,
    seeded: Mutex<Fifo<SeedStamp>>,
    originals: Mutex<Originals>,
    /// The closure-form session dictionary, rebuilt when the logs grew.
    dict: Mutex<Option<Arc<SessionDict>>>,
    last_used: Mutex<Instant>,
    /// Test hook: every originals and session-dictionary build fails.
    #[cfg(test)]
    fail_originals: std::sync::atomic::AtomicBool,
}

/// Lock, recovering from poisoning: a panicked request must not take the
/// whole session (or every session) down with it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Read first, in its own statement: the builder below holds every
        // guard it takes until it finishes, and the lock order is the
        // dictionary, then the context.
        let patterns = lock(&self.dict).as_ref().map_or(0, |d| d.patterns());
        f.debug_struct("Session")
            .field("entries", &lock(&self.ctx).len())
            .field("patterns", &patterns)
            .field("cached", &lock(&self.cache).len())
            .field("memo", &lock(&self.memo).len())
            .field("seeded", &lock(&self.seeded).len())
            .finish()
    }
}

impl Session {
    fn new(ttl: Duration, settings: TokenSettings) -> Session {
        Session {
            ctx: Mutex::new(Context::new(ContextId(String::new()), ttl, settings)),
            cache: Mutex::new(LeafCache::default()),
            memo: Mutex::new(Fifo::new(MEMO_CAP)),
            seeded: Mutex::new(Fifo::new(SEEDED_CAP)),
            originals: Mutex::new(Originals {
                built_at: 0,
                det: None,
            }),
            dict: Mutex::new(None),
            last_used: Mutex::new(Instant::now()),
            #[cfg(test)]
            fail_originals: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Run `f` with the context locked for this call only.
    pub fn with_context<R>(&self, f: impl FnOnce(&mut Context) -> R) -> R {
        f(&mut lock(&self.ctx))
    }

    /// A dictionary over the context's originals (spec §5.4), rebuilt when
    /// the context grew; `None` while the context is empty. Callers fetch it
    /// once per request, not per leaf.
    ///
    /// Fails closed: when the build fails, this returns
    /// `StoreError::Unavailable` (the request fails, nothing is forwarded)
    /// instead of running without the session's dictionary, and the next
    /// call tries again.
    pub fn originals(&self) -> Result<Option<Arc<DictionaryDetector>>, StoreError> {
        let len = self.with_context(|c| c.len());
        let mut o = lock(&self.originals);
        if o.built_at != len || (o.det.is_none() && len > 0) {
            // Copies of originals are held in `Zeroizing` until the detector owns them.
            let entries: Vec<(EntityKind, Zeroizing<String>)> = self.with_context(|c| {
                c.entries()
                    .map(|(k, v)| (k.clone(), Zeroizing::new(v.to_string())))
                    .collect()
            });
            #[cfg(test)]
            let forced = self
                .fail_originals
                .load(std::sync::atomic::Ordering::SeqCst);
            #[cfg(not(test))]
            let forced = false;
            let det = if forced {
                Err(StoreError::Unavailable)
            } else {
                DictionaryDetector::from_entries(
                    entries.iter().map(|(k, v)| (k.clone(), v.as_str())),
                )
                .map_err(|_| StoreError::Unavailable)
            }?;
            o.det = Some(Arc::new(det));
            o.built_at = len;
        }
        Ok(o.det.clone())
    }

    /// Both logs' lengths, read under one context lock.
    /// Past `u32::MAX` entries (a length no session reaches) this
    /// saturates; [`Session::closure_dict`] then fails every request.
    pub fn gen_now(&self) -> Gen {
        self.with_context(|c| {
            gen_of(c).unwrap_or(Gen {
                entries: u32::MAX,
                removed: u32::MAX,
            })
        })
    }

    /// The session's closure-form dictionary (spec §5.4 as amended): every
    /// original in the context's entry log with its transliterated and
    /// folded forms, each PERSON's name parts in the same forms, and every
    /// removed value, in three segments (Task 6, ruling L2-07): base
    /// `[0, b)`, middle `[b, m)`, delta `[m, now)`. Rebuilt only when the
    /// logs grew:
    ///
    /// - the delta over `[m, now)`, while it holds at most
    ///   [`TOP_MAX`](inumaki_core::consistency::TOP_MAX) entries;
    /// - past that, the middle segment over `[b, now)` and no delta;
    /// - the base over `[0, now)`, alone, when there is no base or the
    ///   middle segment would pass
    ///   [`mid_limit`](inumaki_core::consistency::mid_limit) of the base's
    ///   entries.
    ///
    /// The logs never shrink, so the segments carry no eviction lifetime
    /// (Q7). Callers fetch it once per request, after the request's view,
    /// so it covers the view's snapshot.
    ///
    /// Fails closed: a build error is `StoreError::Unavailable` (the
    /// request fails, nothing is forwarded), the cached dictionary is kept,
    /// and the next call tries again.
    pub(crate) fn closure_dict(&self) -> Result<Arc<SessionDict>, StoreError> {
        let mut slot = lock(&self.dict);
        let cached = slot.clone();
        // Under one context lock: the lengths, and copies of only what the
        // new segment covers.
        let copied = self.with_context(|c| {
            let now = gen_of(c)?;
            if let Some(d) = cached.as_ref().filter(|d| d.upto == now) {
                return Ok(Err(Arc::clone(d)));
            }
            let plan = plan_segments(cached.as_deref(), now);
            let from = plan.from();
            let copy = |it: &mut dyn Iterator<Item = (&EntityKind, &str)>, skip: u32| {
                it.skip(skip as usize)
                    .map(|(k, v)| (k.clone(), Zeroizing::new(v.to_string())))
                    .collect::<Vec<_>>()
            };
            let entries = copy(&mut c.entries(), from.entries);
            let removed = copy(&mut c.removed_entries(), from.removed);
            Ok(Ok((now, plan, entries, removed)))
        })?;
        let (now, plan, entries, removed) = match copied {
            Err(up_to_date) => return Ok(up_to_date),
            Ok(new) => new,
        };
        #[cfg(test)]
        let forced = self
            .fail_originals
            .load(std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(test))]
        let forced = false;
        if forced {
            return Err(StoreError::Unavailable);
        }
        let dict = ClosureDict::build(
            entries.iter().map(|(k, v)| (k, v.as_str())),
            removed.iter().map(|(k, v)| (k, v.as_str())),
        )
        .map_err(|_| StoreError::Unavailable)?;
        let seg = Arc::new(Segment {
            from: plan.from(),
            to: now,
            dict,
        });
        let d = Arc::new(match plan {
            Plan::Base => SessionDict::new(Some(seg), None, None, now),
            Plan::Mid(b) => SessionDict::new(Some(b), Some(seg), None, now),
            Plan::Delta(b, m) => SessionDict::new(Some(b), m, Some(seg), now),
        });
        *slot = Some(Arc::clone(&d));
        Ok(d)
    }

    /// Test hook: while set, every originals rebuild fails.
    #[cfg(test)]
    pub(crate) fn fail_originals_for_test(&self, on: bool) {
        self.fail_originals
            .store(on, std::sync::atomic::Ordering::SeqCst);
    }

    /// The session's leaf cache, locked.
    pub fn cache(&self) -> MutexGuard<'_, LeafCache> {
        lock(&self.cache)
    }

    /// The memoized placeholder for a blocked tool-result block (§5.5).
    pub fn memo_get(&self, k: &[u8; 32]) -> Option<String> {
        lock(&self.memo).get(k).cloned()
    }

    /// True when no placeholder is memoized (callers skip the memo keys).
    pub fn memo_is_empty(&self) -> bool {
        lock(&self.memo).len() == 0
    }

    /// Memoize a placeholder; at [`MEMO_CAP`] the oldest entry goes.
    pub fn memo_put(&self, k: [u8; 32], placeholder: String) {
        lock(&self.memo).insert(k, placeholder);
    }

    /// The stamp of a seeded scanned leaf's digest (§5.6), if it was seeded
    /// from a response and not evicted since. `None` means unseeded: the
    /// leaf gets the full step 2 check.
    pub fn seed_stamp(&self, d: &[u8; 32]) -> Option<SeedStamp> {
        lock(&self.seeded).get(d).cloned()
    }

    /// Record a provider-written scanned leaf's digest with `stamp`; at
    /// [`SEEDED_CAP`] the oldest digest goes. On a digest already present
    /// the stamps merge without ever gaining coverage: the component-wise
    /// minimum of the generations and the intersection of the digest sets.
    pub fn seed(&self, d: [u8; 32], stamp: SeedStamp) {
        let mut f = lock(&self.seeded);
        match f.get_mut(&d) {
            Some(old) => {
                old.generation = Gen {
                    entries: old.generation.entries.min(stamp.generation.entries),
                    removed: old.generation.removed.min(stamp.generation.removed),
                };
                old.ds = intersect(&old.ds, &stamp.ds);
            }
            None => f.insert(d, stamp),
        }
    }

    /// A clean step 2 check of a seeded leaf, committed: its stamp
    /// advances to at least `g` and `ds` (component-wise maximum, set
    /// union). The check covered only what the stamp `read` at step 2 left
    /// uncovered, so the bump applies only while the current stamp still
    /// covers `read` (its generation at or past `read`'s, its digests a
    /// superset). A re-seed that lowered the stamp meanwhile (a concurrent
    /// answer with the same text) is kept: the next request checks again
    /// (review 4b, Important 1). A digest evicted meanwhile stays absent.
    pub fn seed_bump(&self, d: &[u8; 32], read: &SeedStamp, g: Gen, ds: &Arc<[u64]>) {
        debug_assert!(
            ds.windows(2).all(|w| w[0] < w[1]),
            "dataset digests are sorted and deduplicated"
        );
        let mut f = lock(&self.seeded);
        let Some(s) = f.get_mut(d) else {
            return;
        };
        let still = s.generation.covers(read.generation)
            && read.ds.iter().all(|x| s.ds.binary_search(x).is_ok());
        if still {
            s.generation = s.generation.max(g);
            s.ds = union(&s.ds, ds);
        }
    }

    fn touch(&self) {
        *lock(&self.last_used) = Instant::now();
    }

    fn idle(&self) -> Duration {
        lock(&self.last_used).elapsed()
    }
}

/// The context's two log lengths. A log longer than `u32::MAX` fails
/// closed rather than wrap: a `Gen` that stops growing would mark new
/// entries as covered.
fn gen_of(c: &Context) -> Result<Gen, StoreError> {
    let n = |x: usize| u32::try_from(x).map_err(|_| StoreError::Unavailable);
    Ok(Gen {
        entries: n(c.len())?,
        removed: n(c.removed_entries().count())?,
    })
}

/// All live sessions. `Debug` prints counts only.
pub struct SessionStore {
    map: Mutex<HashMap<SessionKey, Arc<Session>>>,
    ttl: Duration,
    cap: usize,
    settings: TokenSettings,
    cache_bytes: usize,
}

impl fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionStore")
            .field("sessions", &self.len())
            .field("cap", &self.cap)
            .finish()
    }
}

impl SessionStore {
    /// `ttl` is the idle lifetime, `cap` the session count bound (LRU),
    /// `cache_bytes` the leaf-cache budget over all sessions.
    pub fn new(
        ttl: Duration,
        cap: usize,
        settings: TokenSettings,
        cache_bytes: usize,
    ) -> SessionStore {
        SessionStore {
            map: Mutex::new(HashMap::new()),
            ttl,
            cap,
            settings,
            cache_bytes,
        }
    }

    /// The live session for `key`, created on first use; an expired one is
    /// replaced (its originals are zeroized on drop); at the cap, the least
    /// recently used session goes.
    pub fn get(&self, key: SessionKey) -> Arc<Session> {
        let mut m = lock(&self.map);
        if let Some(s) = m.get(&key) {
            if s.idle() < self.ttl {
                s.touch();
                return Arc::clone(s);
            }
            m.remove(&key);
        }
        if m.len() >= self.cap {
            if let Some(old) = m.iter().max_by_key(|(_, s)| s.idle()).map(|(k, _)| *k) {
                m.remove(&old);
            }
        }
        let s = Arc::new(Session::new(self.ttl, self.settings.clone()));
        m.insert(key, Arc::clone(&s));
        s
    }

    /// Number of live sessions.
    pub fn len(&self) -> usize {
        lock(&self.map).len()
    }

    /// True when no session is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Cache entries over all sessions.
    pub fn entries(&self) -> u64 {
        lock(&self.map)
            .values()
            .map(|s| s.cache().len() as u64)
            .sum()
    }

    /// Drop expired sessions; returns how many went.
    pub fn sweep(&self) -> usize {
        let mut m = lock(&self.map);
        let before = m.len();
        m.retain(|_, s| s.idle() < self.ttl);
        before - m.len()
    }

    /// Clear the caches of the least recently used sessions until all caches fit.
    pub fn enforce_budget(&self) {
        let m = lock(&self.map);
        let mut sessions: Vec<&Arc<Session>> = m.values().collect();
        let mut total: usize = sessions.iter().map(|s| s.cache().bytes()).sum();
        // Each idle time is read once: `elapsed` moves between reads, and
        // a comparator that changes its answer mid-sort is not a total order.
        sessions.sort_by_cached_key(|s| std::cmp::Reverse(s.idle()));
        for s in sessions {
            if total <= self.cache_bytes {
                break;
            }
            let mut c = s.cache();
            total -= c.bytes();
            c.clear();
        }
    }
}

/// Where a token resolves (decision 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// The session context minted it.
    Session,
    /// A live dataset holds it (resolved through the host each request).
    Dataset,
}

struct Known {
    kind: EntityKind,
    original: Zeroizing<String>,
    provenance: Provenance,
}

/// The store one request's engine passes see (spec §5.3). Holds no lock
/// between calls; `Debug` prints counts only.
pub struct SessionView<'a> {
    session: &'a Session,
    host: &'a dyn ProxyHost,
    settings: TokenSettings,
    /// The session's entries at request start (the verifier's leak check).
    snapshot: Vec<(EntityKind, Zeroizing<String>)>,
    removed: Vec<(EntityKind, Zeroizing<String>)>,
    /// The logs' lengths at the snapshot (`removed` grows afterwards).
    snapshot_gen: Gen,
    /// Every token this request touched, with its original as the store
    /// that owns it holds it (dataset originals live here only).
    known: HashMap<String, Known>,
    fault: Option<HostError>,
    /// Task 5: the leak-check layer over this request's dataset values
    /// (never the session's), keyed by their count and the alias table it
    /// was built through. The only leak layer a view keeps; it goes with
    /// the view.
    leak_ds: Option<((usize, u64), Arc<LeakLayer>)>,
}

/// First owner ordinal of a view's dataset layer: after every session value,
/// so a pattern a dataset value shares with a session value is reported
/// under the session value's kind.
const DATASET_LEAK_ORDINAL: usize = usize::MAX / 2;

impl fmt::Debug for SessionView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionView")
            .field("snapshot", &self.snapshot.len())
            .field("known", &self.known.len())
            .field("fault", &self.fault)
            .finish()
    }
}

impl<'a> SessionView<'a> {
    /// A view over `session` for one request; snapshots the session's
    /// entries under a short lock. The view uses the session context's
    /// token settings (the ones its tokens were minted with); `settings`
    /// must equal them, which debug builds assert.
    pub fn new(
        session: &'a Session,
        host: &'a dyn ProxyHost,
        settings: TokenSettings,
    ) -> SessionView<'a> {
        type Copies = Vec<(EntityKind, Zeroizing<String>)>;
        let (settings, snapshot, removed): (TokenSettings, Copies, Copies) =
            session.with_context(|c| {
                debug_assert_eq!(
                    format!("{settings:?}"),
                    format!("{:?}", c.settings()),
                    "a view's token settings must match its session's"
                );
                (
                    c.settings().clone(),
                    c.entries()
                        .map(|(k, v)| (k.clone(), Zeroizing::new(v.to_string())))
                        .collect(),
                    c.removed_entries()
                        .map(|(k, v)| (k.clone(), Zeroizing::new(v.to_string())))
                        .collect(),
                )
            });
        let n = |x: usize| u32::try_from(x).unwrap_or(u32::MAX);
        let snapshot_gen = Gen {
            entries: n(snapshot.len()),
            removed: n(removed.len()),
        };
        SessionView {
            session,
            host,
            settings,
            snapshot,
            removed,
            snapshot_gen,
            known: HashMap::new(),
            fault: None,
            leak_ds: None,
        }
    }

    /// Where `token` resolved in this request, if it did.
    pub fn provenance(&self, token: &str) -> Option<Provenance> {
        self.known.get(token).map(|k| k.provenance)
    }

    /// The session's log lengths at this view's snapshot.
    pub fn snapshot_gen(&self) -> Gen {
        self.snapshot_gen
    }

    /// The dataset values this request resolved (`Provenance::Dataset`):
    /// they live in this view only (decision 12).
    pub fn dataset_entries(&self) -> impl Iterator<Item = (&EntityKind, &str)> {
        self.known
            .values()
            .filter(|k| k.provenance == Provenance::Dataset)
            .map(|k| (&k.kind, k.original.as_str()))
    }

    /// The `(kind, original)` this request resolved `token` to, if it did.
    pub fn resolved(&self, token: &str) -> Option<(&EntityKind, &str)> {
        self.known
            .get(token)
            .map(|k| (&k.kind, k.original.as_str()))
    }

    /// The tokens of [`SessionView::dataset_entries`].
    pub fn dataset_tokens(&self) -> impl Iterator<Item = &str> {
        self.known
            .iter()
            .filter(|(_, k)| k.provenance == Provenance::Dataset)
            .map(|(t, _)| t.as_str())
    }

    /// The host failure behind the last `StoreError::Unavailable`, if any.
    pub fn fault(&self) -> Option<HostError> {
        self.fault
    }

    fn remember(&mut self, token: &str, kind: &EntityKind, original: &str, provenance: Provenance) {
        self.known
            .entry(token.to_string())
            .or_insert_with(|| Known {
                kind: kind.clone(),
                original: Zeroizing::new(original.to_string()),
                provenance,
            });
    }

    fn failed(&mut self, e: HostError) -> StoreError {
        self.fault = Some(e);
        StoreError::Unavailable
    }
}

/// The context's own `(kind, original)` for `token`, copied out under the
/// caller's lock.
fn held(c: &Context, token: &Token) -> Option<(EntityKind, Zeroizing<String>)> {
    let kind = c.kind_of(token.as_str())?;
    let original = Zeroizing::new(c.original(token.as_str())?.to_string());
    Some((kind, original))
}

impl TokenStore for SessionView<'_> {
    /// The session's existing token, else a dataset token (never written
    /// into the session), else a new session token. The session is locked
    /// only inside each lookup or mint.
    fn token_for(&mut self, kind: &EntityKind, original: &str) -> Result<Token, StoreError> {
        let existing = self.session.with_context(|c| {
            c.peek_token(kind, original)
                .and_then(|t| held(c, &t).map(|h| (t, h)))
        });
        if let Some((t, (k, o))) = existing {
            // The context's original, not the queried text: a surname or
            // a different spelling must still become a surface token.
            self.remember(t.as_str(), &k, &o, Provenance::Session);
            return Ok(t);
        }
        match self.host.dataset_token(kind, original) {
            Ok(Some((t, canonical))) => {
                // The vault's canonical original, not the queried spelling:
                // a different spelling then becomes a surface token that
                // restores to exactly the text it replaced.
                self.remember(&t, kind, &canonical, Provenance::Dataset);
                return Ok(Token::from(t));
            }
            Ok(None) => {}
            Err(e) => return Err(self.failed(e)),
        }
        // A parallel request may have minted the same value meanwhile:
        // `Context::token_for` then returns that token (Review Focus 3).
        let (t, h) = self.session.with_context(|c| {
            let t = c.token_for(kind, original)?;
            let h = held(c, &t);
            Ok::<_, StoreError>((t, h))
        })?;
        let (k, o) = h.ok_or(StoreError::Unavailable)?;
        self.remember(t.as_str(), &k, &o, Provenance::Session);
        Ok(t)
    }

    /// The original this request resolved `token` to, from either scope.
    /// Only tokens returned by this view or passed to `prepare` answer.
    fn original(&self, token: &str) -> Option<&str> {
        self.known.get(token).map(|k| k.original.as_str())
    }

    /// The session's entries at request start, plus every value this view
    /// resolved or minted (dataset values included, for the leak check).
    fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        Box::new(
            self.snapshot
                .iter()
                .map(|(k, v)| (k, v.as_str()))
                .chain(self.known.values().map(|k| (&k.kind, k.original.as_str()))),
        )
    }

    fn record_removed(&mut self, kind: &EntityKind, original: &str) -> Result<(), StoreError> {
        self.session
            .with_context(|c| TokenStore::record_removed(c, kind, original))?;
        if !self.removed.iter().any(|(_, v)| v.as_str() == original) {
            self.removed
                .push((kind.clone(), Zeroizing::new(original.to_string())));
        }
        Ok(())
    }

    fn removed_entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        Box::new(self.removed.iter().map(|(k, v)| (k, v.as_str())))
    }

    fn removed_marker(&self, kind: &EntityKind) -> String {
        format!(
            "{}{}_REMOVED{}",
            self.settings.open,
            inumaki_core::token::token_label(kind),
            self.settings.close
        )
    }

    fn settings(&self) -> &TokenSettings {
        &self.settings
    }

    /// Session tokens first (one short lock), then the rest through
    /// `ProxyHost::resolve` over live datasets. Dataset originals stay in
    /// this view for this request only (decision 12).
    fn prepare(&mut self, tokens: &[String]) -> Result<(), StoreError> {
        let missing: Vec<&String> = tokens
            .iter()
            .filter(|t| !self.known.contains_key(t.as_str()))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let (found, rest): (Vec<_>, Vec<String>) = self.session.with_context(|c| {
            let mut found = Vec::new();
            let mut rest = Vec::new();
            for t in &missing {
                match held(c, &Token::from((*t).clone())) {
                    Some(h) => found.push(((*t).clone(), h)),
                    None => rest.push((*t).clone()),
                }
            }
            (found, rest)
        });
        for (t, (k, o)) in found {
            self.remember(&t, &k, &o, Provenance::Session);
        }
        if rest.is_empty() {
            return Ok(());
        }
        match self.host.resolve(&rest, &Scope::Datasets) {
            Ok(found) => {
                for (t, kind, o) in found {
                    self.remember(&t, &kind, &o, Provenance::Dataset);
                }
                Ok(())
            }
            Err(e) => Err(self.failed(e)),
        }
    }

    /// A surface form of a session entity goes to the session context; of
    /// a dataset entity, it becomes an ordinary session token for the
    /// surface text (spec §5.3). Either way it restores to `surface` exactly.
    fn surface_token(&mut self, parent: &Token, surface: &str) -> Result<Token, StoreError> {
        let parent_of = self
            .known
            .get(parent.as_str())
            .map(|k| (k.kind.clone(), k.provenance));
        let (t, h) = self.session.with_context(|c| {
            let t = match parent_of {
                Some((kind, Provenance::Dataset)) => {
                    let t = c.token_for(&kind, surface)?;
                    if c.original(t.as_str()) == Some(surface) {
                        t
                    } else {
                        c.surface_token(&t, surface)?
                    }
                }
                // A session parent, or one this view has not seen: the
                // context answers `UnknownParent` if it is not its entity.
                _ => c.surface_token(parent, surface)?,
            };
            let h = held(c, &t);
            Ok::<_, StoreError>((t, h))
        })?;
        let (k, o) = h.ok_or(StoreError::Unavailable)?;
        self.remember(t.as_str(), &k, &o, Provenance::Session);
        Ok(t)
    }

    /// The session's recent entities, for the linker's store tier.
    fn link_candidates(&self, kind: &EntityKind, window: Duration) -> Vec<Zeroizing<String>> {
        self.session
            .with_context(|c| c.link_candidates(kind, window))
    }

    /// Task 7e: the session context's cached dictionary, plus a layer over
    /// this request's dataset values (which never enter the session).
    fn store_dict(
        &mut self,
        aliases: Option<&inumaki_core::AliasTable>,
    ) -> Option<inumaki_core::Result<inumaki_core::consistency::StoreDict>> {
        let session = self.session.with_context(|c| c.store_dict(aliases))?;
        Some(session.and_then(|d| d.with_values(self.dataset_entries(), aliases)))
    }

    /// Task 5: the session context's cached leak index, plus this view's
    /// layer over its dataset values (rebuilt when their count changes).
    /// The context's index may also hold a value another request minted
    /// since this view's snapshot; that only makes the check stricter.
    fn leak_index(
        &mut self,
        aliases: Option<&inumaki_core::AliasTable>,
    ) -> Option<inumaki_core::Result<LeakIndex>> {
        let idx = match self.session.with_context(|c| c.leak_index(aliases))? {
            Ok(i) => i,
            Err(e) => return Some(Err(e)),
        };
        let n = self.dataset_entries().count();
        if n == 0 {
            return Some(Ok(idx));
        }
        let key = (n, aliases.map_or(0, inumaki_core::AliasTable::fingerprint));
        if self.leak_ds.as_ref().is_none_or(|(k, _)| *k != key) {
            // Dropped before the build: one copy of the patterns at a time.
            self.leak_ds = None;
            let layer = match LeakLayer::build(
                self.dataset_entries(),
                std::iter::empty(),
                aliases,
                DATASET_LEAK_ORDINAL,
            ) {
                Ok(l) => l,
                Err(e) => return Some(Err(e)),
            };
            self.leak_ds = Some((key, Arc::new(layer)));
        }
        let layer = self.leak_ds.as_ref().map(|(_, l)| Arc::clone(l))?;
        Some(Ok(idx.with_layer(layer)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{CFG, DS_TOKEN, EMAIL, FakeHost, NAME};
    use inumaki_core::config::CoreConfig;
    use inumaki_core::detect::{DetectCtx, Detector};
    use inumaki_core::engine::{Engine, Outcome};
    use inumaki_core::span::{DetectorId, EntityKind, Span};
    use inumaki_core::token::TokenStore;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn store() -> SessionStore {
        SessionStore::new(
            Duration::from_secs(60),
            4,
            TokenSettings::default(),
            1 << 20,
        )
    }

    #[test]
    fn session_key_prefers_headers_in_order_and_never_mixes_modes() {
        let pk = [7u8; 32];
        let mut h = http::HeaderMap::new();
        h.insert("x-claude-code-session-id", "abc".parse().unwrap());
        let a = session_key(
            &pk,
            "/anthropic",
            ClientMode::Trusted,
            &h,
            Some("s"),
            Some("u"),
        );
        let b = session_key(
            &pk,
            "/anthropic",
            ClientMode::Trusted,
            &h,
            Some("other"),
            Some("other"),
        );
        assert!(a == b, "the header wins over the content fallback");
        assert!(
            a != session_key(
                &pk,
                "/anthropic",
                ClientMode::Restricted,
                &h,
                Some("s"),
                Some("u")
            )
        );
        h.insert("x-inumaki-session", "mine".parse().unwrap());
        assert!(
            a != session_key(
                &pk,
                "/anthropic",
                ClientMode::Trusted,
                &h,
                Some("s"),
                Some("u")
            )
        );
        let none = http::HeaderMap::new();
        assert!(
            session_key(
                &pk,
                "/openai",
                ClientMode::Trusted,
                &none,
                Some("s"),
                Some("u")
            ) == session_key(
                &pk,
                "/openai",
                ClientMode::Trusted,
                &none,
                Some("s"),
                Some("u")
            )
        );
        assert_eq!(format!("{a:?}"), "SessionKey");
    }

    /// L59: Codex sends `session-id`; `session_id` is an alias for it, and
    /// either one wins over the content fallback. Claude Code's header is
    /// unchanged and keys a different session than the same value as Codex's.
    #[test]
    fn codex_session_header_hyphen_and_underscore_are_one_session() {
        let pk = [7u8; 32];
        let key = |h: &http::HeaderMap| {
            session_key(&pk, "/codex", ClientMode::Trusted, h, Some("s"), Some("u"))
        };
        let mut hyphen = http::HeaderMap::new();
        hyphen.insert("session-id", "019a-thread".parse().unwrap());
        let mut underscore = http::HeaderMap::new();
        underscore.insert("session_id", "019a-thread".parse().unwrap());
        let content = key(&http::HeaderMap::new());
        assert!(key(&hyphen) == key(&underscore));
        assert!(key(&hyphen) != content);
        // The hyphen spelling wins when both are present.
        let mut both = hyphen.clone();
        both.insert("session_id", "other".parse().unwrap());
        assert!(key(&both) == key(&hyphen));
        // A different id is a different session.
        let mut other = http::HeaderMap::new();
        other.insert("session-id", "019b-thread".parse().unwrap());
        assert!(key(&other) != key(&hyphen));
        // Claude Code's header still keys its own session.
        let mut claude = http::HeaderMap::new();
        claude.insert("x-claude-code-session-id", "019a-thread".parse().unwrap());
        assert!(key(&claude) != key(&hyphen) && key(&claude) != content);
        let mut claude_other = claude.clone();
        claude_other.insert("session-id", "zzz".parse().unwrap());
        assert!(
            key(&claude_other) == key(&claude),
            "Claude Code's header first"
        );
    }

    /// Spec decision 12 / review I4.
    #[test]
    fn dataset_tokens_are_never_copied_into_the_session() {
        let host = FakeHost::new();
        let s = store().get(SessionKey([1; 32]));
        let mut v = SessionView::new(&s, &*host, TokenSettings::default());
        let t = v.token_for(&EntityKind::Person, NAME).unwrap();
        assert_eq!(
            t.as_str(),
            DS_TOKEN,
            "a value the dataset knows reuses its token"
        );
        assert_eq!(v.provenance(DS_TOKEN), Some(Provenance::Dataset));
        // A differently cased query reuses the token; the view records the
        // vault's canonical original, so the engine makes the query a
        // surface token rather than restoring a different spelling.
        let mut vl = SessionView::new(&s, &*host, TokenSettings::default());
        let lower = NAME.to_lowercase();
        assert_eq!(
            vl.token_for(&EntityKind::Person, &lower).unwrap().as_str(),
            DS_TOKEN
        );
        assert_eq!(vl.original(DS_TOKEN), Some(NAME));
        drop(vl);
        let e = v.token_for(&EntityKind::Email, EMAIL).unwrap();
        assert_eq!(v.provenance(e.as_str()), Some(Provenance::Session));
        // A surface form of a dataset entity is an ordinary session token.
        let sf = v
            .surface_token(&Token::from(DS_TOKEN.to_string()), "Zyxwuria Q.")
            .unwrap();
        assert_eq!(v.provenance(sf.as_str()), Some(Provenance::Session));
        assert_eq!(v.original(sf.as_str()), Some("Zyxwuria Q."));
        drop(v);
        s.with_context(|c| {
            assert_eq!(c.len(), 2, "only the email and the surface form");
            assert!(c.original(DS_TOKEN).is_none());
            assert!(
                c.entries().all(|(_, o)| o != NAME),
                "the dataset original never enters the session"
            );
        });
        let mut v2 = SessionView::new(&s, &*host, TokenSettings::default());
        v2.prepare(&[DS_TOKEN.to_string(), e.as_str().to_string()])
            .unwrap();
        assert_eq!(v2.original(DS_TOKEN), Some(NAME));
        assert_eq!(v2.original(e.as_str()), Some(EMAIL));
        assert_eq!(v2.provenance(DS_TOKEN), Some(Provenance::Dataset));
        assert_eq!(v2.provenance(e.as_str()), Some(Provenance::Session));
        drop(v2);
        s.with_context(|c| assert!(c.original(DS_TOKEN).is_none(), "prepare copies nothing"));
        host.forget(DS_TOKEN);
        let mut v3 = SessionView::new(&s, &*host, TokenSettings::default());
        v3.prepare(&[DS_TOKEN.to_string()]).unwrap();
        assert_eq!(v3.original(DS_TOKEN), None, "forget applies at once");
    }

    /// Task 7e, decision 12: a request's dataset values reach its own
    /// consistency dictionary (a layer of the view), never the session
    /// context's cached one, so a later request does not inherit them.
    #[test]
    fn dataset_values_stay_out_of_the_session_dictionary() {
        let host = FakeHost::new();
        let s = store().get(SessionKey([3; 32]));
        let mut v = SessionView::new(&s, &*host, TokenSettings::default());
        assert_eq!(
            v.token_for(&EntityKind::Person, NAME).unwrap().as_str(),
            DS_TOKEN
        );
        v.token_for(&EntityKind::Email, EMAIL).unwrap();
        let name = format!("Gruss an {NAME}");
        let email = format!("an {EMAIL} bitte");
        let hits = |d: &inumaki_core::consistency::StoreDict, text: &str| {
            !d.redactions(text, &[], &[]).unwrap().is_empty()
        };
        let view = v.store_dict(None).unwrap().unwrap();
        assert!(hits(&view, &name), "the request's dataset value");
        assert!(hits(&view, &email), "the session's own value");
        drop(view);
        let session = s.with_context(|c| c.store_dict(None)).unwrap().unwrap();
        assert!(!hits(&session, &name), "never in the session's dictionary");
        assert!(hits(&session, &email));
        drop((session, v));
        let mut fresh = SessionView::new(&s, &*host, TokenSettings::default());
        let next = fresh.store_dict(None).unwrap().unwrap();
        assert!(!hits(&next, &name), "a later request does not inherit it");
        assert!(hits(&next, &email));
    }

    /// Task 5 (Q6 c): a view's leak index covers every value the view
    /// reports (a snapshot entry, a value it minted, a session removed
    /// value, a dataset value resolved through its token), so each one's
    /// clear copy is a leak through the index, never through a stale
    /// fallback. The dataset layer is the view's own: a later view's index
    /// does not hold it.
    #[test]
    fn a_views_leak_index_covers_every_view_entry() {
        use inumaki_core::detect::regex::RegexDetector;
        use inumaki_core::policy::VerifierSettings;
        use inumaki_core::sanitize::Sanitized;
        use inumaki_core::verify::{CheckId, SecondPassVerifier, Verdict};
        let verifier = SecondPassVerifier::new(
            RegexDetector::new(),
            None,
            &VerifierSettings {
                allow_no_ner: true,
                ..Default::default()
            },
        )
        .unwrap();
        let cand = |text: &str| Sanitized {
            text: text.to_string(),
            replacements: Vec::new(),
            blocked: Vec::new(),
            escalated: Vec::new(),
            protected: Vec::new(),
        };
        let leaks = |v: &Verdict| matches!(v, Verdict::Fail(r) if r.iter().any(|x| x.check == CheckId::Leak));
        let host = FakeHost::new();
        let s = store().get(SessionKey([4; 32]));
        let mut first = SessionView::new(&s, &*host, TokenSettings::default());
        first.token_for(&EntityKind::Email, EMAIL).unwrap();
        drop(first);
        let mut v = SessionView::new(&s, &*host, TokenSettings::default());
        v.token_for(&EntityKind::Person, "Kurt Brandlinger")
            .unwrap();
        v.record_removed(&EntityKind::custom("SECRET"), "hunter2pwgeheim")
            .unwrap();
        v.prepare(&[DS_TOKEN.to_string()]).unwrap();
        assert_eq!(v.provenance(DS_TOKEN), Some(Provenance::Dataset));
        let idx = v.leak_index(None).unwrap().unwrap();
        assert!(idx.covers(&v), "the index covers the view");
        for text in [
            format!("an {EMAIL} bitte"),
            "Gruss an Kurt Brandlinger".to_string(),
            "das Passwort hunter2pwgeheim bitte".to_string(),
            format!("Gruss an {NAME}"),
        ] {
            let verdict = verifier.verify_with_leak(&cand(&text), &v, Some(&idx));
            assert!(leaks(&verdict), "{} {verdict:?}", text.len());
        }
        let n = idx.layer_count();
        drop(idx);
        let held = v.leak_ds.as_ref().map(|(_, l)| Arc::clone(l)).unwrap();
        let again = v.leak_index(None).unwrap().unwrap();
        assert_eq!(again.layer_count(), n);
        assert!(
            v.leak_ds
                .as_ref()
                .is_some_and(|(_, l)| Arc::ptr_eq(l, &held)),
            "the view's layer is reused, not rebuilt"
        );
        drop(held);
        drop((again, v));
        let mut later = SessionView::new(&s, &*host, TokenSettings::default());
        let idx = later.leak_index(None).unwrap().unwrap();
        assert_eq!(idx.layer_count(), n - 1, "no dataset layer");
        let verdict =
            verifier.verify_with_leak(&cand(&format!("Gruss an {NAME}")), &later, Some(&idx));
        assert!(!leaks(&verdict), "a later view does not inherit it");
    }

    #[test]
    fn a_session_token_wins_over_a_dataset_token_learned_later() {
        let host = FakeHost::new();
        let s = store().get(SessionKey([2; 32]));
        let mut v = SessionView::new(&s, &*host, TokenSettings::default());
        let e = v.token_for(&EntityKind::Email, EMAIL).unwrap();
        host.dataset
            .lock()
            .unwrap()
            .insert("<EMAIL_d4d4d4>".into(), (EntityKind::Email, EMAIL.into()));
        let mut v2 = SessionView::new(&s, &*host, TokenSettings::default());
        assert_eq!(v2.token_for(&EntityKind::Email, EMAIL).unwrap(), e);
        assert_eq!(v2.provenance(e.as_str()), Some(Provenance::Session));
    }

    /// Asserts, from inside detection, that the session lock is free. Only
    /// meaningful single-threaded: another thread may hold the lock briefly.
    struct LockProbe(Arc<Session>, AtomicUsize);

    impl Detector for LockProbe {
        fn id(&self) -> DetectorId {
            DetectorId::Ner
        }
        fn detect(&self, _: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
            assert!(
                self.0.ctx.try_lock().is_ok(),
                "the session lock is held during detection"
            );
            self.1.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    fn pass_text(o: Outcome) -> String {
        match o {
            Outcome::Pass { sanitized } => sanitized.text,
            _ => panic!("expected pass"),
        }
    }

    /// Review Focus 3.
    #[test]
    fn parallel_views_mint_one_token_per_value() {
        const N: usize = 8;
        let host = FakeHost::new();

        // Store level: the threads start their mints together.
        let s = store().get(SessionKey([3; 32]));
        let gate = Barrier::new(N);
        let toks: Vec<String> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..N)
                .map(|_| {
                    sc.spawn(|| {
                        let mut v = SessionView::new(&s, &*host, TokenSettings::default());
                        gate.wait();
                        v.token_for(&EntityKind::Email, EMAIL)
                            .unwrap()
                            .as_str()
                            .to_string()
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(toks.windows(2).all(|w| w[0] == w[1]), "{toks:?}");
        // No lock is held between calls: a view exists while another mints.
        let _held = SessionView::new(&s, &*host, TokenSettings::default());
        s.with_context(|c| assert_eq!(c.len(), 1));

        // Engine level, in parallel: one token for a new value.
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let engine = Engine::from_config(&cfg, "fast", None, None).unwrap();
        let text = "write to other.person@example.invalid please";
        let s2 = store().get(SessionKey([5; 32]));
        let gate = Barrier::new(N);
        let outs: Vec<String> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..N)
                .map(|_| {
                    sc.spawn(|| {
                        let mut v = SessionView::new(&s2, &*host, TokenSettings::default());
                        gate.wait();
                        pass_text(engine.process(text, &mut v).unwrap())
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(outs.windows(2).all(|w| w[0] == w[1]), "{}", outs.len());
        assert!(!outs[0].contains("other.person"));
        s2.with_context(|c| assert_eq!(c.len(), 1));

        // Engine level, one thread: detection never runs under the session
        // lock (the only thread that could hold it is this one).
        let s3 = store().get(SessionKey([7; 32]));
        let probe = Arc::new(LockProbe(Arc::clone(&s3), AtomicUsize::new(0)));
        let probed = Engine::from_config(&cfg, "fast", None, None)
            .unwrap()
            .with_detector(Arc::clone(&probe) as Arc<dyn Detector>);
        let mut v = SessionView::new(&s3, &*host, TokenSettings::default());
        let out = pass_text(probed.process(text, &mut v).unwrap());
        assert!(!out.contains("other.person"));
        assert!(probe.1.load(Ordering::SeqCst) >= 1, "the probe ran");
    }

    /// Review minor 4: a failed session-dictionary build fails the request
    /// instead of silently running without the session's originals.
    #[test]
    fn a_failed_originals_build_fails_closed() {
        let host = FakeHost::new();
        let s = store().get(SessionKey([8; 32]));
        assert!(
            s.originals().unwrap().is_none(),
            "empty session, no dictionary"
        );
        SessionView::new(&s, &*host, TokenSettings::default())
            .token_for(&EntityKind::Email, EMAIL)
            .unwrap();
        s.fail_originals.store(true, Ordering::SeqCst);
        assert_eq!(s.originals().unwrap_err(), StoreError::Unavailable);
        s.fail_originals.store(false, Ordering::SeqCst);
        let d = s.originals().unwrap().expect("rebuilt on the next call");
        let hits = d
            .detect(&format!("to {EMAIL}"), &DetectCtx::for_text(EMAIL))
            .unwrap();
        assert_eq!(hits.len(), 1);
        // The closure-form session dictionary fails the same way, and the
        // next call builds it.
        s.fail_originals.store(true, Ordering::SeqCst);
        assert_eq!(s.closure_dict().unwrap_err(), StoreError::Unavailable);
        s.fail_originals.store(false, Ordering::SeqCst);
        let d = s.closure_dict().unwrap();
        assert_eq!(d.upto, s.gen_now());
        let found: usize = d
            .segments()
            .map(|g| g.dict.spans(&format!("to {EMAIL}")).unwrap().len())
            .sum();
        assert_eq!(found, 1);
        // A failure after a good build keeps nothing half-built: the next
        // call covers the new entry.
        SessionView::new(&s, &*host, TokenSettings::default())
            .token_for(&EntityKind::Person, "Qorvex Brandl")
            .unwrap();
        s.fail_originals.store(true, Ordering::SeqCst);
        assert_eq!(s.closure_dict().unwrap_err(), StoreError::Unavailable);
        s.fail_originals.store(false, Ordering::SeqCst);
        let d = s.closure_dict().unwrap();
        assert_eq!(d.upto, s.gen_now());
        assert!(
            d.segments()
                .any(|g| !g.dict.spans("an Brandl").unwrap().is_empty())
        );
    }

    /// M7: after any sequence of mints and removals, `since(g)` holds every
    /// entry and removed value at or after `g`, in clear form (a name part
    /// here), across delta builds and a merge into the middle segment
    /// (Task 6); `since(upto)` is empty.
    #[test]
    fn the_session_dictionary_covers_every_entry_since_a_gen() {
        let s = store().get(SessionKey([10; 32]));
        let mut steps: Vec<(Gen, Arc<SessionDict>, bool)> = Vec::new();
        for i in 0..300u32 {
            let before = s.gen_now();
            let removes = i % 7 == 0;
            s.with_context(|c| {
                c.token_for(&EntityKind::Person, &format!("Qorvex{i:03} Brandl{i:03}"))
                    .unwrap();
                if removes {
                    c.record_removed(&EntityKind::Iban, &format!("AT{i:03}9999"));
                }
            });
            let d = s.closure_dict().unwrap();
            assert_eq!(d.upto, s.gen_now());
            steps.push((before, d, removes));
        }
        fn hit<'a>(mut segs: impl Iterator<Item = &'a Segment>, text: &str) -> bool {
            segs.any(|g| !g.dict.spans(text).unwrap().is_empty())
        }
        for (i, (before, _, removes)) in steps.iter().enumerate() {
            for (_, dj, _) in &steps[i..] {
                assert!(
                    hit(dj.since(*before), &format!("x brandl{i:03} y")),
                    "entry {i} missing from a later dictionary"
                );
                if *removes {
                    assert!(
                        hit(dj.since(*before), &format!("konto AT{i:03}9999.")),
                        "removed value {i} missing"
                    );
                }
            }
        }
        // The delta merged into a middle segment at least once.
        assert!(
            steps.iter().any(|(_, d, _)| d.mid().is_some()),
            "no middle segment"
        );
        let d = &steps.last().unwrap().1;
        assert_eq!(d.since(d.upto).count(), 0);
        let one_back = Gen {
            entries: d.upto.entries,
            removed: d.upto.removed - 1,
        };
        assert!(d.since(one_back).count() > 0);
        // Unchanged logs: the same dictionary, no rebuild.
        assert!(Arc::ptr_eq(d, &s.closure_dict().unwrap()));
    }

    /// Task 6 (L2-07): over 3 000 session mints (removed values among
    /// them), the tiered dictionary's segments together find the clear
    /// spans a fresh `ClosureDict::build` over the context finds, across
    /// delta builds, merges into the middle segment, and base rebuilds
    /// (L2-19: texts naming values of each segment, before and after each
    /// middle-to-base transition); `since(g)` holds every entry at or after
    /// `g`.
    #[test]
    fn a_tiered_session_dict_finds_what_a_fresh_one_finds() {
        use inumaki_core::rehydrate::Rehydrator;
        let s = store().get(SessionKey([11; 32]));
        let tokens = regex::Regex::new(&Rehydrator::pattern(&TokenSettings::default())).unwrap();
        let value = |i: u32| match i % 5 {
            0..=2 => (EntityKind::Person, format!("Qorvex{i} Brandl{i}"), false),
            3 => (EntityKind::City, format!("Ortschaft{i}"), false),
            _ => (EntityKind::Iban, format!("AT{i}9999."), true),
        };
        let spans = |d: &SessionDict, c: &Context, text: &str| {
            let real = |x: &str| crate::closure::real_token(c, x);
            let mut v: Vec<(usize, usize, String)> = d
                .segments()
                .flat_map(|g| g.dict.clear_spans(&tokens, &real, text).unwrap())
                .map(|x| (x.start, x.end, x.kind.label().to_string()))
                .collect();
            v.sort();
            v.dedup();
            v
        };
        // A fresh build over the logs' prefix `upto`, and its clear spans.
        let fresh = |c: &Context, upto: Gen| {
            ClosureDict::build(
                c.entries().take(upto.entries as usize),
                c.removed_entries().take(upto.removed as usize),
            )
            .unwrap()
        };
        let want = |f: &ClosureDict, c: &Context, text: &str| {
            let real = |x: &str| crate::closure::real_token(c, x);
            let mut v: Vec<(usize, usize, String)> = f
                .clear_spans(&tokens, &real, text)
                .unwrap()
                .into_iter()
                .map(|x| (x.start, x.end, x.kind.label().to_string()))
                .collect();
            v.sort();
            v.dedup();
            v
        };
        let (mut three, mut bases, mut marks) =
            (false, std::collections::HashSet::new(), Vec::new());
        // The entry log's values in order, and the previous dictionary.
        let mut logged: Vec<String> = Vec::new();
        let mut prev: Option<Arc<SessionDict>> = None;
        let mut transitions = 0;
        for i in 0..3000u32 {
            let before = s.gen_now();
            s.with_context(|c| match value(i) {
                (k, v, true) => c.record_removed(&k, &v),
                (k, v, false) => drop(c.token_for(&k, &v).unwrap()),
            });
            if !value(i).2 {
                logged.push(value(i).1);
            }
            // A read every 50 mints (a request's worth), so the delta
            // holds values when the middle segment merges or the base is
            // rebuilt.
            if i % 50 != 49 {
                continue;
            }
            let d = s.closure_dict().unwrap();
            assert_eq!(d.upto, s.gen_now());
            three |= d.segments().count() == 3;
            bases.insert(d.base().unwrap().to.entries);
            // Across a base rebuild (the middle segment passed its limit):
            // values from the old base, middle, and delta segments and
            // from the new base, before (over the old prefix) and after.
            if let Some(p) = prev
                .as_ref()
                .filter(|p| p.mid().is_some() && p.base().unwrap().to != d.base().unwrap().to)
            {
                transitions += 1;
                // The last value of each old segment, the first value,
                // and the newest one (now all in the new base).
                let mut texts: Vec<String> = p
                    .segments()
                    .filter(|g| g.to.entries > g.from.entries)
                    .map(|g| &logged[g.to.entries as usize - 1])
                    .chain([&logged[0], logged.last().unwrap()])
                    .map(|v| format!("Gruss an {v} heute"))
                    .collect();
                texts.sort();
                texts.dedup();
                assert!((4..=5).contains(&texts.len()), "{}", texts.len());
                s.with_context(|c| {
                    let (f_old, f_new) = (fresh(c, p.upto), fresh(c, d.upto));
                    for t in &texts {
                        let old = want(&f_old, c, t);
                        let new = want(&f_new, c, t);
                        assert!(!new.is_empty(), "{i}");
                        assert_eq!(spans(p, c, t), old, "{i} before");
                        assert_eq!(spans(&d, c, t), new, "{i} after");
                    }
                });
            }
            prev = Some(Arc::clone(&d));
            if i % 500 == 499 {
                marks.push((before, i));
                let a = i / 7;
                let text = format!(
                    "Gruss an brandl{} und Qorvex{}, aus Ortschaft{}, konto AT{}9999. und Brandl{}",
                    5 * a,
                    i - 1,
                    5 * (a / 2) + 3,
                    i,
                    i + 1,
                );
                s.with_context(|c| {
                    let want = want(&fresh(c, d.upto), c, &text);
                    assert!(!want.is_empty());
                    assert_eq!(spans(&d, c, &text), want, "{i}");
                });
                // `since(g)`: every entry at or after `g`, here the one
                // minted right after each earlier mark.
                for &(g, j) in &marks {
                    let (_, v, _) = value(j);
                    let hit = d
                        .since(g)
                        .any(|seg| !seg.dict.spans(&v).unwrap().is_empty());
                    assert!(hit, "entry {j} missing from since({g:?})");
                }
            }
        }
        assert!(three, "base, middle, and delta at once");
        assert!(bases.len() >= 2, "a base rebuild: {}", bases.len());
        assert!(transitions >= 2, "{transitions} middle-to-base transitions");
    }

    /// Integrator ruling: the memo and the seeded set are bounded (oldest out).
    #[test]
    fn memo_and_seeded_are_bounded() {
        let s = store().get(SessionKey([9; 32]));
        let key = |i: usize| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_be_bytes());
            k
        };
        for i in 0..MEMO_CAP + 10 {
            s.memo_put(key(i), "p".into());
        }
        let zero = || SeedStamp {
            generation: Gen::ZERO,
            ds: Arc::from([]),
        };
        for i in 0..SEEDED_CAP + 10 {
            s.seed(key(i), zero());
        }
        assert_eq!(lock(&s.memo).len(), MEMO_CAP);
        assert_eq!(lock(&s.seeded).len(), SEEDED_CAP);
        assert!(
            s.memo_get(&key(0)).is_none() && s.seed_stamp(&key(0)).is_none(),
            "oldest evicted"
        );
        assert!(
            s.memo_get(&key(MEMO_CAP + 9)).is_some()
                && s.seed_stamp(&key(SEEDED_CAP + 9)).is_some()
        );
    }

    /// Seed stamps never gain coverage by a re-seed (min and intersection),
    /// advance only by a committed check (max and union), and a bump of an
    /// absent (evicted) digest stays a no-op. `Debug` prints counts.
    #[test]
    fn a_seed_stamp_never_gains_coverage_from_a_reseed() {
        let s = store().get(SessionKey([10; 32]));
        let g = |entries, removed| Gen { entries, removed };
        let st = |generation: Gen, ds: &[u64]| SeedStamp {
            generation,
            ds: Arc::from(ds),
        };
        let d = [1u8; 32];
        s.seed(d, st(g(5, 1), &[1, 2, 3]));
        s.seed(d, st(g(3, 4), &[2, 3, 4]));
        let now = s.seed_stamp(&d).unwrap();
        assert_eq!(now.generation, g(3, 1), "component-wise min");
        assert_eq!(&*now.ds, &[2, 3], "intersection");
        let read = s.seed_stamp(&d).unwrap();
        s.seed_bump(&d, &read, g(4, 0), &Arc::from([1u64, 9]));
        let now = s.seed_stamp(&d).unwrap();
        assert_eq!(now.generation, g(4, 1), "component-wise max");
        assert_eq!(&*now.ds, &[1, 2, 3, 9], "union");
        s.seed_bump(&[2u8; 32], &read, g(9, 9), &Arc::from([7u64]));
        assert!(s.seed_stamp(&[2u8; 32]).is_none(), "absent stays absent");
        let dbg = format!("{now:?}");
        assert!(dbg.contains("ds: 4") && !dbg.contains('9'), "{dbg}");
    }

    /// Review 4b Important 1 (TOCTOU): a request read seed stamp S0 at
    /// step 2 and checked the leaf only against what S0 left uncovered; a
    /// concurrent answer re-seeds the same text with a lower S1 before that
    /// request commits. Its bump must not raise S1: the leaf was never
    /// checked against what S0 covered and S1 does not.
    #[test]
    fn a_seed_bump_never_overrides_a_concurrent_lowering_reseed() {
        let s = store().get(SessionKey([11; 32]));
        let g = |entries, removed| Gen { entries, removed };
        let st = |generation: Gen, ds: &[u64]| SeedStamp {
            generation,
            ds: Arc::from(ds),
        };
        let d = [3u8; 32];
        s.seed(d, st(g(5, 2), &[1, 2]));
        let read = s.seed_stamp(&d).unwrap();
        s.seed(d, st(g(2, 1), &[2]));
        s.seed_bump(&d, &read, g(8, 3), &Arc::from([1u64, 2, 4]));
        let now = s.seed_stamp(&d).unwrap();
        assert_eq!(now.generation, g(2, 1), "S1 unchanged");
        assert_eq!(&*now.ds, &[2], "S1 unchanged");
        // A bump read at the current stamp still applies.
        s.seed_bump(&d, &now, g(8, 3), &Arc::from([1u64, 2, 4]));
        let after = s.seed_stamp(&d).unwrap();
        assert_eq!(after.generation, g(8, 3));
        assert_eq!(&*after.ds, &[1, 2, 4]);
    }

    #[test]
    fn a_host_failure_is_a_store_error_and_a_fault() {
        let host = FakeHost::new();
        *host.fail_vault.lock().unwrap() = true;
        let s = store().get(SessionKey([4; 32]));
        let mut v = SessionView::new(&s, &*host, TokenSettings::default());
        assert_eq!(
            v.token_for(&EntityKind::Person, NAME),
            Err(StoreError::Unavailable)
        );
        assert_eq!(v.fault(), Some(HostError::VaultUnavailable));
        let mut v2 = SessionView::new(&s, &*host, TokenSettings::default());
        assert_eq!(
            v2.prepare(&[DS_TOKEN.to_string()]),
            Err(StoreError::Unavailable)
        );
        assert_eq!(v2.fault(), Some(HostError::VaultUnavailable));
        s.with_context(|c| assert!(c.is_empty(), "nothing minted on a failure"));
    }

    #[test]
    fn debug_carries_counts_only() {
        let host = FakeHost::new();
        let st = store();
        let s = st.get(SessionKey([6; 32]));
        let mut v = SessionView::new(&s, &*host, TokenSettings::default());
        let e = v.token_for(&EntityKind::Email, EMAIL).unwrap();
        v.token_for(&EntityKind::Person, NAME).unwrap();
        let p = v.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        v.record_removed(&EntityKind::Iban, "AT0079999").unwrap();
        let d = s.closure_dict().unwrap();
        assert!(d.patterns() > 0);
        let all = format!("{v:?} {s:?} {st:?} {d:?}");
        for needle in [
            EMAIL,
            NAME,
            DS_TOKEN,
            e.as_str(),
            p.as_str(),
            "Qorvex",
            "Brandl",
            "AT0079999",
        ] {
            assert!(!all.contains(needle), "{needle} in {all}");
        }
    }
}
