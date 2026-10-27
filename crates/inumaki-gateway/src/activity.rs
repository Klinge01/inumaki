//! Writes activity records, and the released payloads behind them (the
//! egress journal, M4 spec §16.3, §16.4), off the request path. A bounded
//! queue feeds one writer thread, which drains what is queued into one
//! vault transaction and then seals each released payload into the
//! journal under its record's id, through a [`JournalWriter`] with its own
//! SQLite connection. A full queue drops the record and counts it, so a
//! slow disk never stalls a tool call. Journal bytes in flight are bounded
//! separately ([`JOURNAL_INFLIGHT_MAX`]): a payload that does not fit is
//! dropped and counted while its record is still written. On shutdown the
//! gateway waits a bounded time for the queue to drain; what is still
//! queued then is counted as dropped.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::Duration;

use inumaki_vault::{Direction, JournalWriter, NewActivity, OpaqueId, Vault, VaultError};

const QUEUE: usize = 1024;

/// Most records one vault transaction takes.
const BATCH: usize = 256;

/// Journal payload bytes allowed in the queue at once.
pub const JOURNAL_INFLIGHT_MAX: usize = 64 * 1024 * 1024;

/// Where a gateway event happened.
#[derive(Debug, Clone)]
pub struct Hop {
    /// Opaque upstream label, when routing got that far.
    pub upstream: Option<OpaqueId>,
    /// Direction.
    pub direction: Direction,
}

/// What the queue carries: a record, or a released record with the bytes
/// that left (journaled under the record's id once it is written).
enum Item {
    Record(NewActivity),
    Released {
        dataset: String,
        record: NewActivity,
        payload: Vec<u8>,
    },
}

/// Counters and settings shared by every handle and the writer.
#[derive(Default)]
struct Shared {
    /// Lost to a full queue, a failed write, or shutdown.
    dropped: AtomicU64,
    /// Journal entries lost to the in-flight cap, a refused or failed
    /// write, or a dropped record.
    journal_dropped: AtomicU64,
    /// Accepted by the queue, not yet written or counted as dropped.
    pending: AtomicU64,
    /// Journal payload bytes queued and not yet written or dropped.
    inflight: AtomicUsize,
    /// Set when a shutdown flush gave up: the writer discards (and counts)
    /// what is left, and new records are counted as dropped.
    closed: AtomicBool,
    /// Cap on `inflight`.
    cap: usize,
    /// Released payloads are journaled at all.
    journal: bool,
}

/// Handle to the writer. Cheap to clone.
#[derive(Clone)]
pub struct ActivitySink {
    tx: Option<SyncSender<Item>>,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for ActivitySink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivitySink")
            .field("enabled", &self.tx.is_some())
            .field("journal", &self.shared.journal)
            .field("dropped", &self.dropped())
            .field("journal_dropped", &self.journal_dropped())
            .field("inflight_bytes", &self.inflight_bytes())
            .finish()
    }
}

/// A fixed, coarse reason for a journal write that failed.
fn journal_failure(e: &VaultError) -> &'static str {
    match e {
        VaultError::JournalRecord(_) => "digest mismatch",
        VaultError::DatasetNotFound(_) => "dataset gone",
        _ => "storage",
    }
}

/// Seal one released payload under its written record. `false` when it
/// was not stored (the caller counts it).
fn journal_one(
    writer: Option<&JournalWriter>,
    dataset: &str,
    rec: &inumaki_vault::ActivityRecord,
    payload: &[u8],
) -> bool {
    let (Some(w), Some(digest)) = (writer, rec.released.as_ref()) else {
        return false;
    };
    match w.append(dataset, &rec.id, rec.at, digest, payload) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                reason = journal_failure(&e),
                bytes = payload.len(),
                "journal entry not written"
            );
            false
        }
    }
}

/// The writer thread: block for one item, take whatever else is queued
/// (up to [`BATCH`]), write the records in one transaction, then journal
/// the released payloads under the ids the records got.
fn write_loop(vault: Vault, rx: Receiver<Item>, shared: Arc<Shared>) {
    // Payloads go through the writer's own connection, so a large INSERT
    // never holds the shared connection the request path takes. Without
    // one the journal is off and every payload counts as dropped; records
    // are still written.
    let writer = if shared.journal {
        match vault.journal_writer() {
            Ok(w) => Some(w),
            Err(e) => {
                tracing::warn!(
                    reason = journal_failure(&e),
                    "journal writer unavailable; payloads are counted as dropped"
                );
                None
            }
        }
    } else {
        None
    };
    while let Ok(first) = rx.recv() {
        let mut batch = vec![first];
        while batch.len() < BATCH {
            match rx.try_recv() {
                Ok(r) => batch.push(r),
                Err(_) => break,
            }
        }
        let n = batch.len() as u64;
        let mut recs = Vec::with_capacity(batch.len());
        let mut payloads: Vec<(usize, String, Vec<u8>)> = Vec::new();
        for item in batch {
            match item {
                Item::Record(r) => recs.push(r),
                Item::Released {
                    dataset,
                    record,
                    payload,
                } => {
                    payloads.push((recs.len(), dataset, payload));
                    recs.push(record);
                }
            }
        }
        let journal_lost = if shared.closed.load(Ordering::Acquire) {
            shared.dropped.fetch_add(n, Ordering::Relaxed);
            payloads.len() as u64
        } else {
            match vault.append_activities(recs) {
                Ok(written) => payloads
                    .iter()
                    .filter(|(i, dataset, payload)| {
                        !written
                            .get(*i)
                            .is_some_and(|r| journal_one(writer.as_ref(), dataset, r, payload))
                    })
                    .count() as u64,
                Err(e) => {
                    shared.dropped.fetch_add(n, Ordering::Relaxed);
                    tracing::warn!(error = %e, records = n, "activity records not written");
                    payloads.len() as u64
                }
            }
        };
        shared
            .journal_dropped
            .fetch_add(journal_lost, Ordering::Relaxed);
        let bytes: usize = payloads.iter().map(|(_, _, p)| p.len()).sum();
        shared.inflight.fetch_sub(bytes, Ordering::AcqRel);
        shared.pending.fetch_sub(n, Ordering::AcqRel);
    }
}

impl ActivitySink {
    /// Start the writer thread; `journal` false writes records only. The
    /// thread exits when the last sink is dropped.
    pub fn spawn(vault: Vault, journal: bool) -> ActivitySink {
        Self::spawn_with_cap(vault, journal, JOURNAL_INFLIGHT_MAX)
    }

    /// [`ActivitySink::spawn`] with a custom in-flight byte cap (tests).
    pub fn spawn_with_cap(vault: Vault, journal: bool, cap: usize) -> ActivitySink {
        let (tx, rx) = sync_channel::<Item>(QUEUE);
        let shared = Arc::new(Shared {
            cap,
            journal,
            ..Shared::default()
        });
        let writer = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("inumaki-activity".into())
            .spawn(move || write_loop(vault, rx, writer))
            .map(|_| ActivitySink {
                tx: Some(tx),
                shared: Arc::clone(&shared),
            })
            .unwrap_or_else(|_| {
                tracing::warn!(
                    "activity writer thread could not start; records are counted as dropped"
                );
                ActivitySink { tx: None, shared }
            })
    }

    /// A sink that records nothing (unit tests of the handler).
    pub fn disabled() -> ActivitySink {
        ActivitySink {
            tx: None,
            shared: Arc::new(Shared::default()),
        }
    }

    /// Queue an item; never blocks. `journal_bytes` is `Some` for a
    /// released payload already counted in `inflight`: when the item is
    /// refused, the payload is counted as dropped and its bytes released.
    fn send(&self, item: Item, journal_bytes: Option<usize>) {
        let s = &self.shared;
        let refuse = || {
            s.dropped.fetch_add(1, Ordering::Relaxed);
            if let Some(n) = journal_bytes {
                s.journal_dropped.fetch_add(1, Ordering::Relaxed);
                s.inflight.fetch_sub(n, Ordering::AcqRel);
            }
        };
        let Some(tx) = &self.tx else {
            return refuse();
        };
        if s.closed.load(Ordering::Acquire) {
            return refuse();
        }
        // Counted before the send so the writer never sees it negative.
        s.pending.fetch_add(1, Ordering::AcqRel);
        match tx.try_send(item) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                s.pending.fetch_sub(1, Ordering::AcqRel);
                refuse();
            }
        }
    }

    /// Queue a record; never blocks.
    pub fn emit(&self, rec: NewActivity) {
        self.send(Item::Record(rec), None);
    }

    /// Queue a released record with the bytes that left; the journal entry
    /// is written under the record's id and checked against its digest.
    /// With the journal disabled only the record is queued (not a drop).
    /// When `payload` would push the bytes in flight over the cap, only
    /// the record is queued and the payload is counted as dropped. Never
    /// blocks.
    pub fn emit_released(&self, dataset: &str, rec: NewActivity, payload: Vec<u8>) {
        let s = &self.shared;
        if !s.journal {
            return self.emit(rec);
        }
        let n = payload.len();
        let before = s.inflight.fetch_add(n, Ordering::AcqRel);
        if before.saturating_add(n) > s.cap {
            s.inflight.fetch_sub(n, Ordering::AcqRel);
            s.journal_dropped.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(bytes = n, "journal payload dropped: writer behind");
            return self.emit(rec);
        }
        self.send(
            Item::Released {
                dataset: dataset.to_string(),
                record: rec,
                payload,
            },
            Some(n),
        );
    }

    /// Wait up to `within` for every queued record to be written. If the
    /// queue has not drained by then, the sink closes: the writer discards
    /// what is left and counts it as dropped, as it does for anything
    /// emitted later. Returns how many were still queued (0 when drained).
    pub async fn flush(&self, within: Duration) -> u64 {
        if self.shared.closed.load(Ordering::Acquire) {
            // Gave up before; the writer counts what is left.
            return self.shared.pending.load(Ordering::Acquire);
        }
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = self.shared.pending.load(Ordering::Acquire);
            if left == 0 {
                return 0;
            }
            if tokio::time::Instant::now() >= deadline {
                self.shared.closed.store(true, Ordering::Release);
                tracing::warn!(
                    records = left,
                    "activity records still queued at shutdown; counted as dropped"
                );
                return left;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Records lost to a full queue, a failed write, or shutdown.
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    /// Journal entries lost to the in-flight cap, a refused or failed
    /// write, or a dropped record.
    pub fn journal_dropped(&self) -> u64 {
        self.shared.journal_dropped.load(Ordering::Relaxed)
    }

    /// Journal payload bytes queued and not yet written (tests poll it).
    pub fn inflight_bytes(&self) -> usize {
        self.shared.inflight.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use inumaki_core::span::EntityKind;
    use inumaki_vault::{
        ActivityFilter, DatasetSpec, FrontDoor, KeySource, KindCount, KindLabel, Vault,
        VaultOptions, Verdict,
    };

    use super::*;

    fn rec(v: &Vault) -> NewActivity {
        NewActivity {
            dataset: v.opaque_ref("crm"),
            front_door: FrontDoor::Gateway,
            upstream: None,
            direction: Direction::Result,
            verdict: Verdict::Released,
            checks: Vec::new(),
            kinds: Vec::new(),
            tripwire: false,
            bytes: 0,
            released: None,
        }
    }

    #[test]
    fn a_disabled_sink_counts_every_record_as_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let v =
            Vault::open(VaultOptions::in_dir(dir.path()).with_key_source(KeySource::File)).unwrap();
        let s = ActivitySink::disabled();
        s.emit(rec(&v));
        s.clone().emit(rec(&v));
        assert_eq!(s.dropped(), 2);
        assert_eq!(
            format!("{s:?}"),
            "ActivitySink { enabled: false, journal: false, dropped: 2, journal_dropped: 0, inflight_bytes: 0 }"
        );
    }

    /// A burst far over the queue bound never blocks the caller; every
    /// record is either written or counted as dropped.
    #[test]
    fn a_burst_never_blocks_and_every_record_is_accounted_for() {
        let dir = tempfile::tempdir().unwrap();
        let v =
            Vault::open(VaultOptions::in_dir(dir.path()).with_key_source(KeySource::File)).unwrap();
        v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
            .unwrap();
        let s = ActivitySink::spawn(v.clone(), true);
        let n = 4 * QUEUE as u64;
        let t0 = Instant::now();
        for _ in 0..n {
            s.emit(rec(&v));
        }
        let emitting = t0.elapsed();
        let all = ActivityFilter {
            dataset: None,
            since: None,
            limit: 10_000,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let written = v.activity(&all).unwrap().len() as u64;
            if written + s.dropped() == n {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{written} written, {} dropped",
                s.dropped()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            emitting < Duration::from_secs(1),
            "emit blocked: {emitting:?}"
        );
        assert_eq!(v.verify_activity_chain().unwrap() as u64 + s.dropped(), n);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flush_waits_for_the_queue_to_drain() {
        let dir = tempfile::tempdir().unwrap();
        let v =
            Vault::open(VaultOptions::in_dir(dir.path()).with_key_source(KeySource::File)).unwrap();
        let s = ActivitySink::spawn(v.clone(), true);
        for _ in 0..300 {
            s.emit(rec(&v));
        }
        assert_eq!(s.flush(Duration::from_secs(10)).await, 0);
        let all = ActivityFilter {
            dataset: None,
            since: None,
            limit: 1_000,
        };
        assert_eq!(v.activity(&all).unwrap().len() as u64 + s.dropped(), 300);
        assert_eq!(s.dropped(), 0, "300 fit the queue");
    }

    /// A writer stuck on the database: the flush gives up after its bound,
    /// and everything not written, queued before or emitted after, is
    /// counted as dropped (review M3).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_flush_that_times_out_counts_what_was_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let v =
            Vault::open(VaultOptions::in_dir(dir.path()).with_key_source(KeySource::File)).unwrap();
        let s = ActivitySink::spawn(v.clone(), true);
        let blocker = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        for _ in 0..10 {
            s.emit(rec(&v));
        }
        let left = s.flush(Duration::from_millis(100)).await;
        assert!(
            left > 0,
            "the writer is stuck behind the lock: dropped {}",
            s.dropped()
        );
        s.emit(rec(&v));
        assert!(s.dropped() >= 1, "a record after the flush is dropped");
        blocker.execute_batch("COMMIT").unwrap();
        let all = ActivityFilter {
            dataset: None,
            since: None,
            limit: 1_000,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let written = v.activity(&all).unwrap().len() as u64;
            if written + s.dropped() == 11 && s.shared.pending.load(Ordering::Acquire) == 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{written} written, {} dropped",
                s.dropped()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn journal_vault(dir: &std::path::Path) -> Vault {
        let v = Vault::open(VaultOptions::in_dir(dir).with_key_source(KeySource::File)).unwrap();
        v.create_dataset(&DatasetSpec::new("crm", "C", "offline"))
            .unwrap();
        v
    }

    fn released(v: &Vault, payload: &[u8]) -> NewActivity {
        NewActivity {
            kinds: vec![KindCount {
                kind: KindLabel::of(&EntityKind::Person),
                count: 1,
            }],
            bytes: payload.len() as u64,
            released: Some(v.released_digest(payload)),
            ..rec(v)
        }
    }

    /// Wait until `records` activity rows exist and no journal bytes are in
    /// flight (the writer has finished the payloads behind them).
    fn wait_for(v: &Vault, sink: &ActivitySink, records: usize) {
        let all = ActivityFilter {
            dataset: None,
            since: None,
            limit: 100,
        };
        let t0 = Instant::now();
        loop {
            let n = v.activity(&all).unwrap().len();
            if n >= records && sink.inflight_bytes() == 0 {
                return;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "writer did not catch up"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Review Focus 5.
    #[test]
    fn oversized_payload_keeps_the_record_and_counts_the_drop() {
        let dir = tempfile::tempdir().unwrap();
        let v = journal_vault(dir.path());
        let sink = ActivitySink::spawn_with_cap(v.clone(), true, 100);
        let small = b"{\"ok\":1}".to_vec();
        let big = vec![b'x'; 101];
        sink.emit_released("crm", released(&v, &small), small.clone());
        sink.emit_released("crm", released(&v, &big), big);
        wait_for(&v, &sink, 2);
        assert_eq!(
            v.activity(&ActivityFilter::default()).unwrap().len(),
            2,
            "both records written"
        );
        let entries = v.journal("crm", None, 10).unwrap();
        assert_eq!(entries.len(), 1, "only the payload that fit was journaled");
        assert_eq!(entries[0].bytes, small.len() as u64);
        let (_, stored) = v.journal_payload("crm", &entries[0].id).unwrap().unwrap();
        assert_eq!(stored.as_slice(), small.as_slice(), "the bytes as released");
        assert_eq!((sink.dropped(), sink.journal_dropped()), (0, 1));
        // The cap is bytes in flight, not a size limit: after the writer
        // drained, a payload of nearly the cap fits.
        let again = vec![b'y'; 90];
        sink.emit_released("crm", released(&v, &again), again);
        wait_for(&v, &sink, 3);
        assert_eq!(v.journal("crm", None, 10).unwrap().len(), 2);
        assert!(!format!("{sink:?}").contains('x'), "{sink:?}");
    }

    /// Review Focus 5: a disabled journal is not a drop; a disabled sink
    /// counts every record as dropped.
    #[test]
    fn disabled_journal_keeps_activity_records() {
        let dir = tempfile::tempdir().unwrap();
        let v = journal_vault(dir.path());
        let sink = ActivitySink::spawn(v.clone(), false);
        let p = b"{\"ok\":1}".to_vec();
        sink.emit_released("crm", released(&v, &p), p);
        wait_for(&v, &sink, 1);
        assert!(v.journal("crm", None, 10).unwrap().is_empty());
        assert_eq!(
            (sink.dropped(), sink.journal_dropped()),
            (0, 0),
            "disabled is not a drop"
        );
        let off = ActivitySink::disabled();
        off.emit_released("crm", released(&v, b"x"), b"x".to_vec());
        assert_eq!(
            off.dropped(),
            1,
            "a sink that writes nothing counts every record as dropped"
        );
    }

    /// Fail closed: a payload that does not match its record's digest, or
    /// whose dataset is gone, is counted, never stored; the record stays.
    #[test]
    fn a_digest_mismatch_or_missing_dataset_is_counted_not_stored() {
        let dir = tempfile::tempdir().unwrap();
        let v = journal_vault(dir.path());
        let sink = ActivitySink::spawn(v.clone(), true);
        let mut rec = released(&v, b"{\"ok\":1}");
        rec.released = Some(v.released_digest(b"other"));
        sink.emit_released("crm", rec, b"{\"ok\":1}".to_vec());
        let mut gone = released(&v, b"{}");
        gone.dataset = v.opaque_ref("nope");
        sink.emit_released("nope", gone, b"{}".to_vec());
        wait_for(&v, &sink, 2);
        assert!(v.journal("crm", None, 10).unwrap().is_empty());
        assert_eq!(sink.journal_dropped(), 2);
        assert_eq!(
            sink.dropped(),
            0,
            "records are written even when their payload is refused"
        );
    }

    /// A shutdown flush that gives up counts the released items it
    /// discards in both counters and releases their in-flight bytes, so
    /// the cap is never leaked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_closed_sink_counts_journal_drops_and_releases_inflight_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let v = journal_vault(dir.path());
        let s = ActivitySink::spawn(v.clone(), true);
        let blocker = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let p = b"{\"ok\":1}".to_vec();
        for _ in 0..10 {
            s.emit_released("crm", released(&v, &p), p.clone());
        }
        assert!(s.flush(Duration::from_millis(100)).await > 0);
        s.emit_released("crm", released(&v, &p), p.clone());
        blocker.execute_batch("COMMIT").unwrap();
        let all = ActivityFilter {
            dataset: None,
            since: None,
            limit: 1_000,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let written = v.activity(&all).unwrap().len() as u64;
            if written + s.dropped() == 11 && s.shared.pending.load(Ordering::Acquire) == 0 {
                let journaled = v.journal("crm", None, 100).unwrap().len() as u64;
                assert_eq!(journaled + s.journal_dropped(), 11, "{s:?}");
                assert!(s.journal_dropped() >= 1);
                assert_eq!(s.inflight_bytes(), 0);
                break;
            }
            assert!(Instant::now() < deadline, "{written} written, {s:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
