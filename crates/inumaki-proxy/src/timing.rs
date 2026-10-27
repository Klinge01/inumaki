//! Per-request timing (M8 spec §20, amendment 2026-10-12, Part 2): the
//! sample a request takes, the ring of the last 64, and the `timing` and
//! `static_cache` objects of `GET /v1/proxy`.
//!
//! Content-free by construction: durations, counts, one timestamp, and
//! flags. Nothing here names a route, a dataset, a session, or a text.

use std::cell::Cell;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::memo::MemoStats;

/// Samples the ring keeps (the most recent).
pub const TIMING_WINDOW: usize = 64;

/// Whole milliseconds, saturating.
pub fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// What the pipeline's stages cost one request, filled by
/// `sanitize_request` (also when it fails). `Cell`s so that a guard can add
/// a stage's time on every exit, `?` included.
///
/// - `engine`: the engine fetch and every step 6 engine call;
/// - `closure`: the whole of step 6b;
/// - `project`: the projections inside step 6b (a part of `closure`).
#[derive(Debug, Default)]
pub(crate) struct StageTimes {
    pub engine: Cell<Duration>,
    pub closure: Cell<Duration>,
    pub project: Cell<Duration>,
}

/// Adds the time since its creation to a stage when dropped.
pub(crate) struct StageGuard<'a> {
    slot: &'a Cell<Duration>,
    start: Instant,
}

impl<'a> StageGuard<'a> {
    /// Start timing into `slot`.
    pub(crate) fn start(slot: &'a Cell<Duration>) -> StageGuard<'a> {
        StageGuard {
            slot,
            start: Instant::now(),
        }
    }
}

impl Drop for StageGuard<'_> {
    fn drop(&mut self) {
        self.slot
            .set(self.slot.get().saturating_add(self.start.elapsed()));
    }
}

/// Run `f`, adding its time to `slot` whatever it returns.
pub(crate) fn timed<T>(slot: &Cell<Duration>, f: impl FnOnce() -> T) -> T {
    let _g = StageGuard::start(slot);
    f()
}

/// One request's time, by stage (the fields of the M8 amendment's table).
/// `first_byte` and `provider` are `None` when no upstream answer arrived.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestTiming {
    /// From arrival to the end of the response.
    pub total: Duration,
    /// Reading and decoding the body.
    pub read: Duration,
    /// `spawn_blocking` to the start of the sanitize task.
    pub queue: Duration,
    /// The sanitize task minus `engine` and `closure`.
    pub scan: Duration,
    /// Step 6's engine calls, the engine fetch included.
    pub engine: Duration,
    /// Step 6b, `project` included.
    pub closure: Duration,
    /// The projections inside step 6b.
    pub project: Duration,
    /// From the start of `send` to the response headers.
    pub first_byte: Option<Duration>,
    /// From the start of `send` to the upstream's last byte, minus the
    /// stream driver's own time and the time it waited on the client.
    pub provider: Option<Duration>,
    /// Answer-side local work.
    pub restore: Duration,
}

impl RequestTiming {
    /// `read + queue + scan + engine + closure + restore`.
    pub fn local(&self) -> Duration {
        [
            self.read,
            self.queue,
            self.scan,
            self.engine,
            self.closure,
            self.restore,
        ]
        .into_iter()
        .fold(Duration::ZERO, Duration::saturating_add)
    }
}

/// A sample in whole milliseconds, in the contract's field order
/// (`ProxyTiming`, M6 spec §9.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TimingMs {
    /// `total_ms`.
    pub total_ms: u64,
    /// `local_ms`.
    pub local_ms: u64,
    /// `provider_ms`; `null` when not forwarded.
    pub provider_ms: Option<u64>,
    /// `first_byte_ms`; `null` when not forwarded.
    pub first_byte_ms: Option<u64>,
    /// `read_ms`.
    pub read_ms: u64,
    /// `queue_ms`.
    pub queue_ms: u64,
    /// `scan_ms`.
    pub scan_ms: u64,
    /// `engine_ms`.
    pub engine_ms: u64,
    /// `closure_ms`.
    pub closure_ms: u64,
    /// `project_ms`.
    pub project_ms: u64,
    /// `restore_ms`.
    pub restore_ms: u64,
}

impl From<&RequestTiming> for TimingMs {
    fn from(t: &RequestTiming) -> TimingMs {
        TimingMs {
            total_ms: millis(t.total),
            local_ms: millis(t.local()),
            provider_ms: t.provider.map(millis),
            first_byte_ms: t.first_byte.map(millis),
            read_ms: millis(t.read),
            queue_ms: millis(t.queue),
            scan_ms: millis(t.scan),
            engine_ms: millis(t.engine),
            closure_ms: millis(t.closure),
            project_ms: millis(t.project),
            restore_ms: millis(t.restore),
        }
    }
}

/// The `timing` object of `GET /v1/proxy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimingBody {
    /// Samples held, at most [`TIMING_WINDOW`].
    pub window: u64,
    /// Unix seconds of the latest sample.
    pub last_at: Option<i64>,
    /// The latest sample.
    pub last: Option<TimingMs>,
    /// Each field's nearest-rank median over the samples where it is set.
    pub p50: Option<TimingMs>,
    /// Each field's nearest-rank 95th percentile, likewise.
    pub p95: Option<TimingMs>,
}

/// The nearest-rank percentile `p` (1 to 100) of `vals`: the value at
/// 1-based rank `ceil(p * n / 100)` of the sorted values; `None` when empty.
fn percentile(mut vals: Vec<u64>, p: usize) -> Option<u64> {
    if vals.is_empty() {
        return None;
    }
    vals.sort_unstable();
    let rank = (p * vals.len()).div_ceil(100).clamp(1, vals.len());
    Some(vals[rank - 1])
}

/// The last [`TIMING_WINDOW`] samples.
#[derive(Debug, Default)]
pub struct TimingRing {
    samples: VecDeque<TimingMs>,
    last_at: Option<i64>,
}

impl TimingRing {
    /// Keep `t`, taken at unix second `at`; the oldest sample goes when the
    /// window is full.
    pub fn push(&mut self, t: &RequestTiming, at: i64) {
        if self.samples.len() == TIMING_WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back(TimingMs::from(t));
        self.last_at = Some(at);
    }

    /// Samples held.
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether no sample is held.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The contract's `timing` object. Percentiles are computed here, when
    /// status is read, not when a sample is taken.
    pub fn body(&self) -> TimingBody {
        let pct = |p: usize| -> Option<TimingMs> {
            if self.samples.is_empty() {
                return None;
            }
            macro_rules! field {
                ($f:ident) => {
                    percentile(self.samples.iter().map(|s| s.$f).collect(), p).unwrap_or(0)
                };
            }
            macro_rules! opt_field {
                ($f:ident) => {
                    percentile(self.samples.iter().filter_map(|s| s.$f).collect(), p)
                };
            }
            Some(TimingMs {
                total_ms: field!(total_ms),
                local_ms: field!(local_ms),
                provider_ms: opt_field!(provider_ms),
                first_byte_ms: opt_field!(first_byte_ms),
                read_ms: field!(read_ms),
                queue_ms: field!(queue_ms),
                scan_ms: field!(scan_ms),
                engine_ms: field!(engine_ms),
                closure_ms: field!(closure_ms),
                project_ms: field!(project_ms),
                restore_ms: field!(restore_ms),
            })
        };
        TimingBody {
            window: self.samples.len() as u64,
            last_at: self.last_at,
            last: self.samples.back().copied(),
            p50: pct(50),
            p95: pct(95),
        }
    }
}

/// The `static_cache` object of `GET /v1/proxy` (the memo's counters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StaticCacheBody {
    /// The effective state: `[proxy] static_cache` is on and the host
    /// provides a memo.
    pub enabled: bool,
    /// Eligible NER calls answered from the memo.
    pub hits: u64,
    /// Eligible NER calls that ran the model.
    pub misses: u64,
    /// Entries held.
    pub entries: u64,
    /// Clears caused by a change of the datasets the proxy sees.
    pub clears: u64,
}

impl StaticCacheBody {
    /// From the configuration flag and the host's memo (`None`: no memo).
    pub fn new(configured: bool, memo: Option<MemoStats>) -> StaticCacheBody {
        let s = memo.unwrap_or_default();
        StaticCacheBody {
            enabled: configured && memo.is_some(),
            hits: s.hits,
            misses: s.misses,
            entries: s.entries,
            clears: s.clears,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// A sample whose total is `n` and whose provider is `p`.
    fn sample(n: u64, p: Option<u64>) -> RequestTiming {
        RequestTiming {
            total: ms(n),
            read: ms(1),
            queue: ms(2),
            scan: ms(3),
            engine: ms(4),
            closure: ms(5),
            project: ms(1),
            first_byte: p.map(|p| ms(p / 2)),
            provider: p.map(ms),
            restore: ms(6),
        }
    }

    #[test]
    fn local_sums_the_six_local_stages_and_not_project() {
        // 1 + 2 + 3 + 4 + 5 + 6; `project` is inside `closure`.
        assert_eq!(sample(100, None).local(), ms(21));
        assert_eq!(TimingMs::from(&sample(100, Some(40))).local_ms, 21);
    }

    #[test]
    fn the_window_keeps_the_most_recent_64() {
        let mut r = TimingRing::default();
        for n in 0..100u64 {
            r.push(&sample(n, None), 1_000 + n as i64);
        }
        assert_eq!(r.len(), TIMING_WINDOW);
        let b = r.body();
        assert_eq!(b.window, 64);
        assert_eq!(b.last_at, Some(1_099));
        assert_eq!(b.last.unwrap().total_ms, 99);
        // Samples 36..=99 remain: the median is the 32nd of them.
        assert_eq!(b.p50.unwrap().total_ms, 36 + 31);
    }

    #[test]
    fn percentiles_are_nearest_rank_and_skip_null_fields() {
        let mut r = TimingRing::default();
        // Totals 1..=20 in a scrambled order; provider set on every other
        // sample (10, 20, 30, 40, 50 over five samples).
        let order = [
            7, 3, 15, 1, 20, 12, 9, 18, 5, 11, 2, 16, 8, 19, 4, 14, 6, 17, 10, 13,
        ];
        for (i, n) in order.iter().enumerate() {
            let p = (i % 4 == 0).then(|| (i as u64 / 4 + 1) * 10);
            r.push(&sample(*n, p), 5);
        }
        let b = r.body();
        assert_eq!(b.window, 20);
        // ceil(0.50 * 20) = rank 10; ceil(0.95 * 20) = rank 19.
        assert_eq!(b.p50.unwrap().total_ms, 10);
        assert_eq!(b.p95.unwrap().total_ms, 19);
        // Provider over its five set values: ranks 3 and 5.
        assert_eq!(b.p50.unwrap().provider_ms, Some(30));
        assert_eq!(b.p95.unwrap().provider_ms, Some(50));
        assert_eq!(b.p50.unwrap().first_byte_ms, Some(15));
        // The latest sample has no provider (index 19, 19 % 4 != 0).
        assert_eq!(b.last.unwrap().provider_ms, None);
    }

    #[test]
    fn a_field_null_in_every_sample_is_null_and_one_sample_is_its_own_percentile() {
        let mut r = TimingRing::default();
        assert_eq!(
            r.body(),
            TimingBody {
                window: 0,
                last_at: None,
                last: None,
                p50: None,
                p95: None
            }
        );
        r.push(&sample(42, None), 9);
        let b = r.body();
        assert_eq!(b.p50.unwrap().total_ms, 42);
        assert_eq!(b.p95.unwrap().total_ms, 42);
        assert_eq!(b.p50.unwrap().provider_ms, None);
        assert_eq!(b.p95.unwrap().first_byte_ms, None);
    }

    /// A value is a number, `null`, or a bool, at every depth (P8).
    fn assert_scalars(v: &serde_json::Value, path: &str) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    assert_scalars(v, &format!("{path}.{k}"));
                }
            }
            serde_json::Value::Number(_) | serde_json::Value::Null | serde_json::Value::Bool(_) => {
            }
            other => panic!("{path} is {other}, not a number, null, or bool"),
        }
    }

    fn keys(v: &serde_json::Value) -> Vec<&str> {
        v.as_object().unwrap().keys().map(String::as_str).collect()
    }

    /// The M6 §9.6 amendment's key set, recursively, in its serialized order.
    #[test]
    fn the_timing_and_static_cache_objects_have_exactly_the_contract_keys() {
        const SAMPLE_KEYS: [&str; 11] = [
            "total_ms",
            "local_ms",
            "provider_ms",
            "first_byte_ms",
            "read_ms",
            "queue_ms",
            "scan_ms",
            "engine_ms",
            "closure_ms",
            "project_ms",
            "restore_ms",
        ];
        let mut r = TimingRing::default();
        r.push(&sample(10, Some(4)), 5);
        r.push(&sample(20, None), 6);
        for body in [r.body(), TimingRing::default().body()] {
            let v = serde_json::to_value(&body).unwrap();
            // `serde_json` keeps insertion order only with a feature, so
            // the order is checked on the text.
            let text = serde_json::to_string(&body).unwrap();
            let mut at = 0;
            for k in ["window", "last_at", "last", "p50", "p95"] {
                let i = text[at..].find(&format!("\"{k}\":")).expect(k);
                at += i;
            }
            let mut got = keys(&v);
            got.sort_unstable();
            assert_eq!(got, ["last", "last_at", "p50", "p95", "window"]);
            assert_scalars(&v, "timing");
            for k in ["last", "p50", "p95"] {
                if v[k].is_null() {
                    assert_eq!(body.window, 0);
                    continue;
                }
                let mut got = keys(&v[k]);
                got.sort_unstable();
                let mut want = SAMPLE_KEYS.to_vec();
                want.sort_unstable();
                assert_eq!(got, want, "{k}");
                // The serialized order is the contract's.
                let t = serde_json::to_string(&body.last.unwrap()).unwrap();
                let mut at = 0;
                for k in SAMPLE_KEYS {
                    at += t[at..].find(&format!("\"{k}\":")).expect(k);
                }
            }
        }
        let v = serde_json::to_value(StaticCacheBody::new(
            true,
            Some(MemoStats {
                hits: 3,
                misses: 2,
                entries: 1,
                clears: 4,
            }),
        ))
        .unwrap();
        let mut got = keys(&v);
        got.sort_unstable();
        assert_eq!(got, ["clears", "enabled", "entries", "hits", "misses"]);
        assert_scalars(&v, "static_cache");
        assert_eq!(v["enabled"], true);
        assert_eq!(
            (v["hits"].as_u64(), v["clears"].as_u64()),
            (Some(3), Some(4))
        );
    }

    #[test]
    fn static_cache_is_enabled_only_when_configured_and_a_memo_exists() {
        let s = MemoStats::default();
        assert!(StaticCacheBody::new(true, Some(s)).enabled);
        assert!(!StaticCacheBody::new(false, Some(s)).enabled);
        let none = StaticCacheBody::new(true, None);
        assert!(!none.enabled);
        assert_eq!(
            (none.hits, none.misses, none.entries, none.clears),
            (0, 0, 0, 0)
        );
    }

    /// Nothing here holds a string, so no `Debug` can print one.
    #[test]
    fn debug_holds_no_string() {
        let mut r = TimingRing::default();
        r.push(&sample(7, Some(3)), 1);
        let d = format!("{r:?} {:?} {:?}", sample(7, Some(3)), r.body());
        assert!(!d.contains('"'));
    }
}
