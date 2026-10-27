//! The work queue (M5 spec §6.5): five priorities, datasets served
//! round-robin within a priority, one job per key queued, a key in flight
//! re-run once after it finishes if pushed again. At most one job per
//! dataset runs at a time: a whole-folder reconcile, a tripwire pass, a
//! removal, and a file of the same folder never overlap, while other
//! datasets' jobs run on the other workers.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

/// Job priority, highest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Removal of a confirmed original.
    Removal = 0,
    /// Outbox files.
    Outbox = 1,
    /// Live source changes and tripwire requeues.
    Live = 2,
    /// Reconcile, rescan, re-mirror.
    Background = 3,
    /// Tripwire passes.
    Tripwire = 4,
}

/// A unit of work. `Debug` prints the kind and sizes only.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Job {
    /// Process one source path.
    Source {
        dataset: String,
        rel: Vec<u8>,
        force: bool,
    },
    /// Remove a confirmed original (a file, or a directory component).
    Confirmed { dataset: String, rel: Vec<u8> },
    /// Process one outbox path.
    Outbox { dataset: String, rel: Vec<u8> },
    /// Reconcile a subtree (empty: all).
    Reconcile {
        dataset: String,
        rel: Vec<u8>,
        full: bool,
    },
    /// Run the tripwire pass.
    Tripwire { dataset: String },
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (k, n) = match self {
            Job::Source { rel, .. } => ("source", rel.len()),
            Job::Confirmed { rel, .. } => ("confirmed", rel.len()),
            Job::Outbox { rel, .. } => ("outbox", rel.len()),
            Job::Reconcile { rel, .. } => ("reconcile", rel.len()),
            Job::Tripwire { .. } => ("tripwire", 0),
        };
        write!(f, "Job({k}, {n} bytes)")
    }
}

type Key = (u8, String, Vec<u8>);

impl Job {
    /// The dataset.
    pub fn dataset(&self) -> &str {
        match self {
            Job::Source { dataset, .. }
            | Job::Confirmed { dataset, .. }
            | Job::Outbox { dataset, .. }
            | Job::Reconcile { dataset, .. }
            | Job::Tripwire { dataset } => dataset,
        }
    }

    /// Merge a duplicate's flags into this job (never clears one).
    fn absorb(&mut self, other: &Job) {
        match (self, other) {
            (Job::Source { force, .. }, Job::Source { force: f, .. }) => *force |= *f,
            (Job::Reconcile { full, .. }, Job::Reconcile { full: f, .. }) => *full |= *f,
            _ => {}
        }
    }

    fn key(&self) -> Key {
        match self {
            Job::Source { dataset, rel, .. } => (0, dataset.clone(), rel.clone()),
            Job::Confirmed { dataset, rel } => (1, dataset.clone(), rel.clone()),
            Job::Outbox { dataset, rel } => (2, dataset.clone(), rel.clone()),
            Job::Reconcile { dataset, rel, .. } => (3, dataset.clone(), rel.clone()),
            Job::Tripwire { dataset } => (4, dataset.clone(), Vec::new()),
        }
    }
}

#[derive(Default)]
struct Q {
    lanes: [BTreeMap<String, VecDeque<Job>>; 5],
    cursor: [Option<String>; 5],
    queued: HashMap<Key, Priority>,
    in_flight: HashSet<Key>,
    /// Datasets with a job in flight; their queued jobs wait.
    running: HashSet<String>,
    again: HashMap<Key, (Job, Priority)>,
    stopped: bool,
}

/// The queue.
#[derive(Default)]
pub struct WorkQueue {
    q: Mutex<Q>,
    cv: Condvar,
}

impl WorkQueue {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue `job` (deduplicated; a higher priority wins). A duplicate never
    /// weakens the job it merges into: `force` and `full` are OR-ed in, so a
    /// forced pass pushed behind a plain one still runs forced.
    pub fn push(&self, mut job: Job, p: Priority) {
        let mut q = self.q.lock().unwrap_or_else(PoisonError::into_inner);
        if q.stopped {
            return;
        }
        let key = job.key();
        if q.in_flight.contains(&key) {
            match q.again.entry(key) {
                Entry::Occupied(mut e) => {
                    let (kept, kp) = e.get_mut();
                    kept.absorb(&job);
                    *kp = (*kp).min(p);
                }
                Entry::Vacant(e) => {
                    e.insert((job, p));
                }
            }
            return;
        }
        if let Some(&old) = q.queued.get(&key) {
            let ds = job.dataset().to_string();
            if old <= p {
                if let Some(kept) = q.lanes[old as usize]
                    .get_mut(&ds)
                    .and_then(|lane| lane.iter_mut().find(|j| j.key() == key))
                {
                    kept.absorb(&job);
                }
                return;
            }
            if let Some(lane) = q.lanes[old as usize].get_mut(&ds) {
                if let Some(i) = lane.iter().position(|j| j.key() == key) {
                    if let Some(prev) = lane.remove(i) {
                        job.absorb(&prev);
                    }
                }
            }
        }
        q.queued.insert(key, p);
        let ds = job.dataset().to_string();
        q.lanes[p as usize].entry(ds).or_default().push_back(job);
        self.cv.notify_one();
    }

    fn take(q: &mut Q) -> Option<(Job, Priority)> {
        let Q {
            lanes,
            cursor,
            queued,
            in_flight,
            running,
            ..
        } = q;
        for p in 0..5 {
            let lane = &mut lanes[p];
            lane.retain(|_, v| !v.is_empty());
            // Round-robin from the dataset after the cursor, skipping
            // datasets that already have a job in flight.
            let after = cursor[p].as_ref().map(|c| {
                lane.range::<String, _>((
                    std::ops::Bound::Excluded(c.clone()),
                    std::ops::Bound::Unbounded,
                ))
                .map(|(k, _)| k)
            });
            let Some(next) = after
                .into_iter()
                .flatten()
                .chain(lane.keys())
                .find(|k| !running.contains(*k))
                .cloned()
            else {
                continue;
            };
            let job = lane.get_mut(&next)?.pop_front()?;
            cursor[p] = Some(next.clone());
            let prio = match p {
                0 => Priority::Removal,
                1 => Priority::Outbox,
                2 => Priority::Live,
                3 => Priority::Background,
                _ => Priority::Tripwire,
            };
            let key = job.key();
            queued.remove(&key);
            in_flight.insert(key);
            running.insert(next);
            return Some((job, prio));
        }
        None
    }

    /// Block until a job is available; `None` after `stop`.
    pub fn pop(&self) -> Option<(Job, Priority)> {
        let mut q = self.q.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if q.stopped {
                return None;
            }
            if let Some(x) = Self::take(&mut q) {
                return Some(x);
            }
            q = self.cv.wait(q).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Like `pop`, giving up after `d` (tests, the poller).
    pub fn pop_timeout(&self, d: Duration) -> Option<(Job, Priority)> {
        let mut q = self.q.lock().unwrap_or_else(PoisonError::into_inner);
        if q.stopped {
            return None;
        }
        if let Some(x) = Self::take(&mut q) {
            return Some(x);
        }
        q = self
            .cv
            .wait_timeout(q, d)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
        if q.stopped {
            return None;
        }
        Self::take(&mut q)
    }

    /// Mark `job` finished; re-queue it if it was pushed meanwhile. Its
    /// dataset's other jobs may run from now on.
    pub fn done(&self, job: &Job) {
        let again = {
            let mut q = self.q.lock().unwrap_or_else(PoisonError::into_inner);
            let key = job.key();
            q.in_flight.remove(&key);
            q.running.remove(job.dataset());
            q.again.remove(&key)
        };
        // A worker may be waiting only because this dataset was busy.
        self.cv.notify_all();
        if let Some((j, p)) = again {
            self.push(j, p);
        }
    }

    /// Drop every queued job of `dataset`.
    pub fn purge(&self, dataset: &str) {
        let mut q = self.q.lock().unwrap_or_else(PoisonError::into_inner);
        for lane in &mut q.lanes {
            lane.remove(dataset);
        }
        q.queued.retain(|k, _| k.1 != dataset);
        q.again.retain(|k, _| k.1 != dataset);
    }

    /// Queued `(source, outbox)` jobs of `dataset`.
    pub fn pending(&self, dataset: &str) -> (u64, u64) {
        let q = self.q.lock().unwrap_or_else(PoisonError::into_inner);
        let mut s = 0;
        let mut o = 0;
        for k in q
            .queued
            .keys()
            .chain(q.in_flight.iter())
            .filter(|k| k.1 == dataset)
        {
            match k.0 {
                0 | 1 => s += 1,
                2 => o += 1,
                _ => {}
            }
        }
        (s, o)
    }

    /// Source, removal, or reconcile work of `dataset` is queued, in
    /// flight, or due again: the folder is still `scanning` (review minor).
    pub fn busy(&self, dataset: &str) -> bool {
        let q = self.q.lock().unwrap_or_else(PoisonError::into_inner);
        q.queued
            .keys()
            .chain(q.in_flight.iter())
            .chain(q.again.keys())
            .any(|k| k.1 == dataset && matches!(k.0, 0 | 1 | 3))
    }

    /// Nothing queued or in flight.
    pub fn is_idle(&self) -> bool {
        let q = self.q.lock().unwrap_or_else(PoisonError::into_inner);
        q.queued.is_empty() && q.in_flight.is_empty() && q.again.is_empty()
    }

    /// Wake every waiter; `pop` returns `None` from now on.
    pub fn stop(&self) {
        self.q
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stopped = true;
        self.cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(force: bool) -> Job {
        Job::Source {
            dataset: "ds".into(),
            rel: b"a".to_vec(),
            force,
        }
    }

    fn forced(j: &Job) -> bool {
        matches!(j, Job::Source { force: true, .. })
    }

    #[test]
    fn duplicate_never_drops_the_force_flag() {
        let ms = Duration::from_millis(1);
        // Queued at the same priority, then pushed forced.
        let q = WorkQueue::new();
        q.push(src(false), Priority::Background);
        q.push(src(true), Priority::Background);
        let (j, _) = q.pop_timeout(ms).unwrap();
        assert!(forced(&j));

        // Queued low, then pushed forced at a higher priority (upgrade).
        let q = WorkQueue::new();
        q.push(src(false), Priority::Background);
        q.push(src(true), Priority::Live);
        let (j, p) = q.pop_timeout(ms).unwrap();
        assert!(forced(&j) && p == Priority::Live);
        // Queued forced, then pushed plain at a higher priority (upgrade).
        let q = WorkQueue::new();
        q.push(src(true), Priority::Background);
        q.push(src(false), Priority::Live);
        assert!(forced(&q.pop_timeout(ms).unwrap().0));

        // In flight, then pushed forced: the re-run is forced.
        let q = WorkQueue::new();
        q.push(src(false), Priority::Live);
        let (j, _) = q.pop_timeout(ms).unwrap();
        q.push(src(false), Priority::Live);
        q.push(src(true), Priority::Background);
        q.done(&j);
        assert!(forced(&q.pop_timeout(ms).unwrap().0));

        // The same for a full reconcile.
        let q = WorkQueue::new();
        let rec = |full| Job::Reconcile {
            dataset: "ds".into(),
            rel: Vec::new(),
            full,
        };
        q.push(rec(false), Priority::Background);
        q.push(rec(true), Priority::Background);
        assert!(matches!(
            q.pop_timeout(ms).unwrap().0,
            Job::Reconcile { full: true, .. }
        ));
    }

    #[test]
    fn nothing_is_handed_out_after_stop() {
        let q = WorkQueue::new();
        q.push(src(false), Priority::Live);
        q.stop();
        assert!(q.pop_timeout(Duration::from_millis(1)).is_none());
    }
}
