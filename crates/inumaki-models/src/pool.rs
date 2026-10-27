//! A small pool of independently loaded ONNX sessions.
//!
//! `ort 2.0.0-rc.13` deliberately makes `Session::run` take `&mut self` (the
//! runtime's `Run` is not thread safe in ort's experience) and `Session` is not
//! `Clone`, so concurrency across requests comes from loading the same model
//! into several sessions and handing each caller one of them. With one slot
//! (the default) this is exactly the milestone-2 behaviour: one mutex.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Fixed set of interchangeable slots; `acquire` hands out a free one and
/// counts the times every slot was busy.
pub struct SessionPool<T> {
    slots: Vec<Mutex<T>>,
    next: AtomicUsize,
    waits: AtomicU64,
}

impl<T> std::fmt::Debug for SessionPool<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionPool")
            .field("slots", &self.slots.len())
            .field("waits", &self.waits.load(Ordering::Relaxed))
            .finish()
    }
}

impl<T> SessionPool<T> {
    /// Build from at least one slot.
    ///
    /// # Panics
    ///
    /// Panics when `slots` is empty; a backend without a session cannot run.
    pub fn new(slots: Vec<T>) -> Self {
        assert!(!slots.is_empty(), "session pool needs at least one slot");
        SessionPool {
            slots: slots.into_iter().map(Mutex::new).collect(),
            next: AtomicUsize::new(0),
            waits: AtomicU64::new(0),
        }
    }

    /// Number of slots.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Always false: a pool has at least one slot.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// How many `acquire` calls found every slot busy and had to wait.
    pub fn waits(&self) -> u64 {
        self.waits.load(Ordering::Relaxed)
    }

    /// A free slot, or (after counting a wait) block on the next slot in
    /// round-robin order. A slot whose earlier holder panicked is reused: an
    /// ORT session keeps no cross-call state.
    ///
    /// Under contention this blocks on the round-robin-selected slot, not
    /// necessarily the first slot to free up, so a waiting caller can still
    /// queue briefly behind a slot other than the one that becomes free first.
    pub fn acquire(&self) -> MutexGuard<'_, T> {
        for slot in &self.slots {
            if let Ok(g) = slot.try_lock() {
                return g;
            }
        }
        self.waits.fetch_add(1, Ordering::Relaxed);
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        self.slots[i].lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn two_slots_serve_two_holders_without_waiting() {
        let pool = SessionPool::new(vec![1u32, 2u32]);
        let a = pool.acquire();
        let b = pool.acquire();
        assert_ne!(*a, *b);
        assert_eq!(pool.waits(), 0);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn third_holder_waits_and_is_counted() {
        let pool = Arc::new(SessionPool::new(vec![1u32, 2u32]));
        let a = pool.acquire();
        let _b = pool.acquire();
        let got = Arc::new(AtomicUsize::new(0));
        let (p2, g2) = (Arc::clone(&pool), Arc::clone(&got));
        let t = std::thread::spawn(move || {
            let g = p2.acquire();
            g2.store(*g as usize, Ordering::SeqCst);
        });
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            got.load(Ordering::SeqCst),
            0,
            "must block while both slots are held"
        );
        drop(a);
        t.join().unwrap();
        assert_eq!(got.load(Ordering::SeqCst), 1);
        assert_eq!(pool.waits(), 1);
    }

    #[test]
    fn guard_release_returns_slot() {
        let pool = SessionPool::new(vec![7u32]);
        {
            let g = pool.acquire();
            assert_eq!(*g, 7);
        }
        let g = pool.acquire();
        assert_eq!(*g, 7);
        assert_eq!(pool.waits(), 0);
    }

    #[test]
    fn empty_pool_is_rejected() {
        let r = std::panic::catch_unwind(|| SessionPool::<u32>::new(vec![]));
        assert!(r.is_err());
    }
}
