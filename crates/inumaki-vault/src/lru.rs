//! Bounded, weight-aware LRU map. Evicted values are handed back to the
//! caller, whose drop wipes them when they are `Zeroizing`.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

struct Slot<V> {
    value: V,
    stamp: u64,
    weight: usize,
}

/// LRU map bounded by total weight (1 per entry for a count bound, bytes
/// for a size bound). Nothing is dropped inside: every evicted or removed
/// value is returned so the caller controls when it is wiped.
pub struct Lru<K, V> {
    map: HashMap<K, Slot<V>>,
    /// Recency stamp → key; the smallest stamp is the least recently used.
    order: BTreeMap<u64, K>,
    stamp: u64,
    capacity: usize,
    weight: usize,
}

impl<K, V> std::fmt::Debug for Lru<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lru")
            .field("len", &self.map.len())
            .field("weight", &self.weight)
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl<K: Hash + Eq + Clone, V> Lru<K, V> {
    /// Empty map holding at most `capacity` weight.
    pub fn new(capacity: usize) -> Self {
        Lru {
            map: HashMap::new(),
            order: BTreeMap::new(),
            stamp: 0,
            capacity,
            weight: 0,
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

    /// Sum of stored weights.
    pub fn weight(&self) -> usize {
        self.weight
    }

    /// Weight bound.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// True when `k` is present (no touch).
    pub fn contains(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }

    /// Value without touching recency.
    pub fn peek(&self, k: &K) -> Option<&V> {
        self.map.get(k).map(|s| &s.value)
    }

    fn touch(&mut self, k: &K) -> bool {
        let Some(slot) = self.map.get_mut(k) else {
            return false;
        };
        self.order.remove(&slot.stamp);
        self.stamp += 1;
        slot.stamp = self.stamp;
        self.order.insert(self.stamp, k.clone());
        true
    }

    /// Value, marking `k` most recently used.
    pub fn get(&mut self, k: &K) -> Option<&V> {
        if self.touch(k) { self.peek(k) } else { None }
    }

    /// Mutable value, marking `k` most recently used.
    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        if self.touch(k) {
            self.map.get_mut(k).map(|s| &mut s.value)
        } else {
            None
        }
    }

    /// Insert or replace. Returns every entry that had to leave: the
    /// replaced value under `k`, the least recently used entries evicted to
    /// make room, or `(k, v)` itself when `weight` exceeds the capacity.
    pub fn insert(&mut self, k: K, v: V, weight: usize) -> Vec<(K, V)> {
        let mut out = Vec::new();
        if let Some(old) = self.remove(&k) {
            out.push((k.clone(), old));
        }
        if weight > self.capacity {
            out.push((k, v));
            return out;
        }
        while self.weight + weight > self.capacity {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            if let Some(slot) = self.map.remove(&oldest) {
                self.weight -= slot.weight;
                out.push((oldest, slot.value));
            }
        }
        self.stamp += 1;
        self.order.insert(self.stamp, k.clone());
        self.map.insert(
            k,
            Slot {
                value: v,
                stamp: self.stamp,
                weight,
            },
        );
        self.weight += weight;
        out
    }

    /// Remove one entry.
    pub fn remove(&mut self, k: &K) -> Option<V> {
        let slot = self.map.remove(k)?;
        self.order.remove(&slot.stamp);
        self.weight -= slot.weight;
        Some(slot.value)
    }

    /// Keep entries for which `keep` is true; return the rest.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) -> Vec<(K, V)> {
        let doomed: Vec<K> = self
            .map
            .iter()
            .filter(|(k, s)| !keep(k, &s.value))
            .map(|(k, _)| k.clone())
            .collect();
        doomed
            .into_iter()
            .filter_map(|k| self.remove(&k).map(|v| (k, v)))
            .collect()
    }

    /// Remove everything, least recently used first.
    pub fn drain(&mut self) -> Vec<(K, V)> {
        let keys: Vec<K> = self.order.values().cloned().collect();
        keys.into_iter()
            .filter_map(|k| self.remove(&k).map(|v| (k, v)))
            .collect()
    }

    /// Entries in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter().map(|(k, s)| (k, &s.value))
    }

    /// Keys, most recently used first.
    pub fn keys_by_recency(&self) -> impl Iterator<Item = &K> {
        self.order.values().rev()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts drops, standing in for a zeroized buffer.
    struct Observed(Arc<AtomicUsize>);
    impl Drop for Observed {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn evicts_least_recently_used_and_the_value_is_dropped() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut lru: Lru<&str, Observed> = Lru::new(2);
        assert!(lru.insert("a", Observed(drops.clone()), 1).is_empty());
        assert!(lru.insert("b", Observed(drops.clone()), 1).is_empty());
        lru.get(&"a"); // a is now the most recent
        let evicted = lru.insert("c", Observed(drops.clone()), 1);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].0, "b");
        assert_eq!(drops.load(Ordering::SeqCst), 0, "caller still holds it");
        drop(evicted);
        assert_eq!(drops.load(Ordering::SeqCst), 1, "dropped once handed back");
        assert!(lru.contains(&"a") && lru.contains(&"c") && !lru.contains(&"b"));
        assert_eq!(lru.len(), 2);
    }

    #[test]
    fn peek_does_not_touch_but_get_does() {
        let mut lru: Lru<u8, u8> = Lru::new(2);
        lru.insert(1, 10, 1);
        lru.insert(2, 20, 1);
        assert_eq!(lru.peek(&1), Some(&10));
        let ev = lru.insert(3, 30, 1);
        assert_eq!(ev, vec![(1, 10)], "peek left 1 the oldest");
        lru.get(&2);
        let ev = lru.insert(4, 40, 1);
        assert_eq!(ev, vec![(3, 30)], "get made 2 recent, so 3 went");
    }

    #[test]
    fn weight_is_bounded_and_oversized_values_are_refused() {
        let mut lru: Lru<u8, &str> = Lru::new(10);
        assert!(lru.insert(1, "x", 6).is_empty());
        let ev = lru.insert(2, "y", 6);
        assert_eq!(ev, vec![(1, "x")]);
        assert_eq!(lru.weight(), 6);
        let ev = lru.insert(3, "z", 11);
        assert_eq!(ev, vec![(3, "z")], "never stored");
        assert_eq!(lru.len(), 1);
        assert_eq!(lru.weight(), 6);
    }

    #[test]
    fn replacing_a_key_returns_the_old_value() {
        let mut lru: Lru<u8, u8> = Lru::new(4);
        lru.insert(1, 10, 1);
        assert_eq!(lru.insert(1, 11, 1), vec![(1, 10)]);
        assert_eq!(lru.len(), 1);
        assert_eq!(lru.peek(&1), Some(&11));
    }

    #[test]
    fn retain_drain_and_recency_order() {
        let mut lru: Lru<u8, u8> = Lru::new(8);
        for i in 1..=4 {
            lru.insert(i, i * 10, 1);
        }
        lru.get(&1);
        let order: Vec<u8> = lru.keys_by_recency().copied().collect();
        assert_eq!(order, vec![1, 4, 3, 2]);
        let removed = lru.retain(|k, _| k % 2 == 0);
        assert_eq!(removed.len(), 2);
        assert_eq!(lru.len(), 2);
        assert_eq!(lru.remove(&2), Some(20));
        let drained = lru.drain();
        assert_eq!(drained, vec![(4, 40)]);
        assert!(lru.is_empty());
        assert_eq!(lru.weight(), 0);
    }
}
