//! Bounded collections — the OOM defence several sans-I/O engines need in one verified place.
//!
//! A network engine that keys a map on a **remote-chosen** value (a session cookie, a service tag, a
//! registration id) must bound that map, or a peer streaming distinct keys grows it without limit — a
//! single-peer remote memory-exhaustion DoS (audit robustness B2). The idiom for that — a `BTreeMap`
//! shadowed by an insertion-order `VecDeque` and a `MAX_*` constant, evicting the oldest key at capacity —
//! was hand-rolled in several engines. [`BoundedMap`] is that idiom, once, tested once: same eviction
//! discipline, no per-engine copy to get subtly wrong.

use alloc::collections::{BTreeMap, VecDeque};

/// A [`BTreeMap`](alloc::collections::BTreeMap) bounded to a fixed capacity with **FIFO eviction**: a new
/// key inserted beyond the capacity evicts the least-recently-**inserted** key (an insertion-order bound,
/// not an access-order LRU). Re-inserting an existing key updates its value and leaves both the size and the
/// eviction order unchanged — so a peer re-sending a known key cannot churn the order or grow the map. This
/// is the bounded-map defence against a remote key flood; a well-behaved client whose entry is evicted
/// simply re-inserts it (the bound is best-effort by design, never a correctness dependency).
pub struct BoundedMap<K: Ord + Copy, V> {
    map: BTreeMap<K, V>,
    /// Insertion order of the keys currently in `map` — enqueued when a key is first inserted, dequeued when
    /// it is evicted, so it tracks exactly the same key set and its front is always the oldest live key.
    order: VecDeque<K>,
    capacity: usize,
}

impl<K: Ord + Copy, V> BoundedMap<K, V> {
    /// A map bounded to `capacity` live entries. A `capacity` of `0` is treated as `1` (a bound is always
    /// enforced).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self { map: BTreeMap::new(), order: VecDeque::new(), capacity: capacity.max(1) }
    }

    /// Insert `(key, value)`. A **new** key takes a fresh slot, evicting the oldest entry if the map was at
    /// capacity; a **known** key just updates its value, leaving the size and eviction order untouched.
    /// Returns the evicted `(key, value)`, if a new key pushed the map over capacity.
    pub fn insert(&mut self, key: K, value: V) -> Option<(K, V)> {
        if self.map.insert(key, value).is_some() {
            return None; // known key: value refreshed; size and order unchanged.
        }
        self.order.push_back(key);
        if self.map.len() > self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            return self.map.remove(&oldest).map(|v| (oldest, v));
        }
        None
    }

    /// A shared reference to `key`'s value, if present.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// Whether `key` is present.
    #[must_use]
    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// The number of live entries (`≤ capacity`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_flood_of_distinct_keys_stays_capped_evicting_oldest_first() {
        let cap = 8usize;
        let mut m: BoundedMap<u32, u32> = BoundedMap::new(cap);
        // Insert cap + overflow distinct keys; the map stays capped, oldest evicted FIFO.
        let overflow = 5u32;
        let mut evictions = 0;
        for i in 0..(cap as u32 + overflow) {
            if let Some((k, _)) = m.insert(i, i * 10) {
                // The evicted key is always the current oldest (FIFO): eviction #j evicts key j.
                assert_eq!(k, evictions);
                evictions += 1;
            }
        }
        assert_eq!(m.len(), cap, "the map is capped, not unbounded");
        assert_eq!(evictions, overflow, "exactly `overflow` keys were evicted");
        // The oldest `overflow` keys are gone; the most recent `cap` are retained with their values.
        for i in 0..overflow {
            assert!(!m.contains_key(&i), "the oldest keys were evicted");
        }
        for i in overflow..(cap as u32 + overflow) {
            assert_eq!(m.get(&i), Some(&(i * 10)), "recent keys retained with their values");
        }
    }

    #[test]
    fn reinserting_a_known_key_refreshes_the_value_without_growing_or_reordering() {
        let mut m: BoundedMap<u8, u8> = BoundedMap::new(3);
        assert!(m.insert(1, 10).is_none());
        assert!(m.insert(2, 20).is_none());
        assert!(m.insert(3, 30).is_none());
        // Re-insert the OLDEST key (1): it must not grow the map, evict anything, or change 1's age.
        assert!(m.insert(1, 11).is_none(), "a re-insertion never evicts");
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(&1), Some(&11), "the value is refreshed");
        // A new key (4) at capacity evicts the still-oldest key — which is 1 (its re-insertion did NOT
        // renew its age; this is a FIFO bound, not an LRU).
        let evicted = m.insert(4, 40).expect("at capacity, a new key evicts the oldest");
        assert_eq!(evicted, (1, 11), "the insertion-order-oldest key is evicted, not the least-recently-used");
        assert!(!m.contains_key(&1) && m.contains_key(&2) && m.contains_key(&4));
    }

    #[test]
    fn a_zero_capacity_still_enforces_a_bound_of_one() {
        let mut m: BoundedMap<u8, u8> = BoundedMap::new(0);
        assert!(m.insert(1, 1).is_none());
        assert_eq!(m.insert(2, 2), Some((1, 1)), "capacity 0 behaves as 1 — every new key evicts the last");
        assert_eq!(m.len(), 1);
    }
}
