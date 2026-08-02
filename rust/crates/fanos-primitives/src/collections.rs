//! Bounded collections — the OOM defence several sans-I/O engines need in one verified place.
//!
//! A network engine that keys a map on a **remote-chosen** value (a session cookie, a service tag, a
//! registration id) must bound that map, or a peer streaming distinct keys grows it without limit — a
//! single-peer remote memory-exhaustion DoS (audit robustness B2). The idiom for that — a `BTreeMap`
//! shadowed by an insertion-order `VecDeque` and a `MAX_*` constant, evicting the oldest key at capacity —
//! was hand-rolled in several engines. [`BoundedMap`] is that idiom, once, tested once: same eviction
//! discipline, no per-engine copy to get subtly wrong.

use alloc::collections::{BTreeMap, VecDeque};

/// A [`BTreeMap`] bounded to a fixed capacity with **FIFO eviction**: a new
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

    /// Iterate the live entries in key order.
    ///
    /// Key order rather than insertion order: the bound is FIFO but a reader wants a deterministic, total order over the
    /// entries, and every caller so far is sweeping all of them (re-requesting the DA shards still missing from each
    /// block being sampled) rather than caring which arrived first.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }

    /// Iterate the live entries in key order, with mutable values.
    ///
    /// Values only, never keys: a key change would have to be mirrored in `order` to keep the eviction bound honest,
    /// and `BTreeMap` rightly forbids it. Mutating a value in place is not a re-insertion, so — exactly as with
    /// [`get_mut`](Self::get_mut) — the size and eviction order are untouched. It exists for the sweep that both
    /// *reads* every entry and *advances* per-entry state in the same pass, such as a retry schedule.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.map.iter_mut()
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

    /// A mutable reference to `key`'s value, if present. Mutating a value in place is not a re-insertion, so the
    /// size and eviction order are untouched (only [`insert`](Self::insert) enrolls a key in the order).
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    /// Remove the **oldest** entry whose key `disposable` accepts, returning it — or `None` if every entry is kept.
    ///
    /// The primitive a caller needs to make room by relevance rather than by age alone, and it lives here because
    /// insertion order lives here: `order` is this type's private FIFO queue, and a caller choosing a victim from
    /// `iter()` would be choosing in *key* order, which is arbitrary with respect to age.
    ///
    /// It exists because the alternative shape does not generalise. Protecting entries by inserting first and
    /// repairing after — put the victim back if it should have been kept — works for exactly one protected entry,
    /// since the re-insert then evicts the next-oldest, which is by construction not the protected one. With two it
    /// can evict another entry that should have been kept, silently. Choosing the victim *before* displacing anything
    /// is the only form that holds for a set.
    pub fn remove_oldest_where(&mut self, mut disposable: impl FnMut(&K) -> bool) -> Option<(K, V)> {
        let at = self.order.iter().position(&mut disposable)?;
        let key = *self.order.get(at)?;
        self.order.remove(at);
        self.map.remove(&key).map(|v| (key, v))
    }

    /// Remove `key`, returning its value if present. Its slot in the eviction order is dropped too, so `order`
    /// keeps tracking exactly the live key set (an eviction never surfaces a stale key that would skip a real
    /// one and break the bound). Removing an absent key is a no-op.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let value = self.map.remove(key)?;
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
        Some(value)
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
    fn selective_removal_takes_the_oldest_disposable_and_keeps_the_rest() {
        // Age order among the disposable, and the kept set untouched however old it is — the two properties a caller
        // needs to make room by relevance without abandoning the FIFO bound.
        let mut m: BoundedMap<u32, u32> = BoundedMap::new(8);
        for i in 0..6 {
            m.insert(i, i * 10);
        }
        // Keep the two OLDEST; they must survive while younger entries are taken.
        let keep = [0u32, 1];
        for expected in [2u32, 3, 4] {
            let (k, v) = m.remove_oldest_where(|k| !keep.contains(k)).expect("a disposable entry exists");
            assert_eq!((k, v), (expected, expected * 10), "removal must take the oldest DISPOSABLE, not the oldest");
        }
        assert!(keep.iter().all(|k| m.contains_key(k)), "kept entries survive regardless of age");

        // With only kept entries left it reports none rather than taking one anyway — the caller must learn that
        // making room would cost something it said it needed.
        m.remove_oldest_where(|k| !keep.contains(k)).expect("one disposable entry remains");
        assert!(m.remove_oldest_where(|k| !keep.contains(k)).is_none(), "nothing disposable left");
        assert_eq!(m.len(), keep.len(), "and the kept set is exactly what remains");
    }

    #[test]
    fn selective_removal_keeps_the_eviction_order_honest() {
        // The queue must lose the same key the map did: a stale key left in `order` would later be dequeued instead
        // of a live one, skipping a real eviction and breaking the bound this type exists to enforce.
        let mut m: BoundedMap<u32, u32> = BoundedMap::new(3);
        for i in 0..3 {
            m.insert(i, i);
        }
        m.remove_oldest_where(|k| *k == 0).expect("key 0 is disposable");
        // Two live entries and room for one more, so this insert must evict NOTHING.
        assert!(m.insert(9, 9).is_none(), "a removal freed a slot, so the next insert evicts nothing");
        // The next one is at capacity again and must evict the true oldest survivor, which is 1.
        assert_eq!(m.insert(10, 10).map(|(k, _)| k), Some(1), "FIFO resumes from the real oldest, not a stale key");
    }

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

    #[test]
    fn get_mut_edits_in_place_and_remove_keeps_the_eviction_order_consistent() {
        let mut m: BoundedMap<u8, u8> = BoundedMap::new(3);
        m.insert(1, 10);
        m.insert(2, 20);
        m.insert(3, 30);
        // get_mut edits in place without touching size or order.
        *m.get_mut(&2).unwrap() = 99;
        assert_eq!(m.get(&2), Some(&99));
        assert_eq!(m.len(), 3);

        // Remove the OLDEST key (1); its slot leaves the order too, so it never surfaces to skip a real key.
        assert_eq!(m.remove(&1), Some(10));
        assert_eq!(m.len(), 2);
        assert_eq!(m.remove(&1), None, "removing an absent key is a no-op");
        // Filling back to capacity and beyond evicts the true oldest LIVE key (2), not the removed stale 1.
        m.insert(4, 40); // {2,3,4} — at capacity, no eviction
        assert_eq!(m.insert(5, 50), Some((2, 99)), "the oldest live key (2) is evicted, not the removed stale 1");
        assert!(!m.contains_key(&1) && !m.contains_key(&2));
        assert!(m.contains_key(&3) && m.contains_key(&4) && m.contains_key(&5));
    }
}
