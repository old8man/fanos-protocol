//! A canonical, bounded byte codec — one reusable reader/writer so every ledger component serializes its
//! full state (state-sync snapshots, `docs/design-taxis.md`), and any other length-prefixed structure,
//! through the SAME deterministic, panic-free, OOM-safe path instead of hand-rolling `bytes.get(..)` loops.
//!
//! Guarantees: every [`Reader`] getter is **total** (returns `None` on a short or malformed buffer, never
//! panics or indexes out of bounds); [`Reader::seq`] **bounds** its pre-allocation against the bytes actually
//! present, so a crafted count can neither over-allocate nor OOM; and encoding is **deterministic** — the same
//! logical value always produces the same bytes (little-endian scalars, caller-sorted collections), so two
//! honest nodes snapshot identical state to identical bytes.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// A cursor over a byte buffer with bounded, total accessors.
pub struct Reader<'a> {
    bytes: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    /// A reader positioned at the start of `bytes`.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, off: 0 }
    }

    /// Advance over and return the next `n` bytes, or `None` if fewer remain.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.off.checked_add(n)?;
        let slice = self.bytes.get(self.off..end)?;
        self.off = end;
        Some(slice)
    }

    /// The next fixed `N`-byte array.
    #[must_use]
    pub fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    /// The next `n` bytes as a borrowed slice, or `None` if fewer remain — a fixed-width field whose length is
    /// only known at run time (e.g. a nested struct's `LEN` constant), the runtime-length counterpart to
    /// [`array`](Self::array).
    #[must_use]
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        self.take(n)
    }

    /// The next byte.
    #[must_use]
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).and_then(|s| s.first().copied())
    }

    /// The next little-endian `u32`.
    #[must_use]
    pub fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    /// The next little-endian `u64`.
    #[must_use]
    pub fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }

    /// A `u32`-length-prefixed byte string.
    #[must_use]
    pub fn var_bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// A `u32`-count-prefixed sequence, each element decoded via `f`. `min_elem` is the fewest bytes one
    /// element can occupy on the wire; the count is rejected if it exceeds `remaining / min_elem`, so the
    /// pre-allocation is bounded by the bytes actually present (`min_elem = 0` is refused — it cannot bound).
    pub fn seq<T>(&mut self, min_elem: usize, mut f: impl FnMut(&mut Reader<'a>) -> Option<T>) -> Option<Vec<T>> {
        let count = self.u32()? as usize;
        let remaining = self.bytes.len().saturating_sub(self.off);
        if min_elem == 0 || count > remaining / min_elem {
            return None;
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(f(self)?);
        }
        Some(out)
    }

    /// The remaining unread bytes, consuming them (a variable-length tail that runs to the end of the buffer).
    #[must_use]
    pub fn rest(&mut self) -> &'a [u8] {
        let out = self.bytes.get(self.off..).unwrap_or(&[]);
        self.off = self.bytes.len();
        out
    }

    /// Whether the whole buffer has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.off == self.bytes.len()
    }

    /// Succeed **only** if the whole buffer was consumed — the standard "no trailing garbage" check that ends
    /// a total decode.
    #[must_use]
    pub fn finish(self) -> Option<()> {
        self.is_empty().then_some(())
    }
}

/// Append a little-endian `u32`.
pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Append a little-endian `u64`.
pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Append a `u32`-length-prefixed byte string.
pub fn put_var_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, u32::try_from(b.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(b);
}

/// Append a `u32`-count-prefixed sequence (`count` then each item written via `f`). The caller supplies the
/// count and an iterator so a `BTreeMap`/`BTreeSet` streams in its own sorted order without an intermediate
/// `Vec` — keeping the encoding canonical.
pub fn put_seq<T>(out: &mut Vec<u8>, count: usize, items: impl IntoIterator<Item = T>, mut f: impl FnMut(&mut Vec<u8>, T)) {
    put_u32(out, u32::try_from(count).unwrap_or(u32::MAX));
    for it in items {
        f(out, it);
    }
}

/// Append a `BTreeMap` canonically (count-prefixed, in the map's sorted key order), each `(key, value)` pair
/// written via `kv`. The one map encoder every ledger component reuses for its state (balances, nonces, name
/// records, deals, htlcs, …).
pub fn put_map<K, V>(out: &mut Vec<u8>, map: &BTreeMap<K, V>, mut kv: impl FnMut(&mut Vec<u8>, &K, &V)) {
    put_u32(out, u32::try_from(map.len()).unwrap_or(u32::MAX));
    for (k, v) in map {
        kv(out, k, v);
    }
}

/// Decode a [`put_map`] into a `BTreeMap`, each `(key, value)` via `kv` (≥ `min_elem` bytes/entry, which bounds
/// the count). `None` on any malformed entry.
pub fn read_map<'a, K: Ord, V>(
    r: &mut Reader<'a>,
    min_elem: usize,
    kv: impl FnMut(&mut Reader<'a>) -> Option<(K, V)>,
) -> Option<BTreeMap<K, V>> {
    Some(r.seq(min_elem, kv)?.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_and_arrays_round_trip_and_are_bounded() {
        let mut out = Vec::new();
        put_u32(&mut out, 0xDEAD_BEEF);
        put_u64(&mut out, 0x0102_0304_0506_0708);
        out.extend_from_slice(&[9u8; 32]);
        let mut r = Reader::new(&out);
        assert_eq!(r.u32(), Some(0xDEAD_BEEF));
        assert_eq!(r.u64(), Some(0x0102_0304_0506_0708));
        assert_eq!(r.array::<32>(), Some([9u8; 32]));
        assert_eq!(r.finish(), Some(()));
        // A short buffer never panics — every getter returns None.
        let mut short = Reader::new(&[0u8; 3]);
        assert_eq!(short.u32(), None);
    }

    #[test]
    fn var_bytes_and_seq_round_trip_and_reject_over_counts() {
        let items: [u64; 3] = [10, 20, 30];
        let mut out = Vec::new();
        put_var_bytes(&mut out, b"hello");
        put_seq(&mut out, items.len(), items.iter().copied(), put_u64);
        let mut r = Reader::new(&out);
        assert_eq!(r.var_bytes(), Some(b"hello".as_slice()));
        assert_eq!(r.seq(8, Reader::u64), Some(alloc::vec![10u64, 20, 30]));
        assert_eq!(r.finish(), Some(()));
        // A crafted over-count (claims billions of 8-byte elements in a few bytes) is refused, not allocated.
        let mut evil = u32::MAX.to_le_bytes().to_vec();
        evil.extend_from_slice(&[0u8; 8]);
        assert_eq!(Reader::new(&evil).seq::<u64>(8, Reader::u64), None);
        // A zero min-elem cannot bound and is refused.
        assert_eq!(Reader::new(&1u32.to_le_bytes()).seq::<()>(0, |_| Some(())), None);
    }
}
