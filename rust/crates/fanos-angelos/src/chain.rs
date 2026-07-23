//! The **symmetric ratchet chain** shared by the 1:1 [`crate::session`] and the [`crate::ratchet`] double
//! ratchet — a one-way BLAKE3 key chain plus **skipped-message-key** handling, so a message can open even when
//! earlier ones are still in flight (real networks, and the async mixnet transport, reorder and drop).
//!
//! A chain is stepped by two domain labels (`mk` derives a message key, `next` advances the chain), passed in by
//! the caller so the session and the double ratchet keep their distinct domains (and their pinned KATs). The
//! send side just pops keys in order. The receive side ([`RecvChain`]) opens message `n`:
//!
//! - `n == next expected` — the ordinary in-order step;
//! - `n > next expected` — a **skip-ahead**: derive and store the message keys for the gap, then open `n` (a
//!   later message arriving before the ones it skipped);
//! - `n < next expected` — a **skipped** message: open it with its stored key and consume that key.
//!
//! Every open **commits state only on success**, so a forgery neither advances the chain nor consumes a stored
//! key — no desync. Two bounds keep an attacker from forcing unbounded work or memory: a single message may skip
//! at most [`MAX_SKIP_PER_MESSAGE`] keys (else it is refused), and a chain retains at most
//! [`MAX_SKIPPED_STORED`] keys (the oldest are evicted first). These are memory/DoS caps, not protocol
//! constants: each stored key is 32 bytes, so the store is bounded to a few tens of KiB per chain.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_primitives::{aead, hash_labeled};
use zeroize::Zeroize;

use crate::nonce;

/// The most message keys one out-of-order message may skip past. A larger gap is refused, bounding the work a
/// single message can force. (Signal's analogous `MAX_SKIP` is ~1000; 1024 is the same order, a round power.)
pub(crate) const MAX_SKIP_PER_MESSAGE: u64 = 1024;
/// The most skipped keys a receive chain retains at once; the oldest are evicted past this, bounding memory to
/// `MAX_SKIPPED_STORED * 32` bytes per chain.
pub(crate) const MAX_SKIPPED_STORED: usize = 2048;

/// The two domain labels that step a chain: `mk` derives a message key from the chain key, `next` advances it.
#[derive(Clone, Copy)]
pub(crate) struct ChainKdf {
    pub mk: &'static str,
    pub next: &'static str,
}

impl ChainKdf {
    /// One step: the message key at the current chain key, and the advanced chain key.
    #[must_use]
    fn step(self, chain: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        (hash_labeled(self.mk, chain), hash_labeled(self.next, chain))
    }
}

/// A sending chain: pops message keys in order.
#[derive(Clone)]
pub(crate) struct SendChain {
    key: [u8; 32],
    n: u64,
    kdf: ChainKdf,
}

impl Drop for SendChain {
    fn drop(&mut self) {
        // Audit AT-M1: wipe the live chain key so it does not linger in freed memory.
        self.key.zeroize();
    }
}

impl SendChain {
    #[must_use]
    pub(crate) fn new(key: [u8; 32], kdf: ChainKdf) -> Self {
        Self { key, n: 0, kdf }
    }

    /// The number of messages sent on this chain so far (the next message's number).
    #[must_use]
    pub(crate) fn count(&self) -> u64 {
        self.n
    }

    /// Take the next `(number, message_key)` and advance the chain.
    #[must_use]
    pub(crate) fn pop(&mut self) -> (u64, [u8; 32]) {
        let n = self.n;
        let (mk, next) = self.kdf.step(&self.key);
        self.key = next;
        self.n = self.n.saturating_add(1);
        (n, mk)
    }
}

/// A receiving chain: opens messages in order, ahead (skipping), or behind (from stored skipped keys).
#[derive(Clone)]
pub(crate) struct RecvChain {
    key: [u8; 32],
    n: u64,
    skipped: BTreeMap<u64, [u8; 32]>,
    kdf: ChainKdf,
}

impl Drop for RecvChain {
    fn drop(&mut self) {
        // Audit AT-M1: wipe the live chain key AND every banked skipped message key.
        self.key.zeroize();
        for mk in self.skipped.values_mut() {
            mk.zeroize();
        }
    }
}

impl RecvChain {
    #[must_use]
    pub(crate) fn new(key: [u8; 32], kdf: ChainKdf) -> Self {
        Self { key, n: 0, skipped: BTreeMap::new(), kdf }
    }

    /// Open message number `target` with body `body`. Handles in-order, skip-ahead (bounded), and stored-skip
    /// lookup; commits chain/skipped-store state only on a successful open. `None` if the gap is too large, the
    /// key is missing (replay or already consumed), or authentication fails.
    #[must_use]
    pub(crate) fn open(&mut self, target: u64, body: &[u8]) -> Option<Vec<u8>> {
        if target < self.n {
            // A skipped (earlier) message: open with its stored key and consume it.
            let mk = self.skipped.get(&target)?;
            let plaintext = aead::open(mk, &nonce(target), body)?;
            self.skipped.remove(&target);
            return Some(plaintext);
        }
        // target >= self.n: derive keys across the gap, open `target`, and (on success) bank the skipped ones.
        if target.saturating_sub(self.n) > MAX_SKIP_PER_MESSAGE {
            return None;
        }
        let mut chain = self.key;
        let mut pending: Vec<(u64, [u8; 32])> = Vec::new();
        let mut i = self.n;
        while i < target {
            let (mk, next) = self.kdf.step(&chain);
            pending.push((i, mk));
            chain = next;
            i = i.saturating_add(1);
        }
        let (mk_target, after) = self.kdf.step(&chain);
        let plaintext = aead::open(&mk_target, &nonce(target), body)?; // failure → no commit below

        for (num, mk) in pending {
            self.skipped.insert(num, mk);
        }
        self.key = after;
        self.n = target.saturating_add(1);
        self.evict_over_capacity();
        Some(plaintext)
    }

    /// Bank the keys still owed on this chain — numbers `self.n .. until` — into the skipped store (called at a
    /// ratchet boundary, so late messages from the chain being left can still open). `false` if `until` is
    /// implausibly far ahead (a DoS-sized `pn`), leaving the chain unchanged.
    #[must_use]
    pub(crate) fn bank_through(&mut self, until: u64) -> bool {
        if until <= self.n {
            return true;
        }
        if until.saturating_sub(self.n) > MAX_SKIP_PER_MESSAGE {
            return false;
        }
        while self.n < until {
            let (mk, next) = self.kdf.step(&self.key);
            self.skipped.insert(self.n, mk);
            self.key = next;
            self.n = self.n.saturating_add(1);
        }
        self.evict_over_capacity();
        true
    }

    /// Open message `target` from *only* the stored skipped keys (used for a message on a past ratchet epoch,
    /// whose live chain is gone). Consumes the key on success.
    #[must_use]
    pub(crate) fn open_skipped(&mut self, target: u64, body: &[u8]) -> Option<Vec<u8>> {
        let mk = self.skipped.get(&target)?;
        let plaintext = aead::open(mk, &nonce(target), body)?;
        self.skipped.remove(&target);
        Some(plaintext)
    }

    /// Whether this chain still holds any skipped keys (a past epoch with none left can be dropped).
    #[must_use]
    pub(crate) fn has_skipped(&self) -> bool {
        !self.skipped.is_empty()
    }

    /// Evict the oldest skipped keys past the retention cap.
    fn evict_over_capacity(&mut self) {
        while self.skipped.len() > MAX_SKIPPED_STORED {
            let Some((&oldest, _)) = self.skipped.iter().next() else { break };
            self.skipped.remove(&oldest);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const KDF: ChainKdf = ChainKdf { mk: "test/mk", next: "test/next" };

    /// A matched send/receive pair over the same root key.
    fn pair() -> (SendChain, RecvChain) {
        (SendChain::new([9u8; 32], KDF), RecvChain::new([9u8; 32], KDF))
    }

    /// Seal `plaintext` at the send chain's next number, returning `(number, ciphertext)`.
    fn seal(send: &mut SendChain, plaintext: &[u8]) -> (u64, Vec<u8>) {
        let (n, mk) = send.pop();
        (n, aead::seal(&mk, &nonce(n), plaintext).unwrap())
    }

    #[test]
    fn in_order_ahead_and_behind_all_open() {
        let (mut send, mut recv) = pair();
        let m: Vec<(u64, Vec<u8>)> = (0..4).map(|i| seal(&mut send, &[i as u8])).collect();
        // Deliver 2, 0, 3, 1 — a later message opens ahead of a gap, a delayed one from its banked key.
        assert_eq!(recv.open(m[2].0, &m[2].1).as_deref(), Some(&[2u8][..]));
        assert_eq!(recv.open(m[0].0, &m[0].1).as_deref(), Some(&[0u8][..]));
        assert_eq!(recv.open(m[3].0, &m[3].1).as_deref(), Some(&[3u8][..]));
        assert_eq!(recv.open(m[1].0, &m[1].1).as_deref(), Some(&[1u8][..]));
        // Every banked key is consumed on use, so a replay is refused.
        assert!(recv.open(m[0].0, &m[0].1).is_none(), "a replay is refused");
    }

    #[test]
    fn a_gap_larger_than_the_skip_bound_is_refused() {
        let (mut send, mut recv) = pair();
        // Advance the sender just past the bound, then present only the distant message.
        let mut last = (0u64, Vec::new());
        for _ in 0..=MAX_SKIP_PER_MESSAGE + 1 {
            last = seal(&mut send, b"x");
        }
        assert!(last.0 > MAX_SKIP_PER_MESSAGE, "the message number exceeds the per-message skip bound");
        assert!(recv.open(last.0, &last.1).is_none(), "a too-large gap is refused (no unbounded key derivation)");
    }

    #[test]
    fn banked_keys_are_evicted_past_the_retention_cap() {
        let (mut send, mut recv) = pair();
        // Capture message 0 specifically; it is banked, then evicted as newer keys pile in.
        let (n0, ct0) = seal(&mut send, b"zero");
        assert_eq!(n0, 0);
        // Jump ahead by the max gap repeatedly; each open banks ~MAX_SKIP keys until the store overflows.
        let rounds = MAX_SKIPPED_STORED / (MAX_SKIP_PER_MESSAGE as usize) + 3;
        for _ in 0..rounds {
            let mut jump = (0u64, Vec::new());
            for _ in 0..MAX_SKIP_PER_MESSAGE {
                jump = seal(&mut send, b"z");
            }
            assert!(recv.open(jump.0, &jump.1).is_some(), "the jumped-to message opens");
        }
        assert!(recv.skipped.len() <= MAX_SKIPPED_STORED, "the skipped store stays within its cap");
        // Message 0's banked key was the oldest, so it was evicted — the genuine message 0 no longer opens.
        assert!(recv.open(n0, &ct0).is_none(), "the oldest banked key was evicted → its message no longer opens");
    }

    #[test]
    fn bank_through_lets_a_past_chains_message_open() {
        // Model a ratchet boundary: the sender sends 3 on a chain, we receive only the first, then bank the rest.
        let (mut send, mut recv) = pair();
        let m: Vec<(u64, Vec<u8>)> = (0..3).map(|i| seal(&mut send, &[i as u8])).collect();
        assert_eq!(recv.open(m[0].0, &m[0].1).as_deref(), Some(&[0u8][..]));
        assert!(recv.bank_through(3), "bank the remaining keys of the chain being left");
        // The late messages from the retired chain still open from the banked keys.
        assert_eq!(recv.open_skipped(m[2].0, &m[2].1).as_deref(), Some(&[2u8][..]));
        assert_eq!(recv.open_skipped(m[1].0, &m[1].1).as_deref(), Some(&[1u8][..]));
        assert!(!recv.has_skipped(), "all banked keys consumed");
    }
}
