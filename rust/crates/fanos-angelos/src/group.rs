//! The **sender-key group session** — the crypto under an ANGELOS channel (`spec/platform.md` §6.2).
//!
//! A channel's members share a **group key** (distributed to each over their 1:1 [`crate::session`]s, or a group
//! handshake). From it, each member deterministically derives their own **sender chain**; because every member
//! can derive every *other* member's chain from the shared group key and the public member id, a post is a
//! *single* encryption under the poster's own chain (`O(1)`), not one per recipient (`O(k)` pairwise) — the
//! property that makes a large channel cheap. Each sender chain is a one-way BLAKE3 ratchet, so a compromised
//! chain reveals only that sender's current-and-future messages, never their past ones (per-sender forward
//! secrecy). Adding or removing a member changes the group key — a **rekey** — so departed members cannot read
//! on, and new ones cannot read back.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_primitives::{aead, hash_labeled};

use crate::nonce;

/// Label deriving a member's sender chain from the group key and member id.
const SENDER_LABEL: &str = "FANOS-angelos-v1/group-sender";
/// Label deriving a message key from a sender chain.
const MK_LABEL: &str = "FANOS-angelos-v1/group-mk";
/// Label advancing a sender chain.
const NEXT_LABEL: &str = "FANOS-angelos-v1/group-next";

/// One member's view of a channel: their own send chain, and a receive chain per other member.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GroupSession {
    my_id: u32,
    send_chain: [u8; 32],
    send_n: u64,
    /// `sender_id -> (their chain as we track it, the next message number we expect from them)`.
    recv: BTreeMap<u32, ([u8; 32], u64)>,
}

impl GroupSession {
    /// Join a channel: derive our send chain and a receive chain for every other member, from the shared
    /// `group_key` and the roster `members` (member ids). Rekeying (membership change) is a fresh session over a
    /// new group key.
    #[must_use]
    pub fn new(group_key: &[u8; 32], my_id: u32, members: &[u32]) -> Self {
        let send_chain = sender_chain(group_key, my_id);
        let recv = members
            .iter()
            .copied()
            .filter(|&m| m != my_id)
            .map(|m| (m, (sender_chain(group_key, m), 0u64)))
            .collect();
        Self { my_id, send_chain, send_n: 0, recv }
    }

    /// This member's id.
    #[must_use]
    pub fn my_id(&self) -> u32 {
        self.my_id
    }

    /// **Post** to the channel: seal `plaintext` under our own sender chain and advance it. Returns
    /// `message_number(8) ‖ ciphertext` — the same object every other member opens with [`recv`](Self::recv),
    /// tagged (out of band) with our [`my_id`](Self::my_id).
    #[must_use]
    pub fn send(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mk = hash_labeled(MK_LABEL, &self.send_chain);
        self.send_chain = hash_labeled(NEXT_LABEL, &self.send_chain);
        let n = self.send_n;
        self.send_n = self.send_n.saturating_add(1);
        let ciphertext = aead::seal(&mk, &nonce(n), plaintext).unwrap_or_default();
        let mut out = Vec::with_capacity(8 + ciphertext.len());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    /// **Receive** a post from `sender_id`. `None` if the sender is not a tracked member, the message is out of
    /// order (this core assumes in-order per sender), or it fails authentication; on failure the sender's chain
    /// is not advanced.
    #[must_use]
    pub fn recv(&mut self, sender_id: u32, sealed: &[u8]) -> Option<Vec<u8>> {
        let n = u64::from_le_bytes(sealed.get(..8)?.try_into().ok()?);
        let (chain, next_n) = self.recv.get_mut(&sender_id)?;
        if n != *next_n {
            return None;
        }
        let current = *chain;
        let mk = hash_labeled(MK_LABEL, &current);
        let plaintext = aead::open(&mk, &nonce(n), sealed.get(8..)?)?;
        *chain = hash_labeled(NEXT_LABEL, &current);
        *next_n = next_n.saturating_add(1);
        Some(plaintext)
    }
}

/// A member's sender chain: `H("group-sender", group_key ‖ member_id)`.
#[must_use]
fn sender_chain(group_key: &[u8; 32], member_id: u32) -> [u8; 32] {
    let mut buf = [0u8; 36];
    let (g, m) = buf.split_at_mut(32);
    g.copy_from_slice(group_key);
    m.copy_from_slice(&member_id.to_le_bytes());
    hash_labeled(SENDER_LABEL, &buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const GROUP_KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn every_member_reads_every_others_posts() {
        let members = [1u32, 2, 3];
        let mut a = GroupSession::new(&GROUP_KEY, 1, &members);
        let mut b = GroupSession::new(&GROUP_KEY, 2, &members);
        let mut c = GroupSession::new(&GROUP_KEY, 3, &members);

        // Alice (1) posts once; Bob and Carol both read it.
        let post = a.send(b"hello channel");
        assert_eq!(b.recv(1, &post).as_deref(), Some(&b"hello channel"[..]));
        assert_eq!(c.recv(1, &post).as_deref(), Some(&b"hello channel"[..]));

        // Bob (2) posts; Alice and Carol read it.
        let post2 = b.send(b"hi from bob");
        assert_eq!(a.recv(2, &post2).as_deref(), Some(&b"hi from bob"[..]));
        assert_eq!(c.recv(2, &post2).as_deref(), Some(&b"hi from bob"[..]));
    }

    #[test]
    fn posts_from_one_sender_stay_in_order_and_ratchet() {
        let members = [1u32, 2];
        let mut a = GroupSession::new(&GROUP_KEY, 1, &members);
        let mut b = GroupSession::new(&GROUP_KEY, 2, &members);
        let m0 = a.send(b"zero");
        let m1 = a.send(b"one");
        // Delivering out of order is refused; in order works.
        assert!(b.recv(1, &m1).is_none(), "a later message before an earlier one is refused");
        assert_eq!(b.recv(1, &m0).as_deref(), Some(&b"zero"[..]));
        assert_eq!(b.recv(1, &m1).as_deref(), Some(&b"one"[..]));
        // The same plaintext posted twice seals differently (the chain ratcheted).
        let mut a2 = GroupSession::new(&GROUP_KEY, 1, &members);
        assert_ne!(a2.send(b"x"), a2.send(b"x"), "the sender chain ratchets per post");
    }

    #[test]
    fn a_non_member_sender_or_a_forgery_is_refused() {
        let members = [1u32, 2];
        let mut a = GroupSession::new(&GROUP_KEY, 1, &members);
        let mut b = GroupSession::new(&GROUP_KEY, 2, &members);
        let post = a.send(b"members only");
        // No chain is tracked for a non-member id.
        assert!(b.recv(99, &post).is_none(), "a post attributed to a non-member is refused");
        // A tampered post fails and does not desync.
        let mut bad = post.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(b.recv(1, &bad).is_none(), "a tampered post is refused");
        assert_eq!(b.recv(1, &post).as_deref(), Some(&b"members only"[..]), "the genuine post still opens");
    }

    #[test]
    fn a_rekey_locks_out_a_departed_member() {
        // A member reading the old key cannot read messages under a new (post-removal) group key.
        let old = GroupSession::new(&GROUP_KEY, 2, &[1, 2, 3]);
        let new_key = [0x99u8; 32];
        let mut a_new = GroupSession::new(&new_key, 1, &[1, 3]); // 2 removed
        let post = a_new.send(b"after removal");
        // The departed member's stale session tracks sender 1 under the OLD key → cannot open the new post.
        let mut stale = old;
        assert!(stale.recv(1, &post).is_none(), "a departed member cannot read post-rekey messages");
    }
}
