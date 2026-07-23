//! The **sender-key group session** — the crypto under an ANGELOS channel (`spec/platform.md` §6.2).
//!
//! A channel's members share a **group key** (distributed to each over their 1:1 [`crate::session`]s, or a group
//! handshake). From it, each member deterministically derives their own **sender chain**; because every member
//! can derive every *other* member's chain from the shared group key and the public member id, a post is a
//! *single* encryption under the poster's own chain (`O(1)`), not one per recipient (`O(k)` pairwise) — the
//! property that makes a large channel cheap. Each sender chain is a one-way BLAKE3 ratchet, so a compromised
//! chain reveals only that sender's current-and-future messages, never their past ones (per-sender forward
//! secrecy). Adding or removing a member changes the group key — a **rekey**.
//!
//! **Sender authentication (load-bearing).** Because every member can derive every other member's sender chain,
//! the chain alone cannot *authenticate* a post — any member could seal a message under another's chain and
//! attribute it to them. So, exactly as Signal's Sender-Keys design, each member also holds a **per-sender
//! signing key**; every post is signed over `sender_id ‖ number ‖ ciphertext`, and a receiver verifies that
//! signature against the sender's public key *before* touching the chain. Only the public halves are shared, so
//! an insider who can derive a victim's chain still cannot forge a post as them — `Message.sender` is
//! cryptographically backed inside the group.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_pqcrypto::sig::HYBRID_SIG_LEN;
use fanos_pqcrypto::{HybridSigSecret, HybridSignature, HybridVerifier};
use fanos_primitives::{aead, hash_labeled};
use zeroize::Zeroize;

use crate::nonce;

/// Label deriving a member's sender chain from the group key and member id.
const SENDER_LABEL: &str = "FANOS-angelos-v1/group-sender";
/// Label deriving a message key from a sender chain.
const MK_LABEL: &str = "FANOS-angelos-v1/group-mk";
/// Label advancing a sender chain.
const NEXT_LABEL: &str = "FANOS-angelos-v1/group-next";

/// One member's view of a channel: their own send chain + signing key, a receive chain per other member, and
/// the roster of members' public verifying keys. Not `Clone` — it owns a signing secret and live chains.
pub struct GroupSession {
    my_id: u32,
    sign_secret: HybridSigSecret,
    send_chain: [u8; 32],
    send_n: u64,
    /// `sender_id -> (their chain as we track it, the next message number we expect from them)`.
    recv: BTreeMap<u32, ([u8; 32], u64)>,
    /// `member_id -> their public verifying key` (for authenticating their posts).
    verifiers: BTreeMap<u32, HybridVerifier>,
}

impl Drop for GroupSession {
    fn drop(&mut self) {
        // Audit AT-M1: wipe our send chain and every tracked peer chain key. `sign_secret` (HybridSigSecret)
        // zeroizes via its own drop; `verifiers` hold only public keys.
        self.send_chain.zeroize();
        for (chain, _n) in self.recv.values_mut() {
            chain.zeroize();
        }
    }
}

impl GroupSession {
    /// Join a channel: derive our send chain and a receive chain for every other member from the shared
    /// `group_key`, take our `sign_secret`, and record the roster `members` (each member's id and public
    /// verifying key — including our own, which is ignored for receiving). Rekeying (membership change) is a
    /// fresh session over a new group key and roster.
    #[must_use]
    pub fn new(
        group_key: &[u8; 32],
        my_id: u32,
        sign_secret: HybridSigSecret,
        members: &[(u32, HybridVerifier)],
    ) -> Self {
        let recv = members
            .iter()
            .filter(|(id, _)| *id != my_id)
            .map(|(id, _)| (*id, (sender_chain(group_key, *id), 0u64)))
            .collect();
        let verifiers = members.iter().filter(|(id, _)| *id != my_id).map(|(id, vk)| (*id, vk.clone())).collect();
        Self { my_id, sign_secret, send_chain: sender_chain(group_key, my_id), send_n: 0, recv, verifiers }
    }

    /// This member's id.
    #[must_use]
    pub fn my_id(&self) -> u32 {
        self.my_id
    }

    /// **Post** to the channel: seal `plaintext` under our own sender chain, advance it, and **sign** the post.
    /// Returns `message_number(8) ‖ ciphertext ‖ signature(HYBRID_SIG_LEN)` — the same object every other member
    /// opens with [`recv`](Self::recv), tagged (out of band) with our [`my_id`](Self::my_id).
    #[must_use]
    pub fn send(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mk = hash_labeled(MK_LABEL, &self.send_chain);
        self.send_chain = hash_labeled(NEXT_LABEL, &self.send_chain);
        let n = self.send_n;
        self.send_n = self.send_n.saturating_add(1);
        let ciphertext = aead::seal(&mk, &nonce(n), plaintext).unwrap_or_default();
        let signature = self.sign_secret.sign(&signed_bytes(self.my_id, n, &ciphertext));
        let mut out = Vec::with_capacity(8 + ciphertext.len() + HYBRID_SIG_LEN);
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&signature.to_bytes());
        out
    }

    /// **Receive** a post from `sender_id`. `None` if the sender is not a tracked member, the **signature does
    /// not verify** against the sender's key (a forgery — refused *before* the chain is touched), the message is
    /// out of order, or it fails authentication; on failure the sender's chain is not advanced.
    #[must_use]
    pub fn recv(&mut self, sender_id: u32, sealed: &[u8]) -> Option<Vec<u8>> {
        // Split the trailing signature, then verify it before anything else.
        let sig_start = sealed.len().checked_sub(HYBRID_SIG_LEN)?;
        let head = sealed.get(..sig_start)?;
        let signature = HybridSignature::from_bytes(sealed.get(sig_start..)?)?;
        let n = u64::from_le_bytes(head.get(..8)?.try_into().ok()?);
        let ciphertext = head.get(8..)?;
        let verifier = self.verifiers.get(&sender_id)?;
        if !verifier.verify(&signed_bytes(sender_id, n, ciphertext), &signature) {
            return None; // forged or tampered attribution — never reaches the chain
        }
        // Authenticated: now advance the sender chain in order.
        let (chain, next_n) = self.recv.get_mut(&sender_id)?;
        if n != *next_n {
            return None;
        }
        let current = *chain;
        let mk = hash_labeled(MK_LABEL, &current);
        let plaintext = aead::open(&mk, &nonce(n), ciphertext)?;
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

/// The bytes a post's signature covers: `sender_id(4, LE) ‖ number(8, LE) ‖ ciphertext`.
#[must_use]
fn signed_bytes(sender_id: u32, n: u64, ciphertext: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(12 + ciphertext.len());
    msg.extend_from_slice(&sender_id.to_le_bytes());
    msg.extend_from_slice(&n.to_le_bytes());
    msg.extend_from_slice(ciphertext);
    msg
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    use fanos_pqcrypto::SeedRng;

    const GROUP_KEY: [u8; 32] = [0x42; 32];

    /// A signing keypair from a seed.
    fn keypair(tag: u8) -> (HybridSigSecret, HybridVerifier) {
        HybridSigSecret::generate(&mut SeedRng::from_seed(&[0x60, tag]))
    }

    /// A three-member channel (ids 1,2,3) with fresh signing keys; returns the sessions.
    fn channel() -> (GroupSession, GroupSession, GroupSession) {
        let (sk1, vk1) = keypair(1);
        let (sk2, vk2) = keypair(2);
        let (sk3, vk3) = keypair(3);
        let roster = [(1u32, vk1), (2, vk2), (3, vk3)];
        let a = GroupSession::new(&GROUP_KEY, 1, sk1, &roster);
        let b = GroupSession::new(&GROUP_KEY, 2, sk2, &roster);
        let c = GroupSession::new(&GROUP_KEY, 3, sk3, &roster);
        (a, b, c)
    }

    #[test]
    fn every_member_reads_every_others_posts() {
        let (mut a, mut b, mut c) = channel();
        let post = a.send(b"hello channel");
        assert_eq!(b.recv(1, &post).as_deref(), Some(&b"hello channel"[..]));
        assert_eq!(c.recv(1, &post).as_deref(), Some(&b"hello channel"[..]));
        let post2 = b.send(b"hi from bob");
        assert_eq!(a.recv(2, &post2).as_deref(), Some(&b"hi from bob"[..]));
        assert_eq!(c.recv(2, &post2).as_deref(), Some(&b"hi from bob"[..]));
    }

    #[test]
    fn posts_from_one_sender_stay_in_order_and_ratchet() {
        let (mut a, mut b, _c) = channel();
        let m0 = a.send(b"zero");
        let m1 = a.send(b"one");
        assert!(b.recv(1, &m1).is_none(), "a later message before an earlier one is refused");
        assert_eq!(b.recv(1, &m0).as_deref(), Some(&b"zero"[..]));
        assert_eq!(b.recv(1, &m1).as_deref(), Some(&b"one"[..]));
    }

    #[test]
    fn an_insider_cannot_forge_a_post_as_another_member() {
        // Member 2 (an insider) knows the group key, so it can DERIVE member 1's sender chain and seal a
        // ciphertext under it — but it cannot sign as member 1. The forged post is refused.
        let (_a, _b, mut c) = channel();
        let victim_chain = sender_chain(&GROUP_KEY, 1); // any member can compute this
        let mk = hash_labeled(MK_LABEL, &victim_chain);
        let ciphertext = aead::seal(&mk, &nonce(0), b"i am member 1").unwrap();
        // The attacker signs with its OWN key (it lacks member 1's signing key).
        let (attacker_sk, _) = keypair(9);
        let signature = attacker_sk.sign(&signed_bytes(1, 0, &ciphertext));
        let mut forged = Vec::new();
        forged.extend_from_slice(&0u64.to_le_bytes());
        forged.extend_from_slice(&ciphertext);
        forged.extend_from_slice(&signature.to_bytes());
        assert!(c.recv(1, &forged).is_none(), "a post not signed by member 1's key cannot be attributed to them");
    }

    #[test]
    fn a_post_cannot_be_relabeled_to_a_different_sender() {
        // A genuine post from member 1, delivered as if from member 2, fails (the signature is over sender 1).
        let (mut a, _b, mut c) = channel();
        let post = a.send(b"members only");
        assert!(c.recv(2, &post).is_none(), "a genuine post cannot be re-attributed to another sender");
        assert_eq!(c.recv(1, &post).as_deref(), Some(&b"members only"[..]), "it still opens for its true sender");
    }

    #[test]
    fn a_non_member_sender_or_a_tampered_post_is_refused() {
        let (mut a, mut b, _c) = channel();
        let post = a.send(b"data");
        assert!(b.recv(99, &post).is_none(), "a post attributed to a non-member is refused");
        let mut bad = post.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF; // corrupt the signature
        assert!(b.recv(1, &bad).is_none(), "a tampered post is refused");
        assert_eq!(b.recv(1, &post).as_deref(), Some(&b"data"[..]), "the genuine post still opens");
    }
}
