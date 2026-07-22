//! The **forward-secret post-quantum end-to-end session** — ANGELOS's message-encryption core.
//!
//! A session is established by a hybrid-ML-KEM handshake: the initiator encapsulates to the responder's KEM
//! public key, both derive the same shared secret, and from it a **root key** and two directional **chain
//! keys** (one per direction). Each message advances its direction's chain by a one-way BLAKE3 step, deriving a
//! fresh **message key**; the plaintext is sealed under it with ChaCha20-Poly1305. Because the chain is one-way,
//! a compromised chain (or message) key reveals only *current and future* keys, never *past* ones — **forward
//! secrecy**. The AEAD tag authenticates each message, so a forged or tampered ciphertext fails to open and does
//! not desync the chain; a replayed message number is refused.
//!
//! *Scope:* this is the symmetric-ratchet half. In-order delivery is assumed (an out-of-order message number is
//! refused rather than key-skipped); skipped-key handling and the asymmetric KEM ratchet (post-compromise
//! security — the double-ratchet's healing step) compose on top.

use alloc::vec::Vec;

use fanos_pqcrypto::SeedRng;
use fanos_pqcrypto::kem::{HybridCiphertext, HybridKemPublic, HybridKemSecret};
use fanos_primitives::{aead, hash_labeled};

use crate::nonce;

/// Label deriving the root key from the KEM shared secret.
const ROOT_LABEL: &str = "FANOS-angelos-v1/root";
/// Label for the initiator→responder chain.
const A2B_LABEL: &str = "FANOS-angelos-v1/a2b";
/// Label for the responder→initiator chain.
const B2A_LABEL: &str = "FANOS-angelos-v1/b2a";
/// Label deriving a message key from a chain key.
const MK_LABEL: &str = "FANOS-angelos-v1/mk";
/// Label advancing a chain key.
const NEXT_LABEL: &str = "FANOS-angelos-v1/next";

/// Which end of the session this party is — it fixes which chain is *send* and which is *receive*.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// The party that encapsulated the handshake.
    Initiator,
    /// The party that decapsulated it.
    Responder,
}

/// A live end-to-end session: a send chain, a receive chain, and their message counters.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Session {
    send_chain: [u8; 32],
    recv_chain: [u8; 32],
    send_n: u64,
    recv_n: u64,
}

impl Session {
    /// **Initiate** a session to a recipient's KEM public key: encapsulate (with `rng_seed` for the encapsulation
    /// randomness — a fresh CSPRNG in production, a fixed seed in tests), returning the session and the handshake
    /// ciphertext to deliver to the recipient. `None` only if the key is non-contributory.
    #[must_use]
    pub fn initiate(recipient_kem: &HybridKemPublic, rng_seed: &[u8]) -> Option<(Self, Vec<u8>)> {
        let mut rng = SeedRng::from_seed(rng_seed);
        let (ct, shared) = recipient_kem.encapsulate(&mut rng)?;
        Some((Self::from_shared_secret(&shared, Role::Initiator), ct.to_bytes()))
    }

    /// **Respond** to a handshake: decapsulate it with the recipient's KEM secret, deriving the mirror session.
    /// `None` if the handshake bytes are malformed.
    #[must_use]
    pub fn respond(kem_secret: &HybridKemSecret, handshake: &[u8]) -> Option<Self> {
        let ct = HybridCiphertext::from_bytes(handshake)?;
        let shared = kem_secret.decapsulate(&ct)?;
        Some(Self::from_shared_secret(&shared, Role::Responder))
    }

    /// Open a session directly over an already-agreed 32-byte `shared` secret — the **seam** between key
    /// agreement and the symmetric ratchet. The KEM handshake ([`initiate`](Self::initiate)/
    /// [`respond`](Self::respond)) is one way to reach a shared secret; a group rekey, a pre-shared key, or the
    /// asymmetric KEM-ratchet step (post-compromise security) are others — all feed the same ratchet through
    /// here. Both parties must pass the same secret and *opposite* [`Role`]s. This mirrors the raw-secret
    /// constructors of [`crate::group`] and [`crate::media`], and is the construction the conformance KAT pins.
    #[must_use]
    pub fn from_shared_secret(shared: &[u8; 32], role: Role) -> Self {
        let root = hash_labeled(ROOT_LABEL, shared);
        let a2b = hash_labeled(A2B_LABEL, &root);
        let b2a = hash_labeled(B2A_LABEL, &root);
        let (send_chain, recv_chain) = match role {
            Role::Initiator => (a2b, b2a),
            Role::Responder => (b2a, a2b),
        };
        Self { send_chain, recv_chain, send_n: 0, recv_n: 0 }
    }

    /// Seal `plaintext` as the next outgoing message: derive a fresh message key, advance the send chain, and
    /// AEAD-encrypt. Returns `message_number(8) ‖ ciphertext`.
    #[must_use]
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
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

    /// Open the next incoming message ([`seal`](Self::seal) output). `None` if it is malformed, out of order
    /// (its number is not the next expected — this core assumes in-order delivery), or fails authentication (a
    /// forgery or tamper) — and in those cases the receive chain is **not** advanced, so the genuine next
    /// message still opens.
    #[must_use]
    pub fn open(&mut self, sealed: &[u8]) -> Option<Vec<u8>> {
        let n = u64::from_le_bytes(sealed.get(..8)?.try_into().ok()?);
        if n != self.recv_n {
            return None;
        }
        let mk = hash_labeled(MK_LABEL, &self.recv_chain);
        let plaintext = aead::open(&mk, &nonce(n), sealed.get(8..)?)?;
        // Only advance on a successful open, so a forged message cannot desync the chain.
        self.recv_chain = hash_labeled(NEXT_LABEL, &self.recv_chain);
        self.recv_n = self.recv_n.saturating_add(1);
        Some(plaintext)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A recipient KEM keypair from a seed.
    fn keypair(tag: u8) -> (HybridKemSecret, HybridKemPublic) {
        let mut rng = SeedRng::from_seed(&[0xE0, tag]);
        HybridKemSecret::generate(&mut rng)
    }

    /// Establish a matched initiator/responder session pair to `(kem_secret, kem_public)`.
    fn establish(secret: &HybridKemSecret, public: &HybridKemPublic) -> (Session, Session) {
        let (initiator, handshake) = Session::initiate(public, b"handshake-seed").expect("initiate");
        let responder = Session::respond(secret, &handshake).expect("respond");
        (initiator, responder)
    }

    #[test]
    fn a_session_carries_messages_both_ways() {
        let (sk, pk) = keypair(1);
        let (mut alice, mut bob) = establish(&sk, &pk);
        // Alice → Bob.
        let m1 = alice.seal(b"hello bob");
        assert_eq!(bob.open(&m1).as_deref(), Some(&b"hello bob"[..]));
        // Bob → Alice.
        let r1 = bob.seal(b"hi alice");
        assert_eq!(alice.open(&r1).as_deref(), Some(&b"hi alice"[..]));
        // A stream of messages one way stays in order.
        for i in 0..5u8 {
            let msg = alloc::vec![i; 40];
            let sealed = alice.seal(&msg);
            assert_eq!(bob.open(&sealed).as_deref(), Some(msg.as_slice()), "message {i} opens in order");
        }
    }

    #[test]
    fn each_message_gets_a_fresh_key_forward_secrecy() {
        let (sk, pk) = keypair(1);
        let (mut alice, _bob) = establish(&sk, &pk);
        let chain0 = alice.send_chain;
        let _ = alice.seal(b"m0");
        let chain1 = alice.send_chain;
        assert_ne!(chain0, chain1, "the send chain ratchets forward per message");
        // Two messages seal under different keys (different ciphertext for the same plaintext).
        let (mut a2, _b2) = establish(&sk, &pk);
        let c0 = a2.seal(b"same");
        let c1 = a2.seal(b"same");
        assert_ne!(c0, c1, "the same plaintext seals differently at each ratchet step");
    }

    #[test]
    fn a_wrong_recipient_cannot_decrypt() {
        let (sk, pk) = keypair(1);
        let (mut alice, _bob) = establish(&sk, &pk);
        // Eve holds a different KEM secret; responding to the handshake yields a different shared secret.
        let (eve_sk, _eve_pk) = keypair(2);
        let (_i, handshake) = Session::initiate(&pk, b"handshake-seed").unwrap();
        let mut eve = Session::respond(&eve_sk, &handshake).expect("eve decapsulates (to the wrong key)");
        let m = alice.seal(b"secret");
        assert!(eve.open(&m).is_none(), "the wrong recipient's session cannot open the message");
    }

    #[test]
    fn a_tampered_message_fails_to_open_without_desyncing() {
        let (sk, pk) = keypair(1);
        let (mut alice, mut bob) = establish(&sk, &pk);
        let mut m1 = alice.seal(b"first");
        let m2 = alice.seal(b"second");
        // Tamper with the first message's ciphertext (flip a byte past the 8-byte number).
        let last = m1.len() - 1;
        m1[last] ^= 0xFF;
        assert!(bob.open(&m1).is_none(), "a tampered message does not open");
        // The chain did not advance, so Bob still expects message 0; the untampered `second` is message 1,
        // hence out of order for this in-order core (skipped-key handling is the documented follow-up).
        assert!(bob.open(&m2).is_none(), "message 1 is out of order while 0 is still pending (in-order core)");
    }

    #[test]
    fn out_of_order_and_replayed_messages_are_refused() {
        let (sk, pk) = keypair(1);
        let (mut alice, mut bob) = establish(&sk, &pk);
        let m0 = alice.seal(b"zero");
        let m1 = alice.seal(b"one");
        // Delivering message 1 before 0 is refused (in-order core).
        assert!(bob.open(&m1).is_none(), "out-of-order is refused");
        // In order works.
        assert_eq!(bob.open(&m0).as_deref(), Some(&b"zero"[..]));
        assert_eq!(bob.open(&m1).as_deref(), Some(&b"one"[..]));
        // Replaying message 0 (now behind the counter) is refused.
        assert!(bob.open(&m0).is_none(), "a replay is refused");
    }
}
