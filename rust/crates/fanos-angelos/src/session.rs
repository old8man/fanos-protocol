//! The **forward-secret post-quantum end-to-end session** — ANGELOS's message-encryption core.
//!
//! A session is established by a hybrid-ML-KEM handshake: the initiator encapsulates to the responder's KEM
//! public key, both derive the same shared secret, and from it a **root key** and two directional **chain
//! keys** (one per direction). Each message advances its direction's chain by a one-way BLAKE3 step, deriving a
//! fresh **message key**; the plaintext is sealed under it with ChaCha20-Poly1305. Because the chain is one-way,
//! a compromised chain (or message) key reveals only *current and future* keys, never *past* ones — **forward
//! secrecy**. The AEAD tag authenticates each message, so a forged or tampered ciphertext fails to open and does
//! not desync the chain.
//!
//! Delivery need not be in order: the receive chain is a [`crate::chain::RecvChain`], which opens a later message
//! ahead of the ones it skipped (banking their keys) and a delayed one from its banked key — bounded, so a
//! replay or a forgery is still refused and neither advances the chain. This is the symmetric-ratchet half; the
//! asymmetric KEM ratchet (post-compromise security) builds on it in [`crate::ratchet`].

use alloc::vec::Vec;

use fanos_pqcrypto::SeedRng;
use fanos_pqcrypto::kem::{HybridCiphertext, HybridKemPublic, HybridKemSecret};
use fanos_primitives::{aead, hash_labeled};

use crate::chain::{ChainKdf, RecvChain, SendChain};
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
/// The chain-stepping labels for a session's directional chains.
const CHAIN_KDF: ChainKdf = ChainKdf { mk: MK_LABEL, next: NEXT_LABEL };

/// Which end of the session this party is — it fixes which chain is *send* and which is *receive*.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// The party that encapsulated the handshake.
    Initiator,
    /// The party that decapsulated it.
    Responder,
}

/// A live end-to-end session: a send chain and a receive chain (out-of-order tolerant). Not `Clone` — cloning a
/// live session would risk sealing two messages under the same key.
pub struct Session {
    send: SendChain,
    recv: RecvChain,
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
        let (send_key, recv_key) = match role {
            Role::Initiator => (a2b, b2a),
            Role::Responder => (b2a, a2b),
        };
        Self { send: SendChain::new(send_key, CHAIN_KDF), recv: RecvChain::new(recv_key, CHAIN_KDF) }
    }

    /// Seal `plaintext` as the next outgoing message: take a fresh message key, advance the send chain, and
    /// AEAD-encrypt. Returns `message_number(8) ‖ ciphertext`.
    #[must_use]
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let (n, mk) = self.send.pop();
        let ciphertext = aead::seal(&mk, &nonce(n), plaintext).unwrap_or_default();
        let mut out = Vec::with_capacity(8 + ciphertext.len());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Open an incoming message ([`seal`](Self::seal) output), in order, ahead of skipped messages, or behind
    /// (from a banked key). `None` if it is malformed, skips too far ahead, is a replay/already-consumed number,
    /// or fails authentication (a forgery or tamper) — and in those cases no state is advanced or consumed, so
    /// the genuine message still opens.
    #[must_use]
    pub fn open(&mut self, sealed: &[u8]) -> Option<Vec<u8>> {
        let n = u64::from_le_bytes(sealed.get(..8)?.try_into().ok()?);
        self.recv.open(n, sealed.get(8..)?)
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
        // The same plaintext seals differently at each step — the send chain ratchets forward per message.
        let (mut alice, _bob) = establish(&sk, &pk);
        let c0 = alice.seal(b"same");
        let c1 = alice.seal(b"same");
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
        let m0 = alice.seal(b"first");
        let m1 = alice.seal(b"second");
        // A tampered copy of message 0 does not open and does not disturb the chain.
        let mut bad = m0.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(bob.open(&bad).is_none(), "a tampered message does not open");
        // Message 1 still opens ahead of the missing 0 (banking 0's key)...
        assert_eq!(bob.open(&m1).as_deref(), Some(&b"second"[..]), "a later message opens ahead of a gap");
        // ...and the genuine message 0 then opens from its banked key — no desync.
        assert_eq!(bob.open(&m0).as_deref(), Some(&b"first"[..]), "the delayed message opens from its banked key");
    }

    #[test]
    fn out_of_order_is_tolerated_and_replays_refused() {
        let (sk, pk) = keypair(1);
        let (mut alice, mut bob) = establish(&sk, &pk);
        let m0 = alice.seal(b"zero");
        let m1 = alice.seal(b"one");
        let m2 = alice.seal(b"two");
        // Deliver out of order: 2, then 0, then 1 — all open.
        assert_eq!(bob.open(&m2).as_deref(), Some(&b"two"[..]), "a message opens ahead of the ones it skips");
        assert_eq!(bob.open(&m0).as_deref(), Some(&b"zero"[..]), "a skipped message opens from its banked key");
        assert_eq!(bob.open(&m1).as_deref(), Some(&b"one"[..]));
        // Replaying any of them is refused — each banked key is consumed on use.
        assert!(bob.open(&m0).is_none(), "a replay is refused");
        assert!(bob.open(&m2).is_none(), "a replay of the highest is refused");
    }
}
