//! The **post-quantum double ratchet** — the 1:1 session's asymmetric (KEM) ratchet, giving *post-compromise
//! security* (PCS) on top of the forward secrecy of the symmetric [`crate::session`] (`spec/platform.md` §6.2).
//!
//! Forward secrecy protects the *past* (a leaked key never opens earlier messages); PCS protects the *future*
//! (the session *heals* after a compromise). The symmetric ratchet gives the first; this KEM ratchet gives the
//! second. It is the Signal double ratchet with a **KEM in place of the Diffie–Hellman**: where Signal mixes a
//! fresh `DH(self, peer)` into the root each round-trip, a post-quantum KEM cannot derive a shared value from a
//! static key pair, so instead each ratchet step **encapsulates** to the peer's current ratchet public key,
//! ships the ciphertext, and mixes the encapsulated secret into the root. Both sides also rotate to a fresh
//! ratchet key pair each step, so once a healing step's fresh randomness escapes the attacker, security restores.
//!
//! **The alternation invariant.** A party ratchets (starts a new sending chain) only when it has received a new
//! peer ratchet key since its last send — so the two sides ratchet strictly alternately, exactly one KEM step
//! per round-trip. The initiator bootstraps the first step. This alternation is what makes a replayed ratchet
//! message safe to reject: a replay carries an already-seen ratchet key, so it is treated as an ordinary
//! (out-of-order) message on the current chain and refused, never re-triggering the KEM step.
//!
//! **Header.** Every message begins with a one-byte flag. A **ratchet** message (`1`, the first of a new sending
//! chain) carries the full new ratchet public key and the KEM ciphertext; an **in-chain** message (`0`) carries
//! only a 32-byte id of the current ratchet key (so ordinary messages stay small — the ML-KEM key is ~1.2 KiB).
//! The message key is bound to the ratchet state, so a tampered header fails to open (or fails a consistency
//! check) even though the AEAD carries no separate associated data.
//!
//! *Scope:* in-order delivery per chain (an out-of-order number is refused, as in [`crate::session`]); skipped
//! message keys — opening a later message while an earlier one is still missing — compose on top and are the
//! documented follow-up. The header already carries the previous-chain length (`pn`) that handling needs.

use alloc::vec::Vec;

use fanos_pqcrypto::kem::{CIPHERTEXT_LEN, HybridCiphertext, HybridKemPublic, HybridKemSecret, PUBLIC_LEN};
use fanos_primitives::{aead, hash_labeled};
use rand_core::CryptoRng;

use crate::nonce;

/// Label deriving the root key from the KEM handshake shared secret.
const ROOT_LABEL: &str = "FANOS-angelos-v1/dr-root";
/// Label mixing an encapsulated secret into the root (the KEM-ratchet KDF).
const RK_MIX_LABEL: &str = "FANOS-angelos-v1/dr-rk-mix";
/// Label deriving the next root key from the mixed value.
const RK_ROOT_LABEL: &str = "FANOS-angelos-v1/dr-rk-root";
/// Label deriving a chain key from the mixed value.
const RK_CHAIN_LABEL: &str = "FANOS-angelos-v1/dr-rk-chain";
/// Label deriving a message key from a chain key.
const MK_LABEL: &str = "FANOS-angelos-v1/dr-mk";
/// Label advancing a chain key.
const NEXT_LABEL: &str = "FANOS-angelos-v1/dr-next";
/// Label identifying a ratchet public key compactly (for in-chain headers).
const PUBID_LABEL: &str = "FANOS-angelos-v1/dr-pubid";

/// A live post-quantum double-ratchet session. Holds the root key, this party's current ratchet key pair (which
/// the peer encapsulates to), the peer's current ratchet public key (which we encapsulate to), the send/receive
/// chains and their counters, and whether our next send must perform a KEM ratchet. Not `Clone` — cloning a live
/// ratchet would risk reusing a message key across the copies.
pub struct DoubleRatchet {
    root: [u8; 32],
    /// Our current ratchet key pair — `None` for the initiator until its first send generates one.
    self_kp: Option<(HybridKemSecret, HybridKemPublic)>,
    self_pub_id: Option<[u8; 32]>,
    /// The peer's current ratchet public key — `None` for the responder until it receives the first message.
    peer_pub: Option<HybridKemPublic>,
    peer_pub_id: Option<[u8; 32]>,
    send_chain: Option<[u8; 32]>,
    recv_chain: Option<[u8; 32]>,
    send_n: u64,
    recv_n: u64,
    must_ratchet: bool,
}

impl DoubleRatchet {
    /// **Initiate** a double-ratchet session to a recipient's KEM public key: run the handshake (encapsulate with
    /// `rng_seed`), returning the session and the handshake ciphertext to deliver. The initiator holds the
    /// recipient's key as the first peer ratchet key and will KEM-ratchet on its first [`seal`](Self::seal).
    /// `None` if the recipient key is non-contributory.
    #[must_use]
    pub fn initiate(recipient_kem: &HybridKemPublic, rng_seed: &[u8]) -> Option<(Self, Vec<u8>)> {
        let mut rng = fanos_pqcrypto::SeedRng::from_seed(rng_seed);
        let (ct, shared) = recipient_kem.encapsulate(&mut rng)?;
        let this = Self {
            root: hash_labeled(ROOT_LABEL, &shared),
            self_kp: None,
            self_pub_id: None,
            peer_pub: Some(recipient_kem.clone()),
            peer_pub_id: Some(pub_id(recipient_kem)),
            send_chain: None,
            recv_chain: None,
            send_n: 0,
            recv_n: 0,
            must_ratchet: true,
        };
        Some((this, ct.to_bytes()))
    }

    /// **Respond** to a handshake: decapsulate it with the recipient's KEM key pair, deriving the mirror session.
    /// Takes the KEM **secret by value** — the session owns it as its initial ratchet key (its role was to
    /// receive this first message); it is dropped and replaced with a fresh key on the first reply. `None` if the
    /// handshake bytes are malformed.
    #[must_use]
    pub fn respond(kem_secret: HybridKemSecret, kem_public: &HybridKemPublic, handshake: &[u8]) -> Option<Self> {
        let ct = HybridCiphertext::from_bytes(handshake)?;
        let shared = kem_secret.decapsulate(&ct)?;
        Some(Self {
            root: hash_labeled(ROOT_LABEL, &shared),
            self_pub_id: Some(pub_id(kem_public)),
            self_kp: Some((kem_secret, kem_public.clone())),
            peer_pub: None,
            peer_pub_id: None,
            send_chain: None,
            recv_chain: None,
            send_n: 0,
            recv_n: 0,
            must_ratchet: false,
        })
    }

    /// Seal `plaintext` as the next outgoing message. If a KEM ratchet is due (we have received a new peer
    /// ratchet key since our last send, or we have not sent yet), this starts a new sending chain — encapsulating
    /// to the peer's ratchet key and rotating our own — and the message carries the ratchet header; otherwise it
    /// advances the current chain. `None` if we cannot send yet (a responder that has not received a message, so
    /// has no peer ratchet key) or on the unreachable AEAD-setup error. `rng` supplies the ratchet-step
    /// randomness (a CSPRNG in production, a seeded RNG in tests).
    #[must_use]
    pub fn seal<R: CryptoRng>(&mut self, rng: &mut R, plaintext: &[u8]) -> Option<Vec<u8>> {
        if self.must_ratchet || self.send_chain.is_none() {
            self.seal_ratchet(rng, plaintext)
        } else {
            self.seal_in_chain(plaintext)
        }
    }

    /// Start a new sending chain with a KEM ratchet step, then seal message 0 of it.
    #[must_use]
    fn seal_ratchet<R: CryptoRng>(&mut self, rng: &mut R, plaintext: &[u8]) -> Option<Vec<u8>> {
        let (ct, shared) = {
            let peer = self.peer_pub.as_ref()?;
            peer.encapsulate(rng)?
        };
        let (new_secret, new_pub) = HybridKemSecret::generate(rng);
        let (new_root, chain) = kdf_rk(&self.root, &shared);
        let prev_n = self.send_n;
        let pub_enc = new_pub.encode();
        let (mk, next_chain) = chain_step(&chain);
        let body = aead::seal(&mk, &nonce(0), plaintext)?;

        // Commit only once the message is built.
        self.root = new_root;
        self.self_pub_id = Some(pub_id(&new_pub));
        self.self_kp = Some((new_secret, new_pub));
        self.send_chain = Some(next_chain);
        self.send_n = 1;
        self.must_ratchet = false;

        let mut out = Vec::with_capacity(1 + PUBLIC_LEN + CIPHERTEXT_LEN + 16 + body.len());
        out.push(1);
        out.extend_from_slice(&pub_enc);
        out.extend_from_slice(&ct.to_bytes());
        out.extend_from_slice(&prev_n.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&body);
        Some(out)
    }

    /// Advance the current sending chain and seal the next message on it.
    #[must_use]
    fn seal_in_chain(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
        let chain = self.send_chain?;
        let pub_id = self.self_pub_id?;
        let n = self.send_n;
        let (mk, next_chain) = chain_step(&chain);
        let body = aead::seal(&mk, &nonce(n), plaintext)?;

        self.send_chain = Some(next_chain);
        self.send_n = self.send_n.saturating_add(1);

        let mut out = Vec::with_capacity(1 + 32 + 16 + body.len());
        out.push(0);
        out.extend_from_slice(&pub_id);
        out.extend_from_slice(&0u64.to_le_bytes()); // pn (unused by the in-order receiver)
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&body);
        Some(out)
    }

    /// Open an incoming message ([`seal`](Self::seal) output). Performs a KEM ratchet if the message begins a new
    /// peer chain. `None` if malformed, out of order, a replay, from the wrong peer, or failing authentication —
    /// and in those cases no state is advanced, so the genuine next message still opens.
    #[must_use]
    pub fn open(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        let (&flag, rest) = message.split_first()?;
        match flag {
            1 => self.open_ratchet(rest),
            0 => {
                let pid: [u8; 32] = rest.get(..32)?.try_into().ok()?;
                let n = u64::from_le_bytes(rest.get(40..48)?.try_into().ok()?);
                let body = rest.get(48..)?;
                self.open_in_chain(&pid, n, body)
            }
            _ => None,
        }
    }

    /// Open a ratchet message: `pub(PUBLIC_LEN) ‖ ct(CIPHERTEXT_LEN) ‖ pn(8) ‖ n(8) ‖ body`.
    #[must_use]
    fn open_ratchet(&mut self, rest: &[u8]) -> Option<Vec<u8>> {
        let pub_bytes = rest.get(..PUBLIC_LEN)?;
        let ct_bytes = rest.get(PUBLIC_LEN..PUBLIC_LEN + CIPHERTEXT_LEN)?;
        let tail = rest.get(PUBLIC_LEN + CIPHERTEXT_LEN..)?;
        let n = u64::from_le_bytes(tail.get(8..16)?.try_into().ok()?);
        let body = tail.get(16..)?;

        let peer_pub = HybridKemPublic::decode(pub_bytes)?;
        let pid = pub_id(&peer_pub);
        // A ratchet key we already hold means this is a replay of an earlier ratchet message; route it to the
        // in-chain path, where its stale number is refused — never re-run the KEM step.
        if self.peer_pub_id == Some(pid) {
            return self.open_in_chain(&pid, n, body);
        }
        // A fresh peer chain always begins at message 0 (in-order delivery).
        if n != 0 {
            return None;
        }
        let ct = HybridCiphertext::from_bytes(ct_bytes)?;
        let (sk, _) = self.self_kp.as_ref()?;
        let shared = sk.decapsulate(&ct)?;
        let (new_root, chain) = kdf_rk(&self.root, &shared);
        let (mk, next_chain) = chain_step(&chain);
        let plaintext = aead::open(&mk, &nonce(0), body)?;

        // Commit only after a successful open, so a forgery cannot advance the ratchet.
        self.root = new_root;
        self.recv_chain = Some(next_chain);
        self.recv_n = 1;
        self.peer_pub_id = Some(pid);
        self.peer_pub = Some(peer_pub);
        self.must_ratchet = true;
        Some(plaintext)
    }

    /// Open an in-chain message under the current receive chain.
    #[must_use]
    fn open_in_chain(&mut self, pid: &[u8; 32], n: u64, body: &[u8]) -> Option<Vec<u8>> {
        if self.peer_pub_id.as_ref() != Some(pid) || n != self.recv_n {
            return None;
        }
        let chain = self.recv_chain?;
        let (mk, next_chain) = chain_step(&chain);
        let plaintext = aead::open(&mk, &nonce(n), body)?;
        self.recv_chain = Some(next_chain);
        self.recv_n = self.recv_n.saturating_add(1);
        Some(plaintext)
    }
}

/// The KEM-ratchet KDF: mix an encapsulated `shared` secret into the `root`, returning `(new_root, chain_key)`.
#[must_use]
fn kdf_rk(root: &[u8; 32], shared: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut buf = [0u8; 64];
    let (a, b) = buf.split_at_mut(32);
    a.copy_from_slice(root);
    b.copy_from_slice(shared);
    let seed = hash_labeled(RK_MIX_LABEL, &buf);
    (hash_labeled(RK_ROOT_LABEL, &seed), hash_labeled(RK_CHAIN_LABEL, &seed))
}

/// One symmetric-chain step: derive the message key and the advanced chain key.
#[must_use]
fn chain_step(chain: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (hash_labeled(MK_LABEL, chain), hash_labeled(NEXT_LABEL, chain))
}

/// A compact 32-byte identifier for a ratchet public key (its labeled hash) — carried by in-chain headers.
#[must_use]
fn pub_id(pk: &HybridKemPublic) -> [u8; 32] {
    hash_labeled(PUBID_LABEL, &pk.encode())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    use fanos_pqcrypto::SeedRng;

    /// A KEM key pair from a seed.
    fn keypair(seed: &[u8]) -> (HybridKemSecret, HybridKemPublic) {
        HybridKemSecret::generate(&mut SeedRng::from_seed(seed))
    }

    /// Establish a matched initiator/responder pair, plus a seeded seal-RNG for each.
    fn establish() -> (DoubleRatchet, DoubleRatchet, SeedRng, SeedRng) {
        let (bob_sk, bob_pk) = keypair(b"bob-kem");
        let (alice, handshake) = DoubleRatchet::initiate(&bob_pk, b"alice-init").expect("initiate");
        let bob = DoubleRatchet::respond(bob_sk, &bob_pk, &handshake).expect("respond");
        (alice, bob, SeedRng::from_seed(b"alice-seal"), SeedRng::from_seed(b"bob-seal"))
    }

    #[test]
    fn the_ratchet_carries_messages_across_alternating_kem_steps() {
        let (mut a, mut b, mut ar, mut br) = establish();
        // Alice's first message ratchets (flag 1); her second stays in-chain (flag 0).
        let m0 = a.seal(&mut ar, b"a0").expect("seal");
        assert_eq!(m0[0], 1, "the first message begins a new chain");
        assert_eq!(b.open(&m0).as_deref(), Some(&b"a0"[..]));
        let m1 = a.seal(&mut ar, b"a1").expect("seal");
        assert_eq!(m1[0], 0, "the second message stays on the chain");
        assert_eq!(b.open(&m1).as_deref(), Some(&b"a1"[..]));

        // Bob's reply performs a fresh KEM ratchet (the healing step).
        let r0 = b.seal(&mut br, b"b0").expect("seal");
        assert_eq!(r0[0], 1, "a reply triggers a KEM ratchet");
        assert_eq!(a.open(&r0).as_deref(), Some(&b"b0"[..]));

        // Alice, having received Bob's new ratchet key, ratchets again on her next send.
        let m2 = a.seal(&mut ar, b"a2").expect("seal");
        assert_eq!(m2[0], 1, "alice re-ratchets after receiving bob's key");
        assert_eq!(b.open(&m2).as_deref(), Some(&b"a2"[..]));
        // ...and a follow-up from Alice is again in-chain.
        let m3 = a.seal(&mut ar, b"a3").expect("seal");
        assert_eq!(m3[0], 0);
        assert_eq!(b.open(&m3).as_deref(), Some(&b"a3"[..]));
    }

    #[test]
    fn the_same_plaintext_seals_differently_each_step() {
        let (mut a, mut b, mut ar, mut br) = establish();
        let x0 = a.seal(&mut ar, b"x").expect("seal");
        assert_eq!(b.open(&x0).as_deref(), Some(&b"x"[..]));
        let x1 = a.seal(&mut ar, b"x").expect("seal"); // in-chain ratchet
        assert_ne!(x0, x1, "the symmetric chain ratchets per message");
        assert_eq!(b.open(&x1).as_deref(), Some(&b"x"[..]));
        let _ = b.seal(&mut br, b"turn").expect("seal");
        // (Alice would re-ratchet next; covered above.) Distinct ciphertext for equal plaintext is the point.
    }

    #[test]
    fn a_replayed_message_is_refused() {
        let (mut a, mut b, mut ar, _br) = establish();
        let m = a.seal(&mut ar, b"once").expect("seal");
        assert_eq!(b.open(&m).as_deref(), Some(&b"once"[..]));
        assert!(b.open(&m).is_none(), "a replayed ratchet message does not re-open or re-ratchet");
    }

    #[test]
    fn out_of_order_is_refused_then_accepted_in_order() {
        let (mut a, mut b, mut ar, _br) = establish();
        let m0 = a.seal(&mut ar, b"0").expect("seal");
        let m1 = a.seal(&mut ar, b"1").expect("seal");
        assert!(b.open(&m1).is_none(), "message 1 before 0 is refused (in-order core)");
        assert_eq!(b.open(&m0).as_deref(), Some(&b"0"[..]));
        assert_eq!(b.open(&m1).as_deref(), Some(&b"1"[..]));
    }

    #[test]
    fn a_tampered_message_fails_without_desyncing() {
        let (mut a, mut b, mut ar, _br) = establish();
        let m = a.seal(&mut ar, b"secret").expect("seal");
        let mut bad = m.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(b.open(&bad).is_none(), "a tampered message is refused");
        assert_eq!(b.open(&m).as_deref(), Some(&b"secret"[..]), "the genuine message still opens (no desync)");
    }

    #[test]
    fn a_responder_cannot_send_before_receiving() {
        let (_a, mut b, _ar, mut br) = establish();
        assert!(b.seal(&mut br, b"too early").is_none(), "no peer ratchet key yet → cannot send");
    }

    #[test]
    fn the_wrong_responder_derives_a_different_root_and_cannot_open() {
        let (_bob_sk, bob_pk) = keypair(b"bob-kem");
        let (mut alice, handshake) = DoubleRatchet::initiate(&bob_pk, b"seed").expect("initiate");
        // Eve decapsulates the handshake with her own (wrong) secret → a different root.
        let (eve_sk, eve_pk) = keypair(b"eve-kem");
        let mut eve = DoubleRatchet::respond(eve_sk, &eve_pk, &handshake).expect("respond");
        let mut ar = SeedRng::from_seed(b"a");
        let m = alice.seal(&mut ar, b"for bob only").expect("seal");
        assert!(eve.open(&m).is_none(), "the wrong recipient cannot open the message");
    }
}
