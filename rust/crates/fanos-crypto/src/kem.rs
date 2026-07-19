//! Hybrid key encapsulation (spec §7.1, §L0).
//!
//! A FANOS identity's KEM key is **hybrid** — classical X25519 alongside post-quantum ML-KEM-768
//! (FIPS 203). Encapsulation runs both and derives the shared secret by a domain-separated BLAKE3 KDF
//! over both component secrets and the full ciphertext (a standard secure KEM combiner: the hybrid
//! stays IND-CCA as long as *either* component does). Keys derive deterministically from a 32-byte
//! identity seed and encapsulation is driven by a caller seed, so key agreement is reproducible in the
//! deterministic simulator — no ambient randomness.
//!
//! The vetted primitives are `x25519-dalek` and `fips203`; the composition is FANOS's (spec §L6).

use alloc::vec::Vec;

use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use rand_core::RngCore;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

use crate::hash::{hash_labeled, label, xof_reader};

/// X25519 public-key / shared-secret length.
pub const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation-key (public) length — FIPS 203.
pub const MLKEM768_EK_LEN: usize = ml_kem_768::EK_LEN;
/// ML-KEM-768 ciphertext length — FIPS 203.
pub const MLKEM768_CT_LEN: usize = ml_kem_768::CT_LEN;

/// Hybrid KEM public-key length: `X25519(32) ‖ ML-KEM-768-ek(1184)`.
pub const HYBRID_KEM_PK_LEN: usize = X25519_LEN + MLKEM768_EK_LEN;
/// Hybrid KEM ciphertext length: `X25519-ephemeral(32) ‖ ML-KEM-768-ct(1088)`.
pub const HYBRID_KEM_CT_LEN: usize = X25519_LEN + MLKEM768_CT_LEN;
/// Hybrid KEM shared-secret length.
pub const HYBRID_KEM_SS_LEN: usize = 32;

/// A deterministic CSPRNG: a domain-separated BLAKE3 XOF stream. ML-KEM encapsulation needs an RNG;
/// seeding it this way makes encapsulation reproducible while remaining a secure pseudo-random stream.
struct SeededRng(blake3::OutputReader);

impl SeededRng {
    fn new(seed: &[u8]) -> Self {
        Self(xof_reader(label::KEM_ENCAPS, seed))
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for SeededRng {}

/// The combiner: the hybrid shared secret is `KDF(ss_x25519 ‖ ss_mlkem ‖ ciphertext)`, binding both
/// component secrets and the full ciphertext under a domain-separated hash.
fn combine(ss_x: &[u8; 32], ss_m: &[u8; 32], ct: &[u8]) -> [u8; HYBRID_KEM_SS_LEN] {
    let mut input = Vec::with_capacity(64 + ct.len());
    input.extend_from_slice(ss_x);
    input.extend_from_slice(ss_m);
    input.extend_from_slice(ct);
    hash_labeled(label::KEM_COMBINE, &input)
}

/// A node's hybrid KEM key: an X25519 static secret and an ML-KEM-768 decapsulation key, both derived
/// (domain-separated) from one 32-byte identity seed. Holds the secret halves; the public bundle is
/// cached for publication.
pub struct HybridKemKey {
    x_secret: XSecret,
    mlkem_dk: ml_kem_768::DecapsKey,
    public: Vec<u8>, // X25519(32) ‖ ML-KEM-768-ek(1184)
}

impl HybridKemKey {
    /// Derive both component keys from one 32-byte identity seed (domain-separated per primitive).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let x_secret = XSecret::from(hash_labeled(label::KEM_X25519, seed));
        let x_public = XPublic::from(&x_secret);
        // ML-KEM keygen needs two 32-byte seeds (d, z): two draws of the derivation XOF.
        let mut r = xof_reader(label::KEM_MLKEM, seed);
        let (mut d, mut z) = ([0u8; 32], [0u8; 32]);
        r.fill(&mut d);
        r.fill(&mut z);
        let (ek, dk) = ml_kem_768::KG::keygen_from_seed(d, z);
        let mut public = Vec::with_capacity(HYBRID_KEM_PK_LEN);
        public.extend_from_slice(x_public.as_bytes());
        public.extend_from_slice(&ek.into_bytes());
        Self { x_secret, mlkem_dk: dk, public }
    }

    /// The public KEM bundle `X25519(32) ‖ ML-KEM-768-ek(1184)` to publish in the identity.
    #[must_use]
    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    /// Decapsulate a hybrid ciphertext to the shared secret. `None` on a malformed ciphertext.
    #[must_use]
    pub fn decapsulate(&self, ct: &[u8]) -> Option<[u8; HYBRID_KEM_SS_LEN]> {
        let ct_x: [u8; X25519_LEN] = ct.get(..X25519_LEN)?.try_into().ok()?;
        let ct_m: [u8; MLKEM768_CT_LEN] = ct.get(X25519_LEN..HYBRID_KEM_CT_LEN)?.try_into().ok()?;
        let ss_x = self.x_secret.diffie_hellman(&XPublic::from(ct_x)).to_bytes();
        let cipher = ml_kem_768::CipherText::try_from_bytes(ct_m).ok()?;
        let ss_m = self.mlkem_dk.try_decaps(&cipher).ok()?.into_bytes();
        Some(combine(&ss_x, &ss_m, ct))
    }
}

/// Encapsulate to a recipient's hybrid KEM public bundle, deterministically from `enc_seed`. Returns
/// the ciphertext `X25519-ephemeral(32) ‖ ML-KEM-768-ct(1088)` and the shared secret. `None` on a
/// malformed recipient key or an ML-KEM encapsulation error.
#[must_use]
pub fn hybrid_encapsulate(
    recipient_public: &[u8],
    enc_seed: &[u8],
) -> Option<(Vec<u8>, [u8; HYBRID_KEM_SS_LEN])> {
    let x_pub: [u8; X25519_LEN] = recipient_public.get(..X25519_LEN)?.try_into().ok()?;
    let ek_bytes: [u8; MLKEM768_EK_LEN] =
        recipient_public.get(X25519_LEN..HYBRID_KEM_PK_LEN)?.try_into().ok()?;

    // One deterministic randomness stream for the whole encapsulation.
    let mut rng = SeededRng::new(enc_seed);
    // X25519: a fresh ephemeral secret from the stream; the ciphertext is its public key.
    let mut eph_seed = [0u8; 32];
    rng.fill_bytes(&mut eph_seed);
    let eph_secret = XSecret::from(eph_seed);
    let eph_public = XPublic::from(&eph_secret);
    let ss_x = eph_secret.diffie_hellman(&XPublic::from(x_pub)).to_bytes();
    // ML-KEM: encapsulate to the recipient's encapsulation key using the same stream.
    let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes).ok()?;
    let (ssk, cipher) = ek.try_encaps_with_rng(&mut rng).ok()?;
    let ss_m = ssk.into_bytes();

    let mut ct = Vec::with_capacity(HYBRID_KEM_CT_LEN);
    ct.extend_from_slice(eph_public.as_bytes());
    ct.extend_from_slice(&cipher.into_bytes());
    let shared = combine(&ss_x, &ss_m, &ct);
    Some((ct, shared))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kem_round_trips() {
        let recipient = HybridKemKey::from_seed(&[1u8; 32]);
        assert_eq!(recipient.public_bytes().len(), HYBRID_KEM_PK_LEN);
        let (ct, ss_sender) = hybrid_encapsulate(recipient.public_bytes(), b"encaps-seed-A").unwrap();
        assert_eq!(ct.len(), HYBRID_KEM_CT_LEN);
        let ss_recipient = recipient.decapsulate(&ct).unwrap();
        assert_eq!(ss_sender, ss_recipient, "sender and recipient derive the same shared secret");
    }

    #[test]
    fn a_tampered_ciphertext_does_not_reproduce_the_secret() {
        let recipient = HybridKemKey::from_seed(&[2u8; 32]);
        let (base, ss) = hybrid_encapsulate(recipient.public_bytes(), b"seed").unwrap();
        // Flip a byte in the X25519 half, then one in the ML-KEM half.
        for pos in [0usize, X25519_LEN + 10] {
            let mut ct = base.clone();
            ct[pos] ^= 0x01;
            assert_ne!(recipient.decapsulate(&ct).unwrap(), ss, "tamper at {pos} changes the secret");
        }
    }

    #[test]
    fn the_wrong_key_does_not_recover_the_secret() {
        let recipient = HybridKemKey::from_seed(&[3u8; 32]);
        let (ct, ss) = hybrid_encapsulate(recipient.public_bytes(), b"seed").unwrap();
        let other = HybridKemKey::from_seed(&[4u8; 32]);
        assert_ne!(other.decapsulate(&ct).unwrap(), ss, "a different key derives a different secret");
    }

    #[test]
    fn keys_and_encapsulation_are_deterministic_from_seeds() {
        assert_eq!(
            HybridKemKey::from_seed(&[5u8; 32]).public_bytes(),
            HybridKemKey::from_seed(&[5u8; 32]).public_bytes(),
            "same seed → same public bundle",
        );
        let r = HybridKemKey::from_seed(&[6u8; 32]);
        let a = hybrid_encapsulate(r.public_bytes(), b"same-seed").unwrap();
        let b = hybrid_encapsulate(r.public_bytes(), b"same-seed").unwrap();
        assert_eq!(a.0, b.0, "same seed → same ciphertext");
        assert_eq!(a.1, b.1, "same seed → same shared secret");
        let c = hybrid_encapsulate(r.public_bytes(), b"different-seed").unwrap();
        assert_ne!(a.0, c.0, "different seed → different ciphertext");
    }

    #[test]
    fn rejects_malformed_inputs_without_panicking() {
        let r = HybridKemKey::from_seed(&[7u8; 32]);
        assert!(hybrid_encapsulate(b"too-short", b"seed").is_none(), "short recipient key rejected");
        assert!(r.decapsulate(b"too-short").is_none(), "short ciphertext rejected");
    }
}
