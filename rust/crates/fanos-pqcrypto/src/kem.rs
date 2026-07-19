//! The hybrid KEM `X25519 ‖ ML-KEM-768` (spec §L6).
//!
//! An ephemeral X25519 exchange and an ML-KEM-768 encapsulation are run in parallel and their
//! shared secrets combined with SHAKE256, so the session key is secure if *either* primitive
//! is (classical hedge + post-quantum). This is the per-hop key establishment NYX needs.

use alloc::vec::Vec;

use ml_kem::array::Array;
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, KeySizeUser, MlKem768};
use rand_core::CryptoRng;
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use x25519_dalek::{PublicKey, StaticSecret};

type MlEncapKey = <MlKem768 as Kem>::EncapsulationKey;
type MlDecapKey = <MlKem768 as Kem>::DecapsulationKey;
type MlCiphertext = ml_kem::Ciphertext<MlKem768>;

const KEM_COMBINER_LABEL: &[u8] = b"FANOS-v1/hybrid-kem/X25519+ML-KEM-768";

/// A hybrid KEM secret (decapsulation) key.
pub struct HybridKemSecret {
    x25519: StaticSecret,
    mlkem: MlDecapKey,
}

/// A hybrid KEM public (encapsulation) key.
#[derive(Clone)]
pub struct HybridKemPublic {
    x25519: PublicKey,
    mlkem: MlEncapKey,
}

/// A hybrid KEM ciphertext: the ephemeral X25519 public key and the ML-KEM ciphertext.
pub struct HybridCiphertext {
    x25519_ephemeral: [u8; 32],
    mlkem: MlCiphertext,
}

/// A 32-byte session key derived from a hybrid encapsulation.
pub type SessionKey = [u8; 32];

/// Serialized hybrid-ciphertext length: `X25519 ephemeral (32) ‖ ML-KEM-768 ciphertext (1088)`.
pub const CIPHERTEXT_LEN: usize = 32 + 1088;

/// ML-KEM-768 encapsulation-key length (FIPS 203).
const MLKEM768_EK_LEN: usize = 1184;

/// Serialized hybrid public-key length: `X25519 (32) ‖ ML-KEM-768 encapsulation key (1184)`.
pub const PUBLIC_LEN: usize = 32 + MLKEM768_EK_LEN;

impl HybridCiphertext {
    /// Serialize to `CIPHERTEXT_LEN` bytes (for the wire).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CIPHERTEXT_LEN);
        out.extend_from_slice(&self.x25519_ephemeral);
        out.extend_from_slice(self.mlkem.as_slice());
        out
    }

    /// Parse from bytes; returns `None` on the wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CIPHERTEXT_LEN {
            return None;
        }
        let mut x25519_ephemeral = [0u8; 32];
        x25519_ephemeral.copy_from_slice(bytes.get(..32)?);
        let mlkem = MlCiphertext::try_from(bytes.get(32..)?).ok()?;
        Some(Self {
            x25519_ephemeral,
            mlkem,
        })
    }
}

/// Combine the two shared secrets into a 32-byte session key, **binding the full transcript** (X-Wing /
/// CFRG hybrid guidance, MAL-BIND-K,PK/CT): SHAKE256 over the two shared secrets *and* the ciphertext
/// (X25519 ephemeral ‖ ML-KEM ct) and the recipient's X25519 static key. Without the transcript the
/// combiner met only MAL-BIND-K, so a re-encapsulation could bind one key to two contexts (audit B5). The
/// ML-KEM encapsulation key is bound transitively — `mlkem_ss` is `decap(dk, ct)` and `ct = encap(ek)`, so
/// folding `mlkem_ss ‖ mlkem_ct` pins `ek`. Both encapsulate and decapsulate feed the identical bytes.
fn combine(
    x25519_ss: &[u8],
    mlkem_ss: &[u8],
    x25519_ephemeral: &[u8],
    mlkem_ct: &[u8],
    x25519_recipient_pk: &[u8],
) -> SessionKey {
    let mut hasher = Shake256::default();
    hasher.update(KEM_COMBINER_LABEL);
    hasher.update(x25519_ss);
    hasher.update(mlkem_ss);
    hasher.update(x25519_ephemeral);
    hasher.update(mlkem_ct);
    hasher.update(x25519_recipient_pk);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

impl HybridKemSecret {
    /// Generate a hybrid KEM keypair from a CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> (Self, HybridKemPublic) {
        let x_sk = StaticSecret::random_from_rng(rng);
        let x_pk = PublicKey::from(&x_sk);
        let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair_from_rng(rng);
        (
            Self {
                x25519: x_sk,
                mlkem: mlkem_dk,
            },
            HybridKemPublic {
                x25519: x_pk,
                mlkem: mlkem_ek,
            },
        )
    }

    /// Decapsulate a ciphertext to recover the session key (spec §L6).
    #[must_use]
    pub fn decapsulate(&self, ciphertext: &HybridCiphertext) -> SessionKey {
        let ephemeral = PublicKey::from(ciphertext.x25519_ephemeral);
        let x_ss = self.x25519.diffie_hellman(&ephemeral);
        let mlkem_ss = self.mlkem.decapsulate(&ciphertext.mlkem);
        // The recipient's own X25519 static public key (this node) — the same pk the sender encapsulated to.
        let recipient_pk = PublicKey::from(&self.x25519);
        combine(
            x_ss.as_bytes(),
            mlkem_ss.as_slice(),
            &ciphertext.x25519_ephemeral,
            ciphertext.mlkem.as_slice(),
            recipient_pk.as_bytes(),
        )
    }

    /// Derive a 32-byte, domain-separated secret subkey from this KEM secret — a one-way SHAKE256 KDF
    /// output that reveals nothing about the underlying key material. Use it to seed secret-keyed PRFs
    /// (e.g. a relay's mixing-delay schedule) that must not be recomputable from public data: keying such
    /// a PRF on a node's public coordinate lets a global passive adversary replay the schedule and relink
    /// a hop's in/out flows (audit E2).
    #[must_use]
    pub fn derive_subkey(&self, domain: &str) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(domain.as_bytes());
        hasher.update(&self.x25519.to_bytes());
        let mut out = [0u8; 32];
        hasher.finalize_xof().read(&mut out);
        out
    }
}

impl HybridKemPublic {
    /// The canonical public-key bytes `X25519(32) ‖ ML-KEM-768` (spec §7.1) for the node-ID.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.x25519.as_bytes());
        out.extend_from_slice(self.mlkem.to_bytes().as_slice());
        out
    }

    /// Parse a public key from its [`encode`](Self::encode) bytes (`PUBLIC_LEN` long). Returns `None`
    /// on the wrong length or an ML-KEM key that fails validation.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PUBLIC_LEN {
            return None;
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(bytes.get(..32)?);
        let x25519 = PublicKey::from(x);
        let encoded =
            Array::<u8, <MlEncapKey as KeySizeUser>::KeySize>::try_from(bytes.get(32..)?).ok()?;
        let mlkem = MlEncapKey::new(&encoded).ok()?;
        Some(Self { x25519, mlkem })
    }

    /// Encapsulate to this public key, returning the ciphertext and the session key.
    #[must_use]
    pub fn encapsulate<R: CryptoRng>(&self, rng: &mut R) -> (HybridCiphertext, SessionKey) {
        let ephemeral = StaticSecret::random_from_rng(rng);
        let ephemeral_pk = PublicKey::from(&ephemeral);
        let x_ss = ephemeral.diffie_hellman(&self.x25519);
        let (mlkem_ct, mlkem_ss) = self.mlkem.encapsulate_with_rng(rng);
        let ephemeral_bytes = ephemeral_pk.to_bytes();
        // `self.x25519` is the recipient's static public key we are encapsulating to.
        let session = combine(
            x_ss.as_bytes(),
            mlkem_ss.as_slice(),
            &ephemeral_bytes,
            mlkem_ct.as_slice(),
            self.x25519.as_bytes(),
        );
        (
            HybridCiphertext {
                x25519_ephemeral: ephemeral_bytes,
                mlkem: mlkem_ct,
            },
            session,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::rng::SeedRng;

    #[test]
    fn encapsulation_and_decapsulation_agree() {
        let mut rng = SeedRng::from_seed(b"kem-test");
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        let (ciphertext, sender_key) = public.encapsulate(&mut rng);
        let receiver_key = secret.decapsulate(&ciphertext);
        assert_eq!(
            sender_key, receiver_key,
            "both sides derive the same session key"
        );
    }

    #[test]
    fn distinct_encapsulations_give_distinct_keys() {
        let mut rng = SeedRng::from_seed(b"kem-test-2");
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        let (ct1, k1) = public.encapsulate(&mut rng);
        let (_ct2, k2) = public.encapsulate(&mut rng);
        assert_ne!(k1, k2, "fresh encapsulations yield fresh keys");
        // The first still decapsulates correctly.
        assert_eq!(secret.decapsulate(&ct1), k1);
    }

    #[test]
    fn a_different_key_cannot_decapsulate() {
        let mut rng = SeedRng::from_seed(b"kem-test-3");
        let (_secret, public) = HybridKemSecret::generate(&mut rng);
        let (ciphertext, sender_key) = public.encapsulate(&mut rng);
        // A different secret derives a different (wrong) session key.
        let (other, _) = HybridKemSecret::generate(&mut rng);
        assert_ne!(other.decapsulate(&ciphertext), sender_key);
    }

    #[test]
    fn public_key_encodes_and_decodes_and_still_encapsulates() {
        let mut rng = SeedRng::from_seed(b"kem-public-roundtrip");
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        let bytes = public.encode();
        assert_eq!(bytes.len(), PUBLIC_LEN);
        let parsed = HybridKemPublic::decode(&bytes).expect("round-trips");
        // A ciphertext encapsulated to the *decoded* key decapsulates under the original secret.
        let (ciphertext, key) = parsed.encapsulate(&mut rng);
        assert_eq!(secret.decapsulate(&ciphertext), key);
        assert!(HybridKemPublic::decode(&bytes[..10]).is_none());
    }

    #[test]
    fn ciphertext_serializes_and_still_decapsulates() {
        let mut rng = SeedRng::from_seed(b"kem-serialize");
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        let (ciphertext, key) = public.encapsulate(&mut rng);
        let bytes = ciphertext.to_bytes();
        assert_eq!(bytes.len(), CIPHERTEXT_LEN);
        let parsed = HybridCiphertext::from_bytes(&bytes).expect("round-trips");
        assert_eq!(secret.decapsulate(&parsed), key);
        assert!(HybridCiphertext::from_bytes(&bytes[..10]).is_none());
    }
}
