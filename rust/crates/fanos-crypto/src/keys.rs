//! Hybrid post-quantum key material and node identity (spec §L0, §7.1).
//!
//! A FANOS identity bundles a **hybrid signature** key (`Ed25519 ‖ ML-DSA-65`) and a
//! **hybrid KEM** key (`X25519 ‖ ML-KEM-768`); the long-term node identifier is the BLAKE3
//! hash of the canonical concatenation of all four public keys. This module models the
//! bundle and derives the node ID. The classical and PQ primitives themselves are pluggable
//! (production wires in `ed25519-dalek`, `ml-dsa`, `x25519-dalek`, `ml-kem`); here we pin the
//! fixed sizes and the canonical bundling so addressing and the node-ID hash are portable.

use alloc::vec::Vec;

use crate::hash::{DIGEST_LEN, hash_labeled, label};

/// Ed25519 public-key length.
pub const ED25519_PK_LEN: usize = 32;
/// ML-DSA-65 public-key length.
pub const MLDSA65_PK_LEN: usize = 1952;
/// X25519 public-key length.
pub const X25519_PK_LEN: usize = 32;
/// ML-KEM-768 public-key length.
pub const MLKEM768_PK_LEN: usize = 1184;

/// A hybrid signature public key: `Ed25519 ‖ ML-DSA-65` (spec §7.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigPublicKey {
    ed25519: [u8; ED25519_PK_LEN],
    mldsa65: Vec<u8>,
}

/// A hybrid KEM public key: `X25519 ‖ ML-KEM-768` (spec §7.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KemPublicKey {
    x25519: [u8; X25519_PK_LEN],
    mlkem768: Vec<u8>,
}

/// A construction error (a component was the wrong length).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BadKeyLength;

impl SigPublicKey {
    /// Assemble from components, validating the ML-DSA length.
    pub fn new(ed25519: [u8; ED25519_PK_LEN], mldsa65: Vec<u8>) -> Result<Self, BadKeyLength> {
        if mldsa65.len() != MLDSA65_PK_LEN {
            return Err(BadKeyLength);
        }
        Ok(Self { ed25519, mldsa65 })
    }

    /// Assemble from fixed-size component keys — infallible (the lengths are guaranteed by the array
    /// types). Used when composing an identity from real primitive keys ([`crate::HybridIdentity`]).
    #[must_use]
    pub fn from_parts(ed25519: [u8; ED25519_PK_LEN], mldsa65: [u8; MLDSA65_PK_LEN]) -> Self {
        Self { ed25519, mldsa65: mldsa65.to_vec() }
    }

    /// The Ed25519 public-key bytes.
    #[must_use]
    pub fn ed25519(&self) -> [u8; ED25519_PK_LEN] {
        self.ed25519
    }

    /// The ML-DSA-65 public-key bytes (length [`MLDSA65_PK_LEN`]).
    #[must_use]
    pub fn mldsa65(&self) -> &[u8] {
        &self.mldsa65
    }

    /// The canonical concatenation `Ed25519 ‖ ML-DSA-65`.
    fn extend_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.mldsa65);
    }
}

impl KemPublicKey {
    /// Assemble from components, validating the ML-KEM length.
    pub fn new(x25519: [u8; X25519_PK_LEN], mlkem768: Vec<u8>) -> Result<Self, BadKeyLength> {
        if mlkem768.len() != MLKEM768_PK_LEN {
            return Err(BadKeyLength);
        }
        Ok(Self { x25519, mlkem768 })
    }

    /// Assemble from fixed-size component keys — infallible (the lengths are guaranteed by the array
    /// types). Used when composing an identity from real primitive keys ([`crate::HybridIdentity`]).
    #[must_use]
    pub fn from_parts(x25519: [u8; X25519_PK_LEN], mlkem768: [u8; MLKEM768_PK_LEN]) -> Self {
        Self { x25519, mlkem768: mlkem768.to_vec() }
    }

    /// The X25519 public-key bytes.
    #[must_use]
    pub fn x25519(&self) -> [u8; X25519_PK_LEN] {
        self.x25519
    }

    /// The ML-KEM-768 encapsulation-key bytes (length [`MLKEM768_PK_LEN`]).
    #[must_use]
    pub fn mlkem768(&self) -> &[u8] {
        &self.mlkem768
    }

    /// The canonical concatenation `X25519 ‖ ML-KEM-768`.
    fn extend_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.x25519);
        out.extend_from_slice(&self.mlkem768);
    }
}

/// A node's public identity: the hybrid signature and KEM keys (spec §L0).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridPublicKey {
    /// The hybrid signature key.
    pub sig: SigPublicKey,
    /// The hybrid KEM key.
    pub kem: KemPublicKey,
}

/// A 32-byte long-term node identifier (spec §L0).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct NodeId(pub [u8; DIGEST_LEN]);

impl HybridPublicKey {
    /// The canonical byte encoding of the full bundle, in declared order
    /// `Ed25519 ‖ ML-DSA-65 ‖ X25519 ‖ ML-KEM-768` (spec §7.1).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(ED25519_PK_LEN + MLDSA65_PK_LEN + X25519_PK_LEN + MLKEM768_PK_LEN);
        self.sig.extend_canonical(&mut out);
        self.kem.extend_canonical(&mut out);
        out
    }

    /// The long-term node identifier: `BLAKE3` of the canonical bundle (spec §L0).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId(hash_labeled(label::NODE_ID, &self.encode()))
    }

    /// The exact length of an encoded bundle: `Ed25519 ‖ ML-DSA-65 ‖ X25519 ‖ ML-KEM-768`.
    pub const ENCODED_LEN: usize =
        ED25519_PK_LEN + MLDSA65_PK_LEN + X25519_PK_LEN + MLKEM768_PK_LEN;

    /// Parse a bundle produced by [`encode`](Self::encode). `None` unless the length is exactly
    /// [`ENCODED_LEN`](Self::ENCODED_LEN) — so a truncated or oversized identity is rejected, never
    /// silently accepted with a wrong-length component.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return None;
        }
        let (a, b) = (ED25519_PK_LEN, ED25519_PK_LEN + MLDSA65_PK_LEN);
        let c = b + X25519_PK_LEN;
        let ed25519 = <[u8; ED25519_PK_LEN]>::try_from(bytes.get(..a)?).ok()?;
        let mldsa65 = bytes.get(a..b)?.to_vec();
        let x25519 = <[u8; X25519_PK_LEN]>::try_from(bytes.get(b..c)?).ok()?;
        let mlkem768 = bytes.get(c..)?.to_vec();
        Some(Self {
            sig: SigPublicKey { ed25519, mldsa65 },
            kem: KemPublicKey { x25519, mlkem768 },
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample_key(fill: u8) -> HybridPublicKey {
        HybridPublicKey {
            sig: SigPublicKey::new([fill; ED25519_PK_LEN], vec![fill; MLDSA65_PK_LEN]).unwrap(),
            kem: KemPublicKey::new([fill; X25519_PK_LEN], vec![fill; MLKEM768_PK_LEN]).unwrap(),
        }
    }

    #[test]
    fn bundle_encodes_to_declared_length() {
        let k = sample_key(7);
        assert_eq!(
            k.encode().len(),
            ED25519_PK_LEN + MLDSA65_PK_LEN + X25519_PK_LEN + MLKEM768_PK_LEN
        );
    }

    #[test]
    fn node_id_is_deterministic_and_distinguishing() {
        let a = sample_key(1);
        let b = sample_key(2);
        assert_eq!(a.node_id(), a.node_id());
        assert_ne!(a.node_id(), b.node_id());
    }

    #[test]
    fn rejects_wrong_component_length() {
        assert_eq!(SigPublicKey::new([0; 32], vec![0; 10]), Err(BadKeyLength));
        assert_eq!(KemPublicKey::new([0; 32], vec![0; 10]), Err(BadKeyLength));
    }
}
