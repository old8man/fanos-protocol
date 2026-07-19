//! Hybrid post-quantum key material and node identity (spec §L0, §7.1).
//!
//! A FANOS identity bundles a **hybrid signature** key (`Ed25519 ‖ ML-DSA-65`), a
//! **hybrid KEM** key (`X25519 ‖ ML-KEM-768`), and the **coordinate-VRF** key (a ristretto255 point);
//! the long-term node identifier is the BLAKE3 hash of the canonical concatenation of all five public
//! keys, so it commits to the VRF key that earns the node's verifiable coordinate. This module models
//! the bundle and derives the node ID. The classical and PQ primitives themselves are pluggable
//! (production wires in `ed25519-dalek`, `ml-dsa`, `x25519-dalek`, `ml-kem`, `fanos-vrf`); here we pin
//! the fixed sizes and the canonical bundling so addressing and the node-ID hash are portable.

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
/// VRF public-key length (a compressed ristretto255 point). Held as opaque bytes here — the light
/// no_std primitives core carries the coordinate-VRF key without depending on the VRF crate
/// (`fanos-vrf` → `fanos-primitives`, so the reverse would cycle); `fanos-vrf` parses these bytes.
pub const VRF_PK_LEN: usize = 32;

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

impl core::fmt::Display for BadKeyLength {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a key component had the wrong length")
    }
}

impl core::error::Error for BadKeyLength {}

impl SigPublicKey {
    /// Assemble from components, validating the ML-DSA length.
    pub fn new(ed25519: [u8; ED25519_PK_LEN], mldsa65: Vec<u8>) -> Result<Self, BadKeyLength> {
        if mldsa65.len() != MLDSA65_PK_LEN {
            return Err(BadKeyLength);
        }
        Ok(Self { ed25519, mldsa65 })
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

    /// The canonical concatenation `X25519 ‖ ML-KEM-768`.
    fn extend_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.x25519);
        out.extend_from_slice(&self.mlkem768);
    }
}

/// A node's public identity: the hybrid signature and KEM keys, plus the coordinate-VRF key (spec §L0).
///
/// The `vrf` key is what makes the node's projective coordinate **verifiable**: the coordinate is
/// `MapToPoint(VRF(vrf_sk, epoch ‖ beacon))`, and because `vrf` is part of the bundle, the long-term
/// [`NodeId`] commits to it — a coordinate proof can only be made with the VRF secret whose public is in
/// the very identity that hashes to that `NodeId` (spec §L0/§L3; see `docs/design-coordinates.md`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridPublicKey {
    /// The hybrid signature key.
    pub sig: SigPublicKey,
    /// The hybrid KEM key.
    pub kem: KemPublicKey,
    /// The coordinate-VRF public key (a compressed ristretto255 point, opaque here — parsed by
    /// `fanos_vrf::VrfPublic::from_bytes`).
    pub vrf: [u8; VRF_PK_LEN],
}

/// A 32-byte long-term node identifier (spec §L0).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct NodeId(pub [u8; DIGEST_LEN]);

impl HybridPublicKey {
    /// The canonical byte encoding of the full bundle, in declared order
    /// `Ed25519 ‖ ML-DSA-65 ‖ X25519 ‖ ML-KEM-768 ‖ VRF` (spec §7.1). The VRF public is appended last,
    /// so the classical/PQ prefix stays byte-stable and the `NodeId` commits to the coordinate-VRF key.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            ED25519_PK_LEN + MLDSA65_PK_LEN + X25519_PK_LEN + MLKEM768_PK_LEN + VRF_PK_LEN,
        );
        self.sig.extend_canonical(&mut out);
        self.kem.extend_canonical(&mut out);
        out.extend_from_slice(&self.vrf);
        out
    }

    /// The coordinate-VRF public key bytes — feed to `fanos_vrf::VrfPublic::from_bytes` to verify this
    /// node's `HELLO` proof-of-coordinate.
    #[must_use]
    pub fn vrf_public(&self) -> &[u8; VRF_PK_LEN] {
        &self.vrf
    }

    /// The long-term node identifier: `BLAKE3` of the canonical bundle (spec §L0).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId(hash_labeled(label::NODE_ID, &self.encode()))
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
            vrf: [fill; VRF_PK_LEN],
        }
    }

    #[test]
    fn bundle_encodes_to_declared_length() {
        let k = sample_key(7);
        assert_eq!(
            k.encode().len(),
            ED25519_PK_LEN + MLDSA65_PK_LEN + X25519_PK_LEN + MLKEM768_PK_LEN + VRF_PK_LEN
        );
    }

    #[test]
    fn node_id_commits_to_the_vrf_key() {
        // Two identities identical but for the VRF key hash to different NodeIds — the coordinate-VRF key
        // is bound into the identity, so a coordinate proof cannot be made with a key not in the bundle.
        let a = sample_key(3);
        let mut b = a.clone();
        b.vrf = [0x99; VRF_PK_LEN];
        assert_ne!(a.node_id(), b.node_id(), "the NodeId commits to the VRF key");
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
