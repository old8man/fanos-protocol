//! # fanos-vrf — a real verifiable random function for the beacon & rendezvous
//!
//! The hash derivation in [`fanos_primitives::vrf`] is deterministic but **unverifiable**: nothing
//! stops a node lying about the coordinate it derived. This crate replaces it with an RFC 9381-*style*
//! VRF on the ristretto255 group (via the vetted [`vrf_r255`] crate) — it is *not* the
//! `ECVRF-EDWARDS25519-SHA512` ciphersuite of RFC 9381 and is not wire-compatible with it, so the RFC is a
//! reference, not a conformance claim: a node *proves* that its
//! per-epoch coordinate was derived correctly from its secret key, and anyone holding the node's
//! public key verifies that proof **without learning the secret** (spec §L6, §L1 beacon).
//!
//! * [`VrfSecret`] / [`VrfPublic`] / [`VrfProof`] wrap the primitive with a small, misuse-resistant
//!   surface (seed-derivable keys, byte encodings).
//! * [`prove_coordinate`] / [`verify_coordinate`] lift it to the protocol object: a **verifiable
//!   projective coordinate** `MapToPoint(VRF(sk, node ‖ epoch ‖ beacon))` that rotates every epoch —
//!   folding the epoch's beacon seed so it is unpredictable ahead of time — and cannot be forged or
//!   misreported (the `HELLO` proof-of-coordinate, spec §7.3).
//!
//! The composition adds no new hardness assumption — ristretto255 discrete log, already assumed by
//! the X25519/Ed25519 hybrid — and the primitive is a published construction, not a novel one.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod beacon;
pub mod dkg;
pub mod vss;

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Point;
use fanos_primitives::hash::label;
use fanos_primitives::{BeaconSeed, Epoch, map_to_point};
use vrf_r255::{Proof, PublicKey, SecretKey};

/// Length of a serialized VRF proof (`Γ ‖ c ‖ s`), in bytes.
pub const PROOF_LEN: usize = 80;
/// Length of a VRF output (the hash `β`), in bytes.
pub const OUTPUT_LEN: usize = 64;

/// A VRF output — the pseudo-random hash `β` a valid proof yields.
pub type VrfOutput = [u8; OUTPUT_LEN];

/// A VRF secret key (seed-derivable; carries its own public key). Deliberately **not** `Copy` — a
/// long-term coordinate secret must not be silently duplicated across stack frames (audit A6) — and its
/// `Debug` is redacted so a secret can never be printed into a log. (Wipe-on-drop is blocked upstream:
/// `vrf_r255::SecretKey` exposes no `Zeroize`; the derivation seed is wiped by its owner instead.)
#[derive(Clone)]
pub struct VrfSecret(SecretKey);

impl core::fmt::Debug for VrfSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VrfSecret(<redacted>)")
    }
}

/// A VRF public key: verifies proofs, reveals nothing about the secret.
#[derive(Clone, Copy, Debug)]
pub struct VrfPublic(PublicKey);

/// A VRF proof `π` binding an input to an output under a public key.
#[derive(Clone, Copy, Debug)]
pub struct VrfProof(Proof);

impl VrfSecret {
    /// Derive a secret key from any 32-byte seed — **total**: every seed yields a key.
    ///
    /// The seed is hashed **uniformly into the scalar field** (a wide reduction of a domain-separated
    /// XOF). A raw `SecretKey::from_bytes` would instead demand an already-canonical scalar
    /// (`< ℓ ≈ 2²⁵²`) and reject ~15/16 of random seeds — a trap for any caller deriving a VRF key
    /// deterministically from a node seed. Reducing mod order first makes the bytes always canonical,
    /// so the construction cannot fail; a node identity can derive its coordinate-VRF key from its seed
    /// with no error path (spec §L0).
    ///
    /// # Panics
    /// Never in practice: the mod-order reduction yields a scalar `< ℓ`, whose canonical bytes
    /// `SecretKey::from_bytes` always accepts. The internal assertion only documents that invariant.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut wide = [0u8; 64];
        fanos_primitives::hash::hash_xof("FANOS-v1/vrf-seed", &seed, &mut wide);
        let scalar = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&wide);
        // A mod-order-reduced scalar (< ℓ) has canonical bytes that `SecretKey::from_bytes` always
        // accepts, so this is total — the reduction above is exactly what guarantees it.
        #[allow(clippy::expect_used)]
        Self(
            Option::from(SecretKey::from_bytes(scalar.to_bytes()))
                .expect("a mod-order-reduced scalar is a canonical VRF secret key"),
        )
    }

    /// The 32-byte canonical encoding of this secret key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// This key's public half.
    #[must_use]
    pub fn public(&self) -> VrfPublic {
        VrfPublic(PublicKey::from(self.0))
    }

    /// Prove the VRF over `alpha`, returning the proof and the output it commits to.
    #[must_use]
    pub fn prove(&self, alpha: &[u8]) -> (VrfProof, VrfOutput) {
        let proof = self.0.prove(alpha);
        // The prover recovers its own output by verifying under its public key (always valid here).
        let output = Option::from(PublicKey::from(self.0).verify(alpha, &proof))
            .unwrap_or([0u8; OUTPUT_LEN]);
        (VrfProof(proof), output)
    }
}

impl VrfPublic {
    /// Parse a public key from its 32-byte encoding (with the group validity check).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        PublicKey::from_bytes(bytes).map(Self)
    }

    /// The 32-byte canonical encoding of this public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify `proof` for input `alpha`, returning the VRF output iff it is valid.
    #[must_use]
    pub fn verify(&self, alpha: &[u8], proof: &VrfProof) -> Option<VrfOutput> {
        Option::from(self.0.verify(alpha, &proof.0))
    }
}

impl VrfProof {
    /// The 80-byte serialized proof.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PROOF_LEN] {
        self.0.to_bytes()
    }

    /// Parse a proof from its 80-byte encoding, or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: [u8; PROOF_LEN]) -> Option<Self> {
        Proof::from_bytes(bytes).map(Self)
    }
}

/// Map a VRF output to a uniform projective point — the verifiable coordinate (spec §7.1, §L6).
#[must_use]
pub fn coordinate_from_output<F: Field>(output: &VrfOutput) -> Point<F> {
    map_to_point::<F>(label::COORD, output)
}

/// The VRF input a node proves for its epoch coordinate: `node_id ‖ epoch_low32_be ‖ beacon_seed`
/// (spec §L0/§L3, `VRF(sk, id ‖ epoch ‖ SEED(epoch))`). Folding the epoch's **beacon seed** is what makes the coordinate
/// *unpredictable ahead of the epoch* — an adversary cannot grind for a future placement it cannot yet
/// compute (§3.2 assumption 2), the load-bearing anti-pre-settling defence on the base cell.
fn beacon_alpha(node_id: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> Vec<u8> {
    let mut alpha = Vec::with_capacity(node_id.len() + 4 + 32);
    alpha.extend_from_slice(node_id);
    alpha.extend_from_slice(&epoch.low32_be_bytes());
    alpha.extend_from_slice(beacon.as_bytes());
    alpha
}

/// Prove a node's verifiable coordinate for `epoch` under the epoch's `beacon` seed:
/// `MapToPoint(VRF(sk, node_id ‖ epoch ‖ beacon))`, with the proof that lets anyone check the derivation
/// (spec §L0, §L3, §7.3 proof-of-coordinate). Use [`BeaconSeed::GENESIS`] before the first beacon round.
#[must_use]
pub fn prove_coordinate<F: Field>(
    secret: &VrfSecret,
    node_id: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> (Point<F>, VrfProof) {
    let (proof, output) = secret.prove(&beacon_alpha(node_id, epoch, beacon));
    (coordinate_from_output::<F>(&output), proof)
}

/// Verify that `claimed` is the correct epoch coordinate for the node with `public` key under the
/// epoch's `beacon` seed — i.e. that it equals `MapToPoint(VRF(sk, node_id ‖ epoch ‖ beacon))` — without
/// the secret (spec §L0, §L3, §7.3). This is the check a peer runs on a `HELLO` proof-of-coordinate.
#[must_use]
pub fn verify_coordinate<F: Field>(
    public: &VrfPublic,
    node_id: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    claimed: &Point<F>,
    proof: &VrfProof,
) -> bool {
    match public.verify(&beacon_alpha(node_id, epoch, beacon), proof) {
        Some(output) => &coordinate_from_output::<F>(&output) == claimed,
        None => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::F31;

    fn secret(seed: u8) -> VrfSecret {
        VrfSecret::from_seed([seed; 32])
    }

    #[test]
    fn every_seed_yields_a_working_key_including_non_canonical_ones() {
        // Seeds whose raw bytes are NOT a canonical scalar (top bytes 0xFF ⇒ ≥ 2²⁵⁵ > ℓ) would be
        // rejected by a raw `from_bytes`; hashing into the field accepts them and the key works.
        for seed in [[0xFFu8; 32], [0x80; 32], [0xEE; 32], [0x00; 32]] {
            let sk = VrfSecret::from_seed(seed); // hashed seed is always a valid key
            let (proof, output) = sk.prove(b"alpha");
            assert_eq!(sk.public().verify(b"alpha", &proof), Some(output));
        }
        // Distinct seeds give distinct keys (the hash is injective in practice).
        assert_ne!(
            VrfSecret::from_seed([0xFF; 32]).to_bytes(),
            VrfSecret::from_seed([0xEE; 32]).to_bytes()
        );
    }

    #[test]
    fn prove_verify_round_trips() {
        let sk = secret(1);
        let pk = sk.public();
        let (proof, output) = sk.prove(b"alpha");
        assert_eq!(
            pk.verify(b"alpha", &proof),
            Some(output),
            "valid proof yields the output"
        );
    }

    #[test]
    fn a_tampered_input_or_key_fails() {
        let sk = secret(2);
        let (proof, _) = sk.prove(b"alpha");
        assert!(
            sk.public().verify(b"different", &proof).is_none(),
            "wrong input rejected"
        );
        assert!(
            secret(3).public().verify(b"alpha", &proof).is_none(),
            "wrong key rejected"
        );
    }

    #[test]
    fn the_verifiable_coordinate_is_deterministic_and_checks_out() {
        let sk = secret(4);
        let pk = sk.public();
        let beacon = BeaconSeed::new([0xB7; 32]);
        let (coord, proof) = prove_coordinate::<F31>(&sk, b"node-A", Epoch::new(7), &beacon);
        // Deterministic: the same key+epoch+beacon always yields the same coordinate.
        let (coord2, _) = prove_coordinate::<F31>(&sk, b"node-A", Epoch::new(7), &beacon);
        assert_eq!(coord, coord2);
        // Anyone with the public key verifies the coordinate without the secret.
        assert!(verify_coordinate::<F31>(
            &pk,
            b"node-A",
            Epoch::new(7),
            &beacon,
            &coord,
            &proof
        ));
        // A forged coordinate (from a different epoch) does not verify for epoch 7.
        let (other, _) = prove_coordinate::<F31>(&sk, b"node-A", Epoch::new(8), &beacon);
        assert!(!verify_coordinate::<F31>(
            &pk,
            b"node-A",
            Epoch::new(7),
            &beacon,
            &other,
            &proof
        ));
    }

    #[test]
    fn the_coordinate_rotates_every_epoch() {
        let sk = secret(5);
        let beacon = BeaconSeed::new([0x5B; 32]);
        let (c7, _) = prove_coordinate::<F31>(&sk, b"n", Epoch::new(7), &beacon);
        let (c8, _) = prove_coordinate::<F31>(&sk, b"n", Epoch::new(8), &beacon);
        assert_ne!(c7, c8, "the beacon coordinate moves each epoch");
    }

    #[test]
    fn the_coordinate_folds_the_beacon_and_is_unpredictable_ahead() {
        // The same key + epoch under a DIFFERENT beacon seed yields a different coordinate — so a node's
        // placement cannot be computed (nor pre-settled onto a victim's lines) until the epoch's beacon is
        // revealed (spec §3.2 assumption 2). A coordinate proven under one seed does not verify under
        // another, so a peer cannot replay a past epoch's proof against the current seed.
        let sk = secret(6);
        let pk = sk.public();
        let (c_a, proof_a) =
            prove_coordinate::<F31>(&sk, b"n", Epoch::new(3), &BeaconSeed::new([0xA1; 32]));
        let (c_b, _) = prove_coordinate::<F31>(&sk, b"n", Epoch::new(3), &BeaconSeed::new([0xB2; 32]));
        assert_ne!(c_a, c_b, "the coordinate depends on the beacon seed");
        assert!(!verify_coordinate::<F31>(
            &pk,
            b"n",
            Epoch::new(3),
            &BeaconSeed::new([0xB2; 32]),
            &c_a,
            &proof_a
        ), "a proof under one beacon does not verify under another");
    }

    #[test]
    fn proof_and_key_bytes_round_trip() {
        let sk = secret(6);
        let (proof, _) = sk.prove(b"x");
        assert!(VrfProof::from_bytes(proof.to_bytes()).is_some());
        let pk = sk.public();
        assert_eq!(
            VrfPublic::from_bytes(pk.to_bytes()).unwrap().to_bytes(),
            pk.to_bytes()
        );
    }
}
