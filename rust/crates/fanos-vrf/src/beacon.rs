//! Distributed randomness beacon (drand-class, pairing-free) — spec §L3, audit E5.
//!
//! A rendezvous meeting line `L_rdv = MapToLine(H(pubkey ‖ epoch ‖ SEED(epoch)))` is only
//! unpredictable-ahead if `SEED(epoch)` is: a bare `H(pubkey ‖ epoch)` (the pre-E5 state) lets anyone
//! compute every future meeting line and pre-position on it. This module produces `SEED(epoch)` as a
//! **threshold** value that no coalition below `t` can predict, no one can bias, and anyone can verify.
//!
//! ## Construction
//!
//! The network runs the existing ristretto255 DKG ([`crate::dkg`]) once, yielding a joint public key
//! `Y = x·G` whose secret `x` is held only as Shamir shares `s_i` (never assembled), with public share
//! commitments `Y_i = s_i·G` recoverable from the aggregate VSS
//! [`VssCommitment`](crate::vss::VssCommitment).
//!
//! For each epoch, let `M = M(epoch)` be a public hash-to-curve point. A holder of share `s_i` emits a
//! **partial** `σ_i = s_i·M` together with a Chaum–Pedersen **DLEQ proof** that the same scalar `s_i`
//! underlies both `σ_i` (base `M`) and the public `Y_i` (base `G`) — so a partial cannot be forged
//! without the share, and a wrong partial is rejected before it ever reaches the combiner. Any `t`
//! verified partials Lagrange-combine *in the exponent* to
//! `σ = Σ_{i∈S} λ_i(S)·σ_i = (Σ_{i∈S} λ_i(S)·s_i)·M = x·M`,
//! the **same point for every `t`-subset** `S` (Lagrange reconstructs `x` at 0). The beacon seed is
//! `SEED(epoch) = H("beacon-seed" ‖ epoch ‖ σ)`.
//!
//! ## Security
//!
//! * **Unpredictable:** `σ = x·M` is a DDH value; without `x` (i.e. below `t` cooperating shareholders)
//!   it is pseudo-random under the ristretto255 discrete-log/DDH assumption — the same assumption the
//!   X25519/Ed25519 hybrid already rests on, so **no new hardness is introduced**.
//! * **Unbiasable:** for a fixed `(Y, epoch)` the output `x·M` is *unique* — there is nothing to grind,
//!   and no subset of contributors can steer it (any `t` honest partials yield the identical `σ`).
//! * **Verifiable:** each partial carries a DLEQ proof checkable against the public `Y_i`; the combined
//!   `σ` is exactly `x·M`, so a client re-deriving its meeting line trusts algebra, not a beacon operator.
//! * **Pairing-free & curve-coherent:** built on ristretto255 — the curve FANOS already fixes for its
//!   coordinate VRF (spec §L6) — rather than the spec's nominal threshold-BLS, avoiding a second
//!   (pairing) trust base. A post-quantum beacon remains the spec's `[P]` research direction.

use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{RistrettoPoint, Scalar};

use fanos_primitives::Epoch;
use fanos_primitives::hash::hash_xof;

use crate::vss::{VssCommitment, VssShare};

/// Domain label for the per-epoch hash-to-curve beacon input `M(epoch)`.
const LABEL_INPUT: &str = "FANOS-v1/beacon-input";
/// Domain label for the DLEQ Fiat–Shamir challenge.
const LABEL_CHALLENGE: &str = "FANOS-v1/beacon-dleq";
/// Domain label for the deterministic DLEQ nonce.
const LABEL_NONCE: &str = "FANOS-v1/beacon-dleq-nonce";
/// Domain label for the final beacon seed `H(σ)`.
const LABEL_SEED: &str = "FANOS-v1/beacon-seed";

/// Wire length of a [`BeaconPartial`]: `index(1) ‖ σ(32) ‖ challenge(32) ‖ response(32)`.
pub const PARTIAL_LEN: usize = 1 + 32 + 32 + 32;
/// Wire length of a [`BeaconOutput`]: the compressed `σ` point.
pub const OUTPUT_LEN: usize = 32;

/// The per-epoch beacon input `M(epoch)` — a public hash-to-curve point, independent of any key, so
/// every party agrees on it from the epoch alone.
fn beacon_point(epoch: Epoch) -> RistrettoPoint {
    let mut wide = [0u8; 64];
    hash_xof(LABEL_INPUT, &epoch.to_be_bytes(), &mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Hash arbitrary transcript bytes to a ristretto scalar via a wide (uniform) reduction.
fn hash_to_scalar(label: &str, data: &[u8]) -> Scalar {
    let mut wide = [0u8; 64];
    hash_xof(label, data, &mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// The DLEQ Fiat–Shamir challenge `c = H(index ‖ epoch ‖ Y_i ‖ σ_i ‖ A ‖ B)`. `M` and `G` are fixed by
/// `epoch`/the label, so binding `epoch` binds the whole instance.
fn dleq_challenge(
    index: u8,
    epoch: Epoch,
    y: &RistrettoPoint,
    sigma: &RistrettoPoint,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
) -> Scalar {
    let mut data = Vec::with_capacity(1 + 8 + 32 * 4);
    data.push(index);
    data.extend_from_slice(&epoch.to_be_bytes());
    data.extend_from_slice(y.compress().as_bytes());
    data.extend_from_slice(sigma.compress().as_bytes());
    data.extend_from_slice(a.compress().as_bytes());
    data.extend_from_slice(b.compress().as_bytes());
    hash_to_scalar(LABEL_CHALLENGE, &data)
}

/// A shareholder's partial evaluation of the beacon for one epoch: `σ_i = s_i·M(epoch)`, with a
/// Chaum–Pedersen DLEQ proof `(challenge, response)` binding it to the public share `Y_i = s_i·G`.
#[derive(Clone, Debug)]
pub struct BeaconPartial {
    index: u8,
    sigma: RistrettoPoint,
    challenge: Scalar,
    response: Scalar,
}

impl BeaconPartial {
    /// The shareholder index this partial was produced by (`1..=n`).
    #[must_use]
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The `index(1) ‖ σ(32) ‖ challenge(32) ‖ response(32)` wire encoding ([`PARTIAL_LEN`] bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PARTIAL_LEN] {
        let mut out = [0u8; PARTIAL_LEN];
        out[0] = self.index;
        out[1..33].copy_from_slice(self.sigma.compress().as_bytes());
        out[33..65].copy_from_slice(&self.challenge.to_bytes());
        out[65..97].copy_from_slice(&self.response.to_bytes());
        out
    }

    /// Decode a partial from its [`PARTIAL_LEN`]-byte encoding, or `None` if `σ` is not a valid group
    /// element or the scalars are non-canonical.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let index = *bytes.first()?;
        let sigma = CompressedRistretto::from_slice(bytes.get(1..33)?)
            .ok()?
            .decompress()?;
        let challenge_bytes: [u8; 32] = bytes.get(33..65)?.try_into().ok()?;
        let response_bytes: [u8; 32] = bytes.get(65..97)?.try_into().ok()?;
        let challenge = Option::from(Scalar::from_canonical_bytes(challenge_bytes))?;
        let response = Option::from(Scalar::from_canonical_bytes(response_bytes))?;
        Some(Self {
            index,
            sigma,
            challenge,
            response,
        })
    }
}

/// The combined beacon value for an epoch: `σ = x·M`, from which the public seed is derived. Unique per
/// `(Y, epoch)`, so any `t` honest partials produce the identical output.
#[derive(Clone, Debug)]
pub struct BeaconOutput {
    sigma: RistrettoPoint,
}

impl BeaconOutput {
    /// The 32-byte public beacon seed `H("beacon-seed" ‖ epoch ‖ σ)` — the value folded into the
    /// meeting-line / coordinate derivation. Binding `epoch` here domain-separates seeds across epochs
    /// even though `σ` already encodes the epoch through `M`.
    #[must_use]
    pub fn seed(&self, epoch: Epoch) -> [u8; 32] {
        let mut data = Vec::with_capacity(8 + 32);
        data.extend_from_slice(&epoch.to_be_bytes());
        data.extend_from_slice(self.sigma.compress().as_bytes());
        let mut out = [0u8; 32];
        hash_xof(LABEL_SEED, &data, &mut out);
        out
    }

    /// The compressed-`σ` wire encoding ([`OUTPUT_LEN`] bytes) — enough to re-derive the seed and to
    /// re-verify against the partials.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; OUTPUT_LEN] {
        self.sigma.compress().to_bytes()
    }

    /// Decode an output from its compressed-`σ` encoding, or `None` if it is not a valid group element.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; OUTPUT_LEN]) -> Option<Self> {
        let sigma = CompressedRistretto::from_slice(bytes).ok()?.decompress()?;
        Some(Self { sigma })
    }
}

/// Compute this shareholder's beacon partial for `epoch` from its DKG share.
///
/// The DLEQ nonce is derived deterministically from the secret share and the (public) `σ_i`, so the
/// proof is reproducible and needs no RNG (sans-I/O friendly) while never reusing a nonce across
/// distinct messages — each `epoch` fixes a distinct `M`, hence a distinct `σ_i` and nonce.
#[must_use]
pub fn partial_eval(share: &VssShare, epoch: Epoch) -> BeaconPartial {
    let s = share.value();
    let m = beacon_point(epoch);
    let sigma = s * m;
    let y = s * RISTRETTO_BASEPOINT_POINT;

    // Deterministic Chaum–Pedersen nonce k, then A = k·G, B = k·M.
    let mut nonce_input = Vec::with_capacity(32 + 8 + 32);
    nonce_input.extend_from_slice(&s.to_bytes());
    nonce_input.extend_from_slice(&epoch.to_be_bytes());
    nonce_input.extend_from_slice(sigma.compress().as_bytes());
    let k = hash_to_scalar(LABEL_NONCE, &nonce_input);
    let a = k * RISTRETTO_BASEPOINT_POINT;
    let b = k * m;

    let challenge = dleq_challenge(share.index(), epoch, &y, &sigma, &a, &b);
    let response = k + challenge * s;
    BeaconPartial {
        index: share.index(),
        sigma,
        challenge,
        response,
    }
}

/// Verify a partial against the aggregate DKG `commitment` for `epoch`: recompute the public share
/// `Y_i` and check the DLEQ (`A = z·G − c·Y_i`, `B = z·M − c·σ_i`, `c ?= H(…)`), so only a genuine
/// holder of share `i` can have produced it.
#[must_use]
pub fn verify_partial(partial: &BeaconPartial, epoch: Epoch, commitment: &VssCommitment) -> bool {
    if partial.index == 0 {
        return false; // x = 0 is not a valid shareholder index
    }
    let m = beacon_point(epoch);
    let y = commitment.public_share(partial.index);
    let a = partial.response * RISTRETTO_BASEPOINT_POINT - partial.challenge * y;
    let b = partial.response * m - partial.challenge * partial.sigma;
    dleq_challenge(partial.index, epoch, &y, &partial.sigma, &a, &b) == partial.challenge
}

/// Lagrange-combine `≥ threshold` partials (distinct indices) into the unique beacon output `σ = x·M`.
///
/// Partials are **assumed already verified** ([`verify_partial`]); this step is pure algebra. Returns
/// `None` if fewer than `threshold` distinct-index partials are supplied. Exactly `threshold` of them
/// are used; because the result is subset-independent, *which* `threshold` does not matter.
#[must_use]
pub fn combine(partials: &[BeaconPartial], threshold: usize) -> Option<BeaconOutput> {
    if threshold == 0 {
        return None;
    }
    // Take the first `threshold` partials with distinct indices (a duplicate index would break the
    // Lagrange denominator and, in any case, contributes no new information).
    let mut chosen: Vec<&BeaconPartial> = Vec::with_capacity(threshold);
    for partial in partials {
        if partial.index != 0 && !chosen.iter().any(|c| c.index == partial.index) {
            chosen.push(partial);
            if chosen.len() == threshold {
                break;
            }
        }
    }
    if chosen.len() < threshold {
        return None;
    }

    let mut sigma = RistrettoPoint::identity();
    for pi in &chosen {
        let xi = Scalar::from(u64::from(pi.index));
        // Lagrange basis λ_i(0) = Π_{j≠i} x_j / (x_j − x_i) over the chosen subset.
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for pj in &chosen {
            if pj.index != pi.index {
                let xj = Scalar::from(u64::from(pj.index));
                num *= xj;
                den *= xj - xi;
            }
        }
        sigma += (num * den.invert()) * pi.sigma;
    }
    Some(BeaconOutput { sigma })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::vss::{DeterministicRng, deal, reconstruct};

    /// Deal a fresh `(t, n)` sharing of a test secret, returning the shares and the public commitment.
    fn shared(seed: &[u8], t: usize, n: usize) -> (Vec<VssShare>, VssCommitment, [u8; 32]) {
        let mut sk = [0u8; 32];
        hash_xof("beacon-test-secret", seed, &mut sk);
        let mut rng = DeterministicRng::new(seed);
        let (shares, commitment) = deal(&sk, t, n, &mut rng).unwrap();
        (shares, commitment, sk)
    }

    #[test]
    fn any_threshold_subset_yields_the_same_unbiasable_seed() {
        let (shares, commitment, sk) = shared(b"beacon-subset", 3, 5);
        let epoch = Epoch::new(9);
        let partials: Vec<_> = shares.iter().map(|s| partial_eval(s, epoch)).collect();
        assert!(
            partials
                .iter()
                .all(|p| verify_partial(p, epoch, &commitment)),
            "every honest partial verifies against the commitment"
        );

        // Distinct 3-subsets all combine to the identical seed (subset-independence ⇒ unbiasable).
        let seed_a = combine(
            &[
                partials[0].clone(),
                partials[1].clone(),
                partials[2].clone(),
            ],
            3,
        )
        .unwrap()
        .seed(epoch);
        let seed_b = combine(
            &[
                partials[4].clone(),
                partials[1].clone(),
                partials[3].clone(),
            ],
            3,
        )
        .unwrap()
        .seed(epoch);
        assert_eq!(seed_a, seed_b, "the beacon is subset-independent");

        // And it equals H(x·M) for the true joint secret x — the output is genuinely the group's DVRF.
        let x = Scalar::from_bytes_mod_order(sk);
        let direct = BeaconOutput {
            sigma: x * beacon_point(epoch),
        }
        .seed(epoch);
        assert_eq!(seed_a, direct, "σ = x·M, the unique threshold value");
    }

    #[test]
    fn a_forged_or_tampered_partial_is_rejected() {
        let (shares, commitment, _) = shared(b"beacon-forge", 2, 3);
        let epoch = Epoch::new(3);
        let honest = partial_eval(&shares[0], epoch);
        assert!(verify_partial(&honest, epoch, &commitment));

        // Tampered σ (a different point) breaks the DLEQ.
        let mut bad_sigma = honest.clone();
        bad_sigma.sigma += RISTRETTO_BASEPOINT_POINT;
        assert!(!verify_partial(&bad_sigma, epoch, &commitment));

        // Tampered response breaks the DLEQ.
        let mut bad_resp = honest.clone();
        bad_resp.response += Scalar::ONE;
        assert!(!verify_partial(&bad_resp, epoch, &commitment));

        // A partial replayed under the wrong index is checked against the wrong Y_i and fails.
        let mut wrong_index = honest.clone();
        wrong_index.index = shares[1].index();
        assert!(!verify_partial(&wrong_index, epoch, &commitment));

        // A partial for a different epoch does not verify for this one.
        let other_epoch = partial_eval(&shares[0], Epoch::new(4));
        assert!(!verify_partial(&other_epoch, epoch, &commitment));
    }

    #[test]
    fn fewer_than_threshold_partials_cannot_form_the_beacon() {
        let (shares, _commitment, sk) = shared(b"beacon-below-t", 3, 5);
        let epoch = Epoch::new(1);
        let partials: Vec<_> = shares.iter().map(|s| partial_eval(s, epoch)).collect();

        // Below threshold ⇒ no output at all.
        assert!(combine(&partials[..2], 3).is_none());
        // Duplicate indices do not count toward the threshold.
        assert!(combine(&[partials[0].clone(), partials[0].clone()], 2).is_none());

        // And a wrong (t−1)-subset "combination" (were one attempted at a lower threshold) is not the
        // true value — the real σ needs the full threshold of independent shares.
        let x = Scalar::from_bytes_mod_order(sk);
        let true_seed = BeaconOutput {
            sigma: x * beacon_point(epoch),
        }
        .seed(epoch);
        let two_seed = combine(&partials[..2], 2).unwrap().seed(epoch);
        assert_ne!(
            two_seed, true_seed,
            "a below-threshold combination is not the group beacon"
        );
    }

    #[test]
    fn the_beacon_rotates_each_epoch() {
        let (shares, _c, _) = shared(b"beacon-rotate", 2, 3);
        let s = |e: u64| {
            let ps: Vec<_> = shares
                .iter()
                .map(|sh| partial_eval(sh, Epoch::new(e)))
                .collect();
            combine(&ps, 2).unwrap().seed(Epoch::new(e))
        };
        assert_ne!(s(1), s(2), "the beacon seed moves each epoch");
        assert_ne!(s(2), s(3));
    }

    #[test]
    fn partial_and_output_bytes_round_trip() {
        let (shares, _c, _) = shared(b"beacon-bytes", 2, 3);
        let epoch = Epoch::new(5);
        let partial = partial_eval(&shares[0], epoch);
        let decoded = BeaconPartial::from_bytes(&partial.to_bytes()).unwrap();
        assert_eq!(decoded.to_bytes(), partial.to_bytes());

        let out = combine(
            &shares
                .iter()
                .map(|s| partial_eval(s, epoch))
                .collect::<Vec<_>>(),
            2,
        )
        .unwrap();
        let out2 = BeaconOutput::from_bytes(&out.to_bytes()).unwrap();
        assert_eq!(out.seed(epoch), out2.seed(epoch));
    }

    #[test]
    fn combined_secret_matches_reconstruction_cross_check() {
        // Independent oracle: reconstruct x from the shares, and confirm the beacon = H(x·M). This ties
        // the DVRF to `vss::reconstruct` without ever assembling x on the beacon path itself.
        let (shares, _c, _) = shared(b"beacon-xcheck", 3, 6);
        let epoch = Epoch::new(42);
        let x_bytes = reconstruct(&shares[..3]).unwrap();
        let x: Scalar = Option::from(Scalar::from_canonical_bytes(x_bytes)).unwrap();
        let expected = BeaconOutput {
            sigma: x * beacon_point(epoch),
        }
        .seed(epoch);
        let got = combine(
            &shares
                .iter()
                .map(|s| partial_eval(s, epoch))
                .collect::<Vec<_>>(),
            3,
        )
        .unwrap()
        .seed(epoch);
        assert_eq!(got, expected);
    }
}
