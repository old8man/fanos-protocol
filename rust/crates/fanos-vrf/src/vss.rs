//! Feldman verifiable secret sharing — a checkable threshold split (spec §L6 threshold hosting).
//!
//! Shamir sharing hides a secret among `n` holders so any `t` reconstruct it, but a **cheating
//! dealer** can hand out inconsistent shares and no recipient can tell. Feldman VSS fixes this: the
//! dealer publishes group commitments `C_j = a_j·G` to its polynomial coefficients, and every
//! recipient checks its own share against them — `s_i·G == Σ_j i^j·C_j` — so a bad share is caught
//! immediately, by the holder, with no interaction. This is the verifiable upgrade the threshold
//! service-key hosting needs (spec §12.3), over the same ristretto255 group as [`crate`]'s VRF.
//!
//! Reconstruction is Lagrange interpolation at `x = 0` over the ristretto scalar field. Interactive
//! multi-dealer DKG (with complaint rounds) composes `n` of these — each node deals, and the joint
//! secret is the sum of the honest dealers' constant terms; that layer is a straightforward
//! extension of this verifiable primitive.

use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use fanos_crypto::hash::hash_xof;

/// A deterministic BLAKE3-XOF RNG for reproducible dealing (tests, seeded deployments). It
/// implements `rand_core` 0.6 so it can drive `Scalar::random`.
pub struct DeterministicRng {
    seed: [u8; 32],
    counter: u64,
}

impl DeterministicRng {
    /// Seed the RNG from arbitrary bytes.
    #[must_use]
    pub fn new(seed: &[u8]) -> Self {
        let mut s = [0u8; 32];
        hash_xof("FANOS-v1/vss-rng", seed, &mut s);
        Self {
            seed: s,
            counter: 0,
        }
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut input = [0u8; 40];
        let (head, tail) = input.split_at_mut(32);
        head.copy_from_slice(&self.seed);
        tail.copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        hash_xof("FANOS-v1/vss-rng-block", &input, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}

/// A verifiable share of a secret: `(index, f(index))`.
#[derive(Clone, Copy, Debug)]
pub struct VssShare {
    /// The holder's evaluation point (`1..=n`).
    pub index: u8,
    value: Scalar,
}

impl VssShare {
    /// The 32-byte encoding of the share value (for transport / storage).
    #[must_use]
    pub fn value_bytes(&self) -> [u8; 32] {
        self.value.to_bytes()
    }

    /// The holder index of this share.
    #[must_use]
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The scalar value (for in-crate aggregation, e.g. DKG).
    pub(crate) fn value(&self) -> Scalar {
        self.value
    }

    /// Construct a share from its parts (for in-crate aggregation, e.g. DKG final shares).
    pub(crate) fn from_parts(index: u8, value: Scalar) -> Self {
        Self { index, value }
    }

    /// Tamper with the share value (test-only, to model a cheating dealer).
    #[cfg(test)]
    pub(crate) fn corrupt(&mut self) {
        self.value += Scalar::ONE;
    }
}

/// The dealer's public commitments to the polynomial coefficients (`C_j = a_j·G`).
#[derive(Clone, Debug)]
pub struct VssCommitment {
    coeffs: Vec<RistrettoPoint>,
}

impl VssCommitment {
    /// The threshold `t` this commitment encodes (the polynomial degree plus one).
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.coeffs.len()
    }

    /// The commitment to the constant term `C_0 = secret·G` — the dealer's public contribution.
    pub(crate) fn commitment_point(&self) -> RistrettoPoint {
        self.coeffs
            .first()
            .copied()
            .unwrap_or_else(RistrettoPoint::identity)
    }
}

/// Deal a secret into `shares` verifiable shares, any `threshold` of which reconstruct it. The
/// secret is reduced into the ristretto scalar field. Returns `None` for a nonsensical
/// `(threshold, shares)` (`1 ≤ t ≤ n ≤ 255`).
#[must_use]
pub fn deal<R: RngCore + CryptoRng>(
    secret: &[u8; 32],
    threshold: usize,
    shares: usize,
    rng: &mut R,
) -> Option<(Vec<VssShare>, VssCommitment)> {
    if threshold == 0 || threshold > shares || shares > 255 {
        return None;
    }
    // Polynomial f(x) = a_0 + a_1 x + … + a_{t-1} x^{t-1}, with a_0 = secret.
    let mut coeffs = Vec::with_capacity(threshold);
    coeffs.push(Scalar::from_bytes_mod_order(*secret));
    for _ in 1..threshold {
        coeffs.push(Scalar::random(rng));
    }
    let commitment = VssCommitment {
        coeffs: coeffs
            .iter()
            .map(|a| a * RISTRETTO_BASEPOINT_POINT)
            .collect(),
    };
    let out = (1..=shares as u8)
        .map(|index| {
            let x = Scalar::from(u64::from(index));
            // Horner evaluation of f(index).
            let mut acc = Scalar::ZERO;
            for a in coeffs.iter().rev() {
                acc = acc * x + a;
            }
            VssShare { index, value: acc }
        })
        .collect();
    Some((out, commitment))
}

/// Verify a share against the dealer's commitments: `s_i·G == Σ_j i^j·C_j` (Feldman check). A
/// holder that fails this has been handed an inconsistent share by a cheating dealer.
#[must_use]
pub fn verify_share(share: &VssShare, commitment: &VssCommitment) -> bool {
    let x = Scalar::from(u64::from(share.index));
    let mut rhs = RistrettoPoint::identity();
    let mut x_pow = Scalar::ONE;
    for c in &commitment.coeffs {
        rhs += x_pow * c;
        x_pow *= x;
    }
    share.value * RISTRETTO_BASEPOINT_POINT == rhs
}

/// Reconstruct the secret from any `≥ t` shares by Lagrange interpolation at `x = 0`. Returns
/// `None` if there are no shares or two of them share an index.
#[must_use]
pub fn reconstruct(shares: &[VssShare]) -> Option<[u8; 32]> {
    if shares.is_empty() {
        return None;
    }
    let mut secret = Scalar::ZERO;
    for si in shares {
        let xi = Scalar::from(u64::from(si.index));
        // Lagrange basis λ_i(0) = Π_{j≠i} x_j / (x_j − x_i).
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for sj in shares {
            if sj.index != si.index {
                let xj = Scalar::from(u64::from(sj.index));
                num *= xj;
                den *= xj - xi;
            }
        }
        if den == Scalar::ZERO {
            return None; // duplicate index
        }
        secret += num * den.invert() * si.value;
    }
    Some(secret.to_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        hash_xof("test-secret", b"the-service-key", &mut s);
        s
    }

    #[test]
    fn any_threshold_subset_reconstructs_the_secret() {
        let mut rng = DeterministicRng::new(b"deal-1");
        let expected = Scalar::from_bytes_mod_order(secret()).to_bytes();
        let (shares, _c) = deal(&secret(), 3, 5, &mut rng).unwrap();
        // Several different 3-subsets all recover the same secret.
        for subset in [[0, 1, 2], [1, 3, 4], [0, 2, 4]] {
            let picked: Vec<_> = subset.iter().map(|&i| shares[i]).collect();
            assert_eq!(reconstruct(&picked), Some(expected));
        }
    }

    #[test]
    fn fewer_than_threshold_shares_do_not_reveal_the_secret() {
        let mut rng = DeterministicRng::new(b"deal-2");
        let expected = Scalar::from_bytes_mod_order(secret()).to_bytes();
        let (shares, _c) = deal(&secret(), 3, 5, &mut rng).unwrap();
        // Two shares interpolate to *something else* — the secret is information-theoretically hidden.
        let two: Vec<_> = shares[..2].to_vec();
        assert_ne!(reconstruct(&two), Some(expected));
    }

    #[test]
    fn every_honest_share_verifies_against_the_commitment() {
        let mut rng = DeterministicRng::new(b"deal-3");
        let (shares, commitment) = deal(&secret(), 4, 7, &mut rng).unwrap();
        assert_eq!(commitment.threshold(), 4);
        assert!(shares.iter().all(|s| verify_share(s, &commitment)));
    }

    #[test]
    fn a_tampered_share_is_caught_by_the_feldman_check() {
        let mut rng = DeterministicRng::new(b"deal-4");
        let (mut shares, commitment) = deal(&secret(), 3, 5, &mut rng).unwrap();
        // A dealer (or a corrupted transport) flips a share; the holder detects it.
        shares[2].value += Scalar::ONE;
        assert!(
            !verify_share(&shares[2], &commitment),
            "the bad share fails verification"
        );
        assert!(
            verify_share(&shares[0], &commitment),
            "honest shares still pass"
        );
    }

    #[test]
    fn nonsensical_parameters_are_rejected() {
        let mut rng = DeterministicRng::new(b"deal-5");
        assert!(deal(&secret(), 0, 3, &mut rng).is_none());
        assert!(deal(&secret(), 4, 3, &mut rng).is_none()); // t > n
    }
}
