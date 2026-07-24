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
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use fanos_primitives::hash::hash_xof;

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
///
/// Deliberately **not** `Copy` (audit #124, mirroring `VrfSecret`): a secret share must not be silently
/// duplicated across stack frames — every propagation is an explicit `clone`, so the places a secret
/// travels are visible and auditable.
#[derive(Clone)]
pub struct VssShare {
    /// The holder's evaluation point (`1..=n`).
    pub index: u8,
    value: Scalar,
}

// Redacted Debug (audit #124): the derived Debug would print `value` — a raw secret Shamir/Feldman share
// (curve25519's own Scalar Debug ignores field privacy and prints the bytes) — so one stray `{:?}`/`dbg!`
// on a share, or on any struct that contains one, would leak enough to reconstruct the dealer's secret.
impl core::fmt::Debug for VssShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VssShare")
            .field("index", &self.index)
            .field("value", &"<redacted>")
            .finish()
    }
}

// Wipe the secret share scalar on drop (audit A6) — `index` is the public evaluation point, `value`
// is the secret. `Scalar: Zeroize` via curve25519-dalek's `zeroize` feature.
impl Drop for VssShare {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}
impl ZeroizeOnDrop for VssShare {}

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

    /// The `index(1) ‖ value(32)` wire encoding (33 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = self.index;
        out[1..].copy_from_slice(&self.value.to_bytes());
        out
    }

    /// Decode a share from its 33-byte encoding, or `None` if the value is not canonical.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let index = *bytes.first()?;
        let value_bytes: [u8; 32] = bytes.get(1..33)?.try_into().ok()?;
        let value = Option::from(Scalar::from_canonical_bytes(value_bytes))?;
        Some(Self { index, value })
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

    /// The public key `Y_i = Σ_j i^j·C_j` of the share held at `index`, evaluated in the exponent by
    /// Horner. This is the value the Feldman check ([`verify_share`]) and a DVRF partial's DLEQ proof
    /// ([`crate::beacon`]) are verified against; derived from the public commitment alone, it reveals
    /// nothing about the secret.
    pub(crate) fn public_share(&self, index: u8) -> RistrettoPoint {
        let x = Scalar::from(u64::from(index));
        let mut acc = RistrettoPoint::identity();
        let mut x_pow = Scalar::ONE;
        for c in &self.coeffs {
            acc += x_pow * c;
            x_pow *= x;
        }
        acc
    }

    /// The `t(1) ‖ C_0 ‖ … ‖ C_{t-1}` wire encoding (`1 + 32t` bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 * self.coeffs.len());
        out.push(self.coeffs.len() as u8);
        for c in &self.coeffs {
            out.extend_from_slice(c.compress().as_bytes());
        }
        out
    }

    /// The coefficient-wise sum of several commitments — the public commitment of the sum of their
    /// polynomials. All must share the same degree (`threshold`); returns `None` if the slice is empty
    /// or the degrees differ. Aggregating a DKG's qualified dealers' commitments yields the joint
    /// polynomial's commitment, whose [`public_share(i)`](Self::public_share) is holder `i`'s public key
    /// `Y_i = s_i·G` — exactly what a distributed-VRF beacon partial ([`crate::beacon`]) is verified
    /// against.
    #[must_use]
    pub fn aggregate(commitments: &[&VssCommitment]) -> Option<VssCommitment> {
        let (first, rest) = commitments.split_first()?;
        let mut coeffs = first.coeffs.clone();
        for c in rest {
            if c.coeffs.len() != coeffs.len() {
                return None;
            }
            for (acc, add) in coeffs.iter_mut().zip(&c.coeffs) {
                *acc += add;
            }
        }
        Some(VssCommitment { coeffs })
    }

    /// Decode a commitment, or `None` if a coefficient is not a valid group element.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let t = *bytes.first()? as usize;
        let mut coeffs = Vec::with_capacity(t);
        for i in 0..t {
            let start = 1 + i * 32;
            let chunk = bytes.get(start..start + 32)?;
            let point = CompressedRistretto::from_slice(chunk).ok()?.decompress()?;
            coeffs.push(point);
        }
        Some(Self { coeffs })
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
    if shares > 255 {
        return None;
    }
    let indices: Vec<u8> = (1..=shares as u8).collect();
    deal_scalar(Scalar::from_bytes_mod_order(*secret), threshold, &indices, rng)
}

/// Deal a secret **scalar** into shares at the given evaluation `indices`, any `threshold` of which
/// reconstruct it — the shared core of [`deal`] (indices `1..=n`, secret reduced from bytes) and
/// [`reshare`] (indices = the *new* holder set, secret = an *old* holder's share). Returns `None` on a
/// nonsensical shape (`1 ≤ t ≤ |indices| ≤ 255`, and no index `0`, which would expose the secret directly).
fn deal_scalar<R: RngCore + CryptoRng>(
    secret: Scalar,
    threshold: usize,
    indices: &[u8],
    rng: &mut R,
) -> Option<(Vec<VssShare>, VssCommitment)> {
    if threshold == 0 || threshold > indices.len() || indices.len() > 255 {
        return None;
    }
    if indices.contains(&0) {
        return None;
    }
    // Polynomial f(x) = a_0 + a_1 x + … + a_{t-1} x^{t-1}, with a_0 = secret.
    let mut coeffs = Vec::with_capacity(threshold);
    coeffs.push(secret);
    for _ in 1..threshold {
        coeffs.push(Scalar::random(rng));
    }
    let commitment = VssCommitment {
        coeffs: coeffs
            .iter()
            .map(|a| a * RISTRETTO_BASEPOINT_POINT)
            .collect(),
    };
    let out = indices
        .iter()
        .map(|&index| {
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
    share.value * RISTRETTO_BASEPOINT_POINT == commitment.public_share(share.index)
}

/// The Lagrange basis coefficients `λ_i(0) = Π_{j≠i} x_j / (x_j − x_i)` at `x = 0` for share `indices`
/// (`x_i = index`), one per index in the given order — the shared core of interpolation in the clear
/// ([`reconstruct`]) and combination in the exponent ([`crate::beacon::combine`]). `None` if `indices`
/// is empty or two entries collide (the denominator vanishes and the interpolation is undefined), so both
/// callers share one guarded derivation instead of hand-rolling it.
pub(crate) fn lagrange_coeffs_at_zero(indices: &[u8]) -> Option<Vec<Scalar>> {
    if indices.is_empty() {
        return None;
    }
    let mut coeffs = Vec::with_capacity(indices.len());
    for &i in indices {
        let xi = Scalar::from(u64::from(i));
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for &j in indices {
            if j != i {
                let xj = Scalar::from(u64::from(j));
                num *= xj;
                den *= xj - xi;
            }
        }
        if den == Scalar::ZERO {
            return None; // a duplicate index — the interpolation is undefined
        }
        coeffs.push(num * den.invert());
    }
    Some(coeffs)
}

/// Reconstruct the secret from any `≥ t` shares by Lagrange interpolation at `x = 0`. Returns
/// `None` if there are no shares or two of them share an index.
#[must_use]
pub fn reconstruct(shares: &[VssShare]) -> Option<[u8; 32]> {
    let indices: Vec<u8> = shares.iter().map(|s| s.index).collect();
    let coeffs = lagrange_coeffs_at_zero(&indices)?;
    let secret: Scalar = shares
        .iter()
        .zip(&coeffs)
        .map(|(s, c)| c * s.value)
        .sum();
    Some(secret.to_bytes())
}

/// One old holder's contribution to a **verifiable secret redistribution** (Desmedt–Jajodia / proactive
/// VSS): a fresh degree-`(t'−1)` polynomial `gᵢ` with `gᵢ(0) = sᵢ` (the holder's own share), materialised as
/// its public Feldman commitment `Dᵢ` and one sub-share `gᵢ(j)` for each new holder `j`. Redistributing the
/// beacon key this way — from a depleted old anchor set to a fresh set at a new threshold — is what lets the
/// epoch clock survive anchor churn without ever exposing the secret or changing the group key (audit R-C1).
///
/// **Not `Copy`, redacted `Debug`** (audit #124): it carries raw secret sub-shares.
#[derive(Clone)]
pub struct ReshareDealing {
    old_index: u8,
    commitment: VssCommitment,
    subshares: Vec<VssShare>,
}

impl core::fmt::Debug for ReshareDealing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReshareDealing")
            .field("old_index", &self.old_index)
            .field("commitment", &self.commitment)
            .field("subshares", &"<redacted>")
            .finish()
    }
}

impl ReshareDealing {
    /// The old holder (evaluation index) that produced this contribution.
    #[must_use]
    pub fn old_index(&self) -> u8 {
        self.old_index
    }

    /// The public Feldman commitment `Dᵢ` to `gᵢ` (its constant term is `sᵢ·G`). Broadcast; verifiable by all.
    #[must_use]
    pub fn commitment(&self) -> &VssCommitment {
        &self.commitment
    }

    /// This contribution's sub-share for new holder `new_index` (`gᵢ(new_index)`), if present. Delivered
    /// privately to that holder, who checks it against [`commitment`](Self::commitment) via [`verify_share`].
    #[must_use]
    pub fn subshare_for(&self, new_index: u8) -> Option<&VssShare> {
        self.subshares.iter().find(|s| s.index == new_index)
    }
}

/// An old holder re-shares its `share` to the `new_indices` holder set at a fresh `new_threshold`. The new
/// polynomial's constant term is fixed to this share's value (`gᵢ(0) = sᵢ`), so the redistribution preserves
/// the dealt secret. Returns `None` on a nonsensical shape (`1 ≤ t' ≤ |new_indices| ≤ 255`, indices non-zero).
#[must_use]
pub fn reshare<R: RngCore + CryptoRng>(
    share: &VssShare,
    new_threshold: usize,
    new_indices: &[u8],
    rng: &mut R,
) -> Option<ReshareDealing> {
    let (subshares, commitment) = deal_scalar(share.value, new_threshold, new_indices, rng)?;
    Some(ReshareDealing {
        old_index: share.index,
        commitment,
        subshares,
    })
}

/// Check that a resharing commitment `Dᵢ` **binds to the real old share**: its constant term equals the old
/// holder's public share `sᵢ·G` derived from the *old* commitment. This is the public gate on the canonical
/// contributor set — a contributor cannot redistribute a *wrong* secret (audit R-C1). Every node (anchor or
/// consumer) applies it identically to the flooded `Dᵢ`, so all agree on the valid contributors.
#[must_use]
pub fn verify_reshare_commit(
    old_index: u8,
    commit: &VssCommitment,
    old_commitment: &VssCommitment,
) -> bool {
    commit.commitment_point() == old_commitment.public_share(old_index)
}

/// Verify a resharing contribution end to end: (1) [`verify_reshare_commit`] binds `gᵢ(0)` to the real old
/// share, and (2) every emitted sub-share verifies against `Dᵢ` (Feldman). Used where the whole dealing is in
/// hand (the dealer, a test); a receiver that holds only its own sub-share checks (1) via
/// [`verify_reshare_commit`] and (2) via [`verify_share`] directly.
#[must_use]
pub fn verify_reshare(dealing: &ReshareDealing, old_commitment: &VssCommitment) -> bool {
    verify_reshare_commit(dealing.old_index, &dealing.commitment, old_commitment)
        && dealing
            .subshares
            .iter()
            .all(|s| verify_share(s, &dealing.commitment))
}

/// Combine the flooded **public** commitments `Dᵢ` of a canonical contributor set into the redistributed
/// group commitment `C' = Σᵢ λᵢ(0)·Dᵢ`. Derivable by **any** node from public data, so every node — anchor or
/// pure consumer — agrees on the new commitment. Contributions are `(old_index, Dᵢ)`.
///
/// Because `C'₀ = Σᵢ λᵢ(0)·sᵢ·G = f(0)·G` (Lagrange interpolation of the *old* sharing at 0), the group key is
/// **unchanged** — future partials against `C'` are the identical DVRF value. `None` if the set is empty, has
/// a duplicate old index, or mixes commitment degrees.
#[must_use]
pub fn combine_reshare_commitment(
    contributions: &[(u8, &VssCommitment)],
) -> Option<VssCommitment> {
    let old_indices: Vec<u8> = contributions.iter().map(|&(i, _)| i).collect();
    let lambdas = lagrange_coeffs_at_zero(&old_indices)?;
    let new_threshold = contributions.first()?.1.coeffs.len();
    let mut coeffs = Vec::with_capacity(new_threshold);
    coeffs.resize(new_threshold, RistrettoPoint::identity());
    for (&(_, d), &lambda) in contributions.iter().zip(&lambdas) {
        if d.coeffs.len() != new_threshold {
            return None; // all contributions must reshare at the same new threshold
        }
        for (acc, c) in coeffs.iter_mut().zip(&d.coeffs) {
            *acc += lambda * c;
        }
    }
    Some(VssCommitment { coeffs })
}

/// Combine the **private** sub-shares `gᵢ(j)` new holder `new_index` received from the *same* canonical
/// contributor set into its share `s'ⱼ = Σᵢ λᵢ(0)·gᵢ(j)` of the redistributed secret. Contributions are
/// `(old_index, gᵢ(j))` and the old-index set **must** match [`combine_reshare_commitment`]'s exactly, so the
/// share lies on the `f'` that commitment commits to. `None` if empty or an old index repeats.
///
/// **Precondition:** `≥` the old threshold `t` **distinct** old holders (else the interpolation does not
/// recover `f(0)`). The resulting share verifies against the combined commitment iff every sub-share was
/// Feldman-valid — the caller must have checked each with [`verify_share`] first.
#[must_use]
pub fn combine_reshare_share(
    new_index: u8,
    contributions: &[(u8, &VssShare)],
) -> Option<VssShare> {
    let old_indices: Vec<u8> = contributions.iter().map(|&(i, _)| i).collect();
    let lambdas = lagrange_coeffs_at_zero(&old_indices)?;
    let value: Scalar = contributions
        .iter()
        .zip(&lambdas)
        .map(|(&(_, s), &lambda)| lambda * s.value)
        .sum();
    Some(VssShare { index: new_index, value })
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
            let picked: Vec<_> = subset.iter().map(|&i| shares[i].clone()).collect();
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

    #[test]
    fn aggregated_commitments_verify_summed_shares() {
        // Two dealers' sharings of the same degree. The aggregate commitment is the commitment of the
        // summed polynomial, so holder i's *summed* share (s¹ᵢ + s²ᵢ) verifies against it — the exact
        // DKG relation the beacon relies on (final share = Σ dealers, joint key = Σ commitments).
        let (sh1, c1) = deal(&secret(), 3, 5, &mut DeterministicRng::new(b"agg-d1")).unwrap();
        let mut s2 = [0u8; 32];
        hash_xof("agg-secret-2", b"second-dealer", &mut s2);
        let (sh2, c2) = deal(&s2, 3, 5, &mut DeterministicRng::new(b"agg-d2")).unwrap();

        let agg = VssCommitment::aggregate(&[&c1, &c2]).unwrap();
        for i in 0..5 {
            let summed = VssShare::from_parts(sh1[i].index, sh1[i].value() + sh2[i].value());
            assert!(
                verify_share(&summed, &agg),
                "the summed share verifies against the aggregate commitment"
            );
        }
        // Mismatched degree, or an empty set, aggregate to nothing.
        let (_, c_lowdeg) = deal(&secret(), 2, 5, &mut DeterministicRng::new(b"agg-d3")).unwrap();
        assert!(VssCommitment::aggregate(&[&c1, &c_lowdeg]).is_none());
        assert!(VssCommitment::aggregate(&[]).is_none());
    }

    #[test]
    fn resharing_preserves_the_secret_and_the_group_key() {
        // An original 4-of-7 sharing.
        let (old_shares, old_c) = deal(&secret(), 4, 7, &mut DeterministicRng::new(b"reshare-1")).unwrap();
        let group_key = old_c.commitment_point();
        let expected = Scalar::from_bytes_mod_order(secret()).to_bytes();

        // A quorum of exactly t = 4 old holders redistribute to a FRESH, smaller anchor set (indices 10..=14)
        // at a new threshold t' = 3 — the R-C1 move: reconstitute a depleted set from survivors, no secret
        // ever exposed, no reconstruction of the key at any single point.
        let new_indices = [10u8, 11, 12, 13, 14];
        let dealings: Vec<ReshareDealing> = old_shares[..4]
            .iter()
            .map(|s| reshare(s, 3, &new_indices, &mut DeterministicRng::new(&[s.index])).unwrap())
            .collect();

        // Every contribution verifies against the OLD commitment (its g_i(0) is the real old share s_i).
        assert!(dealings.iter().all(|d| verify_reshare(d, &old_c)));

        // The new group commitment is derived ONCE from the public D_i — identical for every node — and its
        // constant term is the UNCHANGED group key.
        let commit_contribs: Vec<(u8, &VssCommitment)> =
            dealings.iter().map(|d| (d.old_index(), d.commitment())).collect();
        let new_c = combine_reshare_commitment(&commit_contribs).unwrap();
        assert_eq!(new_c.commitment_point(), group_key, "the redistribution preserves the group key");

        // Each new holder combines its own sub-shares of the same canonical set into its new share.
        let new_shares: Vec<VssShare> = new_indices
            .iter()
            .map(|&j| {
                let share_contribs: Vec<(u8, &VssShare)> = dealings
                    .iter()
                    .map(|d| (d.old_index(), d.subshare_for(j).unwrap()))
                    .collect();
                combine_reshare_share(j, &share_contribs).unwrap()
            })
            .collect();
        for s in &new_shares {
            assert!(verify_share(s, &new_c), "each new share verifies against the new commitment");
        }

        // Any t' = 3 of the new shares reconstruct the ORIGINAL secret — continuity end to end.
        let picked: Vec<VssShare> = new_shares.iter().take(3).cloned().collect();
        assert_eq!(reconstruct(&picked), Some(expected), "the redistributed secret is the original");
        // Two are not enough (the new threshold really is 3).
        let two: Vec<VssShare> = new_shares.iter().take(2).cloned().collect();
        assert_ne!(reconstruct(&two), Some(expected));
    }

    #[test]
    fn a_reshare_that_lies_about_its_old_share_is_caught() {
        let (old_shares, old_c) = deal(&secret(), 3, 5, &mut DeterministicRng::new(b"reshare-2")).unwrap();
        let new_indices = [10u8, 11, 12, 13, 14];
        // An honest reshare verifies against the old commitment.
        let good = reshare(&old_shares[0], 3, &new_indices, &mut DeterministicRng::new(b"good")).unwrap();
        assert!(verify_reshare(&good, &old_c));
        // A contributor that reshares a DIFFERENT constant term (a wrong "share") is rejected: its D_i[0] no
        // longer equals the old commitment's public share for its index — so it cannot inject a wrong secret.
        let mut wrong = old_shares[0].clone();
        wrong.corrupt(); // s_0 + 1
        let bad = reshare(&wrong, 3, &new_indices, &mut DeterministicRng::new(b"bad")).unwrap();
        assert!(!verify_reshare(&bad, &old_c));
    }

    #[test]
    fn a_tampered_reshare_subshare_is_caught() {
        let (old_shares, old_c) = deal(&secret(), 3, 5, &mut DeterministicRng::new(b"reshare-3")).unwrap();
        let mut d = reshare(&old_shares[0], 3, &[10u8, 11, 12], &mut DeterministicRng::new(b"h")).unwrap();
        assert!(verify_reshare(&d, &old_c));
        // A sub-share inconsistent with the contributor's own commitment D_i fails the Feldman check.
        d.subshares[1].value += Scalar::ONE;
        assert!(!verify_reshare(&d, &old_c));
        // The lone honest holder still checks its own sub-share directly (the receiver's view).
        assert!(verify_share(&d.subshares[0], d.commitment()));
        assert!(!verify_share(&d.subshares[1], d.commitment()));
    }
}
