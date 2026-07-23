//! Shamir secret sharing over `GF(256)` (spec §L6, the threshold substrate of NYX/CALYPSO).
//!
//! A secret is split into `n` shares so that any `t` reconstruct it and any `t−1` learn
//! **nothing** — the "0-knowledge below threshold" guarantee that a NYX hop (spec §5.2) and a
//! threshold-hosted CALYPSO service (spec §12.3) rely on. Sharing is byte-wise over
//! `GF(256)`: each secret byte is the constant term of an independent degree-`(t−1)`
//! polynomial, evaluated at the share's `x`-coordinate; reconstruction is Lagrange
//! interpolation at `x = 0`.
//!
//! The caller supplies the polynomial randomness, so the security posture (a CSPRNG) is
//! explicit and the function is deterministic and testable.

use alloc::vec;
use alloc::vec::Vec;

use fanos_field::{F256, Field};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A share: its non-zero `x`-coordinate and the per-byte evaluations `y`.
///
/// The evaluations `y` are secret material (any `t` shares reconstruct the secret), so a `Share`
/// wipes them from memory when it is dropped ([`ZeroizeOnDrop`]). The evaluations are **private** with a
/// borrowing accessor — a caller cannot `mem::take` or otherwise move the secret out of a `Share`, which
/// would bypass that drop-wipe; it can only read it.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    x: u8,
    y: Vec<u8>,
}

// Redacted Debug (audit #124): `y` is secret share material (any `t` shares reconstruct the secret), so
// the derived Debug — which would print it in full — is replaced; only `x` (the public point) is shown.
impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Share")
            .field("x", &self.x)
            .field("y", &"<redacted>")
            .finish()
    }
}

impl Share {
    /// Assemble a share from its evaluation point `x` and per-byte evaluations `y`. `x = 0` is the secret
    /// slot, never a valid share index; a `Share` built with it is rejected at [`reconstruct`], so this
    /// constructor stays total (parsing that cannot yet vouch for `x` defers the check to reconstruction).
    #[must_use]
    pub fn new(x: u8, y: Vec<u8>) -> Self {
        Self { x, y }
    }

    /// The evaluation point (`1..=255`, distinct per share).
    #[must_use]
    pub fn x(&self) -> u8 {
        self.x
    }

    /// The polynomial evaluations, one per secret byte — a **borrow** (the secret never leaves the share).
    #[must_use]
    pub fn y(&self) -> &[u8] {
        &self.y
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

impl ZeroizeOnDrop for Share {}

/// Failure modes of the sharing API.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShamirError {
    /// `threshold` was `0`, or greater than `shares`.
    BadThreshold,
    /// `shares` was `0` or `> 255` (x-coordinates must be distinct and non-zero).
    BadShareCount,
    /// Not enough randomness bytes: need `(threshold − 1) · secret.len()`.
    InsufficientRandomness,
    /// Reconstruction was given fewer shares than needed, or duplicate/zero x-coordinates.
    BadShares,
}

impl core::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::BadThreshold => "threshold is zero or exceeds the share count",
            Self::BadShareCount => "share count is zero or exceeds 255",
            Self::InsufficientRandomness => "not enough randomness for the sharing polynomial",
            Self::BadShares => "too few shares, or duplicate/zero x-coordinates",
        })
    }
}

impl core::error::Error for ShamirError {}

#[inline]
fn mul(a: u8, b: u8) -> u8 {
    F256::mul(u32::from(a), u32::from(b)) as u8
}

#[inline]
fn add(a: u8, b: u8) -> u8 {
    F256::add(u32::from(a), u32::from(b)) as u8
}

/// Split `secret` into `shares` shares with reconstruction threshold `threshold`.
///
/// `randomness` must supply at least `(threshold − 1) · secret.len()` bytes of CSPRNG output
/// (the non-constant polynomial coefficients). Share `x`-coordinates are `1..=shares`.
pub fn split(
    secret: &[u8],
    threshold: u8,
    shares: u8,
    randomness: &[u8],
) -> Result<Vec<Share>, ShamirError> {
    if threshold == 0 || threshold > shares {
        return Err(ShamirError::BadThreshold);
    }
    if shares == 0 {
        return Err(ShamirError::BadShareCount);
    }
    let degree = usize::from(threshold - 1);
    if randomness.len() < degree * secret.len() {
        return Err(ShamirError::InsufficientRandomness);
    }

    let mut out = Vec::with_capacity(usize::from(shares));
    for x in 1..=shares {
        let mut y = Vec::with_capacity(secret.len());
        for (i, &s0) in secret.iter().enumerate() {
            // Evaluate the degree-(t-1) polynomial for byte i at x via Horner, from the top
            // coefficient down to the constant term s0.
            let mut acc = 0u8;
            for c in 0..degree {
                let coeff = *randomness
                    .get(c * secret.len() + i)
                    .ok_or(ShamirError::InsufficientRandomness)?;
                acc = add(mul(acc, x), coeff);
            }
            acc = add(mul(acc, x), s0);
            y.push(acc);
        }
        out.push(Share::new(x, y));
    }
    Ok(out)
}

/// Reconstruct the secret from `shares` (any `≥ t` of them) by Lagrange interpolation at
/// `x = 0`. All shares must have the same length, distinct non-zero `x`-coordinates.
pub fn reconstruct(shares: &[Share]) -> Result<Vec<u8>, ShamirError> {
    let first = shares.first().ok_or(ShamirError::BadShares)?;
    let len = first.y().len();
    if shares.iter().any(|s| s.y().len() != len || s.x() == 0) {
        return Err(ShamirError::BadShares);
    }
    // Distinct x-coordinates.
    for (a, sa) in shares.iter().enumerate() {
        for sb in shares.iter().skip(a + 1) {
            if sa.x() == sb.x() {
                return Err(ShamirError::BadShares);
            }
        }
    }

    let mut secret = vec![0u8; len];
    for (j, sj) in shares.iter().enumerate() {
        // Lagrange basis L_j(0) = Π_{m≠j} x_m / (x_m − x_j).
        let mut num = 1u8;
        let mut den = 1u8;
        for (m, sm) in shares.iter().enumerate() {
            if m == j {
                continue;
            }
            num = mul(num, sm.x());
            den = mul(den, add(sm.x(), sj.x())); // subtraction == addition in GF(2^8)
        }
        let coeff = mul(num, F256::inv(u32::from(den)) as u8);
        for (out, &yij) in secret.iter_mut().zip(sj.y()) {
            *out = add(*out, mul(coeff, yij));
        }
    }
    Ok(secret)
}

/// **Proactively reshare** a secret to a new committee without ever reconstructing it — the combine step
/// (CHURP-style, for a rotating threshold committee).
///
/// Each old committee member at `x`-coordinate `x_i` locally re-splits its OWN share value with
/// [`split`] over the new committee's positions (its *resharing contribution*), and sends new member `j`
/// the sub-share at `j`. This function is what new member `j` (at `new_x`) then runs: given the
/// `contributions` it received — `contributions[k]` from the old member at `old_xs[k]`, all evaluated at
/// this new member's position — it returns member `j`'s share of the **same** secret under the new
/// committee, as the Lagrange-weighted sum `Σ_k λ_k · contributions[k]` where
/// `λ_k = Π_{m≠k} x_m/(x_m − x_k)` reconstructs the old polynomial at 0. The secret is never materialized
/// at any node, and every new member using the same `old_xs` subset lands on one consistent new polynomial.
///
/// `contributions` and `old_xs` must be the same non-zero length (`≥` the old threshold), all sub-shares the
/// same byte length, and the `old_xs` distinct and non-zero. `new_x` must be non-zero.
///
/// # Errors
/// [`ShamirError::BadShares`] on a length mismatch, empty input, zero/duplicate `old_xs`, or zero `new_x`.
pub fn combine_contributions(
    new_x: u8,
    contributions: &[Share],
    old_xs: &[u8],
) -> Result<Share, ShamirError> {
    if new_x == 0 || contributions.is_empty() || contributions.len() != old_xs.len() {
        return Err(ShamirError::BadShares);
    }
    let len = contributions.first().ok_or(ShamirError::BadShares)?.y().len();
    if contributions.iter().any(|c| c.y().len() != len) || old_xs.contains(&0) {
        return Err(ShamirError::BadShares);
    }
    // Distinct old x-coordinates (else the Lagrange denominator is zero / the subset is degenerate).
    for (a, &xa) in old_xs.iter().enumerate() {
        for &xb in old_xs.iter().skip(a + 1) {
            if xa == xb {
                return Err(ShamirError::BadShares);
            }
        }
    }

    let mut y = vec![0u8; len];
    for (k, ck) in contributions.iter().enumerate() {
        // λ_k = Π_{m≠k} x_m / (x_m − x_k) — the old polynomial's Lagrange basis at 0 (subtraction == add).
        let xk = *old_xs.get(k).ok_or(ShamirError::BadShares)?;
        let mut num = 1u8;
        let mut den = 1u8;
        for (m, &xm) in old_xs.iter().enumerate() {
            if m == k {
                continue;
            }
            num = mul(num, xm);
            den = mul(den, add(xm, xk));
        }
        let coeff = mul(num, F256::inv(u32::from(den)) as u8);
        for (out, &c) in y.iter_mut().zip(ck.y()) {
            *out = add(*out, mul(coeff, c));
        }
    }
    Ok(Share::new(new_x, y))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn deterministic_randomness(n: usize) -> Vec<u8> {
        // Not secure — a test fixture standing in for CSPRNG output.
        (0..n).map(|i| ((i * 167 + 13) % 251) as u8).collect()
    }

    #[test]
    fn any_threshold_subset_reconstructs() {
        let secret = b"FANOS threshold sheaf";
        let (t, n) = (3u8, 5u8);
        let rnd = deterministic_randomness(usize::from(t - 1) * secret.len());
        let shares = split(secret, t, n, &rnd).unwrap();
        assert_eq!(shares.len(), usize::from(n));

        // Every 3-of-5 subset recovers the exact secret.
        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let subset = [shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(reconstruct(&subset).unwrap(), secret);
                }
            }
        }
    }

    #[test]
    fn fewer_than_threshold_does_not_recover() {
        let secret = b"secret";
        let rnd = deterministic_randomness(2 * secret.len());
        let shares = split(secret, 3, 5, &rnd).unwrap();
        // Two shares (t-1) interpolate a different (wrong) value — no recovery.
        let wrong = reconstruct(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_ne!(wrong, secret);
    }

    #[test]
    fn all_n_shares_also_reconstruct() {
        let secret = b"quorum";
        let rnd = deterministic_randomness(4 * secret.len());
        let shares = split(secret, 5, 7, &rnd).unwrap();
        assert_eq!(reconstruct(&shares).unwrap(), secret);
    }

    #[test]
    fn rejects_bad_parameters() {
        assert_eq!(split(b"x", 0, 3, &[0; 8]), Err(ShamirError::BadThreshold));
        assert_eq!(split(b"x", 4, 3, &[0; 8]), Err(ShamirError::BadThreshold));
        assert_eq!(
            split(b"xy", 2, 3, &[]),
            Err(ShamirError::InsufficientRandomness)
        );
        assert_eq!(reconstruct(&[]), Err(ShamirError::BadShares));
    }

    #[test]
    fn reconstruct_rejects_malformed_share_sets() {
        // x = 0 is the secret slot, never a valid share index.
        assert_eq!(
            reconstruct(&[Share::new(0, [1].to_vec()), Share::new(2, [3].to_vec())]),
            Err(ShamirError::BadShares),
            "a share at x = 0 is rejected"
        );
        // Duplicate x-coordinates (a replayed / forged share index) must be rejected rather than
        // dividing by zero in the Lagrange denominator (add(x_m, x_j) = 0 when x_m == x_j).
        assert_eq!(
            reconstruct(&[Share::new(1, [5].to_vec()), Share::new(1, [6].to_vec())]),
            Err(ShamirError::BadShares),
            "duplicate share indices are rejected, not a divide-by-zero"
        );
        // Shares of differing y-length cannot come from one split.
        assert_eq!(
            reconstruct(&[Share::new(1, [1, 2].to_vec()), Share::new(2, [3].to_vec())]),
            Err(ShamirError::BadShares),
            "mismatched share lengths are rejected"
        );
    }

    #[test]
    fn proactive_resharing_moves_a_secret_to_a_new_committee_without_reconstructing_it() {
        // Old 2-of-3 committee (x = 1,2,3) holds the secret; rotate to a new 2-of-4 committee (x = 1..4)
        // via resharing, using only a THRESHOLD subset {old 1, old 3} of the old members' contributions.
        let secret = b"POROS ingress descriptor bytes";
        let old_shares = split(secret, 2, 3, &deterministic_randomness(secret.len())).unwrap();
        let old_subset = [old_shares[0].clone(), old_shares[2].clone()]; // old x = 1, 3
        let old_xs = [old_shares[0].x(), old_shares[2].x()];
        let (new_t, new_n) = (2u8, 4u8);

        // Each old member in the subset re-splits its OWN share value over the 4 new positions (a
        // contribution), with its OWN fresh randomness (distinct slopes ⇒ a genuinely new polynomial). No
        // member ever holds or reconstructs the secret.
        let contrib_rnd = |k: usize, len: usize| -> Vec<u8> {
            (0..len).map(|i| ((i * 167 + 13 + k * 97) % 251) as u8).collect()
        };
        let contributions: Vec<Vec<Share>> = old_subset
            .iter()
            .enumerate()
            .map(|(k, s)| split(s.y(), new_t, new_n, &contrib_rnd(k, s.y().len())).unwrap())
            .collect();

        // Each new member j combines the j-th sub-share from every old contribution into its new share.
        let new_shares: Vec<Share> = (0..usize::from(new_n))
            .map(|j| {
                let for_j: Vec<Share> = contributions.iter().map(|c| c[j].clone()).collect();
                combine_contributions(u8::try_from(j + 1).unwrap(), &for_j, &old_xs).unwrap()
            })
            .collect();

        // The new committee reconstructs the SAME secret — from any 2 of the 4 new shares.
        for a in 0..4 {
            for b in (a + 1)..4 {
                assert_eq!(
                    reconstruct(&[new_shares[a].clone(), new_shares[b].clone()]).unwrap(),
                    secret,
                    "new members {a},{b} recover the original secret after resharing",
                );
            }
        }
        // A single new share (< the new threshold) does not recover it (the new committee is a real 2-of-4).
        assert_ne!(reconstruct(&[new_shares[0].clone()]).unwrap(), secret);
        // The new shares lie on a FRESH polynomial H ≠ f (both pass through S at 0): at the shared coordinate
        // x = 1, H(1) ≠ f(1), so a stale old share is not a valid point of the new sharing (proactive refresh —
        // an adversary with < t old shares AND < t new shares, but t total, still cannot reconstruct).
        assert_ne!(
            new_shares[0].y(),
            old_shares[0].y(),
            "the reshared polynomial differs from the old at x = 1 — a genuine refresh, not a copy",
        );
    }

    #[test]
    fn combine_contributions_rejects_bad_inputs() {
        let c = Share::new(1, [9u8].to_vec());
        assert_eq!(combine_contributions(0, core::slice::from_ref(&c), &[1]), Err(ShamirError::BadShares), "zero new_x");
        assert_eq!(combine_contributions(1, &[], &[]), Err(ShamirError::BadShares), "empty input");
        assert_eq!(combine_contributions(1, core::slice::from_ref(&c), &[1, 2]), Err(ShamirError::BadShares), "length mismatch");
        assert_eq!(combine_contributions(1, &[c.clone(), c.clone()], &[2, 2]), Err(ShamirError::BadShares), "dup old_xs");
        assert_eq!(combine_contributions(1, &[c], &[0]), Err(ShamirError::BadShares), "zero old_x");
    }
}
