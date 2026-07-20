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
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Share {
    x: u8,
    y: Vec<u8>,
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
}
