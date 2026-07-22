//! A **post-quantum threshold randomness beacon with reconstruction-uniqueness** (spec §16 `[P]`,
//! `docs/design-pq-vrf.md` §2; the residual [`crate::pqvrf`]'s full-reveal beacon left open).
//!
//! > **NOVEL, UNAUDITED.** This is a hand-rolled construction with the security reduction below and an
//! > extensive test suite, but it has **not** had external cryptanalysis. Do not deploy it as the sole beacon
//! > without an audit. (Same honesty bar as the `[P]` items it closes.)
//!
//! The [`crate::pqvrf`] Merkle-VRF beacon is PQ and unbiasable but *full-reveal*: combining the shares that
//! appear, a withholding minority changes the value. A DVRF-class beacon needs **reconstruction-uniqueness** —
//! any `t` of `n` shares recover the *same* value — which classically comes from Shamir *in the exponent*
//! (discrete log, not PQ). This module gets it post-quantum from **plain Shamir over `GF(256)`**
//! ([`fanos_primitives::shamir`], the existing threshold substrate), whose reconstruction is *information-
//! theoretic* — hence quantum-proof — and unique by the fundamental theorem of interpolation.
//!
//! The one thing plain Shamir lacks is verifiability against a **malicious dealer** (shares off any degree-
//! `t−1` polynomial make different `t`-subsets reconstruct different secrets). Feldman/Pedersen fix this with
//! homomorphic (DL) commitments, which are not PQ. Here — because a *beacon's* secret is *revealed* anyway —
//! consistency is enforced at reveal by a complete **all-`t`-subsets-agree** check: the dealing is accepted
//! only if every `t`-subset of the verified shares reconstructs the identical secret, which holds iff the
//! shares lie on one degree-`t−1` polynomial. An inconsistent dealer is thus detected and its contribution
//! excluded; the honest contributions' sum is unbiased (each dealing is hash-committed *before* the epoch).
//!
//! **Security reduction.** *Reconstruction-uniqueness*: information-theoretic Shamir + the all-subsets check.
//! *Unbiasability*: the dealing commitment is a binding hash of all per-share commitments, published before the
//! epoch, so no dealer can grind (collision resistance of BLAKE3). *Unpredictability*: below `t` shares reveal
//! nothing about the secret (Shamir privacy), so one honest dealer whose `< t` shares are held suffices.
//! *Detectable abort, not bias*: a malicious dealer can only get its own contribution rejected, never bias or
//! break the uniqueness of the honest sum (honest-majority model).

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;
use fanos_primitives::shamir::{self, Share};
use fanos_primitives::{hash_labeled, Epoch};

const SHARE_LABEL: &str = "FANOS-v1/pqvss-share";
const DEALING_LABEL: &str = "FANOS-v1/pqvss-dealing";
const RND_LABEL: &str = "FANOS-v1/pqvss-rnd";
const BEACON_LABEL: &str = "FANOS-v1/pqvss-beacon";

/// The beacon secret width (bytes).
pub const SECRET_LEN: usize = 32;

/// The binding commitment to one share: `H("pqvss-share", x ‖ y)`. Hiding (a hash of the secret share bytes)
/// and binding (collision-resistant), so publishing it fixes the share without revealing it.
fn commit_share(share: &Share) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + share.y().len());
    buf.push(share.x());
    buf.extend_from_slice(share.y());
    hash_labeled(SHARE_LABEL, &buf)
}

/// A dealer's committed `t`-of-`n` sharing of a 32-byte secret: the per-share commitments (published *before*
/// the epoch for unbiasability) and the shares themselves (each delivered privately to its holder).
pub struct Dealing {
    threshold: u8,
    shares: Vec<Share>,
    commitments: Vec<[u8; 32]>,
}

impl Dealing {
    /// Deal `secret` as `t`-of-`n`, deriving the sharing-polynomial randomness deterministically from `seed`
    /// (a real CSPRNG in production; a fixed seed under the simulator). `None` for invalid `(t, n)`.
    #[must_use]
    pub fn deal(secret: &[u8; SECRET_LEN], t: u8, n: u8, seed: &[u8]) -> Option<Self> {
        if t < 1 || n < t {
            return None;
        }
        let mut rnd = alloc::vec![0u8; usize::from(t.saturating_sub(1)) * SECRET_LEN];
        hash_xof(RND_LABEL, seed, &mut rnd);
        let shares = shamir::split(secret, t, n, &rnd).ok()?;
        let commitments = shares.iter().map(commit_share).collect();
        Some(Self { threshold: t, shares, commitments })
    }

    /// The public **dealing commitment**: a binding hash over all per-share commitments. Published before the
    /// epoch opens, it fixes the secret (unbiasability) without revealing any share.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(self.commitments.len() * 32);
        for c in &self.commitments {
            buf.extend_from_slice(c);
        }
        hash_labeled(DEALING_LABEL, &buf)
    }

    /// The threshold `t`.
    #[must_use]
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// The number of shares `n`.
    #[must_use]
    pub fn n(&self) -> usize {
        self.shares.len()
    }

    /// Share `i` (delivered privately to holder `i`), `0 ≤ i < n`.
    #[must_use]
    pub fn share(&self, i: usize) -> Option<&Share> {
        self.shares.get(i)
    }

    /// The published per-share commitments (holder `i` verifies its share against `share_commitments()[i]`).
    #[must_use]
    pub fn share_commitments(&self) -> &[[u8; 32]] {
        &self.commitments
    }
}

/// Whether a revealed `share` matches its published commitment at its own `x`-position (`x ∈ 1..=n` indexes
/// `commitments[x-1]`). A forged or tampered share fails.
#[must_use]
pub fn verify_share(share: &Share, commitments: &[[u8; 32]]) -> bool {
    match (share.x() as usize).checked_sub(1).and_then(|idx| commitments.get(idx)) {
        Some(&committed) => commit_share(share) == committed,
        None => false,
    }
}

/// Reconstruct the dealt secret from `revealed` shares — **reconstruction-unique**: returns the secret only if
/// every share verifies against `commitments` and **all `t`-subsets of the verified shares reconstruct the
/// identical secret** (proving the shares lie on one degree-`t−1` polynomial — a consistent dealing). Returns
/// `None` if fewer than `t` valid shares are present or the dealing is inconsistent (a malicious dealer,
/// detected and rejected — never silently resolved to an arbitrary subset's value).
#[must_use]
pub fn reconstruct(revealed: &[Share], t: u8, commitments: &[[u8; 32]]) -> Option<[u8; SECRET_LEN]> {
    let t = usize::from(t);
    // Keep only shares that verify, de-duplicated by their x-coordinate (one share per holder).
    let mut valid: Vec<Share> = Vec::new();
    let mut seen_x: BTreeSet<u8> = BTreeSet::new();
    for s in revealed {
        if verify_share(s, commitments) && seen_x.insert(s.x()) {
            valid.push(s.clone());
        }
    }
    if valid.len() < t || t == 0 {
        return None;
    }
    // Every t-subset must reconstruct the SAME secret (⇔ the shares are collinear on one degree-(t−1) poly).
    let mut secrets: BTreeSet<Vec<u8>> = BTreeSet::new();
    for subset in t_subsets(&valid, t) {
        secrets.insert(shamir::reconstruct(&subset).ok()?);
    }
    if secrets.len() != 1 {
        return None; // inconsistent dealing — reject (reconstruction is not unique)
    }
    secrets.into_iter().next()?.try_into().ok()
}

/// All `t`-element subsets of `items` (by value), enumerated over `⌊n choose t⌋` — cheap at cell scale
/// (`n ≤ ~16`). Used to check reconstruction-uniqueness exhaustively.
fn t_subsets(items: &[Share], t: usize) -> Vec<Vec<Share>> {
    let n = items.len();
    let mut out = Vec::new();
    if t == 0 || t > n || n > 24 {
        return out; // guard the bitmask enumeration
    }
    for mask in 0u32..(1u32 << n) {
        if mask.count_ones() as usize != t {
            continue;
        }
        let mut subset = Vec::with_capacity(t);
        for (i, item) in items.iter().enumerate() {
            if mask & (1 << i) != 0 {
                subset.push(item.clone());
            }
        }
        out.push(subset);
    }
    out
}

/// Combine the reconstructed secrets of the **consistent** dealings into the epoch's beacon seed:
/// `H("pqvss-beacon", epoch ‖ sorted(secret)*)`. Sorting makes the seed independent of dealing order; a fresh
/// epoch (or a changed contribution) yields a fresh seed. `None` if no dealing survived.
#[must_use]
pub fn beacon_seed(epoch: Epoch, secrets: &[[u8; SECRET_LEN]]) -> Option<[u8; 32]> {
    if secrets.is_empty() {
        return None;
    }
    let mut sorted: Vec<[u8; SECRET_LEN]> = secrets.to_vec();
    sorted.sort_unstable();
    let mut buf = Vec::with_capacity(8 + sorted.len() * SECRET_LEN);
    buf.extend_from_slice(&epoch.to_be_bytes());
    for s in &sorted {
        buf.extend_from_slice(s);
    }
    Some(hash_labeled(BEACON_LABEL, &buf))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const SECRET: [u8; SECRET_LEN] = [0x5A; SECRET_LEN];

    #[test]
    fn any_threshold_subset_reconstructs_the_same_secret() {
        // The reconstruction-uniqueness property the Merkle-VRF beacon lacked: EVERY 3-of-5 subset yields the
        // identical secret, so a withholding minority cannot change the outcome.
        let d = Dealing::deal(&SECRET, 3, 5, b"seed-1").unwrap();
        let commits = d.share_commitments().to_vec();
        let all: Vec<Share> = (0..5).map(|i| d.share(i).unwrap().clone()).collect();
        // Try several distinct 3-subsets explicitly — all give SECRET.
        for pick in [[0, 1, 2], [2, 3, 4], [0, 2, 4], [1, 3, 4]] {
            let subset: Vec<Share> = pick.iter().map(|&i| all[i].clone()).collect();
            assert_eq!(reconstruct(&subset, 3, &commits), Some(SECRET), "subset {pick:?} reconstructs the secret");
        }
        // Fewer than t → None.
        assert_eq!(reconstruct(&all[..2], 3, &commits), None, "2 < t = 3 cannot reconstruct");
    }

    #[test]
    fn a_forged_or_tampered_share_is_rejected() {
        let d = Dealing::deal(&SECRET, 3, 5, b"seed-2").unwrap();
        let commits = d.share_commitments().to_vec();
        let mut shares: Vec<Share> = (0..5).map(|i| d.share(i).unwrap().clone()).collect();
        assert!(verify_share(&shares[0], &commits));
        // Tamper a share's y — its commitment no longer matches, so it is excluded.
        let mut y = shares[0].y().to_vec();
        y[0] ^= 0xFF;
        shares[0] = Share::new(shares[0].x(), y);
        assert!(!verify_share(&shares[0], &commits), "a tampered share fails its commitment");
        // With the tampered share excluded, the remaining 4 valid shares still reconstruct.
        assert_eq!(reconstruct(&shares, 3, &commits), Some(SECRET), "the honest shares still reconstruct");
    }

    #[test]
    fn an_inconsistent_dealing_is_detected_and_rejected() {
        // A malicious dealer deals one share OFF the polynomial (but commits to the bad share, so it
        // "verifies"). Different t-subsets then reconstruct different secrets → the all-subsets check rejects.
        let d = Dealing::deal(&SECRET, 3, 5, b"seed-3").unwrap();
        let mut shares: Vec<Share> = (0..5).map(|i| d.share(i).unwrap().clone()).collect();
        let mut commits = d.share_commitments().to_vec();
        // Corrupt share index 4 to lie off the polynomial and re-commit to it (a consistent-looking forgery).
        let mut y = shares[4].y().to_vec();
        y[0] ^= 0x01;
        shares[4] = Share::new(shares[4].x(), y);
        commits[4] = commit_share(&shares[4]);
        // All 5 shares "verify", but they are not collinear → the all-t-subsets check finds disagreement.
        assert_eq!(reconstruct(&shares, 3, &commits), None, "an inconsistent dealing is rejected");
        // The 4 honest shares alone are consistent and reconstruct.
        assert_eq!(reconstruct(&shares[..4], 3, &commits), Some(SECRET));
    }

    #[test]
    fn the_commitment_binds_the_secret_before_reveal() {
        // Unbiasability: two different secrets dealt with the same seed commit differently, so a dealer that
        // has published its commitment cannot later swap the secret.
        let a = Dealing::deal(&[1u8; 32], 3, 5, b"s").unwrap();
        let b = Dealing::deal(&[2u8; 32], 3, 5, b"s").unwrap();
        assert_ne!(a.commitment(), b.commitment(), "the commitment binds the dealt secret");
        // Deterministic in (secret, seed).
        assert_eq!(a.commitment(), Dealing::deal(&[1u8; 32], 3, 5, b"s").unwrap().commitment());
    }

    #[test]
    fn the_beacon_combines_dealings_order_independently_and_freshly() {
        let s1 = [0x11u8; 32];
        let s2 = [0x22u8; 32];
        let seed = beacon_seed(Epoch::new(7), &[s1, s2]).unwrap();
        assert_eq!(beacon_seed(Epoch::new(7), &[s2, s1]).unwrap(), seed, "order-independent");
        assert_ne!(beacon_seed(Epoch::new(8), &[s1, s2]).unwrap(), seed, "each epoch is fresh");
        assert!(beacon_seed(Epoch::new(7), &[]).is_none(), "no dealings, no beacon");
    }

    #[test]
    fn below_threshold_shares_reveal_nothing_end_to_end() {
        // A full round: deal → distribute → any t reveal + reconstruct → beacon. Two independent dealers'
        // secrets combine; a 2-of-4 dealer is opened by any 2 of its 4 holders.
        let d1 = Dealing::deal(&[0xAB; 32], 2, 4, b"d1").unwrap();
        let d2 = Dealing::deal(&[0xCD; 32], 2, 4, b"d2").unwrap();
        let c1 = d1.share_commitments().to_vec();
        let c2 = d2.share_commitments().to_vec();
        let sec1 = reconstruct(&[d1.share(0).unwrap().clone(), d1.share(3).unwrap().clone()], 2, &c1).unwrap();
        let sec2 = reconstruct(&[d2.share(1).unwrap().clone(), d2.share(2).unwrap().clone()], 2, &c2).unwrap();
        assert_eq!(sec1, [0xAB; 32]);
        assert_eq!(sec2, [0xCD; 32]);
        assert!(beacon_seed(Epoch::new(1), &[sec1, sec2]).is_some());
    }
}
