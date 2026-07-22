//! A **post-quantum threshold randomness beacon with reconstruction-uniqueness** (spec §16 `[P]`,
//! `docs/design-pq-vrf.md` §2; the residual [`crate::pqvrf`]'s full-reveal beacon left open).
//!
//! > **NOVEL, UNAUDITED.** Hand-rolled, with the reduction below and an extensive test suite (including the
//! > adversarial attacks an independent review used to break an earlier design), but **no** external
//! > cryptanalysis. Do not deploy as the sole beacon without an audit.
//!
//! The [`crate::pqvrf`] Merkle-VRF beacon is PQ and unbiasable but *full-reveal*. A DVRF-class beacon needs
//! **reconstruction-uniqueness** — any `t` of `n` shares recover the *same* value — which classically comes
//! from Shamir *in the exponent* (discrete log, not PQ). This module gets it post-quantum from **plain Shamir
//! over `GF(256)`** ([`fanos_primitives::shamir`]), whose reconstruction is *information-theoretic* (hence PQ)
//! and unique by interpolation.
//!
//! **Binding the polynomial, not the shares (the load-bearing design point).** Plain Shamir lacks
//! verifiability against a **malicious dealer**: shares off any single degree-`t−1` polynomial let different
//! `t`-subsets reconstruct different secrets. Per-share hash commitments do **not** fix this — they bind each
//! share to *itself*, so a check that a *revealed* `t`-subset is self-consistent is vacuous (interpolation is
//! trivially self-consistent at exactly `t` points), and detecting an inconsistent dealing would require an
//! *over-determined* reveal, forfeiting the withholding-tolerance a threshold beacon exists to provide.
//! Instead the dealer publishes, **before the epoch**, a commitment to the **polynomial itself** —
//! `H(epoch ‖ dealer ‖ t ‖ P(0) ‖ P(1) ‖ … ‖ P(t−1))`, whose `t` canonical values uniquely determine the
//! degree-`t−1` polynomial. At reveal, any `t` shares are interpolated, the reconstructed polynomial's `t`
//! canonical values are hashed, and the result is checked against the commitment: a `t`-subset that
//! reconstructs a *different* polynomial (an inconsistent dealing, or forged shares) fails and is rejected, so
//! **at most one secret is ever accepted** — reconstruction-unique **and** withholding-tolerant.
//!
//! **Security reduction.** *Reconstruction-uniqueness*: information-theoretic Shamir; the polynomial
//! commitment admits exactly one degree-`t−1` polynomial, and any `t` genuine shares reconstruct it while a
//! divergent subset fails the canonical-value hash (BLAKE3 collision resistance). *Unbiasability*: the
//! commitment fixes the whole polynomial — hence the secret — before the epoch, so no dealer can grind or
//! rush after seeing others' reveals; `t`, `epoch`, and the `dealer` id are all bound, so a wrong `t` or a
//! cross-epoch/cross-dealer replay fails. *Unpredictability*: below `t` shares reveal nothing (Shamir
//! privacy) and the commitment is one-way (BLAKE3). *Detectable abort, not bias*: a malicious dealer can only
//! get its own contribution *rejected* (its committed polynomial's `t` shares unavailable), never bias the
//! honest sum — honest-majority-of-dealers model. [`beacon_seed`] de-duplicates by dealer so a replayed
//! contribution cannot be double-counted.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use fanos_field::{F256, Field};
use fanos_primitives::hash::hash_xof;
use fanos_primitives::shamir::{self, Share};
use fanos_primitives::{hash_labeled, Epoch};

const SHARE_LABEL: &str = "FANOS-v1/pqvss-share";
const DEALING_LABEL: &str = "FANOS-v1/pqvss-dealing";
const RND_LABEL: &str = "FANOS-v1/pqvss-rnd";
const NONCE_LABEL: &str = "FANOS-v1/pqvss-nonce";
const BEACON_LABEL: &str = "FANOS-v1/pqvss-beacon";

/// The beacon secret width (bytes).
pub const SECRET_LEN: usize = 32;

/// A dealer identity — binds a dealing (and its beacon contribution) to its dealer, preventing cross-dealer
/// copy/replay and enabling de-duplication.
pub type DealerId = [u8; 32];

/// `a · b` in `GF(256)` (the shamir field, `fanos_field::F256`).
fn mul8(a: u8, b: u8) -> u8 {
    F256::mul(u32::from(a), u32::from(b)) as u8
}

/// Evaluate — per secret byte, over `GF(256)` — the degree-`(t−1)` polynomial interpolating `points` at the
/// query point `x_q`: `P(x_q) = ⊕_j y_j · Π_{m≠j} (x_q ⊕ x_m)/(x_j ⊕ x_m)`. Matches
/// [`fanos_primitives::shamir::reconstruct`] at `x_q = 0`, generalized to any point. `None` on ragged or
/// repeated-`x` points.
fn eval_at(points: &[Share], x_q: u8) -> Option<Vec<u8>> {
    let len = points.first()?.y().len();
    if points.iter().any(|s| s.y().len() != len) {
        return None;
    }
    let mut out = alloc::vec![0u8; len];
    for sj in points {
        let xj = sj.x();
        let mut num = 1u8;
        let mut den = 1u8;
        for sm in points {
            let xm = sm.x();
            if xm != xj {
                num = mul8(num, x_q ^ xm);
                den = mul8(den, xj ^ xm);
            }
        }
        if den == 0 {
            return None; // a repeated x-coordinate — degenerate
        }
        let coeff = mul8(num, F256::inv(u32::from(den)) as u8);
        for (slot, &yjb) in out.iter_mut().zip(sj.y()) {
            *slot ^= mul8(coeff, yjb);
        }
    }
    Some(out)
}

/// The `t` **canonical values** `[P(0), P(1), …, P(t−1)]` of the polynomial through `basis` — the tuple that
/// uniquely determines a degree-`(t−1)` polynomial (so hashing it commits to the whole polynomial). `None`
/// unless `basis` has at least `t` distinct-`x` shares.
fn canonical_values(basis: &[Share], t: usize) -> Option<Vec<Vec<u8>>> {
    if basis.len() < t {
        return None;
    }
    (0..t).map(|k| eval_at(basis, k as u8)).collect()
}

/// The **polynomial commitment** `H(DEALING ‖ epoch ‖ dealer ‖ t ‖ P(0) ‖ … ‖ P(t−1))` — published before the
/// epoch. Binds the entire polynomial, the threshold `t`, the epoch, and the dealer, over fixed-width fields.
fn dealing_commit(epoch: Epoch, dealer: &DealerId, t: u8, canonical: &[Vec<u8>]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + 32 + 1 + canonical.len() * SECRET_LEN);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(dealer);
    buf.push(t);
    for v in canonical {
        buf.extend_from_slice(v);
    }
    hash_labeled(DEALING_LABEL, &buf)
}

/// A **blinded** per-share commitment `H(SHARE ‖ epoch ‖ dealer ‖ x ‖ y ‖ nonce)` — for a *holder* to verify
/// its own share at deal time. Blinded (a fresh `nonce`) so the commitment is not a confirm-a-guess oracle for
/// a low-entropy share; bound to `(epoch, dealer)` against replay.
fn commit_share(epoch: Epoch, dealer: &DealerId, share: &Share, nonce: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + 32 + 1 + share.y().len() + 32);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(dealer);
    buf.push(share.x());
    buf.extend_from_slice(share.y());
    buf.extend_from_slice(nonce);
    hash_labeled(SHARE_LABEL, &buf)
}

/// A dealer's `t`-of-`n` sharing of a 32-byte secret: the polynomial commitment (published *before* the epoch)
/// plus the shares and their blinded per-share commitments (each delivered privately to its holder).
pub struct Dealing {
    threshold: u8,
    epoch: Epoch,
    dealer: DealerId,
    shares: Vec<Share>,
    nonces: Vec<[u8; 32]>,
    share_commitments: Vec<[u8; 32]>,
    commitment: [u8; 32],
}

impl Dealing {
    /// Deal `secret` as `t`-of-`n` for `dealer` in `epoch`, deriving all randomness deterministically from
    /// `seed` **and the secret** (so re-dealing under the same `seed` cannot leak the secret difference). `t`
    /// must be `≥ 2` (a `1`-of-`n` sharing gives every holder the secret) and `n ≥ t`. `None` otherwise.
    #[must_use]
    pub fn deal(secret: &[u8; SECRET_LEN], t: u8, n: u8, epoch: Epoch, dealer: &DealerId, seed: &[u8]) -> Option<Self> {
        if t < 2 || n < t {
            return None;
        }
        // Sharing-polynomial randomness from seed ‖ secret (independent seeds cannot expose secret diffs).
        let mut rnd_seed = Vec::with_capacity(seed.len() + SECRET_LEN);
        rnd_seed.extend_from_slice(seed);
        rnd_seed.extend_from_slice(secret);
        let mut rnd = alloc::vec![0u8; usize::from(t - 1) * SECRET_LEN];
        hash_xof(RND_LABEL, &rnd_seed, &mut rnd);
        let shares = shamir::split(secret, t, n, &rnd).ok()?;

        // Blinded per-share commitments (nonce derived per share).
        let mut nonces = Vec::with_capacity(shares.len());
        let mut share_commitments = Vec::with_capacity(shares.len());
        for (i, s) in shares.iter().enumerate() {
            let mut nseed = Vec::with_capacity(seed.len() + 8);
            nseed.extend_from_slice(seed);
            nseed.extend_from_slice(&(i as u64).to_be_bytes());
            let nonce = hash_labeled(NONCE_LABEL, &nseed);
            share_commitments.push(commit_share(epoch, dealer, s, &nonce));
            nonces.push(nonce);
        }

        // The polynomial commitment (its t canonical values).
        let canonical = canonical_values(shares.get(..usize::from(t))?, usize::from(t))?;
        let commitment = dealing_commit(epoch, dealer, t, &canonical);

        Some(Self { threshold: t, epoch, dealer: *dealer, shares, nonces, share_commitments, commitment })
    }

    /// The public **polynomial commitment** — publish this before the epoch (unbiasability).
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
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

    /// The epoch this dealing is bound to.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The dealer identity this dealing is bound to (needed by a combiner to [`reconstruct`]).
    #[must_use]
    pub fn dealer(&self) -> DealerId {
        self.dealer
    }

    /// Share `i` (delivered privately to holder `i`).
    #[must_use]
    pub fn share(&self, i: usize) -> Option<&Share> {
        self.shares.get(i)
    }

    /// Holder `i`'s commitment opening (the blinding nonce), so it can verify its share with [`verify_share`].
    #[must_use]
    pub fn opening(&self, i: usize) -> Option<[u8; 32]> {
        self.nonces.get(i).copied()
    }

    /// The published blinded per-share commitments (holder `i` checks `share_commitments()[i]`).
    #[must_use]
    pub fn share_commitments(&self) -> &[[u8; 32]] {
        &self.share_commitments
    }
}

/// A holder's deal-time check that its `share` (with opening `nonce`) matches the published `commitment` under
/// `(epoch, dealer)`. Not needed for reconstruction (the polynomial commitment binds everything there) — it is
/// for a holder to reject a share it was handed off the dealer's polynomial before contributing.
#[must_use]
pub fn verify_share(epoch: Epoch, dealer: &DealerId, share: &Share, nonce: &[u8; 32], commitment: &[u8; 32]) -> bool {
    &commit_share(epoch, dealer, share, nonce) == commitment
}

/// Reconstruct the dealt secret from `revealed` shares and **verify it against the polynomial commitment** —
/// reconstruction-**unique** and withholding-tolerant. Interpolates the polynomial from the first `t`
/// distinct-`x` shares, recomputes its canonical-value hash, and returns the secret `P(0)` only if that hash
/// equals `commitment` for this `(epoch, dealer, t)`. A `t`-subset that reconstructs a *different* polynomial
/// (an inconsistent dealing, a wrong `t`, a cross-epoch/dealer replay, or forged shares) fails the check and
/// returns `None` — so no two `t`-subsets can ever yield two *different* accepted secrets.
#[must_use]
pub fn reconstruct(
    revealed: &[Share],
    t: u8,
    epoch: Epoch,
    dealer: &DealerId,
    commitment: &[u8; 32],
) -> Option<[u8; SECRET_LEN]> {
    if t < 2 {
        return None;
    }
    let tu = usize::from(t);
    // De-duplicate by x-coordinate (one share per holder).
    let mut valid: Vec<Share> = Vec::new();
    let mut seen: BTreeSet<u8> = BTreeSet::new();
    for s in revealed {
        if seen.insert(s.x()) {
            valid.push(s.clone());
        }
    }
    let basis = valid.get(..tu)?; // fewer than t distinct shares ⇒ None
    let canonical = canonical_values(basis, tu)?;
    if dealing_commit(epoch, dealer, t, &canonical) != *commitment {
        return None; // the reconstructed polynomial is not the committed one — reject
    }
    canonical.into_iter().next()?.try_into().ok() // P(0) = the secret
}

/// Combine the reconstructed secrets of **verified** dealings into the epoch's beacon seed:
/// `H(BEACON ‖ epoch ‖ sorted_by_dealer(dealer ‖ secret)*)`. Each `(dealer, secret)` must be the output of a
/// successful [`reconstruct`] against that dealer's pre-epoch commitment. De-duplicates by dealer id (a
/// replayed contribution counts once) and binds the dealer id into the transcript; sorting makes the seed
/// order-independent and each epoch fresh. `None` if no contributions.
#[must_use]
pub fn beacon_seed(epoch: Epoch, contributions: &[(DealerId, [u8; SECRET_LEN])]) -> Option<[u8; 32]> {
    if contributions.is_empty() {
        return None;
    }
    // One contribution per dealer (BTreeMap is sorted by dealer id → deterministic, order-independent).
    let mut by_dealer: BTreeMap<DealerId, [u8; SECRET_LEN]> = BTreeMap::new();
    for &(dealer, secret) in contributions {
        by_dealer.entry(dealer).or_insert(secret);
    }
    let mut buf = Vec::with_capacity(8 + by_dealer.len() * (32 + SECRET_LEN));
    buf.extend_from_slice(&epoch.to_be_bytes());
    for (dealer, secret) in &by_dealer {
        buf.extend_from_slice(dealer);
        buf.extend_from_slice(secret);
    }
    Some(hash_labeled(BEACON_LABEL, &buf))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const SECRET: [u8; SECRET_LEN] = [0x5A; SECRET_LEN];
    const DEALER: DealerId = [0xD1; 32];
    const E: Epoch = Epoch::new(7);

    #[test]
    fn any_threshold_subset_reconstructs_the_same_secret() {
        let d = Dealing::deal(&SECRET, 3, 5, E, &DEALER, b"seed-1").unwrap();
        let c = d.commitment();
        let all: Vec<Share> = (0..5).map(|i| d.share(i).unwrap().clone()).collect();
        // EVERY 3-subset yields the identical secret (reconstruction-uniqueness), including the exact-t case.
        for pick in [[0, 1, 2], [2, 3, 4], [0, 2, 4], [1, 3, 4], [0, 3, 4]] {
            let subset: Vec<Share> = pick.iter().map(|&i| all[i].clone()).collect();
            assert_eq!(reconstruct(&subset, 3, E, &DEALER, &c), Some(SECRET), "subset {pick:?}");
        }
        assert_eq!(reconstruct(&all[..2], 3, E, &DEALER, &c), None, "2 < t = 3 cannot reconstruct");
    }

    #[test]
    fn an_inconsistent_dealing_never_yields_two_different_secrets() {
        // The attack an independent review used to break the earlier design: a dealer commits to ONE
        // polynomial (through shares 0,1,2) but hands off-polynomial shares to holders 3,4. With the
        // POLYNOMIAL commitment, only the committed 3-subset reconstructs; every divergent subset is REJECTED
        // (returns None) — so no two DIFFERENT secrets are ever both accepted.
        let d = Dealing::deal(&SECRET, 3, 5, E, &DEALER, b"seed-2").unwrap();
        let c = d.commitment();
        let mut shares: Vec<Share> = (0..5).map(|i| d.share(i).unwrap().clone()).collect();
        // Corrupt shares 3 and 4 off the committed polynomial.
        for i in [3usize, 4] {
            let mut y = shares[i].y().to_vec();
            y[0] ^= 0x7F;
            shares[i] = Share::new(shares[i].x(), y);
        }
        // The committed subset reconstructs the unique secret.
        let s012: Vec<Share> = [0, 1, 2].iter().map(|&i| shares[i].clone()).collect();
        assert_eq!(reconstruct(&s012, 3, E, &DEALER, &c), Some(SECRET));
        // A subset touching the off-polynomial shares reconstructs a DIFFERENT polynomial → rejected (not a
        // different secret). This is the fix: the old design returned Some(other_secret) here.
        for pick in [[2, 3, 4], [0, 3, 4], [1, 2, 3]] {
            let subset: Vec<Share> = pick.iter().map(|&i| shares[i].clone()).collect();
            assert_eq!(reconstruct(&subset, 3, E, &DEALER, &c), None, "off-poly subset {pick:?} is rejected");
        }
    }

    #[test]
    fn a_wrong_threshold_epoch_or_dealer_is_rejected() {
        let d = Dealing::deal(&SECRET, 3, 5, E, &DEALER, b"seed-3").unwrap();
        let c = d.commitment();
        let all: Vec<Share> = (0..5).map(|i| d.share(i).unwrap().clone()).collect();
        assert_eq!(reconstruct(&all[..3], 3, E, &DEALER, &c), Some(SECRET));
        // A wrong t (announced 2 instead of 3) fails — t is bound in the commitment.
        assert_eq!(reconstruct(&all[..2], 2, E, &DEALER, &c), None, "wrong t is rejected");
        // A cross-epoch or cross-dealer replay of the same shares+commitment fails.
        assert_eq!(reconstruct(&all[..3], 3, Epoch::new(8), &DEALER, &c), None, "wrong epoch is rejected");
        assert_eq!(reconstruct(&all[..3], 3, E, &[0xEE; 32], &c), None, "wrong dealer is rejected");
    }

    #[test]
    fn a_holder_verifies_its_share_and_rejects_a_tampered_one() {
        let d = Dealing::deal(&SECRET, 3, 5, E, &DEALER, b"seed-4").unwrap();
        let commits = d.share_commitments().to_vec();
        for (i, committed) in commits.iter().enumerate() {
            let share = d.share(i).unwrap();
            let nonce = d.opening(i).unwrap();
            assert!(verify_share(E, &DEALER, share, &nonce, committed), "holder {i} verifies its share");
            // A tampered share (or a wrong nonce) fails.
            let mut y = share.y().to_vec();
            y[0] ^= 1;
            assert!(!verify_share(E, &DEALER, &Share::new(share.x(), y), &nonce, committed));
        }
    }

    #[test]
    fn the_commitment_binds_the_polynomial_before_reveal() {
        // Two different secrets commit differently (unbiasable), deterministic in (secret, seed, epoch, dealer).
        let a = Dealing::deal(&[1u8; 32], 3, 5, E, &DEALER, b"s").unwrap();
        let b = Dealing::deal(&[2u8; 32], 3, 5, E, &DEALER, b"s").unwrap();
        assert_ne!(a.commitment(), b.commitment());
        assert_eq!(a.commitment(), Dealing::deal(&[1u8; 32], 3, 5, E, &DEALER, b"s").unwrap().commitment());
        // t < 2 is rejected (a 1-of-n sharing hands every holder the secret).
        assert!(Dealing::deal(&SECRET, 1, 5, E, &DEALER, b"s").is_none());
    }

    #[test]
    fn the_beacon_combines_dealings_order_independently_deduped_and_freshly() {
        let d1: DealerId = [1u8; 32];
        let d2: DealerId = [2u8; 32];
        let s1 = [0x11u8; 32];
        let s2 = [0x22u8; 32];
        let seed = beacon_seed(E, &[(d1, s1), (d2, s2)]).unwrap();
        assert_eq!(beacon_seed(E, &[(d2, s2), (d1, s1)]).unwrap(), seed, "order-independent");
        // A replayed contribution from the same dealer counts once (no double-count / bias).
        assert_eq!(beacon_seed(E, &[(d1, s1), (d2, s2), (d1, s1)]).unwrap(), seed, "deduped by dealer");
        assert_ne!(beacon_seed(Epoch::new(8), &[(d1, s1), (d2, s2)]).unwrap(), seed, "each epoch is fresh");
        assert!(beacon_seed(E, &[]).is_none());
    }

    #[test]
    fn eval_at_zero_matches_shamir() {
        let d = Dealing::deal(&SECRET, 3, 5, E, &DEALER, b"cross").unwrap();
        let shares: Vec<Share> = (0..5).map(|i| d.share(i).unwrap().clone()).collect();
        assert_eq!(eval_at(&shares[..3], 0), Some(shamir::reconstruct(&shares[..3]).unwrap()));
        assert_eq!(eval_at(&shares[..3], shares[0].x()).unwrap().as_slice(), shares[0].y());
    }

    #[test]
    fn a_larger_cell_reconstructs_uniquely_and_is_polynomial_time() {
        // n=20, t=8: no exponential subset scan (the check is O(n·t²) interpolation + one hash).
        let d = Dealing::deal(&SECRET, 8, 20, E, &DEALER, b"large").unwrap();
        let c = d.commitment();
        let all: Vec<Share> = (0..20).map(|i| d.share(i).unwrap().clone()).collect();
        assert_eq!(reconstruct(&all[..8], 8, E, &DEALER, &c), Some(SECRET));
        assert_eq!(reconstruct(&all[6..14], 8, E, &DEALER, &c), Some(SECRET), "a different 8-subset agrees");
    }
}
