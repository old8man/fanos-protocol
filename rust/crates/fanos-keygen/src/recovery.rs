//! Below-threshold recovery — the **re-genesis certificate** (`RGC`) that authorizes a Fano cell which has
//! dropped below its beacon threshold `t` to abandon its (now information-theoretically lost) `(t, n)` DVRF key
//! and re-key from scratch among the survivors (audit §4, `docs/design-recovery.md`).
//!
//! A `(t, n)` secret with `≤ t − 1` shares is *gone* — no resharing recovers it. So a below-threshold cell can
//! only mint a **fresh** key, and the one hazard is a fork: two partitioned minorities each re-keying. The
//! [`RecoveryAuthorization`] closes that with a **single-writer authority + a strictly-monotonic generation**:
//! at most one authorization is ever validly signed per generation, so a returning partitioned group is
//! subordinated (its stale-generation artifacts are rejected), never forked. The authority is the parent cell (a
//! BFT quorum) or, for the root cell, a founder/constitution quorum — a weak-subjectivity checkpoint. Recovery
//! at the root cannot be trustless; it can only be *fenced and single-canonical*.

use fanos_pqcrypto::{HybridSignature, HybridSigSecret, HybridVerifier};
use fanos_primitives::Epoch;
use fanos_primitives::codec::{Reader, put_u64, put_var_bytes};

/// Domain separation for the signed `RGC` message — no other FANOS signature covers this byte string.
const RGC_DOMAIN: &[u8] = b"FANOS-recovery-v1/rgc";

/// The smallest re-genesis threshold an authorization may name. Mirrors the resharing key-exfiltration floor
/// (audit §3.1): `t' = 1` would let a single new holder reconstruct the fresh key alone.
pub const MIN_REGENESIS_THRESHOLD: u8 = 2;

/// A **re-genesis certificate** (`RGC`): a single-writer authority's authorization for a below-threshold cell to
/// re-key from scratch among `survivors`, resuming the epoch clock at `epoch_fence`, generation `generation`.
///
/// Every semantic field is bound by [`sig`](Self::sig), so none can be altered without invalidating it, and the
/// `generation` fences the whole cell: a node rejects any beacon artifact from an older generation
/// (`docs/design-recovery.md` §2).
#[derive(Clone, PartialEq, Debug)]
pub struct RecoveryAuthorization {
    /// The re-genesis generation — must be strictly greater than the cell's current `reshare_gen`. The fencing
    /// counter: at most one authorization is ever validly signed per generation.
    pub generation: u64,
    /// The epoch the beacon resumes at — strictly greater than the frozen epoch, so the resumed clock is
    /// monotone.
    pub epoch_fence: Epoch,
    /// The authorized survivor set, as beacon holder indices (`1..=n`), sorted and distinct. These, and only
    /// these, run the fresh DKG.
    pub survivors: Vec<u8>,
    /// The new threshold `t'` (`MIN_REGENESIS_THRESHOLD ≤ t' ≤ |survivors|`).
    pub threshold: u8,
    /// The provenance anchor the survivors presented — e.g. `H(last ExecCertificate)` for a ledger cell or the
    /// cell's lineage fingerprint for a pure-beacon cell — binding the re-genesis to a specific cell + state, so
    /// an authorization cannot be replayed onto a different cell (`docs/design-recovery.md` §2).
    pub anchor: [u8; 32],
    /// The authority's hybrid PQ signature (`Ed25519 ‖ ML-DSA-65`) over [`signable`](Self::signable).
    pub sig: HybridSignature,
}

impl RecoveryAuthorization {
    /// The canonical signed message binding every semantic field, domain-separated.
    #[must_use]
    pub fn signable(generation: u64, epoch_fence: Epoch, survivors: &[u8], threshold: u8, anchor: &[u8; 32]) -> Vec<u8> {
        let mut m = Vec::with_capacity(RGC_DOMAIN.len() + 8 + 8 + 1 + 4 + survivors.len() + 32);
        m.extend_from_slice(RGC_DOMAIN);
        put_u64(&mut m, generation);
        put_u64(&mut m, epoch_fence.get());
        m.push(threshold);
        put_var_bytes(&mut m, survivors);
        m.extend_from_slice(anchor);
        m
    }

    /// Issue an authorization: the authority signs `(generation, epoch_fence, survivors, threshold, anchor)` with
    /// its recovery key. `survivors` is canonicalized (sorted, deduplicated) so the signed set is unambiguous.
    #[must_use]
    pub fn issue(
        authority: &HybridSigSecret,
        generation: u64,
        epoch_fence: Epoch,
        survivors: &[u8],
        threshold: u8,
        anchor: [u8; 32],
    ) -> Self {
        let mut survivors = survivors.to_vec();
        survivors.sort_unstable();
        survivors.dedup();
        let sig = authority.sign(&Self::signable(generation, epoch_fence, &survivors, threshold, &anchor));
        Self { generation, epoch_fence, survivors, threshold, anchor, sig }
    }

    /// Verify the authorization against the cell's `authority` key and its internal well-formedness: the
    /// signature covers every field, the survivor set is sorted+distinct+non-empty, and
    /// `MIN_REGENESIS_THRESHOLD ≤ threshold ≤ |survivors|`. Does **not** check the anchor or the generation
    /// monotonicity — those are the adopting node's responsibility ([`crate::beacon::BeaconNode::rebootstrap`]),
    /// since they depend on that node's local state.
    #[must_use]
    pub fn verify(&self, authority: &HybridVerifier) -> bool {
        self.well_formed()
            && authority.verify(
                &Self::signable(self.generation, self.epoch_fence, &self.survivors, self.threshold, &self.anchor),
                &self.sig,
            )
    }

    /// Structural validity independent of any key: a non-empty, sorted, distinct survivor set and a threshold in
    /// `[MIN_REGENESIS_THRESHOLD, |survivors|]`.
    #[must_use]
    pub fn well_formed(&self) -> bool {
        self.threshold >= MIN_REGENESIS_THRESHOLD
            && usize::from(self.threshold) <= self.survivors.len()
            && !self.survivors.is_empty()
            && self.survivors.is_sorted_by(|a, b| a < b)
    }

    /// Canonical wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u64(&mut out, self.generation);
        put_u64(&mut out, self.epoch_fence.get());
        out.push(self.threshold);
        put_var_bytes(&mut out, &self.survivors);
        out.extend_from_slice(&self.anchor);
        put_var_bytes(&mut out, &self.sig.to_bytes());
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed / truncated / trailing garbage.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let generation = r.u64()?;
        let epoch_fence = Epoch::new(r.u64()?);
        let threshold = r.u8()?;
        let survivors = r.var_bytes()?.to_vec();
        let anchor = r.array::<32>()?;
        let sig = HybridSignature::from_bytes(r.var_bytes()?)?;
        r.finish()?;
        Some(Self { generation, epoch_fence, survivors, threshold, anchor, sig })
    }
}

/// The honest-majority threshold for a committee of `n` anchors — the smallest `t` with `t > n/2`, clamped to
/// the resharing floor. This is the BFT honest-majority bound (`< t` corrupt tolerated), a derived quantity, not
/// a tuned constant.
#[must_use]
pub fn majority_threshold(n: usize) -> usize {
    (n / 2 + 1).max(usize::from(MIN_REGENESIS_THRESHOLD))
}

/// The recovery action for one epoch, decided purely from the live-anchor set versus the current beacon
/// threshold (audit §4). The two regimes of `docs/design-recovery.md`, expressed as one total function.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RecoveryAction {
    /// The anchor set is healthy for its threshold — no action.
    None,
    /// **Regime A — proactive reshare.** The committee has thinned enough that a lower (still honest-majority)
    /// threshold buys fault-tolerance headroom, and `≥ threshold` anchors remain so a reshare is still possible.
    /// Reshare the key (continuity-preserving) to `survivors` at `new_threshold`. Partition-safe: a `< threshold`
    /// minority cannot reshare, so no competing key can arise.
    ProactiveReshare {
        /// The live anchor holder indices to reshare to.
        survivors: Vec<u8>,
        /// The lower honest-majority threshold for the shrunk committee.
        new_threshold: usize,
    },
    /// **Regime B — below-threshold re-genesis.** The set has already dropped below `threshold`; the `(t, n)` key
    /// is information-theoretically gone and a reshare is impossible. Escalate to the recovery authority for a
    /// [`RecoveryAuthorization`] and re-key the `survivors` from a fresh DKG.
    RequestRegenesis {
        /// The live anchor holder indices that remain to be re-keyed under a fresh DKG.
        survivors: Vec<u8>,
    },
}

/// Decide the recovery action from the current `live_anchors` (holder indices) and the beacon `threshold`.
///
/// - `live < threshold` ⇒ reshare is impossible (it needs `≥ threshold` contributors) ⇒ **re-genesis** (B).
/// - `live ≥ threshold` but the honest-majority threshold for the shrunk set is *below* the current one, and a
///   fault-tolerant committee (`≥ MIN + 1` anchors) still remains ⇒ **proactive reshare** (A), lowering the
///   threshold to `majority_threshold(live)` so the cell tolerates further losses before it can freeze.
/// - otherwise ⇒ **none**.
#[must_use]
pub fn recovery_decision(live_anchors: &[u8], threshold: usize) -> RecoveryAction {
    let live = live_anchors.len();
    if live < threshold {
        return RecoveryAction::RequestRegenesis { survivors: live_anchors.to_vec() };
    }
    let new_threshold = majority_threshold(live);
    if new_threshold < threshold && live > usize::from(MIN_REGENESIS_THRESHOLD) {
        return RecoveryAction::ProactiveReshare { survivors: live_anchors.to_vec(), new_threshold };
    }
    RecoveryAction::None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_pqcrypto::SeedRng;

    fn authority() -> (HybridSigSecret, HybridVerifier) {
        HybridSigSecret::generate(&mut SeedRng::from_seed(b"recovery-authority"))
    }

    #[test]
    fn an_issued_authorization_verifies_and_round_trips() {
        let (sk, vk) = authority();
        let rgc = RecoveryAuthorization::issue(&sk, 1, Epoch::new(9), &[5, 6, 7], 2, [0x11; 32]);
        assert!(rgc.verify(&vk), "the issued authorization verifies against its authority");
        assert_eq!(rgc.survivors, vec![5, 6, 7], "the survivor set is canonicalized");
        let round = RecoveryAuthorization::from_bytes(&rgc.to_bytes()).expect("re-decodes");
        assert_eq!(round, rgc, "the wire form round-trips");
        assert!(round.verify(&vk), "and still verifies");
    }

    #[test]
    fn tampering_or_a_foreign_authority_is_rejected() {
        let (sk, vk) = authority();
        let (_other_sk, other_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"impostor"));
        let rgc = RecoveryAuthorization::issue(&sk, 3, Epoch::new(12), &[1, 2, 3, 4], 3, [0x22; 32]);
        assert!(rgc.verify(&vk));
        assert!(!rgc.verify(&other_vk), "a different authority's key does not verify it");
        // Flip a field: the signature no longer covers the message.
        let mut tampered = rgc.clone();
        tampered.epoch_fence = Epoch::new(13);
        assert!(!tampered.verify(&vk), "altering the fence epoch invalidates the signature");
        let mut widened = rgc.clone();
        widened.survivors.push(5);
        assert!(!widened.verify(&vk), "adding a survivor invalidates the signature");
    }

    #[test]
    fn the_recovery_decision_walks_the_honest_majority_ladder() {
        // majority_threshold is the derived honest-majority bound, clamped to the floor.
        assert_eq!(majority_threshold(7), 4);
        assert_eq!(majority_threshold(5), 3);
        assert_eq!(majority_threshold(4), 3);
        assert_eq!(majority_threshold(3), 2);
        assert_eq!(majority_threshold(2), 2, "the resharing floor clamps a 2-node committee");
        assert_eq!(majority_threshold(1), 2, "and a 1-node committee (never resharable)");

        let idx = |n: usize| (1..=n as u8).collect::<Vec<u8>>();
        // Healthy for its threshold — no action while the majority bound still equals the current threshold.
        assert_eq!(recovery_decision(&idx(7), 4), RecoveryAction::None);
        assert_eq!(recovery_decision(&idx(6), 4), RecoveryAction::None);
        // Thinned to where a lower honest-majority threshold buys headroom — proactively reshare (Regime A),
        // while ≥ threshold anchors still make a reshare possible.
        assert_eq!(
            recovery_decision(&idx(5), 4),
            RecoveryAction::ProactiveReshare { survivors: idx(5), new_threshold: 3 },
        );
        // After that reshare (t=3), the ladder continues: 5,4 healthy; 3 warrants t'=2.
        assert_eq!(recovery_decision(&idx(4), 3), RecoveryAction::None);
        assert_eq!(
            recovery_decision(&idx(3), 3),
            RecoveryAction::ProactiveReshare { survivors: idx(3), new_threshold: 2 },
        );
        // A minimal 2-of-2 committee is healthy (no lower honest-majority threshold exists).
        assert_eq!(recovery_decision(&idx(2), 2), RecoveryAction::None);
        // Below the current threshold — reshare is impossible, escalate to re-genesis (Regime B).
        assert_eq!(
            recovery_decision(&idx(3), 4),
            RecoveryAction::RequestRegenesis { survivors: idx(3) },
            "the R-C1 cliff: 3 < t=4 survivors demand an authorized re-genesis",
        );
        assert_eq!(recovery_decision(&idx(1), 2), RecoveryAction::RequestRegenesis { survivors: idx(1) });
        assert_eq!(recovery_decision(&[], 2), RecoveryAction::RequestRegenesis { survivors: vec![] });
    }

    #[test]
    fn a_below_floor_threshold_is_refused() {
        let (sk, vk) = authority();
        // t' = 1 would let one new holder reconstruct the fresh key alone — refused structurally.
        let rgc = RecoveryAuthorization::issue(&sk, 1, Epoch::new(9), &[6, 7], 1, [0; 32]);
        assert!(!rgc.verify(&vk), "threshold below MIN_REGENESIS_THRESHOLD is not well-formed");
        // t' > |survivors| is impossible to satisfy — refused.
        let rgc = RecoveryAuthorization::issue(&sk, 1, Epoch::new(9), &[6, 7], 3, [0; 32]);
        assert!(!rgc.verify(&vk), "threshold above the survivor count is not well-formed");
    }
}
