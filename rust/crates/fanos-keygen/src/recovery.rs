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

/// The largest recovery-authority committee a decoder will allocate for.
///
/// Not a policy on how many founders a network may have — it is a **decode bound**, and it exists because
/// the signature count on the wire is attacker-supplied: without it, `from_bytes` would reserve capacity
/// from a `u64` a peer chose. Sized at the largest cell this platform's addressing supports, `PG(2, 31)`'s
/// `q² + q + 1 = 993` points, since the authority committee is a founder set and a founder holds a seat.
/// Derived from the plane, not picked.
pub const MAX_AUTHORITY_MEMBERS: usize = 31 * 31 + 31 + 1;

/// The **recovery authority**: the trust root that may order a beacon reshape, as a *committee* rather than
/// one key.
///
/// A cell's DVRF secret is `t`-of-`n` precisely so no single party holds it. The authority that can order that
/// key replaced was, until this type existed, a **single** `HybridVerifier` — one `recovery-authority.key` on
/// one founder's disk, able to authorize a re-genesis of a key it takes a threshold to use. That asymmetry
/// undid the DKG: whoever held the file could replace the beacon, and since coordinates derive from the
/// beacon (`docs/design-governance.md` §2.1) that is the placement of every node in the cell.
///
/// The quorum is **derived, never configured** — see [`authority_quorum`]. A configurable quorum is the
/// `CellParams` defect again (`fanos-cli/tests/provisioning.rs`): a provisioning file one value too loose
/// would silently restore single-party control, and no node could tell.
#[derive(Clone)]
pub struct RecoveryAuthoritySet {
    /// The founders' verifiers, in the order the ceremony fixed. A signature names its member by index into
    /// this vector, so the set's *order* is part of the cell's genesis material.
    members: Vec<HybridVerifier>,
}

/// By encoded bytes: `HybridVerifier` is a key pair of two schemes and implements neither `PartialEq` nor
/// `Debug`, deliberately — a key is compared by its canonical encoding or not at all.
impl PartialEq for RecoveryAuthoritySet {
    fn eq(&self, other: &Self) -> bool {
        self.members.len() == other.members.len()
            && self.members.iter().zip(&other.members).all(|(a, b)| a.encode() == b.encode())
    }
}

/// Size and quorum, never key material — the same posture as `BeaconParams`'s own `Debug`.
impl core::fmt::Debug for RecoveryAuthoritySet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryAuthoritySet")
            .field("members", &self.members.len())
            .field("quorum", &self.quorum())
            .finish()
    }
}

impl RecoveryAuthoritySet {
    /// A committee of `members`. `None` if empty — an authority nobody can be is not an authority, and the
    /// honest way to disable recovery is `authority: None` on the beacon, which fails closed and is already
    /// what an unprovisioned cell does.
    #[must_use]
    pub fn new(members: Vec<HybridVerifier>) -> Option<Self> {
        (!members.is_empty()).then_some(Self { members })
    }

    /// The committee's members.
    #[must_use]
    pub fn members(&self) -> &[HybridVerifier] {
        &self.members
    }

    /// How many members must sign — [`authority_quorum`] of the set size.
    #[must_use]
    pub fn quorum(&self) -> usize {
        authority_quorum(self.members.len())
    }
}

/// The number of authority members that must sign, for a committee of `m`: a **strict majority**, `m/2 + 1`.
///
/// Derived from the property the whole recovery design rests on. `docs/design-recovery.md` §2 makes
/// re-genesis safe by being *single-writer*: "at most one authorization is ever validly signed per
/// generation", so a returning partitioned group is subordinated rather than forking. A committee preserves
/// that exactly when **any two quorums intersect**, which for a set of size `m` is exactly `2k > m`, i.e.
/// `k ≥ m/2 + 1`. Any smaller `k` lets two disjoint subsets each sign a *different* authorization at the same
/// generation — two fresh keys, two lineages, one cell: the fork the fencing exists to prevent.
///
/// It is the same intersection argument as the cell's own `2Q > n + f`, applied to a committee whose failure
/// mode is equivocation rather than crash.
///
/// `m = 1` gives `k = 1`, which is correct rather than a special case: a single-operator cell has one
/// founder, that founder *is* the constitution, and the runbook says so
/// (`docs/testnet.md` §3.1, `docs/design-governance.md` §2.1). The committee buys nothing there and the type
/// does not pretend otherwise.
#[must_use]
pub const fn authority_quorum(m: usize) -> usize {
    m / 2 + 1
}

/// A **re-genesis certificate** (`RGC`): the recovery authority's authorization for a below-threshold cell to
/// re-key from scratch among `survivors`, resuming the epoch clock at `epoch_fence`, generation `generation`.
///
/// Every semantic field is bound by each of [`sigs`](Self::sigs), so none can be altered without invalidating
/// them, and the `generation` fences the whole cell: a node rejects any beacon artifact from an older
/// generation (`docs/design-recovery.md` §2).
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
    /// The authorizing signatures, as `(member index into the authority set, hybrid PQ signature over
    /// [`signable`](Self::signable))`, **sorted by index and distinct** — so one member cannot fill a quorum
    /// by signing repeatedly, and the canonical encoding is unambiguous.
    pub sigs: Vec<(u8, HybridSignature)>,
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

    /// Begin an authorization, with no signatures yet. `survivors` is canonicalized (sorted, deduplicated) so
    /// the signed set is unambiguous.
    ///
    /// Separate from signing because the founders are on **separate machines** — that is the entire point of
    /// a committee. Each independently reconstructs this same value from the agreed parameters, calls
    /// [`sign`](Self::sign), and their signatures are collected; nothing has to travel but the signature.
    #[must_use]
    pub fn unsigned(
        generation: u64,
        epoch_fence: Epoch,
        survivors: &[u8],
        threshold: u8,
        anchor: [u8; 32],
    ) -> Self {
        let mut survivors = survivors.to_vec();
        survivors.sort_unstable();
        survivors.dedup();
        Self { generation, epoch_fence, survivors, threshold, anchor, sigs: Vec::new() }
    }

    /// Add authority member `index`'s signature over every semantic field. `false` — and no change — if that
    /// member has already signed, which is what stops one key from filling a quorum by itself.
    pub fn sign(&mut self, index: u8, member: &HybridSigSecret) -> bool {
        if self.sigs.iter().any(|(i, _)| *i == index) {
            return false;
        }
        let sig = member
            .sign(&Self::signable(self.generation, self.epoch_fence, &self.survivors, self.threshold, &self.anchor));
        self.sigs.push((index, sig));
        self.sigs.sort_by_key(|(i, _)| *i);
        true
    }

    /// Issue a fully-signed authorization in one call — the single-machine ceremony, and the shape every test
    /// wants. `members` are `(index, secret)` pairs.
    #[must_use]
    pub fn issue(
        members: &[(u8, &HybridSigSecret)],
        generation: u64,
        epoch_fence: Epoch,
        survivors: &[u8],
        threshold: u8,
        anchor: [u8; 32],
    ) -> Self {
        let mut rgc = Self::unsigned(generation, epoch_fence, survivors, threshold, anchor);
        for (index, sk) in members {
            rgc.sign(*index, sk);
        }
        rgc
    }

    /// Verify the authorization against the cell's recovery `authority` committee and its internal
    /// well-formedness: a **quorum** of distinct members have each signed every field, the survivor set is
    /// sorted+distinct+non-empty, and `MIN_REGENESIS_THRESHOLD ≤ threshold ≤ |survivors|`.
    ///
    /// Does **not** check the anchor or the generation monotonicity — those are the adopting node's
    /// responsibility ([`crate::beacon::BeaconNode::rebootstrap`]), since they depend on that node's local
    /// state — nor whether the cell is genuinely below threshold, which is guard 6 there.
    #[must_use]
    pub fn verify(&self, authority: &RecoveryAuthoritySet) -> bool {
        if !self.well_formed() || self.sigs.len() < authority.quorum() {
            return false;
        }
        // Distinct and ordered: a repeated index would let one member count twice toward the quorum, and an
        // unordered list would make the canonical encoding ambiguous. Checked rather than assumed, because
        // this value arrives from the wire.
        if !self.sigs.is_sorted_by(|(a, _), (b, _)| a < b) {
            return false;
        }
        let message =
            Self::signable(self.generation, self.epoch_fence, &self.survivors, self.threshold, &self.anchor);
        self.sigs.iter().all(|(index, sig)| {
            authority.members().get(usize::from(*index)).is_some_and(|vk| vk.verify(&message, sig))
        })
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
        put_u64(&mut out, self.sigs.len() as u64);
        for (index, sig) in &self.sigs {
            out.push(*index);
            put_var_bytes(&mut out, &sig.to_bytes());
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed / truncated / trailing garbage.
    ///
    /// The signature count is bounded by [`MAX_AUTHORITY_MEMBERS`] before anything is allocated: the length
    /// arrives from the wire, and a `u64` of them would otherwise be a reservation request from an attacker.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let generation = r.u64()?;
        let epoch_fence = Epoch::new(r.u64()?);
        let threshold = r.u8()?;
        let survivors = r.var_bytes()?.to_vec();
        let anchor = r.array::<32>()?;
        let count = usize::try_from(r.u64()?).ok()?;
        if count > MAX_AUTHORITY_MEMBERS {
            return None;
        }
        let mut sigs = Vec::with_capacity(count);
        for _ in 0..count {
            let index = r.u8()?;
            sigs.push((index, HybridSignature::from_bytes(r.var_bytes()?)?));
        }
        r.finish()?;
        Some(Self { generation, epoch_fence, survivors, threshold, anchor, sigs })
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

/// The **stall detector** (audit §4): the driver state that turns a frozen beacon clock into a
/// [`recovery_decision`]. The recovery watcher folds one observation of the current live-beacon epoch per
/// periodic tick; [`observe`](Self::observe) confirms a *stall* — the clock frozen, not merely quiet between
/// rounds — once the epoch has failed to advance for `patience` consecutive observations, returning `true`
/// exactly on that confirmation and then re-arming, so a persistent freeze re-fires every `patience` ticks
/// (periodic recovery attempts, not a one-shot). Any epoch advance clears the count.
#[derive(Clone, Debug)]
pub struct StallDetector {
    patience: usize,
    last: Option<Epoch>,
    stalled_for: usize,
}

impl StallDetector {
    /// A detector that confirms a stall after `patience` consecutive non-advancing observations. A
    /// `patience` of `0` is treated as `1` (a stall is never confirmed on the first, baseline observation).
    #[must_use]
    pub fn new(patience: usize) -> Self {
        Self { patience: patience.max(1), last: None, stalled_for: 0 }
    }

    /// Fold one periodic observation of the current live `epoch`. Returns `true` iff this observation
    /// confirms a stall (the epoch has not advanced for `patience` consecutive ticks); an advance resets the
    /// counter and returns `false`, and the first observation only establishes the baseline.
    pub fn observe(&mut self, epoch: Epoch) -> bool {
        match self.last {
            // Baseline: the first observation establishes the tracked epoch, never an immediate stall.
            None => {
                self.last = Some(epoch);
                self.stalled_for = 0;
                false
            }
            // Progress: the clock advanced, so the anchors are live — clear the count.
            Some(prev) if epoch > prev => {
                self.last = Some(epoch);
                self.stalled_for = 0;
                false
            }
            // No advance this tick: confirm a stall once the count reaches `patience`, then re-arm.
            Some(_) => {
                self.stalled_for += 1;
                if self.stalled_for >= self.patience {
                    self.stalled_for = 0;
                    true
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_pqcrypto::SeedRng;

    fn authority() -> (HybridSigSecret, RecoveryAuthoritySet) {
        let (sk, vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"recovery-authority"));
        (sk, RecoveryAuthoritySet::new(vec![vk]).unwrap())
    }

    #[test]
    fn an_issued_authorization_verifies_and_round_trips() {
        let (sk, vk) = authority();
        let rgc = RecoveryAuthorization::issue(&[(0, &sk)], 1, Epoch::new(9), &[5, 6, 7], 2, [0x11; 32]);
        assert!(rgc.verify(&vk), "the issued authorization verifies against its authority");
        assert_eq!(rgc.survivors, vec![5, 6, 7], "the survivor set is canonicalized");
        let round = RecoveryAuthorization::from_bytes(&rgc.to_bytes()).expect("re-decodes");
        assert_eq!(round, rgc, "the wire form round-trips");
        assert!(round.verify(&vk), "and still verifies");
    }

    #[test]
    fn tampering_or_a_foreign_authority_is_rejected() {
        let (sk, vk) = authority();
        let (_other_sk, other_key) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"impostor"));
        let other_vk = RecoveryAuthoritySet::new(vec![other_key]).unwrap();
        let rgc = RecoveryAuthorization::issue(&[(0, &sk)], 3, Epoch::new(12), &[1, 2, 3, 4], 3, [0x22; 32]);
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

    /// **One member of the recovery committee cannot order a re-genesis, and cannot fake a quorum.**
    ///
    /// This is the property the committee exists for. A cell's DVRF key is `t`-of-`n` so no single party
    /// holds it; the authority that can order that key REPLACED used to be one `HybridVerifier` — one file on
    /// one founder's disk. Whoever held it could re-key the cell, and coordinates derive from the beacon, so
    /// that is the placement of every node. The DKG's whole guarantee, undone by the key next to it.
    #[test]
    fn a_minority_of_the_recovery_committee_cannot_authorize() {
        let founders: Vec<(HybridSigSecret, HybridVerifier)> = (0u8..5)
            .map(|i| HybridSigSecret::generate(&mut SeedRng::from_seed(&[b'f', i])))
            .collect();
        let set = RecoveryAuthoritySet::new(founders.iter().map(|(_, vk)| vk.clone()).collect()).unwrap();
        assert_eq!(set.quorum(), 3, "5 members ⇒ a strict majority is 3");

        let issue = |signers: &[u8]| {
            let members: Vec<(u8, &HybridSigSecret)> =
                signers.iter().filter_map(|&i| founders.get(usize::from(i)).map(|(sk, _)| (i, sk))).collect();
            RecoveryAuthorization::issue(&members, 1, Epoch::new(9), &[1, 2], 2, [0x33; 32])
        };

        // THE PROPERTY: every sub-quorum is refused, whoever it is.
        for signers in [&[0u8][..], &[4][..], &[0, 1][..], &[2, 3][..], &[0, 4][..]] {
            assert!(
                !issue(signers).verify(&set),
                "{} of 5 authority members signed — below the strict majority that keeps re-genesis \
                 single-writer, so it must not authorize anything",
                signers.len()
            );
        }

        // A member cannot fill the gap by signing twice: `sign` refuses a repeat, so the certificate stays
        // one signature short rather than silently counting the same key toward the quorum.
        let mut doubled = issue(&[0, 1]);
        let (one_sk, _) = founders.get(1).expect("member 1");
        assert!(!doubled.sign(1, one_sk), "a member that has signed cannot sign again");
        assert_eq!(doubled.sigs.len(), 2, "and no signature was added");
        assert!(!doubled.verify(&set));

        // Nor by forging an index it does not hold: the signature is checked against the verifier AT that
        // index, so member 0 claiming to be member 2 fails on the key, not on the count.
        let mut impersonating = issue(&[0, 1]);
        let message = RecoveryAuthorization::signable(1, Epoch::new(9), &[1, 2], 2, &[0x33; 32]);
        let (zero_sk, _) = founders.first().expect("member 0");
        impersonating.sigs.push((2, zero_sk.sign(&message)));
        impersonating.sigs.sort_by_key(|(i, _)| *i);
        assert_eq!(impersonating.sigs.len(), 3, "a quorum by count");
        assert!(!impersonating.verify(&set), "but member 0's signature does not verify under member 2's key");

        // THE MECHANISM, so the test cannot pass by refusing everything: a genuine quorum authorizes, and
        // round-trips through the wire encoding unchanged.
        let good = issue(&[1, 2, 4]);
        assert!(good.verify(&set), "a strict majority of distinct members authorizes");
        let back = RecoveryAuthorization::from_bytes(&good.to_bytes()).expect("round-trips");
        assert_eq!(back, good);
        assert!(back.verify(&set), "and still verifies after a wire round-trip");
    }

    /// The quorum is a strict majority at every size, and that is what keeps two authorizations from being
    /// validly signed at one generation — the single-writer property the fencing rests on.
    #[test]
    fn the_authority_quorum_is_a_strict_majority_so_two_quorums_always_intersect() {
        for m in 1..=64usize {
            let k = authority_quorum(m);
            assert!(2 * k > m, "m={m}: quorum {k} must be a strict majority, or two disjoint quorums exist");
            assert!(k <= m, "m={m}: quorum {k} must be reachable");
            // The intersection statement itself, stated as the pigeonhole it is: two k-subsets of an
            // m-set share at least `2k − m ≥ 1` members, so they cannot sign different certificates.
            assert!(2 * k - m >= 1, "m={m}: any two quorums must share a member");
        }
        assert_eq!(authority_quorum(1), 1, "a single-founder cell is its own constitution");
        assert_eq!(authority_quorum(7), 4);
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
        let rgc = RecoveryAuthorization::issue(&[(0, &sk)], 1, Epoch::new(9), &[6, 7], 1, [0; 32]);
        assert!(!rgc.verify(&vk), "threshold below MIN_REGENESIS_THRESHOLD is not well-formed");
        // t' > |survivors| is impossible to satisfy — refused.
        let rgc = RecoveryAuthorization::issue(&[(0, &sk)], 1, Epoch::new(9), &[6, 7], 3, [0; 32]);
        assert!(!rgc.verify(&vk), "threshold above the survivor count is not well-formed");
    }

    #[test]
    fn the_stall_detector_confirms_a_freeze_after_patience_and_rearms() {
        let mut d = StallDetector::new(3);
        // The first observation is only a baseline — never an immediate stall.
        assert!(!d.observe(Epoch::new(5)));
        // Three consecutive non-advancing observations confirm the stall on the third.
        assert!(!d.observe(Epoch::new(5)));
        assert!(!d.observe(Epoch::new(5)));
        assert!(d.observe(Epoch::new(5)), "a freeze is confirmed after `patience` non-advancing ticks");
        // It re-arms: another `patience` frozen ticks re-fire (periodic recovery attempts, not one-shot).
        assert!(!d.observe(Epoch::new(5)));
        assert!(!d.observe(Epoch::new(5)));
        assert!(d.observe(Epoch::new(5)), "a persistent freeze re-fires every `patience` ticks");
        // An epoch advance clears the count — no stall while the clock is moving.
        assert!(!d.observe(Epoch::new(6)));
        assert!(!d.observe(Epoch::new(6)));
        assert!(!d.observe(Epoch::new(7)));
    }
}
