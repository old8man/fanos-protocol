//! The distributed randomness **beacon** as a running node engine (spec §L3, audit E5) — the live
//! epoch clock that makes E5 (unpredictable rendezvous) and E4 (relay-key rotation) operational.
//!
//! [`fanos_vrf::beacon`] verifies the *cryptography* (pairing-free distributed VRF over the DKG);
//! [`BeaconNode`] makes it a **networked protocol**, exactly as [`crate::DkgNode`] does for the DKG.
//! Each node holds the group commitment (a DKG output, agreed by all honest nodes) and — if it is an
//! **anchor** — its beacon share. Per epoch:
//!
//! 1. On `Command::AdvanceEpoch` an anchor computes its partial `σ_i = s_i·M(next_epoch)` and floods a
//!    `BeaconPartial` to the cell.
//! 2. Any node verifies each partial's DLEQ against the group commitment and buffers it; once a
//!    threshold of distinct partials is in, it assembles a [`BeaconRound`], re-checks it, and **adopts**
//!    the epoch's public seed.
//! 3. It floods the assembled round (`Beacon` frame) so pure consumers (no share) adopt too, and emits
//!    [`Notification::BeaconReady`] carrying `(epoch, seed)` for the node driver to fold into the
//!    rendezvous meeting line and to rotate the E4 onion keys.
//!
//! Because the combined `σ = x·M` is subset-independent, every node adopts the **same** seed regardless
//! of which partials it happened to assemble; adoption is monotone (forward-only), so re-floods
//! terminate. Trust is in the algebra (every partial's DLEQ is checked against the public commitment),
//! never in the peer that relayed it — a forged partial or round is dropped, not adopted.

use std::collections::{BTreeMap, BTreeSet};

use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_ports::{Command, Effect, Engine, Epoch, Escalation, Input, Instant, Notification};
use fanos_pqcrypto::sig::HYBRID_SIG_LEN;
use fanos_pqcrypto::{HybridSigSecret, HybridSignature};
use fanos_primitives::hash_labeled;
use fanos_vrf::beacon::{BeaconPartial, BeaconRound, PARTIAL_LEN, partial_eval, verify_partial};
use fanos_vrf::vss::{
    VssCommitment, VssShare, combine_reshare_commitment, combine_reshare_share, reshare, verify_reshare_commit,
    verify_share,
};
use fanos_wire::{FrameType, decode_frame, encode_frame};

use crate::recovery::{MAX_AUTHORITY_MEMBERS, RecoveryAuthoritySet, RecoveryAuthorization};
use fanos_primitives::BeaconSeed;

/// Domain-separation label for the cell lineage fingerprint an `RGC` binds to (audit §4).
const LINEAGE_LABEL: &str = "FANOS-recovery-v1/lineage";

/// Cap on partials buffered per in-progress epoch. A cell has at most `N` anchors, so honest operation
/// never approaches this; the cap bounds memory against a peer flooding forged `BeaconPartial`s (each
/// still fails its DLEQ, so none is ever adopted — this only bounds the buffer).
const MAX_PARTIALS: usize = 256;

/// Cap on the number of **future epochs** partials are buffered for at once.
///
/// `MAX_PARTIALS` bounds each bucket and nothing bounded the number of buckets: `buffer` refuses only
/// `epoch <= self.epoch`, so every epoch above the adopted one opened a fresh entry. Partials are DLEQ-verified
/// against the group commitment before buffering, which means a forged one is refused — but a **committee
/// member** can evaluate its share at any target, so a Byzantine member could open unboundedly many buckets
/// with entirely valid partials. Authenticated-but-unbounded, the same shape as audit B1's `pending_reveals`
/// and TAXIS's `exec_votes`.
///
/// **Evict the HIGHEST epoch**, and that direction is derived rather than chosen. Beacon epochs are adopted in
/// order — `try_assemble` adopts, then `pending.retain(|&e, _| e > epoch)` clears everything at or below — so
/// the next epoch that can possibly assemble is the *smallest* pending one. Far-future buckets cannot become
/// current until every epoch below them has, which makes them exactly what an attacker fills memory with and
/// exactly what an honest cell does not need. (Contrast TAXIS's `exec_votes`, where the checkpoint is monotone
/// upward and the *highest* is the one worth keeping, and the sealed mempool, where nothing is visible before
/// reveal so there is no honest ordering at all and admission is refused instead. Three retentions, three
/// eviction rules, each read off the ordering its data actually has.)
const MAX_PENDING_EPOCHS: usize = 8;

/// Cap on concurrently-tracked resharing generations. Honest operation runs one at a time; this bounds
/// memory against a peer flooding triggers/commits for many bogus generations (each commit still fails its
/// binding check, so none is ever adopted — this only bounds the buffer). Oldest generations are evicted.
const MAX_RESHARE_GENS: usize = 4;

/// How many generations ahead of the adopted one a resharing trigger may name (audit §3.1). Bounds the
/// flood/eviction surface: an unauthenticated trigger cannot jump to a far-future generation and evict the
/// live in-progress rounds through [`BeaconNode::prune_reshare_gens`].
const MAX_RESHARE_GEN_ADVANCE: u64 = 8;

/// The smallest resharing threshold a trigger may name (audit §3.1 — the CRITICAL key-exfiltration floor).
/// A `new_threshold = 1` reshare deals a **degree-0** polynomial `gᵢ`, so `gᵢ(j) = sᵢ` at *every* new
/// index — one malicious new holder harvests each contributor's raw secret share and reconstructs the beacon
/// master key. Requiring `≥ 2` makes every sub-share a single evaluation of a degree-≥1 polynomial, useless
/// to a holder without `new_threshold` of them (and a single-identity attacker controls exactly one
/// new-holder coordinate). See the security note on [`BeaconNode::on_reshare_trigger`].
const MIN_RESHARE_THRESHOLD: usize = 2;

/// Why the beacon refused something — the counters this crate had none of.
///
/// `fanos-keygen` holds the DKG and the beacon reshare, where **four CRITICALs** were found (audit B1–B3:
/// unauthenticated complaint/commit/justify frames, a discarded `ingest_share` result, a justification checked
/// against the wrong commitment) plus the last live CRITICAL of all four passes (§2.1, the 2-anchor
/// master-key exfiltration, closed 2026-07-24 by authenticating the reshare trigger).
///
/// All are fixed. None were **observable**. A node refusing a forged reshare trigger and a node with nothing
/// to do are the same silence at every surface an operator has — and the beacon is the shared clock: the
/// coordinate VRF, activation heights, mix-key rotation and rendezvous meeting lines all derive from it, so a
/// beacon that stalls stalls everything and the cause has to be readable.
///
/// Counters, not logs: this crate is `no_std` and sans-I/O, with nowhere to write.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconRejects {
    /// A reshare trigger arrived and this cell has **no recovery authority**, so no reshare can be
    /// authenticated at all. Distinct from a forgery: this is a provisioning gap, not an attack.
    pub reshare_no_authority: u64,
    /// A reshare trigger whose signature did not verify against the recovery authority — **forged, foreign,
    /// or tampered**. The §2.1 attack, counted. Nothing else an operator can see distinguishes it from quiet.
    pub reshare_forged: u64,
    /// A reshare trigger this build could not parse (the envelope decoded, the body did not).
    pub reshare_malformed: u64,
    /// A buffered future-epoch partial set discarded at `MAX_PENDING_EPOCHS`.
    ///
    /// Zero in honest operation: a cell runs one epoch ahead, not eight. A nonzero value means partials are
    /// arriving for epochs far beyond the adopted one — which a committee member can produce validly, so this
    /// is the only signal that one is doing it, and the difference between a bounded buffer and a silent one.
    pub partial_epoch_evicted: u64,
    /// A frame that did not decode at all, so its **type was never read** and no handler ran.
    ///
    /// Counted separately from the two above because it is upstream of them: a corrupted attack frame is
    /// refused here without anything downstream ever learning an attack was attempted.
    pub frame_undecodable: u64,

    // --- The steady state (#161) ---------------------------------------------------------------------
    //
    // The five counters above cover the **reshare trigger**: a rare, out-of-band, operator-initiated event.
    // The partial/round flood is what this beacon does every epoch, for ever, and it had no counters at all —
    // so the instrument covered the rare path and not the hot one, on the clock every epoch-aligned mechanism
    // derives from.
    /// A partial for an epoch this node has already adopted.
    ///
    /// **Benign and expected to be nonzero**: re-flooding is how the flood terminates. It is counted only so
    /// it can be told apart from the one below — the two used to share a single `||` early return, which made
    /// them indistinguishable *in principle*, not merely uncounted ([[one-predicate-two-decisions]]).
    pub partial_stale: u64,
    /// A partial whose **DLEQ proof did not verify** against the group commitment.
    ///
    /// Expected zero. Nonzero means one of two things and an operator must investigate both: a forged or
    /// tampered partial, or **this node holding the wrong commitment** — a provisioning mismatch that looks
    /// identical from here and stalls the cell just as thoroughly.
    pub partial_unverified: u64,
    /// A partial frame whose body did not parse.
    pub partial_malformed: u64,
    /// A round frame whose body did not parse.
    pub round_malformed: u64,
    /// A **flooded round that failed verification** against the group commitment — a forged beacon round.
    ///
    /// This is the frame that sets the cell's shared clock. Expected zero.
    pub round_unverified: u64,
    /// This node reached threshold, assembled a round from its own buffered partials, and the **combined
    /// round failed to verify**.
    ///
    /// The worst of the six, because the cell produces no seed and the clock stops. Expected zero.
    ///
    /// **This doc used to enumerate two causes and miss the reachable one.** It said "at least one buffered
    /// partial was bad *and passed* `verify_partial`, or the threshold combination is wrong for this
    /// commitment" — both of which describe a bug in code that is exercised every epoch. The third cause was
    /// the live one: `advance` buffered **this node's own partial**, from `partial_eval`, which is the one
    /// partial in the bucket that never went through `verify_partial` at all. A node holding a share that does
    /// not match its commitment therefore poisoned its own bucket permanently — `BeaconRound::assemble` takes
    /// the first `threshold` distinct indices in insertion order, and its own is inserted first, so every
    /// assembly failed while its peers' partials were all valid (measured: 4 failures in a single epoch on a
    /// 7-node cell). That cause is now closed at the source — `advance` verifies its own partial before it
    /// buffers or floods it, and reports [`Escalation::BeaconShareMismatch`] instead — which leaves this
    /// counter guarding only the two cases above, both of which mean **this build is wrong**, not that the
    /// cell is under attack.
    pub assembly_unverified: u64,

    // --- Provisioning, not attack -------------------------------------------------------------------
    /// This node's own **share does not match the group commitment**, so the partial it computed failed its
    /// own DLEQ and was neither buffered nor flooded.
    ///
    /// Counted separately from [`partial_unverified`](Self::partial_unverified) although the algebraic test is
    /// identical, because the two answer different questions and send an operator to different places: that one
    /// is about a partial that **arrived**, this one about a partial this node **produced**. A cell where one
    /// node reads `share_mismatched` and every other node reads `partial_unverified` is not under attack — it
    /// is one stale share file, and without this counter the only visible evidence was `n − 1` forgery reports
    /// naming an honest peer.
    ///
    /// Rises once per epoch for as long as the file is wrong, because the fault is permanent and the check is
    /// at the point of use; the *rate* is the epoch clock and carries no information beyond "still wrong".
    pub share_mismatched: u64,
}

/// A node running the distributed randomness beacon over its cell.
pub struct BeaconNode<F: Field> {
    /// Why this beacon refused things — see [`BeaconRejects`].
    rejects: BeaconRejects,
    coord: Point<F>,
    n: usize,
    threshold: usize,
    /// This node's beacon share — `Some` for an **anchor** that contributes partials, `None` for a pure
    /// consumer (which still verifies and adopts flooded rounds).
    share: Option<VssShare>,
    /// The group commitment every node verifies partials and rounds against (a DKG output; identical
    /// across all honest nodes, which fold the same qualified set).
    commitment: VssCommitment,
    /// The current adopted beacon epoch and its public seed (this network's genesis seed until the first
    /// round is adopted — see [`BeaconNode::new`]).
    epoch: Epoch,
    seed: [u8; 32],
    /// This network's epoch-0 seed, kept **separately** from `seed` because `seed` advances every round and
    /// the invariant it anchors — that the beacon and the transport were provisioned onto the same network —
    /// has to stay checkable for the node's whole life, not only before the first round. Reading it from
    /// `seed` would make the guard a precondition on startup order, which is the shape that produced the
    /// defect in the first place.
    genesis: BeaconSeed,
    /// Verified partials collected for each not-yet-adopted future epoch, until a round assembles.
    pending: BTreeMap<Epoch, Vec<BeaconPartial>>,
    /// The current epoch's assembled round, cached so this node can answer a `BeaconReq` pull-sync from a
    /// joining node (spec §7.8 bootstrap) — `None` until the first round is adopted.
    current_round: Option<BeaconRound>,
    /// The resharing generation this node has adopted (0 = the genesis sharing, never reshared). Monotone:
    /// only a strictly-newer generation is accepted, so reshare floods terminate (audit R-C1).
    reshare_gen: u64,
    /// In-progress resharings, keyed by generation: the trigger's parameters plus the collected public
    /// commitments and this node's private sub-shares, until a canonical ≥`t`-of-old contributor set
    /// validates and the redistributed sharing is adopted.
    pending_reshare: BTreeMap<u64, ReshareRound>,
    /// The **recovery authority** — the trust root that may authorize a below-threshold re-genesis
    /// ([`rebootstrap`](Self::rebootstrap)). The parent cell's key, or (for the root cell) a founder/constitution
    /// key. `None` disables re-genesis: a cell with no configured authority freezes rather than re-key on an
    /// unauthenticated say-so (audit §4, `docs/design-recovery.md`).
    authority: Option<RecoveryAuthoritySet>,
}

/// An in-progress resharing generation (audit R-C1). A coordinator's trigger fixes the target set; each
/// old anchor floods its public commitment `Dᵢ` and privately sends each new holder its sub-share `gᵢ(j)`.
/// Once `≥ t` old anchors' commitments validate, every node derives the new group commitment from public
/// data (`C' = Σ λᵢ(0)·Dᵢ`), and each new holder combines its sub-shares into its new share.
#[derive(Default)]
struct ReshareRound {
    /// The target threshold `t'` (set by the trigger; `None` until the trigger is seen).
    new_threshold: Option<usize>,
    /// The exact old-anchor contributor set named by the trigger — the canonical set every node combines, so
    /// all agree on the same redistributed sharing regardless of message timing.
    contributors: Vec<u8>,
    /// The target new-holder index set (set by the trigger).
    new_indices: Vec<u8>,
    /// Whether this (anchor) node has already dealt its own contribution for this generation.
    dealt: bool,
    /// old_index → its verified public commitment `Dᵢ` (only binding-valid commitments are stored).
    commits: BTreeMap<u8, VssCommitment>,
    /// old_index → this node's sub-share `gᵢ(my_index)` (stored only if this node is a target new holder).
    subshares: BTreeMap<u8, VssShare>,
}

impl<F: Field> BeaconNode<F> {
    /// How many distinct future epochs currently hold buffered partials — **crate-private, and the demotion is
    /// the point**.
    ///
    /// This was `pub` on the argument that "is this node buffering for eight epochs ahead?" is a real operator
    /// question. It is, and the operator already has its answer: [`BeaconRejects::partial_epoch_evicted`]
    /// counts every time `MAX_PENDING_EPOCHS` actually bound, which is the *event*, while this is only the
    /// gauge behind it. A public gauge with no reader is a door onto nothing, and the unwired-capability
    /// ratchet in `fanos-cli/tests/architecture.rs` exists to stop exactly that accumulating — so the gauge
    /// stays where its one caller is: the test that asserts the bound holds.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn pending_epochs(&self) -> usize {
        self.pending.len()
    }

    /// The smallest future epoch with buffered partials — the next one that can possibly assemble, since
    /// adoption is in order. Crate-private for the same reason as [`pending_epochs`](Self::pending_epochs).
    #[must_use]
    #[cfg(test)]
    pub(crate) fn lowest_pending_epoch(&self) -> Option<Epoch> {
        self.pending.keys().next().copied()
    }

    /// Why this beacon has refused things — the operator's read on whether it is quiet or under attack.
    ///
    /// Public because the distinction is invisible otherwise: a beacon that has stalled because someone is
    /// feeding it forged reshare triggers and a beacon that is simply idle produce the same absence of
    /// rounds, and the beacon is the clock every epoch-aligned mechanism reads.
    #[must_use]
    pub const fn rejects(&self) -> BeaconRejects {
        self.rejects
    }

    /// A beacon node at `coord`, verifying against the group `commitment` at `threshold`. `share` is
    /// this node's DKG beacon share if it is an anchor (it then contributes partials), else `None`.
    /// Starts at [`Epoch::ZERO`] with `genesis` as its seed until the first round is adopted.
    ///
    /// `genesis` is **this network's** epoch-0 seed, and it is a parameter rather than a constant because it
    /// stopped being one. This constructor used to start at `[0u8; 32]` and call that "the genesis seed" —
    /// true until the seed became `H("FANOS-v1/genesis-beacon" ‖ network_id)` so that two deployments would
    /// not share every genesis coordinate. After that change a node held **two** epoch-0 beacons: this one at
    /// zeros and `Client::genesis()` at the derived value, with nothing reading them together (#141).
    ///
    /// A parameter and not a setter: a value that must be right will be absent if it is optional, and the one
    /// production site (`composition.rs`) already holds it as `BeaconParams::genesis_seed()`. A test cell with
    /// no network name passes [`BeaconSeed::GENESIS`] and means it.
    #[must_use]
    pub fn new(
        coord: Point<F>,
        share: Option<VssShare>,
        commitment: VssCommitment,
        threshold: usize,
        genesis: BeaconSeed,
    ) -> Self {
        Self {
            rejects: BeaconRejects::default(),
            coord,
            n: Plane::<F>::N as usize,
            threshold,
            share,
            commitment,
            epoch: Epoch::ZERO,
            seed: *genesis.as_bytes(),
            genesis,
            pending: BTreeMap::new(),
            current_round: None,
            reshare_gen: 0,
            pending_reshare: BTreeMap::new(),
            authority: None,
        }
    }

    /// Configure the **recovery authority** whose signature may authorize a below-threshold re-genesis
    /// ([`rebootstrap`](Self::rebootstrap)). Without it, a cell that falls below threshold freezes permanently
    /// rather than re-key on an unauthenticated request (audit §4).
    #[must_use]
    pub fn with_recovery_authority(mut self, authority: RecoveryAuthoritySet) -> Self {
        self.authority = Some(authority);
        self
    }

    /// The current beacon epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The current public beacon seed (this network's [`genesis`](Self::genesis) until the first round is
    /// adopted).
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// This network's **epoch-0 seed**, as this beacon was provisioned with it — fixed for the node's life,
    /// unlike [`seed`](Self::seed), which advances each round.
    ///
    /// Its purpose is to be compared: the transport seats this node against `Client::genesis()`, and the two
    /// values reaching one node from two independent provisioning paths must be equal or the node is seating
    /// itself in one network's coordinate space while running another's epoch clock. `fanos-quic`'s
    /// `spawn_inner` refuses to start such a node.
    #[must_use]
    pub fn genesis(&self) -> BeaconSeed {
        self.genesis
    }

    /// The current reconstruction threshold `t` — the number of distinct anchor partials a round needs. It
    /// changes when a resharing to a new anchor set is adopted (audit R-C1).
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The resharing generation this node has adopted (0 = the genesis sharing).
    #[must_use]
    pub fn reshare_gen(&self) -> u64 {
        self.reshare_gen
    }

    /// Whether this node currently holds a beacon share (an anchor that contributes partials).
    #[must_use]
    pub fn is_anchor(&self) -> bool {
        self.share.is_some()
    }

    /// Build an **authenticated** resharing-trigger frame for the recovery `authority` to broadcast (audit
    /// R-C1 + §2.1): start generation `generation`, redistributing the beacon key to the `new_indices` holder
    /// set at `new_threshold`, dealt by the named live `contributors` (which must number ≥ the current
    /// threshold). The frame carries the authority's signature over its parameters, so only the holder of the
    /// recovery-authority **secret** — a parent cell or an operator, the same trust root that issues a
    /// re-genesis certificate — can trigger a reshare; a node cannot self-issue one (an unauthenticated
    /// trigger was the §2.1 2-coalition key-exfiltration oracle). The trigger self-floods (monotone) with its
    /// signatures, so it need only reach one live anchor.
    ///
    /// `authority` is `(member index, secret)` for each signing member of the committee, and a **quorum**
    /// must be present or every anchor refuses the frame. Duplicate indices are dropped rather than counted,
    /// which is the same rule [`RecoveryAuthorization::sign`] enforces and for the same reason: a quorum
    /// filled by one key is not a quorum.
    #[must_use]
    pub fn reshare_trigger(
        authority: &[(u8, &HybridSigSecret)],
        generation: u64,
        new_threshold: usize,
        contributors: &[u8],
        new_indices: &[u8],
    ) -> Vec<u8> {
        // A roster too large to describe in the frame's one-byte length fields yields **no trigger** rather
        // than a wrapped one: two members reading two different contributor sets from bytes that verify is
        // the one failure this authenticated message exists to prevent (#110). Unreachable at every
        // supported plane order, and present so it cannot become reachable in silence.
        reshare_trigger_frame(authority, generation, new_threshold, contributors, new_indices)
            .unwrap_or_default()
    }

    /// This node's beacon holder index — its Fano point index `+ 1` (the [`VssShare`] convention: the anchor
    /// at point `i` holds share index `i + 1`).expect("a test roster fits the frame"). Used to tell whether this node is a target new holder of a
    /// reshare and to combine its own sub-shares. `0` if the coord is not a plane point (never, for a member).
    fn beacon_index(&self) -> u8 {
        let me = self.coord.coords();
        // `i < self.n`, a plane point index, so `i + 1` is a share index in `1..=n` and fits a byte.
        (0..self.n)
            .find(|&i| Point::<F>::at(i).coords() == me)
            .map_or(0, |i| u8::try_from(i + 1).unwrap_or(u8::MAX))
    }

    /// Whether every entry of `indices` is a valid, distinct holder index: 1-based, `≤ n`, and appearing
    /// at most once. An out-of-range index maps to no real coordinate (and would panic `Point::at`); a
    /// repeated index is not a second independent Lagrange evaluation. (Audit §3.1 hardening.)
    fn distinct_in_range(&self, indices: &[u8]) -> bool {
        let mut seen = BTreeSet::new();
        indices
            .iter()
            .all(|&i| i != 0 && usize::from(i) <= self.n && seen.insert(i))
    }

    /// Broadcast `frame` to every *other* cell member.
    fn broadcast(&self, frame: &[u8]) -> Vec<Effect> {
        let me = self.coord.coords();
        (0..self.n)
            .map(|i| Point::<F>::at(i).coords())
            .filter(|&c| c != me)
            .map(|to| Effect::Send {
                to,
                frame: frame.to_vec(),
            })
            .collect()
    }

    /// Begin producing the next epoch's beacon: an anchor floods its partial and folds it in. A pure
    /// consumer (no share) is inert here — it only adopts rounds others assemble.
    fn advance(&mut self) -> Vec<Effect> {
        let target = self.epoch.next();
        let partial = match &self.share {
            Some(share) => partial_eval(share, target),
            None => return Vec::new(),
        };
        // **Verify your own partial before you put your name on it.** Every partial that reaches the buffer
        // from a peer has passed `verify_partial` in `on_partial`; this one is the sole exception, and it was
        // the one nothing checked. A share that does not match this node's commitment (a stale or swapped
        // file) then costs the cell twice over: the flood makes every peer count an honest node as a forger,
        // and the buffered copy is picked first by `assemble`, so this node's every assembly fails for ever.
        //
        // **Why at the point of use and not once at construction.** The relation is epoch-independent — a
        // mismatched share fails at every epoch — so hoisting the check to `new` would be cheaper and would
        // answer the same question. It is deliberately here instead, because the share is installed at three
        // places (`new`, `install` for a reshare, `rebootstrap`) and a check on the value at the moment it is
        // *used* covers all three, and any fourth, without anyone remembering to add it. The price is one
        // extra DLEQ verification per epoch against the `threshold` this node already runs on arriving
        // partials — under one part in `threshold`, on a clock that ticks in minutes.
        //
        // **And the argument has a second half this comment first left out.** "The point of use" is not one
        // place: the share is used twice — here, through `partial_eval`, and in `deal_reshare`, through
        // `reshare`. Closing only this one left the reshare path flooding a contribution no peer can bind,
        // which is why `deal_reshare` now carries the matching check. Covering every *install* site is not the
        // same claim as covering every *use*, and writing the first while meaning the second is how a fix
        // reads complete while being half of one.
        if !verify_partial(&partial, target, &self.commitment) {
            self.rejects.share_mismatched = self.rejects.share_mismatched.saturating_add(1);
            return vec![Effect::Notify(Notification::Escalated(
                Escalation::BeaconShareMismatch,
            ))];
        }
        let mut effects = self.broadcast(&partial_frame(target, &partial));
        self.buffer(target, partial);
        effects.extend(self.try_assemble(target));
        effects
    }

    /// Fold a verified partial into the pending set for a future `epoch` (deduped by index, bounded).
    fn buffer(&mut self, epoch: Epoch, partial: BeaconPartial) {
        if epoch <= self.epoch {
            return; // a seed for this or a later epoch is already adopted
        }
        let bucket = self.pending.entry(epoch).or_default();
        if bucket.len() >= MAX_PARTIALS || bucket.iter().any(|p| p.index() == partial.index()) {
            return;
        }
        bucket.push(partial);
        // Bound the number of buckets, not only their contents (see `MAX_PENDING_EPOCHS`). The highest epoch
        // goes: adoption is in order, so a far-future bucket cannot assemble until every epoch below it has.
        while self.pending.len() > MAX_PENDING_EPOCHS {
            let Some(&highest) = self.pending.keys().next_back() else { break };
            self.pending.remove(&highest);
            self.rejects.partial_epoch_evicted = self.rejects.partial_epoch_evicted.saturating_add(1);
        }
    }

    /// If `epoch`'s pending partials reach the threshold, assemble + verify the round, adopt its seed,
    /// flood the round to the cell, and announce it.
    fn try_assemble(&mut self, epoch: Epoch) -> Vec<Effect> {
        if epoch <= self.epoch {
            return Vec::new();
        }
        let round = match self.pending.get(&epoch) {
            Some(bucket) => BeaconRound::assemble(epoch, bucket, self.threshold),
            None => None,
        };
        let Some(round) = round else {
            // Not enough partials yet — the ordinary state between the first arrival and the threshold, and
            // deliberately uncounted: it happens on almost every call and would drown the six that matter.
            return Vec::new();
        };
        let Some(seed) = round.verify_and_seed(&self.commitment, self.threshold) else {
            self.rejects.assembly_unverified = self.rejects.assembly_unverified.saturating_add(1);
            return Vec::new();
        };
        self.adopt_and_announce(epoch, seed, round)
    }

    /// A received round: verify it against the group commitment and, if strictly newer, adopt + re-flood.
    fn on_round(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some(round) = BeaconRound::from_bytes(body) else {
            self.rejects.round_malformed = self.rejects.round_malformed.saturating_add(1);
            return Vec::new();
        };
        let epoch = round.epoch();
        if epoch <= self.epoch {
            return Vec::new(); // not newer — drop (terminates the flood)
        }
        let Some(seed) = round.verify_and_seed(&self.commitment, self.threshold) else {
            self.rejects.round_unverified = self.rejects.round_unverified.saturating_add(1);
            return Vec::new();
        };
        self.adopt_and_announce(epoch, seed, round)
    }

    /// A received partial: verify its DLEQ against the group commitment, buffer it, and try to assemble.
    fn on_partial(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some((epoch, partial)) = parse_partial(body) else {
            self.rejects.partial_malformed = self.rejects.partial_malformed.saturating_add(1);
            return Vec::new();
        };
        // **Two decisions, and they used to share one `||`** (#161). A stale epoch is the flood terminating —
        // benign, expected, constant-rate. A failed DLEQ is a forgery or a wrong commitment. Merged into one
        // early return they were not merely uncounted: they were indistinguishable *in principle*, because no
        // counter placed on that branch could have said which had happened.
        if epoch <= self.epoch {
            self.rejects.partial_stale = self.rejects.partial_stale.saturating_add(1);
            return Vec::new();
        }
        if !verify_partial(&partial, epoch, &self.commitment) {
            self.rejects.partial_unverified = self.rejects.partial_unverified.saturating_add(1);
            return Vec::new();
        }
        self.buffer(epoch, partial);
        self.try_assemble(epoch)
    }

    /// Adopt a new epoch + seed (monotone), dropping now-stale pending partials.
    fn adopt(&mut self, epoch: Epoch, seed: [u8; 32]) {
        self.epoch = epoch;
        self.seed = seed;
        self.pending.retain(|&e, _| e > epoch);
    }

    /// Adopt `round`'s epoch + seed, cache the round so this node can answer a later `BeaconReq`, and
    /// announce it (flood to the cell + notify the driver).
    fn adopt_and_announce(
        &mut self,
        epoch: Epoch,
        seed: [u8; 32],
        round: BeaconRound,
    ) -> Vec<Effect> {
        self.adopt(epoch, seed);
        let effects = self.announce(epoch, seed, &round);
        self.current_round = Some(round);
        effects
    }

    /// Flood `round` to the cell and emit the `BeaconReady` notification for the driver.
    fn announce(&self, epoch: Epoch, seed: [u8; 32], round: &BeaconRound) -> Vec<Effect> {
        let mut effects = self.broadcast(&round_frame(round));
        effects.push(Effect::Notify(Notification::BeaconReady { epoch, seed }));
        effects
    }

    /// Answer a joining node's `BeaconReq` pull-sync: send it the current epoch's round (which it verifies
    /// against the group commitment and adopts). Silent until this node has itself adopted a round.
    fn on_beacon_req(&self, from: Triple) -> Vec<Effect> {
        match &self.current_round {
            Some(round) => std::vec![Effect::Send {
                to: from,
                frame: round_frame(round),
            }],
            None => Vec::new(),
        }
    }

    /// Request the current beacon from the cell on join (spec §7.8 bootstrap): broadcast a `BeaconReq`, to
    /// which any synced peer replies with its round — so a node that missed live rounds still adopts the
    /// current epoch's verified seed rather than assuming one.
    fn request_sync(&self) -> Vec<Effect> {
        self.broadcast(&encode(FrameType::BeaconReq, &[]))
    }

    // ---- Verifiable secret redistribution (proactive resharing) — audit R-C1 ---------------------------
    //
    // A coordinator's trigger names the generation, the target new-holder set and threshold, AND the exact
    // (live) old-anchor contributors — so every node combines the *identical* set deterministically, no
    // matter the message timing. Each named contributor floods its public commitment `Dᵢ` and privately
    // sends each new holder `gᵢ(j)`; once all the named contributors' commitments are in, every node derives
    // the same new group commitment `C' = Σ λᵢ(0)·Dᵢ` (the group key is unchanged), and each new holder
    // combines its sub-shares into its new share. A crashed/absent contributor stalls only that generation;
    // the coordinator retries with a fresh generation over the survivors (eventual liveness). Byzantine
    // sub-share equivocation within the named set is the documented residual — handled, as in the DKG, by a
    // complaint/justify round (`DkgComplaint`/`DkgJustify`); this build detects it (the new-share self-check)
    // but does not yet run that round.

    /// Handle a resharing trigger: record the target parameters for `generation`, re-flood it once (monotone, so it
    /// terminates), and — if this node is a named contributor — deal its verifiable contribution.
    fn on_reshare_trigger(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some((generation, new_threshold, contributors, new_indices, sigs)) = parse_reshare_trigger(body)
        else {
            self.rejects.reshare_malformed = self.rejects.reshare_malformed.saturating_add(1);
            return Vec::new();
        };
        // AUTHENTICATION (audit §2.1 — closes the master-key exfiltration oracle). A reshare CHANGES the
        // sharing threshold, so `new_threshold` alone cannot distinguish a legitimate recovery-reshare (which
        // lowers the threshold to a survivor set — a 4-of-7 cell reshares to 3-of-4) from a malicious
        // downgrade. Without authentication a 2-anchor coalition could name `new_threshold = 2` at its own
        // indices, have ≥`t` honest anchors deal sub-shares to it, and reconstruct the beacon master key. The
        // trigger MUST therefore be signed by the beacon's recovery `authority` — the SAME trust root that
        // authorizes re-genesis (`with_recovery_authority`) — so a node can never self-issue one. A cell with
        // no authority configured cannot reshare at all (consistent with re-genesis being disabled without a
        // trust root). A forged/foreign signature is rejected here, before any anchor deals a single sub-share.
        let Some(authority) = self.authority.clone() else {
            // A provisioning gap, not an attack — and counted apart from a forgery for exactly that reason:
            // one is fixed by configuring an authority, the other by finding who is sending triggers.
            self.rejects.reshare_no_authority = self.rejects.reshare_no_authority.saturating_add(1);
            return Vec::new(); // no trust root ⇒ no authenticated reshare is possible
        };
        let Some(params) = reshare_trigger_params(generation, new_threshold, &contributors, &new_indices)
        else {
            self.rejects.reshare_no_authority = self.rejects.reshare_no_authority.saturating_add(1);
            return Vec::new(); // a roster the frame's length fields cannot describe was never signed
        };
        if !authority_quorum_verifies(&authority, &reshare_trigger_signing_message(&params), &sigs) {
            // **The §2.1 attack, counted.** The 2-anchor coalition that could have reconstructed the beacon
            // master key is refused here — and until now, refused in silence, so the attempt left no trace
            // anywhere an operator could look.
            self.rejects.reshare_forged = self.rejects.reshare_forged.saturating_add(1);
            return Vec::new(); // unauthenticated / forged / tampered trigger
        }
        // Defence-in-depth sanity (the authority signature is the real gate). `MIN_RESHARE_THRESHOLD` keeps a
        // reshare off the degenerate degree-0 (raw-share) case even under a careless/compromised authority;
        // every index is validated distinct + `1..=n` so a sub-share is never routed to a foreign coordinate;
        // and the generation is windowed so a far-future trigger cannot evict the live in-progress rounds.
        if generation <= self.reshare_gen
            || generation > self.reshare_gen.saturating_add(MAX_RESHARE_GEN_ADVANCE)
            || new_threshold < MIN_RESHARE_THRESHOLD
            || new_threshold > new_indices.len()
            || contributors.len() < self.threshold
            || !self.distinct_in_range(&contributors)
            || !self.distinct_in_range(&new_indices)
        {
            return Vec::new(); // stale, out-of-window, key-unsafe, or nonsensical / under-provisioned
        }
        self.prune_reshare_gens(generation);
        if self.pending_reshare.get(&generation).and_then(|r| r.new_threshold).is_some() {
            return Vec::new(); // already have this trigger — do not re-flood or re-deal
        }
        // Re-flood the identical AUTHENTICATED frame (monotone) — the signature travels with it, so every
        // downstream anchor verifies the authority exactly as we just did.
        let reflood = encode(FrameType::BeaconReshareTrigger, body);
        {
            let round = self.pending_reshare.entry(generation).or_default();
            round.new_threshold = Some(new_threshold);
            round.contributors = contributors;
            round.new_indices = new_indices;
        }
        let mut effects = self.broadcast(&reflood);
        effects.extend(self.deal_reshare(generation));
        effects.extend(self.try_reshare(generation));
        effects
    }

    /// If this node is a named contributor that has not yet dealt for `generation`, produce its verifiable
    /// contribution — a fresh polynomial `gᵢ` with `gᵢ(0)` = its share — flood the public commitment, and
    /// privately send each new holder its sub-share. Records its own commitment/sub-share (broadcasts skip self).
    fn deal_reshare(&mut self, generation: u64) -> Vec<Effect> {
        let Some(share) = self.share.clone() else {
            return Vec::new();
        };
        let old_index = share.index();
        let (new_threshold, new_indices) = {
            let Some(round) = self.pending_reshare.get(&generation) else {
                return Vec::new();
            };
            if round.dealt || !round.contributors.contains(&old_index) {
                return Vec::new();
            }
            match round.new_threshold {
                Some(t) => (t, round.new_indices.clone()),
                None => return Vec::new(),
            }
        };
        // Deterministic per (share, generation): reproducible on a re-flood, never reusing a polynomial across
        // generations, and sans-I/O (no entropy port) — the same discipline as the DLEQ nonce. A production
        // anchor MAY instead deal from OS entropy.
        let mut rng = reshare_rng(&share, generation);
        let Some(dealing) = reshare(&share, new_threshold, &new_indices, &mut rng) else {
            return Vec::new();
        };
        // **The check `on_reshare_commit` runs on a peer's contribution, run on our own.** This is the second
        // member of the class `advance` opened, found by walking the class after the first was closed — and
        // finding it corrected the first fix's own reasoning, which claimed a check at the point of use covers
        // every install site. It covers every *install* site and only one of the two *uses*: `partial_eval`
        // here, `reshare` there.
        //
        // A share that does not match the group commitment produces a dealing binding to nothing: every peer
        // refuses it at `verify_reshare_commit`, and recording it here would leave this generation's
        // `pending_reshare` holding a commitment that can never complete — the same poisoning an unverified
        // partial did to the beacon's bucket.
        //
        // `dealt` is deliberately still false when this fires, and the reason is exact rather than hopeful.
        // `deal_reshare` has one caller, so refusing does not by itself schedule a retry — but the trigger is
        // re-flooded by every peer that accepts it, and `on_reshare_trigger`'s guard is `generation <=
        // self.reshare_gen`, the generation this node has ADOPTED. A generation still in progress is therefore
        // not stale, so a re-flood reaches here again. Leaving `dealt` false is what lets that second arrival
        // deal for real once the share is corrected; marking it would close the door for the whole generation.
        if !verify_reshare_commit(old_index, dealing.commitment(), &self.commitment) {
            self.rejects.share_mismatched = self.rejects.share_mismatched.saturating_add(1);
            return vec![Effect::Notify(Notification::Escalated(
                Escalation::BeaconShareMismatch,
            ))];
        }
        if let Some(round) = self.pending_reshare.get_mut(&generation) {
            round.dealt = true;
        }
        self.record_commit(generation, old_index, dealing.commitment().clone());
        if let Some(mine) = dealing.subshare_for(self.beacon_index()) {
            self.record_subshare(generation, old_index, mine.clone());
        }
        let mut effects = self.broadcast(&reshare_commit_frame(generation, old_index, new_threshold, dealing.commitment()));
        let me = self.coord.coords();
        for &j in &new_indices {
            let to = Point::<F>::at(usize::from(j.saturating_sub(1))).coords();
            if to == me {
                continue; // recorded locally above; the broadcast/targeted send skips self
            }
            if let Some(sub) = dealing.subshare_for(j) {
                effects.push(Effect::Send { to, frame: reshare_share_frame(generation, old_index, sub) });
            }
        }
        effects
    }

    /// A received public resharing commitment `Dᵢ`: verify it binds to old holder `old_index`'s real share
    /// (against the CURRENT commitment), store it, and try to complete the generation.
    fn on_reshare_commit(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some((generation, old_index, new_threshold, commit)) = parse_reshare_commit(body) else {
            return Vec::new();
        };
        if generation <= self.reshare_gen || old_index == 0 || commit.threshold() != new_threshold {
            return Vec::new();
        }
        if !verify_reshare_commit(old_index, &commit, &self.commitment) {
            return Vec::new(); // does not bind to the real old share — a wrong-secret contribution
        }
        self.prune_reshare_gens(generation);
        self.record_commit(generation, old_index, commit);
        self.try_reshare(generation)
    }

    /// A received private resharing sub-share `gᵢ(my_index)`: buffer it (verified against its commitment at
    /// completion), and try to complete the generation.
    fn on_reshare_share(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some((generation, old_index, subshare)) = parse_reshare_share(body) else {
            return Vec::new();
        };
        if generation <= self.reshare_gen || old_index == 0 || subshare.index() != self.beacon_index() {
            return Vec::new(); // not addressed to this node, or stale
        }
        self.prune_reshare_gens(generation);
        self.record_subshare(generation, old_index, subshare);
        self.try_reshare(generation)
    }

    /// Store a binding-valid commitment for a generation (bounded and deduped by old index).
    fn record_commit(&mut self, generation: u64, old_index: u8, commit: VssCommitment) {
        if old_index == 0 || usize::from(old_index) > self.n {
            return;
        }
        self.pending_reshare.entry(generation).or_default().commits.entry(old_index).or_insert(commit);
    }

    /// Store this node's sub-share from a contributor for a generation (bounded and deduped by old index).
    fn record_subshare(&mut self, generation: u64, old_index: u8, subshare: VssShare) {
        if old_index == 0 || usize::from(old_index) > self.n {
            return;
        }
        self.pending_reshare.entry(generation).or_default().subshares.entry(old_index).or_insert(subshare);
    }

    /// Complete resharing generation `generation` once **every named contributor's** commitment has validated:
    /// derive the new group commitment from public data, and — if this node is a target new holder — its new
    /// share from the sub-shares, then adopt the redistributed sharing. No effect until the set is complete.
    fn try_reshare(&mut self, generation: u64) -> Vec<Effect> {
        let adopt = {
            let Some(round) = self.pending_reshare.get(&generation) else {
                return Vec::new();
            };
            let Some(new_threshold) = round.new_threshold else {
                return Vec::new();
            };
            // Wait until the identical, trigger-named contributor set is fully present (deterministic agreement).
            if round.contributors.is_empty()
                || !round.contributors.iter().all(|c| round.commits.contains_key(c))
            {
                return Vec::new();
            }
            let commit_contribs: Vec<(u8, &VssCommitment)> = round
                .contributors
                .iter()
                .filter_map(|&i| round.commits.get(&i).map(|c| (i, c)))
                .collect();
            let Some(new_commitment) = combine_reshare_commitment(&commit_contribs) else {
                return Vec::new();
            };
            // A target new holder derives its share, but only once every contributor's sub-share is present
            // AND Feldman-valid, and the combined share self-checks against the new commitment.
            let my_index = self.beacon_index();
            let new_share = if round.new_indices.contains(&my_index) {
                let mut subs: Vec<(u8, &VssShare)> = Vec::with_capacity(round.contributors.len());
                for &i in &round.contributors {
                    match (round.commits.get(&i), round.subshares.get(&i)) {
                        (Some(commit), Some(sub)) if verify_share(sub, commit) => subs.push((i, sub)),
                        _ => return Vec::new(), // still waiting for a valid sub-share from contributor i
                    }
                }
                match combine_reshare_share(my_index, &subs) {
                    Some(s) if verify_share(&s, &new_commitment) => Some(s),
                    _ => return Vec::new(), // self-check failed (sub-share poisoning) — await a retry/justify
                }
            } else {
                None
            };
            (new_threshold, new_commitment, new_share)
        };
        let (new_threshold, new_commitment, new_share) = adopt;
        self.adopt_reshare(generation, new_threshold, new_commitment, new_share);
        Vec::new()
    }

    /// Adopt a completed resharing: install the new commitment, threshold, share, and generation, and drop
    /// buffered partials (they were verified under the old commitment) and superseded reshare state.
    fn adopt_reshare(
        &mut self,
        generation: u64,
        new_threshold: usize,
        new_commitment: VssCommitment,
        new_share: Option<VssShare>,
    ) {
        self.reshare_gen = generation;
        self.threshold = new_threshold;
        self.commitment = new_commitment;
        self.share = new_share;
        self.pending.clear();
        self.pending_reshare.retain(|&g, _| g > generation);
    }

    /// The cell's current **lineage fingerprint** — `H(generation ‖ group-commitment)` — the provenance an
    /// `RGC` binds to (its `anchor`). Every honest member of the same cell at the same generation computes the
    /// same value; a different cell (different commitment) or an already-advanced generation computes a
    /// different one, so an authorization cannot be replayed across cells or re-applied after the fact.
    #[must_use]
    pub fn lineage_anchor(&self) -> [u8; 32] {
        let commitment = self.commitment.to_bytes();
        let mut buf = Vec::with_capacity(8 + commitment.len());
        buf.extend_from_slice(&self.reshare_gen.to_le_bytes());
        buf.extend_from_slice(&commitment);
        hash_labeled(LINEAGE_LABEL, &buf)
    }

    /// **Below-threshold re-genesis** (audit §4, `docs/design-recovery.md`): install a fresh DVRF key produced by
    /// a survivor DKG, resuming the frozen epoch clock at `auth.epoch_fence`. Returns `false` (no change) unless
    /// every guard holds:
    /// 1. a recovery [`authority`](Self::with_recovery_authority) is configured and `auth` verifies under it —
    ///    the single-writer authorization that makes exactly one re-genesis canonical;
    /// 2. `auth.generation > reshare_gen` — the monotonic fence: a stale/replayed authorization is refused, so a
    ///    returning partitioned group is subordinated (its old-generation rounds fail against the new
    ///    commitment), never forked;
    /// 3. `auth.anchor == lineage_anchor()` — the authorization was issued for THIS cell at THIS generation;
    /// 4. `auth.epoch_fence > epoch` — the resumed clock only moves forward;
    /// 5. `new_commitment.threshold() == auth.threshold` — the DKG produced exactly the authorized threshold;
    /// 6. `auth.survivors` is **below this cell's threshold** — the certificate must describe a cell that
    ///    genuinely cannot reshare, which is the only situation re-genesis is the right answer to.
    ///
    /// The fresh key has no continuity with the lost one (it is information-theoretically gone); the `RGC` plus
    /// this commitment ARE the new lineage. `new_share` is this node's share from the survivor DKG — `None` for a
    /// pure consumer, which then adopts the resumed rounds without contributing partials.
    ///
    /// # The obligation this engine cannot discharge
    ///
    /// Guard 6 is what the *certificate* claims about the cell. Whether the cell is **actually** frozen is a
    /// liveness question, and liveness is not visible to a sans-I/O engine — it lives in the node's
    /// [`StallDetector`](crate::recovery::StallDetector) and its
    /// [`recovery_decision`](crate::recovery::recovery_decision) ladder.
    ///
    /// **So a driver that carries an RGC into a running node MUST additionally require its own confirmed
    /// stall before calling this.** Stated here rather than left to be rediscovered: this function has no
    /// production caller yet, and the neighbouring POROS reshare path was once wired by a driver that omitted
    /// the guard the engine was relying on it to apply. The cheapest moment to write the rule down is while
    /// there is still no caller to break.
    pub fn rebootstrap(
        &mut self,
        auth: &RecoveryAuthorization,
        new_commitment: VssCommitment,
        new_share: Option<VssShare>,
    ) -> bool {
        let Some(authority) = &self.authority else {
            return false; // re-genesis disabled — no configured trust root
        };
        // **The certificate must describe a cell that cannot reshare.** Re-genesis abandons a live key and
        // installs one with no continuity to it, which is the right answer to `< t` surviving shares and the
        // wrong answer to anything else — a reshare preserves the key and is available whenever `≥ t` remain.
        // Without this, an authorization naming a *healthy* survivor set replaced the beacon of a working
        // cell, and since coordinates derive from the beacon that is control over where every node lands.
        //
        // Checked through `recovery_decision`, not by re-deriving `len < t` here, so the acceptance rule and
        // the ladder that decides when to *ask* for re-genesis cannot drift apart — they are the same
        // predicate read from two sides.
        //
        // This is a claim the certificate makes about itself, and it is deliberately the weaker of the two
        // guards: a node's own view of liveness lives above this sans-I/O engine (`StallDetector`), so the
        // driver that eventually carries an RGC must ALSO require its own confirmed stall. That obligation is
        // stated on `rebootstrap`'s doc comment rather than left to be rediscovered, because the neighbouring
        // POROS reshare path shipped a driver without its guard once already.
        if !matches!(
            crate::recovery::recovery_decision(&auth.survivors, self.threshold),
            crate::recovery::RecoveryAction::RequestRegenesis { .. }
        ) {
            return false;
        }
        if !auth.verify(authority)
            || auth.generation <= self.reshare_gen
            || auth.anchor != self.lineage_anchor()
            || auth.epoch_fence <= self.epoch
            || new_commitment.threshold() != usize::from(auth.threshold)
        {
            return false;
        }
        self.reshare_gen = auth.generation;
        self.threshold = usize::from(auth.threshold);
        self.commitment = new_commitment;
        self.share = new_share;
        self.epoch = auth.epoch_fence.saturating_sub(1); // the next AdvanceEpoch targets epoch_fence
        self.seed = [0u8; 32];
        self.pending.clear();
        self.current_round = None;
        self.pending_reshare.retain(|&g, _| g > auth.generation);
        true
    }

    /// Drop irrelevant reshare state (generations `≤` the adopted one) and bound the map size against a flood
    /// of bogus generations, keeping room for `incoming`.
    fn prune_reshare_gens(&mut self, incoming: u64) {
        self.pending_reshare.retain(|&g, _| g > self.reshare_gen);
        while self.pending_reshare.len() >= MAX_RESHARE_GENS && !self.pending_reshare.contains_key(&incoming) {
            let Some(&lowest) = self.pending_reshare.keys().next() else {
                break;
            };
            self.pending_reshare.remove(&lowest);
        }
    }
}

impl<F: Field> Engine for BeaconNode<F> {
    fn step(&mut self, _now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // The epoch-advance trigger (a timer/driver tick): an anchor proposes the next epoch's beacon.
            Input::Command(Command::AdvanceEpoch) => self.advance(),
            // On join, pull the current beacon from the cell (spec §7.8 bootstrap).
            Input::Command(Command::StartHeartbeat) => self.request_sync(),
            Input::Message { from, frame } => {
                let Ok((f, _)) = decode_frame(&frame) else {
                    // **A frame that does not decode at all**, so its type was never read and no handler
                    // ran. Found by a test that flipped a byte of a signed reshare trigger: the corruption
                    // is caught upstream of every security check, and until this counter an attacker
                    // probing the beacon with malformed frames left no trace of any kind.
                    self.rejects.frame_undecodable = self.rejects.frame_undecodable.saturating_add(1);
                    return Vec::new();
                };
                match f.frame_type() {
                    Some(FrameType::BeaconPartial) => self.on_partial(f.body),
                    Some(FrameType::Beacon) => self.on_round(f.body),
                    Some(FrameType::BeaconReq) => self.on_beacon_req(from),
                    Some(FrameType::BeaconReshareTrigger) => self.on_reshare_trigger(f.body),
                    Some(FrameType::BeaconReshareCommit) => self.on_reshare_commit(f.body),
                    Some(FrameType::BeaconReshareShare) => self.on_reshare_share(f.body),
                    // A frame type this build does not handle — version skew, not corruption.
                    _ => Vec::new(),
                }
            }
            _ => Vec::new(),
        }
    }

    fn address(&self) -> Triple {
        self.coord.coords()
    }
}

/// `BeaconPartial` frame body: `epoch(8B BE) ‖ partial`. The epoch travels alongside because a partial
/// is verified against it (its DLEQ binds the epoch), so a replay under a different epoch is rejected.
fn partial_frame(epoch: Epoch, partial: &BeaconPartial) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + PARTIAL_LEN);
    body.extend_from_slice(&epoch.to_be_bytes());
    body.extend_from_slice(&partial.to_bytes());
    encode(FrameType::BeaconPartial, &body)
}

/// `Beacon` frame body: the round's own byte encoding (which already carries the epoch).
fn round_frame(round: &BeaconRound) -> Vec<u8> {
    encode(FrameType::Beacon, &round.to_bytes())
}

fn encode(ty: FrameType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(ty.code(), body, &mut out);
    out
}

fn parse_partial(body: &[u8]) -> Option<(Epoch, BeaconPartial)> {
    let epoch = Epoch::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let partial = BeaconPartial::from_bytes(body.get(8..)?)?;
    Some((epoch, partial))
}

/// A deterministic dealing RNG bound to (share, generation): reproducible on a re-flood and distinct per
/// generation, so an anchor deals its reshare contribution without an entropy port (sans-I/O).
fn reshare_rng(share: &VssShare, generation: u64) -> fanos_vrf::vss::DeterministicRng {
    let mut seed = Vec::with_capacity(32 + 8);
    seed.extend_from_slice(&share.value_bytes());
    seed.extend_from_slice(&generation.to_be_bytes());
    fanos_vrf::vss::DeterministicRng::new(&seed)
}

/// Domain label for the authority signature that authorizes a `BeaconReshareTrigger` (audit §2.1). A reshare
/// **changes the sharing threshold**, so the parameters alone cannot distinguish a legitimate recovery-reshare
/// (which lowers the threshold to a survivor set) from a malicious downgrade — hence the trust root must sign.
const RESHARE_TRIGGER_SIG_LABEL: &[u8] = b"FANOS-v1/beacon-reshare-trigger";

/// The canonical parameter encoding of a reshare trigger — the bytes the authority signs, and the frame's
/// prefix before the trailing signature: `generation(8) ‖ new_threshold(1) ‖ n_contrib(1) ‖ contributors ‖
/// n_new(1) ‖ new_indices`.
fn reshare_trigger_params(generation: u64, new_threshold: usize, contributors: &[u8], new_indices: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(8 + 2 + contributors.len() + 1 + new_indices.len());
    body.extend_from_slice(&generation.to_be_bytes());
    // **Length prefixes refuse rather than wrap.** This body is what the beacon's authority signs, and what
    // every member re-derives to agree on the contributor set — a length that wrapped would let two members
    // read two different sets from bytes that verify, which is the one failure this message exists to
    // prevent. A cell has far fewer than 255 members at every supported plane order, so the refusal is
    // unreachable in practice and present so that it cannot become reachable silently (#110).
    body.push(u8::try_from(new_threshold).ok()?);
    body.push(u8::try_from(contributors.len()).ok()?);
    body.extend_from_slice(contributors);
    body.push(u8::try_from(new_indices.len()).ok()?);
    body.extend_from_slice(new_indices);
    Some(body)
}

/// The message the authority signs and every anchor verifies: `LABEL ‖ params`.
fn reshare_trigger_signing_message(params: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(RESHARE_TRIGGER_SIG_LABEL.len() + params.len());
    m.extend_from_slice(RESHARE_TRIGGER_SIG_LABEL);
    m.extend_from_slice(params);
    m
}

/// `BeaconReshareTrigger` body: `params ‖ HybridSignature`, where the signature is by the beacon's recovery
/// `authority` over `LABEL ‖ params` — so an unauthenticated (forged) trigger is rejected before any anchor
/// deals a sub-share (audit §2.1). The frame self-floods with its signature, so every downstream anchor
/// re-verifies the same authorization.
fn reshare_trigger_frame(authority: &[(u8, &HybridSigSecret)], generation: u64, new_threshold: usize, contributors: &[u8], new_indices: &[u8]) -> Option<Vec<u8>> {
    let params = reshare_trigger_params(generation, new_threshold, contributors, new_indices)?;
    let message = reshare_trigger_signing_message(&params);
    let mut signed: Vec<(u8, HybridSignature)> = Vec::new();
    for (index, sk) in authority {
        if !signed.iter().any(|(i, _)| i == index) {
            signed.push((*index, sk.sign(&message)));
        }
    }
    signed.sort_by_key(|(i, _)| *i);
    let mut body = params;
    body.push(u8::try_from(signed.len()).ok()?);
    for (index, sig) in &signed {
        body.push(*index);
        body.extend_from_slice(&sig.to_bytes());
    }
    Some(encode(FrameType::BeaconReshareTrigger, &body))
}

/// Whether `sigs` is a **quorum of distinct authority members** each signing `message`.
///
/// The same rule `RecoveryAuthorization::verify` applies to a re-genesis certificate, applied to the reshare
/// trigger — because they are the same authorization: audit §2.1 established that a reshare CHANGES the
/// sharing threshold and so must come from the trust root, and a trust root that is one key is one key
/// whichever of the two it signs.
fn authority_quorum_verifies(
    authority: &RecoveryAuthoritySet,
    message: &[u8],
    sigs: &[(u8, HybridSignature)],
) -> bool {
    sigs.len() >= authority.quorum()
        && sigs.is_sorted_by(|(a, _), (b, _)| a < b)
        && sigs.iter().all(|(index, sig)| {
            authority.members().get(usize::from(*index)).is_some_and(|vk| vk.verify(message, sig))
        })
}

/// The parsed fields of an authenticated reshare trigger: `(generation, new_threshold, contributors,
/// new_indices, authority_signature)`.
type ParsedReshareTrigger = (u64, usize, Vec<u8>, Vec<u8>, Vec<(u8, HybridSignature)>);

fn parse_reshare_trigger(body: &[u8]) -> Option<ParsedReshareTrigger> {
    let generation = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let new_threshold = usize::from(*body.get(8)?);
    let n_contrib = usize::from(*body.get(9)?);
    let contributors = body.get(10..10 + n_contrib)?.to_vec();
    let n_new_pos = 10 + n_contrib;
    let n_new = usize::from(*body.get(n_new_pos)?);
    let new_indices_end = n_new_pos + 1 + n_new;
    let new_indices = body.get(n_new_pos + 1..new_indices_end)?.to_vec();
    // The tail is the authority quorum: `count(1) ‖ [index(1) ‖ HybridSignature]…`. The count is bounded
    // by the frame itself — each entry has a fixed width, so an oversized count simply fails to slice — and
    // `from_bytes` requires exactly `HYBRID_SIG_LEN`, so a truncated or padded tail is rejected here rather
    // than producing a short quorum that the caller would then have to notice.
    let n_sigs = usize::from(*body.get(new_indices_end)?);
    let mut sigs = Vec::with_capacity(n_sigs.min(MAX_AUTHORITY_MEMBERS));
    let mut at = new_indices_end + 1;
    for _ in 0..n_sigs {
        let index = *body.get(at)?;
        let sig_end = at + 1 + HYBRID_SIG_LEN;
        sigs.push((index, HybridSignature::from_bytes(body.get(at + 1..sig_end)?)?));
        at = sig_end;
    }
    if at != body.len() {
        return None; // trailing garbage
    }
    Some((generation, new_threshold, contributors, new_indices, sigs))
}

/// `BeaconReshareCommit` body: `generation(8) ‖ old_index(1) ‖ new_threshold(1) ‖ VssCommitment(Dᵢ)`.
fn reshare_commit_frame(generation: u64, old_index: u8, new_threshold: usize, commit: &VssCommitment) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&generation.to_be_bytes());
    body.push(old_index);
    body.push(new_threshold as u8);
    body.extend_from_slice(&commit.to_bytes());
    encode(FrameType::BeaconReshareCommit, &body)
}

fn parse_reshare_commit(body: &[u8]) -> Option<(u64, u8, usize, VssCommitment)> {
    let generation = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let old_index = *body.get(8)?;
    let new_threshold = usize::from(*body.get(9)?);
    let commit = VssCommitment::from_bytes(body.get(10..)?)?;
    Some((generation, old_index, new_threshold, commit))
}

/// `BeaconReshareShare` body: `generation(8) ‖ old_index(1) ‖ VssShare(gᵢ(j), 33)`.
fn reshare_share_frame(generation: u64, old_index: u8, subshare: &VssShare) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + 1 + 33);
    body.extend_from_slice(&generation.to_be_bytes());
    body.push(old_index);
    body.extend_from_slice(&subshare.to_bytes());
    encode(FrameType::BeaconReshareShare, &body)
}

fn parse_reshare_share(body: &[u8]) -> Option<(u64, u8, VssShare)> {
    let generation = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let old_index = *body.get(8)?;
    let subshare = VssShare::from_bytes(body.get(9..)?)?;
    Some((generation, old_index, subshare))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::F2;
    use fanos_vrf::vss::{DeterministicRng, deal};

    const N: usize = 7;

    /// The Fano-point index whose node address is `to`.
    fn node_at(to: Triple) -> Option<usize> {
        (0..N).find(|&k| Point::<F2>::at(k).coords() == to)
    }

    /// Step `Command::AdvanceEpoch` on every node, returning the `(target, frame)` bus of partials they
    /// flood — the start of one epoch's beacon round.
    fn kickoff(nodes: &mut [BeaconNode<F2>]) -> Vec<(usize, Vec<u8>)> {
        let mut bus = Vec::new();
        for node in nodes.iter_mut() {
            for e in node.step(Instant(0), Input::Command(Command::AdvanceEpoch)) {
                if let Effect::Send { to, frame } = e
                    && let Some(k) = node_at(to)
                {
                    bus.push((k, frame));
                }
            }
        }
        bus
    }

    /// Deliver the bus between `nodes` until quiescent, recording every `BeaconReady { epoch, seed }` a
    /// node emitted. Returns those adopted `(coord, epoch, seed)`.
    fn run(
        nodes: &mut [BeaconNode<F2>],
        mut bus: Vec<(usize, Vec<u8>)>,
    ) -> Vec<(Triple, Epoch, [u8; 32])> {
        let mut ready = Vec::new();
        let mut clock = 0u64;
        while !bus.is_empty() {
            let (target, frame) = bus.remove(0);
            clock += 1;
            let coord = nodes[target].address();
            for e in nodes[target].step(
                Instant(clock),
                Input::Message {
                    from: [0, 0, 0],
                    frame,
                },
            ) {
                match e {
                    Effect::Send { to, frame } => {
                        if let Some(k) = node_at(to) {
                            bus.push((k, frame));
                        }
                    }
                    Effect::Notify(Notification::BeaconReady { epoch, seed }) => {
                        ready.push((coord, epoch, seed));
                    }
                    _ => {}
                }
            }
        }
        ready
    }

    #[test]
    fn a_cell_of_beacon_nodes_converges_on_one_epoch_seed() {
        // A t-of-n sharing (stands for a completed DKG). Every node is an anchor; on AdvanceEpoch they
        // flood partials, assemble the round, and ALL adopt the SAME epoch-1 seed — the distributed
        // beacon, no node holding the secret.
        let t = 4usize;
        let (shares, commitment) = deal(
            &[0xBE; 32],
            t,
            N,
            &mut DeterministicRng::new(b"beacon-node-cell"),
        )
        .unwrap();
        let mut nodes: Vec<BeaconNode<F2>> = (0..N)
            .map(|i| BeaconNode::new(Point::at(i), Some(shares[i].clone()), commitment.clone(), t, BeaconSeed::GENESIS))
            .collect();

        // Trigger the next epoch on every anchor, then route their partials + assembled rounds.
        let bus = kickoff(&mut nodes);
        let ready = run(&mut nodes, bus);

        // Every node adopted epoch 1 and the SAME seed, which is the canonical beacon value.
        assert_eq!(ready.len(), N, "every node adopted the beacon");
        let seed0 = ready[0].2;
        assert!(
            ready
                .iter()
                .all(|&(_, e, s)| e == Epoch::new(1) && s == seed0),
            "all nodes adopt epoch 1 with one shared seed"
        );
        assert_ne!(
            seed0, [0u8; 32],
            "the seed is a real beacon value, not genesis"
        );
        for node in &nodes {
            assert_eq!(node.epoch(), Epoch::new(1));
            assert_eq!(node.seed(), seed0);
        }
    }

    #[test]
    fn a_below_threshold_cell_re_genesises_only_under_an_authorized_rgc() {
        use crate::RecoveryAuthorization;
        use fanos_pqcrypto::{HybridSigSecret, SeedRng};
        // Genesis (t=4, n=7) and a configured recovery authority (a parent cell / founder key).
        let t = 4usize;
        let (shares, commitment) = deal(&[0xBE; 32], t, N, &mut DeterministicRng::new(b"regen-genesis")).unwrap();
        let (authority_sk, authority_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"parent-authority"));
        let survivor = || {
            BeaconNode::<F2>::new(Point::at(4), Some(shares[4].clone()), commitment.clone(), t, BeaconSeed::GENESIS)
                .with_recovery_authority(RecoveryAuthoritySet::new(vec![authority_vk.clone()]).unwrap())
        };

        // A fresh survivor DKG — a single trusted deal stands for it, exactly as genesis stands for the DKG: a
        // (t'=2, n) sharing of a brand-new secret, with NO continuity to the lost key.
        let t2 = 2u8;
        let (new_shares, new_commitment) =
            deal(&[0x5E; 32], usize::from(t2), N, &mut DeterministicRng::new(b"regen-fresh")).unwrap();
        let survivors = [5u8, 6, 7]; // holder indices of points {4,5,6}
        let fence = Epoch::new(3);

        // (1) An authorized RGC re-genesises: the fresh key installs, the generation fences forward, the clock is
        // set to resume at the fence, and the anchor produces a partial again (the freeze is lifted).
        let mut node = survivor();
        let rgc = RecoveryAuthorization::issue(&[(0, &authority_sk)], 1, fence, &survivors, t2, node.lineage_anchor());
        assert!(node.rebootstrap(&rgc, new_commitment.clone(), Some(new_shares[4].clone())), "authorized re-genesis adopts");
        assert_eq!(node.reshare_gen(), 1, "generation fenced forward");
        assert_eq!(node.threshold(), 2, "the fresh threshold is installed");
        assert_eq!(node.epoch(), fence.saturating_sub(1), "the clock resumes at the fence on next advance");
        let resumed = node.step(Instant(0), Input::Command(Command::AdvanceEpoch));
        assert!(
            resumed.iter().any(|e| matches!(e, Effect::Send { .. })),
            "the re-genesised anchor floods a fresh partial — the clock is un-frozen"
        );

        // (2) A foreign authority is refused (no fork on an unauthorized say-so).
        let mut n = survivor();
        let (impostor_sk, _) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"impostor"));
        let forged = RecoveryAuthorization::issue(&[(0, &impostor_sk)], 1, fence, &survivors, t2, n.lineage_anchor());
        assert!(!n.rebootstrap(&forged, new_commitment.clone(), Some(new_shares[4].clone())), "a foreign authority is refused");

        // (3) An authorization anchored to a different cell/generation is refused (no cross-cell replay).
        let wrong_anchor = RecoveryAuthorization::issue(&[(0, &authority_sk)], 1, fence, &survivors, t2, [0xAA; 32]);
        assert!(!n.rebootstrap(&wrong_anchor, new_commitment.clone(), Some(new_shares[4].clone())), "a foreign anchor is refused");

        // (4) A non-advancing fence is refused (the clock never runs backward).
        let backward = RecoveryAuthorization::issue(&[(0, &authority_sk)], 1, n.epoch(), &survivors, t2, n.lineage_anchor());
        assert!(!n.rebootstrap(&backward, new_commitment.clone(), Some(new_shares[4].clone())), "a non-advancing fence is refused");

        // (5) After a valid adoption, a stale (≤ current) generation is refused — the monotonic fence that makes
        // a returning partition subordinate, not forking.
        assert!(n.rebootstrap(
            &RecoveryAuthorization::issue(&[(0, &authority_sk)], 1, fence, &survivors, t2, n.lineage_anchor()),
            new_commitment.clone(),
            Some(new_shares[4].clone()),
        ));
        let stale = RecoveryAuthorization::issue(&[(0, &authority_sk)], 1, Epoch::new(9), &survivors, t2, n.lineage_anchor());
        assert!(!n.rebootstrap(&stale, new_commitment, Some(new_shares[4].clone())), "a stale generation is refused");
    }

    /// **A re-genesis certificate for a cell that is not below threshold is refused.**
    ///
    /// Re-genesis exists for one situation: `< t` shares survive, so the key is information-theoretically
    /// gone and no reshare can recover it. Every other case has a *reshare*, which preserves the key. Before
    /// this guard, `rebootstrap` checked the authority, the fence, the anchor and the generation — and not
    /// whether there was anything to recover. An authorization naming a healthy survivor set therefore
    /// replaced a working cell's beacon, and since coordinates derive from the beacon
    /// (`docs/design-governance.md` §2.1) that is control over where every node in the cell lands.
    ///
    /// It matters more than it looks because `rebootstrap` has **no production caller**: the R-C1 freeze exit
    /// is engine-complete and unwired, so this guard is being written while there is still nothing to break —
    /// which is the opposite of how the neighbouring POROS reshare path acquired its driver.
    #[test]
    fn re_genesis_is_refused_while_the_cell_can_still_reshare() {
        use crate::RecoveryAuthorization;
        use fanos_pqcrypto::{HybridSigSecret, SeedRng};

        let t = 4usize;
        let (shares, commitment) = deal(&[0xBE; 32], t, N, &mut DeterministicRng::new(b"healthy-genesis")).unwrap();
        let (authority_sk, authority_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"authority"));
        let mut node = BeaconNode::<F2>::new(Point::at(4), Some(shares[4].clone()), commitment.clone(), t, BeaconSeed::GENESIS)
            .with_recovery_authority(RecoveryAuthoritySet::new(vec![authority_vk]).unwrap());

        let t2 = 2u8;
        let (new_shares, new_commitment) =
            deal(&[0x5E; 32], usize::from(t2), N, &mut DeterministicRng::new(b"healthy-fresh")).unwrap();
        let fence = Epoch::new(3);

        // THE PROPERTY. Every other guard passes — genuine authority, this cell's anchor, an advancing fence,
        // a fresh generation, a matching threshold — so nothing but the survivor count can refuse this.
        for healthy in [N, t + 1, t] {
            let survivors: Vec<u8> = (1..=healthy as u8).collect();
            let rgc = RecoveryAuthorization::issue(&[(0, &authority_sk)], 1, fence, &survivors, t2, node.lineage_anchor());
            assert!(
                !node.rebootstrap(&rgc, new_commitment.clone(), Some(new_shares[4].clone())),
                "{healthy} survivors at threshold {t} can still RESHARE, so re-genesis — which abandons the \
                 key — must be refused; accepting it lets an authority re-key a working cell and thereby \
                 choose where every node lands"
            );
            assert_eq!(node.threshold(), t, "and nothing was installed");
            assert_eq!(node.reshare_gen(), 0, "and the generation did not advance");
        }

        // THE MECHANISM, so the test cannot pass by refusing everything: one fewer survivor than the
        // threshold is exactly the case re-genesis is for, and it is accepted.
        let survivors: Vec<u8> = (1..=(t - 1) as u8).collect();
        let rgc = RecoveryAuthorization::issue(&[(0, &authority_sk)], 1, fence, &survivors, t2, node.lineage_anchor());
        assert!(
            node.rebootstrap(&rgc, new_commitment, Some(new_shares[4].clone())),
            "{} survivors at threshold {t} cannot reshare — this is the case re-genesis exists for",
            t - 1
        );
    }

    /// Step `AdvanceEpoch` on only the nodes at `which` (the survivors), returning their flooded-partial bus —
    /// the others are "lost" and never step, modelling an instantaneous mass crash.
    fn kickoff_some(nodes: &mut [BeaconNode<F2>], which: &[usize]) -> Vec<(usize, Vec<u8>)> {
        let mut bus = Vec::new();
        for &p in which {
            for e in nodes[p].step(Instant(0), Input::Command(Command::AdvanceEpoch)) {
                if let Effect::Send { to, frame } = e
                    && let Some(k) = node_at(to)
                {
                    bus.push((k, frame));
                }
            }
        }
        bus
    }

    #[test]
    fn a_survivor_set_resumes_the_frozen_clock_after_re_genesis() {
        use crate::RecoveryAuthorization;
        use fanos_pqcrypto::{HybridSigSecret, SeedRng};
        // Genesis t=4, n=7, recovery authority configured; survivors = points {4,5,6} (3 < t → the cliff).
        let t = 4usize;
        let (shares, commitment) = deal(&[0xBE; 32], t, N, &mut DeterministicRng::new(b"resume-genesis")).unwrap();
        let (authority_sk, authority_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"parent-cell"));
        let mut nodes: Vec<BeaconNode<F2>> = (0..N)
            .map(|i| {
                BeaconNode::new(Point::at(i), Some(shares[i].clone()), commitment.clone(), t, BeaconSeed::GENESIS)
                    .with_recovery_authority(RecoveryAuthoritySet::new(vec![authority_vk.clone()]).unwrap())
            })
            .collect();
        let survivors_pts = [4usize, 5, 6];

        // (1) Frozen: only 3 < t=4 survivors flood, so no round ever assembles — the R-C1 cliff.
        let bus = kickoff_some(&mut nodes, &survivors_pts);
        let frozen = run(&mut nodes, bus);
        assert!(frozen.is_empty(), "below threshold the epoch clock is frozen — no beacon assembles");

        // (2) A fresh survivor DKG (a trusted deal stands in, as genesis does) + an authorized RGC fenced at 3.
        let t2 = 2u8;
        let (new_shares, new_commitment) =
            deal(&[0x5E; 32], usize::from(t2), N, &mut DeterministicRng::new(b"resume-fresh")).unwrap();
        let fence = Epoch::new(3);
        let rgc = RecoveryAuthorization::issue(&[(0, &authority_sk)], 1, fence, &[5, 6, 7], t2, nodes[4].lineage_anchor());
        for &p in &survivors_pts {
            assert!(nodes[p].rebootstrap(&rgc, new_commitment.clone(), Some(new_shares[p].clone())), "survivor re-genesises");
        }

        // (3) Resumed: the 3 survivors now assemble a round at the fence — the clock ticks again, on one fresh
        // seed, under the new key (the old-key nodes' stale partials fail against the new commitment).
        let bus = kickoff_some(&mut nodes, &survivors_pts);
        let resumed = run(&mut nodes, bus);
        assert!(!resumed.is_empty(), "the re-genesised survivors resume the beacon clock");
        assert!(resumed.iter().all(|&(_, e, _)| e == fence), "at the fenced epoch");
        let seed = resumed[0].2;
        assert!(resumed.iter().all(|&(_, _, s)| s == seed), "converging on one fresh seed");
        assert_ne!(seed, [0u8; 32], "a real beacon value under the fresh key");
    }

    #[test]
    fn a_pure_consumer_adopts_the_flooded_round() {
        // A node with no share never produces a partial, but adopts the round the anchors flood — so a
        // client/relay that is not a beacon anchor still learns each epoch's verified seed.
        let t = 4usize;
        let (shares, commitment) = deal(
            &[0xC0; 32],
            t,
            N,
            &mut DeterministicRng::new(b"beacon-consumer"),
        )
        .unwrap();
        // Node 6 is a pure consumer (no share); nodes 0..6 are anchors.
        let mut nodes: Vec<BeaconNode<F2>> = (0..N)
            .map(|i| {
                BeaconNode::new(
                    Point::at(i),
                    (i < 6).then_some(shares[i].clone()),
                    commitment.clone(),
                    t,
                                    BeaconSeed::GENESIS,
                )
            })
            .collect();
        let bus = kickoff(&mut nodes);
        run(&mut nodes, bus);
        // The consumer (node 6) adopted the same seed as an anchor (node 0).
        assert_eq!(nodes[6].epoch(), Epoch::new(1));
        assert_eq!(nodes[6].seed(), nodes[0].seed());
        assert_ne!(nodes[6].seed(), [0u8; 32]);
    }

    #[test]
    fn a_forged_partial_is_refused_at_the_arrival_gate_and_its_honest_twin_is_adopted() {
        // With t = 1 a single valid partial would form the beacon; a forged one (failing its DLEQ) must
        // not — so a Byzantine anchor cannot inject a bogus contribution.
        //
        // **This test used to assert only that the effects were empty, and that was not enough.** Removing
        // the DLEQ gate in `on_partial` left it green, because `try_assemble` verifies the assembled round
        // as well: two gates in series, and emptiness cannot say which refused. It now names the gate by its
        // counter, and pairs the forgery with its uncorrupted twin — without the twin, "no effects" is also
        // what a scenario that could never have adopted anything looks like.
        let (shares, commitment) = deal(
            &[0xF0; 32],
            1,
            N,
            &mut DeterministicRng::new(b"beacon-forge"),
        )
        .unwrap();
        let mut node =
            BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment, 1, BeaconSeed::GENESIS);

        // A valid partial from anchor 2 (index 3), with a flipped response byte.
        let honest = partial_eval(&shares[2], Epoch::new(1));
        let mut bytes = honest.to_bytes();
        bytes[65] ^= 0x01;
        // A non-canonical corruption would be refused at *decode* — also a rejection, but a different one, and
        // it would skip everything below. Requiring `Some` keeps the test on the DLEQ path it is named for.
        let forged = BeaconPartial::from_bytes(&bytes)
            .expect("the flipped response byte must stay canonical, or this test measures the decoder instead");

        let effects = node.step(
            Instant(1),
            Input::Message {
                from: [9, 9, 9],
                frame: partial_frame(Epoch::new(1), &forged),
            },
        );
        assert!(effects.is_empty(), "a forged partial (t=1) yields no beacon");
        assert_eq!(
            node.rejects().partial_unverified,
            1,
            "and it is refused at the ARRIVAL gate — its DLEQ fails against the group commitment"
        );
        assert_eq!(
            node.rejects().assembly_unverified,
            0,
            "so it never entered the buffer, and the assembly gate behind it never had to see it"
        );
        assert_eq!(node.epoch(), Epoch::ZERO, "the node stays at genesis");

        // The twin: same node, same anchor, same epoch, one byte less corruption. It MUST adopt — otherwise
        // the emptiness above is emptiness for a reason that has nothing to do with the forgery.
        let effects = node.step(
            Instant(2),
            Input::Message {
                from: [9, 9, 9],
                frame: partial_frame(Epoch::new(1), &honest),
            },
        );
        assert!(!effects.is_empty(), "the uncorrupted partial forms the round at t = 1");
        assert_eq!(node.epoch(), Epoch::new(1), "and the node adopts the epoch it refused a moment ago");
    }

    /// **The steady state counts, and a stale re-flood is not a forgery** (#161).
    ///
    /// The five original counters covered the reshare trigger — rare and operator-initiated — while the
    /// partial/round flood, which is what the beacon does every epoch for ever, had none. The sharpest part
    /// was one early return carrying two decisions: `epoch <= self.epoch || !verify_partial(…)`. A stale
    /// re-flood is *how the flood terminates* and is expected at a constant rate; a failed DLEQ is a forgery
    /// or a wrong commitment. Merged, no counter placed there could have said which happened.
    ///
    /// Both directions for each, because a counter asserted only at zero is indistinguishable from a field
    /// that is always zero — which is exactly what `deal_rejected` turned out to be.
    #[test]
    fn the_beacons_steady_state_tells_a_stale_reflood_from_a_forgery() {
        let (shares, commitment) =
            deal(&[0xA7; 32], 1, N, &mut DeterministicRng::new(b"beacon-steady")).unwrap();
        let mk = || {
            BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment.clone(), 1, BeaconSeed::GENESIS)
        };
        let send = |node: &mut BeaconNode<F2>, frame: Vec<u8>| {
            node.step(Instant(1), Input::Message { from: [9, 9, 9], frame })
        };

        // Quiet to begin with, or every assertion below is satisfied by a struct of zeros.
        let base = mk();
        let r = base.rejects();
        assert_eq!(
            (r.partial_stale, r.partial_unverified, r.partial_malformed, r.round_malformed, r.round_unverified),
            (0, 0, 0, 0, 0),
            "a fresh beacon node has refused nothing",
        );

        // 1. A malformed partial BODY inside a well-formed frame. Truncating the *frame* instead would be
        //    caught upstream by `frame_undecodable` and never reach `on_partial` at all — the first draft of
        //    this test did exactly that and read 0, which is the counter being right and the test being wrong.
        let mut node = mk();
        send(&mut node, encode(FrameType::BeaconPartial, &[0xEE; 3]));
        assert_eq!(node.rejects().partial_malformed, 1, "a body that does not parse is counted");
        assert_eq!(node.rejects().frame_undecodable, 0, "…by the handler, not by the upstream frame decoder");

        // 2. A **stale** partial — epoch 0, already adopted. Benign; the flood's own terminator.
        let mut node = mk();
        send(&mut node, partial_frame(Epoch::ZERO, &partial_eval(&shares[2], Epoch::ZERO)));
        let r = node.rejects();
        assert_eq!(r.partial_stale, 1, "a re-flood of an adopted epoch is counted as stale");
        assert_eq!(r.partial_unverified, 0, "…and NOT as a forgery — that is the whole point of the split");

        // 3. A **forged** partial: canonical bytes, flipped response, so it parses and fails its DLEQ.
        let mut node = mk();
        let mut bytes = partial_eval(&shares[2], Epoch::new(1)).to_bytes();
        bytes[65] ^= 0x01;
        if let Some(forged) = BeaconPartial::from_bytes(&bytes) {
            send(&mut node, partial_frame(Epoch::new(1), &forged));
            let r = node.rejects();
            assert_eq!(r.partial_unverified, 1, "a partial whose DLEQ fails is counted as unverified");
            assert_eq!(r.partial_stale, 0, "…and NOT as a stale re-flood");
        }

        // 4. A malformed round body.
        let mut node = mk();
        send(&mut node, encode(FrameType::Beacon, &[0xEE; 3]));
        assert_eq!(node.rejects().round_malformed, 1, "a round body that does not parse is counted");

        // 5. And the honest path leaves every one of them at zero — the direction that makes the four above
        //    evidence rather than noise.
        let mut node = mk();
        send(&mut node, partial_frame(Epoch::new(1), &partial_eval(&shares[2], Epoch::new(1))));
        let r = node.rejects();
        assert_eq!(
            (r.partial_stale, r.partial_unverified, r.partial_malformed, r.round_malformed, r.round_unverified, r.assembly_unverified),
            (0, 0, 0, 0, 0, 0),
            "a valid partial refuses nothing",
        );
        assert_eq!(node.epoch(), Epoch::new(1), "and at t = 1 it forms the round");
    }

    #[test]
    fn a_joining_node_pull_syncs_the_current_beacon() {
        // A node that missed the live round adopts the current epoch by asking a synced peer (BeaconReq),
        // rather than assuming an epoch — the bootstrap path (spec §7.8).
        let t = 4usize;
        let (shares, commitment) = deal(
            &[0x5C; 32],
            t,
            N,
            &mut DeterministicRng::new(b"beacon-sync"),
        )
        .unwrap();

        // A synced anchor: it proposes epoch 1 (its own partial) and receives the rest, so it adopts and
        // caches the round.
        let mut synced =
            BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment.clone(), t, BeaconSeed::GENESIS);
        synced.step(Instant(0), Input::Command(Command::AdvanceEpoch));
        for share in &shares[1..t] {
            let p = partial_eval(share, Epoch::new(1));
            synced.step(
                Instant(0),
                Input::Message {
                    from: [0, 0, 0],
                    frame: partial_frame(Epoch::new(1), &p),
                },
            );
        }
        assert_eq!(synced.epoch(), Epoch::new(1), "the anchor adopted epoch 1");

        // A fresh consumer that saw none of it.
        let mut fresh = BeaconNode::<F2>::new(Point::at(1), None, commitment, t, BeaconSeed::GENESIS);
        assert_eq!(fresh.epoch(), Epoch::ZERO);

        // On join it broadcasts a BeaconReq; the synced peer answers with its round; the fresh node
        // verifies and adopts — reaching epoch 1 with the identical seed, no trust in the peer.
        let req_frame = fresh
            .step(Instant(1), Input::Command(Command::StartHeartbeat))
            .into_iter()
            .find_map(|e| match e {
                Effect::Send { frame, .. } => Some(frame),
                _ => None,
            })
            .expect("join broadcasts a BeaconReq");
        let round_frame = synced
            .step(
                Instant(2),
                Input::Message {
                    from: Point::<F2>::at(1).coords(),
                    frame: req_frame,
                },
            )
            .into_iter()
            .find_map(|e| match e {
                Effect::Send { frame, .. } => Some(frame),
                _ => None,
            })
            .expect("a synced peer answers the BeaconReq with its round");
        fresh.step(
            Instant(3),
            Input::Message {
                from: Point::<F2>::at(0).coords(),
                frame: round_frame,
            },
        );
        assert_eq!(
            fresh.epoch(),
            Epoch::new(1),
            "the joining node synced to epoch 1"
        );
        assert_eq!(
            fresh.seed(),
            synced.seed(),
            "and adopted the identical verified seed"
        );
    }

    /// Route a bus of `(target, frame)` messages to quiescence, delivering to live nodes only and returning
    /// every `BeaconReady { epoch, seed }` emitted — a uniform router for partials, rounds, and reshare frames.
    fn route(
        nodes: &mut [BeaconNode<F2>],
        initial: Vec<(usize, Vec<u8>)>,
        dead: &[usize],
    ) -> Vec<(Epoch, [u8; 32])> {
        let mut bus = initial;
        let mut seeds = Vec::new();
        let mut clock = 0u64;
        while !bus.is_empty() {
            let (target, frame) = bus.remove(0);
            if dead.contains(&target) {
                continue;
            }
            clock += 1;
            for e in nodes[target].step(Instant(clock), Input::Message { from: [0, 0, 0], frame }) {
                match e {
                    Effect::Send { to, frame } => {
                        if let Some(k) = node_at(to) {
                            bus.push((k, frame));
                        }
                    }
                    Effect::Notify(Notification::BeaconReady { epoch, seed }) => seeds.push((epoch, seed)),
                    _ => {}
                }
            }
        }
        seeds
    }

    #[test]
    fn a_reshare_moves_the_beacon_to_a_survivor_set_with_a_continuous_seed() {
        // Audit R-C1: a 4-of-7 beacon reshares to the 4 survivors {points 3,4,5,6} at a new threshold t'=3,
        // BEFORE the original set is decimated below t. The survivors then run the clock past the original
        // n−t+1 cliff, and the reshared beacon is the SAME DVRF value (the group key is unchanged).
        use fanos_pqcrypto::{HybridSigSecret, SeedRng};
        use fanos_vrf::beacon::combine;
        let t = 4usize;
        let (shares, commitment) =
            deal(&[0xBE; 32], t, N, &mut DeterministicRng::new(b"reshare-cell")).unwrap();
        // The recovery authority (a parent cell / operator) that must authorize the reshare (§2.1).
        let (authority_sk, authority_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"reshare-authority"));
        let mut nodes: Vec<BeaconNode<F2>> = (0..N)
            .map(|i| {
                BeaconNode::new(Point::at(i), Some(shares[i].clone()), commitment.clone(), t, BeaconSeed::GENESIS)
                    .with_recovery_authority(RecoveryAuthoritySet::new(vec![authority_vk.clone()]).unwrap())
            })
            .collect();

        // Genesis epoch 1 across all 7 anchors.
        let bus = kickoff(&mut nodes);
        run(&mut nodes, bus);
        assert!(nodes.iter().all(|nd| nd.epoch() == Epoch::new(1)));

        // Independent oracle: the true epoch-2 seed is H(x·M(2)) from the ORIGINAL secret x.
        let expected_epoch2 = combine(
            &shares.iter().map(|s| partial_eval(s, Epoch::new(2))).collect::<Vec<_>>(),
            t,
        )
        .unwrap()
        .seed(Epoch::new(2));

        // Reshare generation 1: contributors and new holders are the 4 survivors' indices {4,5,6,7} (points
        // 3..6); new threshold t'=3. A coordinator broadcasts the trigger to the whole cell.
        let contributors = [4u8, 5, 6, 7];
        let new_indices = [4u8, 5, 6, 7];
        let trigger = reshare_trigger_frame(&[(0, &authority_sk)], 1, 3, &contributors, &new_indices).expect("a test roster fits the frame");
        let initial: Vec<(usize, Vec<u8>)> = (0..N).map(|k| (k, trigger.clone())).collect();
        route(&mut nodes, initial, &[]);

        // Survivors adopted a 3-of-4 sharing on the new commitment (still anchors); the dropped {0,1,2}
        // adopted the same new commitment as pure consumers (they no longer contribute).
        for &p in &[3usize, 4, 5, 6] {
            assert_eq!(nodes[p].reshare_gen(), 1, "survivor adopted the reshare");
            assert_eq!(nodes[p].threshold(), 3, "at the new threshold");
            assert!(nodes[p].is_anchor(), "and holds a new share");
        }
        for &p in &[0usize, 1, 2] {
            assert_eq!(nodes[p].reshare_gen(), 1, "a dropped anchor still tracks the new commitment");
            assert!(!nodes[p].is_anchor(), "but becomes a consumer under the new sharing");
        }

        // Now the original {0,1,2} are gone (4 of the original 7 lost — past the WITHOUT-reshare freeze cliff).
        // Advance the epoch driving only the 4 survivors at t'=3.
        let live = [3usize, 4, 5, 6];
        let mut init = Vec::new();
        for &p in &live {
            for e in nodes[p].step(Instant(0), Input::Command(Command::AdvanceEpoch)) {
                if let Effect::Send { to, frame } = e
                    && let Some(k) = node_at(to)
                {
                    init.push((k, frame));
                }
            }
        }
        route(&mut nodes, init, &[0, 1, 2]);

        // The clock SURVIVED: the survivor set reached epoch 2, and the seed is the continuous DVRF value.
        for &p in &live {
            assert_eq!(nodes[p].epoch(), Epoch::new(2), "the clock advanced on the survivor set");
            assert_eq!(nodes[p].seed(), expected_epoch2, "the reshared beacon is the same DVRF value");
        }
    }

    #[test]
    fn a_key_exfiltration_reshare_trigger_is_rejected() {
        // Audit §2.1: a reshare CHANGES the sharing threshold, so an unauthenticated trigger is a beacon
        // master-key exfiltration oracle — a 2-anchor coalition could name new_threshold=2 at its own indices
        // and reconstruct the key. The trigger is authenticated against the beacon's recovery authority; a
        // forged/foreign signature is refused before any anchor deals a single sub-share.
        use fanos_pqcrypto::{HybridSigSecret, SeedRng};
        let t = 4usize;
        let (shares, commitment) = deal(&[0xBE; 32], t, N, &mut DeterministicRng::new(b"exfil-cell")).unwrap();
        let (authority_sk, authority_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"exfil-authority"));
        let (impostor_sk, _) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"exfil-impostor"));
        let mut victim = BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment.clone(), t, BeaconSeed::GENESIS)
            .with_recovery_authority(RecoveryAuthoritySet::new(vec![authority_vk]).unwrap());
        let recv = |v: &mut BeaconNode<F2>, frame: Vec<u8>| v.step(Instant(0), Input::Message { from: [0, 0, 0], frame });

        // The §2.1 exploit — a 2-coalition names new_threshold=2 at its own indices {5,6} — but SIGNED BY THE
        // ATTACKER, not the authority. It is refused, so no honest anchor deals a sub-share. This is the fix.
        assert!(recv(&mut victim, reshare_trigger_frame(&[(0, &impostor_sk)], 1, 2, &[1, 2, 3, 4], &[5, 6]).expect("a test roster fits the frame")).is_empty(),
            "a foreign-signed (unauthenticated) reshare trigger is refused — the 2-coalition exfil is closed");
        assert_eq!(victim.reshare_gen(), 0, "and does not adopt it");
        // Tampering a validly-signed trigger (corrupt a trailing signature byte) also fails verification.
        let mut tampered = reshare_trigger_frame(&[(0, &authority_sk)], 1, 3, &[1, 2, 3, 4], &[4, 5, 6, 7]).expect("a test roster fits the frame");
        if let Some(b) = tampered.last_mut() {
            *b ^= 0xFF;
        }
        assert!(recv(&mut victim, tampered).is_empty(), "a tampered signature is refused");

        // **Refusing it is half the job.** A beacon fed forged triggers and a beacon nobody is talking to
        // produce the same absence of rounds, and the beacon is the clock every epoch-aligned mechanism reads
        // — coordinate VRF, activation heights, mix-key rotation, rendezvous lines. Until this counter the
        // §2.1 attack left no trace anywhere an operator could look.
        // The two refusals take **different paths**, and finding that out is why this assertion exists.
        // The impostor-signed trigger decodes and fails the signature check. The tampered one corrupts the
        // frame envelope, so it never reaches the handler at all — it was refused with no record anywhere
        // until `frame_undecodable` was added. An attacker probing the beacon with malformed triggers looked
        // exactly like silence.
        let r = victim.rejects();
        // The two refusals take **different paths**, and measuring which is the point. The impostor-signed
        // trigger parses and fails the authority check. The tampered one is rejected by
        // `parse_reshare_trigger` before verification ever runs — corrupting a signature byte breaks the
        // body's own length/shape check first. I assumed it would be a second forgery and it is not.
        //
        // That distinction is worth counting rather than folding: a malformed trigger is a peer that is
        // broken or on another wire version, a forged one is a peer that holds a key it should not. They call
        // for different responses and were previously the same silence.
        assert_eq!(r.reshare_forged, 1, "the impostor-signed trigger fails the authority check");
        assert_eq!(r.reshare_malformed, 1, "the tampered one fails the body parse, before verification");
        assert_eq!(
            r.reshare_forged + r.reshare_malformed,
            2,
            "and between them every attempt is accounted for — none is refused in silence"
        );
        assert_eq!(
            victim.rejects().reshare_no_authority,
            0,
            "this cell HAS an authority — a provisioning gap must not be reported as an attack"
        );

        // And the two are kept apart, because they call for opposite responses: configure a trust root, or
        // find who is sending triggers.
        let mut rootless =
            BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment.clone(), t, BeaconSeed::GENESIS);
        assert!(
            recv(&mut rootless, reshare_trigger_frame(&[(0, &authority_sk)], 1, 2, &[1, 2, 3, 4], &[5, 6]).expect("a test roster fits the frame")).is_empty(),
            "a cell with no recovery authority cannot reshare at all"
        );
        assert_eq!(rootless.rejects().reshare_no_authority, 1, "and says so as a provisioning gap");
        assert_eq!(rootless.rejects().reshare_forged, 0, "not as a forgery");

        // Even correctly AUTHORITY-signed, the defence-in-depth guards still refuse: a degree-0 (threshold-1)
        // reshare, an out-of-range or duplicate new index, and a far-future generation.
        assert!(recv(&mut victim, reshare_trigger_frame(&[(0, &authority_sk)], 1, 1, &[1, 2, 3, 4], &[5]).expect("a test roster fits the frame")).is_empty(),
            "the MIN_RESHARE_THRESHOLD floor refuses a degree-0 reshare even from the authority");
        assert!(recv(&mut victim, reshare_trigger_frame(&[(0, &authority_sk)], 1, 3, &[1, 2, 3, 4], &[5, 6, 99]).expect("a test roster fits the frame")).is_empty());
        assert!(recv(&mut victim, reshare_trigger_frame(&[(0, &authority_sk)], 1, 3, &[1, 2, 3, 4], &[5, 5, 6]).expect("a test roster fits the frame")).is_empty());
        assert!(recv(&mut victim, reshare_trigger_frame(&[(0, &authority_sk)], 1_000_000, 3, &[1, 2, 3, 4], &[4, 5, 6]).expect("a test roster fits the frame")).is_empty());
        assert_eq!(victim.reshare_gen(), 0, "no refused trigger advanced any state");

        // A well-formed reshare correctly signed by the authority is honored.
        assert!(!recv(&mut victim, reshare_trigger_frame(&[(0, &authority_sk)], 1, 3, &[1, 2, 3, 4], &[4, 5, 6, 7]).expect("a test roster fits the frame")).is_empty(),
            "a legitimate authority-signed reshare is still dealt");
    }

    /// **A committee member must not be able to open unboundedly many future-epoch buffers.**
    ///
    /// `MAX_PARTIALS` bounded each bucket and nothing bounded the number of buckets: `buffer` refused only
    /// `epoch <= self.epoch`, so every epoch above the adopted one opened a fresh entry. Partials are
    /// DLEQ-verified before buffering, which stops a *forgery* — but a share holder can evaluate at any
    /// target, so a Byzantine member floods with entirely **valid** partials. Authenticated-but-unbounded,
    /// the same shape as audit B1.
    ///
    /// Asserted on both halves: the map stays bounded, and the buckets kept are the LOW epochs — because
    /// adoption is in order, so a far-future bucket cannot assemble until every epoch beneath it has, and
    /// evicting the nearest ones would starve exactly the epoch about to run.
    #[test]
    fn a_member_cannot_open_unbounded_future_epoch_buffers() {
        let t = 2usize;
        let (shares, commitment) =
            deal(&[0xBE; 32], t, N, &mut DeterministicRng::new(b"beacon-flood")).unwrap();
        let mut node: BeaconNode<F2> =
            BeaconNode::new(Point::at(0), Some(shares[0].clone()), commitment.clone(), t, BeaconSeed::GENESIS);

        // A member evaluates its share at many far-future epochs — every partial genuinely verifies.
        let far = 4 * MAX_PENDING_EPOCHS as u64;
        for e in 1..=far {
            let epoch = Epoch::new(e);
            let partial = partial_eval(&shares[1], epoch);
            node.step(Instant(0), Input::Message { from: [0, 0, 0], frame: partial_frame(epoch, &partial) });
        }

        assert!(
            node.pending_epochs() <= MAX_PENDING_EPOCHS,
            "the buffer must bound the number of epochs, not only each bucket: {} > {MAX_PENDING_EPOCHS}",
            node.pending_epochs()
        );
        assert!(
            node.rejects().partial_epoch_evicted > 0,
            "and must say so — a silent discard is indistinguishable from a partial that never arrived"
        );
        assert!(
            node.lowest_pending_epoch().is_some_and(|e| e.get() <= MAX_PENDING_EPOCHS as u64),
            "the epochs KEPT must be the low ones: adoption is in order, so the nearest are the only ones \
             that can assemble next"
        );
    }

    /// Step `AdvanceEpoch` on every node, keeping the partial bus **and** counting the nodes that refused to
    /// contribute. Separate from [`kickoff`] because that one keeps only `Send`s, and the whole question here
    /// is what a node does *instead of* sending.
    fn kickoff_counting_refusals(nodes: &mut [BeaconNode<F2>]) -> (Vec<(usize, Vec<u8>)>, Vec<usize>) {
        let mut bus = Vec::new();
        let mut refused = Vec::new();
        for (k, node) in nodes.iter_mut().enumerate() {
            for e in node.step(Instant(0), Input::Command(Command::AdvanceEpoch)) {
                match e {
                    Effect::Send { to, frame } => {
                        if let Some(j) = node_at(to) {
                            bus.push((j, frame));
                        }
                    }
                    Effect::Notify(Notification::Escalated(Escalation::BeaconShareMismatch)) => {
                        refused.push(k);
                    }
                    _ => {}
                }
            }
        }
        (bus, refused)
    }

    /// A cell of `N` anchors at threshold `t`, where node 0 holds a share from a **different** dealing — the
    /// operator error this whole path defends against (a share file restored from a previous DKG, or copied
    /// from the wrong node). Returns the nodes, the refusal list, and the adoptions.
    #[allow(clippy::type_complexity)]
    fn cell_with_one_stale_share(
        t: usize,
    ) -> (
        Vec<BeaconNode<F2>>,
        Vec<usize>,
        Vec<(Triple, Epoch, [u8; 32])>,
    ) {
        let (good, commitment) = deal(&[0xBE; 32], t, N, &mut DeterministicRng::new(b"beacon-match")).unwrap();
        let (stale, _elsewhere) = deal(&[0xAD; 32], t, N, &mut DeterministicRng::new(b"beacon-stale")).unwrap();
        let mut nodes: Vec<BeaconNode<F2>> = (0..N)
            .map(|k| {
                let share = if k == 0 { stale[0].clone() } else { good[k].clone() };
                BeaconNode::new(Point::at(k), Some(share), commitment.clone(), t, BeaconSeed::GENESIS)
            })
            .collect();
        let (bus, refused) = kickoff_counting_refusals(&mut nodes);
        let ready = run(&mut nodes, bus);
        (nodes, refused, ready)
    }

    #[test]
    fn a_share_that_does_not_match_its_commitment_never_reaches_the_cell_as_a_forgery() {
        // `advance` used to flood and buffer its own partial without ever verifying it — the one partial in
        // the bucket that skipped `verify_partial`. The cost was paid on both sides: every peer counted an
        // honest node as a forger (measured 1 each, on all six), and the node's own bucket was poisoned
        // permanently, because `assemble` takes the first `threshold` distinct indices in insertion order and
        // its own is inserted first (measured 4 failed assemblies in one epoch).
        let (nodes, refused, ready) = cell_with_one_stale_share(4);

        assert_eq!(refused, vec![0], "exactly the node holding the stale share refuses to contribute — and it says so");
        assert_eq!(nodes[0].rejects().share_mismatched, 1, "the refusal is counted where an operator reads it");

        for (k, n) in nodes.iter().enumerate().skip(1) {
            assert_eq!(
                n.rejects().partial_unverified,
                0,
                "node {k} must not see a forgery: the only badly-keyed node never put a partial on the wire"
            );
        }
        assert_eq!(
            nodes[0].rejects().assembly_unverified,
            0,
            "and the bad partial never entered its own bucket, so its assemblies stop failing"
        );

        // The setup has to have produced a working cell, or the two zeros above are zeros for the wrong
        // reason: six good anchors at t = 4 are a quorum, and everyone — including the badly-keyed node,
        // which stays a live *consumer* — must adopt epoch 1.
        assert_eq!(ready.len(), N, "all {N} nodes adopt the epoch-1 seed");
        for (k, n) in nodes.iter().enumerate() {
            assert_eq!(n.epoch(), Epoch::new(1), "node {k} adopted");
        }
    }

    #[test]
    fn a_cell_at_exactly_its_threshold_halts_and_exactly_one_node_can_name_the_reason() {
        // The same fault where it costs most. At `t = N` every anchor is load-bearing, so one unusable share
        // stops the cell's clock outright — measured on the unfixed code as 0 of 7 adopting, every node stuck
        // at epoch 0. The halt is honest (an anchor really is missing) and is NOT what this fixes; what it
        // fixes is that the only instrument reading anything used to be `partial_unverified` on the six
        // innocent nodes, sending an operator to hunt an attacker that does not exist.
        let (nodes, refused, ready) = cell_with_one_stale_share(N);

        assert!(ready.is_empty(), "no seed can be assembled: t = {N} needs every anchor and one cannot contribute");
        for (k, n) in nodes.iter().enumerate() {
            assert_eq!(n.epoch(), Epoch::ZERO, "node {k} is still at genesis, which is the honest outcome");
        }

        assert_eq!(refused, vec![0], "and exactly one node names the cause — the one whose file is wrong");
        assert_eq!(nodes[0].rejects().share_mismatched, 1, "counted, once, on the node that can act on it");
        let blamed: Vec<usize> = nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.rejects().partial_unverified > 0)
            .map(|(k, _)| k)
            .collect();
        assert!(blamed.is_empty(), "and NO node reports a forgery: a stalled cell must not read as an attack (saw {blamed:?})");
    }

    #[test]
    fn the_assembly_gate_refuses_a_partial_that_reached_the_buffer_unverified() {
        // The second of the beacon's two verification gates, pinned on its own. It is unreachable through
        // `on_partial` (which verifies first) and, since `advance` verifies too, unreachable in production —
        // which is exactly why it needed a test: removing it left the whole `fanos-keygen` suite green
        // (24 passed, 0 failed), so nothing was holding it. It is reached here the only way it can be: a
        // partial placed in the buffer without passing a gate, which is what a future second buffering path
        // would look like.
        let (shares, commitment) = deal(&[0xF0; 32], 1, N, &mut DeterministicRng::new(b"beacon-assembly")).unwrap();
        let mut node =
            BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment.clone(), 1, BeaconSeed::GENESIS);

        let honest = partial_eval(&shares[2], Epoch::new(1));
        let mut bytes = honest.to_bytes();
        bytes[65] ^= 0x01;
        let forged = BeaconPartial::from_bytes(&bytes)
            .expect("the flipped response byte must stay canonical, or this test verifies nothing");
        assert!(
            !verify_partial(&forged, Epoch::new(1), &commitment),
            "and it must actually fail its DLEQ — otherwise the gate below has nothing to refuse"
        );

        node.buffer(Epoch::new(1), forged);
        let effects = node.try_assemble(Epoch::new(1));
        assert!(effects.is_empty(), "a round assembled from an unverified partial is not adopted");
        assert_eq!(node.rejects().assembly_unverified, 1, "and the refusal is counted at the assembly gate, not the arrival gate");
        assert_eq!(node.epoch(), Epoch::ZERO, "the node stays at genesis");
    }


    #[test]
    fn a_reshare_contribution_this_node_cannot_bind_is_neither_recorded_nor_flooded() {
        // The second member of the class `advance` opened, one door over. `on_reshare_commit` refuses a
        // PEER's contribution that does not bind to the group commitment; `deal_reshare` built OUR OWN and
        // recorded + flooded it without running the same check. A stale share file therefore made this node
        // deal a contribution every peer refuses, while its own `pending_reshare` kept the useless commitment
        // and the generation could never complete from here.
        //
        // The trigger itself is re-flooded either way (that is the monotone authenticated frame travelling
        // on), so "no effects" is the wrong observable — the question is whether a COMMIT frame goes out.
        use fanos_pqcrypto::{HybridSigSecret, SeedRng};
        let t = 4usize;
        let (good, commitment) = deal(&[0xBE; 32], t, N, &mut DeterministicRng::new(b"reshare-match")).unwrap();
        let (stale, _elsewhere) = deal(&[0xAD; 32], t, N, &mut DeterministicRng::new(b"reshare-stale")).unwrap();

        // Generated twice from the same seed rather than cloned: the key type need not be `Clone` for a test
        // to hand the same authority to two nodes, and a deterministic seed says so without a helper.
        let (authority_sk, authority_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"reshare-authority"));
        let trigger = || {
            reshare_trigger_frame(&[(0, &authority_sk)], 1, 3, &[1, 2, 3, 4], &[1, 2, 3, 4])
                .expect("a test roster fits the frame")
        };
        let commits = |effects: &[Effect]| -> usize {
            effects
                .iter()
                .filter(|e| match e {
                    Effect::Send { frame, .. } => {
                        decode_frame(frame)
                            .is_ok_and(|(f, _)| f.frame_type() == Some(FrameType::BeaconReshareCommit))
                    }
                    _ => false,
                })
                .count()
        };

        // **The control first.** With the matching share the same trigger makes this node deal — without it,
        // the silence below would be silence for a reason that has nothing to do with the share.
        let mut honest = BeaconNode::<F2>::new(
            Point::at(0), Some(good[0].clone()), commitment.clone(), t, BeaconSeed::GENESIS,
        )
        .with_recovery_authority(RecoveryAuthoritySet::new(vec![authority_vk]).unwrap());
        let effects = honest.step(Instant(0), Input::Message { from: [0, 0, 0], frame: trigger() });
        assert!(commits(&effects) > 0, "a matching share deals its contribution and floods the commitment");
        assert_eq!(honest.rejects().share_mismatched, 0, "and nothing about it is refused");

        // The same trigger, at a node whose share came from a different dealing.
        let (_, authority_vk2) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"reshare-authority"));
        let mut stale_node = BeaconNode::<F2>::new(
            Point::at(0), Some(stale[0].clone()), commitment, t, BeaconSeed::GENESIS,
        )
        .with_recovery_authority(RecoveryAuthoritySet::new(vec![authority_vk2]).unwrap());
        let effects = stale_node.step(Instant(0), Input::Message { from: [0, 0, 0], frame: trigger() });
        assert_eq!(
            commits(&effects),
            0,
            "a contribution that binds to nothing never reaches the wire — every peer would refuse it, and \
             the node would have poisoned its own generation with it"
        );
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Escalated(Escalation::BeaconShareMismatch))
            )),
            "and the node says why, with the same escalation the beacon path raises — one cause, one name"
        );
        assert_eq!(stale_node.rejects().share_mismatched, 1, "counted once, on the node that can act on it");
    }

}
