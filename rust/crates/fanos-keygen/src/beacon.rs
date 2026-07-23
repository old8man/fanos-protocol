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
use fanos_ports::{Command, Effect, Engine, Epoch, Input, Instant, Notification};
use fanos_vrf::beacon::{BeaconPartial, BeaconRound, PARTIAL_LEN, partial_eval, verify_partial};
use fanos_vrf::vss::{
    VssCommitment, VssShare, combine_reshare_commitment, combine_reshare_share, reshare, verify_reshare_commit,
    verify_share,
};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// Cap on partials buffered per in-progress epoch. A cell has at most `N` anchors, so honest operation
/// never approaches this; the cap bounds memory against a peer flooding forged `BeaconPartial`s (each
/// still fails its DLEQ, so none is ever adopted — this only bounds the buffer).
const MAX_PARTIALS: usize = 256;

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

/// A node running the distributed randomness beacon over its cell.
pub struct BeaconNode<F: Field> {
    coord: Point<F>,
    n: usize,
    threshold: usize,
    /// This node's beacon share — `Some` for an **anchor** that contributes partials, `None` for a pure
    /// consumer (which still verifies and adopts flooded rounds).
    share: Option<VssShare>,
    /// The group commitment every node verifies partials and rounds against (a DKG output; identical
    /// across all honest nodes, which fold the same qualified set).
    commitment: VssCommitment,
    /// The current adopted beacon epoch and its public seed (genesis all-zero until the first round).
    epoch: Epoch,
    seed: [u8; 32],
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
    /// A beacon node at `coord`, verifying against the group `commitment` at `threshold`. `share` is
    /// this node's DKG beacon share if it is an anchor (it then contributes partials), else `None`.
    /// Starts at [`Epoch::ZERO`] with the genesis (all-zero) seed until the first round is adopted.
    #[must_use]
    pub fn new(
        coord: Point<F>,
        share: Option<VssShare>,
        commitment: VssCommitment,
        threshold: usize,
    ) -> Self {
        Self {
            coord,
            n: Plane::<F>::N as usize,
            threshold,
            share,
            commitment,
            epoch: Epoch::ZERO,
            seed: [0u8; 32],
            pending: BTreeMap::new(),
            current_round: None,
            reshare_gen: 0,
            pending_reshare: BTreeMap::new(),
        }
    }

    /// The current beacon epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The current public beacon seed (all-zero genesis until the first round is adopted).
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        self.seed
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

    /// Build a resharing-trigger frame for a coordinator to broadcast (audit R-C1): start generation
    /// `generation`, redistributing the beacon key to the `new_indices` holder set at `new_threshold`, dealt
    /// by the named live `contributors` (which must number ≥ the current threshold). In production a parent
    /// cell or an operator issues this (authenticated over the parent link); the simulator's driver injects
    /// it directly. The trigger is self-flooding (monotone), so it need only reach one live anchor.
    #[must_use]
    pub fn reshare_trigger(
        generation: u64,
        new_threshold: usize,
        contributors: &[u8],
        new_indices: &[u8],
    ) -> Vec<u8> {
        reshare_trigger_frame(generation, new_threshold, contributors, new_indices)
    }

    /// This node's beacon holder index — its Fano point index `+ 1` (the [`VssShare`] convention: the anchor
    /// at point `i` holds share index `i + 1`). Used to tell whether this node is a target new holder of a
    /// reshare and to combine its own sub-shares. `0` if the coord is not a plane point (never, for a member).
    fn beacon_index(&self) -> u8 {
        let me = self.coord.coords();
        (0..self.n)
            .find(|&i| Point::<F>::at(i).coords() == me)
            .map_or(0, |i| (i + 1) as u8)
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
            return Vec::new();
        };
        let Some(seed) = round.verify_and_seed(&self.commitment, self.threshold) else {
            return Vec::new();
        };
        self.adopt_and_announce(epoch, seed, round)
    }

    /// A received round: verify it against the group commitment and, if strictly newer, adopt + re-flood.
    fn on_round(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some(round) = BeaconRound::from_bytes(body) else {
            return Vec::new();
        };
        let epoch = round.epoch();
        if epoch <= self.epoch {
            return Vec::new(); // not newer — drop (terminates the flood)
        }
        let Some(seed) = round.verify_and_seed(&self.commitment, self.threshold) else {
            return Vec::new();
        };
        self.adopt_and_announce(epoch, seed, round)
    }

    /// A received partial: verify its DLEQ against the group commitment, buffer it, and try to assemble.
    fn on_partial(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some((epoch, partial)) = parse_partial(body) else {
            return Vec::new();
        };
        if epoch <= self.epoch || !verify_partial(&partial, epoch, &self.commitment) {
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
        let Some((generation, new_threshold, contributors, new_indices)) = parse_reshare_trigger(body) else {
            return Vec::new();
        };
        // Security floor (audit §3.1). The confirmed exfiltration set `new_threshold = 1`: a degree-0
        // resharing polynomial evaluates to the contributor's raw share `sᵢ` at every new index, so one
        // member could name itself the sole new holder, collect `{sᵢ}` from ≥`t` contributors, and
        // reconstruct the beacon master key. [`MIN_RESHARE_THRESHOLD`] closes that — with `new_threshold ≥ 2`
        // each new holder receives only a single evaluation of a degree-≥1 polynomial, and a single-identity
        // attacker controls exactly one new-holder coordinate, so it can never gather the `new_threshold`
        // evaluations reconstruction needs. Every index is validated (distinct, `1..=n`) so a sub-share is
        // never routed to an out-of-range/foreign coordinate, and the generation is windowed so a far-future
        // trigger cannot evict the live in-progress rounds. RESIDUAL (Tier-1 follow-up): a coalition of
        // ≥`new_threshold` Byzantine anchors can still extract the raw key via a low-threshold reshare — that
        // is within the beacon's own `< t`-Byzantine trust bound and requires an *authenticated* coordinator
        // authorization (operator control-plane / threshold endorsement) to fully close.
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
        let reflood = reshare_trigger_frame(generation, new_threshold, &contributors, &new_indices);
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
            Input::Message { from, frame } => match decode_frame(&frame) {
                Ok((f, _)) => match f.frame_type() {
                    Some(FrameType::BeaconPartial) => self.on_partial(f.body),
                    Some(FrameType::Beacon) => self.on_round(f.body),
                    Some(FrameType::BeaconReq) => self.on_beacon_req(from),
                    Some(FrameType::BeaconReshareTrigger) => self.on_reshare_trigger(f.body),
                    Some(FrameType::BeaconReshareCommit) => self.on_reshare_commit(f.body),
                    Some(FrameType::BeaconReshareShare) => self.on_reshare_share(f.body),
                    _ => Vec::new(),
                },
                Err(_) => Vec::new(),
            },
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

/// `BeaconReshareTrigger` body: `generation(8) ‖ new_threshold(1) ‖ n_contrib(1) ‖ contributors ‖ n_new(1) ‖ new_indices`.
fn reshare_trigger_frame(generation: u64, new_threshold: usize, contributors: &[u8], new_indices: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + 2 + contributors.len() + 1 + new_indices.len());
    body.extend_from_slice(&generation.to_be_bytes());
    body.push(new_threshold as u8);
    body.push(contributors.len() as u8);
    body.extend_from_slice(contributors);
    body.push(new_indices.len() as u8);
    body.extend_from_slice(new_indices);
    encode(FrameType::BeaconReshareTrigger, &body)
}

fn parse_reshare_trigger(body: &[u8]) -> Option<(u64, usize, Vec<u8>, Vec<u8>)> {
    let generation = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let new_threshold = usize::from(*body.get(8)?);
    let n_contrib = usize::from(*body.get(9)?);
    let contributors = body.get(10..10 + n_contrib)?.to_vec();
    let n_new_pos = 10 + n_contrib;
    let n_new = usize::from(*body.get(n_new_pos)?);
    let new_indices = body.get(n_new_pos + 1..n_new_pos + 1 + n_new)?.to_vec();
    Some((generation, new_threshold, contributors, new_indices))
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
            .map(|i| BeaconNode::new(Point::at(i), Some(shares[i].clone()), commitment.clone(), t))
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
    fn a_forged_partial_is_not_adopted() {
        // With t = 1 a single valid partial would form the beacon; a forged one (failing its DLEQ) must
        // not — so a Byzantine anchor cannot inject a bogus contribution.
        let (shares, commitment) = deal(
            &[0xF0; 32],
            1,
            N,
            &mut DeterministicRng::new(b"beacon-forge"),
        )
        .unwrap();
        let mut node = BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment, 1);

        // A valid partial from anchor 2 (index 3), with a flipped response byte.
        let honest = partial_eval(&shares[2], Epoch::new(1));
        let mut bytes = honest.to_bytes();
        bytes[65] ^= 0x01;
        // A non-canonical corruption is rejected at decode (also a rejection); a canonical one fails DLEQ.
        if let Some(forged) = BeaconPartial::from_bytes(&bytes) {
            let frame = partial_frame(Epoch::new(1), &forged);
            let effects = node.step(
                Instant(1),
                Input::Message {
                    from: [9, 9, 9],
                    frame,
                },
            );
            assert!(
                effects.is_empty(),
                "a forged partial (t=1) yields no beacon"
            );
        }
        assert_eq!(node.epoch(), Epoch::ZERO, "the node stays at genesis");
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
            BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment.clone(), t);
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
        let mut fresh = BeaconNode::<F2>::new(Point::at(1), None, commitment, t);
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
        use fanos_vrf::beacon::combine;
        let t = 4usize;
        let (shares, commitment) =
            deal(&[0xBE; 32], t, N, &mut DeterministicRng::new(b"reshare-cell")).unwrap();
        let mut nodes: Vec<BeaconNode<F2>> = (0..N)
            .map(|i| BeaconNode::new(Point::at(i), Some(shares[i].clone()), commitment.clone(), t))
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
        let trigger = reshare_trigger_frame(1, 3, &contributors, &new_indices);
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
        // Audit §3.1: the confirmed exploit — one member broadcasts a `new_threshold = 1` reshare naming
        // itself the sole new holder. A degree-0 polynomial deals `gᵢ(j) = sᵢ`, so an honest anchor that
        // dealt would hand the attacker its raw secret share; ≥ t of them reconstruct the beacon master key.
        // The floor must make every honest anchor REFUSE, so no sub-share ever leaves for the attacker.
        let t = 4usize;
        let (shares, commitment) = deal(&[0xBE; 32], t, N, &mut DeterministicRng::new(b"exfil-cell")).unwrap();
        let mut victim = BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment.clone(), t);
        let recv = |v: &mut BeaconNode<F2>, frame: Vec<u8>| v.step(Instant(0), Input::Message { from: [0, 0, 0], frame });

        // The malicious trigger: threshold 1, new holder = the attacker's index 5, ≥ t named contributors.
        assert!(recv(&mut victim, reshare_trigger_frame(1, 1, &[1, 2, 3, 4], &[5])).is_empty(),
            "an honest anchor deals nothing for a threshold-1 (key-leaking) reshare");
        assert_eq!(victim.reshare_gen(), 0, "and does not adopt it");
        // Defense-in-depth: an out-of-range new index, a duplicate index, and a far-future generation are
        // all refused before any share is dealt.
        assert!(recv(&mut victim, reshare_trigger_frame(1, 3, &[1, 2, 3, 4], &[5, 6, 99])).is_empty());
        assert!(recv(&mut victim, reshare_trigger_frame(1, 3, &[1, 2, 3, 4], &[5, 5, 6])).is_empty());
        assert!(recv(&mut victim, reshare_trigger_frame(1_000_000, 3, &[1, 2, 3, 4], &[4, 5, 6])).is_empty());
        assert_eq!(victim.reshare_gen(), 0, "no malformed trigger advanced any state");

        // A well-formed reshare (threshold ≥ 2, valid distinct in-range indices, in-window) is still honored.
        assert!(!recv(&mut victim, reshare_trigger_frame(1, 3, &[1, 2, 3, 4], &[4, 5, 6, 7])).is_empty(),
            "a legitimate reshare is still dealt");
    }
}
