//! **Data-availability sampling** as a sans-I/O component (spec §6 / §L4.3).
//!
//! A proposer never broadcasts its block. It broadcasts the small *skeleton* and disperses one erasure shard to each
//! validator, so availability is established by real peer sampling rather than the proposer's own say-so. A replica
//! therefore holds exactly **one** shard of a foreign block — the one dispersed to it — and must gather the rest from
//! peers before it can check the payload against the header's `da_commit` and vote on it.
//!
//! ## Why this is a component and not driver code
//!
//! It was driver code, inline in `fanos_node::taxis_driver`, and that is precisely why a **total** consensus liveness
//! failure was invisible to the test suite: the simulator handed every replica the complete shard set instantly, so it
//! modelled a proposal as arriving whole while production dispersed and sampled. Every engine-level SSLE test passed
//! while a real cell finalized no block at all. The standing rule is that the simulator differs from production only in
//! *transport* — which is only enforceable if the logic under test is not itself tangled into the transport.
//!
//! So the decision procedure lives here, owns no sockets, and returns what to send. The driver does the sending and the
//! simulator does the same over an in-memory bus, and both exercise **this** code rather than two lookalikes that can
//! drift apart.
//!
//! ## Recovery is pattern-dependent, not count-dependent
//!
//! [`fanos_code::erasure::reconstruct`] gates on `lrc::is_recoverable_fano`, so *which* shards are present decides
//! recoverability — `K = 3` of `N = 7` is necessary and not sufficient. [`Sampler::missing`] therefore keeps asking for
//! every absent shard rather than stopping at a count.

use alloc::boxed::Box;
use alloc::vec::Vec;

use fanos_primitives::collections::BoundedMap;

use crate::block::Block;
use crate::consensus::DaShards;

/// Cap on the number of blocks whose own dispersed shard is retained to serve peers' sampling requests.
///
/// Bounded because the key is a **remote-chosen** block hash: without it, a peer streaming distinct skeletons grows this
/// without limit. A well-behaved block whose shard is evicted is simply unavailable from this node, and the erasure code
/// tolerates missing shards by design.
const HELD_CAP: usize = 512;

/// Cap on skeletons awaiting reconstruction — same remote-key reasoning, against a proposal flood.
pub const PENDING_CAP: usize = 64;

/// Longest gap, in resample sweeps, that [`Sampler::due`] will leave between two requests for one block.
///
/// The cap exists because a block's obtainability is not monotone in *our* knowledge: a peer that could answer nothing
/// becomes able to answer **any** index the moment it reconstructs the block itself (the driver falls back to
/// `ConsensusEngine::shard_of`, which regenerates any shard from a held body). Unbounded doubling would let us sleep
/// through that transition. Bounding the gap bounds the loss to one interval.
///
/// The value is the cell's own progress unit rather than a chosen number: one round timeout, expressed in sweeps —
/// `ROUND_TIMEOUT_MAX / TICK_PERIOD` = 24 s / 150 ms. That is the interval after which the cell re-offers and re-votes
/// everything anyway, so a sampler that wakes at least that often can never be the reason a round is lost. The relation
/// is machine-checked in `fanos-node`, which is the crate that owns both constants.
pub const RESAMPLE_MAX_INTERVAL: u32 = 160;

/// A skeleton awaiting reconstruction: the shards gathered so far, this node's own plus those sampled from peers.
struct Pending {
    skeleton: Block,
    shards: Box<DaShards>,
    /// Sweeps still to wait before this block's missing shards are requested again.
    wait: u32,
    /// The gap to apply after the next request — doubles while nothing is learned, resets on progress.
    interval: u32,
}

/// One validator's data-availability sampling state.
pub struct Sampler {
    /// This validator's index, so a request for someone else's shard is not answered from here.
    me: u8,
    /// This validator's own shard for recent blocks, served on request.
    held: BoundedMap<[u8; 32], Vec<u8>>,
    /// Skeletons whose payload is still being sampled, keyed by block hash.
    pending: BoundedMap<[u8; 32], Pending>,
    /// What eviction must not take — see [`retain_relevant`](Sampler::retain_relevant).
    relevant: Vec<[u8; 32]>,
}

impl Sampler {
    /// A sampler for the validator at index `me`.
    #[must_use]
    pub fn new(me: u8) -> Self {
        Self { me, held: BoundedMap::new(HELD_CAP), pending: BoundedMap::new(PENDING_CAP), relevant: Vec::new() }
    }

    /// Retain the shard dispersed to this validator for `block`, so peers can sample it from here.
    pub fn hold(&mut self, block: [u8; 32], shard: Vec<u8>) {
        self.held.insert(block, shard);
    }

    /// Begin sampling `skeleton`, or `false` if it is already in flight.
    ///
    /// Idempotent by design: a skeleton is broadcast and may arrive more than once, and re-seeding would discard the
    /// shards gathered so far.
    pub fn begin(&mut self, skeleton: Block) -> bool {
        let hash = skeleton.hash();
        if self.pending.contains_key(&hash) {
            return false;
        }
        let mut shards: Box<DaShards> = Box::new(core::array::from_fn(|_| None));
        // Seed with our own dispersed shard when we already hold it — the shard order the proposer dispersed in is the
        // validator order, so ours sits at our own index.
        if let Some(mine) = self.held.get(&hash)
            && let Some(slot) = shards.get_mut(usize::from(self.me))
        {
            *slot = Some(mine.clone());
        }
        // Make room BEFORE inserting, by taking the oldest entry that can no longer be decided — never by inserting
        // and repairing afterwards. That older shape works for exactly one protected entry and fails silently for a
        // set (see `BoundedMap::remove_oldest_where`), which is why the single pin it replaces was a workaround
        // rather than a rule.
        if self.pending.len() >= PENDING_CAP {
            // Everything present is still relevant: refuse the skeleton rather than displace something that can
            // still be decided. The honest outcome — the map is at its flood bound with nothing disposable, and the
            // caller re-offers on the next sweep.
            if self.pending.remove_oldest_where(|h| !self.relevant.contains(h)).is_none() {
                return false;
            }
        }
        self.pending.insert(hash, Pending { skeleton, shards, wait: 0, interval: 1 });
        true
    }

    /// What eviction must not take: every block whose body can still be decided at this height.
    ///
    /// **A relevance rule, not a one-entry exemption**, and the difference is the whole finding. This began as `pin`,
    /// a single protected hash, added because [`PENDING_CAP`] evicts in insertion order and the first entry discarded
    /// is the earliest — typically round 0's min-ticket winner, the block the cell converged on. Measured live as
    /// every validator reporting `await` at round 13 for a body none of them held.
    ///
    /// That the pin *worked* was the tell: if the one block the engine has already committed to needing must be
    /// exempted from the cap, the cap cannot be trusted to keep what matters. A larger cap is no answer either —
    /// one height produces `n` skeletons per round times however many rounds it takes, and rounds are bounded by
    /// nothing. There is no correct number, which is why the old one read as arbitrary.
    ///
    /// So the cap goes back to being purely the flood defence its own doc claims (its key is remote-chosen), and
    /// `ConsensusEngine::relevant_bodies` decides what may be displaced. Capacity stops pretending to be a plan.
    pub fn retain_relevant(&mut self, blocks: Vec<[u8; 32]>) {
        self.relevant = blocks;
    }

    /// The shard indices still missing for `block`, i.e. what to request. Empty if nothing is pending for it.
    ///
    /// Excludes this validator's own index: nobody else holds our shard, and asking for it is a wasted round trip.
    #[must_use]
    pub fn missing(&self, block: &[u8; 32]) -> Vec<u8> {
        let Some(p) = self.pending.get(block) else { return Vec::new() };
        (0..u8::try_from(p.shards.len()).unwrap_or(0))
            .filter(|&i| i != self.me && p.shards.get(usize::from(i)).is_none_or(Option::is_none))
            .collect()
    }

    /// The blocks whose missing shards are **due** to be requested on this sweep, paired with those indices.
    ///
    /// Retrying matters more than it looks: a replica requests a shard the moment a skeleton arrives, but the proposer
    /// disperses peer by peer, so the request routinely reaches a peer *before* that peer has been given its own shard.
    /// The peer holds nothing, answers nothing, and without a retry the requester waits forever for a shard its peer
    /// has held all along. One proposal in flight loses that race sometimes; N racing proposals lose it reliably.
    ///
    /// ## Why this is a schedule and not a list
    ///
    /// It returned *everything* outstanding, on every 150 ms tick, forever — and a pending entry leaves the map only by
    /// reconstruction, [`prune_below`](Self::prune_below), or cap eviction. So a block that cannot be completed at a
    /// stalled height was re-requested for the whole stall: measured at one height, `shard=7130/7130 took=5366` per
    /// validator, thousands of requests for two blocks nobody could answer.
    ///
    /// A repeat is worth sending only if the answer could have changed, and exactly two things change it. **(a)** The
    /// proposer's dispersal finally reaches the peer we asked — the race above, bounded by one dispersal sweep, so it
    /// resolves within the first few attempts. **(b)** That peer obtains the block some other way — unbounded in time,
    /// with probability decaying in every attempt that has already failed. Early requests must therefore be dense and
    /// late ones sparse, which is exactly what doubling gives, with no tuned parameter: for a block that completes after
    /// `t` sweeps it costs `O(log t)` requests instead of `t` and delays completion by at most one interval — under 2× —
    /// and for a block that never completes it turns 1600 sweeps into 11.
    ///
    /// That bound is also why there is **no give-up rule**: at logarithmic cost an abandoned entry is not worth an
    /// invented horizon, and `prune_below` plus [`PENDING_CAP`] already bound the map. The gap is capped instead
    /// ([`RESAMPLE_MAX_INTERVAL`]), because obtainability is not monotone.
    pub fn due(&mut self) -> Vec<([u8; 32], Vec<u8>)> {
        let mut out = Vec::new();
        for (&hash, p) in self.pending.iter_mut() {
            if p.wait > 0 {
                p.wait -= 1;
                continue;
            }
            p.wait = p.interval;
            p.interval = p.interval.saturating_mul(2).min(RESAMPLE_MAX_INTERVAL);
            out.push(hash);
        }
        out.into_iter().map(|h| (h, self.missing(&h))).filter(|(_, m)| !m.is_empty()).collect()
    }

    /// The validator that **proposed** a block still being sampled — the one peer guaranteed to hold its whole payload.
    ///
    /// Every other peer is the custodian of a single shard and may never have been dispersed it; the proposer built the
    /// block, so it can regenerate any index (`ConsensusEngine::shard_of`, the fallback behind [`serve`](Self::serve)).
    /// A requester holding the skeleton therefore already knows an address that cannot be empty — and asking anywhere
    /// else is what leaves it waiting for a shard nobody it asked has ever held.
    #[must_use]
    pub fn proposer_of(&self, block: &[u8; 32]) -> Option<u8> {
        self.pending.get(block).map(|p| p.skeleton.header.proposer)
    }

    /// Answer a peer's request for shard `index` of `block` — `Some(shard)` only when it is **ours** and we hold it.
    #[must_use]
    pub fn serve(&self, block: &[u8; 32], index: u8) -> Option<Vec<u8>> {
        (index == self.me).then(|| self.held.get(block).cloned()).flatten()
    }

    /// Record a sampled shard and return the **full block** if the payload is now recoverable.
    ///
    /// A shard at our own index is also retained for serving, so a validator that learns its shard by sampling rather
    /// than by dispersal can still answer for it.
    pub fn accept(&mut self, block: [u8; 32], index: u8, shard: Vec<u8>) -> Option<Block> {
        if index == self.me {
            self.hold(block, shard.clone());
        }
        if let Some(p) = self.pending.get_mut(&block)
            && let Some(slot) = p.shards.get_mut(usize::from(index))
        {
            let fresh = slot.is_none();
            *slot = Some(shard);
            // **Progress resets the schedule.** The backoff in [`due`](Self::due) measures "nothing has been learned
            // about this block"; a shard we did not have is precisely something learned, and it says the peers holding
            // this block are answering. Without the reset a block that gathers its shards slowly would be punished for
            // the very sweeps in which it was gathering them — the doubling would outrun the delivery it is waiting on.
            // Gated on the slot being empty, so a re-delivered duplicate (which teaches nothing) cannot hold the
            // interval at 1 and reinstate the storm this schedule exists to end.
            if fresh {
                p.wait = 0;
                p.interval = 1;
            }
        }
        self.reconstruct(&block)
    }

    /// Rebuild the full block from the shards gathered so far, consuming the pending entry on success.
    ///
    /// `None` while the payload is still unrecoverable — the sampling continues. The check is cryptographic: the
    /// recovered payload is re-encoded and matched against the header's `da_commit`, so a withholding proposer (too few
    /// shards) and a tampering one (wrong payload) both fail here rather than being taken on trust.
    pub fn reconstruct(&mut self, block: &[u8; 32]) -> Option<Block> {
        let full = {
            let p = self.pending.get(block)?;
            p.skeleton.clone().with_sealed_txs(p.skeleton.reconstruct_payload(&p.shards)?)
        };
        self.pending.remove(block);
        Some(full)
    }

    /// Stop sampling `block` — it was obtained another way.
    ///
    /// Reconstruction is not the only route to a body: a parked decision can be discharged by a peer handing over the
    /// whole block (`ConsensusMsg::Body`), and a lagging validator can jump the height entirely by adopting a certified
    /// snapshot. Without this the pending entry outlives its purpose, and `pending` is capped — so entries nobody is
    /// waiting for compete for the space with the one block a validator actually is stuck on, which is exactly the
    /// eviction that ``pin`` exists to prevent.
    pub fn forget(&mut self, block: &[u8; 32]) {
        self.pending.remove(block);
        self.relevant.retain(|h| h != block);
    }

    /// Drop every pending skeleton for a height **below** `height` — work that can never be needed again.
    ///
    /// A skeleton carries its own `header.height`, so this needs nothing from the engine but the current one. Without it
    /// a validator accumulates the sampling it abandoned on the way: measured as a validator at height 4 still holding a
    /// block from an earlier height, missing five of seven shards, which no future request would ever complete. `pending`
    /// is capped, and eviction is by insertion order — so abandoned entries compete for the space with the one block a
    /// validator is actually stuck on, the very eviction ``pin`` exists to prevent.
    pub fn prune_below(&mut self, height: u64) {
        let stale: Vec<[u8; 32]> = self
            .pending
            .iter()
            .filter(|(hash, p)| {
                // Never the entry this validator is blocked on, whatever its height — that is `pin`'s whole purpose.
                p.skeleton.header.height < height && !self.relevant.contains(*hash)
            })
            .map(|(hash, _)| *hash)
            .collect();
        for hash in &stale {
            self.pending.remove(hash);
        }
    }

    /// Whether `block` is already being sampled — so a recovery request is not re-sent while one is in flight.
    #[must_use]
    pub fn is_sampling(&self, block: &[u8; 32]) -> bool {
        self.pending.contains_key(block)
    }

    /// How many blocks are still being sampled — an observable for tests and operator surfaces.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::params::CellParams;

    /// A block with a payload big enough to erasure-code across the cell.
    fn block_with_payload() -> Block {
        Block::assemble([0u8; 32], 0, fanos_primitives::Epoch::ZERO, 0, Vec::new())
    }

    /// A block at `height`, so a stale-vs-current distinction can be constructed.
    fn block_at(height: u64) -> Block {
        Block::assemble([0u8; 32], height, fanos_primitives::Epoch::ZERO, 0, Vec::new())
    }

    #[test]
    fn a_block_nobody_can_answer_costs_logarithmically_many_sweeps_not_linearly() {
        // The measured failure: `outstanding()` returned everything on every 150 ms tick forever, and a pending entry
        // leaves the map only by reconstruction, `prune_below`, or eviction — so a block that cannot be completed at a
        // stalled height was re-requested for the whole stall. One height, per validator: `shard=7130/7130 took=5366`.
        let mut s = Sampler::new(0);
        assert!(s.begin(block_with_payload().skeleton()));
        // 1600 sweeps is the 240 s stall at a 150 ms tick — the exact conditions of that trace.
        let sweeps = 1600u32;
        let asked = u32::try_from((0..sweeps).filter(|_| !s.due().is_empty()).count()).unwrap();
        // The bound is the schedule's own, not a number picked to fit: doubling reaches the cap in `log2(cap)` steps,
        // and every sweep after that costs one request per cap-length. Written this way it stays true if the cap moves.
        let bound = RESAMPLE_MAX_INTERVAL.ilog2() + 2 + sweeps / RESAMPLE_MAX_INTERVAL;
        assert!(
            asked <= bound,
            "a block nobody answers must cost O(log t) requests, not O(t): {asked} sweeps of {sweeps} asked, \
             against a derived bound of {bound}"
        );
        // …and the gap never grows past the cell's own progress unit, because obtainability is not monotone: a peer
        // that could answer nothing becomes able to answer any index the moment it reconstructs the block itself.
        let mut gaps = 0u32;
        for _ in 0..RESAMPLE_MAX_INTERVAL * 3 {
            if !s.due().is_empty() {
                gaps += 1;
            }
        }
        assert!(gaps >= 3, "the interval must cap, so a long-lived entry keeps waking: only {gaps} in 3 cap-lengths");
    }

    #[test]
    fn a_shard_that_teaches_something_resets_the_schedule_and_a_duplicate_does_not() {
        // The backoff measures "nothing learned about this block". A shard we did not have is something learned, so it
        // must reset — otherwise a block gathering its shards slowly is punished for the very sweeps in which it is
        // gathering them, and the doubling outruns the delivery it waits on. A *re-delivered* shard teaches nothing,
        // and letting it reset would hold the interval at 1 and reinstate the storm this schedule exists to end.
        let block = block_with_payload();
        let (hash, shards) = (block.hash(), block.da_shards());
        let mut s = Sampler::new(0);
        assert!(s.begin(block.skeleton()));
        let shard = shards.get(1).expect("the cell has a shard at index 1").clone();
        // Sweep until the schedule asks, which leaves it at the top of a wait as long as the current interval. Driving
        // to a *fire* rather than counting sweeps is what makes this test read the reset instead of the arithmetic: the
        // first draft asserted emptiness on a sweep that was legitimately due, and blamed the duplicate for it.
        let fire = |s: &mut Sampler| (0..RESAMPLE_MAX_INTERVAL * 2).any(|_| !s.due().is_empty());
        for i in 0..3 {
            assert!(fire(&mut s), "the schedule must keep asking about an unanswered block (fire {i})");
        }

        assert!(s.due().is_empty(), "just after a request the schedule waits");
        assert!(s.accept(hash, 1, shard.clone()).is_none(), "one shard cannot reconstruct the payload");
        assert!(!s.due().is_empty(), "a shard never seen before resets the schedule to the very next sweep");

        for i in 0..3 {
            assert!(fire(&mut s), "and the backoff resumes from there (fire {i})");
        }
        assert!(s.accept(hash, 1, shard).is_none(), "the same shard again");
        assert!(
            (0..3).all(|_| s.due().is_empty()),
            "a duplicate teaches nothing, so it must not reset the schedule — three consecutive quiet sweeps can only \
             hold if the wait survived it"
        );
    }

    #[test]
    fn abandoned_sampling_is_dropped_and_a_relevant_entry_never_is() {
        // Sampling a validator walked away from is not harmless: `pending` is capped and evicts by insertion order, so
        // entries for heights already decided compete for the space with the one block a stuck validator depends on.
        // Measured while chasing the live wedge: a validator at height 4 still holding a block from an earlier height,
        // missing five of seven shards, which no future request could ever complete.
        let (old, new) = (block_at(1), block_at(4));
        let (old_hash, new_hash) = (old.hash(), new.hash());
        let mut s = Sampler::new(0);
        assert!(s.begin(old.skeleton()));
        assert!(s.begin(new.skeleton()));
        assert_eq!(s.in_flight(), 2);

        s.prune_below(4);
        assert!(!s.is_sampling(&old_hash), "the height-1 skeleton is finished work at height 4");
        assert!(s.is_sampling(&new_hash), "the height-4 skeleton is still live");

        // And the pin outranks the height, because the whole point of `pin` is the entry a validator is blocked on.
        assert!(s.begin(old.skeleton()));
        s.retain_relevant(vec![old_hash]);
        s.prune_below(9);
        assert!(s.is_sampling(&old_hash), "a relevant entry survives pruning whatever its height");
    }

    #[test]
    fn the_fixture_block_genuinely_needs_more_than_one_shard() {
        // Guards the three tests below against being vacuous. An **empty** payload has zero stripes, so
        // `erasure::reconstruct` returns immediately and a single shard "recovers" it — every exchange test would then
        // pass without exchanging anything. Assert the fixture is not that block.
        let block = block_with_payload();
        let hash = block.hash();
        let shards = block.da_shards();
        let mut s = Sampler::new(0);
        s.hold(hash, shards.first().cloned().expect("a shard at index 0"));
        assert!(s.begin(block.skeleton()));
        assert!(
            s.reconstruct(&hash).is_none(),
            "one shard must NOT recover the fixture block, or the exchange tests below prove nothing"
        );
    }

    #[test]
    fn a_validator_asks_for_every_shard_but_its_own() {
        // Not "enough" shards: `erasure::reconstruct` gates on `is_recoverable_fano`, so K of N is necessary and not
        // sufficient and *which* shards are present decides it. A sampler that stopped requesting at a count would
        // stall on a recoverable-in-principle block.
        let block = block_with_payload();
        let hash = block.hash();
        let mut s = Sampler::new(3);
        assert!(s.begin(block), "a fresh skeleton starts sampling");
        assert_eq!(s.missing(&hash), vec![0, 1, 2, 4, 5, 6], "every index except our own");
        assert!(!s.begin(block_with_payload()), "the same skeleton does not restart sampling");
    }

    #[test]
    fn a_sampler_serves_only_its_own_shard_and_only_when_held() {
        // The responder-side rule. Answering for another index would let one validator's silence be papered over by a
        // peer's copy, which is exactly the proposer-self-report that DA sampling exists to remove.
        let hash = block_with_payload().hash();
        let mut s = Sampler::new(2);
        assert_eq!(s.serve(&hash, 2), None, "nothing held yet");
        s.hold(hash, vec![9, 9, 9]);
        assert_eq!(s.serve(&hash, 2), Some(vec![9, 9, 9]), "our own index, held");
        assert_eq!(s.serve(&hash, 5), None, "another validator's index is never answered from here");
    }

    #[test]
    fn the_whole_cell_recovers_a_dispersed_block_by_exchanging_shards() {
        // The property production depends on and the simulator could not previously express: every validator holds ONE
        // shard, and the cell recovers the block by request/response alone.
        let block = block_with_payload();
        let hash = block.hash();
        let shards = block.da_shards();
        let n = CellParams::FANO.n();

        let mut cell: Vec<Sampler> = (0..n).map(|i| Sampler::new(u8::try_from(i).unwrap())).collect();
        for (i, s) in cell.iter_mut().enumerate() {
            s.hold(hash, shards.get(i).cloned().expect("a shard per point"));
            assert!(s.begin(block.skeleton()));
        }

        // One exchange round: each validator asks for what it lacks, and whoever owns that index answers.
        for i in 0..n {
            let wanted = cell.get(i).map(|s| s.missing(&hash)).unwrap_or_default();
            for index in wanted {
                let Some(shard) = cell.get(usize::from(index)).and_then(|s| s.serve(&hash, index)) else { continue };
                if let Some(s) = cell.get_mut(i) {
                    s.accept(hash, index, shard);
                }
            }
        }
        for (i, s) in cell.iter().enumerate() {
            assert_eq!(s.in_flight(), 0, "validator {i} recovered the block and retired its pending entry");
        }
    }

    #[test]
    fn a_request_answered_before_its_peer_was_dispersed_is_recovered_by_the_retry() {
        // The race that deadlocked a live cell. Validator 0 asks first, while nobody else has been dispersed a shard
        // yet, so every answer is empty; the block must still come back due so a later sweep asks again. This is the
        // property the backoff schedule must not cost: it may make the second attempt *later*, never absent.
        let block = block_with_payload();
        let hash = block.hash();
        let shards = block.da_shards();
        let n = CellParams::FANO.n();
        let mut cell: Vec<Sampler> = (0..n).map(|i| Sampler::new(u8::try_from(i).unwrap())).collect();

        let (first, rest) = cell.split_first_mut().expect("a non-empty cell");
        first.hold(hash, shards.first().cloned().unwrap());
        assert!(first.begin(block.skeleton()));
        for index in first.missing(&hash) {
            let peer = rest.get(usize::from(index) - 1).expect("a peer per index above our own");
            assert!(peer.serve(&hash, index).is_none(), "peer {index} holds nothing yet");
        }
        assert_eq!(first.due().len(), 1, "the block is still outstanding, so the retry will ask again");

        // Dispersal lands late, and the retry now succeeds where the first attempt found nothing. The sweep after a
        // request is a wait, by construction — so drive sweeps until the schedule offers the block again, which is
        // exactly what the driver's tick loop does, and assert it does come back rather than assuming it.
        for (i, peer) in rest.iter_mut().enumerate() {
            peer.hold(hash, shards.get(i + 1).cloned().unwrap());
        }
        let retry = (0..RESAMPLE_MAX_INTERVAL).find_map(|_| Some(first.due()).filter(|d| !d.is_empty()));
        for (h, indices) in retry.expect("the schedule must offer an un-answered block again") {
            for index in indices {
                let Some(peer) = rest.get(usize::from(index) - 1) else { continue };
                let Some(shard) = peer.serve(&h, index) else { continue };
                first.accept(h, index, shard);
            }
        }
        assert_eq!(first.in_flight(), 0, "the retry recovered the block");
    }

    #[test]
    fn the_awaited_skeleton_survives_a_flood_of_later_proposals() {
        // The eviction that stranded a live cell. `pending` is bounded because its key is a remote-chosen block hash,
        // and eviction is by **insertion order** — so the oldest skeleton goes first. Under SSLE every line member
        // proposes, giving one skeleton per validator per round, and the block a cell converges on is round 0's
        // min-ticket winner: the oldest one there is. Later proposals that will never be chosen evict the one that was.
        //
        // The consequence is a loop rather than a delay. Once evicted the block leaves `outstanding`, so no shard is
        // ever requested for it again, and the validator waits forever on a body it is actively voting for. Measured
        // live as seven of seven validators reporting `await` at round 13 for a block none of them held.
        let awaited = Block::assemble([7u8; 32], 1, fanos_primitives::Epoch::ZERO, 0, Vec::new());
        let hash = awaited.hash();
        let mut s = Sampler::new(0);
        assert!(s.begin(awaited.skeleton()));
        s.retain_relevant(vec![hash]);

        // Two full caps' worth of later proposals — far past the point where insertion order would have discarded it.
        for n in 0..(PENDING_CAP * 2) {
            let mut parent = [7u8; 32];
            parent[0] = u8::try_from(n % 251).unwrap_or(0);
            parent[1] = u8::try_from(n / 251).unwrap_or(0);
            s.begin(Block::assemble(parent, 1, fanos_primitives::Epoch::ZERO, 0, Vec::new()).skeleton());
        }

        assert!(s.is_sampling(&hash), "the awaited skeleton was evicted by proposals nobody is waiting for");
        assert!(
            s.due().iter().any(|(h, _)| *h == hash),
            "the awaited block must stay outstanding, or no shard is ever requested for it again"
        );
        assert_eq!(s.proposer_of(&hash), Some(awaited.header.proposer), "and its proposer stays addressable");
    }

    /// The test that failed the first attempt at this, and the reason the fix is a rule rather than a bigger
    /// exemption: **several** blocks can matter at one height — the body awaited, the block locked on, a polka
    /// observed — and a flood must displace none of them. The single-entry `pin` this replaces could protect exactly
    /// one; with three, its insert-then-repair form evicted another that should have been kept, silently.
    #[test]
    fn a_flood_displaces_none_of_the_several_blocks_that_can_still_be_decided() {
        let keep: Vec<Block> = (0..3)
            .map(|i| {
                let mut parent = [0xEE; 32];
                parent[0] = i;
                Block::assemble(parent, 1, fanos_primitives::Epoch::ZERO, 0, Vec::new())
            })
            .collect();
        let mut s = Sampler::new(0);
        for b in &keep {
            assert!(s.begin(b.skeleton()));
        }
        s.retain_relevant(keep.iter().map(Block::hash).collect());

        for n in 0..(PENDING_CAP * 2) {
            let mut parent = [7u8; 32];
            parent[0] = u8::try_from(n % 251).unwrap_or(0);
            parent[1] = u8::try_from(n / 251).unwrap_or(0);
            s.begin(Block::assemble(parent, 1, fanos_primitives::Epoch::ZERO, 0, Vec::new()).skeleton());
        }
        for (i, b) in keep.iter().enumerate() {
            assert!(s.is_sampling(&b.hash()), "relevant block {i} was displaced by proposals nobody is waiting for");
        }
        assert!(s.in_flight() <= PENDING_CAP, "and the flood bound still holds");
    }

    #[test]
    fn relevance_protects_what_can_still_be_decided_and_not_the_cap() {
        // The pin must not become an unbounded exemption: the cap exists against a remote-chosen key, and one protected
        // entry is the whole concession. Everything else still evicts normally.
        let mut s = Sampler::new(0);
        let kept = Block::assemble([9u8; 32], 1, fanos_primitives::Epoch::ZERO, 0, Vec::new());
        assert!(s.begin(kept.skeleton()));
        s.retain_relevant(vec![kept.hash()]);
        let mut early = Vec::new();
        for n in 0..(PENDING_CAP * 2) {
            let mut parent = [9u8; 32];
            parent[0] = u8::try_from(n % 251).unwrap_or(0);
            parent[1] = u8::try_from(n / 251).unwrap_or(0);
            let b = Block::assemble(parent, 1, fanos_primitives::Epoch::ZERO, 0, Vec::new());
            s.begin(b.skeleton());
            if n < 4 {
                early.push(b.hash());
            }
        }
        assert!(s.is_sampling(&kept.hash()), "the relevant entry survives");
        assert!(early.iter().all(|h| !s.is_sampling(h)), "disposable entries still evict — the cap still bounds memory");
        assert!(s.in_flight() <= PENDING_CAP, "the map never exceeds its cap at all now that room is made first");
    }
}
