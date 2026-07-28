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

/// A skeleton awaiting reconstruction: the shards gathered so far, this node's own plus those sampled from peers.
struct Pending {
    skeleton: Block,
    shards: Box<DaShards>,
}

/// One validator's data-availability sampling state.
pub struct Sampler {
    /// This validator's index, so a request for someone else's shard is not answered from here.
    me: u8,
    /// This validator's own shard for recent blocks, served on request.
    held: BoundedMap<[u8; 32], Vec<u8>>,
    /// Skeletons whose payload is still being sampled, keyed by block hash.
    pending: BoundedMap<[u8; 32], Pending>,
    /// The one skeleton eviction must not take — see [`pin`](Sampler::pin).
    pinned: Option<[u8; 32]>,
}

impl Sampler {
    /// A sampler for the validator at index `me`.
    #[must_use]
    pub fn new(me: u8) -> Self {
        Self { me, held: BoundedMap::new(HELD_CAP), pending: BoundedMap::new(PENDING_CAP), pinned: None }
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
        if let Some((evicted, victim)) = self.pending.insert(hash, Pending { skeleton, shards })
            && self.pinned == Some(evicted)
        {
            // Evicting the one block this validator is stuck on would strand it: it leaves `outstanding`, so no shard
            // is ever requested for it again. Put it back — the re-insert takes the next-oldest instead, which is by
            // construction a skeleton nobody is waiting for. See [`pin`](Self::pin).
            self.pending.insert(evicted, victim);
        }
        true
    }

    /// Protect one skeleton from eviction: the block this validator is **stuck waiting for**, or `None`.
    ///
    /// [`PENDING_CAP`] bounds this map because its key is a remote-chosen block hash, and eviction is by insertion
    /// order — which is exactly wrong for the block that matters. Under SSLE every line member proposes, so a height
    /// costs one skeleton per validator per round; a seven-validator cell overruns a 64-entry map in nine rounds, and
    /// the **first** entry discarded is the earliest — typically round 0's min-ticket winner, the block the cell
    /// actually converged on. Later proposals that will never be chosen push out the one that was.
    ///
    /// The effect is not a slow recovery but a loop: once evicted the block leaves [`outstanding`](Self::outstanding),
    /// so no shard is requested for it; the driver notices the validator is still waiting and re-fetches the skeleton;
    /// the next round's proposals evict it again. Measured live as every validator in a cell reporting `await` at round
    /// 13 for a body none of them held.
    ///
    /// Pinning is sound because the pinned entry is the one the engine has *already committed to needing*
    /// (`ConsensusEngine::awaited_body`), and it is a single entry: the flood defence the cap exists for is untouched.
    pub fn pin(&mut self, block: Option<[u8; 32]>) {
        self.pinned = block;
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

    /// Every block still being sampled, paired with the shard indices it is missing — one sweep for a retry tick.
    ///
    /// Retrying matters more than it looks: a replica requests a shard the moment a skeleton arrives, but the proposer
    /// disperses peer by peer, so the request routinely reaches a peer *before* that peer has been given its own shard.
    /// The peer holds nothing, answers nothing, and without a retry the requester waits forever for a shard its peer
    /// has held all along. One proposal in flight loses that race sometimes; N racing proposals lose it reliably.
    #[must_use]
    pub fn outstanding(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.pending.iter().map(|(&h, _)| (h, self.missing(&h))).filter(|(_, m)| !m.is_empty()).collect()
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
            *slot = Some(shard);
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
        let n = CellParams::FANO.n;

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
        // yet, so every answer is empty; `outstanding` must still report the block so the next tick asks again.
        let block = block_with_payload();
        let hash = block.hash();
        let shards = block.da_shards();
        let n = CellParams::FANO.n;
        let mut cell: Vec<Sampler> = (0..n).map(|i| Sampler::new(u8::try_from(i).unwrap())).collect();

        let (first, rest) = cell.split_first_mut().expect("a non-empty cell");
        first.hold(hash, shards.first().cloned().unwrap());
        assert!(first.begin(block.skeleton()));
        for index in first.missing(&hash) {
            let peer = rest.get(usize::from(index) - 1).expect("a peer per index above our own");
            assert!(peer.serve(&hash, index).is_none(), "peer {index} holds nothing yet");
        }
        assert_eq!(first.outstanding().len(), 1, "the block is still outstanding, so the retry will ask again");

        // Dispersal lands late, and the retry now succeeds where the first attempt found nothing.
        for (i, peer) in rest.iter_mut().enumerate() {
            peer.hold(hash, shards.get(i + 1).cloned().unwrap());
        }
        for (h, indices) in first.outstanding() {
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
        s.pin(Some(hash));

        // Two full caps' worth of later proposals — far past the point where insertion order would have discarded it.
        for n in 0..(PENDING_CAP * 2) {
            let mut parent = [7u8; 32];
            parent[0] = u8::try_from(n % 251).unwrap_or(0);
            parent[1] = u8::try_from(n / 251).unwrap_or(0);
            s.begin(Block::assemble(parent, 1, fanos_primitives::Epoch::ZERO, 0, Vec::new()).skeleton());
        }

        assert!(s.is_sampling(&hash), "the awaited skeleton was evicted by proposals nobody is waiting for");
        assert!(
            s.outstanding().iter().any(|(h, _)| *h == hash),
            "the awaited block must stay outstanding, or no shard is ever requested for it again"
        );
        assert_eq!(s.proposer_of(&hash), Some(awaited.header.proposer), "and its proposer stays addressable");
    }

    #[test]
    fn pinning_protects_exactly_one_entry_and_not_the_cap() {
        // The pin must not become an unbounded exemption: the cap exists against a remote-chosen key, and one protected
        // entry is the whole concession. Everything else still evicts normally.
        let mut s = Sampler::new(0);
        let pinned = Block::assemble([9u8; 32], 1, fanos_primitives::Epoch::ZERO, 0, Vec::new());
        assert!(s.begin(pinned.skeleton()));
        s.pin(Some(pinned.hash()));
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
        assert!(s.is_sampling(&pinned.hash()), "the pinned entry survives");
        assert!(early.iter().all(|h| !s.is_sampling(h)), "unpinned entries still evict — the cap still bounds memory");
        assert!(s.in_flight() <= PENDING_CAP + 1, "the map never exceeds its cap by more than the pinned entry");
    }
}
