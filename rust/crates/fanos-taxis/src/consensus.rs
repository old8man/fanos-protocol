//! The sans-I/O PBFT consensus engine (spec §10.1, `docs/design-taxis.md` §4).
//!
//! One [`ConsensusEngine`] is one validator. It is **sans-I/O**: it consumes [`Input`] events (a tick, a
//! received message, a timeout) and returns [`Output`] actions (messages to broadcast, a finalization
//! notice), holding no sockets or clocks — so the identical engine runs under the deterministic simulator
//! and a real transport, exactly like every other FANOS engine.
//!
//! The protocol per height (`docs/design-taxis.md` §4): the beacon-elected leader **proposes**; validators
//! that see an available, well-formed proposal broadcast a **PREPARE**; a `Q`-quorum of prepares is a
//! *prepared certificate* that locks the block and triggers a **COMMIT**; a `Q`-quorum of commits is a
//! *commit certificate* that **finalizes** the block. Finalization then triggers the anti-MEV **REVEAL**:
//! each sealing-committee member releases its share opening, and once `t` are in, the block's transactions
//! are decrypted and applied to the [`StateMachine`] in the committed order.
//!
//! Safety rests on the masking-quorum intersection ([`CellParams::is_safe`]): two `Q`-quorums share an
//! honest validator, and an honest validator never double-votes within a `(height, round, phase)`, so two
//! conflicting blocks cannot both gather a certificate. A validator additionally **locks** on the block it
//! commits to and refuses to prepare a conflicting block at the same height (Tendermint-style), closing the
//! cross-round hole; the sim exercises both.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use fanos_code::lrc::is_recoverable_fano;
use fanos_pqcrypto::kem::HybridKemSecret;
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier};
use fanos_primitives::shamir::Share;
use fanos_primitives::{BeaconSeed, Epoch};

use crate::block::Block;
use crate::chain::Chain;
use crate::committee::{leader, line_members};
use crate::params::CellParams;
use crate::state::StateMachine;
use crate::tx::{SealedTx, TxCommit};
use crate::vote::{Certificate, Phase, SignedVote, Vote};

/// Serialize a Shamir share as `x(1) ‖ y`.
fn share_to_bytes(s: &Share) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + s.y().len());
    out.push(s.x());
    out.extend_from_slice(s.y());
    out
}

/// Deserialize a Shamir share from `x(1) ‖ y`, or `None` if empty.
fn share_from_bytes(bytes: &[u8]) -> Option<Share> {
    let (&x, y) = bytes.split_first()?;
    Some(Share::new(x, y.to_vec()))
}

/// A reveal: a sealing-committee member releasing its share opening for a finalized transaction, so the
/// transaction can be decrypted now that its order is fixed (spec §10.1 anti-MEV).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RevealMsg {
    /// The transaction commitment whose opening this reveals.
    pub commit: TxCommit,
    /// The revealing validator's index (for attribution / de-duplication).
    pub member: u8,
    /// The member's Shamir share bytes (`x ‖ y`).
    pub share: Vec<u8>,
}

impl RevealMsg {
    /// Canonical bytes: `commit(32) ‖ member(1) ‖ share`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33 + self.share.len());
        out.extend_from_slice(&self.commit);
        out.push(self.member);
        out.extend_from_slice(&self.share);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if too short.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let commit = bytes.get(..32)?.try_into().ok()?;
        let member = *bytes.get(32)?;
        let share = bytes.get(33..)?.to_vec();
        Some(Self { commit, member, share })
    }
}

/// A consensus wire message — the payload of a TAXIS App-overlay frame (spec §7.2 `App = 0x70`; see
/// [`crate::wire`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ConsensusMsg {
    /// A leader's block proposal.
    Propose(Block),
    /// A prepare or commit vote.
    Vote(SignedVote),
    /// A sealing member's post-finality share opening.
    Reveal(RevealMsg),
}

impl ConsensusMsg {
    /// Canonical bytes: a 1-byte variant tag then the variant's body, which runs to the end of the message
    /// (the frame layer delimits the whole message, so no inner length prefix is needed).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Propose(b) => {
                out.push(0);
                out.extend_from_slice(&b.to_bytes());
            }
            Self::Vote(sv) => {
                out.push(1);
                out.extend_from_slice(&sv.to_bytes());
            }
            Self::Reveal(r) => {
                out.push(2);
                out.extend_from_slice(&r.to_bytes());
            }
        }
        out
    }

    /// Decode a message from [`to_bytes`](Self::to_bytes), or `None` if the tag or body is malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&tag, body) = bytes.split_first()?;
        match tag {
            0 => Some(Self::Propose(Block::from_bytes(body)?)),
            1 => Some(Self::Vote(SignedVote::from_bytes(body)?)),
            2 => Some(Self::Reveal(RevealMsg::from_bytes(body)?)),
            _ => None,
        }
    }
}

/// An event fed to the engine.
pub enum Input {
    /// Drive the engine — propose if this validator is the current leader.
    Tick,
    /// A proposal received off the wire, together with this validator's DA availability sample `present`
    /// (bit `p` set ⇒ point `p`'s payload shard is retrievable network-wide). A withholding proposer leaves
    /// too few bits set, so the payload is unavailable and the validator withholds PREPARE.
    Propose {
        /// The proposed block.
        block: Block,
        /// The DA availability bitmask sampled from the network.
        present: u8,
    },
    /// A vote received off the wire.
    Vote(SignedVote),
    /// A reveal received off the wire.
    Reveal(RevealMsg),
    /// The round timer fired (the proposer took too long) — advance the round and re-elect a leader.
    Timeout,
}

/// An action the engine asks its driver to take.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Output {
    /// Broadcast this message to all validators (including, in the sim, back to the sender).
    Send(ConsensusMsg),
    /// A block finalized — the ledger extended to `height` with `block_hash`.
    Committed {
        /// The finalized height.
        height: u64,
        /// The finalized block hash.
        block_hash: [u8; 32],
    },
}

/// One validator's sans-I/O consensus engine over a state machine `S`.
pub struct ConsensusEngine<S: StateMachine> {
    params: CellParams,
    me: u8,
    signer: HybridSigSecret,
    kem_secret: HybridKemSecret,
    verifiers: Vec<HybridVerifier>,
    seed: BeaconSeed,
    epoch: Epoch,
    round: u32,
    chain: Chain<S>,
    mempool: Vec<SealedTx>,
    // Per-height working state (reset on finalization).
    proposals: BTreeMap<[u8; 32], Block>,
    proposed_round: Option<u32>,
    prepares: Vec<SignedVote>,
    commits: Vec<SignedVote>,
    sent_prepare: BTreeSet<u32>,
    sent_commit: BTreeSet<u32>,
    locked_block: Option<[u8; 32]>,
    // Anti-MEV reveal collection + execution queue.
    reveals: BTreeMap<TxCommit, BTreeMap<u8, Share>>,
    exec_queue: Vec<Block>,
}

impl<S: StateMachine> ConsensusEngine<S> {
    /// Build a validator's engine. `me` is its validator index; `verifiers[i]` is validator `i`'s signature
    /// key; `seed` the epoch beacon (leader schedule); `genesis_state` the funded genesis ledger.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        params: CellParams,
        me: u8,
        signer: HybridSigSecret,
        kem_secret: HybridKemSecret,
        verifiers: Vec<HybridVerifier>,
        seed: BeaconSeed,
        epoch: Epoch,
        genesis_state: S,
    ) -> Self {
        Self {
            params,
            me,
            signer,
            kem_secret,
            verifiers,
            seed,
            epoch,
            round: 0,
            chain: Chain::new(genesis_state),
            mempool: Vec::new(),
            proposals: BTreeMap::new(),
            proposed_round: None,
            prepares: Vec::new(),
            commits: Vec::new(),
            sent_prepare: BTreeSet::new(),
            sent_commit: BTreeSet::new(),
            locked_block: None,
            reveals: BTreeMap::new(),
            exec_queue: Vec::new(),
        }
    }

    /// The height currently being decided (the chain's next height).
    #[must_use]
    pub fn height(&self) -> u64 {
        self.chain.next_height()
    }

    /// The current round within the height.
    #[must_use]
    pub fn round(&self) -> u32 {
        self.round
    }

    /// This validator's index.
    #[must_use]
    pub fn me(&self) -> u8 {
        self.me
    }

    /// The finalized chain (its head, height, and executed state).
    #[must_use]
    pub fn chain(&self) -> &Chain<S> {
        &self.chain
    }

    /// Submit a sealed transaction into this validator's mempool (a client's `SubmitTx`).
    pub fn submit(&mut self, tx: SealedTx) {
        // De-duplicate by commitment so a re-broadcast does not bloat the mempool.
        let commit = tx.commit();
        if self.mempool.iter().all(|t| t.commit() != commit) {
            self.mempool.push(tx);
        }
    }

    /// Step the engine on one input, returning the actions to take.
    pub fn step(&mut self, input: Input) -> Vec<Output> {
        match input {
            Input::Tick => self.maybe_propose(),
            Input::Propose { block, present } => self.on_propose(block, present),
            Input::Vote(sv) => self.accept_vote(sv),
            Input::Reveal(r) => self.on_reveal(&r),
            Input::Timeout => self.on_timeout(),
        }
    }

    /// Propose a block if this validator is the current-round leader and has not yet proposed this round.
    fn maybe_propose(&mut self) -> Vec<Output> {
        let height = self.height();
        if leader(&self.seed, height, self.round) as u8 != self.me {
            return Vec::new();
        }
        if self.proposed_round == Some(self.round) {
            return Vec::new();
        }
        self.proposed_round = Some(self.round);
        // Order the mempool blindly by commitment (the proposer never sees contents — anti-MEV).
        let mut sealed = self.mempool.clone();
        sealed.sort_by_key(SealedTx::commit);
        let block = Block::assemble(self.chain.head(), height, self.epoch, self.me, sealed);
        // The proposer's own proposal is delivered back to it by the driver, so it prepares like everyone
        // else; here it only broadcasts.
        alloc::vec![Output::Send(ConsensusMsg::Propose(block))]
    }

    /// Validate a proposal and, if it is available and well-formed, prepare it.
    fn on_propose(&mut self, block: Block, present: u8) -> Vec<Output> {
        let height = self.height();
        let bh = block.hash();
        // Structural + leader + link checks.
        let correct_leader = leader(&self.seed, height, self.round) as u8 == block.header.proposer;
        let links = block.header.height == height
            && block.header.parent == self.chain.head()
            && block.header.epoch == self.epoch;
        if !correct_leader || !links || !block.verify_structure() {
            return Vec::new();
        }
        // Data-availability gate (spec §L4.3 / §10.1): the payload must be retrievable. An unavailable
        // payload (a withholding proposer) has too few shards present and fails to be recoverable.
        let missing = (!present) & 0x7F;
        if !is_recoverable_fano(missing) {
            return Vec::new();
        }
        // Remember the (valid, available) block body so we can finalize it later even if a conflicting
        // proposal arrives afterwards (equivocation) — keyed by hash, never overwritten by a different block.
        self.proposals.entry(bh).or_insert(block);
        // Safety lock: never prepare a block conflicting with the one we are locked on this height.
        if let Some(locked) = self.locked_block
            && locked != bh
        {
            return Vec::new();
        }
        if self.sent_prepare.contains(&self.round) {
            return Vec::new();
        }
        self.sent_prepare.insert(self.round);
        let vote = Vote { height, round: self.round, block_hash: bh, phase: Phase::Prepare, voter: self.me };
        let sv = SignedVote::sign(vote, &self.signer);
        let mut out = self.accept_vote(sv.clone());
        out.push(Output::Send(ConsensusMsg::Vote(sv)));
        out
    }

    /// Ingest a vote, store it (de-duplicated), and drive the phase transitions it may complete.
    fn accept_vote(&mut self, sv: SignedVote) -> Vec<Output> {
        let height = self.height();
        let v = sv.vote;
        if v.height != height {
            return Vec::new(); // stale or future height
        }
        let Some(verifier) = self.verifiers.get(usize::from(v.voter)) else {
            return Vec::new();
        };
        if !sv.verify(verifier) {
            return Vec::new(); // bad / forged signature
        }
        match v.phase {
            Phase::Prepare => {
                self.store_vote(sv);
                self.check_prepared(v.block_hash, v.round)
            }
            Phase::Commit => {
                self.store_vote(sv);
                self.check_committed(v.block_hash)
            }
        }
    }

    /// Store a vote in its phase bucket unless an identical (voter, phase, round, block) vote is already
    /// present (idempotent under re-broadcast).
    fn store_vote(&mut self, sv: SignedVote) {
        let bucket = match sv.vote.phase {
            Phase::Prepare => &mut self.prepares,
            Phase::Commit => &mut self.commits,
        };
        let v = sv.vote;
        if bucket.iter().all(|e| {
            !(e.vote.voter == v.voter
                && e.vote.round == v.round
                && e.vote.block_hash == v.block_hash)
        }) {
            bucket.push(sv);
        }
    }

    /// If a prepared certificate exists for `block_hash` at `round` and we have not yet committed this round,
    /// lock the block and broadcast a commit vote.
    fn check_prepared(&mut self, block_hash: [u8; 32], round: u32) -> Vec<Output> {
        if round != self.round || self.sent_commit.contains(&self.round) {
            return Vec::new();
        }
        let cert = self.collect_cert(Phase::Prepare, block_hash);
        if !cert.verify(self.params.quorum, &self.verifiers) {
            return Vec::new();
        }
        // Prepared: lock the block and commit to it.
        self.locked_block = Some(block_hash);
        self.sent_commit.insert(self.round);
        let vote =
            Vote { height: self.height(), round: self.round, block_hash, phase: Phase::Commit, voter: self.me };
        let sv = SignedVote::sign(vote, &self.signer);
        let mut out = self.accept_vote(sv.clone());
        out.push(Output::Send(ConsensusMsg::Vote(sv)));
        out
    }

    /// If a commit certificate exists for `block_hash`, finalize the block.
    fn check_committed(&mut self, block_hash: [u8; 32]) -> Vec<Output> {
        let cert = self.collect_cert(Phase::Commit, block_hash);
        if !cert.verify(self.params.quorum, &self.verifiers) {
            return Vec::new();
        }
        self.finalize(block_hash)
    }

    /// Collect the distinct, current-height/round votes for `(phase, block_hash)` into a certificate
    /// candidate (one vote per voter; the caller checks the quorum with [`Certificate::verify`]).
    fn collect_cert(&self, phase: Phase, block_hash: [u8; 32]) -> Certificate {
        let height = self.height();
        let round = self.round;
        let src = match phase {
            Phase::Prepare => &self.prepares,
            Phase::Commit => &self.commits,
        };
        let mut seen = alloc::vec![false; self.verifiers.len()];
        let mut votes = Vec::new();
        for sv in src {
            let v = &sv.vote;
            if v.phase == phase
                && v.height == height
                && v.round == round
                && v.block_hash == block_hash
                && let Some(slot) = seen.get_mut(usize::from(v.voter))
                && !*slot
            {
                *slot = true;
                votes.push(sv.clone());
            }
        }
        Certificate { phase, height, round, block_hash, votes }
    }

    /// Finalize the block named by `block_hash`: extend the chain, emit the anti-MEV reveals for this
    /// validator's shares, queue execution, and reset per-height state for the next height.
    fn finalize(&mut self, block_hash: [u8; 32]) -> Vec<Output> {
        let Some(block) = self.proposals.get(&block_hash).cloned() else {
            // We do not hold the block body (never saw a valid proposal for it) — cannot execute; ignore
            // (another honest validator that holds it finalizes identically). Safe: the ordering is agreed.
            return Vec::new();
        };
        let height = block.header.height;
        let included: BTreeSet<TxCommit> = block.sealed_txs.iter().map(SealedTx::commit).collect();
        self.chain.finalize(block.header.clone());

        let mut out = alloc::vec![Output::Committed { height, block_hash }];
        out.extend(self.emit_reveals(&block));
        self.exec_queue.push(block);
        self.try_execute();

        // Drop included transactions from the mempool and reset the per-height working state.
        self.mempool.retain(|t| !included.contains(&t.commit()));
        self.round = 0;
        self.proposals.clear();
        self.proposed_round = None;
        self.prepares.clear();
        self.commits.clear();
        self.sent_prepare.clear();
        self.sent_commit.clear();
        self.locked_block = None;
        out
    }

    /// Emit this validator's share openings for every transaction in a just-finalized block it helped seal.
    fn emit_reveals(&mut self, block: &Block) -> Vec<Output> {
        let mut out = Vec::new();
        for tx in &block.sealed_txs {
            let members = line_members(usize::from(tx.line));
            let Some(pos) = members.iter().position(|&m| m == usize::from(self.me)) else {
                continue; // not on this transaction's sealing committee
            };
            let Some(share) = tx.member_share(pos, &self.kem_secret) else {
                continue; // (should not happen for a genuine committee member)
            };
            let commit = tx.commit();
            self.reveals.entry(commit).or_default().insert(share.x(), share.clone());
            out.push(Output::Send(ConsensusMsg::Reveal(RevealMsg {
                commit,
                member: self.me,
                share: share_to_bytes(&share),
            })));
        }
        out
    }

    /// Record a received reveal and try to execute any now-decryptable finalized blocks.
    fn on_reveal(&mut self, r: &RevealMsg) -> Vec<Output> {
        if let Some(share) = share_from_bytes(&r.share) {
            self.reveals.entry(r.commit).or_default().insert(share.x(), share);
        }
        self.try_execute();
        Vec::new()
    }

    /// Execute finalized blocks from the front of the queue, in order, as soon as every transaction in a
    /// block has gathered its `t` share openings (anti-MEV: contents are revealed only after ordering).
    fn try_execute(&mut self) {
        let t = usize::from(self.params.seal_threshold());
        while let Some(block) = self.exec_queue.first().cloned() {
            let mut opened = Vec::new();
            let mut ready = true;
            for tx in &block.sealed_txs {
                let commit = tx.commit();
                let shares: Vec<Share> =
                    self.reveals.get(&commit).map(|m| m.values().cloned().collect()).unwrap_or_default();
                if shares.len() < t {
                    ready = false;
                    break;
                }
                // A tx with ≥ t openings that still fails to decrypt (malformed shares) is skipped, not
                // stalled — the block's other transactions and later blocks still execute.
                if let Ok(txn) = tx.open(&shares) {
                    opened.push(txn);
                }
            }
            if !ready {
                break;
            }
            self.exec_queue.remove(0);
            for txn in &opened {
                self.chain.execute(txn);
            }
        }
    }

    /// Advance the round (proposer timeout): re-elect a leader and clear this round's proposal/prepare state.
    /// Locks and committed-block state persist across rounds (safety); votes are round-tagged so stale-round
    /// votes never form a current-round certificate.
    fn on_timeout(&mut self) -> Vec<Output> {
        self.round = self.round.saturating_add(1);
        // Proposals already seen this height stay valid bodies (same parent/height); only the round advances.
        // A fresh round may re-elect this validator as leader; `proposed_round` is compared against the new
        // round, so no reset is needed for it to propose again.
        self.maybe_propose()
    }
}
