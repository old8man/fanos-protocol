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
use fanos_pqcrypto::sig::HYBRID_SIG_LEN;
use fanos_pqcrypto::{HybridSigSecret, HybridSignature, HybridVerifier};
use fanos_primitives::shamir::Share;
use fanos_primitives::{BeaconSeed, Epoch};

use crate::block::Block;
use crate::chain::Chain;
use crate::committee::{epoch_seal_line, leader, line_members};
use crate::params::CellParams;
use crate::state::StateMachine;
use crate::tx::{SealedTx, Transaction, TxCommit};
use crate::vote::{Certificate, Phase, SignedVote, Vote};

/// A backstop on how many `t`-subsets [`open_from_subset`] tries. The recorded shares of one transaction are
/// first-writer-wins per committee member, so their count never exceeds a line's size (`q + 1`) and the true
/// combination count is already bounded by the cell; this only guards against a pathological configuration.
const MAX_REVEAL_SUBSETS: usize = 4096;

/// Serialize a Shamir share as `x(1) ‖ y`.
fn share_to_bytes(s: &Share) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + s.y().len());
    out.push(s.x());
    out.extend_from_slice(s.y());
    out
}

/// Try to open `tx` from some `t`-subset of `shares` whose reconstructed key AEAD-authenticates (the Poly1305
/// tag is the validity oracle). Fast-paths the honest common case (all shares lie on the polynomial, one
/// reconstruct); otherwise searches `t`-subsets so a single Byzantine garbage share cannot block decryption.
/// `None` if no `t`-subset authenticates (below threshold, or the transaction is malformed).
// Indices `idx[k]` are combination positions in `0..shares.len()` by construction (see `next_combination`), so
// the slice accesses cannot go out of bounds.
#[allow(clippy::indexing_slicing)]
fn open_from_subset(tx: &SealedTx, shares: &[Share], t: usize) -> Option<Transaction> {
    if shares.len() < t {
        return None;
    }
    // Fast path: the whole set (honest case — every share is on the polynomial → correct key).
    if let Ok(txn) = tx.open(shares) {
        return Some(txn);
    }
    // Otherwise search t-subsets in lexicographic order for one that authenticates.
    let mut idx: Vec<usize> = (0..t).collect();
    for _ in 0..MAX_REVEAL_SUBSETS {
        let subset: Vec<Share> = idx.iter().map(|&i| shares[i].clone()).collect();
        if let Ok(txn) = tx.open(&subset) {
            return Some(txn);
        }
        if !next_combination(&mut idx, shares.len()) {
            return None;
        }
    }
    None
}

/// Advance `idx` (a strictly-increasing `t`-subset of `0..n`) to the next combination in lexicographic order.
/// Returns `false` once the final combination has been passed.
// `i` and `j` range within `0..idx.len()` (and `j >= 1` where `idx[j-1]` is read), so every access is in bounds.
#[allow(clippy::indexing_slicing)]
fn next_combination(idx: &mut [usize], n: usize) -> bool {
    let t = idx.len();
    if t == 0 || t > n {
        return false;
    }
    let mut i = t;
    while i > 0 {
        i -= 1;
        if idx[i] != i + n - t {
            idx[i] += 1;
            for j in i + 1..t {
                idx[j] = idx[j - 1] + 1;
            }
            return true;
        }
    }
    false
}

/// Deserialize a Shamir share from `x(1) ‖ y`, or `None` if empty.
fn share_from_bytes(bytes: &[u8]) -> Option<Share> {
    let (&x, y) = bytes.split_first()?;
    Some(Share::new(x, y.to_vec()))
}

/// A reveal: a sealing-committee member releasing its share opening for a finalized transaction, so the
/// transaction can be decrypted now that its order is fixed (spec §10.1 anti-MEV).
///
/// **Authenticated** (audit fix): the revealing member hybrid-PQ-signs `(commit ‖ member ‖ share)` under the
/// same key it votes with, and a receiver verifies the signature, pins the sender to the transaction's keyper
/// line, and pins `share.x` to the member's committee position before recording it — so no unprivileged party
/// can inject a forged share to poison reconstruction (censor a finalized transaction or fork executed state).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RevealMsg {
    /// The transaction commitment whose opening this reveals.
    pub commit: TxCommit,
    /// The revealing validator's index (for attribution / de-duplication).
    pub member: u8,
    /// The member's Shamir share bytes (`x ‖ y`).
    pub share: Vec<u8>,
    /// The member's hybrid-PQ signature over [`signable`](RevealMsg::signable).
    sig: Vec<u8>,
}

impl RevealMsg {
    /// The signed content: `commit(32) ‖ member(1) ‖ share`. Binds the share to its commitment and its author,
    /// so a signature under member `m`'s key attests "member `m` releases exactly this share for this tx."
    #[must_use]
    fn signable(commit: &TxCommit, member: u8, share: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(33 + share.len());
        out.extend_from_slice(commit);
        out.push(member);
        out.extend_from_slice(share);
        out
    }

    /// Build a reveal signed by the revealing member's hybrid signing key.
    #[must_use]
    pub fn signed(commit: TxCommit, member: u8, share: Vec<u8>, signer: &HybridSigSecret) -> Self {
        let sig = signer.sign(&Self::signable(&commit, member, &share)).to_bytes();
        Self { commit, member, share, sig }
    }

    /// Whether the reveal's signature verifies under `verifier` (which must be `member`'s verifying key).
    #[must_use]
    pub fn verify(&self, verifier: &HybridVerifier) -> bool {
        let Some(sig) = HybridSignature::from_bytes(&self.sig) else {
            return false;
        };
        verifier.verify(&Self::signable(&self.commit, self.member, &self.share), &sig)
    }

    /// Canonical bytes: `commit(32) ‖ member(1) ‖ sig(HYBRID_SIG_LEN) ‖ share` — the fixed-width signature
    /// precedes the trailing variable-length share so decoding is unambiguous.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33 + HYBRID_SIG_LEN + self.share.len());
        out.extend_from_slice(&self.commit);
        out.push(self.member);
        out.extend_from_slice(&self.sig);
        out.extend_from_slice(&self.share);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if too short.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let commit = bytes.get(..32)?.try_into().ok()?;
        let member = *bytes.get(32)?;
        let sig = bytes.get(33..33 + HYBRID_SIG_LEN)?.to_vec();
        let share = bytes.get(33 + HYBRID_SIG_LEN..)?.to_vec();
        Some(Self { commit, member, share, sig })
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
    // `reveals`: validated share openings, keyed by (commit, revealing member) — first-writer-wins per member,
    // so a member cannot overwrite another's slot nor change its own. `pending_reveals`: authenticated-but-not-
    // yet-validatable reveals that arrived before this validator finalized the block that names their tx
    // (buffered, then validated against the committee when the block enters the queue) — so a slower validator
    // does not drop the reveals it needs. `exec_queue`: finalized blocks awaiting decryption+execution.
    reveals: BTreeMap<TxCommit, BTreeMap<u8, Share>>,
    pending_reveals: BTreeMap<TxCommit, BTreeMap<u8, RevealMsg>>,
    exec_queue: Vec<Block>,
    // Commit certificates gathered for a height whose block body we have not yet received (an async scheduler
    // may deliver the CC before the proposal). We hold the CC and finalize the moment the body arrives, instead
    // of wedging the validator permanently at that height.
    pending_finalize: BTreeMap<u64, [u8; 32]>,
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
            pending_reveals: BTreeMap::new(),
            exec_queue: Vec::new(),
            pending_finalize: BTreeMap::new(),
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

    /// Submit a sealed transaction into this validator's mempool (a client's `SubmitTx`). A transaction that
    /// is not sealed to this epoch's beacon-chosen keyper line (wrong epoch, wrong line, or wrong committee
    /// size) is **rejected here**, so a malformed seal can never be ordered into a block (audit fix — see
    /// [`valid_seal`](Self::valid_seal)).
    pub fn submit(&mut self, tx: SealedTx) {
        if !self.valid_seal(&tx) {
            return;
        }
        // De-duplicate by commitment so a re-broadcast does not bloat the mempool.
        let commit = tx.commit();
        if self.mempool.iter().all(|t| t.commit() != commit) {
            self.mempool.push(tx);
        }
    }

    /// Whether a sealed transaction is bound to this epoch's **beacon-chosen keyper line** — the anti-MEV
    /// committee is *not* sender-choosable (`docs/design-taxis.md` §5): the transaction's epoch must be the
    /// current one, its committee line must equal [`epoch_seal_line`], and it must be sealed to a full line's
    /// worth of members. This is enforced both at [`submit`](Self::submit) and at [`on_propose`](Self::on_propose)
    /// so neither a client nor a Byzantine proposer can steer a transaction to a committee it controls, or seal
    /// to the wrong line to block decryption. (The KEM slots' binding to each member's *registered* key is not
    /// ciphertext-verifiable without opening; a slot sealed to a non-member key simply yields no honest share,
    /// which the keyper line's honest majority tolerates — see the module doc's liveness note.)
    #[must_use]
    fn valid_seal(&self, tx: &SealedTx) -> bool {
        tx.epoch == self.epoch
            && usize::from(tx.line) == epoch_seal_line(&self.seed, tx.epoch)
            && tx.member_count() == self.params.line_size()
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
        // Anti-MEV admission (audit fix): every included transaction must be sealed to this epoch's beacon
        // keyper line. A block carrying even one malformed seal is refused, so a Byzantine proposer cannot
        // slip in a transaction that no honest committee can ever decrypt (which would stall execution).
        if !block.sealed_txs.iter().all(|tx| self.valid_seal(tx)) {
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
        // If we already hold a commit certificate for this height+block but were waiting on the body (an async
        // scheduler delivered the CC first), finalize now instead of staying wedged (audit fix, HIGH 3).
        if self.pending_finalize.get(&height) == Some(&bh) {
            return self.finalize(bh);
        }
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
        let height = self.height();
        let Some(block) = self.proposals.get(&block_hash).cloned() else {
            // We hold a commit certificate but not the block body yet (an async scheduler delivered the CC
            // before the proposal). Remember the decision and finalize the instant on_propose delivers the
            // body — never wedge permanently at this height (audit fix, HIGH 3).
            self.pending_finalize.insert(height, block_hash);
            return Vec::new();
        };
        self.pending_finalize.remove(&height);
        let included: BTreeSet<TxCommit> = block.sealed_txs.iter().map(SealedTx::commit).collect();
        self.chain.finalize(block.header.clone());

        let mut out = alloc::vec![Output::Committed { height, block_hash }];
        out.extend(self.emit_reveals(&block));
        self.exec_queue.push(block.clone());
        // Validate any reveals that arrived early for this block's transactions, now that we hold the committee.
        self.drain_pending_reveals(&block);
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
    /// Each reveal is hybrid-PQ-**signed** so receivers can authenticate it (audit fix).
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
            self.reveals.entry(commit).or_default().entry(self.me).or_insert(share.clone());
            out.push(Output::Send(ConsensusMsg::Reveal(RevealMsg::signed(
                commit,
                self.me,
                share_to_bytes(&share),
                &self.signer,
            ))));
        }
        out
    }

    /// Record a received reveal and try to execute any now-decryptable finalized blocks. If the reveal's
    /// transaction is already finalized we validate it against the committee immediately; otherwise we buffer
    /// the authenticated reveal until we finalize that block (so a slower validator does not drop what it needs).
    fn on_reveal(&mut self, r: &RevealMsg) -> Vec<Output> {
        if self.sealed_tx_for(&r.commit).is_some() {
            self.validate_and_record(r);
        } else {
            // Buffer, first-writer-wins per member, so a flood cannot displace a genuine early reveal.
            self.pending_reveals.entry(r.commit).or_default().entry(r.member).or_insert_with(|| r.clone());
        }
        self.try_execute();
        Vec::new()
    }

    /// Find a finalized-but-unexecuted transaction by its commitment (searching the execution queue).
    fn sealed_tx_for(&self, commit: &TxCommit) -> Option<SealedTx> {
        self.exec_queue.iter().flat_map(|b| &b.sealed_txs).find(|tx| &tx.commit() == commit).cloned()
    }

    /// Validate a reveal against its transaction's keyper committee and record the share (first-writer-wins per
    /// member). Rejects, in order: an unknown transaction, a sender not on the transaction's line, a bad
    /// signature, a malformed share, or a share whose x-coordinate is not the sender's committee position — so
    /// a forged or misplaced share can never enter reconstruction. Returns whether a share was recorded.
    fn validate_and_record(&mut self, r: &RevealMsg) -> bool {
        let Some(tx) = self.sealed_tx_for(&r.commit) else {
            return false;
        };
        let members = line_members(usize::from(tx.line));
        let Some(pos) = members.iter().position(|&m| m == usize::from(r.member)) else {
            return false; // the sender is not on this transaction's keyper line
        };
        let Some(verifier) = self.verifiers.get(usize::from(r.member)) else {
            return false;
        };
        if !r.verify(verifier) {
            return false; // forged / unauthenticated reveal
        }
        let Some(share) = share_from_bytes(&r.share) else {
            return false;
        };
        // A member's share sits at the fixed Shamir x-coordinate of its committee position (x = pos + 1);
        // pinning it stops a member from writing into another member's slot.
        if usize::from(share.x()) != pos + 1 {
            return false;
        }
        self.reveals.entry(r.commit).or_default().entry(r.member).or_insert(share);
        true
    }

    /// Move any buffered early reveals for a just-finalized block's transactions into the validated set.
    fn drain_pending_reveals(&mut self, block: &Block) {
        for tx in &block.sealed_txs {
            if let Some(early) = self.pending_reveals.remove(&tx.commit()) {
                for r in early.values() {
                    self.validate_and_record(r);
                }
            }
        }
    }

    /// Execute finalized blocks from the front of the queue, in order, as soon as every transaction in a
    /// block has gathered its `t` share openings (anti-MEV: contents are revealed only after ordering).
    fn try_execute(&mut self) {
        let t = usize::from(self.params.seal_threshold());
        while let Some(block) = self.exec_queue.first().cloned() {
            let mut opened = Vec::new();
            let mut ready = true;
            for tx in &block.sealed_txs {
                let shares: Vec<Share> =
                    self.reveals.get(&tx.commit()).map(|m| m.values().cloned().collect()).unwrap_or_default();
                if shares.len() < t {
                    ready = false;
                    break;
                }
                // Open from a t-subset whose reconstructed key AEAD-authenticates — the Poly1305 tag is the
                // share-validity oracle. This tolerates a Byzantine committee member that reveals a validly-
                // signed but off-polynomial share: the subset excluding it still opens.
                match open_from_subset(tx, &shares, t) {
                    Some(txn) => opened.push(txn),
                    None => {
                        // No t-subset opens yet. A Byzantine share among the ≥ t present can hide a decryptable
                        // honest subset that needs one more reveal, so we do NOT give up while any committee
                        // member is still outstanding — we wait until every member has revealed. Only once all
                        // `member_count` shares are in and none opens is the transaction genuinely malformed
                        // and skipped (not stalled) — later transactions and blocks still execute.
                        if shares.len() < tx.member_count() {
                            ready = false;
                            break;
                        }
                    }
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
