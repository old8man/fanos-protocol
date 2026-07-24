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

use fanos_code::erasure;
use fanos_pqcrypto::kem::HybridKemSecret;
use fanos_pqcrypto::sig::HYBRID_SIG_LEN;
use fanos_pqcrypto::{HybridSigSecret, HybridSignature, HybridVerifier};
use fanos_primitives::shamir::Share;
use fanos_primitives::{BeaconSeed, Epoch, codec};

use fanos_vrf::pqvrf::MerkleVrfSecret;

use crate::block::{Block, LeaderWitness};
use crate::chain::Chain;
use crate::checkpoint::{ExecCertificate, ExecVote};
use crate::committee::{
    epoch_seal_line, is_line_member, leader, leader_line, line_members, verify_leader_ticket,
};
use crate::incentive::{detect_equivocation, distribute, SlashEvidence};
use crate::params::CellParams;
use crate::state::StateMachine;
use crate::tx::{SealedTx, Transaction, TxCommit};
use crate::vote::{Certificate, Phase, SignedVote, Vote};

/// A backstop on how many `t`-subsets [`open_from_subset`] tries. The recorded shares of one transaction are
/// first-writer-wins per committee member, so their count never exceeds a line's size (`q + 1`) and the true
/// combination count is already bounded by the cell; this only guards against a pathological configuration.
const MAX_REVEAL_SUBSETS: usize = 4096;

/// The most distinct not-yet-finalized transactions for which authenticated-but-unvalidatable reveals are
/// buffered ([`ConsensusEngine::pending_reveals`]). Reveals are only buffered here after a signature check
/// binds them to a real committee member (audit B1), and this cap bounds the memory even a Byzantine member
/// can force by streaming distinct commits: at most `MAX_PENDING_REVEAL_COMMITS × committee` reveal messages.
/// The oldest-keyed commit is evicted past this; a genuine buffered reveal is drained the moment its block
/// finalizes (well within the reveal window), so eviction almost never touches one.
const MAX_PENDING_REVEAL_COMMITS: usize = 4096;

/// The **reveal window** (in finalized heights): how long a finalized block's execution waits for the anti-MEV
/// reveals before dropping any still-undecryptable transaction. This is the **deterministic clock** that makes
/// execution converge without coupling ordering to reveal timing: a transaction still short of `t` valid
/// openings once consensus has finalized `REVEAL_WINDOW` heights past its block is dropped — a decision keyed to
/// the *finalized height* (identical on every validator), not to local gossip arrival. Under the keyper-line
/// liveness assumption (≥ `t` honest members reveal, and reveals are broadcast on finalization) every
/// well-formed transaction is decrypted well within the window, so only genuinely undecryptable ones (a seal to
/// non-committee keys, or a withholding keyper majority) are dropped; the execution checkpoint
/// ([`crate::checkpoint`]) catches any residual divergence. A liveness parameter (like the round timeout),
/// network-agreed, not a security threshold.
pub const REVEAL_WINDOW: u64 = 4;

/// The DA shards a validator sampled for a proposal: `shards[p]` is point `p`'s payload shard, or `None` if it
/// did not answer. The engine reconstructs the payload from these and checks it against `da_commit`, so
/// availability is *verified* in-engine rather than trusted as a driver-supplied bit.
pub type DaShards = [Option<Vec<u8>>; erasure::N];

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
    /// A validator's execution attestation `(height, state_root)` — the executed-state checkpoint.
    ExecVote(ExecVote),
    /// A lagging node's **catch-up request** — "I am at `have_height`; offer me a newer certified checkpoint."
    /// (audit §3.9 / §4 — a node that missed heights re-enters instead of wedging; `crate::sync` state-sync.)
    SyncReq {
        /// The requester's current next-height, so a peer offers only a strictly-newer checkpoint.
        have_height: u64,
    },
    /// A peer's **catch-up response**: a quorum-signed [`ExecCertificate`], the block `head` hash at its height,
    /// and the full serialized state at that height. All untrusted transport — the receiver verifies the
    /// certificate against the committee keys and the restored `state_root()` against the certified root.
    SyncResp {
        /// The certificate proving `(height, state_root)` under a `Q`-quorum of the fixed committee.
        cert: ExecCertificate,
        /// The block hash at `cert.height` (so the receiver's next proposal links to the right parent).
        head: [u8; 32],
        /// The full state at `cert.height`, per [`StateMachine::snapshot`](crate::state::StateMachine::snapshot).
        snapshot: Vec<u8>,
    },
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
            Self::ExecVote(v) => {
                out.push(3);
                out.extend_from_slice(&v.to_bytes());
            }
            Self::SyncReq { have_height } => {
                out.push(4);
                codec::put_u64(&mut out, *have_height);
            }
            Self::SyncResp { cert, head, snapshot } => {
                out.push(5);
                // Length-prefix the variable-width certificate; `head` is fixed 32; the snapshot runs to the end.
                codec::put_var_bytes(&mut out, &cert.to_bytes());
                out.extend_from_slice(head);
                out.extend_from_slice(snapshot);
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
            3 => Some(Self::ExecVote(ExecVote::from_bytes(body)?)),
            4 => {
                let mut r = codec::Reader::new(body);
                let have_height = r.u64()?;
                r.finish()?;
                Some(Self::SyncReq { have_height })
            }
            5 => {
                let mut r = codec::Reader::new(body);
                let cert = ExecCertificate::from_bytes(r.var_bytes()?)?;
                let head = r.array::<32>()?;
                let snapshot = r.rest().to_vec();
                Some(Self::SyncResp { cert, head, snapshot })
            }
            _ => None,
        }
    }
}

/// An event fed to the engine.
pub enum Input {
    /// Drive the engine — propose if this validator is the current leader.
    Tick,
    /// A proposal received off the wire, together with the payload **shards this validator sampled** from the
    /// network ([`DaShards`]: `shards[p]` = point `p`'s shard, or `None` if it did not answer). The engine
    /// reconstructs the payload from them and checks it against the block's `da_commit` in-engine — a withholding
    /// proposer leaves too few shards to reconstruct (or they fail the commitment), and the validator withholds
    /// PREPARE. This is verified, not a trusted availability bit.
    Propose {
        /// The proposed block.
        block: Block,
        /// The DA shards this validator sampled (`None` = the point did not answer). Boxed so that the
        /// far more frequent small inputs (votes, reveals) stay cheap to move — a proposal is rare.
        shards: Box<DaShards>,
    },
    /// A vote received off the wire.
    Vote(SignedVote),
    /// A reveal received off the wire.
    Reveal(RevealMsg),
    /// An execution attestation received off the wire.
    ExecVote(ExecVote),
    /// The round timer fired (the proposer took too long) — advance the round and re-elect a leader.
    Timeout,
    /// A catch-up request from validator `from` (the authenticated transport source) at `have_height`.
    SyncReq {
        /// The requesting validator's index (the driver fills this from the authenticated source coordinate,
        /// so a response is directed to the real sender, not a spoofable field).
        from: u8,
        /// The requester's current next-height.
        have_height: u64,
    },
    /// A catch-up response received off the wire (verified + adopted only if it beats our height).
    SyncResp {
        /// The offered certificate.
        cert: ExecCertificate,
        /// The block head hash at `cert.height`.
        head: [u8; 32],
        /// The serialized state at `cert.height`.
        snapshot: Vec<u8>,
    },
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
    /// A validator was caught **equivocating** — a self-contained, verifiable proof (two conflicting signed
    /// votes at one slot). The driver applies the slash and can gossip the evidence; anyone can re-verify it.
    Slash(SlashEvidence),
    /// The finalized block's reward split among its commit-certificate signers — `(validator, amount)` pairs
    /// (`incentive::distribute`). The driver credits each validator; this operationalizes the reward `R = F/Q`
    /// the Nash equilibrium assumes (symmetric to [`Slash`](Output::Slash)).
    Reward(Vec<(u8, u64)>),
    /// Send `msg` **point-to-point** to validator `to` (not a broadcast) — used to direct a catch-up response
    /// (`SyncResp`, a large state snapshot) back to the one requester, rather than flooding the cell.
    SendTo {
        /// The destination validator index.
        to: u8,
        /// The message to send.
        msg: ConsensusMsg,
    },
}

/// The **secret-leader sortition** configuration a validator runs in round 0 (SSLE, spec §10.1,
/// `docs/design-taxis.md` §4.2). When present, round 0 is the min-ticket lottery over the elected line
/// ([`committee::leader_ticket`](crate::committee::leader_ticket)); when absent the engine uses the public
/// deterministic [`leader`] for round 0 as well — the pre-SSLE protocol, kept as a safe default.
///
/// The VRF domain is **bounded and re-registered per epoch**: `secret` proves this validator's ticket at
/// index `height − base`, and `roots[i]` is validator `i`'s pre-registered root (verified with the same
/// index). A validator registers its root strictly *before* the epoch beacon it will be used with — the
/// anti-grinding fence — which FANOS's epoch clock provides.
pub struct Sortition {
    /// This validator's Merkle-VRF secret (proves its own ticket witness).
    secret: MerkleVrfSecret,
    /// Validator `i`'s pre-registered Merkle-VRF root (verifies its ticket witness); indexed like `verifiers`.
    roots: Vec<[u8; 32]>,
    /// The registered tree height (domain `2^height`); all roots share it (a per-epoch protocol constant).
    height: u32,
    /// The chain height at VRF index 0 — the current registration's base, so `index = height − base`.
    base: u64,
}

impl Sortition {
    /// The VRF domain index for chain `height`: `height − base`, or `None` if `height` is below the base or
    /// beyond this registration's `2^height` domain (the epoch must re-register before that — a graceful
    /// round-0 abstention, never a panic).
    fn index_for(&self, height: u64) -> Option<u64> {
        let idx = height.checked_sub(self.base)?;
        (idx < (1u64 << self.height)).then_some(idx)
    }
}

/// How long a replica waits (in driver ticks) to collect the elected line's proposals before preparing the
/// lowest-ticket one, when it has *not* already seen all line members propose. The all-members early-exit
/// makes the happy path prepare with no added tick; this Δ_prio only binds when a member is slow/down, and
/// is deliberately short (one tick) so a single silent line member costs one tick, not a full round timeout.
const COLLECT_WINDOW_TICKS: u32 = 1;

/// One validator's sans-I/O consensus engine over a state machine `S`.
pub struct ConsensusEngine<S: StateMachine> {
    params: CellParams,
    me: u8,
    signer: HybridSigSecret,
    kem_secret: HybridKemSecret,
    verifiers: Vec<HybridVerifier>,
    // The on-chain anti-MEV decryption-key commitment (`crate::keyper`): the agreed hash of every validator's
    // self-certified KEM decryption key. An agreed genesis constant alongside `verifiers` and `seed`; a
    // validator only serves clients a keyper registry that both verifies against `verifiers` and matches this.
    keyper_commit: [u8; 32],
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
    // ── Secret-leader sortition (SSLE, round 0 only; `None` ⇒ the public-leader default) ──
    // The registered VRF config (my secret + all validators' roots). Set by `enable_sortition`.
    sortition: Option<Sortition>,
    // Round-0 collected proposals at the current height: proposer index → (ticket, block_hash). Every valid
    // line-member proposal is buffered here (all-propose); the LOWEST ticket is prepared when the collection
    // window closes. Reset per height.
    round0_tickets: BTreeMap<u8, ([u8; 32], [u8; 32])>,
    // Ticks elapsed since the round-0 collection window opened (the first proposal was buffered), or `None`
    // while it has not opened. The window closes — and the min-ticket is prepared — at `COLLECT_WINDOW_TICKS`
    // or when all line members have proposed (early exit), whichever comes first. Reset per height.
    round0_window: Option<u32>,
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
    // Execution attestations, height → voter → vote (first-writer-wins per voter), and the latest execution
    // certificate we have been able to form (a Q-quorum agreeing on a state root) — the executed-state
    // checkpoint that makes divergence detectable and anchors cross-cell proofs.
    exec_votes: BTreeMap<u64, BTreeMap<u8, ExecVote>>,
    checkpoint: Option<ExecCertificate>,
    // ── State-sync retention (audit §3.9 / §4; `crate::sync`) ──
    // The highest height seen in an off-height message we could not process — how far ahead the cell is, so a
    // lagging node knows to request catch-up rather than wedge.
    max_seen_height: u64,
    // The serialized state at each executed height that can be SERVED to a syncing peer, deduped by state root
    // (empty blocks share a root, so their state is stored once). Pruned to the window at/above the checkpoint.
    sync_states: BTreeMap<[u8; 32], Vec<u8>>,
    // Per executed height: its state root (into `sync_states`) and block hash (the head a syncing node adopts).
    sync_heads: BTreeMap<u64, ([u8; 32], [u8; 32])>,
    // The per-block reward pool `F` split among the commit-certificate signers on finalization (`R = F/Q`).
    // Zero (the default) emits no reward — backward-compatible; a driver funds it from collected fees.
    reward_per_block: u64,
}

impl<S: StateMachine> ConsensusEngine<S> {
    /// Build a validator's engine. `me` is its validator index; `verifiers[i]` is validator `i`'s signature
    /// key; `keyper_commit` the agreed on-chain anti-MEV decryption-key commitment
    /// ([`KeyperRegistry::commit`](crate::keyper::KeyperRegistry::commit)); `seed` the epoch beacon (leader
    /// schedule); `genesis_state` the funded genesis ledger.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        params: CellParams,
        me: u8,
        signer: HybridSigSecret,
        kem_secret: HybridKemSecret,
        verifiers: Vec<HybridVerifier>,
        keyper_commit: [u8; 32],
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
            keyper_commit,
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
            sortition: None,
            round0_tickets: BTreeMap::new(),
            round0_window: None,
            reveals: BTreeMap::new(),
            pending_reveals: BTreeMap::new(),
            exec_queue: Vec::new(),
            pending_finalize: BTreeMap::new(),
            exec_votes: BTreeMap::new(),
            checkpoint: None,
            max_seen_height: 0,
            sync_states: BTreeMap::new(),
            sync_heads: BTreeMap::new(),
            reward_per_block: 0,
        }
    }

    /// **Enable secret-leader sortition** (SSLE) for round 0: register this validator's Merkle-VRF `secret`
    /// and every validator's pre-registered `roots` (indexed like the signature `verifiers`), over a domain
    /// whose index-0 sits at chain height `base`. From now on round 0 is the min-ticket lottery
    /// ([`committee::leader_ticket`](crate::committee::leader_ticket)) — all line members propose, the lowest
    /// ticket leads — instead of the public deterministic [`leader`]. Rounds ≥ 1 are unchanged (the public
    /// fallback). Called at genesis and re-called each epoch to rotate the bounded VRF domain (fresh `secret`,
    /// `roots`, and `base`), which is also the anti-grinding registration fence.
    ///
    /// `roots.len()` should match the validator set; a proposer whose index is out of range simply fails
    /// witness verification (its proposal is ignored), so a short/garbled registry degrades to fewer eligible
    /// proposers, never to unsafety.
    pub fn enable_sortition(&mut self, secret: MerkleVrfSecret, roots: Vec<[u8; 32]>, base: u64) {
        let height = secret.height();
        self.sortition = Some(Sortition { secret, roots, height, base });
    }

    /// Whether this validator is running round-0 secret-leader sortition (vs the public-leader default).
    #[must_use]
    pub fn sortition_enabled(&self) -> bool {
        self.sortition.is_some()
    }

    /// Set the per-block reward pool `F` distributed to a block's commit-certificate signers on finalization
    /// (`R = F/Q` per signer). Default `0` (no reward). A driver sets this from the fees it collects per block.
    pub fn set_reward_per_block(&mut self, reward: u64) {
        self.reward_per_block = reward;
    }

    /// The on-chain anti-MEV **decryption-key commitment** this validator agreed to at genesis — the canonical
    /// hash of the keyper registry ([`crate::keyper`]). A light client or a sealing client uses it to check a
    /// served registry names the real decryption authority.
    #[must_use]
    pub fn keyper_commit(&self) -> [u8; 32] {
        self.keyper_commit
    }

    /// Whether `registry` is the cell's agreed anti-MEV decryption authority: it must both **verify** against
    /// the committed consensus identities ([`KeyperRegistry::verify`](crate::keyper::KeyperRegistry::verify) —
    /// each decryption key self-certified by its owner) **and** match this validator's agreed
    /// [`keyper_commit`](Self::keyper_commit). Only such a registry may be used to seal transactions to this
    /// cell — closing the key-substitution gap ([`crate::keyper`]).
    #[must_use]
    pub fn accepts_keyper_registry(&self, registry: &crate::keyper::KeyperRegistry) -> bool {
        registry.commit() == self.keyper_commit && registry.verify(&self.verifiers)
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

    /// The latest **execution checkpoint** — a `Q`-quorum certificate of the cell's canonical executed state
    /// `(height, state_root)`, or `None` before one forms. This is the portable proof of executed state that
    /// a cross-cell transaction verifies against, and the anchor that makes an execution divergence a
    /// detectable fault ([`ExecCertificate::conflicting`]) rather than a silent fork.
    #[must_use]
    pub fn latest_checkpoint(&self) -> Option<&ExecCertificate> {
        self.checkpoint.as_ref()
    }

    /// Submit a sealed transaction into this validator's mempool (a client's `SubmitTx`). A transaction that
    /// is not sealed to this epoch's beacon-chosen keyper line (wrong epoch, wrong line, or wrong committee
    /// size) is **rejected here**, so a malformed seal can never be ordered into a block (audit fix — see
    /// [`valid_seal`](Self::valid_seal)).
    /// Submit a sealed transaction to the mempool. Returns `true` iff it was **valid and newly added** — the
    /// signal a networked driver uses to gossip a received transaction exactly once (an invalid seal, or a
    /// commitment already in the mempool, returns `false`, so re-broadcasts neither bloat the pool nor loop).
    pub fn submit(&mut self, tx: SealedTx) -> bool {
        if !self.valid_seal(&tx) {
            return false;
        }
        // De-duplicate by commitment so a re-broadcast does not bloat the mempool.
        let commit = tx.commit();
        if self.mempool.iter().all(|t| t.commit() != commit) {
            self.mempool.push(tx);
            return true;
        }
        false
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
            Input::Tick => {
                let mut out = self.maybe_propose();
                out.extend(self.tick_round0_window());
                out.extend(self.maybe_request_sync());
                out
            }
            Input::Propose { block, shards } => self.on_propose(block, &shards),
            Input::Vote(sv) => self.accept_vote(sv),
            Input::Reveal(r) => self.on_reveal(&r),
            Input::ExecVote(v) => self.on_exec_vote(v),
            Input::Timeout => self.on_timeout(),
            Input::SyncReq { from, have_height } => self.on_sync_req(from, have_height),
            Input::SyncResp { cert, head, snapshot } => self.on_sync_resp(cert, head, &snapshot),
        }
    }

    /// Note that the cell has reached `height` (seen in a message we cannot yet process) — the lag signal that
    /// tells us to request catch-up. Monotone; never decreases.
    fn note_height(&mut self, height: u64) {
        self.max_seen_height = self.max_seen_height.max(height);
    }

    /// If the cell has clearly moved ahead of us (a peer finalized a height we have not), broadcast a
    /// catch-up request. Emitted at most once per `Tick`, so it is naturally rate-limited; a settled peer
    /// answers with a certified snapshot ([`on_sync_req`](Self::on_sync_req)). Adopting is monotone and
    /// certificate-verified, so a spurious request (we were only transiently behind) is harmless.
    fn maybe_request_sync(&mut self) -> Vec<Output> {
        if self.max_seen_height > self.height() {
            alloc::vec![Output::Send(ConsensusMsg::SyncReq { have_height: self.height() })]
        } else {
            Vec::new()
        }
    }

    /// Serve a catch-up request: if we hold a checkpoint STRICTLY newer than the requester's height and the
    /// certified state's snapshot, send it point-to-point to the authenticated requester `from` (never a
    /// broadcast, and never to a spoofable field — `from` is the real transport source). A Byzantine requester
    /// gains nothing it could not verify; the snapshot + certificate are self-authenticating.
    fn on_sync_req(&mut self, from: u8, have_height: u64) -> Vec<Output> {
        let Some(cert) = &self.checkpoint else {
            return Vec::new();
        };
        if cert.height <= have_height {
            return Vec::new(); // nothing newer to offer
        }
        let Some((root, head)) = self.sync_heads.get(&cert.height) else {
            return Vec::new(); // we do not retain the certified height's head/state (pruned or mid-flight)
        };
        let Some(snapshot) = self.sync_states.get(root) else {
            return Vec::new();
        };
        alloc::vec![Output::SendTo {
            to: from,
            msg: ConsensusMsg::SyncResp { cert: cert.clone(), head: *head, snapshot: snapshot.clone() },
        }]
    }

    /// Adopt a catch-up response — the load-bearing state-sync step. Every guard is mandatory:
    /// 1. **forward-only** — ignore a checkpoint at or below our finalized height (monotone, no rollback);
    /// 2. **certificate-verified** — a `Q`-quorum of the FIXED committee must have signed `(height, root)`, so a
    ///    Byzantine peer cannot forge it (and two certs for one height cannot disagree — the uniqueness proof);
    /// 3. **root-verified** — the restored state's OWN recomputed `state_root()` must equal the certified root,
    ///    so a forged/mismatched snapshot is refused (the snapshot is untrusted transport, the root is trusted).
    ///
    /// Only then install it atomically and reset all per-height working state so we resume at `height + 1`
    /// without re-voting decided heights (which would read as equivocation).
    fn on_sync_resp(&mut self, cert: ExecCertificate, head: [u8; 32], snapshot: &[u8]) -> Vec<Output> {
        if cert.height < self.height() {
            return Vec::new(); // (1) not ahead of us
        }
        if !cert.verify(self.params.quorum, &self.verifiers) {
            return Vec::new(); // (2) forged / under-quorum certificate
        }
        let Some(state) = S::restore(snapshot) else {
            return Vec::new(); // malformed snapshot
        };
        if state.state_root() != cert.state_root {
            return Vec::new(); // (3) the snapshot does not restore to the certified state
        }
        // Atomic adoption: install the certified state at `cert.height` on `head`, reset the round machinery,
        // and drop everything tied to the abandoned heights (the transferred state is already executed).
        let height = cert.height;
        self.chain.restore(height, head, state);
        self.reset_round_state();
        self.pending_finalize.clear();
        self.exec_votes.clear();
        self.exec_queue.clear();
        self.reveals.clear();
        self.pending_reveals.clear();
        self.mempool.clear();
        self.sync_states.clear();
        self.sync_heads.clear();
        self.checkpoint = Some(cert);
        self.max_seen_height = self.max_seen_height.max(self.height());
        // Signal the jump so the driver surfaces the new tip exactly like a finalized height.
        alloc::vec![Output::Committed { height, block_hash: head }]
    }

    /// Propose a block if this validator is entitled to propose this `(height, round)` and has not yet done so.
    ///
    /// Entitlement depends on the round mode:
    /// * **SSLE round 0** — *every* elected-line member proposes (the all-propose min-ticket lottery), each
    ///   attaching its Merkle-VRF sortition [`LeaderWitness`]. Replicas rank the proposals by ticket and
    ///   prepare the lowest; the winner stays secret until it broadcasts, so no adversary can pre-aim at the
    ///   single upcoming proposer.
    /// * **otherwise** (round ≥ 1, or sortition disabled) — only the single public deterministic [`leader`]
    ///   proposes, with no witness. This is the pre-SSLE protocol, the safe fallback a view change lands on.
    fn maybe_propose(&mut self) -> Vec<Output> {
        let height = self.height();
        let sortition_round0 = self.sortition.is_some() && self.round == 0;
        let entitled = if sortition_round0 {
            is_line_member(&self.seed, height, 0, usize::from(self.me))
        } else {
            leader(&self.seed, height, self.round) as u8 == self.me
        };
        if !entitled || self.proposed_round == Some(self.round) {
            return Vec::new();
        }
        // Order the mempool blindly by commitment (the proposer never sees contents — anti-MEV).
        let mut sealed = self.mempool.clone();
        sealed.sort_by_key(SealedTx::commit);
        let mut block = Block::assemble(self.chain.head(), height, self.epoch, self.me, sealed);
        // SSLE round 0: attach my sortition ticket witness. If I cannot prove it (the bounded VRF domain was
        // exhausted before the epoch re-registered), abstain this round rather than broadcast an un-rankable
        // block — a graceful degradation to the remaining eligible proposers, never a stall of the whole line.
        if sortition_round0 {
            let Some(witness) = self.leader_witness(height) else {
                return Vec::new();
            };
            block = block.with_witness(witness);
        }
        self.proposed_round = Some(self.round);
        // The proposer's own proposal is delivered back to it by the driver, so it ranks/prepares like every
        // other member; here it only broadcasts.
        alloc::vec![Output::Send(ConsensusMsg::Propose(block))]
    }

    /// Build this validator's round-0 sortition witness for `height` (its Merkle-VRF `output` + Merkle proof at
    /// the per-epoch domain index `height − base`). `None` if sortition is disabled or the domain is exhausted.
    fn leader_witness(&self, height: u64) -> Option<LeaderWitness> {
        let s = self.sortition.as_ref()?;
        let index = s.index_for(height)?;
        let (output, proof) = s.secret.prove(index)?;
        Some(LeaderWitness { output, proof })
    }

    /// Verify a round-0 proposal's sortition witness and return its ticket (`None` if absent/invalid). The
    /// witness is checked against the proposer's *pre-registered* root at the same per-epoch domain index, so a
    /// forged or grindable ticket cannot enter the min-ticket ranking.
    fn verify_witness(&self, block: &Block) -> Option<[u8; 32]> {
        let s = self.sortition.as_ref()?;
        let witness = block.witness.as_ref()?;
        let height = block.header.height;
        let index = s.index_for(height)?;
        let root = s.roots.get(usize::from(block.header.proposer))?;
        verify_leader_ticket(root, s.height, index, &self.seed, height, self.round, &witness.output, &witness.proof)
    }

    /// Validate a proposal and either prepare it (round ≥ 1 / no sortition) or buffer it into the round-0
    /// min-ticket lottery (SSLE). Every validity gate — proposer entitlement, link, structure, anti-MEV seal,
    /// data-availability — is applied identically in both modes *before* a proposal can influence the outcome.
    fn on_propose(&mut self, block: Block, shards: &DaShards) -> Vec<Output> {
        let height = self.height();
        let bh = block.hash();
        let sortition_round0 = self.sortition.is_some() && self.round == 0;
        // Proposer entitlement: SSLE round 0 admits *any* elected-line member (all-propose); otherwise only
        // the single public deterministic leader. Plus the usual link + structure checks.
        let proposer_ok = if sortition_round0 {
            is_line_member(&self.seed, height, 0, usize::from(block.header.proposer))
        } else {
            leader(&self.seed, height, self.round) as u8 == block.header.proposer
        };
        let links = block.header.height == height
            && block.header.parent == self.chain.head()
            && block.header.epoch == self.epoch;
        if !proposer_ok || !links || !block.verify_structure() {
            if block.header.height > height {
                self.note_height(block.header.height); // a proposal for a height ahead of us — we are behind
            }
            return Vec::new();
        }
        // Anti-MEV admission (audit fix): every included transaction must be sealed to this epoch's beacon
        // keyper line. A block carrying even one malformed seal is refused, so a Byzantine proposer cannot
        // slip in a transaction that no honest committee can ever decrypt (which would stall execution).
        if !block.sealed_txs.iter().all(|tx| self.valid_seal(tx)) {
            return Vec::new();
        }
        // Data-availability gate (spec §L4.3 / §10.1), verified IN-ENGINE: reconstruct the payload from the
        // shards this validator sampled and check it against the header's `da_commit`. A withholding proposer
        // leaves too few shards to reconstruct (an unrecoverable erasure pattern), or the reconstruction fails
        // the commitment — either way `reconstruct_payload` returns `None` and the validator withholds PREPARE.
        // The engine no longer trusts a driver-supplied availability bit; it checks the shards cryptographically.
        if block.reconstruct_payload(shards).is_none() {
            return Vec::new();
        }
        // SSLE round 0: the proposal must carry a valid sortition witness (verified against the proposer's
        // registered root). Computed here — AFTER the availability/seal gates, exactly as for a public block —
        // so a witness probe cannot be answered faster than a genuine proposal. An unverifiable witness ⇒ ignore.
        let ticket = if sortition_round0 {
            let Some(t) = self.verify_witness(&block) else {
                return Vec::new();
            };
            Some(t)
        } else {
            None
        };
        // Remember the (valid, available) block body so we can finalize it later even if a conflicting
        // proposal arrives afterwards (equivocation) — keyed by hash, never overwritten by a different block.
        let proposer = block.header.proposer;
        self.proposals.entry(bh).or_insert(block);
        // If we already hold a commit certificate for this height+block but were waiting on the body (an async
        // scheduler delivered the CC first), finalize now instead of staying wedged (audit fix, HIGH 3).
        if self.pending_finalize.get(&height) == Some(&bh) {
            return self.finalize(bh);
        }
        if let Some(ticket) = ticket {
            // Round-0 lottery: buffer the ticket and (re)open the collection window. Do NOT prepare yet —
            // preparing the first proposal seen would let honest replicas split their PREPAREs across different
            // members and stall the round. We prepare the LOWEST ticket once the window closes.
            self.round0_tickets.entry(proposer).or_insert((ticket, bh));
            if self.round0_window.is_none() {
                self.round0_window = Some(0);
            }
            // Early exit: once every elected line member has proposed, the min is final — prepare immediately,
            // so the happy path adds no waiting beyond proposal propagation.
            let line_size = line_members(leader_line(&self.seed, height, 0)).len();
            if self.round0_tickets.len() >= line_size {
                return self.prepare_round0_min();
            }
            return Vec::new();
        }
        // Round ≥ 1 (or sortition disabled): the single-leader immediate prepare (the pre-SSLE path, unchanged).
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

    /// Prepare the **lowest-ticket** round-0 proposal collected so far — the elected secret leader. Called on
    /// the collection-window early-exit (all line members proposed) or its tick expiry. Prepare-once per round
    /// 0 and lock-respecting, so it composes with the standard PBFT prepare→commit→finalize flow unchanged: the
    /// min-ticket only decides *which* block this validator PREPAREs; everything after is byte-for-byte classical.
    fn prepare_round0_min(&mut self) -> Vec<Output> {
        if self.round != 0 || self.sent_prepare.contains(&0) {
            return Vec::new();
        }
        let Some((_, bh)) = self.round0_tickets.values().min_by_key(|&&(t, _)| t).copied() else {
            return Vec::new(); // nothing collected yet
        };
        // Respect the Tendermint lock (a no-op in round 0 — no prior lock can exist — but kept for uniformity).
        if let Some(locked) = self.locked_block
            && locked != bh
        {
            return Vec::new();
        }
        self.sent_prepare.insert(0);
        let vote =
            Vote { height: self.height(), round: 0, block_hash: bh, phase: Phase::Prepare, voter: self.me };
        let sv = SignedVote::sign(vote, &self.signer);
        let mut out = self.accept_vote(sv.clone());
        out.push(Output::Send(ConsensusMsg::Vote(sv)));
        out
    }

    /// Advance the round-0 collection window on a tick: once it has been open for `COLLECT_WINDOW_TICKS`, prepare
    /// the lowest ticket collected (the Δ_prio expiry that covers a slow/down line member). A no-op outside
    /// round 0, after this validator has already prepared, or before any proposal has opened the window.
    fn tick_round0_window(&mut self) -> Vec<Output> {
        if self.round != 0 || self.sent_prepare.contains(&0) {
            return Vec::new();
        }
        let Some(w) = self.round0_window else {
            return Vec::new(); // not opened — no round-0 proposal buffered yet
        };
        self.round0_window = Some(w + 1);
        if w + 1 >= COLLECT_WINDOW_TICKS && !self.round0_tickets.is_empty() {
            return self.prepare_round0_min();
        }
        Vec::new()
    }

    /// Ingest a vote, store it (de-duplicated), and drive the phase transitions it may complete.
    fn accept_vote(&mut self, sv: SignedVote) -> Vec<Output> {
        let height = self.height();
        let v = sv.vote;
        if v.height != height {
            if v.height > height {
                self.note_height(v.height); // a peer is voting a height we have not reached — we are behind
            }
            return Vec::new(); // stale or future height
        }
        let Some(verifier) = self.verifiers.get(usize::from(v.voter)) else {
            return Vec::new();
        };
        if !sv.verify(verifier) {
            return Vec::new(); // bad / forged signature
        }
        // Equivocation slashing (incentive layer, now operational): if this voter already cast a conflicting
        // vote at the same slot, surface the self-contained proof so the driver applies the slash `S > 0` the
        // Nash equilibrium assumes. Both votes are kept (they differ in block_hash, so store_vote retains each).
        let mut out = Vec::new();
        if let Some(evidence) = self.find_equivocation(&sv) {
            out.push(Output::Slash(evidence));
        }
        let transitions = match v.phase {
            Phase::Prepare => {
                self.store_vote(sv);
                self.check_prepared(v.block_hash, v.round)
            }
            Phase::Commit => {
                self.store_vote(sv);
                self.check_committed(v.block_hash)
            }
        };
        out.extend(transitions);
        out
    }

    /// Scan the vote's phase bucket for a **conflicting** vote from the same validator at the same
    /// `(height, round, phase)` — an equivocation — and return the slashable proof if found. `None` if the
    /// voter has not double-voted this slot (or the conflict does not verify).
    fn find_equivocation(&self, sv: &SignedVote) -> Option<SlashEvidence> {
        let v = &sv.vote;
        let verifier = self.verifiers.get(usize::from(v.voter))?;
        let bucket = match v.phase {
            Phase::Prepare => &self.prepares,
            Phase::Commit => &self.commits,
        };
        bucket.iter().find_map(|e| {
            let ev = &e.vote;
            if ev.voter == v.voter
                && ev.height == v.height
                && ev.round == v.round
                && ev.phase == v.phase
                && ev.block_hash != v.block_hash
            {
                detect_equivocation(e, sv, verifier)
            } else {
                None
            }
        })
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
        // Distribute the block reward `F` among the distinct commit signers this validator certified (`R = F/Q`
        // each) — the operational reward the Nash equilibrium assumes, symmetric to the equivocation slash. The
        // split is over this node's commit view (≥ Q signers); a canonical, cross-node-identical reward would
        // record the commit certificate in the chain (the same refinement the execution checkpoint makes for
        // state) — future work.
        if self.reward_per_block > 0 {
            let mut signers: Vec<u8> = self
                .commits
                .iter()
                .filter(|sv| sv.vote.phase == Phase::Commit && sv.vote.block_hash == block_hash)
                .map(|sv| sv.vote.voter)
                .collect();
            signers.sort_unstable();
            signers.dedup();
            let split = distribute(self.reward_per_block, &signers);
            if !split.is_empty() {
                out.push(Output::Reward(split));
            }
        }
        out.extend(self.emit_reveals(&block));
        // Robustness (audit §3.9): also re-broadcast our reveals for every earlier finalized-but-unexecuted
        // block still awaiting decryption. Reveals are otherwise emitted exactly once, at finality; under
        // async scheduling a validator that finalizes further blocks before a committee peer's reveal arrives
        // could lose the reveal-vs-window race, drop the tx, and execute the block empty — the dromos_quic
        // stall. Re-emitting on each finalize gives every reveal up to REVEAL_WINDOW redundant broadcasts
        // (receivers first-writer-wins-dedup them, now cheaply — no re-verify), the principled analogue of
        // block re-proposal on round timeout. It changes no anti-MEV semantics (reveals still post-finality)
        // and no window backstop (a genuinely-undecryptable tx still drops).
        let awaiting: Vec<Block> = self.exec_queue.clone();
        for prior in &awaiting {
            out.extend(self.emit_reveals(prior));
        }
        self.exec_queue.push(block.clone());
        // Validate any reveals that arrived early for this block's transactions, now that we hold the committee.
        out.extend(self.drain_pending_reveals(&block));
        out.extend(self.try_execute());

        // Drop included transactions from the mempool and reset the per-height working state.
        self.mempool.retain(|t| !included.contains(&t.commit()));
        self.reset_round_state();
        out
    }

    /// Reset the per-height consensus working state — round, proposals, prepare/commit votes, self-vote dedup,
    /// and the Tendermint lock — so the next height starts clean. Shared by [`finalize`](Self::finalize) (after
    /// a normal commit) and [`on_sync_resp`](Self::on_sync_resp) (after a state-sync jump), so a synced node
    /// never re-votes an already-decided height (which would read as equivocation).
    fn reset_round_state(&mut self) {
        self.round = 0;
        self.proposals.clear();
        self.proposed_round = None;
        self.prepares.clear();
        self.commits.clear();
        self.sent_prepare.clear();
        self.sent_commit.clear();
        self.locked_block = None;
        // Round-0 sortition working state (the registered VRF config in `sortition` persists across heights).
        self.round0_tickets.clear();
        self.round0_window = None;
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
        let mut out = Vec::new();
        if self.sealed_tx_for(&r.commit).is_some() {
            if self.validate_and_record(r) {
                out.push(Self::regossip(r));
            }
        } else if !self.pending_reveals.get(&r.commit).is_some_and(|m| m.contains_key(&r.member))
            && self.verifiers.get(usize::from(r.member)).is_some_and(|vk| r.verify(vk))
        {
            // Authenticate before buffering (audit B1): a reveal for a not-yet-finalized tx must still be signed
            // by a real committee member, so an attacker with no member key cannot flood the map with
            // attacker-keyed garbage. (The member-on-the-right-line check needs the tx, and runs in
            // `validate_and_record` once the block finalizes.) The `contains_key` short-circuit skips the PQ
            // verify for an already-buffered (commit, member) — a re-gossiped duplicate was authenticated on
            // first receipt (audit §3.9 / T-H1). Bound the buffer so even a Byzantine member streaming distinct
            // commits cannot grow it without limit — evict the oldest commit past the cap.
            if !self.pending_reveals.contains_key(&r.commit)
                && self.pending_reveals.len() >= MAX_PENDING_REVEAL_COMMITS
                && let Some((&oldest, _)) = self.pending_reveals.iter().next()
            {
                self.pending_reveals.remove(&oldest);
            }
            // Buffer, first-writer-wins per member, so a flood cannot displace a genuine early reveal.
            self.pending_reveals.entry(r.commit).or_default().entry(r.member).or_insert_with(|| r.clone());
        }
        out.extend(self.try_execute());
        out
    }

    /// The number of not-yet-finalized transactions with buffered reveals — observability, and a witness to the
    /// bounded-buffer DoS defence (audit B1): this never exceeds [`MAX_PENDING_REVEAL_COMMITS`].
    #[must_use]
    pub fn pending_reveal_count(&self) -> usize {
        self.pending_reveals.len()
    }

    /// Find a finalized-but-unexecuted transaction by its commitment (searching the execution queue).
    fn sealed_tx_for(&self, commit: &TxCommit) -> Option<SealedTx> {
        self.exec_queue.iter().flat_map(|b| &b.sealed_txs).find(|tx| &tx.commit() == commit).cloned()
    }

    /// Validate a reveal against its transaction's keyper committee and record the share (first-writer-wins per
    /// member). Rejects, in order: an unknown transaction, a sender not on the transaction's line, a bad
    /// signature, a malformed share, or a share whose x-coordinate is not the sender's committee position — so
    /// a forged or misplaced share can never enter reconstruction. Returns whether a share was **newly** recorded
    /// (false on a duplicate), so the caller re-gossips each share exactly once (no amplification loop).
    fn validate_and_record(&mut self, r: &RevealMsg) -> bool {
        // Cheap first-writer-wins dedup BEFORE the expensive hybrid-PQ verify (audit §3.9 / T-H1): a reveal
        // already recorded was fully authenticated on first receipt, so a re-gossiped duplicate — which, with
        // T-H1 re-gossip, arrives ~n× per distinct share — must cost zero signature verifications. Doing the
        // verify first made every duplicate pay a full PQ check, widening the reveal-vs-window race under load
        // until legitimate reveals were dropped and the anti-MEV tx never executed (the dromos_quic stall).
        if self.reveals.get(&r.commit).is_some_and(|members| members.contains_key(&r.member)) {
            return false; // already recorded — not newly recorded, so not re-gossiped, and not re-verified
        }
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
        self.reveals.entry(r.commit).or_default().insert(r.member, share);
        true
    }

    /// Re-gossip a newly-recorded reveal so every honest validator converges on the SAME share set before the
    /// deterministic reveal window — a Byzantine keyper that reveals to only a subset of validators can then no
    /// longer make them decrypt (and execute) different transaction sets and fork intra-cell state (audit T-H1).
    fn regossip(r: &RevealMsg) -> Output {
        Output::Send(ConsensusMsg::Reveal(r.clone()))
    }

    /// Move any buffered early reveals for a just-finalized block's transactions into the validated set,
    /// re-gossiping each newly-recorded one so the share set converges across validators.
    fn drain_pending_reveals(&mut self, block: &Block) -> Vec<Output> {
        let mut out = Vec::new();
        for tx in &block.sealed_txs {
            if let Some(early) = self.pending_reveals.remove(&tx.commit()) {
                for r in early.values() {
                    if self.validate_and_record(r) {
                        out.push(Self::regossip(r));
                    }
                }
            }
        }
        out
    }

    /// Execute finalized blocks from the front of the queue, in order, as soon as every transaction in a
    /// block has gathered its `t` share openings (anti-MEV: contents are revealed only after ordering).
    fn try_execute(&mut self) -> Vec<Output> {
        let t = usize::from(self.params.seal_threshold());
        let mut out = Vec::new();
        while let Some(block) = self.exec_queue.first().cloned() {
            // The reveal window has elapsed for this block once consensus has finalized REVEAL_WINDOW further
            // heights — a deterministic, finalized-height-keyed signal that no more reveals will be waited for.
            let past_window = self.chain.next_height() > block.header.height + REVEAL_WINDOW;
            let mut opened = Vec::new();
            let mut ready = true;
            for tx in &block.sealed_txs {
                let shares: Vec<Share> =
                    self.reveals.get(&tx.commit()).map(|m| m.values().cloned().collect()).unwrap_or_default();
                if shares.len() < t {
                    if past_window {
                        continue; // window elapsed ⇒ drop this undecryptable tx and keep executing the block
                    }
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
                        // honest subset that needs one more reveal, so — until the window elapses — we do NOT
                        // give up while any committee member is still outstanding; we wait until every member
                        // has revealed. Once all `member_count` shares are in and none opens (malformed), OR the
                        // reveal window has passed, the transaction is dropped (not stalled) — later
                        // transactions and blocks still execute. Because every validator re-gossips each reveal
                        // it records ([`regossip`], audit T-H1), the honest share sets converge well within the
                        // window, so this drop decision agrees across validators under partial synchrony; the
                        // executed-state checkpoint ([`crate::checkpoint`]) detects any residual async divergence.
                        if shares.len() < tx.member_count() && !past_window {
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
            self.chain.begin_block(block.header.height);
            // The parent hash is an unpredictable, consensus-committed value (fixed before this block's
            // transactions), so a storage-market audit drawn from it cannot be pre-satisfied by the prover.
            self.chain.set_audit_beacon(block.header.parent);
            for txn in &opened {
                self.chain.execute(txn);
            }
            // Attest the executed state at this height — the checkpoint that makes divergence detectable.
            out.push(self.emit_exec_vote(block.header.height));
            // Retain a servable snapshot of the just-executed state so a lagging peer can state-sync to it
            // (audit §3.9 / §4). Deduped by state root (empty blocks share a root → serialized once) and
            // indexed by height with the block hash a syncing node adopts as its `head`.
            self.capture_sync_snapshot(&block);
        }
        out
    }

    /// Store the just-executed state as a servable state-sync snapshot: dedup the serialized state by its root
    /// (so a run of empty blocks costs one serialization) and record this height's `(root, block hash)`.
    fn capture_sync_snapshot(&mut self, block: &Block) {
        let root = self.chain.state_root();
        if !self.sync_states.contains_key(&root) {
            let snap = self.chain.state().snapshot();
            self.sync_states.insert(root, snap);
        }
        self.sync_heads.insert(block.header.height, (root, block.header.hash()));
    }

    /// Sign and locally record this validator's execution attestation for `height` (the current state root),
    /// returning the broadcast action. Recording our own vote lets a checkpoint form from our view too.
    fn emit_exec_vote(&mut self, height: u64) -> Output {
        let vote = ExecVote::sign(height, self.chain.state_root(), self.me, &self.signer);
        self.record_exec_vote(vote.clone());
        Output::Send(ConsensusMsg::ExecVote(vote))
    }

    /// Ingest an execution attestation off the wire: verify its signature, record it (first-writer-wins per
    /// voter), and try to form/advance the execution checkpoint.
    fn on_exec_vote(&mut self, vote: ExecVote) -> Vec<Output> {
        let Some(verifier) = self.verifiers.get(usize::from(vote.voter)) else {
            return Vec::new();
        };
        if !vote.verify(verifier) {
            return Vec::new(); // forged / unauthenticated attestation
        }
        if vote.height >= self.height() {
            self.note_height(vote.height); // a peer executed a height at/ahead of ours — a catch-up signal
        }
        self.record_exec_vote(vote);
        Vec::new()
    }

    /// Store an execution vote and, if a quorum now agrees on a root at that height, advance the checkpoint.
    fn record_exec_vote(&mut self, vote: ExecVote) {
        let height = vote.height;
        self.exec_votes.entry(height).or_default().entry(vote.voter).or_insert(vote);
        self.try_form_checkpoint(height);
    }

    /// If a `Q`-quorum of stored votes at `height` agree on one state root, form the [`ExecCertificate`] and
    /// adopt it as the latest checkpoint (monotone in height). A minority (e.g. a divergent validator's) root
    /// never forms a certificate — the divergence is visible, not silent.
    fn try_form_checkpoint(&mut self, height: u64) {
        if self.checkpoint.as_ref().is_some_and(|c| c.height >= height) {
            return; // already checkpointed at least this far
        }
        let Some(by_voter) = self.exec_votes.get(&height) else {
            return;
        };
        // Group votes by attested root; the first root reaching the quorum is canonical (two cannot, since a
        // Q-quorum shares an honest validator that attests one root).
        let mut by_root: BTreeMap<[u8; 32], Vec<ExecVote>> = BTreeMap::new();
        for v in by_voter.values() {
            by_root.entry(v.state_root).or_default().push(v.clone());
        }
        for (root, votes) in by_root {
            if votes.len() >= self.params.quorum {
                self.checkpoint = Some(ExecCertificate { height, state_root: root, votes });
                self.prune_sync_retention(height);
                return;
            }
        }
    }

    /// Prune the state-sync retention to the window at/above the newly-certified `checkpoint_height`: a synced
    /// node only ever serves the checkpoint height (or a still-uncertified higher one), so older per-height
    /// heads are dead, and a state whose root no longer backs any retained head is dropped. Bounds the memory to
    /// the (small) execution-to-certification lag.
    fn prune_sync_retention(&mut self, checkpoint_height: u64) {
        self.sync_heads.retain(|&h, _| h >= checkpoint_height);
        let live: BTreeSet<[u8; 32]> = self.sync_heads.values().map(|(r, _)| *r).collect();
        self.sync_states.retain(|r, _| live.contains(r));
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
