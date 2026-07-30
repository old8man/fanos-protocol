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
use fanos_primitives::collections::BoundedMap;
use fanos_primitives::shamir::Share;
use fanos_primitives::{BeaconSeed, Epoch, codec};

use fanos_vrf::pqvrf::MerkleVrfSecret;

use crate::block::{Block, LeaderWitness};
use crate::state::ExecOutcome;
use crate::chain::Chain;
use crate::checkpoint::{ExecCertificate, ExecVote};
use crate::committee::{
    epoch_seal_line, is_line_member, leader, leader_line, line_members, verify_leader_ticket,
};
use crate::incentive::{SlashEvidence, detect_equivocation};
use crate::params::CellParams;
use crate::state::StateMachine;
use crate::tx::{SealedTx, Transaction, TxCommit};
use crate::vote::{Certificate, NIL, Phase, SignedVote, Vote};

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

/// Why proposals were refused, as counters — the observable that tells a **rejected** block apart from an **unprepared**
/// one.
///
/// Both look identical from outside: the round times out and the height never advances. They have nothing in common as
/// fixes, and distinguishing them by reading the code does not work — a stalled cell was attributed to data availability
/// for two rounds of investigation before a measurement showed availability was clear.
///
/// A compact snapshot of a validator's consensus position, for reporting a **frozen cell**.
///
/// A stalled height looks identical from outside whatever caused it, and the outside is all a live-network test could
/// see: it printed the ledger state and the height, so every stall — a lock split, a missing body, a validator that
/// silently fell behind — produced the same message, and each one cost a bespoke instrumentation pass to tell apart.
/// These six fields separate them at the point of failure, which is the only moment the state still exists.
///
/// Read them together: `max_seen_height > height` is a validator that *knows* it is behind (so the question is why
/// catch-up has not run, not why consensus has not); `locked` with `!holds_locked_body` is stuck on a block it cannot
/// execute; `locked` with the body and a high `round` is a lock split; and the reject counters say what it is refusing
/// while it waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusProbe {
    /// The height this validator is trying to finalize.
    pub height: u64,
    /// The round within that height — high means repeated timeouts.
    pub round: u32,
    /// Whether it is locked on a block (so it will refuse every conflicting proposal).
    pub locked: bool,
    /// Whether it actually holds the locked block's body (locked without it cannot even re-prepare).
    pub holds_locked_body: bool,
    /// The **first four bytes** of the body it is waiting for, if any.
    ///
    /// The identity, not merely the fact. A cell in which every validator awaits the *same* block is one whose body
    /// never reached anyone — a dispersal failure. A cell in which each awaits a *different* one is not stuck on a body
    /// at all; it is failing to converge, and the waits are a symptom. The two demand opposite investigations and a
    /// boolean cannot tell them apart, which cost one round of this hunt.
    pub awaiting_body: Option<[u8; 4]>,
    /// The highest height it has *seen* evidence of — above `height`, it knows it is behind.
    pub max_seen_height: u64,
    /// Why it has been refusing proposals.
    pub rejects: ProposalRejects,
    /// Skeleton requests seen, and how many this validator could answer.
    pub skeleton_asks: (u64, u64),
    /// Shard requests seen, and how many this validator could answer.
    pub shard_asks: (u64, u64),
    /// Delivered shards this validator accepted.
    pub shards_taken: u64,
    /// Shards this validator dispersed as a proposer.
    pub shards_sent: u64,
    /// Catch-up requests this validator emitted.
    pub sync_asks: u64,
    /// How it answered peers' catch-up requests: `(snapshot, commit-certificate, nothing)`.
    pub sync_answers: (u64, u64, u64),
    /// Certified-state snapshots adopted.
    pub sync_taken: u64,
    /// Commit certificates **offered by a peer** (`ConsensusMsg::CommitCert`) that finalized a height — the
    /// catch-up path only, never `adopt_certified_parent`'s read of a newer block's `last_commit`.
    pub cert_taken: u64,
    /// Why an offered commit certificate did not: `(wrong height/phase, failed verification, parked for want of the body)`.
    pub cc_rejects: (u64, u64, u64),
    /// Body-recovery requests emitted for a parked decision.
    pub body_asks: u64,
    /// How this validator answered peers' body requests: `(served, not held, refused as unwanted/invalid)`.
    pub body_answers: (u64, u64, u64),
    /// Bodies applied to a decision this validator was holding.
    pub body_taken: u64,
    /// A height whose COMMIT decision is held but **unappliable for want of the block body**.
    ///
    /// The wedge, named. `finalize` parks a certified decision here when the body is absent and applies it "the
    /// instant `on_propose` delivers the body" — an assumption that holds for a scheduler reordering two messages and
    /// not for a straggler whose block the cell has already stopped retaining.
    pub parked: Option<u64>,
}

impl core::fmt::Display for ConsensusProbe {
    /// Dense on purpose: one validator per column in a frozen-cell trace across a whole cell.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "h{}r{}", self.height, self.round)?;
        if self.max_seen_height > self.height {
            write!(f, " behind({})", self.max_seen_height)?;
        }
        if self.locked {
            f.write_str(if self.holds_locked_body { " lock" } else { " lock-nobody" })?;
        }
        if let Some(h) = self.awaiting_body {
            write!(f, " await:{:02x}{:02x}{:02x}{:02x}", h[0], h[1], h[2], h[3])?;
        }
        let (asked, served) = self.skeleton_asks;
        if asked > 0 {
            write!(f, " skel={served}/{asked}")?;
        }
        let (sh_asked, sh_served) = self.shard_asks;
        if sh_asked > 0 || self.shards_taken > 0 {
            write!(f, " shard={sh_served}/{sh_asked} took={}", self.shards_taken)?;
        }
        if self.shards_sent > 0 {
            write!(f, " sent={}", self.shards_sent)?;
        }
        let (snap, cert, none) = self.sync_answers;
        if self.sync_asks > 0 || snap + cert + none > 0 {
            write!(f, " sync={}a/{}s/{}c ans={snap}/{cert}/{none}", self.sync_asks, self.sync_taken, self.cert_taken)?;
        }
        let (bs, bn, br) = self.body_answers;
        if self.body_asks + bs + bn + br + self.body_taken > 0 {
            write!(f, " body={}a/{}got ans={bs}/{bn}/{br}", self.body_asks, self.body_taken)?;
        }
        let (cch, ccv, ccp) = self.cc_rejects;
        if cch + ccv + ccp > 0 {
            write!(f, " ccrej[h={cch} v={ccv} park={ccp}]")?;
        }
        if let Some(h) = self.parked {
            write!(f, " PARKED@{h}")?;
        }
        let r = &self.rejects;
        let total = r.proposer + r.link + r.locked + r.structure + r.last_commit + r.seal + r.witness + r.unavailable;
        if total > 0 {
            write!(f, " rej[")?;
            for (name, n) in [
                ("prop", r.proposer),
                ("link", r.link),
                ("lock", r.locked),
                ("struct", r.structure),
                ("lastc", r.last_commit),
                ("seal", r.seal),
                ("wit", r.witness),
                ("unavail", r.unavailable),
            ] {
                if n > 0 {
                    write!(f, "{name}={n} ")?;
                }
            }
            write!(f, "]")?;
        }
        Ok(())
    }
}

/// Counters rather than log lines because this engine is `no_std` and sans-I/O: it has nowhere to write. A driver reads
/// them and reports; a test asserts on them.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalRejects {
    /// The proposer was not entitled to propose this `(height, round)`.
    pub proposer: u64,
    /// The block did not link to our head at our height and epoch.
    pub link: u64,
    /// `tx_root` / `da_commit` / `last_commit_root` did not match the block's own contents.
    pub structure: u64,
    /// The recorded `last_commit` was not a valid quorum certificate for the parent.
    pub last_commit: u64,
    /// A transaction was not sealed to this epoch's keyper line (anti-MEV admission).
    pub seal: u64,
    /// The payload could not be reconstructed from the sampled shards, or failed `da_commit`.
    pub unavailable: u64,
    /// An SSLE round-0 proposal carried no verifiable sortition witness.
    pub witness: u64,
    /// The block conflicted with the one this validator is locked on.
    pub locked: u64,
}

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
    /// A peer's **commit-certificate answer** to a `SyncReq`: the quorum COMMIT certificate that finalized the
    /// requester's *current* height. Serves the case [`SyncResp`](Self::SyncResp) structurally cannot — see
    /// [`on_commit_cert`](ConsensusEngine::on_commit_cert).
    CommitCert(Certificate),
    /// **"I hold a quorum decision I cannot apply — send me the block itself."**
    ///
    /// The last gap in the catch-up ladder, measured on a live cell: a validator received 1963 commit certificates,
    /// every one passing height, phase and signature checks, and parked every one of them for want of the block body
    /// (`ccrej[h=0 v=0 park=1963] PARKED@1`). Certificates carry the *decision*; nothing carried the *payload*.
    ///
    /// `NeedSkeleton` cannot serve this: a skeleton is payload-less by construction, and re-gathering the payload from
    /// erasure shards asks custodians that may never have been dispersed one. Meanwhile the block sits whole on every
    /// validator that voted COMMIT on it — which the certificate *names*. So the evidence that creates the obligation
    /// also identifies who can discharge it, and this asks exactly one of them.
    NeedBody {
        /// The block hash a quorum certificate decided and this validator cannot apply.
        block: [u8; 32],
    },
    /// The whole block, answering [`NeedBody`](Self::NeedBody). Self-verifying — the requester checks the hash against
    /// the decision it parked, so nothing about the sender is trusted.
    Body(Block),
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
            Self::CommitCert(cert) => {
                out.push(6);
                out.extend_from_slice(&cert.to_bytes());
            }
            Self::NeedBody { block } => {
                out.push(7);
                out.extend_from_slice(block);
            }
            Self::Body(b) => {
                out.push(8);
                out.extend_from_slice(&b.to_bytes());
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
            6 => Some(Self::CommitCert(Certificate::from_bytes(body)?)),
            7 => {
                let mut r = codec::Reader::new(body);
                let block = r.array::<32>()?;
                r.finish()?;
                Some(Self::NeedBody { block })
            }
            8 => Some(Self::Body(Block::from_bytes(body)?)),
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
    /// A proposal **skeleton** received off the wire — header, sortition witness and `last_commit`, no payload.
    ///
    /// Exists so the SSLE round-0 min-ticket lottery can rank a proposal from the thing it actually ranks: the
    /// **ticket**, which rides in the skeleton's witness. The alternative is what shipped, and it deadlocked the cell —
    /// the driver disperses one shard per validator and admits a proposal only once it has *sampled the rest and
    /// reconstructed the body*, so under all-propose every replica ranked whatever different subset of the N proposals
    /// happened to reconstruct inside one collection tick, split its PREPARE, and no quorum ever formed.
    ///
    /// A skeleton is **rank-only** and can never be prepared: its `sealed_txs` is empty, so it cannot pass
    /// [`Block::verify_structure`], and the body it names enters `proposals` solely through the full
    /// [`Input::Propose`] path with every gate applied. The engine prepares a ranked block only once that body is
    /// present, so ranking an unvalidated skeleton costs nothing in safety.
    Skeleton {
        /// The skeleton (`Block::skeleton`): the full header and witness with an empty payload.
        block: Block,
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
    /// A commit certificate received off the wire, finalizing the height we are stuck on (verified before use).
    CommitCert(Certificate),
    /// A peer asks for a block body it holds a quorum decision for; `from` directs the reply.
    NeedBody {
        /// The asking validator's index (from the authenticated transport source, not a spoofable field).
        from: u8,
        /// The block hash wanted.
        block: [u8; 32],
    },
    /// A peer's answer to [`NeedBody`](Self::NeedBody) — the whole block, checked against the parked decision.
    Body(Block),
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

/// How many recently finalized block bodies to retain for serving a lagging peer (see `recent_bodies`).
///
/// A cell's heights advance far faster than a stuck validator takes to notice and ask, so this only has to cover the
/// window between finalization and a recovery request — but it is the whole reason a stuck validator can be helped at
/// all, so it is generous rather than tight.
const RECENT_BODY_CAP: usize = 64;

/// The **structural** half of the unlocking test: everything about a proof-of-lock except its signatures.
///
/// Separated because this is where a subtle error is possible and would be silent. The signature check is
/// all-or-nothing and fails loudly; these five comparisons each admit an off-by-one, and one of them —
/// `pol.round > locked_round` — is the safety boundary of the whole rule.
///
/// * **`> locked_round`, strictly.** Releasing on a proof from the round we locked at, or an earlier one, would
///   break agreement: our lock exists *because* a quorum prepared our value at that round, and a second quorum
///   at the same round can only exist if `f+1` validators equivocated. Accepting it would make one equivocation
///   round enough to split the cell, which is precisely what the lock is for.
/// * **`<= now`.** A certificate from a round we have not reached is not evidence about the past; a peer can
///   mint one for a future round only by getting a quorum to vote there, in which case we will be told by the
///   round-synchronization rule and can re-judge it then.
/// * **phase, height and hash** must all match the proposal, or the proof is about something else.
fn pol_shape_releases(pol: &Certificate, block_hash: [u8; 32], height: u64, locked_round: u32, now: u32) -> bool {
    pol.phase == Phase::Prepare
        && pol.height == height
        && pol.block_hash == block_hash
        && pol.round > locked_round
        && pol.round <= now
}

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
    // Why proposals were refused (`ProposalRejects`) — cumulative, never reset, so a driver or test can diff two reads.
    rejects: ProposalRejects,
    // Skeleton requests seen, and how many this validator could answer. The instrument that separates two failures a
    // frozen trace cannot otherwise tell apart: a cell where every validator awaits one body may be one whose requests
    // are **not arriving**, or one where they arrive and **nobody holds the block**. `await:<hash>` looks identical in
    // both, and they need opposite investigations.
    skeleton_asks: (u64, u64),
    // The same instrument one layer down, for SHARDS — added 2026-07-30 after the skeleton counter answered its own
    // question and pointed past itself. It showed requests arriving in thousands and being served (one validator
    // answered 3461 of 3461), with the requesters *sampling* — so they hold skeletons and lack shards, which is the
    // half `skeleton_asks` cannot see.
    //
    // Both directions, because the skeleton case proved serving alone is not enough to localize a stall: `(asked,
    // served)` is what this validator was asked for and could answer; `taken` is how many delivered shards it
    // accepted. A stall with `asked = 0` is a request-side failure, `served = 0` a holder-side one, and
    // `asked > 0, served > 0, taken = 0` means the replies are produced and lost or refused — three different
    // investigations, and a single counter would conflate them exactly as the first one nearly did.
    shard_asks: (u64, u64),
    shards_taken: u64,
    shards_sent: u64,

    // Catch-up accounting (2026-07-30). The shard counters showed a straggler in dense two-way traffic that still
    // never rejoined, which rules out "it cannot hear" and leaves the catch-up protocol itself. These name which
    // link of it fails, because `behind(n)` says only that the validator knows.
    //
    // `sync_asks` is what we emitted. `sync_answers` is how we answered *peers* — snapshot, commit-certificate, or
    // **nothing**, and the third is the one worth a counter of its own: `on_sync_req` has two paths that send no
    // reply at all once a checkpoint exists but its retained state does not, and a requester cannot tell that from
    // a lost packet. `sync_taken` / `cert_taken` are answers we adopted.
    sync_asks: u64,
    sync_answers: (u64, u64, u64),
    sync_taken: u64,
    cert_taken: u64,
    // Why an offered commit certificate did NOT advance us: `(wrong height or phase, failed verification, parked for
    // want of the body)`. The trace that forced this: two validators answered ~4250 catch-up requests each with a
    // certificate, five laggards each adopted exactly ONE, and `parked` was empty on all of them — so the certificates
    // were refused somewhere, and reading the guards could not say which. Every one of them is self-contained
    // (`Certificate::verify` depends on nothing but the fixed committee), which is exactly why the answer has to be
    // measured instead of derived.
    cc_rejects: (u64, u64, u64),
    /// Body-recovery accounting: requests emitted, `(served, not held, refused)` as a responder, bodies applied.
    body_asks: u64,
    body_answers: (u64, u64, u64),
    body_taken: u64,
    // The canonical COMMIT certificate for each finalized height this validator can still produce, keyed by the height
    // it finalizes. Two sources: one learned from **another block's `last_commit`** (see `adopt_certified_parent`,
    // carried into `finalize` because `collect_cert` can only build a certificate from votes this validator actually
    // received, and in exactly that situation it did not), and the one `finalize` itself collected from its own votes.
    //
    // Keeping the second is what lets this validator *answer* a stuck peer (`offer_commit_cert`): `collect_cert` filters
    // by the current round and height, so once the chain advances the certificate is unrecoverable from raw votes — the
    // moment of finalization is the only one at which it can be captured. Pruned with the rest of the catch-up retention.
    certified: BTreeMap<u64, Certificate>,
    // Recently **finalized** bodies, retained to serve a peer stuck on a block it never received.
    //
    // `reset_round_state` clears `proposals` on every finalization and the chain keeps only headers, so without this the
    // validators best placed to help — the ones that already finalized — are exactly the ones that have thrown the block
    // away. Measured: a recovery request reached peers that all answered nothing, and four of seven validators stayed
    // frozen at genesis. Bounded because the key is a block hash; an evicted body is simply unavailable here, and the
    // requester asks the rest of the cell.
    recent_bodies: BoundedMap<[u8; 32], Block>,
    /// The PREPARE-quorum certificate that set [`locked_block`](Self::locked_block) — the **proof of lock** a
    /// re-proposal carries, so a validator other than the block's original proposer can re-offer it.
    locked_cert: Option<Certificate>,
    /// The block this validator knows the cell has already **prepared**, with the certificate proving it —
    /// Tendermint's `validValue`/`validRound`, and the piece that makes a lock split heal deterministically.
    ///
    /// It is set by *observing* a polka, not only by locking on one: a proposal that arrives carrying a valid
    /// [`Block::pol`] is such an observation. A validator that never saw the original PREPARE quorum therefore
    /// still learns which value the cell was willing to prepare, and proposes *that* when its turn comes instead
    /// of a fresh block the locked minority must refuse.
    ///
    /// Without it, healing is a race rather than a rule: the unlocked majority prepares whatever proposal reaches
    /// it first in a round, and having voted it cannot vote again (a second PREPARE would be equivocation), so
    /// convergence needs a round in which the locked minority's re-offer happens to arrive first. Measured live
    /// at 1 failure in 8 runs with the re-offer alone.
    valid_value: Option<([u8; 32], Certificate)>,
    /// The height at which each still-premature transaction was **first** deferred, so retention is bounded by
    /// [`REVEAL_WINDOW`] rather than being unbounded: a far-future nonce cannot be re-queued forever.
    deferred_since: BoundedMap<TxCommit, u64>,
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
    // The commit certificate of the most-recently-finalized block, captured at finality so the NEXT block this
    // validator proposes can record it as its `last_commit` — the canonical finalizer set every validator then
    // credits the block reward to (`crate::incentive`). `None` until the first block finalizes.
    last_finalized_cert: Option<Certificate>,
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
            rejects: ProposalRejects::default(),
            skeleton_asks: (0, 0),
            shard_asks: (0, 0),
            shards_taken: 0,
            shards_sent: 0,
            sync_asks: 0,
            sync_answers: (0, 0, 0),
            sync_taken: 0,
            cert_taken: 0,
            cc_rejects: (0, 0, 0),
            body_asks: 0,
            body_answers: (0, 0, 0),
            body_taken: 0,
            certified: BTreeMap::new(),
            recent_bodies: BoundedMap::new(RECENT_BODY_CAP),
            locked_cert: None,
            valid_value: None,
            deferred_since: BoundedMap::new(RECENT_BODY_CAP),
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
            last_finalized_cert: None,
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

    /// The block whose **body** this validator is stuck waiting for, if any.
    ///
    /// A validator locks on a block hash, or gathers a commit certificate for one, from **votes alone** — votes are small
    /// and carry only the hash, so neither requires ever having seen the block. If the body then never arrives it cannot
    /// make progress in either direction: [`reprepare_lock`](Self::reprepare_lock) rightly abstains rather than vote to
    /// prepare something it cannot execute, and the `locked_block` gate refuses every conflicting proposal. The height is
    /// stuck on a block it can never obtain.
    ///
    /// State sync does not cover this. `on_sync_req` serves a *checkpoint*, and a cell one block into its life has none —
    /// measured live as four of seven validators frozen at genesis with `locked: 2` refusals, an empty sampler and
    /// nothing to sync from.
    ///
    /// So the driver asks for it: `Some(hash)` means "fetch this block's skeleton from a peer that has it", after which
    /// the ordinary DA sampling and admission path takes over. `None` when nothing is missing.
    /// A third case joined the two above: a block this validator is neither committed to nor locked on, but which
    /// **its peers are voting for** and it has never received.
    ///
    /// It exists because neither of the other two fires for a validator that is merely *watching* a block gather
    /// votes, and that is the state a lock split leaves the majority in. Measured on a live cell: three of seven
    /// received a height's proposal and locked on it, the other four never saw it; quorum is five, so the three
    /// refused every later proposal (`rejects.locked`, 5 each, and nothing else anywhere) while the four proposed
    /// alternatives none of the three could join. A PREPARE carries only a hash, so the votes told the four
    /// nothing they could act on.
    ///
    /// Asking on that evidence is safe: a vote is signature-checked before it reaches `prepares`/`commits`, so the
    /// hash is one a real validator staked its signature on, and whatever body arrives is still verified against
    /// the header's `da_commit` and every ordinary proposal check before admission.
    #[must_use]
    pub fn awaited_body(&self) -> Option<[u8; 32]> {
        let height = self.height();
        if let Some(want) = self.pending_finalize.get(&height).copied().or(self.locked_block)
            && !self.proposals.contains_key(&want)
        {
            return Some(want);
        }
        // The hash peers are backing hardest at this height that we do not hold. Ties break by hash — arbitrary,
        // but identical on every validator, so a split cell converges on asking for the same body.
        let mut tally: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for sv in self.prepares.iter().chain(&self.commits) {
            let hash = sv.vote.block_hash;
            // `nil` is a statement that a validator accepted *nothing*, not a block anyone can fetch. Counting it
            // here made every validator chase a body that does not exist by construction — measured live as a
            // whole cell reporting `await:00000000`, the all-zero sentinel, the moment nil votes were introduced.
            // The interaction is the lesson: a sentinel added to one tally silently joins every other tally that
            // ranges over the same field.
            if sv.vote.block_hash != NIL
                && sv.vote.height == height
                && !self.proposals.contains_key(&hash)
                && self.recent_bodies.get(&hash).is_none()
            {
                *tally.entry(hash).or_insert(0) += 1;
            }
        }
        tally.into_iter().max_by_key(|&(hash, n)| (n, hash)).map(|(hash, _)| hash)
    }

    /// The **skeleton** of a block this validator holds, so it can answer a peer stuck waiting for that body.
    ///
    /// The skeleton rather than the block: it carries the header and witness a requester needs to sample and verify the
    /// payload, and keeps the recovery on the same data-availability path as a first delivery instead of shipping a whole
    /// block around.
    #[must_use]
    pub fn skeleton_of(&self, hash: &[u8; 32]) -> Option<Block> {
        self.proposals.get(hash).or_else(|| self.recent_bodies.get(hash)).map(Block::skeleton)
    }

    /// Record that a peer asked this validator for a skeleton, and whether it could be answered.
    ///
    /// Separate from [`skeleton_of`](Self::skeleton_of) on purpose. The accessor is a pure read and stays one —
    /// making it `&mut` to carry a counter would force every caller, including a test that only wants to look,
    /// to hold a mutable borrow. Counting belongs where the request is *handled*, which is the driver.
    pub fn note_skeleton_ask(&mut self, served: bool) {
        self.skeleton_asks.0 = self.skeleton_asks.0.saturating_add(1);
        if served {
            self.skeleton_asks.1 = self.skeleton_asks.1.saturating_add(1);
        }
    }

    /// Record that a peer asked this validator for a shard, and whether it could be answered.
    pub fn note_shard_ask(&mut self, served: bool) {
        self.shard_asks.0 = self.shard_asks.0.saturating_add(1);
        if served {
            self.shard_asks.1 = self.shard_asks.1.saturating_add(1);
        }
    }

    /// Record that a delivered shard was accepted by the sampler.
    pub fn note_shard_taken(&mut self) {
        self.shards_taken = self.shards_taken.saturating_add(1);
    }

    /// Record that this validator dispersed a shard as a proposer.
    pub fn note_shard_sent(&mut self) {
        self.shards_sent = self.shards_sent.saturating_add(1);
    }

    /// **Any** data-availability shard of a block this validator holds in full.
    ///
    /// A shard normally has exactly one custodian — the validator whose index it is — so a dispersal that never
    /// arrived leaves that shard unobtainable, however many peers hold the whole block. The proposer is the
    /// sharpest case: it built the block, holds every byte of it, and could answer for any index, yet retains
    /// only its own. Measured consequence: a cell split `[7, 6, 6, 7, 6, 6, 6]` on a block carrying a 9 KB
    /// transaction, where the two validators that had it could not help the five that did not.
    ///
    /// Shards are re-derived from the payload rather than stored, so this costs an encode and no memory, and the
    /// requester still checks what arrives against the header's `da_commit` — serving more widely cannot weaken
    /// the availability guarantee, only make it reachable.
    #[must_use]
    pub fn shard_of(&self, hash: &[u8; 32], index: u8) -> Option<Vec<u8>> {
        let block = self.proposals.get(hash).or_else(|| self.recent_bodies.get(hash))?;
        block.da_shards().get(usize::from(index)).cloned()
    }

    /// Why proposals have been refused so far — see [`ProposalRejects`]. Cumulative; diff two reads for a rate.
    #[must_use]
    pub fn rejects(&self) -> ProposalRejects {
        self.rejects
    }

    /// A compact snapshot of **why this validator is where it is** — see [`ConsensusProbe`].
    #[must_use]
    pub fn probe(&self) -> ConsensusProbe {
        ConsensusProbe {
            height: self.height(),
            round: self.round,
            locked: self.locked_block.is_some(),
            holds_locked_body: self.locked_block.is_some_and(|h| self.proposals.contains_key(&h)),
            awaiting_body: self.awaited_body().map(|h| [h[0], h[1], h[2], h[3]]),
            skeleton_asks: self.skeleton_asks,
            shard_asks: self.shard_asks,
            shards_taken: self.shards_taken,
            shards_sent: self.shards_sent,
            sync_asks: self.sync_asks,
            sync_answers: self.sync_answers,
            sync_taken: self.sync_taken,
            cert_taken: self.cert_taken,
            cc_rejects: self.cc_rejects,
            body_asks: self.body_asks,
            body_answers: self.body_answers,
            body_taken: self.body_taken,
            parked: self.pending_finalize.keys().min().copied(),
            max_seen_height: self.max_seen_height,
            rejects: self.rejects,
        }
    }

    /// Step the engine on one input, returning the actions to take.
    pub fn step(&mut self, input: Input) -> Vec<Output> {
        match input {
            Input::Tick => {
                let mut out = self.maybe_propose();
                out.extend(self.tick_round0_window());
                out.extend(self.maybe_request_sync());
                out.extend(self.maybe_request_body());
                out
            }
            Input::Propose { block, shards } => self.on_propose(block, &shards),
            Input::Skeleton { block } => self.on_skeleton(&block),
            Input::Vote(sv) => self.accept_vote(sv),
            Input::Reveal(r) => self.on_reveal(&r),
            Input::ExecVote(v) => self.on_exec_vote(v),
            Input::Timeout => self.on_timeout(),
            Input::SyncReq { from, have_height } => self.on_sync_req(from, have_height),
            Input::NeedBody { from, block } => self.on_need_body(from, &block),
            Input::Body(block) => self.on_body(block),
            Input::CommitCert(cert) => self.on_commit_cert(cert),
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
            self.sync_asks = self.sync_asks.saturating_add(1);
            alloc::vec![Output::Send(ConsensusMsg::SyncReq { have_height: self.height() })]
        } else {
            Vec::new()
        }
    }

    /// Ask one COMMIT-certificate voter for the body of a decision we hold and cannot apply.
    ///
    /// The last rung of the catch-up ladder. `finalize` parks a certified decision when the body is absent, on the
    /// assumption that `on_propose` eventually delivers it — true for a scheduler reordering two messages, false for a
    /// validator the cell has moved past. Measured live: 1963 certificates accepted and parked, `PARKED@1`, forever.
    ///
    /// **Addressed, not broadcast, and provably to a holder.** Every voter in the certificate held the block in order to
    /// sign a COMMIT for it, so the certificate that creates the obligation also names `Q` peers who can discharge it.
    /// One request per tick to one voter, rotating by attempt so a departed voter costs one tick rather than the
    /// recovery. Broadcasting instead would send `n−1` copies of a multi-kilobyte body per tick, and this session's
    /// measurements are unambiguous that added recovery traffic makes the stall worse, not better.
    fn maybe_request_body(&mut self) -> Vec<Output> {
        let height = self.height();
        let Some(&block) = self.pending_finalize.get(&height) else {
            return Vec::new();
        };
        let Some(cert) = self.certified.get(&height) else {
            return Vec::new(); // no certificate to name a holder — `NeedSkeleton`/sampling is all we have
        };
        let voters: Vec<u8> = cert.votes.iter().map(|sv| sv.vote.voter).filter(|&v| v != self.me).collect();
        if voters.is_empty() {
            return Vec::new();
        }
        let turn = usize::try_from(self.body_asks).unwrap_or(0) % voters.len();
        let Some(&pick) = voters.get(turn) else {
            return Vec::new();
        };
        self.body_asks = self.body_asks.saturating_add(1);
        alloc::vec![Output::SendTo { to: pick, msg: ConsensusMsg::NeedBody { block } }]
    }

    /// Answer a peer's [`ConsensusMsg::NeedBody`] with the whole block, if we hold it.
    ///
    /// No entitlement check is needed or possible: the block is one a quorum already decided, its hash is public in
    /// every vote, and the answer is self-verifying at the receiver. Withholding it from a peer that asks would only
    /// stall the cell the responder belongs to.
    fn on_need_body(&mut self, from: u8, block: &[u8; 32]) -> Vec<Output> {
        let Some(full) = self.proposals.get(block).or_else(|| self.recent_bodies.get(block)) else {
            self.body_answers.1 = self.body_answers.1.saturating_add(1);
            return Vec::new();
        };
        let msg = ConsensusMsg::Body(full.clone());
        self.body_answers.0 = self.body_answers.0.saturating_add(1);
        alloc::vec![Output::SendTo { to: from, msg }]
    }

    /// Apply a block body handed over for a decision we already hold.
    ///
    /// Deliberately **not** routed through `on_propose`: this is not a proposal and must not be judged as one. A
    /// proposal is checked for proposer right and round entitlement because accepting it means *voting*; here the cell
    /// has already voted, the quorum certificate is in hand, and the only question is whether these bytes are the block
    /// that quorum named. The hash answers that completely — it binds the whole header, and `verify_structure` binds the
    /// payload to `tx_root`/`da_commit` — so a Byzantine sender can substitute nothing.
    ///
    /// Accepting only a hash we have **parked or locked on** is what keeps it from becoming a back door into
    /// `proposals`: an unsolicited body for any other hash is dropped.
    fn on_body(&mut self, block: Block) -> Vec<Output> {
        let bh = block.hash();
        let height = self.height();
        let wanted = self.pending_finalize.get(&height) == Some(&bh) || self.locked_block == Some(bh);
        if !wanted || block.header.height != height || !block.verify_structure() {
            self.body_answers.2 = self.body_answers.2.saturating_add(1);
            return Vec::new();
        }
        self.body_taken = self.body_taken.saturating_add(1);
        self.proposals.insert(bh, block);
        if self.pending_finalize.get(&height) == Some(&bh) {
            return self.finalize(bh);
        }
        Vec::new()
    }

    /// Serve a catch-up request: if we hold a checkpoint STRICTLY newer than the requester's height and the
    /// certified state's snapshot, send it point-to-point to the authenticated requester `from` (never a
    /// broadcast, and never to a spoofable field — `from` is the real transport source). A Byzantine requester
    /// gains nothing it could not verify; the snapshot + certificate are self-authenticating.
    fn on_sync_req(&mut self, from: u8, have_height: u64) -> Vec<Output> {
        let Some(cert) = &self.checkpoint else {
            return self.answer_with_cert(from, have_height);
        };
        if cert.height <= have_height {
            return self.answer_with_cert(from, have_height);
        }
        // Holding a checkpoint is not the same as being able to *serve* it, and the two were conflated: reaching this
        // point with no retained state used to answer **nothing at all**, which from the requester's side is
        // indistinguishable from a dropped packet — so it re-asks, and is answered with silence again.
        //
        // The state a fresh checkpoint refers to is routinely absent, and not as an edge case: `on_sync_resp` clears
        // `sync_heads`/`sync_states` and *then* installs the certificate it just adopted. A validator that has itself
        // just state-synced therefore holds a checkpoint above every laggard's height and retains no snapshot for it,
        // and until it executes its next block it is a silent hole for exactly the peers it is best placed to help.
        //
        // So fall through to the certificate instead. It is strictly more than nothing — a quorum over
        // `(height, block_hash)` that finalizes the requester's height the moment it holds the body — and the
        // checkpoint path must not pre-empt it merely by existing.
        let Some((root, head)) = self.sync_heads.get(&cert.height) else {
            return self.answer_with_cert(from, have_height);
        };
        let (root, head) = (*root, *head);
        let Some(snapshot) = self.sync_states.get(&root) else {
            return self.answer_with_cert(from, have_height);
        };
        let (snapshot, cert) = (snapshot.clone(), cert.clone());
        self.sync_answers.0 = self.sync_answers.0.saturating_add(1);
        alloc::vec![Output::SendTo { to: from, msg: ConsensusMsg::SyncResp { cert, head, snapshot } }]
    }

    /// [`offer_commit_cert`](Self::offer_commit_cert), counting whether a certificate actually went back.
    fn answer_with_cert(&mut self, from: u8, have_height: u64) -> Vec<Output> {
        let out = self.offer_commit_cert(from, have_height);
        let slot = if out.is_empty() { &mut self.sync_answers.2 } else { &mut self.sync_answers.1 };
        *slot = slot.saturating_add(1);
        out
    }

    /// Answer a `SyncReq` with the COMMIT certificate that finalized the requester's current height, when the
    /// checkpoint path has nothing to offer.
    ///
    /// **Why this exists at all.** A validator finalizes only by gathering `2f+1` COMMIT votes *itself*, and votes
    /// are never retransmitted — so a validator one height behind is missing a set of signatures it can never
    /// obtain again. Two paths were supposed to rescue it and neither reaches this case: `SyncResp` serves an
    /// execution *checkpoint*, and a cell in its first heights has none; `adopt_certified_parent` reads the
    /// certificate out of a **newer block**, which requires the cell to keep proposing without the lagging
    /// validator — precisely what it may be unable to do, since the laggard is part of the quorum. That is a
    /// circularity: the evidence that would free the validator can only be produced by a cell that has already
    /// gone on without it.
    ///
    /// The certificate is that same evidence in retransmissible form. It is a quorum of signatures over
    /// `(height, block_hash)`, self-authenticating against the fixed committee, so answering with one grants a
    /// requester nothing it could not have gathered from the votes it missed — and a Byzantine peer cannot forge
    /// one. Measured on a live cell before this existed: every validator at height 1 while a peer re-offered its
    /// height-0 value into rejection, 501 `rejects.proposer` in one run and no path out.
    fn offer_commit_cert(&self, to: u8, have_height: u64) -> Vec<Output> {
        let Some(cert) = self.certified.get(&have_height).filter(|c| c.phase == Phase::Commit) else {
            return Vec::new(); // we did not finalize that height ourselves (or have pruned it)
        };
        alloc::vec![Output::SendTo { to, msg: ConsensusMsg::CommitCert(cert.clone()) }]
    }

    /// Adopt a commit certificate offered by a peer — the counterpart of [`offer_commit_cert`](Self::offer_commit_cert).
    ///
    /// Verified exactly as one read out of a block's `last_commit`, through the same
    /// [`adopt_commit_cert`](Self::adopt_commit_cert): the sender is not trusted, the quorum of signatures is.
    fn on_commit_cert(&mut self, cert: Certificate) -> Vec<Output> {
        let before = self.height();
        let out = self.adopt_commit_cert(cert);
        // Counted HERE and not inside `adopt_commit_cert`, which `adopt_certified_parent` also calls: a single counter
        // over both sources would say "a certificate advanced us" while the actual carrier was a newer block's
        // `last_commit`, and the live question is specifically whether the *offered* certificates work. Conflating two
        // mechanisms in one number is the error this instrument exists to avoid.
        if self.height() > before {
            self.cert_taken = self.cert_taken.saturating_add(1);
        }
        out
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
        self.sync_taken = self.sync_taken.saturating_add(1);
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
        // Keep the snapshot we just adopted as the one we can serve. Clearing the retention and installing the
        // certificate — which is what this did — throws away the only three things a `SyncResp` is made of, at the one
        // moment we are certain to hold all of them: the certified state, its root, and the head it sits on.
        //
        // The consequence was not a missed optimization but a silent hole. A validator whose checkpoint is above a
        // peer's height takes the snapshot branch of `on_sync_req`, finds no retained state, and answers nothing; and
        // it cannot fall back to a commit certificate either, because it *jumped over* the requester's height and so
        // never finalized it. A node that has just been rescued is the peer most likely to be asked next — it was
        // behind for the same reason its neighbours are — and it answered every one of them with silence.
        // Pinned by `a_freshly_synced_validator_still_answers_a_laggard_instead_of_going_silent`.
        self.sync_states.insert(cert.state_root, snapshot.to_vec());
        self.sync_heads.insert(height, (cert.state_root, head));
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
        // A validator **locked** on a block it holds may re-offer it whatever the round's rota says, because it
        // carries the proof: `on_propose` admits any proposer whose block comes with a PREPARE-quorum
        // certificate over that block. Without this the two halves do not meet — the receiver would accept a
        // justified re-proposal that no one is ever entitled to send, since the rota reaches a locked validator
        // only 3 rounds in 7 while the round timeout doubles toward 24 s. Duplicate re-offers are byte-identical
        // and deduplicated by hash on arrival.
        // …but only while no peer is known to have moved past us. A re-offer carries a PREPARE certificate for
        // *our* height, and `on_propose` admits an out-of-rota proposer only if that certificate matches the
        // **receiver's** height — so once the cell has advanced, every re-offer we send is refused by
        // construction. Off-rota, that refusal is the only outcome: the proposal is not merely ignored, it is
        // counted as a proposer-entitlement violation on every peer.
        //
        // Measured before this guard, on a live seven-validator cell: **501** `rejects.proposer` in one run,
        // every node at height 1, against 130 proposals whose proof was for height 0 — a validator re-offering a
        // value the cell had already left behind, once per round, forever. The lag signal `max_seen_height`
        // already exists for exactly this knowledge and drives `maybe_request_sync`; a validator that knows it is
        // behind should be asking to catch up, not proposing into a wall.
        //
        // This subtracts nothing from the mechanism's purpose. A re-offer exists to break a lock split *at the
        // contested height*, and at that height no peer is ahead — so the guard is inert precisely when the
        // re-offer can do its job, and silent exactly when it cannot.
        let can_reoffer = self.max_seen_height <= height
            && self
                .locked_block
                .is_some_and(|h| self.proposals.contains_key(&h) && self.locked_cert.is_some());
        if (!entitled && !can_reoffer) || self.proposed_round == Some(self.round) {
            return Vec::new();
        }
        // A freshly state-synced validator adopted its parent's state without locally finalizing it, so it holds
        // no commit certificate to record as this block's `last_commit` (every block above height 0 must record
        // one — the reward beneficiaries). Abstain rather than broadcast a block peers will reject; it recovers
        // the instant it helps finalize a height, which sets `last_finalized_cert`.
        if height > 0 && self.last_finalized_cert.is_none() {
            return Vec::new();
        }
        // **Re-propose the value this validator is locked on**, carrying the certificate that locked it.
        //
        // `reprepare_lock`'s liveness argument requires a *quorum* locked on the same block; below that, no
        // number of rounds can re-form the PREPARE quorum, because every fresh proposal differs from the locked
        // block and the locked minority refuses it. Measured live: three of seven locked, five needed, and the
        // four unlocked ones proposed alternatives the three refused — `rejects.locked`, five each, nothing else.
        //
        // Safe by construction: the block already gathered a PREPARE quorum (that is what locked it), so this
        // can only re-offer a value the cell was already willing to prepare, never a conflicting one. The
        // transactions it omits stay in the mempool for the next height, exactly as if this proposal had lost.
        // Prefer, in order: the value we are locked on, then any value we know the cell has already prepared
        // (`valid_value` — a polka we merely *observed*), then a fresh block. The middle rung is what lets an
        // unlocked proposer re-offer the minority's value instead of a fresh one it would have to refuse.
        let locked = self
            .locked_block
            .and_then(|h| Some((self.proposals.get(&h)?.clone(), self.locked_cert.clone()?)))
            .or_else(|| {
                let (hash, cert) = self.valid_value.clone()?;
                Some((self.proposals.get(&hash)?.clone(), cert))
            });
        let mut block = if let Some((locked, cert)) = locked {
            Block { pol: Some(Box::new(cert)), witness: None, ..locked }
        } else {
            // Order the mempool blindly by commitment (the proposer never sees contents — anti-MEV).
            let mut sealed = self.mempool.clone();
            sealed.sort_by_key(SealedTx::commit);
            Block::assemble(self.chain.head(), height, self.epoch, self.me, sealed)
        };
        // Record the certificate that finalized the parent as this block's `last_commit`, so its execution
        // rewards exactly that (agreed) finalizer set. None before the first finalization (genesis child).
        if let Some(cert) = &self.last_finalized_cert {
            block = block.with_last_commit(cert.clone());
        }
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

    /// Adopt the finalization of **our** height when a block from a *higher* height proves it.
    ///
    /// Every block above genesis records, as its `last_commit`, the quorum COMMIT certificate that finalized its parent.
    /// A proposal for height `h+1` is therefore self-authenticating proof of what height `h` finalized — the same evidence
    /// [`check_committed`] acts on, verified the same way against the same quorum, so this adds no trust. Without it the
    /// proof arrives and is **discarded**: the proposal is for a height we have not reached, the link check refuses it, and
    /// the certificate inside goes with it.
    ///
    /// ## The deadlock this breaks
    ///
    /// Quorum is `2f+1`, and a validator finalizes only by gathering that many COMMIT votes **itself**. Votes are never
    /// retransmitted, so a validator that receives `quorum - 1` of them is locked on the winning block, holds its body,
    /// and is missing nothing but a signature it can never obtain. `collect_cert` filters by the *current* round, so
    /// re-voting cannot rebuild the certificate either.
    ///
    /// With one validator short, the cell still has a quorum and advances, and its later blocks carry the proof — so it
    /// recovers. With `f+1` short the remaining validators are **below quorum**, the chain halts, and the cell can no
    /// longer produce the very evidence that would rescue them. That circularity is the deadlock, and it is reachable from
    /// nothing worse than transient message loss.
    ///
    /// Finalizing clears the lock ([`reset_round_state`]), so adoption releases it as a consequence rather than a special
    /// case. If the body is missing the decision is remembered (`pending_finalize`) and
    /// [`awaited_body`](Self::awaited_body) drives the fetch.
    fn adopt_certified_parent(&mut self, block: &Block) -> Vec<Output> {
        if block.header.height <= self.height() {
            return Vec::new();
        }
        let Some(cert) = block.last_commit.clone() else { return Vec::new() };
        self.adopt_commit_cert(cert)
    }

    /// Finalize this validator's current height from a quorum COMMIT certificate, wherever it came from — a newer
    /// block's `last_commit` ([`adopt_certified_parent`](Self::adopt_certified_parent)) or a peer's direct answer to
    /// our catch-up request ([`on_commit_cert`](Self::on_commit_cert)). One implementation, so the two sources cannot
    /// drift apart on what makes a certificate acceptable.
    ///
    /// The certificate must be for *this* height, in the COMMIT phase, and carry a `Q`-quorum of valid committee
    /// signatures. Nothing about the sender is trusted.
    fn adopt_commit_cert(&mut self, cert: Certificate) -> Vec<Output> {
        let height = self.height();
        if cert.height != height || cert.phase != Phase::Commit {
            self.cc_rejects.0 = self.cc_rejects.0.saturating_add(1);
            return Vec::new();
        }
        if !cert.verify(self.params.quorum, &self.verifiers) {
            self.cc_rejects.1 = self.cc_rejects.1.saturating_add(1);
            return Vec::new();
        }
        let bh = cert.block_hash;
        // Carry the certificate into `finalize`: the next block this validator proposes records it as `last_commit`, and
        // one rebuilt from votes we never received would not verify at any peer.
        self.certified.insert(height, cert);
        let out = self.finalize(bh);
        // Counted only when the height actually moved: `finalize` parks the decision and returns nothing when the body
        // is missing, which is precisely the case a `cert_taken` that counted attempts would hide.
        if self.height() <= height {
            self.cc_rejects.2 = self.cc_rejects.2.saturating_add(1);
        }
        out
    }

    /// Rank a round-0 proposal **skeleton** into the min-ticket lottery, without its payload.
    ///
    /// Checks everything a skeleton can carry — the proposer is an elected line member, the block links to our head at
    /// our height and epoch, its `last_commit` matches its header commitment, and its sortition witness verifies against
    /// the proposer's pre-registered root — and then buffers the ticket. It deliberately does **not** run
    /// [`Block::verify_structure`] (a skeleton's payload is empty, so `tx_root`/`da_commit` cannot match) nor the
    /// anti-MEV seal check (there are no transactions here to check); both are applied in full to the *body* before
    /// anything is prepared, which is the only place they can decide a vote.
    ///
    /// A no-op outside SSLE round 0, where there is no lottery to rank into.
    fn on_skeleton(&mut self, block: &Block) -> Vec<Output> {
        // First, and regardless of sortition: a skeleton carries `last_commit`, so it can prove what our height finalized
        // without our ever obtaining its payload.
        let adopted = self.adopt_certified_parent(block);
        if !adopted.is_empty() {
            return adopted;
        }
        if self.sortition.is_none() || self.round != 0 || self.sent_prepare.contains(&0) {
            return Vec::new();
        }
        let height = self.height();
        if !is_line_member(&self.seed, height, 0, usize::from(block.header.proposer))
            || block.header.height != height
            || block.header.parent != self.chain.head()
            || block.header.epoch != self.epoch
            || !block.last_commit_matches()
            || !self.valid_last_commit(block)
        {
            if block.header.height > height {
                self.note_height(block.header.height); // a skeleton for a height ahead of us — we are behind
            }
            return Vec::new();
        }
        let Some(ticket) = self.verify_witness(block) else {
            return Vec::new();
        };
        self.rank_round0(block.header.proposer, ticket, block.hash(), height)
    }

    /// Enter `(proposer, ticket)` into the round-0 lottery and prepare if the outcome is already decided.
    ///
    /// Shared by the skeleton and full-block paths so one rule governs the lottery: buffer the ticket, open the
    /// collection window on the first entry, and short-circuit the wait once **every** elected line member has been
    /// ranked — at which point the minimum is final and no further waiting can change it.
    fn rank_round0(&mut self, proposer: u8, ticket: [u8; 32], bh: [u8; 32], height: u64) -> Vec<Output> {
        self.round0_tickets.entry(proposer).or_insert((ticket, bh));
        if self.round0_window.is_none() {
            self.round0_window = Some(0);
        }
        let line_size = line_members(leader_line(&self.seed, height, 0)).len();
        if self.round0_tickets.len() >= line_size {
            return self.prepare_round0_min();
        }
        // Otherwise the lottery is still open, and preparing now would be the very defect the window exists to prevent:
        // the first proposal seen is not the minimum, and honest replicas seeing different firsts would split their
        // PREPAREs and stall the round.
        //
        // The one exception is a body arriving *after* the window already expired — the winner was ranked from its
        // skeleton and we have been waiting for exactly this payload, so it must be able to trigger the PREPARE rather
        // than wait for the next tick.
        if self.round0_window.is_some_and(|w| w >= COLLECT_WINDOW_TICKS) {
            return self.prepare_round0_min();
        }
        Vec::new()
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
        // A **proof of lock** justifies any proposer: a PREPARE-quorum certificate over this very block at this
        // height proves the cell was already willing to prepare it, which is stronger evidence than holding this
        // round's leader slot. Without it only the original proposer could re-offer a locked block, since the
        // header commits to `proposer` — and it may not be entitled in the round where the re-offer is needed.
        let pol_ok = block.pol.as_ref().is_some_and(|c| {
            c.phase == Phase::Prepare
                && c.height == height
                && c.block_hash == bh
                && c.verify(self.params.quorum, &self.verifiers)
        });
        if pol_ok
            && let Some(cert) = block.pol.as_deref()
        {
            // A polka observed. Keep the newest one: a certificate from a later round supersedes an earlier
            // view of what the cell was willing to prepare.
            let newer = self.valid_value.as_ref().is_none_or(|(_, held)| cert.round >= held.round);
            if newer {
                self.valid_value = Some((bh, cert.clone()));
            }
        }
        let proposer_ok = pol_ok
            || if sortition_round0 {
                is_line_member(&self.seed, height, 0, usize::from(block.header.proposer))
            } else {
                leader(&self.seed, height, self.round) as u8 == block.header.proposer
            };
        let links = block.header.height == height
            && block.header.parent == self.chain.head()
            && block.header.epoch == self.epoch;
        if !proposer_ok || !links || !block.verify_structure() || !self.valid_last_commit(&block) {
            // Counted separately, because "the proposer had no right to propose" and "the block does not link to my
            // head" are different failures with different fixes, and a fused condition cannot say which fired.
            if !proposer_ok {
                self.rejects.proposer += 1;
            } else if !links {
                self.rejects.link += 1;
            } else if !block.verify_structure() {
                self.rejects.structure += 1;
            } else {
                self.rejects.last_commit += 1;
            }
            if block.header.height > height {
                self.note_height(block.header.height); // a proposal for a height ahead of us — we are behind
                // Before discarding it: a block from a higher height carries the certificate that finalized ours.
                let adopted = self.adopt_certified_parent(&block);
                if !adopted.is_empty() {
                    return adopted;
                }
            }
            return Vec::new();
        }
        // Anti-MEV admission (audit fix): every included transaction must be sealed to this epoch's beacon
        // keyper line. A block carrying even one malformed seal is refused, so a Byzantine proposer cannot
        // slip in a transaction that no honest committee can ever decrypt (which would stall execution).
        if !block.sealed_txs.iter().all(|tx| self.valid_seal(tx)) {
            self.rejects.seal += 1;
            return Vec::new();
        }
        // Data-availability gate (spec §L4.3 / §10.1), verified IN-ENGINE: reconstruct the payload from the
        // shards this validator sampled and check it against the header's `da_commit`. A withholding proposer
        // leaves too few shards to reconstruct (an unrecoverable erasure pattern), or the reconstruction fails
        // the commitment — either way `reconstruct_payload` returns `None` and the validator withholds PREPARE.
        // The engine no longer trusts a driver-supplied availability bit; it checks the shards cryptographically.
        if block.reconstruct_payload(shards).is_none() {
            self.rejects.unavailable += 1;
            return Vec::new();
        }
        // SSLE round 0: the proposal must carry a valid sortition witness (verified against the proposer's
        // registered root). Computed here — AFTER the availability/seal gates, exactly as for a public block —
        // so a witness probe cannot be answered faster than a genuine proposal. An unverifiable witness ⇒ ignore.
        let ticket = if sortition_round0 {
            let Some(t) = self.verify_witness(&block) else {
                self.rejects.witness += 1;
                return Vec::new();
            };
            Some(t)
        } else {
            None
        };
        // Remember the (valid, available) block body so we can finalize it later even if a conflicting
        // proposal arrives afterwards (equivocation) — keyed by hash, never overwritten by a different block.
        let proposer = block.header.proposer;
        // Decided before the block moves into `proposals`: the unlocking evidence rides on the proposal, so it
        // has to be read while we still hold it.
        let releases_our_lock = self.unlocks_us(&block);
        self.proposals.entry(bh).or_insert(block);
        // If we already hold a commit certificate for this height+block but were waiting on the body (an async
        // scheduler delivered the CC first), finalize now instead of staying wedged (audit fix, HIGH 3).
        if self.pending_finalize.get(&height) == Some(&bh) {
            return self.finalize(bh);
        }
        if let Some(ticket) = ticket {
            // Round-0 lottery: rank this ticket (never prepare on first sight — that would split honest PREPAREs
            // across members and stall the round). The body is now in `proposals`, so if this block is the current
            // minimum, `rank_round0` prepares it here.
            return self.rank_round0(proposer, ticket, bh, height);
        }
        // Round ≥ 1 (or sortition disabled): the single-leader immediate prepare (the pre-SSLE path, unchanged).
        // Safety lock: never prepare a block conflicting with the one we are locked on — **unless the proposal
        // proves the cell moved on**. See `unlocks_us`.
        if let Some(locked) = self.locked_block
            && locked != bh
            && !releases_our_lock
        {
            self.rejects.locked += 1;
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

    /// Whether `block` carries the evidence that releases this validator's lock — Tendermint's **unlocking
    /// rule**, and it was missing.
    ///
    /// A validator locked on `v` at round `r_lock` refuses every conflicting proposal. Taken alone that is not a
    /// safety property but a deadlock: at the same height it can then accept *nothing else, ever*, no matter
    /// what the rest of the cell demonstrably agreed. The lock is meant to be released by proof, and the proof
    /// is a PREPARE quorum for the new value at a round **strictly later** than the one we locked at.
    ///
    /// The `pol` field carrying that proof already existed and was already checked — but only for *proposer
    /// entitlement* (`pol_ok` in [`on_propose`](Self::on_propose)), never for unlocking. So the mechanism that
    /// decides **who may propose** a re-offered value was built, and the one that decides **who may accept it**
    /// was not. Measured live before this: a sub-quorum lock split froze a cell for its whole 240 s budget with
    /// `rejects.locked` and nothing else anywhere.
    ///
    /// ## Why releasing is safe
    ///
    /// We locked on `v` because we saw `Q = 2f+1` PREPAREs for it at `r_lock`. Releasing requires `Q` PREPAREs
    /// for `v'` at `r_pol > r_lock`. Two quorums of `2f+1` out of `n = 3f+1` intersect in at least `f+1`
    /// validators, so at least one **honest** validator prepared both — which an honest validator does only if
    /// it had itself released its lock on `v`, i.e. only if it had seen this same kind of evidence. The
    /// induction bottoms out at a *committed* value: once `Q` COMMIT votes exist for `v`, no conflicting
    /// PREPARE quorum can form at any later round, because that would need `f+1` honest validators to prepare
    /// against a lock none of them can have released. Agreement is preserved; what is released is the deadlock.
    ///
    /// Refusing to release is therefore not the conservative choice it looks like. It trades a liveness
    /// property the theorem grants for no safety the theorem asks for.
    fn unlocks_us(&self, block: &Block) -> bool {
        let Some(held) = &self.locked_cert else { return false };
        let Some(pol) = &block.pol else { return false };
        pol_shape_releases(pol, block.hash(), self.height(), held.round, self.round)
            && pol.verify(self.params.quorum, &self.verifiers)
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
        // The lottery ranks skeletons, so the winner's *body* may not be here yet. Wait for it rather than prepare a
        // higher ticket: every replica ranks the same skeleton set, so all of them wait for the same block and the
        // outcome stays agreed. A winner that never delivers is evicted by `tick_round0_window` on window expiry, so
        // this waits for propagation, never indefinitely.
        if !self.proposals.contains_key(&bh) {
            return Vec::new();
        }
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
        if w + 1 < COLLECT_WINDOW_TICKS || self.round0_tickets.is_empty() {
            return Vec::new();
        }
        // Past expiry: prepare the minimum as soon as its body is in hand. Retried every tick, because the window
        // bounds how long we wait for further *skeletons* — which arrive without sampling — and not how long the
        // winner's payload takes to reconstruct.
        //
        // Deliberately no eviction timer for a winner whose body never comes. The round timeout already covers it: the
        // round advances and round 1's public fallback proposes, which is the same bounded cost a withheld public
        // proposal has always had (`a_withheld_block_never_finalizes_and_the_round_advances`). An eviction timer here
        // would have to be derived from DA sampling latency, which this sans-I/O engine cannot observe — and a timer
        // guessed at instead was measured evicting every honest proposer in turn, one per tick, until the lottery was
        // empty and the height could never be led at all.
        self.prepare_round0_min()
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
        out.extend(self.round_failed_by_votes());
        out.extend(self.maybe_advance_round());
        out
    }

    /// End a round the **votes** say has failed, without waiting for the clock.
    ///
    /// Tendermint's rule: once `2f+1` validators have PREPAREd in this round and no single value holds a
    /// quorum, the round cannot produce a decision — every remaining validator could vote and still not reach
    /// `Q` for any one value. Waiting out the timeout at that point is waiting for information that has already
    /// arrived.
    ///
    /// It is the other half of [`NIL`]: nil makes "I refused" observable, and this is what observing it is
    /// *for*. Together they turn round failure from a wall-clock event into a message-driven one — and the
    /// clock in question doubles toward 24 s, which is why a live cell was reaching round 13 inside a 240 s
    /// budget while every validator already knew each round had failed.
    ///
    /// Safe unconditionally: advancing a round decides nothing. The lock and all committed state persist, votes
    /// are round-tagged so no certificate can be assembled across the boundary, and a validator that advances
    /// early simply arrives where the timeout would have taken it.
    fn round_failed_by_votes(&mut self) -> Vec<Output> {
        let height = self.height();
        let mut by_value: BTreeMap<[u8; 32], BTreeSet<u8>> = BTreeMap::new();
        let mut voters: BTreeSet<u8> = BTreeSet::new();
        for sv in &self.prepares {
            if sv.vote.height == height && sv.vote.round == self.round {
                voters.insert(sv.vote.voter);
                by_value.entry(sv.vote.block_hash).or_default().insert(sv.vote.voter);
            }
        }
        if voters.len() < self.params.quorum {
            return Vec::new(); // the round has not spoken yet
        }
        // A value that already holds a quorum decides the round; one that *could still* reach one keeps it
        // alive. Only when neither is true has the round provably failed.
        let undecided = self.params.n.saturating_sub(voters.len());
        let alive = by_value
            .iter()
            .any(|(hash, who)| *hash != NIL && who.len().saturating_add(undecided) >= self.params.quorum);
        if alive {
            return Vec::new();
        }
        self.advance_round()
    }

    /// Jump to the round `f + 1` validators have already reached — **round synchronization**, and it was missing.
    ///
    /// Rounds advanced here by exactly one thing: this validator's own timeout firing. Nothing ever moved a validator
    /// toward the round its peers were on. Since local timers are independent, and the round timeout doubles toward
    /// 24 s, validators drift apart on ordinary scheduling noise and then have **no mechanism to re-converge**.
    ///
    /// That is not a cosmetic divergence, because proposer entitlement is round-dependent: `on_propose` judges a
    /// proposal against `leader(seed, height, self.round)` using the **receiver's** round, and the block header
    /// deliberately does not carry the sender's (a header must stay round-independent, or a re-proposal would not be
    /// byte-identical and a locked validator could never accept one). So a proposer that is legitimate at its own round
    /// is an impostor at a peer one round ahead, and the proposal is not merely ignored — it is counted as an
    /// entitlement violation and discarded. A drifted cell rejects the very proposals it makes to itself.
    ///
    /// Measured across every frozen trace in this investigation: hundreds of `rejects.proposer`, rounds climbing to 13,
    /// and validators sitting at different rounds in the same snapshot (`v0` at 12 while six peers were at 13).
    ///
    /// `f + 1` is the threshold because it guarantees at least one **honest** validator has genuinely reached that
    /// round, so the jump follows real progress rather than a Byzantine minority's claim. Jumping forward is safe by
    /// the same argument that makes timeouts safe: the lock and all committed state persist across rounds, and votes
    /// are round-tagged, so no certificate can be assembled from votes of a round we skipped.
    fn maybe_advance_round(&mut self) -> Vec<Output> {
        let height = self.height();
        // Each peer's highest round at this height, above ours.
        let mut highest: BTreeMap<u8, u32> = BTreeMap::new();
        for sv in self.prepares.iter().chain(&self.commits) {
            if sv.vote.height == height && sv.vote.round > self.round && sv.vote.voter != self.me {
                let slot = highest.entry(sv.vote.voter).or_insert(0);
                *slot = (*slot).max(sv.vote.round);
            }
        }
        let threshold = self.params.f + 1;
        if highest.len() < threshold {
            return Vec::new();
        }
        // The highest round that `f + 1` validators have all reached: sort descending, take the `f + 1`-th.
        let mut rounds: Vec<u32> = highest.into_values().collect();
        rounds.sort_unstable_by(|a, b| b.cmp(a));
        let Some(&target) = rounds.get(threshold - 1) else { return Vec::new() };
        if target <= self.round {
            return Vec::new();
        }
        self.round = target;
        // Exactly what a timeout does on arrival at a new round — re-offer the lock, propose if now entitled. Round-0
        // sortition state is not reset: a jump is always *forward*, and round 0 is behind us by construction.
        let mut out = self.reprepare_lock();
        out.extend(self.maybe_propose());
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
        // A quorum of `nil` means the round failed, not that the cell agreed on nothing-in-particular. Locking
        // on it would be locking on the absence of a decision, and every later proposal would then have to
        // "unlock" from a value that never existed.
        if block_hash == NIL || round != self.round || self.sent_commit.contains(&self.round) {
            return Vec::new();
        }
        let cert = self.collect_cert(Phase::Prepare, block_hash);
        if !cert.verify(self.params.quorum, &self.verifiers) {
            return Vec::new();
        }
        // Prepared: lock the block and commit to it. The certificate that justified the lock is retained as the
        // proof-of-lock a later re-proposal needs (see `Block::pol`) — it can only be rebuilt here, because
        // `collect_cert` reads the *current* round's votes and the lock outlives its round.
        self.locked_block = Some(block_hash);
        self.locked_cert = Some(cert.clone());
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

    /// Whether a proposal's recorded `last_commit` is acceptable. A block above height 1 must record a valid
    /// commit **Q-certificate for its parent** — the finalizer set its execution rewards, verified here so a
    /// proposer cannot fabricate beneficiaries. A height-1 block's parent is genesis (never voted), so it records
    /// none. (The round within the certificate is free: any round that finalized the parent is legitimate.)
    fn valid_last_commit(&self, block: &Block) -> bool {
        match &block.last_commit {
            // Only the first block (height 0, parent GENESIS_PARENT) has no parent commit to record; every later
            // block MUST record the certificate that finalized its parent (the reward beneficiaries).
            None => block.header.height == 0,
            Some(cert) => {
                cert.phase == Phase::Commit
                    && cert.block_hash == block.header.parent
                    && cert.height == block.header.height.saturating_sub(1)
                    && cert.verify(self.params.quorum, &self.verifiers)
            }
        }
    }

    /// Finalize the block named by `block_hash`: extend the chain, emit the anti-MEV reveals for this
    /// validator's shares, queue execution, and reset per-height state for the next height.
    fn finalize(&mut self, block_hash: [u8; 32]) -> Vec<Output> {
        let height = self.height();
        let Some(block) = self.proposals.get(&block_hash).cloned() else {
            // We hold a commit certificate but not the block body yet (an async scheduler delivered the CC
            // before the proposal). Remember the decision and finalize the instant on_propose delivers the
            // body — never wedge permanently at this height (audit fix, HIGH 3).
            // Record the evidence while it still exists. `collect_cert` filters votes by the current height and
            // round, so the commit quorum that brought us here — the quorum that is the *reason* we are finalizing — is
            // unrecoverable the moment this height moves on. Parking without it lost two things at once: this validator
            // could not offer the certificate to a peer in the same position, and it could not name a peer to ask for
            // the body, since the certificate's voters are exactly the holders (`maybe_request_body`).
            if !self.certified.contains_key(&height) {
                let cert = self.collect_cert(Phase::Commit, block_hash);
                self.certified.insert(height, cert);
            }
            self.pending_finalize.insert(height, block_hash);
            return Vec::new();
        };
        self.pending_finalize.remove(&height);
        // Retain the body before `reset_round_state` drops it: a validator that never received this block is still
        // committed to it and can only recover by asking someone who has it.
        self.recent_bodies.insert(block_hash, block.clone());
        let included: BTreeSet<TxCommit> = block.sealed_txs.iter().map(SealedTx::commit).collect();
        // Capture the canonical commit certificate that finalized this block — BEFORE `chain.finalize` advances
        // `self.height()`, which `collect_cert` filters votes by. The NEXT block this validator proposes records
        // it as its `last_commit`: that recorded certificate — not any node's local commit view — is the agreed
        // finalizer set the block reward is credited to at execution (`StateMachine::apply_block_reward`), which
        // is what lets the reward be part of committed state at all (a per-node split could differ across
        // validators and so could never be part of the state root).
        let finalizer = self
            .certified
            .get(&height)
            .cloned()
            .unwrap_or_else(|| self.collect_cert(Phase::Commit, block_hash));
        // Retained, not consumed: a peer short of this height's COMMIT quorum can be handed this exact certificate,
        // and after `chain.finalize` below no validator can rebuild it from votes again.
        //
        // Bounded to the same window as `recent_bodies`, and that is not an arbitrary pairing: a certificate is only
        // useful to a stuck peer alongside the body it finalizes, so retaining one past the other buys nothing. Without
        // this the map grows one entry per height forever whenever execution checkpoints stop forming —
        // `prune_sync_retention` is the only other thing that trims it, and it runs only when one does.
        self.certified.insert(height, finalizer.clone());
        if let Some(floor) = height.checked_sub(RECENT_BODY_CAP as u64) {
            self.certified.retain(|&h, _| h >= floor);
        }
        self.last_finalized_cert = Some(finalizer);
        self.chain.finalize(block.header.clone());

        let mut out = alloc::vec![Output::Committed { height, block_hash }];
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
        // Drop included transactions from the mempool **before** executing. Execution returns premature
        // transactions to the pool, and this retain is keyed on inclusion — run afterwards it would take them
        // straight back out, which is the whole defect in miniature. The retain reads no execution state, so
        // the order is free to be the correct one.
        self.mempool.retain(|t| !included.contains(&t.commit()));
        out.extend(self.try_execute());
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
        self.locked_cert = None;
        self.valid_value = None;
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
            // The sealed transaction each opened one came from, paired **by construction**: an undecryptable
            // transaction is skipped below, so the two vectors are not index-aligned with `block.sealed_txs`
            // and a deferred outcome could not otherwise be matched back to the entry to re-queue.
            let mut opened_from: Vec<SealedTx> = Vec::new();
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
                    Some(txn) => {
                        opened.push(txn);
                        opened_from.push(tx.clone());
                    }
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
            // Credit the block reward to the parent's finalizers — the validators whose signatures form this
            // block's recorded `last_commit` (already validated as a commit Q-certificate for the parent in
            // on_propose). Canonical: every validator reads the identical finalizer set from the committed
            // block, so crediting it is a deterministic state transition that lands in the state root.
            if self.reward_per_block > 0
                && let Some(cert) = &block.last_commit
            {
                let beneficiaries: Vec<HybridVerifier> = cert
                    .votes
                    .iter()
                    .filter_map(|sv| self.verifiers.get(usize::from(sv.vote.voter)).cloned())
                    .collect();
                self.chain.apply_block_reward(&beneficiaries, self.reward_per_block);
            }
            // One call, not a loop: `apply_block` lets a state machine schedule the block's independent transactions in
            // parallel (DROMOS does) while a plain ledger keeps the identical serial semantics via the default.
            let outcomes = self.chain.execute_block(&opened);
            // Return premature transactions to the mempool. Blind ordering means a proposer cannot order a
            // sender's transactions by a nonce it cannot see, so a block routinely carries nonce 2 ahead of
            // nonce 1; without this the later one is dropped at finalize (keyed on inclusion, not outcome) and
            // is never executed and never retryable — measured as four transfers from one account executing
            // exactly one.
            //
            // Bounded by the engine's existing give-up horizon rather than a new constant: a transaction still
            // premature `REVEAL_WINDOW` blocks after its first deferral is dropped, the same horizon that
            // already decides when an undecryptable transaction stops being waited for.
            for (sealed, outcome) in opened_from.iter().zip(&outcomes) {
                if *outcome != ExecOutcome::Deferred {
                    self.deferred_since.remove(&sealed.commit());
                    continue;
                }
                let first = *self.deferred_since.get(&sealed.commit()).unwrap_or(&block.header.height);
                if block.header.height.saturating_sub(first) <= REVEAL_WINDOW {
                    self.deferred_since.insert(sealed.commit(), first);
                    self.submit(sealed.clone());
                } else {
                    self.deferred_since.remove(&sealed.commit());
                }
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
        self.certified.retain(|&h, _| h >= checkpoint_height);
        let live: BTreeSet<[u8; 32]> = self.sync_heads.values().map(|(r, _)| *r).collect();
        self.sync_states.retain(|r, _| live.contains(r));
    }

    /// Advance the round (proposer timeout): re-elect a leader and clear this round's proposal/prepare state.
    /// Locks and committed-block state persist across rounds (safety); votes are round-tagged so stale-round
    /// votes never form a current-round certificate.
    fn on_timeout(&mut self) -> Vec<Output> {
        // **First expiry in this round: speak, and stay.** A validator that has accepted nothing says so with a
        // `nil` PREPARE and remains where it is, because the statement is only useful to peers who are still in
        // the round to hear it. Leaving in the same step — which the first version of this did — broadcasts the
        // news to a round everyone has already left.
        //
        // The round then ends on the *votes* ([`round_failed_by_votes`]), which is the whole point: a failed
        // round finishes when the cell knows it failed, not when a clock that doubles toward 24 s says so.
        // Reaching here a second time means those votes never arrived, and the timeout does what it always did.
        if !self.sent_prepare.contains(&self.round) {
            return self.prepare_nil();
        }
        self.advance_round()
    }

    /// Leave the current round for the next one.
    fn advance_round(&mut self) -> Vec<Output> {
        self.round = self.round.saturating_add(1);
        // Proposals already seen this height stay valid bodies (same parent/height); only the round advances.
        // A fresh round may re-elect this validator as leader; `proposed_round` is compared against the new
        // round, so no reset is needed for it to propose again.
        let mut out = self.reprepare_lock();
        out.extend(self.maybe_propose());
        out
    }

    /// Broadcast a `nil` PREPARE for the current round, if this validator has not prepared anything in it.
    ///
    /// The signal that lets a round end **by votes instead of by clock** — see [`NIL`]. Sent once per
    /// round (`sent_prepare` is the same gate a real prepare uses), so a validator cannot both prepare a value
    /// and prepare nil, which would be equivocation.
    fn prepare_nil(&mut self) -> Vec<Output> {
        if self.sent_prepare.contains(&self.round) {
            return Vec::new();
        }
        self.sent_prepare.insert(self.round);
        let vote = Vote {
            height: self.height(),
            round: self.round,
            block_hash: NIL,
            phase: Phase::Prepare,
            voter: self.me,
        };
        let sv = SignedVote::sign(vote, &self.signer);
        let mut out = self.accept_vote(sv.clone());
        out.push(Output::Send(ConsensusMsg::Vote(sv)));
        out
    }

    /// Re-PREPARE the block this validator is **locked** on, in the round just entered.
    ///
    /// Without this a locking consensus deadlocks the moment a PREPARE quorum forms without a COMMIT quorum. The lock is
    /// set by [`check_prepared`] and released only by [`reset_round_state`] — that is, only on finalizing a height — so
    /// every later round's proposal is refused by the `locked_block` gate, no quorum can form for anything, and the
    /// height never advances again.
    ///
    /// Leader rotation alone is not the escape, though it looks like one: a block header commits to
    /// `(parent, height, epoch, proposer, tx_root, da_commit, last_commit_root)` and **not** to the round, so a
    /// re-proposal by the same proposer is byte-identical and a locked validator can accept it — which does recover a
    /// cell whose mempool is unchanged. It fails precisely when the mempool moves underneath, since every later proposal
    /// then differs from the locked block and can never match it. That is the ordinary case: a client submits into a
    /// running cell, so the block that got locked was empty and everything after it carries the transaction.
    ///
    /// This is Tendermint's rule — on entering a round, prevote the value you are locked on — and it is safe by
    /// construction rather than by argument: it only ever prepares the block already locked, never a conflicting one.
    /// Liveness follows because a quorum locked on the same block re-prepares it together, so the PREPARE quorum re-forms
    /// in the new round and the COMMIT quorum follows.
    ///
    /// Requires the body: a validator that locked on a hash whose block it never received cannot vote to prepare
    /// something it cannot execute, and it recovers by sampling or by state sync.
    fn reprepare_lock(&mut self) -> Vec<Output> {
        let Some(bh) = self.locked_block else { return Vec::new() };
        if self.sent_prepare.contains(&self.round) || !self.proposals.contains_key(&bh) {
            return Vec::new();
        }
        self.sent_prepare.insert(self.round);
        let vote =
            Vote { height: self.height(), round: self.round, block_hash: bh, phase: Phase::Prepare, voter: self.me };
        let sv = SignedVote::sign(vote, &self.signer);
        let mut out = self.accept_vote(sv.clone());
        out.push(Output::Send(ConsensusMsg::Vote(sv)));
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A proof-of-lock with the given shape. Signatures are not exercised here — [`pol_shape_releases`] is the
    /// structural half by construction, and the cryptographic half is checked separately by `Certificate::verify`.
    fn pol(phase: Phase, height: u64, round: u32, block_hash: [u8; 32]) -> Certificate {
        Certificate { phase, height, round, block_hash, votes: Vec::new() }
    }

    const BH: [u8; 32] = [7u8; 32];

    #[test]
    fn a_later_prepare_quorum_for_this_block_releases_the_lock() {
        // The rule itself: locked at round 2, a proof from round 4, current round 5.
        assert!(pol_shape_releases(&pol(Phase::Prepare, 9, 4, BH), BH, 9, 2, 5));
    }

    #[test]
    fn a_proof_from_our_own_round_or_earlier_never_releases() {
        // **The safety boundary.** Our lock exists because a quorum prepared our value at round 2; a second
        // quorum for a different value at round 2 can only exist if `f+1` validators equivocated. Releasing on
        // it would make one equivocating round enough to split the cell — exactly what the lock prevents.
        assert!(!pol_shape_releases(&pol(Phase::Prepare, 9, 2, BH), BH, 9, 2, 5), "equal round");
        assert!(!pol_shape_releases(&pol(Phase::Prepare, 9, 1, BH), BH, 9, 2, 5), "earlier round");
        assert!(!pol_shape_releases(&pol(Phase::Prepare, 9, 0, BH), BH, 9, 2, 5), "round zero");
    }

    #[test]
    fn a_proof_from_a_round_we_have_not_reached_never_releases() {
        // Not evidence about the past. If a quorum really is voting there, round synchronization brings us to
        // that round and the proof is judged again on its merits.
        assert!(!pol_shape_releases(&pol(Phase::Prepare, 9, 6, BH), BH, 9, 2, 5));
    }

    #[test]
    fn a_proof_about_something_else_never_releases() {
        assert!(!pol_shape_releases(&pol(Phase::Commit, 9, 4, BH), BH, 9, 2, 5), "wrong phase");
        assert!(!pol_shape_releases(&pol(Phase::Prepare, 8, 4, BH), BH, 9, 2, 5), "wrong height");
        assert!(!pol_shape_releases(&pol(Phase::Prepare, 9, 4, [1u8; 32]), BH, 9, 2, 5), "wrong block");
    }

    #[test]
    fn the_release_window_is_exactly_the_open_interval_above_our_lock() {
        // Every round from 0 to `now`, checked against the rule as stated, so a future edit that widens or
        // narrows the window by one fails here rather than in a cell.
        const LOCKED_AT: u32 = 3;
        const NOW: u32 = 7;
        for round in 0..=NOW + 2 {
            let releases = pol_shape_releases(&pol(Phase::Prepare, 1, round, BH), BH, 1, LOCKED_AT, NOW);
            assert_eq!(
                releases,
                round > LOCKED_AT && round <= NOW,
                "round {round} released={releases}, but the rule is `locked < round <= now`"
            );
        }
    }
}
