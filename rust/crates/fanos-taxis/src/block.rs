//! The block, its hash-linked header, and the data-availability (DA) commitment (spec §10.1,
//! `docs/design-taxis.md` §4, §6).
//!
//! A [`BlockHeader`] is the small, canonically-encoded, hash-linked object that validators **vote on**. It
//! commits to the ordered transaction set (`tx_root`) and to the erasure-coded payload (`da_commit`), so a
//! validator can verify a proposer's header against the payload it actually shipped — a proposer cannot
//! finalize a header describing a payload it withheld or altered.
//!
//! The payload — the ordered [`SealedTx`] ciphertexts — is erasure-coded with the **projective LRC**
//! (`[7,3,4]` on the Fano cell, [`fanos_code::erasure`]) across the cell's seven nodes. Availability then gates
//! PREPARE (see [`crate::consensus`]) by **reconstruction**: a validator rebuilds the payload from the shards it
//! sampled off its peers and matches it against `da_commit`, so a withholding proposer leaves an unrecoverable
//! erasure pattern and a tampering one fails the commitment.
//!
//! Not the `k`-lines *sampling* procedure of [`fanos_code::da`], which this note used to cite — that one, with
//! its `(1/7)^k` bound from the ≤ 1-external-line theorem, is the **L4 erasure store's**
//! (`fanos_runtime::overlay::storage`). The split is deliberate rather than accidental: consensus must hold the
//! body to execute it anyway, so the stronger check costs it nothing, while the store is asked about objects it
//! has no reason to materialise — which is the situation sampling exists for. See `docs/design-taxis.md` §6.

use alloc::vec::Vec;

use fanos_code::erasure;
use fanos_wire::{MAX_FRAME, varint};

use crate::wire::{ShardMsg, shard_to_frame};

/// The bytes an **App frame** adds around a payload that could fill a frame — measured, worst case.
///
/// Every TAXIS message reaches the wire through one `wire::app_frame`, so this is the shared part of both
/// budgets below. It used to be hand-counted as `8 + 8`, a deliberate over-estimate of two varints because
/// under-estimating puts a message back over the ceiling where it is dropped in silence. That asymmetry
/// argument was right and the number was still a guess: the true envelope is a type varint, a length varint
/// and the App kind byte, and only the encoder knows those widths. Measuring cannot drift from the wire
/// when the codec changes; a hand count silently does.
///
/// The only part that grows with the payload is the length varint, so the worst case is added rather than
/// assumed — [`varint::encoded_len`] at a frame-filling body, less what this small probe already charged.
fn app_envelope() -> usize {
    let probe = ShardMsg::NeedSkeleton { block: [0; 32] };
    let framed = shard_to_frame(&probe).len();
    // `framed = varint(type) ‖ varint(body) ‖ body`, and `body = kind(1) ‖ payload`.
    let body = probe.to_bytes().len() + 1;
    // Isolate the type varint by removing the body and the length varint that measured it. Written this way
    // rather than as `framed − payload`: the length varint is the part that GROWS with the payload, so it has
    // to be identified and replaced, not carried over from a probe that happens to be small. At these sizes
    // both are one byte and either arithmetic gives the same answer — which is exactly why the wrong one
    // would have survived until a probe crossed 127 bytes and the allowance silently went short.
    let type_varint = framed - body - varint::encoded_len(body as u64);
    type_varint + varint::encoded_len(MAX_FRAME as u64) + 1
}

/// Bytes a `ShardMsg::Deliver` adds around one DA shard, plus the App envelope — measured by encoding an
/// empty `Deliver` through the same `to_bytes` the driver's `shard_to_frame` calls.
fn shard_frame_overhead() -> usize {
    let header = ShardMsg::Deliver { block: [0; 32], index: 0, data: Vec::new() }.to_bytes().len();
    header + app_envelope()
}

/// Bytes a consensus message adds around a whole block, plus the App envelope.
///
/// `ConsensusMsg::to_bytes` is documented as "a 1-byte variant tag then the variant's body", and that one
/// byte is the entire difference between a block and the message carrying it — there is no inner length
/// prefix, because the frame layer already delimits the message. Stated here rather than measured to avoid
/// encoding a whole block twice merely to learn the size of its wrapper; pinned by a test that encodes a
/// real `ConsensusMsg` and checks the difference is exactly this.
const CONSENSUS_VARIANT_TAG: usize = 1;

fn consensus_msg_overhead() -> usize {
    CONSENSUS_VARIANT_TAG + app_envelope()
}
use fanos_primitives::{Epoch, hash_labeled};
use fanos_vrf::pqvrf::{self, MerkleProof, VrfOutput};
use fanos_wire::Wire;
use fanos_wire_derive::Wire;

use crate::tx::{SealedTx, TxCommit};
use crate::vote::Certificate;

const HEADER_LABEL: &str = "FANOS-v1/taxis-block-header";
const TX_ROOT_LABEL: &str = "FANOS-v1/taxis-tx-root";
const DA_COMMIT_LABEL: &str = "FANOS-v1/taxis-da-commit";
const LAST_COMMIT_LABEL: &str = "FANOS-v1/taxis-last-commit";
const REVEAL_ROOT_LABEL: &str = "FANOS-v1/taxis-reveal-root";

/// The **secret-leader sortition witness** a round-0 proposer attaches to its block: its post-quantum
/// Merkle-VRF `output` at index `height`, plus the `proof` binding that output to the proposer's
/// pre-registered root (verified by [`crate::committee::verify_leader_ticket`]). The ticket
/// `H(output ‖ SEED ‖ height ‖ round)` derives from it, and the **lowest ticket leads** (SSLE, §10.1).
///
/// It lives **outside** the hashed [`BlockHeader`] — an auxiliary leadership proof, like a signature. Because
/// the Merkle-VRF output is unique (RFC 9381 full uniqueness) the valid witness for a given `(proposer,
/// height)` is unique, so keeping it out of the block identity is safe: it cannot be forged, and a stripped
/// or corrupted witness merely makes the proposal un-rankable (the validator ignores it), never a fork. A
/// round ≥ 1 public-fallback block carries `None`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LeaderWitness {
    /// The Merkle-VRF output at index `height` — the sortition value.
    pub output: VrfOutput,
    /// The Merkle authentication path binding `output` to the proposer's registered root.
    pub proof: MerkleProof,
}

impl LeaderWitness {
    /// Canonical bytes: `output(32) ‖ proof-siblings`. The sibling count (tree height) is recovered from the
    /// length, so the encoding is self-describing.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.proof.len() * 32);
        out.extend_from_slice(&self.output);
        out.extend_from_slice(&self.proof.to_bytes());
        out
    }

    /// Decode [`to_bytes`](Self::to_bytes): the leading 32 bytes are the output, the remainder is a whole
    /// number of 32-byte siblings. `None` if the length is not `32 + 32·k`.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 || !(bytes.len() - 32).is_multiple_of(32) {
            return None;
        }
        let (out_bytes, proof_bytes) = bytes.split_at(32);
        let output: VrfOutput = out_bytes.try_into().ok()?;
        let height = (proof_bytes.len() / 32) as u32;
        let proof = MerkleProof::from_bytes(proof_bytes, height)?;
        Some(Self { output, proof })
    }
}

/// The all-zero hash naming "no parent" — the genesis link.
pub const GENESIS_PARENT: [u8; 32] = [0u8; 32];

/// A block header — the hash-linked, voted-on object (spec §10.1). Canonically [`Wire`]-encoded, so every
/// validator hashes the identical bytes and agrees on the block hash.
#[derive(Clone, PartialEq, Eq, Debug, Wire)]
pub struct BlockHeader {
    /// The parent block's [`hash`](Self::hash), or [`GENESIS_PARENT`] at height 0.
    pub parent: [u8; 32],
    /// The block height (0 = genesis).
    pub height: u64,
    /// The epoch this block was proposed in (fixes the beacon leader schedule and sealing committees).
    pub epoch: Epoch,
    /// The elected proposer's validator index `0..7` (`crate::committee::leader`).
    pub proposer: u8,
    /// A binding commitment to the **ordered** list of transaction commitments (`H(commit₀ ‖ commit₁ ‖ …)`).
    pub tx_root: [u8; 32],
    /// A binding commitment to the erasure-coded payload shards — what a reconstructed payload is checked against.
    pub da_commit: [u8; 32],
    /// A binding commitment to the block's `last_commit` — the parent block's commit certificate (`H(cert)`,
    /// or all-zero at genesis / height 1). Recording it in the hashed header fixes the reward beneficiaries (the
    /// parent's finalizers) as part of block identity, so every validator credits the identical, agreed set
    /// (`crate::incentive`).
    pub last_commit_root: [u8; 32],
    /// A binding commitment to this block's [`reveals`](Block::reveals) — the anti-MEV share openings for
    /// **earlier** blocks that this one carries (`H(reveals)`, or all-zero when it carries none).
    ///
    /// Here for exactly the reason `last_commit_root` is (#137). Execution used to read its openings from a
    /// locally gossiped map, so *which transactions a block executes* depended on what each validator had
    /// happened to receive by the time the reveal window elapsed — two honest validators could commit the
    /// same block and produce different state roots, and the defence on record was that the executed-state
    /// checkpoint would *detect* it. An adversarial keyper does not need luck to cause it: revealing to half
    /// the cell, timed across the window boundary, forks executed state on demand.
    ///
    /// Committing the openings makes them what the finalizer set already is — an agreed input to a
    /// deterministic state transition.
    pub reveal_root: [u8; 32],
}

impl BlockHeader {
    /// The block hash: a domain-separated hash of the canonical header encoding. This is the identifier
    /// votes are cast over and children link to.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        hash_labeled(HEADER_LABEL, &self.to_wire())
    }
}

/// One committed anti-MEV opening: sealing-committee member `member` releases its Shamir share for the
/// transaction committed as `commit`, carried **inside a block** rather than gossiped.
///
/// **Unsigned, deliberately.** A gossiped [`RevealMsg`](crate::consensus::RevealMsg) carries a hybrid-PQ
/// signature because a receiver has no other way to know a stranger did not mint it. Inside a block that a
/// quorum has committed there are two stronger authenticators already: the block itself is agreed, and
/// `open_from_subset` reconstructs the key and checks the **Poly1305 tag** — so a share that is not the real
/// one cannot open the transaction, whoever it is attributed to. A proposer stuffing garbage can therefore
/// waste block space and nothing else, while a per-reveal PQ signature would cost kilobytes per transaction
/// and buy no property the AEAD tag does not already give.
///
/// `member` is kept for de-duplication and attribution only; correctness never rests on it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CommittedReveal {
    /// The transaction commitment this opening belongs to.
    pub commit: [u8; 32],
    /// The revealing committee member's index (attribution and de-duplication only).
    pub member: u8,
    /// The member's Shamir share bytes (`x ‖ y`).
    pub share: Vec<u8>,
}

impl CommittedReveal {
    /// Canonical bytes: `commit(32) ‖ member(1) ‖ var_bytes(share)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33 + self.share.len() + 2);
        out.extend_from_slice(&self.commit);
        out.push(self.member);
        fanos_primitives::codec::put_var_bytes(&mut out, &self.share);
        out
    }

    /// The fewest bytes one reveal can occupy on the wire — `commit(32) ‖ member(1) ‖ len(4)` with an empty
    /// share. Bounds `Reader::seq`'s pre-allocation against a forged count.
    const MIN_WIRE: usize = 32 + 1 + 4;

    /// Decode from a reader positioned at [`to_bytes`](Self::to_bytes).
    fn read(r: &mut fanos_primitives::codec::Reader<'_>) -> Option<Self> {
        let commit = r.array::<32>()?;
        let member = r.u8()?;
        let share = r.var_bytes()?.to_vec();
        Some(Self { commit, member, share })
    }
}

/// A full block: the voted-on [`BlockHeader`] plus the ordered sealed-transaction payload it commits to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    /// The hash-linked, voted-on header.
    pub header: BlockHeader,
    /// The ordered anti-MEV sealed transactions (the DA-sampled payload).
    pub sealed_txs: Vec<SealedTx>,
    /// The anti-MEV openings this block **commits** for transactions in earlier blocks — the agreed input
    /// execution reads, in place of each validator's own gossip pool (#137). Committed by the header's
    /// `reveal_root`, so like `last_commit` and unlike `witness`/`pol` it **is** part of the block hash: a
    /// proposer cannot advertise one opening set and ship another.
    pub reveals: Vec<CommittedReveal>,
    /// The secret-leader sortition witness (SSLE, §10.1), present on a round-0 proposal and absent on a
    /// public-fallback (round ≥ 1) block. It rides **outside** the hashed header — an auxiliary leadership
    /// proof, so the block identity ([`hash`](Self::hash)) is independent of it (see [`LeaderWitness`]).
    pub witness: Option<LeaderWitness>,
    /// The parent block's commit certificate — the finalizers rewarded when this block executes (the
    /// Tendermint-style `LastCommit`). `None` at genesis / height 1. Committed by the header's
    /// `last_commit_root`, so unlike the [`witness`](Self::witness) it **is** part of the block hash.
    pub last_commit: Option<Certificate>,
    /// The **proof of lock**: a `Phase::Prepare` quorum certificate over *this* block, attached when a
    /// validator re-proposes a value it is locked on in a later round. Rides outside the hashed header, like
    /// the [`witness`](Self::witness), so a re-proposal is byte-identical in identity to the original.
    ///
    /// It exists because a block header commits to its `proposer`, and a receiver checks that against the
    /// round's entitled leader — so without a justification only the *original* proposer could ever re-offer a
    /// locked block, and it may not be entitled in the round where the re-offer is needed. A polka certificate
    /// is that justification: it proves a quorum was already willing to prepare exactly this block, which is
    /// strictly stronger evidence than being this round's leader. Tendermint's proof-of-lock, in the shape this
    /// block layout allows.
    ///
    /// Boxed because `ConsensusMsg::Propose` carries a whole `Block`: a second inline certificate pushes that
    /// variant well past its siblings, which is a real cost on every message rather than only on a re-proposal.
    pub pol: Option<Box<Certificate>>,
}

impl Block {
    /// Assemble a block from an ordered `sealed_txs` list: derives `tx_root` and `da_commit` from the
    /// payload and links `parent`. The proposer builds this; a validator re-derives the two commitments to
    /// check the header ([`Block::verify_structure`](Self::verify_structure)). No sortition witness is attached —
    /// this is the public-leader form; the secret-leader proposer chains [`with_witness`](Self::with_witness).
    #[must_use]
    pub fn assemble(
        parent: [u8; 32],
        height: u64,
        epoch: Epoch,
        proposer: u8,
        sealed_txs: Vec<SealedTx>,
    ) -> Self {
        let tx_root = tx_root(&commits_of(&sealed_txs));
        let da_commit = commit_shards(&erasure::encode(&encode_payload(&sealed_txs)));
        let header = BlockHeader {
            parent,
            height,
            epoch,
            proposer,
            tx_root,
            da_commit,
            last_commit_root: commit_last(None),
            reveal_root: commit_reveals(&[]),
        };
        Self { header, sealed_txs, reveals: Vec::new(), witness: None, last_commit: None, pol: None }
    }

    /// Attach the parent block's commit certificate as this block's `last_commit`, updating the header's
    /// `last_commit_root` (and thus the block [`hash`](Self::hash)). The proposer chains this after
    /// [`assemble`](Self::assemble) so the block records who finalized its parent — the reward beneficiaries the
    /// incentive equilibrium credits. Chained before [`with_witness`](Self::with_witness), which does not alter
    /// the hash.
    #[must_use]
    pub fn with_last_commit(mut self, cert: Certificate) -> Self {
        self.header.last_commit_root = commit_last(Some(&cert));
        self.last_commit = Some(cert);
        self
    }

    /// Attach a [`pol`](Self::pol) — the PREPARE-quorum certificate justifying a re-proposal of this block.
    #[must_use]
    pub fn with_pol(mut self, pol: Certificate) -> Self {
        self.pol = Some(Box::new(pol));
        self
    }

    /// Attach the secret-leader sortition `witness` (the proposer's Merkle-VRF ticket proof). Chained after
    /// [`assemble`](Self::assemble) by a round-0 secret leader; the witness is verified by replicas against
    /// the proposer's pre-registered root and does not alter the block [`hash`](Self::hash).
    #[must_use]
    pub fn with_witness(mut self, witness: LeaderWitness) -> Self {
        self.witness = Some(witness);
        self
    }

    /// The block hash (its header's hash).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }

    /// The block's **skeleton** — the same header, witness, and last_commit but an EMPTY payload. Because the
    /// hash is header-only, `skeleton().hash() == self.hash()`: for DA dispersal (spec §6) a proposer broadcasts
    /// the skeleton (small) and disperses the erasure shards separately; a validator samples shards from peers,
    /// reconstructs the payload, and rebuilds the identical block with [`with_sealed_txs`](Self::with_sealed_txs).
    /// The header still commits to the real payload via `tx_root`/`da_commit`, so the skeleton cannot misrepresent
    /// it — a rebuilt block whose reconstructed payload disagrees with the header fails [`Block::verify_structure`].
    #[must_use]
    pub fn skeleton(&self) -> Self {
        Self {
            header: self.header.clone(),
            sealed_txs: Vec::new(),
            // Carried, not dropped: `reveals` is committed by the header, so a skeleton without them could
            // not answer `verify_structure` for the field the header pins — the same reason `last_commit`
            // rides along. They are also small next to the payload a skeleton omits.
            reveals: self.reveals.clone(),
            witness: self.witness.clone(),
            pol: self.pol.clone(),
            last_commit: self.last_commit.clone(),
        }
    }

    /// Rebuild a full block from a skeleton by supplying the `sealed_txs` reconstructed from DA shards. The header
    /// (and thus the hash) is unchanged; [`reconstruct_payload`](Self::reconstruct_payload) has already verified
    /// the payload against `da_commit`. Restores the block the proposer assembled, ready for the ordinary
    /// finalize/reveal/execute path.
    #[must_use]
    pub fn with_sealed_txs(mut self, sealed_txs: Vec<SealedTx>) -> Self {
        self.sealed_txs = sealed_txs;
        self
    }

    /// Canonical bytes: the fixed-width [`Wire`] header, the self-delimiting sealed-tx payload, then the
    /// **witness section** — a length-prefixed [`LeaderWitness`] encoding (empty = no witness). The witness
    /// trails the payload so the block identity (header hash) is unaffected by its presence.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.header.to_wire();
        out.extend_from_slice(&encode_payload(&self.sealed_txs));
        // Length-prefixed last_commit (empty ⇒ None): the parent's commit certificate, ahead of the witness.
        let last_commit_bytes = self.last_commit.as_ref().map(Certificate::to_bytes).unwrap_or_default();
        fanos_primitives::codec::put_var_bytes(&mut out, &last_commit_bytes);
        // Length-prefixed witness: empty var-bytes ⇒ no sortition witness (a public-fallback block).
        let witness_bytes = self.witness.as_ref().map(LeaderWitness::to_bytes).unwrap_or_default();
        fanos_primitives::codec::put_var_bytes(&mut out, &witness_bytes);
        // Length-prefixed proof-of-lock (empty ⇒ None), last so the earlier sections decode unchanged.
        let pol_bytes = self.pol.as_ref().map(|c| c.to_bytes()).unwrap_or_default();
        fanos_primitives::codec::put_var_bytes(&mut out, &pol_bytes);
        // The committed anti-MEV openings (#137): a count-prefixed sequence, last so the earlier sections
        // decode unchanged. Unlike the witness and the pol this rides *inside* the block identity via the
        // header's `reveal_root` — the whole point is that no proposer can vary it after the vote.
        fanos_primitives::codec::put_u32(&mut out, self.reveals.len() as u32);
        for reveal in &self.reveals {
            out.extend_from_slice(&reveal.to_bytes());
        }
        out
    }

    /// Decode a block from [`to_bytes`](Self::to_bytes), or `None` if malformed. The receiver still calls
    /// [`Block::verify_structure`](Self::verify_structure) — decoding trusts the bytes, verification checks them —
    /// and re-verifies any [`witness`](Self::witness) against the proposer's registered root.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cur = bytes;
        let header = BlockHeader::wire_decode(&mut cur).ok()?;
        // The payload is a self-delimiting `Vec<Vec<u8>>`; decode it via the cursor so the witness section
        // that follows stays available (cursor decode leaves trailing bytes; `from_wire` would reject them).
        let framed = Vec::<Vec<u8>>::wire_decode(&mut cur).ok()?;
        let sealed_txs = framed.iter().map(|b| SealedTx::from_bytes(b)).collect::<Option<Vec<_>>>()?;
        // Witness section: a length-prefixed LeaderWitness (empty ⇒ None). Trailing bytes after it are
        // rejected, preserving the canonical one-encoding rule.
        let mut r = fanos_primitives::codec::Reader::new(cur);
        let last_commit_bytes = r.var_bytes()?;
        let last_commit =
            if last_commit_bytes.is_empty() { None } else { Some(Certificate::from_bytes(last_commit_bytes)?) };
        let witness_bytes = r.var_bytes()?;
        let witness =
            if witness_bytes.is_empty() { None } else { Some(LeaderWitness::from_bytes(witness_bytes)?) };
        let pol_bytes = r.var_bytes()?;
        let pol =
            if pol_bytes.is_empty() { None } else { Some(Box::new(Certificate::from_bytes(pol_bytes)?)) };
        let reveals = r.seq(CommittedReveal::MIN_WIRE, CommittedReveal::read)?;
        r.finish()?;
        Some(Self { header, sealed_txs, reveals, witness, last_commit, pol })
    }

    /// The ordered transaction commitments — what the proposer ordered by (blind to contents).
    #[must_use]
    pub fn tx_commits(&self) -> Vec<TxCommit> {
        commits_of(&self.sealed_txs)
    }

    /// The canonical payload bytes that are erasure-coded for DA (the ordered sealed-tx ciphertexts).
    #[must_use]
    pub fn payload_bytes(&self) -> Vec<u8> {
        encode_payload(&self.sealed_txs)
    }

    /// The **payload budget** this block may carry, derived from the transport's frame ceiling.
    ///
    /// A block leaves the proposer by two paths and must survive **both**, so the budget is the smaller:
    ///
    /// * **whole-block** — a `NeedBody` catch-up answer ships the entire block in one frame, so
    ///   `payload + everything_else <= MAX_FRAME`;
    /// * **DA shards** — a proposal ships `K`-of-`N` erasure shards, each in its own frame, and
    ///   [`erasure::encode`] makes each shard `ceil(payload / K)` bytes, so
    ///   `ceil(payload / K) + shard_overhead <= MAX_FRAME`.
    ///
    /// **The block's own overhead is MEASURED, not assumed**, and that matters more than it looks: it is
    /// dominated by the `last_commit` certificate, which carries one signature per quorum member — so it
    /// grows with the cell. A constant fitted on a Fano cell would silently over-budget a larger plane and
    /// put the block back over the ceiling, which is the very defect this closes. Measuring costs one
    /// encode of a block that is being encoded anyway.
    ///
    /// Returns `0` if the fixed overhead alone already exceeds a frame — a cell whose certificate cannot
    /// fit has a problem this bound cannot fix, and reporting a budget of zero states that honestly rather
    /// than underflowing into a huge one.
    #[must_use]
    pub fn payload_budget(&self) -> usize {
        let overhead = self.to_bytes().len().saturating_sub(self.payload_bytes().len());
        let whole_block = MAX_FRAME.saturating_sub(overhead + consensus_msg_overhead());
        let via_shards = MAX_FRAME.saturating_sub(shard_frame_overhead()).saturating_mul(erasure::K);
        whole_block.min(via_shards)
    }

    /// Whether this block's payload fits [`payload_budget`](Self::payload_budget) — the check
    /// [`Block::verify_structure`](Self::verify_structure) folds in, so an oversized block is **rejected on
    /// arrival** rather than accepted and then silently dropped by the transport.
    #[must_use]
    pub fn fits_frame(&self) -> bool {
        self.payload_bytes().len() <= self.payload_budget()
    }

    /// The `N = 7` projective-LRC shards of the payload (one per cell node) — the DA-coded block data.
    #[must_use]
    pub fn da_shards(&self) -> [Vec<u8>; erasure::N] {
        erasure::encode(&self.payload_bytes())
    }

    /// Whether the header's `tx_root` and `da_commit` genuinely match the payload — a proposer cannot
    /// finalize a header that describes a different (or withheld) payload than the one it shipped.
    #[must_use]
    pub fn verify_structure(&self) -> bool {
        let tx_root_ok = self.header.tx_root == tx_root(&self.tx_commits());
        let da_ok = self.header.da_commit == commit_shards(&self.da_shards());
        // A block larger than the transport can carry is not a valid block, however well its commitments
        // check out: nothing downstream will complain about it, because an over-ceiling frame is dropped
        // *silently* by the receiver (see `fanos_wire::MAX_FRAME`). Verified structure has to mean
        // deliverable structure, or the mempool cannot drain — the block carrying it never arrives (#46).
        tx_root_ok && da_ok && self.fits_frame() && self.last_commit_matches() && self.reveals_match()
    }

    /// The recorded `last_commit` matches the header's commitment to it.
    ///
    /// A proposer cannot record one finalizer set in the header and ship a different one. Its *validity* as a quorum
    /// certificate is checked by consensus, not here.
    ///
    /// Split out of [`Block::verify_structure`] because it is the one structural check a **skeleton** can still answer: the
    /// other two commit to a payload the skeleton does not carry, while `last_commit` rides along with it
    /// (`Block::skeleton`). The SSLE round-0 lottery ranks skeletons, so it needs exactly this much.
    #[must_use]
    pub fn last_commit_matches(&self) -> bool {
        self.header.last_commit_root == commit_last(self.last_commit.as_ref())
    }

    /// The carried [`reveals`](Self::reveals) match the header's commitment to them.
    ///
    /// The structural half of #137: committing the openings buys nothing unless a receiver checks that the
    /// block it votes on carries the openings its header names. Their *validity* is not checked here and
    /// deliberately not anywhere — a share that is not the real one simply fails the AEAD tag during
    /// `open_from_subset`, so there is no separate verdict to reach (see [`CommittedReveal`]).
    ///
    /// Answerable from a skeleton, like [`last_commit_matches`](Self::last_commit_matches), because the
    /// reveals ride with it.
    #[must_use]
    pub fn reveals_match(&self) -> bool {
        self.header.reveal_root == commit_reveals(&self.reveals)
    }

    /// Attach the anti-MEV openings this block commits for earlier blocks, updating the header's
    /// `reveal_root` (and thus the block [`hash`](Self::hash)).
    ///
    /// Chained by the proposer after [`assemble`](Self::assemble) and before
    /// [`with_last_commit`](Self::with_last_commit) — order is irrelevant to the result (each sets its own
    /// header field), but both must precede [`with_witness`](Self::with_witness), which does not alter the
    /// hash and would otherwise be attached to a different block.
    #[must_use]
    pub fn with_reveals(mut self, reveals: Vec<CommittedReveal>) -> Self {
        self.header.reveal_root = commit_reveals(&reveals);
        self.reveals = reveals;
        self
    }

    /// Reconstruct a block's payload from a **subset** of its shards (an erased point is `None`) and verify
    /// the result against the header's `da_commit`. Returns the recovered sealed transactions, or `None` if
    /// the shard set is unrecoverable (the payload is genuinely unavailable, spec §6.3/§L4.3) or the
    /// re-encoded shards do not match the committed `da_commit` (tampered / wrong block).
    ///
    /// This is the availability check a validator runs after sampling: a withholding proposer leaves too few
    /// shards present, reconstruction fails, and the validator withholds its PREPARE.
    #[must_use]
    pub fn reconstruct_payload(&self, shards: &[Option<Vec<u8>>; erasure::N]) -> Option<Vec<SealedTx>> {
        let payload = erasure::reconstruct(shards)?;
        // Re-encode the recovered payload and check it matches the committed shards (binds availability to
        // *this* block, not some other payload that happens to be recoverable).
        if commit_shards(&erasure::encode(&payload)) != self.header.da_commit {
            return None;
        }
        decode_payload(&payload)
    }
}

/// Take the longest prefix of `sealed` whose encoded payload fits `budget` bytes.
///
/// **The proposer's half of the frame bound.** [`Block::fits_frame`] rejects an oversized block on
/// arrival; this stops one being built, which is where the defect actually bites — an over-ceiling block is
/// dropped *silently* by the receiver, so a proposer that keeps producing them stalls the chain without a
/// single error anywhere (#46). Rejection alone would turn a silent stall into a loud one; packing keeps
/// the chain moving and drains the mempool across successive blocks instead.
///
/// A **prefix**, not a best-fit subset, because the caller has already sorted by commitment for anti-MEV:
/// the order is the fairness property, and reordering to squeeze in one more transaction would trade it
/// away for a few bytes. Transactions that do not fit stay in the mempool for the next block.
///
/// The size accounting bounds each element's framing rather than re-encoding the prefix at every step
/// (which would be quadratic): `Vec<Vec<u8>>::to_wire` writes a sequence prefix and one length prefix per
/// element, each a varint of at most 8 bytes. That over-estimates slightly, so the packer may leave a few
/// bytes unused — the safe direction, for the same reason the overhead constants round up.
#[must_use]
pub fn pack_to_budget(sealed: Vec<SealedTx>, budget: usize) -> Vec<SealedTx> {
    /// Upper bound on a varint length prefix at these sizes.
    const PREFIX_MAX: usize = 8;
    let mut used = PREFIX_MAX; // the sequence's own prefix
    let mut out = Vec::with_capacity(sealed.len());
    for tx in sealed {
        let cost = tx.to_bytes().len().saturating_add(PREFIX_MAX);
        if used.saturating_add(cost) > budget {
            break;
        }
        used += cost;
        out.push(tx);
    }
    out
}

/// The payload budget for a block that is **not yet assembled** — the same derivation as
/// [`Block::payload_budget`], measured on a skeleton carrying `last_commit`.
///
/// The proposer needs the budget *before* it packs, but the certificate that dominates the overhead is
/// attached *after* assembly, so the budget cannot be read off the finished block without risking having
/// already overshot. Building an empty block with the same certificate gives the same overhead for one
/// cheap encode.
#[must_use]
pub fn budget_for(
    parent: [u8; 32],
    height: u64,
    epoch: Epoch,
    proposer: u8,
    last_commit: Option<&Certificate>,
    reveals: &[CommittedReveal],
) -> usize {
    // The reveals are passed in rather than allowed for by a constant, and that is the same choice the
    // `last_commit` note below argues for: their size is the *actual* set this proposer is about to commit,
    // which `payload_budget` then measures through `to_bytes` like everything else. A fixed allowance would
    // have to cover the worst case — a full window's openings — and would spend that on every block.
    let mut skeleton = Block::assemble(parent, height, epoch, proposer, Vec::new()).with_reveals(reveals.to_vec());
    if let Some(cert) = last_commit {
        // Attached as the proof-of-lock TOO, which is not a trick but the worst case measured honestly:
        // `to_bytes` emits `last_commit`, `witness` and `pol`, and a `pol` is a `Certificate` — the same
        // shape and size as `last_commit`. Budgeting for only one of them is a **liveness break in the
        // safety-critical path**: a locked block is re-proposed with a `pol` attached
        // (`maybe_propose`'s locked branch), which *grows* it, so a payload packed against a
        // pol-less budget would then fail its own `fits_frame` and be rejected by the very cell that
        // produced it. Reserving the space up front costs one block's worth of capacity and cannot
        // fail that way.
        skeleton = skeleton.with_last_commit(cert.clone()).with_pol(cert.clone());
    }
    skeleton.payload_budget().saturating_sub(WITNESS_ALLOWANCE)
}

/// Whether a cell of these parameters can carry **at least one** sealed transaction in a block.
///
/// The security bound on the sealing committee ([`CellParams::seal_committee_size`]) is `m ≥ 2f + 1`, which
/// makes `m` grow with the cell — and the seal encapsulates to every member, so a transaction costs
/// `m · SEALED_SHARE_LEN`. Past some order that exceeds a whole block and the cell can finalize nothing.
///
/// A separate predicate from [`CellParams::seal_is_sound`] because it answers a different question — that one
/// asks whether the seal keeps its secret, this one whether it fits on the wire — and a cell can fail either
/// independently. Both are checked before sealing; a provisioning that passes only the first would look
/// correct and produce blocks nothing can carry.
///
/// Measured at the reference cell: 8264 B per transaction, against a payload budget of roughly 1.03 MB.
#[must_use]
pub fn seal_fits_a_block(cell: crate::params::CellParams) -> bool {
    let skeleton = Block::assemble(GENESIS_PARENT, 0, Epoch::ZERO, 0, Vec::new());
    cell.seal_bytes_per_tx() <= skeleton.payload_budget()
}

/// Bytes reserved for the SSLE sortition witness, which `maybe_propose` attaches *after* assembly.
///
/// A [`LeaderWitness`] is `output(32) ‖ Merkle siblings`, so its size is `32 + 32·h` for a Merkle-VRF tree
/// of height `h`. The bound is therefore [`pqvrf::MAX_HEIGHT`] — not a comfortable-looking number, but the
/// **enforced** ceiling: `MerkleVrfSecret::generate` refuses a larger height, so no witness above this size
/// can exist to overflow the budget, and none below it is under-reserved.
///
/// This was `32 + 32 * 32`, reserving for a height of 32 — which reads as prudent and is in fact *unreachable*:
/// it is eight levels above the maximum the VRF will produce. Over-reserving is the safe direction, so this
/// never failed; it simply spent 256 bytes of every block's capacity on tree levels that cannot exist, and
/// stated a bound nothing guaranteed. Deriving it from the guard that makes it true is both tighter and
/// checkable — if `MAX_HEIGHT` moves, this moves with it.
const WITNESS_ALLOWANCE: usize = 32 + 32 * pqvrf::MAX_HEIGHT as usize;

/// The ordered transaction commitments of a sealed-tx list.
fn commits_of(sealed: &[SealedTx]) -> Vec<TxCommit> {
    sealed.iter().map(SealedTx::commit).collect()
}

/// A binding commitment to an ordered commitment list: `H(commit₀ ‖ commit₁ ‖ …)`. A flat hash suffices for
/// consensus safety (validators hold the full block); a Merkle tree would additionally give light clients
/// succinct inclusion proofs — a noted extension, not needed for finality.
fn tx_root(commits: &[TxCommit]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(commits.len() * 32);
    for c in commits {
        buf.extend_from_slice(c);
    }
    hash_labeled(TX_ROOT_LABEL, &buf)
}

/// A binding commitment to a block's `last_commit` certificate — `H(cert)` if present, else all-zero. Folded
/// into the hashed header, so the recorded finalizer set (the reward beneficiaries) is part of block identity —
/// every validator that votes for the block therefore agrees on exactly who its execution will reward.
fn commit_last(last_commit: Option<&Certificate>) -> [u8; 32] {
    match last_commit {
        Some(cert) => hash_labeled(LAST_COMMIT_LABEL, &cert.to_bytes()),
        None => [0u8; 32],
    }
}

/// A binding commitment to the **ordered** committed openings, or all-zero for none — the same
/// absent-is-zero convention [`commit_last`] uses, so a block that carries no reveals is byte-identical in
/// identity to one from before this field existed.
///
/// Order is part of the commitment because it is part of the encoding; execution treats the set as a set
/// (first opening per `(commit, member)` wins), so a proposer reordering them changes the block hash and
/// nothing else.
fn commit_reveals(reveals: &[CommittedReveal]) -> [u8; 32] {
    if reveals.is_empty() {
        return [0u8; 32];
    }
    let mut buf = Vec::new();
    for reveal in reveals {
        buf.extend_from_slice(&reveal.to_bytes());
    }
    hash_labeled(REVEAL_ROOT_LABEL, &buf)
}

/// A binding commitment to all `N = 7` payload shards: `H(len₀ ‖ shard₀ ‖ len₁ ‖ shard₁ ‖ …)`. A validator
/// that downloads a shard set verifies it against this before trusting the recovered payload.
fn commit_shards(shards: &[Vec<u8>; erasure::N]) -> [u8; 32] {
    let mut buf = Vec::new();
    for shard in shards {
        buf.extend_from_slice(&(shard.len() as u32).to_be_bytes());
        buf.extend_from_slice(shard);
    }
    hash_labeled(DA_COMMIT_LABEL, &buf)
}

/// Canonically encode the ordered sealed transactions as the payload — the [`Wire`] form of a
/// `Vec<Vec<u8>>` of per-tx bytes, so it reuses the audited length-prefixed sequence codec.
fn encode_payload(sealed: &[SealedTx]) -> Vec<u8> {
    let framed: Vec<Vec<u8>> = sealed.iter().map(SealedTx::to_bytes).collect();
    framed.to_wire()
}

/// Decode a payload produced by [`encode_payload`] back into sealed transactions, or `None` if malformed.
fn decode_payload(payload: &[u8]) -> Option<Vec<SealedTx>> {
    let framed: Vec<Vec<u8>> = Vec::<Vec<u8>>::from_wire(payload).ok()?;
    framed.iter().map(|b| SealedTx::from_bytes(b)).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_code::lrc::is_recoverable_fano;
    use fanos_pqcrypto::SeedRng;
    use fanos_pqcrypto::kem::{HybridKemPublic, HybridKemSecret};

    use crate::tx::Transaction;

    fn sealed_tx(tag: &[u8], epoch: Epoch) -> SealedTx {
        let kps: Vec<(HybridKemSecret, HybridKemPublic)> = (0..3).map(|i| {
            let mut rng = SeedRng::from_seed(&[tag.first().copied().unwrap_or(0), i]);
            HybridKemSecret::generate(&mut rng)
        }).collect();
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        SealedTx::seal(&Transaction::new(tag.to_vec()), epoch, &pubs, 2, tag).unwrap()
    }

    #[test]
    fn every_framing_allowance_matches_what_the_encoders_actually_produce() {
        // These three were hand-counted constants. Each is now derived, and each derivation is pinned here
        // against the real encoder — because a derivation nothing checks is a constant with a story.

        // 1. The App envelope must cover the WORST case, not the probe's. Under-estimating is the dangerous
        //    direction: a message a byte over the ceiling is dropped in silence.
        let big = ShardMsg::Deliver { block: [7; 32], index: 3, data: alloc::vec![0u8; 60_000] };
        let framed = shard_to_frame(&big).len();
        assert!(
            framed - big.to_bytes().len() <= app_envelope(),
            "a 60 KB shard framed to {framed} bytes, over the allowance of {}",
            app_envelope()
        );

        // 2. The shard overhead is the whole distance from payload to wire, and it must hold for a payload
        //    at the size the budget actually packs to.
        let data = alloc::vec![0u8; 200_000];
        let msg = ShardMsg::Deliver { block: [1; 32], index: 0, data: data.clone() };
        assert!(
            shard_to_frame(&msg).len() <= data.len() + shard_frame_overhead(),
            "the measured shard overhead under-covers a real 200 KB shard"
        );

        // 3. The consensus wrapper is exactly one variant tag around the block, which is what lets
        //    `consensus_msg_overhead` state it instead of encoding a whole block to find out.
        let block = Block::assemble([0; 32], 1, Epoch::new(1), 0, Vec::new());
        let wrapped = crate::consensus::ConsensusMsg::Propose(block.clone()).to_bytes().len();
        assert_eq!(
            wrapped - block.to_bytes().len(),
            CONSENSUS_VARIANT_TAG,
            "a consensus message is a 1-byte tag around its payload; if that changed, the budget is wrong"
        );

        // 4. The witness allowance covers the largest witness the VRF will ever produce — and `MAX_HEIGHT`
        //    is the reason it is a bound rather than a hope.
        let widest = LeaderWitness {
            output: [0; 32],
            proof: MerkleProof::from_bytes(
                &alloc::vec![0u8; 32 * pqvrf::MAX_HEIGHT as usize],
                pqvrf::MAX_HEIGHT,
            )
            .expect("a max-height path decodes"),
        };
        assert_eq!(
            widest.to_bytes().len(),
            WITNESS_ALLOWANCE,
            "the allowance must equal the widest witness exactly — larger wastes block capacity on levels \
             the VRF refuses to build, smaller is a block that grew after it was budgeted"
        );
    }

    #[test]
    fn a_block_is_bounded_by_what_the_transport_can_actually_carry() {
        // #46: the mempool was uncapped, the proposer cloned all of it into a block, `verify_structure`
        // checked no size — and the transport drops an over-ceiling frame in SILENCE. Measured on this
        // codebase: the whole-block path fails past ~1.03 MB, the DA-shard path past ~3.15 MB, and the
        // failure is a receiver-side `continue` with the sender still reporting success. So nothing
        // downstream ever complains: a proposer that keeps building oversized blocks stalls the chain
        // with no error anywhere, and the pool never drains because the block carrying it never arrives.
        let b = sample_block();

        // The budget is POSITIVE and strictly under a frame — a bound that permitted a whole frame of
        // payload would ignore the block's own header and certificate, which is how it got here.
        let budget = b.payload_budget();
        assert!(budget > 0, "a block with a normal certificate has room for transactions");
        assert!(
            budget < MAX_FRAME.saturating_mul(erasure::K),
            "the budget leaves room for per-shard framing: {budget}"
        );
        assert!(b.fits_frame(), "an ordinary block fits");
        assert!(b.verify_structure(), "and verifies");

        // The packer never exceeds the budget, and never reorders — the sort is the anti-MEV property.
        let txs: Vec<SealedTx> = (0..8u8).map(|i| sealed_tx(&[b'p', i], Epoch::new(3))).collect();
        let mut sorted = txs.clone();
        sorted.sort_by_key(SealedTx::commit);
        let packed = pack_to_budget(sorted.clone(), budget);
        assert_eq!(
            packed,
            sorted[..packed.len()],
            "the packer takes a PREFIX — reordering to fit one more would trade away the anti-MEV order"
        );
        assert!(
            encode_payload(&packed).len() <= budget,
            "packed payload {} exceeds budget {budget}",
            encode_payload(&packed).len()
        );

        // A tight budget takes fewer, and a zero budget takes none — the degenerate case must not panic
        // or wrap, because it is reachable when a certificate alone fills a frame.
        let one = pack_to_budget(sorted.clone(), sorted[0].to_bytes().len() + 16);
        assert!(one.len() <= 1, "a budget for one transaction takes at most one, got {}", one.len());
        assert!(pack_to_budget(sorted, 0).is_empty(), "a zero budget takes nothing");

        // **A block must still fit AFTER everything is attached to it.** `to_bytes` emits `last_commit`,
        // `witness` and `pol`, and all three arrive *after* assembly — so a budget measured on a bare
        // skeleton is not the budget the finished block is judged by. Getting this wrong is a liveness
        // break in the safety-critical path: `maybe_propose`'s locked branch re-proposes an
        // already-validated block with a `pol` attached, which GROWS it, and a payload packed against a
        // pol-less budget would then fail its own `fits_frame` — rejected by the cell that produced it.
        // So the packed set is re-checked here with the certificate attached in BOTH slots.
        let grown = Block::assemble(GENESIS_PARENT, 1, Epoch::new(3), 4, packed.clone());
        assert!(
            grown.fits_frame(),
            "a block packed to budget must still fit once last_commit, witness and pol are attached"
        );

        // The gate and the packer must agree, which is the property that actually matters: anything the
        // proposer is willing to BUILD must be something a verifier is willing to ACCEPT. If they
        // disagreed, a proposer would keep producing blocks its own cell rejects — a stall with a
        // different signature but the same effect as the silent one this closes.
        let assembled = Block::assemble(GENESIS_PARENT, 1, Epoch::new(3), 4, packed);
        assert!(assembled.fits_frame(), "what the packer produced, the gate accepts");
        assert!(assembled.verify_structure(), "and it verifies end to end");

        // And `fits_frame` is exactly the budget comparison — not a weaker proxy that could drift from
        // it. Asserted as an identity so a future change to either side has to change both.
        assert_eq!(
            assembled.fits_frame(),
            assembled.payload_bytes().len() <= assembled.payload_budget(),
            "the gate IS the budget comparison"
        );
    }

    fn sample_block() -> Block {
        let txs = vec![sealed_tx(b"tx-one", Epoch::new(3)), sealed_tx(b"tx-two", Epoch::new(3))];
        Block::assemble(GENESIS_PARENT, 1, Epoch::new(3), 4, txs)
    }

    #[test]
    fn a_block_verifies_its_own_structure_and_hashes_stably() {
        let block = sample_block();
        assert!(block.verify_structure(), "the header commitments match the payload");
        assert_eq!(block.hash(), block.header.hash());
        // The header round-trips through its canonical Wire encoding (so all validators hash the same bytes).
        let bytes = block.header.to_wire();
        assert_eq!(BlockHeader::from_wire(&bytes).unwrap(), block.header);
    }

    #[test]
    fn a_skeleton_and_dispersed_shards_reconstruct_the_identical_block() {
        let full = sample_block();
        let skeleton = full.skeleton();
        assert!(skeleton.sealed_txs.is_empty(), "the skeleton drops the payload");
        assert_eq!(skeleton.hash(), full.hash(), "the hash is header-only, so it is unchanged");
        assert!(!skeleton.verify_structure(), "an empty payload does NOT match the header commitments");

        // Disperse the payload as DA shards, reconstruct it, and rebuild the block from the skeleton.
        let shards = full.da_shards();
        let present: [Option<Vec<u8>>; erasure::N] = core::array::from_fn(|p| Some(shards[p].clone()));
        let payload = skeleton.reconstruct_payload(&present).expect("the full shard set reconstructs the payload");
        let rebuilt = skeleton.clone().with_sealed_txs(payload);
        assert_eq!(rebuilt, full, "skeleton + reconstructed payload == the original block");
        assert!(rebuilt.verify_structure(), "the rebuilt block's commitments now match its payload");
    }

    #[test]
    fn a_block_round_trips_with_and_without_a_sortition_witness() {
        // A public-fallback block (no witness) round-trips.
        let plain = sample_block();
        assert_eq!(plain.witness, None);
        assert_eq!(Block::from_bytes(&plain.to_bytes()).unwrap(), plain);

        // A secret-leader block carries a witness; it round-trips AND does not change the block identity.
        let secret = pqvrf::MerkleVrfSecret::generate(&[7u8; 32], 6).unwrap();
        let (output, proof) = secret.prove(plain.header.height).unwrap();
        let witnessed = plain.clone().with_witness(LeaderWitness { output, proof });
        assert_eq!(witnessed.hash(), plain.hash(), "the witness rides outside the hashed header");
        let decoded = Block::from_bytes(&witnessed.to_bytes()).unwrap();
        assert_eq!(decoded, witnessed, "the witness survives the round-trip");
        assert_eq!(decoded.witness.unwrap().output, output);
    }

    #[test]
    fn the_leader_witness_codec_rejects_malformed_lengths() {
        let secret = pqvrf::MerkleVrfSecret::generate(&[1u8; 32], 5).unwrap();
        let (output, proof) = secret.prove(3).unwrap();
        let w = LeaderWitness { output, proof };
        let bytes = w.to_bytes();
        assert_eq!(LeaderWitness::from_bytes(&bytes), Some(w));
        // Too short (no room for the 32-byte output), and a non-multiple-of-32 proof tail are both rejected.
        assert_eq!(LeaderWitness::from_bytes(&bytes[..20]), None);
        assert_eq!(LeaderWitness::from_bytes(&bytes[..bytes.len() - 1]), None);
    }

    #[test]
    fn a_tampered_header_fails_structure_verification() {
        let mut block = sample_block();
        // A proposer that lies about its tx set (swaps tx_root) is caught.
        block.header.tx_root[0] ^= 0xFF;
        assert!(!block.verify_structure(), "a mismatched tx_root is rejected");
    }

    #[test]
    fn the_full_shard_set_reconstructs_the_exact_payload() {
        let block = sample_block();
        let shards = block.da_shards();
        let present: [Option<Vec<u8>>; erasure::N] = core::array::from_fn(|p| Some(shards[p].clone()));
        let recovered = block.reconstruct_payload(&present).expect("full shards reconstruct");
        assert_eq!(recovered, block.sealed_txs, "the exact sealed transactions are recovered");
    }

    #[test]
    fn an_available_payload_survives_up_to_three_lost_shards() {
        // §L4/V20: the projective LRC recovers any ≤3 crashes — DA holds with up to 3 nodes withholding.
        let block = sample_block();
        let shards = block.da_shards();
        for missing in 0u8..=0x7F {
            if missing.count_ones() > 3 {
                continue;
            }
            let present: [Option<Vec<u8>>; erasure::N] =
                core::array::from_fn(|p| if missing & (1 << p) == 0 { Some(shards[p].clone()) } else { None });
            assert!(is_recoverable_fano(missing));
            assert_eq!(
                block.reconstruct_payload(&present).as_deref(),
                Some(block.sealed_txs.as_slice()),
                "≤3 lost shards still reconstruct (missing {missing:#09b})"
            );
        }
    }

    #[test]
    fn a_withheld_payload_is_detected_as_unavailable() {
        // A hyperoval loss (4 nodes, no 3 collinear) is the minimal UNrecoverable pattern — a proposer
        // withholding it cannot have its block reconstructed, so honest validators withhold PREPARE.
        let block = sample_block();
        let shards = block.da_shards();
        // Points {1,2,4} ... build a genuine hyperoval mask via is_recoverable_fano == false.
        let hyperoval = (0u8..=0x7F).find(|&m| !is_recoverable_fano(m)).unwrap();
        let present: [Option<Vec<u8>>; erasure::N] =
            core::array::from_fn(|p| if hyperoval & (1 << p) == 0 { Some(shards[p].clone()) } else { None });
        assert!(block.reconstruct_payload(&present).is_none(), "an unavailable payload cannot be reconstructed");
    }
}
