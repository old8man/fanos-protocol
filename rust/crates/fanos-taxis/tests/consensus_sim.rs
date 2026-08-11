//! End-to-end simulation of the TAXIS BFT blockchain over a 7-node Fano cell (`docs/design-taxis.md` §9).
//!
//! Seven [`ConsensusEngine`]s are driven through a broadcast message bus — the same sans-I/O engine a real
//! transport would drive. The tests prove the properties the design promises: happy-path finality with
//! correct ordered execution and anti-MEV blindness; liveness under `f = 2` crashes and under proposer
//! timeout; a withheld (data-unavailable) block never finalizes; and Byzantine safety — equivocation and
//! forged votes never split agreement or forge a certificate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::{BTreeSet, VecDeque};

use fanos_code::lrc::is_recoverable_fano;
use fanos_pqcrypto::kem::{HybridKemPublic, HybridKemSecret};
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};
use fanos_primitives::{BeaconSeed, Epoch};
use fanos_taxis::committee::{epoch_seal_line, leader, leader_line, leader_ticket, line_members};
use fanos_vrf::pqvrf::MerkleVrfSecret;
use fanos_taxis::consensus::{ConsensusEngine, ConsensusMsg, DaShards, Input, Output, REVEAL_WINDOW, RevealMsg};
use fanos_taxis::da::Sampler;
use fanos_taxis::vote::{SignedVote, Vote};
use fanos_taxis::Phase;
use fanos_taxis::incentive::SlashEvidence;
use fanos_taxis::keyper::{KeyperKeyCert, KeyperRegistry, seal_to_keyper_committee};
use fanos_taxis::state::StateMachine;
use fanos_taxis::tx::TxCommit;
use fanos_taxis::{Accounts, Block, CellParams, SealedTx, Transfer};

/// A Shamir share serialized as the reveal wire carries it: `x(1) ‖ y`.
fn share_bytes(x: u8, y: &[u8]) -> Vec<u8> {
    let mut v = vec![x];
    v.extend_from_slice(y);
    v
}

const N: usize = 7;
const SEED: BeaconSeed = BeaconSeed::new([0x11; 32]);
const EPOCH: Epoch = Epoch::new(1);
const ALICE: [u8; 32] = [0xA1; 32];
const BOB: [u8; 32] = [0xB0; 32];
const CAROL: [u8; 32] = [0xCA; 32];
/// The SSLE Merkle-VRF tree height (domain `2^6 = 64` heights per registration — ample for these tests).
const VRF_HEIGHT: u32 = 6;

/// A deterministic per-validator Merkle-VRF seed (distinct per index, so tickets are independent draws).
fn vrf_seed(i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0x5A;
    s[1] = i as u8;
    s
}

/// The independently-recomputed SSLE winner: the elected line member with the lowest ticket at `(height, 0)`.
fn expected_ssle_leader(height: u64) -> u8 {
    let members = line_members(leader_line(&SEED, height, 0)).expect("a real line");
    members
        .into_iter()
        .min_by_key(|&m| {
            let secret = MerkleVrfSecret::generate(&vrf_seed(m), VRF_HEIGHT).unwrap();
            let (output, _) = secret.prove(height).unwrap();
            leader_ticket(&output, &SEED, height, 0)
        })
        .unwrap() as u8
}

/// One validator's key material (signature + KEM).
struct Keys {
    sig: HybridSigSecret,
    sig_pub: HybridVerifier,
    kem: HybridKemSecret,
    kem_pub: HybridKemPublic,
}

fn gen_keys() -> Vec<Keys> {
    (0..N)
        .map(|i| {
            let mut rng = SeedRng::from_seed(&[0xC0, i as u8]);
            let (sig, sig_pub) = HybridSigSecret::generate(&mut rng);
            let (kem, kem_pub) = HybridKemSecret::generate(&mut rng);
            Keys { sig, sig_pub, kem, kem_pub }
        })
        .collect()
}

/// A driveable cluster of `N` validators with a broadcast bus.
struct Cluster {
    engines: Vec<ConsensusEngine<Accounts>>,
    kem_dir: Vec<HybridKemPublic>,
    /// The cell's agreed anti-MEV decryption authority (its `commit()` is the on-chain commitment every engine holds).
    registry: KeyperRegistry,
    /// The broadcast bus, each message tagged with its SENDER index so a network partition can drop messages
    /// that cross between groups (an injected adversary message uses `usize::MAX` — it reaches everyone).
    bus: VecDeque<(usize, ConsensusMsg)>,
    /// Partition group per validator (all equal ⇒ fully connected). A message from `from` reaches `i` only when
    /// `partition[from] == partition[i]` — a hard network split, the T-H1/T-H2 split-brain condition (§6.5).
    partition: Vec<u8>,
    committed: Vec<Vec<(u64, [u8; 32])>>,
    crashed: Vec<bool>,
    withholding: BTreeSet<u8>,
    /// **DA dispersal latency**, in ticks, or `0` for the historical "a proposal arrives whole" model.
    ///
    /// Production never delivers a full block: the driver broadcasts the small *skeleton*, disperses one erasure shard
    /// per validator, and admits the proposal to the engine only once it has **sampled the rest from peers and
    /// reconstructed the body** (`fanos_node::taxis_driver::begin_sampling`/`try_reconstruct`). This models that: the
    /// skeleton lands immediately (it needs no sampling), and the body lands `da_delay` ticks later.
    ///
    /// It exists because the sim's fidelity gap here hid a **total** SSLE liveness failure — a cell that finalized no
    /// block at all over real QUIC while every engine-level SSLE test passed, because `shards_for` handed each replica
    /// the complete shard set instantly. A sim that differs from production in anything but transport cannot pin what
    /// production does (`docs/design-testing.md`; the standing fidelity rule).
    da_delay: u32,
    /// One **real** [`Sampler`] per validator, so the sim exercises production's DA component rather than a lookalike.
    samplers: Vec<Sampler>,
    /// Shards not yet dispersed: `(ticks remaining, validator, block hash, shard)`. Drained by [`tick`](Self::tick).
    ///
    /// Dispersal is *staggered* on purpose. A replica requests a missing shard the moment a skeleton arrives, so with
    /// simultaneous dispersal every peer already holds its shard and every first request succeeds — which is the one
    /// arrangement that cannot exhibit the race that deadlocked a live cell.
    dispersing: Vec<(u32, usize, [u8; 32], Vec<u8>)>,
    /// Drop votes of one phase **destined for specific validators** — a targeted loss, not a cell-wide outage.
    ///
    /// The global `drop_phase` cannot express the condition that wedges a real cell, because it denies the quorum to
    /// everyone equally and so nothing finalizes at all. What actually happens is asymmetric: a quorum of `2f+1 = 5`
    /// forms for a block and finalizes it, while one or two validators receive only `quorum - 1` of those COMMIT votes.
    /// Those validators are locked on the block, hold its body, and are missing nothing but a signature — and TAXIS does
    /// not retransmit votes, so they are stuck at that height forever while the cell moves on.
    drop_to: Option<(Phase, BTreeSet<usize>)>,
    /// Drop every vote in this phase while set — a network hiccup that lands *between* PREPARE and COMMIT.
    ///
    /// The one condition that wedges a locking consensus permanently, and nothing exercised it: a PREPARE quorum forms
    /// (so every validator locks) while the COMMIT quorum does not (so the height never finalizes and the lock is never
    /// released). Every subsequent round's proposal is then a *different* block, which the locked validators refuse.
    drop_phase: Option<Phase>,
    /// Suppress catch-up **snapshots** (`SyncResp`) while leaving every other message alone — the losing side
    /// of the state-sync race, made deterministic. A validator recovering into a live cell is in a contest
    /// between two ways of moving forward: adopt a certified snapshot, or walk the chain block by block. Only
    /// the first restores the state it missed, and nothing arbitrates which arrives first, so the outcome was
    /// a coin flip nothing could reproduce on purpose.
    drop_sync_resp: bool,
    /// Validators that never receive block bodies (Propose), to exercise the commit-cert-before-body path.
    deaf_propose: BTreeSet<usize>,
    /// Validators that never receive **reveals**, while hearing every vote and body — the one loss pattern that
    /// produces state divergence WITHOUT a height gap, because `finalize` advances on the header and only
    /// execution waits for the openings. A partition cannot express it: it would deny votes too, and then the
    /// height trigger already covers the node.
    deaf_reveal: BTreeSet<usize>,
    /// Every distinct block body seen on the bus (so a test can hand-deliver a withheld body later).
    proposed: Vec<Block>,
    /// Equivocation proofs the engines surfaced (the operational slashing signal).
    slashes: Vec<SlashEvidence>,
    /// Skeletons this cell began sampling, cell-wide — the denominator [`da_requests`](Self::da_requests) needs.
    ///
    /// A count of requests is a count of absolute messages, and the claim under test is a *rate*: requests per block
    /// being sampled. Reading the total alone made a 40-sweep run look 2x worse than an unbounded policy, when what had
    /// actually happened was that the cell was sampling many more blocks.
    da_begins: u64,
    /// Shard **requests** this cell has made, cell-wide — the sim's first message-*cost* counter.
    ///
    /// The sim modelled delivery and never cost, so a defect whose whole harm is traffic volume was invisible to it: a
    /// re-fetch is free and instantaneous here, while in production it is thousands of frames and a round timeout. Both
    /// TAXIS liveness defects fixed on 2026-07-30 were of exactly that shape, and neither could be reproduced here in
    /// any timer pattern — measured, not assumed. A counter is what makes the class expressible.
    da_requests: u64,
}

impl Cluster {
    fn new(genesis: &Accounts) -> Self {
        let keys = gen_keys();
        let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
        let kem_dir: Vec<HybridKemPublic> = keys.iter().map(|k| k.kem_pub.clone()).collect();
        // The on-chain decryption-key commitment: each validator self-certifies its KEM key under its signing
        // key, and every engine agrees on the resulting commitment (an agreed genesis constant).
        let registry = KeyperRegistry::new(
            keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
        );
        let keyper_commit = registry.commit();
        let mut engines = Vec::new();
        for (i, k) in keys.into_iter().enumerate() {
            engines.push(ConsensusEngine::new(
                CellParams::FANO,
                i as u8,
                k.sig,
                k.kem,
                verifiers.clone(),
                keyper_commit,
                SEED,
                EPOCH,
                genesis.clone(),
            ));
        }
        Self {
            engines,
            kem_dir,
            registry,
            bus: VecDeque::new(),
            partition: vec![0; N],
            committed: vec![Vec::new(); N],
            crashed: vec![false; N],
            withholding: BTreeSet::new(),
            da_delay: 0,
            drop_sync_resp: false,
            samplers: (0..N).map(|i| Sampler::new(u8::try_from(i).unwrap_or(0))).collect(),
            dispersing: Vec::new(),
            drop_to: None,
            drop_phase: None,
            deaf_propose: BTreeSet::new(),
            deaf_reveal: BTreeSet::new(),
            proposed: Vec::new(),
            slashes: Vec::new(),
            da_begins: 0,
            da_requests: 0,
        }
    }

    /// The DA shards a validator samples for a block: the full shard set unless its proposer is withholding,
    /// in which case a hyperoval's worth of shards go missing (the minimal unrecoverable erasure pattern).
    /// The engine reconstructs the payload from these and checks it against `da_commit`, so a withheld block
    /// fails to reconstruct and is refused — availability is verified in-engine, never a trusted bit.
    fn shards_for(&self, block: &Block) -> DaShards {
        let all = block.da_shards();
        let present: u8 = if self.withholding.contains(&block.header.proposer) {
            let hyperoval = (0u8..=0x7F).find(|&m| !is_recoverable_fano(m)).unwrap();
            (!hyperoval) & 0x7F
        } else {
            0x7F
        };
        core::array::from_fn(|p| (present & (1 << p) != 0).then(|| all[p].clone()))
    }

    fn collect(&mut self, idx: usize, outs: Vec<Output>) {
        for o in outs {
            match o {
                Output::Send(msg) => self.bus.push_back((idx, msg)),
                Output::Committed { height, block_hash } => self.committed[idx].push((height, block_hash)),
                Output::Slash(ev) => self.slashes.push(ev),
                // A point-to-point send (a catch-up SyncResp): deliver only to `to`, respecting crash +
                // partition, and collect its outputs (the adoption's Committed) so `run` sees them.
                Output::SendTo { to, msg } => {
                    let to = usize::from(to);
                    if self.drop_sync_resp && matches!(msg, ConsensusMsg::SyncResp { .. }) {
                        continue;
                    }
                    if to < N && !self.crashed[to] && self.partition[idx] == self.partition[to] {
                        let input = self.msg_to_input(idx, &msg);
                        let outs = self.engines[to].step(input);
                        // Mirrors the driver: a body obtained whole ends its sampling.
                        if let ConsensusMsg::Body(b) = &msg
                            && let Some(s) = self.samplers.get_mut(to)
                        {
                            s.forget(&b.hash());
                        }
                        self.collect(to, outs);
                    }
                }
            }
        }
    }

    /// Map a wire message from validator `from` to the engine input, filling `SyncReq.from` from the
    /// (authenticated) sender — shared by broadcast [`deliver`](Self::deliver) and point-to-point `SendTo`.
    fn msg_to_input(&self, from: usize, msg: &ConsensusMsg) -> Input {
        match msg {
            ConsensusMsg::Propose(b) => Input::Propose { block: b.clone(), shards: Box::new(self.shards_for(b)) },
            ConsensusMsg::Vote(sv) => Input::Vote(sv.clone()),
            ConsensusMsg::Reveal(r) => Input::Reveal(r.clone()),
            ConsensusMsg::ExecVote(v) => Input::ExecVote(v.clone()),
            ConsensusMsg::SyncReq { have_height, have_root } => {
                Input::SyncReq { from: from as u8, have_height: *have_height, have_root: *have_root }
            }
            ConsensusMsg::SyncResp { cert, above, snapshot } => {
                Input::SyncResp { cert: cert.clone(), above: above.clone(), snapshot: snapshot.clone() }
            }
            ConsensusMsg::CommitCert(cert) => Input::CommitCert(cert.clone()),
            ConsensusMsg::NeedBody { block } => Input::NeedBody { from: from as u8, block: *block },
            // NOT `Input::Propose` like `Propose` above: a body answers a decision the receiver already holds, and is
            // checked against that decision rather than judged as a proposal.
            ConsensusMsg::Body(b) => Input::Body(b.clone()),
        }
    }

    /// How many ticks before validator `to` is dispersed its own shard of `block`.
    ///
    /// **Per (validator, block), not uniform** — and that distinction is the whole fidelity of this model. A proposer
    /// disperses peer by peer, so shards land at different times, and it is that stagger which lets a replica's request
    /// arrive at a peer that has nothing to answer with yet. A uniform delay is worthless as an instrument: every
    /// replica then holds its shard at the identical tick and every first request succeeds. Measured — this model was
    /// written with a uniform delay first and pinned nothing at all.
    ///
    /// Deterministic in `(to, block)`, so a failure reproduces exactly.
    fn sampling_latency(&self, to: usize, block: &Block) -> u32 {
        let h = block.hash();
        let spread = u32::from(h[0]).wrapping_add(u32::try_from(to).unwrap_or(0).wrapping_mul(31));
        1 + spread % self.da_delay
    }

    /// Model production's dispersal for one proposal: the skeleton is broadcast, and ONE shard goes to each validator.
    ///
    /// A withholding proposer omits a hyperoval's worth of shards — the minimal unrecoverable erasure pattern — so the
    /// block can never be reconstructed by anyone, which is what withholding means.
    fn disperse(&mut self, from: usize, block: &Block) {
        let skeleton = block.skeleton();
        let hash = block.hash();
        let all = block.da_shards();
        let present: u8 = if self.withholding.contains(&block.header.proposer) {
            let hyperoval = (0u8..=0x7F).find(|&m| !is_recoverable_fano(m)).unwrap_or(0);
            (!hyperoval) & 0x7F
        } else {
            0x7F
        };
        for i in 0..N {
            if self.crashed[i]
                || (from != usize::MAX && self.partition[from] != self.partition[i])
                || self.deaf_propose.contains(&i)
            {
                continue;
            }
            // Rank the skeleton immediately: it needs no sampling, and the SSLE round-0 lottery ranks the ticket it
            // carries rather than the body.
            let outs = self.engines[i].step(Input::Skeleton { block: skeleton.clone() });
            self.collect(i, outs);
            if self.samplers.get_mut(i).is_some_and(|s| s.begin(skeleton.clone())) {
                self.da_begins += 1;
            }
            if present & (1 << i) != 0
                && let Some(shard) = all.get(i)
            {
                self.dispersing.push((self.sampling_latency(i, block), i, hash, shard.clone()));
            }
        }
    }

    /// Fetch a block body a validator is **committed to but has never received** (`ShardMsg::NeedSkeleton` in the driver).
    ///
    /// Votes carry only a hash, so a validator can be locked on — or hold a commit certificate for — a block it never
    /// saw. It asks the cell for the skeleton, and any holder answers from `skeleton_of`, after which ordinary sampling
    /// takes over. Modelled here because without it the sim cannot express recovery at all: a partitioned validator
    /// rejoins knowing *what* finalized and not *which bytes*.
    fn fetch_awaited_bodies(&mut self) {
        for i in 0..N {
            if self.crashed[i] {
                continue;
            }
            let Some(want) = self.engines.get(i).and_then(ConsensusEngine::awaited_body) else { continue };
            if self.samplers.get(i).is_some_and(|s| s.is_sampling(&want)) {
                continue;
            }
            // Any reachable peer that holds the block answers with its skeleton.
            let skeleton = (0..N)
                .filter(|&p| p != i && !self.crashed[p] && self.partition[p] == self.partition[i])
                .find_map(|p| self.engines.get(p).and_then(|e| e.skeleton_of(&want)));
            let Some(skeleton) = skeleton else { continue };
            let outs = self.engines[i].step(Input::Skeleton { block: skeleton.clone() });
            self.collect(i, outs);
            if self.samplers.get_mut(i).is_some_and(|s| s.begin(skeleton)) {
                self.da_begins += 1;
            }
        }
        // Mirrors the driver's per-tick sweep: drop sampling for heights already decided.
        for i in 0..N {
            let h = self.engines[i].height();
            if let Some(s) = self.samplers.get_mut(i) {
                s.retain_relevant(self.engines[i].relevant_bodies());
                s.prune_below(h);
            }
        }
        self.run();
    }

    /// One DA exchange round for every validator: ask for what is missing, answer from whoever holds it, and admit any
    /// block that becomes recoverable — the same sequence `taxis_driver` performs, over this bus instead of QUIC.
    fn exchange_shards(&mut self) {
        for i in 0..N {
            if self.crashed[i] {
                continue;
            }
            let wanted = self.samplers.get_mut(i).map(Sampler::due).unwrap_or_default();
            for (hash, missing) in wanted {
                for index in missing {
                    // Counted before the partition/crash checks: a request a peer never receives still cost the sender
                    // a frame, which is precisely the cost a storm is made of.
                    self.da_requests += 1;
                    let peer = usize::from(index);
                    // A partition drops the request or its answer; a crashed peer answers nothing.
                    if self.crashed[peer] || self.partition[i] != self.partition[peer] {
                        continue;
                    }
                    let Some(shard) = self.samplers.get(peer).and_then(|s| s.serve(&hash, index)) else { continue };
                    let full = self.samplers.get_mut(i).and_then(|s| s.accept(hash, index, shard));
                    if let Some(full) = full {
                        let shards = Box::new(full.da_shards().map(Some));
                        let outs = self.engines[i].step(Input::Propose { block: full, shards });
                        self.collect(i, outs);
                    }
                }
            }
        }
        self.run();
    }

    /// Deliver every dispersed shard whose latency has elapsed, counting the rest down one tick.
    fn drain_dispersal(&mut self) {
        let due: Vec<(usize, [u8; 32], Vec<u8>)> = self
            .dispersing
            .iter_mut()
            .filter_map(|(left, to, h, shard)| {
                *left = left.saturating_sub(1);
                (*left == 0).then(|| (*to, *h, shard.clone()))
            })
            .collect();
        self.dispersing.retain(|(left, _, _, _)| *left > 0);
        for (to, hash, shard) in due {
            if self.crashed[to] {
                continue;
            }
            if let Some(s) = self.samplers.get_mut(to) {
                s.hold(hash, shard);
            }
        }
    }

    /// Start or stop dropping votes of one phase.
    fn set_drop_phase(&mut self, phase: Option<Phase>) {
        self.drop_phase = phase;
    }

    /// Start or stop dropping `phase` votes addressed to `targets` (see [`Self::drop_to`]).
    fn set_drop_to(&mut self, drop: Option<(Phase, &[usize])>) {
        self.drop_to = drop.map(|(p, t)| (p, t.iter().copied().collect()));
    }

    fn deliver(&mut self, from: usize, msg: &ConsensusMsg) {
        if let ConsensusMsg::Propose(b) = msg
            && !self.proposed.iter().any(|p| p.hash() == b.hash())
        {
            self.proposed.push(b.clone());
        }
        // With the dispersal model on, a proposal is not a single delivery: the skeleton lands now and the body later.
        if self.da_delay > 0
            && let ConsensusMsg::Propose(b) = msg
        {
            let b = b.clone();
            self.disperse(from, &b);
            return;
        }
        // A dropped phase never reaches anyone — the hiccup is in the network, not in a validator.
        if let ConsensusMsg::Vote(sv) = msg
            && self.drop_phase == Some(sv.vote.phase)
        {
            return;
        }
        for i in 0..N {
            if self.crashed[i] {
                continue;
            }
            // A hard partition drops any message crossing between groups (an injected `usize::MAX` sender is
            // exempt — it models an adversary that can reach the whole cluster).
            if from != usize::MAX && self.partition[from] != self.partition[i] {
                continue;
            }
            // A validator deaf to proposals still receives votes/reveals — it can gather a commit certificate
            // without ever seeing the body (the async case the wedge-fix must survive).
            if matches!(msg, ConsensusMsg::Propose(_)) && self.deaf_propose.contains(&i) {
                continue;
            }
            if matches!(msg, ConsensusMsg::Reveal(_)) && self.deaf_reveal.contains(&i) {
                continue;
            }
            // A targeted vote loss: this validator specifically does not hear this phase.
            if let ConsensusMsg::Vote(sv) = msg
                && let Some((phase, targets)) = &self.drop_to
                && *phase == sv.vote.phase
                && targets.contains(&i)
            {
                continue;
            }
            let input = self.msg_to_input(from, msg);
            let outs = self.engines[i].step(input);
            self.collect(i, outs);
        }
    }

    /// Enable the production DA-dispersal model at `delay` ticks of sampling latency (see [`Self::da_delay`]).
    fn with_da_delay(&mut self, delay: u32) {
        self.da_delay = delay;
    }

    /// Push one message onto the bus and drain to quiescence (for injecting an adversary's message — it reaches
    /// every group, `usize::MAX` sender).
    fn inject(&mut self, msg: ConsensusMsg) {
        self.bus.push_back((usize::MAX, msg));
        self.run();
    }

    /// Split the cluster: the listed validators become group 1, the rest group 0 — messages no longer cross.
    fn split(&mut self, group_b: &[usize]) {
        self.partition = (0..N).map(|i| u8::from(group_b.contains(&i))).collect();
    }

    /// Heal the partition — every validator rejoins one fully-connected group.
    fn heal_partition(&mut self) {
        self.partition = vec![0; N];
    }

    /// Register a Merkle-VRF root per validator and enable **secret-leader sortition** (SSLE) on every engine,
    /// over a `2^VRF_HEIGHT` domain based at height 0. Returns the registered roots. After this, round 0 is the
    /// min-ticket lottery over the elected line instead of the public deterministic leader.
    fn enable_sortition_all(&mut self) -> Vec<[u8; 32]> {
        let roots: Vec<[u8; 32]> =
            (0..N).map(|i| MerkleVrfSecret::generate(&vrf_seed(i), VRF_HEIGHT).unwrap().root()).collect();
        for i in 0..N {
            let secret = MerkleVrfSecret::generate(&vrf_seed(i), VRF_HEIGHT).unwrap();
            self.engines[i].enable_sortition(secret, roots.clone(), 0);
        }
        roots
    }

    /// Drain the bus to quiescence.
    fn run(&mut self) {
        let mut guard = 0;
        while let Some((from, msg)) = self.bus.pop_front() {
            self.deliver(from, &msg);
            guard += 1;
            assert!(guard < 200_000, "the message bus did not quiesce");
        }
    }

    fn tick(&mut self) {
        for i in 0..N {
            if self.crashed[i] {
                continue;
            }
            let outs = self.engines[i].step(Input::Tick);
            self.collect(i, outs);
        }
        self.run();
        if self.da_delay > 0 {
            self.drain_dispersal();
            self.exchange_shards();
        }
        // Recovery runs regardless of the dispersal model: it is about a body never received, not one being sampled.
        self.fetch_awaited_bodies();
        self.exchange_shards();
    }

    /// Drive one further height so the previous block's anti-MEV openings are **committed** and it executes.
    ///
    /// Execution lags finality by one block, and that is a protocol property rather than a harness quirk
    /// (#137): the openings for block `H` only exist once `H` is final, so the earliest block that can carry
    /// them is `H+1`, and execution reads them from the chain rather than from each validator's gossip. A
    /// test that finalizes a block and immediately asserts on executed state is asking for the state of a
    /// block whose input has not been agreed yet.
    ///
    /// Named rather than written as a bare extra `tick()` so the reason survives in the tests that need it.
    fn settle(&mut self) {
        self.tick();
        self.timeout();
    }

    fn timeout(&mut self) {
        self.timeout_some(&(0..N).collect::<Vec<_>>());
    }

    /// Fire the round timer of **some** validators only.
    ///
    /// Timers are local and independent, so this is the ordinary case and cell-wide [`timeout`](Self::timeout) is the
    /// special one. The distinction is not cosmetic: a cell-wide timeout keeps every validator in the same round by
    /// construction, which is the one arrangement in which round drift cannot be expressed — and drift is what a live
    /// cell exhibits (measured: four validators at round 8 while three were at round 9, quorum 5, nothing finalizing).
    fn timeout_some(&mut self, who: &[usize]) {
        for &i in who {
            if self.crashed[i] {
                continue;
            }
            let outs = self.engines[i].step(Input::Timeout);
            self.collect(i, outs);
        }
        self.run();
    }

    fn submit_all(&mut self, tx: &SealedTx) {
        for i in 0..N {
            if !self.crashed[i] {
                self.engines[i].submit(tx.clone());
            }
        }
    }

    /// Seal a transfer to this epoch's beacon-selected keyper line (2-of-3 on the Fano cell) — via the
    /// committed decryption authority, exactly as a real client seals ([`seal_to_keyper_committee`]).
    fn seal(&self, transfer: Transfer, tag: &[u8]) -> SealedTx {
        seal_to_keyper_committee(&self.registry, &transfer.into_tx(), EPOCH, CellParams::FANO, tag).unwrap()
    }

    /// The set of honest (non-crashed) validators that have finalized `height`, and the block hashes they
    /// finalized it with (must be a single hash for agreement).
    fn hashes_at(&self, height: u64) -> BTreeSet<[u8; 32]> {
        let mut set = BTreeSet::new();
        for i in 0..N {
            if self.crashed[i] {
                continue;
            }
            for &(h, hash) in &self.committed[i] {
                if h == height {
                    set.insert(hash);
                }
            }
        }
        set
    }

    fn honest_count_at(&self, height: u64) -> usize {
        (0..N)
            .filter(|&i| !self.crashed[i] && self.committed[i].iter().any(|&(h, _)| h == height))
            .count()
    }
}

fn genesis() -> Accounts {
    let mut s = Accounts::new();
    s.credit(ALICE, 1000);
    s
}

#[test]
fn a_transaction_finalizes_and_executes_in_agreed_order() {
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"t0");

    // Anti-MEV precondition, stated against the fault budget rather than against one member (#136): a
    // coalition of `f = 2` — everything the cell tolerates — must not decrypt. The committee is the whole
    // cell in validator-index order, so member `i`'s slot is index `i`. A proposer orders blind.
    let keys = gen_keys();
    let coalition: Vec<_> = (0..CellParams::FANO.f())
        .map(|m| tx.member_share(m, &keys[m].kem).expect("a member opens its own slot"))
        .collect();
    assert!(
        tx.open(&coalition).is_err(),
        "a coalition at the fault bound f = {} must not decrypt (t = {})",
        CellParams::FANO.f(),
        CellParams::FANO.seal_threshold()
    );

    c.submit_all(&tx);
    c.tick(); // leader proposes height 0; the cluster drives prepare → commit → finalize → reveal.
    c.settle(); // and one more height, because the openings are COMMITTED (#137).

    // All seven honest validators finalized height 0, and on the SAME block (agreement).
    assert_eq!(c.honest_count_at(0), N, "every honest validator finalizes height 0");
    assert_eq!(c.hashes_at(0).len(), 1, "all validators agree on one block at height 0");

    // The transfer executed in every replica: ALICE 900, BOB 100 — and every state root agrees.
    let root = c.engines[0].chain().state_root();
    for e in &c.engines {
        assert_eq!(e.chain().state().balance(&ALICE), 900);
        assert_eq!(e.chain().state().balance(&BOB), 100);
        assert_eq!(e.chain().state_root(), root, "all replicas agree on the state root");
    }
}

#[test]
fn ssle_finalizes_when_bodies_arrive_by_da_sampling_rather_than_whole() {
    // THE REGRESSION TEST FOR A TOTAL LIVENESS FAILURE, and for the fidelity gap that hid it.
    //
    // Every other SSLE test here delivers each proposal as a complete block, which production never does: the driver
    // broadcasts the skeleton, disperses one erasure shard per validator, and admits the proposal only after sampling
    // the rest and reconstructing the body. Under all-propose that is N proposals each needing a sampling round trip,
    // against a one-tick collection window — so every replica ranked a different subset of the lottery, split its
    // PREPARE, and the cell finalized NOTHING. Measured over real QUIC: no block in 240 s, while every engine-level
    // SSLE test passed.
    //
    // With `da_delay`, the sim runs production's shape: skeletons land at once, bodies land later. The lottery must
    // therefore rank from skeletons — the ticket rides in the witness — and require availability only for the block it
    // actually prepares. If ranking is ever gated on the body again, this test goes red and the QUIC suite does not
    // have to spend 240 s to say so.
    let mut c = Cluster::new(&genesis());
    c.enable_sortition_all();
    c.with_da_delay(2); // bodies arrive two ticks after their skeletons

    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"ssle-da");
    c.submit_all(&tx);
    // Ticks, not one: the winner is ranked from its skeleton in the first, and its body cannot arrive before the
    // third. A cell that only finalizes when proposals arrive whole never finalizes here at all.
    for _ in 0..6 {
        c.tick();
    }

    assert_eq!(c.honest_count_at(0), N, "every honest validator finalizes height 0 despite dispersed bodies");
    assert_eq!(c.hashes_at(0).len(), 1, "and on ONE block — ranking from skeletons kept the lottery agreed");
    let root = c.engines[0].chain().state_root();
    for e in &c.engines {
        assert_eq!(e.chain().state().balance(&ALICE), 900, "the transfer executed");
        assert_eq!(e.chain().state().balance(&BOB), 100);
        assert_eq!(e.chain().state_root(), root, "all replicas agree on the state root");
    }
}

#[test]
fn every_validator_recovers_a_dispersed_block_not_merely_a_quorum() {
    // The shape `dromos_quic`'s private-transfer test asserts and the live path fails: `sortition: None`, one proposer
    // per round, DA-dispersed bodies — and **unanimity**, not a quorum. A quorum finalizing is not enough, because a
    // validator that gathers the commit certificate without ever recovering the body wedges at genesis forever while
    // the rest of the cell moves on. Measured live as one stuck validator, then three, then only-the-proposer executing.
    //
    // Asserted on the samplers too: `in_flight() == 0` says every validator actually recovered the payload, which is
    // strictly stronger than "it finalized" and is the thing that was failing.
    let mut c = Cluster::new(&genesis());
    c.with_da_delay(4); // a wider dispersal stagger than the SSLE case, so first requests reliably find nothing

    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"da-unanimity");
    c.submit_all(&tx);
    for _ in 0..12 {
        c.tick();
    }

    assert_eq!(c.honest_count_at(0), N, "EVERY validator finalizes height 0, not just a quorum");
    assert_eq!(c.hashes_at(0).len(), 1, "and on one block");
    // The sampler assertion that used to stand here — `in_flight() == 0` for every validator — is **deleted, not
    // relaxed**, and the distinction matters. It read as "every validator recovered the payload", but what it actually
    // said was "no sampling is in progress at the final tick": incidental to one message schedule, and it stopped
    // holding once body recovery changed the timing, with a validator at height 4 legitimately sampling a height-4
    // proposal. The payload claim it stood in for is proven below and far more directly — a validator cannot *execute*
    // a transfer whose payload it never recovered, so the BOB balance is the evidence.
    //
    // A "nothing stale is left to prune" assertion replaced it briefly and was dropped too: falsifying it by removing
    // the per-tick sweep left the test green, so this scenario never produces an abandoned entry and the assertion was
    // vacuous. `Sampler::prune_below` is pinned where a stale entry can actually be constructed — in `da.rs`.
    let root = c.engines[0].chain().state_root();
    for (i, e) in c.engines.iter().enumerate() {
        assert_eq!(e.chain().state().balance(&BOB), 100, "validator {i} executed the transfer");
        assert_eq!(e.chain().state_root(), root, "and agrees on the state root");
    }
}

#[test]
fn ssle_the_secret_min_ticket_line_member_leads_and_finalizes() {
    // Secret-leader election: with sortition enabled, EVERY elected-line member proposes (all-propose), and
    // the cell prepares+finalizes the LOWEST-ticket proposal — the secret leader, unknown until it proposes.
    // The finalized proposer must be the independently-recomputed min-ticket winner, and its block must carry
    // a valid sortition witness. Safety/finality are the standard PBFT flow; only WHO leads changes.
    let mut c = Cluster::new(&genesis());
    c.enable_sortition_all();
    for e in &c.engines {
        assert!(e.sortition_enabled());
    }

    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"ssle0");
    c.submit_all(&tx);
    c.tick(); // all line members propose; the all-collected early-exit prepares the min-ticket in this tick.

    // Height 0 finalized, unanimously and on one block (agreement) — the collection window did not split votes.
    assert_eq!(c.honest_count_at(0), N, "every honest validator finalizes the secret-leader block at height 0");
    assert_eq!(c.hashes_at(0).len(), 1, "all validators agree on one block at height 0");

    // The finalized block was proposed by the min-ticket winner (a genuine line member), and carries its witness.
    let finalized = c.hashes_at(0).into_iter().next().unwrap();
    let block = c.proposed.iter().find(|b| b.hash() == finalized).unwrap();
    let members = line_members(leader_line(&SEED, 0, 0)).expect("a real line");
    assert!(members.contains(&usize::from(block.header.proposer)), "the secret leader is an elected line member");
    assert_eq!(block.header.proposer, expected_ssle_leader(0), "the finalized proposer is the lowest-ticket member");
    assert!(block.witness.is_some(), "a round-0 secret-leader block carries its Merkle-VRF ticket witness");

    // The anti-MEV transfer still executed in agreed order (SSLE composes with the rest of the pipeline).
    c.settle(); // execution lags finality by one block — the openings are COMMITTED (#137).
    for e in &c.engines {
        assert_eq!(e.chain().state().balance(&ALICE), 900);
        assert_eq!(e.chain().state().balance(&BOB), 100);
    }
}

#[test]
fn ssle_leadership_is_secret_valued_and_not_the_public_schedule() {
    // Over several heights the secret min-ticket leader is a line member each time, differs from the PUBLIC
    // deterministic leader at least sometimes (so sortition genuinely hides/reshuffles leadership, not a
    // relabelling of the same schedule), and never forks. Interleave timeouts so a height whose min-ticket
    // winner is unlucky still advances via the public fallback.
    let mut c = Cluster::new(&genesis());
    c.enable_sortition_all();

    for h in 0..5u64 {
        let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 1, nonce: h }, &[b'h', h as u8]);
        c.submit_all(&tx);
        c.tick();
        c.timeout();
    }

    let reached = c.engines[0].chain().next_height();
    assert!(reached >= 3, "the SSLE cell makes progress across heights, reached {reached}");
    let mut differed_from_public = false;
    for h in 0..reached {
        // No fork at any height.
        assert!(c.hashes_at(h).len() <= 1, "no fork at height {h}");
        if let Some(hash) = c.hashes_at(h).into_iter().next()
            && let Some(block) = c.proposed.iter().find(|b| b.hash() == hash)
        {
            // A round-0 (witnessed) block must be led by the min-ticket line member; a public-fallback block
            // (no witness, from a view change) is led by the deterministic leader — both are line members.
            if block.witness.is_some() {
                assert_eq!(block.header.proposer, expected_ssle_leader(h), "height {h}: min-ticket leader");
                assert!(
                    line_members(leader_line(&SEED, h, 0))
                        .is_some_and(|m| m.contains(&usize::from(block.header.proposer)))
                );
                if block.header.proposer != leader(&SEED, h, 0) as u8 {
                    differed_from_public = true;
                }
            }
        }
    }
    assert!(differed_from_public, "the secret leader must diverge from the public schedule on some height");
}

#[test]
fn ssle_a_down_line_member_does_not_stall_the_round_the_window_expiry_finalizes() {
    // The collection-window tick-expiry (Δ_prio) path — the liveness mechanism the happy-path early-exit skips.
    // Crash one member of height 0's elected line so only q of q+1 propose: the all-collected early-exit CANNOT
    // fire, and the window must expire and prepare the min of the LIVE proposals. A down line member just shrinks
    // the candidate set — no view change (round advance) is needed, so this stays a witnessed round-0 block.
    let mut c = Cluster::new(&genesis());
    c.enable_sortition_all();
    let members = line_members(leader_line(&SEED, 0, 0)).expect("a real line");
    let victim = members[0];
    c.crashed[victim] = true;

    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"down0");
    c.submit_all(&tx);
    for _ in 0..3 {
        c.tick(); // tick 1 collects the q live proposals; tick 2 expires the window → prepare min → finalize.
    }

    assert_eq!(c.hashes_at(0).len(), 1, "the window-expiry prepared a single agreed block");
    assert!(c.honest_count_at(0) >= 5, "a Q-quorum finalized height 0 despite a down line member");
    let finalized = c.hashes_at(0).into_iter().next().unwrap();
    let block = c.proposed.iter().find(|b| b.hash() == finalized).unwrap();
    assert_ne!(usize::from(block.header.proposer), victim, "the crashed member did not lead");
    assert!(members.contains(&usize::from(block.header.proposer)), "the leader is a (live) line member");
    assert!(block.witness.is_some(), "still a witnessed round-0 block — the window expiry, not a view-change fallback");
}

/// **The level-and-wrong state, constructed rather than raced — and repaired.**
///
/// `losing_the_sync_race_...` below pins the same property and passes for the wrong reason: in the sim its
/// laggard stays stuck at genesis, so the condition it forbids is never actually built. This builds it.
///
/// One validator hears every vote and every body and no REVEALS, for the whole run. `finalize` advances on the
/// header, so its height tracks the cell exactly; only execution waits for the openings. Once the cell
/// finalizes `REVEAL_WINDOW` further heights it drops the transaction as undecryptable while everyone else
/// executes it — no fork, no equivocation, no Byzantine participant, because the drop CLOCK is agreed and the
/// drop PREDICATE (`shares.len() < t`) is over a local view.
///
/// The property asserted is the OUTCOME, and the second assertion is what stops it being vacuous: the blind
/// validator must have reached the cell's state by **adopting certified state**, not by never diverging. Its
/// own execution attestation disagreeing with the quorum's is the evidence that triggers the ask; the height
/// comparison that used to gate both the ask and the answer cannot see this condition at all.
#[test]
fn a_validator_that_missed_every_gossiped_reveal_executes_the_cells_state_anyway() {
    const BLIND: usize = 5;
    let mut c = Cluster::new(&genesis());
    c.deaf_reveal.insert(BLIND);

    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 250, nonce: 0 }, b"diverge-tx");
    c.submit_all(&tx);
    for _ in 0..14 {
        c.tick();
        c.timeout();
    }
    assert_eq!(c.engines[0].chain().state().balance(&BOB), 250, "the cell executed the transfer");
    assert_eq!(
        c.engines[BLIND].chain().next_height(),
        c.engines[0].chain().next_height(),
        "the blind validator keeps up on HEIGHT — `finalize` advances on the header, so by its own catch-up \
         test it is never behind"
    );

    // THE PROPERTY, and #137 inverted it. This test used to assert that a reveal-deaf validator DIVERGES —
    // executes the block empty — and is then detected by the executed-state checkpoint and repaired by
    // state-sync. That was an accurate description of a defect: the divergence existed because execution read
    // a gossip pool, and detect-then-repair was the mitigation. Committing the openings removes the
    // divergence, so the same fixture now proves the stronger thing.
    let probe = c.engines[BLIND].probe();
    assert_eq!(
        c.engines[BLIND].chain().state().balance(&BOB),
        250,
        "a validator that received not one gossiped reveal still executes the cell's state, because the \
         openings reached it on the chain.\n  blind: {probe}"
    );

    // NON-VACUITY, both directions (`instrument-both-directions`). Either half alone is satisfiable by a
    // harness bug: without the first, gossip may have been delivered after all and the fixture proves
    // nothing; without the second, execution might have had no openings at all and the balance could be
    // right for some other reason.
    assert_eq!(
        probe.reveals_taken.0, 0,
        "the reveal drop must actually take — this validator must have recorded NO gossiped opening.\n  \
         blind: {probe}"
    );
    assert!(
        probe.reveals_taken.1 > 0,
        "and it must have absorbed openings from committed blocks, which is the input it executed from.\n  \
         blind: {probe}"
    );

    // And the repair is now unnecessary rather than merely successful: there was never a divergence to
    // detect. A `sync_taken > 0` here would mean execution had diverged after all.
    assert_eq!(
        probe.sync_taken, 0,
        "no state-sync repair should be needed: with the openings committed there is no divergence to \
         detect.\n  blind: {probe}"
    );
}

#[test]
fn losing_the_sync_race_must_not_leave_a_validator_at_the_cells_height_with_another_state() {
    // The other side of `a_lagging_validator_state_syncs_...`, and the one that was never constructed. A
    // recovering validator has TWO ways forward — adopt a certified snapshot, or walk the chain block by block
    // — and only the first restores the state it missed. Nothing arbitrates which arrives first. This pins what
    // must happen when the snapshot loses.
    const LATE: usize = 6;
    let mut c = Cluster::new(&genesis());
    c.crashed[LATE] = true;

    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 250, nonce: 0 }, b"race-tx");
    c.submit_all(&tx);
    for _ in 0..6 {
        c.tick();
        c.timeout();
    }
    let live_height = c.engines[0].chain().next_height();
    let live_root = c.engines[0].chain().state_root();
    assert!(live_height >= 3, "the live cell advanced past a few heights");
    assert_eq!(c.engines[0].chain().state().balance(&BOB), 250, "the cell executed the transfer");

    // The snapshot never lands. Everything else — proposals, votes, commit certificates, bodies — flows.
    c.drop_sync_resp = true;
    c.crashed[LATE] = false;
    // Six rounds, matching the drive above. The cell advances every round and the laggard does not, so the gap
    // the assertions read only widens — more rounds buy seconds, not confidence, and each is a full PQ round.
    for _ in 0..6 {
        c.tick();
        c.timeout();
    }

    let late_height = c.engines[LATE].chain().next_height();
    let late_root = c.engines[LATE].chain().state_root();
    let cell_height = c.engines[0].chain().next_height();
    let cell_root = c.engines[0].chain().state_root();

    // Observed today: the laggard stays at genesis — visibly stuck, which is the SAFE loss. It cannot walk the
    // chain forward on its own because it can obtain no body for a height it never saw proposed, so without a
    // snapshot it does not move at all. That is worth pinning, because the failure mode this test exists to
    // forbid is the opposite one and the two are easy to conflate: stuck is loud and recoverable, level-and-wrong
    // is silent and permanent.
    assert!(
        late_height < cell_height,
        "with no snapshot the laggard should not have advanced at all, yet it reached {late_height} against \
         the cell's {cell_height} — so it found another way forward, and the assertion below is now the whole \
         guard rather than a backstop"
    );
    // THE PROPERTY. Reaching the cell's height while holding a different state is the one outcome that must be
    // impossible, because it is indistinguishable from health by every quantity the validator itself checks:
    // `maybe_request_sync` fires on `max_seen_height > height()`, so a validator that has closed the height gap
    // is BY ITS OWN TEST not behind, and never asks again. Being stuck is fine — it is visible and it recovers.
    // Being level and wrong is neither.
    assert!(
        !(late_height >= cell_height && late_root != cell_root),
        "the late validator sits at the cell's height {cell_height} (its own {late_height}) with a DIFFERENT \
         state root — alice={} bob={} against the cell's alice={} bob={}. It will never ask for catch-up \
         again, because by height it is not behind. A validator that cannot move forward is recoverable; one \
         that has moved forward wrongly is not.",
        c.engines[LATE].chain().state().balance(&ALICE),
        c.engines[LATE].chain().state().balance(&BOB),
        c.engines[0].chain().state().balance(&ALICE),
        c.engines[0].chain().state().balance(&BOB),
    );
    let _ = (live_root, live_height);
}

#[test]
fn a_lagging_validator_state_syncs_to_the_certified_state_and_rejoins() {
    // Audit §3.9 / §4: a validator that misses heights (crashed, partitioned, or lost a startup race) must not
    // wedge forever. On recovery it detects it is behind, requests catch-up, adopts a peer's QUORUM-CERTIFIED
    // state snapshot, and rejoins live consensus — reaching the state the cell agreed WITHOUT ever re-decrypting
    // the anti-MEV transaction whose reveals it never saw, and with no fork at any height.
    const LAG: usize = 6; // one validator falls behind; the other 6 ≥ Q = 5 keep consensus live
    let mut c = Cluster::new(&genesis());
    c.crashed[LAG] = true;

    // Drive the live cell through a transaction and several empty blocks, forming execution checkpoints.
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 250, nonce: 0 }, b"lag-tx");
    c.submit_all(&tx);
    // Interleave tick + timeout so a height whose round-0 leader is the crashed validator still advances (a
    // timeout re-elects a live leader) — otherwise the cell would stall on the laggard's leader slots.
    for _ in 0..6 {
        c.tick();
        c.timeout();
    }
    let live_height = c.engines[0].chain().next_height();
    assert!(live_height >= 3, "the live cell advanced past a few heights");
    assert!(c.engines[0].latest_checkpoint().is_some(), "the live cell formed an execution checkpoint");
    assert_eq!(c.engines[LAG].chain().next_height(), 0, "the crashed validator is stuck at genesis (no catch-up yet)");

    // Recover the laggard and drive: it hears future-height messages, requests catch-up, and state-syncs.
    c.crashed[LAG] = false;
    for _ in 0..8 {
        c.tick();
        c.timeout();
    }

    // It caught up — advanced far past genesis (it did NOT re-execute heights 1..H, only adopted the certified
    // state) and reflects the transfer it never decrypted, in the exact agreed final balances.
    assert!(c.engines[LAG].chain().next_height() >= live_height, "the laggard synced forward, not wedged");
    assert_eq!(c.engines[LAG].chain().state().balance(&ALICE), 750, "the laggard adopted the certified ALICE balance");
    assert_eq!(c.engines[LAG].chain().state().balance(&BOB), 250, "the laggard adopted the certified BOB balance");
    // Every validator (now all live) agrees on the state root — the synced node is on the SAME chain.
    let root = c.engines[0].chain().state_root();
    assert_eq!(c.engines[LAG].chain().state_root(), root, "the synced validator's state root matches the cell");
    // No fork: every height carries a single block hash across all validators.
    for h in 0..c.engines[0].chain().next_height() {
        assert!(c.hashes_at(h).len() <= 1, "no fork at height {h}");
    }
}

#[test]
fn body_retention_is_bounded_by_the_checkpoint_horizon_and_covers_exactly_what_bodies_serve() {
    // #42. `recent_bodies` was bounded by a count — `RECENT_BODY_CAP`, whose own doc said it was "generous rather
    // than tight" — which is a capacity where a relevance rule belongs. The horizon it should have used was already
    // in the engine, already agreed by a quorum, and already pruning the finalizing certificates beside it: the
    // **execution checkpoint**.
    //
    // The derivation is a partition, and the point of this test is that the partition is EXHAUSTIVE — the retained
    // half is exactly the half bodies serve, so tightening the bound costs nothing:
    //
    //   * a peer at height `h < checkpoint` is carried to the checkpoint by `SyncResp` (certified executed state);
    //     replaying bodies it would have to re-verify is strictly more work for the same destination, so bodies
    //     below the checkpoint serve nobody — and this test's FIRST assertion is that such a peer still rejoins.
    //   * a peer at `h >= checkpoint` gains nothing from `SyncResp` (it is already there), so bodies are its only
    //     path — and every body it can ask for is at a height `>= checkpoint`, which is precisely what is retained.
    //
    // Both halves are asserted, and the second matters as much as the first: a retention rule that keeps everything
    // is a memory leak wearing a correctness argument.
    const LAG: usize = 6;
    let mut c = Cluster::new(&genesis());
    c.crashed[LAG] = true;
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 250, nonce: 0 }, b"horizon");
    c.submit_all(&tx);
    for _ in 0..8 {
        c.tick();
        c.timeout();
    }
    let cp = c.engines[0].latest_checkpoint().expect("the live cell formed an execution checkpoint").height;
    let head = c.engines[0].chain().next_height();
    assert!(head > cp, "the head is ahead of the checkpoint, so there is a retained window to test at all");

    // ---- THE PROPERTY, first: pruning below the horizon costs no liveness. ----
    // The laggard is at genesis — far below the checkpoint, so every body it might have replayed is now gone. It
    // must still rejoin, because the horizon is exactly where the OTHER rescue path takes over.
    c.crashed[LAG] = false;
    for _ in 0..8 {
        c.tick();
        c.timeout();
    }
    assert!(c.engines[LAG].chain().next_height() >= head, "a peer below the horizon is still rescued (by SyncResp)");
    assert_eq!(c.engines[LAG].chain().state_root(), c.engines[0].chain().state_root(), "and lands on the same chain");

    // ---- THE MECHANISM, second: the window is the horizon, on both sides. ----
    // Re-read the checkpoint: it advanced while the laggard synced, so the floor under test is the current one.
    let cp = c.engines[0].latest_checkpoint().expect("checkpoint").height;
    let head = c.engines[0].chain().next_height();
    let (mut served, mut dropped) = (0u64, 0u64);
    for h in 0..head {
        let Some(hash) = c.hashes_at(h).into_iter().next() else { continue };
        // `shard_of` is the serving path a lagging peer reaches (`NeedBody` answers from the same two maps), so it
        // is the honest observable for "could this node still help someone at height h".
        let servable = c.engines[0].shard_of(&hash, 0).is_some();
        if h >= cp {
            assert!(servable, "height {h} is at/above the checkpoint {cp} — the ONLY path for a peer there");
            served += 1;
        } else {
            assert!(!servable, "height {h} is below the checkpoint {cp} — retaining it serves nobody");
            dropped += 1;
        }
    }
    assert!(served > 0, "the retained window is non-empty");
    assert!(dropped > 0, "and the horizon actually released something — otherwise this proves nothing");
}

#[test]
fn a_sustained_deferral_flood_cannot_restart_an_older_transactions_give_up_clock() {
    // #43. A premature transaction (a nonce ahead of its sender's, the common case under blind ordering) is
    // returned to the mempool and aged against `deferred_since[commit]` — the height it was FIRST deferred — until
    // `REVEAL_WINDOW` heights have passed. A MISSING record does not drop the transaction; `note_deferrals` falls
    // back to "first deferred now", so losing the record does not evict the transaction, it **restarts its clock**.
    //
    // That makes the map's eviction order the give-up policy. `BoundedMap` fixes a key's position at its first
    // insert and never refreshes it on re-insertion, so insertion order here IS deferral order exactly — and plain
    // FIFO therefore takes, every single time, the entry closest to its horizon: the one whose value is the only
    // thing still load-bearing. `TxCommit` is derived from submitted transactions, so a steady arrival of newly
    // deferred ones is remote-reachable, and it pushes every predecessor's deadline forward indefinitely.
    //
    // THE PROPERTY, and it is the whole claim: a premature transaction occupies at most `REVEAL_WINDOW + 1`
    // BLOCKS **no matter what arrives after it**.
    const CAP: usize = 64; // `deferred_since`'s capacity
    const PER_HEIGHT: usize = 4; // fresh clocks per height, enough to keep displacing the map's oldest entry
    // Blocks carrying it, not the span of heights between the first and the last — and the difference became
    // load-bearing with #137. The give-up budget bounds RETRIES; the heights between two retries are however
    // long execution takes to reach the transaction, which is now at least two and up to `REVEAL_WINDOW + 1`.
    // A span bound therefore measures the pacing of execution and calls it the retry budget, while the count
    // measures the thing the budget is about and the thing the attack would inflate — the block space one
    // victim can be made to occupy. Measured 6 blocks here, over a span of 17 heights.
    const CARRIED: usize = REVEAL_WINDOW as usize + 2;
    let mut c = Cluster::new(&genesis());

    // The victim goes in alone and first, so it is unambiguously the oldest clock in the map.
    let victim = c.seal(Transfer { from: ALICE, to: BOB, amount: 1, nonce: 9 }, b"victim");
    let vc = victim.commit();
    c.submit_all(&victim);
    c.tick();
    c.timeout();

    // Then a sustained flood: every height, fresh senders with far-future nonces, each deferring forever.
    let mut minted = 0u32;
    for round in 0..12u32 {
        let batch = if round == 0 { CAP + 1 } else { PER_HEIGHT };
        for _ in 0..batch {
            let mut from = [0u8; 32];
            from[0] = 0xF1;
            from[1..5].copy_from_slice(&minted.to_le_bytes());
            minted += 1;
            let flood = c.seal(Transfer { from, to: BOB, amount: 1, nonce: 9 }, b"flood");
            c.submit_all(&flood);
        }
        c.tick();
        c.timeout();
    }

    // Which heights actually carried a transaction, read off the FINALIZED chain (not the proposal set, which
    // can hold blocks no quorum ever agreed).
    let span_of = |c: &Cluster, want: TxCommit| -> Option<Vec<u64>> {
        let mut carried: Vec<u64> = Vec::new();
        for h in 0..c.engines[0].chain().next_height() {
            let Some(hash) = c.hashes_at(h).into_iter().next() else { continue };
            let Some(b) = c.proposed.iter().find(|b| b.hash() == hash) else { continue };
            if b.sealed_txs.iter().any(|t| t.commit() == want) {
                carried.push(h);
            }
        }
        carried.first()?;
        Some(carried)
    };

    let carried = span_of(&c, vc).expect("the victim was included at least once");
    assert!(
        carried.len() <= CARRIED,
        "the victim was carried by {} blocks ({carried:?}), past its horizon of {CARRIED} — a flood of newer \
         deferrals restarted its give-up clock",
        carried.len()
    );

    // And the same rule at the other end, quantified over EVERY transaction rather than a chosen one — because
    // which transaction gets refused a clock is not predictable from this side: the proposer orders the mempool
    // blindly by commitment, so block order is not submission order. A first attempt here nominated one "late"
    // transaction and asserted about it; that probe could not discriminate, since by the round it was minted the
    // first batch's clocks had expired and the map had room again.
    //
    // The universal form needs no guess and is strictly stronger: refusing a clock and refusing the retry are ONE
    // decision, so an engine that re-queues a transaction it declined to age has merely moved immortality from the
    // oldest entry to the newest — and *some* transaction then outlives the span, whichever one it is.
    let mut worst: Option<(TxCommit, Vec<u64>)> = None;
    for tx in c.proposed.iter().flat_map(|b| b.sealed_txs.iter()).map(SealedTx::commit).collect::<BTreeSet<_>>() {
        let Some(carried) = span_of(&c, tx) else { continue };
        if worst.as_ref().is_none_or(|(_, w)| carried.len() > w.len()) {
            worst = Some((tx, carried));
        }
    }
    let (_, worst_carried) = worst.expect("the run finalized transactions");
    assert!(
        worst_carried.len() <= CARRIED,
        "some transaction was carried by {} blocks ({worst_carried:?}), past the horizon of {CARRIED} — every \
         transaction is either aged against a clock or refused outright, and this implementation retried one \
         it could not age",
        worst_carried.len()
    );

    // THE MECHANISM, second: the clock map is still bounded, so keeping the older clock did not trade a horizon
    // for a leak. Read through the operator-visible observable rather than a test-only accessor — an operator
    // watching a deferral attack sees exactly this pair.
    let (pool, clocks) = c.engines[0].probe().backlog;
    assert!(clocks <= CAP, "the deferral map stayed bounded ({clocks} clocks, cap {CAP}) — pool {pool}");
}

/// **A validator holding a decision it cannot apply asks a certificate voter for the body — and applies it.**
///
/// The measured wedge, in deterministic form. A live cell produced `ccrej[h=0 v=0 park=1963] PARKED@1`: 1963 commit
/// certificates accepted — every one passing height, phase and signature — and every one parked, because `finalize`
/// needs the block body and nothing in the protocol carried it. `NeedSkeleton` answers with a payload-less skeleton, and
/// re-gathering the payload from erasure shards asks custodians that may never have been dispersed one, while the block
/// sits whole on every validator that voted COMMIT on it.
#[test]
fn a_validator_holding_a_decision_it_cannot_apply_asks_a_voter_for_the_body() {
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"need-body");
    c.submit_all(&tx);

    // Drop the PROPOSAL to one validator while everyone else prepares and commits it: it collects the commit quorum
    // from their votes and so holds the decision, having never held the block.
    let victim = 0usize;
    c.deaf_propose.insert(victim);
    c.tick();
    c.deaf_propose.remove(&victim);

    let p = c.engines[victim].probe();
    let Some(parked) = p.parked else {
        panic!("setup did not park a decision — asserting the recovery below would be vacuous: {p}");
    };
    assert_eq!(parked, 0, "the parked decision is the height it cannot finalize: {p}");
    assert_eq!(c.engines[victim].chain().next_height(), 0, "and it has not finalized it");

    // Exactly ONE tick, which is what makes this a test of the body path rather than of whatever rescues first. At
    // this instant the snapshot path is provably unavailable: the cell has executed height 0, so the newest checkpoint
    // anywhere is at 0, and `on_sync_req` serves a snapshot only STRICTLY above the requester's height. Give the cell
    // six ticks instead and it is a state-sync that carries the victim — measured, on the first draft of this test.
    c.tick();

    let p = c.engines[victim].probe();
    assert!(p.body_asks > 0, "it asked a certificate voter for the body: {p}");
    assert!(p.body_taken > 0, "and applied one: {p}");
    assert!(p.parked.is_none(), "so nothing is parked any more: {p}");
    assert_eq!(
        c.engines[victim].chain().next_height(),
        c.engines[1].chain().next_height(),
        "it finalized the decision it had been holding and is level with the cell: {p}"
    );
    assert_eq!(c.hashes_at(0).len(), 1, "one block at that height — recovery must not fork it");
}

/// **A cell where the MAJORITY failed to collect the commit quorum still recovers.**
///
/// Every recovery test in this file strands one validator (`LAG = 6`) or three (`short = [4, 5, 6]`). The live
/// `dromos_quic` failure strands **five of seven**, and that is not the same problem scaled: with five short, the
/// execution checkpoint can never advance past them, because a checkpoint needs a `Q`-quorum of *execution* votes and a
/// validator votes only after executing the height it is stuck on. Measured on the live cell: height 1 carried 2 exec
/// votes against `Q = 5`, so the two ahead validators were checkpointed at height **0** — below the laggards' height —
/// and `on_sync_req` served a commit certificate ~4250 times each and a snapshot **never**.
///
/// So this configuration takes the state-sync path off the table entirely and rests the whole recovery on
/// `ConsensusMsg::CommitCert`. Live, that path advanced nobody: five validators asked ~850 times each and adopted
/// exactly one certificate apiece. This is the deterministic form of that cell.
#[test]
fn a_cell_whose_commit_quorum_reached_only_a_minority_still_recovers() {
    let mut c = Cluster::new(&genesis());
    // Five of seven never receive the COMMIT votes, so only two collect the quorum and finalize. They still SEND
    // theirs, which is why the quorum forms at all — the same partial-connectivity fault as the three-short test,
    // past the point where a quorum of *executors* remains.
    let short = [2usize, 3, 4, 5, 6];
    c.set_drop_to(Some((Phase::Commit, &short)));
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"majority-short");
    c.submit_all(&tx);
    c.tick();

    let ahead = c.engines[0].chain().next_height();
    assert!(ahead >= 1, "the two well-connected validators finalized the height: {}", c.engines[0].probe());
    for &i in &short {
        assert_eq!(c.engines[i].chain().next_height(), 0, "validator {i} is short a signature, not a body");
    }
    // The premise of this scenario, asserted rather than assumed: no checkpoint can exist at the finalized height,
    // because only two validators executed it.
    for i in 0..N {
        let ck = c.engines[i].latest_checkpoint().map(|c| c.height);
        assert!(ck.is_none() || ck < Some(ahead), "validator {i} cannot be checkpointed at a height 5 of 7 never executed");
    }

    // What carries them is the **newer-block** path, not the certificate, and that is a measurement rather than an
    // assumption: stubbing `offer_commit_cert` to return nothing leaves this test green, so `adopt_certified_parent`
    // reads the evidence out of the two ahead validators' later proposals. Deliberately NOT also closing that door with
    // `deaf_propose` — the draft that did fails, and not because the certificate is missing: the short validators reach
    // the height with `sync_asks == 0`, having never asked for catch-up at all. Asserting `cert_taken > 0` here would be
    // asserting a mechanism this scenario does not use, which is exactly the vacuous-test class the falsification pass
    // exists to catch.
    c.set_drop_to(None);
    for _ in 0..12 {
        c.tick();
        c.timeout();
    }

    let head = c.engines[0].chain().next_height();
    let root = c.engines[0].chain().state_root();
    for i in 0..N {
        let p = c.engines[i].probe();
        assert_eq!(c.engines[i].chain().next_height(), head, "validator {i} rejoined the cell's height: {p}");
        assert_eq!(c.engines[i].chain().state_root(), root, "validator {i} agrees on the executed state — no fork");
    }

    for h in 0..head {
        assert!(c.hashes_at(h).len() <= 1, "no fork at height {h}");
    }
}

#[test]
fn a_freshly_synced_validator_still_answers_a_laggard_instead_of_going_silent() {
    // The hole this closes is created by the sync path itself, which is what makes it reachable rather than
    // contrived: `on_sync_resp` clears `sync_heads`/`sync_states` and *then* installs the certificate it adopted. So
    // the instant a validator finishes state-syncing it holds a checkpoint above every laggard's height and retains
    // no snapshot for it — and `on_sync_req` used to return an empty vector in exactly that case.
    //
    // Empty is the worst possible answer. The requester cannot distinguish it from a lost packet, so it re-asks on
    // every tick and is met with silence; and the checkpoint's mere existence pre-empted the commit-certificate
    // answer that a validator *without* a checkpoint would have given. A node that just caught up became a silent
    // hole for the peers it was best placed to help.
    const LAG: usize = 6;
    let mut c = Cluster::new(&genesis());
    c.crashed[LAG] = true;
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 250, nonce: 0 }, b"resync-hole");
    c.submit_all(&tx);
    for _ in 0..6 {
        c.tick();
        c.timeout();
    }
    assert!(c.engines[LAG].latest_checkpoint().is_none(), "the crashed validator has no checkpoint of its own");

    // Drive until the laggard has **jumped forward**, and ask it at that first moment — the only instant at which it
    // is both ahead of the requester and guaranteed to retain nothing. Asking later would pass vacuously, because the
    // next executed block refills `sync_heads` and hides the hole.
    //
    // Keyed on the height rather than on `latest_checkpoint()`, which was the first draft of this test and asserted
    // something false: a validator forms a checkpoint from a *quorum of peers' exec votes* at a height it never
    // executed itself, so the laggard holds one while still at genesis — and a validator that far behind genuinely has
    // nothing to offer anyone. Answering nothing is correct there; the defect is answering nothing while ahead.
    c.crashed[LAG] = false;
    let mut asked = false;
    for _ in 0..8 {
        c.tick();
        c.timeout();
        if c.engines[LAG].chain().next_height() > 0 {
            let answer = c.engines[LAG].step(Input::SyncReq { from: 0, have_height: 0, have_root: [0u8; 32] });
            assert!(
                !answer.is_empty(),
                "a validator holding a checkpoint above height 0 answered a catch-up request with nothing: {}",
                c.engines[LAG].probe()
            );
            asked = true;
            break;
        }
    }
    assert!(asked, "the laggard did jump forward, so the case under test actually arose");
}

#[test]
fn a_forged_or_mismatched_catch_up_response_is_refused() {
    // The load-bearing state-sync guards (audit §3.9): a lagging node adopts ONLY a Q-quorum-certified state
    // whose OWN recomputed root matches the certificate. A forged certificate (under-quorum) or a snapshot that
    // does not restore to the certified root is refused — never adopted — so a Byzantine peer cannot inject a
    // fabricated state (which would be an instant, silent fork).
    const LAG: usize = 6;
    let mut c = Cluster::new(&genesis());
    c.crashed[LAG] = true;
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"adv");
    c.submit_all(&tx);
    for _ in 0..6 {
        c.tick();
        c.timeout();
    }
    let cert = c.engines[0].latest_checkpoint().expect("the cell certified a state").clone();
    assert!(cert.height >= 1, "a checkpoint formed past genesis");
    // The tip is INSIDE the certificate now (T-H6) and it is the cell's real one — it used to be a sibling field on the
    // message, which is what let a Byzantine peer pair a genuine certificate with a tip nobody holds. Checked only when
    // the checkpoint is at the chain's own last finalized height, which is the case this scenario produces; asserting it
    // unconditionally would be asserting something the chain does not retain.
    if cert.height + 1 == c.engines[0].chain().next_height() {
        assert_eq!(
            cert.head,
            c.engines[0].chain().head(),
            "the certificate attests the block actually finalized at its height"
        );
    }
    // The certified state, reconstructed deterministically: genesis with the one transfer applied.
    let mut expected = genesis();
    expected.apply(&Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }.into_tx());
    let good = expected.snapshot();
    assert_eq!(expected.state_root(), cert.state_root, "the reconstructed state matches the certified root");

    // (1) A FORGED certificate (votes truncated below the quorum) is refused — no adoption.
    let mut weak = cert.clone();
    weak.votes.truncate(1);
    assert_eq!(c.engines[LAG].step(Input::SyncResp { cert: weak, above: Vec::new(), snapshot: good.clone() }), Vec::new());
    assert_eq!(c.engines[LAG].chain().next_height(), 0, "an under-quorum certificate is not adopted");

    // (2) A MISMATCHED snapshot (the empty state, whose root ≠ the certified root) is refused.
    let wrong = Accounts::new().snapshot();
    assert_eq!(c.engines[LAG].step(Input::SyncResp { cert: cert.clone(), above: Vec::new(), snapshot: wrong }), Vec::new());
    assert_eq!(c.engines[LAG].chain().next_height(), 0, "a snapshot that does not match the certified root is refused");

    // **Both refusals are recorded, and recorded APART.** They are the same non-event to a lagging operator —
    // the node simply never catches up — but they mean opposite things: an under-quorum certificate is a peer
    // attacking, a mismatched snapshot is a peer that is broken or on another fork. T-H6 is the reason the
    // distinction is worth a counter each: safety held there, and what was missing was any way to see it.
    let vr = c.engines[LAG].probe().vote_rejects;
    assert_eq!(vr.sync_head_disagreement, 1, "the under-quorum certificate is counted as a certificate fault");
    assert_eq!(vr.sync_uncertified, 1, "the mismatched snapshot is counted separately, not folded into it");

    // (3) The GENUINE response IS adopted — the positive control: verified certificate + matching snapshot.
    let outs = c.engines[LAG].step(Input::SyncResp { cert: cert.clone(), above: Vec::new(), snapshot: good });
    assert!(matches!(outs.as_slice(), [Output::Committed { .. }]), "a valid response adopts (emits Committed)");
    assert_eq!(c.engines[LAG].chain().next_height(), cert.height + 1, "the laggard adopts the certified height");
    assert_eq!(c.engines[LAG].chain().state_root(), cert.state_root, "and reaches the certified state root");
    // (4) A stale re-offer of the SAME certificate is now a no-op (monotone — never rolls back).
    assert_eq!(c.engines[LAG].step(Input::SyncResp { cert, above: Vec::new(), snapshot: expected.snapshot() }), Vec::new());
}

#[test]
fn many_blocks_finalize_and_a_dependent_transfer_chain_executes() {
    let mut c = Cluster::new(&genesis());
    // Three dependent transfers across three heights: ALICE→BOB 300, BOB→CAROL 120, CAROL→ALICE 20.
    let txs = [
        c.seal(Transfer { from: ALICE, to: BOB, amount: 300, nonce: 0 }, b"h0"),
        c.seal(Transfer { from: BOB, to: CAROL, amount: 120, nonce: 0 }, b"h1"),
        c.seal(Transfer { from: CAROL, to: ALICE, amount: 20, nonce: 0 }, b"h2"),
    ];
    for (h, tx) in txs.iter().enumerate() {
        c.submit_all(tx);
        c.tick();
        assert_eq!(c.honest_count_at(h as u64), N, "height {h} finalizes everywhere");
        assert_eq!(c.hashes_at(h as u64).len(), 1, "agreement at height {h}");
    }
    // The height assertion is read BEFORE settling, so it still measures what it measured: three
    // transaction blocks. Settling adds heights by design (#137), and folding that into the expected number
    // would quietly turn a statement about the workload into a statement about the harness.
    for e in &c.engines {
        assert_eq!(e.chain().next_height(), 3, "three blocks finalized");
    }
    // Final balances: ALICE 1000-300+20=720, BOB 300-120=180, CAROL 120-20=100.
    c.settle(); // execution lags finality by one block — the openings are COMMITTED (#137).
    for e in &c.engines {
        assert_eq!(e.chain().state().balance(&ALICE), 720);
        assert_eq!(e.chain().state().balance(&BOB), 180);
        assert_eq!(e.chain().state().balance(&CAROL), 100);
    }
}

#[test]
fn liveness_holds_with_f_equals_2_crashed_validators() {
    // The tight Fano cell tolerates f = 2 crashes (quorum 5 = exactly the honest count). Crash 2 validators;
    // heights must still finalize — advancing the round when a crashed validator is the elected leader.
    let mut c = Cluster::new(&genesis());
    c.crashed[5] = true;
    c.crashed[6] = true;

    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 42, nonce: 0 }, b"crash");
    c.submit_all(&tx);

    // Drive up to a few rounds: a crashed leader produces no proposal, so timeout advances the round until a
    // live leader is elected and the 5 honest validators finalize.
    c.tick();
    let mut rounds = 0;
    while c.honest_count_at(0) < 5 && rounds < 10 {
        c.timeout();
        rounds += 1;
    }
    assert_eq!(c.honest_count_at(0), 5, "all 5 honest validators finalize despite f=2 crashes");
    assert_eq!(c.hashes_at(0).len(), 1, "the 5 honest validators agree on one block");
    c.settle(); // execution lags finality by one block — the openings are COMMITTED (#137).
    for i in 0..5 {
        assert_eq!(c.engines[i].chain().state().balance(&BOB), 42);
    }
}

#[test]
fn a_withheld_block_never_finalizes_and_the_round_advances() {
    // The round-0 leader withholds its block's payload (DA-unavailable). Honest validators must withhold
    // PREPARE, so it cannot finalize; a round change elects a new, honest leader who does finalize.
    let mut c = Cluster::new(&genesis());
    let bad_leader = leader(&SEED, 0, 0) as u8;
    c.withholding.insert(bad_leader);

    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 7, nonce: 0 }, b"da");
    c.submit_all(&tx);
    c.tick(); // the withholding leader proposes an unavailable block — no finality.
    assert_eq!(c.honest_count_at(0), 0, "a data-withheld block does not finalize");

    // Advance rounds until an honest (non-withholding) leader is elected and finalizes.
    let mut rounds = 0;
    while c.honest_count_at(0) < N && rounds < 10 {
        c.timeout();
        rounds += 1;
    }
    assert_eq!(c.honest_count_at(0), N, "an honest leader finalizes after the round change");
    assert_eq!(c.hashes_at(0).len(), 1, "agreement on the honestly-proposed block");
    // The finalized block was NOT proposed by the withholding validator.
    let final_hash = *c.hashes_at(0).iter().next().unwrap();
    let header = c.engines[0].chain().headers().iter().find(|h| h.hash() == final_hash).unwrap();
    assert_ne!(header.proposer, bad_leader, "the withheld proposal was not the one finalized");
}

#[test]
fn forged_votes_cannot_forge_a_certificate() {
    // Byzantine safety: flood the bus with commit votes for a bogus block, each carrying a garbage
    // signature. Every honest engine rejects them (signature check), so nothing spurious finalizes.
    use fanos_taxis::{Phase, SignedVote, Vote};

    let mut c = Cluster::new(&genesis());
    let bogus = [0x99u8; 32];
    // Hand-craft 5 "votes" (a full quorum) with invalid signatures by corrupting a real one.
    for voter in 0..5u8 {
        let vote = Vote { height: 0, round: 0, block_hash: bogus, phase: Phase::Commit, voter };
        let mut sv_bytes = {
            // Sign with the WRONG validator's key, then claim a different voter — a forged attribution.
            let mut rng = SeedRng::from_seed(&[0xEE, voter]);
            let (wrong_key, _) = HybridSigSecret::generate(&mut rng);
            SignedVote::sign(Vote { voter, ..vote }, &wrong_key).to_bytes()
        };
        // Also flip a signature byte for good measure.
        let last = sv_bytes.len() - 1;
        sv_bytes[last] ^= 0xFF;
        let forged = SignedVote::from_bytes(&sv_bytes).unwrap();
        c.bus.push_back((usize::MAX, ConsensusMsg::Vote(forged)));
    }
    c.run();
    assert_eq!(c.honest_count_at(0), 0, "forged-signature votes cannot finalize anything");
    assert!(c.hashes_at(0).is_empty(), "no block was committed from forged votes");

    // **Refusing them is half the job; being able to say so is the other half.** A peer forging votes and a
    // peer sending nothing produce identical silence at every other observable an operator has — and an
    // isolated validator inside the tolerated fault budget is exactly what T-H6 was. Safety held there too;
    // what was missing was any way to know it was happening.
    let forged: u64 = c.engines.iter().map(|e| e.probe().vote_rejects.forged).sum();
    assert!(
        forged > 0,
        "the cell refused the forgeries but recorded none — a validator under attack is then \
         indistinguishable from one nobody is talking to"
    );
}

#[test]
fn equivocating_proposals_cannot_split_agreement() {
    // A Byzantine leader broadcasts TWO different valid-looking blocks for the same height. Honest validators
    // prepare only the first they process (one prepare per round), so at most one can gather a quorum — the
    // cluster still agrees on a single block (or none), never two conflicting finalizations.
    let mut c = Cluster::new(&genesis());
    let ldr = leader(&SEED, 0, 0) as u8;

    // Two conflicting blocks from the same (correct) leader: different payloads → different hashes.
    let tx_a = c.seal(Transfer { from: ALICE, to: BOB, amount: 1, nonce: 0 }, b"A");
    let tx_b = c.seal(Transfer { from: ALICE, to: CAROL, amount: 2, nonce: 0 }, b"B");
    let block_a = Block::assemble(fanos_taxis::GENESIS_PARENT, 0, EPOCH, ldr, vec![tx_a]);
    let block_b = Block::assemble(fanos_taxis::GENESIS_PARENT, 0, EPOCH, ldr, vec![tx_b]);
    assert_ne!(block_a.hash(), block_b.hash(), "the two proposals genuinely conflict");

    // Inject both proposals; deliver A first, then B.
    c.bus.push_back((usize::MAX, ConsensusMsg::Propose(block_a)));
    c.bus.push_back((usize::MAX, ConsensusMsg::Propose(block_b)));
    c.run();

    // Safety: at most ONE block is finalized at height 0 across all honest validators (agreement), never two.
    assert!(c.hashes_at(0).len() <= 1, "no two conflicting blocks finalize (Byzantine agreement)");
    // And whatever finalized (here A, delivered first) is consistent across everyone who finalized.
    if c.honest_count_at(0) > 0 {
        assert_eq!(c.hashes_at(0).len(), 1, "all validators that finalize agree on the same block");
        // The dropped transaction (from B) did not execute: CAROL never received 2.
        for e in &c.engines {
            assert_eq!(e.chain().state().balance(&CAROL), 0, "the equivocal alternative did not execute");
        }
    }
}

// ---- randomized adversarial Monte-Carlo: BFT safety under random scheduling + Byzantine faults ----

/// A tiny deterministic PRG (splitmix64) — reproducible adversarial schedules, no external rand.
fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A hard **network partition** — the split-brain condition the audit's S-P0.4 targets (§6.5, T-H1/T-H2). On
/// a 7-node cell the commit quorum is `2f + 1 = 5`, so neither side of a `4 | 3` split can finalize alone: no
/// conflicting block can be committed, so no fork is even possible while the network is cut — and once the
/// partition heals the reunited cell reaches quorum and finalizes. BFT safety holds across the whole run, and
/// liveness returns on heal.
#[test]
fn a_network_partition_cannot_split_agreement_and_heals() {
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 10, nonce: 0 }, b"p0");
    c.submit_all(&tx);

    // Cut the cell 4 | 3 and drive many rounds. Each minority proposes and votes within itself but can never
    // gather the 5-vote quorum, so nothing finalizes — the two sides cannot commit conflicting blocks.
    c.split(&[4, 5, 6]);
    for _ in 0..8 {
        c.tick();
        c.timeout();
    }
    assert_eq!(c.honest_count_at(0), 0, "no validator can finalize while cut into sub-quorum groups");

    // Heal: the reunited 7 nodes reach quorum and finalize.
    c.heal_partition();
    for _ in 0..8 {
        c.tick();
        c.timeout();
    }

    // SAFETY across the WHOLE run: no two validators ever finalized different blocks at any height — a partition
    // could not, and did not, split agreement.
    let max_h = (0..N).flat_map(|i| c.committed[i].iter().map(|&(h, _)| h)).max().unwrap_or(0);
    for h in 0..=max_h {
        assert!(c.hashes_at(h).len() <= 1, "FORK at height {h}: the cell finalized {} distinct blocks", c.hashes_at(h).len());
    }
    // LIVENESS restored: the healed cell finalized height 0 across a supermajority.
    assert!(c.honest_count_at(0) >= 5, "the healed cell finalizes across a quorum, got {}", c.honest_count_at(0));
}

/// Over many random seeds: a random Byzantine subset (`≤ f = 2`) equivocates (injects conflicting prepare
/// votes signed by its real key), and the network delivers every message in a **random order** (an adversarial
/// asynchronous scheduler). BFT **safety** — no two honest validators ever finalize different blocks at the
/// same height — must hold on *every* schedule (safety needs no synchrony). Liveness is checked softly in
/// aggregate: under adversarial async scheduling FLP forbids guaranteed progress, but partial synchrony should
/// let most trials advance.
/// The shared Monte-Carlo body (audit §3.8): run `trials` randomized-async + Byzantine-equivocation trials and
/// assert BFT **safety** (no honest fork) on *every* one — safety needs no synchrony, so it must hold on every
/// schedule. `require_liveness` additionally asserts the soft aggregate-progress bound (meaningful only over
/// many trials; off for the small default-suite smoke, on for the exhaustive release run).
#[allow(clippy::too_many_lines)] // a self-contained adversarial Monte-Carlo harness; splitting it hurts clarity
fn run_no_fork_trials(trials: u64, require_liveness: bool, ssle: bool) {
    use std::collections::BTreeMap;

    use fanos_taxis::{Phase, SignedVote, Vote};
    let mut progress_trials = 0u64;
    for trial in 0..trials {
        let mut rng = 0xD1CE_B00F_u64 ^ trial.wrapping_mul(0x9E37_79B9_7F4A_7C15);

        // A random Byzantine subset of size 0..=2 (f = 2).
        let byz_count = (splitmix(&mut rng) % 3) as usize;
        let mut byz: BTreeSet<u8> = BTreeSet::new();
        while byz.len() < byz_count {
            byz.insert((splitmix(&mut rng) % 7) as u8);
        }

        // Build the validators, RETAINING the Byzantine signing keys so they can be made to equivocate under
        // their own (verifier-matching) identity. Byzantine engines get an unused dummy secret and are never
        // stepped honestly.
        let keys = gen_keys();
        let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
        // The agreed decryption-key commitment binds each validator's genuine KEM key under its genuine signing
        // key — a Byzantine validator misbehaves in consensus, not in key registration.
        let keyper_commit = KeyperRegistry::new(
            keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
        )
        .commit();
        let mut engines = Vec::new();
        let mut byz_sig: BTreeMap<u8, HybridSigSecret> = BTreeMap::new();
        for (i, k) in keys.into_iter().enumerate() {
            let idx = i as u8;
            if byz.contains(&idx) {
                byz_sig.insert(idx, k.sig);
                let mut r = SeedRng::from_seed(&[0xDD, idx]);
                let (dummy, _) = HybridSigSecret::generate(&mut r);
                engines.push(ConsensusEngine::new(CellParams::FANO, idx, dummy, k.kem, verifiers.clone(), keyper_commit, SEED, EPOCH, genesis()));
            } else {
                engines.push(ConsensusEngine::new(CellParams::FANO, idx, k.sig, k.kem, verifiers.clone(), keyper_commit, SEED, EPOCH, genesis()));
            }
        }
        let honest: Vec<usize> = (0..N).filter(|i| !byz.contains(&(*i as u8))).collect();

        // With SSLE enabled, register a Merkle-VRF root per validator and turn on round-0 sortition, so honest
        // proposers all-propose witnessed blocks. Random async delivery then stresses the min-ticket collection
        // window (early-exit vs Δ_prio expiry interleaved arbitrarily) — safety must hold on every schedule.
        if ssle {
            let roots: Vec<[u8; 32]> =
                (0..N).map(|i| MerkleVrfSecret::generate(&vrf_seed(i), VRF_HEIGHT).unwrap().root()).collect();
            for (i, e) in engines.iter_mut().enumerate() {
                e.enable_sortition(MerkleVrfSecret::generate(&vrf_seed(i), VRF_HEIGHT).unwrap(), roots.clone(), 0);
            }
        }

        let mut bus: VecDeque<ConsensusMsg> = VecDeque::new();
        let mut committed: Vec<Vec<(u64, [u8; 32])>> = vec![Vec::new(); N];

        for step in 0..18u64 {
            // Honest validators tick (leader proposes); a periodic timeout advances a round stuck behind a
            // Byzantine or badly-scheduled leader.
            for &i in &honest {
                let input = if step % 3 == 2 { Input::Timeout } else { Input::Tick };
                for o in engines[i].step(input) {
                    match o {
                        Output::Send(m) => bus.push_back(m),
                        Output::Committed { height, block_hash } => committed[i].push((height, block_hash)),
                        Output::Slash(_) | Output::SendTo { .. } => {} // equivocation is expected; safety is what this checks
                    }
                }
            }
            // Byzantine equivocation: at each height the honest set is currently deciding, every Byzantine node
            // signs prepare votes for TWO conflicting bogus blocks.
            let heights: BTreeSet<u64> = honest.iter().map(|&i| engines[i].height()).collect();
            for &h in &heights {
                for (&b, sk) in &byz_sig {
                    for tag in [0xAAu8, 0xBB] {
                        let vote = Vote { height: h, round: 0, block_hash: [tag; 32], phase: Phase::Prepare, voter: b };
                        bus.push_back(ConsensusMsg::Vote(SignedVote::sign(vote, sk)));
                    }
                }
            }
            // Deliver the bus in RANDOM order (the adversarial async scheduler), to honest validators only.
            let mut guard = 0;
            while !bus.is_empty() {
                let idx = (splitmix(&mut rng) as usize) % bus.len();
                let Some(msg) = bus.remove(idx) else { break };
                for &i in &honest {
                    let input = match &msg {
                        ConsensusMsg::Propose(b) => Input::Propose { block: b.clone(), shards: Box::new(b.da_shards().map(Some)) },
                        ConsensusMsg::Vote(sv) => Input::Vote(sv.clone()),
                        ConsensusMsg::Reveal(r) => Input::Reveal(r.clone()),
                        ConsensusMsg::ExecVote(v) => Input::ExecVote(v.clone()),
                        // This trial exercises core-message safety; a lagging replica's catch-up is out of scope,
                        // and skipping it cannot cause a fork (an un-synced node simply does not advance).
                        ConsensusMsg::SyncReq { .. }
                        | ConsensusMsg::SyncResp { .. }
                        | ConsensusMsg::CommitCert(_)
                        | ConsensusMsg::NeedBody { .. }
                        | ConsensusMsg::Body(_) => continue,
                    };
                    for o in engines[i].step(input) {
                        match o {
                            Output::Send(m) => bus.push_back(m),
                            Output::Committed { height, block_hash } => committed[i].push((height, block_hash)),
                            Output::Slash(_) | Output::SendTo { .. } => {} // safety is what this trial checks
                        }
                    }
                }
                guard += 1;
                assert!(guard < 1_000_000, "trial {trial}: the bus did not quiesce");
            }
        }

        // SAFETY (must hold on every schedule): honest validators never finalize two different blocks at one height.
        let max_h = committed.iter().flatten().map(|&(h, _)| h).max().unwrap_or(0);
        for h in 0..=max_h {
            let hashes: BTreeSet<[u8; 32]> = honest
                .iter()
                .flat_map(|&i| committed[i].iter().filter(move |&&(hh, _)| hh == h).map(|&(_, hash)| hash))
                .collect();
            assert!(
                hashes.len() <= 1,
                "trial {trial} (byz {byz:?}): FORK at height {h} — honest validators finalized {} distinct blocks",
                hashes.len()
            );
        }
        if honest.iter().any(|&i| !committed[i].is_empty()) {
            progress_trials += 1;
        }
    }
    // Aggregate liveness (soft — FLP forbids a strict async guarantee): most trials make progress. Only
    // meaningful over many trials, so the small default-suite smoke skips it and gates safety alone.
    if require_liveness {
        assert!(
            progress_trials * 2 > trials,
            "only {progress_trials}/{trials} trials progressed — liveness suspiciously low"
        );
    }
}

/// Default-suite gate (audit §3.8): a SMALL randomized-async + Byzantine no-fork Monte-Carlo, so the BFT
/// safety property is checked on every `cargo test` (it was previously only reachable via `--ignored`). Safety
/// only — the soft liveness aggregate needs the exhaustive run below.
#[test]
fn randomized_scheduling_never_forks_smoke() {
    // One deterministic-seed trial: a fast regression gate on a real Byzantine+async schedule (the exhaustive
    // random coverage is the release heavy-lane run below). Kept to a single trial so the default DEBUG suite
    // pays only one trial's worth of hybrid-PQ signing.
    run_no_fork_trials(1, false, false);
}

/// The same no-fork safety gate with **secret-leader sortition enabled**: honest validators all-propose
/// witnessed round-0 blocks and rank by min-ticket, under the adversarial async scheduler + Byzantine
/// equivocation. Proves SSLE preserves BFT safety on every schedule (one-prepare-per-round-0 + quorum
/// intersection are what safety rests on, and the min-ticket only changes which block is prepared).
#[test]
fn ssle_randomized_scheduling_never_forks_smoke() {
    run_no_fork_trials(1, false, true);
}

/// The exhaustive randomized-async + Byzantine no-fork Monte-Carlo (audit §3.8). Heavy in a DEBUG build
/// (hundreds of hybrid ML-DSA sign/verify per trial, ~140 s) but ~5 s in release — run it in the release heavy
/// lane: `cargo test -p fanos-taxis --test consensus_sim --release -- --ignored`.
#[test]
#[ignore = "heavy in debug (~140s); run in release: cargo test -p fanos-taxis --test consensus_sim --release -- --ignored"]
fn randomized_scheduling_and_byzantine_faults_never_fork() {
    run_no_fork_trials(24, true, false);
}

/// The exhaustive no-fork Monte-Carlo with **secret-leader sortition enabled** — the strongest SSLE safety
/// fuzz: all-propose min-ticket round 0 under adversarial async delivery + Byzantine equivocation, over many
/// seeds. Safety must hold on every schedule; liveness is checked softly in aggregate.
#[test]
#[ignore = "heavy in debug; run in release: cargo test -p fanos-taxis --test consensus_sim --release -- --ignored"]
fn ssle_randomized_scheduling_and_byzantine_faults_never_fork() {
    run_no_fork_trials(24, true, true);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Adversarial regression tests for the independent-audit fixes (anti-MEV execution layer).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────

/// Audit CRITICAL 1 (Attack A — censorship by reveal-poisoning): an unprivileged attacker broadcasts a garbage
/// share for a transaction's commitment *before* it finalizes, trying to poison reconstruction so the validly
/// ordered transfer is dropped from execution. Authenticated reveals defeat it — the forgery (signed by a
/// non-committee key) is buffered, then rejected on finalize, and the transfer executes on every replica.
#[test]
fn a_forged_reveal_cannot_censor_a_finalized_transaction() {
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"censor");
    let commit = tx.commit();
    let members = line_members(epoch_seal_line(&SEED, EPOCH)).expect("a real line");
    let keys = gen_keys();
    // A validator NOT on the keyper line forges member 0's slot (x = 1) with garbage, signed by its own key.
    let attacker = (0..N as u8).find(|v| !members.contains(&(*v as usize))).unwrap();
    let forged = RevealMsg::signed(commit, members[0] as u8, share_bytes(1, &[0x55; 32]), &keys[attacker as usize].sig);
    c.inject(ConsensusMsg::Reveal(forged)); // no block finalized yet ⇒ buffered as a pending reveal
    c.submit_all(&tx);
    c.tick();
    // Not censored: every replica finalized and executed the transfer, and all agree on the state root.
    assert_eq!(c.hashes_at(0).len(), 1, "agreement at height 0");
    c.settle(); // execution lags finality by one block — the openings are COMMITTED (#137).
    let root = c.engines[0].chain().state_root();
    for e in &c.engines {
        assert_eq!(e.chain().state().balance(&BOB), 100, "a forged reveal must not censor the transfer");
        assert_eq!(e.chain().state_root(), root, "no executed-state fork");
    }
}

/// Audit CRITICAL 1 (fix #3 — t-subset open): a genuine keyper committee member turns Byzantine and reveals a
/// validly-signed but off-polynomial (garbage) share. Because reconstruction now tries t-subsets and accepts
/// the first whose AEAD tag authenticates, the honest 2-of-3 subset still decrypts the transaction — the lone
/// bad share cannot poison it.
#[test]
fn a_byzantine_committee_members_garbage_share_does_not_block_decryption() {
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 77, nonce: 0 }, b"byz-share");
    let commit = tx.commit();
    let members = line_members(epoch_seal_line(&SEED, EPOCH)).expect("a real line");
    let keys = gen_keys();
    // Keyper member 0 signs a GARBAGE share at its own correct x-coordinate (x = 1) — a well-formed forgery
    // that authentication cannot catch, injected before finality so first-writer-wins records it at slot 0.
    let byz = members[0] as u8;
    let forged = RevealMsg::signed(commit, byz, share_bytes(1, &[0xAB; 32]), &keys[byz as usize].sig);
    c.inject(ConsensusMsg::Reveal(forged));
    c.submit_all(&tx);
    c.tick();
    // The honest {member 1, member 2} subset decrypts it on every replica.
    c.settle(); // execution lags finality by one block — the openings are COMMITTED (#137).
    let root = c.engines[0].chain().state_root();
    for e in &c.engines {
        assert_eq!(e.chain().state().balance(&BOB), 77, "the t-subset open must route around the bad share");
        assert_eq!(e.chain().state_root(), root, "no fork");
    }
}

/// Audit CRITICAL 2 (unvalidated seal → permanent halt): a client submits a transaction sealed to the WRONG
/// committee line (not the epoch's beacon keyper line). It is refused admission at both `submit` and
/// `on_propose`, so it can never be ordered into a block to stall execution behind an undecryptable tx.
#[test]
fn a_transaction_sealed_to_the_wrong_keyper_line_is_refused() {
    let mut c = Cluster::new(&genesis());
    // "The wrong committee" used to mean a different Fano line. The committee is the whole cell now (#136),
    // so the way to name a committee this cell will not accept is to seal to a SUBSET of it — here a line's
    // worth of members, which is exactly the committee that was unsound.
    let member_keys: Vec<&HybridKemPublic> = c.kem_dir.iter().take(CellParams::FANO.line_size()).collect();
    let tx = SealedTx::seal(
        &Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }.into_tx(),
        EPOCH,
        &member_keys,
        CellParams::FANO.seal_threshold(),
        b"wrong-committee",
    )
    .unwrap();
    c.submit_all(&tx);
    c.tick();
    // The chain still advances (an empty block), but the malformed transaction never executes — no halt.
    assert_eq!(c.honest_count_at(0), N, "the cluster still finalizes height 0");
    for e in &c.engines {
        assert_eq!(e.chain().state().balance(&BOB), 0, "a wrong-line seal must never execute");
    }
}

/// Audit HIGH 3 (commit-cert-before-body wedge): a lagging validator gathers a full commit certificate for a
/// height whose block body it never received (an async scheduler dropped the proposal to it). It must not wedge
/// — it holds the decision and finalizes the instant the body is delivered.
#[test]
fn a_validator_finalizes_when_the_body_arrives_after_the_commit_certificate() {
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 5, nonce: 0 }, b"late-body");
    // Pick an honest non-leader to be deaf to the height-0 proposal.
    let ldr = leader(&SEED, 0, 0) as usize;
    let deaf = (0..N).find(|&i| i != ldr).unwrap();
    c.deaf_propose.insert(deaf);
    c.submit_all(&tx);
    c.tick();
    // The deaf validator saw every vote (a commit certificate) but no body ⇒ it has NOT finalized height 0.
    assert!(!c.committed[deaf].iter().any(|&(h, _)| h == 0), "deaf validator must be pending, not finalized");
    assert_eq!(c.honest_count_at(0), N - 1, "the other six finalized");
    // Now hand-deliver the withheld body; the deaf validator finalizes from its held certificate.
    let body = c.proposed.iter().find(|b| b.header.height == 0).cloned().expect("a height-0 body was proposed");
    let shards = Box::new(body.da_shards().map(Some));
    let outs = c.engines[deaf].step(Input::Propose { block: body, shards });
    c.collect(deaf, outs);
    c.run();
    assert!(c.committed[deaf].iter().any(|&(h, _)| h == 0), "the body's arrival unblocks finalization");
    assert_eq!(c.hashes_at(0).len(), 1, "it finalized the same block — no fork");
    // The fixture says "deaf to the height-0 proposal" and was implemented as deaf to EVERY proposal, which
    // did not matter while execution read gossip: the reveals still arrived. It matters now — the openings
    // reach this validator inside block 1, so a validator that can never receive a block can never execute
    // (#137). Lifting the deafness at the point the fixture always meant it to end.
    c.deaf_propose.remove(&deaf);
    c.settle(); // execution lags finality by one block — the openings are COMMITTED (#137).
    assert_eq!(c.engines[deaf].chain().state().balance(&BOB), 5, "and it executes the transfer");
}

/// Audit follow-up (executed-state checkpoint): after a block finalizes and executes, every honest validator
/// emits a signed execution attestation, and a Q-quorum of matching attestations forms an ExecCertificate —
/// a portable proof of the cell's canonical executed state that makes any divergence detectable, not silent.
#[test]
fn honest_validators_certify_the_executed_state() {
    let verifiers: Vec<HybridVerifier> = gen_keys().into_iter().map(|k| k.sig_pub).collect();
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"chk");
    c.submit_all(&tx);
    c.tick();
    // Sanity: it executed.
    c.settle(); // execution lags finality by one block — the openings are COMMITTED (#137).
    assert_eq!(c.engines[0].chain().state().balance(&BOB), 100);
    let root = c.engines[0].chain().state_root();
    // Every honest validator holds a checkpoint certifying height 0 at the agreed root.
    let executed = c.engines[0].latest_checkpoint().expect("an execution checkpoint formed").height;
    for e in &c.engines {
        let cp = e.latest_checkpoint().expect("an execution checkpoint formed");
        // The literal `0` this used to assert became wrong when execution gained its one-block lag (#137):
        // the settle height executes too, so the LATEST checkpoint is no longer the first block's. What the
        // test is about survives unchanged — every honest validator certifies the SAME executed height at
        // the SAME root — so it is stated that way instead of against a number the harness now moves.
        assert_eq!(cp.height, executed, "every validator's checkpoint is at the same executed height");
        assert_eq!(cp.state_root, root, "checkpoint certifies the agreed executed state root");
        assert!(cp.verify(CellParams::FANO.quorum(), &verifiers), "it is a valid Q-quorum certificate");
        // A divergent validator (a wrong root at the same height) would be detectable + attributable.
        // At `cp.height`, not the literal 0: a conflicting vote for a DIFFERENT height is not a conflict,
        // so pinning the height here would have quietly turned the assertion below into a tautology.
        let bad = fanos_taxis::ExecVote::sign(cp.height, [0xEE; 32], [0xAA; 32], 6, &gen_keys()[6].sig);
        assert_eq!(cp.conflicting(&bad, &verifiers), Some(6), "a wrong-root execution is flagged, not silent");
    }
}

/// Incentive layer, now operational (audit MEDIUM 5): a validator that equivocates — signs two conflicting
/// votes at one slot — is CAUGHT by the engine, which surfaces a self-contained, re-verifiable slash proof.
/// The slashing the Nash-equilibrium proof assumes (S > 0) is now emitted, not merely provable in theory.
#[test]
fn an_equivocating_validator_is_caught_and_slashed() {
    use fanos_taxis::{Phase, SignedVote, Vote};
    let keys = gen_keys();
    let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
    let mut c = Cluster::new(&genesis());
    let byz = 3u8;
    // Validator 3 signs two conflicting prepare votes at (height 0, round 0).
    let v_a = Vote { height: 0, round: 0, block_hash: [0xAA; 32], phase: Phase::Prepare, voter: byz };
    let v_b = Vote { height: 0, round: 0, block_hash: [0xBB; 32], phase: Phase::Prepare, voter: byz };
    c.inject(ConsensusMsg::Vote(SignedVote::sign(v_a, &keys[byz as usize].sig)));
    c.inject(ConsensusMsg::Vote(SignedVote::sign(v_b, &keys[byz as usize].sig)));

    // The equivocation was caught and attributed to validator 3, and no honest validator was framed.
    let ev = c.slashes.iter().find(|e| e.validator == byz).expect("the equivocator is caught");
    assert_eq!(ev.height, 0);
    assert!(!c.slashes.iter().any(|e| e.validator != byz), "no honest validator is ever framed");
    // The proof is self-contained: anyone re-verifies it from its two votes under the validator's key.
    assert!(
        fanos_taxis::detect_equivocation(&ev.vote_a, &ev.vote_b, &verifiers[byz as usize]).is_some(),
        "the slash evidence re-verifies independently"
    );
}

/// Audit residual closed (deterministic execution): a transaction sealed to the right keyper line + size (so it
/// passes admission) but to KEM keys nobody on the committee holds is genuinely undecryptable — no honest keyper
/// member can ever produce a share. It pends, then, once consensus finalizes REVEAL_WINDOW further heights, it is
/// dropped UNIFORMLY on every validator (the drop is keyed to the finalized height, not local gossip), so
/// execution converges: all replicas agree on the state root, and the block advances.
#[test]
fn an_undecryptable_transaction_is_deterministically_dropped_after_the_reveal_window() {
    use fanos_taxis::consensus::REVEAL_WINDOW;
    let mut c = Cluster::new(&genesis());
    // Seal to 3 GARBAGE committee keys (random keypairs, not the real committee) — passes valid_seal, but no
    // honest keyper member's secret opens any slot.
    // A full committee's worth of keys that belong to nobody: the seal is well-FORMED (it names the right
    // number of members, so admission accepts it) and undecryptable (no honest node holds a slot). Sized to
    // the cell rather than to a line since #136 — at a line's size admission would refuse it and the test
    // would prove something else.
    let garbage: Vec<(HybridKemSecret, HybridKemPublic)> = (0..CellParams::FANO.seal_committee_size() as u8)
        .map(|i| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xDE, i])))
        .collect();
    let member_keys: Vec<&HybridKemPublic> = garbage.iter().map(|(_, p)| p).collect();
    let bad = SealedTx::seal(
        &Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }.into_tx(),
        EPOCH,
        &member_keys,
        CellParams::FANO.seal_threshold(),
        b"undecryptable",
    )
    .unwrap();
    c.submit_all(&bad);
    c.tick(); // height 0 finalizes with the undecryptable tx; its execution pends
    assert_eq!(c.engines[0].chain().state().balance(&BOB), 0, "pending, not yet executed");
    // Advance the chain past block 0's reveal window with empty blocks.
    for _ in 0..=REVEAL_WINDOW {
        c.tick();
    }
    // The undecryptable tx was dropped uniformly; every replica agrees on the executed state.
    let root = c.engines[0].chain().state_root();
    for e in &c.engines {
        assert_eq!(e.chain().state().balance(&BOB), 0, "an undecryptable tx never executes");
        assert_eq!(e.chain().state_root(), root, "the drop is deterministic — all replicas agree");
    }
    assert!(c.engines[0].latest_checkpoint().is_some(), "execution progressed past the dropped block");
}

/// Incentive layer, reward half now operational (audit MEDIUM 5): finalizing a block distributes its reward
/// pool F among the commit-certificate signers (R = F/Q each) — the reward the Nash equilibrium assumes,
/// surfaced as Output::Reward for the driver to credit, symmetric to the equivocation slash.
#[test]
fn a_finalized_blocks_commit_certificate_is_recorded_as_the_next_blocks_last_commit() {
    use fanos_taxis::Phase;
    // The canonical block reward (`incentive`, `StateMachine::apply_block_reward`) credits the finalizers of the
    // PARENT block, read from the block's recorded `last_commit`. This verifies the consensus half: a block above
    // height 1 records a *valid commit Q-certificate for its parent*, so every validator credits the identical,
    // agreed finalizer set — the property that lets the reward be a deterministic in-state transition (rather
    // than a per-node event that could never enter the state root). The balance effect is a state-machine
    // concern — the reference `Accounts` has no treasury; `fanos-dromos` tests the `HybridLedger` crediting.
    let mut c = Cluster::new(&genesis());
    for e in &mut c.engines {
        // The sentence above — "the reference `Accounts` has no treasury" — is a checked fact now (#138):
        // the engine refuses a reward a state machine will not credit, so a cell cannot be configured with
        // an economy it silently drops. This test is about the consensus half and is unaffected by the
        // refusal; what it verifies is that the block records the finalizer set an execution WOULD reward.
        assert!(
            !e.set_reward_per_block(500),
            "`Accounts` does not pay block rewards, so the engine must refuse to hold a non-zero one"
        );
    }
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"reward");
    c.submit_all(&tx);
    for _ in 0..8 {
        c.tick();
    }

    // The reward is now an in-state transition at execution (there is no surfaced reward event) — the consensus
    // half verified here is that a block records the exact finalizer set its execution will reward.
    // The verifier set is deterministic (the same keys the cluster is built from).
    let verifiers: Vec<HybridVerifier> = gen_keys().iter().map(|k| k.sig_pub.clone()).collect();
    // Every block above genesis (height ≥ 1) records a valid commit certificate for its parent.
    let above_genesis: Vec<&Block> = c.proposed.iter().filter(|b| b.header.height >= 1).collect();
    assert!(!above_genesis.is_empty(), "consensus advanced past the genesis block");
    for b in &above_genesis {
        let cert = b.last_commit.as_ref().expect("a block above genesis records its parent's commit certificate");
        assert_eq!(cert.phase, Phase::Commit, "last_commit is a COMMIT certificate");
        assert_eq!(cert.block_hash, b.header.parent, "it certifies exactly the parent block");
        assert_eq!(cert.height, b.header.height - 1, "at the parent's height");
        assert!(cert.verify(CellParams::FANO.quorum(), &verifiers), "a valid Q-quorum of distinct finalizers");
        assert!(cert.votes.len() >= 5, "at least a Q-quorum of finalizers is recorded, got {}", cert.votes.len());
    }
    // The first block (height 0, parent GENESIS_PARENT) has no parent commit to record.
    for b in c.proposed.iter().filter(|b| b.header.height == 0) {
        assert!(b.last_commit.is_none(), "the genesis block (height 0) records no last_commit");
    }
}

/// The on-chain **decryption-key commitment** (anti-MEV `crate::keyper`): every validator agreed at genesis to
/// the same commitment of the self-certified keyper registry, so it accepts *only* that registry as the cell's
/// decryption authority — closing the key-substitution gap a client would otherwise face when it seals a tx.
#[test]
fn the_agreed_keyper_registry_is_the_only_accepted_decryption_authority() {
    let c = Cluster::new(&genesis());
    // Positive: every engine holds the agreed commitment and accepts the genuine, self-certified registry.
    for eng in &c.engines {
        assert_eq!(eng.keyper_commit(), c.registry.commit(), "every validator holds the agreed commitment");
        assert!(eng.accepts_keyper_registry(&c.registry), "the genuine registry is the cell's decryption authority");
    }
    // Negative: a foreign registry (a different cell's independently-generated keys) is refused — its keys do
    // not match the committed authority even though it is internally well-formed and self-consistent.
    let foreign: KeyperRegistry = KeyperRegistry::new(
        (0..N)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[0xF0, i as u8]);
                let (sig, _sig_pub) = HybridSigSecret::generate(&mut rng);
                let (_kem, kem_pub) = HybridKemSecret::generate(&mut rng);
                KeyperKeyCert::register(i as u8, kem_pub, &sig)
            })
            .collect(),
    );
    assert_ne!(foreign.commit(), c.registry.commit(), "an independent cell has a distinct decryption authority");
    for eng in &c.engines {
        assert!(!eng.accepts_keyper_registry(&foreign), "a substituted decryption authority is refused");
    }
}

// Audit B1: only authenticated reveals are buffered, and the buffer is bounded — no attacker-keyed OOM.
#[test]
fn b1_only_authenticated_reveals_are_buffered() {
    let mut keys = gen_keys();
    let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
    let registry = KeyperRegistry::new(
        keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
    );
    let keyper_commit = registry.commit();
    // An engine for validator 1; validator 0's key stays available to sign a genuine reveal.
    let k1 = keys.remove(1);
    let mut engine =
        ConsensusEngine::new(CellParams::FANO, 1, k1.sig, k1.kem, verifiers, keyper_commit, SEED, EPOCH, genesis());

    let commit: [u8; 32] = [0x42; 32]; // a commitment naming no finalized tx → the buffering path

    // A reveal signed by a NON-committee key, claiming to be member 0, is rejected and NOT buffered.
    let (attacker_sig, _) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"b1-attacker"));
    let forged = RevealMsg::signed(commit, 0, share_bytes(1, &[0x55; 32]), &attacker_sig);
    let _ = engine.step(Input::Reveal(forged));
    assert_eq!(engine.pending_reveal_count(), 0, "an unauthenticated reveal is not buffered (B1)");

    // A reveal genuinely signed by committee member 0 is authenticated and buffered.
    let genuine = RevealMsg::signed(commit, 0, share_bytes(1, &[0x66; 32]), &keys[0].sig);
    let _ = engine.step(Input::Reveal(genuine));
    assert_eq!(engine.pending_reveal_count(), 1, "a member-signed reveal is buffered");
}

/// **The buffer's eviction must not be steerable by the flood it defends against.**
///
/// `pending_reveals` was a `BTreeMap<TxCommit, _>` evicted with `.iter().next()` — the lexicographically
/// SMALLEST commit — while the comment beside it said "the oldest commit". Those are different rules, and the
/// difference is exploitable: `commit()` is `hash(sealed ‖ epoch ‖ line)` over a sealed transaction carried in
/// the block, so it is public. A Byzantine keyper reads a victim's commit, mints commits that all sort ABOVE
/// it, and the victim becomes the smallest key and is evicted first. A few thousand hashes to aim a bound.
///
/// Asserted as SURVIVAL of the earliest entry rather than as "some eviction happened", because the second is
/// true under both rules and only the first tells them apart.
#[test]
fn a_flood_cannot_choose_which_buffered_reveal_it_evicts() {
    let mut keys = gen_keys();
    let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
    let registry = KeyperRegistry::new(
        keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
    );
    let keyper_commit = registry.commit();
    let k1 = keys.remove(1);
    let mut engine =
        ConsensusEngine::new(CellParams::FANO, 1, k1.sig, k1.kem, verifiers, keyper_commit, SEED, EPOCH, genesis());

    // An HONEST keyper's early reveal, at the smallest possible commit — which is what the old key-ordered
    // rule evicted first, and what an attacker would therefore arrange.
    let victim: [u8; 32] = [0x00; 32];
    let _ = engine.step(Input::Reveal(RevealMsg::signed(victim, 0, share_bytes(1, &[0x66; 32]), &keys[0].sig)));
    assert_eq!(engine.pending_reveal_count(), 1, "the honest keyper's early reveal is buffered");

    // A BYZANTINE keyper — a different committee member, since only members' reveals are buffered at all —
    // floods past the cap with commits sorting entirely above the victim. Both halves of the attack are here:
    // the volume, and the aim.
    for i in 0..=fanos_taxis::consensus::MAX_PENDING_REVEAL_COMMITS {
        let mut c = [0xFFu8; 32];
        c[..8].copy_from_slice(&(i as u64).to_be_bytes());
        c[0] |= 0x80; // strictly above the all-zero victim
        let _ = engine.step(Input::Reveal(RevealMsg::signed(c, 2, share_bytes(1, &[0x77; 32]), &keys[1].sig)));
    }

    assert!(
        engine.pending_reveal_count() <= fanos_taxis::consensus::MAX_PENDING_REVEAL_COMMITS,
        "the bound still holds — this is not a test that the cap was removed"
    );
    assert!(
        engine.buffers_reveal_for(&victim),
        "an honest keyper's buffered reveal survives another member's flood. Under ONE shared bound it does \
         not: key-ordered eviction takes the smallest commit (which the attacker arranges), and insertion \
         order takes the OLDEST — which is the honest early reveal by construction, since arriving early is \
         why it is buffered. Neither eviction order protects it; only partitioning the bound per member does, \
         because who sent a reveal is the one thing that distinguishes it locally"
    );
}

#[test]
fn a_height_still_finalizes_after_a_prepare_quorum_that_never_committed() {
    // THE LIVENESS DEFECT `dromos_quic` was actually hitting, reproduced deterministically.
    //
    // `check_prepared` locks a validator on a block the moment a PREPARE quorum forms, and `locked_block` is cleared
    // ONLY by `reset_round_state` — that is, only on finalizing a height. `on_timeout` advances the round and leaves the
    // lock in place. So if a PREPARE quorum forms while the COMMIT quorum does not, every validator is locked on a block
    // that will never finalize, and every later round proposes a *different* block which the locked validators refuse.
    // The height is wedged permanently. Measured live as six of seven validators reporting `locked: 3` refusals with a
    // clear DA path and an empty queue.
    //
    // The recovery this asserts is what any locking consensus needs: a validator must be able to release a lock on
    // evidence that the cell has moved on, or a single lost round of COMMIT votes ends the chain.
    let mut c = Cluster::new(&genesis());

    // Round 0 with an EMPTY mempool: proposals and PREPAREs flow, so every validator locks on an empty block — but no
    // COMMIT is delivered. Empty matters. A block header commits to `(parent, height, epoch, proposer, tx_root,
    // da_commit, last_commit_root)` and NOT to the round, so a re-proposal by the same proposer is byte-identical and a
    // locked validator can accept it — which is why leader rotation alone recovers a *static* mempool. Here the mempool
    // changes underneath, so every later proposal differs from the locked block and the lock can never be matched again.
    c.set_drop_phase(Some(Phase::Commit));
    c.tick();
    assert_eq!(c.honest_count_at(0), 0, "no COMMIT quorum, so nothing finalized yet");

    // Now the transaction arrives — exactly the live sequence, where a client submits into a running cell.
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"lock-release");
    c.submit_all(&tx);

    // The network heals and rounds advance. A locking consensus that cannot release must stall here forever.
    c.set_drop_phase(None);
    for _ in 0..8 {
        c.timeout();
        c.tick();
    }

    assert_eq!(c.honest_count_at(0), N, "the cell recovers and every validator finalizes height 0");
    assert_eq!(c.hashes_at(0).len(), 1, "and on one block — releasing a lock must not fork the height");
}

#[test]
fn a_partitioned_minority_rejoins_without_forking_the_contested_height() {
    // A minority is cut off while the majority finalizes a height, then rejoins. It must converge on the same head and the
    // same executed state, and must not fork the height it missed.
    //
    // Written while chasing a live failure where validators sat locked on a proposal that *lost* — and it does NOT
    // reproduce that. It passes with or without either candidate rule for abandoning such a lock, because the minority here
    // rejoins through the existing catch-up path instead. That is worth knowing and worth keeping: it pins partition-heal
    // convergence, which nothing else asserted, and it records that the live residual needs a scenario this is not.
    let mut c = Cluster::new(&genesis());
    let minority = [5usize, 6];

    // Partition the minority off, then let both sides run: the majority finalizes height 0, the minority does not.
    c.split(&minority);
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"losing-lock");
    c.submit_all(&tx);
    for _ in 0..4 {
        c.tick();
        c.timeout();
    }
    let majority_finalized = c.honest_count_at(0);
    assert!(majority_finalized >= 4, "the majority side finalized height 0 (got {majority_finalized})");

    // Heal, and allow only a SHORT window — the point of the scenario. Checkpoint state-sync eventually rescues a lagging
    // validator, but a checkpoint needs an execution-attestation quorum over several heights, and the live failure this
    // models happens in a cell one block old with no checkpoint to offer. So the only evidence available here is the
    // commit certificate a next-height proposal carries, and the recovery must work off that alone.
    c.heal_partition();
    for _ in 0..3 {
        c.tick();
        c.timeout();
    }

    // Convergence, not block-by-block replay, is the property. A validator that rejoins by adopting a certified state
    // legitimately never finalizes the missed height itself — asserting `honest_count_at(0) == N` would demand it replay
    // history it was proven a snapshot of, and that assertion failed here for exactly that reason while every validator
    // had in fact caught up.
    for i in 0..N {
        eprintln!("DIAG me={i} h={} await={:?} rej={:?}", c.engines[i].chain().next_height(), c.engines[i].awaited_body().is_some(), c.engines[i].rejects());
    }
    c.settle(); // execution lags finality by one block — the openings are COMMITTED (#137).
    // Both read AFTER settling: the comparison below is validators against each other, so the reference has
    // to be taken at the same moment as the values it is compared with. Taken before, it is the height the
    // cell had one block ago and every engine legitimately disagrees with it.
    let head = c.engines[0].chain().next_height();
    let root = c.engines[0].chain().state_root();
    assert!(head > 1, "the cell made real progress past the contested height (reached {head})");
    for (i, e) in c.engines.iter().enumerate() {
        assert_eq!(e.chain().next_height(), head, "validator {i} rejoined the chain at the same height");
        assert_eq!(e.chain().state_root(), root, "validator {i} agrees on the executed state root — no fork");
    }
    // And the contested height agreed on one block among those that finalized it directly.
    assert_eq!(c.hashes_at(0).len(), 1, "rejoining must not fork the contested height");
}

#[test]
fn a_validator_short_one_commit_vote_rejoins_the_chain() {
    // THE SCENARIO THE LIVE `dromos_quic` RESIDUAL IS, reproduced deterministically.
    //
    // Quorum is `2f+1 = 5` of 7. A block gets its five COMMIT votes and the cell finalizes it — while ONE validator
    // receives only four of them. That validator is locked on the winning block, holds its body, and is missing nothing
    // but a signature. TAXIS does not retransmit votes and offers no way to ask for them, so it is stuck at that height
    // forever while the cell advances. Measured live as validators reporting `locked` refusals with `await=None`: nothing
    // pending, nothing unavailable, the right block in hand.
    //
    // A global vote outage cannot express this — denying the quorum to everyone finalizes nothing and the cell simply
    // retries. The loss has to be asymmetric, which is why `drop_to` exists.
    //
    // The recovery asserted here needs no new evidence on the wire: every block records the quorum COMMIT certificate that
    // finalized its parent, so the next height's proposal already proves what this height finalized.
    // THREE validators short, not one, and that is the whole difference. With one stuck the cell still has 6 ≥ quorum, so
    // it keeps making blocks and the stuck validator rejoins from what they carry. With three stuck only 4 remain — below
    // the quorum of 5 — so the cell **halts** and can never produce the evidence that would rescue them. That circularity
    // is the live deadlock, and it is why a one-validator version of this test passes while the cell does not.
    let mut c = Cluster::new(&genesis());
    let short = [4usize, 5, 6];
    c.set_drop_to(Some((Phase::Commit, &short)));
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"short-one-vote");
    c.submit_all(&tx);
    c.tick();

    // The cell finalized; the short validators did not — and crucially they are not missing a body or a shard. They hold
    // the winning block, are locked on it, and lack only a signature they can never obtain.
    assert!(c.honest_count_at(0) >= 1, "the cell reached a commit quorum among the validators that did hear it");
    for &i in &short {
        assert_eq!(c.engines[i].chain().next_height(), 0, "validator {i} has not finalized the height");
        assert_eq!(c.engines[i].awaited_body(), None, "validator {i} is not waiting on a body — it holds the block");
    }

    // The loss ends. The cell keeps making blocks, and the stuck validator must rejoin from what those blocks carry.
    c.set_drop_to(None);
    for _ in 0..6 {
        c.tick();
        c.timeout();
    }

    let head = c.engines[0].chain().next_height();
    let root = c.engines[0].chain().state_root();
    assert!(head >= 1, "the cell finalized the contested height");
    for &i in &short {
        assert_eq!(
            c.engines[i].chain().next_height(),
            head,
            "validator {i}, short a COMMIT vote, rejoined at the cell's height"
        );
        assert_eq!(c.engines[i].chain().state_root(), root, "validator {i} agrees on the executed state — no fork");
    }
    assert_eq!(c.hashes_at(0).len(), 1, "one block at the contested height — rejoining must not fork it");
}


#[test]
fn a_round_nobody_could_accept_ends_on_the_votes_rather_than_the_clock() {
    // Tendermint's nil vote, and what observing it is for. A validator that accepted nothing used to be
    // *silent*, so peers could not tell "has not decided" from "accepted nothing", and a failed round could end
    // only when the wall clock said so — on a timeout that doubles toward 24 s. Measured live: rounds reaching
    // 13 inside a 240 s ceiling while every validator already knew each one had failed.
    //
    // The scenario has to be one where validators genuinely accept nothing, which took two attempts to build.
    // Dropping PREPARE *votes* does not do it: each validator still prepared its own proposal, and one that has
    // spoken cannot also say nil without equivocating. So the proposals themselves are withheld — nobody sees
    // anything to accept, which is exactly the case nil exists for.
    let mut c = Cluster::new(&genesis());
    for i in 0..N {
        c.deaf_propose.insert(i);
    }
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 10, nonce: 0 }, b"votes-not-clock");
    c.submit_all(&tx);
    c.tick();
    assert_eq!(c.engines[0].round(), 0, "no proposal arrived, so nothing has moved yet");

    // One expiry apiece. Every validator says `nil`, the quorum of nils forms immediately, and the round ends
    // on those votes — in the same step, because the simulator delivers them all at once.
    c.timeout();
    assert!(c.engines[0].round() > 0, "the round must end once the votes say it failed");

    // **What this can and cannot show.** The latency gain is a production property: there the clock that would
    // otherwise end the round doubles toward 24 s while the votes cross in milliseconds, so ending on votes is
    // the difference between a cell that retries at once and one that spends its budget in backoff. Here the
    // timeout is *injected by hand*, so there is no wall clock to save and no way to exhibit it. What the
    // simulator can show is that nil is **safe**, which is the half that could silently be wrong:
    assert_eq!(c.hashes_at(0).len(), 0, "a quorum of `nil` must decide nothing — it is the absence of a value");
    for i in 0..N {
        assert_eq!(c.engines[i].chain().next_height(), 0, "validator {i} finalized on nil");
        // The one that could silently be wrong. A quorum of nils *is* a quorum, so nothing stops the ordinary
        // prepare path from locking on it — and a validator locked on the absence of a value would then refuse
        // every real proposal at that height, needing an "unlock" from something that never existed. Checked
        // through the probe because height and hashes cannot see it: locking on nil never finalizes either.
        assert!(!c.engines[i].probe().locked, "validator {i} locked on `nil` — on the absence of a decision");
    }
}

#[test]
fn a_minority_locked_on_a_dead_block_is_released_by_the_majority_s_proof() {
    // Tendermint's **unlocking rule**, which was missing entirely, and the situation that needs it — which is
    // *not* the sub-quorum split above. There, three lock and four do not, and neither side reaches the quorum
    // of five, so no certificate for a conflicting value can exist at all and the release has nothing to fire
    // on; `valid_value` is what heals that one.
    //
    // The rule matters when the locked side is **smaller than the quorum's complement**: two validators lock on
    // a block, the remaining five prepare a different one and form a real certificate for it. The cell is fine —
    // five is a quorum — and the two are stranded forever, refusing every proposal at that height on a lock
    // nothing can release. Their peers hold exactly the proof that should free them, and carry it on every
    // proposal, and before this the acceptor side never looked at it.
    //
    // Deliberately asserted on **all seven**, not on the cell: a test that only checks the cell advanced passes
    // while two validators are permanently deaf, which is precisely how this went unnoticed.
    let mut c = Cluster::new(&genesis());
    let stranded = [0usize, 1];
    let free: Vec<usize> = (0..N).filter(|i| !stranded.contains(i)).collect();

    // Round 0: PREPAREs reach only the two, so they see a polka and lock; the five never do.
    c.set_drop_to(Some((Phase::Prepare, &free)));
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"strand-two");
    c.submit_all(&tx);
    c.tick();
    c.set_drop_to(None);

    // The mempool changes, so every later proposal differs from the block the two locked on — without a release
    // they refuse all of them.
    let second = c.seal(Transfer { from: ALICE, to: BOB, amount: 25, nonce: 1 }, b"the-cell-moves-on");
    c.submit_all(&second);
    for _ in 0..10 {
        c.timeout();
        c.tick();
    }

    let head = c.engines[free[0]].chain().next_height();
    assert!(head >= 1, "the five that were never blinded must finalize — they are a quorum");
    let root = c.engines[free[0]].chain().state_root();
    for &i in &stranded {
        assert_eq!(
            c.engines[i].chain().next_height(),
            head,
            "validator {i} is stranded on a lock the cell has demonstrably moved past"
        );
        assert_eq!(c.engines[i].chain().state_root(), root, "validator {i} disagrees on the executed state");
    }
    for h in 0..head {
        assert_eq!(c.hashes_at(h).len(), 1, "releasing a lock must not fork height {h}");
    }
}

#[test]
fn a_validator_left_behind_in_the_round_rejoins_the_round_its_peers_reached() {
    // Round synchronization, which this engine did not have. Rounds advanced by exactly one thing — a validator's own
    // timeout firing — so nothing ever moved a validator toward the round its peers were on. Local timers are
    // independent and the round timeout doubles toward 24 s, so validators drift on ordinary scheduling noise and then
    // have no way back to each other.
    //
    // The damage is not cosmetic, because proposer entitlement is round-dependent and the block header deliberately
    // carries no round (it must not: a header that committed to the round would make a re-proposal differ byte for
    // byte, and a locked validator could never accept one). `on_propose` therefore judges every proposal against the
    // **receiver's** round — so a proposer legitimate at its own round is an impostor one round ahead, and the
    // proposal is counted as an entitlement violation rather than merely ignored. A drifted cell rejects the proposals
    // it makes to itself. Measured live as hundreds of `rejects.proposer` with validators sitting at different rounds
    // in one snapshot.
    let mut c = Cluster::new(&genesis());
    // COMMIT withheld so nothing finalizes: a finalization resets the round to 0 and would erase the drift being
    // built. Six validators then time out repeatedly while the seventh's timer never fires — the drift, isolated.
    c.set_drop_phase(Some(Phase::Commit));
    let straggler = 6usize;
    c.crashed[straggler] = true;
    for _ in 0..5 {
        c.timeout();
    }
    c.crashed[straggler] = false;
    c.set_drop_phase(None);
    let ahead = c.engines[0].round();
    assert!(ahead >= 3, "the cell advanced several rounds without the straggler, reached {ahead}");
    let _ = ahead;
    assert_eq!(c.engines[straggler].round(), 0, "and the straggler is still at round 0 — the drift is real");

    // One round of ordinary traffic **with the straggler listening**. It missed rounds 1..5 entirely (it was down
    // while they were broadcast), so the votes that teach it where the cell is have to be produced now.
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 10, nonce: 0 }, b"round-sync");
    c.submit_all(&tx);
    c.timeout();
    c.tick();

    assert!(
        c.engines[straggler].round() >= ahead || c.engines[straggler].chain().next_height() > 0,
        "the straggler must reach its peers' round (or finalize past the height) — it sat at round {} while the cell \
         was at {ahead}, and every proposal it hears is judged against its own stale round",
        c.engines[straggler].round()
    );

    // **Which branch of that disjunction fired**, which the assertion above cannot say. Either outcome satisfies it, so
    // it would stay green on a cell that finalized past the height without the synchronization rule ever running — and
    // this test exists to check the rule. `round_jumps` counts `maybe_advance_round` actually firing.
    let p = c.engines[straggler].probe();
    assert!(p.round_jumps.0 > 0, "the straggler jumped rather than merely finalizing around the problem: {p}");
    // After a successful jump nothing is left above us — the pair `(jumped, above)` is what makes a live trace readable:
    // `above >= f + 1` with `jumped = 0` would mean the evidence is present and the rule is not acting on it.
    assert_eq!(p.voters_above, 0, "having jumped, no peer remains at a higher round: {p}");
}

#[test]
fn a_block_that_can_never_be_reconstructed_costs_sub_linearly_in_time() {
    // **The storm class, made expressible.** A withheld block is missing a hyperoval's worth of shards — the minimal
    // unrecoverable erasure pattern — so no peer can ever answer for it and its sampling entry never completes. Before
    // `Sampler::due` became a schedule, that entry was re-requested on every sweep for as long as it stayed pending:
    // measured live at one height as `shard=7130/7130 took=5366` per validator, thousands of frames for two blocks
    // nobody could serve.
    //
    // The sim could not have caught it, and that is why `Cluster::da_requests` exists: it modelled message *delivery*
    // and never message *cost*, so a re-fetch here is free and instantaneous while in production it is frames on a wire
    // and a round-timeout ladder. Re-fusing either TAXIS liveness defect leaves every other scenario in this file
    // byte-identical — measured, not assumed.
    //
    // Two conditions had to be right before the counter said anything, and both were found by measuring:
    //   * the height must **stall**, or `prune_below` retires each entry as soon as its height is decided and no block
    //     stays unobtainable long enough for a retry policy to matter (with heights advancing: 10 % apart);
    //   * the cost must be read **per block sampled**, not in total — the cell samples hundreds of skeletons, and the
    //     absolute figure made a 40-sweep run look worse than an unbounded policy purely because it sampled more.
    //
    // What is asserted is the property itself rather than a threshold: run the same scenario for `s` and `2s` sweeps,
    // and the per-block cost must **not** keep pace with time. An unbounded policy asks on every sweep of a block's
    // life, so doubling the run doubles it; doubling backoff asks on `O(log)` of them, so it must fall behind. No
    // constant is chosen anywhere, and the comparison normalises itself.
    const SHORT: usize = 30;
    let cost = |sweeps: usize| -> f64 {
        let mut c = Cluster::new(&genesis());
        c.with_da_delay(4);
        c.withholding.insert(leader(&SEED, 0, 0) as u8);
        // The height must not advance: the live storm was a *stalled* height holding the same entries for 1600 sweeps.
        c.set_drop_phase(Some(Phase::Commit));
        let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"withheld");
        c.submit_all(&tx);
        // No timeouts: rounds do not advance, so no *new* proposal is ever made and the entries opened at round 0 stay
        // pending for the whole run. That is the live condition — two blocks held for 1600 sweeps — and without it the
        // sim's blocks live about seven sweeps, where doubling saves 7 asks against 3 and no policy is distinguishable.
        for _ in 0..sweeps {
            c.tick();
        }
        assert!(c.da_begins > 0, "the scenario must actually sample something at {sweeps} sweeps");
        #[allow(clippy::cast_precision_loss)]
        let per_block = c.da_requests as f64 / c.da_begins as f64;
        per_block
    };

    let short = cost(SHORT);
    let long = cost(SHORT * 2);

    // The threshold is read off the two models rather than fitted between two measurements. Doubling the run multiplies
    // a `log s` cost by `log(2s)/log(s) = 1 + 1/log2(s)` and a linear cost by 2. At `s = 30` that is 1.25 against 2.00,
    // and the assertion sits at twice the logarithmic growth — enough headroom that scheduling noise cannot trip it,
    // and nowhere near the linear figure. Measured, in both directions: 43.4 → 46.9 with the schedule (a ratio of
    // 1.08), and 215.1 → 420.9 with every pending block asked on every sweep (1.96).
    #[allow(clippy::cast_precision_loss)]
    let allowed = 1.0 + 2.0 / (SHORT.ilog2() as f64);
    assert!(
        long < short * allowed,
        "an unobtainable block must cost O(log t) requests, not O(t): {short:.1} per block over {SHORT} sweeps and \
         {long:.1} over {} — a ratio of {:.2} against a derived ceiling of {allowed:.2}, and 2.00 is what asking on \
         every sweep looks like",
        SHORT * 2,
        long / short
    );
}

#[test]
fn a_cell_whose_timers_never_agree_still_finalizes_a_run_of_heights() {
    // **Local timers are independent, and this suite pretended otherwise.** Every other scenario here fires them
    // cell-wide, which holds every validator in one round *by construction* — the one arrangement in which round drift,
    // and everything downstream of it, cannot occur. Two production liveness defects survived 139 green tests for
    // exactly that reason, and both needed a live QUIC trace to find: a validator that ran ahead discarded the bodies
    // of proposals it was right to refuse a vote for, and the DA sampler re-requested them forever.
    //
    // So here no timer agrees with any other: validator `i` fires on the steps where `(step + i) % 3 == 0`, a fixed
    // phase per validator, which keeps the offsets moving instead of settling. Nothing is dropped, crashed or
    // partitioned — an offset is not a fault, and a consensus that needs the cell's clocks to agree has no liveness
    // argument on a real network. Deterministic in `(step, i)`, so a failure reproduces exactly.
    let mut c = Cluster::new(&genesis());
    // Dispersal latency is what makes a round a real interval. Without it one `tick` drains the bus to quiescence and
    // completes a whole height — propose, prepare, commit, finalize — so every validator sits at round 0 forever and no
    // timer pattern can produce drift. Measured while building this test: 30 heights in 30 steps, `widest = 0`,
    // `jumps = 0`. That is the fidelity gap behind both defects, stated as a number.
    c.with_da_delay(4);
    let mut submitted = 0u64;
    let mut widest = 0u32;
    // Sixty steps, not thirty, and the reason is measured rather than fitted. Execution lags finality by a
    // block (#137), so a step yields roughly half the consensus progress it used to and the drift needs
    // longer to build. Instrumented over 90 steps: the first round jump lands at step ~33 (it was inside
    // thirty before), the second at ~50, the fourth by ~81. Sixty is past the second with margin — chosen
    // for the margin, not for being the first value that passes, since a bound fitted to the exact first
    // occurrence would go vacuous again on any scheduling change.
    for step in 0..60usize {
        // One transaction per height keeps the nonces consecutive, so a rejected transfer can never be what a stalled
        // height is blamed on.
        if c.engines[0].chain().next_height() >= submitted {
            let tag = [b's', u8::try_from(submitted).unwrap_or(0)];
            let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 1, nonce: submitted }, &tag);
            c.submit_all(&tx);
            submitted += 1;
        }
        c.tick();
        let firing: Vec<usize> = (0..N).filter(|i| (step + i) % 3 == 0).collect();
        c.timeout_some(&firing);
        let rounds: Vec<u32> = (0..N).map(|i| c.engines[i].round()).collect();
        let spread = rounds.iter().max().copied().unwrap_or(0) - rounds.iter().min().copied().unwrap_or(0);
        widest = widest.max(spread);
    }

    // The test must have exercised what it claims to. A run in which the cell never drifted would satisfy every
    // assertion below while testing nothing, which is how the synchronous clock model hid two defects in the first
    // place — so the drift itself is asserted, not assumed.
    let jumps: u64 = (0..N).map(|i| c.engines[i].probe().round_jumps.0).sum();
    assert!(widest >= 1, "the timers never actually disagreed, so this run exercised no drift at all");
    assert!(jumps > 0, "the cell drifted by {widest} rounds and never once used the rule that closes it");

    let reached = c.engines[0].chain().next_height();
    let probes: Vec<String> = (0..N).map(|i| format!("v{i}:{}", c.engines[i].probe())).collect();
    let report = probes.join(" | ");
    assert!(reached >= 3, "a cell whose clocks never agree must still make progress — reached {reached}. {report}");
    for h in 0..reached {
        assert_eq!(c.hashes_at(h).len(), 1, "drifting timers must not fork height {h}: {report}");
    }
    assert!(
        c.honest_count_at(reached - 1) >= CellParams::FANO.quorum(),
        "and a quorum must be carried along, not left behind: {report}"
    );
}

#[test]
fn a_validator_that_ran_ahead_still_keeps_the_body_it_refuses_to_prepare() {
    // Round synchronization pulls a validator **forward** to the round its peers reached. Nothing pulls one that has
    // run ahead back — and entitlement is judged against the receiver's round, so the validator furthest ahead refuses
    // the most proposals. Until this fix it also discarded their bodies, and the two are not the same decision:
    // refusing to *vote* for an off-round proposal is the safety rule, throwing away a block that passed link,
    // structure, `last_commit`, seal and the cryptographic DA gate is just losing information it will need.
    //
    // Measured on a live cell frozen at height 1 for 240 s: the validator with 71 `rejects.proposer` could answer 3 of
    // 1749 skeleton requests, the one with 6 could answer 2561 of 2561. Nobody was locked, so no value ever held a
    // PREPARE quorum, and each validator was chasing a different body from peers that did not hold it either.
    let mut c = Cluster::new(&genesis());
    let ahead = 3usize;
    assert_ne!(
        leader(&SEED, 0, 0),
        leader(&SEED, 0, 1),
        "the construction needs the two rounds to elect different leaders, or nothing is off-rota to begin with"
    );
    // Two expiries: the first is the nil PREPARE that makes "I accepted nothing" observable, the second leaves the
    // round. One validator's timer runs fast — an offset, not a fault.
    c.timeout_some(&[ahead]);
    c.timeout_some(&[ahead]);
    assert_eq!(c.engines[ahead].round(), 1, "the validator must be exactly one round ahead of its peers");

    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 10, nonce: 0 }, b"ran-ahead");
    c.submit_all(&tx);
    c.tick();

    let ldr = leader(&SEED, 0, 0) as u8;
    let proposed = c
        .proposed
        .iter()
        .find(|b| b.header.proposer == ldr && b.header.height == 0)
        .map(Block::hash)
        .expect("round 0's leader proposed");
    let p = c.engines[ahead].probe();
    assert!(p.rejects.proposer > 0, "the off-rota proposal must still be refused a vote: {p}");
    assert!(
        c.engines[ahead].skeleton_of(&proposed).is_some(),
        "…and its body kept, so this validator can serve it and prepare it the instant the cell agrees: {p}"
    );
}

#[test]
fn a_cell_whose_rounds_split_four_three_still_finalizes() {
    // The live pathology, reduced to its arithmetic. A certificate is collected from the votes of **one** round
    // (`collect_cert` reads `self.round`), so a cell partitioned across two rounds cannot finalize from either side:
    // 4 < 5 and 3 < 5. No amount of waiting helps, because uniform timers advance both groups together and preserve
    // the offset exactly. Measured over real QUIC: `v1 v3 v4 v5` at round 8, `v0 v2 v6` at round 9, every validator
    // locked and holding its body, no proposal rejected for any reason but entitlement, nothing finalizing for 240 s.
    //
    // Nothing here is dropped, crashed, or partitioned: the *only* deviation from a healthy cell is one extra timer
    // firing on three validators. That is deliberate — an offset is not a fault, and a consensus that needs the whole
    // cell's clocks to agree has no liveness argument on a real network.
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 10, nonce: 0 }, b"round-split");
    c.submit_all(&tx);
    // Lock the whole cell on one block without letting it finalize: a PREPARE quorum forms (so every validator locks
    // and holds the body) while the COMMIT quorum never does. This reproduces the observed `lock` on all seven.
    c.set_drop_phase(Some(Phase::Commit));
    c.tick();
    c.set_drop_phase(None);
    for i in 0..N {
        let p = c.engines[i].probe();
        assert!(p.locked && p.holds_locked_body, "validator {i} must be locked on a body it holds: {p}");
    }
    // The offset: three validators' timers fire once more than the other four. Nothing else changes.
    c.timeout_some(&[0, 1, 2]);
    let probes: Vec<String> = (0..N).map(|i| format!("v{i}:{}", c.engines[i].probe())).collect();
    let report = probes.join(" | ");

    // **The offset does not survive the drain**, and that is the result. The three that advanced re-prepare their lock
    // at the new round (`reprepare_lock`), those PREPAREs reach the four that stayed, `f + 1 = 3` peers are visible
    // above, and `maybe_advance_round` closes the gap inside the same delivery — after which one round holds all seven
    // votes and the height finalizes. So a 4/3 round split is *not* a state a healthy cell can be found in.
    //
    // Which makes this test the sharp half of a live diagnosis rather than a regression guard. Over QUIC the split
    // persisted for 240 s with `above = 0` on every validator — no peer visible above anyone's round — while here the
    // same arithmetic heals immediately. The engine is therefore not the defect: the votes that close the gap are not
    // being *delivered*. `votes_seen`'s third bucket is what tells the two apart, and it is asserted below.
    assert!(
        c.engines[3].probe().round_jumps.0 > 0,
        "a validator that stayed must have jumped to its peers' round, not waited for a clock: {report}"
    );
    assert!(
        c.engines[3].probe().votes_seen.2 > 0,
        "and it must have *received* the above-round votes that justify the jump — the live cell's `above = 0` says it \
         did not, which is a transport claim and only this counter can make it: {report}"
    );
    let rounds: BTreeSet<u32> = (0..N).map(|i| c.engines[i].round()).collect();
    assert_eq!(rounds.len(), 1, "the cell must be back in one round: {rounds:?} — {report}");
    assert!(
        c.honest_count_at(0) >= CellParams::FANO.quorum(),
        "a one-round offset must not cost the cell its liveness — {} of {N} finalized. {report}",
        c.honest_count_at(0)
    );
    assert_eq!(c.hashes_at(0).len(), 1, "and the round split must not fork the height: {report}");
}

#[test]
fn a_peer_stuck_between_the_checkpoint_and_the_head_is_offered_the_certificate() {
    // `finalize` retains the certificate it collects so a stuck peer can be handed it (`offer_commit_cert`), replacing
    // a `remove` that had kept the map small on its own. Retention therefore needs a bound, and it is the same window
    // as `recent_bodies` — a certificate is useless to a stuck peer without the body it finalizes.
    //
    // **What this does and does not cover**, because the difference cost three rewrites to find. It covers retention
    // itself: removing it (going back to consuming the certificate in `finalize`) fails this test and the stuck-peer
    // test with it. It does **not** cover the retention *window*, and cannot — in this cell the execution checkpoint
    // tracks the head to within one height, so `prune_sync_retention` runs constantly, `certified` never approaches its
    // bound, and an over-aggressive floor still leaves the single relevant height retained. Every version of this test
    // that claimed otherwise passed its own falsification.
    //
    // That is worth knowing rather than papering over: the unbounded growth the window guards against requires
    // checkpoints to *stall*, which nothing here produces. The bound stays as cheap insurance; its trigger is untested.
    let mut c = Cluster::new(&genesis());
    for _ in 0..12 {
        c.tick();
        c.timeout();
    }
    let head = c.engines[0].chain().next_height();
    assert!(head >= 4, "the cell advanced enough heights to test retention, reached {head}");

    // Counted **by message**, not by "the reply was non-empty". A first version of this test asserted the latter and
    // was worthless: once a checkpoint forms, `SyncReq` is answered by `SyncResp` from the snapshot path, so an
    // over-aggressive certificate floor still left every request answered — the falsification passed. The certificate
    // path has to be named to be tested.
    // The boundary is exact, and stating it is what makes the assertion bite. `on_sync_req` prefers the checkpoint,
    // so a request below the checkpoint height is answered by `SyncResp` from the snapshot path; only at or above it
    // does the retained certificate become the applicable answer. **Every** such height must be served, not merely one.
    let ckpt = c.engines[0].latest_checkpoint().map_or(0, |c| c.height);
    assert!(head > ckpt, "the cell has finalized past its checkpoint, so the certificate path is exercised at all");
    // The requester's root is the CERTIFIED one, not a placeholder, and that distinction is the test's subject.
    // This peer is *stuck*, not diverged — it agrees with the cell's executed state and is missing only a
    // signature — so it reports the root the checkpoint certifies. A fabricated root would make it look diverged
    // at the checkpoint height and pull the snapshot branch, asserting a reply production would never ask for
    // (the inverse of [[test-narrower-than-production]]: an input the live path cannot emit).
    let agreed = c.engines[0].latest_checkpoint().map_or([0u8; 32], |c| c.state_root);
    for h in ckpt..head {
        let replies = c.engines[0].step(Input::SyncReq { from: 1, have_height: h, have_root: agreed });
        assert!(
            replies.iter().any(|o| {
                matches!(o, Output::SendTo { msg: ConsensusMsg::CommitCert(cert), .. } if cert.height == h)
            }),
            "height {h} is at or above the checkpoint {ckpt} and below the head {head}, so a peer stuck there can only \
             be freed by the retained COMMIT certificate — and it was not offered"
        );
    }
    // And nothing is invented for a height the cell has not reached.
    assert!(
        c.engines[0].step(Input::SyncReq { from: 1, have_height: head, have_root: agreed }).is_empty(),
        "a request at our own height, agreeing on state, has nothing newer to offer"
    );
}

#[test]
fn a_stuck_validator_that_never_sees_a_newer_block_still_rejoins_from_the_commit_certificate() {
    // The case both existing repair paths structurally cannot reach, and the reason `ConsensusMsg::CommitCert`
    // exists. A validator finalizes only by gathering `2f+1` COMMIT votes itself, and TAXIS never retransmits a
    // vote — so a validator short of that quorum is missing signatures it can never obtain again. Two paths are
    // meant to rescue it:
    //
    //   * `adopt_certified_parent` reads the certificate out of a **newer block**, which requires that block to
    //     reach the stuck validator;
    //   * `SyncResp` serves an execution **checkpoint**, which a cell in its first heights has not formed.
    //
    // Deny the first and the second is already absent: the short validators are also deaf to proposals from the
    // moment they fall behind, so no later block ever reaches them. That is not a contrived condition — a
    // validator whose proposal deliveries fail while votes still arrive is exactly a partial-connectivity fault,
    // and it is the arrangement in which the cell holds the evidence and the laggard cannot be handed it.
    //
    // What rescues them is the certificate itself, sent on request: a quorum of signatures over
    // `(height, block_hash)`, self-authenticating against the fixed committee, granting the requester nothing it
    // could not have gathered from the votes it missed.
    let mut c = Cluster::new(&genesis());
    let short = [4usize, 5, 6];
    c.set_drop_to(Some((Phase::Commit, &short)));
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"cert-only-rescue");
    c.submit_all(&tx);
    c.tick();

    // Stuck exactly as documented: holding the winning block, locked on it, short only a signature.
    for &i in &short {
        assert_eq!(c.engines[i].chain().next_height(), 0, "validator {i} has not finalized the height");
        assert_eq!(c.engines[i].awaited_body(), None, "validator {i} holds the block — it is short a vote, not a body");
    }

    // Now close the only door they could otherwise be rescued through, and confirm the other is already shut.
    c.set_drop_to(None);
    for &i in &short {
        c.deaf_propose.insert(i);
        assert!(c.engines[i].latest_checkpoint().is_none(), "validator {i} has no checkpoint to sync from");
    }
    for _ in 0..8 {
        c.tick();
        c.timeout();
    }

    // They rejoined — and the certificate is what carried them, now asserted directly rather than argued by
    // exclusion. `cert_taken` counts only adoptions that actually moved the height, so it cannot be satisfied by a
    // certificate that was received and refused; the old "no newer block ever arrived" reasoning was sound but it
    // could not distinguish *which* mechanism fired, and a live trace has since shown certificates being answered
    // ~4250 times while advancing nobody.
    let head = c.engines[0].chain().next_height();
    let root = c.engines[0].chain().state_root();
    assert!(head >= 1, "the cell finalized the contested height");
    for &i in &short {
        let p = c.engines[i].probe();
        assert_eq!(c.engines[i].chain().next_height(), head, "validator {i} rejoined at the cell's height");
        assert_eq!(c.engines[i].chain().state_root(), root, "validator {i} agrees on the executed state — no fork");
        assert!(p.cert_taken > 0, "validator {i} was carried by a COMMIT certificate, not by something else: {p}");
    }
    assert_eq!(c.hashes_at(0).len(), 1, "one block at the contested height — rejoining must not fork it");
}

#[test]
fn a_validator_that_misses_one_height_rejoins_with_no_further_transactions() {
    // The small-gap case, and the quiescent one — neither covered by the state-sync test above, which crashes a
    // validator at genesis for six heights and lets it adopt a checkpoint. Two things differ here and both matter.
    //
    // The gap is **one height**, so the two repair paths the driver documents may both decline it: `awaited_body`
    // covers a validator committed to a block it never received, and state sync serves *checkpoints*, which a young
    // cell has not formed. A validator that simply never saw a proposal is neither.
    //
    // And nothing is submitted after the gap. A live cell measured on `dromos_quic` showed 5 of 7 validators
    // executing a second transaction while 2 sat at the earlier height for a full frozen span; submitting a third
    // transaction brought all 7 level. This pins the property the deterministic model should have: rejoining must
    // not depend on someone happening to send more traffic.
    const LAG: usize = 6;
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"gap-0");
    c.submit_all(&tx);
    c.tick();
    assert_eq!(c.honest_count_at(0), N, "every validator has height 0 before the gap opens");

    // It misses exactly one height — crashed across the round, so it sees neither the proposal nor the votes, and
    // `submit_all` skips it so its mempool never holds the transaction either.
    c.crashed[LAG] = true;
    let tx2 = c.seal(Transfer { from: ALICE, to: BOB, amount: 50, nonce: 1 }, b"gap-1");
    c.submit_all(&tx2);
    c.tick();
    c.timeout();
    c.crashed[LAG] = false;
    let ahead = c.engines[0].chain().next_height();
    let behind = c.engines[LAG].chain().next_height();
    assert!(behind < ahead, "the gap actually opened: laggard at {behind}, cell at {ahead}");

    // Drive with NO further submissions.
    for _ in 0..12 {
        c.tick();
        c.timeout();
    }

    let cell = c.engines[0].chain().next_height();
    let probe = c.engines[LAG].probe();
    assert_eq!(
        c.engines[LAG].chain().next_height(),
        cell,
        "the laggard rejoined without anyone submitting more work\n  laggard: {probe}"
    );

    // NON-VACUITY: it rejoined by WALKING past the server's executed frontier, not by orbiting it (#142).
    // A checkpoint sits at the executed height, which trails the head, so a snapshot alone lands the
    // requester where the frontier is and the frontier moves as fast as the head — measured before the
    // certificate batch existed: 1 → 15 while the cell went 2 → 18, a ~3-height deficit held for ever.
    // Without this assertion the equality above passes again the moment the batch is dropped and execution
    // happens to keep pace, which is exactly the coincidence that hid the defect.
    assert!(
        probe.synced_certs > 0,
        "the laggard must have parked COMMIT certificates from a sync batch — reaching the cell's height \
         without any means the walk-forward path was not what closed the gap.\n  laggard: {probe}"
    );
    c.settle(); // execution lags finality by one block — the openings are COMMITTED (#137).
    assert_eq!(c.engines[LAG].chain().state().balance(&ALICE), 850, "it holds the state it never executed");
    assert_eq!(c.engines[LAG].chain().state().balance(&BOB), 150);
    let root = c.engines[0].chain().state_root();
    assert_eq!(c.engines[LAG].chain().state_root(), root, "and it is on the same chain, not a fork of it");
    for h in 0..cell {
        assert!(c.hashes_at(h).len() <= 1, "no fork at height {h}");
    }
}

/// **A burst of transactions from one account executes in full.** This was an open defect until the outcome type
/// learned to say "premature"; it is kept as the guard for that.
///
/// Anti-MEV ordering is *blind*: the proposer sees only commitments, so it cannot order a sender's transactions
/// by nonce, and a block routinely carries nonce 2 before nonce 1. Execution rejects the out-of-order ones —
/// correctly, they are not applicable yet — but `on_finalize` has already dropped every *included* commitment
/// from the mempool (`mempool.retain(|t| !included.contains(&t.commit()))`), and that drop is keyed on
/// inclusion, not on outcome. So the premature transactions are gone: never executed, never retryable.
///
/// Measured before the fix: four transfers of 100 from ALICE submitted together, driven for 12 rounds to height
/// 24 — **one** executed. Live over QUIC the same shape lost one of four (three landed across separate blocks).
/// It was never an edge case; it is what happens whenever a client sends a second transaction before the first
/// is included.
///
/// `ExecOutcome` was where the conflation lived: `Rejected` documented "bad nonce, insufficient balance, …" as one
/// terminal verdict, when a nonce *ahead* of the account is not invalid but premature — it becomes valid the
/// moment its predecessor lands. `ExecOutcome::Deferred` now says so, `Accounts` and `TokenLedger` return it, and
/// the engine puts those transactions back in the mempool instead of dropping them.
#[test]
fn a_burst_from_one_account_executes_every_transaction() {
    let mut c = Cluster::new(&genesis());
    let txs: Vec<_> = (0..4u64)
        .map(|n| c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: n }, b"burst"))
        .collect();
    for tx in &txs {
        c.submit_all(tx);
    }
    // Twelve heights sufficed when execution was immediate. Each nonce in the chain is deferred until its
    // predecessor has EXECUTED, and execution now waits a block for its openings to be committed (#137), so
    // the chain advances at roughly half the rate. Doubled rather than nudged to the first passing value:
    // the property is "every transfer eventually executes", and a bound fitted to the exact observed count
    // would fail on any scheduling change.
    for _ in 0..24 {
        c.tick();
        c.timeout();
    }
    for e in &c.engines {
        assert_eq!(e.chain().state().balance(&BOB), 400, "every transfer in the burst executed");
        assert_eq!(e.chain().state().balance(&ALICE), 600, "and ALICE was debited for each");
    }
}

#[test]
fn a_sub_quorum_lock_split_heals() {
    // **The live stall, made deterministic.** Hide the PREPARE votes from four of seven validators for one
    // round: the other three see the quorum, lock, and thereafter refuse every conflicting proposal, while the
    // four — never having seen the polka — keep proposing fresh blocks. Quorum is 5, so neither side reaches it
    // and `reprepare_lock` cannot help, because its liveness argument needs a *quorum* locked on one block.
    //
    // Measured live before the fix: 3 failures in 6 runs of the HERMES suite, all with `rejects.locked` five
    // apiece and nothing else. The proof-of-lock (`Block::pol`) let a locked validator re-offer its value, which
    // took it to 1 in 8 — a race, not a rule, because the unlocked majority prepares whichever proposal reaches
    // it first and cannot vote twice in a round. `valid_value` closes it: a POL-justified proposal is an
    // *observed* polka, so an unlocked proposer re-offers the cell's prepared value instead of a fresh one.
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"split");
    c.submit_all(&tx);

    // Four validators miss the PREPARE round entirely.
    c.set_drop_to(Some((Phase::Prepare, &[3, 4, 5, 6])));
    c.tick();
    c.set_drop_to(None);

    // Drive rounds. Without `valid_value` this needs a lucky ordering; with it, an unlocked proposer offers the
    // value the cell already prepared and the quorum re-forms.
    for _ in 0..20 {
        c.tick();
        c.timeout();
    }

    let height = c.engines[0].chain().next_height();
    assert!(height >= 1, "the cell finalized past the split (height {height})");
    for (i, e) in c.engines.iter().enumerate() {
        assert_eq!(e.chain().next_height(), height, "validator {i} is level with the cell");
        assert_eq!(e.chain().state().balance(&BOB), 100, "validator {i} executed the transfer");
    }
    for h in 0..height {
        assert!(c.hashes_at(h).len() <= 1, "no fork at height {h}");
    }
}

#[test]
fn one_forged_frame_cannot_disable_the_cell_s_lock_split_recovery() {
    // The lag signal `max_seen_height` is **monotone with no reset**, and `accept_vote` used to raise it seven
    // lines BEFORE checking the signature — so one forged frame set it to `u64::MAX` on every validator,
    // permanently. `maybe_propose` gates `can_reoffer` on that signal, which is the mechanism documented as
    // existing "to break a lock split at the contested height".
    //
    // **The severity that suggests is not what falsification showed, and the weaker claim is the honest one.**
    // Reverting the fix does NOT break healing: the cell still reaches height 15 and heals the split, because
    // `reprepare_lock` and `valid_value` also close it and neither reads the poisoned signal. Only `can_reoffer`
    // is suppressed. What the revert *does* produce is the counter assertion below plus a visible sync storm
    // (`sync=9a/0s/0c ans=0/0/63` — every validator asking forever and every answer empty).
    //
    // So the liveness assertion here is a regression guard, not the discriminating one, and saying so matters:
    // ordering it first was what caught the over-claim. A test whose falsification trips only its *last*
    // assertion has an untested prefix, and this one's prefix stays because a future change that made healing
    // depend on `can_reoffer` alone should fail here loudly.
    let mut c = Cluster::new(&genesis());
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"poison");
    c.submit_all(&tx);

    // One frame claiming a height the cell will never reach, attributed to validator 1 and signed by validator 2's
    // key — a forgery an attacker with its OWN key can mint, which is the realistic capability. (`SignedVote.sig`
    // is private, so an unsigned one cannot even be constructed from here; the wire decoder can, and this is the
    // stronger test anyway: it survives a fix that only rejected empty signatures.)
    let keys = gen_keys();
    let vote = Vote { height: u64::MAX, round: 0, block_hash: [9u8; 32], phase: Phase::Prepare, voter: 1 };
    c.inject(ConsensusMsg::Vote(SignedVote::sign(vote, &keys[2].sig)));

    // **The property first, the mechanism second.** Ordered this way deliberately: with the counter assertion
    // leading, falsifying the fix trips it and the liveness half never runs, so nothing would have shown that
    // half to be load-bearing rather than decoration. The cell must still heal the split the poisoned signal
    // disables. Same construction as
    // `a_sub_quorum_lock_split_heals`: hide PREPAREs from four of seven for one round, so three lock and four
    // never see the polka; quorum is 5, so only re-offering can break it.
    c.set_drop_to(Some((Phase::Prepare, &[3, 4, 5, 6])));
    c.tick();
    c.set_drop_to(None);
    for _ in 0..8 {
        c.tick();
        c.timeout();
    }
    let height = c.engines[0].chain().next_height();
    let probes: Vec<String> = (0..N).map(|i| format!("v{i}:{}", c.engines[i].probe())).collect();
    assert!(height >= 1, "a forged frame must not cost the cell its lock-split recovery: {}", probes.join(" | "));
    for h in 0..height {
        assert_eq!(c.hashes_at(h).len(), 1, "and it must not fork height {h}: {}", probes.join(" | "));
    }

    // The mechanism, checked after the property it protects: no validator believed the claim in the first place.
    for (i, e) in c.engines.iter().enumerate() {
        let p = e.probe();
        assert_eq!(p.max_seen_height, 0, "validator {i} believed a forged claim: {p}");
    }
}

/// **The consensus knee, swept rather than asserted.**
///
/// `CellParams::derive` fixes `f = ⌊(n−1)/3⌋` and quorum `Q = ⌈(n+f+1)/2⌉`, giving `f = 2`, `Q = 5` on a Fano
/// cell. That is arithmetic on paper. This drives the actual engines with `k` validators reachable, for every
/// `k` from three to seven, and asks whether anything finalizes.
///
/// It complements the storage sweep in `fanos-sim/tests/minima.rs`, which found the read floor at four
/// survivors. Both floors matter and they are different numbers: a cell that has halted for consensus can
/// still be serving reads, and `docs/deployment-minima.md` says so on the strength of these two measurements
/// rather than on the strength of the formulas they check.
#[test]
fn finalization_needs_the_quorum_and_no_fewer() {
    for k in 3..=N {
        let mut c = Cluster::new(&genesis());
        let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 10, nonce: 0 }, b"quorum-knee");
        c.submit_all(&tx);

        // Cut everything above `k` away. The survivors are `0..k`, so a majority partition of size `k`.
        let cut: Vec<usize> = (k..N).collect();
        if !cut.is_empty() {
            c.split(&cut);
        }
        // Enough rounds that the proposer rotates past any cut-off leader — a sub-quorum group that merely
        // never got a proposal would look identical to one that cannot reach quorum.
        for _ in 0..16 {
            c.tick();
            c.timeout();
        }

        let finalized = c.honest_count_at(0);
        if k >= 5 {
            assert!(finalized >= 5, "k={k} reaches the quorum of 5, so it must finalize; got {finalized}");
        } else {
            assert_eq!(finalized, 0, "k={k} is below the quorum of 5 and must finalize nothing");
        }
    }
}
