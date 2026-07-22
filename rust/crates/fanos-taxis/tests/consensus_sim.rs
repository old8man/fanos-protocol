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
use fanos_taxis::committee::{epoch_seal_line, leader, line_members};
use fanos_taxis::consensus::{ConsensusEngine, ConsensusMsg, DaShards, Input, Output, RevealMsg};
use fanos_taxis::incentive::SlashEvidence;
use fanos_taxis::keyper::{KeyperKeyCert, KeyperRegistry, seal_to_keyper_line};
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
    bus: VecDeque<ConsensusMsg>,
    committed: Vec<Vec<(u64, [u8; 32])>>,
    crashed: Vec<bool>,
    withholding: BTreeSet<u8>,
    /// Validators that never receive block bodies (Propose), to exercise the commit-cert-before-body path.
    deaf_propose: BTreeSet<usize>,
    /// Every distinct block body seen on the bus (so a test can hand-deliver a withheld body later).
    proposed: Vec<Block>,
    /// Equivocation proofs the engines surfaced (the operational slashing signal).
    slashes: Vec<SlashEvidence>,
    /// Block-reward splits the engines surfaced (validator, amount).
    rewards: Vec<(u8, u64)>,
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
            committed: vec![Vec::new(); N],
            crashed: vec![false; N],
            withholding: BTreeSet::new(),
            deaf_propose: BTreeSet::new(),
            proposed: Vec::new(),
            slashes: Vec::new(),
            rewards: Vec::new(),
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
                Output::Send(msg) => self.bus.push_back(msg),
                Output::Committed { height, block_hash } => self.committed[idx].push((height, block_hash)),
                Output::Slash(ev) => self.slashes.push(ev),
                Output::Reward(split) => self.rewards.extend(split),
            }
        }
    }

    fn deliver(&mut self, msg: &ConsensusMsg) {
        if let ConsensusMsg::Propose(b) = msg
            && !self.proposed.iter().any(|p| p.hash() == b.hash())
        {
            self.proposed.push(b.clone());
        }
        for i in 0..N {
            if self.crashed[i] {
                continue;
            }
            // A validator deaf to proposals still receives votes/reveals — it can gather a commit certificate
            // without ever seeing the body (the async case the wedge-fix must survive).
            if matches!(msg, ConsensusMsg::Propose(_)) && self.deaf_propose.contains(&i) {
                continue;
            }
            let input = match msg {
                ConsensusMsg::Propose(b) => Input::Propose { block: b.clone(), shards: Box::new(self.shards_for(b)) },
                ConsensusMsg::Vote(sv) => Input::Vote(sv.clone()),
                ConsensusMsg::Reveal(r) => Input::Reveal(r.clone()),
                ConsensusMsg::ExecVote(v) => Input::ExecVote(v.clone()),
            };
            let outs = self.engines[i].step(input);
            self.collect(i, outs);
        }
    }

    /// Push one message onto the bus and drain to quiescence (for injecting an adversary's message).
    fn inject(&mut self, msg: ConsensusMsg) {
        self.bus.push_back(msg);
        self.run();
    }

    /// Drain the bus to quiescence.
    fn run(&mut self) {
        let mut guard = 0;
        while let Some(msg) = self.bus.pop_front() {
            self.deliver(&msg);
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
    }

    fn timeout(&mut self) {
        for i in 0..N {
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
    /// committed decryption authority, exactly as a real client seals ([`seal_to_keyper_line`]).
    fn seal(&self, transfer: Transfer, tag: &[u8]) -> SealedTx {
        seal_to_keyper_line(&self.registry, &transfer.into_tx(), EPOCH, &SEED, CellParams::FANO, tag).unwrap()
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

    // Anti-MEV precondition: the sealed transaction is opaque to any single validator (< t = 2 shares) —
    // a proposer orders it blind, unable to see it is an ALICE→BOB transfer.
    let members = line_members(epoch_seal_line(&SEED, EPOCH));
    let keys = gen_keys();
    let share0 = tx.member_share(0, &keys[members[0]].kem).expect("member 0 opens its own slot");
    assert!(tx.open(&[share0]).is_err(), "one share (< t = 2) must not decrypt the transaction");

    c.submit_all(&tx);
    c.tick(); // leader proposes height 0; the cluster drives prepare → commit → finalize → reveal → execute.

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
    // Final balances: ALICE 1000-300+20=720, BOB 300-120=180, CAROL 120-20=100.
    for e in &c.engines {
        assert_eq!(e.chain().state().balance(&ALICE), 720);
        assert_eq!(e.chain().state().balance(&BOB), 180);
        assert_eq!(e.chain().state().balance(&CAROL), 100);
        assert_eq!(e.chain().next_height(), 3, "three blocks finalized");
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
        c.bus.push_back(ConsensusMsg::Vote(forged));
    }
    c.run();
    assert_eq!(c.honest_count_at(0), 0, "forged-signature votes cannot finalize anything");
    assert!(c.hashes_at(0).is_empty(), "no block was committed from forged votes");
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
    c.bus.push_back(ConsensusMsg::Propose(block_a));
    c.bus.push_back(ConsensusMsg::Propose(block_b));
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

/// Over many random seeds: a random Byzantine subset (`≤ f = 2`) equivocates (injects conflicting prepare
/// votes signed by its real key), and the network delivers every message in a **random order** (an adversarial
/// asynchronous scheduler). BFT **safety** — no two honest validators ever finalize different blocks at the
/// same height — must hold on *every* schedule (safety needs no synchrony). Liveness is checked softly in
/// aggregate: under adversarial async scheduling FLP forbids guaranteed progress, but partial synchrony should
/// let most trials advance.
#[test]
#[ignore = "heavy: hundreds of hybrid ML-DSA sign/verify per trial over a randomized Monte-Carlo (~140s); \
            run in isolation with `cargo test -p fanos-taxis --test consensus_sim -- --ignored`"]
fn randomized_scheduling_and_byzantine_faults_never_fork() {
    use std::collections::BTreeMap;

    use fanos_taxis::{Phase, SignedVote, Vote};

    let trials = 12u64;
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
                        Output::Slash(_) | Output::Reward(_) => {} // equivocation is expected; safety is what this checks
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
                    };
                    for o in engines[i].step(input) {
                        match o {
                            Output::Send(m) => bus.push_back(m),
                            Output::Committed { height, block_hash } => committed[i].push((height, block_hash)),
                            Output::Slash(_) | Output::Reward(_) => {} // safety is what this trial checks
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
    // Aggregate liveness (soft — FLP forbids a strict async guarantee): most trials make progress.
    assert!(
        progress_trials * 2 > trials,
        "only {progress_trials}/{trials} trials progressed — liveness suspiciously low"
    );
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
    let members = line_members(epoch_seal_line(&SEED, EPOCH));
    let keys = gen_keys();
    // A validator NOT on the keyper line forges member 0's slot (x = 1) with garbage, signed by its own key.
    let attacker = (0..N as u8).find(|v| !members.contains(&(*v as usize))).unwrap();
    let forged = RevealMsg::signed(commit, members[0] as u8, share_bytes(1, &[0x55; 32]), &keys[attacker as usize].sig);
    c.inject(ConsensusMsg::Reveal(forged)); // no block finalized yet ⇒ buffered as a pending reveal
    c.submit_all(&tx);
    c.tick();
    // Not censored: every replica finalized and executed the transfer, and all agree on the state root.
    assert_eq!(c.hashes_at(0).len(), 1, "agreement at height 0");
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
    let members = line_members(epoch_seal_line(&SEED, EPOCH));
    let keys = gen_keys();
    // Keyper member 0 signs a GARBAGE share at its own correct x-coordinate (x = 1) — a well-formed forgery
    // that authentication cannot catch, injected before finality so first-writer-wins records it at slot 0.
    let byz = members[0] as u8;
    let forged = RevealMsg::signed(commit, byz, share_bytes(1, &[0xAB; 32]), &keys[byz as usize].sig);
    c.inject(ConsensusMsg::Reveal(forged));
    c.submit_all(&tx);
    c.tick();
    // The honest {member 1, member 2} subset decrypts it on every replica.
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
    let right = epoch_seal_line(&SEED, EPOCH);
    let wrong = (0..7usize).find(|&l| l != right).unwrap();
    let members = line_members(wrong);
    let member_keys: Vec<&HybridKemPublic> = members.iter().map(|&m| &c.kem_dir[m]).collect();
    let tx = SealedTx::seal(
        &Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }.into_tx(),
        EPOCH,
        wrong as u8,
        &member_keys,
        CellParams::FANO.seal_threshold(),
        b"wrong-line",
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
    assert_eq!(c.engines[0].chain().state().balance(&BOB), 100);
    let root = c.engines[0].chain().state_root();
    // Every honest validator holds a checkpoint certifying height 0 at the agreed root.
    for e in &c.engines {
        let cp = e.latest_checkpoint().expect("an execution checkpoint formed");
        assert_eq!(cp.height, 0, "checkpoint is at the executed height");
        assert_eq!(cp.state_root, root, "checkpoint certifies the agreed executed state root");
        assert!(cp.verify(CellParams::FANO.quorum, &verifiers), "it is a valid Q-quorum certificate");
        // A divergent validator (a wrong root at the same height) would be detectable + attributable.
        let bad = fanos_taxis::ExecVote::sign(0, [0xEE; 32], 6, &gen_keys()[6].sig);
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
    let line = epoch_seal_line(&SEED, EPOCH);
    // Seal to 3 GARBAGE committee keys (random keypairs, not the real committee) — passes valid_seal, but no
    // honest keyper member's secret opens any slot.
    let garbage: Vec<(HybridKemSecret, HybridKemPublic)> =
        (0..3u8).map(|i| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xDE, i]))).collect();
    let member_keys: Vec<&HybridKemPublic> = garbage.iter().map(|(_, p)| p).collect();
    let bad = SealedTx::seal(
        &Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }.into_tx(),
        EPOCH,
        line as u8,
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
fn finalizing_a_block_rewards_its_commit_certificate_signers() {
    let mut c = Cluster::new(&genesis());
    for e in &mut c.engines {
        e.set_reward_per_block(500);
    }
    let tx = c.seal(Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }, b"reward");
    c.submit_all(&tx);
    c.tick();
    assert!(!c.rewards.is_empty(), "finalization surfaces a reward split");
    // Each engine splits F = 500 evenly among the Q..N commit signers it certified, so every surfaced share is
    // F/(signers) ∈ [F/N, F/Q] = [71, 100]. (The split is over each node's commit view; a canonical, cross-node-
    // identical reward would record the commit certificate in the chain — the same refinement the execution
    // checkpoint makes for state, tracked as future work.)
    assert!(c.rewards.iter().all(|(_, amt)| (500 / 7..=500 / 5).contains(amt)), "each share is F/(signers) ∈ [71,100]");
    let rewarded: BTreeSet<u8> = c.rewards.iter().map(|(v, _)| *v).collect();
    assert!(rewarded.len() >= 5, "at least a Q-quorum of distinct signers were rewarded, got {}", rewarded.len());
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
