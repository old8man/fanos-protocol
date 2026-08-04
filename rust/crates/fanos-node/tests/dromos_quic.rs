//! **The full platform, end to end, over real QUIC** — a *private* OBOLOS transfer executing on the DROMOS
//! hybrid ledger, ordered by live TAXIS BFT consensus, across a genuine seven-node Fano cell (`spec/platform.md`
//! §3, §4). This is the E∧L composition proven runnable at the highest tier: the L-machine (consensus) fixes
//! the order blindly through the anti-MEV encrypted mempool, and the E-machine's shielding (the OBOLOS pool)
//! hides the value — a shielded note is spent and a new one created, and every validator's private state
//! agrees, without any amount, sender, or spent-note identity ever appearing in the clear.
//!
//! It composes the pieces built this cycle: `fanos-obolos` (the shielded transfer), `fanos-dromos`
//! (`HybridLedger` as the TAXIS `StateMachine`), and `fanos-node::spawn_taxis` (the live consensus driver over
//! `fanos-quic`). The genesis mints one shielded note to Alice; the transfer spends it to Bob; the assertion is
//! that all seven nodes' shielded pools converge to "Alice's note spent, Bob's note created".
//!
//! Runtime: multi-threaded with **four** workers — a current-thread harness cannot see a parallelism
//! defect at all (#84), and two workers see it only 3 times in 8 where four see it 8 of 8. Measured
//! against the reverted fix for #83; the table is in `fanos-quic/tests/store_acks.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use core::fmt::Write as _;


use fanos_dromos::HybridLedger;
use fanos_field::F2;
use fanos_geometry::Point;
use fanos_node::{TaxisParams, spawn_taxis};
use fanos_obolos::{Note, Randomness, SpendInput, build_transfer, derive_owner_pk, derive_spend_auth, encode_submission, spend_auth_commit};
use fanos_pqcrypto::kem::{HybridKemPublic, HybridKemSecret};
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};
use fanos_primitives::{BeaconSeed, Epoch};
use fanos_quic::spawn_cell;
use fanos_runtime::{Command, Config, Engine, OverlayNode};
use fanos_taxis::keyper::{KeyperKeyCert, KeyperRegistry, seal_to_keyper_line};
use fanos_dromos::TokenLedger;
use fanos_dromos::hermes::{HTLC_ESCROW, HtlcTerms, HtlcTx, hashlock, htlc_id};
use fanos_dromos::token::{SignedTransfer, Transfer, account_id};
use fanos_taxis::wire::tx_to_frame;
use fanos_taxis::{CellParams, Transaction};

const N: usize = 7;
const ALICE_NSK: [u8; 32] = [0xA1; 32];
const BOB_NSK: [u8; 32] = [0xB0; 32];
const SEED: BeaconSeed = BeaconSeed::new([0x11; 32]);
const EPOCH: Epoch = Epoch::new(1);

/// The whole cell's execution state: `(every node has executed the transfer, a per-validator trace)`.
///
/// The trace carries **every** field the condition tests, for the reason `common::converge` documents: a trace that omits
/// part of the state makes a moving system look frozen. Rendered per validator index, because the defect this shape exposed
/// was one validator out of seven — a cell-wide "not yet" cannot say that.
async fn cell_state(handles: &[fanos_node::TaxisHandle<HybridLedger>]) -> (bool, String) {
    let mut all = true;
    let mut trace = String::new();
    for (i, h) in handles.iter().enumerate() {
        let cell = if let Some((height, ledger)) = h.snapshot().await {
            let (spent, notes) = (ledger.shielded().spent_count(), ledger.shielded().note_count());
            all &= height >= 1 && spent == 1 && notes == 2;
            format!("{i}:h{height}/s{spent}/n{notes}")
        } else {
            all = false;
            format!("{i}:down")
        };
        if i > 0 {
            trace.push(' ');
        }
        trace.push_str(&cell);
    }
    (all, trace)
}

fn make_node(coord: Point<F2>) -> Box<dyn Engine + Send> {
    Box::new(OverlayNode::<F2>::new(coord, Config::default()))
}

/// A spend-auth seed, deterministically distinct from the nullifier key `nsk` (audit §5.D-2).
fn spend_seed_of(nsk: &[u8; 32]) -> [u8; 32] {
    let mut s = *nsk;
    s[0] ^= 0xA5;
    s
}

/// The spend-auth commitment a note owned by `nsk` records in its `auth`.
fn auth_of(nsk: &[u8; 32]) -> [u8; 32] {
    spend_auth_commit(&derive_spend_auth(&spend_seed_of(nsk)).1)
}

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

/// Alice's genesis note (1000 units), deterministic so every validator mints the identical one.
fn alice_note() -> Note {
    Note::new(1000, derive_owner_pk(&ALICE_NSK), auth_of(&ALICE_NSK), Randomness::from_seed(b"alice-genesis"), [7u8; 32])
}

/// The genesis hybrid ledger: an empty transparent tree, and a shielded pool holding Alice's one note.
fn genesis_ledger() -> HybridLedger {
    let mut ledger = HybridLedger::new(TokenLedger::new());
    let n = alice_note();
    ledger.mint_shielded(n.commitment(ledger.params())).expect("mint Alice's genesis note");
    ledger
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_private_transfer_executes_over_live_consensus_end_to_end() {
    let _serial = common::serial_cell().await; // one whole-cell fixture at a time — see `common::serial_cell`
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble the QUIC cell");

    // Cell key material + the agreed anti-MEV decryption authority (keyper registry).
    let keys = gen_keys();
    let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
    let registry = KeyperRegistry::new(
        keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
    );
    let keyper_commit = registry.commit();

    // Spawn a TAXIS driver on every node, each over a genesis HybridLedger holding Alice's shielded note.
    let mut handles = Vec::with_capacity(N);
    for (i, k) in keys.into_iter().enumerate() {
        let params = TaxisParams {
            cell: CellParams::FANO,
            me: i as u8,
            signer: k.sig,
            kem_secret: k.kem,
            verifiers: verifiers.clone(),
            keyper_commit,
            seed: SEED,
            epoch: EPOCH,
            genesis_state: genesis_ledger(),
            reward_per_block: 0,
            sortition: None,
            slash_sealer: None,
        };
        handles.push(spawn_taxis::<F2, HybridLedger>(cell.nodes[i].client(), params));
    }

    // Build the private transfer: spend Alice's genesis note (1000) to Bob (1000), fee 0. The anchor and path
    // come from the deterministic genesis ledger every validator shares.
    let ledger = genesis_ledger();
    let anchor = ledger.shielded().anchor();
    let path = ledger.shielded().path(0).expect("Alice's note is at position 0");
    let sp = SpendInput { note: alice_note(), nsk: ALICE_NSK, spend_seed: spend_seed_of(&ALICE_NSK), path };
    let bob_note = Note::new(1000, derive_owner_pk(&BOB_NSK), auth_of(&BOB_NSK), Randomness::from_seed(b"bob"), [9u8; 32]);
    let (stx, proof) = build_transfer(ledger.params(), anchor, &[sp], &[bob_note], 0);

    // Wrap it as a DROMOS shielded transaction and seal it to the epoch keyper line (anti-MEV), then submit it
    // to every validator — a real client's private SubmitTx.
    let dromos_tx = Transaction::new(HybridLedger::shielded_payload(&encode_submission(&stx, &proof)));

    // Sanity (isolates the crypto from the live wiring): the transfer applies to a fresh genesis ledger
    // directly, so a live-path failure is a consensus/transport issue, not an invalid transaction.
    {
        use fanos_taxis::state::{ExecOutcome, StateMachine};
        let mut local = genesis_ledger();
        assert_eq!(local.apply(&dromos_tx), ExecOutcome::Applied, "the built transfer is valid against genesis");
        assert_eq!(local.shielded().spent_count(), 1);
    }

    let sealed = seal_to_keyper_line(&registry, &dromos_tx, EPOCH, &SEED, CellParams::FANO, b"dromos-quic-seed")
        .expect("seal the DROMOS transaction to the keyper line");
    for h in &handles {
        assert!(h.submit(sealed.clone()).await, "submitted the sealed private transfer");
    }

    // Wait until EVERY node's shielded pool reflects the private transfer: Alice's note nullified (spent_count
    // 1) and Bob's note created (note_count 2 — the genesis note plus Bob's). Convergence across all seven is
    // the cross-node witness that the private transfer executed over live consensus without forking.
    // Three-valued (`common::converge`): reached, or **refuted** the moment the cell stops changing, or inconclusive at the
    // ceiling. The old shape was a bare poll-until-`HANG_CEILING`, which can only ever report "too slow" — so a cell that
    // reached a *wrong fixed point* in three seconds was read as contention and answered with more headroom, twice, while
    // each run burned the full 240 s to rediscover the same frozen state. The trace names every validator, so a refutation
    // says which one is stuck instead of only that the cell did not converge.
    common::converge("the private transfer executes across the whole cell", || async {
        cell_state(&handles).await
    })
    .await;

    // Final agreement: every node's shielded pool is identical — one note spent, two notes total, and the
    // transparent half untouched (this was a purely private transfer).
    for h in &handles {
        let (height, ledger) = h.snapshot().await.expect("a live node snapshot");
        assert!(height >= 1, "the node advanced past genesis");
        assert_eq!(ledger.shielded().spent_count(), 1, "Alice's note is nullified on every node");
        assert_eq!(ledger.shielded().note_count(), 2, "Bob's note was created on every node");
        // The DROMOS **parallel** executor ran on the live consensus path, not the serial fallback.
        //
        // Asserted because no outcome can distinguish them: the conflict schedule is serial-equivalent by construction,
        // so a block executes to the identical state either way. `execute_block` was proven, stochastically tested — and
        // then called from nothing but its own tests, so the vertical-parallelism throughput claim delivered no real
        // speedup.
        //
        // **Against the monotone count, not the last-block gauge, and that is a correctness fix rather than a
        // de-flake.** `waves_last_block` answers "how deep was the LAST block" and must therefore reset —
        // and BFT produces empty blocks routinely, so a heartbeat round landing between the transfer and this
        // snapshot set it to zero and the assertion read "the serial default ran". It failed under machine
        // contention and passed on a quiet host: the signature of an assertion that depends on when it looks
        // rather than on what happened. What this test means to check is a *fact* — that the scheduler ran at
        // all — and a fact a later empty block can erase is not one.
        assert!(
            ledger.parallel_blocks() > 0,
            "the parallel scheduler executed a block on this node, rather than the serial default"
        );
    }
    // The data-availability layer actually RAN on this path, asserted for the same reason as `waves_last_block`
    // above: no outcome distinguishes DA from its absence, because the block commits either way. The shape has bitten
    // twice already (the mix threshold, the beacon recovery authority) — machinery finished, tested, and reachable
    // from nothing.
    //
    // Each clause is what its own falsification showed it to be, which is not what the first draft claimed:
    //
    //   * `shards_sent` is the PROPOSER side, and only proposers disperse — so it is asserted cell-wide, not per
    //     validator. Falsified by dropping the dispersal `Emit`.
    //   * `shard_asks` is the sampling loop: a peer asked for a shard and this validator answered. Falsified by
    //     no-oping `request_shards` — every validator then reports `shard=0/0`.
    //   * `shards_taken` counts every accepted delivery, dispersed OR sampled. Dropping dispersal does NOT make it
    //     zero (measured — the test stays green), so it does not pin dispersal and is not claimed to: it pins that
    //     shards flow and the sampler takes them.
    let mut dispersed = 0u64;
    for (i, h) in handles.iter().enumerate() {
        let p = h.probe().await.expect("validator is up").consensus;
        let (asked, served) = p.shard_asks;
        dispersed += p.shards_sent;
        assert!(p.shards_taken > 0, "v{i} accepted a shard the sampler took: {p}");
        assert!(asked > 0 && served > 0, "v{i} answered a peer's shard request (the sampling loop ran): {p}");
    }
    assert!(dispersed > 0, "some proposer dispersed erasure shards rather than shipping whole blocks");
}

/// The same private transfer, but submitted the way a **real external client** does: sealed and sent as a
/// single transaction App-frame to **one** validator over the network — no in-process `handle.submit`
/// anywhere. That validator ingests it into its mempool and gossips it once to the rest of the cell, so every
/// validator's mempool converges and the transfer executes. This proves the shipped chain accepts client
/// transactions over the wire (the network ingress + gossip), not just via a test's in-process injection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transaction_submitted_over_the_network_to_one_validator_reaches_the_whole_cell() {
    let _serial = common::serial_cell().await; // one whole-cell fixture at a time — see `common::serial_cell`
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble the QUIC cell");

    let keys = gen_keys();
    let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
    let registry = KeyperRegistry::new(
        keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
    );
    let keyper_commit = registry.commit();

    let mut handles = Vec::with_capacity(N);
    for (i, k) in keys.into_iter().enumerate() {
        let params = TaxisParams {
            cell: CellParams::FANO,
            me: i as u8,
            signer: k.sig,
            kem_secret: k.kem,
            verifiers: verifiers.clone(),
            keyper_commit,
            seed: SEED,
            epoch: EPOCH,
            genesis_state: genesis_ledger(),
            reward_per_block: 0,
            sortition: None,
            slash_sealer: None,
        };
        handles.push(spawn_taxis::<F2, HybridLedger>(cell.nodes[i].client(), params));
    }

    // Build + seal the identical private transfer (Alice's genesis note → Bob).
    let ledger = genesis_ledger();
    let anchor = ledger.shielded().anchor();
    let path = ledger.shielded().path(0).expect("Alice's note is at position 0");
    let sp = SpendInput { note: alice_note(), nsk: ALICE_NSK, spend_seed: spend_seed_of(&ALICE_NSK), path };
    let bob_note = Note::new(1000, derive_owner_pk(&BOB_NSK), auth_of(&BOB_NSK), Randomness::from_seed(b"bob"), [9u8; 32]);
    let (stx, proof) = build_transfer(ledger.params(), anchor, &[sp], &[bob_note], 0);
    let dromos_tx = Transaction::new(HybridLedger::shielded_payload(&encode_submission(&stx, &proof)));
    let sealed = seal_to_keyper_line(&registry, &dromos_tx, EPOCH, &SEED, CellParams::FANO, b"ingress-seed")
        .expect("seal the DROMOS transaction to the keyper line");

    // Submit OVER THE NETWORK to exactly ONE validator (index 3): emit the transaction App-frame to its
    // coordinate from another node's overlay. Nothing calls `handle.submit` — the cell must gossip the
    // transaction to every mempool from that single ingress point, or no block will include it.
    let target = Point::<F2>::at(3).coords();
    cell.nodes[0].client().command(Command::Emit { to: target, frame: tx_to_frame(&sealed) });

    // Every node's shielded pool converges to "Alice spent, Bob created" — the cross-node witness that a
    // network-submitted transaction propagated to the whole cell and executed over live consensus. Same three-valued
    // verdict as its sibling above.
    common::converge("a network-submitted transfer reaches the whole cell", || async {
        cell_state(&handles).await
    })
    .await;

    for h in &handles {
        let (_, ledger) = h.snapshot().await.expect("a live node snapshot");
        assert_eq!(ledger.shielded().spent_count(), 1, "Alice's note is nullified on every node");
        assert_eq!(ledger.shielded().note_count(), 2, "Bob's note was created on every node");
    }
}

/// The **transparent** party to the hash-locked contract: a deterministic account funded at genesis, so every
/// validator agrees on the same starting balance without any node minting on its own.
fn htlc_party(tag: u8) -> (HybridSigSecret, HybridVerifier) {
    HybridSigSecret::generate(&mut SeedRng::from_seed(&[0x41, tag]))
}

/// A genesis ledger that also funds the HTLC sender transparently. Kept separate from [`genesis_ledger`] so the
/// two shielded tests keep the exact state they assert against.
fn htlc_genesis_ledger(sender: &[u8; 32]) -> HybridLedger {
    let mut tokens = TokenLedger::new();
    tokens.credit(*sender, 1000);
    tokens.credit(account_id(&htlc_party(2).1), 1000);
    let mut ledger = HybridLedger::new(tokens);
    ledger.mint_shielded(alice_note().commitment(ledger.params())).expect("mint the genesis note");
    ledger
}

/// **HERMES over live consensus**: a hash-locked contract funded, gossiped, ordered, executed and *claimed*
/// across the whole seven-node cell over real QUIC (`spec/platform.md` §8).
///
/// The crate's own tests prove the HTLC state machine and two-chain atomicity in isolation. What no test
/// covered was the claim the platform actually makes — that cross-chain custody is **live on the ledger** —
/// because nothing ever submitted an HTLC through consensus. `fanos-hermes` sat inside the shipped node,
/// reached only through `fanos-dromos/src/hermes.rs`, with no path from a network ingress to its state.
///
/// Both halves matter and are asserted separately. The **lock** must move real value into escrow on every
/// validator (a lock that only records terms would leave the escrow empty and the claim would pay nothing),
/// and the **claim** must release exactly that value to the recipient against the preimage. Submitted the
/// same way its sibling above is — one ingress point, one validator, sealed to the keyper line — so the
/// contract has to reach every mempool by gossip rather than by seven direct submissions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hash_locked_contract_is_funded_and_claimed_over_live_consensus() {
    let _serial = common::serial_cell().await; // one whole-cell fixture at a time
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble the QUIC cell");

    let (sender_sk, sender_vk) = htlc_party(0);
    let (_, recipient_vk) = htlc_party(1);
    let sender = account_id(&sender_vk);
    let recipient = account_id(&recipient_vk);
    let preimage = [0x5Au8; 32];
    let terms = HtlcTerms { sender, recipient, amount: 1000, hashlock: hashlock(&preimage), timeout: 1_000_000 };
    let id = htlc_id(&terms, 0);

    let keys = gen_keys();
    let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
    let registry = KeyperRegistry::new(
        keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
    );
    let keyper_commit = registry.commit();

    let mut handles = Vec::with_capacity(N);
    for (i, k) in keys.into_iter().enumerate() {
        let params = TaxisParams {
            cell: CellParams::FANO,
            me: i as u8,
            signer: k.sig,
            kem_secret: k.kem,
            verifiers: verifiers.clone(),
            keyper_commit,
            seed: SEED,
            epoch: EPOCH,
            genesis_state: htlc_genesis_ledger(&sender),
            reward_per_block: 0,
            sortition: None,
            slash_sealer: None,
        };
        handles.push(spawn_taxis::<F2, HybridLedger>(cell.nodes[i].client(), params));
    }

    // Submit each stage through one ingress point, to a different validator each time — the cell must gossip
    // it to every mempool, and the second stage must find the state the first one left.
    let submit = |tx: Transaction, to: usize, seed: &'static [u8]| {
        let sealed = seal_to_keyper_line(&registry, &tx, EPOCH, &SEED, CellParams::FANO, seed)
            .expect("seal the HTLC transaction to the keyper line");
        cell.nodes[0].client().command(Command::Emit { to: Point::<F2>::at(to).coords(), frame: tx_to_frame(&sealed) });
    };

    // 1. Lock: the sender's transparent balance moves into escrow behind the hashlock.
    let payment = SignedTransfer::sign(Transfer { from: sender, to: HTLC_ESCROW, amount: 1000, nonce: 0 }, &sender_sk, sender_vk);
    let lock = HtlcTx::Lock { terms, payment: Box::new(payment) };
    submit(Transaction::new(HybridLedger::htlc_payload(&lock)), 3, b"htlc-lock-seed");

    common::converge("the hash-locked contract is funded on every validator", || async {
        let mut trace = String::new();
        let mut all = true;
        for (i, h) in handles.iter().enumerate() {
            let escrow = match h.snapshot().await {
                Some((_, l)) => l.htlc_escrow(),
                None => return (false, format!("{trace} v{i}:down")),
            };
            all &= escrow == 1000;
            let _ = write!(trace, "v{i}:{escrow} ");
        }
        (all, trace)
    })
    .await;
    for h in &handles {
        let (_, l) = h.snapshot().await.expect("a live node snapshot");
        assert_eq!(l.tokens().balance(&sender), 0, "the sender's balance moved into escrow, not merely a record");
        assert!(l.htlcs().state(&id).is_some(), "the contract is keyed by its id on every validator");
    }

    // 2. Claim: revealing the preimage releases exactly the locked value to the recipient.
    let claim = HtlcTx::Claim { htlc_id: id, preimage };

    // A second, independent contract, submitted right behind the claim. It is not decoration: a validator
    // that missed a block advances only when the *next* proposal arrives, so a chain whose mempool has gone
    // empty leaves a straggler behind indefinitely. Measured on this very test — 5 of 7 reached the claim
    // while 2 sat at the lock height for the full frozen span, and with block production continuing all 7
    // reached height 22. Keeping the chain moving is what makes a whole-cell assertion reachable at all.
    let (s2, v2) = htlc_party(2);
    let a2 = account_id(&v2);
    let t2 = HtlcTerms { sender: a2, recipient, amount: 500, hashlock: hashlock(&[0x77; 32]), timeout: 1_000_000 };
    let p2 = SignedTransfer::sign(Transfer { from: a2, to: HTLC_ESCROW, amount: 500, nonce: 0 }, &s2, v2);
    let lock2 = HtlcTx::Lock { terms: t2, payment: Box::new(p2) };

    // Re-emit while it is outstanding. A single ingress frame that the cell drops under load leaves the
    // mempool empty and the chain quiescent at the lock height — measured, on a contended host, with all
    // seven validators frozen at height 1. That is the transport's luck, not the ledger's behaviour, and a
    // real client resubmits an unconfirmed transaction for exactly the same reason. Both submissions are
    // idempotent: a replayed claim finds the contract already resolved, a replayed lock finds its id taken.
    let mut polls = 0u32;
    common::converge("the preimage releases the escrow on every validator", || {
        polls += 1;
        if polls % 40 == 1 {
            submit(Transaction::new(HybridLedger::htlc_payload(&claim)), 5, b"htlc-claim-seed");
            submit(Transaction::new(HybridLedger::htlc_payload(&lock2)), 2, b"htlc-lock2-seed");
        }
        async {
        let mut trace = String::new();
        let mut all = true;
        for (i, h) in handles.iter().enumerate() {
            // The recipient's balance, not the global escrow: the second contract locks its own 500, so an
            // "escrow is empty" condition would be asserting that the *other* contract had also resolved.
            let (paid, st) = match h.snapshot().await {
                Some((_, l)) => (l.tokens().balance(&recipient), l.htlcs().state(&id)),
                None => return (false, format!("{trace} v{i}:down")),
            };
            all &= paid == 1000;
            // The consensus position, not just the ledger's: a frozen cell's ledger is precisely what has stopped
            // changing, so it cannot say *why*. See `ConsensusProbe`.
            match h.probe().await {
                Some(p) => {
                    let _ = write!(trace, "v{i}:{paid}/{st:?} {p} | ");
                }
                None => return (false, format!("{trace} v{i}:down")),
            }
        }
        (all, trace)
        }
    })
    .await;
}

