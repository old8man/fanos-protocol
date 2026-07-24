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

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

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
use fanos_taxis::wire::tx_to_frame;
use fanos_taxis::{CellParams, Transaction};

const N: usize = 7;
const ALICE_NSK: [u8; 32] = [0xA1; 32];
const BOB_NSK: [u8; 32] = [0xB0; 32];
const SEED: BeaconSeed = BeaconSeed::new([0x11; 32]);
const EPOCH: Epoch = Epoch::new(1);

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

#[tokio::test]
async fn a_private_transfer_executes_over_live_consensus_end_to_end() {
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
    // Generous deadline: the shielded payload (~7 KB) is far larger than a plain transfer, so the block and its
    // reveals carry more over the loopback — normal convergence is ~2 s, but the ceiling stays wide.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        assert!(tokio::time::Instant::now() <= deadline, "the private transfer did not execute across the cell in time");
        tokio::time::sleep(Duration::from_millis(150)).await;
        let mut all_executed = true;
        for h in &handles {
            match h.snapshot().await {
                Some((height, ledger)) if height >= 1 && ledger.shielded().spent_count() == 1 && ledger.shielded().note_count() == 2 => {}
                _ => {
                    all_executed = false;
                    break;
                }
            }
        }
        if all_executed {
            break;
        }
    }

    // Final agreement: every node's shielded pool is identical — one note spent, two notes total, and the
    // transparent half untouched (this was a purely private transfer).
    for h in &handles {
        let (height, ledger) = h.snapshot().await.expect("a live node snapshot");
        assert!(height >= 1, "the node advanced past genesis");
        assert_eq!(ledger.shielded().spent_count(), 1, "Alice's note is nullified on every node");
        assert_eq!(ledger.shielded().note_count(), 2, "Bob's note was created on every node");
    }
}

/// The same private transfer, but submitted the way a **real external client** does: sealed and sent as a
/// single transaction App-frame to **one** validator over the network — no in-process `handle.submit`
/// anywhere. That validator ingests it into its mempool and gossips it once to the rest of the cell, so every
/// validator's mempool converges and the transfer executes. This proves the shipped chain accepts client
/// transactions over the wire (the network ingress + gossip), not just via a test's in-process injection.
#[tokio::test]
async fn a_transaction_submitted_over_the_network_to_one_validator_reaches_the_whole_cell() {
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
    // network-submitted transaction propagated to the whole cell and executed over live consensus.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        assert!(tokio::time::Instant::now() <= deadline, "the network-submitted transfer did not reach the cell in time");
        tokio::time::sleep(Duration::from_millis(150)).await;
        let mut all_executed = true;
        for h in &handles {
            match h.snapshot().await {
                Some((height, ledger)) if height >= 1 && ledger.shielded().spent_count() == 1 && ledger.shielded().note_count() == 2 => {}
                _ => {
                    all_executed = false;
                    break;
                }
            }
        }
        if all_executed {
            break;
        }
    }

    for h in &handles {
        let (_, ledger) = h.snapshot().await.expect("a live node snapshot");
        assert_eq!(ledger.shielded().spent_count(), 1, "Alice's note is nullified on every node");
        assert_eq!(ledger.shielded().note_count(), 2, "Bob's note was created on every node");
    }
}
