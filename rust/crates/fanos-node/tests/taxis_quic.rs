//! **Live TAXIS BFT consensus over a real seven-node Fano cell on QUIC** (task B, `docs/design-taxis.md` §7).
//!
//! The deterministic simulator proves the consensus *logic* (finality, execution, Byzantine safety) with an
//! in-process message bus. This test proves the tier the simulator cannot: the **sans-I/O `ConsensusEngine`
//! driven over genuine mutual-TLS QUIC sockets** by [`fanos_node::spawn_taxis`]. Seven validators, each seated
//! at its Fano point, each running the production driver; a client seals an anti-MEV transaction to the epoch
//! keyper line (the committed decryption authority) and submits it; the cell proposes, prepares, commits,
//! reveals, and executes it — every message crossing the real overlay as an App-overlay (`0x70`) frame — until
//! every node's finalized ledger reflects the transfer. Divergent execution would show as a mismatched ledger,
//! so agreement on the executed balances across all seven nodes is the end-to-end safety+liveness witness.
//!
//! Runtime: multi-threaded with **four** workers — a current-thread harness cannot see a parallelism
//! defect at all (#84), and two workers see it only 3 times in 8 where four see it 8 of 8. Measured
//! against the reverted fix for #83; the table is in `fanos-quic/tests/store_acks.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use core::fmt::Write as _;

use std::time::Duration;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_node::crosscell_dir::resolve_checkpoint;
use fanos_node::{SortitionParams, TaxisEvent, TaxisParams, spawn_checkpoint_publisher, spawn_taxis};
use fanos_pqcrypto::kem::{HybridKemPublic, HybridKemSecret};
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};
use fanos_primitives::{BeaconSeed, Epoch};
use fanos_vrf::pqvrf::MerkleVrfSecret;
use fanos_quic::spawn_cell;
use fanos_runtime::{Config, Engine, OverlayNode};
use fanos_taxis::keyper::{KeyperKeyCert, KeyperRegistry, seal_to_keyper_line};
use fanos_taxis::{Accounts, CellParams, Transfer};

const N: usize = 7;
const ALICE: [u8; 32] = [0xA1; 32];
const BOB: [u8; 32] = [0xB0; 32];
const SEED: BeaconSeed = BeaconSeed::new([0x11; 32]);
const EPOCH: Epoch = Epoch::new(1);
/// The logical cell id this cell publishes its execution checkpoints under (a parent attests them).
const CELL_ID: u32 = 0;

/// The production overlay engine, seated at a pinned point — the same `OverlayNode` that ships, so the cell
/// carries App-overlay (`0x70`) frames (the TAXIS receive seam) and routes by coordinate.
fn make_node(coord: Point<F2>) -> Box<dyn Engine + Send> {
    Box::new(OverlayNode::<F2>::new(coord, Config::default()))
}

/// One validator's key material (signature + KEM), deterministic from its index.
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

fn genesis() -> Accounts {
    let mut s = Accounts::new();
    s.credit(ALICE, 1000);
    s
}

/// The SSLE Merkle-VRF tree height (domain `2^6 = 64` heights — ample for this test's few blocks).
const VRF_HEIGHT: u32 = 6;

/// A deterministic per-validator Merkle-VRF seed (distinct per index).
fn vrf_seed(i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0x5A;
    s[1] = i as u8;
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transaction_finalizes_and_executes_over_a_real_quic_cell() {
    let _serial = common::serial_cell().await; // one whole-cell fixture at a time
    // A genuine seven-node Fano cell over mutual-TLS QUIC, membership established (routing by coordinate works).
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble the QUIC cell");

    // Cell key material and the agreed on-chain anti-MEV decryption authority (the keyper registry commitment).
    let keys = gen_keys();
    let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
    let registry = KeyperRegistry::new(
        keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
    );
    let keyper_commit = registry.commit();

    // Secret-leader sortition registration: each validator's Merkle-VRF root, agreed committee config (like
    // the verifiers). Enabling it here proves SSLE runs over REAL QUIC — round 0 is the all-propose min-ticket
    // lottery, so the winning proposer is secret until it broadcasts, and the cell still finalizes normally.
    let vrf_roots: Vec<[u8; 32]> =
        (0..N).map(|i| MerkleVrfSecret::generate(&vrf_seed(i), VRF_HEIGHT).unwrap().root()).collect();

    // Spawn a production TAXIS driver on every node — validator index i seated at Point::at(i).
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
            genesis_state: genesis(),
            reward_per_block: 0,
            sortition: Some(SortitionParams {
                secret: MerkleVrfSecret::generate(&vrf_seed(i), VRF_HEIGHT).unwrap(),
                roots: vrf_roots.clone(),
                base: 0,
            }),
            slash_sealer: None,
        };
        handles.push(spawn_taxis::<F2, Accounts>(cell.nodes[i].client(), params));
    }

    // The live producer side of cross-cell shared security: every validator publishes its execution
    // checkpoints to the cell's slot in the overlay store, where a parent cell would attest them.
    let mut publishers = Vec::with_capacity(N);
    for (i, h) in handles.iter().enumerate() {
        publishers.push(spawn_checkpoint_publisher(cell.nodes[i].client(), CELL_ID, EPOCH, h));
    }

    // Watch node 0's finalization stream — a direct witness that blocks actually commit over the wire.
    let mut events = handles[0].subscribe();

    // Seal an anti-MEV transfer to the epoch keyper line (the canonical committed-authority seal) and submit it
    // to every validator's mempool — a real client's SubmitTx, fanned to the cell.
    let tx = Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }.into_tx();
    let sealed = seal_to_keyper_line(&registry, &tx, EPOCH, &SEED, CellParams::FANO, b"live-quic-tx")
        .expect("seal to the committed keyper line");
    for h in &handles {
        assert!(h.submit(sealed.clone()).await, "submitted the sealed tx to a live driver");
    }

    // Liveness witness: the cell finalizes at least one block over real QUIC.
    let committed = tokio::time::timeout(common::HANG_CEILING, async {
        loop {
            if let Ok(TaxisEvent::Committed { height, .. }) = events.recv().await {
                return height;
            }
        }
    })
    .await
    .expect("the cell finalized a block over real QUIC");
    assert!(committed < u64::MAX, "a finalized height was observed");

    // End-to-end safety+liveness: wait until EVERY node's finalized ledger reflects the transfer — BOB credited
    // 100 and ALICE debited to 900. Divergent (forked) execution would leave some node's ledger different, so
    // unanimous agreement on the executed balances is the cross-node no-fork witness.
    let deadline = tokio::time::Instant::now() + common::HANG_CEILING;
    loop {
        assert!(tokio::time::Instant::now() <= deadline, "the transfer did not execute across the whole cell in time");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut all_executed = true;
        for h in &handles {
            if let Some((height, state)) = h.snapshot().await {
                if state.balance(&BOB) != 100 || state.balance(&ALICE) != 900 || height == 0 {
                    all_executed = false;
                    break;
                }
            } else {
                all_executed = false;
                break;
            }
        }
        if all_executed {
            break;
        }
    }

    // Final agreement assertion: snapshot every node and confirm the executed ledger is identical and the
    // transfer executed exactly once (no double-spend from re-proposal — the nonce guards it).
    for h in &handles {
        let (height, state) = h.snapshot().await.expect("a live node snapshot");
        assert!(height >= 1, "every node advanced past genesis");
        assert_eq!(state.balance(&BOB), 100, "BOB credited exactly once on every node");
        assert_eq!(state.balance(&ALICE), 900, "ALICE debited exactly once on every node");
    }

    // Cross-cell producer side: a *different* node resolves the cell's published execution checkpoint from the
    // store, and it is a valid Q-quorum certificate over the executed state — exactly what a parent cell attests
    // for hierarchical shared security (`crosscell_dir::attest_children`).
    let reader = cell.nodes[1].client();
    let ckpt_deadline = tokio::time::Instant::now() + common::HANG_CEILING;
    let cert = loop {
        assert!(tokio::time::Instant::now() <= ckpt_deadline, "the cell published no execution checkpoint in time");
        if let Some(cert) = resolve_checkpoint(&reader, CELL_ID, EPOCH).await {
            break cert;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(
        cert.verify(CellParams::FANO.quorum(), &verifiers),
        "the published checkpoint is a valid Q-quorum certificate over the executed state",
    );

    for p in publishers {
        p.abort();
    }
}

/// **A validator that joins after the cell has moved on reaches its executed state** — over real QUIC, with six
/// validators (quorum is 5 of 7) having carried the chain without it.
///
/// It was written to cover the directed reply, and the falsification says it does not. `SyncResp` is the one
/// consensus message this driver sends to a single peer's coordinate (`Output::SendTo`) rather than broadcasting,
/// and the deterministic simulator showed that exchange is what repairs a gap there — remove it and the laggard
/// sits at height 1 while the cell reaches 18. So the obvious expectation was that deleting the directed emit
/// would fail this test. **It does not: the test passes unchanged with that emit deleted.** Whatever carries a
/// late joiner over QUIC, it is not the directed reply — most likely ordinary consensus following, since a height
/// h+1 block's `last_commit` certifies h and the cell emits blocks continuously.
///
/// So the test is kept for what it *does* witness, under its own name: a late joiner arrives at the cell's exact
/// executed state, on the cell's chain rather than a private one. Covering the directed reply needs a gap that
/// ordinary following cannot close, and a first attempt at that (four transfers) hit something else entirely —
/// the cell executed three of them and froze at height 20 with the fourth unexecuted, on a host that was
/// demonstrably answering. That is its own thread, recorded rather than folded in here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_validator_joining_late_reaches_the_cells_executed_state() {
    const LATE: usize = 6;

    // **Declined up front rather than after 250 s.** This is the longest liveness test in the tree and its
    // own budgeted-exchange ceiling already reports INCONCLUSIVE correctly — but only after burning the full
    // window to get there. Measured: 6 s on an idle box, 250 s under contention, both times a correct
    // verdict and one of them forty times more expensive. The guard re-measures for two minutes before
    // declining, so a transient spike still lets the test run (#87).
    common::require_quiet_host("whether a validator joining late catches up to the cell's executed state");

    let _serial = common::serial_cell().await; // one whole-cell fixture at a time
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble the QUIC cell");

    let keys = gen_keys();
    let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
    let registry = KeyperRegistry::new(
        keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
    );
    let keyper_commit = registry.commit();
    let params_for = |i: usize, k: Keys| TaxisParams {
        cell: CellParams::FANO,
        me: i as u8,
        signer: k.sig,
        kem_secret: k.kem,
        verifiers: verifiers.clone(),
        keyper_commit,
        seed: SEED,
        epoch: EPOCH,
        genesis_state: genesis(),
        reward_per_block: 0,
        sortition: None,
        slash_sealer: None,
    };

    // Only six drivers start. The seventh node exists on the overlay (so the cell is routable) but runs no
    // consensus yet — the same shape as a validator that was down while its cell carried on.
    let mut keys = keys.into_iter().enumerate().collect::<Vec<_>>();
    let late_keys = keys.remove(LATE).1;
    let mut handles: Vec<_> =
        keys.into_iter().map(|(i, k)| spawn_taxis::<F2, Accounts>(cell.nodes[i].client(), params_for(i, k))).collect();

    let tx = Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 }.into_tx();
    let sealed = seal_to_keyper_line(&registry, &tx, EPOCH, &SEED, CellParams::FANO, b"late-join-tx")
        .expect("seal to the committed keyper line");
    for h in &handles {
        assert!(h.submit(sealed.clone()).await, "submitted the sealed tx to a live driver");
    }

    // The six-validator cell executes without the seventh.
    common::converge("the quorum executes without the absent validator", || async {
        let mut trace = String::new();
        let mut all = true;
        for (i, h) in handles.iter().enumerate() {
            if let Some((height, state)) = h.snapshot().await {
                all &= height >= 1 && state.balance(&BOB) == 100;
                let _ = write!(trace, "v{i}:h{height}/b{} ", state.balance(&BOB));
            } else {
                all = false;
                let _ = write!(trace, "v{i}:down ");
            }
        }
        (all, trace)
    })
    .await;

    // Now the seventh joins, at genesis, into a cell that has moved on.
    handles.push(spawn_taxis::<F2, Accounts>(cell.nodes[LATE].client(), params_for(LATE, late_keys)));

    common::converge("the late validator catches up to the cell it never saw", || async {
        let Some((height, state)) = handles[LATE].snapshot().await else {
            return (false, "late:down".to_owned());
        };
        (height >= 1 && state.balance(&BOB) == 100, format!("late:h{height}/b{}", state.balance(&BOB)))
    })
    .await;

    // It is on the cell's chain, not a private one: the same executed balances the quorum agreed.
    let (height, state) = handles[LATE].snapshot().await.expect("a live snapshot of the late validator");
    assert!(height >= 1, "the late validator advanced past genesis");
    assert_eq!(state.balance(&BOB), 100, "it holds the transfer it never saw proposed");
    assert_eq!(state.balance(&ALICE), 900, "and the matching debit — one executed state, not a reconstruction");
}

