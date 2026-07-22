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

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_node::{TaxisEvent, TaxisParams, spawn_taxis};
use fanos_pqcrypto::kem::{HybridKemPublic, HybridKemSecret};
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};
use fanos_primitives::{BeaconSeed, Epoch};
use fanos_quic::spawn_cell;
use fanos_runtime::{Config, Engine, OverlayNode};
use fanos_taxis::keyper::{KeyperKeyCert, KeyperRegistry, seal_to_keyper_line};
use fanos_taxis::{Accounts, CellParams, Transfer};

const N: usize = 7;
const ALICE: [u8; 32] = [0xA1; 32];
const BOB: [u8; 32] = [0xB0; 32];
const SEED: BeaconSeed = BeaconSeed::new([0x11; 32]);
const EPOCH: Epoch = Epoch::new(1);

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

#[tokio::test]
async fn a_transaction_finalizes_and_executes_over_a_real_quic_cell() {
    // A genuine seven-node Fano cell over mutual-TLS QUIC, membership established (routing by coordinate works).
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble the QUIC cell");

    // Cell key material and the agreed on-chain anti-MEV decryption authority (the keyper registry commitment).
    let keys = gen_keys();
    let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
    let registry = KeyperRegistry::new(
        keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
    );
    let keyper_commit = registry.commit();

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
        };
        handles.push(spawn_taxis::<F2, Accounts>(cell.nodes[i].client(), params));
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
    let committed = tokio::time::timeout(Duration::from_secs(30), async {
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
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
}
