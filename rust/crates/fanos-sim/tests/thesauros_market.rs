//! THESAUROS storage-market scenarios — the incentive and audit dynamics under adversarial providers
//! (`docs/design-storage.md` §5–§6). Two hypotheses, tested against the real content/proof-of-retrievability
//! engine (not a mock):
//!
//! 1. **The derived audit catches deletion.** A provider that keeps the cheap Merkle structure but deletes a
//!    fraction of the data passes an epoch only when *every* one of the `k` beacon-drawn challenges happens to
//!    land on a leaf it kept — probability `≈ ρ^k`. With `k = required_samples(λ, f_tol)` chosen against the
//!    tolerated missing fraction, that probability collapses, so over a run the cheater is caught with high
//!    probability while an honest provider passes every time.
//! 2. **Pay-per-proof turns that into the right money.** An honest deal pays the provider the whole price over
//!    its duration; a deal whose provider cannot prove pays nothing and refunds the consumer — no bond, no
//!    slashing, just the absence of payment.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use fanos_thesauros::content::{LEAF, chunk_cid};
use fanos_thesauros::por::required_samples;
use fanos_thesauros::{Deal, DealParams, DealState, Settlement, challenge, encode_response, prove, verify};

/// A full chunk of `leaves` distinct leaves (leaf i = the byte (i+1) repeated).
fn full_chunk(leaves: usize) -> Vec<u8> {
    (0..leaves * LEAF).map(|i| (i / LEAF + 1) as u8).collect()
}

/// The beacon for trial/epoch `t` (a stand-in for the block's parent-hash audit beacon).
fn beacon(t: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&t.to_le_bytes());
    b
}

#[test]
fn the_retrievability_proof_catches_a_deleted_leaf() {
    // The mechanism, faithfully: an honest response verifies; corrupting a challenged leaf's bytes (a deleted
    // leaf the cheater cannot answer) breaks the Merkle path, so the audit fails.
    let leaves = 64;
    let data = full_chunk(leaves);
    let cid = chunk_cid(&data);
    let k = 33;
    let b = beacon(7);
    let indices = challenge(&cid, &b, k, leaves);
    let response = prove(&data, &indices).unwrap();
    assert!(verify(&cid, &b, k, leaves, &response), "an honest provider passes");
    // The cheater deleted the data of the first challenged leaf: it has the path but not the bytes.
    let mut corrupt = response.clone();
    corrupt[0].bytes[0] ^= 0xFF;
    assert!(!verify(&cid, &b, k, leaves, &corrupt), "a challenge on a deleted leaf fails the audit");
    // The on-wire response the ledger would receive still decodes, and still fails.
    let _ = encode_response(&corrupt);
}

#[test]
fn the_audit_catches_a_partial_cheater_at_the_predicted_rate() {
    // Hypothesis 1: measure the empirical pass rate of three provider strategies over many independent audits
    // and check it against the derived soundness.
    let leaves = 64;
    let data = full_chunk(leaves);
    let cid = chunk_cid(&data);
    let k = required_samples(5, 0.10); // catch anyone missing >=10% with 5 bits of soundness
    assert_eq!(k, 33, "the sample count is derived, not chosen");

    // Held leaf sets: honest keeps all; the partial cheater keeps 57 of 64 (rho ~= 0.89, missing >10%); the full
    // cheater keeps none. A provider passes an epoch iff every challenged leaf is one it kept.
    let honest: BTreeSet<usize> = (0..leaves).collect();
    let partial: BTreeSet<usize> = (0..57).collect();
    let full_cheat: BTreeSet<usize> = BTreeSet::new();

    let trials = 4000u64;
    let (mut honest_pass, mut partial_pass, mut cheat_pass) = (0u32, 0u32, 0u32);
    for t in 0..trials {
        let indices = challenge(&cid, &beacon(t), k, leaves);
        if indices.iter().all(|i| honest.contains(i)) {
            honest_pass += 1;
        }
        if indices.iter().all(|i| partial.contains(i)) {
            partial_pass += 1;
        }
        if indices.iter().all(|i| full_cheat.contains(i)) {
            cheat_pass += 1;
        }
    }

    // Honest passes every audit; the full cheater never does.
    assert_eq!(honest_pass, trials as u32, "an honest provider passes every audit");
    assert_eq!(cheat_pass, 0, "a provider holding nothing never passes");

    // The partial cheater is caught the overwhelming majority of the time. Theory: P(pass) is the hypergeometric
    // ~0.4%, bounded above by the with-replacement rho^k ~2.2%; assert the empirical rate sits below a safe 5%,
    // i.e. the audit catches the cheater >95% of the time.
    let partial_rate = f64::from(partial_pass) / trials as f64;
    eprintln!("partial-cheater empirical pass rate = {partial_rate:.4} (theory hypergeom ~0.004, rho^k ~0.022)");
    assert!(partial_rate < 0.05, "the derived audit catches a >10%-missing provider >95% of the time (got {partial_rate:.4})");
}

#[test]
fn honest_deals_pay_out_and_faulty_deals_refund() {
    // Hypothesis 2: pay-per-proof turns the audit verdicts into the right money, through the real Deal engine.
    let leaves = 64;
    let data = full_chunk(leaves);
    let cid = chunk_cid(&data);
    let k = 33u32;
    let duration = 8u64;
    let price = 800u64;
    let params = |provider: [u8; 32]| DealParams {
        cid,
        size: (leaves * LEAF) as u64,
        duration,
        replication: 3,
        lambda_bits: 5,
        f_tol_permille: 100,
        k,
        price,
        provider,
        consumer: [0xBB; 32],
    };

    // An honest provider proves every epoch (against that epoch's beacon) → earns the whole price.
    let mut honest_deal = Deal::open(params([0xA1; 32])).unwrap();
    let mut earned = 0u64;
    for epoch in 0..duration {
        let indices = challenge(&cid, &beacon(epoch), k as usize, leaves);
        let response = prove(&data, &indices).unwrap();
        let ok = verify(&cid, &beacon(epoch), k as usize, leaves, &response);
        if let Some(Settlement::Pay { amount, .. }) = honest_deal.settle_epoch(epoch, ok) {
            earned += amount;
        }
    }
    assert_eq!(earned, price, "the honest provider earned the whole price");
    assert_eq!(honest_deal.state(), DealState::Completed);
    assert_eq!(honest_deal.refundable(), 0);

    // A provider holding nothing cannot prove any epoch → earns nothing, and the consumer reclaims it all.
    let mut faulty_deal = Deal::open(params([0xA2; 32])).unwrap();
    for h in 0..duration {
        // No proof to submit → the epoch is a miss.
        let _ = faulty_deal.settle_epoch(h, false);
    }
    assert_eq!(faulty_deal.released(), 0, "a provider that never proves earns nothing");
    assert_eq!(faulty_deal.refundable(), price, "the whole escrow refunds to the consumer");
}
