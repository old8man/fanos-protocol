//! **OBOLOS SecOps scenarios** — adversarial and experimental hypothesis-tests over the shielded-currency
//! state machine (the standing simulator/SecOps directive: the sim must let us *probe attacks and validate
//! defenses*, not just re-check happy paths). Each test states a hypothesis about an attack or an invariant and
//! drives the real [`ShieldedState`] to a verdict, using the same [`build_transfer`] wallet primitive a real
//! client uses — so honest and malicious transactions are built the same way, and only the *content* differs.
//!
//! These run against the [`TransparentProof`] backend (the accounting oracle); when the post-quantum
//! zero-knowledge backend lands, the same scenarios run unchanged — the state machine and its gates are the
//! object under test, not the proof representation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_obolos::commit::MAX_VALUE;
use fanos_obolos::{
    ApplyError, Note, Params, Randomness, ShieldedState, SpendInput, build_transfer, derive_owner_pk,
};

/// A note of `value` owned by `nsk`, with deterministic randomness from `tag`.
fn note(value: u64, nsk: &[u8; 32], tag: &[u8]) -> Note {
    let mut rho = [0u8; 32];
    rho[..tag.len().min(32)].copy_from_slice(&tag[..tag.len().min(32)]);
    Note::new(value, derive_owner_pk(nsk), Randomness::from_seed(tag), rho)
}

/// Mint `n` into `state`, returning the `SpendInput` (note + key + current path) needed to spend it.
fn mint_spendable(state: &mut ShieldedState, params: &Params, n: &Note, nsk: &[u8; 32]) -> SpendInput {
    let pos = state.mint(n.commitment(params)).expect("mint");
    SpendInput { note: n.clone(), nsk: *nsk, path: state.path(pos).expect("path") }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Scenario 1 — HYPOTHESIS: value is conserved across a chain of transfers (no inflation, no burning beyond fee).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn value_is_conserved_across_a_transfer_chain() {
    let p = Params::standard();
    let (alice, bob, carol) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let mut s = ShieldedState::new();

    // Genesis: Alice is minted 1000.
    let a0 = note(1000, &alice, b"genesis");
    let spend0 = mint_spendable(&mut s, &p, &a0, &alice);

    // Alice → Bob 700, change 250, fee 50 (1000 = 700 + 250 + 50).
    let to_bob = note(700, &bob, b"a->b");
    let a_change = note(250, &alice, b"a-change");
    let (tx1, pf1) = build_transfer(&p, s.anchor(), &[spend0], &[to_bob.clone(), a_change], 50);
    assert_eq!(s.apply(&p, &tx1, &pf1), Ok(()), "the first hop conserves value");

    // Bob (now holding 700 at the note just appended) → Carol 400, change 280, fee 20 (700 = 400 + 280 + 20).
    let bob_pos = s.note_count() - 2; // to_bob was the first of tx1's two outputs
    let spend_bob = SpendInput { note: to_bob, nsk: bob, path: s.path(bob_pos).expect("bob's path") };
    let to_carol = note(400, &carol, b"b->c");
    let b_change = note(280, &bob, b"b-change");
    let (tx2, pf2) = build_transfer(&p, s.anchor(), &[spend_bob], &[to_carol, b_change], 20);
    assert_eq!(s.apply(&p, &tx2, &pf2), Ok(()), "the second hop conserves value");

    // Conservation ledger: minted 1000 = unspent (250 + 400 + 280) + fees (50 + 20) = 930 + 70.
    assert_eq!(250 + 400 + 280 + 50 + 20, 1000, "the surviving notes plus fees equal the minted supply");
    assert_eq!(s.spent_count(), 2, "two notes were consumed across the chain");
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Scenario 2 — HYPOTHESIS: no single-field tampering of a valid transfer survives the gates (soundness sweep).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn no_single_field_tampering_of_a_valid_transfer_survives() {
    let p = Params::standard();
    let alice = [1u8; 32];

    // Mint a 1000-note owned by ALICE, then build a two-output transfer spent with `spend_key` (≠ alice models
    // theft), against `anchor_override` if given (Some models a fabricated anchor; None = the real post-mint
    // root). Every attack below perturbs exactly one field of this baseline.
    let build = |s: &mut ShieldedState, out_a: Note, out_b: Note, spend_key: [u8; 32], fee: u64, anchor_override: Option<[u8; 32]>| {
        let a0 = note(1000, &alice, b"g");
        let pos = s.mint(a0.commitment(&p)).expect("mint");
        let anchor = anchor_override.unwrap_or_else(|| s.anchor());
        let sp = SpendInput { note: a0, nsk: spend_key, path: s.path(pos).expect("path") };
        build_transfer(&p, anchor, &[sp], &[out_a, out_b], fee)
    };

    // Attack: inflate an output (600 + 500 > 1000) — the balance law breaks.
    {
        let mut s = ShieldedState::new();
        let (tx, pf) = build(&mut s, note(600, &[2u8; 32], b"a"), note(500, &[3u8; 32], b"b"), alice, 0, None);
        assert_eq!(s.apply(&p, &tx, &pf), Err(ApplyError::InvalidProof), "inflation is rejected");
    }
    // Attack: spend Alice's note with the wrong key (theft).
    {
        let mut s = ShieldedState::new();
        let (tx, pf) = build(&mut s, note(600, &[2u8; 32], b"a"), note(400, &[3u8; 32], b"b"), [9u8; 32], 0, None);
        assert_eq!(s.apply(&p, &tx, &pf), Err(ApplyError::InvalidProof), "theft (wrong key) is rejected");
    }
    // Attack: fabricated anchor.
    {
        let mut s = ShieldedState::new();
        let (tx, pf) = build(&mut s, note(600, &[2u8; 32], b"a"), note(400, &[3u8; 32], b"b"), alice, 0, Some([0x42u8; 32]));
        assert_eq!(s.apply(&p, &tx, &pf), Err(ApplyError::UnknownAnchor), "a fabricated anchor is rejected");
    }
    // Attack: replay a valid transfer (double-spend).
    {
        let mut s = ShieldedState::new();
        let (tx, pf) = build(&mut s, note(600, &[2u8; 32], b"a"), note(400, &[3u8; 32], b"b"), alice, 0, None);
        assert_eq!(s.apply(&p, &tx, &pf), Ok(()), "the honest baseline is accepted once");
        assert_eq!(s.apply(&p, &tx, &pf), Err(ApplyError::DoubleSpend), "the replay is rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Scenario 3 — HYPOTHESIS: the modular-wraparound inflation attack (a "negative" output) is stopped by the
// output range check, even though the balance holds modulo q.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn the_modular_wraparound_inflation_attack_is_stopped_by_the_range_check() {
    let p = Params::standard();
    let alice = [1u8; 32];
    let mut s = ShieldedState::new();
    let a0 = note(100, &alice, b"g");
    let sp = mint_spendable(&mut s, &p, &a0, &alice);

    // The attacker makes one huge (out-of-range) output and one "negative" output whose values sum to 100
    // MODULO q — so the balance law alone would pass. `big = MAX_VALUE`, `neg = 100 − MAX_VALUE (mod q)`.
    let q_u64 = ((1u128 << 61) - 1) as u64;
    let big = MAX_VALUE; // exactly the range boundary → out of range (values must be < MAX_VALUE)
    let neg = q_u64 - MAX_VALUE + 100; // ≡ 100 − MAX_VALUE (mod q); a huge "negative" amount
    let out_big = note(big, &[2u8; 32], b"big");
    let out_neg = note(neg, &[3u8; 32], b"neg");
    let (tx, pf) = build_transfer(&p, s.anchor(), &[sp], &[out_big, out_neg], 0);
    // The balance residual is a commitment to zero (the values conserve mod q) — the attack's whole trick —
    // yet the transfer is refused because an output is out of range.
    assert_eq!(s.apply(&p, &tx, &pf), Err(ApplyError::InvalidProof), "the range check defeats wraparound inflation");
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Scenario 4 — HYPOTHESIS: a note cannot be spent twice even via two *different* transactions to different
// recipients (the nullifier, not the transaction, is what is consumed).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn a_note_cannot_be_double_spent_via_two_distinct_transactions() {
    let p = Params::standard();
    let alice = [1u8; 32];
    let mut s = ShieldedState::new();
    let a0 = note(1000, &alice, b"g");
    let sp = mint_spendable(&mut s, &p, &a0, &alice);

    // First spend: Alice → Bob (accepted).
    let (tx_bob, pf_bob) = build_transfer(&p, s.anchor(), core::slice::from_ref(&sp), &[note(1000, &[2u8; 32], b"bob")], 0);
    assert_eq!(s.apply(&p, &tx_bob, &pf_bob), Ok(()));

    // Second spend of the SAME note to a DIFFERENT recipient, as a genuinely different transaction — the
    // nullifier is the same, so it is caught even though nothing else about the transaction matches.
    let sp2 = SpendInput { path: s.path(0).expect("still-valid membership path"), ..sp };
    let (tx_carol, pf_carol) = build_transfer(&p, s.anchor(), &[sp2], &[note(1000, &[3u8; 32], b"carol")], 0);
    assert_ne!(tx_bob, tx_carol, "the two spends are genuinely different transactions");
    assert_eq!(s.apply(&p, &tx_carol, &pf_carol), Err(ApplyError::DoubleSpend), "the second spend of one note is caught");
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Scenario 5 — HYPOTHESIS: multi-input consolidation works — several notes merge into one, conserving value.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn multiple_notes_consolidate_into_one() {
    let p = Params::standard();
    let alice = [1u8; 32];
    let mut s = ShieldedState::new();
    // Three small notes to Alice: 100, 250, 400 (total 750), minted at different times.
    let mut notes_pos = Vec::new();
    for (v, t) in [(100u64, "n0"), (250, "n1"), (400, "n2")] {
        let n = note(v, &alice, t.as_bytes());
        let pos = s.mint(n.commitment(&p)).unwrap();
        notes_pos.push((n, pos));
    }
    // A wallet spending old notes recomputes each path against the CURRENT root (paths from mint time are stale
    // once the tree has grown) — then all three are proven against one anchor.
    let anchor = s.anchor();
    let inputs: Vec<SpendInput> = notes_pos
        .iter()
        .map(|(n, pos)| SpendInput { note: n.clone(), nsk: alice, path: s.path(*pos).expect("current path") })
        .collect();
    // Consolidate into one note of 730, fee 20 (750 = 730 + 20).
    let consolidated = note(730, &alice, b"merged");
    let (tx, pf) = build_transfer(&p, anchor, &inputs, &[consolidated], 20);
    assert_eq!(s.apply(&p, &tx, &pf), Ok(()), "three notes consolidate into one, conserving value");
    assert_eq!(s.spent_count(), 3, "all three inputs are nullified");
    assert_eq!(s.note_count(), 4, "three minted + one consolidated output");
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Scenario 6 — EXPERIMENT: the anonymity set is the whole pool. As the pool grows, every historical note still
// authenticates against a valid anchor — the set a spend hides in is the entire pool, not a fixed-size ring.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn the_anonymity_set_is_the_entire_pool() {
    let p = Params::standard();
    let mut s = ShieldedState::new();
    // Populate the pool with 64 notes from many owners.
    let mut positions = Vec::new();
    for i in 0..64u8 {
        let n = note(1_000 + u64::from(i), &[i; 32], &[i]);
        positions.push((n.clone(), s.mint(n.commitment(&p)).unwrap()));
    }
    assert_eq!(s.note_count(), 64, "the pool holds every minted note");
    // Every note — the oldest and the newest — is a member of the current tree: the anonymity set of any spend
    // is all 64, and grows with the pool (unlike Monero's fixed ring).
    let anchor = s.anchor();
    for (n, pos) in &positions {
        let path = s.path(*pos).expect("a path for each note");
        assert!(path.verify(&n.commitment(&p), &anchor), "note at {pos} is in the whole-pool anonymity set");
    }
}
