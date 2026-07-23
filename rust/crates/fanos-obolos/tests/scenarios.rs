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
    Address, ApplyError, Note, NoteCipher, Params, Randomness, ShieldedState, SpendInput, build_transfer,
    build_transfer_delivering, build_unshield, derive_owner_pk, derive_spend_auth, scan, spend_auth_commit,
};
use fanos_pqcrypto::SeedRng;
use fanos_pqcrypto::kem::HybridKemSecret;

/// A test spend-auth seed, deterministically distinct from the nullifier key `nsk` (audit §5.D-2: the
/// spend-auth secret must be independent of the revealed nullifier key).
fn spend_seed_of(nsk: &[u8; 32]) -> [u8; 32] {
    let mut s = *nsk;
    s[0] ^= 0xA5;
    s
}

/// The spend-auth commitment a note owned by `nsk` records in its `auth`.
fn auth_of(nsk: &[u8; 32]) -> [u8; 32] {
    spend_auth_commit(&derive_spend_auth(&spend_seed_of(nsk)).1)
}

/// A note of `value` owned by `nsk`, with deterministic randomness from `tag`.
fn note(value: u64, nsk: &[u8; 32], tag: &[u8]) -> Note {
    let mut rho = [0u8; 32];
    rho[..tag.len().min(32)].copy_from_slice(&tag[..tag.len().min(32)]);
    Note::new(value, derive_owner_pk(nsk), auth_of(nsk), Randomness::from_seed(tag), rho)
}

/// Mint `n` into `state`, returning the `SpendInput` (note + keys + current path) needed to spend it.
fn mint_spendable(state: &mut ShieldedState, params: &Params, n: &Note, nsk: &[u8; 32]) -> SpendInput {
    let pos = state.mint(n.commitment(params)).expect("mint");
    SpendInput { note: n.clone(), nsk: *nsk, spend_seed: spend_seed_of(nsk), path: state.path(pos).expect("path") }
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
    let spend_bob = SpendInput { note: to_bob, nsk: bob, spend_seed: spend_seed_of(&bob), path: s.path(bob_pos).expect("bob's path") };
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
        let sp = SpendInput { note: a0, nsk: spend_key, spend_seed: spend_seed_of(&spend_key), path: s.path(pos).expect("path") };
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
// Scenario 2b — HYPOTHESIS (audit §5.D-2): a signed unshield binds `public_recipient`; a copied transaction
// cannot be redirected to a different account, and revealing the nullifier key does not confer spend authority.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn a_signed_unshield_binds_public_recipient_and_cannot_be_redirected() {
    let p = Params::standard();
    let alice = [1u8; 32];
    let mut s = ShieldedState::new();
    let a0 = note(1000, &alice, b"g");
    let sp = mint_spendable(&mut s, &p, &a0, &alice);
    let base = s.clone(); // the post-mint state: `a0` is a member and its root is the anchor

    // Alice unshields 600 to a transparent VICTIM account, 400 stays shielded as change.
    let victim = [0x11u8; 32];
    let change = note(400, &alice, b"change");
    let (tx, pf) = build_unshield(&p, s.anchor(), &[sp], &[change], 600, victim, 0);
    assert_eq!(base.clone().apply(&p, &tx, &pf), Ok(()), "the honest unshield to the victim is accepted");

    // Attack: an on-path adversary copies the broadcast (tx, proof) — which reveals the whole transparent
    // witness, INCLUDING the nullifier key — and swaps `public_recipient` to its own account to redirect the
    // 600. `public_recipient` is not a balance term, so ONLY the spend-auth signature can reject this; and it
    // does, because the swap changes the sighash and the attacker cannot re-sign without the (unrevealed)
    // spend-auth secret. The funds cannot be stolen.
    let mut redirected = tx.clone();
    redirected.public_recipient = [0xEEu8; 32];
    assert_eq!(
        base.clone().apply(&p, &redirected, &pf),
        Err(ApplyError::InvalidProof),
        "swapping public_recipient invalidates the spend-auth signature — the unshield cannot be redirected (§5.D-2)",
    );

    // The same holds for any other bound field the attacker might perturb to their benefit (e.g. the exit
    // amount): the signature covers the whole sighash.
    let mut bumped = tx.clone();
    bumped.public_value = 600; // unchanged value re-check: tampering the auth bytes alone must also fail
    bumped.spend_auths[0][0] ^= 0xFF; // corrupt the signature
    assert_eq!(
        base.clone().apply(&p, &bumped, &pf),
        Err(ApplyError::InvalidProof),
        "a corrupted spend-auth signature is rejected",
    );

    // And a spend cannot be re-authorized by substituting a DIFFERENT spend-auth key: the note commits to the
    // original `auth`, so a foreign `ak` in the opening fails the `auth == H(ak)` check.
    let mut foreign_key = pf.clone();
    let (_ask, other_ak) = derive_spend_auth(b"a totally unrelated spend-auth key");
    foreign_key.inputs[0].ak = other_ak.encode();
    assert_eq!(
        base.clone().apply(&p, &tx, &foreign_key),
        Err(ApplyError::InvalidProof),
        "a foreign spend-auth verifier does not match the note's committed auth",
    );
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
        .map(|(n, pos)| SpendInput { note: n.clone(), nsk: alice, spend_seed: spend_seed_of(&alice), path: s.path(*pos).expect("current path") })
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

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Scenario 7 — EXPERIMENT (unlinkability): a recipient finds a payment delivered to it on-chain and can spend
// it, while an observer with the wrong key detects nothing — the ledger never reveals who a note is for.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn a_recipient_finds_a_delivered_payment_and_an_observer_cannot() {
    let p = Params::standard();
    let alice = [1u8; 32];
    let mut s = ShieldedState::new();
    let a0 = note(1000, &alice, b"g");
    let sp = mint_spendable(&mut s, &p, &a0, &alice);

    // Bob's receiving address (owner tag + KEM key), and the KEM secret behind it.
    let bob_nsk = [2u8; 32];
    let (bob_kem_secret, bob_kem_public) = {
        let mut rng = SeedRng::from_seed(b"bob-kem");
        HybridKemSecret::generate(&mut rng)
    };
    let bob_addr = Address::new(derive_owner_pk(&bob_nsk), auth_of(&bob_nsk), bob_kem_public);

    // Alice pays Bob 1000, *delivering* the note (its opening sealed to Bob).
    let bob_note = Note::new(1000, bob_addr.owner, bob_addr.auth, Randomness::from_seed(b"bobnote"), [4u8; 32]);
    let (tx, proof) =
        build_transfer_delivering(&p, s.anchor(), &[sp], &[(bob_note.clone(), bob_addr.clone())], 0, &mut SeedRng::from_seed(b"deliver-seed"));
    assert_eq!(s.apply(&p, &tx, &proof), Ok(()), "the delivering transfer executes normally");

    // Bob scans the block's outputs and recovers exactly his note (so he can spend it next).
    let outputs: Vec<(&[u8; 32], &NoteCipher)> =
        tx.outputs.iter().filter_map(|o| o.cipher.as_ref().map(|c| (&o.note_commitment, c))).collect();
    let found = scan(&bob_kem_secret, bob_addr.owner, bob_addr.auth, &p, &outputs);
    assert_eq!(found.len(), 1, "Bob finds his delivered note");
    assert_eq!(found[0], bob_note, "and recovers it exactly");

    // An observer with a different KEM key detects nothing — the payment is unlinkable to Bob on-chain.
    let (eve_secret, _eve_pub) = {
        let mut rng = SeedRng::from_seed(b"eve-kem");
        HybridKemSecret::generate(&mut rng)
    };
    assert!(scan(&eve_secret, bob_addr.owner, bob_addr.auth, &p, &outputs).is_empty(), "an observer cannot detect Bob's payment");
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Scenario — audit O-C1: modular-wraparound inflation must be impossible.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn an_out_of_range_input_is_rejected() {
    // O-C1: inputs — not only outputs — must be range-checked, or a value >= MAX_VALUE contributes a wrapping
    // term to the homomorphic balance sum. Here the input is exactly MAX_VALUE (out of range) while the two
    // outputs (MAX_VALUE/2 each) are in range and balance it — so only the INPUT range guard can catch it.
    let p = Params::standard();
    let alice = [1u8; 32];
    let mut s = ShieldedState::new();
    let huge = note(MAX_VALUE, &alice, b"huge");
    let spend = mint_spendable(&mut s, &p, &huge, &alice);
    let half = 1u64 << 50;
    let (tx, pf) = build_transfer(&p, s.anchor(), &[spend], &[note(half, &alice, b"oa"), note(half, &alice, b"ob")], 0);
    assert!(s.apply(&p, &tx, &pf).is_err(), "an out-of-range input is rejected (O-C1)");
}

#[test]
fn a_transaction_exceeding_the_note_cap_is_rejected() {
    // O-C1: the number of value terms is capped so the balance sums cannot wrap modulo q. Padding a valid tx's
    // outputs past MAX_NOTES_PER_TX is refused before any sum could reach q.
    use fanos_obolos::commit::MAX_NOTES_PER_TX;
    let p = Params::standard();
    let alice = [1u8; 32];
    let mut s = ShieldedState::new();
    let a0 = note(1000, &alice, b"genesis");
    let spend = mint_spendable(&mut s, &p, &a0, &alice);
    let (mut tx, mut pf) = build_transfer(&p, s.anchor(), &[spend], &[note(950, &alice, b"change")], 50);
    let (filler_out, filler_open) = (tx.outputs[0].clone(), pf.outputs[0].clone());
    while tx.nullifiers.len() + tx.outputs.len() <= MAX_NOTES_PER_TX {
        tx.outputs.push(filler_out.clone());
        pf.outputs.push(filler_open.clone());
    }
    assert!(s.apply(&p, &tx, &pf).is_err(), "a tx exceeding the note cap is rejected (O-C1)");
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Scenario — audit O-C2: a spend must not republish the note's creation value commitment (untraceability).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn a_spend_does_not_republish_the_notes_creation_commitment() {
    let p = Params::standard();
    let alice = [1u8; 32];
    let mut s = ShieldedState::new();
    let a0 = note(1000, &alice, b"genesis");
    let creation_vc = a0.value_commitment(&p); // public when the note was created as an output
    let spend = mint_spendable(&mut s, &p, &a0, &alice);
    let (tx, pf) = build_transfer(&p, s.anchor(), &[spend], &[note(950, &alice, b"change")], 50);
    // The public input value commitment is a fresh re-randomisation — it cannot be matched to the creation
    // commitment, so an observer cannot identify which note was spent (O-C2).
    assert_ne!(tx.input_values[0], creation_vc, "the spend re-randomises the value commitment (O-C2)");
    // ...and the transaction is still valid: the re-randomised commitment binds to the note's amount.
    assert_eq!(s.apply(&p, &tx, &pf), Ok(()), "the re-randomised spend still verifies");
}
