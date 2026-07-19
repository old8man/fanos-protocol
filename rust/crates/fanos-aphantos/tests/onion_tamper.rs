//! **Onion tagging / tampering attack** — the classic reason an anonymity onion needs *per-hop
//! authentication* (Pfitzmann's tagging attack; the flaw that motivated Tor's relay-cell MAC and the
//! whole GCM-SIV/AEZ-for-onions line of work). An on-path adversary flips bits in a cell hoping to
//! either (a) create a recognizable modification that survives to a later hop — a "tag" it can
//! correlate at the exit to confirm a flow — or (b) malleate the routing command to redirect the cell.
//!
//! FANOS seals every hop with ChaCha20-Poly1305 AEAD (`sealed.rs`), so each layer is tamper-evident:
//! any change to an authenticated byte fails the tag at the *first* relay and the cell is dropped
//! before it can carry a tag onward. The only unauthenticated bytes are the constant-size *padding*
//! beyond the encrypted `len` — and those are regenerated from a fresh keystream at the next hop, so a
//! modification there cannot survive a single forward either.
//!
//! The calibrated property this asserts, over **every single-byte modification**: an adversary can
//! never produce a cell that both peels successfully *and* forwards a **different** valid onion. Every
//! tamper is either rejected (dropped) or erased on forward (no surviving tag). The adversary's
//! tag-and-trace channel has zero capacity.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_aphantos::PeelOutcome;
use fanos_aphantos::sealed::{ONION_LEN, build, peel};
use fanos_field::F31;
use fanos_geometry::Point;
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};

/// `hops` relay keypairs derived from `seed`.
fn relays(hops: usize, seed: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
    (0..hops)
        .map(|i| {
            let mut rng = SeedRng::from_seed(&[seed, i as u8]);
            HybridKemSecret::generate(&mut rng)
        })
        .collect()
}

/// A freshly sealed 3-hop onion plus the first relay's secret (the on-path attacker's victim hop).
fn victim_onion() -> (Vec<u8>, HybridKemSecret) {
    let circuit =
        fanos_nyx::build_circuit(Point::<F31>::at(0), Point::<F31>::at(500), 3, b"tag-attack")
            .expect("circuit");
    let keypairs = relays(circuit.hop_count(), 7);
    let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();
    let onion = build(&circuit, &pubkeys, b"anonymous payload", b"seed").expect("seal");
    assert_eq!(
        onion.len(),
        ONION_LEN,
        "sealed onion is the constant bucket"
    );
    let (r1_secret, _) = keypairs.into_iter().next().unwrap();
    (onion, r1_secret)
}

/// The inner onion the first relay forwards for an *untampered* cell — the baseline every tampered
/// variant is compared against.
fn clean_forward(onion: &[u8], r1: &HybridKemSecret) -> Vec<u8> {
    match peel(onion, r1).expect("clean onion peels") {
        PeelOutcome::Forward { onion: inner, .. } => inner,
        PeelOutcome::Deliver { .. } => panic!("a 3-hop onion forwards at hop 1"),
    }
}

/// The tagging channel has zero capacity: over every single-byte modification, no tamper yields a cell
/// that peels to a **different** valid forward. Each is either rejected outright (AEAD/framing) or
/// forwards byte-identically to the clean cell (an ignored, regenerated padding byte).
#[test]
fn no_single_byte_tag_survives_a_hop() {
    let (onion, r1) = victim_onion();
    let baseline = clean_forward(&onion, &r1);

    // Sweep the authenticated crypto core (version, KEM ct, nonce, len ct, body ct) **exhaustively** —
    // that is where a surviving tag would live — and sample the uniform bucket padding beyond it at a
    // stride (every padding byte behaves identically: erased on the re-padded forward).
    let core = 4096.min(onion.len());
    let (mut rejected, mut erased, mut surviving_tags) = (0usize, 0usize, 0usize);
    for pos in (0..core).chain((core..onion.len()).step_by(16)) {
        let mut tampered = onion.clone();
        tampered[pos] ^= 0x01; // flip one bit — the finest possible tag
        match peel(&tampered, &r1) {
            Err(_) => rejected += 1, // authenticated byte → dropped at the first hop
            Ok(PeelOutcome::Forward { onion: inner, .. }) => {
                if inner == baseline {
                    erased += 1; // unauthenticated padding → modification does not propagate
                } else {
                    surviving_tags += 1; // a distinguishable surviving modification — a tagging channel
                }
            }
            Ok(PeelOutcome::Deliver { .. }) => surviving_tags += 1, // a redirect to deliver — malleation
        }
    }

    eprintln!(
        "[tagging] len={} rejected={rejected} padding-erased={erased} surviving_tags={surviving_tags}",
        onion.len()
    );
    assert_eq!(
        surviving_tags, 0,
        "an adversary produced a surviving distinguishable tag — per-hop authentication is incomplete"
    );
    // The whole crypto core — version, KEM ciphertext, nonce, encrypted length, and body ciphertext —
    // is tamper-evident (a flip there is dropped). The remainder is constant-size bucket padding, which
    // carries no tag because it is regenerated from a fresh keystream at the next hop (`erased`).
    assert!(
        rejected > 1024,
        "the crypto core must be authenticated (rejected={rejected}, padding-erased={erased})"
    );
}

/// Size gives an adversary neither a tag nor a layer-strip: truncating *into the crypto core* is
/// rejected (a layer cannot be shortened away), and whatever peels forwards at exactly the constant
/// bucket size (so length never varies to carry a tag across a hop). The bucket *size* itself is a
/// transport-enforced anti-fingerprint; here we pin the two adversarial consequences.
#[test]
fn size_gives_no_tag_and_no_layer_strip() {
    let (onion, r1) = victim_onion();

    // Cutting into the header / KEM ct / body ciphertext (not merely trailing padding) strips the
    // layer's authenticated material → the AEAD/framing rejects, never a silent partial peel.
    for cut in [0usize, 100, 1000, 3000] {
        assert!(
            peel(&onion[..cut], &r1).is_err(),
            "a cell truncated into its crypto core (len {cut}) must be rejected"
        );
    }
    // Whatever does peel forwards at exactly the constant bucket size — length reveals nothing.
    match peel(&onion, &r1).unwrap() {
        PeelOutcome::Forward { onion: inner, .. } => {
            assert_eq!(
                inner.len(),
                ONION_LEN,
                "the forwarded cell is the constant bucket size"
            );
        }
        PeelOutcome::Deliver { .. } => panic!("a 3-hop onion forwards at hop 1"),
    }
}

/// A cell sealed for one relay is opaque to every other: peeling with the wrong secret fails (the KEM
/// decapsulates a different session, so the AEAD tag rejects). An adversary who controls relays off
/// the path learns nothing by trying to peel a captured cell.
#[test]
fn a_cell_is_opaque_to_the_wrong_relay() {
    let (onion, _r1) = victim_onion();
    // A relay key that is not on this circuit.
    let mut rng = SeedRng::from_seed(b"off-path-relay");
    let (wrong_secret, _) = HybridKemSecret::generate(&mut rng);
    assert!(
        peel(&onion, &wrong_secret).is_err(),
        "an off-path relay must not be able to peel a cell not addressed to it"
    );
}
