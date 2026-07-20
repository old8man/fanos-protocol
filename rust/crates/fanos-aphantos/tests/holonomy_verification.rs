//! **§5.4 NYX holonomy path-integrity verification** — the sender-embedded `Hol` tag is not just
//! computed and carried (`fanos_nyx::ratchet`, `sealed::PeelOutcome::Deliver`); it is now actually
//! *checked*, closing the gap this module exists to close (the dead `HolonomyFail` code path).
//!
//! The only sound verifier is a party with legitimate, independent knowledge of the circuit — here,
//! a client that built its own **reply circuit** (`NyxNode::build_verifiable_circuit`) and later
//! checks a delivery against it (`NyxNode::verified_deliver`). An honest, untampered path verifies
//! and delivers; a substituted interior hop — the circuit the client actually gets back does not
//! match the one it expected — is caught and rejected, never handed to the application.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_aphantos::sealed::{self, PeelOutcome};
use fanos_aphantos::{Directory, NyxNode};
use fanos_field::F31;
use fanos_geometry::Point;
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_wire::error::ProtocolError;
use fanos_wire::{FrameType, encode_frame};

/// A KEM keypair from a fixed seed.
fn keypair(seed: &[u8]) -> (HybridKemSecret, HybridKemPublic) {
    let mut rng = SeedRng::from_seed(seed);
    HybridKemSecret::generate(&mut rng)
}

/// Wrap a sealed onion in the Tessera wire frame a node receives.
fn tessera_frame(onion: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(FrameType::Tessera.code(), onion, &mut out);
    out
}

/// Seal `payload` for `circuit`/`seed` (the last `relay_keys` entry is always the verifying
/// client's own public key, so it — and only it — peels the final `Deliver` layer) and route it
/// through every *interior* relay's real secret, returning the final hop's wire frame: the exact
/// bytes that would arrive at the client.
fn seal_and_route_to_client(
    circuit: &fanos_nyx::Circuit<F31>,
    interior: &[(HybridKemSecret, HybridKemPublic)],
    client_public: &HybridKemPublic,
    payload: &[u8],
    seed: &[u8],
) -> Vec<u8> {
    let mut relay_keys: Vec<&HybridKemPublic> = interior.iter().map(|(_, p)| p).collect();
    relay_keys.push(client_public);
    assert_eq!(relay_keys.len(), circuit.hop_count());

    let mut onion = sealed::build(circuit, &relay_keys, payload, seed).expect("onion seals");
    for (secret, _) in interior {
        match sealed::peel(&onion, secret).expect("interior hop peels") {
            PeelOutcome::Forward { onion: inner, .. } => onion = inner,
            PeelOutcome::Deliver { .. } => panic!("delivered before reaching the client's own hop"),
        }
    }
    tessera_frame(&onion)
}

/// A fresh client `NyxNode` plus a freshly built reply circuit it can later verify against — and
/// the interior-relay keypairs a "service" would need to seal a reply onto that circuit.
struct ReplySetup {
    client: NyxNode<F31>,
    circuit: fanos_nyx::Circuit<F31>,
    seed: Vec<u8>,
    interior: Vec<(HybridKemSecret, HybridKemPublic)>,
    client_public: HybridKemPublic,
}

fn client_with_reply_circuit(client_seed: u8) -> ReplySetup {
    let (client_secret, client_public) = keypair(&[client_seed]);
    let mut client = NyxNode::new(
        Point::<F31>::at(0),
        client_secret,
        Directory::new(),
        [client_seed; 32],
        [0u8; 32],
        3, // 3-hop reply circuit
    );
    // A nominal launch label, distinct from the client's own coordinate (spec §5.4: folded into the
    // holonomy chain like any other hop, but never a routing step the client itself performs).
    let launch = Point::<F31>::at(500).coords();
    let (circuit, seed) = client
        .build_verifiable_circuit(launch)
        .expect("a reply circuit builds");
    assert_eq!(
        circuit.dest(),
        Point::<F31>::at(0),
        "the reply circuit ends at the client"
    );
    let interior: Vec<(HybridKemSecret, HybridKemPublic)> = (0..circuit.hop_count() - 1)
        .map(|i| keypair(&[0xA0, client_seed, i as u8]))
        .collect();
    ReplySetup {
        client,
        circuit,
        seed,
        interior,
        client_public,
    }
}

#[test]
fn an_honest_reply_verifies_through_the_live_nyxnode_path() {
    let ReplySetup {
        mut client,
        circuit,
        seed,
        interior,
        client_public,
    } = client_with_reply_circuit(1);
    let payload = b"the response";
    let frame = seal_and_route_to_client(&circuit, &interior, &client_public, payload, &seed);

    let delivered = client
        .verified_deliver(&frame, &circuit, &seed)
        .expect("an honest, untampered reply verifies");
    assert_eq!(delivered, payload, "the payload arrives unchanged");
}

#[test]
fn a_substituted_hop_fails_verification_and_is_rejected() {
    // The reply actually travels one circuit ("actual"), but the client's own retained expectation
    // is a DIFFERENT one ("expected") — same source/dest, a substituted interior hop (a second,
    // independently-built reply circuit is exactly that: `build_verifiable_circuit`'s per-circuit
    // seed differs, so the interior relays differ). This is what an on-path substitution attack, or
    // a stale/mismatched verifier, produces: the accumulated holonomy cannot match.
    let ReplySetup {
        mut client,
        circuit: actual,
        seed: actual_seed,
        interior: actual_interior,
        client_public,
    } = client_with_reply_circuit(2);
    // A second circuit from the SAME client, built the same way — its own independent seed makes
    // its interior relays differ from `actual`'s.
    let launch = Point::<F31>::at(500).coords();
    let (expected, expected_seed) = client
        .build_verifiable_circuit(launch)
        .expect("a second reply circuit builds");
    assert_ne!(
        actual.relays(),
        expected.relays(),
        "the two circuits genuinely differ (test precondition)"
    );

    let frame = seal_and_route_to_client(
        &actual,
        &actual_interior,
        &client_public,
        b"the response",
        &actual_seed,
    );

    // Verifying the REAL delivery against the client's OWN (but mismatched) expectation must fail —
    // never silently accept a payload that did not travel the intended path.
    assert_eq!(
        client.verified_deliver(&frame, &expected, &expected_seed),
        Err(ProtocolError::HolonomyFail),
        "a substituted hop must be caught, not silently delivered"
    );
}
