//! CALYPSO hidden services, end to end over the real overlay + L4 store (spec Part XII). A
//! service publishes a contact descriptor at its **per-epoch rendezvous key** (rotating, so there
//! is no static location to seize); a client that knows the `.fanos` address verifies the
//! self-certifying binding, solves a PoW, computes the *same* key, fetches the descriptor, and
//! reaches the service — with no directory anywhere. This drives the byte-for-byte `OverlayNode`
//! (Put / Get / Send) that ships; CALYPSO is an application over it, not a second stack.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_calypso::{BeaconSeed, Epoch, HiddenService, client_descriptor_key, descriptor_key, pow};
use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{Sim, spawn_cell};

/// The epoch's public randomness beacon, folded into descriptor keys (audit E5); fixed across this
/// test so keys still rotate by epoch exactly as in production.
const BEACON: BeaconSeed = BeaconSeed::new([0xCA; 32]);

/// The PoW difficulty gating an introduction (small, for a fast test).
const POW_BITS: u32 = 8;

fn triple_bytes(t: Triple) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    for w in t {
        v.extend_from_slice(&w.to_le_bytes());
    }
    v
}

fn parse_triple(b: &[u8]) -> Option<Triple> {
    let x = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?);
    let y = u32::from_le_bytes(b.get(4..8)?.try_into().ok()?);
    let z = u32::from_le_bytes(b.get(8..12)?.try_into().ok()?);
    Some([x, y, z])
}

#[test]
fn hidden_service_hosting_and_client_meeting_over_the_overlay() {
    let mut sim = Sim::new(0xCA1);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    let service = HiddenService::new(b"my-service-hybrid-pubkey".to_vec());
    let address = *service.address();
    let epoch = Epoch::new(7);
    let service_node = cell[0];
    let client_node = cell[3];

    // Service publishes its contact descriptor at the epoch rendezvous key.
    let key = descriptor_key(service.pubkey(), epoch, &BEACON);
    sim.inject(
        service_node,
        Command::Put {
            key: key.clone(),
            value: triple_bytes(service_node),
        },
    );
    sim.run_for(Duration::from_millis(1000));

    // Client verifies the self-certifying address, PoW-gates the intro, computes the SAME key.
    let client_key = client_descriptor_key(&address, service.pubkey(), epoch, &BEACON).unwrap();
    assert_eq!(
        client_key, key,
        "client derives the service's rendezvous key"
    );
    let nonce = pow::solve(&client_key, POW_BITS);
    assert!(
        pow::verify(&client_key, nonce, POW_BITS),
        "the intro PoW is valid"
    );
    // A forged key that the address does not certify yields no rendezvous at all.
    assert!(client_descriptor_key(&address, b"forged-key", epoch, &BEACON).is_none());

    // Client fetches the descriptor from the store.
    sim.inject(client_node, Command::Get { key: client_key });
    sim.run_for(Duration::from_millis(1000));
    let descriptor = sim
        .report()
        .retrievals()
        .filter(|(who, _, _)| *who == client_node)
        .find_map(|(_, _, v)| v.map(<[u8]>::to_vec))
        .expect("client retrieved the service descriptor");
    let service_coord = parse_triple(&descriptor).expect("descriptor is a coordinate");
    assert_eq!(service_coord, service_node);

    // Client reaches the service at the advertised coordinate.
    let before = sim.report().metrics.payloads_delivered;
    sim.inject(
        client_node,
        Command::Send {
            to: service_coord,
            payload: b"hello hidden service".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));
    assert_eq!(sim.report().metrics.payloads_delivered, before + 1);
    let (recv, sender, bytes) = sim.report().deliveries().last().unwrap();
    assert_eq!(recv, service_node, "the service received the client");
    assert_eq!(sender, client_node);
    assert_eq!(bytes, b"hello hidden service");

    // The rendezvous moves every epoch — no static location to seize.
    assert_ne!(
        descriptor_key(service.pubkey(), epoch, &BEACON),
        descriptor_key(service.pubkey(), epoch.next(), &BEACON)
    );
}

#[test]
fn a_client_with_only_the_address_cannot_forge_the_rendezvous() {
    // Only a public key the address certifies yields the rendezvous key (self-certifying, §12.2).
    let service = HiddenService::new(b"another-service".to_vec());
    let address = *service.address();
    assert!(client_descriptor_key(&address, service.pubkey(), Epoch::new(3), &BEACON).is_some());
    assert!(client_descriptor_key(&address, b"impostor", Epoch::new(3), &BEACON).is_none());
}
