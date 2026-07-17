//! CALYPSO-Balance end to end over the real overlay (spec §12.6): a **master** hidden-service domain
//! fronting a fleet of **backend instances**, under FANOS's offline-root / epoch-signing-key
//! hierarchy. The offline root certifies an epoch signing key; that key signs the descriptor and
//! each backend delegation (real hybrid Ed25519 ‖ ML-DSA-65 signatures). The descriptor is published
//! to the L4 store at the master's per-epoch key (LRC-replicated across the cell, so the fetch is
//! fault-tolerant); a client fetches it, verifies the *whole chain* — address→root→signing→backend —
//! then load-balances by weighted rendezvous hashing and fails over down the ranking. Compromising a
//! backend cannot forge the descriptor or a delegation, and the root secret never touches the
//! serving path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_calypso::balance::{InstanceRef, MasterDescriptor, SigningKeyCert, delegation_message};
use fanos_calypso::{ServiceAddress, master_descriptor_key};
use fanos_field::F2;
use fanos_pqcrypto::sig::HybridSignature;
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{Sim, spawn_cell};

/// The real hybrid-signature verification predicate a client uses: reconstruct the verifier and the
/// signature from bytes and check both post-quantum components.
fn hybrid_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match (
        HybridVerifier::decode(pubkey),
        HybridSignature::from_bytes(sig),
    ) {
        (Some(v), Some(s)) => v.verify(msg, &s),
        _ => false,
    }
}

/// Build a fully-signed master descriptor under the offline-root / epoch-signing-key hierarchy: the
/// `root` (offline) certifies the `signing` key for the epoch window; the signing key signs the
/// descriptor and every backend delegation. `backends` are `(coordinate, keypair seed, weight)`.
fn signed_descriptor(
    root: &HybridSigSecret,
    root_pubkey: &[u8],
    signing: &HybridSigSecret,
    signing_pubkey: &[u8],
    epoch: u32,
    backends: &[(Triple, &[u8], u16)],
) -> MasterDescriptor {
    let (valid_from, valid_until) = (epoch, epoch + 4);
    let root_sig = root
        .sign(&SigningKeyCert::signing_message(
            root_pubkey,
            signing_pubkey,
            valid_from,
            valid_until,
        ))
        .to_bytes();
    let signing_cert = SigningKeyCert {
        signing_pubkey: signing_pubkey.to_vec(),
        valid_from,
        valid_until,
        root_sig,
    };

    let instances = backends
        .iter()
        .map(|(coord, seed, weight)| {
            let (_sk, vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(seed));
            let instance_pubkey = vk.encode();
            let msg = delegation_message(root_pubkey, epoch, &instance_pubkey, *coord, *weight);
            InstanceRef {
                instance_pubkey,
                coordinate: *coord,
                weight: *weight,
                delegation_sig: signing.sign(&msg).to_bytes(),
            }
        })
        .collect();
    let mut desc = MasterDescriptor {
        root_pubkey: root_pubkey.to_vec(),
        signing_cert,
        epoch,
        instances,
        descriptor_sig: Vec::new(),
    };
    desc.descriptor_sig = signing.sign(&desc.signing_bytes()).to_bytes();
    desc
}

#[test]
fn a_master_domain_load_balances_across_verified_backends_over_the_overlay() {
    let mut sim = Sim::new(0xBA1);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    // The OFFLINE root identity (the operator's key; never on a serving node) and the online epoch
    // signing key it certifies.
    let (root, root_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"root-identity"));
    let root_pubkey = root_vk.encode();
    let (signing, signing_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"epoch-signer"));
    let signing_pubkey = signing_vk.encode();
    let address = ServiceAddress::from_bundle(&root_pubkey);
    let epoch = 12;

    // Three backend instances at distinct cell coordinates, one with double weight.
    let backends: Vec<(Triple, &[u8], u16)> = vec![
        (cell[0], b"backend-a".as_slice(), 1),
        (cell[2], b"backend-b".as_slice(), 2),
        (cell[4], b"backend-c".as_slice(), 1),
    ];
    let descriptor = signed_descriptor(
        &root,
        &root_pubkey,
        &signing,
        &signing_pubkey,
        epoch,
        &backends,
    );

    // Publish the signed descriptor to the L4 store at the master's per-epoch descriptor key.
    let publisher = cell[6];
    let key = master_descriptor_key(&root_pubkey, epoch);
    sim.inject(
        publisher,
        Command::Put {
            key: key.clone(),
            value: descriptor.encode(),
        },
    );
    sim.run_for(Duration::from_millis(1000));

    // A client that knows only the .fanos address + master pubkey fetches and verifies it.
    let client = cell[5];
    sim.inject(client, Command::Get { key });
    sim.run_for(Duration::from_millis(1000));
    let bytes = sim
        .report()
        .retrievals()
        .filter(|(who, _, _)| *who == client)
        .find_map(|(_, _, v)| v.map(<[u8]>::to_vec))
        .expect("client retrieved the master descriptor");
    let fetched = MasterDescriptor::decode(&bytes).expect("descriptor decodes");
    assert!(
        fetched.verify(&address, hybrid_verify),
        "the master signature and every delegation verify under real hybrid PQ keys"
    );

    // The client selects a backend for its request cookie and connects to it.
    let cookie = b"client-request-cookie";
    let chosen = fetched.select_instance(cookie, 0).unwrap();
    let before = sim.report().metrics.payloads_delivered;
    sim.inject(
        client,
        Command::Send {
            to: chosen.coordinate,
            payload: b"GET / (balanced)".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));
    assert_eq!(sim.report().metrics.payloads_delivered, before + 1);
    let (recv, _sender, _bytes) = sim.report().deliveries().last().unwrap();
    assert_eq!(
        recv, chosen.coordinate,
        "the request reached the chosen backend"
    );

    // Load spreading: distinct cookies map across more than one backend.
    let picks: std::collections::BTreeSet<Triple> = (0..40u32)
        .map(|i| {
            fetched
                .select_instance(&i.to_be_bytes(), 0)
                .unwrap()
                .coordinate
        })
        .collect();
    assert!(picks.len() >= 2, "requests spread across multiple backends");

    // A publisher cannot swap in an undelegated backend: flip a coordinate and re-verify fails.
    let mut tampered = fetched.clone();
    tampered.instances[0].coordinate = cell[3];
    assert!(
        !tampered.verify(&address, hybrid_verify),
        "a tampered instance list is rejected (master signature no longer matches)"
    );
}

#[test]
fn a_client_fails_over_when_a_backend_is_down() {
    let mut sim = Sim::new(0xBA2);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    let (root, root_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(b"failover-root"));
    let root_pubkey = root_vk.encode();
    let (signing, signing_vk) =
        HybridSigSecret::generate(&mut SeedRng::from_seed(b"failover-signer"));
    let signing_pubkey = signing_vk.encode();
    let epoch = 3;
    let backends: Vec<(Triple, &[u8], u16)> = vec![
        (cell[1], b"b1".as_slice(), 1),
        (cell[3], b"b2".as_slice(), 1),
        (cell[5], b"b3".as_slice(), 1),
    ];
    let descriptor = signed_descriptor(
        &root,
        &root_pubkey,
        &signing,
        &signing_pubkey,
        epoch,
        &backends,
    );

    let client = cell[0];
    let cookie = b"sticky-cookie";
    let first = descriptor.select_instance(cookie, 0).unwrap().coordinate;

    // The primary choice is down; the client fails over to the next attempt, which must differ and
    // still be a delegated backend it can reach.
    sim.crash(first);
    sim.run_for(Duration::from_millis(500));
    let second = descriptor.select_instance(cookie, 1).unwrap().coordinate;
    assert_ne!(first, second, "failover selects a different backend");

    let before = sim.report().metrics.payloads_delivered;
    sim.inject(
        client,
        Command::Send {
            to: second,
            payload: b"retry".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));
    assert_eq!(
        sim.report().metrics.payloads_delivered,
        before + 1,
        "the failover backend serves the request"
    );
}
