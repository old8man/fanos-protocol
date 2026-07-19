//! ONOMA name resolution end-to-end over the real overlay + L4 store (spec Part XII,
//! `docs/design-names.md` §5–§6). A service seals its descriptor — encrypted under an
//! address-gated key and PoW-stamped — and publishes it at the rotating, unenumerable epoch slot;
//! a client that knows only the `.fanos` address resolves and *authenticates* it (client is the
//! authority: `H(bundle) == addr`). This drives the byte-for-byte `OverlayNode` (Put / Get) that
//! ships — ONOMA is an application over it, not a second stack.
//!
//! The L4 store is keyed by the descriptor's per-epoch **lookup key** `L = H(addr ‖ epoch)`, so a
//! storage node holds an opaque, address-gated blob at a slot it cannot invert to the address.
//!
//! (Note: full squat-DoS *selection* — the store holding several candidate blobs per slot so a
//! client can pick the one that opens — needs multi-value store support; tracked as a follow-up.
//! The security properties proven here are per-epoch rotation, address-gated confidentiality, and
//! tamper/impersonation rejection.)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_calypso::descriptor::{Descriptor, SealedDescriptor, open, seal};
use fanos_field::F2;
use fanos_onoma::{Address, Epoch, lookup_key};
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Sim, spawn_cell};

/// The descriptor-publish PoW difficulty (small, for a fast test).
const POW_BITS: u32 = 8;

fn service_descriptor(epoch: Epoch, bundle: &[u8]) -> Descriptor {
    Descriptor {
        epoch,
        bundle: bundle.to_vec(),
        metadata: b"profiles=full".to_vec(),
        cert: b"epoch-cert".to_vec(),
        sig: b"epoch-sig".to_vec(),
    }
}

fn fetch(sim: &Sim, who: fanos_runtime::Triple) -> Option<Vec<u8>> {
    sim.report()
        .retrievals()
        .filter(|(node, _, _)| *node == who)
        .find_map(|(_, _, v)| v.map(<[u8]>::to_vec))
}

#[test]
fn a_client_with_only_the_address_resolves_and_authenticates_the_descriptor() {
    let mut sim = Sim::new(0x0_0_1);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    let bundle = b"onoma-service-hybrid-bundle".to_vec();
    let addr = Address::from_bundle(&bundle);
    let epoch = Epoch::new(7);
    let desc = service_descriptor(epoch, &bundle);
    let sealed = seal(&addr, epoch, &desc, POW_BITS).unwrap();

    let service_node = cell[0];
    let client_node = cell[3];

    // Service publishes at the rotating, unenumerable epoch slot `L = H(addr ‖ epoch)`.
    let slot = lookup_key(&addr, epoch).to_vec();
    sim.inject(
        service_node,
        Command::Put {
            key: slot.clone(),
            value: sealed.encode(),
        },
    );
    sim.run_for(Duration::from_millis(1000));

    // Client — knowing only the `.fanos` address — derives the same slot and fetches.
    let name = addr.to_name();
    let resolved = Address::parse(&name).unwrap();
    assert_eq!(resolved, addr, "the .fanos name round-trips to the address");
    let client_slot = lookup_key(&resolved, epoch).to_vec();
    assert_eq!(client_slot, slot, "client derives the same epoch slot");

    sim.inject(client_node, Command::Get { key: client_slot });
    sim.run_for(Duration::from_millis(1000));

    let value = fetch(&sim, client_node).expect("client retrieved the descriptor blob");
    let opened = open(
        &resolved,
        epoch,
        &SealedDescriptor::decode(&value).unwrap(),
        POW_BITS,
    )
    .expect("descriptor opens and self-certifies");
    assert_eq!(opened, desc);
    assert!(
        resolved.verifies(&opened.bundle),
        "H(bundle) == addr: the client is the authority"
    );
}

#[test]
fn a_storage_node_cannot_open_the_address_gated_descriptor() {
    let mut sim = Sim::new(0x0_0_2);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    let bundle = b"confidential-service".to_vec();
    let addr = Address::from_bundle(&bundle);
    let epoch = Epoch::new(11);
    let sealed = seal(&addr, epoch, &service_descriptor(epoch, &bundle), POW_BITS).unwrap();

    let slot = lookup_key(&addr, epoch).to_vec();
    sim.inject(
        cell[0],
        Command::Put {
            key: slot.clone(),
            value: sealed.encode(),
        },
    );
    sim.run_for(Duration::from_millis(1000));

    // Any node fetches the raw blob…
    sim.inject(cell[2], Command::Get { key: slot });
    sim.run_for(Duration::from_millis(1000));
    let value = fetch(&sim, cell[2]).expect("blob is retrievable");
    let blob = SealedDescriptor::decode(&value).unwrap();

    // …but without the address it cannot open it (address-gated AEAD; difficulty 0 isolates the
    // AEAD gate from the address-bound PoW).
    let wrong = Address::from_bundle(b"a-different-service");
    assert!(open(&wrong, epoch, &blob, 0).is_err());

    // The plaintext bundle never appears in the stored ciphertext — content is opaque.
    assert!(
        !blob
            .ciphertext
            .windows(bundle.len())
            .any(|w| w == bundle.as_slice()),
        "the service bundle must not be recoverable from the stored blob"
    );
}

#[test]
fn the_lookup_slot_and_descriptor_are_epoch_bound() {
    let mut sim = Sim::new(0x0_0_3);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    let bundle = b"rotating-service".to_vec();
    let addr = Address::from_bundle(&bundle);
    let sealed7 = seal(
        &addr,
        Epoch::new(7),
        &service_descriptor(Epoch::new(7), &bundle),
        POW_BITS,
    )
    .unwrap();

    // The slot rotates every epoch — no static location to seize.
    assert_ne!(
        lookup_key(&addr, Epoch::new(7)),
        lookup_key(&addr, Epoch::new(8))
    );

    let slot7 = lookup_key(&addr, Epoch::new(7)).to_vec();
    sim.inject(
        cell[0],
        Command::Put {
            key: slot7,
            value: sealed7.encode(),
        },
    );
    sim.run_for(Duration::from_millis(1000));

    // Even if the epoch-7 blob is fetched, it does not open under epoch 8 (key + epoch bound).
    sim.inject(
        cell[3],
        Command::Get {
            key: lookup_key(&addr, Epoch::new(7)).to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(1000));
    let value = fetch(&sim, cell[3]).expect("epoch-7 blob retrievable at its own slot");
    let blob = SealedDescriptor::decode(&value).unwrap();
    assert!(
        open(&addr, Epoch::new(8), &blob, 0).is_err(),
        "an epoch-7 descriptor must not resolve for epoch 8"
    );
}

#[test]
fn a_tampered_or_junk_blob_is_rejected_client_side() {
    let mut sim = Sim::new(0x0_0_4);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    let bundle = b"integrity-service".to_vec();
    let addr = Address::from_bundle(&bundle);
    let epoch = Epoch::new(5);
    let sealed = seal(&addr, epoch, &service_descriptor(epoch, &bundle), POW_BITS).unwrap();

    // A flipped ciphertext byte fails AEAD authentication.
    let mut tampered = sealed.clone();
    tampered.ciphertext[0] ^= 0xFF;
    assert!(open(&addr, epoch, &tampered, POW_BITS).is_err());

    // Arbitrary junk published at the slot never opens as a valid descriptor.
    let junk = b"totally-not-a-descriptor-blob".to_vec();
    let slot = lookup_key(&addr, epoch).to_vec();
    sim.inject(
        cell[0],
        Command::Put {
            key: slot.clone(),
            value: junk,
        },
    );
    sim.run_for(Duration::from_millis(1000));
    sim.inject(cell[3], Command::Get { key: slot });
    sim.run_for(Duration::from_millis(1000));
    if let Some(value) = fetch(&sim, cell[3]) {
        let rejected = match SealedDescriptor::decode(&value) {
            Ok(blob) => open(&addr, epoch, &blob, POW_BITS).is_err(),
            Err(_) => true,
        };
        assert!(
            rejected,
            "a junk blob must never open as a valid descriptor"
        );
    }
}
