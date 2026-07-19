//! Live mixnet key directory over the overlay store.
//!
//! The anonymous profile ([`crate::rendezvous`]) seals each onion hop to the forward-secure onion keys
//! of that hop line's members. In a test those keys are handed in directly; in a real network the
//! client must *discover* them. Each overlay node publishes its current-epoch onion public key at a
//! coordinate-**and-epoch**-derived store slot ([`publish_mix_key`]); a client assembling a circuit for
//! a given epoch resolves the keys of the members it needs ([`build_mix_directory`]) into the
//! [`MixDirectory`] the sealer expects — no hand-built map, no central directory.
//!
//! Forward secrecy (audit E4): the slot is tagged with the epoch, so each epoch's key lives at its own
//! address. A relay publishes its *current* onion public every epoch (the ratchet's `onion_public()`)
//! and ratchets its secret forward; a client resolves the epoch it is sealing for. An adversary who
//! compromises a relay later cannot recover a past epoch's secret, so recorded onions for retired
//! epochs are unpeelable — the directory only ever advertises keys the relay can still peel with.
//!
//! Trust: a key published at another node's slot is not self-certifying, so a forged key can only make
//! that member unable to peel (its real secret does not match) — a hop still needs `t` genuine members,
//! so this degrades to a liveness fault (the circuit fails and is re-drawn), never deanonymization.
//! Binding a member's key to its cert-derived coordinate is a later hardening step.

use fanos_diaulos::Coord;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_quic::Client;
use fanos_rendezvous::{Epoch, MixDirectory};

use crate::resolve::RESOLVE_TIMEOUT;

/// The overlay store slot a node's per-epoch onion key is published at — domain-separated from every
/// other use of the store, keyed by the node's coordinate **and the epoch**. Tagging the slot with the
/// epoch is what makes forward secrecy (audit E4) reachable over a real network: each epoch's onion
/// public lives at its own address, so a client resolves the *current* epoch's key and a relay that has
/// ratcheted past an epoch no longer answers for it. The `Client` hashes this into the storage address.
fn mix_key_slot(coord: Coord, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/mix-key/".to_vec();
    key.extend_from_slice(&fanos_geometry::encode_triple(coord));
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// Publish this node's forward-secure onion public key for `epoch` at its coordinate slot, so clients
/// building anonymous circuits through it in that epoch can seal onion layers to it. Called each epoch
/// with the relay's *current* onion public (the ratchet's `onion_public()`), so the slot always holds
/// a key the relay can still peel with. `false` if the store rejected the write.
pub async fn publish_mix_key(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    public: &HybridKemPublic,
) -> bool {
    client
        .put(mix_key_slot(coord, epoch), public.encode())
        .await
}

/// Resolve the onion public key published by the node at `coord` for `epoch`, or `None` if none is
/// published, the lookup times out, or the stored bytes are not a valid key.
pub async fn resolve_mix_key(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
) -> Option<HybridKemPublic> {
    let bytes = tokio::time::timeout(RESOLVE_TIMEOUT, client.get(mix_key_slot(coord, epoch)))
        .await
        .ok()??;
    HybridKemPublic::decode(&bytes)
}

/// Assemble a [`MixDirectory`] over `coords` by resolving each node's published onion key **for
/// `epoch`** from the store. Returns `None` if any member's key cannot be resolved — the circuit's onion
/// could not be sealed, so the caller should re-draw the circuit rather than proceed with a partial
/// directory. The directory is epoch-scoped: seal onions for the same epoch the directory was built for,
/// so every layer is sealed to a key its relay still holds.
pub async fn build_mix_directory(
    client: &Client,
    coords: &[Coord],
    epoch: Epoch,
) -> Option<MixDirectory> {
    let mut dir = MixDirectory::new();
    for &coord in coords {
        dir.insert(coord, resolve_mix_key(client, coord, epoch).await?);
    }
    Some(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_key_slots_are_deterministic_distinct_and_domain_separated() {
        let e0 = Epoch::ZERO;
        let a = mix_key_slot([1, 2, 3], e0);
        assert_eq!(
            a,
            mix_key_slot([1, 2, 3], e0),
            "same coordinate + epoch → same slot"
        );
        assert_ne!(
            a,
            mix_key_slot([1, 2, 4], e0),
            "distinct coordinates → distinct slots"
        );
        // Forward secrecy hinges on this: the SAME relay's key lives at a DIFFERENT slot each epoch, so a
        // client resolves the current epoch's key and a retired epoch's key is simply a different address.
        assert_ne!(
            a,
            mix_key_slot([1, 2, 3], Epoch::new(1)),
            "same coordinate, distinct epoch → distinct slots (audit E4)"
        );
        assert!(
            a.starts_with(b"FANOS-v1/mix-key/"),
            "the slot is domain-separated from every other store use"
        );
        assert_eq!(
            a.len(),
            b"FANOS-v1/mix-key/".len() + 12 + 8,
            "prefix followed by the 12-byte coordinate and the 8-byte big-endian epoch"
        );
    }
}
