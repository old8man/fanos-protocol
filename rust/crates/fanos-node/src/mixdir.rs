//! Live mixnet key directory over the overlay store.
//!
//! The anonymous profile ([`crate::rendezvous`]) seals each onion hop to the KEM keys of that hop
//! line's members. In a test those keys are handed in directly; in a real network the client must
//! *discover* them. Each overlay node publishes its hybrid KEM public key at a coordinate-derived
//! store slot ([`publish_mix_key`]); a client assembling a circuit resolves the keys of the members it
//! needs ([`build_mix_directory`]) into the [`MixDirectory`] the sealer expects — no hand-built map, no
//! central directory.
//!
//! Trust: a key published at another node's slot is not self-certifying, so a forged key can only make
//! that member unable to peel (its real secret does not match) — a hop still needs `t` genuine members,
//! so this degrades to a liveness fault (the circuit fails and is re-drawn), never deanonymization.
//! Binding a member's key to its cert-derived coordinate is a later hardening step.

use fanos_diaulos::Coord;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_quic::Client;
use fanos_rendezvous::MixDirectory;

use crate::resolve::RESOLVE_TIMEOUT;

/// The overlay store slot a node's KEM key is published at — domain-separated from every other use of
/// the store, keyed by the node's coordinate. The `Client` hashes this into the storage address.
fn mix_key_slot(coord: Coord) -> Vec<u8> {
    let mut key = b"FANOS-v1/mix-key/".to_vec();
    for w in coord {
        key.extend_from_slice(&w.to_be_bytes());
    }
    key
}

/// Publish this node's hybrid KEM public key at its coordinate slot, so clients building anonymous
/// circuits through it can seal onion layers to it. `false` if the store rejected the write.
pub async fn publish_mix_key(client: &Client, coord: Coord, public: &HybridKemPublic) -> bool {
    client.put(mix_key_slot(coord), public.encode()).await
}

/// Resolve the hybrid KEM public key published by the node at `coord`, or `None` if none is published,
/// the lookup times out, or the stored bytes are not a valid key.
pub async fn resolve_mix_key(client: &Client, coord: Coord) -> Option<HybridKemPublic> {
    let bytes = tokio::time::timeout(RESOLVE_TIMEOUT, client.get(mix_key_slot(coord)))
        .await
        .ok()??;
    HybridKemPublic::decode(&bytes)
}

/// Assemble a [`MixDirectory`] over `coords` by resolving each node's published KEM key from the store.
/// Returns `None` if any member's key cannot be resolved — the circuit's onion could not be sealed, so
/// the caller should re-draw the circuit rather than proceed with a partial directory.
pub async fn build_mix_directory(client: &Client, coords: &[Coord]) -> Option<MixDirectory> {
    let mut dir = MixDirectory::new();
    for &coord in coords {
        dir.insert(coord, resolve_mix_key(client, coord).await?);
    }
    Some(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_key_slots_are_deterministic_distinct_and_domain_separated() {
        let a = mix_key_slot([1, 2, 3]);
        assert_eq!(a, mix_key_slot([1, 2, 3]), "same coordinate → same slot");
        assert_ne!(a, mix_key_slot([1, 2, 4]), "distinct coordinates → distinct slots");
        assert!(
            a.starts_with(b"FANOS-v1/mix-key/"),
            "the slot is domain-separated from every other store use"
        );
        assert_eq!(
            a.len(),
            b"FANOS-v1/mix-key/".len() + 12,
            "prefix followed by the 12-byte coordinate"
        );
    }
}
