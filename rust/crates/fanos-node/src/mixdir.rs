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
use fanos_field::Field;
use fanos_geometry::{Plane, Point};
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_quic::Client;
use fanos_rendezvous::{Epoch, MixDirectory};
use fanos_runtime::Notification;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::EpochDriver;
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

/// The mixnet **roster** of the base cell of plane `F`: every one of its `N` points (all seven, for a
/// Fano cell). A base cell *is* its plane, so every point is a potential mix hop; this is the membership
/// a client resolves keys over to discover the live directory ([`build_cell_mix_directory`]). It is the
/// coordinate list a hand-built map used to be — now derived from the geometry, not written by hand.
#[must_use]
pub fn cell_mix_coords<F: Field>() -> Vec<Coord> {
    (0..Plane::<F>::N as usize)
        .map(|i| Point::<F>::at(i).coords())
        .collect()
}

/// Assemble the **live** mix directory of the base cell for `epoch`: resolve every roster member's
/// ([`cell_mix_coords`]) published onion key and keep those currently answering. Unlike
/// [`build_mix_directory`] — which seals *one chosen circuit* and so is all-or-nothing (a single missing
/// member means re-draw) — this is a *best-effort roster view*: a member that is down, or has not yet
/// published for `epoch`, is simply absent, and the client draws its circuit from whoever is present. The
/// two compose: discover the live set here, draw a circuit over it, then (optionally) re-resolve exactly
/// that circuit with [`build_mix_directory`] to seal against keys confirmed present at draw time.
///
/// This is the “live directory from membership” the anonymous profile needs (audit #54): no central
/// directory, no hand-built map — the cell advertises itself through the overlay store, one relay per
/// epoch-tagged slot, and a client reads the current epoch's advertisement.
pub async fn build_cell_mix_directory<F: Field>(client: &Client, epoch: Epoch) -> MixDirectory {
    let mut dir = MixDirectory::new();
    for coord in cell_mix_coords::<F>() {
        if let Some(public) = resolve_mix_key(client, coord, epoch).await {
            dir.insert(coord, public);
        }
    }
    dir
}

/// Keep a relay's onion key **live** in the directory: spawn the task that (re)publishes the relay at
/// `coord` its current forward-secure onion public each epoch, so [`build_cell_mix_directory`] always
/// reads a key the relay can still peel with. This is the async closure of the E4∩E5 loop (see
/// [`EpochDriver`]): it publishes the genesis-epoch key at once, then follows the relay's own
/// [`Notification::BeaconReady`] stream — a mirror [`EpochDriver`] seeded from the same `onion_seed`
/// derives, without reaching into the spawned engine, exactly the key the relay's hosted router rotates
/// to, and republishes it at the new epoch's slot. `onion_seed` MUST be the seed the relay's
/// [`MixRelay`](crate::MixRelay) / [`ThresholdRouter`](fanos_aphantos::ThresholdRouter) was spawned with.
///
/// The task ends when the relay's notification stream closes (the node shut down). Must run inside a
/// tokio runtime.
#[must_use]
pub fn spawn_mix_publisher(client: Client, coord: Coord, onion_seed: [u8; 32]) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut driver = EpochDriver::new(coord, onion_seed);
        let mut events = client.subscribe();
        // Publish the genesis-epoch key immediately, so a circuit drawn before the first beacon can still
        // seal to this relay. Every later republish is driven by the relay's own BeaconReady.
        publish_mix_key(&client, coord, driver.epoch(), driver.public()).await;
        loop {
            match events.recv().await {
                Ok(Notification::BeaconReady { epoch, .. }) => {
                    // Advance the mirror ratchet to the beacon epoch; a stale/replayed epoch reports 0
                    // steps and nothing is republished. On a real advance, republish the now-current key.
                    if driver.advance_to(epoch) > 0 {
                        publish_mix_key(&client, coord, driver.epoch(), driver.public()).await;
                    }
                }
                // Other notifications are irrelevant to key rotation; a lagged stream only means we may
                // have missed an epoch, and the next BeaconReady's catch-up advance covers it.
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
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

    #[test]
    fn the_cell_roster_is_the_planes_points() {
        use fanos_field::F2;
        let roster = cell_mix_coords::<F2>();
        assert_eq!(
            roster.len(),
            7,
            "a Fano cell's mix roster is its seven points"
        );
        let mut sorted = roster.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 7, "the roster's coordinates are distinct");
        // The roster is exactly the geometry's points 0..N — the hand-built directory, now derived.
        let want: Vec<_> = (0..7).map(|i| Point::<F2>::at(i).coords()).collect();
        assert_eq!(roster, want, "roster member i is Point::at(i)");
    }
}
