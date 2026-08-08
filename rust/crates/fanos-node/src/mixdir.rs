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
use fanos_runtime::Command;
use tokio::task::JoinHandle;

use crate::DIRECTORY_SLOT_EPOCHS;
use crate::{EpochDriver, next_epoch};
use fanos_primitives::BeaconSeed;
use fanos_vrf::{VrfProof, VrfPublic};

use crate::bound::Entitlement;
use crate::resolve::{STORE_TIMEOUT, Read, resolve_directory};

/// How a publisher obtains its coordinate proof: `(epoch, beacon) → (identity bytes, VRF public, proof)`.
///
/// A closure rather than the VRF secret, so a signing key never reaches a publisher or a fixture that spawns one — its home
/// is `fanos_quic::NodeHandle::coordinate_prover`, where the credentials already live.
pub use fanos_quic::CoordinateProver;

/// Parse and **verify** a coordinate-bound onion-key record against the coordinate its slot names (sans-I/O).
///
/// `None` on malformed bytes, a proof that does not verify for `(id, epoch, beacon)`, or a coordinate the publisher's own
/// probe walk never reaches. The binding, what it costs an attacker, and why it applies only under VRF coordinates are all
/// in [`crate::bound`]; this is the mix directory's payload on top of it. The whole trust check — the resolver only fetches
/// bytes and calls this.
#[must_use]
pub fn parse_bound_record<F: Field>(
    bytes: &[u8],
    coord: Coord,
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> Option<HybridKemPublic> {
    let (_, payload) = Entitlement::open::<F>(bytes, coord, epoch, beacon)?;
    HybridKemPublic::decode(payload)
}

/// Publish this node's onion key as a **coordinate-bound** record (S1-M3), at its live coordinate slot.
pub async fn publish_bound_mix_key(
    client: &Client,
    proof: &(Vec<u8>, VrfPublic, VrfProof),
    epoch: Epoch,
    public: &HybridKemPublic,
) -> bool {
    let (id, vrf_public, vrf_proof) = proof;
    let landed = client
        .put_ephemeral(
            mix_key_slot(client.address(), epoch),
            Entitlement::encode(id, vrf_public, vrf_proof, &public.encode()),
            DIRECTORY_SLOT_EPOCHS,
        )
        .await;
    crate::note_publish(client, crate::Directory::MixKey, epoch, landed)
}

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
    let landed = client
        .put_ephemeral(mix_key_slot(coord, epoch), public.encode(), DIRECTORY_SLOT_EPOCHS)
        .await;
    crate::note_publish(client, crate::Directory::MixKey, epoch, landed)
}

/// Resolve the onion public key published by the node at `coord` for `epoch`, or `None` if none is
/// published, the lookup times out, or the stored bytes are not a valid key.
pub async fn resolve_mix_key(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
) -> Option<HybridKemPublic> {
    let bytes = tokio::time::timeout(STORE_TIMEOUT, client.get(mix_key_slot(coord, epoch)))
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
/// The second value is **whether every read concluded**, and a caller must act on it.
///
/// It used to be discarded, so a caller could not tell "this cell has three mix relays" from "four reads timed
/// out". Those are different facts and they call for opposite responses, and the difference matters more here
/// than in any other directory, because every anonymous-path construction gates on membership:
/// `select_drop_line` skips a line whose members are absent from the directory, `random_hops` draws only from
/// what resolved, and `HostRegister::onion` refuses a hop it cannot seal to. All three still *succeed* over a
/// partial view — they simply route around whatever did not resolve.
///
/// **What the flag catches, exactly.** A missing record is a *definite* `Absent`, so a node that has not
/// published a mix key leaves the scan complete — and routing around it is right, since it cannot be a hop.
/// `complete` goes false only when a read **timed out**, which is the case that is not a fact about the cell
/// at all but about the reader's luck. An adversary that can slow store reads for a chosen subset of slots —
/// far cheaper than compromising a node — thereby steers circuit placement toward the lines it left alone,
/// while the `2t − 1` cost argument in `docs/design-anonymity-substrate.md` assumes the draw is from the
/// *cell*. That is the hole this closes.
///
/// Every sibling directory already returns it (`build_capability_directory`, `build_cell_setpoint`,
/// `read_diagnosis_window`) and the role loop already declines to act on a partial view. This one was the
/// exception.
pub async fn build_cell_mix_directory<F: Field>(
    client: &Client,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> (MixDirectory, bool) {
    let scan = resolve_directory(client, cell_mix_coords::<F>(), move |client, coord| async move {
        read_mix_key_in_mode::<F>(&client, coord, epoch, beacon).await
    })
    .await;
    let complete = scan.complete();
    let mut dir = MixDirectory::new();
    for (coord, public) in scan.found {
        dir.insert(coord, public);
    }
    (dir, complete)
}

/// One slot read, in whichever mode the cell runs.
///
/// `Some(beacon)` means coordinates are **VRF-derived**, so a record must prove the slot's coordinate is on its
/// publisher's walk ([`parse_bound_record`]) — a forged entry is a definite `Absent`. `None` means a **pinned** cell, where
/// no publisher can produce such a proof and no reader can check one, so the legacy unbound record is read as-is.
///
/// The mode is an `Option<BeaconSeed>` rather than a `verify: bool` deliberately: having a beacon *is* the VRF mode, and
/// its absence is an absent mechanism rather than a disabled check. Nothing in a pinned cell can supply one.
async fn read_mix_key_in_mode<F: Field>(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Read<HybridKemPublic> {
    match tokio::time::timeout(STORE_TIMEOUT, client.get(mix_key_slot(coord, epoch))).await {
        Ok(bytes) => Read::found_or_absent(bytes.and_then(|b| match beacon {
            Some(seed) => parse_bound_record::<F>(&b, coord, epoch, &seed),
            None => HybridKemPublic::decode(&b),
        })),
        Err(_) => Read::Unknown,
    }
}


/// Keep a relay's onion key **live** in the directory: spawn the task that (re)publishes the relay at
/// `coord` its current forward-secure onion public each epoch, so [`build_cell_mix_directory`] always
/// reads a key the relay can still peel with. This is the async closure of the E4∩E5 loop (see
/// [`EpochDriver`]): it publishes the genesis-epoch key at once, then follows the relay's own
/// [`Notification::BeaconReady`](fanos_runtime::Notification::BeaconReady) stream — a mirror [`EpochDriver`] seeded from the same `onion_seed`
/// derives, without reaching into the spawned engine, exactly the key the relay's hosted router rotates
/// to, and republishes it at the new epoch's slot. `onion_seed` MUST be the seed the relay's
/// [`MixRelay`](crate::MixRelay) / [`ThresholdRouter`](fanos_aphantos::ThresholdRouter) was spawned with.
///
/// The task ends when the relay's notification stream closes (the node shut down). Must run inside a
/// tokio runtime.
/// Publishes at the node's **live** coordinate, re-read on every cycle rather than captured at spawn.
///
/// A coordinate moves — every epoch by the beacon reshuffle (spec §L3), and within an epoch when a better claim displaces
/// this node. A publisher that captured it kept writing to the point the node had *left*, so the cell's directory scan found
/// a descriptor at an unoccupied point and none at the occupied one. Measured as rosters frozen one short of the occupied
/// count (`[4, 4, 4, 1, 4]` with five points held) after live coordinate resolution started actually moving nodes.
#[must_use]
pub fn spawn_mix_publisher(
    client: Client,
    onion_seed: [u8; 32],
    prover: Option<CoordinateProver>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut driver = EpochDriver::new(client.address(), onion_seed);
        let mut beacons = client.beacons();
        // A coordinate-**bound** record (S1-M3), which a `Node` can always produce because it always runs VRF coordinates.
        // Genesis first, so a circuit drawn before the first beacon can still seal to this relay — against **this
        // network's** genesis seed, which is what the node was seated against. Naming the constant here published a
        // record bound to a coordinate the node does not occupy, so the reader verified it and found nothing: an
        // empty mix directory for the whole genesis epoch on every network with a beacon.
        let mut beacon = client.genesis();
        // `Some` ⇒ VRF coordinates, so publish a bound record; `None` ⇒ a pinned cell, where no proof is possible and the
        // legacy unbound record is all there is. Symmetric with the reader's `Option<BeaconSeed>`: on both ends, the
        // `Option` says whether the mechanism exists here, not whether someone chose to use it.
        let publish = async |client: &Client, epoch: Epoch, beacon: &BeaconSeed, key: &HybridKemPublic| match &prover {
            Some(prove) => publish_bound_mix_key(client, &prove(epoch, beacon), epoch, key).await,
            None => publish_mix_key(client, client.address(), epoch, key).await,
        };
        publish(&client, driver.epoch(), &beacon, driver.public()).await;
        // Latest-state, not the notification stream: a relay whose key is missing from the directory for an
        // epoch cannot be routed through for that epoch, and the broadcast could drop the round that says so
        // (#86). `advance_to` already handles a multi-step catch-up, which is what a skipped epoch produces.
        while let Some((epoch, seed)) = next_epoch(&mut beacons, driver.epoch()).await {
            // The record binds `(id, epoch, beacon)`, so a republish must use the beacon of the epoch it
            // publishes for — carrying the old one forward would produce a record no reader can verify.
            beacon = seed;
            if driver.advance_to(epoch) > 0 {
                publish(&client, driver.epoch(), &beacon, driver.public()).await;
            }
        }
    })
}

/// Keep this node's **combiner** side supplied with the epoch's mix directory.
///
/// A cell node is a potential meeting combiner for any hidden service whose key lands on its line, and a combiner
/// must seal the forward onion to a registered host's dead-drop — which needs that line's member keys. It cannot
/// resolve them itself: [`RendezvousRelay`](crate::rendezvous_relay::RendezvousRelay) is a sans-I/O engine and
/// [`build_cell_mix_directory`] is a store lookup. So an async sibling resolves and hands it over through
/// [`Command::Control`], which is local by construction — key material may be installed from a command precisely
/// because, unlike a frame, no peer can produce one.
///
/// **The registration used to carry those keys instead.** Measured, that cost `q + 1` keys per hop — ~3.7 KB at
/// `q = 2` and ~39 KB at `q = 31` — against a fixed 7041-byte onion body, so a registration did not fit on any
/// plane past Fano even before authentication added an identity bundle and a signature.
///
/// A rebuild immediately after a beacon advance may see peers that have not yet republished, so the directory can
/// start an epoch incomplete; it is replaced whole on the next advance, and a combiner that cannot seal simply
/// does not forward. That is the correct failure: a partial directory never produces a *wrong* route.
pub fn spawn_mix_directory_feeder<F: Field>(client: Client, vrf_coordinates: bool) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut beacons = client.beacons();
        let install = async |client: &Client, epoch: Epoch, beacon: BeaconSeed| {
            // `.0`: a partial view is *safe* on this side, for the reason the doc above gives — a combiner
            // that cannot seal simply does not forward, so an incomplete directory produces no route rather
            // than a wrong one. The host side is the opposite (`rotate_host`) and must refuse.
            let (dir, _complete) =
                build_cell_mix_directory::<F>(client, epoch, vrf_coordinates.then_some(beacon)).await;
            if !dir.is_empty() {
                client.command(Command::Control {
                    tag: fanos_rendezvous::CONTROL_MIX_DIRECTORY,
                    body: dir.encode(),
                });
            }
        };
        // Genesis first, and for the same reason `spawn_mix_publisher` publishes at genesis before its loop: a
        // cell whose beacon has not advanced yet still has hosts registering and clients dialing, and a combiner
        // with no directory cannot forward. Waiting for the first `BeaconReady` would leave the whole genesis
        // epoch unserved — which is not a corner case, it is how every fixed-epoch deployment runs.
        install(&client, Epoch::ZERO, client.genesis()).await;
        // A combiner with a stale directory seals to keys the line has ratcheted past, so this must not be
        // able to sleep through an epoch — latest-state, not the lossy stream (#86).
        let mut cur = Epoch::ZERO;
        while let Some((epoch, seed)) = next_epoch(&mut beacons, cur).await {
            cur = epoch;
            install(&client, epoch, seed).await;
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_vrf::{coordinate_output, probe_index_of};
    use fanos_field::F7;
    use fanos_pqcrypto::{HybridKemSecret, SeedRng};
    use fanos_vrf::{VrfSecret, prove_coordinate, probe_point};

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

    /// An identity with its coordinate proof for `(epoch, beacon)`, and an onion key to advertise.
    fn relay(seed: u8, epoch: Epoch, beacon: &BeaconSeed) -> (Vec<u8>, VrfPublic, VrfProof, HybridKemPublic) {
        let sk = VrfSecret::from_seed([seed; 32]);
        let id = alloc_id(seed);
        let (_, proof) = prove_coordinate::<F7>(&sk, &id, epoch, beacon);
        let (_, key) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[seed, 0xAA]));
        (id, sk.public(), proof, key)
    }

    fn alloc_id(seed: u8) -> Vec<u8> {
        format!("relay-{seed}").into_bytes()
    }

    #[test]
    fn a_bound_record_verifies_at_a_coordinate_on_its_publishers_walk() {
        // The property S1-M3 is about: the record is only accepted where its publisher can prove the coordinate belongs to
        // it. Every point of the publisher's own walk qualifies — the check is walk membership, not a single index.
        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let (id, public, proof, key) = relay(5, epoch, &beacon);
        let record = Entitlement::encode(&id, &public, &proof, &key.encode());
        let output = coordinate_output(&public, &id, epoch, &beacon, &proof).unwrap();

        for k in 0..fanos_vrf::probe_bound::<F7>() {
            let mine = probe_point::<F7>(&output, k).coords();
            assert!(
                parse_bound_record::<F7>(&record, mine, epoch, &beacon).is_some(),
                "step {k} of the publisher's own walk must verify"
            );
        }
    }

    #[test]
    fn a_record_planted_at_another_coordinate_is_refused() {
        // The forgery the unbound slot accepted for free: publishing a key at a relay's slot to make it unable to peel.
        // A point off the publisher's line cannot be proven, so the record is a definite Absent rather than a Found.
        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let (id, public, proof, key) = relay(5, epoch, &beacon);
        let record = Entitlement::encode(&id, &public, &proof, &key.encode());
        let output = coordinate_output(&public, &id, epoch, &beacon, &proof).unwrap();

        let mut refused = 0;
        for i in 0..Plane::<F7>::N as usize {
            let p = Point::<F7>::at(i);
            if probe_index_of::<F7>(&output, &p).is_none() {
                assert!(parse_bound_record::<F7>(&record, p.coords(), epoch, &beacon).is_none());
                refused += 1;
            }
        }
        // A line holds q+1 of q²+q+1 points, so on PG(2,7) that is 8 of 57 provable and 49 refused. If this were 0 the
        // test would be asserting nothing.
        assert_eq!(refused, 49, "every point off the publisher's line is refused");
    }

    #[test]
    fn a_record_is_bound_to_its_epoch_and_its_beacon() {
        // The proof is over `(id, epoch, beacon)`, so a record replayed into another epoch — or verified against a
        // different beacon — does not verify. Without this, last epoch's key survives its own rotation (audit E4).
        let beacon = BeaconSeed::GENESIS;
        let (id, public, proof, key) = relay(9, Epoch::new(4), &beacon);
        let record = Entitlement::encode(&id, &public, &proof, &key.encode());
        let output = coordinate_output(&public, &id, Epoch::new(4), &beacon, &proof).unwrap();
        let mine = probe_point::<F7>(&output, 0).coords();

        assert!(parse_bound_record::<F7>(&record, mine, Epoch::new(4), &beacon).is_some(), "its own epoch verifies");
        assert!(parse_bound_record::<F7>(&record, mine, Epoch::new(5), &beacon).is_none(), "a replayed epoch does not");
        assert!(
            parse_bound_record::<F7>(&record, mine, Epoch::new(4), &BeaconSeed::new([7u8; 32])).is_none(),
            "nor a different beacon"
        );
        let truncated = record.get(..20).expect("a record is longer than 20 bytes");
        assert!(parse_bound_record::<F7>(truncated, mine, Epoch::new(4), &beacon).is_none(), "nor a truncation");
}
}
