//! Live **capability directory** over the overlay store — the discovery half of the self-organizing role
//! loop (`docs/design-self-organization.md`; the sans-I/O core is `fanos_core::roles`).
//!
//! For the cell to assign roles deterministically, every node must run its `RoleController` over the *same*
//! authenticated capability set. Each node publishes its signed [`CapabilityDescriptor`] for the current epoch
//! at a coordinate-and-epoch-derived store slot ([`publish_capability`]); every node reads the whole cell's
//! roster (`build_capability_directory`) into the `(NodeId, Capability)` list the assignment consumes — no
//! central registry, no hand-built map. This is the exact pattern the mix directory ([`crate::mixdir`]) uses
//! for onion keys, applied to capabilities.
//!
//! Trust (identical to [`crate::mixdir`], and built on the same [`crate::bound`] check): the descriptor is signed with the
//! node's coordinate-VRF key **and** the record proves that key is entitled to the coordinate its slot names. Signing alone
//! was never enough and this module's own doc used to say so: a signature proves *someone* holding that key signed those
//! bytes, so a forger publishing a self-consistent descriptor signed by their own fresh key at another node's slot passed
//! every check and joined the roster as that member. With the binding, the two halves close on each other — the descriptor
//! is authenticated against the very key just proven entitled to the coordinate, and a record that cannot prove entitlement
//! is simply absent from the roster (a liveness fault, which the assignment already tolerates by running over whoever *did*
//! verify).

use fanos_core::roles::{Capability, CapabilityDescriptor};
use fanos_diaulos::Coord;
use fanos_field::Field;
use fanos_geometry::{Plane, Point};
use fanos_primitives::{BeaconSeed, NodeId};
use fanos_quic::{Client, CoordinateProver};
use fanos_rendezvous::Epoch;
use fanos_runtime::Notification;
use fanos_vrf::{VrfProof, VrfPublic, VrfSecret};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

use crate::bound::Entitlement;
use crate::resolve::{STORE_TIMEOUT, Read, resolve_directory};

/// The overlay store slot a node's per-epoch capability advertisement lives at — domain-separated, keyed by
/// the node's coordinate **and** the epoch (so each epoch's advertisement has its own address and a stale one
/// is simply a different slot, exactly as the mix key is epoch-tagged).
fn cap_slot(coord: Coord, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/cap-desc/".to_vec();
    key.extend_from_slice(&fanos_geometry::encode_triple(coord));
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// The stored advertisement bytes: `vrf_public(32) ‖ descriptor`. The VRF public is carried so a reader can
/// authenticate the descriptor's signature self-containedly (the descriptor's own bytes carry the signed
/// capability + proof).
fn advertisement(vrf_secret: &VrfSecret, node_id: NodeId, epoch: Epoch, capability: Capability) -> Vec<u8> {
    let desc = CapabilityDescriptor::sign(node_id, epoch, capability, vrf_secret);
    let mut value = vrf_secret.public().to_bytes().to_vec();
    value.extend_from_slice(&desc.to_bytes());
    value
}

/// Parse and **verify** a stored advertisement (sans-I/O): the VRF public authenticates the descriptor, and
/// the descriptor's epoch must match the slot's. Returns the authenticated `(node_id, capability)`, or `None`
/// if the bytes are malformed, the signature fails, or the epoch is wrong. This is the whole trust check; the
/// async resolvers below just fetch the bytes and call it.
#[must_use]
pub fn parse_advertisement(bytes: &[u8], epoch: Epoch) -> Option<(NodeId, Capability)> {
    let vrf_public = VrfPublic::from_bytes(bytes.get(..32)?.try_into().ok()?)?;
    let desc = CapabilityDescriptor::from_bytes(bytes.get(32..)?)?;
    if desc.epoch != epoch || !desc.verify(&vrf_public) {
        return None;
    }
    Some((desc.node_id, desc.capability))
}

/// The **coordinate-bound** advertisement: an [`Entitlement`] over the signed descriptor.
///
/// The VRF public is carried once, inside the entitlement, and the descriptor is authenticated against *it* — never against
/// a second copy alongside. Two copies of one key is a cross-check waiting to be forgotten, and forgetting it here would let
/// a forger prove entitlement with one key while the descriptor was signed by another.
fn bound_advertisement(
    prove: &(Vec<u8>, VrfPublic, VrfProof),
    vrf_secret: &VrfSecret,
    node_id: NodeId,
    epoch: Epoch,
    capability: Capability,
) -> Vec<u8> {
    let (id, public, proof) = prove;
    let desc = CapabilityDescriptor::sign(node_id, epoch, capability, vrf_secret);
    Entitlement::encode(id, public, proof, &desc.to_bytes())
}

/// Parse and **verify** a coordinate-bound advertisement against the coordinate its slot names (sans-I/O).
///
/// Three things must hold, and the third is the one signing alone never gave: the bytes are well formed, the descriptor's
/// epoch matches the slot's, and the publisher's VRF key is entitled to this coordinate — with the descriptor's signature
/// checked against *that* entitled key. See [`crate::bound`] for what the binding costs an attacker.
#[must_use]
pub fn parse_bound_advertisement<F: Field>(
    bytes: &[u8],
    coord: Coord,
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> Option<(NodeId, Capability)> {
    let (entitled, payload) = Entitlement::open::<F>(bytes, coord, epoch, beacon)?;
    let desc = CapabilityDescriptor::from_bytes(payload)?;
    // The roster's *identity* is bound too, not just its coordinate. A node's role-assignment id **is** its coordinate-VRF
    // public key (`node.rs`'s `SelfOrgConfig`), so requiring them equal means an entitled publisher cannot advertise under
    // some other member's id — which it otherwise could, since owning a coordinate says nothing about which id you claim
    // while sitting there. Without this, the binding would secure the slot and leave the name inside it forgeable.
    if desc.epoch != epoch || desc.node_id.0 != entitled.public.to_bytes() || !desc.verify(&entitled.public) {
        return None;
    }
    Some((desc.node_id, desc.capability))
}

/// Publish this node's signed capability advertisement for `epoch` at its coordinate slot, so the cell can
/// assign its roles this epoch. `false` if the store rejected the write.
pub async fn publish_capability(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    vrf_secret: &VrfSecret,
    node_id: NodeId,
    capability: Capability,
) -> bool {
    client.put(cap_slot(coord, epoch), advertisement(vrf_secret, node_id, epoch, capability)).await
}

/// Resolve and verify the capability the node at `coord` advertised for `epoch`, or `None` if none is
/// published, the lookup times out, or the advertisement fails authentication.
pub async fn resolve_capability(client: &Client, coord: Coord, epoch: Epoch) -> Option<(NodeId, Capability)> {
    let bytes = tokio::time::timeout(STORE_TIMEOUT, client.get(cap_slot(coord, epoch))).await.ok()??;
    parse_advertisement(&bytes, epoch)
}

/// The role-assignment **roster** of the base cell of plane `F`: every one of its `N` points — the same
/// coordinate list the mix roster uses, since every cell member is a candidate for every role.
#[must_use]
pub fn cell_cap_coords<F: Field>() -> Vec<Coord> {
    (0..Plane::<F>::N as usize).map(|i| Point::<F>::at(i).coords()).collect()
}

/// Assemble the cell's **live, authenticated capability directory** for `epoch`: resolve every roster
/// member's advertisement and keep those that verify. The result is exactly the `(NodeId, Capability)` list
/// `fanos_core::roles::assign` / `RoleController::step` consumes — a member that is down, or has not published
/// for `epoch`, or whose advertisement fails to verify, is simply absent, and the assignment runs over the
/// present, authenticated set. Deterministic across nodes given the same live set (the design's agreed-input
/// requirement).
pub(crate) async fn build_capability_directory<F: Field>(
    client: &Client,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> (Vec<(NodeId, Capability)>, bool) {
    let scan = resolve_directory(client, cell_cap_coords::<F>(), move |client, coord| async move {
        read_capability::<F>(&client, coord, epoch, beacon).await
    })
    .await;
    // The second value is what the caller could not previously know: whether this is the whole cell or only the part that
    // answered in time. An assignment derived from a partial view is not a settled answer (`role_loop`).
    let complete = scan.complete();
    (scan.found.into_iter().map(|(_, member)| member).collect(), complete)
}

/// As [`resolve_capability`], distinguishing a read that **did not conclude** from a definite absence.
///
/// The timeout is the whole point: `resolve_capability` answers `Option`, so a slow store read and an unpublished
/// descriptor are the same value, and a roster built from those reads silently shrinks under load.
/// `Some(beacon)` reads a **coordinate-bound** record ([`parse_bound_advertisement`]); `None` a pinned cell's unbound one.
/// Not a `verify: bool` — see [`crate::bound`]: having a beacon *is* the VRF mode, and its absence is an absent mechanism.
async fn read_capability<F: Field>(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Read<(NodeId, Capability)> {
    let slot = cap_slot(coord, epoch);
    match tokio::time::timeout(STORE_TIMEOUT, client.get(slot)).await {
        // Completed: present-and-valid, or a definite negative (absent, malformed, or failing authentication).
        Ok(bytes) => Read::found_or_absent(bytes.and_then(|b| match beacon {
            Some(seed) => parse_bound_advertisement::<F>(&b, coord, epoch, &seed),
            None => parse_advertisement(&b, epoch),
        })),
        Err(_) => Read::Unknown,
    }
}

/// Keep a node's capability advertisement **live**: spawn the task that (re)publishes its signed descriptor at
/// each epoch, so `build_capability_directory` always reads a current, authenticated advertisement. It
/// publishes the genesis-epoch advertisement at once, then follows the node's [`Notification::BeaconReady`]
/// stream, republishing the descriptor (re-signed for the new epoch) on every real advance. Mirrors
/// [`crate::mixdir::spawn_mix_publisher`]. The task ends when the notification stream closes; must run inside a
/// tokio runtime.
/// Publishes at the node's **live** coordinate, re-read on every cycle rather than captured at spawn.
///
/// A coordinate moves — every epoch by the beacon reshuffle (spec §L3), and within an epoch when a better claim displaces
/// this node. A publisher that captured it kept writing to the point the node had *left*, so the cell's directory scan found
/// a descriptor at an unoccupied point and none at the occupied one. Measured as rosters frozen one short of the occupied
/// count (`[4, 4, 4, 1, 4]` with five points held) after live coordinate resolution started actually moving nodes.
#[must_use]
/// `prover` states the cell's mode, exactly as [`crate::mixdir::spawn_mix_publisher`] does: `Some` publishes a
/// **coordinate-bound** advertisement (and the readers in the same deployment verify one), `None` the unbound record a pinned
/// cell can produce. See [`crate::bound`] for why the mode is stated rather than inferred.
pub fn spawn_capability_publisher(
    client: Client,
    node_id: NodeId,
    vrf_secret: VrfSecret,
    capability: Capability,
    prover: Option<CoordinateProver>,
) -> (JoinHandle<()>, oneshot::Receiver<()>) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let mut events = client.subscribe();
        let mut epoch = Epoch::ZERO;
        let mut seed = BeaconSeed::GENESIS;
        // One publish path, chosen per write rather than per spawn: the beacon changes every epoch, so a bound record must
        // be re-proven against the current one — a proof captured once would verify only in the epoch it was made.
        let publish = |epoch: Epoch, seed: BeaconSeed| {
            let client = client.clone();
            let vrf_secret = vrf_secret.clone();
            let prover = prover.clone();
            async move {
                let coord = client.address();
                let bytes = match prover.as_ref() {
                    Some(prove) => bound_advertisement(&prove(epoch, &seed), &vrf_secret, node_id, epoch, capability),
                    None => advertisement(&vrf_secret, node_id, epoch, capability),
                };
                client.put(cap_slot(coord, epoch), bytes).await
            }
        };
        publish(epoch, seed).await;
        // The genesis advertisement is now readable, which the role loop must know before it assigns: a node cannot
        // be assigned from a roster that does not yet contain it. Signalling is deterministic where polling the
        // directory is not — each poll costs a full cell scan, so a retry loop cannot converge promptly.
        let _ = ready_tx.send(());
        loop {
            match events.recv().await {
                Ok(Notification::BeaconReady { epoch: e, seed: s }) => {
                    if e > epoch {
                        epoch = e;
                        seed = BeaconSeed::new(s);
                        publish(epoch, seed).await;
                    }
                }
                // The node MOVED. Republishing only on a beacon was the other half of the stale-descriptor defect: a
                // within-epoch move left the advertisement at the point the node had left until the next epoch, so the
                // cell's roster scan was short by exactly this node for up to a whole epoch.
                Ok(Notification::Reseated { .. }) => {
                    publish(epoch, seed).await;
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    (handle, ready_rx)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_core::roles::{Role, RoleSet};
    use fanos_field::{F2, F7};

    #[test]
    fn cap_slots_are_deterministic_distinct_and_domain_separated() {
        let e0 = Epoch::ZERO;
        let a = cap_slot([1, 2, 3], e0);
        assert_eq!(a, cap_slot([1, 2, 3], e0), "same coordinate + epoch → same slot");
        assert_ne!(a, cap_slot([1, 2, 4], e0), "distinct coordinates → distinct slots");
        assert_ne!(a, cap_slot([1, 2, 3], Epoch::new(1)), "distinct epoch → distinct slot");
        assert!(a.starts_with(b"FANOS-v1/cap-desc/"), "domain-separated from every other store use");
        assert!(!a.starts_with(b"FANOS-v1/mix-key/"), "distinct domain tag from the mix directory");
        assert_eq!(a.len(), b"FANOS-v1/cap-desc/".len() + 12 + 8, "prefix ‖ 12-byte coord ‖ 8-byte epoch");
    }

    #[test]
    fn a_published_advertisement_round_trips_and_authenticates() {
        let sk = VrfSecret::from_seed([0x7C; 32]);
        let id = NodeId([9; 32]);
        let epoch = Epoch::new(5);
        let cap = Capability::new(RoleSet::of(&[Role::Relay, Role::Exit]), 6);
        let bytes = advertisement(&sk, id, epoch, cap);
        // The stored bytes verify to the advertised (node, capability).
        assert_eq!(parse_advertisement(&bytes, epoch), Some((id, cap)));
        // A wrong epoch (a stale/replayed advertisement read at the wrong slot) is rejected.
        assert_eq!(parse_advertisement(&bytes, Epoch::new(6)), None, "epoch mismatch is rejected");
        // A tampered offered-roles byte breaks the signature. In the full advertisement it sits at
        // vrf_public(32) + node_id(32) + epoch(8) = offset 72.
        let mut forged = bytes.clone();
        forged[72] ^= 0xFF;
        assert_eq!(parse_advertisement(&forged, epoch), None, "a tampered advertisement fails authentication");
        // Garbage / truncated bytes are rejected, never panic.
        assert_eq!(parse_advertisement(&bytes[..40], epoch), None);
        assert_eq!(parse_advertisement(b"", epoch), None);
    }

    /// A member with a VRF-derived coordinate, exactly as `Node::start` builds one: its role-assignment id **is** its
    /// coordinate-VRF public key.
    fn member(seed: u8, epoch: Epoch, beacon: &BeaconSeed) -> (VrfSecret, (Vec<u8>, VrfPublic, VrfProof)) {
        let sk = VrfSecret::from_seed([seed; 32]);
        let id = format!("member-{seed}").into_bytes();
        let (_, proof) = fanos_vrf::prove_coordinate::<F7>(&sk, &id, epoch, beacon);
        (sk.clone(), (id, sk.public(), proof))
    }

    fn cap() -> Capability {
        Capability::new(RoleSet::of(&[Role::Relay]), 6)
    }

    #[test]
    fn a_bound_advertisement_verifies_only_on_its_publishers_walk() {
        // The residual this module's own doc used to record, now closed: a signature proves *someone* signed, entitlement
        // proves the key belongs at that coordinate. Accepted on every point of the publisher's own walk; refused elsewhere.
        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let (sk, prove) = member(5, epoch, &beacon);
        let node_id = NodeId(sk.public().to_bytes());
        let record = bound_advertisement(&prove, &sk, node_id, epoch, cap());
        let output = fanos_vrf::coordinate_output(&prove.1, &prove.0, epoch, &beacon, &prove.2).unwrap();

        let mut refused = 0;
        for i in 0..Plane::<F7>::N as usize {
            let p = Point::<F7>::at(i);
            let got = parse_bound_advertisement::<F7>(&record, p.coords(), epoch, &beacon);
            if fanos_vrf::probe_index_of::<F7>(&output, &p).is_some() {
                assert_eq!(got, Some((node_id, cap())), "a point on the publisher's own walk verifies");
            } else {
                assert_eq!(got, None, "a coordinate the publisher cannot prove is refused");
                refused += 1;
            }
        }
        // PG(2,7): 57 points, a line holds q + 1 = 8, so 49 of the 57 are unreachable for this publisher.
        assert_eq!(refused, 49, "the forgery is refused at 49 of the plane's 57 points");
    }

    #[test]
    fn an_entitled_publisher_cannot_advertise_under_another_members_id() {
        // The half a coordinate binding alone leaves open, and the reason `desc.node_id` is cross-checked against the
        // entitled key: owning a coordinate says nothing about which *id* you claim while sitting there. Without the check
        // an entitled node could enter the roster as any member it liked and collect that member's role assignment.
        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let (sk, prove) = member(5, epoch, &beacon);
        let (victim, _) = member(9, epoch, &beacon);
        let output = fanos_vrf::coordinate_output(&prove.1, &prove.0, epoch, &beacon, &prove.2).unwrap();
        let mine = fanos_vrf::probe_point::<F7>(&output, 0).coords();

        // Signed by the entitled key, at a coordinate that key owns — but naming the victim's id.
        let forged = bound_advertisement(&prove, &sk, NodeId(victim.public().to_bytes()), epoch, cap());
        assert_eq!(
            parse_bound_advertisement::<F7>(&forged, mine, epoch, &beacon),
            None,
            "an id that is not the entitled key's own is refused"
        );
        // The honest record at the same coordinate still verifies, so this is not the coordinate check firing.
        let honest = bound_advertisement(&prove, &sk, NodeId(sk.public().to_bytes()), epoch, cap());
        assert!(parse_bound_advertisement::<F7>(&honest, mine, epoch, &beacon).is_some(), "the honest record verifies");
    }

    #[test]
    fn a_bound_advertisement_is_tied_to_its_epoch_and_beacon() {
        // Both are in the VRF input, so a record cannot be replayed out of the epoch it was made for, nor into a cell that
        // reshuffled onto a different beacon.
        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let (sk, prove) = member(5, epoch, &beacon);
        let record = bound_advertisement(&prove, &sk, NodeId(sk.public().to_bytes()), epoch, cap());
        let output = fanos_vrf::coordinate_output(&prove.1, &prove.0, epoch, &beacon, &prove.2).unwrap();
        let mine = fanos_vrf::probe_point::<F7>(&output, 0).coords();

        assert!(parse_bound_advertisement::<F7>(&record, mine, epoch, &beacon).is_some(), "its own epoch and beacon");
        assert_eq!(parse_bound_advertisement::<F7>(&record, mine, Epoch::new(4), &beacon), None, "a replayed epoch");
        let other = BeaconSeed::new([0x11; 32]);
        assert_eq!(parse_bound_advertisement::<F7>(&record, mine, epoch, &other), None, "a different beacon");
    }

    #[test]
    fn the_two_modes_are_not_interchangeable_in_either_direction() {
        // What makes a mode mismatch *loud*. Both parsers are total functions over arbitrary bytes, so a reader in the wrong
        // mode does not misread a record — it finds nothing, and the roster is empty rather than subtly wrong. Asserted
        // because it currently holds by wire-shape accident (the bound form's `id_len` prefix lands where the unbound form
        // expects a VRF public), and a future layout change could make the two collide without any test noticing.
        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let (sk, prove) = member(5, epoch, &beacon);
        let node_id = NodeId(sk.public().to_bytes());
        let output = fanos_vrf::coordinate_output(&prove.1, &prove.0, epoch, &beacon, &prove.2).unwrap();
        let mine = fanos_vrf::probe_point::<F7>(&output, 0).coords();

        let bound = bound_advertisement(&prove, &sk, node_id, epoch, cap());
        let unbound = advertisement(&sk, node_id, epoch, cap());
        assert_eq!(parse_advertisement(&bound, epoch), None, "the unbound reader does not accept a bound record");
        assert_eq!(
            parse_bound_advertisement::<F7>(&unbound, mine, epoch, &beacon),
            None,
            "and the bound reader does not accept an unbound one"
        );
        // Each in its own mode still verifies, so the above is the mode mismatch and not a broken fixture.
        assert_eq!(parse_advertisement(&unbound, epoch), Some((node_id, cap())));
        assert_eq!(parse_bound_advertisement::<F7>(&bound, mine, epoch, &beacon), Some((node_id, cap())));
    }

    #[test]
    fn the_roster_is_the_cell_points() {
        let roster = cell_cap_coords::<F2>();
        assert_eq!(roster.len(), 7, "a Fano cell's role roster is its seven points");
        assert_eq!(roster, crate::mixdir::cell_mix_coords::<F2>(), "same roster as the mix directory");
    }
}
