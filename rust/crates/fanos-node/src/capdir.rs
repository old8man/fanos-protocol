//! Live **capability directory** over the overlay store — the discovery half of the self-organizing role
//! loop (`docs/design-self-organization.md`; the sans-I/O core is `fanos_core::roles`).
//!
//! For the cell to assign roles deterministically, every node must run its `RoleController` over the *same*
//! authenticated capability set. Each node publishes its signed [`CapabilityDescriptor`] for the current epoch
//! at a coordinate-and-epoch-derived store slot ([`publish_capability`]); every node reads the whole cell's
//! roster ([`build_capability_directory`]) into the `(NodeId, Capability)` list the assignment consumes — no
//! central registry, no hand-built map. This is the exact pattern the mix directory ([`crate::mixdir`]) uses
//! for onion keys, applied to capabilities.
//!
//! Trust (identical to [`crate::mixdir`]): the descriptor is signed with the node's coordinate-VRF key, so a
//! forged capability published at another node's slot fails [`CapabilityDescriptor::verify`] and is dropped;
//! at worst it makes that member absent from the roster (a liveness fault — the cell assigns over whoever
//! *did* verify), never a security break. Binding the published VRF key to the node's cert-derived coordinate
//! is the same later-hardening step [`crate::mixdir`] notes.

use fanos_core::roles::{Capability, CapabilityDescriptor};
use fanos_diaulos::Coord;
use fanos_field::Field;
use fanos_geometry::{Plane, Point};
use fanos_primitives::NodeId;
use fanos_quic::Client;
use fanos_rendezvous::Epoch;
use fanos_runtime::Notification;
use fanos_vrf::{VrfPublic, VrfSecret};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::resolve::RESOLVE_TIMEOUT;

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
    let bytes = tokio::time::timeout(RESOLVE_TIMEOUT, client.get(cap_slot(coord, epoch))).await.ok()??;
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
pub async fn build_capability_directory<F: Field>(client: &Client, epoch: Epoch) -> Vec<(NodeId, Capability)> {
    let mut members = Vec::new();
    for coord in cell_cap_coords::<F>() {
        if let Some(member) = resolve_capability(client, coord, epoch).await {
            members.push(member);
        }
    }
    members
}

/// Keep a node's capability advertisement **live**: spawn the task that (re)publishes its signed descriptor at
/// each epoch, so [`build_capability_directory`] always reads a current, authenticated advertisement. It
/// publishes the genesis-epoch advertisement at once, then follows the node's [`Notification::BeaconReady`]
/// stream, republishing the descriptor (re-signed for the new epoch) on every real advance. Mirrors
/// [`crate::mixdir::spawn_mix_publisher`]. The task ends when the notification stream closes; must run inside a
/// tokio runtime.
#[must_use]
pub fn spawn_capability_publisher(
    client: Client,
    coord: Coord,
    node_id: NodeId,
    vrf_secret: VrfSecret,
    capability: Capability,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut events = client.subscribe();
        let mut epoch = Epoch::ZERO;
        publish_capability(&client, coord, epoch, &vrf_secret, node_id, capability).await;
        loop {
            match events.recv().await {
                Ok(Notification::BeaconReady { epoch: e, .. }) => {
                    if e > epoch {
                        epoch = e;
                        publish_capability(&client, coord, epoch, &vrf_secret, node_id, capability).await;
                    }
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_core::roles::{Role, RoleSet};
    use fanos_field::F2;

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

    #[test]
    fn the_roster_is_the_cell_points() {
        let roster = cell_cap_coords::<F2>();
        assert_eq!(roster.len(), 7, "a Fano cell's role roster is its seven points");
        assert_eq!(roster, crate::mixdir::cell_mix_coords::<F2>(), "same roster as the mix directory");
    }
}
