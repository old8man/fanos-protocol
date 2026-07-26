//! Live **load directory** over the overlay store — the setpoint half of the self-organizing role loop
//! (task A3; the sans-I/O load meter + aggregation is `fanos_core::roles::{LoadMeter, cell_setpoint}`).
//!
//! The [`RoleController`](fanos_core::roles::RoleController) tracks a *setpoint*: how many of each role the
//! cell wants, `⌈observed_load / per-node capacity⌉`. For the assignment to stay deterministic every node must
//! use the *same* setpoint, so the setpoint is a **cell aggregate**: each node advertises its own observed
//! per-role load for the epoch at its coordinate slot ([`publish_load`]), every node sums the roster's loads
//! and applies [`cell_setpoint`](fanos_core::roles::cell_setpoint) ([`build_cell_setpoint`]) — the same total
//! on every node. This is the [`crate::capdir`] pattern applied to load telemetry.
//!
//! Trust: the load report is a self-observation, attributed by its slot (like [`crate::mixdir`]). A node can
//! inflate its *own* reported load (over-provisioning a role it serves — bounded, one node's contribution to a
//! sum), never another's; the performance-reputation loop prices sustained mis-reporting. Signing/coord-binding
//! the report is the same later-hardening step the sibling directories note.

use fanos_core::roles::{cell_setpoint, Demand, Role};
use fanos_diaulos::Coord;
use fanos_field::Field;
use fanos_quic::Client;
use fanos_rendezvous::Epoch;
use fanos_runtime::Notification;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

use crate::capdir::cell_cap_coords;
use crate::resolve::{RESOLVE_TIMEOUT, resolve_directory};

/// The overlay store slot a node's per-epoch load report lives at — domain-separated, keyed by coordinate and
/// epoch (each epoch's report at its own address).
fn load_slot(coord: Coord, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/role-load/".to_vec();
    key.extend_from_slice(&fanos_geometry::encode_triple(coord));
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// A load report's canonical width — one big-endian `u16` per role, **derived from [`Role::COUNT`]**.
///
/// It used to be a hand-written `8` for the four roles then defined, which is the same desync hazard the [`Demand`]
/// refactor removed: a fifth role would have silently reported only the first four. Deriving the width means adding
/// a role cannot leave the codec behind.
const LOAD_BYTES: usize = Role::COUNT * 2;

/// A load report's canonical bytes: one big-endian `u16` per role, in [`Role::ALL`] order.
#[must_use]
fn encode_load(load: Demand) -> [u8; LOAD_BYTES] {
    let mut b = [0u8; LOAD_BYTES];
    for (slot, role) in b.as_chunks_mut::<2>().0.iter_mut().zip(Role::ALL) {
        *slot = load.of(role).to_be_bytes();
    }
    b
}

/// Parse a load report (sans-I/O), or `None` if not exactly [`LOAD_BYTES`] long.
///
/// A peer running a different role set therefore writes a wrong-width slot and is simply *not counted* toward the
/// cell setpoint, rather than mis-parsed — the safe direction, since a missing report lowers the setpoint while a
/// mis-parsed one would corrupt it.
#[must_use]
pub fn parse_load(bytes: &[u8]) -> Option<Demand> {
    let b: [u8; LOAD_BYTES] = bytes.try_into().ok()?;
    let pairs = b.as_chunks::<2>().0;
    Some(Demand::per_role(|role| pairs.get(role.index()).map_or(0, |p| u16::from_be_bytes(*p))))
}

/// Publish this node's observed per-role `load` for `epoch` at its coordinate slot. `false` if the store
/// rejected the write.
pub async fn publish_load(client: &Client, coord: Coord, epoch: Epoch, load: Demand) -> bool {
    client.put(load_slot(coord, epoch), encode_load(load).to_vec()).await
}

/// Resolve the load the node at `coord` reported for `epoch`, or `None` if none/timeout/malformed.
pub async fn resolve_load(client: &Client, coord: Coord, epoch: Epoch) -> Option<Demand> {
    let bytes = tokio::time::timeout(RESOLVE_TIMEOUT, client.get(load_slot(coord, epoch))).await.ok()??;
    parse_load(&bytes)
}

/// Assemble the cell's **agreed setpoint** for `epoch`: resolve every roster member's load report, sum them,
/// and apply the per-node `capacity` ([`cell_setpoint`]). A member absent from the store simply contributes
/// zero load. Every node computes the identical setpoint from the identical roster reads — the agreed input the
/// deterministic assignment needs.
pub async fn build_cell_setpoint<F: Field>(client: &Client, epoch: Epoch, capacity: Demand) -> Demand {
    let resolved = resolve_directory(client, cell_cap_coords::<F>(), move |client, coord| async move {
        resolve_load(&client, coord, epoch).await
    })
    .await;
    let loads: Vec<Demand> = resolved.into_iter().map(|(_, load)| load).collect();
    cell_setpoint(&loads, capacity)
}

/// Keep a node's load report **live**: spawn the task that publishes `load_source()`'s current observed load
/// each epoch (the node wires `load_source` to its `LoadMeter`, however it shares it — a closure so this module
/// stays agnostic to the meter's storage). Mirrors [`crate::capdir::spawn_capability_publisher`]; ends when the
/// notification stream closes. Must run inside a tokio runtime.
/// Publishes at the node's **live** coordinate, re-read on every cycle rather than captured at spawn.
///
/// A coordinate moves — every epoch by the beacon reshuffle (spec §L3), and within an epoch when a better claim displaces
/// this node. A publisher that captured it kept writing to the point the node had *left*, so the cell's directory scan found
/// a descriptor at an unoccupied point and none at the occupied one. Measured as rosters frozen one short of the occupied
/// count (`[4, 4, 4, 1, 4]` with five points held) after live coordinate resolution started actually moving nodes.
#[must_use]
pub fn spawn_load_publisher(
    client: Client,
    load_source: impl Fn() -> Demand + Send + 'static,
) -> (JoinHandle<()>, oneshot::Receiver<()>) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let mut events = client.subscribe();
        let mut epoch = Epoch::ZERO;
        publish_load(&client, client.address(), epoch, load_source()).await;
        // Signal the genesis load report, for the same reason as the capability publisher: the setpoint is derived
        // from these reports, and a setpoint of zero correctly assigns nobody — so assigning before the node's own
        // report lands produces an empty assignment that looks like a controller fault.
        let _ = ready_tx.send(());
        loop {
            match events.recv().await {
                Ok(Notification::BeaconReady { epoch: e, .. }) => {
                    if e > epoch {
                        epoch = e;
                        publish_load(&client, client.address(), epoch, load_source()).await;
                    }
                }
                // The node MOVED — see the capability publisher: republishing only on a beacon left the report at the point
                // the node had left, for up to a whole epoch.
                Ok(Notification::Reseated { .. }) => {
                    publish_load(&client, client.address(), epoch, load_source()).await;
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    (handle, ready_rx)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn load_slots_are_deterministic_distinct_and_domain_separated() {
        let a = load_slot([1, 2, 3], Epoch::ZERO);
        assert_eq!(a, load_slot([1, 2, 3], Epoch::ZERO));
        assert_ne!(a, load_slot([1, 2, 4], Epoch::ZERO));
        assert_ne!(a, load_slot([1, 2, 3], Epoch::new(1)));
        assert!(a.starts_with(b"FANOS-v1/role-load/"));
        assert!(!a.starts_with(b"FANOS-v1/cap-desc/"), "distinct domain from the capability directory");
    }

    #[test]
    fn a_load_report_round_trips() {
        let load = Demand::from_counts([25, 3, 0, 7, 0]);
        assert_eq!(parse_load(&encode_load(load)), Some(load));
        assert_eq!(parse_load(b"short"), None, "a wrong-length report is rejected");
    }
}
