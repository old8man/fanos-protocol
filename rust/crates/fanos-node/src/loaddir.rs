//! Live **load directory** over the overlay store — the setpoint half of the self-organizing role loop
//! (task A3; the sans-I/O load meter + aggregation is `fanos_core::roles::{LoadMeter, cell_setpoint}`).
//!
//! The [`RoleController`](fanos_core::roles::RoleController) tracks a *setpoint*: how many of each role the
//! cell wants, `⌈observed_load / per-node capacity⌉`. For the assignment to stay deterministic every node must
//! use the *same* setpoint, so the setpoint is a **cell aggregate**: each node advertises its own observed
//! per-role load for the epoch at its coordinate slot ([`publish_load`]), every node sums the roster's loads
//! and applies [`cell_setpoint`] (`build_cell_setpoint`) — the same total
//! on every node. This is the [`crate::capdir`] pattern applied to load telemetry.
//!
//! Trust: the load report is a self-observation, and "never another's" is what the **coordinate binding**
//! buys. A node can inflate its *own* reported load — over-provisioning a role it serves, bounded, one node's
//! contribution to a sum, and the performance-reputation loop is *specified* to price sustained
//! mis-reporting — but is not yet wired (`Reputation::observe_reachable` has no production caller), so today
//! the coordinate binding is the whole defence and this line must not be read as a second one.
//!
//! **It could inflate anyone's until this was bound, and the doc said otherwise.** The store is
//! content-addressed: a slot key embeds a coordinate, but nothing made the publisher own it, so one member
//! could write every node's report and move the cell setpoint — the input to who relays, which is
//! anonymity-relevant. The same paragraph that claimed "never another's" also called coord-binding "a later
//! hardening step", and the two cannot both be true: the binding IS the claim. Meanwhile the siblings
//! ([`crate::mixdir`], [`crate::capdir`]) had been bound under S1-M3 and this one had not — hardening one
//! member of a family and leaving another asserting a property it cannot back.
//!
//! So a report now travels inside the same [`Entitlement`](crate::bound::Entitlement) envelope a capability
//! advertisement does: the publisher's VRF credential for the slot's coordinate, checked on read. `None` for
//! the prover/beacon keeps the unbound form, which is the honest answer for a pinned cell where no
//! coordinate is provable — symmetric with the sibling directories, and the `Option` says whether the
//! mechanism *exists* here, not whether someone remembered to use it.

use fanos_core::roles::{cell_setpoint, Demand, Role};
use fanos_diaulos::Coord;
use fanos_field::Field;
use fanos_quic::{Client, CoordinateProver};
use fanos_vrf::{VrfProof, VrfPublic};
use fanos_rendezvous::{BeaconSeed, Epoch};
use fanos_runtime::Notification;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

use crate::DIRECTORY_SLOT_EPOCHS;
use crate::bound::Entitlement;
use crate::capdir::cell_cap_coords;
use crate::resolve::{STORE_TIMEOUT, Read, resolve_directory};

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

/// Parse a load report (sans-I/O), or `None` if not exactly `LOAD_BYTES` long.
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
///
/// `credential` is this node's coordinate proof for `epoch` — `Some` on any cell that runs VRF coordinates,
/// which is every deployed node, and the record is then bound so no other member can write this slot.
/// `None` emits the bare report a pinned cell can produce, where no coordinate is provable.
pub async fn publish_load(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    load: Demand,
    credential: Option<&(Vec<u8>, VrfPublic, VrfProof)>,
) -> bool {
    let landed = client
        .put_ephemeral(load_slot(coord, epoch), load_record(load, credential), DIRECTORY_SLOT_EPOCHS)
        .await;
    crate::note_publish(client, crate::Directory::Load, epoch, landed)
}

/// The bytes a load report is stored as: the bare per-role figures, or those inside the coordinate-bound
/// [`Entitlement`] envelope when this deployment can prove coordinates.
///
/// Extracted so the encode and the decode are **one function each, and both testable**. The first version of
/// this binding had its tests drive `Entitlement::encode`/`open` directly, and they stayed green when the
/// binding was deleted from `publish_load` — proving the envelope worked, which the capability directory had
/// already proven, and saying nothing about whether *this* directory used it. A test that survives the
/// removal of what it is testing is not a test.
#[must_use]
fn load_record(load: Demand, credential: Option<&(Vec<u8>, VrfPublic, VrfProof)>) -> Vec<u8> {
    let payload = encode_load(load);
    match credential {
        Some((id, public, proof)) => Entitlement::encode(id, public, proof, &payload),
        None => payload.to_vec(),
    }
}

/// The inverse of [`load_record`]: the reported load, or `None` if malformed or — when `beacon` is `Some` —
/// not bound to `coord` for `epoch`.
#[must_use]
fn open_load_record<F: Field>(
    bytes: &[u8],
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<Demand> {
    match beacon {
        Some(seed) => {
            let (_, payload) = Entitlement::open::<F>(bytes, coord, epoch, &seed)?;
            parse_load(payload)
        }
        None => parse_load(bytes),
    }
}

/// Resolve the load the node at `coord` reported for `epoch`, or `None` if none/timeout/malformed — or, when
/// `beacon` is `Some`, if the record is not **bound to that coordinate**.
///
/// Symmetric with [`publish_load`]'s `credential`: on both ends the `Option` states whether the deployment
/// has provable coordinates, so a reader never accepts a bare report on a cell where a bound one was
/// required — which is what stopped one member from writing every node's slot.
pub async fn resolve_load<F: Field>(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<Demand> {
    let bytes = tokio::time::timeout(STORE_TIMEOUT, client.get(load_slot(coord, epoch))).await.ok()??;
    open_load_record::<F>(&bytes, coord, epoch, beacon)
}

/// Assemble the cell's setpoint for `epoch`: resolve every roster member's load report, sum them, and apply
/// the per-node `capacity` ([`cell_setpoint`]). A member absent from the store simply contributes zero load.
///
/// **`epoch` must be a CLOSED epoch for the result to be agreed, and this function cannot check that.** Its
/// doc used to claim the output was "the agreed input the deterministic assignment needs" outright — untrue of
/// a *live* epoch, and the paragraph below said as much without the two being joined. Members are still
/// publishing their reports for the current epoch while it runs, so two nodes scanning it see different
/// subsets and derive different setpoints; the caller's `ClosedEpoch` is what supplies an epoch whose records
/// have settled. See `role_loop::ClosedEpoch`.
///
/// Also reports whether the scan was **complete**. A member whose report did not resolve in time contributes zero exactly
/// as a genuine absence does, so the setpoint is *understated* by a partial read — and a setpoint derived from a partial
/// read is not a settled answer, however many times it repeats. Note what this does *not* cover: an **expired**
/// directory resolves every slot as a definite absence, so it reads back as a complete scan of a cell with no
/// load at all. Staleness is the caller's to reject, and `ClosedEpoch::readable_for` is where.
pub(crate) async fn build_cell_setpoint<F: Field>(
    client: &Client,
    epoch: Epoch,
    capacity: Demand,
    beacon: Option<BeaconSeed>,
) -> (Demand, bool) {
    let scan = resolve_directory(client, cell_cap_coords::<F>(), move |client, coord| async move {
        read_load::<F>(&client, coord, epoch, beacon).await
    })
    .await;
    let loads: Vec<Demand> = scan.found.iter().map(|(_, load)| *load).collect();
    (cell_setpoint(&loads, capacity), scan.complete())
}

/// As [`resolve_load`], distinguishing a read that **did not conclude** from a definite absence.
///
/// A record that fails its coordinate binding is a definite **absence**, not an unknown: the slot holds
/// something and it is not this coordinate's report, so the member contributed nothing — which is exactly
/// what a genuine absence means to `cell_setpoint`. Reading it as `Unknown` would let one forged record turn
/// the whole scan incomplete, and an incomplete scan is what the role loop declines to act on — a cheaper
/// attack than the one the binding closes.
async fn read_load<F: Field>(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Read<Demand> {
    match tokio::time::timeout(STORE_TIMEOUT, client.get(load_slot(coord, epoch))).await {
        Ok(bytes) => Read::found_or_absent(bytes.and_then(|b| open_load_record::<F>(&b, coord, epoch, beacon))),
        Err(_) => Read::Unknown,
    }
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
    prover: Option<CoordinateProver>,
) -> (JoinHandle<()>, oneshot::Receiver<()>) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let mut events = client.subscribe();
        let mut beacons = client.beacons();
        let mut epoch = Epoch::ZERO;
        // This network's epoch-0 seed, not the constant — the same rule every epoch-0 publisher follows
        // (`docs/design-genesis.md`): a record bound against the wrong seed proves a coordinate this node
        // does not occupy, so no reader can verify it.
        let mut seed = client.genesis();
        let publish = |epoch: Epoch, seed: BeaconSeed, load: Demand| {
            let client = client.clone();
            let prover = prover.clone();
            async move {
                // Proven per write, never once at spawn: the credential names an epoch, so one captured at
                // startup would verify only in the epoch it was made — the same reason the capability
                // publisher re-proves.
                let credential = prover.as_ref().map(|prove| prove(epoch, &seed));
                publish_load(&client, client.address(), epoch, load, credential.as_ref()).await
            }
        };
        publish(epoch, seed, load_source()).await;
        // Signal the genesis load report, for the same reason as the capability publisher: the setpoint is derived
        // from these reports, and a setpoint of zero correctly assigns nobody — so assigning before the node's own
        // report lands produces an empty assignment that looks like a controller fault.
        let _ = ready_tx.send(());
        // Epoch from the `watch`, moves from the stream — see the capability publisher for why the two are
        // different kinds of thing (#86). A missing load report makes this node's work invisible to the
        // setpoint, which then provisions the role as though nobody were carrying it.
        loop {
            tokio::select! {
                advanced = crate::next_epoch(&mut beacons, epoch) => {
                    let Some((e, s)) = advanced else { break };
                    epoch = e;
                    seed = s;
                    publish(epoch, seed, load_source()).await;
                }
                event = events.recv() => match event {
                    // The node MOVED — see the capability publisher: republishing only on a beacon left the
                    // report at the point the node had left, for up to a whole epoch.
                    Ok(Notification::Reseated { .. }) => {
                        let _ = publish(epoch, seed, load_source()).await;
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            }
        }
    });
    (handle, ready_rx)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used)]
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

    /// **A member cannot report load at a coordinate it does not hold**, which is the claim this module's
    /// doc made while nothing enforced it.
    ///
    /// The store is content-addressed: the slot key embeds a coordinate, but nothing made the *publisher*
    /// own it, so one member could write every node's report. The setpoint is the roster's sum, so that is
    /// direct control of the cell-wide role assignment — including who relays, which is anonymity-relevant —
    /// from inside the fault budget.
    ///
    /// The property is stated over the whole plane rather than at one forged point: a publisher's credential
    /// verifies exactly on the coordinates its VRF walk reaches, and nowhere else.
    #[test]
    fn a_load_report_verifies_only_at_a_coordinate_its_publisher_can_prove() {
        use fanos_field::F7;
        use fanos_geometry::{Plane, Point};
        use fanos_vrf::VrfSecret;

        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let sk = VrfSecret::from_seed([5u8; 32]);
        let id = b"member-5".to_vec();
        let (_, proof) = fanos_vrf::prove_coordinate::<F7>(&sk, &id, epoch, &beacon);
        let load = Demand::per_role(|role| u16::try_from(role.index()).unwrap_or(0) + 1);
        let record = load_record(load, Some(&(id.clone(), sk.public(), proof)));
        let output = fanos_vrf::coordinate_output(&sk.public(), &id, epoch, &beacon, &proof)
            .expect("the publisher's own credential yields its walk");

        let mut refused = 0;
        for i in 0..Plane::<F7>::N as usize {
            let p = Point::<F7>::at(i);
            let got = open_load_record::<F7>(&record, p.coords(), epoch, Some(beacon));
            if fanos_vrf::probe_index_of::<F7>(&output, &p).is_some() {
                assert_eq!(got, Some(load), "a point on the publisher's own walk verifies");
            } else {
                assert_eq!(got, None, "a coordinate the publisher cannot prove is refused");
                refused += 1;
            }
        }
        // PG(2,7) holds 57 points and a line holds q + 1 = 8, so 49 are unreachable for this publisher —
        // the same arithmetic the capability directory's own binding test states.
        assert_eq!(refused, 49, "the forgery is refused at 49 of the plane's 57 points");
    }

    /// The binding is **epoch-scoped**, so a report cannot be replayed into a later epoch to hold a stale
    /// load in the setpoint after the node's real one has changed.
    #[test]
    fn a_load_report_does_not_verify_in_another_epoch() {
        use fanos_field::F7;
        use fanos_geometry::{Plane, Point};
        use fanos_vrf::VrfSecret;

        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let sk = VrfSecret::from_seed([9u8; 32]);
        let id = b"member-9".to_vec();
        let (_, proof) = fanos_vrf::prove_coordinate::<F7>(&sk, &id, epoch, &beacon);
        let record = load_record(Demand::default(), Some(&(id.clone(), sk.public(), proof)));
        let output = fanos_vrf::coordinate_output(&sk.public(), &id, epoch, &beacon, &proof)
            .expect("the publisher's own credential yields its walk");
        let mine = (0..Plane::<F7>::N as usize)
            .map(Point::<F7>::at)
            .find(|p| fanos_vrf::probe_index_of::<F7>(&output, p).is_some())
            .expect("a walk reaches at least one point");

        assert!(
            open_load_record::<F7>(&record, mine.coords(), epoch, Some(beacon)).is_some(),
            "it verifies in the epoch it was made for"
        );
        assert!(
            open_load_record::<F7>(&record, mine.coords(), Epoch::new(4), Some(beacon)).is_none(),
            "and not in the next one — the credential names its epoch"
        );
    }

    #[test]
    fn a_load_report_round_trips() {
        let load = Demand::from_counts([25, 3, 0, 7, 0, 0]);
        assert_eq!(parse_load(&encode_load(load)), Some(load));
        assert_eq!(parse_load(b"short"), None, "a wrong-length report is rejected");
    }
}
