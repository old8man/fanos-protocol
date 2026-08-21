//! The **published cell-diagnosis directory** — the record set a node's reputation is recomputed from.
//!
//! Every node writes one record per epoch, coordinate-bound, saying which of its cell's members it found
//! degraded and which it heard from at all. Every node then reads a *closed* window of those records and
//! recomputes the whole reputation from them ([`fanos_core::roles::Reputation::from_published`]).
//!
//! ## Why a directory at all, when the node already measures this
//!
//! The engine's `Notification::Liveness` carries exactly these two masks, and reputation used to be folded
//! from them directly with `observe_reachable`. That is a **carried accumulator over a local measurement**,
//! and both halves are wrong for a decision the cell must agree on. Local: `coord_alive` trusts its own eyes
//! before any corroboration, so two healthy nodes genuinely disagree about a peer they have contacted
//! differently. Carried: the disagreement is written into the score and never washes out — every node's
//! `adjust`, and therefore the cell's whole role assignment, forks with it and stays forked.
//!
//! Publishing turns the local measurement into *evidence*, and recomputing from a closed epoch turns the
//! score into a function of agreed bytes. A node that read a stale set converges the moment it re-reads,
//! which an accumulator cannot offer.
//!
//! ## Retention, and why it is not `DIRECTORY_SLOT_EPOCHS`
//!
//! The routing directories are retained for one epoch: a *reader* needs only the grace a lagging peer needs.
//! A diagnosis reader deliberately wants history — `REP_WINDOW` epochs of it — so these records live at
//! `DIAGNOSIS_SLOT_EPOCHS`, which **is** `REP_WINDOW`. The two constants
//! answer different questions and are derived separately for that reason.
//!
//! Because the window outlives every other directory's retention, a record cannot refer to anything outside
//! itself: the epoch's seating is *in* the record
//! ([`DiagnosisRecord::roster`](fanos_core::roles::DiagnosisRecord::roster)), because the capability
//! directory that would answer "who sat at point 3 six epochs ago" is long gone.

use fanos_core::roles::DiagnosisRecord;
use fanos_diaulos::Coord;
use fanos_field::Field;
use fanos_geometry::Point;
use fanos_primitives::{BeaconSeed, NodeId};
use fanos_quic::Client;
use fanos_rendezvous::Epoch;

use crate::DIAGNOSIS_SLOT_EPOCHS;
use crate::bound::Entitlement;
use crate::capdir::{Seating, plane_cap_coords};
use crate::resolve::{Coverage, Read, STORE_TIMEOUT, resolve_directory};

/// The overlay store slot a node's per-epoch diagnosis lives at — domain-separated, keyed by coordinate and
/// epoch, exactly like [`crate::loaddir`]'s load report.
fn diagnosis_slot(coord: Coord, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/cell-diagnosis/".to_vec();
    key.extend_from_slice(&fanos_geometry::encode_triple(coord));
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// A diagnosis record's canonical width: the two masks, then seven seats of 32 bytes each.
///
/// An empty seat is 32 zero bytes rather than a length prefix or a presence bitmap, so the record is
/// fixed-width and a truncated one is refused rather than parsed as a shorter cell. `NodeId([0; 32])` is not
/// a reachable identity — it is `H(bundle)` — so the encoding loses nothing.
const DIAGNOSIS_BYTES: usize = 2 + 7 * 32;

/// The empty-seat sentinel; see `DIAGNOSIS_BYTES`.
const NO_SEAT: [u8; 32] = [0u8; 32];

/// Encode `(degraded, responsive, roster)` — the inverse of [`parse_diagnosis`].
#[must_use]
fn encode_diagnosis(degraded: u8, responsive: u8, roster: &Seating) -> [u8; DIAGNOSIS_BYTES] {
    let mut out = [0u8; DIAGNOSIS_BYTES];
    out[0] = degraded;
    out[1] = responsive;
    for (i, seat) in roster.iter().enumerate() {
        if let (Some(NodeId(bytes)), Some(slot)) = (seat, out.get_mut(2 + i * 32..2 + i * 32 + 32)) {
            slot.copy_from_slice(bytes);
        }
    }
    out
}

/// The masks and seating a record carries, or `None` if it is not exactly `DIAGNOSIS_BYTES` wide.
#[must_use]
pub fn parse_diagnosis(bytes: &[u8]) -> Option<(u8, u8, Seating)> {
    if bytes.len() != DIAGNOSIS_BYTES {
        return None;
    }
    let (degraded, responsive) = (*bytes.first()?, *bytes.get(1)?);
    let mut roster: Seating = [None; 7];
    for (i, seat) in roster.iter_mut().enumerate() {
        let at = 2 + i * 32;
        let id: [u8; 32] = bytes.get(at..at + 32)?.try_into().ok()?;
        *seat = (id != NO_SEAT).then_some(NodeId(id));
    }
    Some((degraded, responsive, roster))
}

/// Publish this node's view of `epoch`: which members it found `degraded`, which it found `responsive`, and
/// the `roster` those bits are indexed against. Returns whether the write landed.
///
/// `credential` is the coordinate proof, present exactly where the deployment has VRF coordinates — the same
/// `Option`-is-the-mode rule as every other directory (`crate::bound`). Without the binding, one member could
/// write every other member's slot and manufacture a quorum against anyone.
pub async fn publish_diagnosis(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    degraded: u8,
    responsive: u8,
    roster: &Seating,
    credential: Option<&(Vec<u8>, fanos_vrf::VrfPublic, fanos_vrf::VrfProof)>,
) -> bool {
    let payload = encode_diagnosis(degraded, responsive, roster);
    let record = match credential {
        Some((id, public, proof)) => Entitlement::encode(id, public, proof, &payload),
        None => payload.to_vec(),
    };
    let landed = client
        .put_ephemeral(diagnosis_slot(coord, epoch), record, DIAGNOSIS_SLOT_EPOCHS)
        .await;
    crate::note_publish(client, crate::Directory::Diagnosis, epoch, landed)
}

/// The inverse of the publish encoding: the record's contents, or `None` if malformed or — when `beacon` is
/// `Some` — not bound to `coord` for `epoch`.
#[must_use]
fn open_diagnosis<F: Field>(
    bytes: &[u8],
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<(u8, u8, Seating)> {
    match beacon {
        Some(seed) => {
            let (_, payload) = Entitlement::open::<F>(bytes, coord, epoch, &seed)?;
            parse_diagnosis(payload)
        }
        None => parse_diagnosis(bytes),
    }
}

/// Read one member's diagnosis, distinguishing a read that **did not conclude** from a definite absence.
///
/// A record that fails its coordinate binding is a definite absence, for the same reason as the load
/// directory: the slot holds something and it is not this coordinate's diagnosis, so the member contributed
/// no evidence — which is exactly what an absence means to the quorum. Treating it as `Unknown` would let one
/// forged record make the whole window incomplete, and an incomplete window is one this loop declines to act
/// on: a cheaper attack than the one the binding closes.
async fn read_diagnosis<F: Field>(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Read<(u8, u8, Seating)> {
    Read::of(
        tokio::time::timeout(STORE_TIMEOUT, client.read(diagnosis_slot(coord, epoch))).await.ok(),
        |b| open_diagnosis::<F>(b, coord, epoch, beacon),
    )
}

/// Collect every member's diagnosis for the **closed** epochs `window`, as the record set
/// [`fanos_core::roles::Reputation::from_published`] consumes, plus whether every read concluded.
///
/// The `(epoch, seed)` pairs are given rather than derived because a record is bound against the seed of the
/// epoch it was **published in**, not the current one — a credential names its epoch, so verifying an old
/// record against today's seed rejects all of them. This is the same rule `role_loop` already follows for the
/// load directory, applied over several epochs instead of one.
///
/// **Completeness is per-window, not per-epoch.** A caller that folded only the epochs that resolved would
/// compute a score from a subset another node might not have, which is the exact divergence recomputing
/// exists to remove — so the flag covers the whole read and the caller either uses all of it or none.
pub async fn read_diagnosis_window<F: Field>(
    client: &Client,
    window: &[(Epoch, BeaconSeed)],
    vrf: bool,
) -> (Vec<DiagnosisRecord>, Coverage) {
    let mut records = Vec::new();
    // Summed, not AND-folded. Both answer "did the whole window resolve", and only the sum answers "by how much it
    // fell short" — over a three-epoch window that is up to 21 reads, which an AND of ANDs compresses to one bit.
    let mut unresolved = 0usize;
    for (epoch, seed) in window {
        let (epoch, seed) = (*epoch, *seed);
        let scan =
            resolve_directory(client, plane_cap_coords::<F>(), move |client, coord| async move {
                read_diagnosis::<F>(&client, coord, epoch, vrf.then_some(seed)).await
            })
            .await;
        unresolved += scan.unknown;
        for (coord, (degraded, responsive, roster)) in scan.found {
            // The publisher index is the POINT the record was written at, taken from the slot rather than
            // from the record: a self-declared index would let one member publish seven records and satisfy
            // any quorum alone. Points past the seventh cannot be a publisher in the reflex's index space.
            let Some(publisher) = Point::<F>::new(coord).map(|p| p.index()).filter(|i| *i < 7) else {
                continue;
            };
            records.push(DiagnosisRecord {
                publisher: u8::try_from(publisher).unwrap_or(u8::MAX),
                epoch: epoch.get(),
                roster,
                degraded,
                responsive,
            });
        }
    }
    (records, Coverage { unresolved })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use super::*;

    fn seating() -> Seating {
        let mut s: Seating = [None; 7];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = Some(NodeId([i as u8 + 1; 32]));
        }
        s
    }

    #[test]
    fn diagnosis_slots_are_deterministic_distinct_and_domain_separated() {
        let a = diagnosis_slot([1, 2, 3], Epoch::ZERO);
        assert_eq!(a, diagnosis_slot([1, 2, 3], Epoch::ZERO));
        assert_ne!(a, diagnosis_slot([1, 2, 4], Epoch::ZERO));
        assert_ne!(a, diagnosis_slot([1, 2, 3], Epoch::new(1)));
        assert!(a.starts_with(b"FANOS-v1/cell-diagnosis/"));
        // And it does not collide with the load directory's slot for the same coordinate and epoch, which
        // shares its shape and would otherwise let one write clobber the other.
        assert_ne!(a, {
            let mut k = b"FANOS-v1/role-load/".to_vec();
            k.extend_from_slice(&fanos_geometry::encode_triple([1, 2, 3]));
            k.extend_from_slice(&Epoch::ZERO.to_be_bytes());
            k
        });
    }

    /// The codec round-trips, **including the empty seats** — the case a presence bitmap would have got
    /// wrong and a fixed-width sentinel cannot.
    #[test]
    fn a_diagnosis_round_trips_with_gaps_in_the_seating() {
        let mut roster = seating();
        roster[2] = None;
        roster[6] = None;
        let bytes = encode_diagnosis(0b0010_1001, 0b0111_1111, &roster);
        let (degraded, responsive, back) =
            parse_diagnosis(&bytes).expect("a record this module wrote parses");
        assert_eq!(degraded, 0b0010_1001);
        assert_eq!(responsive, 0b0111_1111);
        assert_eq!(back, roster, "the empty seats survived the round trip as empty");
    }

    /// A short or long record is refused rather than parsed as a smaller cell.
    ///
    /// Written as a loop over every truncation because the interesting failure is not "empty input": it is a
    /// record cut inside a seat, where a length-prefixed decoder would happily return the seats before the
    /// cut and a reader would count a quorum over a roster the publisher never wrote.
    #[test]
    fn a_record_that_is_not_exactly_the_canonical_width_is_refused() {
        let bytes = encode_diagnosis(1, 0xFF, &seating());
        for cut in 0..bytes.len() {
            assert!(
                parse_diagnosis(&bytes[..cut]).is_none(),
                "a record truncated to {cut} of {DIAGNOSIS_BYTES} bytes parsed",
            );
        }
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(parse_diagnosis(&longer).is_none(), "an over-long record parsed");
        assert!(parse_diagnosis(&bytes).is_some(), "the canonical width itself is accepted");
    }
}
