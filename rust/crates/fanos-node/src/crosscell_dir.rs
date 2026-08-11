//! Live **L0 cross-cell directories** over the overlay store — the transport that carries the TAXIS L0
//! primitives (`fanos_taxis::{checkpoint, crosscell, hierarchy}`) between cells (task B).
//!
//! Two overlay-store directories, both the [`crate::capdir`] pattern:
//! - **Checkpoint directory** ([`publish_checkpoint`] / [`attest_children`]) — each cell publishes its latest
//!   [`ExecCertificate`] for the epoch at a cell-and-epoch slot; a parent cell reads its children's
//!   certificates and anchors their finality through a [`ChildRegistry`], giving *live* shared security.
//! - **Cross-cell receipt inbox** ([`publish_receipt`] / [`drain_inbox`]) — a source cell publishes a
//!   [`CrossCellReceipt`] to the destination cell's inbox slot; the destination reads and (its state machine)
//!   verifies + applies it, trusting no bridge.
//!
//! The trust model is the sibling directories': a certificate/receipt is self-verifying against the *source*
//! cell's committee keys ([`ExecCertificate::verify`] / [`CrossCellReceipt::verify`]), so a forged one at a
//! cell's slot is simply rejected — never a security break. The wire forms and verification they rely on are
//! complete and tested in `fanos-taxis`.
//!
//! ## Why nothing in a shipped binary calls any of this (#167)
//!
//! [`spawn_health_publisher`] has **no callers at all**, and [`crate::spawn_checkpoint_publisher`] has one,
//! in a test. That was read for a long time as "the wiring is pending", and it is not — the missing piece is
//! not a caller.
//!
//! **A FANOS deployment has exactly one cell, or none.** `Health::reflexive` is `config.plane_order == 2`,
//! and its doc says why: the DIAKRISIS unit is a seven-member cell, and only `PG(2,2)` forms one from the
//! plane itself; on a larger plane a node discovers peers but nothing tells it which seven are its cell
//! (#145). So at `q = 2` the cell *is* the network — a cross-cell publisher's counterpart is itself — and at
//! `q > 2` no cell forms to be a counterpart. There is never a second cell.
//!
//! That also relocates the blocker. It was recorded as an open *cell-identity* question, and identity is not
//! what is missing: `overlay::cell_id` already derives a stable id per `(genesis, plane order)`, which is
//! exactly right for the one cell that exists. What is missing is a cell-**formation** mechanism above
//! `q = 2`, which is #145. Wiring a publisher before then buys an address nobody can be at.
//!
//! The `cell: u32` these slots are keyed by is the visible edge of the same thing: every caller must supply a
//! number the platform has no way to derive, because the space it would index does not exist yet.
//!
//! The observability sibling of this is [`crate::telemetry_dir::Census`], and it is worth reading together:
//! there the same "one cell only" fact was not stated, and an operator-facing verdict claimed to compare
//! cells while reading one cell's members (#280).

use fanos_code::federation;
use fanos_code::golay::{self, Report};
use fanos_quic::Client;
use fanos_rendezvous::Epoch;
use fanos_taxis::checkpoint::ExecCertificate;
use fanos_taxis::crosscell::CrossCellReceipt;
use fanos_taxis::hierarchy::ChildRegistry;

use tokio::task::JoinHandle;

use crate::DIRECTORY_SLOT_EPOCHS;
use crate::resolve::{Read, STORE_TIMEOUT};

/// A cell's checkpoint slot: the store address its latest execution certificate for `epoch` lives at.
fn checkpoint_slot(cell: u32, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/cell-checkpoint/".to_vec();
    key.extend_from_slice(&cell.to_be_bytes());
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// The slot a cell publishes its **health report** at — domain-separated, keyed by cell and epoch, exactly like
/// [`checkpoint_slot`].
fn health_slot(cell: u32, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/cell-health/".to_vec();
    key.extend_from_slice(&cell.to_be_bytes());
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// A destination cell's cross-cell inbox slot for a specific `(source cell, nonce)` message.
fn receipt_slot(dest_cell: u32, source_cell: u32, nonce: u64) -> Vec<u8> {
    let mut key = b"FANOS-v1/xcell-inbox/".to_vec();
    key.extend_from_slice(&dest_cell.to_be_bytes());
    key.extend_from_slice(&source_cell.to_be_bytes());
    key.extend_from_slice(&nonce.to_be_bytes());
    key
}

/// Publish `cell`'s execution certificate for `epoch` so a parent can anchor its finality. `false` if rejected.
pub async fn publish_checkpoint(client: &Client, cell: u32, epoch: Epoch, cert: &ExecCertificate) -> bool {
    let landed =
        client.put_ephemeral(checkpoint_slot(cell, epoch), cert.to_bytes(), DIRECTORY_SLOT_EPOCHS).await;
    crate::note_publish(client, crate::Directory::Checkpoint, epoch, landed)
}

/// Resolve the execution certificate `cell` published for `epoch`, or `None` if none/timeout/malformed.
pub async fn resolve_checkpoint(client: &Client, cell: u32, epoch: Epoch) -> Option<ExecCertificate> {
    let bytes = tokio::time::timeout(STORE_TIMEOUT, client.get(checkpoint_slot(cell, epoch))).await.ok()??;
    ExecCertificate::from_bytes(&bytes)
}

/// A parent cell anchors its `children`'s finalities for `epoch`: resolve each child's published checkpoint
/// and [`attest_available`](ChildRegistry::attest_available) it into `registry` (each child's committee must
/// already be registered). Returns the `(cell, height, state_root)` newly anchored — a child that has not
/// published, or whose certificate fails to verify, does not advance, **or whose data is not available**, is
/// skipped. This is parent-attests-child made live.
///
/// **Each child is named with its availability mask, and that is deliberate (#173).** `ChildRegistry` had two
/// public doors — `attest` and `attest_available` — differing only in whether the parent refuses to vouch for
/// a state whose data is withheld, and this function went through the unguarded one. The safe door was
/// documented as the protection and had no caller anywhere; the guarded twin is now the only door, and the
/// evidence is an argument nobody can forget to pass.
///
/// A caller with no mask for a child has two honest options and no third: leave the child out, or pass a mask
/// that says what it actually knows. `0` means "nothing present" and refuses — the safe direction. Producing
/// a real mask needs the §L4.3 sampler, which no shipped binary issues yet (#173); this signature is where
/// that shows up rather than being skipped in silence.
pub async fn attest_children(
    client: &Client,
    registry: &mut ChildRegistry,
    children: &[(u32, u8)],
    epoch: Epoch,
) -> Vec<(u32, u64, [u8; 32])> {
    let mut anchored = Vec::new();
    for &(cell, present) in children {
        if let Some(cert) = resolve_checkpoint(client, cell, epoch).await
            && let Some((height, root)) = registry.attest_available(cell, cert, present)
        {
            anchored.push((cell, height, root));
        }
    }
    anchored
}

/// Publish this cell's **health report** for `epoch`: the bitmask of its degraded axes plus whether its own bus
/// attestation is damaged. `false` if the store rejected the write.
///
/// One byte, and it is the byte the federated grammar consumes: a cell's health was already represented as a 7-bit
/// degraded-axis mask throughout DIAKRISIS (`polar::rho_vector_from_degraded`), which is exactly `golay::Report::axes`, so
/// the wire format needed no invention. The bus occupies bit 7, which is where the code puts it too.
pub async fn publish_health(client: &Client, cell: u32, epoch: Epoch, report: Report) -> bool {
    let landed = client
        .put_ephemeral(health_slot(cell, epoch), alloc_vec(report.block()), DIRECTORY_SLOT_EPOCHS)
        .await;
    crate::note_publish(client, crate::Directory::Health, epoch, landed)
}

/// One byte as a `Vec` — spelled out so the codec is visibly a single byte rather than a struct that might grow one.
fn alloc_vec(byte: u8) -> Vec<u8> { vec![byte] }

/// Resolve the health report `cell` published for `epoch`, or `None` if none/timeout/malformed.
///
/// A wrong-width value is rejected rather than parsed leniently, and the safe direction is deliberate: an absent report
/// contributes a *clean* block to the federated word (a child that says nothing is not accused), while a mis-parsed one
/// would fabricate faults and could make the grammar accuse an innocent sibling.
pub async fn resolve_health(client: &Client, cell: u32, epoch: Epoch) -> Option<Report> {
    let bytes = tokio::time::timeout(STORE_TIMEOUT, client.get(health_slot(cell, epoch))).await.ok()??;
    let [block] = <[u8; 1]>::try_from(bytes.as_slice()).ok()?;
    Some(Report { axes: block & 0x7F, bus_fault: block >> golay::AXES & 1 == 1 })
}

/// A parent cell diagnoses its seven `children` for `epoch`: resolve each child's published health report and run the
/// **Turyn federated covering** over them (`docs/design-federation.md`).
///
/// This is the last mile of the federation work — the algebra was complete and had nothing feeding it. The parent gets a
/// verdict strictly stronger than per-child self-diagnosis: up to three faults anywhere across its children are localized to
/// `(child, axis)`, including all three inside one child, where that child's own Hamming(7,4) would have answered
/// confidently and wrongly. Beyond the grammar's reach the verdict is `Partial`, naming what remains unexplained rather
/// than inventing an attribution.
///
/// `children` is indexed by position in the parent's plane, so `children[p]` is the cell at point `p` — the covering's
/// federations are the parent's *lines*, and a line names points, not cells. A child that has not published is read as
/// clean for the reason `resolve_health` documents.
pub async fn diagnose_children(
    client: &Client,
    children: &[u32; federation::CHILDREN],
    epoch: Epoch,
) -> federation::Cell {
    let mut reports = [Report::default(); federation::CHILDREN];
    for (slot, &cell) in reports.iter_mut().zip(children.iter()) {
        if let Some(r) = resolve_health(client, cell, epoch).await {
            *slot = r;
        }
    }
    // SELF-REPORTED, and the distinction is load-bearing: these masks are what each child says about *itself*, so a child
    // controlling its own eight coordinates could otherwise relocate blame onto a healthy sibling — the Golay decoder
    // corrects by moving to the nearest codeword, so injected coordinates do not add noise, they move the blame. See
    // `fanos_code::golay::Provenance`. A peer-measured source keeps the full `t = 3`; this one does not.
    federation::diagnose_cell(reports, golay::Provenance::SelfReported)
}

/// Keep this cell's health report **live**: spawn the task that publishes `health()`'s current view each epoch.
///
/// Mirrors [`crate::capdir::spawn_capability_publisher`] — a closure so this module stays agnostic to how a cell observes
/// its own axes, which is DIAKRISIS's business and not the directory's. Ends when the notification stream closes.
#[must_use]
pub fn spawn_health_publisher(
    client: Client,
    cell: u32,
    health: impl Fn() -> Report + Send + 'static,
) -> JoinHandle<()> {
    // Supervised: this actor's death is a capability the node loses, and the counters that would
    // have shown it are written by the actor itself (#251).
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        let mut beacons = client.beacons();
        let mut epoch = Epoch::ZERO;
        publish_health(&client, cell, epoch, health()).await;
        // Latest-state, not the lossy stream: a cell whose health report is missing for an epoch reads to its
        // neighbours as a cell that has nothing to say, which is not the same as one that is healthy (#86).
        while let Some((e, _)) = crate::next_epoch(&mut beacons, epoch).await {
            epoch = e;
            publish_health(&client, cell, epoch, health()).await;
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::HealthPublisher, &supervised, task)
}

/// Publish a cross-cell `receipt` into the destination cell's inbox (addressed by source cell + message nonce).
/// `false` if the store rejected the write.
pub async fn publish_receipt(client: &Client, source_cell: u32, receipt: &CrossCellReceipt) -> bool {
    let slot = receipt_slot(receipt.msg.dest_cell, source_cell, receipt.msg.nonce);
    client.put(slot, receipt.to_bytes()).await
}

/// Read the cross-cell receipt for `(dest_cell, source_cell, nonce)` from the inbox, three-valued. The caller
/// verifies it against the source cell's committee ([`CrossCellReceipt::verify`]) before applying — no trust in
/// the relaying bridge or the store.
///
/// [`Read::Absent`] and [`Read::Unknown`] are kept apart because [`drain_inbox`] has to tell them apart: an
/// empty slot ends a walk, a timeout must not.
pub async fn read_receipt(
    client: &Client,
    dest_cell: u32,
    source_cell: u32,
    nonce: u64,
) -> Read<CrossCellReceipt> {
    // `read`, not `get`: `get` collapses "the slot is empty" and "the read did not conclude" into one
    // `None`, and telling those apart is the whole of the walk below.
    Read::of(
        tokio::time::timeout(STORE_TIMEOUT, client.read(receipt_slot(dest_cell, source_cell, nonce)))
            .await
            .ok(),
        CrossCellReceipt::from_bytes,
    )
}

/// What a drain does with one slot's read — the whole content of [`drain_inbox`], named.
///
/// Carries the receipt rather than reporting on it, so the walk applies the rule to the value it actually
/// read. A verdict computed from one read and then acted on by re-reading is two readings of two moments.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum Step<T> {
    /// A receipt is here: apply it and advance the cursor.
    Take(T),
    /// A **definite** gap — the source has published nothing at this nonce. Nonces are per-source monotonic
    /// (`fanos_taxis::crosscell`), so nothing beyond it can exist yet: the inbox is drained to here, and the
    /// cursor stops at this nonce because it is where the next message will land.
    Exhausted,
    /// The read did not conclude. The walk ends and **concludes nothing**: the cursor does not advance, and
    /// the result is not evidence of an empty inbox.
    ///
    /// This is the one distinction that makes a drain safe to run repeatedly. Folding it into `Exhausted`
    /// would let one timeout mark the inbox drained and skip every message behind the gap, permanently — the
    /// `Read` rule this crate states without exception: an incomplete scan may make a caller decline to act,
    /// never act on a substitute.
    Inconclusive,
}

/// The drain's rule, as a function of one read.
pub fn step<T>(read: Read<T>) -> Step<T> {
    match read {
        Read::Found(receipt) => Step::Take(receipt),
        Read::Absent => Step::Exhausted,
        Read::Unknown => Step::Inconclusive,
    }
}

/// What one drain pass recovered, and whether it saw the bottom of the inbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drained<T> {
    /// The receipts, in nonce order from the requested start. **Unverified** — the caller checks each
    /// against the source cell's committee before applying.
    pub receipts: Vec<T>,
    /// The nonce to resume from next time.
    pub next: u64,
    /// Whether the walk ended at a definite gap. `false` means a read did not conclude or the cap was hit,
    /// so the inbox may hold more at [`next`](Self::next) and this pass is **not** evidence of an empty one.
    pub complete: bool,
}

/// Walk `(dest_cell ← source_cell)` from nonce `from`, taking at most `max` receipts.
///
/// The inbox had a writer and no reader: [`publish_receipt`] addresses a slot by the nonce carried *inside*
/// the message, and [`read_receipt`] asks for a nonce, so a destination could only fetch a letter whose
/// serial number it already knew. Nothing enumerated the slots, and nothing could — which is why the module
/// header named a `drain_inbox` that was never written.
///
/// The walk is derived rather than chosen: nonces are **per-source monotonic** and the destination applies
/// each `(source, nonce)` at most once, so successive nonces from a remembered cursor *are* the enumeration.
/// The rule at each step is [`step`], and the whole reason it is three-valued is stated there.
///
/// `max` is the caller's, never a constant here: this is an unbounded read of a remote-controlled sequence,
/// and the ceiling belongs to whoever has to hold the result (#194).
pub async fn drain_inbox(
    client: &Client,
    dest_cell: u32,
    source_cell: u32,
    from: u64,
    max: usize,
) -> Drained<CrossCellReceipt> {
    drain_with(from, max, |nonce| read_receipt(client, dest_cell, source_cell, nonce)).await
}

/// [`drain_inbox`]'s walk with the store lifted out, so the loop can be tested without one.
///
/// The split is not for convenience. What can be wrong here is the *stopping rule* and the cursor, and a
/// test that needs a live overlay to reach them is a test that will not be written for a mechanism no
/// deployment can run yet (#167: there is never a second cell).
async fn drain_with<T, F, Fut>(from: u64, max: usize, read: F) -> Drained<T>
where
    F: Fn(u64) -> Fut,
    Fut: Future<Output = Read<T>>,
{
    let mut receipts = Vec::new();
    let mut nonce = from;
    loop {
        if receipts.len() >= max {
            // The cap is not a gap. Stopping here says nothing about what is at `nonce`.
            return Drained { receipts, next: nonce, complete: false };
        }
        match step(read(nonce).await) {
            Step::Take(receipt) => {
                receipts.push(receipt);
                nonce += 1;
            }
            Step::Exhausted => return Drained { receipts, next: nonce, complete: true },
            Step::Inconclusive => return Drained { receipts, next: nonce, complete: false },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_slots_are_deterministic_distinct_and_domain_separated() {
        let h = health_slot(3, Epoch::new(7));
        assert_eq!(h, health_slot(3, Epoch::new(7)));
        assert_ne!(h, health_slot(4, Epoch::new(7)), "distinct cell → distinct slot");
        assert_ne!(h, health_slot(3, Epoch::new(8)), "distinct epoch → distinct slot");
        assert!(h.starts_with(b"FANOS-v1/cell-health/"));
        assert!(!h.starts_with(b"FANOS-v1/cell-checkpoint/"), "a distinct domain from its sibling directory");
    }

    #[test]
    fn a_health_report_is_one_byte_and_round_trips_through_it() {
        // The wire format needed no invention: a cell's health was already a 7-bit degraded-axis mask throughout
        // DIAKRISIS, which is exactly golay::Report::axes, with the bus in bit 7 — where the code puts it too.
        for axes in 0u8..128 {
            for bus_fault in [false, true] {
                let r = Report { axes, bus_fault };
                let block = r.block();
                assert_eq!(block & 0x7F, axes);
                assert_eq!(block >> golay::AXES & 1 == 1, bus_fault);
                let decoded = Report { axes: block & 0x7F, bus_fault: block >> golay::AXES & 1 == 1 };
                assert_eq!(decoded, r, "one byte, and it round-trips");
            }
        }
        assert_eq!(alloc_vec(0x81).len(), 1, "a single byte on the wire, not a struct that might grow one");
    }

    #[test]
    fn an_absent_child_reads_as_clean_rather_than_accused() {
        // The safe direction, and it is the one that matters for a grammar: a child that has published nothing
        // contributes a clean block, so silence is never turned into an accusation against it — or, worse, into faults
        // that make the covering blame an innocent sibling.
        let quiet = Report::default();
        assert_eq!(quiet.block(), 0);
        assert_eq!(
            federation::diagnose_cell([Report::default(); federation::CHILDREN], golay::Provenance::Measured),
            federation::Cell::Healthy,
            "seven silent children are healthy, not seven accusations"
        );
    }

    #[test]
    fn a_parents_verdict_over_its_children_is_stronger_than_their_self_diagnosis() {
        // What the directory buys, expressed on the reports it carries. Three faulty axes inside one child: that child's
        // own Hamming(7,4) answers with a confident WRONG single-fault verdict, while the parent's federated covering
        // names all three, and the right child.
        let mut reports = [Report::default(); federation::CHILDREN];
        reports[5] = Report { axes: 0b0100_1001, bus_fault: false }; // axes 0, 3, 6
        let federation::Cell::Localized(f) = federation::diagnose_cell(reports, golay::Provenance::Measured) else {
            panic!("three faults must localize")
        };
        assert_eq!(f.axes[5], 0b0100_1001, "all three named, and attributed to child 5");
        assert_eq!(f.total(), 3);

        // The lone-cell contrast: Hamming returns *a* position for a triple fault — confidently, and wrongly.
        assert!(fanos_code::hamming::locate_single(0b0100_1001).is_some());
    }

    #[test]
    fn checkpoint_and_receipt_slots_are_deterministic_distinct_and_domain_separated() {
        // Checkpoint slots.
        let c = checkpoint_slot(1, Epoch::ZERO);
        assert_eq!(c, checkpoint_slot(1, Epoch::ZERO));
        assert_ne!(c, checkpoint_slot(2, Epoch::ZERO), "distinct cell → distinct slot");
        assert_ne!(c, checkpoint_slot(1, Epoch::new(1)), "distinct epoch → distinct slot");
        assert!(c.starts_with(b"FANOS-v1/cell-checkpoint/"));
        // Receipt slots.
        let r = receipt_slot(2, 1, 0);
        assert_eq!(r, receipt_slot(2, 1, 0));
        assert_ne!(r, receipt_slot(2, 1, 1), "distinct nonce → distinct inbox slot");
        assert_ne!(r, receipt_slot(3, 1, 0), "distinct destination → distinct inbox");
        assert_ne!(r, receipt_slot(2, 4, 0), "distinct source → distinct inbox");
        assert!(r.starts_with(b"FANOS-v1/xcell-inbox/"));
        // The two directories are domain-separated from each other and from the capability directory.
        assert!(!c.starts_with(b"FANOS-v1/xcell-inbox/") && !r.starts_with(b"FANOS-v1/cell-checkpoint/"));
        assert!(!c.starts_with(b"FANOS-v1/cap-desc/") && !r.starts_with(b"FANOS-v1/cap-desc/"));
    }

    // The walk is tested over `u64` rather than a receipt, because the walk does not depend on what it
    // carries — and a hand-built receipt fixture would be a second thing that can be wrong about a
    // mechanism nothing runs yet. Decoding is `CrossCellReceipt::from_bytes`, tested where it lives.

    /// One pass drains what is there, in order, and says it saw the bottom.
    #[tokio::test]
    async fn a_drain_walks_the_monotonic_nonces_and_stops_at_a_definite_gap() {
        let drained = drain_with(4, 100, |n| async move {
            if (4..7).contains(&n) { Read::Found(n) } else { Read::Absent }
        })
        .await;
        assert_eq!(drained.receipts, vec![4, 5, 6], "the walk takes successive nonces from the cursor");
        assert_eq!(drained.next, 7, "and resumes where the next message will land");
        assert!(drained.complete, "an empty slot is a definite bottom");
    }

    /// **The distinction the type exists for.** A timeout must not be read as an empty inbox.
    ///
    /// Falsify by mapping `Read::Unknown` to `Step::Exhausted`: this goes green on the receipts and red on
    /// `complete`, and the failure it stands for is permanent — a drain that concluded "empty" advances
    /// nothing, so every message behind the gap is skipped for good.
    #[tokio::test]
    async fn a_read_that_did_not_conclude_is_not_an_empty_inbox() {
        let drained = drain_with(0, 100, |n| async move {
            if n < 2 { Read::Found(n) } else { Read::Unknown }
        })
        .await;
        assert_eq!(drained.receipts.len(), 2, "what was read is still returned");
        assert_eq!(drained.next, 2, "the cursor stops at the slot that did not answer");
        assert!(!drained.complete, "and the pass must not claim the inbox is empty");
    }

    /// The cap is the caller's, and hitting it is not a gap either.
    #[tokio::test]
    async fn the_callers_cap_stops_the_walk_without_concluding_anything() {
        let drained = drain_with(0, 3, |n| async move { Read::Found(n) }).await;
        assert_eq!(drained.receipts.len(), 3);
        assert_eq!(drained.next, 3);
        assert!(!drained.complete, "an inbox longer than the cap is not an inbox that ended");
    }

    /// An empty inbox and an unreachable one are different answers to the same question.
    #[tokio::test]
    async fn an_empty_inbox_and_an_unreachable_one_are_told_apart() {
        let empty = drain_with::<u64, _, _>(0, 10, |_| async { Read::Absent }).await;
        let unreachable = drain_with::<u64, _, _>(0, 10, |_| async { Read::Unknown }).await;
        assert_eq!(empty.receipts, unreachable.receipts, "neither returns anything");
        assert_eq!(empty.next, unreachable.next, "neither moves the cursor");
        assert!(empty.complete && !unreachable.complete, "and only one of them is a reading");
    }
}
