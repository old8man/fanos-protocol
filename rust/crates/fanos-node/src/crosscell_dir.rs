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
//! cell's slot is simply rejected — never a security break. **These are transport-ready:** they compose with a
//! TAXIS engine running over the real transport (a validator publishing its `latest_checkpoint`), which is the
//! remaining live-node piece; the wire forms + verification they rely on are complete and tested in
//! `fanos-taxis`.

use fanos_code::federation;
use fanos_code::golay::{self, Report};
use fanos_quic::Client;
use fanos_rendezvous::Epoch;
use fanos_taxis::checkpoint::ExecCertificate;
use fanos_taxis::crosscell::CrossCellReceipt;
use fanos_taxis::hierarchy::ChildRegistry;

use fanos_runtime::Notification;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::resolve::RESOLVE_TIMEOUT;

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
    client.put(checkpoint_slot(cell, epoch), cert.to_bytes()).await
}

/// Resolve the execution certificate `cell` published for `epoch`, or `None` if none/timeout/malformed.
pub async fn resolve_checkpoint(client: &Client, cell: u32, epoch: Epoch) -> Option<ExecCertificate> {
    let bytes = tokio::time::timeout(RESOLVE_TIMEOUT, client.get(checkpoint_slot(cell, epoch))).await.ok()??;
    ExecCertificate::from_bytes(&bytes)
}

/// A parent cell anchors its `children`'s finalities for `epoch`: resolve each child's published checkpoint and
/// [`attest`](ChildRegistry::attest) it into `registry` (each child's committee must already be registered).
/// Returns the `(cell, height, state_root)` newly anchored — a child that has not published, or whose
/// certificate fails to verify or does not advance, is skipped. This is parent-attests-child made live.
pub async fn attest_children(
    client: &Client,
    registry: &mut ChildRegistry,
    children: &[u32],
    epoch: Epoch,
) -> Vec<(u32, u64, [u8; 32])> {
    let mut anchored = Vec::new();
    for &cell in children {
        if let Some(cert) = resolve_checkpoint(client, cell, epoch).await
            && let Some((height, root)) = registry.attest(cell, cert)
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
    client.put(health_slot(cell, epoch), alloc_vec(report.block())).await
}

/// One byte as a `Vec` — spelled out so the codec is visibly a single byte rather than a struct that might grow one.
fn alloc_vec(byte: u8) -> Vec<u8> { vec![byte] }

/// Resolve the health report `cell` published for `epoch`, or `None` if none/timeout/malformed.
///
/// A wrong-width value is rejected rather than parsed leniently, and the safe direction is deliberate: an absent report
/// contributes a *clean* block to the federated word (a child that says nothing is not accused), while a mis-parsed one
/// would fabricate faults and could make the grammar accuse an innocent sibling.
pub async fn resolve_health(client: &Client, cell: u32, epoch: Epoch) -> Option<Report> {
    let bytes = tokio::time::timeout(RESOLVE_TIMEOUT, client.get(health_slot(cell, epoch))).await.ok()??;
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
    tokio::spawn(async move {
        let mut events = client.subscribe();
        let mut epoch = Epoch::ZERO;
        publish_health(&client, cell, epoch, health()).await;
        loop {
            match events.recv().await {
                Ok(Notification::BeaconReady { epoch: e, .. }) => {
                    if e > epoch {
                        epoch = e;
                        publish_health(&client, cell, epoch, health()).await;
                    }
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// Publish a cross-cell `receipt` into the destination cell's inbox (addressed by source cell + message nonce).
/// `false` if the store rejected the write.
pub async fn publish_receipt(client: &Client, source_cell: u32, receipt: &CrossCellReceipt) -> bool {
    let slot = receipt_slot(receipt.msg.dest_cell, source_cell, receipt.msg.nonce);
    client.put(slot, receipt.to_bytes()).await
}

/// Read the cross-cell receipt for `(dest_cell, source_cell, nonce)` from the inbox, or `None`. The caller
/// verifies it against the source cell's committee ([`CrossCellReceipt::verify`]) before applying — no trust in
/// the relaying bridge or the store.
pub async fn read_receipt(
    client: &Client,
    dest_cell: u32,
    source_cell: u32,
    nonce: u64,
) -> Option<CrossCellReceipt> {
    let bytes =
        tokio::time::timeout(RESOLVE_TIMEOUT, client.get(receipt_slot(dest_cell, source_cell, nonce))).await.ok()??;
    CrossCellReceipt::from_bytes(&bytes)
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
}
