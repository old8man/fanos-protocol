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

use fanos_quic::Client;
use fanos_rendezvous::Epoch;
use fanos_taxis::checkpoint::ExecCertificate;
use fanos_taxis::crosscell::CrossCellReceipt;
use fanos_taxis::hierarchy::ChildRegistry;

use crate::resolve::RESOLVE_TIMEOUT;

/// A cell's checkpoint slot: the store address its latest execution certificate for `epoch` lives at.
fn checkpoint_slot(cell: u32, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/cell-checkpoint/".to_vec();
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
