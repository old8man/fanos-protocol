//! The **THESAUROS storage market on the ledger** — the `TAG_STORAGE` transaction family that turns the
//! sans-I/O deal engine (`fanos-thesauros`) into real currency movement (`docs/design-storage.md` §6).
//!
//! A consumer **opens** a deal by escrowing the price into the keyless [`STORAGE_ESCROW`] sink (an ordinary
//! signed transfer); a provider **proves** retrievability each audit epoch and is paid its slice from escrow the
//! instant the proof verifies — the exact "keyless sink released by a proof" idiom the shielded pool's unshield
//! uses (`hybrid::apply_shielded`), now driven by [`fanos_thesauros::verify`] instead of a range proof; a
//! consumer **closes** to reclaim any unproven escrow. No bond, no staking (it would deanonymise): a provider
//! that stops proving simply stops being paid.
//!
//! **Audit soundness rests on the beacon.** The challenge for a deal at an epoch is
//! `challenge(cid, beacon, k, leaves)` — the provider must answer *the leaves that beacon selects*. For the
//! audit to be unforgeable the `beacon` must be the block's **unpredictable PQ-VRF beacon** (fed by the
//! consensus driver via `HybridLedger::set_audit_beacon`), so a provider cannot pick a beacon that only
//! challenges leaves it kept. With a predictable beacon the audit is grindable — hence the driver contract.

use std::collections::BTreeMap;

use fanos_primitives::hash_labeled;
use fanos_thesauros::content::LEAF;
use fanos_thesauros::{Deal, DealParams, DealState};

use crate::token::SignedTransfer;

/// The keyless sink that holds deal escrow — funds enter by a signed transfer and leave only by `move_system`
/// gated on a verified retrievability proof (or a consumer-authorised close).
pub const STORAGE_ESCROW: [u8; 32] = *b"FANOS-thesauros-storage-escrow!!";

/// The storage-audit cadence: blocks per audit epoch. A deal's audit deadline is
/// `open_height + duration · AUDIT_PERIOD`; at that height an un-proven deal auto-completes and its unproven
/// escrow refunds to the consumer (audit AT-H2), so a stalled deal never sits `Active` forever awaiting a manual
/// close. A protocol parameter (like the block time), not a per-deal secret.
pub const AUDIT_PERIOD: u64 = 64;

/// Domain label for a deal identifier.
const DEAL_ID_LABEL: &str = "FANOS-dromos-v1/storage-deal";
/// Domain label for the storage-market sub-state root.
const STORAGE_ROOT_LABEL: &str = "FANOS-dromos-v1/storage-root";

/// Transaction subtype tag within `TAG_STORAGE`.
const OP_OPEN: u8 = 0x00;
const OP_PROVE: u8 = 0x01;
const OP_CLOSE: u8 = 0x02;

/// A deal's on-ledger identifier: `H(params ‖ funding-nonce)`, so a consumer's distinct escrow transfers open
/// distinct deals even for identical parameters.
#[must_use]
pub fn deal_id(params: &DealParams, funding_nonce: u64) -> [u8; 32] {
    let mut buf = params.to_bytes();
    buf.extend_from_slice(&funding_nonce.to_le_bytes());
    hash_labeled(DEAL_ID_LABEL, &buf)
}

/// A storage-market transaction. (Not `Debug`: it carries a `SignedTransfer`, whose PQ verifier is not `Debug`.)
#[derive(Clone)]
pub enum StorageTx {
    /// Open a deal, funding its escrow with `payment` (consumer → [`STORAGE_ESCROW`], amount = price).
    Open {
        /// The deal terms.
        params: DealParams,
        /// The escrow-funding signed transfer.
        payment: SignedTransfer,
    },
    /// Prove retrievability for the deal's current epoch; `response` is a `fanos_thesauros::encode_response`.
    Prove {
        /// The deal being proven.
        deal_id: [u8; 32],
        /// A signed transfer *from the provider, to the deal id* (verified, never applied) authorising the
        /// proof — binds the payment-triggering proof to the designated provider, so a third party holding a
        /// replica of the public leaves cannot make the provider be paid for data it deleted (audit AT-H1).
        prover_auth: SignedTransfer,
        /// The encoded audit response.
        response: Vec<u8>,
    },
    /// Close a deal early and refund unproven escrow to the consumer; `auth` proves the caller is the consumer.
    Close {
        /// The deal being closed.
        deal_id: [u8; 32],
        /// A signed transfer *from the consumer* (verified, never applied) authorising the close.
        auth: SignedTransfer,
    },
}

impl StorageTx {
    /// Canonical bytes: `op(1) ‖ …`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            StorageTx::Open { params, payment } => {
                out.push(OP_OPEN);
                out.extend_from_slice(&params.to_bytes());
                out.extend_from_slice(&payment.to_bytes());
            }
            StorageTx::Prove { deal_id, prover_auth, response } => {
                out.push(OP_PROVE);
                out.extend_from_slice(deal_id);
                out.extend_from_slice(&prover_auth.to_bytes());
                out.extend_from_slice(response);
            }
            StorageTx::Close { deal_id, auth } => {
                out.push(OP_CLOSE);
                out.extend_from_slice(deal_id);
                out.extend_from_slice(&auth.to_bytes());
            }
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&op, body) = bytes.split_first()?;
        match op {
            OP_OPEN => {
                let params = DealParams::from_bytes(body.get(..fanos_thesauros::DEAL_PARAMS_LEN)?)?;
                let payment = SignedTransfer::from_bytes(body.get(fanos_thesauros::DEAL_PARAMS_LEN..)?)?;
                Some(StorageTx::Open { params, payment })
            }
            OP_PROVE => {
                let deal_id = body.get(..32)?.try_into().ok()?;
                let auth_end = 32usize.checked_add(SignedTransfer::WIRE_LEN)?;
                let prover_auth = SignedTransfer::from_bytes(body.get(32..auth_end)?)?;
                let response = body.get(auth_end..)?.to_vec();
                Some(StorageTx::Prove { deal_id, prover_auth, response })
            }
            OP_CLOSE => Some(StorageTx::Close {
                deal_id: body.get(..32)?.try_into().ok()?,
                auth: SignedTransfer::from_bytes(body.get(32..)?)?,
            }),
            _ => None,
        }
    }
}

/// The storage market sub-state: the live deals, keyed by [`deal_id`].
#[derive(Clone, Debug, Default)]
pub struct StorageMarket {
    pub(crate) deals: BTreeMap<[u8; 32], Deal>,
}

impl StorageMarket {
    /// A commitment over all deals (sorted by id): `H( [ id ‖ released ‖ epoch ‖ passed ‖ state ] × )`.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(self.deals.len() * 57);
        for (id, deal) in &self.deals {
            buf.extend_from_slice(id);
            buf.extend_from_slice(&deal.released().to_le_bytes());
            buf.extend_from_slice(&deal.epoch().to_le_bytes());
            buf.extend_from_slice(&deal.passed().to_le_bytes());
            buf.push(match deal.state() {
                DealState::Active => 0,
                DealState::Completed => 1,
                DealState::Closed => 2,
            });
        }
        hash_labeled(STORAGE_ROOT_LABEL, &buf)
    }
}

/// The number of Merkle leaves a chunk of `size` bytes exposes to the audit.
#[must_use]
pub(crate) fn leaves_for_size(size: u64) -> usize {
    (usize::try_from(size).unwrap_or(usize::MAX)).div_ceil(LEAF).max(1)
}
