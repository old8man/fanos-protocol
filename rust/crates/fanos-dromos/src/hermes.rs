//! The **HERMES atomic swaps on the ledger** — the `TAG_HTLC` transaction family that settles hash time-locked
//! contracts (`fanos-hermes`) in currency (`spec/platform.md` §8).
//!
//! A **lock** escrows the sender's funds into the keyless [`HTLC_ESCROW`] sink behind a hashlock and a timeout;
//! a **claim** releases them to the recipient the instant a matching preimage is revealed (before the timeout);
//! a **refund** returns them to the sender once the timeout — measured by the ledger's block-height clock — has
//! passed. The escrow leaves the sink only through the HTLC state machine's verdict, the same proof-gated
//! keyless-sink release the shielded pool and the storage market use.

use std::collections::BTreeMap;

use fanos_hermes::{Htlc, HtlcState, HtlcTerms};
use fanos_primitives::codec::{Reader, put_map, put_var_bytes, read_map};
use fanos_primitives::hash_labeled;

use crate::token::SignedTransfer;

/// The keyless sink holding all locked HTLC funds — entered by a signed transfer, left only by `move_system` on
/// a valid claim or a timed-out refund.
pub const HTLC_ESCROW: [u8; 32] = *b"FANOS-hermes-htlc-escrow-sink!!!";

/// Domain label deriving a contract identifier.
const HTLC_ID_LABEL: &str = "FANOS-dromos-v1/htlc-id";
/// Domain label for the HTLC sub-state root.
const HTLC_ROOT_LABEL: &str = "FANOS-dromos-v1/htlc-root";

/// Transaction subtype tags within `TAG_HTLC`.
const OP_LOCK: u8 = 0x00;
const OP_CLAIM: u8 = 0x01;
const OP_REFUND: u8 = 0x02;

/// A contract's on-ledger identifier: `H(terms ‖ funding-nonce)`, so a sender's distinct locks are distinct
/// contracts even under identical terms.
#[must_use]
pub fn htlc_id(terms: &HtlcTerms, funding_nonce: u64) -> [u8; 32] {
    let mut buf = terms.to_bytes();
    buf.extend_from_slice(&funding_nonce.to_le_bytes());
    hash_labeled(HTLC_ID_LABEL, &buf)
}

/// An atomic-swap (HTLC) transaction.
#[derive(Clone)]
pub enum HtlcTx {
    /// Lock funds behind `terms`, funding the escrow with `payment` (sender → [`HTLC_ESCROW`], amount = terms.amount).
    /// The signed transfer is boxed — it dwarfs the other variants — so the enum stays small.
    Lock {
        /// The contract terms.
        terms: HtlcTerms,
        /// The escrow-funding signed transfer.
        payment: Box<SignedTransfer>,
    },
    /// Claim a locked contract by revealing its `preimage`.
    Claim {
        /// The contract being claimed.
        htlc_id: [u8; 32],
        /// The revealed preimage secret.
        preimage: [u8; 32],
    },
    /// Refund a timed-out contract to its sender.
    Refund {
        /// The contract being refunded.
        htlc_id: [u8; 32],
    },
}

impl HtlcTx {
    /// Canonical bytes: `op(1) ‖ …`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            HtlcTx::Lock { terms, payment } => {
                out.push(OP_LOCK);
                out.extend_from_slice(&terms.to_bytes());
                out.extend_from_slice(&payment.to_bytes());
            }
            HtlcTx::Claim { htlc_id, preimage } => {
                out.push(OP_CLAIM);
                out.extend_from_slice(htlc_id);
                out.extend_from_slice(preimage);
            }
            HtlcTx::Refund { htlc_id } => {
                out.push(OP_REFUND);
                out.extend_from_slice(htlc_id);
            }
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&op, body) = bytes.split_first()?;
        match op {
            OP_LOCK => {
                let terms = HtlcTerms::from_bytes(body.get(..fanos_hermes::htlc::TERMS_LEN)?)?;
                let payment = SignedTransfer::from_bytes(body.get(fanos_hermes::htlc::TERMS_LEN..)?)?;
                Some(HtlcTx::Lock { terms, payment: Box::new(payment) })
            }
            OP_CLAIM => Some(HtlcTx::Claim {
                htlc_id: body.get(..32)?.try_into().ok()?,
                preimage: body.get(32..64)?.try_into().ok()?,
            }),
            OP_REFUND if body.len() == 32 => Some(HtlcTx::Refund { htlc_id: body.try_into().ok()? }),
            _ => None,
        }
    }
}

/// The HTLC sub-state: the live contracts, keyed by [`htlc_id`].
#[derive(Clone, Debug, Default)]
pub struct HtlcBook {
    pub(crate) htlcs: BTreeMap<[u8; 32], Htlc>,
}

impl HtlcBook {
    /// A commitment over all contracts (sorted by id): `H( [ id ‖ state ] × )`.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(self.htlcs.len() * 33);
        for (id, htlc) in &self.htlcs {
            buf.extend_from_slice(id);
            buf.push(match htlc.state() {
                HtlcState::Locked => 0,
                HtlcState::Claimed => 1,
                HtlcState::Refunded => 2,
            });
        }
        hash_labeled(HTLC_ROOT_LABEL, &buf)
    }

    /// Canonical bytes for a state-sync snapshot ([`fanos_primitives::codec`]): every contract in sorted id
    /// order (`id ‖ contract-bytes` each), so a restore reproduces the HTLC `state_root` exactly.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_map(&mut out, &self.htlcs, |o, id, htlc| {
            o.extend_from_slice(id);
            put_var_bytes(o, &htlc.to_bytes());
        });
        out
    }

    /// Reconstruct a book from [`to_bytes`](Self::to_bytes), or `None` if malformed / truncated / over-long.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        // Smallest entry: id (32) ‖ length-prefixed contract (≥ 4) = 36 bytes.
        let htlcs = read_map(&mut r, 36, |r| {
            let id = r.array::<32>()?;
            let htlc = Htlc::from_bytes(r.var_bytes()?)?;
            Some((id, htlc))
        })?;
        r.finish()?;
        Some(Self { htlcs })
    }
}
