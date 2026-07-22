//! The **shield bridge** — moving public token value into the private OBOLOS pool (`spec/platform.md` §4, the
//! transparent↔shielded seam). Shielding lets a holder of public funds acquire privacy on demand: a signed
//! transfer moves `amount` from the shielder to a keyless **pool sink** (whose balance is the public, auditable
//! total backing the shielded pool — an invariant maintained by construction: it equals the sum of all unspent
//! shielded note values), and a note of that value is minted into the pool.
//!
//! A shield reveals the *entry* — the amount and the note's opening are public at the boundary (like Zcash's
//! transparent→shielded direction, which reveals the shielded amount). Privacy begins at the **first shielded
//! transfer**: from then on the value moves under hidden commitments and unlinkable nullifiers. The reverse
//! direction (unshield: spend a note, reveal its value, credit a transparent account, debit the pool sink)
//! composes on top — it needs a shielded spend that reveals a public output, an extension of the OBOLOS proof.

use fanos_obolos::{Note, Randomness};

use crate::token::SignedTransfer;

/// The keyless account that backs the shielded pool: every shield credits it, every (future) unshield debits
/// it, and no signature ever moves it — so its balance is exactly the public total of value held privately.
pub const POOL_SINK: [u8; 32] = *b"FANOS-obolos-shielded-pool-sink!";

/// The serialized length of a note's public opening (`value(8) ‖ owner(32) ‖ value_r ‖ rho(32)`).
const NOTE_OPENING_LEN: usize = 72 + Randomness::WIRE_LEN;

/// A **shield** transaction: fund the private pool from public tokens. `payment` sends `note.value` to the
/// [`POOL_SINK`]; the `note` (its opening public at entry) is minted into the pool for later private spending.
#[derive(Clone)]
pub struct ShieldTx {
    /// The signed transfer to the pool sink (its amount must equal `note.value`).
    pub payment: SignedTransfer,
    /// The note minted into the shielded pool.
    pub note: Note,
}

impl ShieldTx {
    /// Canonical bytes: the fixed-width payment, then the note's opening.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.payment.to_bytes();
        out.extend_from_slice(&self.note.value.to_le_bytes());
        out.extend_from_slice(&self.note.owner);
        out.extend_from_slice(&self.note.value_r.to_bytes());
        out.extend_from_slice(&self.note.rho);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SignedTransfer::WIRE_LEN + NOTE_OPENING_LEN {
            return None;
        }
        let payment = SignedTransfer::from_bytes(bytes.get(..SignedTransfer::WIRE_LEN)?)?;
        let rest = bytes.get(SignedTransfer::WIRE_LEN..)?;
        let value = u64::from_le_bytes(rest.get(..8)?.try_into().ok()?);
        let owner = rest.get(8..40)?.try_into().ok()?;
        let value_r = Randomness::from_bytes(rest.get(40..40 + Randomness::WIRE_LEN)?)?;
        let rho = rest.get(40 + Randomness::WIRE_LEN..)?.try_into().ok()?;
        Some(Self { payment, note: Note::new(value, owner, value_r, rho) })
    }
}
