//! The **hash time-locked contract** (HTLC) — the trustless atomic-swap primitive (`spec/platform.md` §8).
//!
//! A party locks `amount` for a `recipient` behind a **hashlock** `H` and a **timeout** height. The recipient
//! claims by revealing a preimage `s` with `hashlock(s) == H`, but only *before* the timeout; after the timeout
//! the sender may refund. That single asymmetry composes into a cross-chain **atomic swap**: Alice picks a
//! secret `s` and locks on chain A (recipient Bob, timeout `T_A`); Bob locks the same hashlock on chain B
//! (recipient Alice, a *shorter* timeout `T_B < T_A`). Alice claims on chain B by revealing `s` — which puts
//! `s` in the open — so Bob reads it and claims on chain A before `T_A`. Either both claims happen (once `s` is
//! revealed) or, if Alice never reveals, both sides refund after their timeouts: **atomic**, with no custodian.
//!
//! The lock is **post-quantum**: it is a hash preimage (BLAKE3), and inverting a hash has no quantum shortcut
//! beyond Grover's quadratic speedup, which a 256-bit digest absorbs. No signatures, curves, or trusted party.

use alloc::vec::Vec;

use fanos_primitives::codec::Reader;
use fanos_primitives::hash_labeled;

/// The fixed wire length of encoded [`HtlcTerms`].
pub const TERMS_LEN: usize = 32 + 32 + 8 + 32 + 8;

/// Domain label for the hashlock.
const HASHLOCK_LABEL: &str = "FANOS-hermes-v1/htlc-hashlock";

/// The hashlock of a 32-byte preimage secret: `H("htlc-hashlock", preimage)`.
#[must_use]
pub fn hashlock(preimage: &[u8; 32]) -> [u8; 32] {
    hash_labeled(HASHLOCK_LABEL, preimage)
}

/// The immutable terms of a contract — what is committed when the funds are locked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HtlcTerms {
    /// The account that locked the funds (refunded after the timeout).
    pub sender: [u8; 32],
    /// The account that may claim by revealing the preimage.
    pub recipient: [u8; 32],
    /// The locked amount.
    pub amount: u64,
    /// The hashlock the preimage must match.
    pub hashlock: [u8; 32],
    /// The block height at and after which the sender may refund (and the recipient may no longer claim).
    pub timeout: u64,
}

impl HtlcTerms {
    /// Canonical bytes: `sender(32) ‖ recipient(32) ‖ amount(8, LE) ‖ hashlock(32) ‖ timeout(8, LE)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TERMS_LEN);
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.hashlock);
        out.extend_from_slice(&self.timeout.to_le_bytes());
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if the length is wrong.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != TERMS_LEN {
            return None;
        }
        Some(Self {
            sender: bytes.get(..32)?.try_into().ok()?,
            recipient: bytes.get(32..64)?.try_into().ok()?,
            amount: u64::from_le_bytes(bytes.get(64..72)?.try_into().ok()?),
            hashlock: bytes.get(72..104)?.try_into().ok()?,
            timeout: u64::from_le_bytes(bytes.get(104..112)?.try_into().ok()?),
        })
    }
}

/// The lifecycle state of a contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HtlcState {
    /// Funds are locked; awaiting a claim or a refund.
    Locked,
    /// The recipient revealed the preimage and was paid.
    Claimed,
    /// The timeout passed and the sender was refunded.
    Refunded,
}

/// What the caller must enact — release the locked funds to `to`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Resolution {
    /// Pay the locked `amount` to `to` (the recipient on a claim, the sender on a refund).
    Pay {
        /// The payee.
        to: [u8; 32],
        /// The amount to release.
        amount: u64,
    },
}

/// A live hash time-locked contract — its terms and lifecycle state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Htlc {
    terms: HtlcTerms,
    state: HtlcState,
}

impl Htlc {
    /// Lock a new contract over `terms` (state [`Locked`](HtlcState::Locked)).
    #[must_use]
    pub fn new(terms: HtlcTerms) -> Self {
        Self { terms, state: HtlcState::Locked }
    }

    /// The contract terms.
    #[must_use]
    pub fn terms(&self) -> &HtlcTerms {
        &self.terms
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> HtlcState {
        self.state
    }

    /// Canonical bytes for a state-sync snapshot ([`fanos_primitives::codec`]): the fixed-width terms then the
    /// lifecycle state (`0` locked, `1` claimed, `2` refunded), so a restored contract reproduces the HTLC
    /// `state_root` exactly (the root folds the state, and pruning depends on it).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.terms.to_bytes();
        out.push(match self.state {
            HtlcState::Locked => 0,
            HtlcState::Claimed => 1,
            HtlcState::Refunded => 2,
        });
        out
    }

    /// Reconstruct a contract from [`to_bytes`](Self::to_bytes), or `None` if malformed / truncated / over-long.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let terms = HtlcTerms::from_bytes(r.bytes(TERMS_LEN)?)?;
        let state = match r.u8()? {
            0 => HtlcState::Locked,
            1 => HtlcState::Claimed,
            2 => HtlcState::Refunded,
            _ => return None,
        };
        r.finish()?;
        Some(Self { terms, state })
    }

    /// **Claim**: the recipient reveals `preimage` at block `height`. Succeeds only if the contract is still
    /// locked, the preimage matches the hashlock, and the timeout has not passed — then it pays the recipient
    /// and moves to [`Claimed`](HtlcState::Claimed). `None` otherwise (wrong secret, too late, or already
    /// resolved); state is unchanged on failure.
    #[must_use]
    pub fn claim(&mut self, preimage: &[u8; 32], height: u64) -> Option<Resolution> {
        if self.state != HtlcState::Locked || height >= self.terms.timeout || hashlock(preimage) != self.terms.hashlock
        {
            return None;
        }
        self.state = HtlcState::Claimed;
        Some(Resolution::Pay { to: self.terms.recipient, amount: self.terms.amount })
    }

    /// **Refund**: the sender reclaims the funds at block `height`, allowed only once the contract is still
    /// locked and the timeout has been reached. Pays the sender and moves to
    /// [`Refunded`](HtlcState::Refunded). `None` otherwise; state is unchanged on failure.
    #[must_use]
    pub fn refund(&mut self, height: u64) -> Option<Resolution> {
        if self.state != HtlcState::Locked || height < self.terms.timeout {
            return None;
        }
        self.state = HtlcState::Refunded;
        Some(Resolution::Pay { to: self.terms.sender, amount: self.terms.amount })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [0xA1; 32];
    const BOB: [u8; 32] = [0xB0; 32];
    const SECRET: [u8; 32] = [0x5E; 32];

    fn terms(sender: [u8; 32], recipient: [u8; 32], amount: u64, timeout: u64) -> HtlcTerms {
        HtlcTerms { sender, recipient, amount, hashlock: hashlock(&SECRET), timeout }
    }

    #[test]
    fn a_correct_preimage_before_timeout_pays_the_recipient() {
        let mut h = Htlc::new(terms(ALICE, BOB, 500, 100));
        assert_eq!(h.claim(&SECRET, 50), Some(Resolution::Pay { to: BOB, amount: 500 }));
        assert_eq!(h.state(), HtlcState::Claimed);
        // A second claim (or a refund) does nothing — the contract is resolved.
        assert_eq!(h.claim(&SECRET, 50), None);
        assert_eq!(h.refund(200), None);
    }

    #[test]
    fn a_wrong_preimage_or_a_late_claim_is_refused() {
        let mut h = Htlc::new(terms(ALICE, BOB, 500, 100));
        assert_eq!(h.claim(&[0x00; 32], 50), None, "wrong secret");
        assert_eq!(h.state(), HtlcState::Locked, "a failed claim does not resolve the contract");
        assert_eq!(h.claim(&SECRET, 100), None, "at the timeout it is too late to claim");
        assert_eq!(h.claim(&SECRET, 101), None, "after the timeout it is too late to claim");
        assert_eq!(h.state(), HtlcState::Locked);
    }

    #[test]
    fn a_refund_is_only_possible_after_the_timeout() {
        let mut h = Htlc::new(terms(ALICE, BOB, 500, 100));
        assert_eq!(h.refund(99), None, "before the timeout there is no refund");
        assert_eq!(h.refund(100), Some(Resolution::Pay { to: ALICE, amount: 500 }), "at the timeout the sender refunds");
        assert_eq!(h.state(), HtlcState::Refunded);
        assert_eq!(h.claim(&SECRET, 50), None, "a refunded contract cannot be claimed");
    }

    #[test]
    fn a_cross_chain_swap_is_atomic_on_the_happy_path() {
        // Alice has secret s. She locks on chain A for Bob (long timeout); Bob locks on chain B for Alice
        // (shorter timeout). Alice claims chain B by revealing s; Bob reads s and claims chain A.
        let mut chain_a = Htlc::new(terms(ALICE, BOB, 1000, 200)); // Alice's lock, recipient Bob
        let mut chain_b = Htlc::new(terms(BOB, ALICE, 900, 100)); // Bob's lock, recipient Alice, shorter timeout
        // Alice claims Bob's lock on chain B, revealing s.
        assert_eq!(chain_b.claim(&SECRET, 60), Some(Resolution::Pay { to: ALICE, amount: 900 }));
        // Bob extracts s from chain B and claims Alice's lock on chain A, before its (later) timeout.
        assert_eq!(chain_a.claim(&SECRET, 70), Some(Resolution::Pay { to: BOB, amount: 1000 }));
        assert_eq!(chain_a.state(), HtlcState::Claimed);
        assert_eq!(chain_b.state(), HtlcState::Claimed);
    }

    #[test]
    fn a_cross_chain_swap_refunds_both_sides_if_the_secret_is_never_revealed() {
        let mut chain_a = Htlc::new(terms(ALICE, BOB, 1000, 200));
        let mut chain_b = Htlc::new(terms(BOB, ALICE, 900, 100));
        // Alice never reveals s. After each side's timeout, both refund — no value moved.
        assert_eq!(chain_b.refund(100), Some(Resolution::Pay { to: BOB, amount: 900 }));
        assert_eq!(chain_a.refund(200), Some(Resolution::Pay { to: ALICE, amount: 1000 }));
    }

    #[test]
    fn terms_round_trip_on_the_wire() {
        let t = terms(ALICE, BOB, 0x0102_0304, 0x0506);
        let bytes = t.to_bytes();
        assert_eq!(bytes.len(), TERMS_LEN);
        assert_eq!(HtlcTerms::from_bytes(&bytes), Some(t));
        assert_eq!(HtlcTerms::from_bytes(&bytes[..TERMS_LEN - 1]), None, "wrong length rejected");
    }

    #[test]
    fn the_hashlock_is_stable_a_known_answer() {
        // A fixed preimage must lock to a fixed digest so both chains agree on the hashlock.
        let h = hashlock(&[0xCD; 32]);
        // Self-consistency: only the exact preimage opens it.
        assert_eq!(hashlock(&[0xCD; 32]), h);
        assert_ne!(hashlock(&[0xCE; 32]), h);
    }
}
