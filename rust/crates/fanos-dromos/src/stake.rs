//! DROMOS validator **staking and slashing** (T-H5) — the economic-security layer that gives the incentive
//! equilibrium (`fanos_taxis::incentive`) its teeth in executed state.
//!
//! The equilibrium theorem assumes two things the consensus layer can only *detect*: that a provable fault is
//! slashed by a positive amount (condition C2), and that a validator has value at stake to lose. This module
//! puts both into the committed ledger state:
//!
//! * **Bonded stake** — a validator moves currency from its balance into locked collateral ([`StakeTx::Bond`]),
//!   backed 1:1 by the keyless [`STAKE_SINK`] (the analogue of the shielded pool's `POOL_SINK`: its balance is
//!   exactly `Σ bonded` by construction). It can be returned with [`StakeTx::Unbond`].
//! * **Slashing** — a [`SlashTx`] carries a self-contained equivocation proof (two conflicting signed votes) and
//!   the equivocator's verifying key. Execution re-verifies the equivocation and debits the equivocator's bonded
//!   stake to the treasury. The slashed account is `account_id(verifier)` — the very account the validator bonds
//!   from — so the evidence *names its own target* and no validator registry is needed in the execution layer.
//!   A per-slot guard makes a slash idempotent: an old proof cannot be replayed against freshly re-bonded stake.
//!
//! Slashing is thus permissionless (anyone can submit a genuine proof), deterministic (a pure function of the
//! proof and the committed state), and self-verifying (no trusted party, no synchrony assumption) — the exact
//! properties `docs/design-incentive-equilibrium.md` requires of the punishment mechanism.

use std::collections::{BTreeMap, BTreeSet};

use fanos_pqcrypto::HybridVerifier;
use fanos_primitives::codec::{Reader, put_u32, put_u64, put_var_bytes};
use fanos_primitives::hash_labeled;
use fanos_taxis::{SignedVote, SlashEvidence, detect_equivocation};

use crate::token::SignedTransfer;

/// Domain label for the staked-balance state-root commitment.
const STAKE_ROOT_LABEL: &str = "FANOS-dromos-v1/stake-root";
/// Domain label for a recorded (already-slashed) equivocation slot — the double-slash guard key.
const SLASHED_SLOT_LABEL: &str = "FANOS-dromos-v1/slashed-slot";

/// The keyless sink account that **backs every bonded stake**: its balance equals `Σ bonded` by construction.
/// Stake bonded out of a validator's balance lives here until it is unbonded or slashed — the staking analogue
/// of the shielded pool's `POOL_SINK`. No key hashes to it, so it can only move under the staking rules here.
pub const STAKE_SINK: [u8; 32] = *b"FANOS-dromos-stake-collateral!!!";

/// A staking operation, authorised by a [`SignedTransfer`] to [`STAKE_SINK`] — reusing the transfer's signature
/// and its sender's per-account nonce as the replay guard (a stake op shares the sender's one nonce sequence
/// with ordinary transfers, so neither can be replayed as the other).
#[derive(Clone)]
pub enum StakeTx {
    /// Bond `transfer.amount` from the signer's balance into locked stake.
    Bond(SignedTransfer),
    /// Unbond `transfer.amount` from locked stake back to the signer's balance.
    Unbond(SignedTransfer),
}

impl StakeTx {
    /// The authorising transfer (its `to` must be [`STAKE_SINK`]).
    #[must_use]
    pub fn transfer(&self) -> &SignedTransfer {
        match self {
            StakeTx::Bond(st) | StakeTx::Unbond(st) => st,
        }
    }

    /// Canonical bytes: a 1-byte discriminant (`0` bond, `1` unbond) then the fixed-width signed transfer.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let (tag, st): (u8, &SignedTransfer) = match self {
            StakeTx::Bond(st) => (0, st),
            StakeTx::Unbond(st) => (1, st),
        };
        let mut out = Vec::with_capacity(1 + SignedTransfer::WIRE_LEN);
        out.push(tag);
        out.extend_from_slice(&st.to_bytes());
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` on an unknown discriminant or a malformed transfer.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (tag, rest) = bytes.split_first()?;
        let st = SignedTransfer::from_bytes(rest)?;
        match tag {
            0 => Some(StakeTx::Bond(st)),
            1 => Some(StakeTx::Unbond(st)),
            _ => None,
        }
    }
}

/// A **self-contained slashing proof**: two conflicting votes plus the equivocator's verifying key. Anyone can
/// submit it; execution re-verifies the equivocation ([`detect_equivocation`]) and, if genuine, slashes
/// `account_id(verifier)` — the account the equivocator bonds from. The key is bound into the proof precisely so
/// the executed state needs no validator registry to identify the target: the votes verifying under the key
/// *are* the proof that this key equivocated.
#[derive(Clone)]
pub struct SlashTx {
    /// The first conflicting vote.
    pub vote_a: SignedVote,
    /// The second conflicting vote (same slot, different block).
    pub vote_b: SignedVote,
    /// The equivocator's verifying key; the slashed account is `account_id(verifier)`.
    pub verifier: HybridVerifier,
}

impl SlashTx {
    /// The canonical equivocation evidence if the two votes are a genuine, validly-signed conflict under
    /// `verifier`; `None` otherwise (different slot, identical vote, or a signature that does not verify).
    #[must_use]
    pub fn evidence(&self) -> Option<SlashEvidence> {
        detect_equivocation(&self.vote_a, &self.vote_b, &self.verifier)
    }

    /// Canonical bytes: length-prefixed `vote_a`, `vote_b`, and the encoded verifying key.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_var_bytes(&mut out, &self.vote_a.to_bytes());
        put_var_bytes(&mut out, &self.vote_b.to_bytes());
        put_var_bytes(&mut out, &self.verifier.encode());
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if any field is malformed or bytes remain.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let vote_a = SignedVote::from_bytes(r.var_bytes()?)?;
        let vote_b = SignedVote::from_bytes(r.var_bytes()?)?;
        let verifier = HybridVerifier::decode(r.var_bytes()?)?;
        if !r.is_empty() {
            return None; // trailing bytes ⇒ non-canonical
        }
        Some(Self { vote_a, vote_b, verifier })
    }
}

/// The **validator stake ledger**: bonded collateral by account, and the set of equivocation slots already
/// slashed (so an old proof cannot be replayed to drain freshly re-bonded stake). Both fold into the DROMOS
/// state root, so every validator agrees on who has how much at stake and which faults are already punished.
#[derive(Clone, Debug, Default)]
pub struct StakeLedger {
    bonded: BTreeMap<[u8; 32], u64>,
    slashed: BTreeSet<[u8; 32]>,
}

impl StakeLedger {
    /// An empty stake ledger — nothing bonded, nothing slashed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The stake `account` currently has bonded (0 if none).
    #[must_use]
    pub fn bonded(&self, account: &[u8; 32]) -> u64 {
        self.bonded.get(account).copied().unwrap_or(0)
    }

    /// The total stake bonded across all accounts — equal to [`STAKE_SINK`]'s balance by construction.
    #[must_use]
    pub fn total_bonded(&self) -> u64 {
        self.bonded.values().fold(0u64, |acc, v| acc.saturating_add(*v))
    }

    /// The number of validators with a positive bonded stake.
    #[must_use]
    pub fn bonded_count(&self) -> usize {
        self.bonded.len()
    }

    /// Add `amount` to `account`'s bonded stake (saturating).
    pub(crate) fn increase(&mut self, account: [u8; 32], amount: u64) {
        let e = self.bonded.entry(account).or_insert(0);
        *e = e.saturating_add(amount);
    }

    /// Remove `amount` from `account`'s bonded stake; `false` (unchanged) if it does not have that much. A
    /// balance that reaches zero is pruned, so the ledger holds only positive stakes (a canonical commitment).
    pub(crate) fn decrease(&mut self, account: &[u8; 32], amount: u64) -> bool {
        let Some(bal) = self.bonded.get_mut(account) else {
            return false;
        };
        if *bal < amount {
            return false;
        }
        *bal -= amount;
        if *bal == 0 {
            self.bonded.remove(account);
        }
        true
    }

    /// Record `slot` as slashed; `true` if it was newly recorded (`false` if already present).
    pub(crate) fn record_slashed(&mut self, slot: [u8; 32]) -> bool {
        self.slashed.insert(slot)
    }

    /// Canonical bytes: `n(4) ‖ (account‖bonded)ⁿ ‖ m(4) ‖ slotᵐ`, both maps in sorted (`BTree`) order — the
    /// state-sync snapshot form and the preimage of [`state_root`](Self::state_root).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.bonded.len() * 40 + 4 + self.slashed.len() * 32);
        put_u32(&mut out, u32::try_from(self.bonded.len()).unwrap_or(u32::MAX));
        for (acct, amt) in &self.bonded {
            out.extend_from_slice(acct);
            put_u64(&mut out, *amt);
        }
        put_u32(&mut out, u32::try_from(self.slashed.len()).unwrap_or(u32::MAX));
        for slot in &self.slashed {
            out.extend_from_slice(slot);
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed, truncated, or trailed by extra bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let n = usize::try_from(r.u32()?).ok()?;
        let mut bonded = BTreeMap::new();
        for _ in 0..n {
            let acct = r.array::<32>()?;
            let amt = r.u64()?;
            bonded.insert(acct, amt);
        }
        let m = usize::try_from(r.u32()?).ok()?;
        let mut slashed = BTreeSet::new();
        for _ in 0..m {
            slashed.insert(r.array::<32>()?);
        }
        r.finish()?;
        Some(Self { bonded, slashed })
    }

    /// `H(to_bytes)` — the stake sub-state commitment folded into the hybrid state root. Both maps are ordered
    /// (`BTreeMap`/`BTreeSet`), so the encoding — and thus the commitment — is canonical.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        hash_labeled(STAKE_ROOT_LABEL, &self.to_bytes())
    }
}

/// The canonical id of an equivocation slot — `H(account ‖ height ‖ round ‖ phase)`. Two proofs of the *same*
/// equivocation (same validator, same voting slot) map to the same key, so the second is a no-op: a validator
/// is slashed for a given fault exactly once, however many times the proof is submitted.
#[must_use]
pub(crate) fn slot_key(account: &[u8; 32], ev: &SlashEvidence) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 8 + 4 + 1);
    buf.extend_from_slice(account);
    buf.extend_from_slice(&ev.height.to_be_bytes());
    buf.extend_from_slice(&ev.round.to_be_bytes());
    buf.push(ev.phase.code());
    hash_labeled(SLASHED_SLOT_LABEL, &buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_stake_ledger_round_trips_through_its_snapshot_bytes() {
        let mut s = StakeLedger::new();
        s.increase([1u8; 32], 100);
        s.increase([2u8; 32], 250);
        s.increase([1u8; 32], 50); // account 1 now holds 150
        assert!(s.record_slashed([9u8; 32]));
        assert!(s.record_slashed([8u8; 32]));
        assert!(!s.record_slashed([9u8; 32]), "an equivocation slot is recorded exactly once");

        let back = StakeLedger::from_bytes(&s.to_bytes()).expect("snapshot round-trips");
        assert_eq!(back.bonded(&[1u8; 32]), 150);
        assert_eq!(back.bonded(&[2u8; 32]), 250);
        assert_eq!(back.total_bonded(), 400);
        assert_eq!(back.bonded_count(), 2);
        assert_eq!(back.state_root(), s.state_root(), "the commitment survives the round-trip");

        // Trailing bytes are rejected (canonical decoding).
        let mut extra = s.to_bytes();
        extra.push(0);
        assert!(StakeLedger::from_bytes(&extra).is_none(), "trailing bytes are rejected");
    }

    #[test]
    fn decrease_prunes_zeroed_stakes_and_guards_underflow() {
        let mut s = StakeLedger::new();
        s.increase([1u8; 32], 100);
        assert!(!s.decrease(&[1u8; 32], 200), "cannot remove more than is bonded");
        assert_eq!(s.bonded(&[1u8; 32]), 100, "a failed decrease changes nothing");
        assert!(s.decrease(&[1u8; 32], 100));
        assert_eq!(s.bonded(&[1u8; 32]), 0);
        assert_eq!(s.bonded_count(), 0, "a stake that reaches zero is pruned from the ledger");
    }
}
