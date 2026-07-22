//! # DROMOS — the swift execution fabric (L9)
//!
//! *Greek δρόμος, a running-course.* DROMOS is where the FANOS platform's two halves meet: it runs the
//! **OBOLOS** private-currency pool (`fanos-obolos`) as a **TAXIS** `StateMachine` (`fanos-taxis`), so a
//! shielded transfer — ordered blindly by the anti-MEV encrypted mempool — *executes on the blockchain*. This
//! is the E∧L composition made runnable (`spec/platform.md` §3): the L-machine (consensus) fixes the order,
//! the E-machine's shielding (the SKIA pool) hides the value, and the same execution checkpoint that certifies
//! the ledger certifies the private state.
//!
//! This first increment is the **hybrid state machine's shielded half** — [`ShieldedLedger`], a `StateMachine`
//! whose transactions are OBOLOS submissions (`fanos_obolos::encode_submission`). It decodes each committed
//! transaction, verifies its proof, and applies it to the shielded pool; its `state_root` is the pool's root,
//! ready to fold into the block's executed-state commitment. The transparent-account half (public contracts,
//! staking, naming) and the parallel post-reveal scheduler (`spec/platform.md` §3.1) compose on top next.

#![forbid(unsafe_code)]

use std::sync::Arc;

use fanos_obolos::{Params, ShieldedState, decode_submission};
use fanos_taxis::state::{ExecOutcome, StateMachine};
use fanos_taxis::tx::Transaction;

/// A TAXIS ledger whose state is the OBOLOS shielded pool: shielded transactions execute here after consensus
/// fixes their order. Cheaply cloneable — the (large, fixed) commitment parameters are shared via [`Arc`], so
/// cloning the ledger (for a genesis snapshot or a checkpoint) copies only the pool.
#[derive(Clone, Debug)]
pub struct ShieldedLedger {
    state: ShieldedState,
    params: Arc<Params>,
}

impl ShieldedLedger {
    /// A fresh, empty shielded ledger over the canonical commitment parameters.
    #[must_use]
    pub fn new() -> Self {
        Self { state: ShieldedState::new(), params: Arc::new(Params::standard()) }
    }

    /// A shielded ledger over caller-supplied commitment parameters (e.g. a test CRS).
    #[must_use]
    pub fn with_params(params: Params) -> Self {
        Self { state: ShieldedState::new(), params: Arc::new(params) }
    }

    /// The underlying shielded state (read-only): the commitment tree, nullifier set, and anchors.
    #[must_use]
    pub fn state(&self) -> &ShieldedState {
        &self.state
    }

    /// The commitment parameters this ledger verifies against.
    #[must_use]
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// **Issuance** — mint a note commitment into the pool by a consensus rule (genesis allocation or block
    /// reward), with no spend proof. Returns the note's position, or `None` if the pool is full. (A production
    /// chain gates this by the monetary policy; here it is the value-creation seam DROMOS exposes to consensus.)
    pub fn mint(&mut self, note_commitment: [u8; 32]) -> Option<u64> {
        self.state.mint(note_commitment)
    }
}

impl Default for ShieldedLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachine for ShieldedLedger {
    /// Execute one committed transaction: decode it as an OBOLOS submission (transaction + proof), verify the
    /// proof, and apply it to the shielded pool.
    ///
    /// - [`ExecOutcome::Malformed`] — the bytes are not a valid OBOLOS submission;
    /// - [`ExecOutcome::Rejected`] — well-formed but invalid against the current pool (double-spend, unknown
    ///   anchor, failing proof — recorded as included-but-rejected, not a consensus failure);
    /// - [`ExecOutcome::Applied`] — the shielded transfer executed and the pool advanced.
    fn apply(&mut self, tx: &Transaction) -> ExecOutcome {
        let Some((shielded_tx, proof)) = decode_submission(&tx.payload) else {
            return ExecOutcome::Malformed;
        };
        match self.state.apply(&self.params, &shielded_tx, &proof) {
            Ok(()) => ExecOutcome::Applied,
            Err(_) => ExecOutcome::Rejected,
        }
    }

    /// A binding commitment to the whole shielded pool — the value DROMOS contributes to the block's executed
    /// `state_root`, and what the TAXIS execution checkpoint certifies.
    fn state_root(&self) -> [u8; 32] {
        self.state.root()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_obolos::{Note, Randomness, SpendInput, build_transfer, derive_owner_pk, encode_submission};

    fn note(value: u64, nsk: &[u8; 32], tag: &[u8]) -> Note {
        Note::new(value, derive_owner_pk(nsk), Randomness::from_seed(tag), [tag.len() as u8; 32])
    }

    /// Package an OBOLOS transfer as a TAXIS transaction.
    fn submission(tx: &fanos_obolos::ShieldedTx, proof: &fanos_obolos::TransparentProof) -> Transaction {
        Transaction::new(encode_submission(tx, proof))
    }

    #[test]
    fn a_shielded_transfer_executes_on_the_ledger() {
        let mut ledger = ShieldedLedger::new();
        let nsk = [1u8; 32];
        let n0 = note(1000, &nsk, b"n0");
        // Issuance: Alice is minted 1000.
        let pos = ledger.mint(n0.commitment(ledger.params())).unwrap();
        let root_before = ledger.state_root();

        // Alice → Bob 700, change 300 (fee 0).
        let sp = SpendInput { note: n0, nsk, path: ledger.state().path(pos).unwrap() };
        let (tx, proof) =
            build_transfer(ledger.params(), ledger.state().anchor(), &[sp], &[note(700, &[2u8; 32], b"bob"), note(300, &nsk, b"chg")], 0);
        assert_eq!(ledger.apply(&submission(&tx, &proof)), ExecOutcome::Applied, "the shielded transfer executes");
        assert_ne!(ledger.state_root(), root_before, "execution advances the state root");
        assert_eq!(ledger.state().spent_count(), 1);
        assert_eq!(ledger.state().note_count(), 3);
    }

    #[test]
    fn a_double_spend_is_recorded_as_rejected_not_a_consensus_failure() {
        let mut ledger = ShieldedLedger::new();
        let nsk = [1u8; 32];
        let n0 = note(1000, &nsk, b"n0");
        let pos = ledger.mint(n0.commitment(ledger.params())).unwrap();
        let sp = SpendInput { note: n0, nsk, path: ledger.state().path(pos).unwrap() };
        let (tx, proof) = build_transfer(ledger.params(), ledger.state().anchor(), &[sp], &[note(1000, &[2u8; 32], b"bob")], 0);
        let submitted = submission(&tx, &proof);
        assert_eq!(ledger.apply(&submitted), ExecOutcome::Applied);
        assert_eq!(ledger.apply(&submitted), ExecOutcome::Rejected, "the replay is rejected, not fatal");
    }

    #[test]
    fn a_non_obolos_payload_is_malformed() {
        let mut ledger = ShieldedLedger::new();
        assert_eq!(ledger.apply(&Transaction::new(vec![0xFF; 7])), ExecOutcome::Malformed);
        assert_eq!(ledger.apply(&Transaction::new(Vec::new())), ExecOutcome::Malformed);
    }

    #[test]
    fn replaying_the_same_ordered_transactions_yields_the_same_root() {
        // Determinism: two ledgers fed the identical ordered submissions reach the identical state root — the
        // property the execution checkpoint relies on.
        let build = || {
            let mut ledger = ShieldedLedger::new();
            let nsk = [1u8; 32];
            let n0 = note(500, &nsk, b"n0");
            let pos = ledger.mint(n0.commitment(ledger.params())).unwrap();
            let sp = SpendInput { note: n0, nsk, path: ledger.state().path(pos).unwrap() };
            let (tx, proof) = build_transfer(ledger.params(), ledger.state().anchor(), &[sp], &[note(500, &[2u8; 32], b"bob")], 0);
            ledger.apply(&submission(&tx, &proof));
            ledger.state_root()
        };
        assert_eq!(build(), build(), "the same ordered execution is deterministic");
    }
}
