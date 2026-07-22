//! The execution layer: a pluggable [`StateMachine`] and a reference account instantiation
//! (`docs/design-taxis.md` §1, ABCI-style separation).
//!
//! TAXIS orders transactions but does not interpret them — *what* a transaction does to application state is
//! the state machine's business, exactly as Tendermint separates consensus from the app via ABCI. The
//! consensus engine applies the reconstructed transactions **in the committed order** after a block finalizes
//! (post-REVEAL), and records the resulting [`StateMachine::state_root`] in the chain. Anyone replaying the
//! same ordered transactions from genesis reaches the same root — the ledger property.
//!
//! [`Accounts`] is the reference machine: balances and per-account nonces, with a [`Transfer`] transaction.
//! It is deliberately simple; a real deployment swaps in its own `StateMachine` (a full VM, a UTXO set, …)
//! without touching consensus.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_primitives::hash_labeled;
use fanos_wire::Wire;
use fanos_wire_derive::Wire;

use crate::tx::Transaction;

const STATE_ROOT_LABEL: &str = "FANOS-v1/taxis-state-root";

/// The outcome of applying one transaction to the state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExecOutcome {
    /// The transaction was valid and mutated the state.
    Applied,
    /// The transaction was well-formed but invalid against the current state (bad nonce, insufficient
    /// balance, …) — it is recorded as included-but-rejected, not a consensus failure.
    Rejected,
    /// The transaction bytes did not parse under this state machine's format.
    Malformed,
}

/// A replicated state machine over which TAXIS provides ordered, final agreement. The consensus engine is
/// generic over this trait, so the same consensus runs any application.
pub trait StateMachine {
    /// Begin executing the block at `height` — a per-block context hook the engine calls **once** before that
    /// block's transactions, so a state machine with height-dependent rules (expiries, vesting, block rewards)
    /// has a canonical, agreed clock. The default is a no-op; a plain ledger ignores it.
    fn begin_block(&mut self, _height: u64) {}

    /// Apply one transaction (already reconstructed and in committed order) to the state.
    fn apply(&mut self, tx: &Transaction) -> ExecOutcome;

    /// A binding 32-byte commitment to the entire current state — the ledger's verifiable summary, and what
    /// the execution checkpoint ([`crate::checkpoint`]) certifies. A **cross-cell-aware** state machine folds
    /// its cross-cell outbox in here — `crate::crosscell::compose_state_root(app_root, outbox.root())` — so the
    /// same certificate that proves its balances also proves the messages it emitted to other cells; a plain
    /// state machine commits only its application state.
    fn state_root(&self) -> [u8; 32];
}

/// A reference account transfer: move `amount` from `from` to `to`, valid only at the sender's current
/// `nonce` (replay protection).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Wire)]
pub struct Transfer {
    /// The sender account (a 32-byte identifier).
    pub from: [u8; 32],
    /// The recipient account.
    pub to: [u8; 32],
    /// The amount to move.
    pub amount: u64,
    /// The sender's expected next nonce (must equal the account's current nonce).
    pub nonce: u64,
}

impl Transfer {
    /// Encode this transfer as a [`Transaction`] payload.
    #[must_use]
    pub fn into_tx(self) -> Transaction {
        Transaction::new(self.to_wire())
    }
}

/// The reference state machine: account balances and per-account nonces.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Accounts {
    balances: BTreeMap<[u8; 32], u64>,
    nonces: BTreeMap<[u8; 32], u64>,
}

impl Accounts {
    /// A fresh empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fund an account at genesis (or by mint) — outside the transaction flow.
    pub fn credit(&mut self, account: [u8; 32], amount: u64) {
        let entry = self.balances.entry(account).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    /// The balance of an account (0 if unknown).
    #[must_use]
    pub fn balance(&self, account: &[u8; 32]) -> u64 {
        self.balances.get(account).copied().unwrap_or(0)
    }

    /// The current nonce of an account (0 if it has never sent).
    #[must_use]
    pub fn nonce(&self, account: &[u8; 32]) -> u64 {
        self.nonces.get(account).copied().unwrap_or(0)
    }
}

impl StateMachine for Accounts {
    fn apply(&mut self, tx: &Transaction) -> ExecOutcome {
        let Ok(t) = Transfer::from_wire(&tx.payload) else {
            return ExecOutcome::Malformed;
        };
        // Replay protection: the transfer must name the sender's current nonce.
        if self.nonce(&t.from) != t.nonce {
            return ExecOutcome::Rejected;
        }
        // Sufficient funds (a transfer to self is a no-op that still consumes the nonce).
        if self.balance(&t.from) < t.amount {
            return ExecOutcome::Rejected;
        }
        // Debit, credit, bump the nonce. Debit cannot underflow (checked above); credit saturates.
        *self.balances.entry(t.from).or_insert(0) -= t.amount;
        let to = self.balances.entry(t.to).or_insert(0);
        *to = to.saturating_add(t.amount);
        *self.nonces.entry(t.from).or_insert(0) += 1;
        ExecOutcome::Applied
    }

    fn state_root(&self) -> [u8; 32] {
        // A binding hash over the sorted (account, balance, nonce) triples — deterministic, so any node
        // replaying the same ordered transactions computes the identical root.
        let mut buf = Vec::new();
        // Union of all accounts appearing in either map, in sorted order (BTreeMap iterates sorted).
        let mut accounts: Vec<[u8; 32]> = self.balances.keys().copied().collect();
        for k in self.nonces.keys() {
            if !accounts.contains(k) {
                accounts.push(*k);
            }
        }
        accounts.sort_unstable();
        for acct in accounts {
            buf.extend_from_slice(&acct);
            buf.extend_from_slice(&self.balance(&acct).to_be_bytes());
            buf.extend_from_slice(&self.nonce(&acct).to_be_bytes());
        }
        hash_labeled(STATE_ROOT_LABEL, &buf)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [0xA1; 32];
    const BOB: [u8; 32] = [0xB0; 32];

    #[test]
    fn a_valid_transfer_moves_funds_and_bumps_the_nonce() {
        let mut s = Accounts::new();
        s.credit(ALICE, 100);
        let tx = Transfer { from: ALICE, to: BOB, amount: 30, nonce: 0 }.into_tx();
        assert_eq!(s.apply(&tx), ExecOutcome::Applied);
        assert_eq!(s.balance(&ALICE), 70);
        assert_eq!(s.balance(&BOB), 30);
        assert_eq!(s.nonce(&ALICE), 1);
    }

    #[test]
    fn a_replayed_or_overdraft_transfer_is_rejected() {
        let mut s = Accounts::new();
        s.credit(ALICE, 50);
        let tx = Transfer { from: ALICE, to: BOB, amount: 20, nonce: 0 }.into_tx();
        assert_eq!(s.apply(&tx), ExecOutcome::Applied);
        // Replaying the same (nonce-0) transfer is rejected — the nonce has advanced.
        assert_eq!(s.apply(&tx), ExecOutcome::Rejected);
        // Overdraft is rejected.
        let big = Transfer { from: ALICE, to: BOB, amount: 1000, nonce: 1 }.into_tx();
        assert_eq!(s.apply(&big), ExecOutcome::Rejected);
        // Balances unchanged by the rejected transactions.
        assert_eq!(s.balance(&ALICE), 30);
        assert_eq!(s.balance(&BOB), 20);
    }

    #[test]
    fn the_state_root_is_order_independent_of_final_state_but_reflects_it() {
        // Two ledgers that reach the SAME final balances/nonces have the same root; a different state
        // has a different root (binding).
        let mut a = Accounts::new();
        let mut b = Accounts::new();
        a.credit(ALICE, 100);
        b.credit(ALICE, 100);
        assert_eq!(a.state_root(), b.state_root());
        a.apply(&Transfer { from: ALICE, to: BOB, amount: 10, nonce: 0 }.into_tx());
        assert_ne!(a.state_root(), b.state_root(), "a state change changes the root");
        b.apply(&Transfer { from: ALICE, to: BOB, amount: 10, nonce: 0 }.into_tx());
        assert_eq!(a.state_root(), b.state_root(), "the same final state → the same root");
    }

    #[test]
    fn malformed_bytes_are_reported_not_applied() {
        let mut s = Accounts::new();
        assert_eq!(s.apply(&Transaction::new(b"not a transfer".to_vec())), ExecOutcome::Malformed);
    }
}
