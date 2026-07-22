//! The **hybrid ledger** — the DROMOS state that carries *both* halves of the platform under one `state_root`
//! (`spec/platform.md` §3.3): a **transparent** account tree (public smart-contract/staking/naming state, the
//! TAXIS [`Accounts`] model) and the **shielded** OBOLOS pool (`fanos-obolos`). Public value and private value
//! coexist on one chain, and the *same* execution checkpoint certifies both.
//!
//! A DROMOS transaction is a tagged payload — a leading byte selects which half executes it:
//!
//! - `0x00` **transparent** — the body is a TAXIS transfer (`Accounts::apply`);
//! - `0x01` **shielded** — the body is an OBOLOS submission (`fanos_obolos::decode_submission`).
//!
//! The hybrid `state_root` is `H(accounts_root ‖ shielded_root)`, so one binding commitment covers the entire
//! ledger — transparent balances and shielded notes alike — and any divergence in either half is caught by the
//! same checkpoint (the ХОЛАРХ **LU — Consistency** invariant, over public and private state at once).

use std::sync::Arc;

use fanos_obolos::{Params, ShieldedState, decode_submission};
use fanos_primitives::hash_labeled;
use fanos_taxis::state::{Accounts, ExecOutcome, StateMachine};
use fanos_taxis::tx::Transaction;

/// Transaction-type tag: a transparent TAXIS transfer.
pub const TAG_TRANSPARENT: u8 = 0x00;
/// Transaction-type tag: a shielded OBOLOS submission.
pub const TAG_SHIELDED: u8 = 0x01;

/// Domain-separation label for the hybrid state root.
const HYBRID_ROOT_LABEL: &str = "FANOS-dromos-v1/hybrid-root";

/// The DROMOS hybrid ledger: a transparent account tree and a shielded note pool under one `state_root`.
#[derive(Clone, Debug)]
pub struct HybridLedger {
    accounts: Accounts,
    shielded: ShieldedState,
    params: Arc<Params>,
}

impl HybridLedger {
    /// A hybrid ledger over a funded genesis account set and an empty shielded pool (canonical parameters).
    #[must_use]
    pub fn new(genesis_accounts: Accounts) -> Self {
        Self { accounts: genesis_accounts, shielded: ShieldedState::new(), params: Arc::new(Params::standard()) }
    }

    /// The transparent account state (read-only).
    #[must_use]
    pub fn accounts(&self) -> &Accounts {
        &self.accounts
    }

    /// The shielded pool state (read-only).
    #[must_use]
    pub fn shielded(&self) -> &ShieldedState {
        &self.shielded
    }

    /// The commitment parameters the shielded half verifies against.
    #[must_use]
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Issuance into the shielded pool (genesis allocation or block reward); returns the note position.
    pub fn mint_shielded(&mut self, note_commitment: [u8; 32]) -> Option<u64> {
        self.shielded.mint(note_commitment)
    }

    /// Wrap a transparent transfer's wire bytes as a DROMOS transaction payload.
    #[must_use]
    pub fn transparent_payload(transfer_wire: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + transfer_wire.len());
        out.push(TAG_TRANSPARENT);
        out.extend_from_slice(transfer_wire);
        out
    }

    /// Wrap an OBOLOS submission (`fanos_obolos::encode_submission`) as a DROMOS transaction payload.
    #[must_use]
    pub fn shielded_payload(submission: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + submission.len());
        out.push(TAG_SHIELDED);
        out.extend_from_slice(submission);
        out
    }
}

impl StateMachine for HybridLedger {
    /// Execute one committed transaction by dispatching on its type tag to the transparent or shielded half.
    /// An unknown tag or an empty payload is [`ExecOutcome::Malformed`].
    fn apply(&mut self, tx: &Transaction) -> ExecOutcome {
        match tx.payload.split_first() {
            Some((&TAG_TRANSPARENT, body)) => self.accounts.apply(&Transaction::new(body.to_vec())),
            Some((&TAG_SHIELDED, body)) => match decode_submission(body) {
                Some((shielded_tx, proof)) => match self.shielded.apply(&self.params, &shielded_tx, &proof) {
                    Ok(()) => ExecOutcome::Applied,
                    Err(_) => ExecOutcome::Rejected,
                },
                None => ExecOutcome::Malformed,
            },
            _ => ExecOutcome::Malformed,
        }
    }

    /// `H(accounts_root ‖ shielded_root)` — one binding commitment over the whole ledger, transparent and
    /// shielded, for the block's executed-state checkpoint.
    fn state_root(&self) -> [u8; 32] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.accounts.state_root());
        buf[32..].copy_from_slice(&self.shielded.root());
        hash_labeled(HYBRID_ROOT_LABEL, &buf)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_obolos::{Note, Randomness, SpendInput, build_transfer, derive_owner_pk, encode_submission};
    use fanos_taxis::Transfer;

    const ALICE: [u8; 32] = [0xA1; 32];
    const BOB: [u8; 32] = [0xB0; 32];

    fn genesis() -> Accounts {
        let mut a = Accounts::new();
        a.credit(ALICE, 1000);
        a
    }

    fn note(value: u64, nsk: &[u8; 32], tag: &[u8]) -> Note {
        Note::new(value, derive_owner_pk(nsk), Randomness::from_seed(tag), [tag.len() as u8; 32])
    }

    #[test]
    fn transparent_and_shielded_transactions_execute_on_one_ledger() {
        let mut ledger = HybridLedger::new(genesis());
        let root0 = ledger.state_root();

        // A transparent transfer Alice → Bob 100.
        let transfer = Transfer { from: ALICE, to: BOB, amount: 100, nonce: 0 };
        let tx_t = Transaction::new(HybridLedger::transparent_payload(&transfer.into_tx().payload));
        assert_eq!(ledger.apply(&tx_t), ExecOutcome::Applied, "the transparent transfer executes");
        assert_eq!(ledger.accounts().balance(&BOB), 100, "Bob's public balance updated");
        let root1 = ledger.state_root();
        assert_ne!(root1, root0, "the hybrid root reflects the transparent change");

        // A shielded transfer of a freshly-minted note.
        let nsk = [1u8; 32];
        let n0 = note(500, &nsk, b"n0");
        let pos = ledger.mint_shielded(n0.commitment(ledger.params())).unwrap();
        let sp = SpendInput { note: n0, nsk, path: ledger.shielded().path(pos).unwrap() };
        let (stx, proof) =
            build_transfer(ledger.params(), ledger.shielded().anchor(), &[sp], &[note(500, &[2u8; 32], b"o")], 0);
        let tx_s = Transaction::new(HybridLedger::shielded_payload(&encode_submission(&stx, &proof)));
        assert_eq!(ledger.apply(&tx_s), ExecOutcome::Applied, "the shielded transfer executes on the same ledger");
        assert_ne!(ledger.state_root(), root1, "the hybrid root reflects the shielded change too");
        // The transparent half is untouched by the shielded transaction.
        assert_eq!(ledger.accounts().balance(&BOB), 100, "public balances are unaffected by shielded activity");
    }

    #[test]
    fn the_hybrid_root_binds_both_halves() {
        // Two ledgers that differ only in the shielded half have different hybrid roots (and vice versa) — the
        // root commits to public AND private state.
        let mut only_transparent = HybridLedger::new(genesis());
        let mut also_shielded = HybridLedger::new(genesis());
        assert_eq!(only_transparent.state_root(), also_shielded.state_root(), "identical genesis ⇒ identical root");
        also_shielded.mint_shielded(note(1, &[1u8; 32], b"x").commitment(also_shielded.params())).unwrap();
        assert_ne!(only_transparent.state_root(), also_shielded.state_root(), "a shielded-only change moves the hybrid root");
        // Now diverge the transparent half of the first.
        let transfer = Transfer { from: ALICE, to: BOB, amount: 1, nonce: 0 };
        only_transparent.apply(&Transaction::new(HybridLedger::transparent_payload(&transfer.into_tx().payload)));
        assert_ne!(only_transparent.state_root(), also_shielded.state_root(), "divergent halves ⇒ divergent roots");
    }

    #[test]
    fn an_unknown_tag_or_empty_payload_is_malformed() {
        let mut ledger = HybridLedger::new(genesis());
        assert_eq!(ledger.apply(&Transaction::new(Vec::new())), ExecOutcome::Malformed, "empty payload");
        assert_eq!(ledger.apply(&Transaction::new(vec![0x7F, 1, 2, 3])), ExecOutcome::Malformed, "unknown tag");
        // A shielded tag with garbage body is malformed (not a valid submission).
        assert_eq!(ledger.apply(&Transaction::new(vec![TAG_SHIELDED, 0xFF])), ExecOutcome::Malformed);
    }
}
