//! The **hybrid ledger** — the DROMOS state that carries the whole platform under one `state_root`
//! (`spec/platform.md` §3.3, §5): an **authenticated transparent** token ledger (public balances that move
//! under a PQ signature — [`TokenLedger`]), the **shielded** OBOLOS pool (private value — `fanos-obolos`), and
//! the **name registry** (currency-bought names — [`NameRegistry`]). Public value, private value, and names
//! coexist on one chain, and the *same* execution checkpoint certifies all three.
//!
//! A DROMOS transaction is a tagged payload — a leading byte selects which subsystem executes it:
//!
//! - `0x00` **transparent** — a [`SignedTransfer`] on the token ledger;
//! - `0x01` **shielded** — an OBOLOS submission (`fanos_obolos::decode_submission`);
//! - `0x02` **name** — a [`NameTx`] (register/renew/update/transfer, paid on the token ledger).
//!
//! The registry's expiry rules read the block height, which the engine feeds via [`begin_block`](StateMachine::begin_block).
//! The hybrid `state_root` is `H(tokens ‖ shielded ‖ names)` — one binding commitment over the entire ledger.

use std::sync::Arc;

use fanos_obolos::{Params, ShieldedState, ShieldedTx, TransparentProof, decode_submission};
use fanos_primitives::hash_labeled;
use fanos_taxis::state::{ExecOutcome, StateMachine};
use fanos_taxis::tx::Transaction;

use crate::bridge::{POOL_SINK, ShieldTx};
use crate::naming::{NameRegistry, NameTx};
use crate::token::{SignedTransfer, TokenLedger};

/// Transaction-type tag: an authenticated transparent transfer.
pub const TAG_TRANSPARENT: u8 = 0x00;
/// Transaction-type tag: a shielded OBOLOS submission.
pub const TAG_SHIELDED: u8 = 0x01;
/// Transaction-type tag: a name-registry operation.
pub const TAG_NAME: u8 = 0x02;
/// Transaction-type tag: a shield (transparent → private pool).
pub const TAG_SHIELD: u8 = 0x03;

/// Domain-separation label for the hybrid state root.
const HYBRID_ROOT_LABEL: &str = "FANOS-dromos-v1/hybrid-root";

/// The DROMOS hybrid ledger: an authenticated token ledger, a shielded pool, and a name registry under one
/// `state_root`, with a block-height clock for the registry's expiries.
#[derive(Clone, Debug)]
pub struct HybridLedger {
    tokens: TokenLedger,
    shielded: ShieldedState,
    names: NameRegistry,
    params: Arc<Params>,
    height: u64,
}

impl HybridLedger {
    /// A hybrid ledger over a funded genesis token ledger, an empty shielded pool, and an empty name registry.
    #[must_use]
    pub fn new(genesis_tokens: TokenLedger) -> Self {
        Self {
            tokens: genesis_tokens,
            shielded: ShieldedState::new(),
            names: NameRegistry::new(),
            params: Arc::new(Params::standard()),
            height: 0,
        }
    }

    /// The authenticated transparent token ledger (read-only).
    #[must_use]
    pub fn tokens(&self) -> &TokenLedger {
        &self.tokens
    }

    /// The shielded pool state (read-only).
    #[must_use]
    pub fn shielded(&self) -> &ShieldedState {
        &self.shielded
    }

    /// The name registry (read-only).
    #[must_use]
    pub fn names(&self) -> &NameRegistry {
        &self.names
    }

    /// The commitment parameters the shielded half verifies against.
    #[must_use]
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// The current block height (the registry's clock), as fed by [`begin_block`](StateMachine::begin_block).
    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Issuance into the shielded pool; returns the note position.
    pub fn mint_shielded(&mut self, note_commitment: [u8; 32]) -> Option<u64> {
        self.shielded.mint(note_commitment)
    }

    /// The public total backing the shielded pool (the pool-sink balance) — equals the sum of unspent shielded
    /// note values by construction (every shield credits it, every unshield debits it).
    #[must_use]
    pub fn pool_backing(&self) -> u64 {
        self.tokens.balance(&POOL_SINK)
    }

    /// Wrap a shield operation as a DROMOS transaction payload.
    #[must_use]
    pub fn shield_payload(sx: &ShieldTx) -> Vec<u8> {
        Self::tagged(TAG_SHIELD, &sx.to_bytes())
    }

    /// Shield public tokens into the private pool: settle the payment to the pool sink and mint the note. The
    /// amount and the note's opening are public at entry; the note is privately spendable thereafter.
    fn shield(&mut self, sx: &ShieldTx) -> bool {
        if sx.payment.transfer.to != POOL_SINK || sx.payment.transfer.amount != sx.note.value {
            return false;
        }
        // Capacity guard so the (atomic) payment is never applied without the mint following.
        if self.shielded.note_count() >= (1u64 << fanos_obolos::TREE_DEPTH) {
            return false;
        }
        if self.tokens.apply(&sx.payment).is_err() {
            return false;
        }
        self.shielded.mint(sx.note.commitment(&self.params)).is_some()
    }

    /// Apply a shielded submission, handling an **unshield**: after the shielded spend verifies and applies, any
    /// `public_value` exiting the pool is moved from the pool sink to the `public_recipient` on the token ledger
    /// (authorised by the shielded proof, which enforced `Σ inputs = Σ shielded outputs + fee + public_value`).
    /// Atomic: the pool must back the exit before anything mutates, and the shielded spend leaves token balances
    /// untouched, so the transparent move always completes.
    fn apply_shielded(&mut self, stx: &ShieldedTx, proof: &TransparentProof) -> bool {
        if stx.public_value > 0 && self.pool_backing() < stx.public_value {
            return false;
        }
        if self.shielded.apply(&self.params, stx, proof).is_err() {
            return false;
        }
        if stx.public_value > 0 {
            let _ = self.tokens.move_system(&POOL_SINK, stx.public_recipient, stx.public_value);
        }
        true
    }

    /// Wrap a signed transparent transfer as a DROMOS transaction payload.
    #[must_use]
    pub fn transparent_payload(transfer: &SignedTransfer) -> Vec<u8> {
        Self::tagged(TAG_TRANSPARENT, &transfer.to_bytes())
    }

    /// Wrap an OBOLOS submission (`fanos_obolos::encode_submission`) as a DROMOS transaction payload.
    #[must_use]
    pub fn shielded_payload(submission: &[u8]) -> Vec<u8> {
        Self::tagged(TAG_SHIELDED, submission)
    }

    /// Wrap a name operation as a DROMOS transaction payload.
    #[must_use]
    pub fn name_payload(name_tx: &NameTx) -> Vec<u8> {
        Self::tagged(TAG_NAME, &name_tx.to_bytes())
    }

    fn tagged(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(tag);
        out.extend_from_slice(body);
        out
    }
}

impl StateMachine for HybridLedger {
    /// Set the registry's clock to the block being executed.
    fn begin_block(&mut self, height: u64) {
        self.height = height;
    }

    /// Execute one committed transaction by dispatching on its type tag. An unknown tag or empty payload is
    /// [`ExecOutcome::Malformed`]; a well-formed-but-invalid transaction (bad signature, double-spend, taken
    /// name, insufficient funds) is [`ExecOutcome::Rejected`]; success is [`ExecOutcome::Applied`].
    fn apply(&mut self, tx: &Transaction) -> ExecOutcome {
        match tx.payload.split_first() {
            Some((&TAG_TRANSPARENT, body)) => match SignedTransfer::from_bytes(body) {
                Some(st) => outcome(self.tokens.apply(&st).is_ok()),
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_SHIELDED, body)) => match decode_submission(body) {
                Some((shielded_tx, proof)) => outcome(self.apply_shielded(&shielded_tx, &proof)),
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_NAME, body)) => match NameTx::from_bytes(body) {
                Some(name_tx) => outcome(self.names.apply(&name_tx, &mut self.tokens, self.height).is_ok()),
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_SHIELD, body)) => match ShieldTx::from_bytes(body) {
                Some(sx) => outcome(self.shield(&sx)),
                None => ExecOutcome::Malformed,
            },
            _ => ExecOutcome::Malformed,
        }
    }

    /// `H(tokens_root ‖ shielded_root ‖ names_root)` — one commitment over transparent balances, shielded
    /// notes, and names, for the block's executed-state checkpoint.
    fn state_root(&self) -> [u8; 32] {
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(&self.tokens.state_root());
        buf[32..64].copy_from_slice(&self.shielded.root());
        buf[64..].copy_from_slice(&self.names.state_root());
        hash_labeled(HYBRID_ROOT_LABEL, &buf)
    }
}

/// Map an apply result to the coarse execution outcome (`Applied` on success, `Rejected` on a valid-but-refused
/// transaction — recorded as included-but-rejected, never a consensus failure).
fn outcome(ok: bool) -> ExecOutcome {
    if ok { ExecOutcome::Applied } else { ExecOutcome::Rejected }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::naming::{NameOp, TREASURY, price};
    use crate::token::{Transfer, account_id};
    use fanos_obolos::{Note, Randomness, SpendInput, build_transfer, build_unshield, derive_owner_pk, encode_submission};
    use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};

    fn account(tag: u8) -> (HybridSigSecret, HybridVerifier, [u8; 32]) {
        let mut rng = SeedRng::from_seed(&[0xC0, tag]);
        let (signer, verifier) = HybridSigSecret::generate(&mut rng);
        let id = account_id(&verifier);
        (signer, verifier, id)
    }

    fn note(value: u64, nsk: &[u8; 32], tag: &[u8]) -> Note {
        Note::new(value, derive_owner_pk(nsk), Randomness::from_seed(tag), [tag.len() as u8; 32])
    }

    #[test]
    fn transparent_shielded_and_name_transactions_execute_on_one_ledger() {
        let (alice_sk, alice_vk, alice) = account(1);
        let (_bob_sk, _bob_vk, bob) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 1_000_000);
        let mut ledger = HybridLedger::new(tokens);
        let root0 = ledger.state_root();

        // (1) A signed transparent transfer Alice → Bob 100.
        let st = SignedTransfer::sign(Transfer { from: alice, to: bob, amount: 100, nonce: 0 }, &alice_sk, alice_vk.clone());
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::transparent_payload(&st))), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&bob), 100);
        let root1 = ledger.state_root();
        assert_ne!(root1, root0);

        // (2) A shielded transfer of a minted note.
        let nsk = [9u8; 32];
        let n0 = note(500, &nsk, b"n0");
        let pos = ledger.mint_shielded(n0.commitment(ledger.params())).unwrap();
        let sp = SpendInput { note: n0, nsk, path: ledger.shielded().path(pos).unwrap() };
        let (stx, proof) = build_transfer(ledger.params(), ledger.shielded().anchor(), &[sp], &[note(500, &[2u8; 32], b"o")], 0);
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shielded_payload(&encode_submission(&stx, &proof)))), ExecOutcome::Applied);
        let root2 = ledger.state_root();
        assert_ne!(root2, root1);

        // (3) A name registration paid from Alice's transparent funds.
        let name = b"alice.fanos".to_vec();
        let fee = price(&name, 10);
        let name_tx = NameTx {
            op: NameOp::Register { name: name.clone(), target: b"addr".to_vec(), duration: 10 },
            payment: SignedTransfer::sign(Transfer { from: alice, to: TREASURY, amount: fee, nonce: 1 }, &alice_sk, alice_vk),
        };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::name_payload(&name_tx))), ExecOutcome::Applied);
        assert_eq!(ledger.names().resolve(&name, 0).unwrap().owner, alice, "the name is Alice's");
        assert_ne!(ledger.state_root(), root2, "the name registration moved the hybrid root");
    }

    #[test]
    fn the_block_clock_governs_name_expiry() {
        let (sk, vk, alice) = account(1);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 1_000_000);
        let mut ledger = HybridLedger::new(tokens);

        // At height 0, register for duration 10 → expiry 10.
        ledger.begin_block(0);
        let name = b"clock.fanos".to_vec();
        let fee = price(&name, 10);
        let tx = NameTx {
            op: NameOp::Register { name: name.clone(), target: vec![1], duration: 10 },
            payment: SignedTransfer::sign(Transfer { from: alice, to: TREASURY, amount: fee, nonce: 0 }, &sk, vk),
        };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::name_payload(&tx))), ExecOutcome::Applied);
        assert!(ledger.names().resolve(&name, ledger.height()).is_some(), "resolves at height 0");

        // Advance the clock past expiry: the engine's begin_block sets it, and the name no longer resolves.
        ledger.begin_block(11);
        assert_eq!(ledger.height(), 11);
        assert!(ledger.names().resolve(&name, ledger.height()).is_none(), "the name has expired by height 11");
    }

    #[test]
    fn an_unsigned_transparent_transfer_is_rejected_not_applied() {
        let (_alice_sk, _alice_vk, alice) = account(1);
        let (mallory_sk, mallory_vk, _m) = account(9);
        let (_b, _bv, bob) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 1000);
        let mut ledger = HybridLedger::new(tokens);
        // Mallory signs a transfer of Alice's funds with her own key → not authorised.
        let forged = SignedTransfer::sign(Transfer { from: alice, to: bob, amount: 100, nonce: 0 }, &mallory_sk, mallory_vk);
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::transparent_payload(&forged))), ExecOutcome::Rejected);
        assert_eq!(ledger.tokens().balance(&alice), 1000, "Alice's funds are untouched");
    }

    #[test]
    fn shielding_moves_public_tokens_into_a_spendable_private_note() {
        let (alice_sk, alice_vk, alice) = account(1);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 10_000);
        let mut ledger = HybridLedger::new(tokens);

        // Alice shields 500 into a note she owns.
        let nsk = [7u8; 32];
        let shield_note = Note::new(500, derive_owner_pk(&nsk), Randomness::from_seed(b"shield"), [1u8; 32]);
        let sx = ShieldTx {
            payment: SignedTransfer::sign(Transfer { from: alice, to: POOL_SINK, amount: 500, nonce: 0 }, &alice_sk, alice_vk),
            note: shield_note.clone(),
        };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shield_payload(&sx))), ExecOutcome::Applied);
        assert_eq!(ledger.pool_backing(), 500, "the pool sink backs the shielded value");
        assert_eq!(ledger.tokens().balance(&alice), 9_500, "Alice's public balance dropped by the shielded amount");
        assert_eq!(ledger.shielded().note_count(), 1, "the note entered the pool");

        // The shielded note is now privately spendable: Alice → Bob (shielded).
        let path = ledger.shielded().path(0).unwrap();
        let sp = SpendInput { note: shield_note, nsk, path };
        let (stx, proof) = build_transfer(ledger.params(), ledger.shielded().anchor(), &[sp], &[note(500, &[2u8; 32], b"bob")], 0);
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shielded_payload(&encode_submission(&stx, &proof)))), ExecOutcome::Applied, "the shielded note spends privately");
        assert_eq!(ledger.shielded().spent_count(), 1, "the shielded-from-transparent note was spent");
    }

    #[test]
    fn unshielding_moves_private_value_back_to_a_transparent_account() {
        let (alice_sk, alice_vk, alice) = account(1);
        let (_b, _bv, bob) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 10_000);
        let mut ledger = HybridLedger::new(tokens);

        // Alice shields 1000 into a private note.
        let nsk = [7u8; 32];
        let shielded_note = Note::new(1000, derive_owner_pk(&nsk), Randomness::from_seed(b"u"), [1u8; 32]);
        let sx = ShieldTx {
            payment: SignedTransfer::sign(Transfer { from: alice, to: POOL_SINK, amount: 1000, nonce: 0 }, &alice_sk, alice_vk),
            note: shielded_note.clone(),
        };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shield_payload(&sx))), ExecOutcome::Applied);
        assert_eq!(ledger.pool_backing(), 1000);

        // Alice unshields the whole 1000 to Bob's transparent account (spend the note, all value exits public).
        let path = ledger.shielded().path(0).unwrap();
        let sp = SpendInput { note: shielded_note, nsk, path };
        let (stx, proof) = build_unshield(ledger.params(), ledger.shielded().anchor(), &[sp], &[], 1000, bob, 0);
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shielded_payload(&encode_submission(&stx, &proof)))), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&bob), 1000, "the value exited the pool to Bob's public account");
        assert_eq!(ledger.pool_backing(), 0, "the pool sink was drained by the unshield");
        assert_eq!(ledger.shielded().spent_count(), 1, "the note was nullified");
    }

    #[test]
    fn a_shield_with_a_mismatched_amount_or_wrong_sink_is_refused() {
        let (alice_sk, alice_vk, alice) = account(1);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 10_000);
        let mut ledger = HybridLedger::new(tokens);
        let n = Note::new(500, derive_owner_pk(&[7u8; 32]), Randomness::from_seed(b"s"), [1u8; 32]);
        // Payment amount (400) ≠ note value (500) — you can't mint more private value than you paid.
        let mismatch = ShieldTx {
            payment: SignedTransfer::sign(Transfer { from: alice, to: POOL_SINK, amount: 400, nonce: 0 }, &alice_sk, alice_vk.clone()),
            note: n.clone(),
        };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shield_payload(&mismatch))), ExecOutcome::Rejected);
        // Payment not to the pool sink.
        let wrong_sink = ShieldTx {
            payment: SignedTransfer::sign(Transfer { from: alice, to: [0u8; 32], amount: 500, nonce: 0 }, &alice_sk, alice_vk),
            note: n,
        };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shield_payload(&wrong_sink))), ExecOutcome::Rejected);
        assert_eq!(ledger.pool_backing(), 0, "no value entered the pool on a refused shield");
        assert_eq!(ledger.tokens().balance(&alice), 10_000, "no funds moved");
    }

    #[test]
    fn an_unknown_tag_or_empty_payload_is_malformed() {
        let mut ledger = HybridLedger::new(TokenLedger::new());
        assert_eq!(ledger.apply(&Transaction::new(Vec::new())), ExecOutcome::Malformed);
        assert_eq!(ledger.apply(&Transaction::new(vec![0x7F, 1, 2, 3])), ExecOutcome::Malformed);
        assert_eq!(ledger.apply(&Transaction::new(vec![TAG_NAME, 0xFF])), ExecOutcome::Malformed);
    }
}
