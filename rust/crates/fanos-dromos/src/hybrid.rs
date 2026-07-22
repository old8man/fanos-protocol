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

use std::collections::BTreeMap;
use std::sync::Arc;

use fanos_obolos::{Params, ShieldedState, ShieldedTx, TransparentProof, decode_submission};
use fanos_primitives::hash_labeled;
use fanos_taxis::state::{ExecOutcome, StateMachine};
use fanos_taxis::tx::Transaction;

use fanos_thesauros::{Deal, DealParams, DealState, Settlement, decode_response, verify};

use crate::bridge::{POOL_SINK, ShieldTx};
use crate::naming::{NameRegistry, NameTx, TREASURY};
use crate::scheduler::{AccessList, schedule};
use crate::storage::{STORAGE_ESCROW, StorageMarket, StorageTx, deal_id, leaves_for_size};
use crate::token::{SignedTransfer, TokenLedger};

/// The shared state key every shielded operation touches — so shielded spends serialize against each other
/// (they mutate the one nullifier set / commitment tree) while parallelizing against disjoint transparent work.
const SHIELDED_MARKER: [u8; 32] = *b"FANOS-dromos-shielded-pool-mark!";
/// Domain label deriving a name's scheduler key from its bytes.
const NAME_KEY_LABEL: &str = "FANOS-dromos-v1/name-key";

/// Transaction-type tag: an authenticated transparent transfer.
pub const TAG_TRANSPARENT: u8 = 0x00;
/// Transaction-type tag: a shielded OBOLOS submission.
pub const TAG_SHIELDED: u8 = 0x01;
/// Transaction-type tag: a name-registry operation.
pub const TAG_NAME: u8 = 0x02;
/// Transaction-type tag: a shield (transparent → private pool).
pub const TAG_SHIELD: u8 = 0x03;
/// Transaction-type tag: a THESAUROS storage-market operation (open/prove/close).
pub const TAG_STORAGE: u8 = 0x04;

/// Domain-separation label for the hybrid state root.
const HYBRID_ROOT_LABEL: &str = "FANOS-dromos-v1/hybrid-root";

/// The DROMOS hybrid ledger: an authenticated token ledger, a shielded pool, and a name registry under one
/// `state_root`, with a block-height clock for the registry's expiries.
#[derive(Clone, Debug)]
pub struct HybridLedger {
    tokens: TokenLedger,
    shielded: ShieldedState,
    names: NameRegistry,
    storage: StorageMarket,
    params: Arc<Params>,
    height: u64,
    audit_beacon: [u8; 32],
}

impl HybridLedger {
    /// A hybrid ledger over a funded genesis token ledger, an empty shielded pool, and an empty name registry.
    #[must_use]
    pub fn new(genesis_tokens: TokenLedger) -> Self {
        Self {
            tokens: genesis_tokens,
            shielded: ShieldedState::new(),
            names: NameRegistry::new(),
            storage: StorageMarket::default(),
            params: Arc::new(Params::standard()),
            height: 0,
            audit_beacon: [0u8; 32],
        }
    }

    /// The storage market sub-state (read-only).
    #[must_use]
    pub fn storage(&self) -> &StorageMarket {
        &self.storage
    }

    /// The balance held in the storage-escrow sink (the sum of unreleased deal escrow by construction).
    #[must_use]
    pub fn storage_escrow(&self) -> u64 {
        self.tokens.balance(&STORAGE_ESCROW)
    }

    /// Wrap a storage-market operation as a DROMOS transaction payload.
    #[must_use]
    pub fn storage_payload(tx: &StorageTx) -> Vec<u8> {
        Self::tagged(TAG_STORAGE, &tx.to_bytes())
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

    /// Open a storage deal: the consumer's `payment` must fund the escrow sink with exactly the price. Validates
    /// the transfer binds the consumer and targets the sink, opens the deal (a fresh id), then settles the
    /// payment — so a rejected open never moves money (the naming registry's validate→settle ordering).
    fn open_deal(&mut self, params: &DealParams, payment: &SignedTransfer) -> bool {
        if !payment.verify()
            || payment.transfer.from != params.consumer
            || payment.transfer.to != STORAGE_ESCROW
            || payment.transfer.amount != params.price
        {
            return false;
        }
        let id = deal_id(params, payment.transfer.nonce);
        if self.storage.deals.contains_key(&id) {
            return false;
        }
        let Some(deal) = Deal::open(*params) else {
            return false;
        };
        if self.tokens.apply(payment).is_err() {
            return false;
        }
        self.storage.deals.insert(id, deal);
        true
    }

    /// Prove retrievability for a deal's current epoch: recompute the audit challenge from the block's beacon,
    /// verify the response against the committed CID, then — only on success — settle the epoch and release the
    /// slice from escrow to the provider (`move_system`, the proof-gated keyless-sink release).
    fn prove_deal(&mut self, id: &[u8; 32], response_bytes: &[u8]) -> bool {
        let Some(params) = self.storage.deals.get(id).filter(|d| d.state() == DealState::Active).map(|d| *d.params())
        else {
            return false;
        };
        let Some(response) = decode_response(response_bytes) else {
            return false;
        };
        let leaves = leaves_for_size(params.size);
        if !verify(&params.cid, &self.audit_beacon, params.k as usize, leaves, &response) {
            return false;
        }
        let Some(settlement) = self.storage.deals.get_mut(id).and_then(|d| d.settle_epoch(true)) else {
            return false;
        };
        if let Settlement::Pay { provider, amount } = settlement {
            let _ = self.tokens.move_system(&STORAGE_ESCROW, provider, amount);
        }
        true
    }

    /// Close a deal early: `auth` must be a valid signed transfer *from the consumer* (checked, never applied).
    /// Refunds the unreleased escrow to the consumer.
    fn close_deal(&mut self, id: &[u8; 32], auth: &SignedTransfer) -> bool {
        let Some(consumer) = self.storage.deals.get(id).map(|d| d.params().consumer) else {
            return false;
        };
        if !auth.verify() || auth.transfer.from != consumer {
            return false;
        }
        let Some(refund) = self.storage.deals.get_mut(id).map(Deal::close) else {
            return false;
        };
        if refund > 0 {
            let _ = self.tokens.move_system(&STORAGE_ESCROW, consumer, refund);
        }
        true
    }

    /// Execute a block's ordered transactions with DROMOS's **parallel scheduler** (`spec/platform.md` §3.1):
    /// derive each transaction's [`AccessList`], partition into conflict-free waves, and execute wave-by-wave.
    /// The scheduler guarantees the outcome is independent of intra-wave order and identical to serial execution
    /// (`crate::scheduler`) — so every validator reaches the same state, and a production executor may run a
    /// wave's transactions across a thread pool where this reference runs them in index order. Returns each
    /// transaction's [`ExecOutcome`] in the original order.
    #[must_use]
    pub fn execute_block(&mut self, txs: &[Transaction]) -> Vec<ExecOutcome> {
        let access = self.access_lists(txs);
        let waves = schedule(&access);
        let mut outcomes = vec![ExecOutcome::Malformed; txs.len()];
        for wave in &waves {
            for &i in wave {
                if let (Some(tx), Some(slot)) = (txs.get(i), outcomes.get_mut(i)) {
                    *slot = self.apply(tx);
                }
            }
        }
        outcomes
    }

    /// Derive the access list of every transaction, in a single forward pass that also tracks deals **opened
    /// earlier in the same block** — so a `Prove`/`Close` for a not-yet-committed deal still declares that deal's
    /// provider/consumer, and cannot race a parallel transfer touching them.
    #[must_use]
    fn access_lists(&self, txs: &[Transaction]) -> Vec<AccessList> {
        // deal_id -> (provider, consumer) for deals opened earlier in this block.
        let mut pending: BTreeMap<[u8; 32], ([u8; 32], [u8; 32])> = BTreeMap::new();
        let mut out = Vec::with_capacity(txs.len());
        for tx in txs {
            out.push(self.access_of(tx, &pending));
            if let Some((&TAG_STORAGE, body)) = tx.payload.split_first()
                && let Some(StorageTx::Open { params, payment }) = StorageTx::from_bytes(body)
            {
                pending.insert(deal_id(&params, payment.transfer.nonce), (params.provider, params.consumer));
            }
        }
        out
    }

    /// The state keys one transaction touches — a conservative superset (so the scheduler never lets two
    /// genuinely-dependent transactions share a wave). A transaction that does not decode touches nothing (its
    /// execution is a no-op). `pending` supplies deals opened earlier in the same block.
    #[must_use]
    fn access_of(&self, tx: &Transaction, pending: &BTreeMap<[u8; 32], ([u8; 32], [u8; 32])>) -> AccessList {
        match tx.payload.split_first() {
            Some((&TAG_TRANSPARENT, body)) => match SignedTransfer::from_bytes(body) {
                Some(st) => AccessList::new([], [st.transfer.from, st.transfer.to]),
                None => AccessList::default(),
            },
            Some((&TAG_SHIELDED, body)) => match decode_submission(body) {
                Some((stx, _)) => {
                    let mut writes = vec![SHIELDED_MARKER, POOL_SINK];
                    if stx.public_value > 0 {
                        writes.push(stx.public_recipient);
                    }
                    AccessList::new([], writes)
                }
                None => AccessList::default(),
            },
            Some((&TAG_NAME, body)) => match NameTx::from_bytes(body) {
                Some(nt) => AccessList::new(
                    [],
                    [nt.payment.transfer.from, TREASURY, hash_labeled(NAME_KEY_LABEL, nt.op.name())],
                ),
                None => AccessList::default(),
            },
            Some((&TAG_SHIELD, body)) => match ShieldTx::from_bytes(body) {
                Some(sx) => AccessList::new([], [sx.payment.transfer.from, POOL_SINK, SHIELDED_MARKER]),
                None => AccessList::default(),
            },
            Some((&TAG_STORAGE, body)) => match StorageTx::from_bytes(body) {
                Some(StorageTx::Open { params, payment }) => AccessList::new(
                    [],
                    [params.consumer, STORAGE_ESCROW, deal_id(&params, payment.transfer.nonce)],
                ),
                Some(StorageTx::Prove { deal_id: id, .. }) => {
                    let mut writes = vec![STORAGE_ESCROW, id];
                    if let Some(provider) = self.deal_party(&id, pending).map(|(p, _)| p) {
                        writes.push(provider);
                    }
                    AccessList::new([], writes)
                }
                Some(StorageTx::Close { deal_id: id, .. }) => {
                    let mut writes = vec![STORAGE_ESCROW, id];
                    if let Some(consumer) = self.deal_party(&id, pending).map(|(_, c)| c) {
                        writes.push(consumer);
                    }
                    AccessList::new([], writes)
                }
                None => AccessList::default(),
            },
            _ => AccessList::default(),
        }
    }

    /// A deal's `(provider, consumer)` — from committed state, or a same-block pending open.
    #[must_use]
    fn deal_party(
        &self,
        id: &[u8; 32],
        pending: &BTreeMap<[u8; 32], ([u8; 32], [u8; 32])>,
    ) -> Option<([u8; 32], [u8; 32])> {
        if let Some(deal) = self.storage.deals.get(id) {
            let p = deal.params();
            return Some((p.provider, p.consumer));
        }
        pending.get(id).copied()
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

    /// Adopt the block's audit beacon (the parent hash) — the storage market's retrievability challenges are
    /// drawn from it, so its consensus-committed unpredictability is what makes the audit ungrindable
    /// (`crate::storage`).
    fn set_audit_beacon(&mut self, beacon: [u8; 32]) {
        self.audit_beacon = beacon;
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
            Some((&TAG_STORAGE, body)) => match StorageTx::from_bytes(body) {
                Some(StorageTx::Open { params, payment }) => outcome(self.open_deal(&params, &payment)),
                Some(StorageTx::Prove { deal_id, response }) => outcome(self.prove_deal(&deal_id, &response)),
                Some(StorageTx::Close { deal_id, auth }) => outcome(self.close_deal(&deal_id, &auth)),
                None => ExecOutcome::Malformed,
            },
            _ => ExecOutcome::Malformed,
        }
    }

    /// `H(tokens_root ‖ shielded_root ‖ names_root ‖ storage_root)` — one commitment over transparent balances,
    /// shielded notes, names, and storage deals, for the block's executed-state checkpoint.
    fn state_root(&self) -> [u8; 32] {
        let mut buf = [0u8; 128];
        buf[..32].copy_from_slice(&self.tokens.state_root());
        buf[32..64].copy_from_slice(&self.shielded.root());
        buf[64..96].copy_from_slice(&self.names.state_root());
        buf[96..].copy_from_slice(&self.storage.state_root());
        hash_labeled(HYBRID_ROOT_LABEL, &buf)
    }
}

/// Map an apply result to the coarse execution outcome (`Applied` on success, `Rejected` on a valid-but-refused
/// transaction — recorded as included-but-rejected, never a consensus failure).
fn outcome(ok: bool) -> ExecOutcome {
    if ok { ExecOutcome::Applied } else { ExecOutcome::Rejected }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
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
    fn a_storage_deal_pays_per_verified_proof_and_refunds_on_close() {
        use fanos_thesauros::content::{LEAF, chunk_cid};
        use fanos_thesauros::{DealParams, challenge, encode_response, prove};

        let (consumer_sk, consumer_vk, consumer) = account(1);
        let (_p_sk, _p_vk, provider) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(consumer, 1_000_000);
        let mut ledger = HybridLedger::new(tokens);
        let beacon = [0x5Au8; 32];
        ledger.set_audit_beacon(beacon); // the block's VRF beacon (fixed here for the test)

        // An 8-leaf chunk and the deal storing it for 4 audit epochs at price 400.
        let chunk: Vec<u8> = (0..8 * LEAF).map(|i| (i / LEAF + 1) as u8).collect();
        let cid = chunk_cid(&chunk);
        let params = DealParams {
            cid,
            size: chunk.len() as u64,
            duration: 4,
            replication: 3,
            lambda_bits: 10,
            f_tol_permille: 100,
            k: 3,
            price: 400,
            provider,
            consumer,
        };
        // Open: escrow 400 from the consumer into the sink.
        let payment = SignedTransfer::sign(
            Transfer { from: consumer, to: STORAGE_ESCROW, amount: 400, nonce: 0 },
            &consumer_sk,
            consumer_vk.clone(),
        );
        let open = StorageTx::Open { params, payment };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&open))), ExecOutcome::Applied);
        assert_eq!(ledger.storage_escrow(), 400, "the price is escrowed");
        assert_eq!(ledger.tokens().balance(&consumer), 999_600);
        let id = deal_id(&params, 0);

        // Prove epoch 0: the provider answers the beacon's challenge → paid one slice (price/duration = 100).
        let indices = challenge(&cid, &beacon, 3, 8);
        let response = encode_response(&prove(&chunk, &indices).unwrap());
        let prove_tx = StorageTx::Prove { deal_id: id, response };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&prove_tx))), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&provider), 100, "the provider earned one slice from escrow");
        assert_eq!(ledger.storage_escrow(), 300);

        // A garbage proof pays nothing.
        let bad = StorageTx::Prove { deal_id: id, response: vec![0u8; 4] };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&bad))), ExecOutcome::Rejected);
        assert_eq!(ledger.tokens().balance(&provider), 100, "an unverifiable proof releases nothing");

        // Close: the consumer reclaims the unproven 300 (an auth transfer from the consumer, never applied).
        let auth = SignedTransfer::sign(
            Transfer { from: consumer, to: STORAGE_ESCROW, amount: 0, nonce: 1 },
            &consumer_sk,
            consumer_vk,
        );
        let close = StorageTx::Close { deal_id: id, auth };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&close))), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&consumer), 999_900, "the consumer recovered the unproven escrow");
        assert_eq!(ledger.storage_escrow(), 0, "the escrow sink is drained");
    }

    #[test]
    fn a_storage_open_with_the_wrong_escrow_amount_is_rejected() {
        use fanos_thesauros::DealParams;
        let (consumer_sk, consumer_vk, consumer) = account(1);
        let (_p, _pv, provider) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(consumer, 1000);
        let mut ledger = HybridLedger::new(tokens);
        let params = DealParams {
            cid: fanos_thesauros::Cid::new([1u8; 32]),
            size: 4096,
            duration: 4,
            replication: 3,
            lambda_bits: 10,
            f_tol_permille: 100,
            k: 3,
            price: 400,
            provider,
            consumer,
        };
        // Payment is 300, but the price is 400 — refused, no money moves.
        let payment = SignedTransfer::sign(
            Transfer { from: consumer, to: STORAGE_ESCROW, amount: 300, nonce: 0 },
            &consumer_sk,
            consumer_vk,
        );
        let open = StorageTx::Open { params, payment };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&open))), ExecOutcome::Rejected);
        assert_eq!(ledger.storage_escrow(), 0, "nothing was escrowed on a refused open");
        assert_eq!(ledger.tokens().balance(&consumer), 1000, "the consumer's funds are untouched");
    }

    #[test]
    fn execute_block_matches_serial_execution_and_parallelizes_independent_work() {
        // Six funded accounts.
        let accts: Vec<_> = (0..6).map(account).collect();
        let fund = || {
            let mut t = TokenLedger::new();
            for (_, _, id) in &accts {
                t.credit(*id, 10_000);
            }
            t
        };
        let transfer = |from: &(HybridSigSecret, HybridVerifier, [u8; 32]),
                        to: [u8; 32],
                        amount: u64,
                        nonce: u64| {
            let st = SignedTransfer::sign(Transfer { from: from.2, to, amount, nonce }, &from.0, from.1.clone());
            Transaction::new(HybridLedger::transparent_payload(&st))
        };
        // Three independent transfers, then one that conflicts with two of them (shared sender a, recipient c).
        let txs = vec![
            transfer(&accts[0], accts[1].2, 100, 0), // a -> b
            transfer(&accts[2], accts[3].2, 200, 0), // c -> d   (independent)
            transfer(&accts[4], accts[5].2, 300, 0), // e -> f   (independent)
            transfer(&accts[0], accts[2].2, 50, 1),  // a -> c   (touches a and c)
        ];

        // Serial reference.
        let mut serial = HybridLedger::new(fund());
        let serial_outcomes: Vec<_> = txs.iter().map(|t| serial.apply(t)).collect();

        // Parallel execution reproduces the outcomes and the state exactly.
        let mut parallel = HybridLedger::new(fund());
        let parallel_outcomes = parallel.execute_block(&txs);
        assert_eq!(parallel_outcomes, serial_outcomes, "parallel outcomes match serial");
        assert_eq!(parallel.state_root(), serial.state_root(), "parallel state matches serial");
        assert!(serial_outcomes.iter().all(|o| *o == ExecOutcome::Applied), "all transfers applied");

        // The first three transfers are independent → one parallel wave; the fourth waits (conflicts a and c).
        let waves = schedule(&parallel.access_lists(&txs));
        assert_eq!(crate::scheduler::width(&waves), 3, "the three independent transfers run in parallel");
        assert_eq!(waves.len(), 2, "the conflicting fourth transfer is a second wave");
    }

    #[test]
    fn an_unknown_tag_or_empty_payload_is_malformed() {
        let mut ledger = HybridLedger::new(TokenLedger::new());
        assert_eq!(ledger.apply(&Transaction::new(Vec::new())), ExecOutcome::Malformed);
        assert_eq!(ledger.apply(&Transaction::new(vec![0x7F, 1, 2, 3])), ExecOutcome::Malformed);
        assert_eq!(ledger.apply(&Transaction::new(vec![TAG_NAME, 0xFF])), ExecOutcome::Malformed);
    }
}
