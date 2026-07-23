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
use fanos_primitives::codec::{Reader, put_u64, put_var_bytes};
use fanos_primitives::hash_labeled;
use fanos_taxis::state::{ExecOutcome, StateMachine};
use fanos_taxis::tx::Transaction;

use fanos_hermes::{Htlc, HtlcState, HtlcTerms, Resolution};
use fanos_thesauros::{Deal, DealParams, DealState, Settlement, decode_response, verify};

use crate::bridge::{POOL_SINK, ShieldTx};
use crate::hermes::{HTLC_ESCROW, HtlcBook, HtlcTx, htlc_id};
use crate::naming::{NameRegistry, NameTx, TREASURY};
use crate::scheduler::{AccessList, schedule};
use crate::storage::{
    AUDIT_PERIOD, MAX_DEAL_DURATION, MAX_DEAL_SIZE, STORAGE_ESCROW, StorageMarket, StorageTx, deal_id,
    leaves_for_size,
};
use crate::token::{ProverAuth, SignedTransfer, TokenLedger};

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
/// Transaction-type tag: a HERMES atomic-swap operation (lock/claim/refund).
pub const TAG_HTLC: u8 = 0x05;

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
    htlcs: HtlcBook,
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
            htlcs: HtlcBook::default(),
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

    /// The HTLC book (read-only).
    #[must_use]
    pub fn htlcs(&self) -> &HtlcBook {
        &self.htlcs
    }

    /// The balance held in the HTLC escrow sink (the sum of unresolved locked contracts by construction).
    #[must_use]
    pub fn htlc_escrow(&self) -> u64 {
        self.tokens.balance(&HTLC_ESCROW)
    }

    /// Wrap a HERMES atomic-swap operation as a DROMOS transaction payload.
    #[must_use]
    pub fn htlc_payload(tx: &HtlcTx) -> Vec<u8> {
        Self::tagged(TAG_HTLC, &tx.to_bytes())
    }

    /// Lock an HTLC: the sender's `payment` must fund the escrow with exactly the contract amount. Validates,
    /// opens the contract (a fresh id), then settles the payment (validate-then-settle, so a rejected lock moves
    /// no money).
    fn lock_htlc(&mut self, terms: &HtlcTerms, payment: &SignedTransfer) -> bool {
        // A non-zero escrow floor (audit §3.4): an `amount == 0` lock passes the token check (`balance < 0` is
        // false) for only a signature, yet inserts a permanent `htlcs` entry. Requiring a real locked amount
        // makes growing the book cost the attacker locked capital.
        if terms.amount == 0
            || !payment.verify()
            || payment.transfer.from != terms.sender
            || payment.transfer.to != HTLC_ESCROW
            || payment.transfer.amount != terms.amount
        {
            return false;
        }
        let id = htlc_id(terms, payment.transfer.nonce);
        if self.htlcs.htlcs.contains_key(&id) {
            return false;
        }
        if self.tokens.apply(payment).is_err() {
            return false;
        }
        self.htlcs.htlcs.insert(id, Htlc::new(*terms));
        true
    }

    /// Claim an HTLC by revealing `preimage`: the contract's state machine checks the hashlock and the timeout
    /// (against the block-height clock); on success the escrow is released to the recipient.
    fn claim_htlc(&mut self, id: &[u8; 32], preimage: &[u8; 32]) -> bool {
        let height = self.height;
        let Some(Resolution::Pay { to, amount }) =
            self.htlcs.htlcs.get_mut(id).and_then(|h| h.claim(preimage, height))
        else {
            return false;
        };
        let _ = self.tokens.move_system(&HTLC_ESCROW, to, amount);
        true
    }

    /// Refund a timed-out HTLC to its sender (the state machine enforces the timeout against the height clock).
    fn refund_htlc(&mut self, id: &[u8; 32]) -> bool {
        let height = self.height;
        let Some(Resolution::Pay { to, amount }) = self.htlcs.htlcs.get_mut(id).and_then(|h| h.refund(height)) else {
            return false;
        };
        let _ = self.tokens.move_system(&HTLC_ESCROW, to, amount);
        true
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
        // Both the public output and the fee are clear value LEAVING the shielded pool (the balance law is
        // Σ inputs = Σ shielded outputs + fee + public_value), so the pool sink must back their sum.
        let leaving = stx.public_value.saturating_add(stx.fee);
        if leaving > 0 && self.pool_backing() < leaving {
            return false;
        }
        if self.shielded.apply(&self.params, stx, proof).is_err() {
            return false;
        }
        if stx.public_value > 0 {
            let _ = self.tokens.move_system(&POOL_SINK, stx.public_recipient, stx.public_value);
        }
        // The fee leaves the pool to the treasury (audit O-H1): otherwise it silently reduces the shielded
        // supply while staying stranded in the pool sink, breaking the `POOL_SINK == Σ unspent notes` invariant
        // and paying no one — now the fee is collected and validator-distributable.
        if stx.fee > 0 {
            let _ = self.tokens.move_system(&POOL_SINK, TREASURY, stx.fee);
        }
        true
    }

    /// Open a storage deal: the consumer's `payment` must fund the escrow sink with exactly the price. Validates
    /// the transfer binds the consumer and targets the sink, opens the deal (a fresh id), then settles the
    /// payment — so a rejected open never moves money (the naming registry's validate→settle ordering).
    fn open_deal(&mut self, params: &DealParams, payment: &SignedTransfer) -> bool {
        // Bound the deal's audit parameters (audit §3.3). `size` is attacker-chosen and sets `por::challenge`'s
        // leaf domain (`leaves_for_size`) on the deterministic prove path — bounding it to one chunk keeps the
        // leaf count (and hence the audit allocation) tiny, so a crafted oversized deal can never make
        // `challenge` reserve gigabytes and OOM-abort every validator. `k` needs no upper bound once `size` is
        // capped (`challenge` audits at most `leaves` regardless, and `k ≥ leaves` legitimately means "audit
        // all"); a zero `size`/`k`/`duration` is a degenerate no-op deal.
        if params.size == 0
            || params.size > MAX_DEAL_SIZE
            || params.k == 0
            || params.duration == 0
            || params.duration > MAX_DEAL_DURATION
            || params.price == 0
        {
            return false;
        }
        // A non-zero escrow floor (audit §3.4): `balance < amount` is false for `amount == 0`, so a `price = 0`
        // deal would cost a funds-less attacker only a signature yet still insert a permanent `deals` entry that
        // every block's lapse sweep + state root must carry. Requiring a real escrow (checked equal to `price`
        // below) means growing the deals map costs the attacker locked capital, one Active deal at a time.
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
        // Anchor the audit deadline at the current height so the deal can auto-complete + refund if the provider
        // stops proving (audit AT-H2), rather than sitting Active forever awaiting a manual close.
        let Some(deal) = Deal::open_at(*params, self.height) else {
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
    fn prove_deal(&mut self, id: &[u8; 32], prover_auth: &ProverAuth, response_bytes: &[u8]) -> bool {
        let Some(params) = self.storage.deals.get(id).filter(|d| d.state() == DealState::Active).map(|d| *d.params())
        else {
            return false;
        };
        // The proof must be authorised by the deal's provider — a FRESH per-audit signature over this exact
        // `deal_id ‖ H(response)` (audit §3.6 / AT-H1). Only the designated provider's key can produce it, and it
        // commits to the specific response (which `por::verify` binds to the block beacon), so a captured auth
        // cannot be replayed at a later epoch and a third party holding a replica of the public leaves cannot
        // forge it to be paid for data the provider deleted. The auth is verified, never applied.
        if !prover_auth.verify(id, response_bytes, &params.provider) {
            return false;
        }
        let Some(response) = decode_response(response_bytes) else {
            return false;
        };
        let leaves = leaves_for_size(params.size);
        if !verify(&params.cid, &self.audit_beacon, params.k as usize, leaves, &response) {
            return false;
        }
        // Settle at this block height; the deal rejects a second settlement at the same height, so a provider
        // cannot replay one proof many times within a block to drain the escrow (audit AT-C1).
        let height = self.height;
        let Some(settlement) = self.storage.deals.get_mut(id).and_then(|d| d.settle_epoch(height, true, AUDIT_PERIOD)) else {
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
        // The close authorisation must be signed by the consumer AND bound to this deal (to == deal id), so a
        // historical signed transfer from the consumer cannot be replayed to force-close an active deal early
        // (audit AT-M4). The auth is verified, never applied.
        if !auth.verify() || auth.transfer.from != consumer || auth.transfer.to != *id {
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

    /// Finalize storage deals whose audit deadline has lapsed at the current height: each auto-completes and its
    /// unproven escrow is refunded to the consumer (audit AT-H2), so a provider that stops proving stops being
    /// paid without the consumer having to close manually. Linear in the open-deal count per block — a
    /// deadline-ordered index is the scaling refinement.
    fn finalize_lapsed_deals(&mut self) {
        let height = self.height;
        let mut refunds: Vec<([u8; 32], u64)> = Vec::new();
        for deal in self.storage.deals.values_mut() {
            if let Some(refund) = deal.finalize_if_lapsed(height, AUDIT_PERIOD)
                && refund > 0
            {
                refunds.push((deal.params().consumer, refund));
            }
        }
        for (consumer, refund) in refunds {
            let _ = self.tokens.move_system(&STORAGE_ESCROW, consumer, refund);
        }
        // Prune terminal deals (audit §3.4): a Completed/Closed deal settles/refunds no further, so keeping it
        // only makes every subsequent block's lapse sweep + state root carry dead entries without bound. A
        // prove/close for a pruned id is rejected (the deal is no longer found), and a fresh open uses a distinct
        // nonce-derived id, so pruning can neither be replayed nor collide. Deterministic (every node prunes the
        // same terminal set at this height), so the state root stays identical across the cell.
        self.storage.deals.retain(|_, d| d.state() == DealState::Active);
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
        // Deals / contracts opened earlier in this block: id -> the two parties whose balances they may move.
        let mut deals: BTreeMap<[u8; 32], ([u8; 32], [u8; 32])> = BTreeMap::new();
        let mut htlcs: BTreeMap<[u8; 32], ([u8; 32], [u8; 32])> = BTreeMap::new();
        let mut out = Vec::with_capacity(txs.len());
        for tx in txs {
            out.push(self.access_of(tx, &deals, &htlcs));
            match tx.payload.split_first() {
                Some((&TAG_STORAGE, body)) => {
                    if let Some(StorageTx::Open { params, payment }) = StorageTx::from_bytes(body) {
                        deals.insert(deal_id(&params, payment.transfer.nonce), (params.provider, params.consumer));
                    }
                }
                Some((&TAG_HTLC, body)) => {
                    if let Some(HtlcTx::Lock { terms, payment }) = HtlcTx::from_bytes(body) {
                        htlcs.insert(htlc_id(&terms, payment.transfer.nonce), (terms.sender, terms.recipient));
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// The state keys one transaction touches — a conservative superset (so the scheduler never lets two
    /// genuinely-dependent transactions share a wave). A transaction that does not decode touches nothing (its
    /// execution is a no-op). `pending` supplies deals opened earlier in the same block.
    #[must_use]
    fn access_of(
        &self,
        tx: &Transaction,
        pending: &BTreeMap<[u8; 32], ([u8; 32], [u8; 32])>,
        pending_htlc: &BTreeMap<[u8; 32], ([u8; 32], [u8; 32])>,
    ) -> AccessList {
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
                    if stx.fee > 0 {
                        // The fee moves POOL_SINK → TREASURY at runtime (`apply_shielded`, audit O-H1), so
                        // TREASURY is a real write — declare it (audit §3.7). Without this a shielded-fee tx and a
                        // name tx (which also writes TREASURY) read as non-conflicting yet both write it, so once
                        // the parallel scheduler is live and TREASURY gains a read/debit they could fork the state.
                        writes.push(TREASURY);
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
            Some((&TAG_HTLC, body)) => match HtlcTx::from_bytes(body) {
                Some(HtlcTx::Lock { terms, payment }) => {
                    AccessList::new([], [terms.sender, HTLC_ESCROW, htlc_id(&terms, payment.transfer.nonce)])
                }
                Some(HtlcTx::Claim { htlc_id: id, .. }) => {
                    let mut writes = vec![HTLC_ESCROW, id];
                    if let Some(recipient) = self.htlc_party(&id, pending_htlc).map(|(_, r)| r) {
                        writes.push(recipient);
                    }
                    AccessList::new([], writes)
                }
                Some(HtlcTx::Refund { htlc_id: id }) => {
                    let mut writes = vec![HTLC_ESCROW, id];
                    if let Some(sender) = self.htlc_party(&id, pending_htlc).map(|(s, _)| s) {
                        writes.push(sender);
                    }
                    AccessList::new([], writes)
                }
                None => AccessList::default(),
            },
            _ => AccessList::default(),
        }
    }

    /// An HTLC's `(sender, recipient)` — from committed state, or a same-block pending lock.
    #[must_use]
    fn htlc_party(
        &self,
        id: &[u8; 32],
        pending: &BTreeMap<[u8; 32], ([u8; 32], [u8; 32])>,
    ) -> Option<([u8; 32], [u8; 32])> {
        if let Some(htlc) = self.htlcs.htlcs.get(id) {
            let t = htlc.terms();
            return Some((t.sender, t.recipient));
        }
        pending.get(id).copied()
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
    /// Set the registry's clock to the block being executed, and finalize any storage deals whose audit deadline
    /// has now lapsed (auto-refunding the consumer — audit AT-H2).
    fn begin_block(&mut self, height: u64) {
        self.height = height;
        self.finalize_lapsed_deals();
        // Prune terminal HTLCs (audit §3.4): a Claimed/Refunded htlc resolves no further, so keeping it only
        // grows the book + state root without bound. A Locked htlc holds real escrow (self-limiting) and stays
        // until it resolves; a claim/refund for a pruned id is rejected (not found). Deterministic across the cell.
        self.htlcs.htlcs.retain(|_, h| h.state() == HtlcState::Locked);
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
                Some(StorageTx::Prove { deal_id, prover_auth, response }) => {
                    outcome(self.prove_deal(&deal_id, &prover_auth, &response))
                }
                Some(StorageTx::Close { deal_id, auth }) => outcome(self.close_deal(&deal_id, &auth)),
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_HTLC, body)) => match HtlcTx::from_bytes(body) {
                Some(HtlcTx::Lock { terms, payment }) => outcome(self.lock_htlc(&terms, &payment)),
                Some(HtlcTx::Claim { htlc_id, preimage }) => outcome(self.claim_htlc(&htlc_id, &preimage)),
                Some(HtlcTx::Refund { htlc_id }) => outcome(self.refund_htlc(&htlc_id)),
                None => ExecOutcome::Malformed,
            },
            _ => ExecOutcome::Malformed,
        }
    }

    /// `H(tokens ‖ shielded ‖ names ‖ storage ‖ htlc)` — one commitment over transparent balances, shielded
    /// notes, names, storage deals, and atomic-swap contracts, for the block's executed-state checkpoint.
    fn state_root(&self) -> [u8; 32] {
        let mut buf = [0u8; 160];
        buf[..32].copy_from_slice(&self.tokens.state_root());
        buf[32..64].copy_from_slice(&self.shielded.root());
        buf[64..96].copy_from_slice(&self.names.state_root());
        buf[96..128].copy_from_slice(&self.storage.state_root());
        buf[128..].copy_from_slice(&self.htlcs.state_root());
        hash_labeled(HYBRID_ROOT_LABEL, &buf)
    }

    /// Serialize the entire ledger to a canonical state-sync snapshot ([`fanos_primitives::codec`]): every
    /// sub-ledger, then the block height and audit beacon. Each component is length-framed so decoding is total.
    /// The consensus [`Params`] are a network constant (`Params::standard()`, identical on every node), so they
    /// are reconstructed on [`restore`](Self::restore) rather than transferred.
    fn snapshot(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_var_bytes(&mut out, &self.tokens.to_bytes());
        put_var_bytes(&mut out, &self.shielded.to_bytes());
        put_var_bytes(&mut out, &self.names.to_bytes());
        put_var_bytes(&mut out, &self.storage.to_bytes());
        put_var_bytes(&mut out, &self.htlcs.to_bytes());
        put_u64(&mut out, self.height);
        out.extend_from_slice(&self.audit_beacon);
        out
    }

    /// Reconstruct the ledger from [`snapshot`](Self::snapshot), or `None` if any component is malformed,
    /// truncated, or trailed by garbage. `restore(s.snapshot()).state_root() == s.state_root()` for every `s`.
    fn restore(snapshot: &[u8]) -> Option<Self> {
        let mut r = Reader::new(snapshot);
        let tokens = TokenLedger::from_bytes(r.var_bytes()?)?;
        let shielded = ShieldedState::from_bytes(r.var_bytes()?)?;
        let names = NameRegistry::from_bytes(r.var_bytes()?)?;
        let storage = StorageMarket::from_bytes(r.var_bytes()?)?;
        let htlcs = HtlcBook::from_bytes(r.var_bytes()?)?;
        let height = r.u64()?;
        let audit_beacon = r.array::<32>()?;
        r.finish()?;
        Some(Self {
            tokens,
            shielded,
            names,
            storage,
            htlcs,
            params: Arc::new(Params::standard()),
            height,
            audit_beacon,
        })
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
    use fanos_obolos::{
        Note, Randomness, SpendInput, build_transfer, build_unshield, derive_owner_pk, derive_spend_auth,
        encode_submission, spend_auth_commit,
    };

    /// A test spend-auth seed, deterministically distinct from the nullifier key `nsk`.
    fn spend_seed_of(nsk: &[u8; 32]) -> [u8; 32] {
        let mut s = *nsk;
        s[0] ^= 0xA5;
        s
    }

    /// The spend-auth commitment a note owned by `nsk` records in its `auth`.
    fn auth_of(nsk: &[u8; 32]) -> [u8; 32] {
        spend_auth_commit(&derive_spend_auth(&spend_seed_of(nsk)).1)
    }
    use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};

    fn account(tag: u8) -> (HybridSigSecret, HybridVerifier, [u8; 32]) {
        let mut rng = SeedRng::from_seed(&[0xC0, tag]);
        let (signer, verifier) = HybridSigSecret::generate(&mut rng);
        let id = account_id(&verifier);
        (signer, verifier, id)
    }

    fn note(value: u64, nsk: &[u8; 32], tag: &[u8]) -> Note {
        Note::new(value, derive_owner_pk(nsk), auth_of(nsk), Randomness::from_seed(tag), [tag.len() as u8; 32])
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
        let sp = SpendInput { note: n0, nsk, spend_seed: spend_seed_of(&nsk), path: ledger.shielded().path(pos).unwrap() };
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
    fn the_full_ledger_snapshots_and_restores_reproducing_the_root() {
        // End-to-end state-sync (audit §3.9 / §4 recovery): build state across the sub-ledgers, drive the block
        // context (height + audit beacon), then prove `restore(snapshot())` is bit-for-bit faithful — same state
        // root, height, and per-component state — so a lagging validator can adopt a checkpoint and rejoin.
        let (alice_sk, alice_vk, alice) = account(1);
        let (_bob_sk, _bob_vk, bob) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 1_000_000);
        let mut ledger = HybridLedger::new(tokens);
        ledger.begin_block(7);
        ledger.set_audit_beacon([0x5a; 32]);

        // Transparent transfer Alice → Bob.
        let st = SignedTransfer::sign(Transfer { from: alice, to: bob, amount: 100, nonce: 0 }, &alice_sk, alice_vk.clone());
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::transparent_payload(&st))), ExecOutcome::Applied);
        // Shielded mint + transfer — advances the note tree, creating multiple anchors (the critical path).
        let nsk = [9u8; 32];
        let n0 = note(500, &nsk, b"n0");
        let pos = ledger.mint_shielded(n0.commitment(ledger.params())).unwrap();
        let sp = SpendInput { note: n0, nsk, spend_seed: spend_seed_of(&nsk), path: ledger.shielded().path(pos).unwrap() };
        let (stx, proof) =
            build_transfer(ledger.params(), ledger.shielded().anchor(), &[sp], &[note(500, &[2u8; 32], b"o")], 0);
        let submission = encode_submission(&stx, &proof);
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shielded_payload(&submission))), ExecOutcome::Applied);
        // Name registration paid from Alice's transparent funds.
        let name = b"alice.fanos".to_vec();
        let fee = price(&name, 10);
        let name_tx = NameTx {
            op: NameOp::Register { name: name.clone(), target: b"addr".to_vec(), duration: 10 },
            payment: SignedTransfer::sign(Transfer { from: alice, to: TREASURY, amount: fee, nonce: 1 }, &alice_sk, alice_vk),
        };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::name_payload(&name_tx))), ExecOutcome::Applied);

        // Snapshot → restore, and prove faithfulness.
        let snapshot = ledger.snapshot();
        let restored = HybridLedger::restore(&snapshot).expect("the snapshot restores");
        assert_eq!(restored.state_root(), ledger.state_root(), "the restored ledger reproduces the exact state root");
        assert_eq!(restored.height(), ledger.height(), "and the block height");
        assert_eq!(restored.tokens().balance(&bob), 100, "and transparent balances");
        assert_eq!(restored.names().resolve(&name, 0).unwrap().owner, alice, "and the name registry");
        assert_eq!(restored.shielded().root(), ledger.shielded().root(), "and the shielded pool (with its anchors)");
        // A trailing byte is refused — the decode is total.
        let mut extended = snapshot.clone();
        extended.push(0);
        assert!(HybridLedger::restore(&extended).is_none(), "trailing garbage is refused");
    }

    #[test]
    fn a_shielded_fee_transaction_declares_the_treasury_write() {
        // Audit §3.7: a shielded tx with a fee moves POOL_SINK → TREASURY at runtime, so TREASURY must be in its
        // access list — else the parallel scheduler would run it concurrently with a name tx (also a TREASURY
        // writer), forking the state once TREASURY gains a read/debit.
        let (alice_sk, alice_vk, alice) = account(1);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 1_000_000);
        let mut ledger = HybridLedger::new(tokens);
        // A shielded tx spending a 600 note: 500 out, fee 100 → 600 = 500 + 100 (balance law).
        let nsk = [9u8; 32];
        let n0 = note(600, &nsk, b"n0");
        let pos = ledger.mint_shielded(n0.commitment(ledger.params())).unwrap();
        let sp = SpendInput { note: n0, nsk, spend_seed: spend_seed_of(&nsk), path: ledger.shielded().path(pos).unwrap() };
        let (stx, proof) = build_transfer(ledger.params(), ledger.shielded().anchor(), &[sp], &[note(500, &[2u8; 32], b"o")], 100);
        let shielded_tx = Transaction::new(HybridLedger::shielded_payload(&encode_submission(&stx, &proof)));

        let empty: BTreeMap<[u8; 32], ([u8; 32], [u8; 32])> = BTreeMap::new();
        let shielded_access = ledger.access_of(&shielded_tx, &empty, &empty);
        assert!(shielded_access.writes.contains(&TREASURY), "a shielded-fee tx declares the TREASURY write");

        // A name tx also writes TREASURY, so the scheduler must treat the two as conflicting (never parallel).
        let name_tx = NameTx {
            op: NameOp::Register { name: b"a.fanos".to_vec(), target: b"x".to_vec(), duration: 10 },
            payment: SignedTransfer::sign(
                Transfer { from: alice, to: TREASURY, amount: price(b"a.fanos", 10), nonce: 0 },
                &alice_sk,
                alice_vk,
            ),
        };
        let name_access = ledger.access_of(&Transaction::new(HybridLedger::name_payload(&name_tx)), &empty, &empty);
        assert!(shielded_access.conflicts_with(&name_access), "shielded-fee and name txs both write TREASURY → conflict");
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
        let shield_note = Note::new(500, derive_owner_pk(&nsk), auth_of(&nsk), Randomness::from_seed(b"shield"), [1u8; 32]);
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
        let sp = SpendInput { note: shield_note, nsk, spend_seed: spend_seed_of(&nsk), path };
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
        let shielded_note = Note::new(1000, derive_owner_pk(&nsk), auth_of(&nsk), Randomness::from_seed(b"u"), [1u8; 32]);
        let sx = ShieldTx {
            payment: SignedTransfer::sign(Transfer { from: alice, to: POOL_SINK, amount: 1000, nonce: 0 }, &alice_sk, alice_vk),
            note: shielded_note.clone(),
        };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shield_payload(&sx))), ExecOutcome::Applied);
        assert_eq!(ledger.pool_backing(), 1000);

        // Alice unshields the whole 1000 to Bob's transparent account (spend the note, all value exits public).
        let path = ledger.shielded().path(0).unwrap();
        let sp = SpendInput { note: shielded_note, nsk, spend_seed: spend_seed_of(&nsk), path };
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
        let n = Note::new(500, derive_owner_pk(&[7u8; 32]), auth_of(&[7u8; 32]), Randomness::from_seed(b"s"), [1u8; 32]);
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
        let (provider_sk, provider_vk, provider) = account(2);
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

        // Prove epoch 0 at the first audit boundary (§3.5 cadence: a settlement may land only one AUDIT_PERIOD
        // past the open) — the provider answers the beacon's challenge → paid one slice (price/duration = 100).
        // The proof carries a FRESH per-audit provider authorisation over `deal_id ‖ H(response)` (§3.6).
        ledger.begin_block(AUDIT_PERIOD);
        let indices = challenge(&cid, &beacon, 3, 8);
        let response = encode_response(&prove(&chunk, &indices).unwrap());
        let prover_auth = ProverAuth::sign(&id, &response, &provider_sk, provider_vk.clone());
        let prove_tx = StorageTx::Prove { deal_id: id, prover_auth, response };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&prove_tx))), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&provider), 100, "the provider earned one slice from escrow");
        assert_eq!(ledger.storage_escrow(), 300);

        // AT-C1: replaying the SAME proof at the same height pays nothing more (no escrow drain).
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&prove_tx))), ExecOutcome::Rejected);
        assert_eq!(ledger.tokens().balance(&provider), 100, "a replayed proof does not settle a second time");
        assert_eq!(ledger.storage_escrow(), 300, "the escrow is not drained by proof replay");

        // A garbage response pays nothing — even with a valid provider auth over it, `por::verify` fails.
        let bad_response = vec![0u8; 4];
        let bad_auth = ProverAuth::sign(&id, &bad_response, &provider_sk, provider_vk.clone());
        let bad = StorageTx::Prove { deal_id: id, prover_auth: bad_auth, response: bad_response };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&bad))), ExecOutcome::Rejected);
        assert_eq!(ledger.tokens().balance(&provider), 100, "an unverifiable proof releases nothing");

        // AT-H1/§3.6: a VALID response NOT authorised by the provider is refused — a third party holding a
        // replica of the public leaves cannot forge the provider's per-audit signature to be paid. (Advance past
        // the next audit boundary so only the auth check can reject it, not the per-height cadence guard.)
        ledger.begin_block(2 * AUDIT_PERIOD);
        let real_response = encode_response(&prove(&chunk, &challenge(&cid, &beacon, 3, 8)).unwrap());
        let impostor_auth = ProverAuth::sign(&id, &real_response, &consumer_sk, consumer_vk.clone());
        let impostor = StorageTx::Prove { deal_id: id, prover_auth: impostor_auth, response: real_response };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&impostor))), ExecOutcome::Rejected);
        assert_eq!(ledger.tokens().balance(&provider), 100, "a proof not signed by the provider pays nothing");

        // AT-M4: a close authorisation NOT bound to the deal (to != deal id) is refused — a historical signed
        // transfer from the consumer cannot be replayed to force-close the deal early.
        let unbound = SignedTransfer::sign(
            Transfer { from: consumer, to: STORAGE_ESCROW, amount: 0, nonce: 3 },
            &consumer_sk,
            consumer_vk.clone(),
        );
        let bad_close = StorageTx::Close { deal_id: id, auth: unbound };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&bad_close))), ExecOutcome::Rejected);
        assert_eq!(ledger.storage_escrow(), 300, "an unbound close does not touch the escrow");

        // Close: the consumer reclaims the unproven 300 (an auth signed by the consumer, bound to the deal id).
        let auth = SignedTransfer::sign(
            Transfer { from: consumer, to: id, amount: 0, nonce: 1 },
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
    fn a_storage_open_with_out_of_range_audit_params_is_rejected() {
        use fanos_thesauros::DealParams;
        // Audit §3.3: a deal whose size exceeds one chunk (⇒ an unbounded audit leaf domain) — or a degenerate
        // zero size/duration — is refused at open, so a crafted deal can never reach the prove path and OOM
        // every validator through `por::challenge`.
        let (consumer_sk, consumer_vk, consumer) = account(1);
        let (_p, _pv, provider) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(consumer, 1_000_000);
        let mut ledger = HybridLedger::new(tokens);
        let open = |ledger: &mut HybridLedger, size: u64, duration: u64, nonce: u64| {
            let params = DealParams {
                cid: fanos_thesauros::Cid::new([1u8; 32]),
                size,
                duration,
                replication: 3,
                lambda_bits: 10,
                f_tol_permille: 100,
                k: 3,
                price: 400,
                provider,
                consumer,
            };
            let payment = SignedTransfer::sign(
                Transfer { from: consumer, to: STORAGE_ESCROW, amount: 400, nonce },
                &consumer_sk,
                consumer_vk.clone(),
            );
            ledger.apply(&Transaction::new(HybridLedger::storage_payload(&StorageTx::Open { params, payment })))
        };
        let max = MAX_DEAL_SIZE;
        // A full-chunk in-range deal opens (the one applied tx uses nonce 0); the rejected variants below never
        // reach the payment (they fail the param bound first), so they consume no nonce.
        assert_eq!(open(&mut ledger, max, 4, 0), ExecOutcome::Applied, "a full-chunk in-range deal is accepted");
        assert_eq!(open(&mut ledger, max + 1, 4, 1), ExecOutcome::Rejected, "one byte past a chunk is refused");
        assert_eq!(open(&mut ledger, 0, 4, 2), ExecOutcome::Rejected, "a zero-size deal is refused");
        assert_eq!(open(&mut ledger, max, 0, 3), ExecOutcome::Rejected, "a zero-duration deal is refused");
    }

    #[test]
    fn zero_value_market_txs_are_refused_and_terminal_deals_are_pruned() {
        use fanos_thesauros::{Cid, DealParams};
        // Audit §3.4: a zero-price deal costs a funds-less attacker only a signature yet would insert a permanent
        // entry — it is refused, leaving no entry. A terminal (Closed) deal is pruned at the next block, so the
        // deals map cannot grow without bound.
        let (consumer_sk, consumer_vk, consumer) = account(1);
        let (_p, _pv, provider) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(consumer, 1_000_000);
        let mut ledger = HybridLedger::new(tokens);
        let deal = |price: u64| DealParams {
            cid: Cid::new([7u8; 32]),
            size: 4096,
            duration: 2,
            replication: 1,
            lambda_bits: 10,
            f_tol_permille: 100,
            k: 1,
            price,
            provider,
            consumer,
        };
        let open = |ledger: &mut HybridLedger, price: u64, nonce: u64| {
            let payment = SignedTransfer::sign(
                Transfer { from: consumer, to: STORAGE_ESCROW, amount: price, nonce },
                &consumer_sk,
                consumer_vk.clone(),
            );
            ledger.apply(&Transaction::new(HybridLedger::storage_payload(&StorageTx::Open { params: deal(price), payment })))
        };
        // A zero-price deal is refused before the token move, so no free entry is inserted.
        assert_eq!(open(&mut ledger, 0, 0), ExecOutcome::Rejected, "a zero-price deal is refused");
        assert_eq!(ledger.storage.deals.len(), 0, "a refused free deal leaves no entry");
        // A funded deal opens (one entry); the consumer then closes it early (→ Closed).
        assert_eq!(open(&mut ledger, 400, 0), ExecOutcome::Applied);
        assert_eq!(ledger.storage.deals.len(), 1);
        let id = deal_id(&deal(400), 0);
        let close_auth = SignedTransfer::sign(
            Transfer { from: consumer, to: id, amount: 0, nonce: 1 },
            &consumer_sk,
            consumer_vk.clone(),
        );
        assert_eq!(
            ledger.apply(&Transaction::new(HybridLedger::storage_payload(&StorageTx::Close { deal_id: id, auth: close_auth }))),
            ExecOutcome::Applied
        );
        // The next block prunes the now-terminal deal, so the map returns to empty.
        ledger.begin_block(1);
        assert_eq!(ledger.storage.deals.len(), 0, "a terminal deal is pruned from the map");
    }

    #[test]
    fn an_htlc_pays_the_recipient_on_reveal_and_a_second_claim_does_nothing() {
        use fanos_hermes::hashlock;

        let (alice_sk, alice_vk, alice) = account(1);
        let (_b, _bv, bob) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 10_000);
        let mut ledger = HybridLedger::new(tokens);
        ledger.begin_block(50); // current height 50, before the timeout

        let secret = [0x5E; 32];
        let terms = HtlcTerms { sender: alice, recipient: bob, amount: 1000, hashlock: hashlock(&secret), timeout: 100 };
        let id = htlc_id(&terms, 0);

        // Lock 1000 behind the hashlock.
        let payment = SignedTransfer::sign(Transfer { from: alice, to: HTLC_ESCROW, amount: 1000, nonce: 0 }, &alice_sk, alice_vk);
        let lock = HtlcTx::Lock { terms, payment: Box::new(payment) };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::htlc_payload(&lock))), ExecOutcome::Applied);
        assert_eq!(ledger.htlc_escrow(), 1000, "the amount is escrowed");
        assert_eq!(ledger.tokens().balance(&alice), 9_000);

        // A wrong preimage does not release the funds.
        let bad = HtlcTx::Claim { htlc_id: id, preimage: [0; 32] };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::htlc_payload(&bad))), ExecOutcome::Rejected);
        assert_eq!(ledger.tokens().balance(&bob), 0);

        // The correct preimage before the timeout pays the recipient.
        let claim = HtlcTx::Claim { htlc_id: id, preimage: secret };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::htlc_payload(&claim))), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&bob), 1000, "the recipient was paid on reveal");
        assert_eq!(ledger.htlc_escrow(), 0);
        // A second claim (or a refund) is a no-op — the contract is resolved.
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::htlc_payload(&claim))), ExecOutcome::Rejected);
    }

    #[test]
    fn an_htlc_refunds_the_sender_after_the_timeout() {
        use fanos_hermes::hashlock;

        let (alice_sk, alice_vk, alice) = account(1);
        let (_b, _bv, bob) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 10_000);
        let mut ledger = HybridLedger::new(tokens);
        ledger.begin_block(50);

        let terms = HtlcTerms { sender: alice, recipient: bob, amount: 1000, hashlock: hashlock(&[0x11; 32]), timeout: 100 };
        let id = htlc_id(&terms, 0);
        let payment = SignedTransfer::sign(Transfer { from: alice, to: HTLC_ESCROW, amount: 1000, nonce: 0 }, &alice_sk, alice_vk);
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::htlc_payload(&HtlcTx::Lock { terms, payment: Box::new(payment) }))), ExecOutcome::Applied);

        // Before the timeout there is no refund.
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::htlc_payload(&HtlcTx::Refund { htlc_id: id }))), ExecOutcome::Rejected);
        assert_eq!(ledger.htlc_escrow(), 1000);

        // Advance past the timeout: the sender may refund.
        ledger.begin_block(100);
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::htlc_payload(&HtlcTx::Refund { htlc_id: id }))), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&alice), 10_000, "the sender recovered the locked funds");
        assert_eq!(ledger.htlc_escrow(), 0);
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
    fn a_stalled_storage_deal_auto_refunds_at_the_audit_deadline() {
        use crate::storage::AUDIT_PERIOD;
        use fanos_thesauros::{Cid, DealParams};
        // Audit AT-H2: a provider that never proves must not leave the deal Active forever; at the audit
        // deadline begin_block auto-completes the deal and refunds the consumer, with no manual close.
        let (consumer_sk, consumer_vk, consumer) = account(1);
        let (_p, _pv, provider) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(consumer, 1_000_000);
        let mut ledger = HybridLedger::new(tokens);
        ledger.begin_block(10); // the deal opens at height 10
        let params = DealParams {
            cid: Cid::new([1u8; 32]),
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
        let payment = SignedTransfer::sign(
            Transfer { from: consumer, to: STORAGE_ESCROW, amount: 400, nonce: 0 },
            &consumer_sk,
            consumer_vk,
        );
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::storage_payload(&StorageTx::Open { params, payment }))), ExecOutcome::Applied);
        assert_eq!(ledger.storage_escrow(), 400);

        // The provider never proves. The deadline is open_height(10) + duration(4)·AUDIT_PERIOD.
        let deadline = 10 + 4 * AUDIT_PERIOD;
        ledger.begin_block(deadline - 1);
        assert_eq!(ledger.storage_escrow(), 400, "not yet lapsed");
        assert_eq!(ledger.tokens().balance(&consumer), 999_600);
        // At the deadline the deal auto-completes and the full unproven escrow refunds to the consumer.
        ledger.begin_block(deadline);
        assert_eq!(ledger.storage_escrow(), 0, "the lapsed deal's escrow left the sink");
        assert_eq!(ledger.tokens().balance(&consumer), 1_000_000, "the consumer got the full unproven escrow back");
    }

    #[test]
    fn a_shielded_fee_is_collected_to_the_treasury_and_the_pool_invariant_holds() {
        // Audit O-H1: the fee is clear value leaving the pool; it must be debited from the pool sink (else the
        // POOL_SINK == Σ unspent-notes invariant drifts) and credited to the treasury (else no one is paid).
        let (alice_sk, alice_vk, alice) = account(1);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 10_000);
        let mut ledger = HybridLedger::new(tokens);

        // Alice shields 1000.
        let nsk = [7u8; 32];
        let shield_note = Note::new(1000, derive_owner_pk(&nsk), auth_of(&nsk), Randomness::from_seed(b"o"), [1u8; 32]);
        let sx = ShieldTx {
            payment: SignedTransfer::sign(Transfer { from: alice, to: POOL_SINK, amount: 1000, nonce: 0 }, &alice_sk, alice_vk),
            note: shield_note.clone(),
        };
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shield_payload(&sx))), ExecOutcome::Applied);
        assert_eq!(ledger.pool_backing(), 1000);

        // A shielded transfer paying a fee of 100: 1000 = 900 (shielded output) + 100 (fee).
        let path = ledger.shielded().path(0).unwrap();
        let sp = SpendInput { note: shield_note, nsk, spend_seed: spend_seed_of(&nsk), path };
        let (stx, proof) = build_transfer(ledger.params(), ledger.shielded().anchor(), &[sp], &[note(900, &[2u8; 32], b"out")], 100);
        assert_eq!(ledger.apply(&Transaction::new(HybridLedger::shielded_payload(&encode_submission(&stx, &proof)))), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&TREASURY), 100, "the shielded fee is collected to the treasury");
        assert_eq!(ledger.pool_backing(), 900, "the pool sink backs exactly the unspent shielded value (invariant holds)");
    }

    #[test]
    fn an_unknown_tag_or_empty_payload_is_malformed() {
        let mut ledger = HybridLedger::new(TokenLedger::new());
        assert_eq!(ledger.apply(&Transaction::new(Vec::new())), ExecOutcome::Malformed);
        assert_eq!(ledger.apply(&Transaction::new(vec![0x7F, 1, 2, 3])), ExecOutcome::Malformed);
        assert_eq!(ledger.apply(&Transaction::new(vec![TAG_NAME, 0xFF])), ExecOutcome::Malformed);
    }

    /// A signing account: `(secret, verifier, id)`.
    type Account = (HybridSigSecret, HybridVerifier, [u8; 32]);

    /// A deterministic splitmix64 PRNG (reproducible, no wall-clock entropy) for building random blocks.
    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A fresh ledger with each account credited generously, so no transfer ever overspends and the block's
    /// accept/reject set is decided purely by the committed order, never by balance exhaustion.
    fn ledger_with(accounts: &[Account]) -> HybridLedger {
        let mut tokens = TokenLedger::new();
        for (_, _, id) in accounts {
            tokens.credit(*id, 1_000_000);
        }
        HybridLedger::new(tokens)
    }

    /// A random block of valid transfers over a small account pool (small ⇒ heavy conflict), each carrying its
    /// sender's correct running nonce, so every transfer is individually valid and the block genuinely mixes
    /// conflicting (same-account) and independent (disjoint-account) work — the adversarial input the parallel
    /// scheduler must execute identically to serial.
    fn random_conflicting_block(
        seed: u64,
    ) -> (Vec<Account>, Vec<Transaction>) {
        let mut st = seed.wrapping_add(1);
        let n_acct = 3 + (splitmix(&mut st) % 4) as usize; // 3..=6 accounts — a small pool forces conflicts
        let accounts: Vec<_> = (0..n_acct).map(|i| account(i as u8 + 1)).collect();
        let mut nonces = vec![0u64; n_acct];
        let n_tx = 6 + (splitmix(&mut st) % 9) as usize; // 6..=14 transfers
        let mut txs = Vec::with_capacity(n_tx);
        for _ in 0..n_tx {
            let from = (splitmix(&mut st) % n_acct as u64) as usize;
            let to = {
                let t = (splitmix(&mut st) % n_acct as u64) as usize;
                if t == from { (t + 1) % n_acct } else { t }
            };
            let amount = 1 + splitmix(&mut st) % 50;
            let (sk, vk, from_id) = &accounts[from];
            let transfer = Transfer { from: *from_id, to: accounts[to].2, amount, nonce: nonces[from] };
            nonces[from] += 1;
            let signed = SignedTransfer::sign(transfer, sk, vk.clone());
            txs.push(Transaction::new(HybridLedger::transparent_payload(&signed)));
        }
        (accounts, txs)
    }

    #[test]
    fn parallel_block_execution_equals_serial_over_random_conflicting_blocks() {
        // DROMOS's load-bearing claim (spec/platform.md §3.1, the high-speed L1): the parallel scheduler's
        // resulting state is byte-identical to serial execution of the committed order, and deterministic —
        // for ANY block, however adversarially its transactions conflict. Verified against the REAL ledger
        // over 200 random conflicting blocks (the scheduler's own tests use a MockTx; this drives real
        // signed transfers end to end).
        for seed in 0..24u64 {
            let (accounts, txs) = random_conflicting_block(seed);

            let mut par = ledger_with(&accounts);
            let par_outcomes = par.execute_block(&txs);
            let root_parallel = par.state_root();

            let mut ser = ledger_with(&accounts);
            let ser_outcomes: Vec<_> = txs.iter().map(|tx| ser.apply(tx)).collect();
            let root_serial = ser.state_root();

            assert_eq!(root_parallel, root_serial, "parallel state == serial state at seed {seed}");
            assert_eq!(par_outcomes, ser_outcomes, "parallel per-tx outcomes == serial at seed {seed}");

            // Determinism: an independent re-execution of the same block reaches the identical state.
            let mut again = ledger_with(&accounts);
            let _ = again.execute_block(&txs);
            assert_eq!(again.state_root(), root_parallel, "execute_block is deterministic at seed {seed}");
        }
    }

    #[test]
    fn the_scheduler_faithfully_respects_the_committed_order() {
        // The scheduler must never silently reorder CONFLICTING transactions: for a permuted committed order,
        // parallel execution still equals serial execution of THAT order — and reordering conflicting
        // transactions generally reaches a different state (order-sensitivity is real, and the scheduler
        // honours it rather than smearing it away).
        let mut diverged = 0u32;
        for seed in 0..24u64 {
            let (accounts, txs) = random_conflicting_block(seed);
            if txs.len() < 2 {
                continue;
            }
            // A reversed committed order — a strong adversarial permutation. Repeat senders' nonces are now
            // out of order, so some transfers reject, but parallel MUST still match serial on this order.
            let mut permuted = txs.clone();
            permuted.reverse();

            let mut par = ledger_with(&accounts);
            let _ = par.execute_block(&permuted);
            let mut ser = ledger_with(&accounts);
            for tx in &permuted {
                ser.apply(tx);
            }
            assert_eq!(par.state_root(), ser.state_root(), "parallel == serial on the permuted order (seed {seed})");

            let root_original = {
                let mut l = ledger_with(&accounts);
                let _ = l.execute_block(&txs);
                l.state_root()
            };
            if root_original != par.state_root() {
                diverged += 1;
            }
        }
        assert!(diverged > 0, "reordering conflicting transactions changes the state — order is real (diverged on {diverged})");
    }

    #[test]
    fn conflicting_shielded_spends_in_a_block_admit_exactly_one() {
        // OBOLOS money-safety under DROMOS's parallel execution (audit S-P0.5, the L10 crown jewel): two spends
        // of the SAME note reveal the same nullifier. They CONFLICT (both mutate the shared shielded pool), so
        // the scheduler MUST serialize them — exactly one is admitted, the other rejected as a double-spend —
        // whichever validator's block wins the merge. Were the scheduler to wrongly parallelize them, both
        // could apply and mint value from nothing; this proves it does not, in either committed order.
        fn minted() -> (HybridLedger, SpendInput) {
            let mut ledger = HybridLedger::new(TokenLedger::new());
            let nsk = [9u8; 32];
            let n0 = note(500, &nsk, b"dbl");
            let pos = ledger.mint_shielded(n0.commitment(ledger.params())).unwrap();
            let sp = SpendInput { note: n0, nsk, spend_seed: spend_seed_of(&nsk), path: ledger.shielded().path(pos).unwrap() };
            (ledger, sp)
        }
        fn spend(ledger: &HybridLedger, sp: &SpendInput, out_tag: &[u8], out_nsk: &[u8; 32]) -> Transaction {
            let (stx, proof) = build_transfer(
                ledger.params(),
                ledger.shielded().anchor(),
                std::slice::from_ref(sp),
                &[note(500, out_nsk, out_tag)],
                0,
            );
            Transaction::new(HybridLedger::shielded_payload(&encode_submission(&stx, &proof)))
        }

        // Both orders a merge could pick — the two partitioned validators' conflicting spends.
        for first_is_a in [true, false] {
            let (base, sp) = minted();
            let tx_a = spend(&base, &sp, b"outA", &[1u8; 32]);
            let tx_b = spend(&base, &sp, b"outB", &[2u8; 32]);
            let block = if first_is_a { vec![tx_a, tx_b] } else { vec![tx_b, tx_a] };

            let mut ledger = base.clone(); // the minted note, before either spend
            let outcomes = ledger.execute_block(&block);
            assert_eq!(
                outcomes.iter().filter(|o| **o == ExecOutcome::Applied).count(),
                1,
                "exactly one conflicting spend is admitted (first_is_a = {first_is_a})"
            );
            assert_eq!(
                outcomes.iter().filter(|o| **o == ExecOutcome::Rejected).count(),
                1,
                "the other is rejected as a double-spend (first_is_a = {first_is_a})"
            );
            // The winner is the first in the committed (merged) order — the consensus decision, applied
            // deterministically by the scheduler's conflict serialization.
            assert_eq!(outcomes[0], ExecOutcome::Applied, "the first-committed spend wins");
            assert_eq!(outcomes[1], ExecOutcome::Rejected);
        }
    }
}
