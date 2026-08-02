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
use fanos_pqcrypto::HybridVerifier;
use fanos_primitives::codec::{Reader, put_u64, put_var_bytes};
use fanos_primitives::hash_labeled;
use fanos_taxis::state::{ExecOutcome, StateMachine};
use fanos_taxis::tx::Transaction;

use fanos_hermes::{Htlc, HtlcState, HtlcTerms, Resolution};
use fanos_thesauros::{Deal, DealParams, DealState, Settlement, decode_response, verify};

use crate::bridge::{POOL_SINK, ShieldTx};
use fanos_ergon::Limits;

use crate::ergon_host::{
    LedgerHost, LedgerState, SignedTerm, balance_key, htlc_key, name_key, shielded_key, storage_key,
};
use crate::hermes::{HTLC_ESCROW, HtlcBook, HtlcTx, htlc_id};
use crate::naming::{NameError, NameRegistry, NameTx, TREASURY};
use crate::scheduler::{AccessList, schedule};
use crate::stake::{STAKE_SINK, SlashTx, StakeLedger, StakeTx, slot_key};
use crate::storage::{
    AUDIT_PERIOD, MAX_DEAL_DURATION, MAX_DEAL_SIZE, STORAGE_ESCROW, StorageMarket, StorageTx, deal_id,
    leaves_for_size,
};
use crate::token::{TokenError, ProverAuth, SignedTransfer, TokenLedger, account_id};

/// The shared state key every shielded operation touches — so shielded spends serialize against each other
/// (they mutate the one nullifier set / commitment tree) while parallelizing against disjoint transparent work.
const SHIELDED_MARKER: [u8; 32] = *b"FANOS-dromos-shielded-pool-mark!";

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
/// Transaction-type tag: a validator staking operation (bond/unbond).
pub const TAG_STAKE: u8 = 0x06;
/// Transaction-type tag: a validator slashing proof (equivocation evidence).
pub const TAG_SLASH: u8 = 0x07;

/// Transaction-type tag: an **ERGON term** — a composition over the primitive effects, submitted as a transaction.
///
/// The tag that makes user programmability reachable from the wire rather than from a test. Everything the term does is
/// checked by the chain independently of whoever produced it: the envelope's signature authenticates the caller, the
/// canonical codec refuses a non-canonical encoding, `well_typed` refuses an ill-typed term, `Term::footprint` derives the
/// access list, and the evaluator confines execution to it.
pub const TAG_ERGON: u8 = 0x08;

/// Domain-separation label for the hybrid state root.
const HYBRID_ROOT_LABEL: &str = "FANOS-dromos-v1/hybrid-root";

/// The DROMOS hybrid ledger: an authenticated token ledger, a shielded pool, and a name registry under one
/// `state_root`, with a block-height clock for the registry's expiries.
#[derive(Clone, Debug)]
pub struct HybridLedger {
    /// Waves in the last block's conflict schedule, or `0` if no block has run through the parallel executor.
    ///
    /// A **local metric, never consensus state**: it is not hashed into `state_root` and not carried in `snapshot`, so two
    /// validators that schedule identically-rooted state with different core counts still agree. It exists because
    /// "vertical parallelism" is a throughput claim and a claim needs a number: one wave means the whole block committed
    /// with no serialization, `n` waves means the block was `n` dependent steps deep. It is also the only way to observe
    /// that the parallel executor ran at all — the schedule is serial-equivalent by construction, so no *outcome* can
    /// distinguish it from the serial default, and it was reachable from nothing but its own tests for exactly that reason.
    waves_last_block: usize,
    tokens: TokenLedger,
    shielded: ShieldedState,
    names: NameRegistry,
    storage: StorageMarket,
    htlcs: HtlcBook,
    stake: StakeLedger,
    params: Arc<Params>,
    height: u64,
    audit_beacon: [u8; 32],
}

impl HybridLedger {
    /// A hybrid ledger over a funded genesis token ledger, an empty shielded pool, and an empty name registry.
    #[must_use]
    pub fn new(genesis_tokens: TokenLedger) -> Self {
        Self {
            waves_last_block: 0,
            tokens: genesis_tokens,
            shielded: ShieldedState::new(),
            names: NameRegistry::new(),
            storage: StorageMarket::default(),
            htlcs: HtlcBook::default(),
            stake: StakeLedger::new(),
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

    /// The validator stake sub-state (read-only) — bonded collateral and slashed-fault records.
    #[must_use]
    pub fn stake(&self) -> &StakeLedger {
        &self.stake
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
    /// `None` ⇒ premature (the funding nonce is ahead); `Some(ok)` ⇒ applied or terminally rejected.
    fn lock_htlc(&mut self, terms: &HtlcTerms, payment: &SignedTransfer) -> Option<bool> {
        // A non-zero escrow floor (audit §3.4): an `amount == 0` lock passes the token check (`balance < 0` is
        // false) for only a signature, yet inserts a permanent `htlcs` entry. Requiring a real locked amount
        // makes growing the book cost the attacker locked capital.
        if terms.amount == 0
            || !payment.verify()
            || payment.transfer.from != terms.sender
            || payment.transfer.to != HTLC_ESCROW
            || payment.transfer.amount != terms.amount
        {
            return Some(false);
        }
        let id = htlc_id(terms, payment.transfer.nonce);
        if self.htlcs.htlcs.contains_key(&id) {
            return Some(false);
        }
        // Premature funding, checked only after the contract's own terms: a sound lock whose transfer is
        // merely early is deferred, while a malformed one stays terminally rejected.
        if self.tokens.is_premature(payment) {
            return None;
        }
        if self.tokens.apply(payment).is_err() {
            return Some(false);
        }
        self.htlcs.htlcs.insert(id, Htlc::new(*terms));
        Some(true)
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

    /// Mutable access to the transparent sub-ledger, for the ERGON state adapter (`crate::ergon_host`).
    ///
    /// Crate-private for the same reason `TokenLedger::set_balance` is: the public surface is the one that preserves
    /// invariants. The adapter may hold this because ERGON confines every write to a footprint the term derives, so the
    /// invariant is split rather than dropped — the host rule checks the ledger's conditions, the evaluator checks the key
    /// was permitted.
    pub(crate) fn tokens_mut(&mut self) -> &mut TokenLedger { &mut self.tokens }

    /// The name registry, mutably — for the ERGON state adapter, which routes `SPACE_NAME` writes here.
    pub(crate) fn names_mut(&mut self) -> &mut NameRegistry { &mut self.names }

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
    /// `None` ⇒ premature (the funding nonce is ahead); `Some(ok)` ⇒ applied or terminally rejected.
    fn shield(&mut self, sx: &ShieldTx) -> Option<bool> {
        if sx.payment.transfer.to != POOL_SINK || sx.payment.transfer.amount != sx.note.value {
            return Some(false);
        }
        // Capacity guard so the (atomic) payment is never applied without the mint following.
        if self.shielded.note_count() >= (1u64 << fanos_obolos::TREE_DEPTH) {
            return Some(false);
        }
        // Premature funding: the shield's own content is already checked, so this transfer is sound but not
        // yet applicable — defer rather than lose it (`ExecOutcome::Deferred`).
        if self.tokens.is_premature(&sx.payment) {
            return None;
        }
        if self.tokens.apply(&sx.payment).is_err() {
            return Some(false);
        }
        Some(self.shielded.mint(sx.note.commitment(&self.params)).is_some())
    }

    /// Apply a shielded submission, handling an **unshield**: after the shielded spend verifies and applies, any
    /// `public_value` exiting the pool is moved from the pool sink to the `public_recipient` on the token ledger
    /// (authorised by the shielded proof, which enforced `Σ inputs = Σ shielded outputs + fee + public_value`).
    /// Atomic: the pool must back the exit before anything mutates, and the shielded spend leaves token balances
    /// untouched, so the transparent move always completes.
    fn apply_shielded(&mut self, stx: &ShieldedTx, proof_ok: bool) -> bool {
        // Both the public output and the fee are clear value LEAVING the shielded pool (the balance law is
        // Σ inputs = Σ shielded outputs + fee + public_value), so the pool sink must back their sum.
        let leaving = stx.public_value.saturating_add(stx.fee);
        if leaving > 0 && self.pool_backing() < leaving {
            return false;
        }
        // The proof verdict (`proof_ok`) was computed by the caller — inline for a single transaction, or in the
        // parallel pre-pass for a block. The commit itself reads only shielded state (anchors, nullifiers, tree).
        if self.shielded.apply_with_verdict(stx, proof_ok).is_err() {
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

    /// Apply a validator staking operation. **Bond**: settle the signer's authorised transfer to [`STAKE_SINK`]
    /// (its signature, nonce, and balance are all checked by the token ledger), then record the bonded amount —
    /// so `STAKE_SINK`'s balance stays exactly equal to the total bonded stake. **Unbond**: verify the signer's
    /// authorisation, require they have that much bonded, then release it from `STAKE_SINK` back to their
    /// balance. `false` (rejected, no state change) on a bad signature, wrong nonce, insufficient balance or
    /// stake, or a transfer not directed at `STAKE_SINK`.
    fn apply_stake(&mut self, tx: &StakeTx) -> bool {
        let st = tx.transfer();
        if st.transfer.to != STAKE_SINK {
            return false; // a staking op must be authorised specifically to the stake sink
        }
        match tx {
            StakeTx::Bond(_) => {
                // The transfer debits the signer and credits STAKE_SINK, with signature, nonce, and balance all
                // checked; on success the same amount is recorded as bonded (STAKE_SINK now backs it 1:1).
                if self.tokens.apply(st).is_ok() {
                    self.stake.increase(st.transfer.from, st.transfer.amount);
                    true
                } else {
                    false
                }
            }
            StakeTx::Unbond(_) => {
                // Unbond releases funds back to the signer, so it cannot reuse the transfer's from→to debit; the
                // authorisation and available stake are checked explicitly, then STAKE_SINK → signer is moved.
                if !st.verify() || self.stake.bonded(&st.transfer.from) < st.transfer.amount {
                    return false;
                }
                if !self.tokens.consume_nonce(&st.transfer.from, st.transfer.nonce) {
                    return false; // stale / replayed nonce
                }
                let ok = self.stake.decrease(&st.transfer.from, st.transfer.amount);
                debug_assert!(ok, "bonded ≥ amount was checked immediately above");
                let _ = self.tokens.move_system(&STAKE_SINK, st.transfer.from, st.transfer.amount);
                true
            }
        }
    }

    /// Apply a slashing proof: re-verify the equivocation, then debit the equivocator's **entire** bonded stake
    /// to the treasury. The slashed account is `account_id(verifier)` — the account it bonds from — recovered
    /// from the proof itself, so no validator registry is consulted. Idempotent per fault: the equivocation slot
    /// is recorded, so resubmitting the proof (or a second proof of the same slot) is rejected and cannot drain
    /// freshly re-bonded stake. `false` (rejected) if the proof is not a genuine equivocation, or is a duplicate.
    fn apply_slash(&mut self, tx: &SlashTx) -> bool {
        let Some(ev) = tx.evidence() else {
            return false; // not a genuine, validly-signed equivocation ⇒ not slashable
        };
        let account = account_id(&tx.verifier);
        let slot = slot_key(&account, &ev);
        if !self.stake.record_slashed(slot) {
            return false; // this fault was already punished ⇒ a duplicate, no further effect
        }
        let amount = self.stake.bonded(&account);
        if amount > 0 {
            let _ = self.stake.decrease(&account, amount);
            let _ = self.tokens.move_system(&STAKE_SINK, TREASURY, amount);
        }
        true
    }

    /// Open a storage deal: the consumer's `payment` must fund the escrow sink with exactly the price. Validates
    /// the transfer binds the consumer and targets the sink, opens the deal (a fresh id), then settles the
    /// payment — so a rejected open never moves money (the naming registry's validate→settle ordering).
    /// `None` ⇒ premature (the funding nonce is ahead); `Some(ok)` ⇒ applied or terminally rejected.
    fn open_deal(&mut self, params: &DealParams, payment: &SignedTransfer) -> Option<bool> {
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
            return Some(false);
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
            return Some(false);
        }
        let id = deal_id(params, payment.transfer.nonce);
        if self.storage.deals.contains_key(&id) {
            return Some(false);
        }
        // Anchor the audit deadline at the current height so the deal can auto-complete + refund if the provider
        // stops proving (audit AT-H2), rather than sitting Active forever awaiting a manual close.
        let Some(deal) = Deal::open_at(*params, self.height) else {
            return Some(false);
        };
        // Premature funding, checked only after the deal's own bounds: see `lock_htlc`.
        if self.tokens.is_premature(payment) {
            return None;
        }
        if self.tokens.apply(payment).is_err() {
            return Some(false);
        }
        self.storage.deals.insert(id, deal);
        Some(true)
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
        // The conflict-free schedule (spec §3): each wave's transactions touch disjoint state, so they are safe
        // to commit in any order. The expensive, stateless half of validation — hybrid PQ signatures and shielded
        // zero-knowledge proofs — is verified in parallel up front (`verify_batch`), reading no ledger state;
        // then each transaction is committed in schedule order using its pre-computed verdict. Because every
        // verdict is a pure function of its transaction, the result is independent of how the verification is
        // split across cores — a validator with more cores computes the *same* block, so consensus is preserved.
        let access = self.access_lists(txs);
        let waves = schedule(&access);
        self.waves_last_block = waves.len();
        let verdicts = self.verify_batch(txs);
        let mut outcomes = vec![ExecOutcome::Malformed; txs.len()];
        for wave in &waves {
            for &i in wave {
                if let (Some(tx), Some(slot)) = (txs.get(i), outcomes.get_mut(i)) {
                    *slot = self.apply_with_verdict(tx, verdicts.get(i).copied().flatten());
                }
            }
        }
        outcomes
    }

    /// Waves in the last block's conflict schedule — see [`HybridLedger::waves_last_block`]. `0` before any block.
    #[must_use]
    pub fn waves_last_block(&self) -> usize {
        self.waves_last_block
    }

    /// Verify every parallelizable transaction's signature or proof **concurrently** — the stateless, expensive
    /// half of execution, which reads no ledger state and so runs across all cores before the serial commit.
    /// Returns a verdict per transaction: `Some(valid)` for a transparent or shielded transfer checked here,
    /// `None` for every other transaction (committed with an inline check, and for a malformed body that the
    /// commit will reject anyway). Deterministic: each verdict is a pure function of its transaction, so the
    /// output does not depend on the thread count or scheduling.
    #[must_use]
    fn verify_batch(&self, txs: &[Transaction]) -> Vec<Option<bool>> {
        let jobs: Vec<(usize, StatelessJob)> =
            txs.iter().enumerate().filter_map(|(i, tx)| stateless_job(tx).map(|j| (i, j))).collect();
        let mut verdicts = vec![None; txs.len()];
        if jobs.is_empty() {
            return verdicts;
        }
        for (i, ok) in par_verify(&jobs, &self.params) {
            if let Some(slot) = verdicts.get_mut(i) {
                *slot = Some(ok);
            }
        }
        verdicts
    }

    /// Execute one committed transaction, dispatching on its type tag. When a pre-computed stateless `verdict`
    /// (its signature or proof result from [`verify_batch`](Self::verify_batch)) is supplied it is used; when
    /// `None` — the single-transaction path — the check runs inline. Outcomes are identical either way: an
    /// unknown tag or malformed body is [`ExecOutcome::Malformed`]; a well-formed-but-invalid transaction is
    /// [`ExecOutcome::Rejected`]; success is [`ExecOutcome::Applied`].
    fn apply_with_verdict(&mut self, tx: &Transaction, verdict: Option<bool>) -> ExecOutcome {
        match tx.payload.split_first() {
            Some((&TAG_TRANSPARENT, body)) => match SignedTransfer::from_bytes(body) {
                Some(st) => {
                    let ok = verdict.unwrap_or_else(|| st.verify());
                    match self.tokens.apply_with_verdict(&st, ok) {
                        Ok(()) => ExecOutcome::Applied,
                        // Premature, not invalid: the engine returns it to the mempool for a later block.
                        Err(TokenError::NonceAhead) => ExecOutcome::Deferred,
                        Err(_) => ExecOutcome::Rejected,
                    }
                }
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_ERGON, body)) => self.apply_term(body, verdict),
            Some((&TAG_SHIELDED, body)) => match decode_submission(body) {
                Some((shielded_tx, proof)) => {
                    let ok =
                        verdict.unwrap_or_else(|| ShieldedState::verify_proof(&self.params, &shielded_tx, &proof));
                    outcome(self.apply_shielded(&shielded_tx, ok))
                }
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_NAME, body)) => match NameTx::from_bytes(body) {
                Some(name_tx) => match self.names.apply(&name_tx, &mut self.tokens, self.height) {
                    Ok(()) => ExecOutcome::Applied,
                    // The registry validates the operation *before* settling its payment, so a premature nonce
                    // here means the operation itself was sound: defer it rather than lose it.
                    Err(NameError::Payment(TokenError::NonceAhead)) => ExecOutcome::Deferred,
                    Err(_) => ExecOutcome::Rejected,
                },
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_SHIELD, body)) => match ShieldTx::from_bytes(body) {
                Some(sx) => self.shield(&sx).map_or(ExecOutcome::Deferred, outcome),
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_STORAGE, body)) => match StorageTx::from_bytes(body) {
                Some(StorageTx::Open { params, payment }) => {
                    self.open_deal(&params, &payment).map_or(ExecOutcome::Deferred, outcome)
                }
                // Same premature-versus-invalid distinction as the HTLC arms below: blind ordering can put a
                // proof or a close ahead of the `Open` that creates the deal, and a deal this ledger has never
                // held may simply not have been opened *yet*.
                Some(StorageTx::Prove { deal_id, prover_auth, response }) => {
                    if self.storage.deals.contains_key(&deal_id) {
                        outcome(self.prove_deal(&deal_id, &prover_auth, &response))
                    } else {
                        ExecOutcome::Deferred
                    }
                }
                Some(StorageTx::Close { deal_id, auth }) => {
                    if self.storage.deals.contains_key(&deal_id) {
                        outcome(self.close_deal(&deal_id, &auth))
                    } else {
                        ExecOutcome::Deferred
                    }
                }
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_HTLC, body)) => match HtlcTx::from_bytes(body) {
                Some(HtlcTx::Lock { terms, payment }) => {
                    self.lock_htlc(&terms, &payment).map_or(ExecOutcome::Deferred, outcome)
                }
                // A contract this ledger has never held is *premature*, not invalid: blind anti-MEV ordering
                // routinely puts a claim ahead of the lock that funds it — measured as `[Rejected, Applied]`
                // for `[claim, lock]` in one block, with the recipient paid nothing and the escrow stranded
                // until the timeout. Deferring re-queues it for a later block; a contract that is present but
                // unclaimable (wrong preimage, already resolved, past its timeout) stays a terminal rejection.
                Some(HtlcTx::Claim { htlc_id, preimage }) => {
                    if self.htlcs.state(&htlc_id).is_none() {
                        ExecOutcome::Deferred
                    } else {
                        outcome(self.claim_htlc(&htlc_id, &preimage))
                    }
                }
                Some(HtlcTx::Refund { htlc_id }) => {
                    if self.htlcs.state(&htlc_id).is_none() {
                        ExecOutcome::Deferred
                    } else {
                        outcome(self.refund_htlc(&htlc_id))
                    }
                }
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_STAKE, body)) => match StakeTx::from_bytes(body) {
                Some(stake_tx) => outcome(self.apply_stake(&stake_tx)),
                None => ExecOutcome::Malformed,
            },
            Some((&TAG_SLASH, body)) => match SlashTx::from_bytes(body) {
                Some(slash_tx) => outcome(self.apply_slash(&slash_tx)),
                None => ExecOutcome::Malformed,
            },
            _ => ExecOutcome::Malformed,
        }
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

    /// Execute an [`ERGON term`](crate::ergon_host) transaction.
    ///
    /// Every check the chain relies on happens here and none of them is taken on trust from the submitter: the signature
    /// authenticates the caller and binds the exact term bytes, the nonce is checked exactly as a transfer's is,
    /// `SignedTerm::checked` decodes canonically *and* type-checks in one step, and the evaluator confines execution to
    /// the footprint it derives itself.
    ///
    /// A term reaching a value space this ledger does not map is **rejected**, not partially applied. The alternative —
    /// executing what it can — would let a term's footprint describe less than it touched, which is the one thing the
    /// scheduler cannot survive.
    fn apply_term(&mut self, body: &[u8], verdict: Option<bool>) -> ExecOutcome {
        let Some(envelope) = SignedTerm::from_bytes(body) else {
            return ExecOutcome::Malformed;
        };
        if !verdict.unwrap_or_else(|| envelope.verify()) {
            return ExecOutcome::Rejected;
        }
        let caller = envelope.caller();
        let expected = self.tokens.nonce(&caller);
        if envelope.nonce > expected {
            // Premature, not invalid — the same reading a transfer gets under blind anti-MEV ordering.
            return ExecOutcome::Deferred;
        }
        if envelope.nonce != expected {
            return ExecOutcome::Rejected;
        }
        let Some(checked) = envelope.checked(&Limits::unbounded()) else {
            return ExecOutcome::Malformed;
        };
        // No pre-check on value spaces any more: `LedgerState` records every key it cannot route, read or written, and the
        // check below refuses the transaction if anything was. One decision in one place — a duplicate would be a second
        // thing to keep in step with the adapter, and the adapter is the only code that knows what it can route.
        // The height is the runtime's, never the term's — see `LedgerHost::height`.
        let mut host = LedgerHost::new(caller, self.height);
        let mut state = LedgerState::new(self);
        let outcome = fanos_ergon::eval(&checked, &[], &mut host, &mut state);
        // Defence in depth behind the space check above: if the adapter could not route anything, the term is refused even
        // if the evaluator was satisfied. A dropped write must never reach a committed state.
        if state.unmapped().is_some() {
            return ExecOutcome::Rejected;
        }
        match outcome {
            Ok(_) => {
                self.tokens.bump_nonce(caller);
                ExecOutcome::Applied
            }
            // The evaluator is atomic, so a fault has already rolled back everything the term wrote. The nonce is NOT
            // bumped: a term that did nothing must not consume the caller's counter, or a rejected submission would
            // invalidate the caller's next one.
            Err(_) => ExecOutcome::Rejected,
        }
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
                Some(st) => AccessList::new([], [balance_key(st.transfer.from), balance_key(st.transfer.to)]),
                None => AccessList::default(),
            },
            // The ERGON access list is **derived from the term**, not declared beside it — which is the property
            // `docs/design-ergon.md` §1 refuses a VM to keep. A term whose footprint reaches a value space this ledger does
            // not map is rejected at execution, so mapping only `SPACE_BALANCE` here is exact rather than optimistic: a
            // rejected transaction writes nothing, and any access list is safe for one that writes nothing.
            Some((&TAG_ERGON, body)) => match SignedTerm::from_bytes(body).and_then(|st| st.checked(&Limits::unbounded())) {
                Some(checked) => {
                    let fp = checked.term().footprint();
                    AccessList::new(
                        fp.reads().iter().copied(),
                        fp.writes().iter().copied(),
                    )
                }
                None => AccessList::default(),
            },
            Some((&TAG_SHIELDED, body)) => match decode_submission(body) {
                Some((stx, _)) => {
                    let mut writes = vec![shielded_key(SHIELDED_MARKER), balance_key(POOL_SINK)];
                    if stx.public_value > 0 {
                        writes.push(balance_key(stx.public_recipient));
                    }
                    if stx.fee > 0 {
                        // The fee moves POOL_SINK → TREASURY at runtime (`apply_shielded`, audit O-H1), so
                        // TREASURY is a real write — declare it (audit §3.7). Without this a shielded-fee tx and a
                        // name tx (which also writes TREASURY) read as non-conflicting yet both write it, so once
                        // the parallel scheduler is live and TREASURY gains a read/debit they could fork the state.
                        writes.push(balance_key(TREASURY));
                    }
                    AccessList::new([], writes)
                }
                None => AccessList::default(),
            },
            Some((&TAG_NAME, body)) => match NameTx::from_bytes(body) {
                Some(nt) => AccessList::new(
                    [],
                    [balance_key(nt.payment.transfer.from), balance_key(TREASURY), name_key(crate::naming::name_digest(nt.op.name()))],
                ),
                None => AccessList::default(),
            },
            Some((&TAG_SHIELD, body)) => match ShieldTx::from_bytes(body) {
                Some(sx) => AccessList::new([], [balance_key(sx.payment.transfer.from), balance_key(POOL_SINK), shielded_key(SHIELDED_MARKER)]),
                None => AccessList::default(),
            },
            Some((&TAG_STORAGE, body)) => match StorageTx::from_bytes(body) {
                Some(StorageTx::Open { params, payment }) => AccessList::new(
                    [],
                    [balance_key(params.consumer), balance_key(STORAGE_ESCROW), storage_key(deal_id(&params, payment.transfer.nonce))],
                ),
                Some(StorageTx::Prove { deal_id: id, .. }) => {
                    let mut writes = vec![balance_key(STORAGE_ESCROW), storage_key(id)];
                    if let Some(provider) = self.deal_party(&id, pending).map(|(p, _)| p) {
                        writes.push(balance_key(provider));
                    }
                    AccessList::new([], writes)
                }
                Some(StorageTx::Close { deal_id: id, .. }) => {
                    let mut writes = vec![balance_key(STORAGE_ESCROW), storage_key(id)];
                    if let Some(consumer) = self.deal_party(&id, pending).map(|(_, c)| c) {
                        writes.push(balance_key(consumer));
                    }
                    AccessList::new([], writes)
                }
                None => AccessList::default(),
            },
            Some((&TAG_HTLC, body)) => match HtlcTx::from_bytes(body) {
                Some(HtlcTx::Lock { terms, payment }) => {
                    AccessList::new([], [balance_key(terms.sender), balance_key(HTLC_ESCROW), htlc_key(htlc_id(&terms, payment.transfer.nonce))])
                }
                Some(HtlcTx::Claim { htlc_id: id, .. }) => {
                    let mut writes = vec![balance_key(HTLC_ESCROW), htlc_key(id)];
                    if let Some(recipient) = self.htlc_party(&id, pending_htlc).map(|(_, r)| r) {
                        writes.push(balance_key(recipient));
                    }
                    AccessList::new([], writes)
                }
                Some(HtlcTx::Refund { htlc_id: id }) => {
                    let mut writes = vec![balance_key(HTLC_ESCROW), htlc_key(id)];
                    if let Some(sender) = self.htlc_party(&id, pending_htlc).map(|(s, _)| s) {
                        writes.push(balance_key(sender));
                    }
                    AccessList::new([], writes)
                }
                None => AccessList::default(),
            },
            Some((&TAG_STAKE, body)) => match StakeTx::from_bytes(body) {
                // Bond debits `from` → STAKE_SINK; unbond releases STAKE_SINK → `from`. Both touch exactly these
                // two accounts, so declaring them serializes a stake op against any conflicting transfer (e.g. a
                // same-sender transfer that shares the nonce sequence).
                Some(stake_tx) => AccessList::new([], [balance_key(stake_tx.transfer().transfer.from), balance_key(STAKE_SINK)]),
                None => AccessList::default(),
            },
            Some((&TAG_SLASH, body)) => match SlashTx::from_bytes(body) {
                // Slashing moves the equivocator's bonded stake STAKE_SINK → TREASURY: it writes the equivocator's
                // account (its bonded balance), the sink, and the treasury. Declaring TREASURY also serializes it
                // against name and shielded-fee txs, which write TREASURY too.
                Some(slash_tx) => AccessList::new(
                    [],
                    [balance_key(account_id(&slash_tx.verifier)), balance_key(STAKE_SINK), balance_key(TREASURY)],
                ),
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

    /// Wrap a signed ERGON term as a DROMOS transaction payload.
    ///
    /// The counterpart of the tag wrappers above, and it exists for the same reason they do: a term must be
    /// submittable exactly the way every other operation is, or an equivalence between the two can only be asserted
    /// by comparing different submission paths — which measures the layers between them rather than the operation.
    #[must_use]
    pub fn term_payload(term: &SignedTerm) -> Vec<u8> {
        Self::tagged(TAG_ERGON, &term.to_bytes())
    }

    /// Wrap a validator staking operation (bond/unbond) as a DROMOS transaction payload.
    #[must_use]
    pub fn stake_payload(tx: &StakeTx) -> Vec<u8> {
        Self::tagged(TAG_STAKE, &tx.to_bytes())
    }

    /// Wrap a validator slashing proof (equivocation evidence) as a DROMOS transaction payload.
    #[must_use]
    pub fn slash_payload(tx: &SlashTx) -> Vec<u8> {
        Self::tagged(TAG_SLASH, &tx.to_bytes())
    }

    fn tagged(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(tag);
        out.extend_from_slice(body);
        out
    }
}

impl StateMachine for HybridLedger {
    /// Execute the block through the **parallel scheduler** rather than one transaction at a time.
    ///
    /// This is the hook that puts `spec/platform.md` §3.1's vertical parallelism on the live consensus path: waves of
    /// conflict-free transactions, with the expensive stateless verification (hybrid PQ signatures, shielded ZK proofs)
    /// batched across a thread pool before the serial commit. Serial-equivalent by construction and pinned as such by
    /// `execute_block_matches_serial_execution_and_parallelizes_independent_work` and the determinism KATs.
    fn apply_block(&mut self, txs: &[Transaction]) -> Vec<ExecOutcome> {
        self.execute_block(txs)
    }

    /// Set the registry's clock to the block being executed, and finalize any storage deals whose audit deadline
    /// has now lapsed (auto-refunding the consumer — audit AT-H2).
    fn begin_block(&mut self, height: u64) {
        self.height = height;
        self.finalize_lapsed_deals();
        // Prune terminal HTLCs (audit §3.4): a Claimed/Refunded htlc resolves no further, so keeping it only
        // grows the book + state root without bound. A Locked htlc holds real escrow (self-limiting) and stays
        // until it resolves. Deterministic across the cell.
        //
        // A claim for a pruned id now reads as *deferred* rather than rejected, because the book cannot tell
        // "already resolved" from "not locked yet" — both are simply absent — and the second reading is the one
        // blind ordering makes common. The cost of preferring it is bounded and small: such a claim is
        // re-proposed for at most `REVEAL_WINDOW` blocks before the engine drops it, and only if it was included
        // at all. Distinguishing the two would need a resolved-id set, which is exactly the unbounded growth
        // this pruning exists to prevent.
        self.htlcs.htlcs.retain(|_, h| h.state() == HtlcState::Locked);
    }

    /// Adopt the block's audit beacon (the parent hash) — the storage market's retrievability challenges are
    /// drawn from it, so its consensus-committed unpredictability is what makes the audit ungrindable
    /// (`crate::storage`).
    fn set_audit_beacon(&mut self, beacon: [u8; 32]) {
        self.audit_beacon = beacon;
    }

    fn apply_block_reward(&mut self, beneficiaries: &[HybridVerifier], amount: u64) {
        // Pay the block reward from the TREASURY — which accumulates transaction fees and slashed stake — so
        // users' fees and forfeited stakes fund the validators who finalize blocks (the economic loop closes;
        // no minting, so rewards are never inflationary). Cap at the treasury balance (graceful when empty) and
        // split equally among the finalizers; any integer-division remainder stays in the treasury. Deterministic:
        // the beneficiaries come from the committed `last_commit` certificate and the treasury balance is state.
        let count = u64::try_from(beneficiaries.len()).unwrap_or(u64::MAX);
        if count == 0 || amount == 0 {
            return;
        }
        let pot = amount.min(self.tokens.balance(&TREASURY));
        let share = pot / count;
        if share == 0 {
            return;
        }
        for v in beneficiaries {
            // Total paid = share·count ≤ pot ≤ treasury, so each move is funded (never underflows).
            let _ = self.tokens.move_system(&TREASURY, account_id(v), share);
        }
    }

    /// Execute one committed transaction by dispatching on its type tag. An unknown tag or empty payload is
    /// [`ExecOutcome::Malformed`]; a well-formed-but-invalid transaction (bad signature, double-spend, taken
    /// name, insufficient funds) is [`ExecOutcome::Rejected`]; success is [`ExecOutcome::Applied`]. The
    /// single-transaction entry point: it verifies inline (no pre-computed verdict). Block execution instead
    /// verifies in parallel and drives ``apply_with_verdict`` directly.
    fn apply(&mut self, tx: &Transaction) -> ExecOutcome {
        self.apply_with_verdict(tx, None)
    }

    /// `H(tokens ‖ shielded ‖ names ‖ storage ‖ htlc ‖ stake)` — one commitment over transparent balances,
    /// shielded notes, names, storage deals, atomic-swap contracts, and validator stake, for the block's
    /// executed-state checkpoint.
    fn state_root(&self) -> [u8; 32] {
        let mut buf = [0u8; 192];
        buf[..32].copy_from_slice(&self.tokens.state_root());
        buf[32..64].copy_from_slice(&self.shielded.root());
        buf[64..96].copy_from_slice(&self.names.state_root());
        buf[96..128].copy_from_slice(&self.storage.state_root());
        buf[128..160].copy_from_slice(&self.htlcs.state_root());
        buf[160..].copy_from_slice(&self.stake.state_root());
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
        put_var_bytes(&mut out, &self.stake.to_bytes());
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
        let stake = StakeLedger::from_bytes(r.var_bytes()?)?;
        let height = r.u64()?;
        let audit_beacon = r.array::<32>()?;
        r.finish()?;
        Some(Self {
            // A restored snapshot has executed no block here, so the metric starts at zero rather than being carried: it
            // describes *this* validator's last scheduling pass, not the state it adopted.
            waves_last_block: 0,
            tokens,
            shielded,
            names,
            storage,
            htlcs,
            stake,
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

/// A transaction's **stateless verification job** — the signature or proof that can be checked without any
/// ledger state, and so verified in parallel before the serial commit (see [`HybridLedger::verify_batch`]).
/// Only the two high-volume transaction types with an expensive verification are represented; every other type
/// is committed with an inline check. The shielded pair is boxed to keep the two variants a similar size.
enum StatelessJob {
    /// A transparent transfer: verify its hybrid post-quantum signature. Boxed — the signature is multi-kilobyte.
    Transparent(Box<SignedTransfer>),
    /// A shielded transfer: verify its zero-knowledge proof against the pool parameters.
    Shielded(Box<(ShieldedTx, TransparentProof)>),
}

/// The stateless verification job for `tx`, or `None` for a transaction type committed with an inline check (or
/// a malformed body, which the commit rejects anyway).
fn stateless_job(tx: &Transaction) -> Option<StatelessJob> {
    match tx.payload.split_first() {
        Some((&TAG_TRANSPARENT, body)) => {
            SignedTransfer::from_bytes(body).map(|st| StatelessJob::Transparent(Box::new(st)))
        }
        Some((&TAG_SHIELDED, body)) => decode_submission(body).map(|pair| StatelessJob::Shielded(Box::new(pair))),
        _ => None,
    }
}

/// Evaluate one job's verdict — a pure function of the job and the shared, immutable pool `params`.
fn eval_job((i, job): &(usize, StatelessJob), params: &Params) -> (usize, bool) {
    let ok = match job {
        StatelessJob::Transparent(st) => st.verify(),
        StatelessJob::Shielded(pair) => ShieldedState::verify_proof(params, &pair.0, &pair.1),
    };
    (*i, ok)
}

/// Evaluate every job's verdict, fanned out across the machine's parallelism with scoped threads. Each verdict
/// depends only on its job and `params` (never ledger state), so splitting the jobs across threads cannot change
/// any result — the output is deterministic regardless of the thread count or scheduling, which is what lets
/// validators with different core counts agree on the block. A thread that panics contributes no verdicts; those
/// transactions simply fall back to the inline check in `apply_with_verdict`, so a panic costs speed, not safety.
fn par_verify(jobs: &[(usize, StatelessJob)], params: &Params) -> Vec<(usize, bool)> {
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    if threads <= 1 || jobs.len() <= 1 {
        return jobs.iter().map(|j| eval_job(j, params)).collect();
    }
    let chunk = jobs.len().div_ceil(threads);
    std::thread::scope(|s| {
        let handles: Vec<_> = jobs
            .chunks(chunk)
            .map(|c| s.spawn(move || c.iter().map(|j| eval_job(j, params)).collect::<Vec<_>>()))
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::naming::{NameOp, TREASURY, price};
    use crate::token::Transfer;
    use fanos_taxis::{Phase, SignedVote, Vote};
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
    use crate::ergon_host::transfer_term;
    use crate::hermes::{HtlcTerms, hashlock};
    use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};

    fn account(tag: u8) -> (HybridSigSecret, HybridVerifier, [u8; 32]) {
        let mut rng = SeedRng::from_seed(&[0xC0, tag]);
        let (signer, verifier) = HybridSigSecret::generate(&mut rng);
        let id = account_id(&verifier);
        (signer, verifier, id)
    }

    /// An ERGON term submitted as a transaction, signed by `tag`'s account.
    fn ergon_tx(term: &fanos_ergon::Term, nonce: u64, signer: &HybridSigSecret, key: &HybridVerifier) -> Transaction {
        let envelope = SignedTerm::sign(term.encode(), nonce, signer, key.clone());
        let mut payload = vec![TAG_ERGON];
        payload.extend_from_slice(&envelope.to_bytes());
        Transaction::new(payload)
    }

    #[test]
    fn a_signed_term_executes_as_a_transaction_and_is_replay_protected() {
        // The wiring that makes ERGON reachable from the wire rather than from a test — and the point of the whole
        // exercise: a composition the eight tags cannot express, submitted by a user, executed by the chain.
        let (signer, key, alice) = account(1);
        let (_, _, bob) = account(2);
        let (_, _, carol) = account(3);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 1000);
        let mut ledger = HybridLedger::new(tokens);

        // Atomic pay-two-parties, which no single tag expresses.
        let term = fanos_ergon::Term::Seq(vec![
            transfer_term(alice, bob, 300),
            transfer_term(alice, carol, 200),
        ]);
        let tx = ergon_tx(&term, 0, &signer, &key);
        assert_eq!(ledger.apply(&tx), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&alice), 500);
        assert_eq!(ledger.tokens().balance(&bob), 300);
        assert_eq!(ledger.tokens().balance(&carol), 200);

        // Replayed verbatim: the nonce has moved on, so it is refused.
        assert_eq!(ledger.apply(&tx), ExecOutcome::Rejected, "a replay is refused");
        assert_eq!(ledger.tokens().balance(&bob), 300, "and nothing moved twice");
    }

    #[test]
    fn a_tampered_term_is_refused_because_the_signature_covers_its_bytes() {
        // The envelope binds the exact bytes. Substituting a term the caller never signed — the obvious attack on a
        // "submit a program" tag — must fail on the signature, not on the term's own rules.
        let (signer, key, alice) = account(1);
        let (_, _, bob) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 1000);
        let mut ledger = HybridLedger::new(tokens);

        let honest = transfer_term(alice, bob, 1);
        let greedy = transfer_term(alice, bob, 1000);
        let envelope = SignedTerm::sign(honest.encode(), 0, &signer, key.clone());
        let forged = SignedTerm::from_bytes(&{
            let mut b = envelope.to_bytes();
            b.truncate(b.len() - honest.encode().len());
            b.extend_from_slice(&greedy.encode());
            b
        })
        .expect("the forged envelope still decodes");
        assert!(!forged.verify(), "the signature does not cover the substituted term");

        let mut payload = vec![TAG_ERGON];
        payload.extend_from_slice(&forged.to_bytes());
        assert_eq!(ledger.apply(&Transaction::new(payload)), ExecOutcome::Rejected);
        assert_eq!(ledger.tokens().balance(&bob), 0, "nothing moved");
    }

    #[test]
    fn the_ergon_access_list_is_the_terms_own_derived_footprint() {
        // What DROMOS schedules on. Derived from the term by the chain, never read from a declaration — so a term cannot
        // understate what it touches, which is the property the scheduler cannot survive losing.
        let (signer, key, alice) = account(1);
        let (_, _, bob) = account(2);
        let term = transfer_term(alice, bob, 5);
        let tx = ergon_tx(&term, 0, &signer, &key);
        let empty = BTreeMap::new();
        let access = HybridLedger::new(TokenLedger::new()).access_of(&tx, &empty, &empty);
        assert_eq!(
            access.writes,
            [balance_key(alice), balance_key(bob)].into_iter().collect(),
            "exactly the two balances"
        );
        assert!(access.reads.is_empty());
    }

    #[test]
    fn a_term_reaching_an_unmapped_value_space_is_rejected_rather_than_partly_applied() {
        // Where the ledger cannot be precise it is conservative and loud. `AccessList` keys are 32 bytes with no space, so
        // a term touching a space this ledger does not map could have a footprint that describes less than it touches —
        // and executing what it can would be exactly the mis-schedule the footprint exists to prevent.
        let (signer, key, alice) = account(1);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 1000);
        let mut ledger = HybridLedger::new(tokens);
        let unmapped = fanos_ergon::Key::at(crate::ergon_host::LEDGER_POINT, 9, alice);
        let term = fanos_ergon::Term::Do(
            fanos_ergon::Effect::internal(
                crate::ergon_host::EFFECT_TRANSFER,
                fanos_ergon::Footprint::new(vec![], vec![unmapped]),
            ),
        );
        let tx = ergon_tx(&term, 0, &signer, &key);
        assert_eq!(ledger.apply(&tx), ExecOutcome::Rejected);
        assert_eq!(ledger.tokens().balance(&alice), 1000, "untouched");
    }

    #[test]
    fn the_native_and_term_paths_name_the_same_state_with_the_same_keys() {
        // The invariant that keeps two execution paths from forking the state, pinned before it can be broken rather than
        // after. A transfer can now arrive two ways — as `TAG_TRANSPARENT` or inside a `TAG_ERGON` term — and the
        // scheduler decides they conflict by comparing access lists. If the two paths named the same accounts differently
        // they would read as disjoint, run in the same wave, and both debit the same balance.
        //
        // It holds trivially today because `AccessList` keys are bare 32-byte ids and both paths use account ids. It stops
        // holding the moment either path qualifies its keys and the other does not, which is exactly what widening
        // `AccessList` to carry `Key::space` would invite — see the note in `docs/design-ergon.md` §11 step 3. This test is
        // what fails then, instead of a fork appearing under load.
        let (signer, key, alice) = account(1);
        let (_, _, bob) = account(2);
        let empty = BTreeMap::new();
        let ledger = HybridLedger::new(TokenLedger::new());

        let native = SignedTransfer::sign(
            Transfer { from: alice, to: bob, amount: 7, nonce: 0 },
            &signer,
            key.clone(),
        );
        let native_access =
            ledger.access_of(&Transaction::new(HybridLedger::transparent_payload(&native)), &empty, &empty);

        let term_access = ledger.access_of(
            &ergon_tx(&transfer_term(alice, bob, 7), 0, &signer, &key),
            &empty,
            &empty,
        );

        assert_eq!(
            native_access.writes, term_access.writes,
            "both paths name the same two balances, so the scheduler sees the conflict"
        );
        assert_eq!(native_access.reads, term_access.reads);
        assert!(native_access.conflicts_with(&term_access), "and they are therefore never scheduled together");
    }

    #[test]
    fn a_term_can_branch_on_a_live_htlc_without_being_able_to_resolve_it() {
        // The capability the second value space buys, and the shape §11 step 4's correction leaves available: a user term
        // reads protocol state and imposes its OWN condition, while the escrow stays behind the rule that guards it.
        //
        // Both halves are asserted, because the read alone would prove nothing: the term pays when the hashlock is the one
        // it expected and does not when it is not — so it is genuinely reading the contract rather than the guard being
        // vacuous.
        let (signer, key, alice) = account(1);
        let (_, _, bob) = account(2);
        let preimage = [0x5Au8; 32];
        let terms = HtlcTerms {
            sender: alice,
            recipient: bob,
            amount: 10,
            hashlock: hashlock(&preimage),
            timeout: 100,
        };
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 1000);
        let mut ledger = HybridLedger::new(tokens);
        let lock = SignedTransfer::sign(
            Transfer { from: alice, to: HTLC_ESCROW, amount: 10, nonce: 0 },
            &signer,
            key.clone(),
        );
        let id = htlc_id(&terms, 0);
        assert_eq!(
            ledger.apply(&Transaction::new(HybridLedger::htlc_payload(&HtlcTx::Lock {
                terms,
                payment: Box::new(lock),
            }))),
            ExecOutcome::Applied,
            "the contract is live"
        );

        let gated = |expected: [u8; 32]| {
            fanos_ergon::Term::Gate(
                fanos_ergon::exec::compare(
                    fanos_ergon::Cmp::Eq,
                    fanos_ergon::Expr::Load(htlc_key(id)),
                    fanos_ergon::Expr::bytes32(expected),
                ),
                Box::new(transfer_term(alice, bob, 1)),
            )
        };

        // The wrong expectation: the guard refuses, nothing moves, and the transaction still commits (a declined `Gate` is
        // the identity, not a fault).
        let before = ledger.tokens().balance(&bob);
        assert_eq!(ledger.apply(&ergon_tx(&gated([0xFFu8; 32]), 1, &signer, &key)), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&bob), before, "the guard declined");

        // The right one: the term reads the live contract's hashlock and pays.
        assert_eq!(ledger.apply(&ergon_tx(&gated(hashlock(&preimage)), 2, &signer, &key)), ExecOutcome::Applied);
        assert_eq!(ledger.tokens().balance(&bob), before + 1, "the guard admitted");
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
        assert!(
            shielded_access.writes.contains(&balance_key(TREASURY)),
            "a shielded-fee tx declares the TREASURY write"
        );

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

    /// **The drift guard**: what `apply` actually writes must be inside what `access_of` declared.
    ///
    /// `access_of` and `apply` are two hand-maintained matches over the same eight tags — one computing what a
    /// transaction *touches*, the other what it *does* — and the parallel scheduler's correctness rests entirely on
    /// them agreeing. Add a write to `apply` and forget it in `access_of`, and two genuinely conflicting transactions
    /// share a wave and fork the state.
    ///
    /// That is not hypothetical. The shielded arm of `access_of` carries a comment recording exactly this defect: a
    /// missing `TREASURY` write (audit §3.7), found by review rather than by a test. This is the test.
    ///
    /// The direction is deliberately one-way. A declared write that never happens is *conservative* — it costs
    /// parallelism, never correctness — so over-declaring is not a failure. Only under-declaring is, and only
    /// under-declaring can fork the state.
    ///
    /// The guard was checked to have teeth rather than assumed to: deleting `TREASURY` from the name arm of `access_of`
    /// — reintroducing the §3.7 defect exactly — fails this on seed 0. A guard that cannot fail proves nothing.
    #[test]
    fn every_key_apply_touches_was_declared_by_access_of() {
        for seed in 0..64u64 {
            let (accounts, txs) = random_conflicting_block(seed);
            let ids: Vec<[u8; 32]> = accounts.iter().map(|(_, _, id)| *id).collect();
            // TREASURY and the shielded markers are ledger-wide keys a transaction may touch without being an account.
            let watched: Vec<[u8; 32]> =
                ids.iter().copied().chain([TREASURY, POOL_SINK, SHIELDED_MARKER]).collect();

            let mut ledger = ledger_with(&accounts);
            // The generator only produces transparent transfers, and the defect this guards against lived in the
            // arms that touch TREASURY. A guard that never exercises the risky arm is theatre, so a name registration
            // — which debits its payer AND credits TREASURY — is appended to every block.
            let (payer_sk, payer_vk, payer) = &accounts[0];
            let payer_nonce = txs
                .iter()
                .filter_map(|t| match t.payload.split_first() {
                    Some((&TAG_TRANSPARENT, body)) => SignedTransfer::from_bytes(body),
                    _ => None,
                })
                .filter(|st| st.transfer.from == *payer)
                .count() as u64;
            let name = format!("acct{seed}.fanos").into_bytes();
            let name_tx = NameTx {
                op: NameOp::Register { name: name.clone(), target: b"addr".to_vec(), duration: 10 },
                payment: SignedTransfer::sign(
                    Transfer { from: *payer, to: TREASURY, amount: price(&name, 10), nonce: payer_nonce },
                    payer_sk,
                    payer_vk.clone(),
                ),
            };
            let mut txs = txs;
            txs.push(Transaction::new(HybridLedger::name_payload(&name_tx)));
            let declared = ledger.access_lists(&txs);

            for (tx, access) in txs.iter().zip(declared.iter()) {
                let before: Vec<u64> = watched.iter().map(|k| ledger.tokens().balance(k)).collect();
                ledger.apply(tx);
                let after: Vec<u64> = watched.iter().map(|k| ledger.tokens().balance(k)).collect();

                for ((key, b), a) in watched.iter().zip(before.iter()).zip(after.iter()) {
                    if b != a {
                        assert!(
                            access.writes.contains(&balance_key(*key)),
                            "seed {seed}: apply changed a balance access_of did not declare — this is the shape of \
                             the audit §3.7 fork: the scheduler would place this transaction in a wave with another \
                             that also writes it"
                        );
                    }
                }
            }
        }
    }

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

    #[test]
    fn parallel_verification_of_a_mixed_block_matches_serial_including_a_forgery() {
        // The parallel executor verifies the stateless half of validation — hybrid PQ signatures AND shielded
        // zero-knowledge proofs — off the commit thread. This exercises all three cases in ONE block: a valid
        // transparent transfer, a valid shielded spend, and a FORGED transfer (signed by the wrong key). The
        // committed result — including rejecting the forgery — must be byte-identical to serial inline
        // execution: moving verification off-thread changes nothing but speed.
        let a = account(1);
        let b = account(2);
        let build = |acct: &(HybridSigSecret, HybridVerifier, [u8; 32]), to: [u8; 32], amount: u64, nonce: u64| {
            let st = SignedTransfer::sign(Transfer { from: acct.2, to, amount, nonce }, &acct.0, acct.1.clone());
            Transaction::new(HybridLedger::transparent_payload(&st))
        };
        // A single shielded note minted into the pool; the ledger also funds the two transparent accounts.
        let nsk = [7u8; 32];
        let n0 = note(500, &nsk, b"mix");
        let make_ledger = || {
            let mut t = TokenLedger::new();
            t.credit(a.2, 10_000);
            t.credit(b.2, 10_000);
            let mut l = HybridLedger::new(t);
            let pos = l.mint_shielded(n0.commitment(l.params())).unwrap();
            (l, pos)
        };
        let (base, pos) = make_ledger();
        let sp = SpendInput {
            note: n0.clone(),
            nsk,
            spend_seed: spend_seed_of(&nsk),
            path: base.shielded().path(pos).unwrap(),
        };
        let (stx, proof) = build_transfer(
            base.params(),
            base.shielded().anchor(),
            std::slice::from_ref(&sp),
            &[note(500, &[8u8; 32], b"out")],
            0,
        );
        let shielded_tx = Transaction::new(HybridLedger::shielded_payload(&encode_submission(&stx, &proof)));
        // Forged: claims to be FROM `a`, but is signed by `b`'s key — its signature does not authorise it.
        let forged = {
            let st = SignedTransfer::sign(Transfer { from: a.2, to: b.2, amount: 500, nonce: 0 }, &b.0, b.1.clone());
            Transaction::new(HybridLedger::transparent_payload(&st))
        };
        let txs = vec![build(&a, b.2, 100, 0), shielded_tx, forged, build(&b, a.2, 200, 0)];

        let (mut serial, _) = make_ledger();
        let serial_outcomes: Vec<_> = txs.iter().map(|t| serial.apply(t)).collect();
        let (mut parallel, _) = make_ledger();
        let parallel_outcomes = parallel.execute_block(&txs);

        assert_eq!(parallel_outcomes, serial_outcomes, "parallel outcomes == serial for the mixed block");
        assert_eq!(parallel.state_root(), serial.state_root(), "parallel state == serial");
        assert_eq!(serial_outcomes[0], ExecOutcome::Applied, "the transparent transfer applied");
        assert_eq!(serial_outcomes[1], ExecOutcome::Applied, "the shielded spend applied");
        assert_eq!(serial_outcomes[2], ExecOutcome::Rejected, "the forgery is rejected off-thread exactly as inline");
        assert_eq!(serial_outcomes[3], ExecOutcome::Applied, "the second transparent transfer applied");
    }

    #[test]
    fn a_validator_bonds_unbonds_and_the_stake_sink_backs_the_total() {
        let (sk, vk, acct) = account(1);
        let mut tokens = TokenLedger::new();
        tokens.credit(acct, 1000);
        let mut ledger = HybridLedger::new(tokens);
        let stake_op = |bond: bool, amount: u64, nonce: u64| {
            let st = SignedTransfer::sign(Transfer { from: acct, to: STAKE_SINK, amount, nonce }, &sk, vk.clone());
            let tx = if bond { StakeTx::Bond(st) } else { StakeTx::Unbond(st) };
            Transaction::new(HybridLedger::stake_payload(&tx))
        };

        // Bond 600: the balance falls, the bonded rises, and the sink backs it exactly.
        assert_eq!(ledger.apply(&stake_op(true, 600, 0)), ExecOutcome::Applied);
        assert_eq!(ledger.stake().bonded(&acct), 600);
        assert_eq!(ledger.tokens().balance(&acct), 400);
        assert_eq!(ledger.tokens().balance(&STAKE_SINK), 600, "the sink balance equals the total bonded");
        assert_eq!(ledger.stake().total_bonded(), 600);

        // Unbond 250 back to the balance.
        assert_eq!(ledger.apply(&stake_op(false, 250, 1)), ExecOutcome::Applied);
        assert_eq!(ledger.stake().bonded(&acct), 350);
        assert_eq!(ledger.tokens().balance(&acct), 650);
        assert_eq!(ledger.tokens().balance(&STAKE_SINK), 350, "the sink still backs the bonded total");

        // The stake ledger's guards: cannot unbond more than bonded, nor bond more than the balance.
        assert_eq!(ledger.apply(&stake_op(false, 9999, 2)), ExecOutcome::Rejected, "over-unbond rejected");
        assert_eq!(ledger.stake().bonded(&acct), 350, "a failed unbond changes nothing");
        assert_eq!(ledger.apply(&stake_op(true, 999_999, 2)), ExecOutcome::Rejected, "over-bond rejected");
        assert_eq!(ledger.stake().bonded(&acct), 350);
        // A stake op not directed at STAKE_SINK is not a valid authorisation.
        let misdirected =
            SignedTransfer::sign(Transfer { from: acct, to: [9u8; 32], amount: 1, nonce: 2 }, &sk, vk.clone());
        let tx = Transaction::new(HybridLedger::stake_payload(&StakeTx::Bond(misdirected)));
        assert_eq!(ledger.apply(&tx), ExecOutcome::Rejected, "a bond must be authorised to STAKE_SINK");
    }

    #[test]
    fn an_equivocating_validator_is_slashed_of_its_entire_bonded_stake() {
        let (sk, vk, acct) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(acct, 1000);
        let mut ledger = HybridLedger::new(tokens);

        let bond = |amount: u64, nonce: u64| {
            let st = SignedTransfer::sign(Transfer { from: acct, to: STAKE_SINK, amount, nonce }, &sk, vk.clone());
            Transaction::new(HybridLedger::stake_payload(&StakeTx::Bond(st)))
        };
        assert_eq!(ledger.apply(&bond(800, 0)), ExecOutcome::Applied);
        assert_eq!(ledger.stake().bonded(&acct), 800);

        // The validator equivocates: two Commit votes at the same (height, round) for different blocks.
        let vote = |block_hash: [u8; 32]| {
            SignedVote::sign(Vote { height: 5, round: 0, block_hash, phase: Phase::Commit, voter: 2 }, &sk)
        };
        let slash =
            SlashTx { vote_a: vote([0xAA; 32]), vote_b: vote([0xBB; 32]), verifier: vk.clone() };
        let slash_tx = Transaction::new(HybridLedger::slash_payload(&slash));

        assert_eq!(ledger.apply(&slash_tx), ExecOutcome::Applied, "a genuine equivocation is slashable");
        assert_eq!(ledger.stake().bonded(&acct), 0, "the entire bonded stake is slashed");
        assert_eq!(ledger.tokens().balance(&TREASURY), 800, "the slashed stake goes to the treasury");
        assert_eq!(ledger.tokens().balance(&STAKE_SINK), 0, "the sink is emptied to match");

        // The same fault cannot be slashed twice (idempotent per equivocation slot).
        assert_eq!(ledger.apply(&slash_tx), ExecOutcome::Rejected, "a duplicate slash is a no-op");
        assert_eq!(ledger.tokens().balance(&TREASURY), 800, "no double-slash");

        // Re-bonding is safe: the recorded fault cannot drain freshly bonded stake.
        assert_eq!(ledger.apply(&bond(100, 1)), ExecOutcome::Applied);
        assert_eq!(ledger.apply(&slash_tx), ExecOutcome::Rejected, "the old proof cannot re-slash");
        assert_eq!(ledger.stake().bonded(&acct), 100, "the re-bonded stake is untouched");
    }

    #[test]
    fn a_bogus_slash_proof_slashes_no_one() {
        let (sk, vk, acct) = account(3);
        let (_sk2, vk2, _acct2) = account(4);
        let mut tokens = TokenLedger::new();
        tokens.credit(acct, 1000);
        let mut ledger = HybridLedger::new(tokens);
        let bond = SignedTransfer::sign(Transfer { from: acct, to: STAKE_SINK, amount: 500, nonce: 0 }, &sk, vk.clone());
        assert_eq!(
            ledger.apply(&Transaction::new(HybridLedger::stake_payload(&StakeTx::Bond(bond)))),
            ExecOutcome::Applied
        );

        // Two IDENTICAL votes are not a conflict — no equivocation.
        let v = Vote { height: 1, round: 0, block_hash: [1u8; 32], phase: Phase::Prepare, voter: 3 };
        let same = SlashTx { vote_a: SignedVote::sign(v, &sk), vote_b: SignedVote::sign(v, &sk), verifier: vk.clone() };
        assert_eq!(
            ledger.apply(&Transaction::new(HybridLedger::slash_payload(&same))),
            ExecOutcome::Rejected,
            "identical votes are not equivocation"
        );
        assert_eq!(ledger.stake().bonded(&acct), 500, "no stake moved");

        // Conflicting votes, but the cited verifier (vk2) did not sign them → the signatures do not verify.
        let mk = |bh: [u8; 32]| SignedVote::sign(Vote { height: 1, round: 0, block_hash: bh, phase: Phase::Commit, voter: 3 }, &sk);
        let wrong = SlashTx { vote_a: mk([1u8; 32]), vote_b: mk([2u8; 32]), verifier: vk2 };
        assert_eq!(
            ledger.apply(&Transaction::new(HybridLedger::slash_payload(&wrong))),
            ExecOutcome::Rejected,
            "votes not signed by the cited key are not evidence"
        );
        assert_eq!(ledger.stake().bonded(&acct), 500, "no stake moved");
    }

    #[test]
    fn the_block_reward_is_paid_from_the_treasury_to_the_finalizers() {
        // The canonical block reward (`StateMachine::apply_block_reward`) credits the parent's finalizers from
        // the TREASURY — where fees and slashed stake accumulate — capped at the treasury balance (no minting).
        let (_s1, v1, a1) = account(1);
        let (_s2, v2, a2) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(TREASURY, 1000); // the treasury is funded (fees + slashes accrue here)
        let mut ledger = HybridLedger::new(tokens);

        // Reward 300 split between two finalizers → 150 each; the treasury is debited by 300.
        ledger.apply_block_reward(&[v1.clone(), v2.clone()], 300);
        assert_eq!(ledger.tokens().balance(&a1), 150);
        assert_eq!(ledger.tokens().balance(&a2), 150);
        assert_eq!(ledger.tokens().balance(&TREASURY), 700, "the treasury funds the reward");

        // Capped at the treasury balance (never minted): 999_999 requested, only 700 left → 350 each, treasury 0.
        ledger.apply_block_reward(&[v1.clone(), v2.clone()], 999_999);
        assert_eq!(ledger.tokens().balance(&a1), 500);
        assert_eq!(ledger.tokens().balance(&a2), 500);
        assert_eq!(ledger.tokens().balance(&TREASURY), 0, "the reward never exceeds the treasury (no inflation)");

        // An empty treasury pays nothing (graceful — the equilibrium's C1 holds only while fees fund rewards).
        ledger.apply_block_reward(&[v1, v2], 500);
        assert_eq!(ledger.tokens().balance(&a1), 500, "an empty treasury pays no reward");
        assert_eq!(ledger.tokens().balance(&TREASURY), 0);
    }
    /// **A claim ordered ahead of its lock is deferred, not lost.** Anti-MEV ordering is blind, so a proposer
    /// cannot keep a contract's funding ahead of its claim — it sees only commitments. Measured before the fix:
    /// `[claim, lock]` in one block gave `[Rejected, Applied]`, the recipient was paid nothing, and the escrow
    /// sat stranded until the timeout while the claim was dropped from the mempool as "included".
    /// **Deferral is a last resort, not a first check.** A transaction that is *both* malformed and premature must
    /// be rejected: no later state makes a bad parameter good, so re-queueing it wastes block space for
    /// `REVEAL_WINDOW` blocks and then drops it anyway.
    ///
    /// This is not hypothetical — the first version of the premature check ran *before* each handler's own
    /// validation, and turned the out-of-range storage deals below from `Rejected` into `Deferred`. The existing
    /// suite caught it, which is why the check now lives inside each handler, immediately before it settles the
    /// payment and after everything it can judge on its own.
    #[test]
    fn a_transaction_that_is_both_malformed_and_premature_is_rejected_not_deferred() {
        use fanos_thesauros::{Cid, DealParams};
        let (sk, vk, consumer) = account(1);
        let (_p, _pv, provider) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(consumer, 1_000_000);
        let mut ledger = HybridLedger::new(tokens);
        let open = |ledger: &mut HybridLedger, size: u64, nonce: u64| {
            let params = DealParams {
                cid: Cid::new([2u8; 32]),
                size,
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
                Transfer { from: consumer, to: STORAGE_ESCROW, amount: 400, nonce },
                &sk,
                vk.clone(),
            );
            ledger.apply(&Transaction::new(HybridLedger::storage_payload(&StorageTx::Open { params, payment })))
        };
        // Sound deal, premature nonce (the account is still at 0) ⇒ deferred, and it survives to be retried.
        assert_eq!(open(&mut ledger, MAX_DEAL_SIZE, 7), ExecOutcome::Deferred, "sound but early ⇒ deferred");
        // Malformed deal, equally premature nonce ⇒ rejected, because deferring could never help it.
        assert_eq!(open(&mut ledger, MAX_DEAL_SIZE + 1, 7), ExecOutcome::Rejected, "malformed wins over early");
        // And the same sound deal applies once its nonce is the account's.
        assert_eq!(open(&mut ledger, MAX_DEAL_SIZE, 0), ExecOutcome::Applied, "the deferral was correct");
    }

    #[test]
    fn a_claim_ordered_ahead_of_its_lock_is_deferred_rather_than_lost() {
        use fanos_hermes::hashlock;
        let (alice_sk, alice_vk, alice) = account(1);
        let (_b, _bv, bob) = account(2);
        let mut tokens = TokenLedger::new();
        tokens.credit(alice, 10_000);
        let mut ledger = HybridLedger::new(tokens);
        ledger.begin_block(50);
        let secret = [0x5E; 32];
        let terms = HtlcTerms { sender: alice, recipient: bob, amount: 1000, hashlock: hashlock(&secret), timeout: 100 };
        let id = htlc_id(&terms, 0);
        let payment = SignedTransfer::sign(Transfer { from: alice, to: HTLC_ESCROW, amount: 1000, nonce: 0 }, &alice_sk, alice_vk);
        let lock = Transaction::new(HybridLedger::htlc_payload(&HtlcTx::Lock { terms, payment: Box::new(payment) }));
        let claim = Transaction::new(HybridLedger::htlc_payload(&HtlcTx::Claim { htlc_id: id, preimage: secret }));
        // Blind ordering puts the claim first.
        let outcomes = ledger.apply_block(&[claim.clone(), lock]);
        assert_eq!(
            outcomes,
            vec![ExecOutcome::Deferred, ExecOutcome::Applied],
            "the claim is premature, not invalid — the engine re-queues a deferred transaction"
        );
        assert_eq!(ledger.tokens().balance(&bob), 0, "and it has not paid yet");

        // Re-applied against the state its lock left behind, it pays — which is what makes deferring correct.
        assert_eq!(ledger.apply_block(&[claim]), vec![ExecOutcome::Applied]);
        assert_eq!(ledger.tokens().balance(&bob), 1000, "the recipient is paid once the ordering resolves");
    }

}
