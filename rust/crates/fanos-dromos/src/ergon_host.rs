//! The ledger as an ERGON **host** — step 2 of `docs/design-ergon.md` §11, and `fanos-ergon`'s first caller.
//!
//! The design's plan is to re-express the eight transaction tags as primitive effects, so that any well-typed term over
//! them is a new transaction kind requiring no protocol release. This module starts that with the transparent transfer,
//! the rule everything else funds itself through.
//!
//! ## What the split between term and host actually is
//!
//! ERGON owns *structure* — sequencing, gating, proven disjointness, and now computed arguments. The host owns the
//! *rule*: what a transfer means. That division is why the effect `kind` stays an opaque `u16` in `fanos-ergon`, and it is
//! also why the host cannot cheat: it is handed a state view confined to the footprint the term derives, so a rule that
//! touches a key outside it faults rather than succeeding quietly.
//!
//! ## Authorization is the envelope's job, not the term's
//!
//! A subtlety worth stating because getting it wrong would be a theft vector. The native path takes a `SignedTransfer`
//! and checks the signature inside the rule. A term carries no signature — it carries *arguments*. So the sender is
//! **argument 0, supplied by the runtime from the authenticated envelope**, never written into the term by its author.
//! A term is what an authorized caller asked to happen; it is not where the authorization lives. Any future effect that
//! debits an account follows the same rule.
//!
//! The **nonce belongs to the envelope too**, for the same reason, and that is a correction to this module's first draft.
//! A nonce authorizes *this* transfer *once*; it is replay protection, which is authorization, not value movement. Putting
//! it in the effect forced a slot the adapter could not decode — a nonce slot has to be domain-separated from an account
//! id, so it is a hash, and a hash cannot be read back to the account whose nonce it is. The complexity was the signal:
//! the nonce was in the wrong layer. So the effect moves value, the envelope authenticates `(caller, nonce)` before the
//! term runs, and `TokenLedger::apply_with_verdict` keeps doing the nonce bookkeeping on the transaction path.
//!
//! One consequence, stated because it is what an equivalence test can and cannot claim: an ERGON-executed transfer and a
//! native `apply_with_verdict` agree on **balances**, and the nonce is not the effect's business. See the tests.

use crate::naming::{MAX_NAME_LEN, MIN_NAME_LEN, NameRecord, TREASURY, name_digest, price};
use fanos_ergon::value::{Fault, Value};
use fanos_ergon::{Checked, Limits};
use fanos_pqcrypto::sig::{HYBRID_SIG_LEN, HYBRID_VK_LEN};
use fanos_pqcrypto::{HybridSigSecret, HybridSignature, HybridVerifier};
use fanos_ergon::{Effect, Expr, Footprint, Host, Key, PointId, Reader, State, Term};

use crate::hybrid::{TAG_NAME, TAG_TRANSPARENT};
use crate::token::TokenLedger;

/// The transparent-transfer effect. Numbered by its wire tag so the correspondence to the existing transaction kind is
/// mechanical rather than a mapping table someone has to maintain.
pub const EFFECT_TRANSFER: u16 = TAG_TRANSPARENT as u16;

/// Register a free name, paying the registry's price to the treasury.
///
/// **One effect, not `Seq[transfer, record]`** — and the reason generalises. The registry requires
/// `fee >= price(name, duration)`, so the payment is a *precondition of the record*, not a separable step. Split in
/// two, the record half would take the fee as an argument, and the author writes the arguments: a term could transfer
/// one coin and claim a thousand. Composition is for composing operations; the halves of one operation are not
/// separable when a condition binds them. (Where a payment is genuinely independent — a flat fee with no threshold —
/// the split is right.)
pub const EFFECT_NAME_REGISTER: u16 = TAG_NAME as u16;

/// The projective point ledger state currently lives at.
///
/// One cell, so one point. It is spelled out rather than left implicit because `Key` carries a point precisely so that
/// state can later be sharded across the plane, and `Locality` can then say whether a term is confined to a point, a
/// line's quorum, or the whole cell (`design-ergon.md` §8). Until state is sharded, every key sits here.
pub const LEDGER_POINT: PointId = 0;

/// The value space of transparent account balances.
///
/// Named rather than left as `0` because the space is what makes a footprint identify what it touches: an account and a
/// name entry may share an identifier, and without the space they would be one key — a conflict the scheduler sees that is
/// not real, and worse, a footprint that no longer says unambiguously what a term reaches. See [`Key::space`].
pub const SPACE_BALANCE: u16 = 0;

/// The value space of the shielded pool's aggregate state — a pool-wide marker, not an account.
pub const SPACE_SHIELDED: u16 = 1;
/// The value space of name-registry entries, keyed by the name's hash.
pub const SPACE_NAME: u16 = 2;
/// The value space of storage deals, keyed by deal id.
pub const SPACE_STORAGE: u16 = 3;
/// The value space of hash time-locked contracts, keyed by contract id.
pub const SPACE_HTLC: u16 = 4;

/// The key naming the shielded pool's aggregate state.
#[must_use]
pub const fn shielded_key(marker: [u8; 32]) -> Key { Key::at(LEDGER_POINT, SPACE_SHIELDED, marker) }

/// The key holding the name-registry entry for a name hash.
#[must_use]
pub const fn name_key(name_hash: [u8; 32]) -> Key { Key::at(LEDGER_POINT, SPACE_NAME, name_hash) }

/// The key holding a storage deal.
#[must_use]
pub const fn storage_key(deal: [u8; 32]) -> Key { Key::at(LEDGER_POINT, SPACE_STORAGE, deal) }

/// The key holding a hash time-locked contract.
///
/// Readable from a term (its hashlock), never writable by one: ERGON has no HTLC effect, so a term may **branch on** a
/// contract without being able to resolve it. That asymmetry is deliberate — see `LedgerState`.
#[must_use]
pub const fn htlc_key(contract: [u8; 32]) -> Key { Key::at(LEDGER_POINT, SPACE_HTLC, contract) }

/// The key holding `account`'s balance — the account id itself, which is what `access_of` already uses, now qualified by
/// its space.
#[must_use]
pub const fn balance_key(account: [u8; 32]) -> Key { Key::at(LEDGER_POINT, SPACE_BALANCE, account) }

/// A transparent transfer as an ERGON term.
///
/// `to` and `amount` are the term's own arguments; the sender is [`Expr::Arg`] `0`, bound by the runtime from the
/// authenticated envelope. The footprint names the two balance slots the rule may touch, and `Term::footprint` derives
/// the same set independently — the chain never reads this declaration, it recomputes it.
#[must_use]
pub fn transfer_term(from: [u8; 32], to: [u8; 32], amount: u64) -> Term {
    let footprint = Footprint::new(vec![], vec![balance_key(from), balance_key(to)]);
    Term::Do(Effect::internal(EFFECT_TRANSFER, footprint).with_args(vec![
        Expr::bytes32(from),
        Expr::bytes32(to),
        Expr::int(u128::from(amount)),
    ]))
}

/// A term that registers `name` — the composable form of what `TAG_NAME` does.
///
/// The footprint is written out because it is the term's *declaration* of what it touches, and `Confined` refuses any
/// access outside it: the payer's balance, the treasury's, and the name's own key. It must equal the hand-written
/// access list for this operation, which is asserted by the equivalence test.
#[must_use]
pub fn name_register_term(name: &[u8], target: &[u8], duration: u64, fee: u64, payer: [u8; 32]) -> Term {
    let footprint = Footprint::new(vec![], vec![balance_key(payer), balance_key(TREASURY), name_key(name_digest(name))]);
    Term::Do(Effect::internal(EFFECT_NAME_REGISTER, footprint).with_args(vec![
        Expr::Lit(Value::Bytes(name.to_vec())),
        Expr::Lit(Value::Bytes(target.to_vec())),
        Expr::int(u128::from(duration)),
        Expr::int(u128::from(fee)),
    ]))
}

/// The domain label the envelope's signature covers.
const TERM_LABEL: &str = "FANOS/ergon/term/v1";

/// A **term submitted as a transaction** — the envelope that makes everything above reachable from the wire.
///
/// This is where the platform's two halves meet, and the division is the one `docs/design-ergon.md` §11 step 4's
/// correction insists on: the envelope authenticates, the term describes, and the effect's own rule authorizes. The
/// signature covers the term bytes **and** the nonce, so a term is bound to one submission by one account — signing the
/// term alone would leave it replayable by anyone who saw it, and signing the nonce alone would let the bytes be swapped.
#[derive(Clone)]
pub struct SignedTerm {
    /// The canonically encoded term (`Term::encode`).
    pub term: Vec<u8>,
    /// The caller's replay counter, checked against the ledger exactly as a transfer's is.
    pub nonce: u64,
    /// The caller's public key; its `account_id` is the identity effects are authorized against.
    pub caller_key: HybridVerifier,
    /// The signature over `TERM_LABEL ‖ nonce ‖ term`.
    sig: Vec<u8>,
}

impl core::fmt::Debug for SignedTerm {
    /// Hand-written because [`HybridVerifier`] is not `Debug`, and reporting the caller's *account* is more useful than
    /// its key bytes anyway — an account id is what every other diagnostic in the ledger speaks in.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Non-exhaustive on purpose: the caller's *account* is what every other diagnostic in the ledger speaks in, and
        // the key bytes and the signature say nothing a reader can act on.
        f.debug_struct("SignedTerm")
            .field("caller", &hex4(&self.caller()))
            .field("nonce", &self.nonce)
            .field("term_bytes", &self.term.len())
            .finish_non_exhaustive()
    }
}

/// The first four bytes of an identifier, for diagnostics — the form the consensus probes already use.
fn hex4(id: &[u8; 32]) -> String {
    use core::fmt::Write as _;
    id.iter().take(4).fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

impl SignedTerm {
    fn signable(nonce: u64, term: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(TERM_LABEL.len() + 8 + term.len());
        out.extend_from_slice(TERM_LABEL.as_bytes());
        out.extend_from_slice(&nonce.to_le_bytes());
        out.extend_from_slice(term);
        out
    }

    /// Sign an encoded term for submission.
    #[must_use]
    pub fn sign(term: Vec<u8>, nonce: u64, signer: &HybridSigSecret, caller_key: HybridVerifier) -> Self {
        let sig = signer.sign(&Self::signable(nonce, &term)).to_bytes();
        Self { term, nonce, caller_key, sig }
    }

    /// The account the term acts for.
    #[must_use]
    pub fn caller(&self) -> [u8; 32] { crate::token::account_id(&self.caller_key) }

    /// Whether the signature verifies over the nonce and the exact term bytes.
    #[must_use]
    pub fn verify(&self) -> bool {
        let Some(sig) = HybridSignature::from_bytes(&self.sig) else {
            return false;
        };
        self.caller_key.verify(&Self::signable(self.nonce, &self.term), &sig)
    }

    /// Canonical bytes: `nonce(8) ‖ key ‖ sig ‖ term`, the term last so it runs to the end and needs no length prefix.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + HYBRID_VK_LEN + HYBRID_SIG_LEN + self.term.len());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.caller_key.encode());
        out.extend_from_slice(&self.sig);
        out.extend_from_slice(&self.term);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let nonce = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
        let caller_key = HybridVerifier::decode(bytes.get(8..8 + HYBRID_VK_LEN)?)?;
        let sig = bytes.get(8 + HYBRID_VK_LEN..8 + HYBRID_VK_LEN + HYBRID_SIG_LEN)?.to_vec();
        let term = bytes.get(8 + HYBRID_VK_LEN + HYBRID_SIG_LEN..)?.to_vec();
        Some(Self { term, nonce, caller_key, sig })
    }

    /// The term this envelope carries, decoded **and** type-checked, or `None` if it is neither.
    ///
    /// One function, so that decoding cannot be followed by "and then someone type-checks it" — the same reason
    /// `fanos_ergon::Checked::decode` exists.
    #[must_use]
    pub fn checked(&self, limits: &Limits) -> Option<Checked> { Checked::decode(&self.term, limits).ok() }
}

/// A [`State`] view of the **whole** hybrid ledger, routed by [`Key::space`].
///
/// The reason this exists alongside [`TokenState`] is the property a chain actually needs: consensus is on `state_root`,
/// which folds all six sub-ledgers. Showing that an ERGON-executed transfer produces the same *balances* as the native
/// rule is necessary and not sufficient — it is the identical **root** that would let `HybridLedger::apply` be replaced by
/// the term interpreter (`docs/design-ergon.md` §11 step 3) without a consensus change. So the equivalence is asserted
/// where consensus reads it.
pub struct LedgerState<'a> {
    ledger: &'a mut crate::hybrid::HybridLedger,
    /// The first write this adapter could not route, if any.
    ///
    /// Recorded rather than returned, for the reason [`fanos_ergon::Confined`] records its violations: a `Result` a host
    /// rule can discard with `let _ =` is not a guarantee, and a **silently dropped write** is the worst failure available
    /// here — the rule believes it moved value, the state says otherwise, and nothing anywhere says so. `apply_term`
    /// rejects the transaction if this is set, which is defence in depth behind its own space check: that check is what
    /// stops such a term today, and this is what stops the next caller who forgets to make one.
    unmapped: core::cell::Cell<Option<Key>>,
}

impl<'a> LedgerState<'a> {
    /// View `ledger` as ERGON state.
    pub fn new(ledger: &'a mut crate::hybrid::HybridLedger) -> Self {
        Self { ledger, unmapped: core::cell::Cell::new(None) }
    }

    /// The first key this adapter could not route, read or written.
    #[must_use]
    pub fn unmapped(&self) -> Option<Key> { self.unmapped.get() }
}

impl Reader for LedgerState<'_> {
    fn get(&self, key: &Key) -> Option<Value> {
        if key.space == SPACE_BALANCE {
            return Some(Value::Int(u128::from(self.ledger.tokens().balance(&key.slot))));
        }
        // The HTLC space is **readable and not writable**, and the asymmetry is the point: a term may branch on a
        // contract's hashlock without being able to resolve the contract, because ERGON has no HTLC effect and a `Gate`
        // cannot carry authorization (§11 step 4's correction). So `Gate(Load(htlc_key(id)) == expected, transfer)` is a
        // user-level condition over protocol state — a new capability — while the escrow stays where its own rule guards
        // it. A write here is refused and recorded by `set` below.
        if key.space == SPACE_HTLC {
            return self.ledger.htlcs().htlcs.get(&key.slot).map(|h| Value::Bytes32(h.terms().hashlock));
        }
        // The name space, readable and writable both, which the other mapped spaces are not: a name record is ordinary
        // state with no rule guarding it beyond the registry's own, and now that the registry is keyed by the same
        // digest the footprint uses (`naming::name_digest`), the key alone is enough to find it. `None` for an absent
        // name is the honest answer and not a default — `Expr::Load` turns it into `Fault::Missing`, which refuses a
        // term that assumed a name exists rather than inventing an empty record for it.
        if key.space == SPACE_NAME {
            return self.ledger.names().record_at(&key.slot).map(name_record_value);
        }
        // Every further space is a sub-ledger yet to be mapped, and `None` is the honest answer: `Expr::Load` on it becomes
        // `Fault::Missing`, which refuses the term rather than inventing a value for state this adapter cannot see. Adding
        // a space is adding a branch here. Recorded as well as refused, so a caller that ignores the fault still cannot
        // proceed as though the read succeeded.
        self.unmapped.set(self.unmapped.get().or(Some(*key)));
        None
    }
}

impl State for LedgerState<'_> {
    fn set(&mut self, key: Key, value: Value) {
        match (key.space, value.as_u64()) {
            (SPACE_BALANCE, Ok(n)) => self.ledger.tokens_mut().set_balance(key.slot, n),
            // A name write must land under the digest of the name INSIDE the record, not under whatever key the term
            // named — `put` derives the address, so a term cannot store a record at an address that does not resolve
            // to it. A key/record mismatch is therefore not a silent relocation but an unmapped write, recorded below.
            (SPACE_NAME, _) => match name_record_from(&value) {
                Some(rec) if name_digest(&rec.name) == key.slot => self.ledger.names_mut().put(rec),
                _ => self.unmapped.set(self.unmapped.get().or(Some(key))),
            },
            // A write this adapter cannot route must never vanish quietly. It is dropped — a value written to a space the
            // adapter does not understand would be a guess — and recorded, so the transaction is rejected rather than
            // committed with a rule believing it did something it did not.
            _ => self.unmapped.set(self.unmapped.get().or(Some(key))),
        }
    }
}

/// A [`State`] view of a token ledger alone: account balances, addressed by key.
pub struct TokenState<'a> {
    ledger: &'a mut TokenLedger,
}

impl<'a> TokenState<'a> {
    /// View `ledger` as ERGON state.
    pub fn new(ledger: &'a mut TokenLedger) -> Self { Self { ledger } }
}

impl Reader for TokenState<'_> {
    fn get(&self, key: &Key) -> Option<Value> {
        // Routed by the key's space, which is the whole reason `Key` carries one: this adapter answers for balances and
        // must not answer for a name entry that happens to share an identifier.
        if key.space != SPACE_BALANCE {
            return None;
        }
        // An account with no entry has balance **zero** — a fact about the ledger rather than an absence. So a balance
        // query never answers `None`, which would make `Expr::Load` on a fresh recipient a `Fault::Missing` and refuse the
        // first payment anyone ever receives.
        Some(Value::Int(u128::from(self.ledger.balance(&key.slot))))
    }
}

impl State for TokenState<'_> {
    fn set(&mut self, key: Key, value: Value) {
        if key.space == SPACE_BALANCE
            && let Ok(n) = value.as_u64()
        {
            self.ledger.set_balance(key.slot, n);
        }
    }
}

/// Why a ledger rule refused, mapped onto ERGON's fault vocabulary.
///
/// Every rejection is [`Fault::Rejected`] carrying the effect kind, because ERGON's contract with a host is that a fault
/// is *deterministic*, not that it is descriptive: a validator must reach the same verdict as every other, and the reason
/// belongs in the node's diagnostics rather than in consensus.
pub struct LedgerHost {
    /// The authenticated caller, bound into [`Expr::Arg`] `0` by the runtime.
    caller: [u8; 32],
    /// The height this term executes at.
    ///
    /// Supplied by the runtime and never by the term, for the same reason `caller` is: an effect whose conditions
    /// depend on time must not let the author choose the time. A term that could name its own height would register
    /// an expired name as free, or renew one it no longer owns.
    height: u64,
}

impl LedgerHost {
    /// A host acting for `caller` — the identity the envelope authenticated.
    #[must_use]
    pub const fn new(caller: [u8; 32], height: u64) -> Self { Self { caller, height } }

    /// The transfer rule, over evaluated arguments and a confined state view.
    ///
    /// Mirrors the value half of `TokenLedger::apply_with_verdict`: the sender must be the authenticated caller, the
    /// balance must cover the amount, and the credit must not overflow. Signature and nonce are the envelope's, per the
    /// module note.
    fn apply_transfer(&self, args: &[Value], state: &mut dyn State) -> Result<(), Fault> {
        let (from, to, amount) = match args {
            [f, t, a] => (f.as_bytes32()?, t.as_bytes32()?, a.as_u64()?),
            _ => return Err(Fault::Rejected { kind: EFFECT_TRANSFER }),
        };
        // The sender must be the authenticated caller. Without this the term's author could name any account and the
        // effect would debit it — the whole reason argument 0 is bound by the runtime.
        if from != self.caller {
            return Err(Fault::Rejected { kind: EFFECT_TRANSFER });
        }
        let from_bal = state.get(&balance_key(from)).ok_or(Fault::Rejected { kind: EFFECT_TRANSFER })?.as_u64()?;
        let to_bal = state.get(&balance_key(to)).ok_or(Fault::Rejected { kind: EFFECT_TRANSFER })?.as_u64()?;
        let debited = from_bal.checked_sub(amount).ok_or(Fault::Rejected { kind: EFFECT_TRANSFER })?;
        let credited = to_bal.checked_add(amount).ok_or(Fault::Overflow)?;
        state.set(balance_key(from), Value::Int(u128::from(debited)));
        state.set(balance_key(to), Value::Int(u128::from(credited)));
        Ok(())
    }
}

impl LedgerHost {
    /// The name-registration rule, over evaluated arguments and a confined state view.
    ///
    /// Every condition `NameRegistry::apply` enforces lives **inside** the effect, because the author writes the term
    /// and may omit a `Gate`: a protocol condition offered as a gate is a condition nobody must obey. So the length
    /// bound, the treasury payee, freeness at this height and the price floor are all checked here, and the fee is
    /// moved here too — it is a precondition of the record, so it cannot be a sibling step.
    ///
    /// One thing the algebra supplies that the hand-written path pays for: `NameRegistry::apply` deliberately
    /// validates before settling payment "so a rejected op never touches the token ledger". Under ERGON the `Journal`
    /// undoes a failed term, so ordering here is not load-bearing — the same guarantee without the discipline.
    fn apply_name_register(&self, args: &[Value], state: &mut dyn State) -> Result<(), Fault> {
        let kind = EFFECT_NAME_REGISTER;
        let [name, target, duration, fee] = args else { return Err(Fault::Rejected { kind }) };
        let (name, target) = (name.as_bytes()?, target.as_bytes()?);
        let (duration, fee) = (duration.as_u64()?, fee.as_u64()?);

        if !(MIN_NAME_LEN..=MAX_NAME_LEN).contains(&name.len()) {
            return Err(Fault::Rejected { kind });
        }
        let key = name_key(name_digest(name));
        // Free *at this height* — an expired record is not an obstacle, which is why the read does not filter expiry
        // and the comparison happens here, where the height is the runtime's rather than the term's.
        if let Some(existing) = state.get(&key)
            && name_record_from(&existing).is_some_and(|rec| self.height <= rec.expiry)
        {
            return Err(Fault::Rejected { kind });
        }
        if fee < price(name, duration) {
            return Err(Fault::Rejected { kind });
        }

        // The fee, paid by the authenticated caller to the treasury. Not a sibling `Do(transfer)`: the price check
        // above is only meaningful if this effect is the one that moves the money.
        let payer = balance_key(self.caller);
        let payee = balance_key(TREASURY);
        let from = state.get(&payer).ok_or(Fault::Rejected { kind })?.as_u64()?;
        let to = state.get(&payee).ok_or(Fault::Rejected { kind })?.as_u64()?;
        let debited = from.checked_sub(fee).ok_or(Fault::Rejected { kind })?;
        let credited = to.checked_add(fee).ok_or(Fault::Overflow)?;
        state.set(payer, Value::Int(u128::from(debited)));
        state.set(payee, Value::Int(u128::from(credited)));

        state.set(
            key,
            name_record_value(&NameRecord {
                name: name.to_vec(),
                owner: self.caller,
                target: target.to_vec(),
                expiry: self.height.saturating_add(duration),
            }),
        );
        Ok(())
    }
}

impl Host for LedgerHost {
    fn effect(&mut self, kind: u16, args: &[Value], state: &mut dyn State) -> Result<(), Fault> {
        match kind {
            EFFECT_TRANSFER => self.apply_transfer(args, state),
            EFFECT_NAME_REGISTER => self.apply_name_register(args, state),
            _ => Err(Fault::Rejected { kind }),
        }
    }

    fn predicate(&self, kind: u16, _reads: &[Key], _args: &[Value], _state: &dyn Reader) -> Result<bool, Fault> {
        // No host predicates yet: everything the transfer needs to ask is expressible as a `Predicate::Compare` over the
        // balance keys, which is the point of the expression layer. A signature check is the first real host predicate,
        // and it belongs to the envelope rather than a `Gate` — see the module note on authorization.
        Err(Fault::Rejected { kind })
    }
}

/// Field tags for a [`crate::naming::NameRecord`] as an ERGON value.
///
/// Numbered rather than positional because the encoding is canonical by tag order: adding a field later must not
/// renumber the existing ones, or every previously-stored record would decode as something else.
pub mod name_fields {
    /// The name itself — the preimage of the key the record is stored under.
    pub const NAME: u16 = 3;
    /// The owning account id.
    pub const OWNER: u16 = 0;
    /// The descriptor the name resolves to — opaque to the chain.
    pub const TARGET: u16 = 1;
    /// The height after which the name expires.
    pub const EXPIRY: u16 = 2;
}

/// A name record as an ERGON value, and back.
///
/// This pair is the proof that the value language represents the ledger's own state rather than an approximation of
/// it: if a record cannot survive the round trip byte-identically, an ERGON term writing it would silently store
/// something else, and the footprint would name a key whose contents no longer mean what the ledger thinks.
#[must_use]
pub fn name_record_value(rec: &NameRecord) -> Value {
    // `record` cannot fail here — the tags are distinct constants — but the fallible constructor is the only one, so
    // that a non-canonical record cannot be built anywhere, including here.
    Value::record(vec![
        (name_fields::NAME, Value::Bytes(rec.name.clone())),
        (name_fields::OWNER, Value::Bytes32(rec.owner)),
        (name_fields::TARGET, Value::Bytes(rec.target.clone())),
        (name_fields::EXPIRY, Value::Int(u128::from(rec.expiry))),
    ])
    .unwrap_or(Value::Int(0))
}

/// Read a name record back out of an ERGON value, or `None` if it is not one.
#[must_use]
pub fn name_record_from(v: &Value) -> Option<NameRecord> {
    Some(NameRecord {
        name: v.field(name_fields::NAME).ok()?.as_bytes().ok()?.to_vec(),
        owner: v.field(name_fields::OWNER).ok()?.as_bytes32().ok()?,
        target: v.field(name_fields::TARGET).ok()?.as_bytes().ok()?.to_vec(),
        expiry: u64::try_from(v.field(name_fields::EXPIRY).ok()?.as_int().ok()?).ok()?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_ergon::{Checked, Limits, eval};

    /// **The claim, checked rather than asserted:** an ERGON term and the hardcoded `TAG_NAME` path produce the
    /// IDENTICAL state root from the same input. Both paths exist side by side, so the equivalence is mechanical —
    /// and it is the whole justification for expressing a ledger operation as a term at all. Anything less and the
    /// term is a second implementation with its own bugs rather than the same operation, expressed.
    #[test]
    fn registering_a_name_by_term_and_by_tag_reach_the_same_state() {
        use crate::hybrid::HybridLedger;
        use crate::naming::{NameOp, NameTx};
        use crate::token::{SignedTransfer, Transfer, account_id};
        use crate::StateMachine as _;
        use fanos_pqcrypto::{HybridSigSecret, SeedRng};

        let mut rng = SeedRng::from_seed(&[0x5A; 2]);
        let (secret, public) = HybridSigSecret::generate(&mut rng);
        let actor = account_id(&public);
        let (name, target, duration) = (b"alice".to_vec(), vec![9u8, 9], 10u64);
        let fee = price(&name, duration);

        let funded = || {
            let mut t = TokenLedger::new();
            t.credit(actor, 1_000_000);
            t.credit(TREASURY, 0);
            HybridLedger::new(t)
        };

        // The hardcoded path.
        let mut by_tag = funded();
        let transfer = Transfer { from: actor, to: TREASURY, amount: fee, nonce: 0 };
        let tx = NameTx { op: NameOp::Register { name: name.clone(), target: target.clone(), duration }, payment: SignedTransfer::sign(transfer, &secret, public.clone()) };
        let outcome = <HybridLedger as crate::StateMachine>::apply(&mut by_tag, &crate::Transaction::new(HybridLedger::name_payload(&tx)));
        assert_eq!(outcome, crate::ExecOutcome::Applied, "the hardcoded path must apply, or there is nothing to compare against");

        // The same operation as a term, submitted THE SAME WAY: through its envelope and `apply`, not through a
        // bare `eval`. The first version of this test called the evaluator directly while submitting the tag through
        // the full path, so it compared a complete transaction against an inner API and duly found the difference the
        // layers between them make — the nonce the envelope maintains. An equivalence test must submit both sides
        // alike, or it measures the layers rather than the operation.
        let mut by_term = funded();
        let term = name_register_term(&name, &target, duration, fee, actor);
        let envelope = SignedTerm::sign(term.encode(), 0, &secret, public.clone());
        let outcome = <HybridLedger as crate::StateMachine>::apply(
            &mut by_term,
            &crate::Transaction::new(HybridLedger::term_payload(&envelope)),
        );
        assert_eq!(outcome, crate::ExecOutcome::Applied, "the term must apply through its envelope");

        assert_eq!(by_term.state_root(), by_tag.state_root(), "the term and the tag must reach the same state");
        assert_eq!(by_term.names().resolve(&name, 1).map(|r| r.owner), Some(actor), "and the name is registered");
    }

    /// What the whole #38 -> #39 -> #37 chain was for: a term SEES and CHANGES the real registry, addressed by the
    /// same digest the access list and the scheduler use. Before this, `SPACE_NAME` was unmapped — reads answered
    /// `None` and writes were dropped and recorded, honestly refusing rather than pretending.
    #[test]
    fn a_term_reads_and_writes_a_real_name_record_through_the_state_adapter() {
        use crate::hybrid::HybridLedger;

        let mut ledger = HybridLedger::new(TokenLedger::new());
        let rec = NameRecord { name: b"alice".to_vec(), owner: [4u8; 32], target: vec![1, 2, 3], expiry: 500 };
        ledger.names_mut().put(rec.clone());

        let key = name_key(name_digest(b"alice"));
        {
            let state = LedgerState::new(&mut ledger);
            let seen = state.get(&key).expect("a stored name is readable at its digest");
            assert_eq!(name_record_from(&seen).as_ref(), Some(&rec), "and reads back as the record it is");
            assert!(state.unmapped().is_none(), "a mapped space must not be recorded as unmapped");
            let absent = name_key(name_digest(b"nobody"));
            assert_eq!(state.get(&absent), None, "an absent name is `None`, not an invented empty record");
        }

        // A write lands in the registry, and lands under the digest of the name INSIDE the record.
        let renamed = NameRecord { expiry: 900, ..rec.clone() };
        {
            let mut state = LedgerState::new(&mut ledger);
            state.set(key, name_record_value(&renamed));
            assert!(state.unmapped().is_none(), "a well-addressed name write is routed, not dropped");
        }
        assert_eq!(ledger.names().resolve(b"alice", 800).map(|r| r.expiry), Some(900), "the registry changed");

        // A record whose own name does not hash to the key it was written at is REFUSED, not relocated: a term that
        // could store a record at an address it does not resolve to would make the footprint a fiction.
        {
            let mut state = LedgerState::new(&mut ledger);
            state.set(name_key(name_digest(b"mallory")), name_record_value(&rec));
            assert!(state.unmapped().is_some(), "a mis-addressed name write must be refused and recorded");
        }
        assert!(ledger.names().resolve(b"mallory", 100).is_none(), "and must not have landed anywhere");
    }

    /// The verification #38 set for itself: a REAL ledger record, not one shaped like it, surviving the value
    /// language byte-identically. Anything less and an ERGON term writing this record would silently store something
    /// else, while its footprint went on naming a key whose contents no longer mean what the ledger thinks.
    #[test]
    fn a_real_name_record_round_trips_through_the_value_language() {
        for target in [vec![], vec![0u8], vec![9u8; 300]] {
            let rec = NameRecord { name: b"alice".to_vec(), owner: [3u8; 32], target: target.clone(), expiry: 12_345 };
            let value = name_record_value(&rec);
            assert_eq!(name_record_from(&value).as_ref(), Some(&rec), "target of {} bytes", target.len());

            // …and through the CODEC too, which is where canonicity is enforced: a record that decodes to itself but
            // re-encodes differently would give one ledger record two contract identities.
            let bytes = fanos_ergon::codec::encode_value(&value);
            let decoded = fanos_ergon::codec::decode_value(&bytes).expect("a canonical record decodes");
            assert_eq!(decoded, value, "the encoding must round-trip");
            assert_eq!(fanos_ergon::codec::encode_value(&decoded), bytes, "and re-encode to the same bytes");
        }
    }

    const ALICE: [u8; 32] = [1u8; 32];
    const BOB: [u8; 32] = [2u8; 32];
    const CAROL: [u8; 32] = [3u8; 32];

    fn funded() -> TokenLedger {
        let mut l = TokenLedger::new();
        l.credit(ALICE, 1000);
        l
    }

    fn run(term: &Term, caller: [u8; 32], ledger: &mut TokenLedger) -> Result<(), Fault> {
        let checked = Checked::new(term.clone(), &Limits::unbounded()).expect("well typed");
        let mut host = LedgerHost::new(caller, 0);
        let mut state = TokenState::new(ledger);
        eval(&checked, &[], &mut host, &mut state).map(|_| ())
    }

    #[test]
    fn a_term_expressed_transfer_moves_the_same_value_as_the_native_rule() {
        // Step 2's whole claim: re-expressing a tag as a primitive effect loses no capability. Compared on balances only,
        // because the nonce is the envelope's — see the module note. Comparing what the layer *does* own is the honest
        // form of an equivalence test; comparing more would fail for a reason that is not a defect.
        let mut viaergon = funded();
        run(&transfer_term(ALICE, BOB, 250), ALICE, &mut viaergon).expect("the transfer applies");
        assert_eq!(viaergon.balance(&ALICE), 750);
        assert_eq!(viaergon.balance(&BOB), 250);

        let mut native = funded();
        native.set_balance(ALICE, 750);
        native.credit(BOB, 250);
        assert_eq!(viaergon.balance(&ALICE), native.balance(&ALICE), "same debit");
        assert_eq!(viaergon.balance(&BOB), native.balance(&BOB), "same credit");
    }

    #[test]
    fn an_ergon_transfer_and_the_native_rule_reach_the_identical_state_root() {
        // The property that would let step 3 happen — replacing `HybridLedger::apply` with the term interpreter — without
        // a consensus change. Consensus is on `state_root`, which folds all six sub-ledgers, so equal balances are
        // necessary and not sufficient: a term path that touched the shielded pool or the name registry as a side effect
        // would pass a balance comparison and fork the root.
        use fanos_taxis::state::StateMachine;

        let mut viaergon = crate::hybrid::HybridLedger::new(funded());
        {
            let checked = Checked::new(transfer_term(ALICE, BOB, 250), &Limits::unbounded()).expect("well typed");
            let mut host = LedgerHost::new(ALICE, 0);
            let mut state = LedgerState::new(&mut viaergon);
            eval(&checked, &[], &mut host, &mut state).expect("the transfer applies");
        }

        let mut native_tokens = funded();
        native_tokens.set_balance(ALICE, 750);
        native_tokens.credit(BOB, 250);
        let native = crate::hybrid::HybridLedger::new(native_tokens);

        assert_eq!(
            viaergon.state_root(),
            native.state_root(),
            "the term path and the native path agree where consensus reads them"
        );
    }

    #[test]
    fn an_unroutable_write_is_recorded_rather_than_dropped() {
        // Defence in depth, tested directly because the primary check in `apply_term` shields it in the live path — and
        // code a shield keeps unreachable is code nobody has run. A write to a space this adapter cannot route must not
        // vanish quietly: dropped it is (writing a guess would be worse), but recorded, so the transaction is rejected
        // instead of committing with a rule believing it moved value.
        let mut ledger = crate::hybrid::HybridLedger::new(funded());
        let stray = Key::at(LEDGER_POINT, SPACE_BALANCE + 5, ALICE);
        let mut state = LedgerState::new(&mut ledger);
        assert_eq!(state.unmapped(), None, "nothing recorded yet");
        state.set(stray, Value::Int(999));
        assert_eq!(state.unmapped(), Some(stray), "the write was recorded");
        assert_eq!(state.get(&balance_key(ALICE)), Some(Value::Int(1000)), "and it did not land anywhere");

        // A read of an unroutable key is recorded too — the footprint DROMOS scheduled on would otherwise be a footprint
        // the rule did not use, which is the same defect from the read side.
        let mut fresh = crate::hybrid::HybridLedger::new(funded());
        let reader = LedgerState::new(&mut fresh);
        assert_eq!(reader.get(&stray), None);
        assert_eq!(reader.unmapped(), Some(stray));
    }

    #[test]
    fn the_htlc_space_is_readable_and_not_writable() {
        // The asymmetry the second value space rests on, asserted where it is actually reachable. A term-level test was
        // written first and was theatre: it built a transfer effect whose footprint named an HTLC slot, and the effect was
        // refused for having no arguments at all — falsifying the write refusal left it green. No effect in this host
        // *tries* to write an HTLC slot, so the property lives in the adapter and is tested there.
        //
        // Read yes: a term may branch on a contract. Write no: ERGON has no HTLC effect and a `Gate` cannot carry
        // authorization, so reading protocol state must not become a way to change it.
        let mut ledger = crate::hybrid::HybridLedger::new(funded());
        let lock = htlc_key([3u8; 32]);
        let mut state = LedgerState::new(&mut ledger);
        assert_eq!(state.get(&lock), None, "an absent contract reads as absent, not as a value");
        assert_eq!(state.unmapped(), None, "and that is a routed answer, not an unroutable key");

        state.set(lock, Value::Bytes32([9u8; 32]));
        assert_eq!(state.unmapped(), Some(lock), "the write is refused and recorded");
    }

    #[test]
    fn a_space_this_adapter_does_not_map_reads_as_missing_rather_than_zero() {
        // The honest answer for an unmapped sub-ledger. Returning zero would let a term compute over state the adapter
        // cannot see and reach a confident wrong answer; `Fault::Missing` refuses the term instead.
        let mut ledger = crate::hybrid::HybridLedger::new(funded());
        let unmapped = Key::at(LEDGER_POINT, 7, ALICE);
        let term = Term::Do(
            Effect::internal(EFFECT_TRANSFER, Footprint::new(vec![unmapped], vec![]))
                .with_args(vec![Expr::Load(unmapped)]),
        );
        let checked = Checked::new(term, &Limits::unbounded()).expect("well typed");
        let mut host = LedgerHost::new(ALICE, 0);
        let mut state = LedgerState::new(&mut ledger);
        assert_eq!(eval(&checked, &[], &mut host, &mut state).expect_err("unmapped space"), Fault::Missing(unmapped));
    }

    #[test]
    fn the_derived_footprint_is_the_two_accounts_and_nothing_else() {
        // What DROMOS consumes. Derived by `Term::footprint` from the term — the chain never reads the declaration in
        // `transfer_term`, so this asserts the thing the scheduler will actually see.
        let fp = transfer_term(ALICE, BOB, 1).footprint();
        assert_eq!(fp.writes(), &[balance_key(ALICE), balance_key(BOB)][..].to_vec().as_slice().to_vec(), "exactly the two balances");
        assert!(fp.reads().is_empty(), "the rule reads through the same keys it writes, so no separate read set");

        // And the property that makes it useful: disjoint senders and recipients do not conflict.
        let other = transfer_term(CAROL, [9u8; 32], 1).footprint();
        assert!(fp.parallel_safe(&other), "two unrelated transfers are schedulable in parallel");
        let overlapping = transfer_term(CAROL, BOB, 1).footprint();
        assert!(fp.conflicts(&overlapping), "sharing a recipient is a conflict");
    }

    #[test]
    fn a_host_cannot_touch_a_key_the_term_did_not_name() {
        // The confinement property, from the host's side rather than the algebra's. The term declares only ALICE's
        // balance, so crediting BOB is out of bounds — and it must FAULT, not silently skip, because a rule that half
        // applies is how a ledger reaches a state no rule can produce.
        let narrow = Term::Do(
            Effect::internal(EFFECT_TRANSFER, Footprint::new(vec![], vec![balance_key(ALICE)]))
                .with_args(vec![Expr::bytes32(ALICE), Expr::bytes32(BOB), Expr::int(100)]),
        );
        let mut ledger = funded();
        let fault = run(&narrow, ALICE, &mut ledger).expect_err("must fault");
        assert_eq!(fault, Fault::OutsideFootprint(balance_key(BOB)));
        assert_eq!(ledger.balance(&ALICE), 1000, "and the debit was rolled back");
        assert_eq!(ledger.balance(&BOB), 0, "the credit never landed");
    }

    #[test]
    fn the_balance_adapter_refuses_a_key_from_another_value_space() {
        // The adapter answers for balances and must not answer for a name entry, a hashlock or a stake record that
        // happens to share an identifier. Without the space in the key those are the same key, and the adapter would hand
        // out a balance for something that is not one.
        let mut ledger = funded();
        let state = TokenState::new(&mut ledger);
        assert_eq!(state.get(&balance_key(ALICE)), Some(Value::Int(1000)), "its own space answers");
        let foreign = Key::at(LEDGER_POINT, SPACE_BALANCE + 1, ALICE);
        assert_eq!(state.get(&foreign), None, "another space does not");
    }

    #[test]
    fn only_the_authenticated_caller_can_be_debited() {
        // Argument 0 is bound by the runtime, not by the term's author. Without this check a term naming any account
        // would debit it, which is the theft vector the module note names.
        let mut ledger = funded();
        let fault = run(&transfer_term(ALICE, BOB, 100), BOB, &mut ledger).expect_err("BOB cannot spend ALICE's balance");
        assert_eq!(fault, Fault::Rejected { kind: EFFECT_TRANSFER });
        assert_eq!(ledger.balance(&ALICE), 1000, "nothing moved");
    }

    #[test]
    fn a_gate_cannot_carry_authorization_because_the_author_writes_the_term() {
        // The finding that corrects `docs/design-ergon.md` §11 step 4, pinned rather than argued.
        //
        // Step 4 proposes migrating the HTLC to `Gate(preimage_matches, release_escrow)` and retiring `TAG_HTLC`. But a
        // term is submitted by a user who chooses its structure, so the user can simply OMIT the gate and submit the
        // release alone. A `Gate` therefore gives the author's own conditional logic, atomicity with siblings, and a
        // footprint widened by the predicate's reads — and never authorization.
        //
        // Demonstrated on the rule that does hold its own check: the transfer verifies `from == caller`, so wrapping it in
        // a gate adds a condition and removing the gate does not remove the check. If authorization lived in the gate
        // instead, the ungated term below would succeed.
        let ungated = transfer_term(ALICE, BOB, 100);
        let gated = Term::Gate(
            fanos_ergon::exec::compare(fanos_ergon::Cmp::Ge, Expr::Load(balance_key(ALICE)), Expr::int(100)),
            Box::new(transfer_term(ALICE, BOB, 100)),
        );

        // The gate admits, and the transfer applies, when the caller is authorized.
        let mut allowed = funded();
        run(&gated, ALICE, &mut allowed).expect("evaluates");
        assert_eq!(allowed.balance(&BOB), 100);

        // Strip the gate and the effect's OWN check still refuses an unauthorized caller — which is what makes the rule
        // safe against a term that omits its guard.
        let mut stripped = funded();
        assert_eq!(
            run(&ungated, BOB, &mut stripped).expect_err("BOB is not ALICE"),
            Fault::Rejected { kind: EFFECT_TRANSFER }
        );
        assert_eq!(stripped.balance(&ALICE), 1000, "nothing moved");

        // And the converse, which is the load-bearing half: the gate is NOT what refused. Give the same unauthorized
        // caller the gated term with a guard that passes, and the effect still refuses.
        let mut gated_but_unauthorized = funded();
        assert_eq!(
            run(&gated, BOB, &mut gated_but_unauthorized).expect_err("the guard passes; the rule does not"),
            Fault::Rejected { kind: EFFECT_TRANSFER }
        );
        assert_eq!(gated_but_unauthorized.balance(&BOB), 0);
    }

    #[test]
    fn an_overdraft_is_refused_and_leaves_the_state_untouched() {
        let mut ledger = funded();
        let fault = run(&transfer_term(ALICE, BOB, 1001), ALICE, &mut ledger).expect_err("insufficient funds");
        assert_eq!(fault, Fault::Rejected { kind: EFFECT_TRANSFER });
        assert_eq!(ledger.balance(&ALICE), 1000);
        assert_eq!(ledger.balance(&BOB), 0);
    }

    #[test]
    fn a_composite_of_two_transfers_is_atomic() {
        // The capability step 2 exists to unlock: an atomic multi-step transition that no single tag can express. The
        // second transfer overdraws, so the first must be undone — `Seq` is documented atomic and `Journal` makes it so.
        let term = Term::Seq(vec![transfer_term(ALICE, BOB, 600), transfer_term(ALICE, CAROL, 600)]);
        let mut ledger = funded();
        let fault = run(&term, ALICE, &mut ledger).expect_err("the second leg overdraws");
        assert_eq!(fault, Fault::Rejected { kind: EFFECT_TRANSFER });
        assert_eq!(ledger.balance(&ALICE), 1000, "the first leg was rolled back");
        assert_eq!(ledger.balance(&BOB), 0);

        // And it succeeds when both legs fit — otherwise the test above would pass on a term that never works.
        let ok = Term::Seq(vec![transfer_term(ALICE, BOB, 400), transfer_term(ALICE, CAROL, 400)]);
        let mut ledger2 = funded();
        run(&ok, ALICE, &mut ledger2).expect("both legs fit");
        assert_eq!((ledger2.balance(&ALICE), ledger2.balance(&BOB), ledger2.balance(&CAROL)), (200, 400, 400));
    }

    #[test]
    fn a_gate_over_a_balance_makes_the_transfer_conditional() {
        // Expressiveness that needs no new protocol rule: "pay only if the recipient already holds something" is a
        // `Gate` over a `Compare`, and it is a transaction kind the eight tags cannot express.
        let gated = |threshold: u128| {
            Term::Gate(
                fanos_ergon::exec::compare(fanos_ergon::Cmp::Ge, Expr::Load(balance_key(BOB)), Expr::int(threshold)),
                Box::new(transfer_term(ALICE, BOB, 100)),
            )
        };
        let mut poor = funded();
        run(&gated(1), ALICE, &mut poor).expect("evaluates");
        assert_eq!(poor.balance(&BOB), 0, "BOB held nothing, so the guard refused and no value moved");

        let mut seeded = funded();
        seeded.credit(BOB, 5);
        run(&gated(1), ALICE, &mut seeded).expect("evaluates");
        assert_eq!(seeded.balance(&BOB), 105, "BOB held 5, so the guard admitted the transfer");
    }
}
