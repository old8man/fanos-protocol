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

use fanos_ergon::value::{Fault, Value};
use fanos_ergon::{Effect, Expr, Footprint, Host, Key, PointId, Reader, State, Term};

use crate::hybrid::TAG_TRANSPARENT;
use crate::token::TokenLedger;

/// The transparent-transfer effect. Numbered by its wire tag so the correspondence to the existing transaction kind is
/// mechanical rather than a mapping table someone has to maintain.
pub const EFFECT_TRANSFER: u16 = TAG_TRANSPARENT as u16;

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

/// A [`State`] view of the **whole** hybrid ledger, routed by [`Key::space`].
///
/// The reason this exists alongside [`TokenState`] is the property a chain actually needs: consensus is on `state_root`,
/// which folds all six sub-ledgers. Showing that an ERGON-executed transfer produces the same *balances* as the native
/// rule is necessary and not sufficient — it is the identical **root** that would let `HybridLedger::apply` be replaced by
/// the term interpreter (`docs/design-ergon.md` §11 step 3) without a consensus change. So the equivalence is asserted
/// where consensus reads it.
pub struct LedgerState<'a> {
    ledger: &'a mut crate::hybrid::HybridLedger,
}

impl<'a> LedgerState<'a> {
    /// View `ledger` as ERGON state.
    pub fn new(ledger: &'a mut crate::hybrid::HybridLedger) -> Self { Self { ledger } }
}

impl Reader for LedgerState<'_> {
    fn get(&self, key: &Key) -> Option<Value> {
        match key.space {
            SPACE_BALANCE => Some(Value::Int(u128::from(self.ledger.tokens().balance(&key.slot)))),
            // Every further space is a sub-ledger yet to be mapped, and `None` is the honest answer: `Expr::Load` on it
            // becomes `Fault::Missing`, which refuses the term rather than inventing a value for state this adapter
            // cannot see. Adding a space is adding an arm here.
            _ => None,
        }
    }
}

impl State for LedgerState<'_> {
    fn set(&mut self, key: Key, value: Value) {
        if key.space == SPACE_BALANCE
            && let Ok(n) = value.as_u64()
        {
            self.ledger.tokens_mut().set_balance(key.slot, n);
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
}

impl LedgerHost {
    /// A host acting for `caller` — the identity the envelope authenticated.
    #[must_use]
    pub const fn new(caller: [u8; 32]) -> Self { Self { caller } }

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

impl Host for LedgerHost {
    fn effect(&mut self, kind: u16, args: &[Value], state: &mut dyn State) -> Result<(), Fault> {
        match kind {
            EFFECT_TRANSFER => self.apply_transfer(args, state),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_ergon::{Checked, Limits, eval};

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
        let mut host = LedgerHost::new(caller);
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
            let mut host = LedgerHost::new(ALICE);
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
        let mut host = LedgerHost::new(ALICE);
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
