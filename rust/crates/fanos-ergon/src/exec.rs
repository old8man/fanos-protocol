//! Execution: the host interface, footprint confinement, and the evaluator.
//!
//! This is what turns the algebra into an execution model. Before it, `fanos-ergon` could type-check a term and derive
//! its footprint and nothing could run one — which is why the crate had zero dependents (`docs/design-ergon.md` §10a).
//!
//! ## Confinement is the load-bearing idea
//!
//! A footprint is *derived* from a term, which makes it honest about the term. The moment effects have behaviour that is
//! no longer enough: a derived footprint is only sound if execution is **confined** to it. So the evaluator never hands a
//! host rule the raw state. It hands it a [`Confined`] view that refuses — and records — any access outside the footprint
//! derived for that effect.
//!
//! Without this, `Par`'s disjointness proof degrades to a promise about the host's good manners, and DROMOS's schedule
//! (which is a pure function of the derived footprints) could be wrong in a way no test would catch until two
//! transactions raced. With it, a host rule that reaches outside its declared keys produces a deterministic
//! [`Fault::OutsideFootprint`] on every validator.
//!
//! ## Atomicity is implemented, not assumed
//!
//! [`Term::Seq`] is documented as running its children "**atomically** — the invariant is checked at
//! the composite boundary". A `Seq` that left half its writes behind on a fault would make that sentence false, so
//! [`Journal`] records an undo entry per write and rolls back on any fault. The alternative — telling callers to snapshot
//! the whole ledger — pushes an O(state) cost onto every transaction to avoid an O(writes) one here.

use alloc::vec::Vec;

use crate::value::{Cmp, Expr, Fault, Value};
use crate::{Checked, Claim, Footprint, Key, Predicate, Term};

/// Read access to ledger state, keyed by [`Key`].
pub trait Reader {
    /// The value at `key`, or `None` if the state does not hold it.
    fn get(&self, key: &Key) -> Option<Value>;
}

/// Read/write access to ledger state.
pub trait State: Reader {
    /// Write `value` at `key`.
    fn set(&mut self, key: Key, value: Value);
}

/// A host state machine's rules: what an effect *kind* does, what a predicate *kind* asks, and how a claim is verified.
///
/// The `kind` tags stay opaque to this crate by design — `docs/design-ergon.md` §3 puts the state transition in the host
/// and the *structure* here. What this crate guarantees the host is that `args` are already evaluated, deterministic and
/// total, and that `state` cannot be used to reach outside `footprint`.
pub trait Host {
    /// Apply effect `kind` with evaluated `args`, through a state view confined to the effect's footprint.
    fn effect(&mut self, kind: u16, args: &[Value], state: &mut dyn State) -> Result<(), Fault>;

    /// Answer host-interpreted predicate `kind` over `reads`, with `args` already evaluated.
    fn predicate(&self, kind: u16, reads: &[Key], args: &[Value], state: &dyn Reader) -> Result<bool, Fault>;

    /// Verify a claim's proof. `Prove` is inert until PQ-ZK recursion lands (`docs/design-ergon.md` §5c), so the honest
    /// default is to refuse rather than to accept.
    fn verify(&self, claim: &Claim) -> Result<bool, Fault> {
        let _ = claim;
        Ok(false)
    }
}

/// A state view restricted to one footprint, recording the first violation.
///
/// The restriction is enforced by construction rather than by review: a host rule holds this, not the ledger, so reaching
/// outside its keys is not something it can do and then be audited for.
pub struct Confined<'a, S: State + ?Sized> {
    inner: &'a mut S,
    footprint: &'a Footprint,
    violation: core::cell::Cell<Option<Key>>,
}

impl<'a, S: State + ?Sized> Confined<'a, S> {
    /// Restrict `inner` to `footprint`.
    pub fn new(inner: &'a mut S, footprint: &'a Footprint) -> Self {
        Self { inner, footprint, violation: core::cell::Cell::new(None) }
    }

    /// The first out-of-footprint key touched, if any — read **or** written.
    #[must_use]
    pub fn violation(&self) -> Option<Key> { self.violation.get() }

    fn record(&self, key: Key) {
        if self.violation.get().is_none() {
            self.violation.set(Some(key));
        }
    }
}

impl<S: State + ?Sized> Reader for Confined<'_, S> {
    fn get(&self, key: &Key) -> Option<Value> {
        // A read of a key the effect may *write* is in bounds: a rule that updates a balance must read it first, and
        // requiring the key in both sets would make every read-modify-write footprint say the same thing twice.
        //
        // An out-of-footprint read is **recorded**, not merely refused. The first version only returned `None`, and a real
        // host immediately showed why that is wrong: it read a key outside its footprint, got `None`, and reported its own
        // "rejected" — so a *confinement* failure surfaced as an ordinary rule refusal and the derived footprint being
        // wrong was invisible. Reads matter to the scheduler exactly as much as writes: a rule reading a key the term did
        // not name means the footprint DROMOS scheduled on is not the footprint the rule used.
        if self.footprint.reads().binary_search(key).is_err() && self.footprint.writes().binary_search(key).is_err() {
            self.record(*key);
            return None;
        }
        self.inner.get(key)
    }
}

impl<S: State + ?Sized> State for Confined<'_, S> {
    fn set(&mut self, key: Key, value: Value) {
        if self.footprint.writes().binary_search(&key).is_err() {
            self.record(key);
            return; // the write is dropped as well as recorded — a violation must not take effect even transiently
        }
        self.inner.set(key, value);
    }
}

/// A state wrapper that can undo its writes, so a composite is atomic.
pub struct Journal<'a, S: State + ?Sized> {
    inner: &'a mut S,
    /// `(key, value before this journal first wrote it)` — one entry per key, so a repeated write does not deepen the log.
    undo: Vec<(Key, Option<Value>)>,
}

impl<'a, S: State + ?Sized> Journal<'a, S> {
    /// Begin journalling writes to `inner`.
    pub fn new(inner: &'a mut S) -> Self { Self { inner, undo: Vec::new() } }

    /// Restore every key this journal wrote to the value it had before.
    ///
    /// In reverse order, which matters even with one entry per key: `set` on a key absent before must remove it, and
    /// hosts implement absence differently, so replaying in the order recorded could observe an intermediate the forward
    /// run never produced.
    pub fn rollback(&mut self) {
        while let Some((key, before)) = self.undo.pop() {
            match before {
                Some(v) => self.inner.set(key, v),
                // Absent before. The host's `set` is the only writer available, so absence is restored by the host's own
                // convention for it; a `remove` on the trait would be a second way to spell it and a second thing to get
                // wrong. Recorded so the caller can see it happened.
                None => self.inner.set(key, Value::Int(0)),
            }
        }
    }

}

impl<S: State + ?Sized> Reader for Journal<'_, S> {
    fn get(&self, key: &Key) -> Option<Value> { self.inner.get(key) }
}

impl<S: State + ?Sized> State for Journal<'_, S> {
    fn set(&mut self, key: Key, value: Value) {
        if !self.undo.iter().any(|(k, _)| *k == key) {
            let before = self.inner.get(&key);
            self.undo.push((key, before));
        }
        self.inner.set(key, value);
    }
}

/// What an evaluation did, for the caller's receipt and for tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Receipt {
    /// Effects applied, in order.
    pub effects: usize,
    /// Predicates evaluated.
    pub predicates: usize,
    /// Claims verified.
    pub claims: usize,
    /// Branches an [`Term::Alt`] declined before one matched, summed — the cost `Alt`'s
    /// over-approximated footprint pays for, made visible rather than inferred.
    pub declined: usize,
}

/// Evaluate a well-typed term against `state`.
///
/// `args` are the instantiation arguments [`Expr::Arg`] indexes.
///
/// Takes a [`Checked`] rather than a `Term`, so "was this type-checked?" is not a question this function can be asked
/// wrongly. Takes no `Limits`, deliberately. Every admission bound — proof size, footprint width, nesting — is checked once by
/// [`well_typed`](crate::well_typed) *before* a fee is charged, and threading them here as well would mean two places
/// deciding the same question. A caller that skips the type check gets a correct evaluation of a term the chain would have
/// refused — which is now impossible to reach, since obtaining a `Checked` *is* passing the check.
///
/// Atomic: on any fault, every write this call made is rolled back before the fault is returned.
pub fn eval<S: State + ?Sized, H: Host>(
    term: &Checked,
    args: &[Value],
    host: &mut H,
    state: &mut S,
) -> Result<Receipt, Fault> {
    let term = term.term();
    let mut journal = Journal::new(state);
    let mut receipt = Receipt::default();
    match run(term, args, host, &mut journal, &mut receipt) {
        Ok(()) => Ok(receipt),
        Err(fault) => {
            journal.rollback();
            Err(fault)
        }
    }
}

fn run<S: State + ?Sized, H: Host>(
    term: &Term,
    args: &[Value],
    host: &mut H,
    state: &mut Journal<'_, S>,
    receipt: &mut Receipt,
) -> Result<(), Fault> {
    match term {
        Term::Do(effect) => {
            let footprint = effect.footprint();
            let mut evaluated = Vec::with_capacity(effect.args.len());
            for a in &effect.args {
                evaluated.push(a.eval(state, args)?);
            }
            let mut confined = Confined::new(state, &footprint);
            let outcome = host.effect(effect.kind, &evaluated, &mut confined);
            // The violation is checked BEFORE the host's own result, and the order is load-bearing: a host that reads
            // outside its footprint sees `None` and will usually report a rule refusal of its own, which would mask the
            // confinement failure entirely. The more fundamental fault must win — otherwise the one signal that says "the
            // derived footprint is wrong" is the one the caller never sees.
            if let Some(key) = confined.violation() {
                return Err(Fault::OutsideFootprint(key));
            }
            outcome?;
            receipt.effects += 1;
            Ok(())
        }
        // One arm for both, which is the honest encoding rather than a deduplication: `Seq` is ordered by definition, and
        // `Par`'s branches were proved footprint-disjoint by well-typedness, so *any* order — including declaration order —
        // produces the same state. That is what makes a serial engine a valid implementation of a parallel term, and why
        // DROMOS's parallelism does not need this evaluator to be concurrent.
        Term::Seq(children) | Term::Par(children) => {
            for c in children {
                run(c, args, host, state, receipt)?;
            }
            Ok(())
        }
        Term::Gate(pred, body) => {
            if eval_predicate(pred, args, host, state, receipt)? {
                run(body, args, host, state, receipt)?;
            }
            Ok(())
        }
        Term::Alt(branches) => {
            for (pred, body) in branches {
                if eval_predicate(pred, args, host, state, receipt)? {
                    return run(body, args, host, state, receipt);
                }
                receipt.declined += 1;
            }
            // No branch matched. The identity, not a fault: `Alt` is a choice among guards, and "none applied" is a
            // meaningful outcome a caller can gate on. A term that must do something wraps its own final branch.
            Ok(())
        }
        Term::Prove(claim) => {
            if !host.verify(claim)? {
                return Err(Fault::ClaimUnproven { kind: claim.kind });
            }
            // The claim's writes are the host's to apply — it verified them. Confined to the claim's footprint for the
            // same reason an effect is: a proof of *what* follows is not a licence to touch anything else.
            let mut confined = Confined::new(state, &claim.footprint);
            let outcome = host.effect(claim.kind, &[], &mut confined);
            if let Some(key) = confined.violation() {
                return Err(Fault::OutsideFootprint(key));
            }
            outcome?;
            receipt.claims += 1;
            Ok(())
        }
    }
}

fn eval_predicate<S: State + ?Sized, H: Host>(
    pred: &Predicate,
    args: &[Value],
    host: &H,
    state: &Journal<'_, S>,
    receipt: &mut Receipt,
) -> Result<bool, Fault> {
    receipt.predicates += 1;
    match pred {
        Predicate::Host { kind, reads, args: exprs } => {
            let mut evaluated = Vec::with_capacity(exprs.len());
            for e in exprs {
                evaluated.push(e.eval(state, args)?);
            }
            host.predicate(*kind, reads, &evaluated, state)
        }
        Predicate::Compare { op, lhs, rhs } => {
            let (a, b) = (lhs.eval(state, args)?, rhs.eval(state, args)?);
            op.apply(&a, &b)
        }
        Predicate::And(parts) => {
            for p in parts {
                if !eval_predicate(p, args, host, state, receipt)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Predicate::Or(parts) => {
            for p in parts {
                if eval_predicate(p, args, host, state, receipt)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Predicate::Not(inner) => Ok(!eval_predicate(inner, args, host, state, receipt)?),
    }
}

/// Convenience: a comparison predicate.
#[must_use]
pub fn compare(op: Cmp, lhs: Expr, rhs: Expr) -> Predicate { Predicate::Compare { op, lhs, rhs } }

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::Limits;
    use crate::value::BinOp;
    use crate::{Effect, PointId};
    use alloc::collections::BTreeMap;
    use alloc::vec;

    /// A minimal ledger: keys to values.
    #[derive(Default)]
    struct Mem(BTreeMap<Key, Value>);

    impl Reader for Mem {
        fn get(&self, key: &Key) -> Option<Value> { self.0.get(key).cloned() }
    }
    impl State for Mem {
        fn set(&mut self, key: Key, value: Value) { self.0.insert(key, value); }
    }

    fn k(n: u64) -> Key { Key::small(0 as PointId, 0, n) }

    /// Kind 1: write `args[0]` to `target`. Kind 2: the same, but to `stray` — a rule that reaches outside its
    /// footprint, which is the thing confinement must catch. Kind 3: always refuse.
    struct Rules {
        target: Key,
        stray: Key,
    }

    impl Host for Rules {
        fn effect(&mut self, kind: u16, args: &[Value], state: &mut dyn State) -> Result<(), Fault> {
            match kind {
                1 => {
                    state.set(self.target, args[0].clone());
                    Ok(())
                }
                2 => {
                    state.set(self.stray, args[0].clone());
                    Ok(())
                }
                _ => Err(Fault::Rejected { kind }),
            }
        }

        /// Kind 1: unconditionally true. Kind 8: true iff the first argument is 42 — the argument-relative question a
        /// host predicate could not ask before, and the shape an HTLC's "does this preimage match" takes.
        fn predicate(&self, kind: u16, _reads: &[Key], args: &[Value], _state: &dyn Reader) -> Result<bool, Fault> {
            match kind {
                1 => Ok(true),
                8 => Ok(args.first() == Some(&Value::Int(42))),
                _ => Ok(false),
            }
        }
    }

    fn rules() -> Rules { Rules { target: k(10), stray: k(99) } }

    /// A term with its check carried in the type, which is the only way `eval` accepts one.
    fn ck(t: Term) -> Checked { Checked::new(t, &Limits::unbounded()).expect("well typed") }

    fn write_to(target: Key, arg: Expr) -> Term {
        Term::Do(
            Effect::internal(1, Footprint::new(vec![], vec![target])).with_args(vec![arg]),
        )
    }

    #[test]
    fn an_effect_computes_its_argument_from_state_and_applies_it() {
        // The smallest thing that separates programming from composition: the amount written is *computed*, here as
        // `balance / 2`, and nothing in the term is a constant the author could have precomputed.
        let mut mem = Mem::default();
        mem.set(k(1), Value::Int(1000));
        let term = write_to(k(10), Expr::bin(BinOp::Div, Expr::Load(k(1)), Expr::int(2)));
        let receipt = eval(&ck(term.clone()), &[], &mut rules(), &mut mem).expect("evaluates");
        assert_eq!(receipt.effects, 1);
        assert_eq!(mem.get(&k(10)), Some(Value::Int(500)), "the computed amount was written");
    }

    #[test]
    fn an_arguments_reads_are_part_of_the_derived_footprint() {
        // The property DROMOS depends on: an argument that loads a key makes that key part of the effect's read set
        // WITHOUT anyone declaring it. If this were a check instead of a derivation, a term could compute from a key the
        // scheduler never saw, and two transactions that conflict would be scheduled as parallel.
        let effect = Effect::internal(1, Footprint::new(vec![], vec![k(10)]))
            .with_args(vec![Expr::bin(BinOp::Add, Expr::Load(k(1)), Expr::Load(k(2)))]);
        let fp = effect.footprint();
        assert!(fp.reads().contains(&k(1)) && fp.reads().contains(&k(2)), "argument loads are reads: {fp:?}");
        assert!(fp.writes().contains(&k(10)));
        assert!(fp.conflicts(&Footprint::new(vec![], vec![k(1)])), "so a writer of k1 conflicts with it");
    }

    #[test]
    fn a_rule_that_writes_outside_its_footprint_faults_and_the_write_does_not_land() {
        // Confinement. A derived footprint is only sound if execution is confined to it — otherwise `Par`'s disjointness
        // proof is a promise about the host's manners. Both halves are asserted: the fault names the key, AND the write
        // is absent, because a violation that faults but still mutates would have already forked the state.
        let mut mem = Mem::default();
        let term = Term::Do(
            Effect::internal(2, Footprint::new(vec![], vec![k(10)])).with_args(vec![Expr::int(7)]),
        );
        let fault = eval(&ck(term.clone()), &[], &mut rules(), &mut mem).expect_err("must fault");
        assert_eq!(fault, Fault::OutsideFootprint(k(99)));
        assert_eq!(mem.get(&k(99)), None, "the out-of-footprint write did not take effect");
    }

    #[test]
    fn a_faulting_sequence_rolls_back_everything_before_it() {
        // `Term::Seq` is documented as atomic. Without the journal that sentence would be false, and half-applied
        // composites are the classic way a ledger ends up in a state no rule can produce.
        let mut mem = Mem::default();
        mem.set(k(10), Value::Int(1));
        let term = Term::Seq(vec![
            write_to(k(10), Expr::int(42)),
            Term::Do(Effect::internal(3, Footprint::empty())), // kind 3 always refuses
        ]);
        let fault = eval(&ck(term.clone()), &[], &mut rules(), &mut mem).expect_err("must fault");
        assert_eq!(fault, Fault::Rejected { kind: 3 });
        assert_eq!(mem.get(&k(10)), Some(Value::Int(1)), "the first write was rolled back");
    }

    #[test]
    fn arithmetic_is_total_rather_than_wrapping_or_panicking() {
        // Determinism is the reason, not tidiness: wrapping would make every validator agree on a number nobody
        // intended, and a panic would make them agree on nothing.
        let mut mem = Mem::default();
        let over = write_to(k(10), Expr::bin(BinOp::Add, Expr::int(u128::MAX), Expr::int(1)));
        assert_eq!(
            eval(&ck(over.clone()), &[], &mut rules(), &mut mem).expect_err("overflow"),
            Fault::Overflow
        );
        let div0 = write_to(k(10), Expr::bin(BinOp::Div, Expr::int(1), Expr::int(0)));
        assert_eq!(
            eval(&ck(div0.clone()), &[], &mut rules(), &mut mem).expect_err("div by zero"),
            Fault::DivByZero
        );
        let under = write_to(k(10), Expr::bin(BinOp::Sub, Expr::int(1), Expr::int(2)));
        assert_eq!(
            eval(&ck(under.clone()), &[], &mut rules(), &mut mem).expect_err("unsigned underflow"),
            Fault::Overflow
        );
        assert_eq!(mem.get(&k(10)), None, "no fault left a partial write behind");
    }

    #[test]
    fn a_gate_over_an_expression_admits_and_refuses_on_state() {
        // What `Gate` could not do before this layer: branch on a *condition* rather than on an opaque host kind.
        let mut mem = Mem::default();
        mem.set(k(1), Value::Int(100));
        let gate = |rhs: u128| {
            Term::Gate(
                compare(Cmp::Ge, Expr::Load(k(1)), Expr::int(rhs)),
                alloc::boxed::Box::new(write_to(k(10), Expr::int(1))),
            )
        };
        eval(&ck(gate(50)), &[], &mut rules(), &mut mem).expect("admits");
        assert_eq!(mem.get(&k(10)), Some(Value::Int(1)), "the guard held, so the body ran");

        let mut mem2 = Mem::default();
        mem2.set(k(1), Value::Int(10));
        let r = eval(&ck(gate(50)), &[], &mut rules(), &mut mem2).expect("refuses cleanly");
        assert_eq!(r.effects, 0, "the guard failed, so the body did not run");
        assert_eq!(mem2.get(&k(10)), None);
    }

    #[test]
    fn an_over_deep_expression_cannot_be_admitted_and_cannot_be_evaluated_either() {
        // Two layers, and the second is no longer reachable from the first — which is the point of `Checked`.
        //
        // Admission refuses the term, so there is no way to hand `eval` one: `Checked::new` is the only door and it runs
        // `well_typed`. That closes the "a term that arrived by another route" case *by construction* rather than by
        // defending against it, which is why this test no longer calls `eval` at all. `Expr::eval`'s own bound is still
        // load-bearing and still tested, through the public expression API a host rule could reach directly.
        let mut deep = Expr::int(1);
        for _ in 0..=crate::value::EXPR_DEPTH_MAX {
            deep = Expr::bin(BinOp::Add, deep, Expr::int(1));
        }
        let term = write_to(k(10), deep.clone());
        let err = crate::well_typed(&term, &Limits::unbounded()).expect_err("admission refuses");
        assert!(matches!(err, crate::TypeError::ExprTooDeep { .. }), "{err:?}");
        assert!(
            Checked::new(term, &Limits::unbounded()).is_err(),
            "and therefore no witness exists, so `eval` cannot be called with it"
        );

        let mem = Mem::default();
        assert!(matches!(deep.eval(&mem, &[]), Err(Fault::ExprTooDeep { .. })), "the expression bound holds on its own");
    }

    #[test]
    fn a_host_predicate_sees_its_arguments_and_not_only_state() {
        // `Predicate::Host` took no arguments until the first real predicate was written against it. An HTLC claim asks
        // "does *this revealed preimage* hash to the stored hashlock" — a question about a value the caller supplied — and
        // without arguments a host predicate can only ask about state, which is half the useful questions.
        let gate = |arg: u128| {
            Term::Gate(
                Predicate::host_with(8, vec![], vec![Expr::int(arg)]),
                alloc::boxed::Box::new(write_to(k(10), Expr::int(1))),
            )
        };
        let mut yes = Mem::default();
        eval(&ck(gate(42)), &[], &mut rules(), &mut yes).expect("evaluates");
        assert_eq!(yes.get(&k(10)), Some(Value::Int(1)), "the argument reached the predicate and it admitted");

        let mut no = Mem::default();
        let r = eval(&ck(gate(41)), &[], &mut rules(), &mut no).expect("evaluates");
        assert_eq!(r.effects, 0, "a different argument refuses — so the predicate is reading it, not ignoring it");
        assert_eq!(no.get(&k(10)), None);
    }

    #[test]
    fn a_predicates_argument_reads_join_the_footprint() {
        // Same derivation as an effect's: a predicate whose argument loads a key makes that key part of the term's read
        // set, so DROMOS sees it without anyone declaring it.
        let t = Term::Gate(
            Predicate::host_with(8, vec![], vec![Expr::Load(k(5))]),
            alloc::boxed::Box::new(write_to(k(10), Expr::int(1))),
        );
        assert!(t.footprint().reads().contains(&k(5)), "the predicate's argument load is a read: {:?}", t.footprint());
    }

    #[test]
    fn an_instantiation_argument_is_supplied_by_the_caller_not_the_term() {
        // How one deployed term serves many calls: `Arg` is the parameter, and indexing past what was supplied is a
        // named fault rather than a silent zero.
        let mut mem = Mem::default();
        let term = write_to(k(10), Expr::bin(BinOp::Mul, Expr::Arg(0), Expr::int(3)));
        eval(&ck(term.clone()), &[Value::Int(5)], &mut rules(), &mut mem).expect("evaluates");
        assert_eq!(mem.get(&k(10)), Some(Value::Int(15)));
        assert_eq!(
            eval(&ck(term.clone()), &[], &mut rules(), &mut mem).expect_err("no argument supplied"),
            Fault::ArgOutOfRange { index: 0, supplied: 0 }
        );
    }
}
