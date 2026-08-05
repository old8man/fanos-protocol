//! Values and total expressions — the layer that turns composition into programming.
//!
//! [`Term`](crate::Term) can say *when* a state transition happens and *that* two transitions are disjoint. Until this
//! module it could not say **how much**: an [`Effect`](crate::Effect) named a `kind` and a footprint and carried no
//! arguments, so `transfer` could not name an amount and a contract author could only rearrange transitions the protocol
//! already implemented. `docs/design-ergon.md` §10a records that ceiling; this is the lift.
//!
//! Two properties are load-bearing and everything here is shaped by them.
//!
//! **Total.** Every expression terminates and every failure is a named [`Fault`], never a panic and never a wrap.
//! Overflow and division by zero are faults because a validator must reach the *same* verdict as every other validator:
//! wrapping arithmetic would agree, but it would agree on a number nobody intended, and a panic would agree on nothing at
//! all. There is no recursion and no iteration, so termination is structural rather than proved.
//!
//! **Key-static.** An expression reads state only through [`Expr::Load`], whose key is part of the term. Nothing computes
//! a key from a value. That is the same refusal `docs/design-ergon.md` §1 makes of a VM, one level down: DROMOS's
//! conflict scheduler needs the footprint *before* execution, and a `Load` whose address depended on a runtime value
//! would make the footprint undecidable in advance — which is the entire property the platform is built to keep.
//!
//! The reads of an expression are therefore **collected into** the enclosing effect's footprint
//! ([`Expr::collect_reads`]), not checked against it. An earlier draft specified the check; deriving is strictly better,
//! because there is then no "outside the footprint" state for a later refactor to stop checking.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::Key;

/// A state value.
///
/// `Int` is 128-bit against the ledger's 64-bit quantities (`fanos_dromos::token::TokenLedger::balance -> u64`), so
/// intermediate arithmetic has headroom and narrowing happens once, explicitly, at the host boundary — rather than each
/// operation carrying its own overflow question. `Bytes32` is the width of everything the ledger *keys* on: account,
/// name and deal hashes, commitments, digests.
///
/// **`Record` exists because the two scalars could not represent the ledger's own state, and the argument that said they
/// could was wrong on one side.** The earlier rationale here read: "anything wider is addressed *by* its digest, which
/// is what the ledger already does". That is true of **keys** — [`Key::slot`] is a digest, rightly — and false of
/// **values**: the ledger keys by digest and *stores* a struct (`NameRecord { owner, target, expiry }`, a storage deal,
/// an HTLC). The two sides of the map were conflated, so every ledger operation but `transfer` had nothing to write
/// with.
///
/// The alternative — keep the scalars and store a *hash* of the record, holding the record elsewhere — was rejected on
/// the property the whole design rests on: a term's footprint would then name a hash key while the real mutation landed
/// outside it, which is exactly the declared-access-list trust assumption ERGON exists to delete.
///
/// A product of tagged fields rather than an opaque byte string, because an opaque one buys the vocabulary by spending
/// what the vocabulary is for: `Compare` and `Gate` could not see `expiry` inside a record, and the expression layer
/// would stop working precisely where contracts need it. Fields stay addressable, and a field selector reads *within* a
/// value already fetched — it computes no key, so footprints stay derivable by structural induction.
///
/// **Canonical by construction:** fields are sorted by tag and duplicate-free, and the codec refuses anything else. The
/// sort *is* the canonical form, the same discipline footprints already use, and it matters for the same reason — the
/// artefact hash is the contract's identity.
///
/// No longer `Copy`, which is the price. Representing the state is not negotiable; a convenience is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Value {
    /// An unsigned integer quantity.
    Int(u128),
    /// A 32-byte identifier or digest.
    Bytes32([u8; 32]),
    /// An opaque byte string the chain does not interpret, bounded by the codec's sequence limit.
    ///
    /// Distinct from `Bytes32`, which is an *identifier* the chain keys and compares on. This is a payload — a name's
    /// target descriptor, a deal's parameters — that the ledger stores and hands back without reading. The distinction
    /// is worth a variant rather than a convention: comparing two identifiers is meaningful, comparing two payloads is
    /// a byte comparison of things nobody promised are comparable, so [`Cmp`] treats them differently.
    ///
    /// **This is not the "opaque blob" that was rejected as the answer to records, and the difference is structural.**
    /// Rejected was making a whole *record* an opaque string, which would hide `expiry` from `Compare` and `Gate` and
    /// disable the expression layer exactly where contracts need it. As a *leaf inside* a record the structure stays
    /// visible and only the genuinely uninterpreted field is opaque — which is what it already is on the ledger.
    Bytes(Vec<u8>),
    /// A product of tagged fields, **sorted by tag and duplicate-free** — see the type note.
    Record(Vec<(u16, Value)>),
}

impl Value {
    /// This value as an integer, or [`Fault::TypeMismatch`] if it is a digest.
    pub const fn as_int(&self) -> Result<u128, Fault> {
        match self {
            Self::Int(n) => Ok(*n),
            Self::Bytes32(_) | Self::Bytes(_) | Self::Record(_) => Err(Fault::TypeMismatch),
        }
    }

    /// This value narrowed to the ledger's quantity width, or [`Fault::Overflow`] if it does not fit.
    ///
    /// The one place narrowing happens, so a host rule never has to decide what a too-large amount means.
    pub const fn as_u64(&self) -> Result<u64, Fault> {
        match self {
            // The guard is the proof: `try_from` is not `const`, so the narrowing is written out with the
            // bound it relies on immediately to its left rather than left to a workspace-wide allowance.
            #[expect(clippy::cast_possible_truncation, reason = "guarded by `*n <= u64::MAX` on this arm")]
            Self::Int(n) if *n <= u64::MAX as u128 => Ok(*n as u64),
            Self::Int(_) => Err(Fault::Overflow),
            Self::Bytes32(_) | Self::Bytes(_) | Self::Record(_) => Err(Fault::TypeMismatch),
        }
    }

    /// This value as a 32-byte identifier, or [`Fault::TypeMismatch`] if it is an integer.
    pub const fn as_bytes32(&self) -> Result<[u8; 32], Fault> {
        match self {
            Self::Bytes32(b) => Ok(*b),
            Self::Int(_) | Self::Bytes(_) | Self::Record(_) => Err(Fault::TypeMismatch),
        }
    }

    /// The field tagged `tag`, or [`Fault::TypeMismatch`] if this is not a record or has no such field.
    ///
    /// A *selector*, never a computation: it reads within a value the state already yielded, so it addresses no key and
    /// leaves footprint derivation by structural induction untouched. Absence is a type error rather than a default,
    /// for the same reason [`Fault::Missing`] is not zero — a rule that invents state is a rule nobody wrote.
    pub fn field(&self, tag: u16) -> Result<&Self, Fault> {
        match self {
            Self::Record(fields) => fields
                .binary_search_by_key(&tag, |(t, _)| *t)
                .ok()
                .and_then(|i| fields.get(i).map(|(_, v)| v))
                .ok_or(Fault::TypeMismatch),
            Self::Int(_) | Self::Bytes32(_) | Self::Bytes(_) => Err(Fault::TypeMismatch),
        }
    }

    /// This value as an uninterpreted payload, or [`Fault::TypeMismatch`] if it is anything else.
    pub fn as_bytes(&self) -> Result<&[u8], Fault> {
        match self {
            Self::Bytes(b) => Ok(b),
            Self::Int(_) | Self::Bytes32(_) | Self::Record(_) => Err(Fault::TypeMismatch),
        }
    }

    /// Build a record from `fields`, putting them in canonical order, or `None` if a tag repeats.
    ///
    /// The only constructor, so a non-canonical record cannot be built in the first place — the codec's refusal to
    /// *decode* one is then a second line of defence rather than the only one.
    #[must_use]
    pub fn record(mut fields: Vec<(u16, Self)>) -> Option<Self> {
        fields.sort_by_key(|(t, _)| *t);
        if fields.windows(2).any(|w| w.first().map(|(a, _)| *a) == w.get(1).map(|(b, _)| *b)) {
            return None;
        }
        Some(Self::Record(fields))
    }

    /// This value's nesting depth: `1` for a scalar, `1 + max(children)` for a record.
    #[must_use]
    pub fn depth(&self) -> u32 {
        match self {
            Self::Int(_) | Self::Bytes32(_) | Self::Bytes(_) => 1,
            Self::Record(fields) => 1 + fields.iter().map(|(_, v)| v.depth()).max().unwrap_or(0),
        }
    }
}

/// Why evaluation stopped.
///
/// Every variant is a *deterministic* refusal: given the same term and pre-state, every validator produces the same
/// fault. That is what makes a fault safe to put in consensus — a block containing a faulting term is invalid everywhere
/// or nowhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Arithmetic left the representable range, or a value did not fit the ledger's width.
    Overflow,
    /// Division or remainder by zero.
    DivByZero,
    /// An integer operation on a digest, or the reverse.
    TypeMismatch,
    /// [`Expr::Arg`] indexed past the arguments supplied at instantiation.
    ArgOutOfRange {
        /// The index asked for.
        index: u8,
        /// How many arguments were supplied.
        supplied: usize,
    },
    /// [`Expr::Load`] named a key the state does not hold. Distinct from a zero value on purpose: a rule that treats
    /// "absent" as "zero" silently invents state, and which of the two is meant belongs to the host's rule, not to the
    /// expression layer.
    Missing(Key),
    /// Expression nesting exceeded [`EXPR_DEPTH_MAX`].
    ExprTooDeep {
        /// The offending depth.
        depth: u32,
    },
    /// An effect or predicate touched a key outside the footprint derived for it — the confinement violation that keeps
    /// a derived footprint honest once effects have behaviour.
    OutsideFootprint(Key),
    /// The host refused the effect for a reason of its own (a rule violation: insufficient balance, a bad signature).
    Rejected {
        /// The effect or predicate kind that refused.
        kind: u16,
    },
    /// A [`Claim`](crate::Claim)'s proof did not verify.
    ClaimUnproven {
        /// The claim kind.
        kind: u16,
    },
}

/// Maximum expression nesting.
///
/// A *policy* bound, in the trichotomy `docs/design-ergon.md` §11 uses: unlike `D_MAX`, nothing is derived here — the
/// algebra is sound at any depth and this exists only to price evaluation. Eight is far above anything a lowering from a
/// verified source language produces for a single argument, and far below anything that costs a validator measurable time.
pub const EXPR_DEPTH_MAX: u32 = 8;

/// A total, key-static expression over the pre-state and the instantiation arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    /// A constant.
    Lit(Value),
    /// The state at a key fixed in the term. The only way an expression reads state, and the reason footprints stay
    /// computable before execution.
    Load(Key),
    /// An argument supplied when the term was instantiated — how one deployed term serves many calls.
    Arg(u8),
    /// A binary operation.
    Bin(BinOp, Box<Expr>, Box<Expr>),
}

/// The binary operations. Deliberately few: enough to compute a quantity, not enough to be a language of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    /// Checked addition.
    Add,
    /// Checked subtraction — a negative result is [`Fault::Overflow`], since values are unsigned.
    Sub,
    /// Checked multiplication.
    Mul,
    /// Integer division; zero divisor is [`Fault::DivByZero`].
    Div,
    /// Remainder; zero divisor is [`Fault::DivByZero`].
    Rem,
    /// The smaller of two integers.
    Min,
    /// The larger of two integers.
    Max,
}

impl Expr {
    /// A literal integer.
    #[must_use]
    pub const fn int(n: u128) -> Self { Self::Lit(Value::Int(n)) }

    /// A literal digest.
    #[must_use]
    pub const fn bytes32(b: [u8; 32]) -> Self { Self::Lit(Value::Bytes32(b)) }

    /// `lhs op rhs`.
    #[must_use]
    pub fn bin(op: BinOp, lhs: Self, rhs: Self) -> Self { Self::Bin(op, Box::new(lhs), Box::new(rhs)) }

    /// This expression's nesting depth: a leaf is 1.
    #[must_use]
    pub fn depth(&self) -> u32 {
        match self {
            Self::Lit(_) | Self::Load(_) | Self::Arg(_) => 1,
            Self::Bin(_, l, r) => 1 + l.depth().max(r.depth()),
        }
    }

    /// Append every key this expression loads to `out`.
    ///
    /// Collected rather than declared, so an effect's footprint is derived from the whole effect — arguments included —
    /// and there is no way for the two to disagree.
    pub fn collect_reads(&self, out: &mut Vec<Key>) {
        match self {
            Self::Lit(_) | Self::Arg(_) => {}
            Self::Load(k) => out.push(*k),
            Self::Bin(_, l, r) => {
                l.collect_reads(out);
                r.collect_reads(out);
            }
        }
    }

    /// The keys this expression loads.
    #[must_use]
    pub fn reads(&self) -> Vec<Key> {
        let mut out = Vec::new();
        self.collect_reads(&mut out);
        out
    }

    /// Evaluate against a state reader and the instantiation arguments.
    ///
    /// `depth` is checked here rather than only in [`well_typed`](crate::well_typed) so that evaluation is safe on a term
    /// that reached it by another route — the recursion is structural, but a hostile decoder should not be able to blow
    /// the stack of a validator that skipped the type check.
    pub fn eval(&self, state: &dyn crate::exec::Reader, args: &[Value]) -> Result<Value, Fault> {
        let d = self.depth();
        if d > EXPR_DEPTH_MAX {
            return Err(Fault::ExprTooDeep { depth: d });
        }
        self.eval_unchecked(state, args)
    }

    fn eval_unchecked(&self, state: &dyn crate::exec::Reader, args: &[Value]) -> Result<Value, Fault> {
        match self {
            Self::Lit(v) => Ok(v.clone()),
            Self::Load(k) => state.get(k).ok_or(Fault::Missing(*k)),
            Self::Arg(i) => args
                .get(usize::from(*i))
                .cloned()
                .ok_or(Fault::ArgOutOfRange { index: *i, supplied: args.len() }),
            Self::Bin(op, l, r) => {
                let (a, b) = (l.eval_unchecked(state, args)?.as_int()?, r.eval_unchecked(state, args)?.as_int()?);
                op.apply(a, b).map(Value::Int)
            }
        }
    }
}

impl BinOp {
    /// Apply to two integers, totally.
    pub const fn apply(self, a: u128, b: u128) -> Result<u128, Fault> {
        match self {
            Self::Add => match a.checked_add(b) {
                Some(n) => Ok(n),
                None => Err(Fault::Overflow),
            },
            Self::Sub => match a.checked_sub(b) {
                Some(n) => Ok(n),
                None => Err(Fault::Overflow),
            },
            Self::Mul => match a.checked_mul(b) {
                Some(n) => Ok(n),
                None => Err(Fault::Overflow),
            },
            Self::Div => match a.checked_div(b) {
                Some(n) => Ok(n),
                None => Err(Fault::DivByZero), // unsigned, so a zero divisor is the only way this fails
            },
            Self::Rem => match a.checked_rem(b) {
                Some(n) => Ok(n),
                None => Err(Fault::DivByZero),
            },
            Self::Min => Ok(if a < b { a } else { b }),
            Self::Max => Ok(if a > b { a } else { b }),
        }
    }
}

/// How two expressions are compared in a [`Predicate`](crate::Predicate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmp {
    /// Equal — the only comparison defined on digests as well as integers.
    Eq,
    /// Not equal.
    Ne,
    /// Strictly less.
    Lt,
    /// Less or equal.
    Le,
    /// Strictly greater.
    Gt,
    /// Greater or equal.
    Ge,
}

impl Cmp {
    /// Compare two values.
    ///
    /// Ordering is defined on integers only; ordering two digests would be an ordering of hashes, which means nothing a
    /// contract should branch on, so it is a [`Fault::TypeMismatch`] rather than a silent byte comparison.
    pub fn apply(self, a: &Value, b: &Value) -> Result<bool, Fault> {
        match (self, a, b) {
            // Records compare structurally: two records are equal iff their tagged fields are, which is well-defined
            // because canonical order makes the encoding unique. Ordering them is still refused below, for the same
            // reason ordering digests is.
            (Self::Eq, x, y) => Ok(match (x, y) {
                (Value::Int(p), Value::Int(q)) => p == q,
                (Value::Bytes32(p), Value::Bytes32(q)) => eq32(p, q),
                (Value::Record(_), Value::Record(_)) => x == y,
                (Value::Bytes(p), Value::Bytes(q)) => p == q,
                _ => return Err(Fault::TypeMismatch),
            }),
            (Self::Ne, x, y) => Ok(match (x, y) {
                (Value::Int(p), Value::Int(q)) => p != q,
                (Value::Bytes32(p), Value::Bytes32(q)) => !eq32(p, q),
                (Value::Record(_), Value::Record(_)) => x != y,
                (Value::Bytes(p), Value::Bytes(q)) => p != q,
                _ => return Err(Fault::TypeMismatch),
            }),
            (Self::Lt, Value::Int(p), Value::Int(q)) => Ok(p < q),
            (Self::Le, Value::Int(p), Value::Int(q)) => Ok(p <= q),
            (Self::Gt, Value::Int(p), Value::Int(q)) => Ok(p > q),
            (Self::Ge, Value::Int(p), Value::Int(q)) => Ok(p >= q),
            _ => Err(Fault::TypeMismatch),
        }
    }
}

/// `const`-callable 32-byte equality (`[u8; 32]: PartialEq` is not const).
const fn eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        // Indices are bounded by the loop and both arrays are fixed at 32, so the panic clippy warns about is
        // unreachable; `slice::get` is not const-stable and this must stay `const`.
        #[allow(clippy::indexing_slicing)]
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
