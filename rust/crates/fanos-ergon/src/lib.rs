//! # ERGON — the FANOS execution model
//!
//! ἔργον — *work, deed, that which is done.*
//!
//! A transaction is not a program. It is a **claim about a state transition, accompanied by evidence** — either a bounded
//! total term a validator re-executes, or a proof it verifies. One model, two evidence regimes. The design derivation is
//! `docs/design-ergon.md`; this crate is its sans-I/O core: the term algebra, the derived footprint, well-typedness, and
//! the closure induction. It knows nothing about a ledger, a wire format, or a clock.
//!
//! ## Why an algebra rather than a virtual machine
//!
//! DROMOS's parallelism — the platform's throughput claim — rests on each transaction's **footprint** (the state keys it
//! reads and writes) being computable *before* execution: a scheduling wave is conflict-free precisely because footprints
//! are known in advance. A stack or WASM VM computes its storage keys at run time, so the footprint becomes undecidable
//! ahead of execution and the scheduler must either over-approximate (everything conflicts, and the claim evaporates) or
//! speculate and roll back. Adopting a VM would not *add* expressiveness to FANOS; it would **spend** a structural
//! property the platform already has in order to buy a familiar one.
//!
//! So footprints here are **derived by structural induction** on the term ([`Term::footprint`]) rather than declared by
//! the submitter. That deletes a trust assumption rather than mitigating it: today a wrong declared access list is a
//! consensus fault, and under ERGON there is nothing to declare.
//!
//! ## Why there is no gas
//!
//! Gas is not a cost model — it is a bound on a computation whose termination could not be proven. ERGON terms are finite
//! trees whose depth is bounded (see [`D_MAX`]), so [`Term::cost`] is a pure function of the term, computable without
//! executing it. A transaction is therefore priced *at admission* and can never exhaust a budget mid-flight: there is no
//! out-of-gas state, no refund rule, and no revert semantics to get wrong.
//!
//! ## Where the depth bound comes from
//!
//! Not from engineering taste. The platform's ontology (SYNARC-Ω, Theorem K.5, the *composition ceiling*) scales the
//! order-`m` viability threshold as `P_crit^[m] = P_crit · 3^(m-1)/(m+1)` with `P_crit = 2/7`, giving `1/7`, `2/7`,
//! `9/14`, and then `P_crit^[4] = 54/35 > 1` — beyond the mathematical maximum. A fourth-order composite is
//! *arithmetically foreclosed*, and unbounded growth is available only **horizontally**: more effects at a level, richer
//! federation, never deeper nesting. [`D_MAX`] is that theorem, and it is not a tunable.
//!
//! ## What composition means
//!
//! Imported from the ecology-bus contract (SYNARC-Ω Definition U.14, B1–B3): influence between levels passes through a
//! **gate, not a message**; a parent's safety filter clamps its children, so safety composes *downward*; and conflicts
//! resolve **lexicographically**, parent invariant over child preference. That is why ERGON has no reentrancy class —
//! there is no call, so nothing can re-enter, and influence flows one way through a predicate.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// The maximum nesting depth of a well-typed term — **three**, and not a configuration knob.
///
/// SYNARC-Ω Theorem K.5 (the composition ceiling) scales the order-`m` viability threshold as
/// `P_crit^[m] = P_crit · 3^(m-1)/(m+1)` with `P_crit = 2/7`:
///
/// | order `m` | `P_crit^[m]` | reading |
/// |---|---|---|
/// | 1 | `1/7` | the purity of the maximally mixed state — a first-order self-model is free |
/// | 2 | `2/7` | baseline |
/// | 3 | `9/14` | the last admissible rung |
/// | 4 | `54/35 > 1` | **exceeds the mathematical maximum — foreclosed** |
///
/// So depth is capped by arithmetic rather than by resources: no amount of hardware admits a fourth order. Expressiveness
/// is therefore *horizontal* — unbounded breadth of composed effects at a level — which is exactly the growth axis K.5
/// leaves open. `verify_composition_ceiling` in the tests recomputes the ladder rather than trusting this table.
pub const D_MAX: u8 = 3;

/// A projective point's index in the plane's canonical enumeration — where a piece of state *lives*.
///
/// FANOS state is geometrically placed (`spec/protocol.md` §L4: `target = MapToPoint(H_storage(key))`), so a state key
/// that does not carry its point is a **lossy type**. Carrying it is what makes [`Footprint::locality`] computable, and
/// hence what turns the plane's incidence structure into a scheduling resource rather than a diagram.
pub type PointId = u32;
/// A projective line's index — the unit a quorum, a replica set, and a shard all coincide with.
pub type LineId = u32;

/// A state key an effect touches: *where* it lives, and *which* slot at that point.
///
/// The algebra remains ignorant of what a slot **means**, so it can be proven once and reused by any state machine; but it
/// is deliberately *not* ignorant of placement, because placement is what decides whether two effects can run on
/// different machines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Key {
    /// The projective point this state lives at.
    pub point: PointId,
    /// The slot at that point.
    pub slot: u64,
}

impl Key {
    /// A key at `point`, slot `slot`.
    #[must_use]
    pub const fn at(point: PointId, slot: u64) -> Self { Self { point, slot } }
}

/// How *localised* a term's state access is — the geometric reading of a footprint, and the axis of parallelism that
/// DROMOS's conflict DAG cannot see.
///
/// DROMOS parallelises **within** a cell: given the committed order, non-conflicting transactions run concurrently on one
/// machine. Locality is the orthogonal question — *which machines need be involved at all* — and it is answerable only
/// because a [`Key`] carries its point.
///
/// This is the shape modality `Π` of the ontology read at the ledger level. In SYNARC-Ω's operational semantics `Π` is
/// literally `decompose_fano_lines`: the path-connected components of a holon "are precisely the set of seven Fano-line
/// projections". Decomposing a footprint into its line components is not an analogy to that operation, it is that
/// operation applied to ledger state, which is why the reading is worth stating rather than decorating with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locality {
    /// Touches nothing.
    Empty,
    /// Confined to a single point — the tightest case: one node holds everything the term needs.
    Point(PointId),
    /// Confined to a single line: executable entirely within that line's quorum, so the term is **shardable** and needs
    /// no cell-wide coordination.
    Line(LineId),
    /// Spread across points that share no line — inherently cell-wide.
    ///
    /// By the dual Steiner property any two distinct lines of `PG(2,q)` meet in exactly one point, so a `PlaneWide`
    /// footprint conflicts with every other `PlaneWide` footprint on at least one point. That makes plane-wide access the
    /// **pessimal** case structurally rather than by bad luck, and it is why an effect should own points, not lines.
    PlaneWide,
}

/// The state keys a term reads and writes — the input DROMOS's conflict scheduler consumes.
///
/// Derived, never declared. Two terms conflict iff one writes a key the other reads or writes; read–read never conflicts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Footprint {
    reads: Vec<Key>,
    writes: Vec<Key>,
}

impl Footprint {
    /// The empty footprint — touches nothing, conflicts with nothing.
    #[must_use]
    pub const fn empty() -> Self { Self { reads: Vec::new(), writes: Vec::new() } }

    /// A footprint over the given reads and writes, normalised (sorted, deduplicated).
    ///
    /// Normalisation is not cosmetic: footprint equality and the disjointness check below are used inside well-typedness,
    /// so two spellings of the same footprint must not produce two different verdicts.
    #[must_use]
    pub fn new(mut reads: Vec<Key>, mut writes: Vec<Key>) -> Self {
        reads.sort_unstable();
        reads.dedup();
        writes.sort_unstable();
        writes.dedup();
        Self { reads, writes }
    }

    /// The keys read, sorted and deduplicated.
    #[must_use]
    pub fn reads(&self) -> &[Key] { &self.reads }

    /// The keys written, sorted and deduplicated.
    #[must_use]
    pub fn writes(&self) -> &[Key] { &self.writes }

    /// The total number of distinct keys touched — the quantity an admission cap bounds.
    #[must_use]
    pub fn width(&self) -> usize { self.reads.len() + self.writes.len() }

    /// The union of two footprints.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut reads = self.reads.clone();
        reads.extend_from_slice(&other.reads);
        let mut writes = self.writes.clone();
        writes.extend_from_slice(&other.writes);
        Self::new(reads, writes)
    }

    /// Whether these two footprints **conflict**: one writes a key the other reads or writes.
    ///
    /// Read–read is not a conflict, which is the whole reason parallelism is available at all.
    #[must_use]
    pub fn conflicts(&self, other: &Self) -> bool {
        intersects(&self.writes, &other.writes)
            || intersects(&self.writes, &other.reads)
            || intersects(&self.reads, &other.writes)
    }

    /// Whether these footprints may run **in parallel**: no write of either touches anything of the other.
    ///
    /// This is the precondition [`Term::Par`] must satisfy to be well-typed, and it is checked structurally rather than
    /// promised by the submitter.
    #[must_use]
    pub fn parallel_safe(&self, other: &Self) -> bool { !self.conflicts(other) }

    /// The distinct projective points this footprint touches, ascending — the `Π` decomposition's input.
    #[must_use]
    pub fn points(&self) -> Vec<PointId> {
        let mut ps: Vec<PointId> =
            self.reads.iter().chain(self.writes.iter()).map(|k| k.point).collect();
        ps.sort_unstable();
        ps.dedup();
        ps
    }

    /// This footprint's [`Locality`], given an incidence oracle that answers "do these points lie on a common line, and
    /// which?".
    ///
    /// The oracle is a parameter rather than an implementation because incidence belongs to `fanos-geometry`: this crate
    /// must stay a `no_std` algebra with no plane baked in, and a plane-agnostic algebra is what lets the same proofs hold
    /// for every `q`. One closure is the whole coupling.
    #[must_use]
    pub fn locality(&self, common_line: impl Fn(&[PointId]) -> Option<LineId>) -> Locality {
        let ps = self.points();
        match ps.as_slice() {
            [] => Locality::Empty,
            [only] => Locality::Point(*only),
            many => common_line(many).map_or(Locality::PlaneWide, Locality::Line),
        }
    }
}

/// Whether two sorted, deduplicated key slices share an element. Linear merge, no allocation.
fn intersects(a: &[Key], b: &[Key]) -> bool {
    let (mut i, mut j) = (0usize, 0usize);
    while let (Some(&x), Some(&y)) = (a.get(i), b.get(j)) {
        match x.cmp(&y) {
            core::cmp::Ordering::Equal => return true,
            core::cmp::Ordering::Less => i += 1,
            core::cmp::Ordering::Greater => j += 1,
        }
    }
    false
}

/// A primitive effect: the leaf of a term, and the *only* place a state transition is defined.
///
/// The `kind` is an opaque tag a host state machine interprets (the eight existing ledger rules become eight kinds), and
/// the footprint is part of the effect's **type** rather than a claim about it. `Extern` marks an effect whose consequence
/// reaches outside the ledger.
///
/// The `Extern` distinction is imported from SYNARC-Ω Definition U.8, which types effectors as *state-actuating* (fully
/// governed by the mathematics) versus *symbol-emitting* (world-effects that are "semantic and invisible at Γ-granularity"
/// and need a screen **outside** the core — a deployment obligation, not a theorem). ERGON governs an `Extern` effect's
/// *ledger* consequence only, and says so rather than implying more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effect {
    /// The host-interpreted effect kind.
    pub kind: u16,
    /// The keys this effect reads and writes — part of its type.
    pub footprint: Footprint,
    /// Whether the effect's consequence escapes the ledger (see the type note above).
    pub external: bool,
}

impl Effect {
    /// A ledger-internal effect of the given kind over the given footprint.
    #[must_use]
    pub const fn internal(kind: u16, footprint: Footprint) -> Self {
        Self { kind, footprint, external: false }
    }

    /// An effect whose consequence escapes the ledger; the algebra guards its ledger half only.
    #[must_use]
    pub const fn external(kind: u16, footprint: Footprint) -> Self {
        Self { kind, footprint, external: true }
    }
}

/// A predicate over the **pre-state**, used to gate a sub-term.
///
/// It is a *gate*, not a message (SYNARC-Ω Definition U.14 B1): a composite never hands state to a child to mutate, it
/// only admits or refuses the child based on what it reads. That one-way flow is why there is no reentrancy to reason
/// about — a child cannot re-enter its parent, because influence has no upward path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Predicate {
    /// The host-interpreted predicate kind.
    pub kind: u16,
    /// The keys the predicate reads. A predicate never writes — that is what makes it a gate.
    pub reads: Vec<Key>,
}

impl Predicate {
    /// A predicate of the given kind over the given read set.
    #[must_use]
    pub fn new(kind: u16, mut reads: Vec<Key>) -> Self {
        reads.sort_unstable();
        reads.dedup();
        Self { kind, reads }
    }

    /// This predicate's footprint: its reads, and no writes.
    #[must_use]
    pub fn footprint(&self) -> Footprint { Footprint::new(self.reads.clone(), Vec::new()) }
}

/// A claim about an off-chain computation, to be **verified** rather than re-executed: given `footprint.reads`, the
/// declared writes follow.
///
/// This is the shape OBOLOS already uses for *value* — a shielded spend is a claim that these nullifiers are fresh and
/// value is conserved — generalised from value to arbitrary state. Expressiveness is unbounded and on-chain cost is one
/// verification, while the footprint survives contact with arbitrary computation because it is *proven*, not trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// The host-interpreted proof system / statement kind.
    pub kind: u16,
    /// The read and write sets the proof attests to.
    pub footprint: Footprint,
    /// The proof's size in bytes, which is what a verifier's cost is a function of.
    ///
    /// Carried in the claim rather than measured from the proof so that [`Term::cost`] stays a pure function of the term,
    /// and so admission can cap it *before* touching the proof. Bounding the claim rather than the proof is the right
    /// place for the bound: a verification cost superlinear in a prover-chosen field is otherwise a griefing vector.
    pub proof_bytes: u32,
}

/// An ERGON term: a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    /// A primitive effect.
    Do(Effect),
    /// All sub-terms, in order, **atomically** — the invariant is checked at the composite boundary, so no child may pass
    /// through a violating intermediate state and be rescued by a sibling.
    Seq(Vec<Term>),
    /// All sub-terms, order-irrelevant. Well-typed only if the sub-terms' footprints are pairwise parallel-safe, which is
    /// *checked* here rather than promised — so a `Par` is a proof of disjointness the scheduler can use.
    Par(Vec<Term>),
    /// Run the sub-term iff the predicate holds of the pre-state; otherwise the identity.
    Gate(Predicate, alloc::boxed::Box<Term>),
    /// The first branch whose predicate holds, by **declaration order** — deterministic, never "whichever matches".
    Alt(Vec<(Predicate, Term)>),
    /// An off-chain computation, verified against its claim.
    Prove(Claim),
}

impl Term {
    /// This term's **derived** footprint.
    ///
    /// `Alt` unions over *all* branches rather than the taken one. That is deliberate, and it is the single place ERGON
    /// pays for determinism: the scheduler must know a footprint before it knows which branch will run, and the schedule
    /// must be a pure function of the ordered transactions (DROMOS's load-bearing property). Scheduling after evaluating
    /// the guard would make the schedule depend on state the scheduler has not yet reached. The cost is pessimistic
    /// conflict for branchy terms; the mitigation is [`Term::Gate`], which has one branch and an exact footprint.
    #[must_use]
    pub fn footprint(&self) -> Footprint {
        match self {
            Self::Do(e) => e.footprint.clone(),
            Self::Seq(ts) | Self::Par(ts) => {
                ts.iter().fold(Footprint::empty(), |acc, t| acc.union(&t.footprint()))
            }
            Self::Gate(p, t) => t.footprint().union(&p.footprint()),
            Self::Alt(bs) => bs.iter().fold(Footprint::empty(), |acc, (p, t)| {
                acc.union(&t.footprint()).union(&p.footprint())
            }),
            Self::Prove(c) => c.footprint.clone(),
        }
    }

    /// This term's [`Locality`] — whether it can be executed inside one point, one line's quorum, or only cell-wide.
    ///
    /// This is the second axis of parallelism, and the one the platform has so far left on the table. DROMOS answers
    /// *which transactions may run together*; locality answers *which machines need be involved at all*. A `Line`-local
    /// term is executable entirely within that line's quorum — a shard — so throughput scales with the number of lines
    /// (`q² + q + 1` of them) and not merely with a cell's cores.
    ///
    /// Terms are naturally line-local far more often than they are plane-wide, because placement is content-addressed: a
    /// transfer touches two accounts, a name registration one name and one account. The unlock is that the algebra can now
    /// *prove* it, so a scheduler may act on it.
    #[must_use]
    pub fn locality(&self, common_line: impl Fn(&[PointId]) -> Option<LineId>) -> Locality {
        self.footprint().locality(common_line)
    }

    /// This term's nesting depth. A leaf is 0; a combinator is one more than its deepest child.
    ///
    /// `Prove` is depth 0 on purpose: the proof is opaque, so whatever structure the *prover* composed is the prover's
    /// problem and costs the verifier nothing. That asymmetry is what lets unbounded off-chain computation coexist with a
    /// hard on-chain depth ceiling.
    #[must_use]
    pub fn depth(&self) -> u32 {
        match self {
            Self::Do(_) | Self::Prove(_) => 0,
            Self::Seq(ts) | Self::Par(ts) => 1 + ts.iter().map(Self::depth).max().unwrap_or(0),
            Self::Gate(_, t) => 1 + t.depth(),
            Self::Alt(bs) => 1 + bs.iter().map(|(_, t)| t.depth()).max().unwrap_or(0),
        }
    }

    /// The number of nodes in the term — its size, and the linear factor in [`Self::cost`].
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            Self::Do(_) | Self::Prove(_) => 1,
            Self::Seq(ts) | Self::Par(ts) => 1 + ts.iter().map(Self::size).sum::<usize>(),
            Self::Gate(_, t) => 1 + t.size(),
            Self::Alt(bs) => 1 + bs.iter().map(|(_, t)| t.size()).sum::<usize>(),
        }
    }

    /// Whether the term escapes the ledger anywhere — i.e. contains an [`Effect::external`] leaf.
    ///
    /// Surfaced because an `Extern` effect's outside-the-ledger consequence needs a guard of its own kind, so a host must
    /// be able to *see* that a term has one without walking it again.
    #[must_use]
    pub fn is_external(&self) -> bool {
        match self {
            Self::Do(e) => e.external,
            Self::Prove(_) => false,
            Self::Seq(ts) | Self::Par(ts) => ts.iter().any(Self::is_external),
            Self::Gate(_, t) => t.is_external(),
            Self::Alt(bs) => bs.iter().any(|(_, t)| t.is_external()),
        }
    }

    /// Every primitive effect kind the term can apply, in traversal order — what a host needs to know which rules a term
    /// invokes without interpreting it.
    #[must_use]
    pub fn effect_kinds(&self) -> Vec<u16> {
        let mut out = Vec::new();
        self.collect_kinds(&mut out);
        out
    }

    fn collect_kinds(&self, out: &mut Vec<u16>) {
        match self {
            Self::Do(e) => out.push(e.kind),
            Self::Prove(_) => {}
            Self::Seq(ts) | Self::Par(ts) => {
                for t in ts {
                    t.collect_kinds(out);
                }
            }
            Self::Gate(_, t) => t.collect_kinds(out),
            Self::Alt(bs) => {
                for (_, t) in bs {
                    t.collect_kinds(out);
                }
            }
        }
    }
}

/// Why a term is not well-typed. Every variant is a *rejection at the port*, never a partial application.
///
/// This mirrors SYNARC-Ω's admissibility contract (Definition U.7): a nonviable target is "rejected at the port, not
/// discovered in operation". It is the property gas cannot offer — a metered VM discovers invalidity by running out, and
/// must then define revert semantics for the half-applied state. ERGON has no such state to define.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeError {
    /// Nesting exceeded [`D_MAX`]. Not a resource limit: `P_crit^[4] > 1` forecloses a fourth order arithmetically.
    TooDeep {
        /// The offending term's depth.
        depth: u32,
    },
    /// A [`Term::Par`]'s sub-terms are not footprint-disjoint, so their order would be observable — and a `Par` whose
    /// order matters is not a `Par`.
    ParallelConflict {
        /// Index of the first conflicting branch.
        left: usize,
        /// Index of the second conflicting branch.
        right: usize,
    },
    /// A combinator with no children. Rejected rather than treated as the identity: an empty `Seq` is almost always a
    /// construction bug, and silently accepting it would let a caller pay a fee for nothing.
    EmptyCombinator,
    /// A claim's proof size exceeds the admission cap. Bounded on the *claim* because verification cost superlinear in a
    /// prover-chosen field would otherwise be a griefing vector.
    ProofTooLarge {
        /// The claim's stated proof size.
        bytes: u32,
        /// The admission cap it exceeded.
        cap: u32,
    },
    /// The footprint is wider than the per-transaction cap.
    FootprintTooWide {
        /// Distinct keys the term touches.
        width: usize,
        /// The admission cap it exceeded.
        cap: usize,
    },
}

/// The limits a host applies at admission. Every field is a *policy* bound, in contrast to [`D_MAX`], which is a theorem.
///
/// The distinction is the SYNARC-Ω constants trichotomy (Appendix U, §G10): derive a constant, bound it, or prove the
/// architecture safe for any value and declare it free. `D_MAX` is *derived*. These are *bounded* — the algebra is sound
/// for any value of them, and they exist only to price a block, so a deployment may set them without touching soundness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum bytes of a single [`Claim`]'s proof.
    pub proof_bytes: u32,
    /// Maximum distinct keys a term may touch.
    pub footprint_width: usize,
}

impl Limits {
    /// Permissive limits for tests and for hosts that impose their own bounds elsewhere.
    #[must_use]
    pub const fn unbounded() -> Self { Self { proof_bytes: u32::MAX, footprint_width: usize::MAX } }
}

/// Check well-typedness: depth within [`D_MAX`], `Par` branches disjoint, no empty combinator, claims and footprint
/// within `limits`.
///
/// Checked **before** execution and in cheapest-first order, so a malformed term is refused at its first violation rather
/// than after work has been done on it.
pub fn well_typed(term: &Term, limits: &Limits) -> Result<(), TypeError> {
    let depth = term.depth();
    if depth > u32::from(D_MAX) {
        return Err(TypeError::TooDeep { depth });
    }
    let width = term.footprint().width();
    if width > limits.footprint_width {
        return Err(TypeError::FootprintTooWide { width, cap: limits.footprint_width });
    }
    check_structure(term, limits)
}

/// The recursive half of [`well_typed`]: structure and claim bounds, independent of the whole-term aggregates.
fn check_structure(term: &Term, limits: &Limits) -> Result<(), TypeError> {
    match term {
        Term::Do(_) => Ok(()),
        Term::Prove(c) => {
            if c.proof_bytes > limits.proof_bytes {
                Err(TypeError::ProofTooLarge { bytes: c.proof_bytes, cap: limits.proof_bytes })
            } else {
                Ok(())
            }
        }
        Term::Seq(ts) => {
            if ts.is_empty() {
                return Err(TypeError::EmptyCombinator);
            }
            ts.iter().try_for_each(|t| check_structure(t, limits))
        }
        Term::Par(ts) => {
            if ts.is_empty() {
                return Err(TypeError::EmptyCombinator);
            }
            let prints: Vec<Footprint> = ts.iter().map(Term::footprint).collect();
            for (i, a) in prints.iter().enumerate() {
                for (j, b) in prints.iter().enumerate().skip(i + 1) {
                    if !a.parallel_safe(b) {
                        return Err(TypeError::ParallelConflict { left: i, right: j });
                    }
                }
            }
            ts.iter().try_for_each(|t| check_structure(t, limits))
        }
        Term::Gate(_, t) => check_structure(t, limits),
        Term::Alt(bs) => {
            if bs.is_empty() {
                return Err(TypeError::EmptyCombinator);
            }
            bs.iter().try_for_each(|(_, t)| check_structure(t, limits))
        }
    }
}

/// What a validator will spend on a term, in abstract units — **computed without executing it**.
///
/// This is why ERGON needs no gas. Each primitive is O(1) in ledger operations, each combinator adds a bounded constant,
/// depth is capped, and a proof's cost is a function of a size carried in the claim. So the cost is a sum over a finite
/// tree that is *entirely present in the transaction*, and the fee can be priced at admission. A term therefore cannot
/// exhaust a budget mid-flight, which is what removes out-of-gas states, refund rules, and revert semantics from the
/// design — not by handling them well, but by not having them.
///
/// `PROOF_UNIT_BYTES` converts proof bytes to units; it is a *policy* constant in the trichotomy's second class (bounded,
/// soundness-independent), and named rather than sprinkled so a host can re-price verification without editing the
/// algebra.
#[must_use]
pub fn cost(term: &Term) -> u64 {
    /// Units per primitive effect application.
    const EFFECT: u64 = 1;
    /// Units per combinator node — the scheduler's own bookkeeping.
    const NODE: u64 = 1;
    /// Units per predicate evaluation.
    const PREDICATE: u64 = 1;
    /// Bytes of proof per unit of verification cost.
    const PROOF_UNIT_BYTES: u64 = 32;

    match term {
        Term::Do(_) => EFFECT,
        Term::Prove(c) => NODE + u64::from(c.proof_bytes) / PROOF_UNIT_BYTES,
        Term::Seq(ts) | Term::Par(ts) => NODE + ts.iter().map(cost).sum::<u64>(),
        Term::Gate(_, t) => NODE + PREDICATE + cost(t),
        // Every branch's predicate may be evaluated (they are tried in order), but only one body runs. Charging the
        // maximum body rather than the sum keeps the price honest for the work actually done, while charging all
        // predicates reflects the work actually done in the worst case.
        Term::Alt(bs) => {
            NODE + bs.len() as u64 * PREDICATE + bs.iter().map(|(_, t)| cost(t)).max().unwrap_or(0)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use super::*;

    /// A key at point `n`, slot 0 — the tests care about identity and placement, not slots.
    fn k(n: PointId) -> Key { Key::at(n, 0) }

    /// Keys at the given points.
    fn ks(ns: &[PointId]) -> Vec<Key> { ns.iter().copied().map(k).collect() }

    /// An effect reading points `r` and writing points `w`.
    fn eff(kind: u16, r: &[PointId], w: &[PointId]) -> Term {
        Term::Do(Effect::internal(kind, Footprint::new(ks(r), ks(w))))
    }

    fn pred(kind: u16, r: &[PointId]) -> Predicate { Predicate::new(kind, ks(r)) }

    /// The Fano plane's seven lines, as the incidence oracle the locality analysis takes.
    ///
    /// Written out rather than imported so this crate stays plane-agnostic: `PG(2,2)`'s lines are the seven triples of
    /// points in which any two lines meet in exactly one point (the Steiner property the pessimal case rests on).
    fn fano_line(points: &[PointId]) -> Option<LineId> {
        const LINES: [[PointId; 3]; 7] = [
            [0, 1, 2], [0, 3, 4], [0, 5, 6], [1, 3, 5], [1, 4, 6], [2, 3, 6], [2, 4, 5],
        ];
        LINES
            .iter()
            .position(|l| points.iter().all(|p| l.contains(p)))
            .and_then(|i| LineId::try_from(i).ok())
    }

    #[test]
    fn the_composition_ceiling_is_recomputed_not_trusted() {
        // D_MAX is a theorem, so the theorem is checked here rather than the constant being asserted against itself.
        // P_crit^[m] = P_crit · 3^(m-1)/(m+1) with P_crit = 2/7 (SYNARC-Ω Theorem K.5).
        let p_crit = 2.0_f64 / 7.0;
        let ladder = |m: u32| p_crit * 3.0_f64.powi(m as i32 - 1) / f64::from(m + 1);

        assert!((ladder(1) - 1.0 / 7.0).abs() < 1e-12, "order 1 is the maximally mixed purity — free");
        assert!((ladder(2) - 2.0 / 7.0).abs() < 1e-12, "order 2 is baseline");
        assert!((ladder(3) - 9.0 / 14.0).abs() < 1e-12, "order 3 is the last admissible rung");
        assert!(ladder(4) > 1.0, "order 4 exceeds the mathematical maximum — foreclosed");
        assert!((ladder(4) - 54.0 / 35.0).abs() < 1e-12);

        // And D_MAX is exactly the largest admissible order.
        let highest = (1..8).filter(|&m| ladder(m) <= 1.0).max().unwrap();
        assert_eq!(u32::from(D_MAX), highest, "D_MAX is the ceiling the ladder computes, not a chosen number");
    }

    #[test]
    fn a_footprint_is_derived_from_the_term_not_declared() {
        // The trust assumption this deletes: nothing in a term states its own access list, so nothing can misstate it.
        let t = Term::Seq(vec![eff(1, &[1], &[2]), eff(2, &[2], &[3])]);
        let fp = t.footprint();
        assert_eq!(fp.reads(), ks(&[1, 2]));
        assert_eq!(fp.writes(), ks(&[2, 3]));
        assert_eq!(fp.width(), 4);
    }

    #[test]
    fn a_line_local_term_is_shardable_and_a_plane_wide_one_is_the_pessimal_case() {
        // The second axis of parallelism, which DROMOS's conflict DAG structurally cannot see: not *which transactions may
        // run together* but *which machines need be involved at all*. Answerable only because a Key carries its point.
        let one_point = eff(1, &[3], &[3]);
        assert_eq!(one_point.locality(fano_line), Locality::Point(3), "tightest: a single node holds everything");

        // {1, 3, 5} is a Fano line, so this term executes entirely inside that line's quorum — a shard.
        let line_local = Term::Seq(vec![eff(1, &[1], &[3]), eff(2, &[3], &[5])]);
        assert_eq!(line_local.locality(fano_line), Locality::Line(3), "the line {{1,3,5}}");

        // {1, 2, 3} is not a line of PG(2,2), so this is inherently cell-wide.
        let spread = Term::Seq(vec![eff(1, &[1], &[2]), eff(2, &[2], &[3])]);
        assert_eq!(spread.locality(fano_line), Locality::PlaneWide);

        assert_eq!(Footprint::empty().locality(fano_line), Locality::Empty);
    }

    #[test]
    fn plane_wide_footprints_always_conflict_which_is_why_effects_should_own_points() {
        // The dual Steiner property, and the reason §8's design guideline is derived rather than stylistic: any two
        // distinct lines of PG(2,2) meet in exactly one point, so two line-sized footprints ALWAYS share a point. A
        // contract whose state is a whole line therefore serialises against every other such contract — structurally, not
        // by bad luck.
        const LINES: [[PointId; 3]; 7] = [
            [0, 1, 2], [0, 3, 4], [0, 5, 6], [1, 3, 5], [1, 4, 6], [2, 3, 6], [2, 4, 5],
        ];
        for (i, a) in LINES.iter().enumerate() {
            for b in LINES.iter().skip(i + 1) {
                let shared = a.iter().filter(|p| b.contains(p)).count();
                assert_eq!(shared, 1, "any two distinct lines meet in exactly one point");
                // And two effects each writing a whole line therefore always conflict.
                let fa = Footprint::new(Vec::new(), ks(a));
                let fb = Footprint::new(Vec::new(), ks(b));
                assert!(fa.conflicts(&fb), "line-sized footprints are the pessimal case");
            }
        }
        // Whereas point-sized footprints conflict only on equality — the whole reason to own points.
        assert!(!Footprint::new(Vec::new(), ks(&[1])).conflicts(&Footprint::new(Vec::new(), ks(&[2]))));
        assert!(Footprint::new(Vec::new(), ks(&[1])).conflicts(&Footprint::new(Vec::new(), ks(&[1]))));
    }

    #[test]
    fn read_read_is_not_a_conflict_but_every_write_overlap_is() {
        let a = Footprint::new(ks(&[1, 2]), vec![]);
        let b = Footprint::new(ks(&[2, 3]), vec![]);
        assert!(!a.conflicts(&b), "read–read never conflicts — this is where parallelism comes from");
        assert!(a.parallel_safe(&b));

        let w = Footprint::new(vec![], ks(&[2]));
        assert!(a.conflicts(&w), "read vs write");
        assert!(w.conflicts(&a), "and symmetrically");
        assert!(w.conflicts(&Footprint::new(vec![], ks(&[2]))), "write vs write");
        assert!(!w.conflicts(&Footprint::new(ks(&[9]), ks(&[8]))), "disjoint keys never conflict");
    }

    #[test]
    fn par_is_a_proof_of_disjointness_and_is_rejected_otherwise() {
        // A `Par` whose branches conflict would have an observable order, and a `Par` whose order matters is not a `Par`.
        // Checked structurally, so the scheduler can *use* a well-typed `Par` rather than re-verify it.
        let ok = Term::Par(vec![eff(1, &[1], &[2]), eff(2, &[3], &[4])]);
        assert_eq!(well_typed(&ok, &Limits::unbounded()), Ok(()));

        let clash = Term::Par(vec![eff(1, &[1], &[2]), eff(2, &[2], &[5])]);
        assert_eq!(
            well_typed(&clash, &Limits::unbounded()),
            Err(TypeError::ParallelConflict { left: 0, right: 1 })
        );

        // Nested: the conflict is between grandchildren, and unioned footprints still catch it.
        let nested = Term::Par(vec![
            Term::Seq(vec![eff(1, &[], &[7])]),
            Term::Seq(vec![eff(2, &[7], &[])]),
        ]);
        assert_eq!(
            well_typed(&nested, &Limits::unbounded()),
            Err(TypeError::ParallelConflict { left: 0, right: 1 })
        );
    }

    #[test]
    fn depth_is_capped_by_the_ceiling_and_prove_is_opaque() {
        let leaf = eff(1, &[], &[1]);
        assert_eq!(leaf.depth(), 0);
        let d3 = Term::Seq(vec![Term::Par(vec![Term::Gate(pred(9, &[1]), Box::new(leaf.clone()))])]);
        assert_eq!(d3.depth(), 3);
        assert_eq!(well_typed(&d3, &Limits::unbounded()), Ok(()));

        let d4 = Term::Seq(vec![d3]);
        assert_eq!(d4.depth(), 4);
        assert_eq!(well_typed(&d4, &Limits::unbounded()), Err(TypeError::TooDeep { depth: 4 }));

        // A `Prove` is depth 0 however much the prover composed: that asymmetry is what lets unbounded off-chain
        // computation coexist with a hard on-chain ceiling.
        let proof = Term::Prove(Claim {
            kind: 1,
            footprint: Footprint::new(ks(&[1]), ks(&[2])),
            proof_bytes: 4096,
        });
        assert_eq!(proof.depth(), 0);
        let wrapped = Term::Seq(vec![Term::Par(vec![Term::Seq(vec![proof])])]);
        assert_eq!(wrapped.depth(), 3, "three combinators, and the proof adds none");
        assert_eq!(well_typed(&wrapped, &Limits::unbounded()), Ok(()));
    }

    #[test]
    fn cost_is_computable_without_executing_and_is_monotone_in_size() {
        // The property that removes gas: cost is a pure function of the term.
        let t = Term::Seq(vec![eff(1, &[], &[1]), eff(2, &[], &[2])]);
        assert_eq!(cost(&t), 3, "one node plus two effects");
        assert_eq!(cost(&t), cost(&t.clone()), "and deterministic");

        // Alt charges every predicate (all may be tried) but only the largest body (only one runs) — the price tracks
        // the work actually done in the worst case, not a fiction.
        let alt = Term::Alt(vec![
            (pred(1, &[1]), eff(1, &[], &[1])),
            (pred(2, &[2]), Term::Seq(vec![eff(2, &[], &[2]), eff(3, &[], &[3])])),
        ]);
        assert_eq!(cost(&alt), 1 + 2 + 3, "node + 2 predicates + max body (a Seq of two)");

        // Monotone: adding a node never lowers the price, so there is no term that is cheaper for being bigger.
        let bigger = Term::Seq(vec![t.clone(), eff(9, &[], &[9])]);
        assert!(cost(&bigger) > cost(&t));

        // A proof's cost comes from the claim, which is why it can be capped before the proof is touched.
        let cheap = Term::Prove(Claim { kind: 1, footprint: Footprint::empty(), proof_bytes: 32 });
        let dear = Term::Prove(Claim { kind: 1, footprint: Footprint::empty(), proof_bytes: 32_000 });
        assert!(cost(&dear) > cost(&cheap));
    }

    #[test]
    fn alt_takes_the_worst_case_footprint_because_the_schedule_precedes_the_guard() {
        // The one place ERGON pays for determinism, made explicit: the scheduler must know a footprint before it knows
        // which branch runs, so the footprint is the union over branches — pessimistic, but a pure function of the term.
        let alt = Term::Alt(vec![
            (pred(1, &[100]), eff(1, &[], &[1])),
            (pred(2, &[200]), eff(2, &[], &[2])),
        ]);
        let fp = alt.footprint();
        assert_eq!(fp.reads(), ks(&[100, 200]), "both guards' reads");
        assert_eq!(fp.writes(), ks(&[1, 2]), "both bodies' writes, though only one will run");

        // `Gate` is the exact-footprint alternative for the one-branch case, and is strictly tighter.
        let gate = Term::Gate(pred(1, &[100]), Box::new(eff(1, &[], &[1])));
        assert_eq!(gate.footprint().writes(), ks(&[1]));
        assert!(gate.footprint().width() < fp.width());
    }

    #[test]
    fn a_predicate_is_a_gate_and_can_never_write() {
        // Definition U.14 B1 read at the ledger level: influence between levels is a gate, not a message. A predicate
        // that could write would be a message, and would open the upward path that reentrancy needs.
        let p = pred(7, &[1, 2, 2]);
        assert_eq!(p.footprint().writes(), [] as [Key; 0], "structurally impossible for a predicate to write");
        assert_eq!(p.footprint().reads(), ks(&[1, 2]), "and its reads are normalised");
    }

    #[test]
    fn empty_combinators_and_oversized_claims_are_refused_at_the_port() {
        let lim = Limits::unbounded();
        assert_eq!(well_typed(&Term::Seq(vec![]), &lim), Err(TypeError::EmptyCombinator));
        assert_eq!(well_typed(&Term::Par(vec![]), &lim), Err(TypeError::EmptyCombinator));
        assert_eq!(well_typed(&Term::Alt(vec![]), &lim), Err(TypeError::EmptyCombinator));

        let tight = Limits { proof_bytes: 100, footprint_width: usize::MAX };
        let big = Term::Prove(Claim { kind: 1, footprint: Footprint::empty(), proof_bytes: 101 });
        assert_eq!(
            well_typed(&big, &tight),
            Err(TypeError::ProofTooLarge { bytes: 101, cap: 100 })
        );

        let narrow = Limits { proof_bytes: u32::MAX, footprint_width: 1 };
        assert_eq!(
            well_typed(&eff(1, &[1], &[2]), &narrow),
            Err(TypeError::FootprintTooWide { width: 2, cap: 1 })
        );
    }

    #[test]
    fn externality_and_effect_kinds_are_visible_without_interpreting_the_term() {
        // A host must be able to see that a term escapes the ledger — an `Extern` consequence needs a guard of its own
        // kind (Definition U.8) — and which rules it invokes, without walking it itself.
        let internal = Term::Seq(vec![eff(1, &[], &[1]), eff(2, &[], &[2])]);
        assert!(!internal.is_external());
        assert_eq!(internal.effect_kinds(), [1, 2]);

        let escapes = Term::Seq(vec![
            eff(1, &[], &[1]),
            Term::Do(Effect::external(5, Footprint::new(vec![], ks(&[9])))),
        ]);
        assert!(escapes.is_external(), "one external leaf makes the whole term external");
        assert_eq!(escapes.effect_kinds(), [1, 5]);

        // A `Prove` contributes no effect kind: its transition is attested by the proof, not applied by a rule.
        let proved = Term::Prove(Claim { kind: 3, footprint: Footprint::empty(), proof_bytes: 0 });
        assert!(proved.effect_kinds().is_empty());
        assert!(!proved.is_external());
    }

    #[test]
    fn the_closure_induction_holds_over_every_combinator() {
        // The closure theorem's shape, tested as the invariant it is: if every primitive's footprint is within a bound,
        // every well-typed composition's footprint is within the *union* bound — i.e. composition introduces no key that
        // no primitive touches. That is the mechanical core of "safety composes by structural induction": a composite
        // cannot reach state its parts could not.
        let leaves = [eff(1, &[1], &[2]), eff(2, &[3], &[4]), eff(3, &[5], &[6])];
        let allowed: Vec<Key> = ks(&[1, 2, 3, 4, 5, 6]);

        let composites = vec![
            Term::Seq(leaves.to_vec()),
            Term::Par(leaves.to_vec()),
            Term::Gate(pred(1, &[1]), Box::new(Term::Seq(leaves.to_vec()))),
            Term::Alt(leaves.iter().cloned().map(|t| (pred(1, &[3]), t)).collect()),
        ];
        for c in composites {
            let fp = c.footprint();
            for k in fp.reads().iter().chain(fp.writes()) {
                assert!(allowed.contains(k), "composition introduced key {k:?}, which no primitive touches");
            }
            // And the composite's cost is the sum of its parts plus bookkeeping — never less than any part alone.
            assert!(cost(&c) >= leaves.iter().map(cost).max().unwrap());
        }
    }
}
