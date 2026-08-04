//! BFT quorum parameters of a projective consensus cell (spec §10.1, `docs/design-taxis.md` §2).
//!
//! The TAXIS consensus domain is one projective cell `PG(2, q)` with `n = q² + q + 1` validators. This
//! module derives — and *proves*, exhaustively in the tests — the PBFT-class quorum system on that cell:
//! the Byzantine fault tolerance `f = ⌊(n−1)/3⌋` and the finality quorum `Q = ⌈(n + f + 1)/2⌉`, together
//! with the two properties consensus needs (Lamport/Castro–Liskov masking quorums):
//!
//! * **Safety** — any two `Q`-quorums intersect in `2Q − n ≥ f + 1` validators, so they share at least one
//!   **honest** validator; two conflicting blocks can never both gather a quorum certificate.
//! * **Liveness** — `n − f ≥ Q`, so the honest validators alone contain a full quorum; progress never waits
//!   on a Byzantine vote.
//!
//! A clean structural result falls out (`corollary_tight_cells`): for `q ≢ 1 (mod 3)` — including the
//! reference Fano cell `q = 2` (`n = 7`, `f = 2`, `Q = 5`) — `n ≡ 1 (mod 3)`, so `n = 3f + 1` **exactly** and
//! the cell is a *tight* PBFT system with optimal tolerance `f = (q² + q)/3` and quorum `2f + 1`.

use fanos_geometry::fano;

/// The BFT parameters of one projective consensus cell `PG(2, q)`.
///
/// Every field is derived from the cell order `q` alone; construct with [`CellParams::for_order`], or with
/// [`checked`](Self::checked) when the values arrive from outside. The invariants
/// [`is_safe`](Self::is_safe) and [`is_live`](Self::is_live) hold for every valid projective order.
///
/// **The fields are private, and that is the fix rather than a style choice.** They were public, so a
/// provisioning file decoded them one by one (`fanos-node::taxis_config`) with nothing checking that the
/// four agreed. A validator whose config carried a `quorum` below `⌈(n+f+1)/2⌉` would run consensus in
/// which two quorums can be **disjoint** — two conflicting blocks both finalize, which is a fork, and a
/// safety failure rather than a liveness one. It would look healthy until the cell partitioned. The
/// doc here previously claimed the invariants were "asserted at construction"; they were asserted in the
/// *tests*, over orders the tests chose.
///
/// So the invalid state is now **unrepresentable** rather than merely discouraged: outside this module a
/// `CellParams` can only come from [`for_order`](Self::for_order), [`checked`](Self::checked) or
/// [`FANO`](Self::FANO), each of which derives every field from `q`. A validator function that a caller can
/// forget to call is a validator function that will be absent in production — the same lesson the POROS
/// descriptor binding learned by being a builder method.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CellParams {
    /// The projective order `q` (the plane is `PG(2, q)`; a line carries `q + 1` validators).
    q: u32,
    /// The validator count `n = q² + q + 1`.
    n: usize,
    /// The Byzantine fault tolerance `f = ⌊(n − 1)/3⌋`.
    f: usize,
    /// The finality quorum size `Q = ⌈(n + f + 1)/2⌉`.
    quorum: usize,
}

impl CellParams {
    /// The reference Fano cell `PG(2, 2)`: `n = 7`, `f = 2`, `Q = 5` — a tight (optimal) PBFT system.
    pub const FANO: Self = Self {
        q: 2,
        n: fano::N,
        f: 2,
        quorum: 5,
    };

    /// Derive the BFT parameters for a projective cell of order `q` (`q ≥ 2`).
    ///
    /// Returns `None` if `q < 2` (no consensus below the Fano cell) or if `n = q² + q + 1` would overflow
    /// `usize`. The derived system always satisfies safety and liveness (asserted in the tests over every
    /// prime-power order); this is total for all valid `q`.
    #[must_use]
    pub fn for_order(q: u32) -> Option<Self> {
        if q < 2 {
            return None;
        }
        // n = q² + q + 1, guarding the square against overflow on 32-bit targets.
        let q64 = u64::from(q);
        let n = q64.checked_mul(q64)?.checked_add(q64)?.checked_add(1)?;
        let n = usize::try_from(n).ok()?;
        // f = ⌊(n−1)/3⌋; Q = ⌈(n+f+1)/2⌉ = (n+f+2)/2 in integer arithmetic.
        let f = (n - 1) / 3;
        let quorum = (n + f + 2) / 2;
        Some(Self { q, n, f, quorum })
    }

    /// The projective order `q`.
    #[must_use]
    pub const fn q(self) -> u32 {
        self.q
    }

    /// The validator count `n = q² + q + 1`.
    #[must_use]
    pub const fn n(self) -> usize {
        self.n
    }

    /// The Byzantine fault tolerance `f = ⌊(n − 1)/3⌋`.
    #[must_use]
    pub const fn f(self) -> usize {
        self.f
    }

    /// The finality quorum size `Q = ⌈(n + f + 1)/2⌉`.
    #[must_use]
    pub const fn quorum(self) -> usize {
        self.quorum
    }

    /// Accept parameters that arrived from **outside** — a provisioning file, a peer, an operator — only if
    /// they are exactly what `q` derives.
    ///
    /// The three non-`q` fields are a pure function of `q`, so carrying them is redundant by construction and
    /// disagreement is either tampering or a typo. Both are refused the same way, because a cell cannot tell
    /// them apart and neither should be run: an under-sized quorum is a fork waiting for a partition, and an
    /// over-sized one is a cell that cannot finalize at all.
    ///
    /// Checking equality rather than re-deriving and ignoring the file is deliberate. Silently overriding
    /// would let a wrong file run a *different* cell than its operator believes they provisioned — the two
    /// halves of a network disagreeing about `n` while each thinks it is right, which is worse than refusing
    /// to start.
    #[must_use]
    pub fn checked(q: u32, n: usize, f: usize, quorum: usize) -> Option<Self> {
        let derived = Self::for_order(q)?;
        (derived.n == n && derived.f == f && derived.quorum == quorum).then_some(derived)
    }

    /// The number of validators on one line (committee): `q + 1`.
    #[must_use]
    pub fn line_size(self) -> usize {
        self.q as usize + 1
    }

    /// The anti-MEV mempool sealing threshold for a line committee: `t = ⌊(q+1)/3⌋ + 1` — the smallest
    /// threshold such that an adversary holding at most `⌊(q+1)/3⌋` of a line's members (the per-line
    /// Byzantine bound) cannot decrypt, while `t` honest members always can once `< t` are faulty.
    /// For the Fano line (`q+1 = 3`) this is `2`-of-`3`.
    #[must_use]
    pub fn seal_threshold(self) -> u8 {
        let line = self.line_size();
        // ⌊line/3⌋ + 1, clamped to at least 2 and at most `line` (a threshold must be satisfiable).
        let t = (line / 3) + 1;
        t.clamp(2, line) as u8
    }

    /// Whether the masking-quorum **safety** property holds: two `Q`-quorums share `≥ f + 1` validators
    /// (`2Q − n ≥ f + 1`), hence at least one honest validator in common.
    #[must_use]
    pub fn is_safe(self) -> bool {
        // 2Q ≥ n + f + 1  ⇔  2Q > n + f  ⇔  the intersection of two quorums has ≥ f+1 nodes, ≥ 1 honest.
        2 * self.quorum > self.n + self.f
    }

    /// Whether the **liveness** property holds: the honest validators alone contain a quorum
    /// (`n − f ≥ Q`), so progress never requires a Byzantine vote.
    #[must_use]
    pub fn is_live(self) -> bool {
        self.n - self.f >= self.quorum
    }

    /// Whether this is a **tight** (optimal) PBFT cell: `n = 3f + 1`, so `f` is the largest tolerable and
    /// `Q = 2f + 1`. Holds exactly when `q ≢ 1 (mod 3)` (see the module docs).
    #[must_use]
    pub fn is_tight(self) -> bool {
        self.n == 3 * self.f + 1
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// The prime-power orders for which `PG(2, q)` exists (small end) — the cells a real deployment picks.
    const PRIME_POWER_ORDERS: [u32; 9] = [2, 3, 4, 5, 7, 8, 9, 11, 13];

    #[test]
    fn the_reference_fano_cell_is_tight_7_2_5() {
        let p = CellParams::for_order(2).unwrap();
        assert_eq!(p, CellParams::FANO);
        assert_eq!((p.n(), p.f(), p.quorum()), (7, 2, 5));
        assert!(p.is_tight(), "the Fano cell is a tight PBFT system (n = 3f+1)");
        // A tight cell's quorum is exactly 2f+1.
        assert_eq!(p.quorum(), 2 * p.f() + 1);
    }

    #[test]
    fn every_projective_cell_is_a_safe_and_live_quorum_system() {
        // The load-bearing theorem (design-taxis §2.1): for every prime-power order, the derived
        // (n, f, Q) is a masking quorum system — safe AND live.
        for q in PRIME_POWER_ORDERS {
            let p = CellParams::for_order(q).unwrap();
            assert_eq!(p.n(), (q * q + q + 1) as usize, "n = q²+q+1 for q={q}");
            assert!(p.is_safe(), "safety must hold for q={q} (n={}, f={}, Q={})", p.n(), p.f(), p.quorum());
            assert!(p.is_live(), "liveness must hold for q={q}");
            // The optimal-tolerance bound: n ≥ 3f+1, i.e. n > 3f (never tolerate more than PBFT allows).
            assert!(p.n() > 3 * p.f(), "f = ⌊(n−1)/3⌋ never exceeds the PBFT bound for q={q}");
        }
    }

    #[test]
    fn corollary_tight_cells_are_exactly_q_not_1_mod_3() {
        // design-taxis §2.2: n = q²+q+1 ≡ 1 (mod 3) ⇔ q ≢ 1 (mod 3), and that is exactly when the cell
        // is tight (n = 3f+1). Verified over a wide q-range, prime-power or not (the identity is arithmetic).
        for q in 2..=200u32 {
            let n = (q * q + q + 1) as usize;
            let f = (n - 1) / 3;
            let tight = n == 3 * f + 1;
            assert_eq!(tight, n % 3 == 1, "tightness ⇔ n≡1 mod 3, q={q}");
            assert_eq!(n % 3 == 1, q % 3 != 1, "n≡1 mod 3 ⇔ q≢1 mod 3, q={q}");
        }
    }

    #[test]
    fn safety_and_liveness_hold_for_every_order_up_to_a_thousand() {
        // Exhaustive over all orders 2..=1000 (well past any real cell): the quorum system is always
        // valid, so no deployable cell size can silently break BFT.
        for q in 2..=1000u32 {
            let p = CellParams::for_order(q).unwrap();
            assert!(p.is_safe() && p.is_live(), "q={q}");
        }
    }

    #[test]
    fn the_seal_threshold_masks_the_per_line_byzantine_bound() {
        // The anti-MEV sealing threshold t must exceed the per-line Byzantine bound ⌊(q+1)/3⌋, so an
        // adversary at that bound cannot open a sealed tx, yet t ≤ line so honest members always can.
        for q in PRIME_POWER_ORDERS {
            let p = CellParams::for_order(q).unwrap();
            let t = usize::from(p.seal_threshold());
            let line = p.line_size();
            let per_line_byz = line / 3;
            assert!(t > per_line_byz, "t={t} must exceed the per-line Byzantine bound {per_line_byz} (q={q})");
            assert!(t >= 2 && t <= line, "t={t} must be a satisfiable threshold on a line of {line} (q={q})");
        }
        // The Fano line is 2-of-3.
        assert_eq!(CellParams::FANO.seal_threshold(), 2);
        assert_eq!(CellParams::FANO.line_size(), 3);
    }

    #[test]
    fn sub_fano_orders_are_rejected() {
        assert_eq!(CellParams::for_order(0), None);
        assert_eq!(CellParams::for_order(1), None);
        assert!(CellParams::for_order(2).is_some());
    }

    #[test]
    fn parameters_from_outside_are_refused_unless_q_derives_them() {
        // **A fork, reachable through a provisioning file.** `CellParams`'s fields were public and
        // `fanos-node::taxis_config` decoded all four from a validator's config, one `u32` at a time, with
        // nothing checking they agreed. A `quorum` below `⌈(n+f+1)/2⌉` breaks the masking-quorum property
        // `2Q > n + f`: two quorums can then be DISJOINT, so two conflicting blocks both finalize. That is a
        // safety failure, not a liveness one — and the cell would look healthy right up until it partitioned.
        //
        // The fields are private now, so outside this module the only ways in derive every field from `q`.
        // This pins the remaining door, the one untrusted data comes through.
        let good = CellParams::FANO;
        assert_eq!(
            CellParams::checked(good.q(), good.n(), good.f(), good.quorum()),
            Some(good),
            "a file that agrees with its own order is accepted",
        );

        // One short of the derived quorum: the exact value an attacker or a typo would produce, and the one
        // that forks.
        let forkable = CellParams::checked(good.q(), good.n(), good.f(), good.quorum() - 1);
        assert_eq!(forkable, None, "an under-sized quorum is refused rather than run");

        // Over-sized is refused too, and for a different reason worth keeping distinct: it cannot fork, it
        // simply cannot finalize. A cell that never reaches quorum is not safer than one that forks — it is
        // dead — and either way the file does not describe the cell its operator provisioned.
        assert_eq!(
            CellParams::checked(good.q(), good.n(), good.f(), good.quorum() + 1),
            None,
            "an over-sized quorum is refused too — it cannot finalize, which is not a safe failure",
        );

        // A wrong `n` or `f` is the same class: every field is a function of `q`, so any disagreement means
        // the file and the order describe different cells.
        assert_eq!(CellParams::checked(good.q(), good.n() + 1, good.f(), good.quorum()), None);
        assert_eq!(CellParams::checked(good.q(), good.n(), good.f() + 1, good.quorum()), None);

        // And the invariants the whole thing exists for hold on every order the plane admits — asserted here
        // rather than only in a doc sentence, which is what the type previously relied on.
        for q in [2u32, 3, 4, 5, 7, 8, 9, 11, 13, 16, 31] {
            let Some(p) = CellParams::for_order(q) else {
                panic!("q={q} is a valid projective order and must derive parameters")
            };
            assert!(p.is_safe(), "q={q}: two quorums must share an honest validator");
            assert!(p.is_live(), "q={q}: the honest validators alone must contain a quorum");
        }
    }
}
