//! The **Φ lifter**: the one mechanism §6.7 names and the platform did not have (#139).
//!
//! # Why a lifter has to exist at all
//!
//! UHM T-319 measured what dissipation alone does to a holon: `Φ(ρ*) < Φ(Γ)` for **every** state (5000 of
//! 5000), dephasing raised `Φ` in 0 of 2000, and the obvious repair — adding a Hamiltonian term — was
//! implemented and produced 0.000 survivors. The conclusion the theory draws is that *integration is
//! maintained only by a writing from outside*. A balanced holon loses its gate in about 25 ticks.
//!
//! FANOS diagnoses this correctly. [`homeostat::control`](crate::homeostat) raises
//! [`BandControl::Bind`](crate::homeostat::BandControl) on an under-coupled cell, and the healer forwards a
//! `Notification::Rebalance`. What the platform then does with it, in production, is `info!`. The only
//! derived answer beside it — [`loadbalance::balance_exact`](crate::loadbalance) — drives every node to the
//! cell's global mean, which is precisely the shape UHM measured as **harmful**: blind cell-wide exchange
//! monotonically dilutes everyone, and past a threshold collapses a colony of seven into a crowd with no
//! conscious members.
//!
//! # The five conditions, and where each one lands here
//!
//! 1. **Step size** (`1547ab4`). The transition is discontinuous: between `λ = 0.4` and `0.5` correlation
//!    jumps to `r̄ = 1.000` and carriers vanish. A band controller catches the *crossing*, not a jump caused
//!    by one application, so one application must be **unable** to leave the band. [`prescribe`] does not
//!    bound `λ` with an inequality someone chose — it evaluates the platform's own law on the resulting
//!    cell and keeps the largest `λ` whose result is still inside the band.
//! 2. **Personal anchor** (`1547ab4`). Not this module's to supply, and it is *not* silently assumed: see
//!    [`Prescription::NoDonor`], the arm that fires when nothing distinguishes the donors.
//! 3. **Injection, not amplification** (`1ea2b27`). Feeding through the organism's own regenerative channel
//!    self-locks — satiety raises `R → 1` while regeneration goes as `(1 − R)` — and *more* feeding was
//!    strictly worse across 27 regimes. What works is a convex mixture `(1−λ)Γ + λρ_food` at a modest `λ`,
//!    which bypasses the loop. [`Lift`] is exactly that mixture, applied to one node's couplings.
//! 4. **The medicine has an ADDRESS** (`1ea2b27`). On a colony of seven, blind exchange dilutes; naming the
//!    starving axis and drawing from the one donor specialised in it passes every threshold. So a
//!    prescription is a *pair*, never a cell-wide instruction: [`CoherenceMatrix::starved_axis`] names the
//!    recipient, and the donor is the node most strongly coupled to it — the reading that says "specialised
//!    in this axis" in the only vocabulary the matrix has.
//! 5. **Hierarchical lift is a degeneracy, not a face**. Out of scope here — this module lifts *within* a
//!    cell. See #167.
//!
//! # What this module is not
//!
//! It **decides**; it does not act. There is no protocol message here and no caller in a running node. That
//! is deliberate and is the honest state: the actuator has to carry a pair and a weight across the cell, and
//! that is a wire change with its own agreement problem. What was missing before was not the wire — it was
//! *the answer*, and an answer that is a cell-wide broadcast is measurably the wrong one.

use alloc::vec;

use crate::coherence::CoherenceMatrix;
use crate::eig::eigenvalues_symmetric;
use crate::window::CollectiveState;

/// A prescribed injection: feed `recipient` from `donor` at convex weight `lambda`.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Lift {
    /// The **hungry axis** — the node whose activity share is furthest below an equal one.
    pub recipient: usize,
    /// The **one** donor drawn from: the node most strongly coupled to the recipient, which is what
    /// "specialised in that axis" means in the matrix's own vocabulary. One, not the cell (condition 4).
    pub donor: usize,
    /// The convex mixing weight, in `(0, MAX_LAMBDA]`. Derived by evaluating the result, not chosen.
    pub lambda: f64,
}

/// What the lifter decided, including every reason it declined.
///
/// Four arms rather than an `Option`, because "no lift" has four different meanings and an operator or a
/// future executor must be able to tell them apart — a cell that needs nothing, a cell with no one to feed,
/// a cell with no one to feed *from*, and a cell where every admissible dose would overshoot.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Prescription {
    /// The cell is **not under-coupled** — it is already a collective subject, or over-coupled, where the
    /// answer is `Decouple` and not this. Feeding here is the harm condition 3 names.
    NotIndicated,
    /// Nobody is starving: the activity shares are within [`HUNGER_FLOOR`] of uniform, so there is no axis
    /// to address and a lift would be the blind exchange condition 4 rules out.
    NoHungryAxis,
    /// Someone is starving and **no donor is distinguishable**: the candidates' couplings to the hungry
    /// axis are within [`SPECIALISATION_FLOOR`] of each other, so "the one specialised in it" does not
    /// exist. Drawing from an arbitrary one would be blind exchange wearing an address.
    NoDonor,
    /// Every admissible dose down to [`MIN_LAMBDA`] either leaves the band or is not a reachable state.
    /// Reported rather than clamped to zero: a dose of nothing dressed as a treatment is what #275 nearly
    /// shipped on the shedding side.
    Overshoots,
    /// Feed, at this weight.
    Feed(Lift),
}

/// The largest weight ever prescribed.
///
/// UHM's colony reached every threshold at `λ ≈ 0.02`, and its sweep found *more* feeding strictly worse
/// across 27 regimes — so this is not a performance knob to open up. It is a ceiling on the search below,
/// and the search may return far less; what it may never do is return more.
pub const MAX_LAMBDA: f64 = 0.02;

/// The smallest weight worth prescribing. Below this the mixture is inside the estimator's own noise on a
/// realistic observation window, so a "lift" would be a report rather than a treatment.
pub const MIN_LAMBDA: f64 = 1e-4;

/// How far below an equal share counts as hungry, as a fraction of that equal share.
///
/// A cell is never exactly uniform, and treating a rounding-level deficit as an axis would produce a
/// prescription every round — which is the blind-exchange failure reached one dose at a time.
pub const HUNGER_FLOOR: f64 = 0.10;

/// How much more coupled to the hungry axis the best donor must be than the runner-up, in absolute
/// correlation, before it counts as *specialised* in that axis rather than merely first in an ordering.
pub const SPECIALISATION_FLOOR: f64 = 0.02;

/// Decide the cell's lift.
///
/// Returns [`Prescription::Feed`] only when all four hold: the cell is under-coupled, an axis is genuinely
/// hungry, one donor is genuinely specialised in it, and a dose exists whose *evaluated* result is a
/// reachable state still inside the band.
#[must_use]
pub fn prescribe(g: &CoherenceMatrix) -> Prescription {
    if g.collective_state() != CollectiveState::Aggregate {
        return Prescription::NotIndicated;
    }
    let n = g.n();
    let Some((recipient, shortfall)) = g.starved_axis() else {
        return Prescription::NoHungryAxis;
    };
    if shortfall < HUNGER_FLOOR / n as f64 {
        return Prescription::NoHungryAxis;
    }
    let Some(donor) = specialised_donor(g, recipient) else {
        return Prescription::NoDonor;
    };

    // Condition 1, by evaluation rather than by an inequality: halve the dose until the RESULT is a
    // reachable state that is still inside the band. The largest surviving dose is the prescription, so a
    // single application provably cannot carry the cell past the edge — the check is the platform's own
    // classifier on the mixed cell, not a bound on how far `r` might move.
    let mut lambda = MAX_LAMBDA;
    while lambda >= MIN_LAMBDA {
        if let Some(after) = apply(g, Lift { recipient, donor, lambda })
            && after.collective_state() != CollectiveState::OverCoupled
        {
            return Prescription::Feed(Lift { recipient, donor, lambda });
        }
        lambda /= 2.0;
    }
    Prescription::Overshoots
}

/// The node most strongly coupled to `axis`, if it is distinguishably more so than the runner-up.
fn specialised_donor(g: &CoherenceMatrix, axis: usize) -> Option<usize> {
    let (mut best, mut best_c, mut runner_c) = (usize::MAX, f64::NEG_INFINITY, f64::NEG_INFINITY);
    for j in 0..g.n() {
        if j == axis {
            continue;
        }
        let c = g.pairwise(axis, j)?.abs();
        if c > best_c {
            runner_c = best_c;
            (best, best_c) = (j, c);
        } else if c > runner_c {
            runner_c = c;
        }
    }
    (best != usize::MAX && best_c - runner_c >= SPECIALISATION_FLOOR).then_some(best)
}

/// Apply a lift and return the resulting cell, or `None` if the result is not a state a cell can be in.
///
/// The mixture is on the **recipient's couplings only** — `c_rk ← (1−λ)c_rk + λ c_dk` for every other node
/// `k`, and `c_rd ← (1−λ)c_rd + λ` toward the donor's own unit self-coupling. That is the convex form of
/// condition 3 written at the level the matrix exposes: the recipient's row moves a little way toward the
/// donor's, and nothing else in the cell is touched. A cell-wide version of the same expression would be
/// the blind exchange condition 4 rules out.
///
/// **PSD is checked, not assumed.** `from_correlation` accepts any symmetric unit-diagonal matrix in range,
/// so a mixture can be arithmetically fine and still not be a correlation matrix of anything. A
/// prescription evaluated on an unreachable state would be advice about a cell that cannot exist
/// ([[a-probe-must-admit-only-reachable-states]]), so the eigenvalues are read and a negative one refuses.
#[must_use]
pub fn apply(g: &CoherenceMatrix, lift: Lift) -> Option<CoherenceMatrix> {
    let (n, r, d) = (g.n(), lift.recipient, lift.donor);
    if r >= n || d >= n || r == d || !(0.0..=1.0).contains(&lift.lambda) {
        return None;
    }
    let mut c = vec![0.0; n * n];
    for i in 0..n {
        for j in 0..n {
            *c.get_mut(i * n + j)? = g.pairwise(i, j)?;
        }
    }
    for k in 0..n {
        if k == r {
            continue;
        }
        // The donor's coupling to itself is 1, which is what makes this a mixture toward the donor rather
        // than an average with it.
        let toward = if k == d { 1.0 } else { g.pairwise(d, k)? };
        let mixed = (1.0 - lift.lambda) * g.pairwise(r, k)? + lift.lambda * toward;
        let mixed = mixed.clamp(-1.0, 1.0);
        *c.get_mut(r * n + k)? = mixed;
        *c.get_mut(k * n + r)? = mixed;
    }
    let eigs = eigenvalues_symmetric(&c, n)?;
    if eigs.iter().any(|&e| e < -1e-9) {
        return None;
    }
    CoherenceMatrix::from_correlation(c, n)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A cell at exchange strength `lambda`, node 0's activity scaled to `amp`, and — when `pair` is set —
    /// a second mode shared only between node 0 and that node.
    ///
    /// The private mode is what makes a donor **specialised in the hungry axis**. Without it every node is
    /// coupled to node 0 identically, and `prescribe` answers `NoDonor` — which is the correct answer and
    /// is how the first version of this fixture was caught: it starved a node in a cell where nothing
    /// distinguished the candidates, then expected an address to exist.
    fn cell(lambda: f64, amp: f64, pair: Option<usize>) -> CoherenceMatrix {
        const T: usize = 4096;
        let noise = |seed: u64| -> Vec<f64> {
            let mut s = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (0..T)
                .map(|_| {
                    s = s
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    f64::from((s >> 32) as u32) / f64::from(u32::MAX) * 2.0 - 1.0
                })
                .collect()
        };
        let shared = noise(0x00C0_FFEE);
        let private = noise(0x0BAD_F00D);
        let signals: Vec<Vec<f64>> = (0..7)
            .map(|i| {
                let own = noise(0x5EED + i as u64);
                let scale = if i == 0 { amp } else { 1.0 };
                let extra = f64::from(u8::from(pair == Some(i) || (pair.is_some() && i == 0))) * 0.35;
                (0..T)
                    .map(|t| {
                        scale
                            * ((1.0 - lambda - extra) * own[t] + lambda * shared[t] + extra * private[t])
                    })
                    .collect()
            })
            .collect();
        CoherenceMatrix::from_signals(&signals).expect("real signals give a PSD correlation matrix")
    }

    /// **The lift raises `Φ` and stays inside the band** — both halves, because either alone is worthless.
    #[test]
    fn a_prescribed_lift_raises_integration_without_leaving_the_band() {
        let before = cell(0.25, 0.25, Some(3)); // under-coupled, node 0 starved
        assert_eq!(
            before.collective_state(),
            CollectiveState::Aggregate,
            "the fixture must be the state a lift is for"
        );
        let Prescription::Feed(lift) = prescribe(&before) else {
            panic!("no prescription for an under-coupled cell with a starved axis: {:?}", prescribe(&before));
        };
        let after = apply(&before, lift).expect("the prescribed dose was evaluated as reachable");
        println!(
            "lift: feed node {} from node {} at λ={:.5} — Φ {:.6} → {:.6}, state {:?} → {:?}",
            lift.recipient,
            lift.donor,
            lift.lambda,
            before.measures().phi,
            after.measures().phi,
            before.collective_state(),
            after.collective_state()
        );
        assert_eq!(lift.recipient, 0, "the starved node is the one addressed");
        assert!(lift.lambda <= MAX_LAMBDA, "never more than the ceiling UHM's sweep justifies");
        assert!(
            after.measures().phi > before.measures().phi,
            "a lift that does not raise Φ is not a lift: {:.9} → {:.9}",
            before.measures().phi,
            after.measures().phi
        );
        assert_ne!(
            after.collective_state(),
            CollectiveState::OverCoupled,
            "one application must not carry the cell out of the band (condition 1)"
        );
    }

    /// Every declining arm must be reachable, or the enum is decoration.
    #[test]
    fn each_refusal_has_a_cell_that_produces_it() {
        // Not indicated: a cell already in the band.
        let in_band = cell(0.5, 1.0, None);
        assert_ne!(in_band.collective_state(), CollectiveState::Aggregate);
        assert_eq!(prescribe(&in_band), Prescription::NotIndicated);

        // No hungry axis: under-coupled, but the shares are uniform.
        let flat = cell(0.25, 1.0, None);
        assert_eq!(flat.collective_state(), CollectiveState::Aggregate);
        assert_eq!(
            prescribe(&flat),
            Prescription::NoHungryAxis,
            "a uniform cell has no axis to address, so the answer must not be a cell-wide dose"
        );

        // No donor: a starved axis whose couplings to every candidate are indistinguishable. The fixture
        // above is exactly that — one shared mode makes every pair equally coupled — so it is reached by
        // starving a node in a cell nobody is specialised in.
        // No donor: a starved axis in a cell where every candidate is coupled to it identically. One
        // shared mode does exactly that, and this arm caught the first draft of the fixture above.
        let no_specialist = cell(0.25, 0.25, None);
        assert_eq!(no_specialist.collective_state(), CollectiveState::Aggregate);
        assert_eq!(
            no_specialist.starved_axis().expect("a 7-node cell has an axis").0,
            0,
            "node 0 is the starved one, so the refusal below is about the DONOR and not the recipient"
        );
        assert_eq!(
            prescribe(&no_specialist),
            Prescription::NoDonor,
            "with nothing to distinguish the donors, an address does not exist and drawing from an \
             arbitrary one would be blind exchange wearing an address"
        );
    }

    /// The dose is DERIVED: raising the ceiling must not silently raise the prescription past the band.
    #[test]
    fn the_dose_is_the_largest_one_whose_evaluated_result_is_still_in_the_band() {
        let g = cell(0.25, 0.25, Some(3));
        let Prescription::Feed(lift) = prescribe(&g) else {
            panic!("expected a prescription");
        };
        // Twice the prescribed dose must be worse by the platform's own classifier, or the search stopped
        // early and the number is not the largest admissible one.
        let doubled = Lift { lambda: (lift.lambda * 2.0).min(1.0), ..lift };
        let over = apply(&g, doubled);
        let stayed = over.as_ref().is_some_and(|a| a.collective_state() != CollectiveState::OverCoupled);
        assert!(
            lift.lambda >= MAX_LAMBDA || !stayed,
            "λ={} was prescribed but twice it is still admissible, so the search returned early rather \
             than the largest safe dose",
            lift.lambda
        );
    }
}
