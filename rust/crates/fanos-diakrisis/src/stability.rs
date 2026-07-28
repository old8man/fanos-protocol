//! The T-104 stability primitives — the *measured* viability quantities of a coherent cell.
//!
//! This is the **sense** half of DDoS homeostasis (the **act** half is [`homeostat`](crate::homeostat)),
//! kept separate so the measurements are reusable without pulling in the control policy — the same
//! sense/act split the crate draws between [`coherence`](crate::coherence) and [`plan`](crate::plan).
//! Everything here is a pure function of scalars a symmetric cell already computes (`P`, the excursion),
//! so nothing binds it to any particular controller.
//!
//! From the corpus stability chapter (T-104): the stability radius `r_stab = √(P − 2/N)` is the Bures
//! distance from the healthy attractor `ρ*` to the viability boundary `P = 2/N`; the Lyapunov `V = ‖Γ − ρ*‖²`
//! contracts as `√V' ≤ −κ√V + ‖h‖`, so a bounded disturbance settles the excursion into the ball `‖h‖/κ`
//! and, once it abates, decays geometrically. See `docs/ddos-homeostasis.md`.

use crate::coherence::p_crit;
use crate::healing::KAPPA_BOOTSTRAP;
use crate::mathfns::{log2, sqrt};

/// The canonical decoherence-channel survival threshold `‖δΓ₂‖ < κ_bootstrap/2` (T-104 §6.1): the largest
/// *aggregate* multi-target-DDoS noise a cell absorbs while remaining viable. The factor ½ (versus the
/// `h^(R)` threshold `κ_bootstrap`) is because a noise attack raises dissipation *and* depresses the
/// environmental coherence `Coh_E` the cell would regenerate from — the double blow.
pub const NOISE_SURVIVAL_THRESHOLD: f64 = KAPPA_BOOTSTRAP / 2.0;

/// The optimal purity `P_opt = 3/N` — the upper edge of the collective-subject / Goldilocks band, where the
/// V-preservation gate saturates (`g_V = 1`).
#[must_use]
pub fn p_opt(n: usize) -> f64 {
    3.0 / n as f64
}

/// The stability radius `r_stab = √(max(0, P − 2/N))` (T-104): the Bures distance from the healthy
/// attractor to the viability boundary — the cell's viability speedometer. Exactly zero at or below
/// collapse (`P ≤ 2/N`), so it is a genuine "how much can I still take" gauge.
#[must_use]
pub fn stability_radius(purity: f64, n: usize) -> f64 {
    sqrt((purity - p_crit(n)).max(0.0))
}

/// The V-preservation gate `g_V(P) = clamp((P − 2/N)/(3/N − 2/N), 0, 1)` (corpus `variational`, T-124):
/// the fraction of regeneration authority that is *enabled* by the current purity. It is `0` at or below
/// viability (`P ≤ 2/N` — regeneration switches off, the death-spiral point of no return) and `1` at or
/// above `P_opt = 3/N`. This is what makes self-recovery impossible below the boundary: the gate, not the
/// rate, is what closes.
#[must_use]
pub fn v_preservation_gate(purity: f64, n: usize) -> f64 {
    let (pc, po) = (p_crit(n), p_opt(n));
    ((purity - pc) / (po - pc)).clamp(0.0, 1.0)
}

/// One discrete step of the T-104 Lyapunov contraction in the excursion norm `e = ‖Γ − ρ*‖`:
/// `e_{k+1} ≤ (1 − κ)·e_k + h` — the discretization of `e' ≤ −κ·e + ‖h‖`. With `κ ∈ (0, 1]` this is a
/// contraction toward the attractor whose fixed point is the ultimate excursion `h/κ`. Exposed so the
/// contraction can be *checked numerically* (the ISS property test) rather than merely asserted.
#[must_use]
pub fn excursion_step(excursion: f64, kappa: f64, noise: f64) -> f64 {
    let kappa = kappa.clamp(0.0, 1.0);
    ((1.0 - kappa) * excursion.max(0.0) + noise.max(0.0)).max(0.0)
}

/// The ultimate (steady-state) excursion under sustained noise `h` at gain `κ`: `h/κ` (`∞` if `κ = 0`) —
/// the radius of the ball the coherence never leaves (the T-104 ISS bound). Shrinks with the gain, so a
/// stronger controller holds the self-model closer to health under the same flood.
#[must_use]
pub fn ultimate_excursion(kappa: f64, noise: f64) -> f64 {
    if kappa > 0.0 {
        noise / kappa
    } else {
        f64::INFINITY
    }
}

/// Whether a cell at stability radius `r_stab` survives sustained noise `h` at gain `κ` without reaching
/// the viability boundary: the T-104 survival condition `h < κ·r_stab`. The excursion then settles inside
/// the viable region (`h/κ < r_stab`) rather than crossing `∂𝒱`.
#[must_use]
pub fn survives(stability_radius: f64, kappa: f64, noise: f64) -> bool {
    noise < kappa * stability_radius
}


/// The largest admission difficulty this law will demand, in bits.
///
/// Derived, not chosen: a proof of `b` bits costs `2^b` hashes in expectation, so the ceiling is the point at
/// which an *honest* joiner can still finish in a tolerable time on ordinary hardware. At roughly `10^7` hashes a
/// second — a single modest core — a one-minute budget is `log₂(60 · 10^7) ≈ 29.2` bits. Thirty is that bound.
///
/// The ceiling is not a safety valve for the cell; it is a safety valve for the *newcomer*. An unbounded cost
/// would deny entry to the honest along with the flood, which is the attacker's goal achieved by the defence.
pub const MAX_ADMISSION_BITS: u32 = 30;

/// The cell's **stress ratio** `s = (‖h‖/κ) / r_stab` — the T-104 excursion ball as a fraction of the distance
/// to the viability boundary.
///
/// Dimensionless on purpose, so a control law built on it carries no units to calibrate and no threshold to
/// tune. `s = 0` is an unperturbed cell; `s = 1` is the survival condition [`survives`] exactly at equality —
/// the excursion ball touching `∂𝒱`; `s > 1` is the death spiral, where the ball extends past the boundary and
/// the V-preservation gate has closed.
///
/// A cell with no room left (`r_stab = 0`, meaning `P ≤ 2/N`) is already past the boundary, so any noise at all
/// reads as unbounded stress rather than as a division to be papered over.
#[must_use]
pub fn stress(stability_radius: f64, kappa: f64, noise: f64) -> f64 {
    let ball = ultimate_excursion(kappa, noise);
    if stability_radius <= 0.0 {
        return if ball > 0.0 { f64::INFINITY } else { 0.0 };
    }
    ball / stability_radius
}

/// The stress a node can actually **measure about itself**: `1 − g_V(P)`.
///
/// [`stress`] is the honest T-104 quantity and the right one for analysis, but it needs `‖h‖` — the magnitude of
/// the disturbance being *offered* — and a node cannot observe that. It sees its own coherence, not the flood
/// aimed at it. A controller built on a quantity it must model rather than read is a controller with a model to
/// be wrong about, and the first closed-loop simulation of exactly that produced a limit cycle: the law relaxed
/// on its estimate faster than the cell recovered, re-admitted the flood, and oscillated the purity down.
///
/// The observable form is already in the theory. The V-preservation gate `g_V(P)` is `1` at the optimal purity
/// `3/N`, falls linearly through the collective-subject band, and is exactly `0` at the viability boundary
/// `2/N` — where regeneration switches off. So `1 − g_V` is a dimensionless stress that is `0` in health, `1` at
/// the boundary, needs nothing but `P`, and diverges the law precisely where the theory says self-recovery
/// stops being possible.
///
/// The two agree on the frontier and differ in what they require: use [`stress`] to reason, this to act.
#[must_use]
pub fn observed_stress(purity: f64, n: usize) -> f64 {
    1.0 - v_preservation_gate(purity, n)
}

/// Infer the disturbance `a` a cell is under, from **its own purity trajectory**.
///
/// The measurement that makes the admission law leading instead of lagging, and it is an inversion rather than
/// an estimate. The reduced master equation ([`crate::dynamics`]) reads
///
/// ```text
///     dP/dτ = -2·(λ + a)·(P - 1/N) + 2·κ·g_V(P)·(P_ideal - P)
/// ```
///
/// Every term but `a` is either known to the node (`λ`, `κ`, `P_ideal`, `N`) or measured by it (`P`, and `dP/dτ`
/// from two consecutive observation windows). Solving for the one unknown:
///
/// ```text
///     a = [2·κ·g_V·(P_ideal - P) - dP/dτ] / [2·(P - 1/N)] - λ
/// ```
///
/// **Why this and not the purity itself.** The first two closed-loop experiments drove the controller from the
/// purity's *level* and the cell died anyway, because that quantity only moves once damage is done — and by then
/// `g_V` has throttled the very regeneration that would undo it. The descent *rate* carries a flood on the first
/// window, while `P` is still healthy. V17 says the same thing structurally: the failure region sits inside the
/// integration alarm, so the earliest signal is never the level of the thing that fails last.
///
/// Returns `0` rather than a negative number when the trajectory is better than the undisturbed flow predicts —
/// a cell recovering faster than expected is not under negative attack — and `0` at the maximally mixed floor,
/// where `P - 1/N = 0` leaves `a` genuinely unidentifiable.
#[must_use]
pub fn inferred_disturbance(
    purity: f64,
    purity_rate: f64,
    lambda: f64,
    kappa: f64,
    p_ideal: f64,
    n: usize,
) -> f64 {
    let mixed = 1.0 / n as f64;
    let denominator = 2.0 * (purity - mixed);
    if denominator <= 0.0 {
        return 0.0; // at the mixed floor the disturbance leaves no trace in this coordinate
    }
    let regeneration = 2.0 * kappa * v_preservation_gate(purity, n) * (p_ideal - purity);
    ((regeneration - purity_rate) / denominator - lambda).max(0.0)
}

/// The admission difficulty a cell under stress `s` should demand, in proof-of-work bits.
///
/// **The missing actuator.** T-104 says a cell survives a sustained flood iff `‖h‖ < κ·r_stab`, and everything
/// FANOS does about a disturbance — the homeostat's band control, the healing plan's reroute and repair —
/// acts on `κ` and on internal structure. Nothing acted on `‖h‖`. Against a flood large enough, the theorem is
/// explicit that the cell dies and no amount of internal healing changes it. The only decentralized lever on the
/// *input* side is the cost of entry, and it was a static number in a configuration file — set once, by a human,
/// which is precisely the failure mode of every network that answers a flood by pushing a parameter.
///
/// ## The derivation
///
/// A proof of `b` bits admits attempts at rate proportional to `2^-b`. Hold the admitted share of offered load
/// equal to the headroom the cell has left, `1 − s`:
///
/// ```text
///     2^(−Δb) = 1 − s     ⟹     Δb = −log₂(1 − s)
/// ```
///
/// so `bits(s) = base − log₂(1 − s)`. Every constant in it belongs to the theory already — `κ_bootstrap` and
/// `2/N` through `s` — and the operator supplies only the peacetime `base`.
///
/// | stress `s` | extra bits | cost multiplier |
/// |---|---|---|
/// | 0    | 0  | ×1 — peace is free |
/// | ½    | 1  | ×2 |
/// | ¾    | 2  | ×4 |
/// | ⅞    | 3  | ×8 |
/// | → 1  | → ∞ | diverges exactly where the theorem places the boundary |
///
/// Clamped at [`MAX_ADMISSION_BITS`], and at `s ≥ 1` it simply *is* the maximum: past the survival bound the
/// honest answer is that this cell has no capacity to offer, not a slightly larger number.
///
/// ## Why this is better than a pushed parameter
///
/// Every node computes this from its **own** measurement. There is no consensus to reach, no authority to
/// petition, and therefore none to capture, coerce or wait for — the response is live within one observation
/// window instead of a release cycle. And it leaks nothing to a passive observer: the only way to learn a cell's
/// current difficulty is to attempt to join it, which is information an attacker already has, since they are the
/// one supplying the stress.
#[must_use]
pub fn admission_bits(base_bits: u32, stress: f64) -> u32 {
    // NaN included by construction: an unmeasurable stress must not silently raise the cost of entry, so
    // anything that is not positively greater than zero falls through to the peacetime difficulty.
    if stress.is_nan() || stress <= 0.0 {
        return base_bits.min(MAX_ADMISSION_BITS);
    }
    if stress >= 1.0 {
        return MAX_ADMISSION_BITS;
    }
    let extra = -log2(1.0 - stress);
    // `extra` is finite here (0 < stress < 1), so the cast is bounded by the clamp below.
    let raised = f64::from(base_bits) + extra;
    if raised >= f64::from(MAX_ADMISSION_BITS) {
        MAX_ADMISSION_BITS
    } else {
        // Round up: a fractional bit of demanded work is a bit the attacker does not have to do.
        raised.ceil() as u32
    }
}

/// The admission controller: the law with the **memory** it needs to work.
///
/// [`admission_bits`] is the correct instantaneous relation and, driven directly from a live measurement, it
/// oscillates — for a reason worth stating, because it is a property of the problem and not of the code.
///
/// **The disturbance is only observable while it is being admitted.** [`inferred_disturbance`] reads the flood
/// correctly on the first window and the law prices it out; the next window therefore shows a quiet cell, the
/// inference honestly reports no disturbance, the price drops, and the flood returns. The controller ends up
/// admitting the attack half the time, which for a sustained flood is as fatal as admitting all of it. Measured:
/// a cell driven this way dies exactly as fast as an unpriced one.
///
/// The system is observable only when it is under attack, so a controller cannot re-derive its estimate every
/// window — it must **hold** it and let it decay. The decay rate is not a new parameter: the T-104 contraction
/// says an excursion falls as `(1 − κ)` per window once the disturbance abates, so releasing the price at that
/// same rate is the matched choice. Releasing faster than the cell recovers is precisely what produced the
/// oscillation; releasing slower would leave a cell needlessly closed after an attack ends.
///
/// So: raise instantly on evidence, release at the system's own recovery constant.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionController {
    /// Extra bits above the operator's peacetime base, held between windows and decayed at rate `κ`.
    extra: f64,
}

impl Default for AdmissionController {
    fn default() -> Self {
        Self::new()
    }
}

impl AdmissionController {
    /// A controller at rest — no extra cost demanded.
    #[must_use]
    pub const fn new() -> Self {
        Self { extra: 0.0 }
    }

    /// Fold one window's measured `stress` in, and return the difficulty to demand now.
    ///
    /// Raises to whatever this window's evidence justifies; otherwise decays what it was already holding.
    ///
    /// `retention` is the fraction of the held price that survives **one observation window** — the cell's own
    /// recovery constant expressed in the caller's time units, `1 − κ·Δt` for a window of length `Δt`. The units
    /// are the caller's to get right and they matter: passing the per-unit-time `1 − κ` for a window a hundred
    /// times shorter drains the memory in a few windows and restores the oscillation this type exists to
    /// prevent. Measured, when exactly that mistake was made here.
    pub fn observe(&mut self, base_bits: u32, stress: f64, retention: f64) -> u32 {
        let demanded = f64::from(admission_bits(base_bits, stress)) - f64::from(base_bits);
        let decayed = self.extra * retention.clamp(0.0, 1.0);
        self.extra = if demanded > decayed { demanded } else { decayed };
        let raised = f64::from(base_bits) + self.extra;
        if raised >= f64::from(MAX_ADMISSION_BITS) {
            MAX_ADMISSION_BITS
        } else {
            raised.ceil() as u32
        }
    }

    /// The extra bits currently held, for an operator surface that wants to show the cost of an attack.
    #[must_use]
    pub fn held_bits(&self) -> f64 {
        self.extra
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    const N: usize = 7;

    #[test]
    fn stress_is_one_exactly_where_the_survival_condition_turns() {
        // `s` must agree with `survives` at the boundary, or the control law would be defending a different
        // frontier from the one the theorem proves.
        let r = stability_radius(3.0 / 7.0, N); // mid-band
        let kappa = 0.5;
        let critical_noise = kappa * r; // `survives` is `noise < κ·r_stab`
        assert!(!survives(r, kappa, critical_noise), "at equality the cell does not survive");
        let s = stress(r, kappa, critical_noise);
        assert!((s - 1.0).abs() < 1e-12, "stress at the survival boundary must be exactly 1, got {s}");
        assert!(stress(r, kappa, critical_noise * 0.5) < 1.0, "half the critical noise is survivable");
        assert!(stress(r, kappa, critical_noise * 2.0) > 1.0, "twice it is the death spiral");
    }

    #[test]
    fn a_cell_past_the_viability_boundary_reads_as_unbounded_stress() {
        // `r_stab = 0` means `P ≤ 2/N`: the V-preservation gate has closed and there is no headroom left. Any
        // noise at all is then unbounded stress — not a division to be quietly clamped.
        let r = stability_radius(p_crit(N), N);
        assert_eq!(r, 0.0, "at the boundary the radius is exactly zero");
        assert!(stress(r, 0.5, 0.01).is_infinite(), "no headroom + any noise = unbounded");
        assert_eq!(stress(r, 0.5, 0.0), 0.0, "no headroom and no noise is not stress, it is stillness");
    }

    #[test]
    fn the_admission_law_reproduces_its_own_derivation() {
        // `Δb = −log₂(1 − s)`: the table in the doc comment, asserted. Each row is a halving of the headroom
        // and therefore exactly one more bit of work.
        const BASE: u32 = 8;
        assert_eq!(admission_bits(BASE, 0.0), BASE, "peace is free");
        assert_eq!(admission_bits(BASE, 0.5), BASE + 1, "half the headroom gone doubles the cost");
        assert_eq!(admission_bits(BASE, 0.75), BASE + 2);
        assert_eq!(admission_bits(BASE, 0.875), BASE + 3);
        // The law is monotone in stress — a cell under more pressure never asks for less work.
        let mut previous = 0;
        for i in 0..=100 {
            let bits = admission_bits(BASE, f64::from(i) / 100.0);
            assert!(bits >= previous, "difficulty fell as stress rose: {bits} after {previous}");
            previous = bits;
        }
    }

    #[test]
    fn past_the_survival_bound_the_cell_offers_no_capacity() {
        // At `s ≥ 1` the honest answer is the maximum, not a slightly larger number: the theorem says this cell
        // has no capacity to give away.
        assert_eq!(admission_bits(8, 1.0), MAX_ADMISSION_BITS);
        assert_eq!(admission_bits(8, 12.5), MAX_ADMISSION_BITS);
        assert_eq!(admission_bits(8, f64::INFINITY), MAX_ADMISSION_BITS);
    }

    #[test]
    fn an_unmeasurable_stress_never_raises_the_cost_of_entry() {
        // The failure mode that would matter most in production: a sensor that goes NaN must not silently close
        // the network. Failing *open* is right here — a broken gauge is not evidence of an attack.
        assert_eq!(admission_bits(9, f64::NAN), 9);
        assert_eq!(admission_bits(9, -1.0), 9, "a negative stress is not a reason to demand more work");
    }

    #[test]
    fn the_ceiling_protects_the_newcomer_not_the_cell() {
        // `MAX_ADMISSION_BITS` is set by what an honest joiner can still complete — roughly a minute on one
        // modest core — because an unbounded cost denies entry to the honest along with the flood, which is the
        // attacker's goal reached through the defence.
        let hashes = crate::mathfns::powi(2.0, MAX_ADMISSION_BITS);
        let seconds_at_ten_million_per_second = hashes / 1.0e7;
        assert!(
            seconds_at_ten_million_per_second < 300.0,
            "the ceiling demands {seconds_at_ten_million_per_second:.0}s of a single core — too much to join"
        );
        // …and it must be high enough to actually cost an attacker something.
        assert!(MAX_ADMISSION_BITS >= 20, "a ceiling below ~20 bits is free at flood scale");
    }

    #[test]
    fn a_base_difficulty_above_the_ceiling_is_still_bounded() {
        // An operator may configure any number; the newcomer's budget still governs.
        assert_eq!(admission_bits(64, 0.0), MAX_ADMISSION_BITS);
        assert_eq!(admission_bits(u32::MAX, 0.9), MAX_ADMISSION_BITS);
    }

    /// The closed loop on the real reduced-master-equation simulator: a flood the cell **dies to** unpriced and
    /// **survives** when it prices entry from what it infers about its own trajectory.
    ///
    /// The claim the law exists to make, measured rather than argued — and it took three attempts, each of which
    /// taught the design something:
    ///
    /// 1. driving the controller from a *modelled* offered load produced a limit cycle: it relaxed on its own
    ///    estimate faster than the cell recovered, re-admitted the flood, and oscillated the purity down;
    /// 2. driving it from the purity *level* (`1 − g_V`) died anyway, because that quantity only moves after
    ///    damage — and by then `g_V` has throttled the regeneration that would have undone it;
    /// 3. driving it from the *inferred disturbance* works, because the descent rate carries the attack on the
    ///    first window, while the purity is still healthy.
    #[test]
    fn the_admission_law_saves_a_cell_that_would_otherwise_die() {
        use crate::dynamics::PurityDynamics;

        const BASE_BITS: u32 = 8;
        const OFFERED: f64 = 0.20; // a sustained flood, far past what this cell absorbs unpriced
        const STEPS: usize = 6_000;
        // Parameters of a cell that is **viable when undisturbed** — asserted below, because the first version of
        // this experiment used a `λ` so large that the cell died with no attack at all, and every "the law did not
        // save it" reading was really "there was nothing to save".
        let (lambda, kappa, p_ideal, dt) = (0.005, KAPPA_BOOTSTRAP, 3.0 / 7.0, 0.01);

        let mut quiet = PurityDynamics::new(lambda, kappa, p_ideal, dt, N, 3.0 / 7.0);
        for _ in 0..STEPS {
            quiet.step(0.0);
        }
        assert!(
            quiet.viable(),
            "the fixture cell is not viable undisturbed (P = {}) — it has no equilibrium above the boundary, so \
             this experiment could only ever measure its own parameters",
            quiet.purity()
        );

        // --- unpriced: the offered load arrives in full ---
        let mut open = PurityDynamics::new(lambda, kappa, p_ideal, dt, N, 3.0 / 7.0);
        for _ in 0..STEPS {
            open.step(OFFERED);
        }
        assert!(
            !open.viable(),
            "the fixture is not a flood — an unpriced cell survived it at P = {}, so this proves nothing",
            open.purity()
        );

        // --- priced: each window, infer the disturbance from the trajectory and charge for entry ---
        let mut priced = PurityDynamics::new(lambda, kappa, p_ideal, dt, N, 3.0 / 7.0);
        let mut controller = AdmissionController::new();
        let (mut bits, mut peak_bits, mut previous) = (BASE_BITS, BASE_BITS, priced.purity());
        for _ in 0..STEPS {
            let share = crate::mathfns::powi(0.5, bits - BASE_BITS);
            let now = priced.step(OFFERED * share);
            let rate = (now - previous) / dt;
            previous = now;
            let a = inferred_disturbance(now, rate, lambda, kappa, p_ideal, N);
            let s = stress(stability_radius(now, N), kappa, a);
            bits = controller.observe(BASE_BITS, s, 1.0 - kappa * dt);
            peak_bits = peak_bits.max(bits);
        }
        assert!(
            priced.viable(),
            "the cell died at P = {} despite pricing entry (peaked at {peak_bits} bits)",
            priced.purity()
        );
        assert!(peak_bits > BASE_BITS, "the law never engaged, so the survival is not attributable to it");
        assert!(
            peak_bits <= MAX_ADMISSION_BITS,
            "the law demanded {peak_bits} bits, past what an honest joiner can pay"
        );
    }

    #[test]
    fn stability_radius_matches_t104() {
        // r_stab = √(P − 2/7): zero at the boundary, √(1/7) at the band's upper edge P = 3/7.
        assert!(
            stability_radius(2.0 / 7.0, N).abs() < 1e-12,
            "zero at collapse"
        );
        assert!(
            stability_radius(0.2, N).abs() < 1e-12,
            "clamped to zero below the boundary"
        );
        assert!((stability_radius(3.0 / 7.0, N) - sqrt(1.0 / 7.0)).abs() < 1e-12);
        // A pure state P = 1 gives the theoretical maximum √(5/7).
        assert!((stability_radius(1.0, N) - sqrt(5.0 / 7.0)).abs() < 1e-12);
    }

    #[test]
    fn v_preservation_gate_is_the_clamped_ramp() {
        // g_V = clamp((P−2/7)/(3/7−2/7)) = clamp(7P − 2). Zero at/below 2/7, one at/above 3/7.
        assert_eq!(v_preservation_gate(2.0 / 7.0, N), 0.0);
        assert_eq!(v_preservation_gate(0.1, N), 0.0);
        assert_eq!(v_preservation_gate(3.0 / 7.0, N), 1.0);
        assert_eq!(v_preservation_gate(0.9, N), 1.0);
        // Midpoint P = 2.5/7 → g_V = 0.5, and equals the clamp(7P − 2) closed form.
        let p = 2.5 / 7.0;
        assert!((v_preservation_gate(p, N) - 0.5).abs() < 1e-12);
        assert!((v_preservation_gate(p, N) - (7.0 * p - 2.0).clamp(0.0, 1.0)).abs() < 1e-12);
    }

    #[test]
    fn the_excursion_contracts_to_the_ultimate_ball_under_sustained_noise() {
        // ISS: iterating e_{k+1} = (1−κ)e_k + h converges to the fixed point h/κ from any start.
        let kappa = 0.3;
        let noise = 0.05;
        let mut e = 2.0; // far from the attractor
        for _ in 0..500 {
            e = excursion_step(e, kappa, noise);
        }
        let want = ultimate_excursion(kappa, noise);
        assert!(
            (e - want).abs() < 1e-9,
            "converged to h/κ = {want}, got {e}"
        );
        assert!((want - noise / kappa).abs() < 1e-12);
    }

    #[test]
    fn the_excursion_decays_geometrically_once_the_attack_stops() {
        // With no noise the excursion decays as (1−κ)^k → 0: the cell springs back to the attractor.
        let kappa = 0.25;
        let mut e = 1.0;
        for _ in 0..200 {
            e = excursion_step(e, kappa, 0.0);
        }
        assert!(e < 1e-12, "excursion relaxes to zero, got {e}");
    }

    #[test]
    fn survival_is_the_canonical_threshold() {
        // Survives iff noise < κ·r_stab (T-104). The decoherence-channel bound is κ_bootstrap/2 = 1/14.
        let r_stab = stability_radius(3.0 / 7.0, N); // √(1/7) ≈ 0.378
        assert!(survives(r_stab, 0.5, 0.1), "0.1 < 0.5·0.378 survives");
        assert!(!survives(r_stab, 0.5, 0.3), "0.3 > 0.5·0.378 does not");
        assert!(
            (NOISE_SURVIVAL_THRESHOLD - 1.0 / 14.0).abs() < 1e-12,
            "h^(D) bound is 1/14"
        );
        // A cell at the boundary (r_stab = 0) survives no perturbation at all.
        assert!(!survives(0.0, 1.0, 1e-9));
    }
}
