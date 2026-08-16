//! The operator-facing **coherence snapshot** — a cell's vital signs, for humans *and* agents.
//!
//! A [`CoherenceFrame`] is the compact on-wire cell-aggregate observation. This folds it into a stable,
//! documented snapshot enriched with the *derived* operator quantities — the stability radius, the
//! theorem-fixed band thresholds, and a **readiness** verdict — and renders it as canonical JSON for
//! `fanos monitor --json` / OpenTelemetry / an agent consuming it programmatically. The bands are fixed
//! by theorems, not tuned: read *coherence*, not CPU. Readiness is `Φ ≥ 1 ∧ R ≥ 1/3` — a cell that is
//! one bound subject *and* still self-observing — which is the honest liveness gate a Kubernetes probe
//! or an SLO should read, in place of a hand-picked latency.
//!
//! ## This is the canonical summary, and why it has to live here (#277)
//!
//! There were four summaries of one thing. Three are legitimate and one was a fossil:
//!
//! - **[`CoherenceSnapshot`] — canonical.** Everything an operator or an agent reads about a cell's
//!   coherence goes through it: `fanos status coherence` off a deployed node's socket, the
//!   `fanos-monitor` panel, the OpenMetrics exposition, `--json`.
//! - `fanos_observatory::HealthSummary` — a five-field projection of this one for `/healthz`. A
//!   projection, not a rival: its own doc is that the two can never disagree.
//! - `fanos_sim::observatory::CoherenceReading` — the simulator's *forecasting* instrument, which sweeps a
//!   cascade and measures lead time. It reads a matrix because it has no node and no wire; the simulator's
//!   view of a node's telemetry goes through this snapshot, like production's.
//! - `fanos_diakrisis::VitalSigns` — **deleted.** It called itself "the one canonical, stable summary of a
//!   cell's health" and was constructed nowhere outside its own tests.
//!
//! The fossil is worth recording, because it says where the canonical summary *must* live. `VitalSigns`
//! read a [`CoherenceMatrix`](fanos_diakrisis::CoherenceMatrix) — and a matrix does not know where it came
//! from. So its readiness gate was `Φ ≥ 1 ∧ R ≥ 1/3`, the pre-#154 form: at the shipped
//! `healthy_correlation = 0.45` a node that had observed **nothing** produces exactly those numbers and
//! would have read ready. It could not have carried the third conjunct even if someone had thought to,
//! because **readiness is a question about provenance as much as about magnitudes**, and provenance is a
//! property of the frame. A summary one layer down cannot answer it. (Two smaller fossils rode along: band
//! edges from the flat `1/√(N−1)`, and the *steering* stability radius on a *reporting* surface.)
//!
//! ## What must NOT be added here
//!
//! This is an **export** surface — its JSON leaves the node. The data-path plane's counters
//! (`fanos_ports::stations`) are therefore deliberately absent, and adding them would be a defect rather than
//! an improvement: their per-family DP sensitivities are not yet derived (the way `Δr = 1/21` was for the
//! coherence frame), and a rate keyed by line is a signal a global passive adversary can correlate against
//! observed traffic. Station counts stay node-local until that analysis exists — see
//! `docs/design-observability.md` §8. If they ever do cross a boundary, they cross through
//! [`crate::dp`], never through a second unprivatized door beside it.

use alloc::string::String;
use core::fmt::Write as _;

use fanos_diakrisis::minima::OPTIMAL_INTEGRATION;
use fanos_diakrisis::stability::stability_radius_exact;

use crate::frame::{AlarmLevel, CellId, CoherenceFrame, Regime};

/// The Fano cell size `N = 7` (the DIAKRISIS observation unit, spec §6).
pub const CELL_N: usize = 7;

/// The largest supported plane, `PG(2,31)` — the ceiling on a recovered node count.
///
/// Present because the previous estimate clamped to [`CELL_N`], which silently capped every reading from a
/// cell larger than Fano at seven.
pub const MAX_CELL_N: usize = 993;

/// Integration threshold: a cell is one bound subject iff `Φ ≥ 1` (spec §6, V11).
pub const PHI_THRESHOLD: f64 = 1.0;
/// Purity floor `P_crit = 2/N` — the viability boundary (T-104).
pub const PURITY_FLOOR: f64 = 2.0 / CELL_N as f64;
/// Reflection floor: self-observation holds iff `R ≥ 1/3` (V19).
pub const REFLECTION_FLOOR: f64 = 1.0 / 3.0;
/// Cascade early-warning line `r* = 1/√6 ≈ 0.4082` — the onset of the systemic/cascade regime (§2.7).
pub const R_STAR: f64 = 0.408_248_290_463_863;
/// Over-coupling bound `1/√3 ≈ 0.5774` — above this the cell loses its self-model (`R < 1/3`, V19).
pub const OVER_COUPLING: f64 = 0.577_350_269_189_626;

// The collective-subject band is the half-open interval `(r*, 1/√3]`, so its endpoints must be
// ordered. A compile-time guarantee (stronger than a runtime test): if the published constants were
// ever mistyped out of order, the crate would fail to build.
const _: () = assert!(R_STAR < OVER_COUPLING);

/// A cell's vital signs at one observation window, enriched for an operator.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CoherenceSnapshot {
    /// The cell this observes.
    pub cell_id: CellId,
    /// The agreed epoch of the observation.
    pub epoch: u64,
    /// Integration `Φ` — is the cell one bound subject (`Φ ≥ 1`)? (the ECG.)
    ///
    /// **Not `6r²`.** This doc used to state the flat closed form as the definition; that is the
    /// equicorrelated stratum's special case, and #219 deleted it from the code precisely so the stratum
    /// could not be assumed by omission (UHM T-312/T-316). The general law is `Φ = r²·(1−p)/p` with `p` the
    /// cell's *diagonal* purity, and a reader who computes `6·mean_correlation²` on a cell whose behavioural
    /// weight is concentrated gets a number that is not this one.
    ///
    /// A reader who wants the relation back can have it from this struct alone: `p = purity/(1 + phi)`,
    /// since `P = p·(1 + Φ)`.
    pub phi: f64,
    /// Structuredness `P = Tr(Γ²)` — viable while `P > 2/N`.
    pub purity: f64,
    /// Reflection `R = 1/(N·P)` — self-observation holds while `R ≥ 1/3`.
    pub reflection: f64,
    /// Mean off-diagonal correlation `r` — compare against `r*` and the over-coupling bound.
    pub mean_correlation: f64,
    /// Polar spectral gap `Δ` (T-226(v)) — the healing-rate / density signal.
    pub spectral_gap: f64,
    /// Stability radius (T-104) — the Bures distance to the viability shell `{P = 2/N}`, i.e. the cell's
    /// viability speedometer.
    ///
    /// **This field carries the *exact* radius, not the one the homeostat steers on**, and the two are
    /// different functions on purpose. `fanos_diakrisis::stability` ships both: a closed runtime form
    /// (≤1.13% error across the window, <0.01% at the wall) that the shed law and the setpoint derivation
    /// use, and [`stability_radius_exact`] — machine-exact to `1e-14` — whose own doc says to use it *"when
    /// reporting a number rather than steering on one"*. This is the reporting surface: it reaches an
    /// operator through `fanos-observatory`'s dashboard and the `fanos_coherence_stability_radius` gauge,
    /// and nothing decides on it.
    ///
    /// The steering sites keep the runtime form deliberately. In particular the band setpoint `Φ*` is the
    /// max-min point *of the law the controller measures with* — derive it from the exact form instead and
    /// the homeostat would be aimed at a point its own gauge does not consider optimal.
    ///
    /// The old doc here read `√(max(0, P − 2/N))`. That form was refuted in 2026-08 (it overstates the
    /// margin by up to 81.7× at the viability wall, and the error grows precisely as the wall is
    /// approached); see `stability::stability_radius` for the derivation and the measured error table.
    pub stability_radius: f64,
    /// The collective-subject band classification.
    ///
    /// Not optional, deliberately, and [`verdict_understood`](Self::verdict_understood) is why: an encoding
    /// this build does not know is coerced *here*, once, to the most severe value in the vocabulary, and the
    /// coercion is reported beside the value rather than hidden inside it.
    pub regime: Regime,
    /// The leading-indicator alarm level. Same coercion rule as [`regime`](Self::regime).
    pub alarm: AlarmLevel,
    /// **Whether every field of the source frame's verdict byte was an encoding this build knows.**
    ///
    /// `false` means the frame came from a peer whose vocabulary is ahead of this one's — a reserved regime
    /// or alarm encoding, or a flag in the verdict byte's unused high bits. When it is `false`,
    /// [`regime`](Self::regime) and [`alarm`](Self::alarm) still carry a value, and that value is the most
    /// severe one this build can name. **That direction is chosen, not incidental**: #278 measured the two
    /// ways this can go wrong and found silence to be the dangerous one, so an unrecognised frame errs
    /// toward a false alarm an operator will investigate, never toward a quiet "healthy" it will not.
    ///
    /// It is a separate observable rather than an `Option` on the two fields for the reason
    /// [`CoherenceFrame::correlation_is_measured`] already established (#154): making the *value* optional
    /// pushes a fallback decision onto all fourteen of its readers, each free to invent a different one,
    /// while a companion flag leaves the value's meaning intact and lets exactly the readers that care ask.
    pub verdict_understood: bool,
    /// Whether a node fault is localized (`syndrome ≠ 0`).
    pub faulted: bool,
    /// The 3-bit fault syndrome (which points are degraded).
    pub syndrome: u8,
    /// Cascade forecast: ticks of lead time before a predicted cascade, or `-1` for none.
    pub cascade_lead: i16,
    /// The monotone self-healing action counter (a sparse healing timeline).
    pub heal_seq: u32,
    /// Readiness: `Φ ≥ 1 ∧ R ≥ 1/3` — bound *and* self-observing. The theorem-grounded liveness gate.
    pub ready: bool,
    /// The cell's alive-node count, recovered **exactly** as `N = 1/(R·P)`.
    ///
    /// Since `P = Tr(Γ²) = frob/n²` and `R = 1/(N·P) = n/frob`, their product is `1/n` on *any* coherence
    /// matrix. The compact 3-bit syndrome deliberately carries no count (Minimal Self-Observation Overhead
    /// theorem), and this recovers it from the measures already on the wire — no stratum assumption and no
    /// widening of the frame.
    ///
    /// It replaces an inversion of the equicorrelated identity `Φ = (N−1)·r²`, which was exact only for the
    /// liveness-only fold, approximate for frames built from measured per-node signals, undefined at `r ≈ 0`
    /// (a fully decorrelated cell — the *diversified* regime, not a fault), and clamped to [`CELL_N`], so a
    /// `PG(2,31)` cell reported at most seven alive nodes out of 993.
    ///
    /// Falls back to the binary syndrome signal only when `P = 0`, which means an unreadable matrix rather
    /// than any state a cell can be in.
    pub alive_nodes: u32,
    /// How far the cell sits from its **robust operating point**: `Φ − Φ*`, where `Φ* = 5/4`.
    ///
    /// Negative means under-coupled — nearer the collapse boundary than it needs to be; positive means nearer
    /// over-coupling. Zero is the point that maximizes the smaller of the two distances
    /// (`fanos_diakrisis::minima::OPTIMAL_INTEGRATION`, derived from the metric `r_stab` itself implies).
    ///
    /// **Why an operator needs it.** The band is `Φ ∈ (1, 2]` and [`Regime`] reports only *which* band the cell
    /// is in, so a cell at `Φ = 1.05` reads as a healthy collective subject, the homeostat correctly answers
    /// `Hold`, and nothing anywhere says its stability radius is a *third* of what the same cell could hold
    /// (`0.120` against `0.378` on a Fano plane). This is the number that says so.
    ///
    /// It reports; it does not steer. Teaching the homeostat to drive toward `Φ*` is a control-law change and
    /// is gated separately (`docs/open-tasks.md`).
    pub setpoint_offset: f64,
}

impl CoherenceSnapshot {
    /// Fold a [`CoherenceFrame`] into the operator snapshot, deriving `r_stab`, `alive_nodes`, and the
    /// readiness verdict.
    #[must_use]
    pub fn from_frame(frame: &CoherenceFrame) -> Self {
        let phi = f64::from(frame.phi);
        let purity = f64::from(frame.purity);
        let reflection = f64::from(frame.reflection);
        let mean_correlation = f64::from(frame.mean_r);
        let faulted = frame.is_faulted();
        // Recovered exactly from the frame's own measures, and used for *both* the node count and the
        // stability radius — `r_stab = √(P − 2/N)` was previously computed against a hard-coded seven, which
        // made the operator's headroom reading wrong on every cell that is not `PG(2,2)`.
        let alive = recover_cell_size(purity, reflection, faulted);
        Self {
            cell_id: frame.cell_id,
            epoch: frame.epoch,
            phi,
            purity,
            reflection,
            mean_correlation,
            spectral_gap: f64::from(frame.gap),
            stability_radius: stability_radius_exact(purity, alive.max(1) as usize),
            // The ONE place an unknown encoding is coerced, and it is written out rather than left to a
            // catch-all arm in the decoder. `unwrap_or` here reads as an assertion about the direction of
            // the error: toward the most severe value, never toward healthy (#278). Whether the coercion
            // happened at all is `verdict_understood` below.
            regime: frame.regime().unwrap_or(Regime::OverCoupled),
            alarm: frame.alarm().unwrap_or(AlarmLevel::Structure),
            verdict_understood: frame.fully_understood(),
            faulted,
            syndrome: frame.syndrome,
            cascade_lead: frame.forecast,
            heal_seq: frame.heal_seq,
            // **Self-observing is a premise, not a corollary** (#154). This read `Φ ≥ 1 ∧ R ≥ 1/3` and was
            // documented as *"bound and self-observing"* — but both scalars are the equicorrelated model's,
            // and when the node has no observation window the caller evaluates that model at the configured
            // `healthy_correlation = 0.45`, which gives `Φ = 1.215` and `R = 0.4514`. So a node that had
            // observed **nothing** satisfied its own liveness gate, on numbers chosen to be healthy. The
            // third conjunct is the one the sentence always claimed.
            ready: frame.correlation_is_measured()
                && phi >= PHI_THRESHOLD
                && reflection >= REFLECTION_FLOOR,
            alive_nodes: alive,
            setpoint_offset: phi - OPTIMAL_INTEGRATION,
        }
    }

    /// Whether the cell is a healthy, self-observing subject (`Φ ≥ 1 ∧ R ≥ 1/3`) — the readiness /
    /// liveness gate an operator (human or agent) should probe, grounded in the theorems, not a latency.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// Whether a cascade is forecast (a non-negative lead time).
    #[must_use]
    pub fn cascade_imminent(&self) -> bool {
        self.cascade_lead >= 0
    }

    /// The cell's **diagonal purity** `p = Σᵢ dᵢ²` — how concentrated its behavioural weight is.
    ///
    /// Recovered from two measures already on the wire rather than widened into the frame: `P = p·(1 + Φ)`
    /// is the general law's own identity, so `p = P/(1 + Φ)` exactly. `p = 1/N` is the flat (equicorrelated)
    /// stratum; `p → 1` is a cell where one node carries all the variance.
    ///
    /// Carried to f32 precision, because that is what the frame carries. That is ample for a band edge an
    /// operator reads and **not** enough to re-derive a verdict from — which is why nothing here does; see
    /// [`Self::collective_band`].
    #[must_use]
    pub fn diagonal_purity(&self) -> f64 {
        let denom = 1.0 + self.phi;
        if denom > 0.0 { self.purity / denom } else { f64::NAN }
    }

    /// The collective-subject band `(r*, r_over]` **of this cell** — the two edges of `Φ ∈ [1, 2]` solved
    /// at the cell's own diagonal, not at a flat seven-node one.
    ///
    /// [`R_STAR`] and [`OVER_COUPLING`] are these same two edges frozen at `p = 1/7`, and they are correct
    /// there and nowhere else: `r*` *rises* as behavioural weight concentrates, so on a lopsided cell the
    /// frozen pair sits below the real band. This is what a renderer should draw and what a reader should
    /// compare a `mean_correlation` against.
    ///
    /// **It is not a verdict, and must not be used as one.** The cell's regime is decided at the source, on
    /// the full matrix, and travels in [`Self::regime`] — the upper edge in particular is settled by the
    /// *measured* reflection rather than by `r` (#275), which no consumer of this snapshot can recompute.
    /// A consumer that re-derives the regime from `(r, p)` here is running a weaker law beside the
    /// answer it was handed (#277).
    #[must_use]
    pub fn collective_band(&self) -> (f64, f64) {
        fanos_diakrisis::window::collective_subject_window_at(self.diagonal_purity())
    }

    /// The viability floor `P_crit = 2/N` for **this** cell, using the node count recovered exactly from
    /// its own measures.
    ///
    /// [`PURITY_FLOOR`] is this at `N = 7`. The same substitution was already made for
    /// [`Self::stability_radius`] — whose old form "was previously computed against a hard-coded seven,
    /// which made the operator's headroom reading wrong on every cell that is not `PG(2,2)`" — and the
    /// floor that radius is measured *from* was left behind on the constant.
    #[must_use]
    pub fn purity_floor(&self) -> f64 {
        2.0 / f64::from(self.alive_nodes.max(1))
    }

    /// Canonical JSON — a flat, stable object for `fanos monitor --json` / OTLP / agent consumption.
    /// Field order and shape are fixed (KAT-pinned); non-finite scalars render as `null`.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push('{');
        s.push_str("\"cell_id\":\"");
        for b in self.cell_id.0 {
            let _ = write!(s, "{b:02x}");
        }
        s.push_str("\",");
        let _ = write!(s, "\"epoch\":{},", self.epoch);
        push_num(&mut s, "phi", self.phi);
        push_num(&mut s, "purity", self.purity);
        push_num(&mut s, "reflection", self.reflection);
        push_num(&mut s, "mean_correlation", self.mean_correlation);
        push_num(&mut s, "spectral_gap", self.spectral_gap);
        push_num(&mut s, "stability_radius", self.stability_radius);
        let _ = write!(s, "\"regime\":\"{}\",", self.regime.as_str());
        let _ = write!(s, "\"alarm\":\"{}\",", self.alarm.as_str());
        // Emitted next to the two values it qualifies, so an agent reading this object cannot take
        // `regime`/`alarm` at face value without also being told whether they were understood. A monitor
        // that ignores it reads exactly what it read before the field existed — the coerced value — which
        // is why adding it is compatible rather than breaking.
        let _ = write!(s, "\"verdict_understood\":{},", self.verdict_understood);
        let _ = write!(s, "\"faulted\":{},", self.faulted);
        let _ = write!(s, "\"syndrome\":{},", self.syndrome);
        let _ = write!(s, "\"cascade_lead\":{},", self.cascade_lead);
        let _ = write!(s, "\"heal_seq\":{},", self.heal_seq);
        let _ = write!(s, "\"ready\":{},", self.ready);
        // Appended after the pre-existing fields (never inserted earlier): the doc-promised field
        // order of everything before it stays byte-identical for an existing consumer, and a fixed
        // terminal-width renderer (ui.rs) that only has room to show up through "ready" is unaffected.
        let _ = write!(s, "\"alive_nodes\":{},", self.alive_nodes);
        push_num_last(&mut s, "setpoint_offset", self.setpoint_offset);
        s.push('}');
        s
    }
}

/// [`push_num`] without the trailing comma, for the last field of the object.
fn push_num_last(s: &mut String, key: &str, v: f64) {
    if v.is_finite() {
        let _ = write!(s, "\"{key}\":{v}");
    } else {
        let _ = write!(s, "\"{key}\":null");
    }
}

/// Write `"key":<number>,` — a finite `f64` as a JSON number, non-finite as `null` (JSON has no NaN).
fn push_num(s: &mut String, key: &str, v: f64) {
    if v.is_finite() {
        let _ = write!(s, "\"{key}\":{v},");
    } else {
        let _ = write!(s, "\"{key}\":null,");
    }
}

/// Recover the cell's node count from the frame **exactly**: `N = 1/(R·P)`.
///
/// The measures are `P = Tr(Γ²) = frob/n²` and `R = 1/(N·P) = n/frob`, so their product is `1/n` on *any*
/// coherence matrix. No stratum assumption, no degeneracy, no division by a quantity that legitimately
/// approaches zero.
///
/// This replaces an inversion of the equicorrelated identity `Φ = (N−1)·r²`, which had three defects the exact
/// form does not:
///
/// * it held only on the equicorrelated stratum, and was documented as "approximate" elsewhere;
/// * it divided by `r²`, so a fully decorrelated cell — the *diversified* regime, not a fault — could not be
///   inverted at all and fell back to a binary syndrome guess;
/// * it clamped the result to `CELL_N`, so on `PG(2,31)` it reported at most 7 alive nodes out of 993.
///
/// `faulted` is retained only for the genuinely degenerate case `P = 0`, which means an empty or unreadable
/// matrix rather than any cell state.
fn recover_cell_size(purity: f64, reflection: f64, faulted: bool) -> u32 {
    let product = reflection * purity;
    let inverted = 1.0 / product;
    if product > 1e-12 && inverted.is_finite() {
        // No `f64::round()` in core-only no_std (it needs libm, and this crate's own `libm` feature only wires
        // the backend through to fanos-diakrisis, not to bare f64 methods here). Clamp to non-negative first,
        // then the classic round-to-nearest-via-truncation trick: adding 0.5 before the truncating cast rounds
        // correctly for any non-negative input.
        //
        // The upper clamp is the largest supported plane, not `CELL_N` — a `PG(2,31)` cell has 993 points and
        // clamping it to seven was the defect this replaced.
        let clamped = inverted.clamp(0.0, MAX_CELL_N as f64);
        (clamped + 0.5) as u32
    } else if faulted {
        (CELL_N - 1) as u32
    } else {
        CELL_N as u32
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use fanos_diakrisis::coherence::CoherenceMatrix;

    /// A frame from an equicorrelated cell at correlation `r` over `alive` nodes.
    fn frame(r: f64) -> CoherenceFrame {
        let matrix = CoherenceMatrix::equicorrelated(7, r);
        CoherenceFrame::observe(CellId([0xAB; 16]), 9, &matrix, 0, 0.5, -1, 3, true)
    }

    /// The property that decides where the canonical summary can live (#277): readiness is a question
    /// about **provenance**, not only about magnitudes, and a fold that cannot see provenance must not be
    /// allowed to answer it.
    ///
    /// The two frames here carry *bit-identical* scalars — same matrix, same `Φ`, `P`, `R`, `r`. The only
    /// difference is the measured bit, and it must decide the verdict on its own. `0.45` is not an
    /// arbitrary correlation: it is the shipped `healthy_correlation`, the value the fallback evaluates its
    /// model at when a node has no observation window, and it lands inside the band on purpose. That is
    /// exactly why the deleted `VitalSigns` — which read a matrix, where the bit does not exist — reported
    /// a node that had observed *nothing* as ready.
    /// **The upper edge of the collective-subject band is a triple point, and readiness holds there.**
    ///
    /// On an equicorrelated cell `purity = (1 + (N−1)r²)/N` and `R = 1/(N·purity) = 1/(1 + Φ)`, so `R = 1/3`
    /// *is* `Φ = 2` *is* `purity = 3/7` — the reflection floor, the integration the band tops out at, and
    /// **V2's dominance ceiling** at one correlation, `r = 1/√3`. Nothing pinned that the three coincide, or
    /// that a cell sitting there is still self-observing.
    ///
    /// **What this deliberately does NOT claim, having tried to.** `ready` reads
    /// `reflection >= REFLECTION_FLOOR`, and changing that to `>` leaves this crate green — which looks like
    /// an unguarded boundary and is not one. The frame's scalars are `f32` and the floor is an `f64`
    /// constant, so a widened `f32` can never equal `f64(1/3)`: the equality case is **unreachable**, and the
    /// two comparisons are the same function on every input this plane can produce. A guard written for that
    /// boundary would pass under either spelling — vacuous, and it took a falsification to see it. If the
    /// pipeline ever carries `f64` end to end, the distinction becomes live and the spec's "R ≥ 1/3" decides
    /// it.
    #[test]
    fn the_bands_upper_edge_is_one_point_for_three_invariants_and_is_still_ready() {
        let on_edge = 1.0 / 3.0_f64.sqrt();
        let snap = CoherenceSnapshot::from_frame(&CoherenceFrame::observe(
            CellId([0xAB; 16]), 9, &CoherenceMatrix::equicorrelated(7, on_edge), 0, 0.5, -1, 3, true,
        ));
        // **To f32, which is a fact about this plane worth stating.** The frame's scalars are `f32` and the
        // floor is an `f64` constant, so `reflection` comes back as `0.33333334…` — `1/3` rounded up in
        // single precision — and the comparison at the boundary is decided by that rounding rather than by
        // the spec. The displacement is ~1e-8 and harmless; what would not be harmless is an assertion
        // written as exact `f64` equality, which fails for a reason that has nothing to do with the property.
        let eps = f64::from(f32::EPSILON);
        assert!(
            (snap.reflection - REFLECTION_FLOOR).abs() < eps,
            "r = 1/√3 must land on the floor to f32, or this pins nothing: {} vs {REFLECTION_FLOOR}",
            snap.reflection
        );
        assert!((snap.purity - 3.0 / 7.0).abs() < eps, "and on V2's dominance ceiling — the same point");
        assert!(
            snap.ready,
            "a cell exactly on the floor is self-observing (R ≥ 1/3); `>` here would exile it at the one \
             correlation where three separate invariants meet"
        );

        // The other side, one step out, so the assertion above is about the boundary and not about `ready`
        // being unable to say no.
        let over = CoherenceSnapshot::from_frame(&CoherenceFrame::observe(
            CellId([0xAB; 16]), 9, &CoherenceMatrix::equicorrelated(7, 0.578), 0, 0.5, -1, 3, true,
        ));
        assert!(over.reflection < REFLECTION_FLOOR && !over.ready, "just past it, the cell is not");
    }

    #[test]
    fn two_frames_with_identical_scalars_disagree_on_readiness_when_one_measured_nothing() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.45); // the shipped `healthy_correlation`
        let measured = CoherenceFrame::observe(CellId([1; 16]), 1, &matrix, 0, 0.0, -1, 0, true);
        let assumed = CoherenceFrame::observe(CellId([1; 16]), 1, &matrix, 0, 0.0, -1, 0, false);

        let (m, a) = (
            CoherenceSnapshot::from_frame(&measured),
            CoherenceSnapshot::from_frame(&assumed),
        );
        assert_eq!(
            (m.phi, m.purity, m.reflection, m.mean_correlation),
            (a.phi, a.purity, a.reflection, a.mean_correlation),
            "the two frames must differ ONLY in provenance, or this proves nothing about provenance"
        );
        assert!(
            m.phi >= PHI_THRESHOLD && m.reflection >= REFLECTION_FLOOR,
            "both numeric conjuncts hold at the shipped baseline (Φ={}, R={}) — which is what makes the \
             assumed frame dangerous rather than obviously wrong",
            m.phi,
            m.reflection
        );
        assert!(m.is_ready(), "a measured cell in the band is ready");
        assert!(
            !a.is_ready(),
            "a node that has observed nothing must not report ready on numbers it assumed (#154)"
        );
    }

    #[test]
    fn readiness_is_phi_ge_1_and_r_ge_one_third() {
        // A healthy collective subject (r in the band) is integrated (Φ≥1) and self-observing (R≥1/3).
        let healthy = CoherenceSnapshot::from_frame(&frame(0.5));
        assert!(healthy.phi >= PHI_THRESHOLD, "Φ={} ≥ 1", healthy.phi);
        assert!(
            healthy.reflection >= REFLECTION_FLOOR,
            "R={} ≥ 1/3",
            healthy.reflection
        );
        assert!(healthy.is_ready(), "a healthy collective subject is ready");

        // A weakly-coupled aggregate (r small) is NOT integrated (Φ<1) → not ready.
        let aggregate = CoherenceSnapshot::from_frame(&frame(0.05));
        assert!(aggregate.phi < PHI_THRESHOLD, "Φ={} < 1", aggregate.phi);
        assert!(
            !aggregate.is_ready(),
            "an unintegrated aggregate is not ready"
        );
    }

    #[test]
    fn stability_radius_matches_the_theorem() {
        // This test used to restate `r = √(max(0, P − 2/N))` and check the field against it. That law was
        // refuted (T-104, 2026-08): it overstates the margin by up to 81.7× at the viability wall, and this
        // test held the wrong number in place from a second crate, outside the sweep that fixed the first.
        //
        // The reported field carries the **exact** radius, so the theorem restated here is the exact one —
        // written out independently rather than by calling the function it checks, which would assert
        // nothing:
        //   a(P) = (1 + √((N−1)(N·P − 1)))/N,   a_c = a(2/N) = (1 + √(N−1))/N
        //   r    = √(2·(1 − √(a·a_c) − √((1−a)(1−a_c))))
        let snap = CoherenceSnapshot::from_frame(&frame(0.5));
        let n = snap.alive_nodes as f64;
        let a = (1.0 + ((n - 1.0) * (n * snap.purity - 1.0)).sqrt()) / n;
        let ac = (1.0 + (n - 1.0).sqrt()) / n;
        let expect = (2.0 * (1.0 - (a * ac).sqrt() - ((1.0 - a) * (1.0 - ac)).sqrt())).max(0.0).sqrt();
        assert!(
            (snap.stability_radius - expect).abs() < 1e-9,
            "reported {} vs exact theorem {expect}",
            snap.stability_radius
        );

        // Exactly zero at and below the viability shell, so it stays a genuine "how much can I still take"
        // gauge rather than going imaginary or negative. `PURITY_FLOOR = 2/N` is that shell.
        let n7 = CELL_N;
        assert_eq!(stability_radius_exact(PURITY_FLOOR, n7), 0.0, "no margin left at the wall");
        assert_eq!(stability_radius_exact(PURITY_FLOOR - 0.01, n7), 0.0, "and none below it");

        // The refuted law is not merely different, it is different in the dangerous direction — larger, and
        // increasingly so toward the wall. Pinned so a revert to it fails here as well as in fanos-diakrisis.
        let refuted = (snap.purity - PURITY_FLOOR).max(0.0).sqrt();
        assert!(
            refuted > snap.stability_radius * 2.0,
            "the old surd overstates the margin (old {refuted}, exact {})",
            snap.stability_radius
        );
    }

    #[test]
    fn band_thresholds_match_their_closed_forms() {
        // The operator bands are theorem-fixed, not tuned — verify the published constants.
        assert!((R_STAR - 1.0 / 6.0_f64.sqrt()).abs() < 1e-12, "r* = 1/√6");
        assert!(
            (OVER_COUPLING - 1.0 / 3.0_f64.sqrt()).abs() < 1e-12,
            "over-coupling = 1/√3"
        );
        assert!(
            (PURITY_FLOOR - 2.0 / 7.0).abs() < 1e-12,
            "P_crit = 2/N = 2/7"
        );
        assert!(
            (REFLECTION_FLOOR - 1.0 / 3.0).abs() < 1e-12,
            "R floor = 1/3"
        );
        // The band ordering `r* < 1/√3` is now a compile-time `const _` assertion above.
    }

    /// **An encoding this build cannot read errs toward alarm, and the snapshot says that it did** (#333).
    ///
    /// Two claims in one test because they are one decision: keeping `regime`/`alarm` non-optional is only
    /// defensible *because* the coercion is reported beside them. Assert either alone and the pair can drift
    /// — a fallback that quietly flips to `Healthy` would still satisfy "the field is always populated".
    ///
    /// The direction is not a preference. #278 measured the two ways a telemetry verdict can be wrong and
    /// found silence to be the dangerous one: an invented alarm gets investigated, a hidden one does not. So
    /// an unrecognised frame reads as the most severe value in each vocabulary — and `verdict_understood`
    /// is what stops that from being indistinguishable from a genuinely alarmed cell.
    #[test]
    fn an_unreadable_verdict_errs_toward_alarm_and_says_that_it_did() {
        let mut f = frame(0.5);
        // Both fields carry the reserved encoding 3 — a peer whose vocabulary is ahead of this build's.
        f.verdict = (f.verdict & !0b0000_1111) | 0b0000_1111;
        let snap = CoherenceSnapshot::from_frame(&f);

        assert_eq!(snap.regime, Regime::OverCoupled, "toward the most severe regime, never toward healthy");
        assert_eq!(snap.alarm, AlarmLevel::Structure, "and toward the most severe alarm, for the same reason");
        assert!(
            !snap.verdict_understood,
            "and the snapshot reports that both values are coercions rather than readings — without this \
             the two assertions above are indistinguishable from a cell that really is collapsing"
        );
        assert!(
            snap.to_json().contains("\"verdict_understood\":false"),
            "the flag reaches an agent through the canonical export, not only through the struct"
        );

        // The control: an ordinary frame is understood, and the SAME two fields then mean what they say.
        let ok = CoherenceSnapshot::from_frame(&frame(0.5));
        assert!(ok.verdict_understood);
        assert!(ok.to_json().contains("\"verdict_understood\":true"));
    }

    #[test]
    fn json_is_a_stable_flat_object() {
        let snap = CoherenceSnapshot::from_frame(&frame(0.5));
        let json = snap.to_json();
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"cell_id\":\"abababababababababababababababab\""));
        assert!(json.contains("\"epoch\":9,"));
        assert!(json.contains("\"regime\":\""));
        assert!(json.contains("\"alive_nodes\":"));
        assert!(json.contains("\"ready\":"));
        // No non-finite scalar leaked as an invalid JSON token.
        assert!(!json.contains("NaN") && !json.contains("inf"));
    }

    #[test]
    fn alive_nodes_is_exact_for_the_equicorrelated_liveness_fold() {
        // frame(r) builds CoherenceMatrix::equicorrelated(7, r) — exactly the shape
        // observe_liveness produces from a live alive_count — so Φ=(N−1)r² inverts back to N=7
        // exactly, for any nonzero r, healthy or weakly correlated alike.
        for r in [0.05, 0.3, 0.5, 0.7] {
            let snap = CoherenceSnapshot::from_frame(&frame(r));
            assert_eq!(snap.alive_nodes, 7, "r={r}");
        }
    }

    #[test]
    fn alive_nodes_tracks_a_smaller_live_count() {
        // Mirrors SelfObserver::observe_liveness with 2 nodes down (5 alive): the matrix really is
        // 5×5 equicorrelated, so the inversion recovers 5, not the fixed CELL_N=7.
        let matrix = CoherenceMatrix::equicorrelated(5, 0.45);
        let f = CoherenceFrame::observe(CellId([0xCD; 16]), 1, &matrix, 0b0001_1000, 0.3, -1, 0, true);
        let snap = CoherenceSnapshot::from_frame(&f);
        assert_eq!(snap.alive_nodes, 5);
    }

    #[test]
    fn a_fully_decorrelated_cell_is_still_counted_exactly() {
        // `r = 0` is the diversified/resilient regime, not a fault — and it is precisely where the old
        // inversion of `Φ = (N−1)r²` divided by zero and had to guess from the binary syndrome. `N = 1/(R·P)`
        // has no such hole: a decorrelated cell has `Γ = I/n`, so `P = 1/n`, `R = 1`, and the product is `1/n`
        // exactly as for any other correlation.
        let healthy = CoherenceSnapshot::from_frame(&frame(0.0));
        assert_eq!(healthy.alive_nodes, 7, "a decorrelated 7-cell is seven nodes, not a syndrome guess");

        // And a localized fault does not change the count, because the count is measured rather than inferred
        // from the fault bit. The old code returned `CELL_N − 1` here purely because it could not divide.
        let matrix = CoherenceMatrix::equicorrelated(7, 0.0);
        let faulted_frame = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0b0000_0001, 0.0, -1, 0, true);
        let faulted = CoherenceSnapshot::from_frame(&faulted_frame);
        assert!(faulted.faulted);
        assert_eq!(faulted.alive_nodes, 7, "the matrix still describes seven nodes");
    }

    #[test]
    fn the_setpoint_offset_says_which_way_the_cell_is_off_and_by_how_much() {
        // The band reports only *which* band, so a cell just above the collapse boundary reads healthy. This
        // field is what distinguishes "in the band" from "where in the band", which is an **8.58×** difference
        // in stability radius on a Fano plane (`0.0171` at `Φ = 1.1` against `0.1466` at `Φ = 2`). That read
        // "3.16×" — the refuted metric's answer — until T-104 was corrected.
        //
        // Φ = 6r² on a 7-cell, so r = √(Φ/6): pick correlations that land the cell below, at, and above Φ*.
        //
        // The probes are placed **relative to `OPTIMAL_INTEGRATION`**, not at literals. They used to be
        // 1.05 / 1.25 / 1.90 with 1.25 standing in for Φ*, and when T-104's correction moved the setpoint to
        // `5/4 + (√2−1)/2 ≈ 1.4571` the middle probe silently became a point 0.207 off it — the assertion
        // "at Φ* it reads ~zero" was then a claim about a Φ that is not Φ*. Derived offsets cannot go stale
        // that way. `±0.4` keeps all three inside the band `Φ ∈ (1, 2]` and below the over-coupling edge.
        const PROBE: f64 = 0.4;
        let at_phi = |phi: f64| CoherenceSnapshot::from_frame(&frame((phi / 6.0).sqrt()));
        let below = at_phi(OPTIMAL_INTEGRATION - PROBE);
        let at = at_phi(OPTIMAL_INTEGRATION);
        let above = at_phi(OPTIMAL_INTEGRATION + PROBE);

        assert!(below.setpoint_offset < -0.35, "under-coupled reads negative: {}", below.setpoint_offset);
        assert!(at.setpoint_offset.abs() < 0.01, "at Φ* it reads ~zero: {}", at.setpoint_offset);
        assert!(above.setpoint_offset > 0.35, "toward over-coupling reads positive: {}", above.setpoint_offset);
        // Ordered, so the field is a signed distance and not merely three signs that happen to differ.
        assert!(below.setpoint_offset < at.setpoint_offset && at.setpoint_offset < above.setpoint_offset);

        // All three are inside the band, so `Regime` cannot tell them apart — which is the whole reason this
        // field exists. Assert that, or the test would pass on a field nobody needs.
        assert_eq!(below.regime, at.regime, "the regime is identical across a 3× robustness difference");
        assert_eq!(at.regime, above.regime);
    }

    #[test]
    fn the_json_prefix_stays_byte_identical_when_a_field_is_appended() {
        // Appending must not renumber: an existing consumer reading up to `alive_nodes` must see exactly the
        // bytes it saw before, which is the discipline `alive_nodes` itself followed.
        let json = CoherenceSnapshot::from_frame(&frame(0.5)).to_json();
        let (prefix, tail) = json.split_once(",\"setpoint_offset\":").expect("appended last, with a comma");
        assert!(prefix.starts_with('{'), "the prefix is the whole object minus the new field");
        assert!(prefix.contains("\"alive_nodes\":"), "and it still ends with the previously-last field");
        assert!(tail.ends_with('}'), "the new field closes the object");
        assert!(!prefix.contains("setpoint_offset"), "the field appears exactly once, at the end");
    }

    #[test]
    fn the_count_is_exact_for_every_supported_plane() {
        // The defect this replaced clamped to `CELL_N`, so a `PG(2,31)` cell reported seven alive nodes out of
        // 993 — and the stability radius was computed against the wrong `N` with it.
        for n in [7usize, 21, 57, 993] {
            for r in [0.0, 0.05, 0.3] {
                let matrix = CoherenceMatrix::equicorrelated(n, r);
                let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0, 0.0, -1, 0, true);
                let snap = CoherenceSnapshot::from_frame(&f);
                assert_eq!(snap.alive_nodes as usize, n, "N={n} r={r}: the count must be exact");
                // …and the radius must follow the recovered N, not a constant. Reported means exact.
                let expected = stability_radius_exact(snap.purity, n);
                assert!(
                    (snap.stability_radius - expected).abs() < 1e-9,
                    "N={n} r={r}: r_stab must use the recovered N (got {}, want {expected})",
                    snap.stability_radius
                );
            }
        }
    }

    #[test]
    fn alive_nodes_is_always_within_the_physical_cell_bound() {
        // Whatever r/Φ combination a (possibly adversarial or degenerate) frame carries, the derived
        // count must never exceed the cell size or go negative — it is clamped, not merely "usually"
        // in range.
        for r in [-0.9, -0.1, 0.0, 1e-7, 0.408, 0.577, 0.9, 1.0] {
            let matrix = CoherenceMatrix::equicorrelated(7, r);
            let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0, 0.0, -1, 0, true);
            let snap = CoherenceSnapshot::from_frame(&f);
            assert!(snap.alive_nodes <= MAX_CELL_N as u32, "r={r}");
        }
    }
}
