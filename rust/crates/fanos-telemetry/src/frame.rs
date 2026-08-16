//! The [`CoherenceFrame`] — the minimal sufficient statistic for a cell's health at a window.
//!
//! It folds a cell's coherence into a small, fixed-size, canonically-encoded record
//! (`docs/design-telemetry.md` §2). The **load-bearing** field is the 3-bit Fano/Hamming
//! `syndrome` (the perfect-code fault localizer — `Θ(log N)` bits, information-theoretically minimal
//! by the Minimal Self-Observation Overhead theorem); the `f32` coherence scalars (`Φ`, `P`, `R`,
//! mean `r`, spectral gap) are a convenience for humans and cross-cell roll-up. Per-node raw signals
//! never *leave their node* — only this cell-level fold does. Note this is data *minimization*, not
//! anonymization: the frame still names the faulted point (the exact 3-bit syndrome) and the cell's
//! exact scalars, so a frame observer learns which node is down and the cell's health. **Do not export a
//! raw frame** — cross the anonymity boundary through [`CoherenceFrame::privatize`](crate::dp), which
//! Laplace-noises the scalars at the derived sensitivity `Δr = 1/21` and withholds the exact syndrome for
//! an ε-DP export (audit C7, `design-telemetry.md` §5).

use fanos_code::syndrome::syndrome3;
use fanos_diakrisis::coherence::{CoherenceMatrix, PHI_TH};
use fanos_diakrisis::window::{Alarm, CollectiveState};
use fanos_wire::Wire;

/// A 16-byte opaque cell identifier (a leaf cell, a rolled-up parent cell, or a per-PID `Γ_app` cell).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, fanos_wire_derive::Wire)]
pub struct CellId(pub [u8; 16]);

/// The collective-subject regime of a cell (from its mean inter-node correlation, spec §18.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Regime {
    /// `r ≤ 1/√(N−1)`: too weakly coupled to bind (`Φ < 1`).
    Aggregate,
    /// In the window `(1/√(N−1), √(2/(N−1))]`: integrated, structured, still self-modelling.
    CollectiveSubject,
    /// `r > √(2/(N−1))`: over-coupled, losing its self-model (`R < 1/3`).
    OverCoupled,
}

impl Regime {
    /// The stable lower-snake-case label (used by `CoherenceSnapshot::to_json` and any labeled-metric
    /// rendering — one canonical spelling, so a consumer cross-referencing JSON against a metrics
    /// surface sees the same string in both).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aggregate => "aggregate",
            Self::CollectiveSubject => "collective_subject",
            Self::OverCoupled => "over_coupled",
        }
    }
}

/// The leading-indicator alarm level (spec §6.6): integration crosses before structure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlarmLevel {
    /// `Φ ≥ 1` and `P ≥ 2/N`.
    Healthy,
    /// `Φ < 1` but `P ≥ 2/N` — the earliest warning.
    Integration,
    /// `Φ < 1` and `P < 2/N`.
    Structure,
}

impl AlarmLevel {
    /// The stable lower-snake-case label (see [`Regime::as_str`]).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Integration => "integration",
            Self::Structure => "structure",
        }
    }
}

// `verdict` byte layout: [ .. .. measured | integrated | alarm(2) | regime(2) ].
const REGIME_MASK: u8 = 0b0000_0011;
const ALARM_SHIFT: u8 = 2;
const ALARM_MASK: u8 = 0b0000_1100;
const INTEGRATED_BIT: u8 = 1 << 4;
/// The verdict byte's unused high bits. Named so that "this build does not understand the frame" can be
/// ONE question ([`CoherenceFrame::fully_understood`]) rather than a bit-twiddle repeated at each reader —
/// and so that a future flag placed here is a deliberate act with a name, not a silent widening.
const UNUSED_VERDICT_BITS: u8 = 0b1100_0000;

/// **The wire vocabulary and the computed one are the same size, and each fits its field.**
///
/// `Regime` mirrors [`CollectiveState`] and `AlarmLevel` mirrors [`Alarm`]; `observe`'s exhaustive matches
/// force a new *computed* state to be noticed here, but what they force the author to write is a NUMBER —
/// and a number has to fit two bits. These four assertions say the rest out loud:
///
/// * a state added in `fanos-diakrisis` and not mirrored here fails the build, rather than being folded
///   into whichever wire value the new match arm happened to pick;
/// * a vocabulary that outgrows its field fails the build, rather than being masked into an existing
///   value — `REGIME_MASK` cannot say "this did not fit", it can only truncate.
const _: () = assert!(
    core::mem::variant_count::<Regime>() == core::mem::variant_count::<CollectiveState>(),
    "the wire's regime vocabulary and the computed one have drifted apart"
);
const _: () = assert!(
    core::mem::variant_count::<AlarmLevel>() == core::mem::variant_count::<Alarm>(),
    "the wire's alarm vocabulary and the computed one have drifted apart"
);
const _: () = assert!(
    core::mem::variant_count::<Regime>() <= REGIME_MASK as usize + 1,
    "the regime field is too narrow for its own vocabulary"
);
const _: () = assert!(
    core::mem::variant_count::<AlarmLevel>() <= (ALARM_MASK >> ALARM_SHIFT) as usize + 1,
    "the alarm field is too narrow for its own vocabulary"
);

/// Whether the correlation the scalars were computed at was **measured** rather than assumed (#154).
///
/// Absent-bit means *assumed*, which is the fail-safe direction: a producer that does not set it is read as
/// unmeasured, never the reverse.
const MEASURED_BIT: u8 = 1 << 5;
/// The syndrome occupies 3 bits (`0` healthy, `1..=7` a point address).
const SYNDROME_MASK: u8 = 0b0000_0111;

/// The canonical on-wire length of a [`CoherenceFrame`] (bytes). Fixed and KAT-pinned.
pub const FRAME_LEN: usize = 52;

/// A cell's coherence at one observation window — the unit of FANOS telemetry. The struct field order
/// **is** the canonical byte layout: `#[derive(Wire)]` emits exactly `cell_id(16) ‖ epoch(8) ‖
/// syndrome(1) ‖ verdict(1) ‖ phi(4) ‖ purity(4) ‖ reflection(4) ‖ mean_r(4) ‖ gap(4) ‖ forecast(2) ‖
/// heal_seq(4)` = [`FRAME_LEN`] bytes (audit A1).
#[derive(Clone, Copy, PartialEq, Debug, fanos_wire_derive::Wire)]
pub struct CoherenceFrame {
    /// Which cell this describes.
    pub cell_id: CellId,
    /// The observation window / epoch.
    pub epoch: u64,
    /// The 3-bit Fano/Hamming fault localizer: `0` = healthy, `1..=7` = the faulted point's address.
    pub syndrome: u8,
    /// Packed regime + alarm + integrated bit (read via [`regime`](Self::regime),
    /// [`alarm`](Self::alarm), [`is_integrated`](Self::is_integrated)).
    pub verdict: u8,
    /// Integration `Φ` (threshold `1`).
    pub phi: f32,
    /// Structuredness `P = Tr(Γ²)` (threshold `2/N`).
    pub purity: f32,
    /// Reflection `R = 1/(N·P)` (threshold `1/3` — the self-model floor).
    pub reflection: f32,
    /// Mean inter-node correlation `r` (vs `r* = 1/√(N−1)`, over-coupling `√(2/(N−1))`).
    pub mean_r: f32,
    /// Spectral gap `Δ` (recovery rate; healing time constant `τ = 1/Δ`).
    pub gap: f32,
    /// Cascade lead: windows to over-coupling, or `-1` if none forecast.
    pub forecast: i16,
    /// Monotone counter of healing actions (the sparse event stream is keyed off this).
    pub heal_seq: u32,
}

/// Coerce a non-finite scalar (`NaN`/`±∞`, e.g. from a degenerate coherence matrix) to `0.0`, so a
/// frame is always finite. This keeps the wire round-trip an equality (`NaN != NaN` would otherwise
/// break `decode(encode(f)) == f`) and stops a meaningless value from poisoning forecasts, history
/// aggregation, or any comparison downstream.
fn finite(x: f32) -> f32 {
    if x.is_finite() { x } else { 0.0 }
}

impl CoherenceFrame {
    /// Fold a cell's coherence `matrix`, its degraded-node bitmask, and its spectral `gap` into a
    /// frame. The `degraded` mask (bit `k` = point `k` faulted) becomes the 3-bit syndrome; the
    /// scalars and regime/alarm are read from the matrix. Non-finite scalars are coerced to `0.0`.
    ///
    /// `measured` says whether the correlation behind `matrix` was **read from a full observation window** or
    /// **assumed** from configuration. It is not cosmetic: with `measured = false` and the shipped
    /// `healthy_correlation = 0.45`, the equicorrelated closed forms give `Φ = (N−1)r² = 1.215 ≥ 1`,
    /// `P = 0.3164 ≥ 2/N`, `R = 0.4514 ≥ 1/3` and `r = 0.45` inside the band `(0.4082, 0.5774]` — so a node
    /// that has observed **nothing** produces a frame that reads as a healthy collective subject, and
    /// [`CoherenceSnapshot::from_frame`](crate::CoherenceSnapshot::from_frame) called it *"bound and self-observing"* (#154).
    #[must_use]
    // **The narrowing is deliberate for the wire, and it also fixes the comparison basis — which is the
    // half worth saying, because it is the half a future shortcut would break.**
    //
    // Every threshold downstream (`PHI_THRESHOLD`, `REFLECTION_FLOOR`, `PURITY_FLOOR`) is an `f64` constant,
    // and every value compared against one has passed through here: `CoherenceSnapshot::from_frame` is the
    // only constructor, and the observatory's own `snapshot()` builds a frame first rather than reading its
    // matrix directly. So all consumers compare the *same rounded number* and cannot disagree about
    // readiness at a boundary.
    //
    // A local `f64` shortcut — computing a scalar straight from the matrix and testing it against the same
    // constant, skipping the frame — would be a silent way to break that: two nodes, one reading a peer's
    // frame and one reading its own matrix, would sit on opposite sides of a threshold for values within
    // ~1e-7 of it. Cheap to introduce as an "optimisation", and invisible until a cell is on an edge.
    //
    // One consequence is already visible and recorded at
    // `snapshot::the_bands_upper_edge_is_one_point_for_three_invariants_and_is_still_ready`: a widened `f32`
    // can never equal an `f64` constant, so `>=` and `>` are the same function on every producible input and
    // the spec's choice between them is unobservable here.
    #[allow(clippy::cast_possible_truncation)] // f64→f32 narrowing is deliberate for the wire frame.
    // Eight distinct inputs to one fold, same as `SelfObserver::observe_liveness`: a params struct would
    // add a type whose only job is to be destructured immediately, and would hide `measured` — the one
    // argument a caller must think about — among six it copies from the frame it is building.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        cell_id: CellId,
        epoch: u64,
        matrix: &CoherenceMatrix,
        degraded: u8,
        gap: f64,
        forecast: i16,
        heal_seq: u32,
        measured: bool,
    ) -> Self {
        let m = matrix.measures();
        let regime = match matrix.collective_state() {
            CollectiveState::Aggregate => 0,
            CollectiveState::CollectiveSubject => 1,
            CollectiveState::OverCoupled => 2,
        };
        let alarm = match matrix.alarm() {
            Alarm::Healthy => 0,
            Alarm::Integration => 1,
            Alarm::Structure => 2,
        };
        let mut verdict = regime | (alarm << ALARM_SHIFT);
        if m.phi >= PHI_TH {
            verdict |= INTEGRATED_BIT;
        }
        if measured {
            verdict |= MEASURED_BIT;
        }
        Self {
            cell_id,
            epoch,
            syndrome: syndrome3(degraded) & SYNDROME_MASK,
            verdict,
            phi: finite(m.phi as f32),
            purity: finite(m.purity as f32),
            reflection: finite(m.reflection as f32),
            mean_r: finite(matrix.mean_correlation() as f32),
            gap: finite(gap as f32),
            forecast,
            heal_seq,
        }
    }

    /// The collective-subject regime, or `None` if this build does not know the encoding.
    ///
    /// **The field is two bits wide and the vocabulary has three values**, so encoding `3` is reserved —
    /// the natural home for a fourth regime. It used to be folded into `OverCoupled` by a catch-all arm,
    /// which reports a *newer peer* as *the most alarming state this build can name*, confidently and
    /// wrongly. Same shape as [`fanos_wire::FrameType::from_code`], which has always answered `None` for a
    /// code it does not know; the raw byte stays available in [`verdict`](Self::verdict) for a caller that
    /// wants to report it through `Escalation::UnsupportedCritical`.
    ///
    /// `None` is **not** a synonym for healthy. It is not a reading at all, and a caller that folds it
    /// into the healthy side hides the very thing the encoding was reserved to carry.
    #[must_use]
    pub fn regime(&self) -> Option<Regime> {
        Some(match self.verdict & REGIME_MASK {
            0 => Regime::Aggregate,
            1 => Regime::CollectiveSubject,
            2 => Regime::OverCoupled,
            _ => return None,
        })
    }

    /// The leading-indicator alarm level, or `None` if this build does not know the encoding.
    ///
    /// Two bits, three values, encoding `3` reserved — see [`regime`](Self::regime) for the whole reasoning;
    /// this field carries it with a sharper consequence, because the alarm level is what the cell census
    /// counts. An unknown level must be counted **beside** `silent` and `unreachable`, never among the
    /// alarmed: counting it as sickness lets one peer that is merely newer speak for the network, which is
    /// the rule `Census::verdict` already states for silence.
    #[must_use]
    pub fn alarm(&self) -> Option<AlarmLevel> {
        Some(match (self.verdict & ALARM_MASK) >> ALARM_SHIFT {
            0 => AlarmLevel::Healthy,
            1 => AlarmLevel::Integration,
            2 => AlarmLevel::Structure,
            _ => return None,
        })
    }

    /// Whether every field of the verdict byte is an encoding this build knows.
    ///
    /// The two vocabularies plus the two **unused high bits** (6-7), which `decode` does not inspect: a
    /// future flag set there is invisible today, and a reader that wants to know whether it is looking at
    /// a frame from a build ahead of it needs one answer, not three separate `is_none()` checks.
    #[must_use]
    pub fn fully_understood(&self) -> bool {
        self.regime().is_some() && self.alarm().is_some() && self.verdict & UNUSED_VERDICT_BITS == 0
    }

    /// Whether the cell is integrated (`Φ ≥ 1`).
    #[must_use]
    pub fn is_integrated(&self) -> bool {
        self.verdict & INTEGRATED_BIT != 0
    }

    /// Whether the correlation these scalars were computed at was **measured**, or **assumed** from
    /// configuration because the node has no full observation window yet (#154).
    ///
    /// Every other field is meaningless without this one. The scalars are always the equicorrelated model's
    /// (`design-telemetry.md` §2: the syndrome is the load-bearing part); the only question is whether the
    /// `r` it was evaluated at came from `BehaviorMonitor::coherence` or from `Config::healthy_correlation`.
    /// At the shipped `0.45` the assumed frame reads `Φ = 1.215`, `P = 0.3164`, `R = 0.4514`, `r` inside the
    /// collective-subject band — **healthy on every axis**, from a node that has observed nothing.
    ///
    /// A node is in that state for a full observation window after **every** epoch turn (#153 clears the
    /// window at a boundary because it is indexed by seats the boundary permutes), which at the shipped
    /// 600 s epoch and `W = 178` is ~89 s in 600 — 15% of uptime, on every node in the cell at once.
    ///
    /// **Absent means assumed.** A producer that does not set the bit reads as unmeasured, never the reverse,
    /// so an older or unknown producer is treated conservatively.
    #[must_use]
    pub fn correlation_is_measured(&self) -> bool {
        self.verdict & MEASURED_BIT != 0
    }

    /// **Pairwise dispersion** `v = q² − m²` — the variance of the cell's off-diagonal correlations, where
    /// `q` is their RMS and `m` the reported [`mean_r`](Self::mean_r).
    ///
    /// It needs **no field of its own**, and the reason is the finding it exposes: `Φ`, `P` and `R` are
    /// bijections of a single scalar on any unit-diagonal correlation matrix, so the cell size falls out of
    /// the frame as `N = (1 + Φ)/P` and the RMS as `q² = Φ/(N − 1)`. Three of this frame's four coherence
    /// numbers carry one degree of freedom between them; the fourth, `mean_r`, is what makes the pair
    /// two-dimensional, and this is that second dimension read out.
    ///
    /// Worth watching rather than inferring: a cell in the under-coupled `Aggregate` regime with **zero**
    /// dispersion is coming apart uniformly, while the same regime with high dispersion is a **load
    /// hotspot** — one part of the cell locked onto a target, the rest untouched. The two want opposite
    /// operator responses and the regime alone cannot tell them apart.
    ///
    /// `0.0` for a degenerate frame (no cell size recoverable, or rounding below zero — Cauchy–Schwarz makes
    /// `m² ≤ q²` exact, so a negative here is never real).
    #[must_use]
    pub fn dispersion(&self) -> f32 {
        let (phi, purity) = (f64::from(self.phi), f64::from(self.purity));
        if purity <= 0.0 {
            return 0.0;
        }
        let n = (1.0 + phi) / purity;
        if n < 2.0 || !n.is_finite() {
            return 0.0;
        }
        let m = f64::from(self.mean_r);
        finite(((phi / (n - 1.0)) - m * m).max(0.0) as f32)
    }

    /// **Which of the three paths carried the gate** — the verdict `Φ` split into the exact terms it is made
    /// of (UHM T-311), as `(consistency, inequality, concentration)`.
    ///
    /// ```text
    /// Φ = (n−1)·m²  +  (n−1)·v  +  (Φ − Φ_flat)
    ///     consistency  inequality   concentration
    /// ```
    ///
    /// An identity, not a model: `Φ_flat = (n−1)(m² + v)` is what the cell would read at even activity, and
    /// the first two terms compose it exactly. Checked over 3000 random matrices, worst drift **8.9e-16** —
    /// the same machine-epsilon signature UHM reports for its own three sums, reached independently.
    ///
    /// **The verdict alone cannot say which actuator to call, and each term has a different one.** Low
    /// consistency wants `Bind` (regenerate coupling); high inequality is a load hotspot and wants the §6.7
    /// rebalance; high concentration wants the weights spread across nodes rather than the couplings. One
    /// scalar hid which. Measured on a 4-of-7 clique at `c = 0.8` — an admissible cell, `λ_min = +3.4` — the
    /// gate opens at `Φ = 1.0971` with consistency contributing **29 %** and inequality **71 %**.
    ///
    /// The consistency term is `m²`, so it does not distinguish a correlated cell from an anti-correlated
    /// one; `Φ` is blind to sign and this decomposition inherits that exactly (see `dispersion`'s siblings
    /// in `fanos_diakrisis`).
    ///
    /// All three are `0.0` for a degenerate frame, for the same reason [`dispersion`](Self::dispersion) is.
    #[must_use]
    pub fn integration_paths(&self) -> (f32, f32, f32) {
        let (phi, purity) = (f64::from(self.phi), f64::from(self.purity));
        if purity <= 0.0 {
            return (0.0, 0.0, 0.0);
        }
        let n = (1.0 + phi) / purity;
        if n < 2.0 || !n.is_finite() {
            return (0.0, 0.0, 0.0);
        }
        let m = f64::from(self.mean_r);
        let v = f64::from(self.dispersion());
        let consistency = (n - 1.0) * m * m;
        let inequality = (n - 1.0) * v;
        (
            finite(consistency as f32),
            finite(inequality as f32),
            finite((phi - consistency - inequality) as f32),
        )
    }

    /// Whether the syndrome localizes a fault (`syndrome != 0`).
    #[must_use]
    pub fn is_faulted(&self) -> bool {
        self.syndrome != 0
    }

    /// The canonical fixed-size byte encoding (KAT-pinned): `cell_id(16) ‖ epoch(8) ‖ syndrome(1) ‖
    /// verdict(1) ‖ phi(4) ‖ purity(4) ‖ reflection(4) ‖ mean_r(4) ‖ gap(4) ‖ forecast(2) ‖
    /// heal_seq(4)`, all big-endian, `f32` as IEEE-754 bits.
    #[must_use]
    /// Encode this frame's exact bytes — **cell-local only**.
    ///
    /// The reflexive loop needs the exact syndrome to localize a fault, so this is the right thing *inside* a cell. For
    /// anything that leaves the cell — cross-cell roll-up, a monitor feed, any shareable telemetry — use
    /// [`CoherenceFrame::export`], which privatizes first. Shipping these bytes outward publishes the exact 3-bit
    /// syndrome, spectral gap, heal counter and forecast, which is precisely what the ε-DP release exists to withhold.
    pub fn encode(&self) -> [u8; FRAME_LEN] {
        // The derived `Wire` codec emits the fields in declaration order, which is exactly the layout
        // above — byte-for-byte identical to the previous hand-rolled writer (audit A1). A fixed-layout
        // frame is always `FRAME_LEN` bytes, so the conversion never falls back.
        Wire::to_wire(self).try_into().unwrap_or([0u8; FRAME_LEN])
    }

    /// Decode a frame from its canonical encoding. Reads exactly [`FRAME_LEN`] bytes from the front
    /// (any trailing bytes are left unread, so a frame may be embedded); `None` if too short.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cur = bytes;
        Wire::wire_decode(&mut cur).ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample_frame() -> CoherenceFrame {
        // A collective-subject cell (r = 0.5 ∈ (1/√6, 1/√3]) with point 0 faulted.
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        CoherenceFrame::observe(CellId([0x11; 16]), 42, &matrix, 0b0000_0001, 0.5, -1, 3, true)
    }

    #[test]
    fn the_frame_recovers_the_dispersion_it_never_carried() {
        // The frame has no dispersion field and does not need one: `Φ`, `P` and `R` are bijections of one
        // scalar, so the cell size falls out as `N = (1+Φ)/P` and the RMS as `q² = Φ/(N−1)`. Checked against
        // the matrix's own figure — if the identity ever stopped holding, this readout would silently start
        // reporting a different quantity under the same name.
        //
        // Both an equicorrelated cell (dispersion exactly zero) and a hotspot block (dispersion strictly
        // positive), because a readout that returned zero unconditionally would pass the first alone.
        let mut block = alloc::vec![0.0; 49];
        for i in 0..7 {
            block[i * 7 + i] = 1.0;
            for j in 0..7 {
                if i != j && i < 4 && j < 4 {
                    block[i * 7 + j] = 1.0;
                }
            }
        }
        let cases = [
            CoherenceMatrix::equicorrelated(7, 0.5),
            CoherenceMatrix::from_correlation(block, 7).expect("a block matrix is PSD"),
        ];
        for matrix in cases {
            let frame = CoherenceFrame::observe(CellId([0x22; 16]), 1, &matrix, 0, 0.5, -1, 0, true);
            let expected = matrix.dispersion() as f32;
            assert!(
                (frame.dispersion() - expected).abs() < 1e-4,
                "the frame's derived dispersion {} must be the matrix's {expected}",
                frame.dispersion(),
            );
        }
        // …and the two cases really are different, so the comparison above has content.
        let flat = CoherenceFrame::observe(
            CellId([0x22; 16]), 1, &CoherenceMatrix::equicorrelated(7, 0.5), 0, 0.5, -1, 0, true,
        );
        assert!(flat.dispersion() < 1e-6, "an equicorrelated cell reads zero dispersion");
    }

    #[test]
    fn observe_reads_the_matrix_measures() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        let m = matrix.measures();
        let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0, 0.25, -1, 0, true);
        assert!((f64::from(f.phi) - m.phi).abs() < 1e-6);
        assert!((f64::from(f.purity) - m.purity).abs() < 1e-6);
        assert!((f64::from(f.reflection) - m.reflection).abs() < 1e-6);
        assert_eq!(f.regime(), Some(Regime::CollectiveSubject));
        assert!(!f.is_faulted(), "syndrome 0 for a healthy mask");
    }

    #[test]
    fn syndrome_localizes_a_single_fault() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        // Point 0's address is 1 (Fano/Hamming): a single fault there is a non-zero 3-bit syndrome.
        let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0b0000_0001, 0.0, -1, 0, true);
        assert!(f.is_faulted());
        assert!(f.syndrome <= 7, "syndrome is 3 bits");
    }

    #[test]
    fn syndrome_folds_a_multi_bit_degraded_mask() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        // Several faulted points at once: the mask still folds to a valid 3-bit syndrome (no panic,
        // no overflow), and the frame round-trips.
        for mask in [0b0000_0110u8, 0b0101_1010, 0b1111_1111] {
            let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, mask, 0.0, -1, 0, true);
            assert!(
                f.syndrome <= 7,
                "a multi-bit mask still yields a 3-bit syndrome"
            );
            assert_eq!(CoherenceFrame::decode(&f.encode()), Some(f));
        }
    }

    #[test]
    fn observe_sanitizes_non_finite_scalars() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        // A non-finite gap (a degenerate spectral computation could produce one) must not leak into
        // the frame: NaN would break the by-value round-trip (NaN != NaN) and poison comparisons.
        let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0, f64::NAN, 0, 0, true);
        assert!(
            f.gap.is_finite() && f.gap == 0.0,
            "a non-finite gap is coerced to 0.0"
        );
        assert!(
            [f.phi, f.purity, f.reflection, f.mean_r, f.gap]
                .iter()
                .all(|x| x.is_finite()),
            "every scalar in a frame is finite"
        );
        // With all scalars finite the frame round-trips by value, not merely byte-for-byte.
        assert_eq!(CoherenceFrame::decode(&f.encode()), Some(f));
    }

    /// **A reserved encoding reads as "I do not know", not as the worst value in the vocabulary.**
    ///
    /// The whole point of #333: the regime field is two bits wide and the vocabulary has three values, so
    /// encoding `3` is the natural home for a fourth regime. Before this, the catch-all arm reported it as
    /// `OverCoupled` — a *newer* peer described as the most alarming state this build can name, with full
    /// confidence and no way for any reader to tell.
    ///
    /// The two per-field assertions are deliberately separate from `fully_understood()`: a reader that
    /// needs only the alarm must still get it, so the unknown regime must NOT poison the alarm beside it.
    #[test]
    fn a_reserved_regime_encoding_is_unknown_rather_than_the_worst_known_value() {
        let mut f = sample_frame();
        f.verdict = (f.verdict & !REGIME_MASK) | 3;
        assert_eq!(f.regime(), None, "encoding 3 is not a regime this build knows");
        assert!(
            f.alarm().is_some(),
            "the alarm field is independent and must survive an unknown regime — a reader that needs only \
             the alarm is not blocked by a vocabulary it does not use"
        );
        assert!(!f.fully_understood(), "and the frame as a whole is not fully understood");
    }

    /// The same, one field over — and it matters more, because the cell census reads the alarm and nothing
    /// else. (`fanos_node::telemetry_dir::Census`, named rather than linked: that crate depends on this one,
    /// not the reverse, so rustdoc has nothing here to resolve the path against.)
    #[test]
    fn a_reserved_alarm_encoding_is_unknown_rather_than_the_worst_known_value() {
        let mut f = sample_frame();
        f.verdict = (f.verdict & !ALARM_MASK) | (3 << ALARM_SHIFT);
        assert_eq!(f.alarm(), None, "encoding 3 is not an alarm level this build knows");
        assert!(f.regime().is_some(), "the regime field is independent and survives");
        assert!(!f.fully_understood(), "and the frame as a whole is not fully understood");
    }

    /// **The unused high bits are part of the question, and this is the half no per-field check can give.**
    ///
    /// Both vocabularies read cleanly here, so `regime()` and `alarm()` are both `Some` and every
    /// field-level check passes — yet the frame carries a flag in bits 6-7 that this build does not know
    /// exists. That is precisely the case `fully_understood()` was added for: a reader asking "am I looking
    /// at a frame from a build ahead of mine" cannot answer it by testing the two values.
    #[test]
    fn a_flag_in_the_unused_high_bits_makes_a_frame_not_fully_understood() {
        let mut f = sample_frame();
        f.verdict |= UNUSED_VERDICT_BITS & 0b0100_0000;
        assert!(f.regime().is_some(), "the regime still reads — this is the control");
        assert!(f.alarm().is_some(), "and so does the alarm — also the control");
        assert!(
            !f.fully_understood(),
            "but a bit this build does not know is set, so the frame is not fully understood; without \
             this the predicate would be nothing more than `regime().is_some() && alarm().is_some()`"
        );
    }

    /// The negative control for the three above: an ordinary frame this build produced is fully understood.
    ///
    /// Without it the three assertions prove only that `fully_understood()` can return `false`, which a
    /// function returning a constant `false` would also satisfy.
    #[test]
    fn a_frame_this_build_produced_is_fully_understood() {
        let f = sample_frame();
        assert!(f.fully_understood());
        assert!(f.regime().is_some() && f.alarm().is_some());
    }

    #[test]
    fn verdict_packing_round_trips_through_accessors() {
        let f = sample_frame();
        // Reconstruct the packed byte from the accessors and compare.
        //
        // The two matches stay EXHAUSTIVE on purpose — that is what makes a fourth variant fail the build
        // here rather than pick up a number silently. Unwrapping is legitimate at exactly this site and
        // nowhere else: the frame was produced by this build's own encoder, so an encoding it cannot read
        // back would mean `observe` and the accessors disagree, which is a defect and should panic loudly
        // rather than be absorbed by a fallback.
        let regime = match f.regime().expect("this build encoded the frame, so it can read its regime") {
            Regime::Aggregate => 0u8,
            Regime::CollectiveSubject => 1,
            Regime::OverCoupled => 2,
        };
        let alarm = match f.alarm().expect("this build encoded the frame, so it can read its alarm") {
            AlarmLevel::Healthy => 0u8,
            AlarmLevel::Integration => 1,
            AlarmLevel::Structure => 2,
        };
        let mut rebuilt = regime | (alarm << ALARM_SHIFT);
        if f.is_integrated() {
            rebuilt |= INTEGRATED_BIT;
        }
        if f.correlation_is_measured() {
            rebuilt |= MEASURED_BIT;
        }
        assert_eq!(rebuilt, f.verdict);
    }

    /// Known-answer test for the canonical frame: a `r = 0.5` collective-subject Fano cell with point 0
    /// faulted, epoch 42, gap 0.5, no forecast, heal_seq 3, correlation **measured**. Pins the wire layout
    /// *and* the coherence math (`Φ = 1.5`, `R = 0.4`, `r = 0.5`). Any drift in either breaks this.
    ///
    /// The word *"mirrored in `conformance/vectors/telemetry.json`"* used to stand here and was the only
    /// thing holding the two copies together — nothing read the JSON (#160). `tests/conformance.rs` now
    /// loads it and compares, so this constant and the vector cannot drift apart in silence. This one stays
    /// because it is the in-crate check that survives `no_std` (an integration test has `std`, a unit test
    /// in this crate does not).
    #[test]
    fn frame_matches_the_known_answer_vector() {
        use core::fmt::Write;
        const KAT: &str = "11111111111111111111111111111111000000000000002a04313fc000003eb6db6e3ecccccd3f0000003f000000ffff00000003";
        let mut hex = String::with_capacity(FRAME_LEN * 2);
        for b in sample_frame().encode() {
            let _ = write!(hex, "{b:02x}");
        }
        assert_eq!(hex, KAT, "canonical telemetry frame KAT");
    }

    /// **The measured bit, both directions** (#154) — a bit checked only in the `true` case is
    /// indistinguishable from a constant.
    #[test]
    fn a_frame_says_whether_its_correlation_was_measured_or_assumed() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.45); // the shipped `healthy_correlation`
        let assumed = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0, 0.5, -1, 0, false);
        let measured = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0, 0.5, -1, 0, true);

        assert!(!assumed.correlation_is_measured(), "a fallback frame says so");
        assert!(measured.correlation_is_measured(), "and a measured one says so");

        // **The reason the bit exists.** The two frames are byte-identical apart from it, and every scalar
        // in both reads healthy: at the shipped `r = 0.45` the equicorrelated closed forms give
        // `Φ = (N−1)r² = 1.215 ≥ 1` and `R = 1/(N·P) = 0.4514 ≥ 1/3`. Without the bit, a node that had
        // observed nothing was indistinguishable from a healthy one — on the numbers, in the same direction.
        assert!(f64::from(assumed.phi) > 1.0, "the assumed frame reads integrated");
        assert!(assumed.is_integrated(), "…and says so in its verdict");
        assert_eq!(
            assumed.verdict | MEASURED_BIT,
            measured.verdict,
            "the two differ in exactly one bit — which is why nothing else could have told them apart",
        );

        // It survives the wire, or a reader on the other side is back where it started.
        let back = CoherenceFrame::decode(&assumed.encode()).expect("round-trips");
        assert!(!back.correlation_is_measured());
        let back = CoherenceFrame::decode(&measured.encode()).expect("round-trips");
        assert!(back.correlation_is_measured());
    }

    #[test]
    fn encode_decode_round_trips_exactly() {
        let f = sample_frame();
        let bytes = f.encode();
        assert_eq!(bytes.len(), FRAME_LEN);
        let back = CoherenceFrame::decode(&bytes).expect("round-trips");
        assert_eq!(back, f);
    }

    #[test]
    fn decode_ignores_trailing_bytes_and_rejects_short() {
        let f = sample_frame();
        let mut bytes = f.encode().to_vec();
        bytes.extend_from_slice(&[0xFF; 8]); // embedded: trailing ignored
        assert_eq!(CoherenceFrame::decode(&bytes), Some(f));
        assert!(CoherenceFrame::decode(&bytes[..10]).is_none());
    }
}
