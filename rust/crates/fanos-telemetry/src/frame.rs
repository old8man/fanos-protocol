//! The [`CoherenceFrame`] — the minimal sufficient statistic for a cell's health at a window.
//!
//! It folds a cell's coherence into a small, fixed-size, canonically-encoded record
//! (`docs/design-telemetry.md` §2). The **load-bearing** field is the 3-bit Fano/Hamming
//! `syndrome` (the perfect-code fault localizer — `Θ(log N)` bits, information-theoretically minimal
//! by the Minimal Self-Observation Overhead theorem); the `f32` coherence scalars (`Φ`, `P`, `R`,
//! mean `r`, spectral gap) are a convenience for humans and cross-cell roll-up. Per-node raw signals
//! never appear — the fold *is* the anonymization (design-telemetry.md §5).

use fanos_code::syndrome::syndrome3;
use fanos_diakrisis::coherence::{CoherenceMatrix, PHI_TH};
use fanos_diakrisis::window::{Alarm, CollectiveState};

/// A 16-byte opaque cell identifier (a leaf cell, a rolled-up parent cell, or a per-PID `Γ_app` cell).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
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

// `verdict` byte layout: [ .. .. integrated | alarm(2) | regime(2) ].
const REGIME_MASK: u8 = 0b0000_0011;
const ALARM_SHIFT: u8 = 2;
const ALARM_MASK: u8 = 0b0000_1100;
const INTEGRATED_BIT: u8 = 1 << 4;
/// The syndrome occupies 3 bits (`0` healthy, `1..=7` a point address).
const SYNDROME_MASK: u8 = 0b0000_0111;

/// The canonical on-wire length of a [`CoherenceFrame`] (bytes). Fixed and KAT-pinned.
pub const FRAME_LEN: usize = 52;

/// A cell's coherence at one observation window — the unit of FANOS telemetry.
#[derive(Clone, Copy, PartialEq, Debug)]
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
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // f64→f32 narrowing is deliberate for the wire frame.
    pub fn observe(
        cell_id: CellId,
        epoch: u64,
        matrix: &CoherenceMatrix,
        degraded: u8,
        gap: f64,
        forecast: i16,
        heal_seq: u32,
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

    /// The collective-subject regime.
    #[must_use]
    pub fn regime(&self) -> Regime {
        match self.verdict & REGIME_MASK {
            0 => Regime::Aggregate,
            1 => Regime::CollectiveSubject,
            _ => Regime::OverCoupled,
        }
    }

    /// The leading-indicator alarm level.
    #[must_use]
    pub fn alarm(&self) -> AlarmLevel {
        match (self.verdict & ALARM_MASK) >> ALARM_SHIFT {
            0 => AlarmLevel::Healthy,
            1 => AlarmLevel::Integration,
            _ => AlarmLevel::Structure,
        }
    }

    /// Whether the cell is integrated (`Φ ≥ 1`).
    #[must_use]
    pub fn is_integrated(&self) -> bool {
        self.verdict & INTEGRATED_BIT != 0
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
    pub fn encode(&self) -> [u8; FRAME_LEN] {
        let mut buf = [0u8; FRAME_LEN];
        let mut w = Writer { buf: &mut buf };
        w.put(&self.cell_id.0);
        w.put(&self.epoch.to_be_bytes());
        w.put(&[self.syndrome, self.verdict]);
        w.put(&self.phi.to_bits().to_be_bytes());
        w.put(&self.purity.to_bits().to_be_bytes());
        w.put(&self.reflection.to_bits().to_be_bytes());
        w.put(&self.mean_r.to_bits().to_be_bytes());
        w.put(&self.gap.to_bits().to_be_bytes());
        w.put(&self.forecast.to_be_bytes());
        w.put(&self.heal_seq.to_be_bytes());
        buf
    }

    /// Decode a frame from its canonical encoding. Reads exactly [`FRAME_LEN`] bytes from the front
    /// (any trailing bytes are ignored, so a frame may be embedded); `None` if too short.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader { buf: bytes };
        let cell_id = CellId(r.take()?);
        let epoch = u64::from_be_bytes(r.take()?);
        let [syndrome, verdict] = r.take()?;
        let phi = f32::from_bits(u32::from_be_bytes(r.take()?));
        let purity = f32::from_bits(u32::from_be_bytes(r.take()?));
        let reflection = f32::from_bits(u32::from_be_bytes(r.take()?));
        let mean_r = f32::from_bits(u32::from_be_bytes(r.take()?));
        let gap = f32::from_bits(u32::from_be_bytes(r.take()?));
        let forecast = i16::from_be_bytes(r.take()?);
        let heal_seq = u32::from_be_bytes(r.take()?);
        Some(Self {
            cell_id,
            epoch,
            syndrome,
            verdict,
            phi,
            purity,
            reflection,
            mean_r,
            gap,
            forecast,
            heal_seq,
        })
    }
}

/// A forward byte writer over a fixed buffer — sequential `copy_from_slice` with no indexing or
/// panics for a correctly-sized total (each [`put`](Writer::put) consumes exactly its bytes).
struct Writer<'a> {
    buf: &'a mut [u8],
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        let taken = core::mem::take(&mut self.buf);
        let (head, tail) = taken.split_at_mut(bytes.len());
        head.copy_from_slice(bytes);
        self.buf = tail;
    }
}

/// A forward byte reader returning fixed-size arrays, `None` when exhausted (no indexing/unwrap).
struct Reader<'a> {
    buf: &'a [u8],
}

impl Reader<'_> {
    fn take<const M: usize>(&mut self) -> Option<[u8; M]> {
        let (head, tail) = self.buf.split_at_checked(M)?;
        self.buf = tail;
        head.try_into().ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample_frame() -> CoherenceFrame {
        // A collective-subject cell (r = 0.5 ∈ (1/√6, 1/√3]) with point 0 faulted.
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        CoherenceFrame::observe(CellId([0x11; 16]), 42, &matrix, 0b0000_0001, 0.5, -1, 3)
    }

    #[test]
    fn observe_reads_the_matrix_measures() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        let m = matrix.measures();
        let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0, 0.25, -1, 0);
        assert!((f64::from(f.phi) - m.phi).abs() < 1e-6);
        assert!((f64::from(f.purity) - m.purity).abs() < 1e-6);
        assert!((f64::from(f.reflection) - m.reflection).abs() < 1e-6);
        assert_eq!(f.regime(), Regime::CollectiveSubject);
        assert!(!f.is_faulted(), "syndrome 0 for a healthy mask");
    }

    #[test]
    fn syndrome_localizes_a_single_fault() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        // Point 0's address is 1 (Fano/Hamming): a single fault there is a non-zero 3-bit syndrome.
        let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0b0000_0001, 0.0, -1, 0);
        assert!(f.is_faulted());
        assert!(f.syndrome <= 7, "syndrome is 3 bits");
    }

    #[test]
    fn syndrome_folds_a_multi_bit_degraded_mask() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        // Several faulted points at once: the mask still folds to a valid 3-bit syndrome (no panic,
        // no overflow), and the frame round-trips.
        for mask in [0b0000_0110u8, 0b0101_1010, 0b1111_1111] {
            let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, mask, 0.0, -1, 0);
            assert!(f.syndrome <= 7, "a multi-bit mask still yields a 3-bit syndrome");
            assert_eq!(CoherenceFrame::decode(&f.encode()), Some(f));
        }
    }

    #[test]
    fn observe_sanitizes_non_finite_scalars() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        // A non-finite gap (a degenerate spectral computation could produce one) must not leak into
        // the frame: NaN would break the by-value round-trip (NaN != NaN) and poison comparisons.
        let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0, f64::NAN, 0, 0);
        assert!(f.gap.is_finite() && f.gap == 0.0, "a non-finite gap is coerced to 0.0");
        assert!(
            [f.phi, f.purity, f.reflection, f.mean_r, f.gap].iter().all(|x| x.is_finite()),
            "every scalar in a frame is finite"
        );
        // With all scalars finite the frame round-trips by value, not merely byte-for-byte.
        assert_eq!(CoherenceFrame::decode(&f.encode()), Some(f));
    }

    #[test]
    fn verdict_packing_round_trips_through_accessors() {
        let f = sample_frame();
        // Reconstruct the packed byte from the accessors and compare.
        let regime = match f.regime() {
            Regime::Aggregate => 0u8,
            Regime::CollectiveSubject => 1,
            Regime::OverCoupled => 2,
        };
        let alarm = match f.alarm() {
            AlarmLevel::Healthy => 0u8,
            AlarmLevel::Integration => 1,
            AlarmLevel::Structure => 2,
        };
        let mut rebuilt = regime | (alarm << ALARM_SHIFT);
        if f.is_integrated() {
            rebuilt |= INTEGRATED_BIT;
        }
        assert_eq!(rebuilt, f.verdict);
    }

    /// Known-answer test (mirrored in `conformance/vectors/telemetry.json`): the canonical frame for
    /// a `r = 0.5` collective-subject Fano cell with point 0 faulted, epoch 42, gap 0.5, no forecast,
    /// heal_seq 3. Pins the wire layout *and* the coherence math (`Φ = 1.5`, `R = 0.4`, `r = 0.5`).
    /// Any drift in either breaks this.
    #[test]
    fn frame_matches_the_known_answer_vector() {
        use core::fmt::Write;
        const KAT: &str = "11111111111111111111111111111111000000000000002a04113fc000003eb6db6e3ecccccd3f0000003f000000ffff00000003";
        let mut hex = String::with_capacity(FRAME_LEN * 2);
        for b in sample_frame().encode() {
            let _ = write!(hex, "{b:02x}");
        }
        assert_eq!(hex, KAT, "canonical telemetry frame KAT");
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
