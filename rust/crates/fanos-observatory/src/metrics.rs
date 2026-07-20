//! Operator-facing metrics: render a [`CoherenceSnapshot`] as [OpenMetrics](https://openmetrics.io)
//! text exposition format — the DIAKRISIS coherence self-model (`Φ`/`P`/`R`, spec §2.7), the 3-bit
//! syndrome and derived verdict, and the leading-indicator/cascade alarms (spec §6.6, §2.7), for a
//! Prometheus-compatible scraper.
//!
//! This is a **pure rendering function**: no I/O, no server, just `&CoherenceSnapshot -> String`. The
//! node's async layer serves the text over an HTTP endpoint (a deployment concern, `#120`); this module
//! only produces the bytes that endpoint would write. Every gauge is exactly what
//! [`CoherenceSnapshot::to_json`](fanos_telemetry::CoherenceSnapshot::to_json) already exposes for
//! `--json` — one self-model, now a third audience (a metrics scraper, after the human TUI and the JSON
//! agent).

use std::fmt::Write as _;

use fanos_telemetry::snapshot::{OVER_COUPLING, PHI_THRESHOLD, R_STAR};
use fanos_telemetry::{AlarmLevel, CoherenceSnapshot, Regime};

/// The cell-identifying label every metric line carries, so a multi-node/multi-cell scrape can tell
/// series apart (the standard Prometheus exporter convention — e.g. `node_exporter`'s `instance`).
fn cell_id_label(snapshot: &CoherenceSnapshot) -> String {
    let mut hex = String::with_capacity(32);
    for b in snapshot.cell_id.0 {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// The derived, single-state DIAKRISIS verdict an operator dashboard reads at a glance — narrower than
/// the full `fanos_diakrisis::Verdict` (this snapshot does not carry the structural/partition checks,
/// only what a per-cell coherence fold observes), but ordered the same way `diagnose()` prioritizes
/// (structural/localized first, then systemic, then the leading-indicator alarm): a node fault is the
/// most actionable signal, so it wins over a merely-elevated alarm level.
fn derived_verdict(s: &CoherenceSnapshot) -> &'static str {
    if s.faulted {
        "localized"
    } else if matches!(s.regime, Regime::OverCoupled) {
        "systemic"
    } else {
        match s.alarm {
            AlarmLevel::Structure => "structure_alarm",
            AlarmLevel::Integration => "integration_alarm",
            AlarmLevel::Healthy => "healthy",
        }
    }
}

/// All possible [`derived_verdict`] states, in the same priority order — the labeled-state metric emits
/// one line per state (the standard Prometheus "enum gauge" pattern, e.g. `kube_pod_status_phase`), so a
/// PromQL consumer can select on `state=` without needing `topk`/aggregation tricks.
const VERDICT_STATES: [&str; 5] = [
    "localized",
    "systemic",
    "structure_alarm",
    "integration_alarm",
    "healthy",
];

/// Append one gauge's `# HELP`/`# TYPE` header and single value line.
fn push_gauge(out: &mut String, name: &str, help: &str, cell_id: &str, value: f64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    if value.is_finite() {
        let _ = writeln!(out, "{name}{{cell_id=\"{cell_id}\"}} {value}");
    } else {
        // OpenMetrics has no NaN/Inf token for a value; a non-finite scalar (a degenerate matrix,
        // already sanitized to 0.0 by CoherenceFrame::observe — see its `finite()` guard — but
        // defended here too, since a future snapshot source should not be able to emit invalid text)
        // is surfaced as a fixed sentinel line rather than silently dropped or malformed.
        let _ = writeln!(out, "{name}{{cell_id=\"{cell_id}\"}} 0");
    }
}

/// Append one monotone counter's header and single value line (spec: `_total`-suffixed by convention).
fn push_counter(out: &mut String, name: &str, help: &str, cell_id: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name}{{cell_id=\"{cell_id}\"}} {value}");
}

/// Append a labeled-state gauge: one line per possible `state`, `1` for the current one and `0` for
/// every other — the Prometheus "enum" convention (queryable with a plain `== 1` selector, unlike
/// OpenMetrics' native `stateset` type, which fewer dashboards support).
fn push_state(out: &mut String, name: &str, help: &str, cell_id: &str, states: &[&str], current: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    for &state in states {
        let v = i32::from(state == current);
        let _ = writeln!(out, "{name}{{cell_id=\"{cell_id}\",state=\"{state}\"}} {v}");
    }
}

/// The core DIAKRISIS coherence gauges (`Φ`/`P`/`R`, spec §2.7) plus the cell/epoch/syndrome/readiness
/// state every operator dashboard's top row wants.
fn push_coherence_gauges(out: &mut String, cell_id: &str, s: &CoherenceSnapshot) {
    push_gauge(
        out,
        "fanos_coherence_phi",
        "Integration Φ = 6r² (spec §2.7); a cell is one bound subject iff Φ ≥ 1.",
        cell_id,
        s.phi,
    );
    push_gauge(
        out,
        "fanos_coherence_purity",
        "Structuredness P = Tr(Γ²) (spec §2.7); viable while P > 2/N.",
        cell_id,
        s.purity,
    );
    push_gauge(
        out,
        "fanos_coherence_reflection",
        "Reflection R = 1/(N·P) (spec §2.7); self-observation holds while R ≥ 1/3.",
        cell_id,
        s.reflection,
    );
    push_gauge(
        out,
        "fanos_coherence_mean_correlation",
        "Mean off-diagonal inter-node correlation r, compared against r* and the over-coupling bound.",
        cell_id,
        s.mean_correlation,
    );
    push_gauge(
        out,
        "fanos_coherence_spectral_gap",
        "Polar spectral gap Δ (T-226(v)); the self-healing rate, τ = 1/Δ.",
        cell_id,
        s.spectral_gap,
    );
    push_gauge(
        out,
        "fanos_coherence_stability_radius",
        "Stability radius r_stab = √(max(0, P − 2/N)) (T-104); the viability speedometer.",
        cell_id,
        s.stability_radius,
    );
    push_gauge(
        out,
        "fanos_cell_alive_nodes",
        "Estimated alive nodes in the cell, recovered from Φ = (N−1)r² (spec §2.7); exact for the \
         mandatory liveness self-observation, approximate for the measured-behavioural fold.",
        cell_id,
        f64::from(s.alive_nodes),
    );
    push_gauge(
        out,
        "fanos_epoch",
        "The agreed observation-window epoch (the flooded beacon), decoupled from any node's local clock.",
        cell_id,
        // The epoch is opaque/monotone, not a coherence scalar — render exactly, no NaN path applies.
        s.epoch as f64,
    );
    push_gauge(
        out,
        "fanos_diakrisis_syndrome",
        "The 3-bit Fano/Hamming fault-localizer address: 0 = healthy, 1..=7 = the faulted point.",
        cell_id,
        f64::from(s.syndrome),
    );
    push_gauge(
        out,
        "fanos_diakrisis_faulted",
        "1 iff the 3-bit syndrome localizes a node fault (syndrome ≠ 0).",
        cell_id,
        f64::from(i32::from(s.faulted)),
    );
    push_gauge(
        out,
        "fanos_cell_ready",
        "Readiness: Φ ≥ 1 ∧ R ≥ 1/3 — bound and still self-observing. The theorem-grounded liveness \
         gate a probe should read in place of a hand-picked latency.",
        cell_id,
        f64::from(i32::from(s.ready)),
    );
}

/// The leading-indicator (`Φ < 1`, spec §6.6) and cascade/over-coupling (spec §2.7, §18.2) alarms,
/// plus the sparse healing counter.
fn push_alarm_gauges(out: &mut String, cell_id: &str, s: &CoherenceSnapshot) {
    push_gauge(
        out,
        "fanos_coherence_integration_alarm",
        "Leading-indicator alarm (spec §6.6): Φ < 1 — integration crosses before structure, the \
         earliest warning of the two-stage collapse.",
        cell_id,
        f64::from(i32::from(s.phi < PHI_THRESHOLD)),
    );
    push_gauge(
        out,
        "fanos_coherence_cascade_alarm",
        "Cascade early-warning (spec §2.7): mean correlation r has crossed r* = 1/√6, the onset of the \
         collective-subject/cascade-risk band.",
        cell_id,
        f64::from(i32::from(s.mean_correlation >= R_STAR)),
    );
    push_gauge(
        out,
        "fanos_coherence_over_coupling_alarm",
        "Over-coupling alarm (spec §18.2): r has crossed 1/√3 — the cell is losing its self-model \
         (R < 1/3); the response is to shed correlation (Decouple).",
        cell_id,
        f64::from(i32::from(s.mean_correlation >= OVER_COUPLING)),
    );
    push_gauge(
        out,
        "fanos_coherence_cascade_lead_windows",
        "Forecast windows of lead time before a predicted cascade, or -1 if none forecast.",
        cell_id,
        f64::from(s.cascade_lead),
    );
    push_gauge(
        out,
        "fanos_coherence_cascade_imminent",
        "1 iff a cascade is forecast (cascade_lead ≥ 0).",
        cell_id,
        f64::from(i32::from(s.cascade_imminent())),
    );
    push_counter(
        out,
        "fanos_healing_actions_total",
        "Monotone count of self-healing actions taken (the sparse healing event timeline).",
        cell_id,
        u64::from(s.heal_seq),
    );
}

/// The three labeled-state (enum) gauges: the derived operator verdict, the raw collective-subject
/// regime, and the raw alarm level.
fn push_labeled_states(out: &mut String, cell_id: &str, s: &CoherenceSnapshot) {
    push_state(
        out,
        "fanos_diakrisis_verdict",
        "The derived single-state operator verdict for this cell (priority: localized fault > \
         systemic over-coupling > leading-indicator alarm level > healthy).",
        cell_id,
        &VERDICT_STATES,
        derived_verdict(s),
    );
    push_state(
        out,
        "fanos_coherence_regime",
        "The collective-subject regime classification (spec §18.2).",
        cell_id,
        &["aggregate", "collective_subject", "over_coupled"],
        s.regime.as_str(),
    );
    push_state(
        out,
        "fanos_coherence_alarm_level",
        "The raw leading-indicator alarm level (spec §6.6).",
        cell_id,
        &["healthy", "integration", "structure"],
        s.alarm.as_str(),
    );
}

/// Render `snapshot` as OpenMetrics text exposition format: the DIAKRISIS coherence gauges (`Φ`/`P`/`R`,
/// spec §2.7), the cell/epoch/syndrome state, the derived verdict, and the leading-indicator (`Φ < 1`,
/// spec §6.6) and cascade (`r ≥ r* = 1/√6`, spec §2.7) alarms — terminated by the mandatory `# EOF`
/// marker (OpenMetrics §"ABNF": a conformant exposition MUST end with it; Prometheus's own scraper
/// accepts it as a harmless trailing comment too, so this text is valid for both).
#[must_use]
pub fn render_openmetrics(snapshot: &CoherenceSnapshot) -> String {
    let mut out = String::with_capacity(2048);
    let cell_id = cell_id_label(snapshot);

    push_coherence_gauges(&mut out, &cell_id, snapshot);
    push_alarm_gauges(&mut out, &cell_id, snapshot);
    push_labeled_states(&mut out, &cell_id, snapshot);

    out.push_str("# EOF\n");
    out
}

/// A compact, programmatic health check — the fields an operator's alerting rule or a `/healthz`
/// handler wants without parsing the full metrics text. Derived from the same [`CoherenceSnapshot`]
/// the OpenMetrics rendering reads, so the two never disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthSummary {
    /// `Φ ≥ 1 ∧ R ≥ 1/3` — the theorem-grounded liveness gate.
    pub ready: bool,
    /// The derived single-state verdict (see [`render_openmetrics`]'s `fanos_diakrisis_verdict`).
    pub verdict: &'static str,
    /// The estimated alive-node count (see [`CoherenceSnapshot::alive_nodes`]).
    pub alive_nodes: u32,
    /// The leading-indicator alarm has fired (`Φ < 1`, spec §6.6).
    pub integration_alarm: bool,
    /// The cascade early-warning has fired (`r ≥ r*`, spec §2.7).
    pub cascade_alarm: bool,
}

impl HealthSummary {
    /// Derive the summary from a snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: &CoherenceSnapshot) -> Self {
        Self {
            ready: snapshot.ready,
            verdict: derived_verdict(snapshot),
            alive_nodes: snapshot.alive_nodes,
            integration_alarm: snapshot.phi < PHI_THRESHOLD,
            cascade_alarm: snapshot.mean_correlation >= R_STAR,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use fanos_diakrisis::coherence::CoherenceMatrix;
    use fanos_telemetry::{CellId, CoherenceFrame};

    /// A frame from an equicorrelated cell at correlation `r`, mirroring `snapshot.rs`'s own test
    /// helper so the two crates' tests exercise the same shape of sample data.
    fn snapshot(r: f64) -> CoherenceSnapshot {
        let matrix = CoherenceMatrix::equicorrelated(7, r);
        let frame = CoherenceFrame::observe(CellId([0xAB; 16]), 9, &matrix, 0, 0.5, -1, 3);
        CoherenceSnapshot::from_frame(&frame)
    }

    #[test]
    fn renders_valid_openmetrics_framing() {
        let text = render_openmetrics(&snapshot(0.5));
        assert!(text.ends_with("# EOF\n"), "OpenMetrics requires the EOF marker");
        // Every metric line is either a `#`-comment or `name{labels} value`; no line is empty-but-not-EOF.
        for line in text.lines() {
            assert!(
                line.starts_with('#') || line.contains('{'),
                "unexpected bare line: {line:?}"
            );
        }
        // HELP/TYPE always precede their metric's first sample line.
        assert!(text.contains("# TYPE fanos_coherence_phi gauge"));
        assert!(text.contains("# TYPE fanos_healing_actions_total counter"));
    }

    #[test]
    fn healthy_cell_gauges_carry_the_correct_values() {
        let snap = snapshot(0.5); // collective-subject band: Φ=1.5, R=0.4, r=0.5
        let text = render_openmetrics(&snap);
        let cell_id = cell_id_label(&snap);
        assert!(text.contains(&format!(
            "fanos_coherence_phi{{cell_id=\"{cell_id}\"}} {}",
            snap.phi
        )));
        assert!(text.contains(&format!(
            "fanos_coherence_purity{{cell_id=\"{cell_id}\"}} {}",
            snap.purity
        )));
        assert!(text.contains(&format!(
            "fanos_coherence_reflection{{cell_id=\"{cell_id}\"}} {}",
            snap.reflection
        )));
        assert!(text.contains(&format!("fanos_cell_alive_nodes{{cell_id=\"{cell_id}\"}} 7")));
        assert!(text.contains(&format!("fanos_epoch{{cell_id=\"{cell_id}\"}} 9")));
        assert!(text.contains(&format!("fanos_cell_ready{{cell_id=\"{cell_id}\"}} 1")));
        assert!(text.contains(&format!(
            "fanos_diakrisis_verdict{{cell_id=\"{cell_id}\",state=\"healthy\"}} 1"
        )));
        assert!(text.contains(&format!(
            "fanos_diakrisis_verdict{{cell_id=\"{cell_id}\",state=\"localized\"}} 0"
        )));
        assert!(text.contains(&format!(
            "fanos_coherence_regime{{cell_id=\"{cell_id}\",state=\"collective_subject\"}} 1"
        )));
        assert!(text.contains(&format!(
            "fanos_coherence_integration_alarm{{cell_id=\"{cell_id}\"}} 0"
        )));
        // r=0.5 is already past r*=1/√6≈0.408 (it sits in the collective-subject band, (r*, 1/√3]) —
        // the cascade alarm is r≥r* itself, not "unhealthy": on the equicorrelated stratum r≥r* and
        // Φ≥1 are the SAME crossing (r*=1/√(N−1) is defined as exactly the Φ=1 boundary), so every
        // ready cell has it set. It stays meaningful because a measured (non-equicorrelated) frame's
        // mean r and Φ need not cross at the same point — this snapshot's idealized generator just
        // happens to make them coincide.
        assert!(text.contains(&format!("fanos_coherence_cascade_alarm{{cell_id=\"{cell_id}\"}} 1")));
        assert!(text.contains(&format!(
            "fanos_coherence_over_coupling_alarm{{cell_id=\"{cell_id}\"}} 0"
        )));
    }

    #[test]
    fn a_faulted_cell_shows_the_localized_verdict_and_syndrome() {
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        let frame = CoherenceFrame::observe(CellId([0x22; 16]), 4, &matrix, 0b0000_0001, 0.1, -1, 1);
        let snap = CoherenceSnapshot::from_frame(&frame);
        let text = render_openmetrics(&snap);
        let cell_id = cell_id_label(&snap);
        assert!(snap.faulted);
        assert!(text.contains(&format!("fanos_diakrisis_faulted{{cell_id=\"{cell_id}\"}} 1")));
        assert!(text.contains(&format!(
            "fanos_diakrisis_verdict{{cell_id=\"{cell_id}\",state=\"localized\"}} 1"
        )));
        assert!(text.contains(&format!(
            "fanos_diakrisis_verdict{{cell_id=\"{cell_id}\",state=\"healthy\"}} 0"
        )));
        assert!(!text.contains(&format!("fanos_diakrisis_syndrome{{cell_id=\"{cell_id}\"}} 0")));
    }

    #[test]
    fn leading_indicator_and_cascade_alarms_fire_past_their_thresholds() {
        // Φ < 1 fires the integration alarm well before over-coupling; a weakly-coupled aggregate.
        let weak = snapshot(0.1);
        assert!(weak.phi < PHI_THRESHOLD);
        let weak_text = render_openmetrics(&weak);
        let weak_id = cell_id_label(&weak);
        assert!(weak_text.contains(&format!(
            "fanos_coherence_integration_alarm{{cell_id=\"{weak_id}\"}} 1"
        )));

        // r past r* = 1/√6 ≈ 0.408 fires the cascade alarm.
        let cascading = snapshot(0.42);
        assert!(cascading.mean_correlation >= R_STAR);
        let cascading_text = render_openmetrics(&cascading);
        let cascading_id = cell_id_label(&cascading);
        assert!(cascading_text.contains(&format!(
            "fanos_coherence_cascade_alarm{{cell_id=\"{cascading_id}\"}} 1"
        )));

        // r past 1/√3 fires the over-coupling alarm too (the systemic verdict).
        let over_coupled = snapshot(0.6);
        assert!(over_coupled.mean_correlation >= OVER_COUPLING);
        let over_text = render_openmetrics(&over_coupled);
        let over_id = cell_id_label(&over_coupled);
        assert!(over_text.contains(&format!(
            "fanos_coherence_over_coupling_alarm{{cell_id=\"{over_id}\"}} 1"
        )));
        assert!(over_text.contains(&format!(
            "fanos_diakrisis_verdict{{cell_id=\"{over_id}\",state=\"systemic\"}} 1"
        )));
    }

    #[test]
    fn health_summary_matches_the_rendered_metrics() {
        let snap = snapshot(0.1); // aggregate, Φ<1, not ready
        let summary = HealthSummary::from_snapshot(&snap);
        assert_eq!(summary.ready, snap.ready);
        assert!(!summary.ready);
        assert_eq!(summary.verdict, derived_verdict(&snap));
        assert_eq!(summary.alive_nodes, snap.alive_nodes);
        assert!(summary.integration_alarm, "Φ<1 must set the alarm");
        assert!(!summary.cascade_alarm, "r=0.1 is well below r*");
    }

    #[test]
    fn most_verdict_states_are_reachable_via_the_equicorrelated_generator() {
        // Not a vacuous label list: each of these states actually fires for some real snapshot.
        assert_eq!(derived_verdict(&snapshot(0.5)), "healthy");
        assert_eq!(derived_verdict(&snapshot(0.1)), "structure_alarm");
        assert_eq!(derived_verdict(&snapshot(0.6)), "systemic");
        let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
        let frame = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 1, 0.0, -1, 0);
        assert_eq!(derived_verdict(&CoherenceSnapshot::from_frame(&frame)), "localized");
        // "integration_alarm" (Φ<1 but P≥2/N) is NOT reachable from this generator: on the
        // equicorrelated stratum P = (1+Φ)/N, so P=2/N and Φ=1 are the exact same crossing —
        // `AlarmLevel::Integration` requires a non-equicorrelated (real measured) coherence
        // structure, where mean r and the matrix-wide Φ need not cross together. All 5
        // VERDICT_STATES are exercised in the OpenMetrics rendering regardless (every state gets a
        // line — see `renders_valid_openmetrics_framing`); this test documents which are reachable
        // through the idealized fixture the rest of this suite (and snapshot.rs's) uses.
    }
}
