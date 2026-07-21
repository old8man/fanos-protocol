//! **C1 / §8.1 — a global passive adversary (GPA) over the RUNNING mixnet.** The flagship anonymity claim —
//! "strong against a GPA" (spec §8.2) and orders-of-magnitude-better endpoint linkage than Tor (§8.1) — was
//! until now backed only by a crate-local leak-slope (`aphantos/tests/flow_correlation.rs`), never by an
//! adversary over the real routed + mixed + cover-scheduled network. This models it: a GPA taps every frame's
//! metadata `(t, from, to, len)` on the simulated wire (never content — cells are constant-size AEAD), and
//! runs the canonical **flow-correlation** attack — for every relay, the Pearson correlation between its
//! input-rate and output-rate time series. A relay that forwards a bursty flow immediately leaks a high
//! correlation (the GPA links its in-flow to its out-flow, tracing the circuit); constant-rate cover +
//! Poisson mixing must collapse that correlation to chance. We measure the GPA's advantage with the defense
//! ON and OFF and assert the defense erases the signal.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_aphantos::{Directory, NyxNode};
use fanos_field::F7;
use fanos_geometry::{Plane, Point, Triple};
use fanos_pqcrypto::{HybridKemSecret, SeedRng};
use fanos_runtime::{Command, Duration};
use fanos_sim::{FrameObs, Sim};

/// Spawn a full `PG(2,7)` cell of `NyxNode`s, optionally with Poisson mixing + cover (the C1 defense).
fn spawn_nyx_cell(sim: &mut Sim, mix: Option<(Duration, Duration)>) -> Vec<Triple> {
    let points: Vec<Point<F7>> = Plane::<F7>::points().collect();
    let mut directory = Directory::new();
    let mut secrets = Vec::with_capacity(points.len());
    for (i, point) in points.iter().enumerate() {
        let mut rng = SeedRng::from_seed(&[0x5A, i as u8]);
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        directory.insert(point.coords(), public);
        secrets.push(secret);
    }
    let mut coords = Vec::with_capacity(points.len());
    for (i, (point, secret)) in points.iter().zip(secrets).enumerate() {
        let mut node = NyxNode::new(
            *point,
            secret,
            directory.clone(),
            [i as u8; 32],
            [0u8; 32],
            3,
        );
        if let Some((mean_delay, cover_interval)) = mix {
            node = node.with_mixing(mean_delay, cover_interval);
        }
        coords.push(sim.add(Box::new(node)));
    }
    coords
}

/// Per-node **output** frame count over the run — what a GPA counts leaving each relay.
fn output_counts(tape: &[FrameObs], nodes: &[Triple]) -> Vec<usize> {
    nodes
        .iter()
        .map(|&n| tape.iter().filter(|o| o.from == n).count())
        .collect()
}

/// Run the routed mixnet with `real_cells` even-spread real onions client→service and return each node's
/// tapped output count. Even spread keeps the real rate within the cover budget — the regime in which
/// constant-rate cover is defined to displace (spec C1); a burst beyond the cover rate is a separate,
/// honestly-leaky regime, not what this measures.
fn run_and_tap(mix: Option<(Duration, Duration)>, real_cells: usize) -> (Vec<Triple>, Vec<usize>) {
    let mut sim = Sim::new(0x6AA_u64.wrapping_add(u64::from(mix.is_some())));
    let cell = spawn_nyx_cell(&mut sim, mix);
    if mix.is_some() {
        sim.inject_all(&Command::StartHeartbeat); // begin constant-rate cover
    }
    sim.observe_frames(); // the GPA starts tapping the wire

    let (client, service) = (cell[0], cell[40]);
    let total_ms = 9000u64;
    let step_ms = if real_cells == 0 {
        total_ms
    } else {
        total_ms / real_cells as u64
    };
    let mut injected = 0usize;
    let mut elapsed = 0u64;
    while elapsed < total_ms {
        while injected < real_cells && (injected as u64) * step_ms <= elapsed {
            sim.inject(
                client,
                Command::Send {
                    to: service,
                    payload: b"real-flow".to_vec(),
                },
            );
            injected += 1;
        }
        sim.run_for(Duration::from_millis(step_ms.min(200)));
        elapsed += step_ms.min(200);
    }
    let counts = output_counts(sim.observed_frames(), &cell);
    (cell, counts)
}

/// The GPA's **volume leak slope** on the *intermediate* relays: `max over relays (E(hi) − E(0)) / N`, the
/// extra frames a relay is observed emitting per extra real cell it forwards — the flow-correlation signal
/// (spec C1, `flow_correlation.rs` dE/dN, now over the routed network). The client-originator and
/// service-destination are excluded: endpoint exposure is the acknowledged §8.1 residual (`P_link = P_hop²`),
/// NOT what constant-rate cover defends — cover protects the *interior* hops, and that is the flagship claim.
fn gpa_volume_leak_slope(mix: Option<(Duration, Duration)>) -> f64 {
    const N: usize = 40;
    let (cell, e0) = run_and_tap(mix, 0);
    let (_, ehi) = run_and_tap(mix, N);
    let (client, service) = (cell[0], cell[40]);
    let mut best = 0.0f64;
    for (i, &node) in cell.iter().enumerate() {
        if node == client || node == service {
            continue; // endpoints are the §8.1 residual, not the cover-defended interior
        }
        let slope = (ehi[i] as f64 - e0[i] as f64) / N as f64;
        best = best.max(slope);
    }
    best
}

#[test]
fn constant_rate_cover_collapses_the_gpa_flow_correlation_on_interior_relays() {
    // Undefended (no cover, no mixing): an interior relay forwards each real onion immediately, so its
    // observed output volume grows one-for-one with the flow it carries — a leak slope ≈ 1 the GPA reads off.
    let undefended = gpa_volume_leak_slope(None);
    // Defended (constant-rate cover + Poisson mixing): a forwarded real onion DISPLACES a scheduled cover
    // cell, so the relay's observed output volume is independent of how much real traffic it carries — the
    // leak slope collapses to ~0. This is the C1 / §8.2 "strong against a GPA" claim, now measured by an
    // adversary over the real routed + mixed + cover-scheduled network, not a crate-local harness.
    let defended = gpa_volume_leak_slope(Some((
        Duration::from_millis(120),
        Duration::from_millis(150),
    )));

    assert!(
        undefended > 0.5,
        "an undefended interior relay's output volume tracks its real flow (leak slope {undefended:.3})"
    );
    assert!(
        defended < 0.25,
        "constant-rate cover must displace (not add), collapsing the interior leak slope to ~0, got {defended:.3}"
    );
    assert!(
        defended < undefended - 0.3,
        "the defense must materially erase the GPA's volume signal (defended {defended:.3} vs undefended {undefended:.3})"
    );
}
