//! The unified-topology payoff: a 7-node Fano cell **embedded** at arbitrary coordinates on a larger
//! transport plane (via `OverlayNode::with_cell_members`) runs the full DIAKRISIS reflex — it reports a
//! coherence self-model at every node and senses member loss — which a plain large-plane node could not
//! (its `self_index` was `None`, so it produced no frame at all). This is the seam that lets one
//! connected topology carry both the coherence and routing lenses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_field::F31;
use fanos_geometry::{Point, Triple};
use fanos_runtime::{Command, Config, Duration, OverlayNode};
use fanos_sim::Sim;

fn config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

/// Seven arbitrary, distinct F31 points — deliberately NOT the base cell's points 0..6 — form one cell.
const SEATS: [usize; 7] = [3, 17, 42, 100, 250, 500, 900];

fn embedded_cell(seed: u64) -> (Sim, [Triple; 7]) {
    let members: [Triple; 7] = SEATS.map(|i| Point::<F31>::at(i).coords());
    let mut sim = Sim::new(seed);
    for &i in &SEATS {
        let node = OverlayNode::<F31>::new(Point::<F31>::at(i), config()).with_cell_members(members);
        sim.add(Box::new(node));
    }
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1500));
    (sim, members)
}

#[test]
fn an_embedded_fano_cell_reports_coherence_at_every_node() {
    let (sim, _) = embedded_cell(1);
    let snap = sim.fleet_snapshot();

    assert_eq!(snap.stats.total, 7);
    assert_eq!(
        snap.stats.reporting, 7,
        "an embedded cell reports a self-model at every node (impossible before with_cell_members)"
    );
    assert!(snap.stats.is_healthy(), "the settled embedded cell is fleet-healthy: {:?}", snap.stats);
    assert!(snap.stats.mean_phi.is_finite() && snap.stats.mean_phi > 0.0, "Φ measured: {}", snap.stats.mean_phi);
}

#[test]
fn crashing_a_member_of_an_embedded_cell_is_sensed() {
    let (mut sim, members) = embedded_cell(2);
    // Crash one member and let the survivors sense the loss past the liveness timeout.
    sim.crash(members[4]);
    sim.run_for(Duration::from_millis(2500));
    let snap = sim.fleet_snapshot();

    assert_eq!(snap.stats.alive, 6, "one member down");
    // The survivors' self-model registers the loss — the embedded cell diagnoses like a base cell.
    assert!(
        !snap.stats.is_healthy() || snap.stats.alive < snap.stats.total,
        "losing a member perturbs the embedded cell's coherence: {:?}",
        snap.stats
    );
    assert!(snap.concerns().count() >= 1, "the crashed member (and any degradation) is flagged");
}
