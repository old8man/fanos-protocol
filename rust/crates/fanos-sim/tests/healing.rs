//! Self-healing scenarios: the cell does not merely *diagnose* a fault — it *acts*. These drive
//! the reflexive loop's act phase (reroute / repair / escalate, spec §6.7, §6.9) over the
//! simulator and assert the emergent property that matters operationally: **service continuity**
//! under loss. Each is grounded in the UHM healing theory (projective LRC, peeling, §6.3/§L4).

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_diakrisis::{Fault, Verdict};
use fanos_field::F2;
use fanos_geometry::fano;
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Sim, spawn_cell};

fn healing_config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

/// Bring a Fano cell to steady state, crash `victim`, and let its heartbeats time out.
fn cell_with_crash(seed: u64, victim: usize, cfg: Config) -> (Sim, Vec<[u32; 3]>) {
    let mut sim = Sim::new(seed);
    let cell = spawn_cell::<F2>(&mut sim, cfg);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    sim.crash(cell[victim]);
    sim.run_for(Duration::from_millis(3000));
    (sim, cell)
}

#[test]
fn a_crash_triggers_repair_and_reroute() {
    let (mut sim, cell) = cell_with_crash(1, 5, healing_config());
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    let report = sim.report();
    // Survivors both localize the crash AND act on it.
    assert!(report.any_verdict(&Verdict::Localized(Fault::Single(5))));
    assert!(report.metrics.repairs > 0, "the lost shard was regenerated");
    assert!(
        report.metrics.reroutes > 0,
        "traffic was rerouted around it"
    );
    assert!(
        report.any_repaired(cell[5]),
        "node 5's shard specifically repaired"
    );
}

#[test]
fn rerouted_traffic_to_a_dead_node_still_delivers() {
    // The operational payoff: after healing, a message addressed to the dead node's data is
    // served by the co-linear survivor (LRC availability, spec §L4) — service continuity.
    let (mut sim, cell) = cell_with_crash(2, 5, healing_config());
    sim.inject_all(&Command::Diagnose); // installs each survivor's reroute table
    sim.settle();

    let before = sim.report().metrics.payloads_delivered;
    sim.inject(
        cell[0],
        Command::Send {
            to: cell[5],
            payload: b"served-anyway".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));

    let report = sim.report();
    assert_eq!(
        report.metrics.payloads_delivered,
        before + 1,
        "delivered despite the crash"
    );
    // It was served by mediator(0,5), the surviving co-linear node — not the dead node.
    let via = cell[fano::mediator(0, 5).unwrap()];
    let (recv, sender, bytes) = report.deliveries().last().unwrap();
    assert_eq!(recv, via, "served by the co-linear survivor");
    assert_eq!(sender, cell[0]);
    assert_eq!(bytes, b"served-anyway");
}

#[test]
fn without_healing_the_same_traffic_is_lost() {
    // Contrast: a sense-only cell (no act phase) drops traffic to the dead node.
    let cfg = Config {
        self_healing: false,
        ..healing_config()
    };
    let (mut sim, cell) = cell_with_crash(2, 5, cfg);
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    let before = sim.report().metrics.payloads_delivered;
    sim.inject(
        cell[0],
        Command::Send {
            to: cell[5],
            payload: b"into-the-void".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));

    assert_eq!(
        sim.report().metrics.payloads_delivered,
        before,
        "with no reroute, traffic to a dead node is dropped"
    );
}

#[test]
fn a_recovered_node_clears_its_reroute_and_is_reachable_directly() {
    let (mut sim, cell) = cell_with_crash(3, 5, healing_config());
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    assert!(sim.report().metrics.reroutes > 0);

    // The node rejoins (churn). A rejoining node re-bootstraps its heartbeat (its old timer was
    // lost while crashed), then its pings/pongs clear the reroute across the cell.
    sim.recover(cell[5]);
    sim.inject(cell[5], Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    // The last round of verdicts is healthy again — the cell fully reintegrated.
    let last_seven: Vec<_> = sim.report().verdicts().rev().take(7).collect();
    assert!(
        last_seven.iter().all(|(_, v)| **v == Verdict::Healthy),
        "cell returned to healthy after rejoin: {last_seven:?}"
    );
}

#[test]
fn three_crashes_escalate_yet_heal_locally() {
    // The syndrome decoder saturates at ≥3 faults (Escalate), but the peeling LRC still recovers
    // 0,1,2 (not a hyperoval) — so the cell heals without the parent (spec §6.3, V20).
    let mut sim = Sim::new(4);
    let cell = spawn_cell::<F2>(&mut sim, healing_config());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    for &i in &[0usize, 1, 2] {
        sim.crash(cell[i]);
    }
    sim.run_for(Duration::from_millis(3000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    let report = sim.report();
    assert!(
        report
            .verdicts()
            .any(|(_, v)| matches!(v, Verdict::Escalate(_)))
    );
    // A survivor (e.g. node 3) regenerated all three lost shards locally.
    assert!(report.any_repaired(cell[0]));
    assert!(report.any_repaired(cell[1]));
    assert!(report.any_repaired(cell[2]));
}

#[test]
fn a_hyperoval_crash_escalates_to_the_parent() {
    // Four points, no three collinear — the minimal irrecoverable pattern (V20). The cell cannot
    // heal it locally and must escalate.
    let hyperoval = (0u8..=0x7F).find(|&m| is_hyperoval(m)).unwrap();
    let victims: Vec<usize> = (0..7).filter(|i| hyperoval & (1 << i) != 0).collect();

    let mut sim = Sim::new(5);
    let cell = spawn_cell::<F2>(&mut sim, healing_config());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    for &i in &victims {
        sim.crash(cell[i]);
    }
    sim.run_for(Duration::from_millis(3000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    assert!(
        sim.report().any_escalated(),
        "hyperoval must escalate to the parent"
    );
}

/// Local hyperoval predicate (avoids depending on a fanos-code re-export in the test crate).
fn is_hyperoval(mask: u8) -> bool {
    if mask.count_ones() != 4 {
        return false;
    }
    for &line in &fano::INCIDENCE {
        if line & mask == line {
            return false; // three collinear points
        }
    }
    true
}

#[test]
fn sustained_churn_keeps_the_healing_cost_bounded() {
    // A flapping adversary crashes and recovers one node over many cycles, forcing the reflex to heal
    // repeatedly. The `⌊log₉Φ⌋` reroute-depth budget (spec §6.7) bounds each crash's blast radius, so the
    // cumulative healing work is LINEAR in the churn count — a cascade (super-linear reroutes) or an
    // escalation storm would be the DoS-via-healing failure this rules out.
    const CYCLES: u64 = 12;
    let cfg = healing_config();
    let mut sim = Sim::new(0xF1A9);
    let cell = spawn_cell::<F2>(&mut sim, cfg);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    let victim = cell[3];
    for _ in 0..CYCLES {
        sim.crash(victim);
        sim.run_for(Duration::from_millis(2500));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        sim.recover(victim);
        sim.run_for(Duration::from_millis(2500));
    }

    let (reroutes, repairs, escalations) = {
        let m = &sim.report().metrics;
        (m.reroutes, m.repairs, m.escalations)
    };
    // The cost is LINEAR in churn, not a cascade: each crash reroutes only the victim's `N−1` co-linear
    // survivors and repairs its one shard (≈ N−1 each per crash), because the `⌊log₉Φ⌋` reroute-depth
    // budget (spec §6.7) bounds each crash's blast radius. Over CYCLES crashes that is `O(N·CYCLES)`, well
    // below the super-linear reroute count a cascade would produce.
    assert!(
        reroutes <= 10 * CYCLES && repairs <= 10 * CYCLES,
        "healing work is bounded per crash (linear in churn): reroutes={reroutes} repairs={repairs} over {CYCLES} cycles"
    );
    // Escalations are the transient corroboration-disruption of a *fresh* crash — liveness corroboration
    // flows through the same links, so a just-crashed node briefly makes the syndrome over-count until the
    // survivors re-corroborate directly (they are all mutually adjacent in a Fano cell). It self-corrects
    // and is bounded at ≤ 1 per crash: a flapping node cannot trigger an unbounded escalation storm.
    assert!(
        escalations <= CYCLES,
        "escalations are bounded (≤ 1 per crash, transient), not a storm: {escalations} over {CYCLES} cycles"
    );

    // After the churn stops, the cell converges back to health — the flapping left no persistent damage.
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    assert!(
        sim.report().any_verdict(&Verdict::Healthy),
        "the cell converges back to health once the churn stops"
    );
}
