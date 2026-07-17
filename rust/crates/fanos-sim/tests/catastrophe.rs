//! Catastrophic-regime tests: the properties the [`catastrophe`](../examples/catastrophe.rs)
//! probe revealed, pinned as regressions. These exercise the *real* node engine under loss,
//! partition, churn, and scale — the cases a live fleet cannot be made to reproduce on demand.
//!
//! The headline is `witness_corroboration_eliminates_false_positives_under_loss`: a weakness the
//! simulator surfaced (per-link timeouts fire spuriously under loss) and the fix that followed —
//! liveness corroborated across a node's `q+1` projective line-witnesses (spec §6.4), so a single
//! lossy link can no longer forge a PeerDown.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_diakrisis::Verdict;
use fanos_field::{F2, F7};
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{NetworkModel, Sim, spawn_cell};

fn established_lossy(seed: u64, loss: f64) -> (Sim, Vec<[u32; 3]>) {
    let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), loss);
    let mut sim = Sim::with_network(seed, net);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    (sim, cell)
}

#[test]
fn witness_corroboration_eliminates_false_positives_under_loss() {
    // A healthy cell (no crash) must NOT declare anyone down, even at 30% link loss — because a
    // peer stays live as long as *any* of its line-witnesses still hears it (spec §6.4).
    let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), 0.30);
    let mut sim = Sim::with_network(0xA11, net);
    let _cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(10_000));
    assert_eq!(
        sim.report().metrics.peer_downs,
        0,
        "no false PeerDown under 30% loss with witness corroboration"
    );
}

#[test]
fn a_true_death_is_still_detected_under_loss() {
    // Corroboration must not mask a real crash: a genuinely dead node lapses from *every* witness,
    // so it is still localized and repaired even under 20% loss.
    let (mut sim, cell) = established_lossy(0xDEAD, 0.20);
    sim.crash(cell[5]);
    sim.run_for(Duration::from_millis(8000)); // allow for loss-delayed gossip
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    let report = sim.report();
    assert!(
        report.any_repaired(cell[5])
            || report.any_verdict(&Verdict::Localized(fanos_diakrisis::Fault::Single(5))),
        "a true death is still detected and healed under loss"
    );
}

#[test]
fn a_partition_escalates_then_heals() {
    // A real cut isolates group B from group A across *all* links, so corroboration correctly
    // still sees B as gone (no witness bridges the cut) → escalate; healing the cut restores it.
    use std::collections::BTreeSet;
    let mut sim = Sim::new(0x9A17);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    let a: BTreeSet<[u32; 3]> = [cell[0], cell[1], cell[2], cell[3]].into_iter().collect();
    let b: BTreeSet<[u32; 3]> = [cell[4], cell[5], cell[6]].into_iter().collect();
    sim.network_mut().partition([a, b]);
    sim.run_for(Duration::from_millis(4000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    assert!(
        sim.report()
            .verdicts()
            .any(|(_, v)| matches!(v, Verdict::Escalate(_))),
        "a partition escalates"
    );

    sim.network_mut().heal();
    sim.run_for(Duration::from_millis(4000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    let last_seven: Vec<_> = sim.report().verdicts().rev().take(7).collect();
    assert!(
        last_seven.iter().all(|(_, v)| **v == Verdict::Healthy),
        "healed partition returns to healthy: {last_seven:?}"
    );
}

#[test]
fn a_churn_storm_converges_to_healthy() {
    // Repeated crash/recover must not leave the cell oscillating: after the storm it settles.
    let mut sim = Sim::new(0x00C0_FFEE);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    for round in 0..8usize {
        let victim = cell[(round * 3 + 1) % 7];
        sim.crash(victim);
        sim.run_for(Duration::from_millis(1500));
        sim.recover(victim);
        sim.inject(victim, Command::StartHeartbeat); // churn rejoin re-bootstraps
        sim.run_for(Duration::from_millis(1500));
    }
    sim.run_for(Duration::from_millis(3000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    let last_seven: Vec<_> = sim.report().verdicts().rev().take(7).collect();
    assert!(
        last_seven.iter().all(|(_, v)| **v == Verdict::Healthy),
        "cell converges after churn: {last_seven:?}"
    );
}

#[test]
fn a_large_cell_establishes_and_rendezvous_delivers() {
    // PG(2,7) is 57 nodes, fully connected at cell scale. Liveness and O(1) rendezvous must hold
    // at that fan-out (the reflexive DIAKRISIS decoder is Fano-scoped and stays a graceful no-op).
    let mut sim = Sim::new(7);
    let cell = spawn_cell::<F7>(&mut sim, Config::default());
    assert_eq!(cell.len(), 57);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(3000));

    let before = sim.report().metrics.payloads_delivered;
    sim.inject(
        cell[0],
        Command::Send {
            to: cell[40],
            payload: b"far".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));
    assert_eq!(
        sim.report().metrics.payloads_delivered,
        before + 1,
        "one-hop rendezvous delivers across a 57-node cell"
    );
    // No node should have been falsely declared down while establishing such a large cell.
    assert_eq!(sim.report().metrics.peer_downs, 0);
}
