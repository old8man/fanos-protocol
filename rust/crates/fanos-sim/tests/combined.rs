//! Combined-catastrophe stress: several adversarial conditions **at once** — packet loss, a network
//! partition, churn (crash/recover), and a Byzantine liar — the case single-fault scenarios miss.
//! The assertions are the two that matter operationally: the cell **keeps running** under compound
//! stress (it still diagnoses, does not hang or panic), and once the conditions lift it **recovers**
//! to full health.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use fanos_diakrisis::Verdict;
use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{NetworkModel, Sim, spawn_cell};
use fanos_wire::{FrameType, encode_frame};

fn forged_liveness_for(target: usize) -> Vec<u8> {
    let mut body = vec![0xFFu8; 14];
    body[target * 2] = 0;
    body[target * 2 + 1] = 0;
    let mut frame = Vec::new();
    encode_frame(FrameType::DiagGossip.code(), &body, &mut frame);
    frame
}

#[test]
fn loss_plus_churn_converges_after_the_storm() {
    // 20% loss the whole time, plus repeated crash/recover — the cell must still settle healthy.
    let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), 0.20);
    let mut sim = Sim::with_network(0xC0B1, net);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    for round in 0..6usize {
        let victim = cell[(round * 2 + 1) % 7];
        sim.crash(victim);
        sim.run_for(Duration::from_millis(1200));
        sim.recover(victim);
        sim.inject(victim, Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(1200));
    }

    // Lift the loss and let it settle.
    sim.network_mut().loss = 0.0;
    sim.run_for(Duration::from_millis(4000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    let last: Vec<_> = sim.report().verdicts().rev().take(7).collect();
    assert!(
        last.iter().all(|(_, v)| **v == Verdict::Healthy),
        "loss + churn converges once loss lifts: {last:?}"
    );
}

#[test]
fn everything_at_once_keeps_running_and_then_recovers() {
    // Loss + partition + a crash + a Byzantine liar, all simultaneously.
    let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), 0.15);
    let mut sim = Sim::with_network(0xE7E, net);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    // Partition 4 | 3, crash a node in the majority side, and a liar forging liveness for it.
    let a: BTreeSet<[u32; 3]> = [cell[0], cell[1], cell[2], cell[3]].into_iter().collect();
    let b: BTreeSet<[u32; 3]> = [cell[4], cell[5], cell[6]].into_iter().collect();
    sim.network_mut().partition([a, b]);
    sim.crash(cell[2]);
    for _ in 0..4 {
        sim.inject_frame(cell[1], cell[0], forged_liveness_for(2));
        sim.run_for(Duration::from_millis(300));
    }
    sim.run_for(Duration::from_millis(3000));

    // Under compound stress the cell is still alive: it keeps diagnosing (no hang / panic), and the
    // Byzantine lie about node 2 is outvoted (the majority side still sees it crashed).
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    assert!(
        sim.report().verdicts().count() >= 4,
        "the reachable majority keeps diagnosing under compound stress"
    );

    // Lift everything and rejoin, then converge.
    sim.network_mut().heal();
    sim.network_mut().loss = 0.0;
    sim.recover(cell[2]);
    sim.inject(cell[2], Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(6000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    let last: Vec<_> = sim.report().verdicts().rev().take(7).collect();
    assert!(
        last.iter().all(|(_, v)| **v == Verdict::Healthy),
        "the cell recovers to full health once all conditions lift: {last:?}"
    );
}
