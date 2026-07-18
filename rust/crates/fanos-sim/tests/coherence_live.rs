//! The coherence homeostat on the **live engine**, in the simulator — the #74 capstone.
//!
//! `coherence_ddos.rs` validated the *mathematics* (load balancing raises the cell's mean coherence)
//! against the observatory's abstract signal model. This validates the *running organism*: a real routed
//! flood, delivered through the simulator's transport to a real [`OverlayNode`], drives that node's
//! behavioural coherence **self-model** (`BehaviorMonitor` → `Γ_net`) into the over-coupled regime, and
//! its live homeostat sheds correlation (`Decouple`). This is the Conant–Ashby *good regulator* closed on
//! the engine: every good regulator of a system must contain a model of that system, and here the node
//! regulates against its own measured coherence, not a proxy — the simulator is the network's up-to-date
//! model of itself (`docs/ddos-homeostasis.md §2`, `docs/coherent-cybernetics.md`).
//!
//! The experiment is **controlled** and falsifiable: the trigger is *correlation structure*, not *load*.
//! The attack (common-mode flood) and the control (a decorrelated flood of the **same total relay
//! volume**) differ only in whether the peers move in lockstep, so a shed in the first but not the second
//! isolates over-coupling — not mere traffic — as the cause.

// Fixed-size cell indexing reads clearest here; no fallible unwraps in the harness.
#![allow(clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{Sim, spawn_cell};
use fanos_wire::{FrameType, encode_frame};

/// One `Route` data-relay frame — the behavioural load signal the coherence self-model senses (control
/// chatter such as pings/gossip is excluded, so only these move `Γ_net`).
fn route_frame() -> Vec<u8> {
    let mut f = Vec::new();
    encode_frame(FrameType::Route.code(), b"x", &mut f);
    f
}

fn homeostasis_config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

/// Number of heartbeat windows of flood to drive — a full behavioural window (`BEHAVIOR_WINDOW = 8`) plus
/// slack, so the monitor's rolling window is entirely flood samples when the homeostat reads it.
const FLOOD_WINDOWS: usize = 12;

/// How many `Route` relays the victim actually received (from the report's delivery notifications) — used
/// to prove the control's negative is *not* vacuous: the same substantial volume arrives in both cases,
/// so a shed in one but not the other is about structure, not delivery.
fn routes_delivered_to(sim: &Sim, victim: Triple) -> usize {
    sim.report()
        .deliveries()
        .filter(|(receiver, _, _)| *receiver == victim)
        .count()
}

/// Drive `FLOOD_WINDOWS` heartbeat windows of routed flood into `victim_idx`, where `bursts(w, peer)`
/// gives how many `Route` frames Fano peer `peer` relays to the victim in window `w`. Then diagnose the
/// victim and return the settled `Sim` for the caller to inspect. Every peer's frames for a window are
/// injected together, so — whatever the per-window sampling phase — they land as one common event, which
/// is exactly what makes the lockstep case common-mode and the independent case decorrelated.
fn run_flood(seed: u64, victim_idx: usize, bursts: impl Fn(usize, usize) -> u32) -> (Sim, Triple) {
    let mut sim = Sim::new(seed);
    let cell = spawn_cell::<F2>(&mut sim, homeostasis_config());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1000)); // settle to steady state (no Route traffic yet)

    let victim = cell[victim_idx];
    for w in 0..FLOOD_WINDOWS {
        for (peer_idx, &peer) in cell.iter().enumerate() {
            if peer_idx == victim_idx {
                continue;
            }
            for _ in 0..bursts(w, peer_idx) {
                sim.inject_frame(peer, victim, route_frame());
            }
        }
        // Advance exactly one heartbeat window: the delivered relays accumulate into the victim's
        // activity map, then its heartbeat folds this window's per-peer sample into the coherence monitor.
        sim.run_for(Duration::from_millis(500));
    }
    sim.inject(victim, Command::Diagnose);
    sim.settle();
    (sim, victim)
}

#[test]
fn a_common_mode_routed_flood_drives_the_live_homeostat_to_decouple() {
    // Attack: every peer relays the SAME lockstep-varying amount each window, so the victim's per-peer
    // activity slots move together — pairwise correlation in the over-coupled band (r > 1/√3). The live
    // homeostat, running on the measured Γ_net, sheds correlation.
    let (sim, victim) = run_flood(1, 0, |w, _peer| (w as u32 % 3) + 1);
    // The flood genuinely reached the victim (mean 2 bursts × 6 peers × 12 windows ≈ 144 relays), so the
    // shed below is a response to real over-coupling, not an artefact of an empty monitor.
    assert!(
        routes_delivered_to(&sim, victim) >= 60,
        "the routed flood is actually delivered to the victim"
    );
    assert!(
        sim.report().decouples().any(|n| n == victim),
        "the flooded node's live homeostat sheds correlation under common-mode over-coupling"
    );
}

#[test]
fn a_decorrelated_flood_of_equal_volume_does_not_decouple() {
    // Control: the SAME expected total relay volume (mean 2 bursts/peer/window), but each peer's burst
    // count is INDEPENDENT across peers and windows — no common-mode structure. Load is identical to the
    // attack; correlation is absent — so the homeostat must NOT shed. This isolates the trigger as
    // over-coupling rather than traffic volume. (The hash mixes window and peer with distinct odd
    // multipliers, giving a per-(window,peer) value in {1,2,3}, mean 2 — matching the lockstep mean.)
    let bursts = |w: usize, peer: usize| -> u32 {
        let h = (w as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ (peer as u64).wrapping_mul(0xD1B5_4A32_D192_ED03);
        ((h >> 29) % 3) as u32 + 1
    };
    let (sim, victim) = run_flood(2, 0, bursts);
    // Non-vacuity: the control delivers a comparable volume to the attack — the difference is structure,
    // not traffic. (Same mean-2 bursts × 6 peers × 12 windows.)
    assert!(
        routes_delivered_to(&sim, victim) >= 60,
        "the control flood is actually delivered (its negative result is meaningful, not vacuous)"
    );
    assert!(
        !sim.report().any_decoupled(),
        "a decorrelated flood of equal volume does not trigger a spurious shed (load ≠ over-coupling)"
    );
}
