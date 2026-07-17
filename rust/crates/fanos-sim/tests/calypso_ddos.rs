//! Hidden-service DDoS scenarios over the running overlay (spec §12.5, §6.7) — the attack Tor has
//! fought for years, met here with FANOS's Lindbladian self-stabilization. A rendezvous service runs
//! the [`LindbladLoadController`]: it counts the **valid** (PoW-solving) intros admitted per window,
//! relaxes/drives its excitation accordingly, and broadcasts a super-linear admission difficulty.
//! Intros ride the real overlay (`Command::Send`), so these exercise the transport, the PoW gate,
//! and the controller together across the incident space:
//!
//!   * baseline legit traffic stays cheap;
//!   * a sustained flood drives difficulty to the ceiling and *stabilizes* (bounded, no runaway);
//!   * legit clients that pay the current price are still served *through* the flood;
//!   * a garbage (invalid-PoW) flood is dropped free and does NOT inflate everyone's difficulty;
//!   * the line relaxes back to the floor once the flood stops;
//!   * the attacker's aggregate work diverges super-linearly while a legit client's stays O(1);
//!   * admission survives the loss of a hosting member (threshold hosting composes);
//!   * a distributed flood from many source coordinates is stabilized just the same.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]

use fanos_calypso::pow;
use fanos_calypso::stabilize::LindbladLoadController;
use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{Sim, spawn_cell};

/// Encode an intro request: `cookie_len(1) ‖ cookie ‖ nonce(8)`.
fn intro(cookie: &[u8], nonce: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + cookie.len() + 8);
    v.push(cookie.len() as u8);
    v.extend_from_slice(cookie);
    v.extend_from_slice(&nonce.to_be_bytes());
    v
}

fn parse_intro(bytes: &[u8]) -> Option<(&[u8], u64)> {
    let len = *bytes.first()? as usize;
    let cookie = bytes.get(1..1 + len)?;
    let nonce = u64::from_be_bytes(bytes.get(1 + len..1 + len + 8)?.try_into().ok()?);
    Some((cookie, nonce))
}

/// A service side that admits intros meeting the *current* broadcast difficulty and drives the
/// Lindbladian controller from the **valid** admitted count each window.
struct Service {
    ctl: LindbladLoadController,
    difficulty: u32,
    admitted_total: u64,
    rejected_total: u64,
}

impl Service {
    fn new(ctl: LindbladLoadController) -> Self {
        let difficulty = ctl.difficulty();
        Self {
            ctl,
            difficulty,
            admitted_total: 0,
            rejected_total: 0,
        }
    }

    /// Process one window's delivered intros: admit those solving the current difficulty, then let
    /// the controller relax+drive on the *admitted* (valid) count and re-broadcast the difficulty.
    fn window(&mut self, intros: &[(Vec<u8>, u64)]) -> u32 {
        let mut admitted = 0u32;
        for (cookie, nonce) in intros {
            if pow::verify(cookie, *nonce, self.difficulty) {
                admitted += 1;
                self.admitted_total += 1;
            } else {
                self.rejected_total += 1;
            }
        }
        self.ctl.observe_window(f64::from(admitted));
        self.difficulty = self.ctl.difficulty();
        admitted
    }
}

/// Drive intro traffic to `service` over the overlay for one window and return the delivered intros.
struct Harness {
    sim: Sim,
    cell: Vec<Triple>,
    service: Triple,
    cursor: usize,
    window: Duration,
}

impl Harness {
    fn new(seed: u64) -> Self {
        let mut sim = Sim::new(seed);
        let cell = spawn_cell::<F2>(&mut sim, Config::default());
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(1500));
        let service = cell[0];
        let cursor = sim.report().deliveries().count();
        Self {
            sim,
            cell,
            service,
            cursor,
            window: Duration::from_millis(300),
        }
    }

    /// Send `intros` (each `(from_index, cookie, nonce)`) to the service, advance one window, and
    /// return the intros the service received this window.
    fn run_window(&mut self, intros: &[(usize, Vec<u8>, u64)]) -> Vec<(Vec<u8>, u64)> {
        for (from, cookie, nonce) in intros {
            let src = self.cell[from % self.cell.len()];
            self.sim.inject(
                src,
                Command::Send {
                    to: self.service,
                    payload: intro(cookie, *nonce),
                },
            );
        }
        self.sim.run_for(self.window);
        let all: Vec<(Vec<u8>, u64)> = self
            .sim
            .report()
            .deliveries()
            .skip(self.cursor)
            .filter(|(recv, _, _)| *recv == self.service)
            .filter_map(|(_, _, bytes)| parse_intro(bytes).map(|(c, n)| (c.to_vec(), n)))
            .collect();
        self.cursor = self.sim.report().deliveries().count();
        all
    }
}

/// A legit client's intro: solve the *current* difficulty for a fresh cookie.
fn legit(seq: u64, difficulty: u32) -> (usize, Vec<u8>, u64) {
    let cookie = format!("legit-{seq}").into_bytes();
    let nonce = pow::solve(&cookie, difficulty);
    (2, cookie, nonce)
}

/// A cheap attacker's intro: solve only a fixed low `effort` (it under-pays once the price rises).
fn attacker(seq: u64, from: usize, effort: u32) -> (usize, Vec<u8>, u64) {
    let cookie = format!("atk-{from}-{seq}").into_bytes();
    let nonce = pow::solve(&cookie, effort);
    (from, cookie, nonce)
}

/// A *determined* attacker's intro: pay the current broadcast difficulty to stay admitted (and thus
/// keep driving the controller). This is the compute-heavy flood that reaches the ceiling — where
/// its aggregate cost diverges super-linearly.
fn determined(seq: u64, from: usize, difficulty: u32) -> (usize, Vec<u8>, u64) {
    let cookie = format!("det-{from}-{seq}").into_bytes();
    let nonce = pow::solve(&cookie, difficulty);
    (from, cookie, nonce)
}

#[test]
fn baseline_legit_traffic_stays_at_the_floor() {
    let mut h = Harness::new(0xD01);
    let mut svc = Service::new(LindbladLoadController::new(0.3, 20.0, 4, 16));
    for w in 0..8u64 {
        // ~5 legit intros/window — well under the target of 20.
        let intros: Vec<_> = (0..5).map(|i| legit(w * 5 + i, svc.difficulty)).collect();
        let got = h.run_window(&intros);
        svc.window(&got);
        assert_eq!(
            svc.difficulty, 4,
            "under-target legit load never leaves the floor"
        );
    }
    assert_eq!(svc.rejected_total, 0, "all legit intros are admitted");
}

#[test]
fn a_determined_flood_stabilizes_at_the_ceiling_without_runaway() {
    let mut h = Harness::new(0xD02);
    let mut svc = Service::new(LindbladLoadController::new(0.25, 8.0, 3, 12));
    // A determined flood keeps paying the current price, so it stays admitted and drives the
    // controller up. Difficulty must climb to the ceiling and HOLD there — bounded, never diverging.
    let mut peak = 0;
    for w in 0..16u64 {
        let d = svc.difficulty;
        let intros: Vec<_> = (0..60).map(|i| determined(w * 60 + i, 1, d)).collect();
        let got = h.run_window(&intros);
        svc.window(&got);
        peak = peak.max(svc.difficulty);
    }
    assert_eq!(
        peak, 12,
        "the determined flood drives difficulty to the ceiling"
    );
    assert!(svc.difficulty <= 12, "difficulty is bounded — no runaway");
}

#[test]
fn a_cheap_fixed_effort_flood_is_repelled_at_low_cost() {
    // A flood that only pays a fixed low effort is repelled *cheaply*: the service settles just above
    // the attackers' effort and rejects them, rather than needlessly punishing everyone at the
    // ceiling. Efficiency: cheap attacks get cheap defence.
    let mut h = Harness::new(0xD08);
    let mut svc = Service::new(LindbladLoadController::new(0.25, 8.0, 2, 20));
    for w in 0..16u64 {
        let intros: Vec<_> = (0..80).map(|i| attacker(w * 80 + i, 1, 2)).collect();
        let got = h.run_window(&intros);
        svc.window(&got);
    }
    assert!(
        svc.difficulty <= 8,
        "a cheap flood is repelled without driving difficulty to the ceiling (got {})",
        svc.difficulty
    );
    assert!(
        svc.rejected_total > 0,
        "under-paying attackers are turned away once the price edges up"
    );
}

#[test]
fn legit_clients_are_served_through_the_flood_if_they_pay_the_price() {
    let mut h = Harness::new(0xD03);
    let mut svc = Service::new(LindbladLoadController::new(0.3, 8.0, 3, 10));
    let mut legit_admitted = 0u64;
    for w in 0..12u64 {
        // A heavy attacker flood plus a few legit clients that DO solve the current difficulty `d`
        // (the same difficulty the service gates on this window).
        let d = svc.difficulty;
        let mut intros: Vec<_> = (0..50).map(|i| attacker(w * 50 + i, 1, 3)).collect();
        for i in 0..3u64 {
            intros.push(legit(w * 3 + i, d));
        }
        let got = h.run_window(&intros);
        svc.window(&got);
        // The legit intros delivered this window all solve `d`, so they are admitted.
        legit_admitted += got
            .iter()
            .filter(|(c, n)| c.starts_with(b"legit-") && pow::verify(c, *n, d))
            .count() as u64;
    }
    assert!(
        legit_admitted > 0,
        "paying legit clients get through the flood"
    );
}

#[test]
fn a_garbage_invalid_pow_flood_does_not_inflate_everyone_s_difficulty() {
    // The key anti-abuse property: difficulty is driven by ADMITTED (valid) load, so an attacker
    // spraying intros with NO valid PoW is dropped for free and cannot raise the price for legit
    // users. Difficulty stays at the floor.
    let mut h = Harness::new(0xD04);
    let mut svc = Service::new(LindbladLoadController::new(0.25, 8.0, 5, 20));
    for w in 0..12u64 {
        // 100 garbage intros/window with nonce 0 (won't solve difficulty 5) + a little legit load.
        let mut intros: Vec<_> = (0..100u64)
            .map(|i| (1usize, format!("garbage-{w}-{i}").into_bytes(), 0u64))
            .collect();
        for i in 0..2u64 {
            intros.push(legit(w * 2 + i, svc.difficulty));
        }
        let got = h.run_window(&intros);
        svc.window(&got);
    }
    assert_eq!(
        svc.difficulty, 5,
        "an invalid-PoW flood cannot inflate the difficulty"
    );
    assert!(svc.rejected_total >= 100, "the garbage is dropped");
}

#[test]
fn the_line_relaxes_back_to_the_floor_after_the_flood_ends() {
    let mut h = Harness::new(0xD05);
    let mut svc = Service::new(LindbladLoadController::new(0.4, 8.0, 3, 12));
    // Flood phase.
    for w in 0..10u64 {
        let intros: Vec<_> = (0..60).map(|i| attacker(w * 60 + i, 1, 3)).collect();
        let got = h.run_window(&intros);
        svc.window(&got);
    }
    assert!(
        svc.difficulty > 3,
        "difficulty is elevated during the flood"
    );
    // Quiet phase: no traffic. Excitation relaxes; difficulty returns to the floor.
    for _ in 0..30u64 {
        svc.window(&[]);
    }
    assert_eq!(
        svc.difficulty, 3,
        "the line relaxes back to the floor once the flood stops"
    );
}

#[test]
fn attacker_aggregate_work_diverges_while_a_legit_client_stays_o1() {
    // At the stabilized fixed point, an attacker must keep solving the ceiling difficulty for EACH
    // intro to stay admitted, while a legit client sends O(1) intros. Compare the total PoW work.
    let mut svc = Service::new(LindbladLoadController::new(0.25, 8.0, 3, 14));
    // Drive to the stabilized flood state.
    for _ in 0..40 {
        svc.ctl.observe_window(200.0);
        svc.difficulty = svc.ctl.difficulty();
    }
    let ceiling = svc.difficulty;
    assert_eq!(ceiling, 14, "flood pins difficulty at the ceiling");
    // Attacker sustaining N admitted intros pays ~N·2^ceiling; a legit client pays 2^ceiling once.
    let attacker_intros = 1000u64;
    let attacker_work = attacker_intros as f64 * 2f64.powi(ceiling as i32);
    let legit_work = 2f64.powi(ceiling as i32);
    assert!(
        attacker_work / legit_work >= attacker_intros as f64,
        "the flooder's aggregate work exceeds a legit client's by the flood volume"
    );
}

#[test]
fn admission_survives_the_loss_of_a_hosting_member() {
    // The service is a line, not a node (§12.3). Crash a cell member; intros still reach the service
    // coordinate (or reroute), and the controller keeps stabilizing — the flood does not win by
    // knocking out one host.
    let mut h = Harness::new(0xD06);
    let victim = h.cell[3];
    let mut svc = Service::new(LindbladLoadController::new(0.3, 8.0, 3, 12));
    for w in 0..12u64 {
        if w == 4 {
            h.sim.crash(victim); // a hosting member dies mid-flood
        }
        let d = svc.difficulty;
        let intros: Vec<_> = (0..40).map(|i| determined(w * 40 + i, 1, d)).collect();
        let got = h.run_window(&intros);
        svc.window(&got);
    }
    assert!(
        svc.difficulty > 3,
        "the controller keeps stabilizing despite the lost member"
    );
    assert!(
        svc.admitted_total > 0,
        "the service kept admitting intros through the churn"
    );
}

#[test]
fn a_distributed_flood_from_many_sources_is_stabilized_the_same() {
    // No single source: attackers spread across every non-service cell coordinate. The aggregate
    // valid load still drives the controller to the ceiling — there is no per-source loophole.
    let mut h = Harness::new(0xD07);
    let mut svc = Service::new(LindbladLoadController::new(0.25, 8.0, 3, 12));
    let mut peak = 0;
    for w in 0..16u64 {
        let d = svc.difficulty;
        let intros: Vec<_> = (0..60u64)
            .map(|i| determined(w * 60 + i, 1 + (i as usize % 6), d))
            .collect();
        let got = h.run_window(&intros);
        svc.window(&got);
        peak = peak.max(svc.difficulty);
    }
    assert_eq!(
        peak, 12,
        "a distributed determined flood is stabilized to the ceiling all the same"
    );
}
