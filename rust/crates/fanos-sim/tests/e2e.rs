//! End-to-end simulator properties: the protocol's networked behaviour under *random* faults.
//!
//! These run the real node engines over the simulated environment and assert emergent
//! properties across randomized seeds and fault choices — the strongest test that the whole
//! stack (liveness → syndrome → verdict) behaves correctly, not just its formulas.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_cmp
)]

use fanos_diakrisis::{Fault, Verdict};
use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Sim, spawn_cell};
use proptest::prelude::*;

fn cfg() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

proptest! {
    // Simulator runs are heavier than pure computation; a few dozen randomized runs is plenty
    // to shake out timing and ordering bugs (and each is deterministic per seed).
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// For *any* crashed node and *any* seed, a surviving node localizes the crash by syndrome.
    #[test]
    fn any_single_crash_is_localized(crash in 0usize..7, seed in any::<u64>()) {
        let mut sim = Sim::new(seed);
        let cell = spawn_cell::<F2>(&mut sim, cfg());
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(2000));
        sim.crash(cell[crash]);
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        prop_assert!(sim.report().any_verdict(&Verdict::Localized(Fault::Single(crash))));
    }

    /// For any two distinct crashed nodes, the 7-theme layer localizes them as that pair.
    #[test]
    fn any_two_crashes_localize_as_the_pair(i in 0usize..7, j in 0usize..7, seed in any::<u64>()) {
        prop_assume!(i != j);
        let (lo, hi) = (i.min(j), i.max(j));
        let mut sim = Sim::new(seed);
        let cell = spawn_cell::<F2>(&mut sim, cfg());
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(2000));
        sim.crash(cell[lo]);
        sim.crash(cell[hi]);
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        prop_assert!(sim.report().any_verdict(&Verdict::Localized(Fault::Pair(lo, hi))));
    }

    /// A healthy cell (no faults) always diagnoses healthy, for any seed.
    #[test]
    fn healthy_cell_is_always_healthy(seed in any::<u64>()) {
        let mut sim = Sim::new(seed);
        let _cell = spawn_cell::<F2>(&mut sim, cfg());
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        let verdicts: Vec<_> = sim.report().verdicts().collect();
        prop_assert_eq!(verdicts.len(), 7);
        prop_assert!(verdicts.iter().all(|(_, v)| **v == Verdict::Healthy));
    }

    /// The determinism contract: the same seed reproduces byte-identical metrics.
    #[test]
    fn same_seed_is_reproducible(seed in any::<u64>(), crash in 0usize..7) {
        let run = |s: u64| {
            let mut sim = Sim::new(s);
            let cell = spawn_cell::<F2>(&mut sim, cfg());
            sim.inject_all(&Command::StartHeartbeat);
            sim.run_for(Duration::from_millis(2000));
            sim.crash(cell[crash]);
            sim.run_for(Duration::from_millis(2000));
            sim.report().metrics.clone()
        };
        prop_assert_eq!(run(seed), run(seed));
    }
}
