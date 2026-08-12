//! `minima` — how few nodes will do, measured against what three derivations predict.
//!
//! Run: `cargo run -p fanos-sim --example minima --release`
//!
//! Three pieces of theory answer this question separately. `fanos_diakrisis::minima` derives in closed form
//! that a cell's robustness ceiling is `r_stab ≤ 1/√N`. `fanos_code::lrc` proves the projective `[7,3,4]` code
//! peels back any `≤3` losses, and fails on four **exactly** when they form a hyperoval. `CellParams::derive`
//! fixes a Byzantine quorum. This sweep runs cells without consulting any of them, so agreement is evidence
//! and disagreement is a bug worth having.
//!
//! ## Two directions, and only one of them has a knee
//!
//! **Growth** — a cell filling up, `k = 1…7`. It reads back a stored value at every size, and that is correct
//! rather than surprising: shard homes are *points of the plane*, so in a small cell every shard lands on one
//! of the few live members and the read reconstructs locally. The erasure floor bounds **shards, not nodes**,
//! and cannot bind while the cell is still filling. What does show a knee here is the cell's own diagnosis,
//! which only reads healthy once the plane is complete.
//!
//! **Attrition** — a full cell that dispersed a value across seven homes and then lost members. This is where
//! the code's tolerance is real, and where the geometry becomes operational: at four losses the outcome
//! depends on *which* four, so the sweep enumerates **every** loss pattern rather than sampling one. A fixed
//! victim order would report one arbitrary draw as the cell's fate — the first version of this file did
//! exactly that, and called a 20%-failure regime a hard floor.
#![allow(clippy::print_stdout, clippy::indexing_slicing, clippy::unwrap_used)]

use fanos_code::lrc::is_hyperoval_fano;
use fanos_diakrisis::Verdict;
use fanos_diakrisis::minima::{MIN_VIABLE_CELL, max_stability_radius};
use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Sim, spawn_partial_cell};

/// How long each phase of a run is given to settle.
const PHASE: Duration = Duration::from_millis(3500);

/// What a `k`-member cell managed to do while growing into place.
struct Row {
    k: usize,
    healthy: usize,
    hits: u64,
    misses: u64,
    losses: u64,
    repairs: u64,
}

/// Grow a cell to `k` members, store a value, read it back from a different member, diagnose.
fn measure_growth(k: usize, seed: u64) -> Row {
    let mut sim = Sim::new(seed);
    let cell = spawn_partial_cell::<F2>(&mut sim, Config::default(), k);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(PHASE);

    let key = b"minima-growth-key".to_vec();
    sim.inject(cell[0], Command::Put { key: key.clone(), value: vec![0xA5u8; 512] });
    sim.run_for(PHASE);
    sim.inject(cell[k - 1], Command::Get { key });
    sim.run_for(PHASE);

    sim.inject_all(&Command::Diagnose);
    sim.settle();

    let report = sim.report();
    let healthy = report.verdicts().rev().take(k).filter(|(_, v)| **v == Verdict::Healthy).count();
    let m = &report.metrics;
    Row {
        k,
        healthy,
        hits: m.retrieval_hits,
        misses: m.retrieval_misses,
        losses: m.data_losses,
        repairs: m.repairs,
    }
}

/// Disperse a value across a full cell, then crash exactly the members in `lost` and read it back.
///
/// Returns whether the read still returned the value. The reader is the highest-indexed survivor, and the
/// value was written by point 0, so any pattern that keeps point 0 alive could in principle be served from the
/// writer — which is why the caller reads the *pattern* result rather than a single number.
fn reads_after_losses(lost: u8, seed: u64) -> bool {
    let mut sim = Sim::new(seed);
    let cell = spawn_partial_cell::<F2>(&mut sim, Config::default(), 7);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(PHASE);

    let key = b"minima-attrition-key".to_vec();
    sim.inject(cell[0], Command::Put { key: key.clone(), value: vec![0x5Au8; 512] });
    sim.run_for(PHASE);

    for (i, point) in cell.iter().enumerate() {
        if lost & (1 << i) != 0 {
            sim.crash(*point);
        }
    }
    sim.run_for(PHASE);

    let Some(reader) = (0..7).rev().find(|i| lost & (1 << i) == 0).map(|i| cell[i]) else {
        return false;
    };
    sim.inject(reader, Command::Get { key });
    sim.run_for(PHASE);
    sim.settle();

    sim.report().metrics.retrieval_hits > 0
}

/// Every 7-bit mask with exactly `bits` bits set.
fn patterns(bits: u32) -> Vec<u8> {
    (0u8..=0x7F).filter(|m| m.count_ones() == bits).collect()
}

fn growth_sweep() -> Vec<Row> {
    println!("== Growth: a cell filling up, one node at a time (median of 5 seeds) ==\n");
    println!("   k  healthy   hits  miss  lost  repairs    1/√k");
    println!("  ──────────────────────────────────────────────────");
    let mut rows = Vec::new();
    for k in 1..=7 {
        let mut runs: Vec<Row> = (0..5).map(|s| measure_growth(k, 0x51E0 + s)).collect();
        runs.sort_by_key(|r| (r.hits, r.healthy));
        let row = runs.remove(2);
        println!(
            "  {:>2}  {:>7}   {:>4}  {:>4}  {:>4}  {:>7}   {:.3}",
            row.k,
            format!("{}/{}", row.healthy, row.k),
            row.hits,
            row.misses,
            row.losses,
            row.repairs,
            max_stability_radius(row.k),
        );
        rows.push(row);
    }
    println!();
    rows
}

/// One row of the attrition sweep. The hyperoval counts are carried, not just printed, because the
/// `[7,3,4]` theorem's claim is an **exactly**, and checking an "exactly" needs both directions.
struct Attrition {
    lost: usize,
    survivors: usize,
    patterns: usize,
    ok: usize,
    failures: usize,
    failed_hyperovals: usize,
    hyperovals: usize,
}

/// For each number of losses, run **every** pattern and report how many still serve the read.
fn attrition_sweep() -> Vec<Attrition> {
    println!("== Attrition: a full cell that dispersed a value, then lost members ==\n");
    println!("  Every loss pattern is run, not sampled — at four losses the outcome depends on which four.\n");
    println!("  lost  survivors   patterns   reads ok   hyperovals among the failures");
    println!("  ────────────────────────────────────────────────────────────────────");
    let mut out = Vec::new();
    for lost_count in 0..=6u32 {
        let masks = patterns(lost_count);
        let mut ok = 0;
        let mut failed_hyperovals = 0;
        let mut failures = 0;
        for (i, &mask) in masks.iter().enumerate() {
            if reads_after_losses(mask, 0x51E0 + i as u64) {
                ok += 1;
            } else {
                failures += 1;
                if is_hyperoval_fano(mask) {
                    failed_hyperovals += 1;
                }
            }
        }
        let survivors = 7 - lost_count as usize;
        println!(
            "  {:>4}  {:>9}   {:>8}   {:>8}   {}",
            lost_count,
            survivors,
            masks.len(),
            ok,
            if failures == 0 {
                "—".to_owned()
            } else {
                format!("{failed_hyperovals} of {failures}")
            }
        );
        out.push(Attrition {
            lost: lost_count as usize,
            survivors,
            patterns: masks.len(),
            ok,
            failures,
            failed_hyperovals,
            hyperovals: masks.iter().filter(|&&m| is_hyperoval_fano(m)).count(),
        });
    }
    println!();
    out
}

fn main() {
    let growth = growth_sweep();
    let attrition = attrition_sweep();

    println!("== Where the knees fall ==\n");
    let all_healthy = growth.iter().find(|r| r.healthy == r.k && r.k >= MIN_VIABLE_CELL).map(|r| r.k);
    let always_reads = attrition.iter().filter(|a| a.patterns == a.ok).map(|a| a.survivors).min();
    let ever_reads = attrition.iter().filter(|a| a.ok > 0).map(|a| a.survivors).min();

    println!("  fewest members whose cell calls itself healthy   : {all_healthy:?}");
    println!("  fewest survivors that ALWAYS serve a read        : {always_reads:?}");
    println!("  fewest survivors that SOMETIMES serve a read     : {ever_reads:?}");
    println!("  coherence floor (the window is non-empty)        : {MIN_VIABLE_CELL}");
    println!(
        "\n  The absolute robustness ceiling falls with the cell: 1/√3 = {:.3} > 1/√7 = {:.3}.",
        max_stability_radius(3),
        max_stability_radius(7)
    );
    println!("  That is NOT 'smaller is sturdier'. Each fault costs less in a bigger cell at the same rate,");
    println!("  so the tolerated FRACTION is 1 − 1/√2 ≈ 29.3% at every size and the absorbed COUNT grows:");
    println!("  2 faults at N=7, 291 at N=993. See fanos_diakrisis::minima result 6.");

    std::process::exit(verdict(&attrition));
}

/// **The disagreement this sweep exists to find, made reportable.**
///
/// The header has always said "agreement is evidence and disagreement is a bug worth having", and until
/// now the sweep printed its numbers and exited 0 whatever they were — a verdict that lived only in a
/// reader's eye, for output nobody read, because no gate ran this. An alarm with no way to sound is not a
/// weaker alarm; it is a decoration that reads as one.
///
/// Checked against `fanos_code::lrc`'s theorem, whose claim is an **exactly** and therefore needs BOTH
/// directions — "every failure is a hyperoval" and "every hyperoval fails" are different statements, and a
/// bug that satisfied one while breaking the other is exactly the kind this sweep is meant to catch.
///
/// Deliberately NOT checked: `CellParams::derive`'s Byzantine quorum. The sweep does not measure it, so
/// there is nothing here to compare a derivation against, and a check with no measurement behind it would
/// be the defect this function was written to remove.
fn verdict(attrition: &[Attrition]) -> i32 {
    let mut disagreements = Vec::new();

    for a in attrition {
        // `[7,3,4]` peels back any three losses. Below four, a failure means the code or the store
        // disagrees with the algebra.
        if a.lost <= 3 && a.ok != a.patterns {
            disagreements.push(format!(
                "at {} losses {} of {} patterns failed to read; the [7,3,4] code peels back any three, so \
                 one of the two is wrong",
                a.lost,
                a.failures,
                a.patterns
            ));
        }
        // At four, the theorem is an EXACTLY: the failures are the hyperovals and nothing else.
        if a.lost == 4 {
            if a.failed_hyperovals != a.failures {
                disagreements.push(format!(
                    "at four losses {} patterns failed but only {} were hyperovals — something that is not \
                     a hyperoval defeated the code",
                    a.failures, a.failed_hyperovals
                ));
            }
            if a.failed_hyperovals != a.hyperovals {
                disagreements.push(format!(
                    "at four losses {} of the {} hyperovals still served the read — the theorem says a \
                     hyperoval always defeats it",
                    a.hyperovals - a.failed_hyperovals,
                    a.hyperovals
                ));
            }
        }
    }

    if disagreements.is_empty() {
        println!("\n  AGREEMENT: every checked prediction of fanos_code::lrc held on every pattern run.");
        return 0;
    }
    println!("\n  DISAGREEMENT — this is the bug this sweep exists to have:");
    for d in &disagreements {
        println!("    * {d}");
    }
    1
}
