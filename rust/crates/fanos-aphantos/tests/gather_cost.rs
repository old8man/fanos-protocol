//! **What a share-gather actually costs** — the measurement `DEFAULT_GATHER_TIMEOUT` must be derived from.
//!
//! A combiner gathering a hop sends `TAG_REQ` to the line's other members and waits for `t − 1` `TAG_REP`
//! partials, abandoning the hop at a deadline. That deadline was a chosen constant (2000 ms), and #55 measured
//! what a chosen constant buys: under CPU contention gathers expired at 1 of `t = 2` shares *by the hundreds*,
//! turning a demonstrated censorship-survival property into a run-to-run coin flip.
//!
//! Before choosing a better number — or a better *shape* — the terms have to be named and measured. A gather's
//! wall-clock is
//!
//! ```text
//!   T_gather  =  RTT(combiner ↔ member)          // two direct sends; NOT mix-delayed or cover-slotted
//!              + C_partial                        // ML-KEM decap + Shamir share, per member, CPU-bound
//!              + Q                                // queueing: C_partial × (share requests already queued)
//! ```
//!
//! `RTT` is the transport's and is measured elsewhere; `Q` is load-dependent by definition. What this file pins
//! is **`C_partial`** — the irreducible CPU cost of answering one share request — because it is the unit `Q` is
//! counted in, and therefore the thing that says whether a fixed 2 s deadline is generous or absurd on a given
//! machine. It also pins `C_seal`, the cost of sealing an onion, since a retransmitting client generates share
//! requests at that rate.
//!
//! These are *reported*, not asserted against a threshold: a timing assertion on shared CI hardware is a flake
//! generator. The one assertion made is the ratio the derivation actually needs — see the test body.
//!
//! **The measurement's verdict on the constant, recorded because it is the argument for replacing it.** On one
//! Apple-silicon machine: `C_partial = 47 ms` under `dev` and `1.05 ms` under `release` — a **45x spread from a
//! build flag alone**. The 2 s deadline therefore absorbs ~42 queued share requests per member in the profile
//! the end-to-end tests actually run in, and ~1900 in the shipped one. #55 measured the consequence directly:
//! gathers expiring at 1 of `t = 2` in the hundreds, turning a censorship-survival property into a coin flip.
//! No single number is right across a 45x range — let alone across the hardware a real cell spans — so the
//! deadline cannot be a constant at all. It has to come from what the engine observes, and a completed gather
//! is exactly the sample needed: its wall-clock contains `RTT`, `C_partial` and `Q` together, measured under
//! the load the *next* gather will meet.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Instant;

use fanos_aphantos::threshold_onion::{HopLine, member_partial, seal_onion};
use fanos_field::F2;
use fanos_geometry::{Line, Plane};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};

/// A Fano line's members, as `(secret, public)` KEM pairs in canonical seal order.
fn line_members(seed: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
    let line = Line::<F2>::at(0);
    Plane::<F2>::points_on(line)
        .enumerate()
        .map(|(i, _)| {
            let mut rng = SeedRng::from_seed(&[seed, i as u8]);
            HybridKemSecret::generate(&mut rng)
        })
        .collect()
}

#[test]
fn the_cpu_cost_of_a_share_gather_is_measured_and_reported() {
    // Iteration counts: enough to average out scheduler noise, few enough to stay a test rather than a bench.
    const SEALS: u32 = 40;
    const PARTIALS: u32 = 200;

    let members = line_members(0xC0);
    let publics: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
    let line = Line::<F2>::at(0).coords();
    let hops = [HopLine { line, members: &publics }];
    let t = 2u8;
    // --- C_seal: what a client (or a retransmit) pays to produce one onion. ---
    let mut onion = Vec::new();
    let start = Instant::now();
    for i in 0..SEALS {
        onion = seal_onion(&hops, t, b"gather-cost-probe", &i.to_be_bytes()).unwrap();
    }
    let c_seal = start.elapsed() / SEALS;

    // --- C_partial: what a member pays to answer ONE share request. ---
    let start = Instant::now();
    for _ in 0..PARTIALS {
        let share = member_partial::<F2>(&onion, 1, &members[1].0);
        assert!(share.is_some(), "the probe onion must yield member 1's share");
    }
    let c_partial = start.elapsed() / PARTIALS;

    // How many queued share requests a 2 s deadline can absorb before an honest gather starts expiring —
    // the number that turns "2000 ms" from an opaque constant into a claim about load.
    let budget_2s = 2_000_000u128 / c_partial.as_micros().max(1);

    println!(
        "[gather-cost] C_seal = {c_seal:?} | C_partial = {c_partial:?} | a 2 s deadline absorbs \
         ~{budget_2s} queued share requests per member before honest gathers expire"
    );

    // The assertion the derivation needs, and the only one that is machine-independent: **answering a share
    // request is cheaper than sealing an onion**. That inequality is what makes a gather deadline derivable at
    // all — it says a member can always drain share requests faster than a client can generate the onions that
    // cause them, so the queue `Q` is bounded by the number of concurrent *clients*, not by a race the member
    // loses. If it ever inverts, no deadline can be derived and the design needs admission control on gathers
    // instead; that would be a genuine finding rather than a slow machine.
    assert!(
        c_partial < c_seal,
        "a share answer ({c_partial:?}) must be cheaper than sealing the onion that asks for it \
         ({c_seal:?}) — otherwise members lose the race against clients by construction and the gather \
         deadline cannot be derived from load at all"
    );
}
