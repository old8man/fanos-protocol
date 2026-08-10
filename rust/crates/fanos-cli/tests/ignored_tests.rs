//! **What `#[ignore]` means here, made checkable.** One attribute was carrying two incompatible meanings, and a
//! CI job cannot select on an ambiguity.
//!
//! A *measurement* prints numbers and asserts little or nothing: it exists to be read by a person, and it must
//! **never** gate a release — several deliberately take minutes, and at least one is a knee sweep whose whole
//! output is a table. A *cost-gated assertion* is an ordinary test that happens to be expensive — the OBOLOS
//! zero-knowledge proofs at real parameters, the multi-node real-QUIC end-to-end paths, the randomized
//! no-fork searches — and it must gate **somewhere**, or the property it checks decays unobserved.
//!
//! Both were spelled `#[ignore]`, so "run the ignored tests" could not mean one thing, and the nightly job had
//! to name packages instead of selecting a class. The convention that separates them is the test's own name:
//! a measurement is prefixed `measure_`, `probe_` or `sweep_`. This test holds the workspace to it, so
//! `--ignored --skip measure_ --skip probe_ --skip sweep_` provably selects exactly the assertions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use fanos_testkit::corpus::rust_sources;

/// Name prefixes that mark a test as a measurement rather than an assertion.
const MEASUREMENT_PREFIXES: [&str; 3] = ["measure_", "probe_", "sweep_"];

/// **Retracted metrics: shaped like instruments, kept as counter-examples, and they must never be run as
/// instruments** (#255).
///
/// The third meaning. This file split `#[ignore]` into two — measurement and cost-gated assertion — and the
/// measurement class turns out to hold two different things. Most of its members are live instruments whose
/// numbers a person should read. These two are *retracted*: the metric was found invalid, and the test is
/// kept, `#[ignore]`d and labelled, because a deleted mistake teaches nothing and the next person re-derives
/// it. Both facts live only in free-text `#[ignore]` reasons today, where no selection can see them.
///
/// That matters the moment anything **selects** the class. An executor keyed on the `measure_` prefix — the
/// obvious way to give #255's measurements the job they lack — would run these two and publish their output
/// beside the real readings, which is precisely republishing a retracted number as a measurement. The
/// category read as one thing and contained two, so every consumer of it was wrong for half its members.
///
/// Declared as a list with a reason, in the shape [`COST_GATED`] already uses: adding one is a decision,
/// and the guards below hold the rows to the tree in both directions.
const RETRACTED: &[(&str, &str)] = &[
    (
        "measure_gpa_timing_on_the_shipping_router",
        "a lone flow's in/out rate correlation is high for ANY conserving relay, ideal ones included — the \
         metric measures the physics, not the implementation. The valid experiment is linkability among \
         CONCURRENT flows, which lives beside it.",
    ),
    (
        "measure_the_timing_channel_at_the_shipping_defaults",
        "the same retracted metric at the shipping defaults; it inherits the flaw of the one above.",
    ),
];

/// Cost-gated assertions: expensive, but they check a property and must run somewhere. Listed explicitly so
/// that adding one is a decision — a new `#[ignore]`d test is a measurement by its name or it is here, and the
/// nightly job's selection is meaningful either way.
const COST_GATED: &[&str] = &[
    // OBOLOS zero-knowledge proofs at real parameters (`bits = LOG_BASE = 16`); ~40 s in release, far longer
    // in debug, which is why they are gated rather than run per push.
    "a_correct_nullifier_proves_and_a_wrong_one_is_rejected",
    "a_full_input_spend_proves_and_verifies",
    "a_one_in_one_out_shielded_transfer_proves_and_verifies",
    "a_real_zero_knowledge_transfer_applies_to_the_ledger",
    "a_sound_membership_path_proves_and_verifies",
    "a_spend_proves_membership_and_nullifier_over_one_note",
    "a_well_formed_note_proves_and_a_mismatched_cm_is_rejected",
    // Multi-node real-QUIC end-to-end: reliable in isolation, unreliable when a full-workspace run saturates
    // the loopback transport.
    "connect_to_a_hosted_service_and_echo_over_the_c_abi",
    "host_a_service_and_serve_a_client_over_the_c_abi",
    "the_fabric_seam_carries_real_node_traffic",
    // Randomized no-fork searches: many seeds, so cost scales with the search rather than with one scenario.
    "randomized_scheduling_and_byzantine_faults_never_fork",
    "ssle_randomized_scheduling_and_byzantine_faults_never_fork",
    // Anonymous-path properties over many real-QUIC fixtures (2026-08-03). Each of these is minutes of
    // multi-node dialling, and each `#[ignore]` reason calls itself a "diagnostic sweep" — but their names
    // are property claims and their bodies assert them, so they are assertions that happen to be expensive,
    // not measurements. The distinction is not cosmetic: the first two exist BECAUSE the properties were
    // found violated (a service was reachable or not depending on which node dialled it, and on where the
    // host sat, on a plane whose point-transitivity says neither may matter), and the third is the
    // censorship-survival claim §6 of `docs/design-rendezvous.md` rests on. Left unclassified they would
    // have decayed unobserved, which is the exact failure this file was written to prevent.
    "reachability_does_not_depend_on_which_node_is_the_client",
    "every_legitimate_host_placement_is_reachable",
    "hedging_holds_the_arrival_rate_when_a_meeting_point_is_silent",
];

/// Every `#[ignore]`d test in a file, by the name of the function that follows the attribute.
///
/// Takes the already-read text rather than a path: a read that fails here used to yield an empty string, so
/// the one file this guard could not open contributed zero ignored tests and the guard stayed green about it
/// (#253). [`rust_sources`] does the reading, and refuses to hand over a file it could not open.
fn ignored_in(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if !line.trim_start().starts_with("#[ignore") {
            continue;
        }
        // The function may be preceded by further attributes and, in async tests, by `async`.
        for candidate in lines.clone().take(4) {
            let t = candidate.trim_start();
            let after_async = t.strip_prefix("async ").unwrap_or(t);
            if let Some(rest) = after_async.strip_prefix("fn ")
                && let Some(name) = rest.split(['(', '<']).next()
            {
                names.push(name.to_owned());
                break;
            }
        }
    }
    names
}



/// Every ignored test is a measurement by name, or a declared cost-gated assertion — never neither.
///
/// Failing means a new `#[ignore]`d test appeared and its class is undeclared. Name it `measure_`/`probe_`/
/// `sweep_` if it prints rather than asserts, or add it to [`COST_GATED`] so the nightly job runs it. The
/// third option — leaving it unclassified — is what made "run the ignored tests" meaningless.
#[test]
fn every_ignored_test_declares_whether_it_is_a_measurement_or_a_cost_gated_assertion() {
    let declared: BTreeSet<&str> = COST_GATED.iter().copied().collect();
    let mut found = 0usize;
    let mut unclassified = Vec::new();
    for src in rust_sources() {
        for name in ignored_in(&src.text) {
            found += 1;
            let is_measurement = MEASUREMENT_PREFIXES.iter().any(|p| name.starts_with(p));
            if !is_measurement && !declared.contains(name.as_str()) {
                unclassified.push(format!("{name} ({})", src.rel));
            }
        }
    }
    assert!(found >= 20, "expected to find the workspace's ignored tests, found {found}");
    assert!(
        unclassified.is_empty(),
        "these #[ignore]d tests declare no class: {unclassified:#?}\n\
         Name a measurement `measure_`/`probe_`/`sweep_`, or add a cost-gated assertion to COST_GATED."
    );
}

/// **A retracted metric is declared, still exists, and still says so where a person reads it (#255).**
///
/// Three obligations, because a row that drifts from the tree is worse than no row: it makes the class look
/// classified while the selection it authorises is wrong.
///
/// * the test still exists and is still `#[ignore]`d — otherwise the row governs nothing;
/// * it is named like a measurement, because that is the class this list carves a third meaning out of;
/// * its own `#[ignore]` reason still marks it retracted, so the two places cannot disagree. That last one
///   is what keeps the list from becoming the only witness — a reader who never opens this file must still
///   be told at the test.
#[test]
fn every_retracted_metric_is_declared_and_still_says_so_at_the_test() {
    let sources = rust_sources();
    let ignored: BTreeSet<String> = sources.iter().flat_map(|s| ignored_in(&s.text)).collect();

    for (name, why) in RETRACTED {
        assert!(!why.trim().is_empty(), "`{name}` is declared retracted with no reason, which teaches nothing");
        assert!(
            ignored.contains(*name),
            "RETRACTED names `{name}`, which is no longer an #[ignore]d test — delete the row, or the class              it carves out is describing something that does not exist"
        );
        assert!(
            MEASUREMENT_PREFIXES.iter().any(|p| name.starts_with(p)),
            "`{name}` is declared retracted but is not named like a measurement, so it was never in the              class this list narrows"
        );
        // The reason at the test, not only here — and the first version of this **could not fail**. It asked
        // `sources.iter().any(..)` with a first arm true for every file that does NOT contain the name, which
        // is nearly all of them, so the whole predicate was satisfied by any unrelated file. Removing the
        // marker from the source left it green; that is how it was caught ([[an-alarm-that-cannot-fire]]).
        // The fix is to find THE file and read the attributes that precede THIS function, with no `any` to
        // hide behind and a hard failure if the definition is not found at all.
        let decl = format!("fn {name}(");
        let home = sources
            .iter()
            .find(|s| s.text.contains(&decl))
            .unwrap_or_else(|| panic!("`{name}` is declared retracted and is defined in no file at all"));
        let before = home.text.split(&decl).next().unwrap_or_default();
        let attrs = before.rsplit("\n\n").next().unwrap_or_default();
        assert!(
            attrs.contains("INVALID METRIC"),
            "`{name}` is declared retracted here and its own #[ignore] reason no longer says so — a reader at \
             the test would take its output for a measurement. Attributes found:\n{attrs}"
        );
    }
}

/// Markers that make a diagnostic's output **host-dependent**: it reads a clock and reports what it read.
///
/// Deliberately about the clock rather than about the name. `sweep_timing_correlation_against_the_mix_delay`
/// has "timing" in its name and is not host-dependent at all — it correlates events in the simulator's
/// *virtual* time, so a seeded run gives the same answer on any box. Three of eighteen diagnostics actually
/// read a wall clock, and stamping the other fifteen would teach a reader to skip the line.
const WALL_CLOCK: [&str; 4] = ["Instant::now()", ".elapsed()", "as_micros", "as_secs_f"];

/// **A wall-clock measurement publishes what its number is worth (#255).**
///
/// A µs figure with no host beside it gets quoted, and this tree has been burned twice by exactly that — a
/// viability gauge wrong by 81.7×, and load figures that turned out to be the measurer's own leaked
/// processes. The fix is not `require_quiet_host`, which *declines*: declining is right for a liveness
/// assertion, where a starved box and a defect are indistinguishable, and wrong for a measurement, whose
/// whole job is to produce a number a person reads. What it owes instead is its conditions, printed beside
/// the reading — `fanos_testkit::measurement_conditions`.
///
/// This is what makes an executor for #255 safe to build: the job can publish output that says, per
/// measurement, whether the machine it ran on could support the claim.
#[test]
fn every_wall_clock_measurement_states_the_conditions_it_was_taken_under() {
    let myself = fanos_testkit::corpus::workspace_root().join(file!()).canonicalize().ok();
    let mut checked = 0usize;
    let mut bare = Vec::new();

    for src in rust_sources() {
        if src.path.canonicalize().ok() == myself {
            continue; // this file names the markers in order to look for them
        }
        for (name, body) in measurement_bodies(&src.text) {
            if !WALL_CLOCK.iter().any(|m| body.contains(m)) {
                continue; // host-independent: a correlation or a count over a seeded simulator
            }
            checked += 1;
            if !body.contains("measurement_conditions()") {
                bare.push(format!("{name} ({})", src.rel));
            }
        }
    }

    assert!(checked > 0, "no wall-clock measurement found at all — the marker set has stopped matching");
    assert!(
        bare.is_empty(),
        "these measurements report a wall-clock number and never say what it is worth: {bare:#?}\n\
         Print `fanos_testkit::measurement_conditions()` before the reading. A duration published with no \
         host beside it is quoted as a cost of the code, and on a shared runner it is a cost of the runner."
    );
}

/// Each measurement-named **test** in `text`, with its body — for a rule that has to look at what the test
/// DOES rather than at what it is called.
///
/// **The prefix is a convention about test names, and production code shares the words.** The first version
/// of this dropped the attribute check and immediately reported `sweep_idle_sessions`, a shipping function in
/// `rendezvous_host.rs` that times nothing and prints nothing. `probe_point`, `probe_index_of` and
/// `sweep_expired` are the same shape. Requiring a test attribute above the `fn` is what makes the population
/// the one [`MEASUREMENT_PREFIXES`] is about.
fn measurement_bodies(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for prefix in MEASUREMENT_PREFIXES {
        for (before, chunk) in text.split(&format!("fn {prefix}")).zip(text.split(&format!("fn {prefix}")).skip(1))
        {
            // The attribute block immediately above, and nothing further back than the last blank line.
            let attrs = before.rsplit("\n\n").next().unwrap_or_default();
            if !attrs.contains("#[test") && !attrs.contains("#[tokio::test") {
                continue;
            }
            let Some(name) = chunk.split(['(', '<']).next() else { continue };
            // Brace-matched, so a later function in the same file is not read as part of this one.
            let Some(open) = chunk.find('{') else { continue };
            let mut depth = 0i32;
            let mut end = chunk.len();
            for (i, c) in chunk[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            out.push((format!("{prefix}{name}"), chunk[open..end].to_owned()));
        }
    }
    out
}

/// The reverse direction: every declared cost-gated assertion still exists, and none of them is named like a
/// measurement — otherwise the `--skip` selection would silently drop it.
#[test]
fn the_cost_gated_list_matches_the_tests_that_exist() {
    let mut all = BTreeSet::new();
    for src in rust_sources() {
        all.extend(ignored_in(&src.text));
    }
    for name in COST_GATED {
        assert!(
            all.contains(*name),
            "COST_GATED names `{name}`, which is no longer an #[ignore]d test — delete the row or restore the test"
        );
        // `contains`, not `starts_with` — and the difference is the whole point of this assertion.
        //
        // Two predicates are in play and they are not the same one. **Classification** is by prefix: a
        // measurement is *named* `measure_…`, which is what the check above tests. **Skip safety** is by
        // substring, because `cargo test -- --skip probe_` matches anywhere in a test's path, so a declared
        // assertion called `relay_probe_gate_is_enforced` is silently dropped by the nightly while passing a
        // prefix check clean. This assertion's own message has always said "`--skip` would drop it" — naming
        // the substring rule — while testing the prefix rule one line above it, and `ci.yml` calls the skip
        // set "provably" exact on the strength of it. Empty today; the guard is what keeps it so.
        assert!(
            !MEASUREMENT_PREFIXES.iter().any(|p| name.contains(p)),
            "`{name}` is declared cost-gated but CONTAINS a measurement prefix, so `cargo test --skip` — which \
             matches a substring, not a prefix — would drop it from the nightly with nothing reporting the gap"
        );
    }
}
