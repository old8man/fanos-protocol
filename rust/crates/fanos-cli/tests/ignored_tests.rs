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
use std::path::{Path, PathBuf};

/// Name prefixes that mark a test as a measurement rather than an assertion.
const MEASUREMENT_PREFIXES: [&str; 3] = ["measure_", "probe_", "sweep_"];

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
];

/// Every `#[ignore]`d test in a file, by the name of the function that follows the attribute.
fn ignored_in(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
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

/// Every `.rs` file under `crates/`, so a test added anywhere is covered.
fn sources() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let mut out = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "target") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out
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
    for path in sources() {
        for name in ignored_in(&path) {
            found += 1;
            let is_measurement = MEASUREMENT_PREFIXES.iter().any(|p| name.starts_with(p));
            if !is_measurement && !declared.contains(name.as_str()) {
                unclassified.push(format!("{name} ({})", path.display()));
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

/// The reverse direction: every declared cost-gated assertion still exists, and none of them is named like a
/// measurement — otherwise the `--skip` selection would silently drop it.
#[test]
fn the_cost_gated_list_matches_the_tests_that_exist() {
    let mut all = BTreeSet::new();
    for path in sources() {
        all.extend(ignored_in(&path));
    }
    for name in COST_GATED {
        assert!(
            all.contains(*name),
            "COST_GATED names `{name}`, which is no longer an #[ignore]d test — delete the row or restore the test"
        );
        assert!(
            !MEASUREMENT_PREFIXES.iter().any(|p| name.starts_with(p)),
            "`{name}` is declared cost-gated but named like a measurement, so `--skip` would drop it"
        );
    }
}
