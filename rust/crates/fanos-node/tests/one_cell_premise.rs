//! **The cross-cell publishers and cell formation must be fixed together** (#167, and #280 beside it).
//!
//! `crosscell_dir` ships a checkpoint directory, a health directory and a receipt inbox, and no shipped
//! binary calls any of them. That is not pending wiring. A FANOS deployment has **exactly one cell, or
//! none**: `Health::reflexive` is `config.plane_order == 2`, because the DIAKRISIS unit is a seven-member
//! cell and only `PG(2,2)` forms one from the plane itself; above that a node discovers peers but nothing
//! tells it which seven are its cell (#145). At `q = 2` the cell *is* the network, so a cross-cell
//! publisher's counterpart is itself; at `q > 2` no cell forms to be one.
//!
//! So the obligation is conditional, and a conditional obligation needs a tripwire, or the condition becomes
//! true and nobody notices. This file holds one: **if a cross-cell publisher gains a production caller while
//! cells still cannot form above `q = 2`, that is the defect** — a publisher wired to an address nobody can
//! be at, which reads exactly like working shared security and carries none.
//!
//! It fails in either direction, which is the point: wiring a publisher fails it, and so does changing how
//! cells form, and both failures are a demand to re-read the design rather than a demand to revert.

#![allow(clippy::expect_used)]

/// The premise, as it is written in the code that decides it.
///
/// A source-text observable rather than a behavioural one, deliberately: the fact is *derived from
/// configuration and nothing at run time can change it* (`Health::reflexive`'s own doc), so there is no
/// state a running node could be in that would report it. The line is the fact.
const CELL_FORMATION_PREMISE: &str = "reflexive: config.plane_order == 2";

/// The entry points that would carry a cell's state to another cell.
const CROSS_CELL_PUBLISHERS: [&str; 5] = [
    "spawn_checkpoint_publisher",
    "spawn_health_publisher",
    "publish_checkpoint",
    "publish_health",
    "publish_receipt",
];

/// Shipping sources across the workspace, with test modules cut away.
fn shipping_sources() -> Vec<(String, String)> {
    let out: Vec<(String, String)> = fanos_testkit::corpus::rust_sources()
        .into_iter()
        .filter(fanos_testkit::corpus::RustSource::is_crate_src)
        .map(|s| (s.rel, fanos_testkit::source::code_only(&s.text)))
        .collect();
    assert!(!out.is_empty(), "the corpus contributed nothing — the filter, not the workspace, is empty");
    out
}

#[test]
fn a_cross_cell_publisher_may_not_be_wired_while_only_one_cell_can_exist() {
    let sources = shipping_sources();

    // The scan asserts itself first. A call scan that cannot see the definitions cannot see the calls
    // either, and it would report "nothing is wired" for the wrong reason — which is the same sentence
    // this file exists to make trustworthy.
    let defined: Vec<&str> = CROSS_CELL_PUBLISHERS
        .iter()
        .copied()
        .filter(|name| sources.iter().any(|(_, text)| text.contains(&format!("fn {name}"))))
        .collect();
    assert_eq!(
        defined.len(),
        CROSS_CELL_PUBLISHERS.len(),
        "the scan cannot see every publisher's definition, so its call count means nothing: found {defined:?}"
    );

    // Callers, from **outside** the modules that define these functions.
    //
    // The exemption is named rather than left implicit, and it is narrow on purpose (a scanner must never
    // quietly excuse itself). `spawn_health_publisher` calls `publish_health`, and
    // `spawn_checkpoint_publisher` calls `publish_checkpoint` — a publisher reaching for its own primitive is
    // the mechanism, not a deployment reaching for the mechanism. What it does NOT excuse is a wiring written
    // inside those same two files; that would pass here and is the one hole in this guard. It is a strange
    // place to wire a node loop from, and the module doc says why nobody should.
    let defining_files: Vec<&String> = sources
        .iter()
        .filter(|(_, text)| CROSS_CELL_PUBLISHERS.iter().any(|n| text.contains(&format!("fn {n}"))))
        .map(|(path, _)| path)
        .collect();
    let mut callers: Vec<String> = Vec::new();
    for (path, text) in &sources {
        if defining_files.contains(&path) {
            continue;
        }
        for (i, line) in text.lines().enumerate() {
            for name in CROSS_CELL_PUBLISHERS {
                if line.contains(&format!("{name}(")) {
                    callers.push(format!("{path}:{} {}", i + 1, line.trim()));
                }
            }
        }
    }
    println!(
        "{} shipping files, {} of them define a cross-cell publisher, {} call one from outside",
        sources.len(),
        defining_files.len(),
        callers.len()
    );

    let one_cell_only =
        sources.iter().any(|(path, text)| path.contains("node.rs") && text.contains(CELL_FORMATION_PREMISE));

    assert!(
        one_cell_only || !callers.is_empty(),
        "`{CELL_FORMATION_PREMISE}` is gone from node.rs, so cells may now form above q=2 — the premise \
         behind leaving every cross-cell publisher unwired (#167) no longer holds. Wire them, and re-read \
         `Census`'s single-cell verdict (#280), which refuses a network reading for the same reason."
    );
    assert!(
        !one_cell_only || callers.is_empty(),
        "a cross-cell publisher has a production caller while `{CELL_FORMATION_PREMISE}` still holds, so \
         there is no second cell for it to reach: it will publish to a slot no cell occupies and the \
         deployment will look like it has live shared security. Close #145 (cell formation above q=2) \
         first, or state here why this caller is exempt.\ncallers:\n  {}",
        callers.join("\n  ")
    );
}
