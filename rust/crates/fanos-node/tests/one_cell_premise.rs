//! **The cross-cell publishers and cell formation must be fixed together** (#167, and #280 beside it).
//!
//! `crosscell_dir` ships a checkpoint directory, a health directory and a receipt inbox, and no shipped
//! binary calls any of them. That was once because there was nowhere to publish *to*: a deployment had
//! exactly one cell or none, since only `PG(2,2)` formed a cell from the plane itself.
//!
//! **#145 is answered and that half has changed.** `fano::cell_of` is `index mod (N/7)`, a pure function
//! every node computes identically, so any plane whose point count divides by seven now forms cells and
//! `compose_engine` seats a node in its own. `Health::reflexive` follows the same predicate. So a
//! cross-cell publisher *does* have a counterpart on `PG(2,4)`, `PG(2,11)`, `PG(2,16)` and `PG(2,32)`.
//!
//! **What still holds them back is evidence, not addressing**, and this file now watches that instead:
//!
//! * `publish_health` carries **one bare byte** (`alloc_vec(report.block())`) at a `(cell, epoch)` slot,
//!   and `resolve_health` parses it with **no signature, no envelope and no publisher binding** — while
//!   its consumer `diagnose_children` runs the Turyn federated covering and localizes up to three faults
//!   to `(child, axis)`. A covering designed to localize confidently will mislocalize confidently on
//!   forged input. The sibling directories solved exactly this and said why: `telemetry_dir.rs` — *"the
//!   slot key names a coordinate; nothing used to make that name true"* — and `ingressdir.rs`. This slot
//!   is keyed `(cell, epoch)`, so a coordinate-bound ownership rule would not cover it.
//! * `attest_children` calls `ChildRegistry::attest_available`, whose availability mask needs the §L4.3
//!   sampler that **no shipped binary issues** (#173). A caller with none must pass `0`, which refuses
//!   every child — so the loop would run and vouch for nothing.
//!
//! So the obligation is still conditional, and a conditional obligation still needs a tripwire: **if a
//! cross-cell publisher gains a production caller while `publish_health` is unauthenticated, that is the
//! defect** — a federated covering fed forgeable input, which reads exactly like working shared security
//! and carries none.
//!
//! It fails in either direction, which is the point: wiring a publisher fails it, and so does giving
//! `publish_health` an envelope, and both failures are a demand to re-read the design rather than to
//! revert.

#![allow(clippy::expect_used)]

/// The premise, as it is written in the code that decides it.
///
/// A source-text observable rather than a behavioural one, deliberately: no state a running node could be
/// in would report "this directory's record is unauthenticated". The line is the fact.
///
/// It used to be `"reflexive: config.plane_order == 2"` — the claim that only the base plane forms a cell.
/// That claim is now false (#145 is answered by `fano::cell_of`), and its going false is exactly what this
/// tripwire is for: the premise moved rather than vanished, from *"there is no second cell"* to *"a
/// parent would be deciding on unsigned evidence"*.
///
/// **It has to be a line of CODE, not of prose**, and the first attempt at this was a doc paragraph in
/// `crosscell_dir.rs` that the scan could never see: `shipping_sources` runs every file through
/// `fanos_testkit::source::code_only`, which strips comments. So the observable is `resolve_health`'s
/// parse — it reads **exactly one byte** and nothing else, which is precisely what an envelope would have
/// to change.
const CELL_FORMATION_PREMISE: &str = "<[u8; 1]>::try_from(bytes.as_slice())";

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

    let evidence_is_unsigned = sources
        .iter()
        .any(|(path, text)| path.contains("crosscell_dir.rs") && text.contains(CELL_FORMATION_PREMISE));

    assert!(
        evidence_is_unsigned || !callers.is_empty(),
        "`{CELL_FORMATION_PREMISE}` is gone from crosscell_dir.rs, so the health record now carries its own \
         evidence — the reason for leaving every cross-cell publisher unwired (#167) no longer holds. Wire \
         them, and re-read `Census`'s single-cell verdict (#280), which refuses a network reading for the \
         same reason.\n\n\
         The addressing half is already done: `fano::cell_of` answers #145 and `compose_engine` seats a node \
         in its own cell, so a publisher has a counterpart on any plane whose point count divides by seven. \
         What remains before wiring is the availability sampler (#173) — `attest_children` must pass a real \
         mask or `0`, and `0` refuses every child, so the loop would vouch for nothing."
    );
    assert!(
        !evidence_is_unsigned || callers.is_empty(),
        "a cross-cell publisher has a production caller while `{CELL_FORMATION_PREMISE}` still holds, so a \
         parent would run the Turyn federated covering over **unsigned** health records and localize faults \
         to `(child, axis)` from them. A covering designed to localize confidently will mislocalize \
         confidently on forged input, and the deployment will look like it has live shared security. Give \
         `publish_health` an envelope and a publisher binding first, or state here why this caller is \
         exempt.\ncallers:\n  {}",
        callers.join("\n  ")
    );
}
