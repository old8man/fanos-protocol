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
//! * `attest_children` calls `ChildRegistry::attest_available`, whose availability mask needs a §L4.3
//!   sampler nothing issued (#173). A caller with none must pass `0`, which refuses every child — so the
//!   loop would run and vouch for nothing. **Closed**: `sample_child_availability` establishes the mask by
//!   sampling the child cell's own shards, so a parent can now say yes.
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
/// **The premise has moved three times, and each move is the tripwire working rather than failing.**
///
/// 1. `"reflexive: config.plane_order == 2"` — *"there is no second cell"* — until #145 was answered by
///    `fano::cell_of`, which makes cells on any plane whose point count divides by seven.
/// 2. `resolve_health`'s one-byte parse — *"a parent would decide on unsigned evidence"* — until that record
///    gained an `Entitlement` binding it to a member of the cell it speaks for.
/// 3. The availability mask — *"ratification can only say no"* — until `sample_child_availability` built one
///    from the child cell's own shards.
///
/// 4. The committee — *"a parent cannot learn whose keys sit at its child's seven points"* — until
///    `crosscell_dir::publish_seat_key` / `resolve_committee` gave each validator a slot of its own, opened
///    against **that seat's** coordinate. This tripwire fired on the commit that added them, which is what it
///    is for.
///
/// **What is left is agreement, and it is a different shape from all four.** The health slot is keyed
/// `(cell, epoch)` — *one record per cell* — while every input a node has is its own local reading: the
/// `degraded` mask from its own `Notification::Liveness`. Wire seven members to that slot and they race, and
/// whichever wrote last speaks for the cell. The `Entitlement` proves *a member* wrote it and cannot prove
/// the cell agreed, which is the standing rule that no cell-wide decision may be taken on a local input.
///
/// So the premise is now a sentence in `crosscell_dir.rs` recording that gap, and the guard is: **either
/// that sentence is still there, or a cross-cell publisher has a production caller.** Deleting the sentence
/// while leaving the publishers unwired fails, and so does wiring them while the sentence stands — both are
/// a demand to re-read the design.
///
/// The observable stayed a source-text one for the reason at the top: no state a running node could be in
/// reports "the seven writers of this slot do not agree".
///
/// One earlier attempt is worth recording because it corrected the work queue. The premise was once written
/// as *"nothing issues `Command::SampleAvailability`"* on the queue's word that #173 was open, and the scan
/// immediately reported a production issuer — `fanos_quic::Client::sample_availability` exists, and *"no way
/// for anything outside the engine to issue one"* describes the state **before** it.
///
/// **It has to be a line of CODE, not of prose**, and an early attempt at this was a doc paragraph in
/// `crosscell_dir.rs` that the scan could never see: `shipping_sources` runs every file through
/// `fanos_testkit::source::code_only`, which strips comments.
const CELL_FORMATION_PREMISE: &str = "UNWIRED_BECAUSE";

/// The file the premise lives in. Unlike the three premises before it, this one is a *declaration* rather
/// than a use: its presence in this file is the fact, so the guard is about presence here rather than about
/// a construction site somewhere else.
const PREMISE_HOME: &str = "crosscell_dir.rs";

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
                // **`name(` and `name::<`, because a generic publisher is called with a turbofish** and
                // matching only the first spelling made this scan blind to exactly the wiring it guards:
                // `spawn_health_publisher::<F>(client, …)` does not contain `spawn_health_publisher(`.
                // Found by wiring one and watching the tripwire stay green.
                if line.contains(&format!("{name}(")) || line.contains(&format!("{name}::<")) {
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

    // The premise is a declaration now, so its presence in its own file is the fact. The scan still asserts
    // itself — `code_only` strips comments and test modules, and a premise it cannot see would read as
    // "closed" from the start and make the guard vacuous forever — but the check and the fact have collapsed
    // into one, so the guard below is stated as an exclusive or rather than as an implication.
    let blocker_recorded = sources
        .iter()
        .any(|(path, text)| path.contains(PREMISE_HOME) && text.contains(CELL_FORMATION_PREMISE));

    assert!(
        // `==` rather than the `!=` the sentence reads as: "the blocker stands" must equal "there are no
        // callers", which is the same exclusive-or said in the form clippy will accept.
        blocker_recorded == callers.is_empty(),
        "exactly one of these must hold, and right now {} of them does:\n\
         \x20 - `{CELL_FORMATION_PREMISE}` stands in {PREMISE_HOME}: {blocker_recorded}\n\
         \x20 - a cross-cell publisher has a production caller: {}\n\n\
         Deleting the constant while the publishers stay unwired leaves the reason unrecorded; wiring them \
         while it stands ships a cell-wide record written from one node's local reading, with seven members \
         racing for one slot and the `Entitlement` proving only that *a* member wrote it. Either way, \
         re-read the design — and `Census`'s single-cell verdict (#280) with it.\n\n\
         The four earlier reasons are closed: `fano::cell_of` answers #145 and `compose_engine` seats a node \
         in its own cell; the health record carries an `Entitlement` binding it to a member of the cell it \
         speaks for; `sample_child_availability` establishes the availability mask (#173); and \
         `publish_seat_key`/`resolve_committee` let a parent learn whose keys sit at a child's seven points.",
        u8::from(blocker_recorded) + u8::from(!callers.is_empty()),
        !callers.is_empty()
    );
    // The second half of the old guard is now the same statement as the first — an exclusive or says both
    // directions at once — so what remains here is the caller list itself, printed when the guard fails so
    // the failure names *which* wiring to re-read rather than only that some exists.
    assert!(
        callers.is_empty() || !blocker_recorded,
        "callers exist while the blocker stands:\n  {}",
        callers.join("\n  ")
    );
}
