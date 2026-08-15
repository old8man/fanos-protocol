//! **Why the flow-matching metric cannot be transplanted onto the shipping relay — and why the reason on
//! record is the wrong one.**
//!
//! `traffic_analysis.rs` measures the anonymity question properly: among `K` concurrent flows, can a global
//! passive adversary match entries to exits better than chance? It states its own limit — *"this uses
//! `NyxNode` (the **Lite** profile), because `PG(2,7)`'s 57 points give room for several simultaneous flows
//! while the `ThresholdRouter` harness has 7. Running the same metric on the shipping engine is the named
//! follow-up."*
//!
//! That was tried here, in full, and the point count is not what blocks it. Three obstructions were measured,
//! and only the third is fatal:
//!
//! 1. **A line and a point wear the same coordinate.** In `PG(2,q)` both are triples, and the frame tape is
//!    point-addressed, so scoring `to == meeting_line` silently measures receptions at an unrelated *point*.
//!    Measured: entry volumes `[141, 96, 341]` against exit volumes `[220, 40, 123]` — the exit that should
//!    have been largest was not, which is how a wrong observable announces itself. Fixed by summing over
//!    `Plane::points_on(line)`.
//!
//! 2. **The shipping cover schedule makes every rate series the same series.** With the heartbeat and cover
//!    running, the adversary's `3×3` score matrix comes back uniform at `0.985 … 0.999`: every entry
//!    correlates with every exit, because all seven nodes emit at the same constant rate. That is cover
//!    traffic doing exactly its job, and it also means the metric cannot tell a working defence from a blind
//!    instrument — which is why an undefended control has to come first, and why the first run of this
//!    experiment reported `0.333` against a chance of `0.333` at every traffic volume from 1 to 24 sends per
//!    round: a degenerate score matrix, not an anonymity result.
//!
//! 3. **The exit observables cannot be made disjoint, at any `q`.** This is the fatal one and it is geometry,
//!    not harness size. A rendezvous flow terminates on a *meeting line*, so its exit observable is that
//!    line's point set — and in a projective plane **any two distinct lines meet in exactly one point**. Three
//!    flows therefore share three points pairwise, and each frame is counted into several flows' exits at
//!    once: measured `585 + 481 + 425 = 1491` receptions for `578` sends. The adversary's score matrix is
//!    contaminated by construction, and averaging over seeds cannot undo it.
//!
//! The Lite measurement escapes (3) because its flows are **point-to-point** `Command::Send`s, whose exits are
//! single points and genuinely disjoint. The shipping relay cannot be measured that way: `Command::Send`
//! never enters `ThresholdRouter::forward_send` — the trap `composed_relay_gpa.rs` fell into and now asserts
//! against — so a point-to-point flow through this cell is a flow through no defence at all.
//!
//! **So the follow-up needs a different instrument, not a bigger plane.** Either a rendezvous variant that
//! terminates a flow at a point rather than a line, or a matcher that scores overlapping exit sets by
//! attributing each reception to at most one flow — which needs an observable the tape does not carry today.
//! Recorded here so the next attempt starts from the obstruction rather than from the point count.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

use fanos_field::F2;
use fanos_geometry::{Line, Plane, Point, Triple};
use fanos_rendezvous::{BeaconSeed, Epoch, meeting_line};

/// The number of concurrent flows the transplanted metric would need.
const K: usize = 3;

/// **The metric's precondition, and that this engine cannot satisfy it.**
///
/// Pinned as a test rather than left in the note above, for a reason this tree keeps paying for: a blocker
/// written in prose becomes a permanent excuse, while one written as an assertion is re-checked every run.
/// If a future rendezvous terminates flows at points, or the derivation stops producing three distinct
/// lines, this goes red — and going red is the signal that the note above is what needs revisiting.
#[test]
fn a_line_terminated_flow_cannot_have_a_private_exit_observable() {
    // The meeting lines are DERIVED from a service label, not chosen — the same derivation the rendezvous
    // uses — so this asks about lines a real deployment would actually produce.
    let mut meetings: Vec<Triple> = Vec::new();
    for n in 0..4096usize {
        let m = meeting_line::<F2>(format!("svc-{n}").as_bytes(), Epoch::ZERO, &BeaconSeed::GENESIS).coords();
        if !meetings.contains(&m) {
            meetings.push(m);
        }
        if meetings.len() == K {
            break;
        }
    }
    assert_eq!(meetings.len(), K, "the label search must find {K} distinct meeting lines");

    // Entries CAN be made disjoint — three lines leave four points free, one entry each and one spare. Stated
    // as an assertion because it is the half that works: obstruction 3 is about exits specifically, and a
    // reader who took it to mean "seven coordinates are too few" would draw the wrong conclusion again.
    let entries: Vec<Triple> = (0..Plane::<F2>::N as usize)
        .map(|i| Point::<F2>::at(i).coords())
        .filter(|c| !meetings.contains(c))
        .take(K)
        .collect();
    assert_eq!(entries.len(), K, "entries disjoint from the meeting lines must exist — the point count is not the obstruction");

    // Exits cannot. Every pair of distinct meeting lines shares a point, so a reception there belongs to two
    // flows' exit series at once — the contamination measured at 1491 receptions for 578 sends.
    let point_sets: Vec<Vec<Triple>> = meetings
        .iter()
        .map(|&m| {
            let line = Line::<F2>::new(m).expect("a derived meeting line is a line");
            Plane::<F2>::points_on(line).map(|p| p.coords()).collect()
        })
        .collect();
    for i in 0..K {
        for j in (i + 1)..K {
            let shared: Vec<Triple> =
                point_sets[i].iter().copied().filter(|p| point_sets[j].contains(p)).collect();
            assert_eq!(
                shared.len(),
                1,
                "two distinct lines of a projective plane meet in exactly one point — meeting lines {i} and \
                 {j} share {shared:?}, so neither flow can have an exit observable the other does not touch"
            );
        }
    }
}
