//! The session layer's memory budget, and the two bounds derived from it (#205).
//!
//! # The defect this exists to end
//!
//! There were two constants and no third one holding their product. `MAX_SESSIONS = 1024` was derived
//! against **count** — "a client dialing the service is not admission-gated, so without a cap a flood of
//! distinct source coordinates would grow the peer map without bound" (audit A4). `ChannelTransport::CAP =
//! 1024` was derived against **not shedding** — "the depth sits far above a healthy in-flight window, so it
//! never sheds under honest load", which is an argument for the *opposite* of a memory bound. Each was sound
//! about its own concern. Neither doc mentioned the other, and every session opens **two** queues:
//!
//! ```text
//! 1024 sessions × 2 queues × 1024 cells × 1064 B = 2 231 369 728 B = 2.078 GiB
//! ```
//!
//! That is not merely large — the platform states its own number. `fanos_runtime`'s store budget says the
//! node's recommendation is **256 MiB**, of which ~45 MiB is measured resident for everything else, and #118
//! then gave the store 128 MiB of it as deliberate discipline. So one subsystem was fitted into half the
//! node while its neighbour's product exceeded the **whole** node by 8.3×, reachable by an anonymous flood:
//! sessions are explicitly not admission-gated and the queues are bounded-lossy, so "full" is the sustained
//! state under a flood rather than a transient.
//!
//! # Why the obvious repair does not fit, which is the real finding
//!
//! Hold `MAX_SESSIONS = 1024` and solve for the depth at a 64 MiB budget and it comes out at **30** — below
//! the in-flight window the depth exists to clear. Hold the depth at its floor instead and solve for the
//! budget and it comes out at **266 MiB**, more than the entire node recommendation, for the queues alone.
//!
//! **A thousand sessions and a queue above the in-flight window were never simultaneously affordable.** One
//! of them always had to move; nobody had done the division. So the budget is stated, the depth is derived
//! from the protocol, and the session count is whatever the budget then buys — an odd number, because it
//! came from arithmetic rather than from a preference for round ones.

use fanos_stream::SACK_WIDTH;

use crate::cell::CELL_LEN;

/// What the DIAULOS session layer may hold in queued cells, across every session at once.
///
/// **Half of what the store left**, following #118's discipline rather than restating it: the node's
/// recommendation is 256 MiB, `STORE_MEMORY_BUDGET` takes 128 MiB, and taking the whole remainder would put
/// a saturated node exactly at its recommendation — "the largest legal value, not a good one", in that
/// constant's own words. The other half covers the driver, the engine and the consensus paths.
pub const SESSION_MEMORY_BUDGET: usize = fanos_primitives::budget::SESSION_SHARE;

/// How many cells one direction of one session may hold before the queue drops the oldest.
///
/// **The derived floor, not a comfortable number.** A DIAULOS `DATA` cell carries exactly one
/// [`fanos_stream::Segment`] (`MAX_SEGMENT = 1024` inside `CELL_PLAINTEXT = 1040`), so the in-flight window
/// is [`SACK_WIDTH`] cells of data. The queue must hold that window **and** the acknowledgements that retire
/// it — an `ACK` is its own cell — or a full window cannot be buffered while the peer acks it. Hence twice
/// the window, and that is a floor rather than a target.
///
/// Headroom above the floor trades memory for shed-resistance and has **no derivation without a
/// measurement**: how deep a queue must be to absorb a consumer descheduling is a scheduling fact, not a
/// protocol one. It is left at the floor deliberately, so that raising it is a decision someone has to make
/// with evidence rather than a number that drifted upward.
pub const QUEUE_DEPTH: usize = 2 * SACK_WIDTH as usize;

/// How many client sessions one accept loop tracks concurrently.
///
/// **What the budget buys**, at the derived depth: `budget / (2 queues × QUEUE_DEPTH × CELL_LEN)`. It is not
/// a round number and should not be made one — the roundness of `1024` is exactly what let it sit beside a
/// `1024`-deep queue for as long as it did.
///
/// This is also a **cell-wide denominator**: `fanos_node`'s role controller divides the Exit role's measured
/// load by it, so it must stay a protocol bound and never become a node's local configuration. Two nodes
/// computing capacity from different values disagree permanently about how many exits the cell needs.
pub const MAX_SESSIONS: usize = SESSION_MEMORY_BUDGET / (2 * QUEUE_DEPTH * CELL_LEN);

/// The product the two bounds were never checked against, now checked by the compiler.
///
/// This is the assertion whose absence *was* the defect: both constants could be edited independently, and
/// were, and nothing multiplied them. A future change to either that breaks the budget stops the build here
/// rather than shipping a node that can be flooded into eight times its own memory recommendation.
const _: () = assert!(
    MAX_SESSIONS * 2 * QUEUE_DEPTH * CELL_LEN <= SESSION_MEMORY_BUDGET,
    "the session queues' worst case exceeds SESSION_MEMORY_BUDGET — raise the budget deliberately or lower a factor"
);

/// The queue must clear the in-flight window, or it sheds under honest load rather than under attack.
///
/// Stated separately from the product assert because it is the *other* direction: that one stops the bounds
/// growing past the budget, this one stops them shrinking past the protocol. A repair that satisfied only
/// the budget — depth 30 at a thousand sessions — passes the assert above and destroys the property
/// [`QUEUE_DEPTH`]'s doc exists to state.
const _: () = assert!(
    QUEUE_DEPTH >= 2 * SACK_WIDTH as usize,
    "the queue no longer holds one in-flight window plus its acknowledgements"
);

/// [`MAX_SESSIONS`] is the **largest** count the budget buys, not merely a count that fits.
///
/// Without this the two asserts above are satisfied by any small number, and neither says the count was
/// *derived* from the budget rather than picked below it. Written as a `const` assertion for the same reason
/// as its siblings — a runtime test only fails a run, and this class of defect ships between runs.
const _: () = assert!(
    (MAX_SESSIONS + 1) * 2 * QUEUE_DEPTH * CELL_LEN > SESSION_MEMORY_BUDGET,
    "MAX_SESSIONS is below what the budget buys, so it was chosen rather than derived"
);

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers, written out — so a reader can check the arithmetic without running it, and so a change
    /// to any input shows up here as a diff rather than as a silently different bound.
    #[test]
    fn the_derived_bounds_are_what_the_budget_buys() {
        assert_eq!(CELL_LEN, 1064, "cell size feeds both bounds");
        assert_eq!(QUEUE_DEPTH, 128, "two in-flight windows of 64");
        assert_eq!(MAX_SESSIONS, 246, "64 MiB / (2 × 128 × 1064)");
        // The two invariants are `const` assertions above, so they fail the BUILD rather than a run. What is
        // left here is the arithmetic a reader checks by eye.
        let worst = MAX_SESSIONS * 2 * QUEUE_DEPTH * CELL_LEN;
        assert_eq!(worst, 67_006_464, "the worst case, 63.9 MiB of the 64 MiB budget");
    }

    /// What the old pair would cost, kept as a number rather than a memory.
    #[test]
    fn the_bounds_this_replaced_exceeded_the_whole_node_recommendation() {
        let before = 1024 * 2 * 1024 * CELL_LEN;
        assert_eq!(before, 2_231_369_728, "1024 sessions × 2 queues × 1024 cells");
        let node_recommendation = 256 * 1024 * 1024;
        assert!(before > 8 * node_recommendation, "8.3× the whole node, for one subsystem's queues");
        assert!(
            MAX_SESSIONS * 2 * QUEUE_DEPTH * CELL_LEN * 33 < before,
            "and the derived pair is more than thirty times smaller"
        );
    }
}
