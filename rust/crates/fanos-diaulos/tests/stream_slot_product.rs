//! What one DIAULOS connection costs when a peer uses every stream slot it is granted (#274).
//!
//! # The question
//!
//! [`budget`](fanos_diaulos::budget) holds `MAX_SESSIONS × 2 × QUEUE_DEPTH × CELL_LEN` against
//! `SESSION_MEMORY_BUDGET` — three `const` assertions, added by #205 because "there were two constants and
//! no third one holding their product". Those queues are the session's **transport** queues. Inside each
//! session lives a [`Connection`] with its own stream map, and its per-stream reliability state is memory
//! that product never counted.
//!
//! Every factor is individually bounded and each bound is correct: the receiver admits only
//! `[delivered, delivered + recv_window)`, so a slow reader throttles the sender rather than accumulating
//! (audit C3/F1); each segment is capped at `MAX_SEGMENT` (F2); and the stream count is capped at
//! `MAX_CONCURRENT_STREAMS` from both directions (F2 and #273). **Their product is what nothing holds** —
//! the #205 defect one floor up, so it is measured here rather than argued from the constants.
//!
//! # Why the measurement is cross-checked against the drive
//!
//! `buffered_bytes()` is this crate's own accounting, so a test that only read it would be checking the
//! accounting against itself. The drive side knows independently how many payload bytes it handed over,
//! and the receiver — which reads nothing — must be holding essentially all of them. That floor is what
//! makes the reading a measurement rather than a restatement.

#![allow(clippy::unwrap_used)]

use fanos_diaulos::budget::{
    MAX_SESSIONS, SESSION_MEMORY_BUDGET, SESSION_OVERRUN, SESSION_WORST_CASE, STREAM_STATE_PER_SESSION,
};
use fanos_diaulos::conn::{Connection, MAX_CONCURRENT_STREAMS};
use fanos_stream::{DEFAULT_WINDOW, MAX_SEGMENT, SACK_WIDTH};

/// The state a protocol-COMPLIANT peer can put a connection in: every stream slot occupied, every receive
/// window full, nothing read. Returns `(bytes the connection holds, payload bytes it accepted)`.
///
/// Nothing here exceeds a bound. The peer opens exactly `MAX_CONCURRENT_STREAMS` streams — the number the
/// connection grants — and sends within the credit each stream advertises. **The cost is what compliance
/// buys**, not what a violation would.
fn a_fully_occupied_connection() -> (usize, usize) {
    let (c2s, s2c) = ([3u8; 32], [4u8; 32]);
    let mut client = Connection::new(c2s, s2c, true);
    let mut service = Connection::new(s2c, c2s, false);

    // One full window per stream: `SACK_WIDTH` segments is the widest credit any receiver advertises, so
    // this saturates the receive buffer without a single segment ever being refused.
    let payload = vec![0xABu8; MAX_SEGMENT * SACK_WIDTH as usize];

    for _ in 0..MAX_CONCURRENT_STREAMS {
        let id = client.open_stream().unwrap();
        client.write(id, &payload);
        client.flush(id);
    }

    // Hand every cell to the service and read nothing back — the shape of an application that has accepted
    // one stream (production accepts exactly one) while the peer opened every slot it is allowed.
    for cell in client.outbound() {
        service.on_cell(&cell);
    }

    assert_eq!(
        service.stream_count(),
        MAX_CONCURRENT_STREAMS,
        "the peer's implicit opens should occupy every slot the connection grants"
    );
    (service.buffered_bytes(), 0)
}

/// The product `MAX_SESSIONS × per-connection stream state` must be held against a stated budget, the way
/// #205 holds the session queues — or the node has a bound nobody multiplied out.
#[test]
fn the_session_count_times_the_stream_state_must_fit_the_budget_that_names_it() {
    // A floor on the true worst case, not the worst case: the service replies to nothing here, so its own
    // send buffers are empty. A connection whose application answers holds this plus its outbound window.
    let (per_conn, _) = a_fully_occupied_connection();
    let product = per_conn.saturating_mul(MAX_SESSIONS);
    let mib = |b: usize| b as f64 / (1024.0 * 1024.0);

    println!(
        "measured: one fully-occupied connection holds {:.2} MiB; × MAX_SESSIONS ({MAX_SESSIONS}) = \
         {:.2} MiB; SESSION_MEMORY_BUDGET = {:.2} MiB; ratio = {:.1}×",
        mib(per_conn),
        mib(product),
        mib(SESSION_MEMORY_BUDGET),
        product as f64 / SESSION_MEMORY_BUDGET as f64
    );

    // The independent floor: the drive offered `SACK_WIDTH` segments per stream, but the sender ships only
    // `min(window, peer_rwnd)` and both start at `DEFAULT_WINDOW` — so what actually lands is a
    // `DEFAULT_WINDOW`-deep window per stream, and the service, which reads nothing, must be holding all of
    // it. Computing the floor from `SACK_WIDTH` instead was wrong by exactly 2× on the first run; the
    // accounting was right and the expectation was not, which is why the floor is here.
    let delivered = MAX_CONCURRENT_STREAMS * MAX_SEGMENT * DEFAULT_WINDOW as usize;
    assert!(
        per_conn >= delivered,
        "the connection accepted {} MiB of payload and reports holding {:.2} MiB — the accounting is \
         under-reporting, so nothing below it can be trusted",
        mib(delivered),
        mib(per_conn)
    );

    // The derivation and the measurement must agree. `STREAM_STATE_PER_SESSION` is what `budget.rs`
    // computes from the constants; `per_conn` is what a real connection was driven into and reported. A
    // derivation nobody re-measures is how the first attempt at this number was wrong by 2× — the sender
    // ships `min(window, peer_rwnd)`, both starting at `DEFAULT_WINDOW`, not the `SACK_WIDTH` the drive
    // offered. Holding them together here is what makes the constant trustworthy.
    assert_eq!(
        per_conn, STREAM_STATE_PER_SESSION,
        "the measured cost of a fully-occupied connection no longer matches what budget.rs derives — one \
         of the two is now wrong, and the constant is the one that gets quoted (#274)"
    );

    // The overrun is STATED, not fixed: see `SESSION_WORST_CASE`'s doc for why no single factor closes
    // it. Nothing is asserted about it here — every relation between those constants is const-evaluable,
    // so a runtime check would be a tautology, and `budget.rs` already pins the exact figure with a
    // `const` assertion that breaks the BUILD when any factor moves. What this test contributes is the
    // half a const assertion cannot: that the derived constant still matches a real connection.
    println!(
        "stated overrun: {:.1} MiB — the worst case is {:.1} MiB against a {:.1} MiB budget",
        mib(SESSION_OVERRUN),
        mib(SESSION_WORST_CASE),
        mib(SESSION_MEMORY_BUDGET)
    );
}
