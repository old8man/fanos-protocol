//! **Every clock-skew window must be measured against the same clock** — the invariant that cost a defect
//! and two follow-ons to establish, and that nothing else enforces.
//!
//! FANOS has four constants answering one question: *how far behind may an honest party be?* A client and a
//! host derive the meeting line from `(epoch, beacon)` independently, so they turn at different moments, and
//! every component that expires something has to decide what it owes a party that has not turned yet.
//!
//! The onion ratchet is the **binding constraint**, not one voice among four: past its retain window the
//! onion carrying a request cannot be peeled at all, so a longer window anywhere else keeps a path nothing
//! can reach — and where that path is a secret or a route, keeping it is also an exposure. A shorter window
//! anywhere breaks an honest lagging party.
//!
//! The history is the argument for enforcing it. `9d8e611` added host-registration retirement with **no**
//! window at all, making every hidden service unreachable once per `epoch_period` while the host beside it
//! kept three epochs of keys and the ratchet kept one — three components, three different answers, and the
//! symptom would have read as "the service is randomly down". `6b1567b` measured that and derived the grace;
//! `348b892` then derived the key ring, which had been a comfortable guess.
//!
//! Read from source rather than by importing, because three of the four are private to their crate and
//! *should* be — the coupling is a design invariant, not an API. That is the same trade `provisioning.rs`
//! makes for the same reason.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

/// A constant's value, read from its definition in the tree.
fn constant(rel: &str, name: &str) -> u64 {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let text = std::fs::read_to_string(root.join(rel))
        .unwrap_or_else(|e| panic!("{rel} must be readable to check the skew windows: {e}"));
    let needle = format!("const {name}");
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with(&needle) || l.contains(&format!(" {needle}")))
        .unwrap_or_else(|| panic!("{name} is gone from {rel} — the window it bounded still needs one"));
    // `... = <expr>;` — take the first integer literal in the expression, which is what every one of these
    // is, whether written bare or as `1 + OTHER`.
    let (_, rhs) = line.split_once('=').unwrap_or_else(|| panic!("{name} has no value in {rel}"));
    rhs.split(|c: char| !c.is_ascii_digit())
        .find(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{name}'s value in {rel} is not a literal this check can read: {rhs}"))
}

/// The root window: how many past epochs a relay's onion ratchet can still peel.
fn ratchet_retain() -> u64 {
    constant("crates/fanos-pqcrypto/src/onion_ratchet.rs", "DEFAULT_RETAIN")
}

#[test]
fn every_epoch_window_is_measured_against_the_onion_ratchet() {
    let retain = ratchet_retain();
    assert_eq!(
        retain, 1,
        "the ratchet's retain window is the clock every other window is derived from; if it moves, each of \
         the assertions below is measuring against a different system than the one that was reasoned about",
    );

    // A directory slot is read by a client that may be one epoch behind — the same case the ratchet retains
    // a past secret for, on the lookup side rather than the peel side.
    let slots = constant("crates/fanos-node/src/lib.rs", "DIRECTORY_SLOT_EPOCHS");
    assert_eq!(
        slots, retain,
        "DIRECTORY_SLOT_EPOCHS must equal the ratchet's retain window: shorter and a lagging client resolves \
         nothing, longer and the store holds slots no honest reader can use — which is what filled it in a day",
    );

    // A host registration is matched for a client that may be one epoch behind, for the same reason.
    let grace = constant("crates/fanos-node/src/rendezvous_relay.rs", "HOST_GRACE_EPOCHS");
    assert_eq!(
        grace, retain,
        "HOST_GRACE_EPOCHS must equal the ratchet's retain window. At 0 — which it was — every hidden \
         service goes unreachable once per epoch_period and reads as randomly down; above it, a recorded \
         service tag reaches a retired dead-drop for longer than any other component concedes",
    );
}

#[test]
fn the_reply_key_ring_is_expressed_as_the_window_a_combiner_serves() {
    // **Asserted on the expression, not on the number, and that is the stronger check.** A reply key opens a
    // request the COMBINER matched, so its window is the combiner's serve window — the current epoch plus the
    // grace. Writing `= 2` would satisfy any arithmetic check today and silently stop tracking the moment
    // `HOST_GRACE_EPOCHS` moved: the coupling is the invariant, so the coupling is what must be in the code.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let host = std::fs::read_to_string(root.join("crates/fanos-node/src/rendezvous_host.rs")).unwrap();
    let line = host
        .lines()
        .find(|l| l.contains("const MAX_REPLY_KEYS"))
        .expect("MAX_REPLY_KEYS is gone — the window it bounded still needs one");
    assert!(
        line.contains("1 +") && line.contains("HOST_GRACE_EPOCHS"),
        "MAX_REPLY_KEYS must be written as `1 + HOST_GRACE_EPOCHS`, not as the number that happens to equal \
         it: one fewer and a request the combiner legitimately served cannot be opened; one more is a \
         dead-drop secret held past every path that could use it. It was a bare `3` against a grace of 1 — a \
         key that could never open anything, kept in memory. Found at: {line}",
    );
}

/// **The control loop's clock must be the platform's clock** — the same class of invariant as the windows
/// above, and it needs enforcing for the same reason: the two halves live in crates that cannot see each
/// other.
///
/// `fanos-runtime` derives its whole band-keeping loop — the control confidence, the observation window and
/// the shed ceiling — from `HEARTBEATS_PER_EPOCH`, the platform's epoch expressed in that loop's own
/// heartbeats. `DEFAULT_EPOCH_PERIOD` lives in `fanos-node`, one layer **above** the runtime, so the runtime
/// cannot import it and holds the figure as a literal. Nothing but this check stops the two from drifting,
/// and a drift is silent: both sides keep compiling, and the loop simply regulates against a period the
/// network no longer has — a confidence derived for 1200 opportunities per epoch, applied to a network that
/// gives it some other number.
#[test]
fn the_control_loops_epoch_is_the_platforms_epoch() {
    let heartbeat_ms = constant("crates/fanos-runtime/src/overlay/mod.rs", "HEARTBEAT_PERIOD");
    let epoch_secs = constant("crates/fanos-node/src/config.rs", "DEFAULT_EPOCH_PERIOD");
    let claimed = constant("crates/fanos-runtime/src/overlay/mod.rs", "HEARTBEATS_PER_EPOCH");

    assert_eq!(
        epoch_secs * 1000 / heartbeat_ms,
        claimed,
        "HEARTBEATS_PER_EPOCH ({claimed}) must be the {epoch_secs}s epoch divided by the {heartbeat_ms}ms \
         heartbeat — it is the denominator of the loop's derived control confidence, so a stale value is a \
         confidence derived for a network that does not exist",
    );

    // **The self-model must fill inside an epoch.** The observation window is derived from the band's
    // resolution, and the epoch is when the cell reconfigures — coordinates, rosters, roles. A window that
    // took longer than an epoch to fill would leave the node permanently without a self-model, since it
    // would never reach `ready()` before the thing it is modelling changed underneath it. 178 samples at
    // 500 ms is 89 s against a 600 s epoch.
    let window = constant("crates/fanos-runtime/src/overlay/mod.rs", "BEHAVIOR_WINDOW");
    let fill_ms = window * heartbeat_ms;
    assert!(
        fill_ms * 4 <= epoch_secs * 1000,
        "the behavioural window takes {fill_ms}ms to fill against a {epoch_secs}s epoch — a self-model that \
         is not ready for most of an epoch is a self-model the loop never gets to use",
    );
}
