//! **Every frame type this protocol defines is either handled, or declared unhandled with a reason.**
//!
//! Plan item I.2. The motivating defect: `FrameType::Error` was encoded, sent, and had **no receive arm
//! anywhere** — so every rejection this network ever sent arrived somewhere that did not read it. Nothing
//! failed, nothing logged, and it was found by accident while building something else months later.
//!
//! That is the shape of the whole class. A frame type is a promise on the wire, and a promise with no reader is
//! indistinguishable from a working feature until the day it matters. Under a *static* admission difficulty an
//! unread rejection cost only a diagnostic; under an adaptive one it would have been a permanent unexplained
//! refusal of honest joiners.
//!
//! So the classification is made mandatory rather than left to drift. Every variant of [`FrameType`] appears in
//! exactly one of three lists below, and adding a variant without classifying it fails this test.
//!
//! It is a *reachability* check over the source, not a behavioural one: it cannot tell a correct handler from a
//! wrong one. What it can do — and what nothing did before — is refuse to let a frame exist with no handler at
//! all.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use fanos_testkit::corpus::{RustSource, rust_sources};

/// Frames deliberately sent with **no reader**, each with the reason it is sound.
///
/// A short list on purpose. "Fire-and-forget" is a real design, but it is a claim about the protocol that has to
/// be argued, not a default a frame falls into by nobody writing the other half.
const SEND_ONLY: &[(&str, &str)] = &[(
    "HelloAck",
    "Each side computes the same deterministic negotiation from the peer's HELLO, so establishing a session \
     never blocks on reading the ack back — a peer that never sends one cannot wedge us (fanos-quic \
     `send_hello_ack`). Spec §7.3/§7.4 mandates the frame; nothing depends on receiving it.",
)];

/// Wire codes defined and unimplemented. **Empty, and that is the point.**
///
/// It held eleven entries for about an hour. The audit that produced this test found `Goaway`, `Join`,
/// `Bridge`, `StreamOpen`, `StreamData`, `StreamFin`, `PartialDec`, `Cover`, `SvcAnnounce`, `DiagSyndrome` and
/// `DiagVerdict` defined in the registry and referenced nowhere — a third of the table naming a protocol the
/// implementation does not speak. Every one had a working mechanism under another name: diagnosis gossips as
/// `DiagGossip`/`DiagAttest`/`DiagLoss`, streams frame themselves inside an established session, a service
/// announces through the descriptor store, a partial decryption is a CALYPSO method rather than a frame.
///
/// They were deleted rather than documented. A reserved code is not free: the decoder maps attacker-supplied
/// bytes onto a type nothing handles, and every reader of the enum reasonably concludes the capability exists.
/// Deleting them makes those bytes *unknown*, which is the behaviour the framing layer already has for garbage.
///
/// If this list grows again, the entry must say what the code is for and name the decision — see the test
/// below. The intended steady state is empty.
const RESERVED_UNIMPLEMENTED: &[(&str, &str)] = &[];

/// Every `.rs` file under `crates/`, so a handler added anywhere counts — read through the shared corpus,
/// The path of the file that *defines* `FrameType` — excluded when looking for handlers, since the definition
/// and its own decoder mention every variant by construction.
fn definition() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fanos-wire/src/frame.rs")
        .canonicalize()
        .unwrap()
}

/// Every `FrameType` variant, read from the enum itself.
fn variants() -> Vec<String> {
    let text = std::fs::read_to_string(definition()).unwrap();
    let start = text.find("pub enum FrameType").expect("the enum is where this test thinks it is");
    let body = &text[start..];
    let end = body.find("\n}").expect("a closed enum");
    let mut names = Vec::new();
    for line in body[..end].lines() {
        let t = line.trim();
        if let Some(name) = t.split(" = ").next()
            && let Some(first) = name.chars().next()
            && first.is_ascii_uppercase()
            && t.contains(" = 0x")
        {
            names.push(name.to_owned());
        }
    }
    assert!(names.len() > 15, "expected the full frame table, found {}: {names:?}", names.len());
    names
}

/// Whether any file outside the definition *matches on* this variant — i.e. handles it.
///
/// Comment lines are skipped, and that is not a detail: the first version of this check called `HelloAck`
/// handled because a **doc link** — ``[`HelloAck`](crate::frame::FrameType::HelloAck)`` — matched the pattern.
/// A reachability check that counts prose is worse than none, because it reports coverage that does not exist.
fn is_handled(variant: &str, files: &[RustSource]) -> bool {
    let def = definition();
    let arm = format!("FrameType::{variant})");
    let arrow = format!("FrameType::{variant} =>");
    files.iter().filter(|s| s.path != def).any(|s| {
        s.text
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with("//"))
            .any(|line| line.contains(&arm) || line.contains(&arrow))
    })
}

#[test]
fn every_frame_type_is_handled_or_declared_unhandled_with_a_reason() {
    let files = rust_sources();
    let send_only: BTreeSet<&str> = SEND_ONLY.iter().map(|(n, _)| *n).collect();
    let reserved: BTreeSet<&str> = RESERVED_UNIMPLEMENTED.iter().map(|(n, _)| *n).collect();

    let mut unclassified = Vec::new();
    for variant in variants() {
        if send_only.contains(variant.as_str()) || reserved.contains(variant.as_str()) {
            continue;
        }
        if !is_handled(&variant, &files) {
            unclassified.push(variant);
        }
    }
    assert!(
        unclassified.is_empty(),
        "these frame types are sent or defined but handled nowhere, and are not declared: {unclassified:#?}\n\
         Add a receive arm, or list it in SEND_ONLY / RESERVED_UNIMPLEMENTED with the reason. A frame with no \
         reader is indistinguishable from a working feature until the day it matters — which is exactly how \
         `Error` went unhandled for the whole life of the protocol."
    );
}

#[test]
fn the_declared_exceptions_are_still_exceptions() {
    // The reverse direction, and the one that keeps the lists honest: a frame that has *since been given* a
    // handler must come off the exception list, or the list becomes a place where truth goes to rot.
    let files = rust_sources();
    let mut now_handled = Vec::new();
    for (name, _) in SEND_ONLY.iter().chain(RESERVED_UNIMPLEMENTED) {
        if is_handled(name, &files) {
            now_handled.push(*name);
        }
    }
    assert!(
        now_handled.is_empty(),
        "these are declared unhandled but now have a handler: {now_handled:?} — remove them from the list"
    );
}

#[test]
fn every_exception_carries_a_reason_worth_reading() {
    // A one-word excuse is how a list like this stops being a decision and becomes a habit. Each entry must say
    // what the frame is for and — for a reserved code — what the decision to make about it is.
    for (name, reason) in SEND_ONLY.iter().chain(RESERVED_UNIMPLEMENTED) {
        assert!(
            reason.len() > 60,
            "`{name}`'s reason is too short to be a reason: {reason:?}"
        );
    }
    for (name, reason) in RESERVED_UNIMPLEMENTED {
        assert!(
            reason.contains("DECIDE:"),
            "`{name}` is reserved-and-unimplemented but names no decision. A reserved code nobody revisits \
             becomes a permanent lie about what this protocol does."
        );
    }
}
