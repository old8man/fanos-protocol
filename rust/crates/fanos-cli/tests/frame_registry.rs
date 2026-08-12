//! **The spec's frame table is the registry, so it is checked against the registry.**
//!
//! `spec/protocol.md` §7.2 tabulates the wire frame types by dispatch group. On 2026-07-29 the
//! implementation deleted eleven of them (`6415f26`) as codes it never spoke — each had a working mechanism
//! under a different name, and a reserved code is not neutral, because the decoder maps attacker-supplied
//! bytes onto a type nothing handles while every reader of the registry reasonably concludes the capability
//! exists.
//!
//! The spec table was not updated. Neither was `conformance/vectors/wire.json`, which asserts the registry
//! from the outside — and that vector **had been failing for six days**, unnoticed, because `cargo test`
//! stops at the first failing target and a live-QUIC flake came first in the ordering. Two independent
//! records of the same registry, both stale, one of them mechanically checkable and red the whole time.
//!
//! So this file closes the loop the deletion left open: the spec's own table must name exactly the types
//! `fanos_wire::FrameType` implements. It reads the spec rather than the vectors deliberately — the vectors
//! are already checked by `fanos-wire/tests/wire_kat.rs`, and the thing that had no check at all was the
//! prose an implementer reads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

/// **One wire type, one codec.** The `ERROR` frame had two: `fanos-wire`'s `encode_error` (spec §7.5, a
/// varint code then the reason — the one the conformance vector pins and `fanos-quic`'s handshake sends) and
/// a local `ErrorBody` in `fanos-runtime` deriving `Wire`, whose `u64` is a fixed 8-byte big-endian integer
/// and whose `Vec<u8>` is length-prefixed. They are not the same bytes. A handshake `ERROR` reaching the
/// overlay's receive arm therefore failed to parse and was dropped in silence — the same defect class as the
/// receive arm that was missing entirely, one layer along.
///
/// It survived because only one of the two was verified: `wire_kat.rs` checks the wire codec, nothing
/// checked the runtime one, and the divergence is invisible to a gate that only sees the tested half. Both
/// the encoder and the decoder now live in `fanos-wire`; this fails if a second definition appears.
#[test]
fn the_error_frame_has_exactly_one_codec() {
    let runtime = std::fs::read_to_string(repo_root().join("rust/crates/fanos-runtime/src/frames.rs")).unwrap();
    assert!(
        !runtime.contains("struct ErrorBody"),
        "`fanos-runtime` defines its own ERROR body again. Spec §7.5's encoding is `varint(code) || reason` \
         and `fanos_wire::error::{{encode_error, decode_error}}` implement it; a second definition means two \
         encodings for one frame type, and only the wire one is in `conformance/vectors/wire.json`."
    );
    for (rel, what) in [
        ("rust/crates/fanos-runtime/src/frames.rs", "the overlay's producer and parser"),
        ("rust/crates/fanos-sim/tests/sybil_admission.rs", "the simulator's SYBIL_REJECT recogniser"),
    ] {
        let text = std::fs::read_to_string(repo_root().join(rel)).unwrap();
        assert!(
            text.contains("fanos_wire::error::"),
            "{rel} ({what}) must go through `fanos_wire::error`, not hand-decode the ERROR body — a \
             hand-rolled reader is a third encoding, and the one that drifts is the one nobody tests."
        );
    }
}

/// The type names the spec's §7.2 table lists, with `*`-suffixed families expanded away.
///
/// The table writes families as `DKG_*`, `BEACON_RESHARE_*`, `POROS_*` — one cell for a group of codes that
/// vary only by role. Comparing those literally would force the table to spell out every variant, which is
/// worse prose for no more safety, so a `*` entry stands for "every implemented name with this prefix" and
/// the check below is on the *set of prefixes covered*, not on a name-for-name match.
fn spec_entries() -> (BTreeSet<String>, Vec<String>) {
    let text = std::fs::read_to_string(repo_root().join("spec/protocol.md")).unwrap();
    let rows: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("| `0x") && l.contains("*` |"))
        .collect();
    assert!(
        rows.len() >= 8,
        "the §7.2 frame table was not found in spec/protocol.md (matched {} rows) — if the table moved or \
         changed shape, this test must be re-pointed rather than deleted",
        rows.len()
    );
    let mut exact = BTreeSet::new();
    let mut prefixes = Vec::new();
    for row in rows {
        // The names live in the third pipe-delimited cell, as `` `NAME` `` items.
        let Some(cell) = row.split('|').nth(3) else { continue };
        for name in cell.split(',').map(|s| s.trim().trim_matches('`').trim()) {
            if name.is_empty() {
                continue;
            }
            match name.strip_suffix('*') {
                Some(prefix) => prefixes.push(prefix.to_owned()),
                None => {
                    exact.insert(name.to_owned());
                }
            }
        }
    }
    (exact, prefixes)
}

/// `FrameType`'s variant names, converted to the SCREAMING_SNAKE the spec writes them in.
fn implemented() -> BTreeSet<String> {
    let src = std::fs::read_to_string(repo_root().join("rust/crates/fanos-wire/src/frame.rs")).unwrap();
    // Only the outer registry: the inner `SessionFrameType` (PADDING/DATA/ACK/RESET) is a separate registry
    // the table does not tabulate, and it is declared after this enum closes.
    let outer = src.split("pub enum SessionFrameType").next().unwrap_or(&src);
    let mut names = BTreeSet::new();
    for line in outer.lines().map(str::trim) {
        let Some((name, rest)) = line.split_once(" = 0x") else { continue };
        if !rest.trim_end_matches(',').chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        if !name.chars().next().is_some_and(char::is_uppercase) {
            continue;
        }
        let mut screaming = String::new();
        for (i, c) in name.char_indices() {
            if c.is_uppercase() && i > 0 {
                screaming.push('_');
            }
            screaming.push(c.to_ascii_uppercase());
        }
        names.insert(screaming);
    }
    assert!(names.len() > 30, "the FrameType scan found only {} variants", names.len());
    names
}

/// **Three documents claim §12.3 identity custody has no live protocol. This is what makes that checkable.**
///
/// `fanos_calypso::hosting`, `fanos_node::threshold_rendezvous` and `fanos-sim/tests/threshold_calypso.rs`
/// all now state that identity custody is **at rest**: dealing is a one-time ceremony, recovery brings `t`
/// members' files together deliberately, and no node ever asks another for its opened share. They did not
/// always agree — two of them described reconstruction "on demand … e.g. re-signing an epoch cert", which
/// reads as a protocol that does not exist, and the one that had it right was a scope note explaining why
/// something need not be tested. A reader deciding whether a hosted service can rotate its own registration
/// got the answer from whichever file they opened first.
///
/// Prose cannot hold that. **The registry can**: a live gather needs frame types, and there are none. So the
/// day someone allocates `SVC_IDENTITY_*` this fails, and the failure lands on the author who is in the best
/// position — the only position — to move the three claims with the code.
///
/// It is deliberately keyed on the WIRE and not on a function name. `recover_service_key` having a caller
/// proves nothing either way (the ceremony calls it, correctly); what distinguishes at-rest custody from a
/// live one is whether a share can cross a link.
#[test]
fn identity_custody_has_no_wire_protocol_and_three_documents_say_so() {
    let implemented = implemented();
    let identity_frames: Vec<&String> = implemented
        .iter()
        .filter(|n| n.contains("IDENTITY") || (n.starts_with("SVC_") && n.contains("SHARE") && n.contains("ID")))
        .collect();
    assert!(
        identity_frames.is_empty(),
        "the frame registry now allocates {identity_frames:?}, so a share can cross a link and identity \
         custody is no longer only at-rest. Three documents state the opposite and must move with it: \
         `fanos-calypso/src/hosting.rs` (module header, the (a) paragraph), \
         `fanos-node/src/threshold_rendezvous.rs` (the identity-custody bullet), and \
         `fanos-sim/tests/threshold_calypso.rs` (the scope note). Update all three, then this list.",
    );

    // CONTROL: the scan can see the frames that DO exist, so an empty result above is a fact about identity
    // frames rather than about a filter that matches nothing. Without this the assertion passes for a
    // registry it never read — the failure mode `falsify-the-scan-before-the-finding` is named for.
    assert!(
        implemented.contains("SVC_SHARE_REQ") && implemented.contains("SVC_PARTIAL"),
        "the intro-gather frames must be visible to this scan, or its silence about identity means nothing: \
         {implemented:?}",
    );
}

#[test]
fn the_spec_frame_table_and_the_wire_registry_name_the_same_types() {
    let (exact, prefixes) = spec_entries();
    let implemented = implemented();

    // A spec name with no code behind it is the defect that produced this file: an implementer reads the
    // table, writes a peer that sends the type, and every one of those frames is discarded as unknown.
    let fictional: Vec<&String> = exact.difference(&implemented).collect();
    assert!(
        fictional.is_empty(),
        "spec/protocol.md §7.2 names frame types `fanos_wire::FrameType` does not implement: {fictional:?}. \
         A named-but-absent code is worse than an omission — a conforming implementation sends it and the \
         frames vanish. Delete the name, or implement it."
    );

    // The reverse: a code that exists and is undocumented. Less dangerous, still a divergence, and it is how
    // the table drifted in the first place (`CELL_ESCALATE` shipped without ever being tabulated).
    let undocumented: Vec<&String> = implemented
        .iter()
        .filter(|n| !exact.contains(*n) && !prefixes.iter().any(|p| n.starts_with(p)))
        .collect();
    assert!(
        undocumented.is_empty(),
        "`fanos_wire::FrameType` implements types spec/protocol.md §7.2 does not list: {undocumented:?}. \
         Add them to the table (a `PREFIX_*` cell covers a family), or say in the commit why the wire \
         carries something the specification does not describe."
    );
}

/// **The operator-facing verb list is a second record of the dispatch table, so it is checked against it.**
///
/// `docs/testnet.md`'s quick-command reference and `bin/fanos.rs`'s `match` are two descriptions of the same
/// thing, and only one of them is compiled. The same shape as the frame registry above: a reader of the doc
/// reasonably concludes a verb exists, or does not, and nothing said otherwise.
///
/// It is a **one-way** check, deliberately. Every verb the doc names must dispatch — a documented command
/// that does not exist is a lie an operator finds by running it. The converse is not asserted, because the
/// reference is a *quick* one and is allowed to omit verbs (`fanos --help` is the complete listing, and the
/// binary's own `every_verb_has_a_help_block` test is what keeps that honest).
#[test]
fn every_verb_the_testnet_guide_names_is_one_the_binary_dispatches() {
    let doc = std::fs::read_to_string(repo_root().join("docs/testnet.md")).expect("docs/testnet.md");
    let dispatch =
        std::fs::read_to_string(repo_root().join("rust/crates/fanos-node/src/bin/fanos.rs"))
            .expect("bin/fanos.rs");

    // The reference table's rows are ``| … | `fanos <verb> …` |``.
    let table = doc
        .split("## Quick command reference")
        .nth(1)
        .expect("the quick command reference")
        .split("See also:")
        .next()
        .expect("the table ends before the see-also");

    let named: BTreeSet<String> = table
        .lines()
        .filter_map(|l| l.split("`fanos ").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|v| v.trim_end_matches('`').to_owned())
        // `<verb>` is the placeholder in the "what does one verb do" row, not a verb.
        .filter(|v| !v.starts_with('<') && !v.starts_with('-'))
        .collect();
    assert!(named.len() >= 8, "the reference table parsed to {} rows, which cannot be right", named.len());

    let missing: Vec<&String> =
        named.iter().filter(|v| !dispatch.contains(&format!("Some(\"{v}\")"))).collect();
    assert!(
        missing.is_empty(),
        "docs/testnet.md's quick reference names commands the binary does not dispatch: {missing:?}\n\
         An operator finds this by typing it. Either add the verb or correct the table."
    );
}
