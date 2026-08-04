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
