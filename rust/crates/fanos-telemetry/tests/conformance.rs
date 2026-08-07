//! **The conformance vector is the authority, and this is what makes that true** (#160).
//!
//! `conformance/vectors/telemetry.json` exists so a *second implementation* can check itself against the
//! reference. Until this file, nothing in the repo read it: `frame.rs`'s known-answer test carried its own
//! hex constant and a doc comment saying the JSON was *"mirrored"*. Two hand-maintained copies of one wire
//! format with nothing comparing them is exactly the shape #75 was found in — *"the ERROR frame has two
//! incompatible encodings, and only one is in the conformance vector"* — and the divergence is silent on
//! this side: the Rust suite goes green while the JSON describes a protocol nobody speaks. The person who
//! finds out is an implementer whose node cannot talk to the network.
//!
//! So the vector is loaded and compared, field by field, against what this crate actually produces.
//!
//! No JSON dependency: the vector's shape is fixed and the three things needed from it — a hex string, an
//! integer, a float — are extracted by key. A parser here would be a second thing that can be wrong.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::fmt::Write as _;

use fanos_diakrisis::coherence::CoherenceMatrix;
use fanos_telemetry::{CellId, CoherenceFrame};

/// The vector, read from the repo root (`CARGO_MANIFEST_DIR` is `rust/crates/fanos-telemetry`).
fn vector() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../conformance/vectors/telemetry.json"
    );
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// The raw text of `"key": <value>`, up to the next `,` or newline. Deliberately crude — see the header.
fn field<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = alloc_key(key);
    let start = json
        .find(&needle)
        .unwrap_or_else(|| panic!("the vector has no `{key}` — it is the authority, so this is a real gap"))
        + needle.len();
    let rest = &json[start..];
    let end = rest.find([',', '\n']).unwrap_or(rest.len());
    rest[..end].trim().trim_matches('"')
}

fn alloc_key(key: &str) -> String {
    format!("\"{key}\": ")
}

/// The canonical frame the vector describes, built through the crate's own constructor.
fn canonical() -> CoherenceFrame {
    let matrix = CoherenceMatrix::equicorrelated(7, 0.5);
    CoherenceFrame::observe(CellId([0x11; 16]), 42, &matrix, 0b0000_0001, 0.5, -1, 3, true)
}

#[test]
fn the_published_vector_is_the_frame_this_crate_actually_encodes() {
    let json = vector();
    let mut hex = String::with_capacity(fanos_telemetry::frame::FRAME_LEN * 2);
    for b in canonical().encode() {
        let _ = write!(hex, "{b:02x}");
    }
    assert_eq!(
        hex,
        field(&json, "encoded_hex"),
        "the published vector and the encoder disagree — one of them is lying to an implementer, and the \
         vector is the one they read",
    );
}

#[test]
fn the_vectors_derived_scalars_are_the_ones_the_frame_carries() {
    let json = vector();
    let f = canonical();

    // The syndrome and verdict are the load-bearing bytes: the 3-bit Fano localizer and the packed
    // regime/alarm/integrated/**measured** nibble. An implementer reading the vector reproduces these
    // exactly or it is not speaking the protocol.
    assert_eq!(field(&json, "syndrome").parse::<u8>().unwrap(), f.syndrome, "syndrome");
    assert_eq!(field(&json, "verdict").parse::<u8>().unwrap(), f.verdict, "verdict byte");

    for (key, got) in [
        ("phi", f.phi),
        ("purity", f.purity),
        ("reflection", f.reflection),
        ("mean_r", f.mean_r),
    ] {
        let want: f32 = field(&json, key).parse().unwrap_or_else(|e| panic!("{key}: {e}"));
        assert!(
            (want - got).abs() < 1e-6,
            "{key}: the vector says {want}, the frame carries {got}",
        );
    }

    // The bit this vector gained in #154. Asserted through the accessor rather than by re-deriving the
    // mask, so a change to the packing that leaves the byte intact still has to keep the meaning.
    assert!(
        f.correlation_is_measured(),
        "the canonical frame is the MEASURED case; the assumed one is a different vector",
    );
}
