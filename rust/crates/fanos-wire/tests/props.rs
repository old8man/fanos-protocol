//! Property tests: canonical encoding round-trips, and non-canonical input is always rejected.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_cmp
)]

use fanos_field::{F7, F31};
use fanos_geometry::{Line, Plane, Point};
use fanos_wire::{FrameType, Wire, decode_frame, element, encode_frame, varint};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Every varint round-trips and uses the minimal length.
    #[test]
    fn varint_round_trips_minimally(value in 0u64..(1u64 << 62)) {
        let mut buf = Vec::new();
        varint::encode(value, &mut buf);
        prop_assert_eq!(buf.len(), varint::encoded_len(value));
        let (decoded, n) = varint::decode(&buf).unwrap();
        prop_assert_eq!(decoded, value);
        prop_assert_eq!(n, buf.len());
    }

    /// Every point of `PG(2, q)` round-trips through the canonical encoding.
    #[test]
    fn point_round_trips(i in 0..(Plane::<F31>::N as usize)) {
        let p = Point::<F31>::at(i);
        let mut buf = Vec::new();
        element::encode_point(&p, &mut buf);
        let (back, n) = element::decode_point::<F31>(&buf).unwrap();
        prop_assert_eq!(back, p);
        prop_assert_eq!(n, buf.len());
    }

    /// Lines round-trip too.
    #[test]
    fn line_round_trips(i in 0..(Plane::<F7>::N as usize)) {
        let l = Line::<F7>::at(i);
        let mut buf = Vec::new();
        element::encode_line(&l, &mut buf);
        let (back, _) = element::decode_line::<F7>(&buf).unwrap();
        prop_assert_eq!(back, l);
    }

    /// Frames round-trip with arbitrary bodies and type codes.
    #[test]
    fn frame_round_trips(type_code in 0u64..0x1000, body in proptest::collection::vec(any::<u8>(), 0..256)) {
        let mut buf = Vec::new();
        encode_frame(type_code, &body, &mut buf);
        let (frame, n) = decode_frame(&buf).unwrap();
        prop_assert_eq!(frame.type_code, type_code);
        prop_assert_eq!(frame.body, body.as_slice());
        prop_assert_eq!(n, buf.len());
        prop_assert_eq!(frame.frame_type(), FrameType::from_code(type_code));
    }

    /// Byte strings round-trip.
    #[test]
    fn byte_string_round_trips(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let mut buf = Vec::new();
        element::encode_bytes(&data, &mut buf);
        let (body, n) = element::decode_bytes(&buf).unwrap();
        prop_assert_eq!(body, data.as_slice());
        prop_assert_eq!(n, buf.len());
    }

    /// A field element `≥ q` is always rejected (canonical range check).
    #[test]
    fn out_of_range_field_element_rejected(byte in 7u8..=255) {
        // In GF(7), any single byte ≥ 7 is out of range.
        prop_assert!(element::decode_element::<F7>(&[byte]).is_err());
    }

    /// A projective triple whose leading coordinate is not 1 is rejected as non-canonical.
    #[test]
    fn non_canonical_point_rejected(x in 2u8..7, y in 0u8..7, z in 0u8..7) {
        // [x:y:z] with x ∈ 2..7 has a leading coordinate ≠ 1 → not canonical.
        prop_assert!(element::decode_point::<F7>(&[x, y, z]).is_err());
    }

    /// **Arbitrary bytes reach a verdict, never a panic — the hand-written decoders (#155).**
    ///
    /// Read this as a RATCHET, not as a hunt for a live defect. The surface it guards is empty today
    /// and the compiler is what proves it: `unwrap_used`, `expect_used` and `indexing_slicing` are
    /// workspace lints, the gate runs clippy with `-D warnings`, and every waiver in this crate sits
    /// inside a test module — which the sibling test below checks by position. What makes the property
    /// still worth its cost is that the discipline is waivable by one `#[allow]` line, and a decoder
    /// written by hand with a slice would sail past all five round-trip properties above, because each
    /// of those feeds the decoder exactly what the encoder produced and so never leaves the happy path.
    ///
    /// The panic-freedom is the floor. The assertion carries more: a decoder that reports consuming
    /// more than it was handed has mis-measured its own input, and no round-trip test can see that
    /// because on a well-formed buffer the two lengths agree by construction.
    #[test]
    fn arbitrary_bytes_reach_a_verdict_in_the_frame_decoder(
        bytes in proptest::collection::vec(any::<u8>(), 0..1024)
    ) {
        if let Ok((frame, n)) = decode_frame(&bytes) {
            prop_assert!(
                n <= bytes.len(),
                "decode_frame claimed {n} bytes from a {}-byte input", bytes.len()
            );
            prop_assert!(
                frame.body.len() <= bytes.len(),
                "the body is longer than the whole input it came from"
            );
        }
    }

    /// **Arbitrary bytes reach a verdict, never a panic — the 90 DERIVED decoders (#155).**
    ///
    /// Separate from the property above because the risk is separate: proc-macro output is the one
    /// place a lint is easy to assume covers you when it might not. It does cover this one — the
    /// generator emits `Wire::wire_decode(cur)?` per field and nothing else, so a derived decoder is
    /// exactly as safe as the leaf impls it calls — but "I read the generator" is an argument that
    /// expires the next time the generator changes, and this property does not.
    ///
    /// The shape covers the three field kinds the generator handles differently: a fixed-width array,
    /// a length-prefixed `Vec`, and a nested derived struct.
    #[test]
    fn arbitrary_bytes_reach_a_verdict_in_a_derived_decoder(
        bytes in proptest::collection::vec(any::<u8>(), 0..1024)
    ) {
        // `from_wire` rejects trailing bytes, so on random input Err is the overwhelmingly likely
        // verdict. Reaching one at all is the property.
        let outer = Outer::from_wire(&bytes);
        if let Ok(v) = outer {
            prop_assert_eq!(v.to_wire(), bytes, "from_wire accepted bytes it does not re-encode to");
        }
    }
}

/// A nested derived type, used only by the property above.
#[derive(Debug, PartialEq, Eq, fanos_wire_derive::Wire)]
struct Inner {
    tag: [u8; 4],
    payload: Vec<u8>,
}

/// The representative `#[derive(Wire)]` shape: fixed array, length-prefixed vector, nested struct.
#[derive(Debug, PartialEq, Eq, fanos_wire_derive::Wire)]
struct Outer {
    id: [u8; 8],
    items: Vec<Inner>,
    trailer: Vec<u8>,
}

/// **Every panic-lint waiver in this crate is inside a test module (#155).**
///
/// The paired half of the two properties above, and the reason they are a ratchet rather than a hunt:
/// their premise is that production code cannot panic *because the lint forbids it*, and that premise
/// dies quietly the day someone writes `#[allow(clippy::unwrap_used)]` above a production function.
/// clippy will not complain — the waiver is exactly what makes it not complain — so nothing else in
/// the build can notice. Checking the waivers by POSITION is what notices.
///
/// The scan is asserted before its result is (see the two floors below): a walk that silently matched
/// nothing would otherwise report "no production waivers" in the same green as a genuinely clean crate,
/// which is the failure mode a count-based guard is most prone to.
#[test]
fn no_production_code_waives_a_panic_lint() {
    const PANIC_LINTS: [&str; 4] = [
        "unwrap_used",
        "expect_used",
        "indexing_slicing",
        "clippy::panic",
    ];

    // The corpus and the test-block slice are the SHARED ones (#252/#253). Both were hand-rolled here, and
    // both hand-rolled forms have the same failure: a walk that cannot open a file skips it in silence and
    // then reports green about code it never read, and a slice cut at the FIRST `#[cfg(test)]` drops the
    // shipping code below it. `shipping_lines` also keeps the 1-indexed numbers this test reports, which a
    // naive "slice then enumerate" would have quietly shifted.
    let files: Vec<(String, String)> = fanos_testkit::corpus::rust_sources()
        .into_iter()
        .filter(|s| s.krate == "fanos-wire" && s.is_crate_src())
        .map(|s| (s.rel.clone(), s.text.clone()))
        .collect();

    // FLOOR 1 — the walk reached the files this crate is made of. Named individually, because
    // asserting the count against itself would pass on an empty directory listing.
    for expected in ["lib.rs", "frame.rs", "varint.rs", "element.rs", "wire.rs"] {
        assert!(
            files.iter().any(|(rel, _)| rel.ends_with(expected)),
            "the scan did not reach src/{expected}, so its verdict covers an unknown subset of the crate"
        );
    }

    let is_waiver = |line: &str| {
        let trimmed = line.trim_start();
        (trimmed.starts_with("#[allow(") || trimmed.starts_with("#![allow("))
            && PANIC_LINTS.iter().any(|lint| line.contains(lint))
    };

    let mut waivers = 0usize;
    let mut production = Vec::new();
    for (rel, text) in &files {
        // Counted over the WHOLE file, because FLOOR 2 below is about the matcher being alive, and every
        // waiver in this crate lives inside a test module — the very lines the shipping slice removes.
        waivers += text.lines().filter(|l| is_waiver(l)).count();
        // Reported over the SHIPPING lines only: a waiver that survives the cut is a production waiver, and
        // the `#[cfg(test)]` lookback this used to do by hand is what the shared slice already knows.
        for (n, line) in fanos_testkit::source::shipping_lines(text) {
            if is_waiver(line) {
                production.push(format!("{rel}:{n}: {}", line.trim_start()));
            }
        }
    }

    // FLOOR 2 — the matcher still recognises a waiver. Deliberately 1 and not the nine that exist
    // today: nine would fail the day a test module legitimately stops needing one, which is a change
    // in the right direction and must not read as a regression. One is all that is needed to tell a
    // working scan from a scan that matches nothing.
    assert!(
        waivers > 0,
        "the scan found no panic-lint waiver anywhere in {} files. Every file in this crate has one \
         inside its test module, so zero means the matcher is broken, not that the crate is clean.",
        files.len()
    );

    assert!(
        production.is_empty(),
        "a panic lint is waived outside a test module, which removes the compiler proof that this \
         crate's decoders cannot panic on hostile input — the premise the two arbitrary-bytes \
         properties in this file rest on (#155):\n  {}",
        production.join("\n  ")
    );
}
