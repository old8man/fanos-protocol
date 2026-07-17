//! Property tests: canonical encoding round-trips, and non-canonical input is always rejected.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_cmp
)]

use fanos_field::{F7, F31};
use fanos_geometry::{Line, Plane, Point};
use fanos_wire::{FrameType, decode_frame, element, encode_frame, varint};
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
}
