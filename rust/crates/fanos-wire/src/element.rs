//! Canonical encoding of field elements, projective points/lines, and byte strings (§7.1).

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::element::is_canonical;
use fanos_geometry::{Line, Point};

use crate::error::WireError;
use crate::varint;

/// The fixed byte width of a `GF(q)` element: `⌈log₂ q / 8⌉` (spec §7.1). Every element of the field
/// is encoded big-endian, high bits zero-padded, in exactly this many bytes. A re-export of the one
/// canonical [`fanos_field::element_width`], so the wire codec and the `MapToPoint` sampler share it.
pub use fanos_field::element_width as field_element_width;

/// The element width for the field `F`.
#[must_use]
pub fn width<F: Field>() -> usize {
    field_element_width(F::Q)
}

/// Append a `GF(q)` element (given as its `u32` code) big-endian in the field's fixed width.
pub fn encode_element<F: Field>(elem: u32, out: &mut Vec<u8>) {
    let w = width::<F>();
    for i in (0..w).rev() {
        out.push((elem >> (8 * i)) as u8);
    }
}

/// Decode one `GF(q)` element from the front of `buf`, returning `(element, bytes_consumed)`.
/// Rejects values `≥ q` (spec §7.1 canonical field element).
pub fn decode_element<F: Field>(buf: &[u8]) -> Result<(u32, usize), WireError> {
    let w = width::<F>();
    let bytes = buf.get(..w).ok_or(WireError::UnexpectedEnd)?;
    let mut value = 0u32;
    for &b in bytes {
        value = (value << 8) | u32::from(b);
    }
    if !F::in_range(value) {
        return Err(WireError::FieldElementOutOfRange);
    }
    Ok((value, w))
}

/// Encode a projective point as three canonical field elements (spec §7.1).
pub fn encode_point<F: Field>(point: &Point<F>, out: &mut Vec<u8>) {
    for c in point.coords() {
        encode_element::<F>(c, out);
    }
}

/// Encode a projective line as three canonical field elements.
pub fn encode_line<F: Field>(line: &Line<F>, out: &mut Vec<u8>) {
    for c in line.coords() {
        encode_element::<F>(c, out);
    }
}

/// Decode a projective triple and return `(coords, bytes_consumed)`, rejecting any triple that
/// is not already in canonical form (first non-zero coordinate `1`).
fn decode_triple<F: Field>(buf: &[u8]) -> Result<([u32; 3], usize), WireError> {
    let w = width::<F>();
    let mut coords = [0u32; 3];
    for (idx, slot) in coords.iter_mut().enumerate() {
        let (elem, _) = decode_element::<F>(buf.get(idx * w..).ok_or(WireError::UnexpectedEnd)?)?;
        *slot = elem;
    }
    if !is_canonical(coords) {
        return Err(WireError::NonCanonicalProjective);
    }
    Ok((coords, 3 * w))
}

/// Decode a projective **point**, rejecting non-canonical input (spec §7.1).
pub fn decode_point<F: Field>(buf: &[u8]) -> Result<(Point<F>, usize), WireError> {
    let (coords, n) = decode_triple::<F>(buf)?;
    let point = Point::new(coords).ok_or(WireError::NonCanonicalProjective)?;
    Ok((point, n))
}

/// Decode a projective **line**, rejecting non-canonical input.
pub fn decode_line<F: Field>(buf: &[u8]) -> Result<(Line<F>, usize), WireError> {
    let (coords, n) = decode_triple::<F>(buf)?;
    let line = Line::new(coords).ok_or(WireError::NonCanonicalProjective)?;
    Ok((line, n))
}

/// Encode a byte string as `varint length ‖ bytes` (spec §7.1).
pub fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    varint::encode(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// Decode a length-prefixed byte string, returning `(slice, bytes_consumed)`.
pub fn decode_bytes(buf: &[u8]) -> Result<(&[u8], usize), WireError> {
    let (len, head) = varint::decode(buf)?;
    // `usize::try_from`, not `as usize`: a 64-bit length must not truncate on a 32-bit target
    // (wasm32) — that would desynchronise the byte-string stream between node widths.
    let len = usize::try_from(len).map_err(|_| WireError::ValueTooLarge)?;
    let end = head.checked_add(len).ok_or(WireError::ValueTooLarge)?;
    let body = buf.get(head..end).ok_or(WireError::UnexpectedEnd)?;
    Ok((body, end))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::{F2, F7, F256};
    use fanos_geometry::Plane;

    #[test]
    fn element_widths_match_spec() {
        assert_eq!(field_element_width(2), 1);
        assert_eq!(field_element_width(7), 1);
        assert_eq!(field_element_width(256), 1);
        assert_eq!(field_element_width(127), 1);
        assert_eq!(field_element_width(65536), 2);
    }

    #[test]
    fn all_points_round_trip_canonically() {
        for p in Plane::<F7>::points() {
            let mut buf = Vec::new();
            encode_point(&p, &mut buf);
            assert_eq!(buf.len(), 3 * width::<F7>());
            let (decoded, n) = decode_point::<F7>(&buf).unwrap();
            assert_eq!(decoded, p);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn rejects_out_of_range_element() {
        // In GF(7), a byte value of 7 is out of range.
        assert_eq!(
            decode_element::<F7>(&[7]),
            Err(WireError::FieldElementOutOfRange)
        );
        assert!(decode_element::<F7>(&[6]).is_ok());
    }

    #[test]
    fn rejects_non_canonical_point() {
        // [2:0:0] in GF(7) is a valid vector but not canonical (leading coord ≠ 1).
        assert_eq!(
            decode_point::<F7>(&[2, 0, 0]),
            Err(WireError::NonCanonicalProjective)
        );
        // The zero vector is rejected too.
        assert_eq!(
            decode_point::<F7>(&[0, 0, 0]),
            Err(WireError::NonCanonicalProjective)
        );
    }

    #[test]
    fn gf2_point_is_three_bytes() {
        let p = Plane::<F2>::points().next().unwrap();
        let mut buf = Vec::new();
        encode_point(&p, &mut buf);
        assert_eq!(buf, [1, 0, 0]); // [1:0:0] in one byte per coord
    }

    #[test]
    fn byte_string_round_trips() {
        let mut buf = Vec::new();
        encode_bytes(b"FANOS", &mut buf);
        let (body, n) = decode_bytes(&buf).unwrap();
        assert_eq!(body, b"FANOS");
        assert_eq!(n, buf.len());
    }

    #[test]
    fn gf256_element_uses_one_byte() {
        let mut buf = Vec::new();
        encode_element::<F256>(200, &mut buf);
        assert_eq!(buf, [200]);
    }
}
