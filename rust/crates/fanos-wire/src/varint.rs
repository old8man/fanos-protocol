//! QUIC variable-length integers with canonical (minimal-length) encoding (spec §7.1).
//!
//! The two most-significant bits of the first byte select the length (1/2/4/8 bytes); the
//! remaining bits are the big-endian value. FANOS additionally requires the **minimal**
//! length — a decoder rejects a value padded into a longer form — so that every integer has
//! exactly one valid encoding.

use alloc::vec::Vec;

use crate::error::WireError;

/// The largest value representable by a varint (`2^62 − 1`).
pub const MAX: u64 = (1 << 62) - 1;

/// The minimal encoded length (in bytes) for `value`.
#[must_use]
pub fn encoded_len(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

/// Append the canonical (minimal-length) encoding of `value` to `out`.
///
/// # Panics
/// If `value > MAX` (`2^62 − 1`), which cannot be represented.
pub fn encode(value: u64, out: &mut Vec<u8>) {
    assert!(value <= MAX, "varint value {value} exceeds 2^62-1");
    let len = encoded_len(value);
    let tag: u8 = match len {
        1 => 0b00,
        2 => 0b01,
        4 => 0b10,
        _ => 0b11,
    };
    let start = out.len();
    // Big-endian value in `len` bytes; then OR the length tag into the top two bits.
    for i in (0..len).rev() {
        out.push((value >> (8 * i)) as u8);
    }
    if let Some(first) = out.get_mut(start) {
        *first |= tag << 6;
    }
}

/// Decode a varint from the front of `buf`, returning `(value, bytes_consumed)`.
///
/// Rejects non-minimal encodings with [`WireError::NonCanonicalVarint`] and truncated input
/// with [`WireError::UnexpectedEnd`].
pub fn decode(buf: &[u8]) -> Result<(u64, usize), WireError> {
    let first = *buf.first().ok_or(WireError::UnexpectedEnd)?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return Err(WireError::UnexpectedEnd);
    }
    // High two bits are the length tag; mask them off the first byte.
    let mut value = u64::from(first & 0x3F);
    for &b in buf.get(1..len).ok_or(WireError::UnexpectedEnd)? {
        value = (value << 8) | u64::from(b);
    }
    if encoded_len(value) != len {
        return Err(WireError::NonCanonicalVarint);
    }
    Ok((value, len))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_across_all_length_classes() {
        let cases = [0u64, 1, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, MAX];
        for value in cases {
            let mut buf = Vec::new();
            encode(value, &mut buf);
            assert_eq!(buf.len(), encoded_len(value));
            let (decoded, n) = decode(&buf).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn boundary_values_use_minimal_length() {
        let mut b = Vec::new();
        encode(63, &mut b);
        assert_eq!(b.len(), 1);
        b.clear();
        encode(64, &mut b);
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn rejects_non_minimal_encoding() {
        // Value 0 encoded in two bytes (0x4000) is non-canonical and must be rejected.
        let non_canonical = [0x40u8, 0x00];
        assert_eq!(decode(&non_canonical), Err(WireError::NonCanonicalVarint));
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(decode(&[]), Err(WireError::UnexpectedEnd));
        // Announces 4 bytes (tag 0b10) but only 2 present.
        assert_eq!(decode(&[0x80, 0x01]), Err(WireError::UnexpectedEnd));
    }

    /// Known-answer vectors from RFC 9000 §16 (values), FANOS canonical form.
    #[test]
    fn rfc9000_known_answers() {
        let mut b = Vec::new();
        encode(37, &mut b);
        assert_eq!(b, [0x25]); // 1-byte
        b.clear();
        encode(15293, &mut b);
        assert_eq!(b, [0x7B, 0xBD]); // 2-byte
        b.clear();
        encode(494_878_333, &mut b);
        assert_eq!(b, [0x9D, 0x7F, 0x3E, 0x7D]); // 4-byte
    }

    /// The exact encode vectors published in `conformance/vectors/wire.json`.
    #[test]
    fn conformance_varint_vectors() {
        let cases: [(u64, &[u8]); 8] = [
            (0, &[0x00]),
            (37, &[0x25]),
            (63, &[0x3F]),
            (64, &[0x40, 0x40]),
            (15293, &[0x7B, 0xBD]),
            (16383, &[0x7F, 0xFF]),
            (16384, &[0x80, 0x00, 0x40, 0x00]),
            (494_878_333, &[0x9D, 0x7F, 0x3E, 0x7D]),
        ];
        for (value, expected) in cases {
            let mut b = Vec::new();
            encode(value, &mut b);
            assert_eq!(b, expected, "varint({value})");
        }
    }
}
