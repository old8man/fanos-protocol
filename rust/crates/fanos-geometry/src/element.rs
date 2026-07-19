//! The homogeneous-triple algebra underneath points and lines (spec §2.1–§2.2).
//!
//! A point and a line of `PG(2, q)` are both a triple `[x:y:z]` over `GF(q)` taken up to
//! scaling; the operations that join two points, meet two lines, and test incidence are the
//! vector **cross product** and **dot product**. Keeping them here — generic over the field
//! and free of the `Point`/`Line` newtypes — lets both the typed API and the const Fano
//! acceleration share one audited implementation.

use fanos_field::Field;

/// A homogeneous coordinate triple, stored as three canonical `GF(q)` element codes.
pub type Triple = [u32; 3];

/// The fixed serialized width of a [`Triple`] as a field-agnostic overlay/transport address:
/// `x‖y‖z`, each a 4-byte **big-endian** `u32`.
pub const TRIPLE_WIRE_LEN: usize = 12;

/// Encode a [`Triple`] as its canonical 12-byte wire form (`x‖y‖z`, each big-endian `u32`).
///
/// This is the field-agnostic address form used wherever a coordinate travels as an opaque
/// transport/overlay address (a `Triple`, its field erased). It is deliberately distinct from
/// `fanos_wire::encode_point`, which serializes a *typed* `Point<F>` at the field-optimal width
/// (`⌈log₂q/8⌉` bytes per element). Big-endian is the one canonical spelling across the whole stack
/// (spec §7.1 "one encoding") — every coordinate serializer must agree, or two nodes disagree on the
/// same bytes.
#[inline]
#[must_use]
pub fn encode_triple(t: Triple) -> [u8; TRIPLE_WIRE_LEN] {
    let [x, y, z] = t;
    let ([x0, x1, x2, x3], [y0, y1, y2, y3], [z0, z1, z2, z3]) =
        (x.to_be_bytes(), y.to_be_bytes(), z.to_be_bytes());
    [x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3]
}

/// Decode a [`Triple`] from exactly [`TRIPLE_WIRE_LEN`] big-endian bytes, or `None` on a wrong length.
/// The inverse of [`encode_triple`].
#[inline]
#[must_use]
pub fn decode_triple(bytes: &[u8]) -> Option<Triple> {
    let [x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3]: [u8; TRIPLE_WIRE_LEN] =
        bytes.try_into().ok()?;
    Some([
        u32::from_be_bytes([x0, x1, x2, x3]),
        u32::from_be_bytes([y0, y1, y2, y3]),
        u32::from_be_bytes([z0, z1, z2, z3]),
    ])
}

/// The cross product `a × b` over `GF(q)`.
///
/// This single operation is FANOS's O(1) rendezvous (spec §2.2): the join of two points is
/// their cross product, and — by self-duality — so is the meet of two lines. The identity
/// `(a × b) · a = 0` holds over any commutative ring, which is exactly why the resulting
/// line passes through both operands.
#[inline]
pub fn cross<F: Field>(a: Triple, b: Triple) -> Triple {
    let [a0, a1, a2] = a;
    let [b0, b1, b2] = b;
    [
        F::sub(F::mul(a1, b2), F::mul(a2, b1)),
        F::sub(F::mul(a2, b0), F::mul(a0, b2)),
        F::sub(F::mul(a0, b1), F::mul(a1, b0)),
    ]
}

/// The dot product `a · b` over `GF(q)`. Incidence is exactly its vanishing (spec §2.1).
#[inline]
pub fn dot<F: Field>(a: Triple, b: Triple) -> u32 {
    let [a0, a1, a2] = a;
    let [b0, b1, b2] = b;
    F::add(F::add(F::mul(a0, b0), F::mul(a1, b1)), F::mul(a2, b2))
}

/// Whether a triple is the zero vector (not a valid projective element).
#[inline]
pub fn is_zero(a: Triple) -> bool {
    a == [0, 0, 0]
}

/// Whether every coordinate is a canonical element of `GF(q)` and the triple is non-zero.
#[inline]
pub fn is_valid<F: Field>(a: Triple) -> bool {
    let [a0, a1, a2] = a;
    !is_zero(a) && F::in_range(a0) && F::in_range(a1) && F::in_range(a2)
}

/// Reduce a triple to **canonical form**: scale so the first non-zero coordinate is `1`
/// (spec §7.1). Returns `None` for the zero vector. Two triples denote the same projective
/// element iff their canonical forms are equal, which makes canonical triples directly
/// hashable and comparable.
#[inline]
pub fn canonicalize<F: Field>(a: Triple) -> Option<Triple> {
    let [a0, a1, a2] = a;
    let lead_inv = if a0 != 0 {
        F::inv(a0)
    } else if a1 != 0 {
        F::inv(a1)
    } else if a2 != 0 {
        F::inv(a2)
    } else {
        return None;
    };
    Some([
        F::mul(a0, lead_inv),
        F::mul(a1, lead_inv),
        F::mul(a2, lead_inv),
    ])
}

/// Whether a triple is already in canonical form (its first non-zero coordinate is `1`).
#[inline]
pub fn is_canonical(a: Triple) -> bool {
    match a {
        [0, 0, 0] => false,
        [0, 0, z] => z == 1,
        [0, y, _] => y == 1,
        [x, _, _] => x == 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_wire_codec_round_trips_big_endian() {
        for t in [[0u32, 0, 1], [7, 0, 1], [1, 2, 3], [u32::MAX, 0, u32::MAX]] {
            let bytes = encode_triple(t);
            assert_eq!(bytes.len(), TRIPLE_WIRE_LEN);
            assert_eq!(decode_triple(&bytes), Some(t));
        }
        // Big-endian is the canonical spelling: the top byte of x leads.
        assert_eq!(encode_triple([0x0102_0304, 0, 0])[0], 0x01);
    }

    #[test]
    fn decode_triple_rejects_wrong_length() {
        assert_eq!(decode_triple(&[0u8; 4]), None);
        assert_eq!(decode_triple(&[0u8; TRIPLE_WIRE_LEN + 1]), None);
        assert_eq!(decode_triple(&[]), None);
    }
}
