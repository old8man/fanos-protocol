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
