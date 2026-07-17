//! `MapToPoint` / `MapToLine` — uniform hashing into `PG(2, q)` (spec §7.1, L0).
//!
//! A node coordinate is `MapToPoint(VRF(pubkey, epoch))`; a content key maps to
//! `MapToPoint(H(k))`; a rendezvous line is `MapToLine(VRF(secret, epoch))`. All three need a
//! *uniform* projective element deterministically derived from a label and some bytes. The
//! construction draws field coordinates from the domain-separated BLAKE3 XOF stream — masked
//! for binary fields, rejection-sampled for prime fields to avoid modulo bias — discards the
//! zero vector, and normalises to canonical form (first non-zero coordinate `1`). Because
//! every projective point has exactly `q−1` non-zero representatives, uniform nonzero triples
//! yield a **uniform point**.

// The draw buffer is a fixed `[u8; 8]` and the draw width `w = coord_bytes(F::Q)` is `≤ 2`
// for every field FANOS instantiates (q ≤ 2^16), so `buf[..w]` never panics; asserted below.
#![allow(clippy::indexing_slicing)]

use blake3::OutputReader;

use fanos_field::{Field, FieldKind};
use fanos_geometry::{Line, Point};

use crate::hash::xof_reader;

/// Bytes needed to cover the value range `0..q` (smallest `w` with `256^w ≥ q`).
const fn coord_bytes(q: u32) -> usize {
    let mut w = 1usize;
    let mut space = 256u64;
    while space < q as u64 {
        space *= 256;
        w += 1;
    }
    w
}

/// Draw one uniform `GF(q)` element from the XOF stream.
fn sample_element<F: Field>(reader: &mut OutputReader) -> u32 {
    let w = coord_bytes(F::Q);
    debug_assert!(w <= 8, "draw width must fit the 8-byte buffer");
    let mut buf = [0u8; 8];
    let take = &mut buf[..w];
    match F::KIND {
        FieldKind::Binary => {
            reader.fill(take);
            let mut v = 0u64;
            for &b in take.iter() {
                v = (v << 8) | u64::from(b);
            }
            let mask = if F::M >= 32 {
                u32::MAX
            } else {
                (1u32 << F::M) - 1
            };
            (v as u32) & mask
        }
        FieldKind::Prime => {
            let q = u64::from(F::Q);
            // Largest multiple of q within the w-byte space; values at or above bias the modulo.
            let space = 1u64 << (8 * w);
            let bound = space - (space % q);
            loop {
                let slot = &mut buf[..w];
                reader.fill(slot);
                let mut v = 0u64;
                for &b in slot.iter() {
                    v = (v << 8) | u64::from(b);
                }
                if v < bound {
                    return (v % q) as u32;
                }
            }
        }
    }
}

/// Draw a uniform non-zero canonical triple from the XOF stream.
fn sample_triple<F: Field>(reader: &mut OutputReader) -> [u32; 3] {
    loop {
        let c = [
            sample_element::<F>(reader),
            sample_element::<F>(reader),
            sample_element::<F>(reader),
        ];
        if c != [0, 0, 0] {
            return c;
        }
    }
}

/// Map a label and data to a uniform **point** of `PG(2, q)` (spec §7.1, `MapToPoint`).
#[must_use]
pub fn map_to_point<F: Field>(label: &str, data: &[u8]) -> Point<F> {
    let mut reader = xof_reader(label, data);
    let coords = sample_triple::<F>(&mut reader);
    // `Point::new` canonicalizes; the triple is already non-zero and in range.
    Point::new(coords).unwrap_or_else(|| Point::at(0))
}

/// Map a label and data to a uniform **line** of `PG(2, q)` (spec §7.1, `MapToLine`).
#[must_use]
pub fn map_to_line<F: Field>(label: &str, data: &[u8]) -> Line<F> {
    let mut reader = xof_reader(label, data);
    let coords = sample_triple::<F>(&mut reader);
    Line::new(coords).unwrap_or_else(|| Line::at(0))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hash::label;
    use fanos_field::{F7, F31, F256};
    use fanos_geometry::Plane;

    #[test]
    fn map_to_point_is_deterministic() {
        let a = map_to_point::<F7>(label::COORD, b"node-key");
        let b = map_to_point::<F7>(label::COORD, b"node-key");
        assert_eq!(a, b);
    }

    #[test]
    fn map_to_point_output_is_canonical_and_valid() {
        for i in 0u32..200 {
            let p = map_to_point::<F31>(label::COORD, &i.to_be_bytes());
            // Round-trips through the index bijection ⇒ it is a genuine canonical point.
            assert_eq!(Point::<F31>::at(p.index()), p);
        }
    }

    #[test]
    fn map_covers_the_whole_plane_roughly_uniformly() {
        // Over many inputs every one of the 7-cell's points is hit (uniform coverage).
        let n = Plane::<F7>::N as usize;
        let mut seen = std::vec![false; n];
        for i in 0u32..2000 {
            let p = map_to_point::<F7>(label::COORD, &i.to_le_bytes());
            seen[p.index()] = true;
        }
        assert!(seen.iter().all(|&b| b), "every point should be reachable");
    }

    #[test]
    fn different_labels_give_different_points() {
        let coord = map_to_point::<F31>(label::COORD, b"same");
        let rdv = map_to_point::<F31>(label::RDV, b"same");
        // Overwhelmingly likely to differ (993 points); domain separation in action.
        assert_ne!(coord, rdv);
    }

    #[test]
    fn map_to_point_works_over_binary_field() {
        let p = map_to_point::<F256>(label::COORD, b"binary");
        assert_eq!(Point::<F256>::at(p.index()), p);
    }
}
