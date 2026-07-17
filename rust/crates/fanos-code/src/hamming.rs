//! The Hamming(7,4) / Fano correspondence (spec §2.4, V10).
//!
//! The base cell `PG(2, 2)` **coincides** with the Hamming(7,4) code: its 7 lines are
//! exactly the 7 weight-3 codewords. This is what gives every FANOS cell an *innate*
//! single-error-locating code — the same structure that makes it a native quantum
//! error-correcting code (the Steane code is `CSS(Hamming, Hamming)`).
//!
//! Positions are numbered `1..=7`; a 7-bit word packs position `p` into bit `p-1`. The
//! **syndrome** of a word is the XOR of the positions of its set bits, so a single error at
//! position `p` yields syndrome `p` — the position's own address. This is the arithmetic
//! behind the DIAKRISIS localizer (spec §6.3, and [`crate::syndrome`]).

/// Number of code positions / Fano points.
pub const N: usize = 7;

/// The parity-check syndrome of a 7-bit word: the XOR of the addresses (`1..=7`) of its set
/// bits. Returns a value in `0..=7`. A single error at position `p` gives syndrome `p`.
///
/// Implemented branchlessly as three parity checks — the three rows of the Hamming
/// parity-check matrix `H` (positions grouped by which bit of their address is set).
#[inline]
#[must_use]
pub const fn syndrome(word: u8) -> u8 {
    let w = (word & 0x7F) as u32;
    // Row r collects positions whose address has bit r set:
    //   bit0 → addresses {1,3,5,7} = mask 0x55
    //   bit1 → addresses {2,3,6,7} = mask 0x66
    //   bit2 → addresses {4,5,6,7} = mask 0x78
    let s0 = (w & 0x55).count_ones() & 1;
    let s1 = (w & 0x66).count_ones() & 1;
    let s2 = (w & 0x78).count_ones() & 1;
    (s0 | (s1 << 1) | (s2 << 2)) as u8
}

/// Locate a single error: returns the position `1..=7` whose flip explains the syndrome, or
/// `None` if the word is a codeword (syndrome `0`).
///
/// For an all-zero-or-single-error input this is exact; for a general word it returns the
/// coset leader (the single flip that reaches the nearest codeword), which is the standard
/// Hamming decoding.
#[inline]
#[must_use]
pub const fn locate_single(word: u8) -> Option<u8> {
    match syndrome(word) {
        0 => None,
        p => Some(p),
    }
}

/// Whether a 7-bit word is a Hamming(7,4) codeword (syndrome zero).
#[inline]
#[must_use]
pub const fn is_codeword(word: u8) -> bool {
    syndrome(word) == 0
}

#[allow(clippy::indexing_slicing)] // const builder indexes by a bounded counter
const fn build_codewords() -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut count = 0;
    let mut w = 0u8;
    loop {
        if is_codeword(w) {
            out[count] = w;
            count += 1;
        }
        if w == 0x7F {
            break;
        }
        w += 1;
    }
    assert!(count == 16, "Hamming(7,4) has exactly 16 codewords");
    out
}

#[allow(clippy::indexing_slicing)]
const fn build_weight3() -> [u8; 7] {
    let all = build_codewords();
    let mut out = [0u8; 7];
    let mut count = 0;
    let mut i = 0;
    while i < 16 {
        if all[i].count_ones() == 3 {
            out[count] = all[i];
            count += 1;
        }
        i += 1;
    }
    assert!(
        count == 7,
        "there are exactly 7 weight-3 codewords = 7 Fano lines"
    );
    out
}

/// All 16 Hamming(7,4) codewords (the words of syndrome zero).
pub const CODEWORDS: [u8; 16] = build_codewords();

/// The 7 weight-3 codewords — **the 7 Fano lines** as position bitmasks (spec §2.4, V10).
pub const LINE_CODEWORDS: [u8; 7] = build_weight3();

/// The address of a Fano geometric point (from [`fanos_geometry::fano`]): the packed value
/// `4x + 2y + z ∈ 1..=7` of its `GF(2)` coordinates. Collinear points have addresses XOR-ing
/// to zero, so a geometric line maps to a weight-3 codeword — the concrete V10 link between
/// the geometry crate's plane and this code.
#[must_use]
pub fn point_address(point_index: usize) -> u8 {
    let [x, y, z] = fanos_geometry::fano::POINT_COORDS
        .get(point_index)
        .copied()
        .unwrap_or([0, 0, 0]);
    (4 * x + 2 * y + z) as u8
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn syndrome_matches_address_xor_definition() {
        // Cross-check the branchless syndrome against the plain XOR-of-addresses definition.
        for word in 0u8..=0x7F {
            let mut expect = 0u8;
            for i in 0..7 {
                if word & (1 << i) != 0 {
                    expect ^= (i + 1) as u8;
                }
            }
            assert_eq!(syndrome(word), expect, "word {word:#09b}");
        }
    }

    #[test]
    fn single_error_localizes_to_its_position() {
        // V13 core: a single error at position p produces syndrome p.
        for p in 1u8..=7 {
            let word = 1u8 << (p - 1);
            assert_eq!(syndrome(word), p);
            assert_eq!(locate_single(word), Some(p));
        }
        assert_eq!(locate_single(0), None);
    }

    #[test]
    fn code_has_16_codewords_and_7_lines() {
        // V10: the Fano plane = Hamming(7,4); 16 codewords, 7 of weight 3 = the 7 lines.
        assert_eq!(CODEWORDS.len(), 16);
        assert_eq!(LINE_CODEWORDS.len(), 7);
        for &cw in &LINE_CODEWORDS {
            assert_eq!(cw.count_ones(), 3);
            assert!(is_codeword(cw));
        }
        // Minimum distance 3: every nonzero codeword has weight >= 3.
        for &cw in &CODEWORDS {
            assert!(cw == 0 || cw.count_ones() >= 3);
        }
    }

    #[test]
    fn geometric_lines_are_weight3_codewords() {
        // V10 link: map each geometry Fano line's 3 points to their addresses; the resulting
        // position bitmask must be one of the 7 weight-3 codewords.
        use fanos_geometry::fano;
        for line in &fano::LINE_POINTS {
            let mut mask = 0u8;
            for &pt in line {
                let addr = point_address(pt as usize);
                assert!((1..=7).contains(&addr));
                mask |= 1 << (addr - 1);
            }
            assert!(
                LINE_CODEWORDS.contains(&mask),
                "geometric line {line:?} → mask {mask:#09b} is not a weight-3 codeword"
            );
        }
    }
}
