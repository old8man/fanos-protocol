//! Fault localization on the Fano cell — the `21 → 7 → 3 → 1` pyramid (spec §6.3, V13/V21).
//!
//! When a cell's health degrades, DIAKRISIS localizes the culprit by compressing 21 pairwise
//! readings into 7 line-themes, then (for a single fault) into a 3-bit syndrome that is the
//! **binary address of the damaged node**. This module implements the two decode layers:
//!
//! * [`syndrome3`] — the 3-bit fast path: localizes **one** degraded node (V13).
//! * [`decode_themes`] — the 7-line-theme layer: localizes **two** degraded nodes exactly
//!   (V21), because all 21 pairs flag distinct line-sets; three or more saturate and escalate.
//!
//! Health is a 7-bit mask over Fano point indices `0..7` (bit `i` set ⇒ point `i` degraded).

use fanos_geometry::fano;

use crate::hamming::point_address;

/// A localization verdict from the health/theme observation (spec §6.3, §6.9).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Fault {
    /// No degraded node detected.
    Healthy,
    /// Exactly one degraded node, at the given Fano point index (`0..7`).
    Single(usize),
    /// Two degraded nodes, resolved by the 7-theme layer.
    Pair(usize, usize),
    /// Three or more faults: the single-cell decoder is saturated; escalate to the parent
    /// cell (spec §6.3 stratification). Carries the observed line-theme flags.
    Escalate(u8),
}

/// The largest fault set this cell can **name**, and it is the plane's order: `q` on `PG(2, q)`, so
/// **2** here.
///
/// [`theme_flags`] reports, per line, whether that line holds a degraded node, and [`decode_themes`]
/// inverts it. **That inversion is unique exactly on sets of size `≤ q`**, by the plane's own axiom: if
/// two degraded sets share a theme and `p` lies in one but not the other, every one of the `q + 1` lines
/// through `p` must meet the other set — and those lines pairwise meet only at `p`, so they demand
/// `q + 1` **distinct** points of it. A collision therefore needs `q + 1` faults.
///
/// The first ambiguous size is exactly `q + 1`, and its witness is constructed rather than searched: a
/// **line** is a minimum blocking set, so a line and that line plus any point both meet every line of the
/// plane and share a theme. So [`Fault::Escalate`] is not a heuristic cut-off — it fires at the first
/// size where the answer is provably not unique
/// (`the_first_ambiguous_fault_set_is_a_line_plus_a_point`).
///
/// **The cell is the only projective order that can name every fault it survives**, which is why
/// DIAKRISIS is defined on a Fano cell rather than on the transport plane: naming grows as `q` and
/// surviving as `⌊(q²+q)/3⌋`, so `q ≥ ⌊(q²+q)/3⌋` reduces to `q ≤ 2` and the two coincide exactly once
/// (`the_base_cell_is_the_only_order_that_can_name_every_fault_it_survives`).
pub const LOCALIZABLE_FAULTS: usize = fano::LINE_SIZE - 1;

/// The 3-bit syndrome of a degraded-node mask: the XOR of the **addresses** (packed
/// `GF(2)` coordinates, `1..=7`) of the degraded points. A single degraded point `i` yields
/// its own address, which localizes it (spec §6.3, V13).
#[inline]
#[must_use]
pub fn syndrome3(degraded: u8) -> u8 {
    let mut s = 0u8;
    let mut i = 0;
    while i < 7 {
        if degraded & (1 << i) != 0 {
            s ^= point_address(i);
        }
        i += 1;
    }
    s
}

/// The point index whose address is `a`, or `None` if `a` is not a valid address.
#[must_use]
pub fn index_of_address(a: u8) -> Option<usize> {
    (0..7).find(|&i| point_address(i) == a)
}

/// The 7-bit **line-theme** vector: bit `l` is set iff line `l` contains a degraded node
/// (spec §6.3, the `21 → 7` stage). A single fault flags exactly 3 lines (its pencil); a
/// pair flags exactly 5.
#[inline]
#[must_use]
pub fn theme_flags(degraded: u8) -> u8 {
    let mut flags = 0u8;
    let mut l = 0;
    while l < fano::N {
        // Safe: fano::LINE_POINTS is length 7, l < 7.
        if let Some(points) = fano::LINE_POINTS.get(l) {
            for &p in points {
                if degraded & (1 << p) != 0 {
                    flags |= 1 << l;
                    break;
                }
            }
        }
        l += 1;
    }
    flags
}

/// The 3 lines through a point, as a line-theme bitmask (the flags a single fault raises).
#[must_use]
fn single_signature(point: usize) -> u8 {
    theme_flags(1 << point)
}

/// Decode a fault from the observed **line-theme flags** alone — the realistic DIAKRISIS
/// input (spec §6.3). Resolves zero, one, or two faults exactly; escalates on three+.
///
/// * `0` flags → [`Fault::Healthy`].
/// * flags equal to some point's 3-line signature → [`Fault::Single`].
/// * flags equal to some pair's 5-line signature → [`Fault::Pair`] (all 21 pairs distinct).
/// * anything else → [`Fault::Escalate`].
#[must_use]
pub fn decode_themes(flags: u8) -> Fault {
    if flags == 0 {
        return Fault::Healthy;
    }
    for i in 0..7 {
        if single_signature(i) == flags {
            return Fault::Single(i);
        }
    }
    for i in 0..7 {
        for j in (i + 1)..7 {
            if theme_flags((1 << i) | (1 << j)) == flags {
                return Fault::Pair(i, j);
            }
        }
    }
    Fault::Escalate(flags)
}

/// Localize directly from a known degraded-node mask (simulation / oracle view). Demonstrates
/// the stratified capability: 1 fault via the 3-bit syndrome, 2 via the theme layer, 3+
/// escalate (spec §6.3).
#[must_use]
pub fn locate(degraded: u8) -> Fault {
    match (degraded & 0x7F).count_ones() as usize {
        0 => Fault::Healthy,
        1 => {
            let addr = syndrome3(degraded);
            index_of_address(addr).map_or(Fault::Escalate(theme_flags(degraded)), Fault::Single)
        }
        // The cap is stated once, by [`LOCALIZABLE_FAULTS`], rather than repeated as a literal here.
        n if n <= LOCALIZABLE_FAULTS => decode_themes(theme_flags(degraded)),
        _ => Fault::Escalate(theme_flags(degraded)),
    }
}

/// The seven UHM sectors labelling the Fano positions `1..=7` (spec §6.3, V13 table). Used
/// for the human-readable syndrome table; the address ordering `A..U = 1..7` reproduces the
/// specification's `σ` column exactly.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[allow(missing_docs)] // the seven sector letters are self-describing
pub enum Sector {
    A,
    S,
    D,
    L,
    E,
    O,
    U,
}

/// `Sector::ALL` must list every sector, or the conformance sweep that iterates it silently checks a
/// subset and reports the same green it would for full coverage.
const _: () = assert!(
    Sector::ALL.len() == core::mem::variant_count::<Sector>(),
    "a Sector variant is missing from Sector::ALL, so every reader that enumerates is blind to it"
);

impl Sector {
    /// All seven sectors in address order.
    pub const ALL: [Sector; 7] = [
        Sector::A,
        Sector::S,
        Sector::D,
        Sector::L,
        Sector::E,
        Sector::O,
        Sector::U,
    ];

    /// The sector's Hamming address `1..=7`.
    #[inline]
    #[must_use]
    pub const fn address(self) -> u8 {
        self as u8 + 1
    }

    /// The sector's letter.
    #[inline]
    #[must_use]
    pub const fn label(self) -> char {
        match self {
            Sector::A => 'A',
            Sector::S => 'S',
            Sector::D => 'D',
            Sector::L => 'L',
            Sector::E => 'E',
            Sector::O => 'O',
            Sector::U => 'U',
        }
    }

    /// The 3-bit syndrome written **LSB-first** (spec §6.3 `σ` column): `[bit0, bit1, bit2]`
    /// of the address. Sector `O` (address 6) gives `[0,1,1]` — the `011` of the table.
    #[inline]
    #[must_use]
    pub const fn syndrome_lsb(self) -> [u8; 3] {
        let a = self.address();
        [a & 1, (a >> 1) & 1, (a >> 2) & 1]
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn v13_syndrome_table_matches_spec() {
        // spec §6.3 table: (sector, address, σ as written LSB-first).
        let table: [(Sector, u8, &str); 7] = [
            (Sector::A, 1, "100"),
            (Sector::S, 2, "010"),
            (Sector::D, 3, "110"),
            (Sector::L, 4, "001"),
            (Sector::E, 5, "101"),
            (Sector::O, 6, "011"),
            (Sector::U, 7, "111"),
        ];
        for (sector, address, sigma) in table {
            assert_eq!(sector.address(), address);
            let bits = sector.syndrome_lsb();
            let rendered: String = bits.iter().map(|b| char::from(b'0' + b)).collect();
            assert_eq!(rendered, sigma, "σ for {}", sector.label());
        }
    }

    #[test]
    fn single_fault_localizes_every_node() {
        // V13: a single degraded node is pinned exactly, for all 7 points.
        for i in 0..7 {
            let degraded = 1u8 << i;
            assert_eq!(locate(degraded), Fault::Single(i));
            // and via the realistic theme-only decoder
            assert_eq!(decode_themes(theme_flags(degraded)), Fault::Single(i));
            // a single fault flags exactly its 3 lines
            assert_eq!(theme_flags(degraded).count_ones(), 3);
        }
    }

    #[test]
    fn two_faults_resolve_via_theme_layer() {
        // V21: all 21 pairs produce distinct 5-line signatures and are localized exactly.
        use std::collections::HashSet;
        let mut sigs = HashSet::new();
        for i in 0..7 {
            for j in (i + 1)..7 {
                let degraded = (1u8 << i) | (1u8 << j);
                let flags = theme_flags(degraded);
                assert_eq!(flags.count_ones(), 5, "a pair flags exactly 5 lines");
                assert!(sigs.insert(flags), "pair signatures must be distinct");
                match decode_themes(flags) {
                    Fault::Pair(a, b) => assert_eq!((a, b), (i, j)),
                    other => panic!("expected Pair({i},{j}), got {other:?}"),
                }
            }
        }
        assert_eq!(sigs.len(), 21);
    }

    #[test]
    fn three_faults_escalate() {
        // ≥3 faults saturate the single-cell decoder (spec §6.3 stratification).
        let degraded = 0b0000_0111; // points 0,1,2
        assert!(matches!(locate(degraded), Fault::Escalate(_)));
    }

    #[test]
    fn worked_example_node_o() {
        // spec §6.3 worked example: node O (address 6) degrades → syndrome addresses to O.
        let o = index_of_address(6).unwrap();
        assert_eq!(syndrome3(1 << o), 6);
        assert_eq!(locate(1 << o), Fault::Single(o));
    }

    /// **The base cell is the only projective order that can name every fault it survives**, and that is
    /// why DIAKRISIS is defined on a Fano cell rather than on the transport plane it sits in.
    ///
    /// A cell of order `q` names `q` ([`LOCALIZABLE_FAULTS`]) and survives `f = ⌊(q²+q)/3⌋`;
    /// `q ≥ ⌊(q²+q)/3⌋` reduces to `3q ≥ q² + q`, i.e. `q ≤ 2`. Naming grows linearly and surviving
    /// quadratically, so they coincide exactly once. Above the base order a cell tolerates more faults
    /// than it can point at, and `Escalate` — the parent — becomes the normal outcome rather than the
    /// edge case. Asserted as an equivalence over a range of orders, so the *uniqueness* is what fails if
    /// either side moves, not merely the `q = 2` value.
    #[test]
    fn the_base_cell_is_the_only_order_that_can_name_every_fault_it_survives() {
        for q in 2usize..64 {
            let n = q * q + q + 1;
            let survives = fanos_geometry::fault_budget(n);
            assert_eq!(
                q >= survives,
                q == 2,
                "q={q}: names {q}, survives {survives} — the coincidence must be unique to the base cell"
            );
        }
        assert_eq!(
            LOCALIZABLE_FAULTS,
            fanos_geometry::fault_budget(fano::N),
            "and on this cell the two ARE the same number, which is the whole design"
        );
    }

    /// The cap is `q` because `q + 1` is provably ambiguous, and the witness is **constructed**: a line
    /// is a minimum blocking set, so it meets every line of the plane, and adding any point to it changes
    /// no theme bit. `Escalate` is therefore the first size at which no decoder could do better.
    #[test]
    fn the_first_ambiguous_fault_set_is_a_line_plus_a_point() {
        let line = fano::LINE_POINTS[0].iter().fold(0u8, |m, &p| m | (1 << p));
        assert_eq!(line.count_ones() as usize, LOCALIZABLE_FAULTS + 1, "a line holds q+1 points");
        assert_eq!(theme_flags(line), 0x7F, "and, being a blocking set, meets every line");
        // The complement of a line is the hyperoval `lrc::is_hyperoval_fano` names, and its size is the
        // reason a point outside always exists — asserted rather than assumed.
        let outside: Vec<u8> = (0..7u8).filter(|i| line & (1 << i) == 0).collect();
        assert_eq!(
            outside.len(),
            fano::N - (LOCALIZABLE_FAULTS + 1),
            "a line's complement holds the remaining points"
        );
        assert_eq!(
            theme_flags(line | (1 << outside[0])),
            theme_flags(line),
            "so one more fault is invisible in the theme vector"
        );
        assert!(
            matches!(decode_themes(theme_flags(line)), Fault::Escalate(_)),
            "and the decoder escalates rather than naming one of the two"
        );
    }

    /// The positive half, so the cap is pinned from both sides: every set **within** it has a theme of
    /// its own and decodes back to exactly itself.
    #[test]
    fn every_fault_set_within_the_cap_decodes_to_itself() {
        let mut by_theme = alloc::collections::BTreeMap::new();
        for mask in 1u8..0x80 {
            if (mask.count_ones() as usize) > LOCALIZABLE_FAULTS {
                continue;
            }
            let theme = theme_flags(mask);
            assert!(
                by_theme.insert(theme, mask).is_none(),
                "two sets within the cap share theme {theme:#x}"
            );
            let back = match decode_themes(theme) {
                Fault::Single(i) => 1u8 << i,
                Fault::Pair(i, j) => (1u8 << i) | (1u8 << j),
                other => panic!("{mask:#x} is within the cap but decoded as {other:?}"),
            };
            assert_eq!(back, mask, "decoded set differs from the injected one");
        }
    }
}
