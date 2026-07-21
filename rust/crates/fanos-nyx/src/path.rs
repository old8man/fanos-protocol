//! Geometric flag paths — a NYX circuit as a chain of incident point–line pairs (spec §5.3).
//!
//! A NYX path is `p₀ ∈ L₁ ∋ p₁ ∈ L₂ ∋ p₂ …`: each hop is a **line** (a threshold group), and
//! adjacent lines meet at the relaying point (dual Steiner). Because `PGL(3,q)` acts
//! transitively on flags, a path built from uniformly-chosen relays is uniform over flags —
//! the property NYX relies on for unbiased selection, verifiable by algebra rather than by
//! trusting VRF weights. Relays are drawn deterministically from a seed (a per-circuit PRF),
//! so circuit construction is reproducible and testable.

use alloc::vec::Vec;

use blake3::OutputReader;

use fanos_field::Field;
use fanos_geometry::{Line, Plane, Point};
use fanos_primitives::hash::xof_reader;

/// The domain label for NYX path derivation.
const PATH_LABEL: &str = "FANOS-v1/nyx-path";

/// A NYX circuit: the relay points `r₀…r_L` (source … destination) and the `L` hop lines
/// `hop_k = r_k × r_{k+1}` (each a threshold group).
#[derive(Clone, Debug)]
pub struct Circuit<F: Field> {
    relays: Vec<Point<F>>,
    hops: Vec<Line<F>>,
}

/// Draw a uniform point index in `0..n` from the XOF stream (rejection-sampled, unbiased).
fn draw_index(reader: &mut OutputReader, n: u64) -> u64 {
    let bound = u64::MAX - (u64::MAX % n);
    loop {
        let mut buf = [0u8; 8];
        reader.fill(&mut buf);
        let v = u64::from_le_bytes(buf);
        if v < bound {
            return v % n;
        }
    }
}

/// Draw a uniform point satisfying `accept`, or `None` after too many rejections. Shared with the guard
/// module, which draws a distinct guard set from the same rejection-sampled stream.
pub(crate) fn draw_point<F: Field>(
    reader: &mut OutputReader,
    accept: impl Fn(&Point<F>) -> bool,
) -> Option<Point<F>> {
    let n = u64::from(Plane::<F>::N);
    for _ in 0..64 {
        let idx = draw_index(reader, n) as usize;
        let point = Point::<F>::at(idx);
        if accept(&point) {
            return Some(point);
        }
    }
    None
}

/// Build an `hops`-length NYX circuit from `source` to `dest`, with relays derived from `seed`
/// (spec §5.3). Returns `None` for a degenerate request (`hops == 0`, `source == dest`, or an
/// unrecoverable relay collision).
#[must_use]
pub fn build_circuit<F: Field>(
    source: Point<F>,
    dest: Point<F>,
    hops: usize,
    seed: &[u8],
) -> Option<Circuit<F>> {
    if hops == 0 || source == dest {
        return None;
    }
    let mut reader = xof_reader(PATH_LABEL, seed);
    let mut relays = Vec::with_capacity(hops + 1);
    relays.push(source);
    // Intermediate relays r₁ … r_{hops-1}, each distinct from its predecessor (so the hop line
    // exists) and — for the last one — from the destination.
    for k in 1..hops {
        let prev = *relays.get(k - 1)?;
        let avoid_dest = k == hops - 1;
        let point = draw_point::<F>(&mut reader, |p| *p != prev && (!avoid_dest || *p != dest))?;
        relays.push(point);
    }
    if *relays.last()? == dest {
        return None;
    }
    relays.push(dest);

    circuit_from_relays(relays)
}

/// Assemble a [`Circuit`] from an ordered relay chain, computing each hop line `r_k × r_{k+1}`.
/// `None` if fewer than two relays or any adjacent pair coincides (no unique join line).
fn circuit_from_relays<F: Field>(relays: Vec<Point<F>>) -> Option<Circuit<F>> {
    if relays.len() < 2 {
        return None;
    }
    let mut hop_lines = Vec::with_capacity(relays.len() - 1);
    for k in 0..relays.len() - 1 {
        hop_lines.push(relays.get(k)?.join(relays.get(k + 1)?)?);
    }
    Some(Circuit {
        relays,
        hops: hop_lines,
    })
}

/// Build an `hops`-length circuit whose **first hop is the fixed `guard`** — a stable, per-client entry
/// relay that bounds the predecessor attack (Wright et al.): `source → guard → r₂ … → dest`. The
/// guard-onward segment is an ordinary seed-derived circuit, so only the entry is pinned; the interior
/// still rotates per circuit. `None` for a degenerate request (`hops < 2`, or `source` equal to `guard`
/// or `dest`, or an unrecoverable relay collision).
#[must_use]
pub fn build_circuit_via_guard<F: Field>(
    source: Point<F>,
    guard: Point<F>,
    dest: Point<F>,
    hops: usize,
    seed: &[u8],
) -> Option<Circuit<F>> {
    if hops < 2 || source == guard || source == dest {
        return None;
    }
    // `guard → … → dest` is an ordinary derived circuit of one fewer hop; prepend the source.
    let inner = build_circuit(guard, dest, hops - 1, seed)?;
    let mut relays = Vec::with_capacity(inner.relays.len() + 1);
    relays.push(source);
    relays.extend_from_slice(&inner.relays);
    circuit_from_relays(relays)
}

impl<F: Field> Circuit<F> {
    /// The source (entry) point.
    #[must_use]
    pub fn source(&self) -> Point<F> {
        self.relays.first().copied().unwrap_or_else(|| Point::at(0))
    }

    /// The destination (exit) point.
    #[must_use]
    pub fn dest(&self) -> Point<F> {
        self.relays.last().copied().unwrap_or_else(|| Point::at(0))
    }

    /// The number of hops (threshold-line hops).
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// The hop lines (each a threshold group), from entry to exit.
    #[must_use]
    pub fn hops(&self) -> &[Line<F>] {
        &self.hops
    }

    /// The relay points `r₀…r_L`.
    #[must_use]
    pub fn relays(&self) -> &[Point<F>] {
        &self.relays
    }

    /// Whether this is a valid flag chain: each interior relay lies on both adjacent hop
    /// lines, the source lies on the first hop, and the destination on the last.
    #[must_use]
    pub fn is_valid_flag_chain(&self) -> bool {
        let l = self.hops.len();
        if self.relays.len() != l + 1 {
            return false;
        }
        for k in 0..l {
            let (Some(r0), Some(r1), Some(line)) =
                (self.relays.get(k), self.relays.get(k + 1), self.hops.get(k))
            else {
                return false;
            };
            if !r0.is_on(line) || !r1.is_on(line) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::{F7, F31};

    #[test]
    fn circuit_is_a_valid_flag_chain() {
        let source = Point::<F31>::at(0);
        let dest = Point::<F31>::at(500);
        let circuit = build_circuit(source, dest, 3, b"seed-1").unwrap();
        assert_eq!(circuit.hop_count(), 3);
        assert_eq!(circuit.source(), source);
        assert_eq!(circuit.dest(), dest);
        assert!(circuit.is_valid_flag_chain());
        // Source on first hop, dest on last hop (spec §5.3).
        assert!(source.is_on(&circuit.hops()[0]));
        assert!(dest.is_on(circuit.hops().last().unwrap()));
    }

    #[test]
    fn derivation_is_deterministic() {
        let s = Point::<F7>::at(0);
        let d = Point::<F7>::at(30);
        let a = build_circuit(s, d, 4, b"same").unwrap();
        let b = build_circuit(s, d, 4, b"same").unwrap();
        assert_eq!(a.relays(), b.relays());
        // A different seed almost surely differs.
        let c = build_circuit(s, d, 4, b"other").unwrap();
        assert_ne!(a.relays(), c.relays());
    }

    #[test]
    fn single_hop_is_the_direct_line() {
        let s = Point::<F7>::at(1);
        let d = Point::<F7>::at(2);
        let circuit = build_circuit(s, d, 1, b"x").unwrap();
        assert_eq!(circuit.hop_count(), 1);
        assert_eq!(circuit.hops()[0], s.join(&d).unwrap());
    }

    #[test]
    fn rejects_degenerate_requests() {
        let p = Point::<F7>::at(0);
        assert!(build_circuit(p, p, 3, b"x").is_none());
        assert!(build_circuit(p, Point::<F7>::at(1), 0, b"x").is_none());
    }

    #[test]
    fn paths_are_spread_over_the_plane() {
        // Distinct seeds explore many different relay sets (transitivity → uniform spread).
        use std::collections::HashSet;
        let s = Point::<F31>::at(0);
        let d = Point::<F31>::at(1);
        let mut interior = HashSet::new();
        for i in 0u32..200 {
            let c = build_circuit(s, d, 3, &i.to_le_bytes()).unwrap();
            interior.insert(c.relays()[1].index());
        }
        assert!(
            interior.len() > 20,
            "relays should spread widely, got {}",
            interior.len()
        );
    }
}
