//! The byte-level projective erasure codec — the `[7,3,4]` simplex dual of Hamming(7,4)
//! (spec §L4; V9, V20).
//!
//! [`crate::lrc`] is a **recoverability oracle**: `peel_fano` decides *which* erasure
//! patterns recover, by peeling the Fano line parities down to bits. This module is the
//! actual data path — it encodes a value into `N = 7` per-point shards and decodes it back
//! from any recoverable subset, reusing that same peeling closure to fill in bytes instead
//! of only clearing lost-bits.
//!
//! ## The construction: why this is the simplex dual of Hamming
//!
//! Hamming(7,4) ([`crate::hamming`]) has parity-check matrix `H`, a `3×7` `GF(2)` matrix
//! whose column for point `p` is `p`'s own address ([`crate::hamming::point_address`]) —
//! that is exactly why a single error at `p` produces syndrome `p`
//! ([`crate::hamming::syndrome`]). The classical Hamming/simplex duality says the **dual**
//! of a `[7,4,3]` code is a `[7,3,4]` code whose *generator* matrix is that same `H`. Taking
//! `H`'s columns as this code's generator means: **a point's shard is the `GF(2)`-linear
//! combination of the `K = 3` data symbols selected by that point's own coordinate triple**
//! ([`fanos_geometry::fano::POINT_COORDS`]):
//!
//! ```text
//! shard[p] = Σ_{r ∈ {x,y,z}} coord_r(p) · data[r]        (coord_r(p) ∈ {0, 1})
//! ```
//!
//! Because collinear points' coordinates XOR to zero — the address-XOR law already exploited
//! by [`crate::hamming::syndrome`] and [`crate::syndrome::syndrome3`] — **every one of the 7
//! Fano lines is a parity check of this code**: for any line `{p, q, r}` and any message,
//! `shard[p] ⊕ shard[q] ⊕ shard[r] = 0`. That is *exactly* the equation
//! [`crate::lrc::peel_fano`] already peels: this module reuses that closure's control flow
//! verbatim ([`peel_group`]), so `reconstruct` inherits its exact recoverability boundary —
//! any `≤3` simultaneous losses, and among `4`-losses precisely the non-hyperovals (spec
//! §6.3 note, V20; [`crate::is_hyperoval_fano`]).
//!
//! Restricted to `{0,1}`-valued data this is the textbook binary `[7,3,4]` simplex code:
//! `2³ − 1 = 7` nonzero codewords, each of weight exactly `4`, whose support is *exactly* a
//! hyperoval — the complement of the line polar to the message (tested below as
//! `bit_plane_codewords_have_weight_four_and_support_a_hyperoval`). A general **byte**
//! codeword is 8 of these binary codewords running in independent bit-planes simultaneously.
//! That is precisely why plain byte XOR — not a `GF(256)` field *multiplication* — is the
//! correct arithmetic, not merely a convenient shortcut: erasure is byte-granular (a shard
//! is present or absent as a whole byte), so all 8 planes share one *identical*
//! recoverability boundary, and peeling them together with a single byte XOR is exactly
//! equivalent to peeling each plane separately. This is sound because `GF(256)`'s addition
//! (`fanos_field::F256::add`) is *defined* as XOR (cross-checked exhaustively below by
//! `byte_xor_is_gf256_addition`), and no coefficient of `H` is ever anything but `0` or `1`,
//! so multiplication never actually arises.
//!
//! ## Layout
//!
//! `data` is padded PKCS#7-style to a multiple of `K` bytes — always padded, even when
//! already aligned, so decoding stays unambiguous on every length including zero — and
//! striped into groups of `K` data symbols; group `g`'s `K` bytes are coded into `N` shard
//! bytes, and `shards[p][g]` is group `g`'s coded value at point `p`. [`encode`] returns the
//! `N` shards; [`reconstruct`] takes `N` optional shards (an erased point is `None`), peels
//! every stripe independently, and returns the depadded payload — or `None` the instant any
//! stripe's erasure mask is not [`crate::lrc::is_recoverable_fano`], or the shards are
//! malformed (inconsistent lengths, invalid padding).
//!
//! ## Achieved parameters vs. the spec's ideal — a reconciliation note
//!
//! [`crate::lrc::redundancy`] reports `(q+1)/q` (`1.5` at the base cell `q = 2`), which is
//! the **availability-1** ideal: the storage cost of a scheme that tolerates exactly one loss
//! per line and nothing more. This module's actual code has availability `q + 1 = 3` — a
//! lost point recovers from **any one** of its 3 lines, reading only that line's other `q = 2`
//! members (`availability_three_repairs_any_lost_point_from_any_one_of_its_lines`, below) —
//! at the much stronger guarantee of `≤3` *simultaneous* losses cell-wide. That strength
//! costs more: the true redundancy is the code rate's reciprocal, `N/K = 7/3 ≈ 2.33×`
//! (`parameters_match_the_simplex_dual_of_hamming`, below) — still far below `7×` full
//! replication, but well above the `1.5×` figure. `lrc::redundancy()` is deliberately left
//! unchanged (this module must not silently reinterpret it); the specification text's §L4
//! headline redundancy claim needs reconciling against the concrete availability-3 code that
//! actually delivers the `≤3`-crash guarantee it also advertises. There is likewise no
//! separate "§L4.1" heading in the specification — §L4 is a single flat section — so this
//! module cites it as `§L4` throughout rather than a subsection that does not exist.

use alloc::vec::Vec;

use fanos_geometry::fano;

/// Shard count: one symbol per Fano point, `N = 7` (spec §L4).
pub const N: usize = fano::N;

/// Data symbols per stripe: the dimension of the `[7,3,4]` simplex dual of Hamming(7,4).
pub const K: usize = 3;

/// The `K` Fano points carrying a data symbol **verbatim** under [`encode_group`]: point
/// `BASIS_POINTS[r]` has coordinate triple `e_r` (all-zero but for a `1` in slot `r`), so its
/// shard equals `data[r]` exactly. [`decode_group`] reads these back once every shard is
/// known — the inverse of the systematic frame this code happens to fall into.
const BASIS_POINTS: [usize; K] = build_basis_points();

#[allow(clippy::indexing_slicing)] // const builder: `p`/`r`/`i` are loop-bounded, matches fano.rs's own table builders
const fn build_basis_points() -> [usize; K] {
    let mut out = [0usize; K];
    let mut r = 0;
    while r < K {
        let mut p = 0;
        while p < fano::N {
            let c = fano::POINT_COORDS[p];
            let mut i = 0;
            let mut is_e_r = true;
            while i < 3 {
                let want = if i == r { 1 } else { 0 };
                if c[i] != want {
                    is_e_r = false;
                }
                i += 1;
            }
            if is_e_r {
                out[r] = p;
                break;
            }
            p += 1;
        }
        r += 1;
    }
    out
}

/// Encode one stripe of `K` data symbols into the `N` shards of the simplex code:
/// `shard[p] = Σ_{r : coord_r(p) = 1} data[r]` (XOR — see the module doc-comment).
fn encode_group(data: [u8; K]) -> [u8; N] {
    let mut out = [0u8; N];
    for (p, slot) in out.iter_mut().enumerate() {
        let Some(coords) = fano::POINT_COORDS.get(p) else {
            continue;
        };
        let mut value = 0u8;
        for (r, &c) in coords.iter().enumerate() {
            if c != 0
                && let Some(&d) = data.get(r)
            {
                value ^= d;
            }
        }
        *slot = value;
    }
    out
}

/// Recover the `K` data symbols from a **fully-known** stripe of `N` shard bytes, by reading
/// the systematic [`BASIS_POINTS`] verbatim — the inverse of [`encode_group`].
fn decode_group(symbols: [u8; N]) -> [u8; K] {
    let mut out = [0u8; K];
    for (r, slot) in out.iter_mut().enumerate() {
        if let Some(&p) = BASIS_POINTS.get(r) {
            *slot = symbols.get(p).copied().unwrap_or(0);
        }
    }
    out
}

/// The erasure mask of a stripe: bit `p` set iff symbol `p` is unknown.
fn mask_of(symbols: &[Option<u8>; N]) -> u8 {
    let mut mask = 0u8;
    for (p, s) in symbols.iter().enumerate() {
        if s.is_none() {
            mask |= 1 << p;
        }
    }
    mask
}

/// Peel-decode one stripe's `N` optional shard bytes via the Fano line parities, filling in
/// every recoverable symbol **in place**. Mirrors [`crate::lrc::peel_fano`]'s closure exactly
/// — same iteration order, same "exactly one loss on this line" test, same `lost &=
/// !lost_on_line` update — but carries values instead of only a lost-mask. Returns the final
/// stopping-set mask (`0` iff every symbol was recovered); `reconstruct` gates on
/// [`crate::lrc::is_recoverable_fano`] *first* (cheap, mask-only, the single source of truth
/// for the recoverability boundary) and only then runs this to materialize bytes — the two
/// are cross-checked exhaustively in `peel_group_stopping_set_matches_peel_fano_exhaustively`.
fn peel_group(symbols: &mut [Option<u8>; N]) -> u8 {
    let mut lost = mask_of(symbols);
    loop {
        let mut progressed = false;
        for l in 0..fano::N {
            let Some(&line_mask) = fano::INCIDENCE.get(l) else {
                continue;
            };
            let lost_on_line = line_mask & lost;
            if lost_on_line.is_power_of_two() {
                // Exactly one loss on this line: rebuild it by XOR-ing the other two (the
                // line's parity check, spec §2.4/§L4).
                let missing = lost_on_line.trailing_zeros() as usize;
                let mut value = 0u8;
                for p in 0..fano::N {
                    if line_mask & (1 << p) != 0
                        && p != missing
                        && let Some(Some(byte)) = symbols.get(p).copied()
                    {
                        value ^= byte;
                    }
                }
                if let Some(slot) = symbols.get_mut(missing) {
                    *slot = Some(value);
                }
                lost &= !lost_on_line;
                progressed = true;
            }
        }
        if !progressed {
            return lost;
        }
    }
}

/// Pad `data` to a multiple of `K` bytes, PKCS#7-style: append `p` bytes of value `p`, where
/// `p = K − (len mod K)`, or a full padding group of `K` when `len` is already a multiple of
/// `K` — always padding (even the empty input) keeps [`unpad`] unambiguous.
fn pad(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + K);
    out.extend_from_slice(data);
    let rem = out.len() % K;
    let pad_len = if rem == 0 { K } else { K - rem };
    for _ in 0..pad_len {
        out.push(pad_len as u8);
    }
    out
}

/// The inverse of [`pad`]: strip and validate the trailing padding. Returns `None` on
/// malformed padding (wrong length or inconsistent bytes) rather than guessing — a corrupt
/// tail must not be silently misreported as valid data.
fn unpad(mut data: Vec<u8>) -> Option<Vec<u8>> {
    let pad_len = usize::from(*data.last()?);
    if pad_len == 0 || pad_len > K || pad_len > data.len() {
        return None;
    }
    let start = data.len() - pad_len;
    if data.get(start..)?.iter().any(|&b| usize::from(b) != pad_len) {
        return None;
    }
    data.truncate(start);
    Some(data)
}

/// Erasure-encode `data` into the `N = 7` point-shards of the projective simplex code (spec
/// §L4). See the module doc-comment for the padding/striping layout.
#[must_use]
pub fn encode(data: &[u8]) -> [Vec<u8>; N] {
    let padded = pad(data);
    let groups = padded.len() / K;
    let mut shards: [Vec<u8>; N] = core::array::from_fn(|_| Vec::with_capacity(groups));
    let (chunks, _remainder) = padded.as_chunks::<K>(); // `pad` guarantees an empty remainder
    for &group in chunks {
        let coded = encode_group(group);
        for (p, shard) in shards.iter_mut().enumerate() {
            if let Some(&byte) = coded.get(p) {
                shard.push(byte);
            }
        }
    }
    shards
}

/// Reconstruct the original payload from `N = 7` point-shards, any of which may be erased
/// (`None`). Peel-decodes each stripe independently via the Fano line parities
/// ([`peel_group`]); returns `None` if any stripe's erasure mask is not
/// [`crate::lrc::is_recoverable_fano`] (spec §6.3, V20), or if the shards are malformed
/// (inconsistent lengths, or padding that fails to validate).
#[must_use]
pub fn reconstruct(shards: &[Option<Vec<u8>>; N]) -> Option<Vec<u8>> {
    let groups = shards.iter().find_map(|s| s.as_ref().map(Vec::len))?;
    if shards.iter().flatten().any(|s| s.len() != groups) {
        return None; // malformed: shards must agree on stripe count
    }
    let mut out = Vec::with_capacity(groups * K);
    for g in 0..groups {
        let mut symbols: [Option<u8>; N] = [None; N];
        for (p, slot) in symbols.iter_mut().enumerate() {
            *slot = shards
                .get(p)
                .and_then(|s| s.as_ref())
                .and_then(|s| s.get(g))
                .copied();
        }
        if !crate::lrc::is_recoverable_fano(mask_of(&symbols)) {
            return None;
        }
        let remaining = peel_group(&mut symbols);
        debug_assert_eq!(
            remaining, 0,
            "is_recoverable_fano guarantees a full peel closure"
        );
        if remaining != 0 {
            return None; // unreachable given the guard above; defensive, not a panic
        }
        let mut resolved = [0u8; N];
        for (p, slot) in resolved.iter_mut().enumerate() {
            *slot = symbols.get(p).copied().flatten().unwrap_or(0);
        }
        out.extend_from_slice(&decode_group(resolved));
    }
    unpad(out)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::{F256, Field};

    #[test]
    fn parameters_match_the_simplex_dual_of_hamming() {
        assert_eq!(N, 7);
        assert_eq!(K, 3);
        // Stored size is exactly N * groups, where `pad` always appends 1..=K bytes (module
        // doc-comment: PKCS#7-style, padded even when already aligned, so a 300-byte input —
        // itself a multiple of K — gets a full extra pad group: 303 padded bytes, 101 groups.
        let data = alloc::vec![7u8; 300];
        let shards = encode(&data);
        let stored: usize = shards.iter().map(Vec::len).sum();
        assert_eq!(stored, N * 101, "7 shards of 101 stripes each");
        // The N/K = 7/3 ≈ 2.33× headline figure (vs. 7× full replication, and vs.
        // lrc::redundancy(2) = 1.5×, the availability-1 ideal — module doc-comment's
        // reconciliation note) is the asymptotic rate as the fixed 1..=K padding overhead
        // vanishes relative to a growing payload.
        let large = alloc::vec![7u8; 300_000];
        let large_shards = encode(&large);
        let large_stored: usize = large_shards.iter().map(Vec::len).sum();
        let ratio = large_stored as f64 / large.len() as f64;
        assert!((ratio - 7.0 / 3.0).abs() < 1e-4, "ratio = {ratio}");
    }

    #[test]
    fn availability_three_repairs_any_lost_point_from_any_one_of_its_lines() {
        // V9/§L4: availability q+1=3, locality q=2 — a lost point recovers from ANY ONE of
        // its 3 lines, reading only that line's other 2 members; the rest of the cell is
        // irrelevant to that one repair.
        let full = encode_group([11u8, 22, 33]);
        for lost in 0..fano::N {
            let Some(lines) = fano::POINT_LINES.get(lost) else {
                continue;
            };
            for &line in lines {
                let Some(&line_mask) = fano::INCIDENCE.get(line as usize) else {
                    continue;
                };
                let mut symbols: [Option<u8>; N] = [None; N];
                for p in 0..fano::N {
                    if line_mask & (1 << p) != 0
                        && p != lost
                        && let Some(slot) = symbols.get_mut(p)
                    {
                        *slot = full.get(p).copied();
                    }
                }
                peel_group(&mut symbols);
                assert_eq!(
                    symbols.get(lost).copied().flatten(),
                    full.get(lost).copied(),
                    "point {lost} must recover from line {line}"
                );
            }
        }
    }

    #[test]
    fn byte_xor_is_gf256_addition() {
        // Justifies operating byte-wise (module doc-comment): F256's `add` is XOR (fanos-field
        // Gf2m's mask is a no-op at M=8), so encoding via plain `^` on bytes IS this code's
        // GF(256) arithmetic, not an ad hoc shortcut. Exhaustive over both operands.
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(a ^ b, F256::add(u32::from(a), u32::from(b)) as u8);
            }
        }
    }

    #[test]
    fn encode_group_decode_group_are_inverses() {
        for m in [
            [0u8, 0, 0],
            [1, 0, 0],
            [0, 1, 0],
            [0, 0, 1],
            [255, 128, 7],
            [1, 2, 3],
        ] {
            assert_eq!(decode_group(encode_group(m)), m);
        }
    }

    #[test]
    fn every_line_is_a_parity_check_of_the_code() {
        // The defining property (module doc-comment): for ANY message, the 3 shard bytes on
        // any Fano line XOR to zero — the 7 lines literally ARE this code's parity checks.
        for m in [[1u8, 2, 3], [255, 0, 128], [7, 7, 7]] {
            let coded = encode_group(m);
            for l in 0..fano::N {
                let Some(points) = fano::LINE_POINTS.get(l) else {
                    continue;
                };
                let mut acc = 0u8;
                for &p in points {
                    acc ^= coded.get(p as usize).copied().unwrap_or(0);
                }
                assert_eq!(acc, 0, "line {l} parity for message {m:?}");
            }
        }
    }

    #[test]
    fn bit_plane_codewords_have_weight_four_and_support_a_hyperoval() {
        // Restricting to {0,1}-valued data isolates a single bit-plane, showing this
        // byte-wise code is 8 parallel copies of the classical GF(2) [7,3,4] simplex dual of
        // Hamming(7,4): its nonzero codewords have weight 4 and their support is exactly a
        // hyperoval (spec §6.3 note, V20) — the module doc-comment's "why the simplex dual"
        // derivation, made concrete.
        for m in [
            [1u8, 0, 0],
            [0, 1, 0],
            [0, 0, 1],
            [1, 1, 0],
            [1, 0, 1],
            [0, 1, 1],
            [1, 1, 1],
        ] {
            let coded = encode_group(m);
            let mut support = 0u8;
            for (p, &byte) in coded.iter().enumerate() {
                if byte != 0 {
                    support |= 1 << p;
                }
            }
            assert_eq!(support.count_ones(), 4, "message {m:?} codeword weight");
            assert!(
                crate::is_hyperoval_fano(support),
                "message {m:?} support must be a hyperoval"
            );
        }
    }

    #[test]
    fn peel_group_stopping_set_matches_peel_fano_exhaustively() {
        // Cross-check two independent implementations of the same closure: `peel_group`
        // (byte-carrying) must reach exactly the same stopping-set mask as `peel_fano`
        // (bits-only), for every one of the 128 erasure patterns.
        for mask in 0u8..=0x7F {
            let mut symbols: [Option<u8>; N] =
                core::array::from_fn(|p| if mask & (1 << p) == 0 { Some(p as u8) } else { None });
            let got = peel_group(&mut symbols);
            assert_eq!(got, crate::lrc::peel_fano(mask), "mask {mask:#09b}");
        }
    }

    #[test]
    fn exhaustive_reconstruct_matches_is_recoverable_fano() {
        // V9/V20 tie-in: reconstruct() returns the exact original payload iff
        // is_recoverable_fano(mask), for EVERY one of the 128 erasure patterns, across
        // payloads that do and do not stripe evenly into groups of K=3 (including empty and
        // a multi-stripe payload of length not a multiple of K).
        let long: Vec<u8> = (0u8..100).collect(); // len 100, 100 % 3 == 1
        let payloads: [&[u8]; 6] = [b"", b"A", b"AB", b"ABC", b"ABCDE", &long];
        for &payload in &payloads {
            let shards = encode(payload);
            for mask in 0u8..=0x7F {
                let input: [Option<Vec<u8>>; N] = core::array::from_fn(|p| {
                    if mask & (1 << p) == 0 {
                        shards.get(p).cloned()
                    } else {
                        None
                    }
                });
                let got = reconstruct(&input);
                if crate::is_recoverable_fano(mask) {
                    assert_eq!(
                        got.as_deref(),
                        Some(payload),
                        "mask {mask:#09b} payload len {}",
                        payload.len()
                    );
                } else {
                    assert!(
                        got.is_none(),
                        "mask {mask:#09b} should be unrecoverable, payload len {}",
                        payload.len()
                    );
                }
            }
        }
    }
}
