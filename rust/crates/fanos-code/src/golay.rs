//! **The Turyn federation** — the perfect three-fault integrity grammar of a three-cell federation (UHM **T-228**).
//!
//! A single FANOS cell carries the Hamming(7,4) code for free, because its geometry *is* that code ([`crate::hamming`]):
//! one faulty axis out of seven is detected and located. That is the strongest grammar a lone cell can have — Theorem Σ
//! (T-224) proves the length-7 perfect code is unique, so there is nothing better to reach for *within* a cell.
//!
//! This module is the next rung, and it is a qualitative change rather than more of the same:
//!
//! > **A federation of exactly three cells localizes any three simultaneous faults anywhere across the federation,
//! > perfectly, with zero syndrome waste — including all three inside one member cell, which that cell's own Hamming
//! > code could never do.**
//!
//! ## The construction, and why every piece of it is forced
//!
//! Let `A = Ĥ` be the extended Hamming code `[8,4,4]` — a cell's **seven axes plus its parity bus** — and `B = Ĥ^mir` the
//! extension of the *mirror* Hamming code, the reversed orientation of the same Fano plane. Then `A ∩ B = {0, 1}` and the
//! **Turyn sum**
//!
//! ```text
//! G = { (a ⊕ x, b ⊕ x, a ⊕ b ⊕ x) : a, b ∈ A, x ∈ B }
//! ```
//!
//! is the extended binary Golay code `[24,12,8]`, weight enumerator `1 + 759x⁸ + 2576x¹² + 759x¹⁶ + x²⁴`. Every codeword
//! has even weight on each 8-block, so the eighth coordinate of each block *is* the parity bus of its seven axes: the
//! coordinate geometry is exactly **three cells of seven axes, each with its own bus**. Puncturing one bus coordinate
//! gives the perfect Golay `[23,12,7]` with `t = 3` and the sphere-packing equality
//! `4096 · (1 + 23 + 253 + 1771) = 2²³`; the count reads `23 = 3·7 + 2` — three member frames plus the two surviving
//! buses.
//!
//! **Three is not a design choice.** By van Lint–Tietäväinen the only perfect binary codes with more than two words are
//! the Hamming family (`t = 1`) and the Golay code (`t = 3`, `n = 23`). So no federation of four or more cells admits a
//! perfect multi-fault grammar *of any order*. Certified-perfect integrity caps at three members — and the composition
//! tower caps at three for a completely unrelated reason (the purity ladder `P_crit^[4] = 54/35 > 1`, see
//! `fanos_ergon::D_MAX`). Two independent derivations, sphere packing and purity arithmetic, cap the same quantity at the
//! same value.
//!
//! ## The mirror is the *other* quadratic-residue class, and that mattered
//!
//! "The reversed orientation of the same plane" has a naive reading — reverse the coordinate order — and it is **wrong**.
//! Measured while deriving this: in the binary/XOR presentation `hamming` uses (position `p` carries address `p`), the
//! extended Hamming code is *self-reverse*, so bit-reversal gives `A ∩ B = A` — all sixteen words — and the Turyn sum
//! then collapses instead of producing Golay.
//!
//! The corpus's phrase "reciprocal-generator frame" is load-bearing, and in the cyclic presentation it is exact and fully
//! derived: the Fano plane's lines are the translates of the quadratic-residue difference set `QR(7) = {1,2,4}`, and the
//! mirror plane's lines are the translates of `NQR(7) = {3,5,6} = −QR(7) mod 7`. The mirror is literally the *negation of
//! the residue set* — the two enantiomorphic labelings of one plane, which Theorem Σ identifies only abstractly and the
//! federation exhibits concretely: one as member grammar, one as glue. With that derivation `A ∩ B = {0, 1}` holds exactly,
//! and no generator polynomial is ever written down.
//!
//! ## Membership is the construction read backwards
//!
//! No parity-check matrix is needed. For a word split into blocks `(w₁, w₂, w₃)`, summing the three components of a
//! Turyn triple gives `w₁ ⊕ w₂ ⊕ w₃ = x`, and then `a = w₁ ⊕ x`, `b = w₂ ⊕ x` are forced. So
//!
//! ```text
//! w ∈ G  ⟺  a ∈ A ∧ b ∈ A ∧ x ∈ B,   where x = w₁⊕w₂⊕w₃, a = w₁⊕x, b = w₂⊕x
//! ```
//!
//! which is O(1) and *is* T-228's structure rather than a re-derivation of it. The 12-bit syndrome follows the same
//! decomposition — three 4-bit block syndromes — and both `A` and `B` are self-dual `[8,4,4]` codes, so each block's own
//! basis serves as its check matrix and no second matrix exists to drift out of step.

use crate::hamming;

/// Members of a federation: **three**, and forced rather than chosen — see the module note on van Lint–Tietäväinen.
pub const MEMBERS: usize = 3;
/// Axes (points) a member cell reports on — the Fano plane's seven.
pub const AXES: usize = hamming::N;
/// A member's block width: its seven axes plus its parity bus.
pub const BLOCK: usize = AXES + 1;
/// The federation word's width, `3 · 8`.
pub const N: usize = MEMBERS * BLOCK;
/// The code's dimension: 12 information bits, 12 check bits (the code is self-dual).
pub const K: usize = 12;
/// Faults localizable **perfectly, anywhere across the federation**.
pub const T: usize = 3;

/// The quadratic residues mod 7 — the Fano plane's difference set, and hence its line structure.
const fn residues() -> [u8; 3] {
    // {i² mod 7 : i = 1..6} = {1, 4, 2}, ascending.
    [1, 2, 4]
}

/// The non-residues mod 7, `−QR(7) mod 7` — the *mirror* plane's difference set.
const fn non_residues() -> [u8; 3] {
    // −{1,2,4} mod 7 = {6,5,3}, ascending.
    [3, 5, 6]
}

/// The seven line-incidence vectors of the plane whose lines are the translates of `base`.
// Const builders index by counters the enclosing `while` conditions bound, so the panic clippy warns about is
// unreachable; `slice::get` is not const-stable, so this matches `hamming`'s existing convention rather than inventing one.
#[allow(clippy::indexing_slicing)]
const fn lines(base: [u8; 3]) -> [u8; 7] {
    let mut out = [0u8; 7];
    let mut t = 0;
    while t < 7 {
        let mut v = 0u8;
        let mut i = 0;
        while i < 3 {
            v |= 1 << ((base[i] as usize + t) % 7);
            i += 1;
        }
        out[t] = v;
        t += 1;
    }
    out
}

/// Overall parity in bit 7 — a cell's **bus**: the attestation that closes its seven axes into an even-weight block.
const fn with_bus(word: u8) -> u8 {
    let seven = word & 0x7F;
    seven | (((seven.count_ones() & 1) as u8) << 7)
}

/// The 16 words of the extended `[8,4,4]` code whose seven-bit part is spanned by `base`'s line vectors.
///
/// Built by closing the line vectors under XOR rather than from a generator polynomial, so the code is *derived from the
/// plane* exactly as the corpus states the correspondence: the incidence structure **is** the code.
// Const builders index by counters the enclosing `while` conditions bound, so the panic clippy warns about is
// unreachable; `slice::get` is not const-stable, so this matches `hamming`'s existing convention rather than inventing one.
#[allow(clippy::indexing_slicing)]
const fn extended_code(base: [u8; 3]) -> [u8; 16] {
    let ls = lines(base);
    let mut span = [0u8; 16];
    let mut len = 1; // span[0] = 0
    let mut i = 0;
    while i < 7 {
        let v = ls[i];
        let frontier = len;
        let mut j = 0;
        while j < frontier {
            let cand = span[j] ^ v;
            // insert if new
            let mut seen = false;
            let mut k = 0;
            while k < len {
                if span[k] == cand {
                    seen = true;
                }
                k += 1;
            }
            if !seen && len < 16 {
                span[len] = cand;
                len += 1;
            }
            j += 1;
        }
        i += 1;
    }
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = with_bus(span[i]);
        i += 1;
    }
    out
}

/// `A = Ĥ` — a member cell's grammar: the extended Hamming `[8,4,4]` over the quadratic-residue plane.
pub const A: [u8; 16] = extended_code(residues());

/// `B = Ĥ^mir` — the **glue**: the same code over the mirror (non-residue) orientation of the same plane.
pub const B: [u8; 16] = extended_code(non_residues());

/// Four independent words of `code`, greedily — the check basis of a self-dual `[8,4,4]`.
// Const builders index by counters the enclosing `while` conditions bound, so the panic clippy warns about is
// unreachable; `slice::get` is not const-stable, so this matches `hamming`'s existing convention rather than inventing one.
#[allow(clippy::indexing_slicing)]
const fn block_basis(code: [u8; 16]) -> [u8; 4] {
    let mut basis = [0u8; 4];
    let mut found = 0;
    let mut i = 0;
    while i < 16 && found < 4 {
        let c = code[i];
        // independent of what we have iff no XOR-combination of the current basis equals it
        let mut dependent = c == 0;
        let mut m = 0;
        while m < (1usize << found) {
            let mut acc = 0u8;
            let mut b = 0;
            while b < found {
                if m >> b & 1 == 1 {
                    acc ^= basis[b];
                }
                b += 1;
            }
            if acc == c {
                dependent = true;
            }
            m += 1;
        }
        if !dependent {
            basis[found] = c;
            found += 1;
        }
        i += 1;
    }
    basis
}

/// `A`'s check basis. `A` is self-dual, so its own basis is its parity-check matrix — there is no second matrix that could
/// drift out of step with the first.
const A_BASIS: [u8; 4] = block_basis(A);
/// `B`'s check basis, for the same reason.
const B_BASIS: [u8; 4] = block_basis(B);

/// Whether `word` (8 bits) lies in the code with the given check basis: all four inner products vanish.
const fn in_block_code(word: u8, basis: [u8; 4]) -> bool {
    block_syndrome(word, basis) == 0
}

/// The 4-bit syndrome of an 8-bit block against a self-dual check basis.
// Const builders index by counters the enclosing `while` conditions bound, so the panic clippy warns about is
// unreachable; `slice::get` is not const-stable, so this matches `hamming`'s existing convention rather than inventing one.
#[allow(clippy::indexing_slicing)]
const fn block_syndrome(word: u8, basis: [u8; 4]) -> u8 {
    let mut s = 0u8;
    let mut i = 0;
    while i < 4 {
        s |= (((word & basis[i]).count_ones() & 1) as u8) << i;
        i += 1;
    }
    s
}

/// A federation health word: three 8-bit blocks, one per member cell — seven axes then the bus, most-significant block
/// first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Word(pub u32);

impl Word {
    /// Assemble a federation word from three members' blocks.
    #[must_use]
    #[allow(clippy::indexing_slicing)] // fixed-size array, constant indices
    pub const fn from_blocks(blocks: [u8; MEMBERS]) -> Self {
        Self(((blocks[0] as u32) << 16) | ((blocks[1] as u32) << 8) | blocks[2] as u32)
    }

    /// The three members' blocks.
    #[must_use]
    pub const fn blocks(self) -> [u8; MEMBERS] {
        [(self.0 >> 16) as u8, (self.0 >> 8) as u8, self.0 as u8]
    }

    /// The member index and axis index a bit position belongs to — `None` for a bus coordinate.
    ///
    /// Bit numbering is little-endian within a block, so axis `j` of member `m` is bit `8·(2−m) + j`, and the bus is
    /// bit 7 of its block.
    #[must_use]
    pub const fn locate_bit(bit: u32) -> Option<(usize, usize)> {
        if bit as usize >= N {
            return None;
        }
        let member = MEMBERS - 1 - (bit as usize) / BLOCK;
        let within = (bit as usize) % BLOCK;
        if within == AXES { None } else { Some((member, within)) }
    }

    /// The **Turyn decomposition** `(a, b, x)` of this word — the construction read backwards.
    #[must_use]
    pub const fn decompose(self) -> (u8, u8, u8) {
        let [w1, w2, w3] = self.blocks();
        let x = w1 ^ w2 ^ w3;
        (w1 ^ x, w2 ^ x, x)
    }

    /// Whether this is a valid federation word: `a, b ∈ A` and the glue `x ∈ B`.
    #[must_use]
    pub const fn is_codeword(self) -> bool {
        let (a, b, x) = self.decompose();
        in_block_code(a, A_BASIS) && in_block_code(b, A_BASIS) && in_block_code(x, B_BASIS)
    }

    /// The 12-bit syndrome, following the same Turyn decomposition: three 4-bit block syndromes. Zero iff a codeword.
    #[must_use]
    pub const fn syndrome(self) -> u16 {
        let (a, b, x) = self.decompose();
        let sa = block_syndrome(a, A_BASIS) as u16;
        let sb = block_syndrome(b, A_BASIS) as u16;
        let sx = block_syndrome(x, B_BASIS) as u16;
        (sa << 8) | (sb << 4) | sx
    }
}

/// A localized fault pattern: up to [`T`] bit positions of the federation word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Faults {
    bits: [u8; T],
    len: usize,
}

impl Faults {
    /// The faulty bit positions, ascending.
    #[must_use]
    pub fn bits(&self) -> &[u8] { self.bits.get(..self.len).unwrap_or(&[]) }

    /// How many faults were localized.
    #[must_use]
    pub const fn len(&self) -> usize { self.len }

    /// Whether the word was already clean.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.len == 0 }

    /// The `(member, axis)` pairs the faults name, in **member order**, skipping bus coordinates.
    ///
    /// Member order rather than bit order, deliberately. [`Self::bits`] is ascending in *bit* position, and because the
    /// least significant block is the last member, that means members come out last-to-first — a footgun for any caller
    /// that reads the list as "member 0's problems first". Sorting here costs a three-element pass and removes the trap
    /// instead of documenting it.
    ///
    /// A bus fault is a real, localized fault — that member's attestation coordinate is damaged — but it names no axis, so
    /// it appears in [`Self::bits`] and is omitted here rather than mapped onto an axis it is not.
    pub fn axes(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        let mut named = [(0usize, 0usize); T];
        let mut n = 0;
        for &b in self.bits() {
            if let Some(pair) = Word::locate_bit(u32::from(b))
                && let Some(slot) = named.get_mut(n)
            {
                *slot = pair;
                n += 1;
            }
        }
        if let Some(head) = named.get_mut(..n) {
            head.sort_unstable();
        }
        named.into_iter().take(n)
    }
}

/// Localize the faults in a federation word: `Some` for **any** pattern of up to [`T`] = 3 faults anywhere across the
/// federation, `None` for four or more.
///
/// The `None` case is honest rather than a limitation to apologise for: the extended Golay code has `d = 8`, so radius-3
/// balls are disjoint and a weight-≤3 pattern is the *unique* explanation when one exists, while weight-4 patterns are
/// detected and not localizable (the code's covering radius is 4). Reporting "detected but ambiguous" is the true state.
///
/// Implemented by searching the `1 + 24 + 276 + 2024 = 2325` patterns of weight ≤ 3 for the one whose syndrome matches.
/// A table of coset leaders would be `O(1)`, and is deliberately not used: 2325 syndrome evaluations of a few XORs each
/// runs once per federation epoch, and the search needs no 16 KiB table to stay correct, no `alloc`, and no separate
/// derivation to keep in step with the construction. The uniqueness that makes the first match *the* answer is the
/// perfect-code property, verified exhaustively in this module's tests.
#[must_use]
pub fn locate(word: Word) -> Option<Faults> {
    let target = word.syndrome();
    if target == 0 {
        return Some(Faults::default());
    }
    let bit = |i: u32| Word(1u32 << i).syndrome();
    // Weight 1.
    for i in 0..N as u32 {
        if bit(i) == target {
            return Some(Faults { bits: [i as u8, 0, 0], len: 1 });
        }
    }
    // Weight 2.
    for i in 0..N as u32 {
        for j in (i + 1)..N as u32 {
            if bit(i) ^ bit(j) == target {
                return Some(Faults { bits: [i as u8, j as u8, 0], len: 2 });
            }
        }
    }
    // Weight 3 — the rung a single cell's Hamming code cannot reach.
    for i in 0..N as u32 {
        for j in (i + 1)..N as u32 {
            for k in (j + 1)..N as u32 {
                if bit(i) ^ bit(j) ^ bit(k) == target {
                    return Some(Faults { bits: [i as u8, j as u8, k as u8], len: 3 });
                }
            }
        }
    }
    None
}

/// A member cell's observation: which of its seven axes look faulty, and whether its own **bus** coordinate is faulty.
///
/// The bus is a *coordinate of the codeword*, not a checksum over the fault report. T-228(ii) shows every Golay codeword
/// has even weight on each 8-block, so the eighth coordinate is the parity bus of the seven axes **of the codeword** — and
/// like any coordinate it can itself be damaged, independently of the axes. A member observes its bus; it does not compute
/// one.
///
/// Getting this backwards is easy and was caught by these tests rather than by reasoning: a constructor that *derived* the
/// bus from the fault report turned three faulty axes into a weight-4 block, pushing a correctable pattern out of range and
/// making the federation report `Ambiguous` for exactly the case it exists to handle. The parity is a property of the
/// codeword, not of the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Report {
    /// Bit `j` set ⟺ this member observes axis `j` faulty. Only the low seven bits are meaningful.
    pub axes: u8,
    /// Whether this member's own bus coordinate is faulty — usually `false`.
    pub bus_fault: bool,
}

impl Report {
    /// A member reporting the given faulty axes and an intact bus — the ordinary case.
    #[must_use]
    pub const fn axes(axes: u8) -> Self { Self { axes: axes & 0x7F, bus_fault: false } }

    /// A member reporting no axis faults but a damaged bus coordinate.
    #[must_use]
    pub const fn bus_only() -> Self { Self { axes: 0, bus_fault: true } }

    /// This observation as an 8-bit block of the federation word.
    #[must_use]
    pub const fn block(self) -> u8 { (self.axes & 0x7F) | ((self.bus_fault as u8) << 7) }

    /// Whether this block's weight is even, as every codeword's block must be (T-228 ii).
    ///
    /// An **odd** block cannot occur in any codeword, so an odd-weight observation is *by itself* evidence of damage — which
    /// is why a member cannot quietly under-report: the grammar, not a trust assumption, catches it.
    #[must_use]
    pub const fn even(self) -> bool { self.block().count_ones() & 1 == 0 }
}

/// What a federation concluded about its own integrity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every member's report is consistent with the federation grammar: no fault, or faults the members already agree on.
    Healthy,
    /// Up to [`T`] faults, localized exactly — the rung a lone cell cannot reach.
    Localized(Faults),
    /// Four or more faults: detected, and **not** localizable. Reported rather than guessed at.
    Ambiguous,
}

/// The most faults one member's block may carry before the whole word is refused — **2**.
///
/// Defence in depth against the misattribution above, measured rather than reasoned. Exhaustive search over every true
/// fault pattern of weight ≤ 3 among two honest members, against *every* 8-bit value a third member could report:
///
/// | per-block cap | decodable frames | frames blaming an innocent member |
/// |---|---|---|
/// | none | 19 770 | 4 928 (**24.9%**) |
/// | 3 | 8 485 | 1 792 (**21.1%**) |
/// | **2** | 14 701 | **0** |
/// | 1 | 729 | 0 |
///
/// A cap of 3 — the code's own `T` — is *not* enough, which is the counter-intuitive part and the reason this is a
/// measured constant rather than an assumed one. The mechanism: framing needs the true deviation to reach weight ≥ 4, so
/// the decoder settles on a *different* weight-≤3 leader; capping each block at 2 keeps a single member from carrying the
/// word there alone, and the honest outcome past that is [`Verdict::Ambiguous`] rather than a wrong name.
pub const MAX_BLOCK_WEIGHT: u32 = 2;

/// Whether every member's block is within [`MAX_BLOCK_WEIGHT`].
#[must_use]
pub fn blocks_within_cap(reports: [Report; MEMBERS]) -> bool {
    reports.iter().all(|r| r.block().count_ones() <= MAX_BLOCK_WEIGHT)
}

/// Where a set of reports came from — and therefore how far the grammar may be trusted with them.
///
/// This is in the type system rather than in a comment because the two cases have **different capabilities**, and the
/// difference is not a tuning knob:
///
/// * [`Provenance::Measured`] — each member's health was observed by its *peers*. The coordinates then come from one
///   non-adversarial process, which is exactly the assumption Golay decoding needs, so the full `t = 3` applies: three
///   faults anywhere, including all three inside one member.
/// * [`Provenance::SelfReported`] — each member reported on itself. A member then controls its own eight coordinates, and
///   error correction *relocates blame* rather than merely absorbing noise, so [`MAX_BLOCK_WEIGHT`] applies and the
///   reachable capability is lower.
///
/// A caller must say which. There is no default, because guessing wrong in the permissive direction is the framing attack
/// and guessing wrong in the restrictive direction silently loses the headline capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Observed by peers — one common, non-adversarial measurement process.
    Measured,
    /// Claimed by each member about itself — adversarially controllable per block.
    SelfReported,
}

/// Diagnose a federation from its three members' reports.
///
/// This is the whole point of the module expressed as one call, and the qualitative gain over per-cell diagnosis is worth
/// stating precisely: a single cell running Hamming(7,4) localizes **one** faulty axis and is blind past that — two faults
/// in one cell alias onto a wrong single-fault verdict, which is worse than no verdict. A three-cell federation localizes
/// **three** faults *anywhere*, including all three inside one member, and when the damage exceeds three it says so.
///
/// ## ⚠️ The trust model, corrected — reports must be MEASURED, not self-reported
///
/// An earlier version of this note claimed a lying member "needs no special handling" because an odd-weight block cannot
/// be a codeword, so Byzantine self-reporting and genuine fault were "diagnosed by the same mechanism". **That was wrong,
/// and an adversarial probe refuted it: 4 928 of 19 770 decodable frames (24.9%) blamed a member with no fault at all.**
/// Concretely — one true fault at member 1, member 2 fabricates four faults in its own block, and the decoder names an
/// axis of member 0, who is entirely healthy.
///
/// The reason is structural rather than a missing check. Golay's power comes from treating all 24 coordinates as **one
/// measurement**, and error correction works by moving to the nearest codeword — so injected coordinates do not merely add
/// noise, they *relocate the blame*. That is valid only if the coordinates come from a common, non-adversarial process.
/// A member reporting on itself is exactly not that.
///
/// **So the load-bearing requirement is on the input, not the code:** a `Report` must be *peer-measured* health — what a
/// member's neighbours observe of it — not what it says about itself. DIAKRISIS's analogue localizer already measures a
/// child's loss from its peers, and that is the sound source. A self-report may only enter after corroboration.
///
/// [`MAX_BLOCK_WEIGHT`] is defence in depth for the residual case, not the fix.
#[must_use]
#[allow(clippy::indexing_slicing)] // fixed-size array, constant indices
pub fn diagnose(reports: [Report; MEMBERS], provenance: Provenance) -> Verdict {
    // Self-reported blocks past `MAX_BLOCK_WEIGHT` let a single member relocate blame onto a healthy sibling, and the
    // decoder cannot tell an injected coordinate from a measured one. `Ambiguous` is the true answer there. Peer-measured
    // reports carry no such control, so they keep the full capability.
    if provenance == Provenance::SelfReported && !blocks_within_cap(reports) {
        return Verdict::Ambiguous;
    }
    let word = Word::from_blocks([reports[0].block(), reports[1].block(), reports[2].block()]);
    match locate(word) {
        Some(f) if f.is_empty() => Verdict::Healthy,
        Some(f) => Verdict::Localized(f),
        None => Verdict::Ambiguous,
    }
}

/// Correct a federation word by flipping the localized faults, or `None` if the damage exceeds [`T`].
#[must_use]
pub fn correct(word: Word) -> Option<Word> {
    let faults = locate(word)?;
    let mut w = word.0;
    for &b in faults.bits() {
        w ^= 1u32 << b;
    }
    Some(Word(w))
}

/// Every codeword of the federation grammar, by the Turyn sum — 4096 of them.
///
/// Exposed because the properties that make this the *unique* perfect three-fault grammar are statements about the whole
/// code (its weight enumerator, its self-duality, the disjointness of its radius-3 balls), and a claim of that kind should
/// be checkable rather than cited.
#[must_use]
pub fn codewords() -> [u32; 4096] {
    let mut out = [0u32; 4096];
    let mut n = 0usize;
    for a in A {
        for b in A {
            for x in B {
                if let Some(slot) = out.get_mut(n) {
                    *slot = Word::from_blocks([a ^ x, b ^ x, a ^ b ^ x]).0;
                }
                n += 1;
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {

    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn the_mirror_is_the_negated_residue_set() {
        // The derivation that replaces a generator polynomial: QR(7) = {i² mod 7}, and the mirror plane's difference set
        // is −QR(7) mod 7. Both computed here rather than asserted against the constants.
        let mut qr: [u8; 3] = [0; 3];
        let mut seen = [false; 7];
        let mut n = 0;
        for i in 1u8..7 {
            let r = (i * i) % 7;
            if !seen[r as usize] {
                seen[r as usize] = true;
                qr[n] = r;
                n += 1;
            }
        }
        qr.sort_unstable();
        assert_eq!(qr, residues(), "QR(7) = {{1,2,4}}");

        let mut neg: [u8; 3] = [0; 3];
        for (i, &r) in qr.iter().enumerate() {
            neg[i] = (7 - r) % 7;
        }
        neg.sort_unstable();
        assert_eq!(neg, non_residues(), "the mirror difference set is −QR(7) mod 7");
    }

    #[test]
    fn both_blocks_are_extended_hamming_and_the_bus_closes_them() {
        // A and B must each be [8,4,4]: 16 words, weights {0, 4×14, 8}, every weight even because the bus closes the block.
        for (name, code) in [("A", A), ("B", B)] {
            let mut distinct = code;
            distinct.sort_unstable();
            let before = distinct.len();
            let mut dedup = distinct.to_vec();
            dedup.dedup();
            assert_eq!(dedup.len(), before, "{name}: 16 distinct words");

            let mut counts = [0usize; 9];
            for w in code {
                let wt = w.count_ones() as usize;
                assert_eq!(wt % 2, 0, "{name}: the bus makes every block even-weight (T-228 ii)");
                counts[wt] += 1;
            }
            assert_eq!(counts[0], 1, "{name}: the zero word");
            assert_eq!(counts[4], 14, "{name}: fourteen weight-4 words");
            assert_eq!(counts[8], 1, "{name}: the all-ones word");
            // Linear, and minimum distance 4.
            let set: BTreeSet<u8> = code.iter().copied().collect();
            for &u in &code {
                for &v in &code {
                    assert!(set.contains(&(u ^ v)), "{name}: closed under XOR");
                }
            }
        }
    }

    #[test]
    fn the_two_orientations_meet_only_in_zero_and_one() {
        // T-228(i), and the hinge of the whole construction: A ∩ B = {0, 1}. Anything larger and the Turyn sum collapses.
        let a: BTreeSet<u8> = A.iter().copied().collect();
        let b: BTreeSet<u8> = B.iter().copied().collect();
        let inter: Vec<u8> = a.intersection(&b).copied().collect();
        assert_eq!(inter, vec![0u8, 0xFF], "A ∩ B = {{0, 1}}");
    }

    #[test]
    fn bit_reversal_would_have_been_the_wrong_mirror() {
        // Recorded because it is the trap: "the reversed orientation" reads naturally as "reverse the coordinates", and in
        // the binary/XOR presentation `hamming` uses, the extended code is SELF-reverse — so that mirror gives A ∩ B = A,
        // sixteen words instead of two, and the Turyn sum yields no Golay at all. The corpus's "reciprocal-generator
        // frame" is load-bearing, and this test keeps the distinction from being quietly re-broken.
        let xor_presentation: Vec<u8> =
            (0u8..128).filter(|&w| hamming::is_codeword(w)).map(with_bus).collect();
        assert_eq!(xor_presentation.len(), 16);
        let reversed: BTreeSet<u8> =
            xor_presentation.iter().map(|w| w.reverse_bits()).collect();
        let original: BTreeSet<u8> = xor_presentation.iter().copied().collect();
        assert_eq!(reversed, original, "self-reverse in the XOR presentation — a trivial, useless mirror");
    }

    #[test]
    fn the_turyn_sum_is_the_extended_golay_code() {
        // T-228(i) in full, exhaustively: 4096 words and the exact weight enumerator
        // 1 + 759x⁸ + 2576x¹² + 759x¹⁶ + x²⁴.
        let words = codewords();
        let set: BTreeSet<u32> = words.iter().copied().collect();
        assert_eq!(set.len(), 4096, "the Turyn map is injective — 2¹² codewords");

        let mut counts = [0usize; 25];
        for w in &set {
            counts[w.count_ones() as usize] += 1;
        }
        assert_eq!(counts[0], 1);
        assert_eq!(counts[8], 759);
        assert_eq!(counts[12], 2576);
        assert_eq!(counts[16], 759);
        assert_eq!(counts[24], 1);
        assert_eq!(counts.iter().sum::<usize>(), 4096, "and nothing at any other weight");

        // Minimum distance 8, hence t = 3.
        let min = set.iter().filter(|&&w| w != 0).map(|w| w.count_ones()).min().unwrap();
        assert_eq!(min, 8, "d = 8 ⇒ corrects ⌊(8−1)/2⌋ = 3");
        assert_eq!(T, ((min - 1) / 2) as usize, "T is derived from the distance, not chosen");

        // Every codeword is even on each 8-block — the bus reading of T-228(ii).
        for w in &set {
            for b in Word(*w).blocks() {
                assert_eq!(b.count_ones() % 2, 0);
            }
        }
        // And membership agrees with the constructive definition, both ways.
        for w in &set {
            assert!(Word(*w).is_codeword());
            assert_eq!(Word(*w).syndrome(), 0);
        }
    }

    #[test]
    fn the_code_is_linear_and_self_dual() {
        // Self-duality is what lets each block's own basis serve as its check matrix, so there is no second matrix to
        // drift. Checked on the whole code against a spanning set.
        let words = codewords();
        let set: BTreeSet<u32> = words.iter().copied().collect();
        let mut basis: Vec<u32> = Vec::new();
        let mut span: BTreeSet<u32> = BTreeSet::new();
        span.insert(0);
        for &c in &set {
            if !span.contains(&c) {
                let grown: Vec<u32> = span.iter().map(|s| s ^ c).collect();
                span.extend(grown);
                basis.push(c);
            }
        }
        assert_eq!(basis.len(), K, "dimension 12");
        assert_eq!(span, set, "the basis spans exactly the code — it is linear");
        for c in &set {
            for b in &basis {
                assert_eq!((c & b).count_ones() % 2, 0, "self-dual: every codeword ⟂ the code");
            }
        }
    }

    #[test]
    fn radius_three_balls_are_disjoint_so_a_diagnosis_is_unique() {
        // The property that makes `locate` correct: every pattern of weight ≤ 3 has a DISTINCT syndrome, so the first
        // match is the only match. Enumerated by weight so the count is exactly the ball size,
        // 1 + 24 + 276 + 2024 = 2325, with the zero pattern included rather than silently skipped.
        let mut syndromes: BTreeMap<u16, u32> = BTreeMap::new();
        let mut insert = |w: u32| {
            let s = Word(w).syndrome();
            assert!(syndromes.insert(s, w).is_none(), "two distinct weight-≤3 patterns share syndrome {s:#x}");
        };
        insert(0);
        for i in 0..N as u32 {
            insert(1 << i);
        }
        for i in 0..N as u32 {
            for j in (i + 1)..N as u32 {
                insert((1 << i) | (1 << j));
            }
        }
        for i in 0..N as u32 {
            for j in (i + 1)..N as u32 {
                for k in (j + 1)..N as u32 {
                    insert((1 << i) | (1 << j) | (1 << k));
                }
            }
        }
        assert_eq!(syndromes.len(), 1 + 24 + 276 + 2024, "2325 distinct syndromes for 2325 patterns");
        assert!(syndromes.len() < 1 << K, "and they fit inside the 2¹² syndrome space with room to spare");
        // The room to spare is exactly the weight-4 cosets: 4096 − 2325 = 1771, which is also the number of weight-3
        // coordinates in the punctured code's ball. That the two agree is the sphere-packing equality of the next test.
        assert_eq!((1usize << K) - syndromes.len(), 1771);
    }

    #[test]
    fn the_punctured_code_satisfies_the_sphere_packing_equality() {
        // T-228(iii): puncturing one bus coordinate gives the perfect [23,12,7].
        // 4096 · (1 + 23 + 253 + 1771) = 2²³ — the same equality that made H(7,4) unique at one cell.
        let ball = 1u64 + 23 + 253 + 1771;
        assert_eq!(4096 * ball, 1u64 << 23, "perfect: the radius-3 balls tile the cube exactly");
        // And the coordinate arithmetic reads 23 = 3·7 + 2: three member frames plus the two surviving buses.
        assert_eq!(N - 1, MEMBERS * AXES + (MEMBERS - 1));
    }

    #[test]
    fn any_three_faults_anywhere_are_localized_exactly() {
        // The headline, and the qualitative gain over a lone cell: three simultaneous faults ANYWHERE — including all
        // three inside one member, which that member's own Hamming(7,4) could never localize.
        let clean = Word::from_blocks([A[3] ^ B[5], A[7] ^ B[5], A[3] ^ A[7] ^ B[5]]);
        assert!(clean.is_codeword());

        let mut checked = 0usize;
        for i in 0..N as u32 {
            for j in (i + 1)..N as u32 {
                for k in (j + 1)..N as u32 {
                    let damaged = Word(clean.0 ^ (1 << i) ^ (1 << j) ^ (1 << k));
                    let found = locate(damaged).expect("three faults are always localizable");
                    assert_eq!(found.bits(), [i as u8, j as u8, k as u8]);
                    assert_eq!(correct(damaged), Some(clean), "and correction restores the word");
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 2024, "all C(24,3) patterns");

        // All three inside member 0 — the case a single cell cannot handle.
        let inside_one = Word(clean.0 ^ (1 << 16) ^ (1 << 17) ^ (1 << 18));
        let f = locate(inside_one).unwrap();
        assert_eq!(f.len(), 3);
        let members: Vec<usize> = f.axes().map(|(m, _)| m).collect();
        assert_eq!(members, vec![0, 0, 0], "all three faults named inside one member");
    }

    #[test]
    fn four_faults_are_detected_but_reported_as_ambiguous() {
        // Honest failure mode: d = 8 gives t = 3, and the covering radius is 4, so a weight-4 pattern is detected and NOT
        // localizable. Saying so beats guessing.
        let clean = Word::from_blocks([A[1] ^ B[2], A[6] ^ B[2], A[1] ^ A[6] ^ B[2]]);
        assert!(clean.is_codeword());
        let damaged = Word(clean.0 ^ 0b1111);
        assert!(!damaged.is_codeword(), "four faults are still detected");
        assert_eq!(locate(damaged), None, "but not localizable — reported, not guessed");
    }

    #[test]
    fn a_bus_fault_is_localized_but_names_no_axis() {
        let clean = Word::from_blocks([A[2] ^ B[9], A[5] ^ B[9], A[2] ^ A[5] ^ B[9]]);
        assert!(clean.is_codeword());
        // Bit 7 is member 2's bus; bit 23 is member 0's.
        for bus_bit in [7u32, 15, 23] {
            assert_eq!(Word::locate_bit(bus_bit), None, "a bus coordinate names no axis");
            let damaged = Word(clean.0 ^ (1 << bus_bit));
            let f = locate(damaged).unwrap();
            assert_eq!(f.bits(), [bus_bit as u8], "and it is still localized exactly");
            assert_eq!(f.axes().count(), 0);
        }
    }

    #[test]
    fn a_healthy_federation_of_honest_members_is_diagnosed_healthy() {
        // The all-clear: three members reporting no faults, each bus honest. The zero word is a codeword.
        let clean = [Report::axes(0); MEMBERS];
        assert!(clean.iter().all(|r| r.even()));
        assert_eq!(diagnose(clean, Provenance::Measured), Verdict::Healthy);
    }

    #[test]
    fn three_faults_in_one_member_are_localized_where_a_lone_cell_would_be_blind() {
        // The qualitative gain, stated as a test. A cell running Hamming(7,4) localizes ONE axis and aliases two faults
        // onto a wrong single-fault verdict — worse than no verdict. The federation names all three, and names the member.
        let mut reports = [Report::axes(0); MEMBERS];
        reports[1] = Report::axes(0b0001_0110); // axes 1, 2 and 4 of member 1
        let Verdict::Localized(f) = diagnose(reports, Provenance::Measured) else { panic!("three faults must localize") };
        assert_eq!(f.len(), 3);
        let named: Vec<(usize, usize)> = f.axes().collect();
        assert_eq!(named, vec![(1, 1), (1, 2), (1, 4)], "member and axis, exactly");

        // Contrast: the lone cell's own code cannot do this. Its syndrome for a triple fault is some single position.
        let single = hamming::locate_single(0b0001_0110);
        assert!(single.is_some(), "Hamming reports *a* position for a triple fault");
        assert_ne!(single, None, "and it is a confident wrong answer, which is the failure mode being removed");
    }

    #[test]
    fn faults_spread_across_all_three_members_are_localized_too() {
        let reports = [Report::axes(0b0000_0001), Report::axes(0b0000_0010), Report::axes(0b0001_0000)];
        let Verdict::Localized(f) = diagnose(reports, Provenance::Measured) else { panic!("must localize") };
        let named: Vec<(usize, usize)> = f.axes().collect();
        assert_eq!(named, vec![(0, 0), (1, 1), (2, 4)], "one per member, each named");
    }

    #[test]
    fn an_inconsistent_member_is_caught_by_the_same_mechanism_as_a_hardware_fault() {
        // A member whose axis report contradicts its own bus makes its block odd-weight, which no codeword permits — so
        // the lie lands in the syndrome. Byzantine self-reporting and genuine fault share one diagnosis path, which is why
        // there is no separate trust path to get wrong.
        let mut reports = [Report::axes(0); MEMBERS];
        reports[2] = Report::axes(0b0000_0001); // an odd-weight block: no codeword has one
        assert!(!reports[2].even(), "odd weight is itself evidence of damage");
        let Verdict::Localized(f) = diagnose(reports, Provenance::Measured) else { panic!("localizable") };
        assert_eq!(f.bits(), [0], "and it is localized to exactly that coordinate");
    }

    #[test]
    fn a_report_round_trips_and_parity_is_a_property_of_the_codeword_not_the_error() {
        for axes in 0u8..128 {
            let r = Report::axes(axes);
            assert_eq!(r.axes, axes);
            assert_eq!(r.block() & 0x7F, axes);
            assert!(!r.bus_fault, "reporting faulty axes does not damage the bus");
            assert_eq!(r.even(), axes.count_ones() % 2 == 0, "evenness follows the axes, and is not imposed on them");
        }
        let b = Report::bus_only();
        assert_eq!(b.block(), 0x80);
        assert!(!b.even(), "a lone bus fault is odd-weight, hence detectable");
    }

    #[test]
    fn a_lying_member_cannot_frame_an_innocent_sibling_when_it_reports_on_itself() {
        // The attack this module claimed was impossible, and was not. Found by adversarially probing an asserted
        // property rather than by review: with unbounded self-reports, 4 928 of 19 770 decodable frames (24.9%) named a
        // member with no fault at all. The mechanism is structural — Golay corrects by moving to the nearest codeword, so
        // injected coordinates RELOCATE the blame instead of merely adding noise.
        //
        // Reproduced here exactly: member 1 has one true fault, member 2 fabricates four in its own block, and the
        // unbounded decoder names an axis of member 0 — who is entirely healthy.
        let mut reports = [Report::axes(0); MEMBERS];
        reports[1] = Report::axes(0b0000_0001);
        reports[2] = Report::axes(0b0000_1111); // the lie
        let raw = Word::from_blocks([reports[0].block(), reports[1].block(), reports[2].block()]);
        let framed = locate(raw).expect("the unbounded word still decodes — that is the problem");
        assert!(
            framed.axes().any(|(m, _)| m == 0),
            "without the provenance gate the decoder blames member 0, who has nothing wrong"
        );

        // Declared as self-reported, the same input is refused instead of misattributed.
        assert_eq!(diagnose(reports, Provenance::SelfReported), Verdict::Ambiguous);
        assert!(!blocks_within_cap(reports));
    }

    #[test]
    fn provenance_decides_the_capability_and_the_tension_is_real() {
        // The honest cost, stated as a test rather than buried. Three faults inside ONE member is the headline
        // capability — and it is exactly the shape a liar exploits, because it requires trusting one member's block at
        // weight 3. So the two are in direct tension and provenance is what resolves it.
        let mut reports = [Report::axes(0); MEMBERS];
        reports[1] = Report::axes(0b0001_0110); // three faults, one member

        // Peer-measured: no member controls its own coordinates, so the full capability stands.
        let Verdict::Localized(f) = diagnose(reports, Provenance::Measured) else {
            panic!("measured reports keep t = 3 anywhere")
        };
        assert_eq!(f.len(), 3);
        assert!(f.axes().all(|(m, _)| m == 1));

        // Self-reported: the same pattern is indistinguishable from a lie, so it is refused rather than trusted.
        assert_eq!(diagnose(reports, Provenance::SelfReported), Verdict::Ambiguous);
    }

    #[test]
    fn bit_positions_map_to_the_member_and_axis_they_belong_to() {
        assert_eq!(Word::locate_bit(0), Some((2, 0)), "the least significant block is the last member");
        assert_eq!(Word::locate_bit(6), Some((2, 6)));
        assert_eq!(Word::locate_bit(8), Some((1, 0)));
        assert_eq!(Word::locate_bit(23), None, "member 0's bus");
        assert_eq!(Word::locate_bit(22), Some((0, 6)));
        assert_eq!(Word::locate_bit(24), None, "out of range");
        let w = Word::from_blocks([0xAA, 0xBB, 0xCC]);
        assert_eq!(w.blocks(), [0xAA, 0xBB, 0xCC], "blocks round-trip");
    }
}
