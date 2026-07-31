//! The canonical encoding of a term — the form a contract is *identified by*.
//!
//! A deployed contract's on-chain identity is the hash of its encoded term, so this codec has a stronger obligation than
//! a transport format: it must be a **bijection** on well-formed terms. One term encodes to exactly one byte string, and
//! one byte string decodes to exactly one term. If two byte strings could decode to the same term, two artefacts would
//! have different hashes and identical behaviour — malleability in the one place where a hash is supposed to bind source
//! to conduct, and reviewers would be auditing an identity the chain does not actually enforce.
//!
//! That is why decoding **rejects** non-canonical input instead of normalising it:
//!
//! - an unsorted or duplicated footprint is refused, not re-sorted (`Footprint::new` sorts on construction, so a
//!   canonical encoder never emits one — an unsorted one is either a foreign encoder or an attack);
//! - a boolean byte other than `0`/`1` is refused, not coerced;
//! - an unknown tag or operator byte is refused, so a future extension cannot be silently reinterpreted by an old node.
//!
//! **Decoding is total and bounds depth as it goes.** The decoder is the first thing a hostile artefact meets, before
//! [`well_typed`](crate::well_typed) has seen it, so a nested-`Seq` bomb must be refused *during* parsing — checking depth
//! afterwards would mean the stack was already consumed building the value that gets rejected. No input panics.
//!
//! ## On not reusing `fanos_primitives::codec`
//!
//! Deliberate, and worth saying so a later reader does not "fix" it. This crate has **no dependencies** — it defines its
//! own `PointId`/`LineId` aliases rather than importing `fanos-geometry` — and that purity is the reason it can be the
//! shared execution model without dragging the field, the geometry, BLAKE3 and `zeroize` behind it.
//! `fanos_primitives::codec` brings all four for the sake of a reader. So the **convention** is reused — a leading tag
//! byte, big-endian integers, length-prefixed sequences, `finish()` refusing trailing bytes — while the forty lines
//! implementing it are local.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::value::{BinOp, Cmp, EXPR_DEPTH_MAX, Expr, Value};
use crate::{Claim, D_MAX, Effect, Footprint, Key, PointId, Predicate, Term};

/// Maximum items in any encoded sequence.
///
/// A parse-time bound, not a policy one: without it a two-byte count could ask a decoder to build a collection no
/// artefact would ever contain, and the refusal must happen before the allocation rather than after. Real terms are
/// bounded far below this by [`D_MAX`] and the footprint-width limit.
const SEQ_MAX: usize = 4096;

/// A cursor over an encoded term. Every read is bounds-checked and returns `None` rather than panicking.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, pos: 0 } }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> { self.take(1)?.first().copied() }

    fn u16(&mut self) -> Option<u16> { Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?)) }

    fn u32(&mut self) -> Option<u32> { Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?)) }

    fn u128(&mut self) -> Option<u128> { Some(u128::from_be_bytes(self.take(16)?.try_into().ok()?)) }

    fn array32(&mut self) -> Option<[u8; 32]> { self.take(32)?.try_into().ok() }

    /// A boolean, refusing any byte but `0` and `1` — two spellings of `true` would be two encodings of one term.
    fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// A length-prefixed sequence, bounded by [`SEQ_MAX`] before anything is allocated.
    fn seq<T>(&mut self, mut item: impl FnMut(&mut Self) -> Option<T>) -> Option<Vec<T>> {
        let n = usize::from(self.u16()?);
        if n > SEQ_MAX {
            return None;
        }
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(item(self)?);
        }
        Some(out)
    }

    /// Refuse trailing bytes: an artefact with extra data is a different artefact, and accepting it would give one term
    /// unboundedly many encodings.
    const fn finish(self) -> Option<()> {
        if self.pos == self.bytes.len() { Some(()) } else { None }
    }
}

fn put_u16(out: &mut Vec<u8>, v: u16) { out.extend_from_slice(&v.to_be_bytes()); }
fn put_u32(out: &mut Vec<u8>, v: u32) { out.extend_from_slice(&v.to_be_bytes()); }

/// Encode a sequence with its `u16` count. Refuses nothing — an over-long sequence cannot arise from a well-typed term,
/// and the decoder is where untrusted input is bounded.
fn put_seq<T>(out: &mut Vec<u8>, items: &[T], mut f: impl FnMut(&mut Vec<u8>, &T)) {
    put_u16(out, u16::try_from(items.len()).unwrap_or(u16::MAX));
    for i in items {
        f(out, i);
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Leaves
// ---------------------------------------------------------------------------------------------------------------------

fn put_key(out: &mut Vec<u8>, k: &Key) {
    put_u32(out, k.point);
    put_u16(out, k.space);
    out.extend_from_slice(&k.slot);
}

fn key(r: &mut Reader<'_>) -> Option<Key> {
    let point: PointId = r.u32()?;
    let space = r.u16()?;
    Some(Key::at(point, space, r.array32()?))
}

fn put_value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Int(n) => {
            out.push(0);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Bytes32(b) => {
            out.push(1);
            out.extend_from_slice(b);
        }
        Value::Record(fields) => {
            out.push(2);
            put_seq(out, fields, |o, (tag, val)| {
                o.extend_from_slice(&tag.to_be_bytes());
                put_value(o, val);
            });
        }
    }
}

/// Decode a value, **bounding depth during the parse**.
///
/// Before the bound, not after: a nesting bomb is a few bytes that expand into an arbitrarily deep tree, so a check
/// applied to the finished value has already paid for it. The term codec bounds depth the same way and for the same
/// reason; this is that discipline extended to the value language now that values nest.
///
/// The bound is [`EXPR_DEPTH_MAX`], and the coupling is derived even though the number is policy: a field-selector
/// chain in an expression is exactly what walks a record's depth, so a record deeper than can be *expressed* is
/// unaddressable and therefore useless.
fn value_at(r: &mut Reader<'_>, depth: u32) -> Option<Value> {
    if depth > EXPR_DEPTH_MAX {
        return None;
    }
    match r.u8()? {
        0 => Some(Value::Int(r.u128()?)),
        1 => Some(Value::Bytes32(r.array32()?)),
        2 => {
            let mut last: Option<u16> = None;
            let fields = r.seq(|r| {
                let tag = r.u16()?;
                // Canonical order, refused rather than repaired: the artefact hash is the contract's identity, so two
                // encodings of one record would be two identities. Strictly increasing rejects duplicates too.
                if last.is_some_and(|prev| prev >= tag) {
                    return None;
                }
                last = Some(tag);
                Some((tag, value_at(r, depth + 1)?))
            })?;
            Some(Value::Record(fields))
        }
        _ => None,
    }
}

fn value(r: &mut Reader<'_>) -> Option<Value> {
    value_at(r, 1)
}

/// A footprint, and the canonicity check that makes an artefact hash meaningful.
fn put_footprint(out: &mut Vec<u8>, f: &Footprint) {
    put_seq(out, f.reads(), put_key);
    put_seq(out, f.writes(), put_key);
}

fn footprint(r: &mut Reader<'_>) -> Option<Footprint> {
    let reads = r.seq(key)?;
    let writes = r.seq(key)?;
    // Refused rather than normalised. `Footprint::new` sorts and deduplicates, so a canonical encoder cannot produce an
    // unsorted footprint; accepting one would give the same term two encodings and two contract identities.
    if !is_sorted_unique(&reads) || !is_sorted_unique(&writes) {
        return None;
    }
    Some(Footprint::new(reads, writes))
}

fn is_sorted_unique(keys: &[Key]) -> bool { keys.windows(2).all(|w| w.first() < w.last()) }

fn put_binop(out: &mut Vec<u8>, op: BinOp) {
    out.push(match op {
        BinOp::Add => 0,
        BinOp::Sub => 1,
        BinOp::Mul => 2,
        BinOp::Div => 3,
        BinOp::Rem => 4,
        BinOp::Min => 5,
        BinOp::Max => 6,
    });
}

fn binop(r: &mut Reader<'_>) -> Option<BinOp> {
    Some(match r.u8()? {
        0 => BinOp::Add,
        1 => BinOp::Sub,
        2 => BinOp::Mul,
        3 => BinOp::Div,
        4 => BinOp::Rem,
        5 => BinOp::Min,
        6 => BinOp::Max,
        _ => return None,
    })
}

fn put_cmp(out: &mut Vec<u8>, op: Cmp) {
    out.push(match op {
        Cmp::Eq => 0,
        Cmp::Ne => 1,
        Cmp::Lt => 2,
        Cmp::Le => 3,
        Cmp::Gt => 4,
        Cmp::Ge => 5,
    });
}

fn cmp(r: &mut Reader<'_>) -> Option<Cmp> {
    Some(match r.u8()? {
        0 => Cmp::Eq,
        1 => Cmp::Ne,
        2 => Cmp::Lt,
        3 => Cmp::Le,
        4 => Cmp::Gt,
        5 => Cmp::Ge,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------------------------------------------------
// Expressions — depth bounded during the parse
// ---------------------------------------------------------------------------------------------------------------------

fn put_expr(out: &mut Vec<u8>, e: &Expr) {
    match e {
        Expr::Lit(v) => {
            out.push(0);
            put_value(out, v);
        }
        Expr::Load(k) => {
            out.push(1);
            put_key(out, k);
        }
        Expr::Arg(i) => {
            out.push(2);
            out.push(*i);
        }
        Expr::Bin(op, l, r) => {
            out.push(3);
            put_binop(out, *op);
            put_expr(out, l);
            put_expr(out, r);
        }
    }
}

fn expr(r: &mut Reader<'_>, depth: u32) -> Option<Expr> {
    if depth > EXPR_DEPTH_MAX {
        return None;
    }
    Some(match r.u8()? {
        0 => Expr::Lit(value(r)?),
        1 => Expr::Load(key(r)?),
        2 => Expr::Arg(r.u8()?),
        3 => {
            let op = binop(r)?;
            let lhs = expr(r, depth + 1)?;
            let rhs = expr(r, depth + 1)?;
            Expr::Bin(op, Box::new(lhs), Box::new(rhs))
        }
        _ => return None,
    })
}

// ---------------------------------------------------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------------------------------------------------

fn put_predicate(out: &mut Vec<u8>, p: &Predicate) {
    match p {
        Predicate::Host { kind, reads, args } => {
            out.push(0);
            put_u16(out, *kind);
            put_seq(out, reads, put_key);
            put_seq(out, args, put_expr);
        }
        Predicate::Compare { op, lhs, rhs } => {
            out.push(1);
            put_cmp(out, *op);
            put_expr(out, lhs);
            put_expr(out, rhs);
        }
        Predicate::And(parts) => {
            out.push(2);
            put_seq(out, parts, put_predicate);
        }
        Predicate::Or(parts) => {
            out.push(3);
            put_seq(out, parts, put_predicate);
        }
        Predicate::Not(inner) => {
            out.push(4);
            put_predicate(out, inner);
        }
    }
}

fn predicate(r: &mut Reader<'_>, depth: u32) -> Option<Predicate> {
    // Boolean structure nests too, and an `And(And(And(…)))` chain recurses just as a term does — so it shares the
    // expression bound rather than being unbounded because nobody thought of it.
    if depth > EXPR_DEPTH_MAX {
        return None;
    }
    Some(match r.u8()? {
        0 => {
            let kind = r.u16()?;
            let reads = r.seq(key)?;
            if !is_sorted_unique(&reads) {
                return None; // `Predicate::host` sorts; see `footprint`
            }
            let args = r.seq(|r| expr(r, 1))?;
            Predicate::Host { kind, reads, args }
        }
        1 => {
            let op = cmp(r)?;
            let lhs = expr(r, 1)?;
            let rhs = expr(r, 1)?;
            Predicate::Compare { op, lhs, rhs }
        }
        2 => Predicate::And(r.seq(|r| predicate(r, depth + 1))?),
        3 => Predicate::Or(r.seq(|r| predicate(r, depth + 1))?),
        4 => Predicate::Not(Box::new(predicate(r, depth + 1)?)),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------------------------------------------------
// Effects, claims, terms
// ---------------------------------------------------------------------------------------------------------------------

fn put_effect(out: &mut Vec<u8>, e: &Effect) {
    put_u16(out, e.kind);
    put_footprint(out, &e.footprint);
    put_seq(out, &e.args, put_expr);
    out.push(u8::from(e.external));
}

fn effect(r: &mut Reader<'_>) -> Option<Effect> {
    let kind = r.u16()?;
    let footprint = footprint(r)?;
    let args = r.seq(|r| expr(r, 1))?;
    let external = r.bool()?;
    Some(Effect { kind, footprint, args, external })
}

fn put_claim(out: &mut Vec<u8>, c: &Claim) {
    put_u16(out, c.kind);
    put_footprint(out, &c.footprint);
    put_u32(out, c.proof_bytes);
}

fn claim(r: &mut Reader<'_>) -> Option<Claim> {
    let kind = r.u16()?;
    let footprint = footprint(r)?;
    let proof_bytes = r.u32()?;
    Some(Claim { kind, footprint, proof_bytes })
}

fn put_term(out: &mut Vec<u8>, t: &Term) {
    match t {
        Term::Do(e) => {
            out.push(0);
            put_effect(out, e);
        }
        Term::Seq(cs) => {
            out.push(1);
            put_seq(out, cs, put_term);
        }
        Term::Par(cs) => {
            out.push(2);
            put_seq(out, cs, put_term);
        }
        Term::Gate(p, b) => {
            out.push(3);
            put_predicate(out, p);
            put_term(out, b);
        }
        Term::Alt(bs) => {
            out.push(4);
            put_seq(out, bs, |o, (p, b)| {
                put_predicate(o, p);
                put_term(o, b);
            });
        }
        Term::Prove(c) => {
            out.push(5);
            put_claim(out, c);
        }
    }
}

fn term(r: &mut Reader<'_>, depth: u32) -> Option<Term> {
    // The nesting ceiling, enforced here and not only in `well_typed`. `D_MAX` is derived rather than policy
    // (`P_crit^[4] > 1` forecloses a fourth order), so a deeper term is not expensive, it is *ill-typed* — and refusing it
    // during the parse is what stops a nested-`Seq` bomb from consuming the stack of a node that has not yet type-checked
    // anything.
    if depth > u32::from(D_MAX) {
        return None;
    }
    Some(match r.u8()? {
        0 => Term::Do(effect(r)?),
        1 => Term::Seq(r.seq(|r| term(r, depth + 1))?),
        2 => Term::Par(r.seq(|r| term(r, depth + 1))?),
        3 => {
            let p = predicate(r, 1)?;
            Term::Gate(p, Box::new(term(r, depth + 1)?))
        }
        4 => Term::Alt(r.seq(|r| {
            let p = predicate(r, 1)?;
            let b = term(r, depth + 1)?;
            Some((p, b))
        })?),
        5 => Term::Prove(claim(r)?),
        _ => return None,
    })
}

impl Term {
    /// The canonical encoding. A deployed contract's identity is the hash of this.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_term(&mut out, self);
        out
    }

    /// Decode a canonical encoding, or `None` if the bytes are not one.
    ///
    /// Total: no input panics, no input allocates unboundedly, and no input recurses past [`D_MAX`]. Non-canonical input
    /// is refused rather than repaired — see the module documentation for why that matters to an artefact identified by
    /// its hash.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let t = term(&mut r, 1)?;
        r.finish()?;
        Some(t)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {

    /// Every record type the ledger actually stores must survive the value language byte-identically, or the language
    /// does not represent the state it addresses — which was the whole finding that motivated `Record`.
    #[test]
    fn a_ledger_record_round_trips_byte_identically() {
        // Shaped like `NameRecord { owner, target, expiry }`: a digest, a variable-length blob, and a quantity. The
        // blob is the field the two scalars could not hold and the reason a hash-and-store-elsewhere workaround was
        // refused — a footprint naming a hash key while the mutation lands outside it is the trust assumption ERGON
        // deletes.
        let record = Value::record(vec![
            (0u16, Value::Bytes32([7u8; 32])),
            (2u16, Value::Int(4242)),
            (1u16, Value::Record(vec![(0u16, Value::Int(1)), (1u16, Value::Int(2))])),
        ])
        .expect("distinct tags");
        let mut bytes = Vec::new();
        put_value(&mut bytes, &record);
        let mut r = Reader::new(&bytes);
        assert_eq!(value(&mut r), Some(record.clone()), "a record must decode to itself");
        let mut again = Vec::new();
        put_value(&mut again, &record);
        assert_eq!(bytes, again, "and re-encode to the same bytes — the artefact hash is the contract's identity");
    }

    #[test]
    fn a_non_canonical_record_is_refused_rather_than_repaired() {
        // Two encodings of one record would be two identities, so the decoder must refuse rather than sort. Both
        // non-canonical shapes are rejected: out of order, and a repeated tag.
        for fields in [vec![(5u16, 1u128), (1u16, 2u128)], vec![(3u16, 1u128), (3u16, 2u128)]] {
            let mut bytes = vec![2u8];
            put_u16(&mut bytes, u16::try_from(fields.len()).unwrap());
            for (tag, n) in &fields {
                bytes.extend_from_slice(&tag.to_be_bytes());
                bytes.push(0);
                bytes.extend_from_slice(&n.to_be_bytes());
            }
            let mut r = Reader::new(&bytes);
            assert_eq!(value(&mut r), None, "non-canonical field order or a duplicate tag must not decode: {fields:?}");
        }
    }

    #[test]
    fn the_constructor_cannot_build_a_non_canonical_record() {
        // The decoder's refusal is the second line of defence, not the only one: a record that cannot be *built*
        // wrongly cannot be encoded wrongly either.
        assert!(Value::record(vec![(1u16, Value::Int(0)), (1u16, Value::Int(1))]).is_none(), "duplicate tag");
        let sorted = Value::record(vec![(9u16, Value::Int(0)), (2u16, Value::Int(1))]).expect("distinct tags");
        let Value::Record(fields) = &sorted else { panic!("a record") };
        assert_eq!(fields.first().map(|(t, _)| *t), Some(2), "the constructor puts fields in canonical order");
    }

    #[test]
    fn a_nesting_bomb_is_refused_during_the_parse_not_after_it() {
        // A few bytes that expand into an arbitrarily deep tree. Bounded DURING the parse, because a check applied to
        // the finished value has already paid for it — the same discipline the term codec uses.
        let mut bytes = Vec::new();
        for _ in 0..(EXPR_DEPTH_MAX + 4) {
            bytes.push(2);
            put_u16(&mut bytes, 1);
            bytes.extend_from_slice(&0u16.to_be_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&0u128.to_be_bytes());
        let mut r = Reader::new(&bytes);
        assert_eq!(value(&mut r), None, "a record nested past the addressable depth must be refused");
    }

    #[test]
    fn a_field_selector_reads_within_a_value_and_addresses_no_key() {
        // The property that keeps footprints derivable: selecting a field touches nothing the term did not already
        // name. Absence is a type error rather than a default, for the same reason `Missing` is not zero.
        let record = Value::record(vec![(1u16, Value::Int(7)), (4u16, Value::Bytes32([1u8; 32]))]).unwrap();
        assert_eq!(record.field(1).and_then(Value::as_int), Ok(7));
        assert_eq!(record.field(9).err(), Some(crate::value::Fault::TypeMismatch), "an absent field is a type error, not a default");
        assert_eq!(Value::Int(1).field(0).err(), Some(crate::value::Fault::TypeMismatch), "a scalar has no fields");
    }

    use super::*;
    use crate::exec::compare;
    use alloc::vec;

    fn k(n: u64) -> Key { Key::small(0 as PointId, 0, n) }

    /// A term using every constructor, so a round-trip test covers the whole grammar rather than the easy half.
    fn every_shape() -> Term {
        Term::Seq(vec![
            Term::Do(
                Effect::internal(1, Footprint::new(vec![k(1)], vec![k(2)]))
                    .with_args(vec![Expr::bin(BinOp::Div, Expr::Load(k(1)), Expr::int(2)), Expr::Arg(0)]),
            ),
            Term::Par(vec![
                Term::Do(Effect::external(2, Footprint::new(vec![], vec![k(3)]))),
                Term::Do(Effect::internal(3, Footprint::new(vec![], vec![k(4)]))),
            ]),
            Term::Gate(
                Predicate::And(vec![
                    compare(Cmp::Ge, Expr::Load(k(1)), Expr::int(10)),
                    Predicate::Not(Box::new(Predicate::host(7, vec![k(5), k(6)]))),
                ]),
                Box::new(Term::Do(Effect::internal(4, Footprint::empty()))),
            ),
            Term::Alt(vec![
                (compare(Cmp::Eq, Expr::Arg(1), Expr::bytes32([9u8; 32])), Term::Do(Effect::internal(5, Footprint::empty()))),
                (Predicate::Or(vec![compare(Cmp::Lt, Expr::int(1), Expr::int(2))]), Term::Prove(Claim {
                    kind: 6,
                    footprint: Footprint::new(vec![k(7)], vec![k(8)]),
                    proof_bytes: 1234,
                })),
            ]),
        ])
    }

    #[test]
    fn every_constructor_round_trips_and_the_encoding_is_unique() {
        let t = every_shape();
        let bytes = t.encode();
        let back = Term::decode(&bytes).expect("decodes");
        assert_eq!(back, t, "round trip is faithful");
        assert_eq!(back.encode(), bytes, "and the encoding of the decoded term is identical — a bijection, not a lossy map");
    }

    #[test]
    fn two_spellings_of_one_footprint_encode_identically() {
        // `Footprint::new` normalises, so this is really a test that the codec does not undo that — an encoder that wrote
        // insertion order would give one term two identities.
        let a = Effect::internal(1, Footprint::new(vec![k(3), k(1), k(3)], vec![k(2)]));
        let b = Effect::internal(1, Footprint::new(vec![k(1), k(3)], vec![k(2)]));
        assert_eq!(Term::Do(a).encode(), Term::Do(b).encode());
    }

    #[test]
    fn an_unsorted_footprint_is_refused_rather_than_repaired() {
        // The malleability check. Hand-build the bytes an unsorted encoder would produce and require rejection: repairing
        // it would mean two byte strings, two hashes, one behaviour — in the one place a hash is supposed to bind source
        // to conduct.
        let mut bytes = vec![0u8]; // Term::Do
        bytes.extend_from_slice(&1u16.to_be_bytes()); // kind
        bytes.extend_from_slice(&2u16.to_be_bytes()); // 2 reads, descending
        for key in [k(3), k(1)] {
            put_key(&mut bytes, &key);
        }
        bytes.extend_from_slice(&0u16.to_be_bytes()); // 0 writes
        bytes.extend_from_slice(&0u16.to_be_bytes()); // 0 args
        bytes.push(0); // not external
        assert!(Term::decode(&bytes).is_none(), "descending reads are not a canonical footprint");
    }

    #[test]
    fn a_duplicated_key_is_refused() {
        let mut bytes = vec![0u8];
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&2u16.to_be_bytes());
        for key in [k(1), k(1)] {
            put_key(&mut bytes, &key);
        }
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.push(0);
        assert!(Term::decode(&bytes).is_none(), "a repeated key is a second encoding of one read set");
    }

    #[test]
    fn a_non_boolean_byte_and_an_unknown_tag_are_refused() {
        let good = Term::Do(Effect::internal(1, Footprint::empty())).encode();
        let mut bad_bool = good.clone();
        let last = bad_bool.len() - 1;
        bad_bool[last] = 2; // `external` is neither 0 nor 1
        assert!(Term::decode(&bad_bool).is_none(), "two spellings of true would be two encodings");

        let mut bad_tag = good.clone();
        bad_tag[0] = 99;
        assert!(Term::decode(&bad_tag).is_none(), "an unknown tag must not be silently reinterpreted");
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = Term::Do(Effect::internal(1, Footprint::empty())).encode();
        bytes.push(0);
        assert!(Term::decode(&bytes).is_none(), "extra data is a different artefact");
    }

    #[test]
    fn a_nesting_bomb_is_refused_during_the_parse() {
        // The reason depth is checked here and not only in `well_typed`: this input must be refused *before* the value it
        // would build exists. Constructed by hand because `encode` can only be fed a term, and a term this deep is one no
        // encoder in this crate would produce.
        let mut bytes = Vec::new();
        for _ in 0..64 {
            bytes.push(1); // Term::Seq
            bytes.extend_from_slice(&1u16.to_be_bytes()); // with exactly one child
        }
        bytes.push(0); // …eventually a Do
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.push(0);
        assert!(Term::decode(&bytes).is_none(), "64 levels of Seq is refused, and D_MAX is 3");
    }

    #[test]
    fn no_truncation_of_a_valid_encoding_ever_panics() {
        // Totality, exhaustively over one term rather than by assertion. Every prefix is either a clean `None` or — for
        // the full length — the term itself; nothing in between may panic or hang.
        let bytes = every_shape().encode();
        for cut in 0..bytes.len() {
            assert!(Term::decode(&bytes[..cut]).is_none(), "prefix of length {cut} decoded");
        }
        assert!(Term::decode(&bytes).is_some());
    }

    #[test]
    fn a_huge_sequence_count_is_refused_before_it_allocates() {
        let mut bytes = vec![1u8]; // Term::Seq
        bytes.extend_from_slice(&u16::MAX.to_be_bytes()); // 65 535 children, none of them present
        assert!(Term::decode(&bytes).is_none(), "the count is bounded before anything is built");
    }
}
