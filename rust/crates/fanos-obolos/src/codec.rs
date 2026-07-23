//! Canonical **wire encoding** for the OBOLOS objects that cross the network and the ledger — the shielded
//! transaction and its proof. Deterministic and length-checked, so every node encodes the identical bytes and
//! agrees on the transaction's identity; it is what a TAXIS/DROMOS `StateMachine` decodes from a committed
//! transaction payload, and what a wallet puts on the wire.
//!
//! The encoding is a plain concatenation of fixed-width fields with `u32` length prefixes on the vectors; no
//! self-description, because the schema is fixed by this module. Parsing is total — malformed or truncated
//! bytes return `None`, never panic (the workspace forbids indexing/slicing that could).

use alloc::vec::Vec;

use crate::commit::{Commitment, Randomness};
use crate::note::Note;
use crate::note_cipher::NoteCipher;
use crate::nullifier::Nullifier;
use crate::tree::{AuthPath, TREE_DEPTH};
use crate::tx::{InputOpening, OutputNote, OutputOpening, ShieldedTx, TransparentProof};

/// A minimal forward-only byte reader — index-free, so a malformed length can only yield `None`.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn array32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }

    /// Whether the reader has consumed exactly all its bytes — a canonical encoding has no trailing garbage.
    fn is_exhausted(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// The remaining unread bytes (consuming them).
    fn rest(&mut self) -> &'a [u8] {
        let s = self.buf.get(self.pos..).unwrap_or(&[]);
        self.pos = self.buf.len();
        s
    }
}

// ── Component encoders/decoders ─────────────────────────────────────────────────────────────────────────────

fn put_commitment(out: &mut Vec<u8>, c: &Commitment) {
    out.extend_from_slice(&c.to_bytes());
}

fn get_commitment(r: &mut Reader<'_>) -> Option<Commitment> {
    Commitment::from_bytes(r.take(Commitment::WIRE_LEN)?)
}

fn put_randomness(out: &mut Vec<u8>, x: &Randomness) {
    out.extend_from_slice(&x.to_bytes());
}

fn get_randomness(r: &mut Reader<'_>) -> Option<Randomness> {
    Randomness::from_bytes(r.take(Randomness::WIRE_LEN)?)
}

fn put_note(out: &mut Vec<u8>, n: &Note) {
    out.extend_from_slice(&n.value.to_le_bytes());
    out.extend_from_slice(&n.owner);
    put_randomness(out, &n.value_r);
    out.extend_from_slice(&n.rho);
}

fn get_note(r: &mut Reader<'_>) -> Option<Note> {
    let value = r.u64()?;
    let owner = r.array32()?;
    let value_r = get_randomness(r)?;
    let rho = r.array32()?;
    Some(Note::new(value, owner, value_r, rho))
}

fn put_auth_path(out: &mut Vec<u8>, p: &AuthPath) {
    out.extend_from_slice(&p.index.to_le_bytes());
    for sib in &p.siblings {
        out.extend_from_slice(sib);
    }
}

fn get_auth_path(r: &mut Reader<'_>) -> Option<AuthPath> {
    let index = r.u64()?;
    let mut siblings = [[0u8; 32]; TREE_DEPTH];
    for sib in &mut siblings {
        *sib = r.array32()?;
    }
    Some(AuthPath { index, siblings })
}

// ── Value-commitment (de)serialization lives here to keep the wire schema in one module ─────────────────────

impl Commitment {
    /// The fixed serialized length of a commitment (`N` `i64` for `t0`, plus `t1`).
    pub const WIRE_LEN: usize = (crate::commit::N + 1) * 8;

    /// Decode a commitment from [`to_bytes`](Self::to_bytes). `None` on the wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        let mut r = Reader::new(bytes);
        let mut t0 = Vec::with_capacity(crate::commit::N);
        for _ in 0..crate::commit::N {
            t0.push(r.i64()?);
        }
        let t1 = r.i64()?;
        Some(Self::from_parts(t0, t1))
    }
}

impl Randomness {
    /// The fixed serialized length of commitment randomness (`L` `i64`).
    pub const WIRE_LEN: usize = crate::commit::L * 8;

    /// Canonical bytes: the `L` coefficients as little-endian `i64` (centered representation).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        for &c in self.coeffs_ref() {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes). `None` on the wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        let mut r = Reader::new(bytes);
        let mut coeffs = Vec::with_capacity(crate::commit::L);
        for _ in 0..crate::commit::L {
            coeffs.push(r.i64()?);
        }
        // Reject non-ternary randomness (audit §3.2). The wire is attacker-controlled; commitment randomness is
        // ALWAYS ternary (`{−1, 0, 1}^L`). Without this bound, full-range i64 coefficients make the `A₁·r` dot
        // product (`L = 256` terms of `≈2⁶¹ · x`) reach `≈2¹³²`, overflowing `i128` — which PANICS every
        // overflow-checked validator on the consensus verify path (a single decodable `TAG_SHIELDED` submission
        // → network-wide halt) or, in release, silently wraps and voids the mod-`Q` inflation bound (O-C1).
        let rand = Self::from_coeffs(coeffs);
        rand.is_ternary().then_some(rand)
    }
}

// ── The wire objects ────────────────────────────────────────────────────────────────────────────────────────

impl ShieldedTx {
    /// Canonical bytes of the public transaction.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.anchor);
        out.extend_from_slice(&(self.nullifiers.len() as u32).to_le_bytes());
        for nf in &self.nullifiers {
            out.extend_from_slice(nf.as_bytes());
        }
        out.extend_from_slice(&(self.input_values.len() as u32).to_le_bytes());
        for c in &self.input_values {
            put_commitment(&mut out, c);
        }
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            out.extend_from_slice(&o.note_commitment);
            put_commitment(&mut out, &o.value_commitment);
            match &o.cipher {
                Some(c) => {
                    let cb = c.to_bytes();
                    out.push(1);
                    out.extend_from_slice(&(cb.len() as u32).to_le_bytes());
                    out.extend_from_slice(&cb);
                }
                None => out.push(0),
            }
        }
        out.extend_from_slice(&self.fee.to_le_bytes());
        out.extend_from_slice(&self.public_value.to_le_bytes());
        out.extend_from_slice(&self.public_recipient);
        out
    }

    /// Decode a transaction from [`to_bytes`](Self::to_bytes), or `None` if malformed/truncated/over-long.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let anchor = r.array32()?;
        let nullifiers = read_vec(&mut r, |r| Some(Nullifier::from_bytes(r.array32()?)))?;
        let input_values = read_vec(&mut r, get_commitment)?;
        let outputs = read_vec(&mut r, |r| {
            let note_commitment = r.array32()?;
            let value_commitment = get_commitment(r)?;
            let cipher = match r.u8()? {
                0 => None,
                1 => {
                    let len = r.u32()? as usize;
                    Some(NoteCipher::from_bytes(r.take(len)?)?)
                }
                _ => return None,
            };
            Some(OutputNote { note_commitment, value_commitment, cipher })
        })?;
        let fee = r.u64()?;
        let public_value = r.u64()?;
        let public_recipient = r.array32()?;
        r.is_exhausted()
            .then_some(Self { anchor, nullifiers, input_values, outputs, fee, public_value, public_recipient })
    }
}

impl TransparentProof {
    /// Canonical bytes of the transparent proof (the revealed witness).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for i in &self.inputs {
            put_note(&mut out, &i.note);
            put_auth_path(&mut out, &i.path);
            out.extend_from_slice(&i.nsk);
            put_randomness(&mut out, &i.value_r_in);
        }
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            out.extend_from_slice(&o.value.to_le_bytes());
            put_randomness(&mut out, &o.value_r);
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let inputs = read_vec(&mut r, |r| {
            let note = get_note(r)?;
            let path = get_auth_path(r)?;
            let nsk = r.array32()?;
            let value_r_in = get_randomness(r)?;
            Some(InputOpening { note, path, nsk, value_r_in })
        })?;
        let outputs = read_vec(&mut r, |r| {
            let value = r.u64()?;
            let value_r = get_randomness(r)?;
            Some(OutputOpening { value, value_r })
        })?;
        r.is_exhausted().then_some(Self { inputs, outputs })
    }
}

/// Encode a shielded transaction together with its (transparent) proof as one ledger **submission payload**:
/// `tx_len(u32) ‖ tx ‖ proof`. This is exactly what a TAXIS transaction carries; a DROMOS `StateMachine`
/// decodes it with [`decode_submission`]. (When the zero-knowledge backend lands, the trailing `proof` becomes
/// the succinct proof — the framing is unchanged.)
#[must_use]
pub fn encode_submission(tx: &ShieldedTx, proof: &TransparentProof) -> Vec<u8> {
    let tx_bytes = tx.to_bytes();
    let proof_bytes = proof.to_bytes();
    let mut out = Vec::with_capacity(4 + tx_bytes.len() + proof_bytes.len());
    out.extend_from_slice(&(tx_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&tx_bytes);
    out.extend_from_slice(&proof_bytes);
    out
}

/// Decode a [`encode_submission`] payload back into `(transaction, proof)`, or `None` if malformed.
#[must_use]
pub fn decode_submission(bytes: &[u8]) -> Option<(ShieldedTx, TransparentProof)> {
    let mut r = Reader::new(bytes);
    let tx_len = r.u32()? as usize;
    let tx = ShieldedTx::from_bytes(r.take(tx_len)?)?;
    let proof = TransparentProof::from_bytes(r.rest())?;
    Some((tx, proof))
}

/// Read a `u32`-length-prefixed vector, decoding each element with `f`.
fn read_vec<T>(r: &mut Reader<'_>, mut f: impl FnMut(&mut Reader<'_>) -> Option<T>) -> Option<Vec<T>> {
    let count = r.u32()? as usize;
    let mut out = Vec::with_capacity(count.min(1024)); // cap the pre-allocation; genuine over-count fails in f
    for _ in 0..count {
        out.push(f(r)?);
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::commit::Params;
    use crate::note::derive_owner_pk;
    use crate::state::ShieldedState;
    use crate::{SpendInput, build_transfer};

    fn note(value: u64, nsk: &[u8; 32], tag: &[u8]) -> Note {
        Note::new(value, derive_owner_pk(nsk), Randomness::from_seed(tag), [tag.len() as u8; 32])
    }

    #[test]
    fn a_commitment_round_trips() {
        let p = Params::standard();
        let c = Commitment::commit(&p, 12_345, &Randomness::from_seed(b"c"));
        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), Commitment::WIRE_LEN);
        assert_eq!(Commitment::from_bytes(&bytes), Some(c));
        assert_eq!(Commitment::from_bytes(&bytes[..bytes.len() - 1]), None, "a truncated commitment is rejected");
    }

    #[test]
    fn randomness_round_trips_and_rejects_non_ternary() {
        // Genuine ternary randomness round-trips.
        let x = Randomness::from_seed(b"x");
        let bytes = x.to_bytes();
        assert_eq!(bytes.len(), Randomness::WIRE_LEN);
        assert_eq!(Randomness::from_bytes(&bytes), Some(x));
        // Audit §3.2: a NON-ternary coefficient is refused at decode, so a crafted `TAG_SHIELDED` submission
        // can never drive the `A₁·r` dot product to overflow the consensus verify path. (Centered balance
        // randomness — `sub`, coefficients in `{−2,…,2}` — is an internal verify-time computation and is
        // deliberately never serialized onto the wire; every opening's randomness is ternary, from_seed.)
        let mut bad = Randomness::from_seed(b"ok").to_bytes();
        bad[..8].copy_from_slice(&i64::MAX.to_le_bytes());
        assert_eq!(Randomness::from_bytes(&bad), None, "a full-range coefficient is refused");
        bad[..8].copy_from_slice(&2i64.to_le_bytes());
        assert_eq!(Randomness::from_bytes(&bad), None, "even a coefficient of 2 (just past ternary) is refused");
    }

    #[test]
    fn a_shielded_transaction_and_its_proof_round_trip() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let mut s = ShieldedState::new();
        let n0 = note(1000, &nsk, b"n0");
        let pos = s.mint(n0.commitment(&p)).unwrap();
        let sp = SpendInput { note: n0, nsk, path: s.path(pos).unwrap() };
        let (tx, proof) =
            build_transfer(&p, s.anchor(), &[sp], &[note(600, &[2u8; 32], b"a"), note(400, &[3u8; 32], b"b")], 0);

        let tx_bytes = tx.to_bytes();
        assert_eq!(ShieldedTx::from_bytes(&tx_bytes), Some(tx.clone()), "the transaction round-trips");
        assert_eq!(ShieldedTx::from_bytes(&[tx_bytes.as_slice(), b"x"].concat()), None, "trailing bytes are rejected");

        let pf_bytes = proof.to_bytes();
        assert_eq!(TransparentProof::from_bytes(&pf_bytes), Some(proof), "the proof round-trips");

        // The decoded transaction verifies and applies exactly as the original — encoding is faithful.
        let decoded = ShieldedTx::from_bytes(&tx_bytes).unwrap();
        let decoded_proof = TransparentProof::from_bytes(&pf_bytes).unwrap();
        assert_eq!(s.apply(&p, &decoded, &decoded_proof), Ok(()), "a round-tripped tx applies");
    }

    #[test]
    fn a_non_ternary_opening_is_refused_not_overflowed() {
        // Audit §3.2 defense-in-depth: a proof carrying a long (non-ternary) opening randomness is REJECTED by
        // the relation — the shortness gate runs before any `commit`, so the `A₁·r` dot product is never
        // evaluated on a long coefficient and cannot overflow/panic the consensus verify path.
        let p = Params::standard();
        let nsk = [1u8; 32];
        let mut s = ShieldedState::new();
        let n0 = note(1000, &nsk, b"n0");
        let pos = s.mint(n0.commitment(&p)).unwrap();
        let sp = SpendInput { note: n0, nsk, path: s.path(pos).unwrap() };
        let (tx, mut proof) =
            build_transfer(&p, s.anchor(), &[sp], &[note(600, &[2u8; 32], b"a"), note(400, &[3u8; 32], b"b")], 0);
        // Smuggle a full-range coefficient into the first input opening's re-randomisation (a non-wire path).
        proof.inputs[0].value_r_in = Randomness::from_coeffs((0..crate::commit::L).map(|_| i64::MAX).collect());
        assert!(s.apply(&p, &tx, &proof).is_err(), "a long-randomness opening is refused, not overflowed");
    }

    #[test]
    fn a_submission_payload_round_trips() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let mut s = ShieldedState::new();
        let n0 = note(1000, &nsk, b"n0");
        let pos = s.mint(n0.commitment(&p)).unwrap();
        let sp = SpendInput { note: n0, nsk, path: s.path(pos).unwrap() };
        let (tx, proof) = build_transfer(&p, s.anchor(), &[sp], &[note(1000, &[2u8; 32], b"a")], 0);
        let payload = encode_submission(&tx, &proof);
        let (tx2, proof2) = decode_submission(&payload).expect("submission round-trips");
        assert_eq!(tx2, tx);
        assert_eq!(proof2, proof);
        assert_eq!(s.apply(&p, &tx2, &proof2), Ok(()), "the decoded submission applies");
        assert_eq!(decode_submission(&payload[..payload.len() - 1]), None, "a truncated submission is rejected");
    }

    #[test]
    fn garbage_and_truncation_are_rejected_without_panic() {
        assert_eq!(ShieldedTx::from_bytes(&[]), None);
        assert_eq!(ShieldedTx::from_bytes(&[0xFF; 3]), None);
        assert_eq!(TransparentProof::from_bytes(&[0xFF; 5]), None);
        // A huge length prefix must not over-allocate or panic — it simply runs out of bytes.
        let mut evil = [0u8; 32].to_vec(); // anchor
        evil.extend_from_slice(&u32::MAX.to_le_bytes()); // claims 4 billion nullifiers
        assert_eq!(ShieldedTx::from_bytes(&evil), None, "an oversized count fails cleanly");
    }
}
