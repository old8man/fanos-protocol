//! The [`Wire`] trait — canonical encode/decode for framed types, deriveable with `#[derive(Wire)]`
//! (the `fanos-wire-derive` crate). The single rule is **canonical encoding**: exactly one valid byte
//! sequence per object, so a decoder rejects everything else — that is what makes hashes, signatures,
//! and MACs agree across implementations (spec §7.1). [`Wire::from_wire`] enforces the rule at the top
//! level by rejecting trailing bytes.
//!
//! `#[derive(Wire)]` implements the trait for a struct by encoding/decoding each field **in declaration
//! order**; primitive impls are provided here for the fixed-width integers (big-endian), fixed byte
//! arrays, `bool`, and a length-prefixed `Vec<u8>`. Composition is canonical because every part is.

use alloc::vec::Vec;

use crate::error::WireError;
use crate::varint;

/// A type with a single canonical byte encoding.
pub trait Wire: Sized {
    /// Append the canonical bytes of `self` to `out`.
    fn wire_encode(&self, out: &mut Vec<u8>);

    /// Decode one value from the front of `*cur`, advancing `*cur` past the bytes it consumed.
    ///
    /// # Errors
    /// A [`WireError`] if the input is too short or not canonical.
    fn wire_decode(cur: &mut &[u8]) -> Result<Self, WireError>;

    /// Encode to a fresh `Vec`.
    #[must_use]
    fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.wire_encode(&mut out);
        out
    }

    /// Decode from a complete slice, **rejecting trailing bytes**. This enforces the canonical
    /// one-encoding rule: two distinct byte strings can never decode to the same object.
    ///
    /// # Errors
    /// [`WireError::TrailingBytes`] if any bytes remain after the object, or any decode error.
    fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let mut cur = bytes;
        let value = Self::wire_decode(&mut cur)?;
        if cur.is_empty() {
            Ok(value)
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

/// Split exactly `n` bytes off the front of `*cur`, advancing it; `UnexpectedEnd` if it is too short.
pub(crate) fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], WireError> {
    if cur.len() < n {
        return Err(WireError::UnexpectedEnd);
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

macro_rules! impl_wire_int {
    ($($t:ty),*) => {$(
        impl Wire for $t {
            fn wire_encode(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
            fn wire_decode(cur: &mut &[u8]) -> Result<Self, WireError> {
                let bytes = take(cur, core::mem::size_of::<$t>())?;
                let arr = bytes.try_into().map_err(|_| WireError::UnexpectedEnd)?;
                Ok(<$t>::from_be_bytes(arr))
            }
        }
    )*};
}
impl_wire_int!(u8, u16, u32, u64, i16, i32, i64);

/// IEEE-754 `f32`, encoded as its big-endian bit pattern (`to_bits`) — bit-exact and portable, the
/// convention the coherence telemetry frames already use.
impl Wire for f32 {
    fn wire_encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_bits().to_be_bytes());
    }
    fn wire_decode(cur: &mut &[u8]) -> Result<Self, WireError> {
        Ok(Self::from_bits(u32::wire_decode(cur)?))
    }
}

impl Wire for bool {
    fn wire_encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }
    fn wire_decode(cur: &mut &[u8]) -> Result<Self, WireError> {
        match take(cur, 1)?.first() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            // A bool is canonically 0 or 1; anything else is non-canonical.
            _ => Err(WireError::FieldElementOutOfRange),
        }
    }
}

impl<const N: usize> Wire for [u8; N] {
    fn wire_encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
    fn wire_decode(cur: &mut &[u8]) -> Result<Self, WireError> {
        take(cur, N)?
            .try_into()
            .map_err(|_| WireError::UnexpectedEnd)
    }
}

/// A byte string, encoded **length-prefixed** with a minimal QUIC varint, so it composes canonically as
/// a struct field (a bare tail would be ambiguous under composition). The length is bounded by the
/// remaining input, so a hostile prefix cannot force a huge allocation.
impl Wire for Vec<u8> {
    fn wire_encode(&self, out: &mut Vec<u8>) {
        varint::encode(self.len() as u64, out);
        out.extend_from_slice(self);
    }
    fn wire_decode(cur: &mut &[u8]) -> Result<Self, WireError> {
        let (len, consumed) = varint::decode(cur)?;
        *cur = cur.get(consumed..).ok_or(WireError::UnexpectedEnd)?;
        let len = usize::try_from(len).map_err(|_| WireError::ValueTooLarge)?;
        Ok(take(cur, len)?.to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A round-trip helper that also asserts `from_wire` rejects a trailing byte (canonicity).
    fn round_trip<T: Wire + PartialEq + core::fmt::Debug>(value: &T) {
        let bytes = value.to_wire();
        assert_eq!(&T::from_wire(&bytes).unwrap(), value, "round-trips");
        let mut extended = bytes.clone();
        extended.push(0);
        assert_eq!(
            T::from_wire(&extended),
            Err(WireError::TrailingBytes),
            "from_wire rejects trailing bytes (canonical)"
        );
    }

    #[test]
    fn primitives_round_trip_and_reject_trailing() {
        round_trip(&0x12u8);
        round_trip(&0xABCDu16);
        round_trip(&0x1234_5678u32);
        round_trip(&0x0123_4567_89AB_CDEFu64);
        round_trip(&true);
        round_trip(&false);
        round_trip(&[1u8, 2, 3, 4, 5]);
        round_trip(&alloc::vec![9u8; 130]); // Vec<u8> with a 2-byte varint length
    }

    #[test]
    fn integers_are_big_endian_and_length_checked() {
        assert_eq!(0x0102u16.to_wire(), alloc::vec![0x01, 0x02]);
        assert_eq!(u32::from_wire(&[0, 0, 0]), Err(WireError::UnexpectedEnd));
    }

    #[test]
    fn a_non_canonical_bool_is_rejected() {
        assert_eq!(bool::from_wire(&[2]), Err(WireError::FieldElementOutOfRange));
    }

    #[test]
    fn a_vec_length_prefix_cannot_over_read() {
        // A varint claiming 200 bytes with only 1 present is rejected, not a huge alloc.
        let mut bytes = Vec::new();
        varint::encode(200, &mut bytes);
        bytes.push(0xAA);
        assert_eq!(Vec::<u8>::from_wire(&bytes), Err(WireError::UnexpectedEnd));
    }
}
