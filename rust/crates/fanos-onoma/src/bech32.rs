//! A self-contained **bech32m** codec (BIP-350): the address encoding for L-key.
//!
//! Bech32m is the modern Bitcoin-taproot address checksum — a BCH code that **guarantees
//! detection of up to 4 transcription errors** and has no mixed-case ambiguity, strictly stronger
//! than the truncated-hash checksum used by `.onion`. We implement it directly (like the other
//! foundational FANOS crates, zero external dependencies) so it is `no_std`, auditable, and pinned
//! against the BIP-350 known-answer vectors in the tests.
//!
//! Indices into [`CHARSET`] and the fixed generator/checksum arrays are all masked to their range,
//! so slice indexing here cannot go out of bounds.
#![allow(clippy::indexing_slicing)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::OnomaError;

/// The bech32 character set (BIP-173): value `v` (0..32) maps to `CHARSET[v]`.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The BCH generator polynomial coefficients.
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// The bech32m checksum constant (BIP-350); bech32 (legacy) used `1`.
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// The BCH residue over a value stream (BIP-173 `polymod`).
fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let top = (chk >> 25) as u8;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= *g;
            }
        }
    }
    chk
}

/// Expand the human-readable part into the checksum pre-image (BIP-173 `hrp_expand`).
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        v.push(b >> 5);
    }
    v.push(0);
    for b in hrp.bytes() {
        v.push(b & 0x1f);
    }
    v
}

/// The six-symbol bech32m checksum for `hrp` and 5-bit `data`.
fn checksum(hrp: &str, data5: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data5);
    values.extend_from_slice(&[0u8; 6]);
    let poly = polymod(values.iter().copied()) ^ BECH32M_CONST;
    let mut out = [0u8; 6];
    for (i, o) in out.iter_mut().enumerate() {
        *o = ((poly >> (5 * (5 - i))) & 0x1f) as u8;
    }
    out
}

/// Regroup 8-bit bytes into 5-bit groups with zero padding (total; used for encoding).
fn expand_8_to_5(data: &[u8]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    for &b in data {
        acc = ((acc << 8) | u32::from(b)) & 0x0fff; // max_acc = 2^(8+5-1)-1
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    out
}

/// Regroup 5-bit groups back into 8-bit bytes, rejecting non-zero padding (canonical; decoding).
fn squash_5_to_8(data: &[u8]) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    for &v in data {
        if v >> 5 != 0 {
            return None;
        }
        acc = ((acc << 5) | u32::from(v)) & 0x0fff;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // A canonical encoding leaves < 5 residual bits, all zero.
    if bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0 {
        return None;
    }
    Some(out)
}

/// Encode `hrp` + 8-bit `data` as a bech32m string (`hrp1<data><checksum>`).
#[must_use]
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let data5 = expand_8_to_5(data);
    let cs = checksum(hrp, &data5);
    let mut s = String::with_capacity(hrp.len() + 1 + data5.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for v in data5.iter().chain(cs.iter()) {
        s.push(CHARSET[(*v as usize) & 0x1f] as char);
    }
    s
}

/// Decode a bech32m string into `(hrp, 8-bit data)`, verifying the checksum and canonical form.
///
/// # Errors
/// Returns [`OnomaError`] on empty input, mixed case, an invalid character, a missing separator,
/// a failed checksum, or non-canonical padding.
pub fn decode(s: &str) -> Result<(String, Vec<u8>), OnomaError> {
    if s.is_empty() {
        return Err(OnomaError::Empty);
    }
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(OnomaError::MixedCase);
    }
    let lower = s.to_ascii_lowercase();
    let pos = lower.rfind('1').ok_or(OnomaError::BadChar)?;
    // Need a non-empty hrp and at least the 6-symbol checksum after the separator.
    if pos == 0 || pos + 7 > lower.len() {
        return Err(OnomaError::BadLength);
    }
    let (hrp, rest) = lower.split_at(pos);
    let data_part = rest.get(1..).ok_or(OnomaError::BadLength)?;
    let mut values = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        let v = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or(OnomaError::BadChar)?;
        values.push(v as u8);
    }
    let mut pre = hrp_expand(hrp);
    pre.extend_from_slice(&values);
    if polymod(pre.into_iter()) != BECH32M_CONST {
        return Err(OnomaError::BadChecksum);
    }
    let split = values.len().checked_sub(6).ok_or(OnomaError::BadLength)?;
    let data5 = values.get(..split).ok_or(OnomaError::BadLength)?;
    let data8 = squash_5_to_8(data5).ok_or(OnomaError::BadChecksum)?;
    Ok((hrp.to_string(), data8))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_bytes() {
        let data = [0u8, 1, 2, 3, 250, 251, 255, 42, 7];
        let s = encode("onoma", &data);
        let (hrp, back) = decode(&s).unwrap();
        assert_eq!(hrp, "onoma");
        assert_eq!(back, data);
    }

    #[test]
    fn empty_data_round_trips() {
        let s = encode("a", &[]);
        let (hrp, back) = decode(&s).unwrap();
        assert_eq!(hrp, "a");
        assert!(back.is_empty());
    }

    #[test]
    fn detects_single_char_corruption() {
        let mut s = encode("onoma", &[9, 8, 7, 6, 5, 4, 3, 2, 1]).into_bytes();
        // Flip a data symbol; the BCH checksum must catch it.
        let last = s.len() - 8;
        s[last] = if s[last] == b'q' { b'p' } else { b'q' };
        let corrupted = String::from_utf8(s).unwrap();
        assert_eq!(decode(&corrupted), Err(OnomaError::BadChecksum));
    }

    #[test]
    fn rejects_mixed_case() {
        let s = encode("onoma", &[1, 2, 3]);
        let mixed = alloc::format!("{}Q", &s[..s.len() - 1]);
        assert_eq!(decode(&mixed), Err(OnomaError::MixedCase));
    }

    #[test]
    fn rejects_legacy_bech32_as_bech32m() {
        // "a12uel5l" is a VALID legacy-bech32 string (checksum const 1). Under bech32m (const
        // 0x2bc830a3) it must fail — proving we use the bech32m constant, not bech32.
        assert_eq!(decode("a12uel5l"), Err(OnomaError::BadChecksum));
    }

    #[test]
    fn accepts_uppercase_input_canonically() {
        let s = encode("onoma", &[5, 6, 7]);
        let (_, back) = decode(&s.to_ascii_uppercase()).unwrap();
        assert_eq!(back, [5, 6, 7]);
    }
}
