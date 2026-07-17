//! A dictionary-free, pronounceable rendering of an address commitment — for **human
//! verification** ("read me your service's words"), which humans do far more reliably than
//! comparing base32.
//!
//! We use **proquints** (Wilkerson's *pronounceable quintuplets*): each 16-bit group becomes a
//! consonant-vowel-consonant-vowel-consonant syllable from a fixed 16-consonant / 4-vowel table.
//! Unlike a BIP-39-style wordlist this needs no embedded dictionary, so it is tiny, `no_std`, and
//! trivially identical across implementations. The 256-bit commitment renders as 16 proquints.
//!
//! Table indices are masked to 4/2 bits, so they are always in range.
#![allow(clippy::indexing_slicing)]

use alloc::string::String;
use core::fmt::Write;

/// 16 consonants (4 bits each).
const CONSONANTS: &[u8; 16] = b"bdfghjklmnprstvz";
/// 4 vowels (2 bits each).
const VOWELS: &[u8; 4] = b"aiou";

/// Append the proquint for one 16-bit word.
fn push_proquint(word: u16, out: &mut String) {
    let w = word as usize;
    out.push(CONSONANTS[(w >> 12) & 0x0f] as char);
    out.push(VOWELS[(w >> 10) & 0x03] as char);
    out.push(CONSONANTS[(w >> 6) & 0x0f] as char);
    out.push(VOWELS[(w >> 4) & 0x03] as char);
    out.push(CONSONANTS[w & 0x0f] as char);
}

/// Render `version` + a 32-byte commitment as `v<version>-<proquint>-…` (16 proquints).
#[must_use]
pub fn encode_commitment(version: u8, commitment: &[u8; 32]) -> String {
    let mut s = String::with_capacity(2 + 16 * 6);
    let _ = write!(s, "v{version}");
    let (pairs, _rest) = commitment.as_chunks::<2>();
    for &[hi, lo] in pairs {
        let word = (u16::from(hi) << 8) | u16::from(lo);
        s.push('-');
        push_proquint(word, &mut s);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_deterministic_and_shaped() {
        let c = [0x11u8; 32];
        let m = encode_commitment(1, &c);
        assert_eq!(m, encode_commitment(1, &c));
        // "v1" + 16 groups of "-xxxxx"
        assert_eq!(m.matches('-').count(), 16);
        assert!(m.starts_with("v1-"));
    }

    #[test]
    fn distinguishes_commitments() {
        let a = encode_commitment(1, &[0x00; 32]);
        let b = encode_commitment(1, &[0x01; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn known_word_mapping() {
        // 0x0000 -> "babab" (all-zero indices), 0xffff -> "zuzuz" (all-max indices).
        let mut s = String::new();
        push_proquint(0x0000, &mut s);
        assert_eq!(s, "babab");
        s.clear();
        push_proquint(0xffff, &mut s);
        assert_eq!(s, "zuzuz");
    }
}
