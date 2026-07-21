//! # fanos-code — the innate error-correcting codes of `PG(2, q)`
//!
//! A FANOS cell carries error correction for free, because its geometry *is* a code
//! (spec §2.4): the base Fano cell coincides with the Hamming(7,4) code, whose 7 weight-3
//! codewords are the 7 lines, and the projective plane at any `q` is a locally-recoverable
//! code (LRC). This crate exposes both, and the DIAKRISIS fault localizer built on them:
//!
//! * [`hamming`] — the Hamming(7,4) / Fano correspondence and single-error syndrome (V10).
//! * [`syndrome`] — the `21 → 7 → 3 → 1` localization pyramid: 3-bit syndrome for one fault,
//!   the 7-theme layer for two (V13, V21).
//! * [`lrc`] — projective erasure repair by peeling, and hyperoval failure (V9, V20): a
//!   recoverability *oracle* only.
//! * [`erasure`] — the byte-level `[7,3,4]` simplex codec built on `lrc`'s peeling (spec
//!   §L4): the actual erasure-coded data path. Needs the `alloc` feature (a heap to hold the
//!   coded shards); `hamming`/`lrc`/`syndrome` do not.
//!
//! `#![no_std]`; the `hamming`/`lrc`/`syndrome` tables are compile-time and the decoders are
//! branch-light bit work.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod hamming;
pub mod lrc;
pub mod syndrome;

#[cfg(feature = "alloc")]
pub mod da;
#[cfg(feature = "alloc")]
pub mod erasure;

pub use hamming::{LINE_CODEWORDS, point_address, syndrome as hamming_syndrome};
pub use lrc::{is_hyperoval_fano, is_recoverable_fano, peel_fano};
pub use syndrome::{Fault, Sector, decode_themes, locate, syndrome3, theme_flags};

#[cfg(feature = "alloc")]
pub use da::{false_available_bound, line_present, sample_lines, samples_pass};
#[cfg(feature = "alloc")]
pub use erasure::{encode, reconstruct};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    //! Cross-module integration: the three layers describe one coherent structure.
    use super::*;

    #[test]
    fn syndrome_and_lrc_agree_on_single_fault() {
        // A single crash is both localized by the syndrome and trivially peel-recoverable.
        for i in 0..7 {
            let mask = 1u8 << i;
            assert_eq!(locate(mask), Fault::Single(i));
            assert!(is_recoverable_fano(mask));
        }
    }

    #[test]
    fn lines_and_codewords_are_the_same_seven_objects() {
        // The 7 LINE_CODEWORDS (from the code) and the 7 geometric lines (via addresses)
        // are the same set — the V10 coincidence, checked once more at the crate root.
        use fanos_geometry::fano;
        let mut from_geometry = [0u8; 7];
        for (l, line) in fano::LINE_POINTS.iter().enumerate() {
            let mut mask = 0u8;
            for &p in line {
                mask |= 1 << (point_address(p as usize) - 1);
            }
            from_geometry[l] = mask;
        }
        from_geometry.sort_unstable();
        let mut from_code = LINE_CODEWORDS;
        from_code.sort_unstable();
        assert_eq!(from_geometry, from_code);
    }
}
