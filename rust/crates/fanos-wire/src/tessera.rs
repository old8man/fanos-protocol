//! The Tessera / APHANTOS sealed-onion wire format (spec §5.7, §7.7) — the canonical,
//! length-indistinguishable packet of NYX.
//!
//! This module pins the onion's **canonical byte layout**: the fixed *cleartext* header fields and
//! their offsets, and the constant total size [`TOTAL_LEN`] that makes every hop's packet identical in
//! length regardless of path length or hop position. It mirrors the shipping onion in
//! `fanos_aphantos::sealed`; the cryptographic content (the hybrid-KEM layer key, the nested AEAD
//! layers, the threshold routing commands) is produced by the privacy/crypto layers — here we define
//! and validate the byte frame that carries them.
//!
//! ```text
//! onion   = version(1) ‖ kem_ct(1120) ‖ nonce(12) ‖ len_ct(18) ‖ body_ct(len) ‖ padding  → TOTAL_LEN
//! len_ct  = AEAD(len_key,  nonce, u16 body_len)        — the real layer length, encrypted
//! body_ct = AEAD(body_key, nonce, cmd ‖ inner)         — the routing layer, encrypted
//! cmd     = (DELIVER ‖ holonomy(32)) | (NEXT ‖ next_coord(12))   — inside body_ct, never cleartext
//! ```
//!
//! # The path authenticator is encrypted, never a cleartext header field
//!
//! The **holonomy** path-authenticator travels *inside the innermost (DELIVER) command*, AEAD-encrypted
//! end-to-end, so it is visible only to the endpoint. It is deliberately **not** a cleartext header
//! field: a constant per-circuit tag at a fixed offset would be a perfect **cross-hop correlator** —
//! any two relays, or any observer of a single un-encrypted hop, could link entry to exit by matching
//! it, collapsing the threshold `P_hop^L` endpoint-unlinkability to `1` (spec §5.4). An earlier
//! revision of this canonical layout carried exactly such a cleartext `holonomy_tag`; it has been
//! removed, and this invariant is documented here so no re-implementation reintroduces the leak
//! (audit A1). The only widths given for `holonomy`/`next_coord` live in [`command`] — they never
//! appear at a fixed packet offset.

use crate::error::WireError;

/// Tessera format version.
pub const VERSION: u8 = 1;
/// `version` field width.
pub const VERSION_LEN: usize = 1;

/// Hybrid per-hop KEM ciphertext `X25519 ephemeral (32) ‖ ML-KEM-768 ciphertext (1088)` (spec §7.7).
/// Equals `fanos_pqcrypto::kem::CIPHERTEXT_LEN`; defined locally to keep this codec crate dependency-free
/// (a debug assertion in `fanos_aphantos::sealed` pins the two together).
pub const KEM_CT_LEN: usize = 32 + 1088;
/// Per-packet AEAD `nonce` width (ChaCha20-Poly1305).
pub const NONCE_LEN: usize = 12;
/// AEAD authentication-tag width (ChaCha20-Poly1305).
pub const TAG_LEN: usize = 16;
/// Encrypted `len` field: AEAD of a 2-byte big-endian body length (`2 + TAG_LEN`).
pub const LEN_CT_LEN: usize = 2 + TAG_LEN;

/// The constant total packet size (spec §7.7): a wire-level requirement, independent of path length or
/// hop position, so packets are length-indistinguishable. Matches `fanos_aphantos::sealed::ONION_LEN`.
pub const TOTAL_LEN: usize = 8192;

/// Byte offset of each **cleartext header** field within the packet. Everything from [`offset::BODY_CT`]
/// onward is AEAD ciphertext followed by keystream padding — opaque to every relay but the one peeling it.
pub mod offset {
    use super::{KEM_CT_LEN, LEN_CT_LEN, NONCE_LEN, VERSION_LEN};
    /// Offset of `version`.
    pub const VERSION: usize = 0;
    /// Offset of the hybrid KEM ciphertext.
    pub const KEM_CT: usize = VERSION + VERSION_LEN;
    /// Offset of the AEAD nonce.
    pub const NONCE: usize = KEM_CT + KEM_CT_LEN;
    /// Offset of the encrypted length field.
    pub const LEN_CT: usize = NONCE + NONCE_LEN;
    /// Offset of the encrypted routing body (and, after it, keystream padding to `TOTAL_LEN`).
    pub const BODY_CT: usize = LEN_CT + LEN_CT_LEN;
}

/// The fixed cleartext-header length: everything before the encrypted body (`= offset::BODY_CT`).
pub const HEADER_LEN: usize = offset::BODY_CT;

/// The most encrypted-body-plus-padding bytes the packet holds (`TOTAL_LEN − HEADER_LEN`). The padding
/// is keystream-derived, so it is indistinguishable from ciphertext and a passive observer sees a
/// constant-size packet at every hop.
pub const MAX_BODY_CT_LEN: usize = TOTAL_LEN - HEADER_LEN;

/// The **encrypted** routing-command layout, carried inside `body_ct` — never at a fixed packet offset.
/// Documented for a re-implementation: `cmd = (DELIVER ‖ holonomy(32)) | (NEXT ‖ next_coord(12))`. That
/// the holonomy width appears only here, and never among the cleartext [`offset`]s, is what keeps the
/// path-authenticator from being a cross-hop correlator (see the module docs).
pub mod command {
    /// `DELIVER` command tag (first byte of the decrypted body): the payload has reached its endpoint.
    pub const DELIVER: u8 = 0;
    /// `NEXT` command tag: forward the inner onion to the carried next-hop coordinate.
    pub const NEXT: u8 = 1;
    /// The path-authenticator holonomy carried in a `DELIVER` command (encrypted, endpoint-only).
    pub const HOLONOMY_LEN: usize = 32;
    /// The next-hop coordinate carried in a `NEXT` command (a projective triple, `3 × u32`) — the one
    /// canonical [`fanos_geometry::TRIPLE_WIRE_LEN`].
    pub const NEXT_COORD_LEN: usize = fanos_geometry::TRIPLE_WIRE_LEN;
}

// Compile-time guarantee that the cleartext header fits the fixed packet with room for a body.
const _: () = assert!(
    HEADER_LEN < TOTAL_LEN,
    "Tessera cleartext header must fit within the fixed total size",
);

/// A view over the fixed-size Tessera packet buffer, exposing each **cleartext** field slice. The
/// routing body ([`body`](TesseraView::body)) is AEAD ciphertext; this view does not — and cannot —
/// decrypt it (that requires the hop key), and there is no holonomy accessor because the authenticator
/// is not a cleartext field.
pub struct TesseraView<'a>(&'a [u8; TOTAL_LEN]);

impl<'a> TesseraView<'a> {
    /// Wrap a fixed-size buffer, checking the version byte.
    ///
    /// # Errors
    /// Returns [`WireError::UnsupportedVersion`] if the leading version byte is not [`VERSION`].
    pub fn new(buf: &'a [u8; TOTAL_LEN]) -> Result<Self, WireError> {
        if buf.first().copied() != Some(VERSION) {
            return Err(WireError::UnsupportedVersion);
        }
        Ok(Self(buf))
    }

    /// The hybrid KEM ciphertext bytes (this hop's layer-key encapsulation).
    #[must_use]
    pub fn kem_ct(&self) -> &[u8] {
        self.field(offset::KEM_CT, KEM_CT_LEN)
    }
    /// The AEAD nonce bytes.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        self.field(offset::NONCE, NONCE_LEN)
    }
    /// The encrypted length-field bytes.
    #[must_use]
    pub fn len_ct(&self) -> &[u8] {
        self.field(offset::LEN_CT, LEN_CT_LEN)
    }
    /// The encrypted routing body plus keystream padding (opaque without the hop key).
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.field(offset::BODY_CT, MAX_BODY_CT_LEN)
    }

    fn field(&self, off: usize, len: usize) -> &[u8] {
        // Offsets and lengths are compile-time constants within TOTAL_LEN.
        self.0.get(off..off + len).unwrap_or(&[])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn layout_offsets_are_consistent_and_fit() {
        assert_eq!(offset::VERSION, 0);
        assert_eq!(offset::KEM_CT, 1);
        assert_eq!(offset::NONCE, 1 + KEM_CT_LEN);
        assert_eq!(offset::LEN_CT, offset::NONCE + NONCE_LEN);
        assert_eq!(offset::BODY_CT, offset::LEN_CT + LEN_CT_LEN);
        assert_eq!(HEADER_LEN, offset::BODY_CT);
        // The cleartext header plus the maximum encrypted body equals the constant total.
        assert_eq!(HEADER_LEN + MAX_BODY_CT_LEN, TOTAL_LEN);
    }

    #[test]
    fn the_header_matches_the_shipping_onion_layout() {
        // Byte-exact agreement with fanos_aphantos::sealed's cleartext header (one source of truth):
        // version(1) ‖ kem_ct(1120) ‖ nonce(12) ‖ len_ct(18) = 1151, total 8192.
        assert_eq!(KEM_CT_LEN, 1120);
        assert_eq!(LEN_CT_LEN, 18);
        assert_eq!(HEADER_LEN, 1 + 1120 + 12 + 18);
        assert_eq!(TOTAL_LEN, 8192);
    }

    #[test]
    fn view_exposes_cleartext_fields_and_checks_version() {
        let mut buf = [0u8; TOTAL_LEN];
        buf[offset::VERSION] = VERSION;
        let view = TesseraView::new(&buf).unwrap();
        assert_eq!(view.kem_ct().len(), KEM_CT_LEN);
        assert_eq!(view.nonce().len(), NONCE_LEN);
        assert_eq!(view.len_ct().len(), LEN_CT_LEN);
        assert_eq!(view.body().len(), MAX_BODY_CT_LEN);

        buf[offset::VERSION] = 99;
        assert!(TesseraView::new(&buf).is_err());
    }

    #[test]
    fn there_is_no_cleartext_holonomy_field() {
        // Regression guard for the removed cross-hop correlator: the cleartext header is exactly
        // version ‖ kem_ct ‖ nonce ‖ len_ct — no authenticator among them — and the holonomy width is
        // defined only within the (encrypted) `command` module, never as a packet offset.
        assert_eq!(HEADER_LEN, offset::LEN_CT + LEN_CT_LEN);
        assert_eq!(command::HOLONOMY_LEN, 32);
        assert_eq!(command::NEXT_COORD_LEN, 12);
    }
}
