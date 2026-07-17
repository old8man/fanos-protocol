//! The Tessera packet wire format (spec §5.7, §7.7).
//!
//! Tessera is the fixed-size, Sphinx-derived, threshold, post-quantum packet of NYX. This
//! module pins its **layout** — the field sizes and offsets, and the constant total size that
//! makes packets length-indistinguishable regardless of path length or hop position. The
//! cryptographic content (hybrid group elements, the β-ratchet, threshold routing commands)
//! is produced by the privacy/crypto layers; here we define and validate the byte frame.

use crate::error::WireError;

/// Tessera format version.
pub const VERSION: u8 = 1;

/// `version` field width.
pub const VERSION_LEN: usize = 1;
/// `epoch` field width (spec §7.7).
pub const EPOCH_LEN: usize = 4;
/// Hybrid `group_element`: `X25519 (32) ‖ ML-KEM-768 ciphertext (1088)` (spec §7.7).
pub const GROUP_ELEMENT_LEN: usize = 32 + 1088;
/// Encrypted `routing_cmd` (peeled by the line threshold).
pub const ROUTING_CMD_LEN: usize = 32;
/// `header_mac` integrity tag for the current hop.
pub const HEADER_MAC_LEN: usize = 16;
/// Accumulated `holonomy_tag` — the path authenticator (spec §5.4).
pub const HOLONOMY_TAG_LEN: usize = 32;
/// AEAD `payload`, re-encrypted per hop.
pub const PAYLOAD_LEN: usize = 2048;

/// The constant total packet size (spec §7.7): a wire-level requirement, independent of path
/// length or hop position, so packets are indistinguishable by size.
pub const TOTAL_LEN: usize = 4096;

/// Byte offset of each field within the packet.
pub mod offset {
    use super::{
        EPOCH_LEN, GROUP_ELEMENT_LEN, HEADER_MAC_LEN, HOLONOMY_TAG_LEN, ROUTING_CMD_LEN,
        VERSION_LEN,
    };
    /// Offset of `version`.
    pub const VERSION: usize = 0;
    /// Offset of `epoch`.
    pub const EPOCH: usize = VERSION + VERSION_LEN;
    /// Offset of `group_element`.
    pub const GROUP_ELEMENT: usize = EPOCH + EPOCH_LEN;
    /// Offset of `routing_cmd`.
    pub const ROUTING_CMD: usize = GROUP_ELEMENT + GROUP_ELEMENT_LEN;
    /// Offset of `header_mac`.
    pub const HEADER_MAC: usize = ROUTING_CMD + ROUTING_CMD_LEN;
    /// Offset of `holonomy_tag`.
    pub const HOLONOMY_TAG: usize = HEADER_MAC + HEADER_MAC_LEN;
    /// Offset of `payload`.
    pub const PAYLOAD: usize = HOLONOMY_TAG + HOLONOMY_TAG_LEN;
}

/// The number of bytes of padding after the payload, filling up to [`TOTAL_LEN`].
pub const PADDING_LEN: usize = TOTAL_LEN - (offset::PAYLOAD + PAYLOAD_LEN);

// Compile-time guarantee that the declared fields fit the fixed packet.
const _: () = assert!(
    offset::PAYLOAD + PAYLOAD_LEN <= TOTAL_LEN,
    "Tessera fields must fit within the fixed total size",
);

/// A view over the fixed-size Tessera packet buffer, exposing each field slice.
pub struct TesseraView<'a>(&'a [u8; TOTAL_LEN]);

impl<'a> TesseraView<'a> {
    /// Wrap a fixed-size buffer, checking the version byte.
    pub fn new(buf: &'a [u8; TOTAL_LEN]) -> Result<Self, WireError> {
        if buf.first().copied() != Some(VERSION) {
            return Err(WireError::UnsupportedVersion);
        }
        Ok(Self(buf))
    }

    /// The `epoch` field bytes.
    #[must_use]
    pub fn epoch(&self) -> &[u8] {
        self.field(offset::EPOCH, EPOCH_LEN)
    }
    /// The `group_element` field bytes.
    #[must_use]
    pub fn group_element(&self) -> &[u8] {
        self.field(offset::GROUP_ELEMENT, GROUP_ELEMENT_LEN)
    }
    /// The encrypted `routing_cmd` field bytes.
    #[must_use]
    pub fn routing_cmd(&self) -> &[u8] {
        self.field(offset::ROUTING_CMD, ROUTING_CMD_LEN)
    }
    /// The `holonomy_tag` field bytes.
    #[must_use]
    pub fn holonomy_tag(&self) -> &[u8] {
        self.field(offset::HOLONOMY_TAG, HOLONOMY_TAG_LEN)
    }
    /// The AEAD `payload` field bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.field(offset::PAYLOAD, PAYLOAD_LEN)
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
        assert_eq!(offset::EPOCH, 1);
        assert_eq!(offset::GROUP_ELEMENT, 5);
        assert_eq!(offset::PAYLOAD + PAYLOAD_LEN + PADDING_LEN, TOTAL_LEN);
        // Fields sum plus padding equals the constant total.
        let used = VERSION_LEN
            + EPOCH_LEN
            + GROUP_ELEMENT_LEN
            + ROUTING_CMD_LEN
            + HEADER_MAC_LEN
            + HOLONOMY_TAG_LEN
            + PAYLOAD_LEN;
        assert_eq!(used + PADDING_LEN, TOTAL_LEN);
    }

    #[test]
    fn view_exposes_fields_and_checks_version() {
        let mut buf = [0u8; TOTAL_LEN];
        buf[offset::VERSION] = VERSION;
        let view = TesseraView::new(&buf).unwrap();
        assert_eq!(view.epoch().len(), EPOCH_LEN);
        assert_eq!(view.group_element().len(), GROUP_ELEMENT_LEN);
        assert_eq!(view.payload().len(), PAYLOAD_LEN);

        buf[offset::VERSION] = 99;
        assert!(TesseraView::new(&buf).is_err());
    }
}
