//! **Attachments** — files and media sent in a conversation, stored in THESAUROS (`spec/platform.md` §6, §7).
//!
//! An attachment is not carried inline: the sender seals the file at the edge, stores the ciphertext in the
//! content store (a THESAUROS object → a content id), and sends this small [`Attachment`] descriptor *inside* an
//! ordinary message. Because that message is already end-to-end encrypted (the session/group ratchet), the
//! object key rides safely within it — only the recipient learns it, then fetches the object by its content id
//! and decrypts. This is the Signal/CDN model with THESAUROS as the store: the network sees an opaque blob and
//! an encrypted pointer, never the file.
//!
//! The descriptor is transport- and crate-agnostic: it carries the raw 32-byte content id and object key as
//! bytes (not a THESAUROS type), so the messenger layer needs no dependency on the storage crate — the
//! application glues `thesauros::get(cid)` + `open_object(key)` on the far side.

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroize;

/// A pointer to a stored file: its content id, the key to decrypt it, its size, and its media type.
///
/// **`Debug` is hand-written and `Drop` wipes the key** — this type carries secret material, and the four
/// other key-holding types in this crate (`SendChain`, `RecvChain`, `MediaSession`, `DoubleRatchet`) already
/// live by both rules. It was the only one that did not (#342).
#[derive(Clone, PartialEq, Eq)]
pub struct Attachment {
    /// The THESAUROS content id of the sealed object (a manifest or chunk CID).
    pub cid: [u8; 32],
    /// The object encryption key (carried inside the E2E-encrypted message).
    pub key: [u8; 32],
    /// The plaintext size in bytes.
    pub size: u64,
    /// The media type (a MIME-ish label, e.g. `image/png`, `video/mp4`).
    pub media_type: String,
}

impl Drop for Attachment {
    fn drop(&mut self) {
        // Audit AT-M1: wipe the object key.
        //
        // **What this buys, and what it does NOT** — the difference is easy to overstate and worth writing
        // down. The key is *deliberately transmitted*: it rides inside the E2E-encrypted message, so copies
        // also exist in [`to_bytes`](Self::to_bytes)'s `Vec` and in the ciphertext. Wiping here removes only
        // this struct's own copy from freed memory. That is exactly the claim the four sibling types make
        // for theirs — not a claim that the key is unexposed.
        self.key.zeroize();
    }
}

/// Redacted `Debug`: never render the object key.
///
/// The derived one printed all 32 bytes, and `assert_eq!` on this type — which the conformance suite uses —
/// would have put them in a failure message. The crate's other secret-holders avoid this by deriving no
/// `Debug` at all; that is not available here, because the equality assertions want one. So the shape is the
/// tree's other precedent (`ProteusShaper`, `ServiceParams`): render every field but the secret.
impl core::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Attachment")
            .field("cid", &self.cid)
            .field("key", &"<redacted>")
            .field("size", &self.size)
            .field("media_type", &self.media_type)
            .finish()
    }
}

impl Attachment {
    /// A new attachment descriptor.
    #[must_use]
    pub fn new(cid: [u8; 32], key: [u8; 32], size: u64, media_type: &str) -> Self {
        Self { cid, key, size, media_type: String::from(media_type) }
    }

    /// Canonical bytes: `cid(32) ‖ key(32) ‖ size(8, LE) ‖ mt_len(2, LE) ‖ media_type`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mt = self.media_type.as_bytes();
        let mut out = Vec::with_capacity(74 + mt.len());
        out.extend_from_slice(&self.cid);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&u16::try_from(mt.len()).unwrap_or(u16::MAX).to_le_bytes());
        out.extend_from_slice(mt);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed / truncated / over-long / non-UTF-8.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let cid = bytes.get(..32)?.try_into().ok()?;
        let key = bytes.get(32..64)?.try_into().ok()?;
        let size = u64::from_le_bytes(bytes.get(64..72)?.try_into().ok()?);
        let mt_len = u16::from_le_bytes(bytes.get(72..74)?.try_into().ok()?) as usize;
        let mt = bytes.get(74..74 + mt_len)?;
        if bytes.len() != 74 + mt_len {
            return None; // no trailing garbage
        }
        let media_type = String::from(core::str::from_utf8(mt).ok()?);
        Some(Self { cid, key, size, media_type })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod key_hygiene_tests {
    use super::*;
    use alloc::format;

    /// **The object key never reaches a `Debug` rendering** (#342).
    ///
    /// This is the falsifiable half of the pair. Restoring `#[derive(Debug)]` makes it red HERE, at the
    /// assertion that looks for the key's own bytes — not at some downstream test that happens to print.
    ///
    /// The `Drop` half has no test and cannot have one: whether freed memory was wiped is not observable
    /// from safe Rust, and inventing an `unsafe` read of a dropped struct would assert something the
    /// language does not promise. It is held by consistency with the four siblings and by review, and
    /// saying so is better than a test that only looks like evidence.
    #[test]
    fn a_debug_rendering_of_an_attachment_never_contains_the_object_key() {
        let key = [0x5Au8; 32];
        let a = Attachment::new([0x11; 32], key, 4096, "image/png");
        let shown = format!("{a:?}");

        assert!(shown.contains("<redacted>"), "the key field must render as a redaction: {shown}");
        assert!(!shown.contains("90, 90, 90"), "the key's bytes must not appear in decimal: {shown}");
        assert!(!shown.contains("5a, 5a"), "nor in hex: {shown}");
        // The CONTROL: the non-secret fields must still render, or a `Debug` that prints nothing at all
        // would pass every assertion above while being useless.
        assert!(shown.contains("4096"), "size must still render: {shown}");
        assert!(shown.contains("image/png"), "media_type must still render: {shown}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn an_attachment_round_trips_and_rejects_garbage() {
        let a = Attachment::new([0x11; 32], [0x22; 32], 4096, "image/png");
        let bytes = a.to_bytes();
        assert_eq!(Attachment::from_bytes(&bytes), Some(a.clone()));
        assert_eq!(Attachment::from_bytes(&bytes[..bytes.len() - 1]), None, "truncation rejected");
        assert_eq!(Attachment::from_bytes(&[bytes.as_slice(), b"x"].concat()), None, "trailing garbage rejected");
    }

    #[test]
    fn the_attachment_wire_format_is_stable_a_known_answer() {
        let a = Attachment::new([0xAB; 32], [0xCD; 32], 0x0102, "video/mp4");
        let bytes = a.to_bytes();
        assert_eq!(&bytes[..32], &[0xAB; 32], "cid");
        assert_eq!(&bytes[32..64], &[0xCD; 32], "key");
        assert_eq!(&bytes[64..72], &0x0102u64.to_le_bytes(), "size (LE)");
        assert_eq!(&bytes[72..74], &9u16.to_le_bytes(), "media-type length (LE)");
        assert_eq!(&bytes[74..], b"video/mp4", "media type");
        assert_eq!(bytes.len(), 83);
    }
}
