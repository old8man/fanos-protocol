//! Authenticated encryption — the one ChaCha20-Poly1305 seal/open the whole stack shares (spec §7.1).
//!
//! Every hop-layer, cell, descriptor, and share seal in FANOS is a ChaCha20-Poly1305 AEAD under a
//! 32-byte key and a 12-byte nonce. This module is the single audited implementation; callers supply
//! the key, the (unique-per-key) nonce, and the message, and map the `None` failure onto their own
//! error type. Keeping it here means the construction — key setup, nonce handling, tag verification —
//! is written and reviewed once, not re-derived in every privacy crate.

use alloc::vec::Vec;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

// `Nonce::from(*nonce)` converts the fixed 12-byte array into the cipher's nonce type without the
// deprecated `from_slice` path.

/// The AEAD key length (bytes).
pub const KEY_LEN: usize = 32;
/// The AEAD nonce length (bytes).
pub const NONCE_LEN: usize = 12;
/// The AEAD authentication-tag length (bytes) appended to every ciphertext.
pub const TAG_LEN: usize = 16;

/// Seal `plaintext` under `key` with `nonce` (which must be unique per key), returning
/// `ciphertext ‖ tag`. `None` only on the internal cipher-setup error path (unreachable for a
/// fixed-length key), so a caller maps it to its own "AEAD failed" error.
#[must_use]
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new_from_slice(key)
        .ok()?
        .encrypt(&Nonce::from(*nonce), plaintext)
        .ok()
}

/// Open `ciphertext` (`ct ‖ tag`) under `key` with `nonce`, returning the plaintext. `None` on a wrong
/// key, a wrong nonce, or any tamper (a failed tag) — the caller then drops the message. Never panics.
#[must_use]
pub fn open(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new_from_slice(key)
        .ok()?
        .decrypt(&Nonce::from(*nonce), ciphertext)
        .ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trips_and_rejects_tampering() {
        let key = [7u8; KEY_LEN];
        let nonce = [3u8; NONCE_LEN];
        let msg = b"authenticated payload";
        let ct = seal(&key, &nonce, msg).unwrap();
        assert_eq!(ct.len(), msg.len() + TAG_LEN, "ciphertext carries the tag");
        assert_eq!(open(&key, &nonce, &ct).as_deref(), Some(msg.as_ref()));

        // A flipped ciphertext byte fails the tag.
        let mut bad = ct.clone();
        bad[0] ^= 0x01;
        assert_eq!(open(&key, &nonce, &bad), None, "tamper is rejected");
        // The wrong key / wrong nonce cannot open it.
        assert_eq!(
            open(&[8u8; KEY_LEN], &nonce, &ct),
            None,
            "wrong key rejected"
        );
        assert_eq!(
            open(&key, &[4u8; NONCE_LEN], &ct),
            None,
            "wrong nonce rejected"
        );
    }
}
