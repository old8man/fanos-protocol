//! The DIAULOS cell — the constant-size, per-cell-nonce AEAD wire atom.
//!
//! `cell = cnonce(8) ‖ AEAD_ChaCha20Poly1305(key, nonce, frame ‖ zero-pad → CELL_PLAINTEXT)`.
//!
//! Every cell is exactly [`CELL_LEN`] bytes, so a passive observer sees an indistinguishable stream
//! and the real frame length (encrypted inside the frame, [`crate::frame`]) never leaks. The
//! **explicit per-cell nonce** (`cnonce`, a monotone counter, never reused under one key) means a
//! lost or reordered cell does not stall decryption of any other — there is no crypto head-of-line
//! blocking, unlike a running stream cipher. A tampered or wrong-key cell fails AEAD authentication
//! and [`open`] returns `None`, so it is dropped and (for data) retransmitted.

/// A 32-byte end-to-end direction key (distinct per direction; distinct from the onion's hop keys).
pub type Key = [u8; 32];

/// The fixed plaintext capacity of a cell — holds the largest frame ([`crate::frame`]) with room to
/// pad. A `DATA` frame is at most `1 + 4 + 4 + 1 + 2 + MAX_SEGMENT(1024) = 1036` bytes.
pub const CELL_PLAINTEXT: usize = 1040;
const NONCE_LEN: usize = 8;
const TAG_LEN: usize = 16;
/// The constant on-the-wire cell size: `cnonce(8) ‖ ciphertext(CELL_PLAINTEXT + 16-byte tag)`.
pub const CELL_LEN: usize = NONCE_LEN + CELL_PLAINTEXT + TAG_LEN;

/// The 12-byte AEAD nonce for a cell: four zero bytes followed by the 8-byte little-endian counter.
fn aead_nonce(cnonce: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.iter_mut()
        .skip(4)
        .zip(cnonce.to_le_bytes())
        .for_each(|(dst, src)| *dst = src);
    n
}

/// Seal `frame` into a constant-size cell under `key` with the explicit counter `cnonce` (which must
/// be unique per key). `None` if the frame exceeds [`CELL_PLAINTEXT`] or AEAD setup fails.
#[must_use]
pub fn seal(key: &Key, cnonce: u64, frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() > CELL_PLAINTEXT {
        return None;
    }
    let mut plaintext = vec![0u8; CELL_PLAINTEXT];
    plaintext.get_mut(..frame.len())?.copy_from_slice(frame);
    let ciphertext = fanos_primitives::aead::seal(key, &aead_nonce(cnonce), &plaintext)?;
    let mut out = Vec::with_capacity(CELL_LEN);
    out.extend_from_slice(&cnonce.to_le_bytes());
    out.extend_from_slice(&ciphertext);
    Some(out)
}

/// Open a cell under `key`, returning the [`CELL_PLAINTEXT`]-byte frame plaintext (the caller's
/// [`crate::frame::Frame::decode`] trims the zero padding via the frame's own length field). Returns
/// `None` on a wrong size, wrong key, or tampering — the cell is then dropped.
#[must_use]
pub fn open(key: &Key, cell: &[u8]) -> Option<Vec<u8>> {
    if cell.len() != CELL_LEN {
        return None;
    }
    let (nonce_bytes, ciphertext) = cell.split_at_checked(NONCE_LEN)?;
    let mut cn = [0u8; NONCE_LEN];
    cn.copy_from_slice(nonce_bytes);
    fanos_primitives::aead::open(key, &aead_nonce(u64::from_le_bytes(cn)), ciphertext)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trips_and_is_constant_size() {
        let key = [7u8; 32];
        let frame = b"a diaulos frame";
        let cell = seal(&key, 42, frame).unwrap();
        assert_eq!(
            cell.len(),
            CELL_LEN,
            "every cell is the same size on the wire"
        );
        let pt = open(&key, &cell).unwrap();
        assert_eq!(&pt[..frame.len()], frame);
        assert!(
            pt[frame.len()..].iter().all(|&b| b == 0),
            "the rest is zero pad"
        );
    }

    #[test]
    fn a_tampered_or_wrong_key_cell_fails_to_open() {
        let key = [1u8; 32];
        let mut cell = seal(&key, 1, b"secret").unwrap();
        // wrong key
        assert!(open(&[2u8; 32], &cell).is_none());
        // flip a ciphertext byte
        let last = cell.len() - 1;
        cell[last] ^= 0xFF;
        assert!(open(&key, &cell).is_none());
    }

    #[test]
    fn different_nonces_give_different_cells() {
        let key = [3u8; 32];
        assert_ne!(seal(&key, 1, b"x").unwrap(), seal(&key, 2, b"x").unwrap());
    }

    #[test]
    fn an_oversized_frame_is_rejected() {
        assert!(seal(&[0u8; 32], 0, &vec![0u8; CELL_PLAINTEXT + 1]).is_none());
    }

    #[test]
    fn a_frame_exactly_filling_the_cell_seals() {
        // The `> CELL_PLAINTEXT` size guard's boundary: exactly CELL_PLAINTEXT bytes must still seal.
        let key = [6u8; 32];
        let frame = vec![0xABu8; CELL_PLAINTEXT];
        let cell = seal(&key, 0, &frame).unwrap();
        assert_eq!(cell.len(), CELL_LEN);
        assert_eq!(
            open(&key, &cell).unwrap(),
            frame,
            "a max-size frame round-trips"
        );
    }

    #[test]
    fn tampering_the_cnonce_prefix_fails_to_open() {
        // The explicit 8-byte counter prefix is the AEAD nonce. Flipping a bit there makes `open`
        // derive a different nonce than the tag was sealed under, so authentication fails — the nonce
        // is bound, not merely advisory.
        let key = [5u8; 32];
        let mut cell = seal(&key, 100, b"bind the nonce").unwrap();
        cell[0] ^= 0x01;
        assert!(
            open(&key, &cell).is_none(),
            "a tampered cnonce prefix is rejected"
        );
    }
}
