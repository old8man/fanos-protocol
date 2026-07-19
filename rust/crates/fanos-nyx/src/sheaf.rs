//! The threshold-sheaf layer — a hop peeled by `t` of `q+1` members (spec §5.2).
//!
//! Each onion layer is encrypted under a fresh symmetric key `K` with a vetted AEAD
//! (ChaCha20-Poly1305). `K` is then **Shamir-shared** across the line's `q+1` members, so any
//! `t` reconstruct it and peel the layer, while fewer than `t` learn *nothing* — the layer's
//! routing command is information-theoretically hidden below threshold. No single node can
//! peel a hop alone; that is the property that drops endpoint linkage to `P_hop²` (spec §5.2,
//! and [`crate::security`]).
//!
//! This module is the `no_std` **transparent form**: the shares are carried in the clear, so its
//! below-threshold guarantee holds only when each share is delivered privately to its member. The
//! **production form binds every share to its member cryptographically** — each Shamir share is
//! hybrid-KEM-sealed to that member's public key, so an adversary holding the whole packet learns
//! nothing below threshold and each hop is forward-secret — see
//! `fanos_aphantos::threshold::ThresholdSealed` (which needs the post-quantum KEM and so lives above
//! this `no_std` crate). AEAD and secret sharing are vetted primitives; the FANOS novelty is
//! composing them so a *line* — not a node — is the unit of trust.

use alloc::vec::Vec;

use fanos_primitives::shamir::{self, ShamirError, Share};

/// A NYX error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NyxError {
    /// AEAD sealing or opening failed (below-threshold reconstruction manifests here: the
    /// wrong key fails authentication).
    Aead,
    /// Secret-sharing parameters or shares were invalid.
    Sharing(ShamirError),
    /// A reconstructed key was the wrong length.
    KeyLength,
}

impl From<ShamirError> for NyxError {
    fn from(e: ShamirError) -> Self {
        Self::Sharing(e)
    }
}

impl core::fmt::Display for NyxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Aead => f.write_str("AEAD sealing/opening failed (wrong key or below threshold)"),
            Self::Sharing(e) => write!(f, "secret sharing failed: {e}"),
            Self::KeyLength => f.write_str("reconstructed key was the wrong length"),
        }
    }
}

impl core::error::Error for NyxError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Sharing(e) => Some(e),
            _ => None,
        }
    }
}

/// A sealed threshold layer: the AEAD ciphertext, its nonce, and the `q+1` key shares (each
/// distributed to a line member privately — cryptographically KEM-sealed per member in the
/// production form, `fanos_aphantos::threshold::ThresholdSealed`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ThresholdLayer {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    shares: Vec<Share>,
}

impl ThresholdLayer {
    /// The per-member key shares (`q+1` of them).
    #[must_use]
    pub fn shares(&self) -> &[Share] {
        &self.shares
    }

    /// The sealed ciphertext length.
    #[must_use]
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }
}

/// Seal `routing_cmd` under `key`/`nonce` and split `key` into `line_size` shares with
/// reconstruction threshold `threshold` (spec §5.2). `key_randomness` must supply
/// `(threshold − 1) · 32` bytes of CSPRNG output for the sharing polynomial.
pub fn seal(
    routing_cmd: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    threshold: u8,
    line_size: u8,
    key_randomness: &[u8],
) -> Result<ThresholdLayer, NyxError> {
    let ciphertext =
        fanos_primitives::aead::seal(key, nonce, routing_cmd).ok_or(NyxError::Aead)?;
    let shares = shamir::split(key, threshold, line_size, key_randomness)?;
    Ok(ThresholdLayer {
        ciphertext,
        nonce: *nonce,
        shares,
    })
}

/// Peel a layer using `t` (or more) member shares: reconstruct `K`, then decrypt (spec §5.2).
///
/// With fewer than `t` shares the reconstructed key is wrong and AEAD authentication fails,
/// so the routing command stays hidden — the zero-knowledge-below-threshold guarantee.
pub fn open(layer: &ThresholdLayer, shares: &[Share]) -> Result<Vec<u8>, NyxError> {
    let key = shamir::reconstruct(shares)?;
    let key: [u8; 32] = key.as_slice().try_into().map_err(|_| NyxError::KeyLength)?;
    fanos_primitives::aead::open(&key, &layer.nonce, &layer.ciphertext).ok_or(NyxError::Aead)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixture_randomness(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 131 + 7) % 253) as u8).collect()
    }

    #[test]
    fn any_threshold_of_members_peels_the_layer() {
        let key = [3u8; 32];
        let nonce = [7u8; 12];
        let cmd = b"next line = L_42; delay = 120ms";
        // A line of q+1 = 8 members, threshold t = 6.
        let rnd = fixture_randomness(5 * 32);
        let layer = seal(cmd, &key, &nonce, 6, 8, &rnd).unwrap();
        assert_eq!(layer.shares().len(), 8);

        // Any 6 members reconstruct and peel.
        let subset = &layer.shares()[1..7];
        assert_eq!(open(&layer, subset).unwrap(), cmd);
        // A different 6 also works.
        let subset2 = &layer.shares()[2..8];
        assert_eq!(open(&layer, subset2).unwrap(), cmd);
    }

    #[test]
    fn below_threshold_learns_nothing() {
        let key = [9u8; 32];
        let nonce = [1u8; 12];
        let cmd = b"secret routing command";
        let rnd = fixture_randomness(5 * 32);
        let layer = seal(cmd, &key, &nonce, 6, 8, &rnd).unwrap();
        // Five shares (t-1) reconstruct the wrong key → AEAD authentication fails.
        let too_few = &layer.shares()[0..5];
        assert_eq!(open(&layer, too_few), Err(NyxError::Aead));
    }

    #[test]
    fn full_line_also_peels() {
        let key = [42u8; 32];
        let nonce = [2u8; 12];
        let cmd = b"deliver";
        let rnd = fixture_randomness(4 * 32);
        let layer = seal(cmd, &key, &nonce, 5, 7, &rnd).unwrap();
        assert_eq!(open(&layer, layer.shares()).unwrap(), cmd);
    }

    #[test]
    fn ciphertext_hides_the_command() {
        let key = [1u8; 32];
        let nonce = [0u8; 12];
        let rnd = fixture_randomness(2 * 32);
        let layer = seal(b"AAAA", &key, &nonce, 3, 5, &rnd).unwrap();
        // The ciphertext is the plaintext length plus the 16-byte Poly1305 tag.
        assert_eq!(layer.ciphertext_len(), 4 + 16);
    }
}
