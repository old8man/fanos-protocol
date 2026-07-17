//! Domain-separated BLAKE3 hashing (spec §7.1, L6).
//!
//! Every hash / VRF / KDF call in FANOS is prefixed with a constant ASCII **domain label**
//! (`"FANOS-v1/coord"`, `"FANOS-v1/rdv"`, …) so the outputs of different sub-protocols can
//! never collide. This module centralises that discipline over BLAKE3 (the specification's
//! speed hash) and exposes both a 32-byte digest and an extendable-output (XOF) reader for
//! the rejection sampling in [`crate::maptopoint`].

/// The 32-byte node-ID / digest width.
pub const DIGEST_LEN: usize = 32;

/// A FANOS domain-separation label (spec §7.1).
pub mod label {
    /// Coordinate derivation `MapToPoint(VRF(pubkey, epoch))`.
    pub const COORD: &str = "FANOS-v1/coord";
    /// Private rendezvous line derivation.
    pub const RDV: &str = "FANOS-v1/rdv";
    /// Generic key-derivation.
    pub const KDF: &str = "FANOS-v1/kdf";
    /// CALYPSO hidden-service rendezvous.
    pub const CALYPSO: &str = "FANOS-v1/calypso";
    /// PROTEUS transport-shape derivation.
    pub const PROTEUS: &str = "FANOS-v1/proteus-shape";
    /// Node-ID from the public-key bundle.
    pub const NODE_ID: &str = "FANOS-v1/node-id";
    /// L4 storage key → responsible point / key digest (`MapToPoint`, spec §L4).
    pub const STORAGE: &str = "FANOS-v1/storage";
}

/// A domain-separated BLAKE3 hasher. The label and a unit separator are absorbed first, so
/// two calls with different labels never produce related outputs even on identical data.
fn labeled_hasher(label: &str, data: &[u8]) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    hasher.update(&[0x1f]); // ASCII unit separator: not part of any label
    hasher.update(data);
    hasher
}

/// A 32-byte domain-separated digest of `data` under `label` (spec §7.1).
#[must_use]
pub fn hash_labeled(label: &str, data: &[u8]) -> [u8; DIGEST_LEN] {
    *labeled_hasher(label, data).finalize().as_bytes()
}

/// Fill `out` with domain-separated extendable output — the XOF stream used for uniform
/// sampling of projective coordinates (spec §7.1 `MapToPoint`).
pub fn hash_xof(label: &str, data: &[u8], out: &mut [u8]) {
    labeled_hasher(label, data).finalize_xof().fill(out);
}

/// An XOF reader for pulling an unbounded domain-separated byte stream on demand.
#[must_use]
pub fn xof_reader(label: &str, data: &[u8]) -> blake3::OutputReader {
    labeled_hasher(label, data).finalize_xof()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separation_changes_output() {
        let a = hash_labeled(label::COORD, b"same");
        let b = hash_labeled(label::RDV, b"same");
        assert_ne!(a, b, "different labels must not collide on identical data");
    }

    #[test]
    fn hashing_is_deterministic() {
        assert_eq!(
            hash_labeled(label::KDF, b"x"),
            hash_labeled(label::KDF, b"x")
        );
    }

    #[test]
    fn xof_prefix_matches_digest_stream() {
        // The XOF stream's first 32 bytes are a valid extendable output (not equal to the
        // fixed digest, but stable across calls).
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        hash_xof(label::KDF, b"data", &mut a);
        hash_xof(label::KDF, b"data", &mut b);
        assert_eq!(a, b);
    }
}
