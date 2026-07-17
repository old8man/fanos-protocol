//! Beacon-rotating polymorphism — the wire signature moves every epoch (spec §13.4, V22).
//!
//! Static AmneziaWG picks its junk/padding parameters once. PROTEUS derives them from the
//! epoch beacon: `θ_epoch = KDF("FANOS-v1/proteus-shape" ‖ community_secret ‖ epoch)`. The wire
//! signature therefore **changes every epoch**, so a censor's ML classifier trained on this
//! epoch's flows has stale features next epoch — the moving-target discipline applied to
//! traffic *shape*.

use alloc::vec::Vec;

use fanos_crypto::hash_labeled;

const SHAPE_LABEL: &str = "FANOS-v1/proteus-shape";

/// The polymorphic shape parameters for one epoch (`θ_epoch`).
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct ShapeParams {
    /// Number of junk blocks prepended (`1..=16`).
    pub junk_count: u8,
    /// Size of each junk block in bytes (`16..=79`).
    pub junk_size: u16,
    /// Padding granularity in bytes (`64..=191`).
    pub padding_multiple: u16,
    /// Keystream seed for junk content and header scrambling.
    pub scramble_seed: [u8; 32],
}

impl ShapeParams {
    /// Total junk-prefix length in bytes.
    #[must_use]
    pub fn junk_len(&self) -> usize {
        usize::from(self.junk_count) * usize::from(self.junk_size)
    }
}

/// Derive the epoch shape `θ_epoch` from the community secret and epoch (spec §13.4).
#[must_use]
#[allow(clippy::indexing_slicing)] // seed is [u8; 32]; indices 0..=2 are always in bounds
pub fn epoch_shape(community_secret: &[u8], epoch: u32) -> ShapeParams {
    let mut data = Vec::with_capacity(community_secret.len() + 4);
    data.extend_from_slice(community_secret);
    data.extend_from_slice(&epoch.to_be_bytes());
    let seed = hash_labeled(SHAPE_LABEL, &data);
    ShapeParams {
        junk_count: (seed[0] % 16) + 1,
        junk_size: (u16::from(seed[1]) % 64) + 16,
        padding_multiple: (u16::from(seed[2]) % 128) + 64,
        scramble_seed: seed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_rotates_every_epoch() {
        // V22: θ(e0) ≠ θ(e1) ≠ θ(e2).
        let secret = b"community-bridge-secret";
        let s0 = epoch_shape(secret, 0);
        let s1 = epoch_shape(secret, 1);
        let s2 = epoch_shape(secret, 2);
        assert_ne!(s0, s1);
        assert_ne!(s1, s2);
        assert_ne!(s0, s2);
    }

    #[test]
    fn shape_is_unpredictable_without_the_secret() {
        // A different community secret yields a different shape (can't predict without it).
        assert_ne!(epoch_shape(b"secret-a", 5), epoch_shape(b"secret-b", 5));
        // Deterministic for those who hold the secret.
        assert_eq!(epoch_shape(b"s", 5), epoch_shape(b"s", 5));
    }

    #[test]
    fn parameters_are_in_range() {
        for e in 0..64 {
            let shape = epoch_shape(b"s", e);
            assert!((1..=16).contains(&shape.junk_count));
            assert!((16..80).contains(&shape.junk_size));
            assert!((64..192).contains(&shape.padding_multiple));
        }
    }
}
