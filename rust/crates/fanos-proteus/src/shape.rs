//! Beacon-rotating polymorphism — the wire signature moves every epoch (spec §13.4, V22).
//!
//! Static AmneziaWG picks its junk/padding parameters once. PROTEUS derives them from the
//! epoch beacon: `θ_epoch = KDF("FANOS-v1/proteus-shape" ‖ community_secret ‖ epoch)`. The wire
//! signature therefore **changes every epoch**, so a censor's ML classifier trained on this
//! epoch's flows has stale features next epoch — the moving-target discipline applied to
//! traffic *shape*.

use alloc::vec::Vec;

use fanos_primitives::{Epoch, hash_labeled};

const SHAPE_LABEL: &str = "FANOS-v1/proteus-shape";

// The parameter ranges. These are the **single source** for the three quantities: `epoch_shape` draws
// from them, `parameters_are_in_range` checks against them, and — the reason they are `pub` —
// [`MAX_WIRE_OVERHEAD`](crate::MAX_WIRE_OVERHEAD) is derived from them. A receiver sizes its read bound
// on that overhead, so a range widened here without the bound following would silently put full frames
// back over the ceiling. Importing the value is the only way to keep the two in step.

/// Junk blocks per packet are drawn from `1..=MAX_JUNK_COUNT`.
pub const MAX_JUNK_COUNT: u8 = 16;
/// Each junk block is `MIN_JUNK_SIZE..=MAX_JUNK_SIZE` bytes.
pub const MIN_JUNK_SIZE: u16 = 16;
/// The largest a junk block can be.
pub const MAX_JUNK_SIZE: u16 = 79;
/// Padding granularity is drawn from `MIN_PADDING_MULTIPLE..=MAX_PADDING_MULTIPLE`.
pub const MIN_PADDING_MULTIPLE: u16 = 64;
/// The coarsest padding granularity, and so the most padding a packet can carry (`− 1`).
pub const MAX_PADDING_MULTIPLE: u16 = 191;

/// The most junk one packet can carry: every block at its largest.
pub const MAX_JUNK_LEN: usize = MAX_JUNK_COUNT as usize * MAX_JUNK_SIZE as usize;

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
pub fn epoch_shape(community_secret: &[u8], epoch: Epoch) -> ShapeParams {
    let mut data = Vec::with_capacity(community_secret.len() + 4);
    data.extend_from_slice(community_secret);
    data.extend_from_slice(&epoch.low32_be_bytes());
    let seed = hash_labeled(SHAPE_LABEL, &data);
    ShapeParams {
        junk_count: (seed[0] % MAX_JUNK_COUNT) + 1,
        junk_size: (u16::from(seed[1]) % (MAX_JUNK_SIZE - MIN_JUNK_SIZE + 1)) + MIN_JUNK_SIZE,
        padding_multiple: (u16::from(seed[2])
            % (MAX_PADDING_MULTIPLE - MIN_PADDING_MULTIPLE + 1))
            + MIN_PADDING_MULTIPLE,
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
        let s0 = epoch_shape(secret, Epoch::new(0));
        let s1 = epoch_shape(secret, Epoch::new(1));
        let s2 = epoch_shape(secret, Epoch::new(2));
        assert_ne!(s0, s1);
        assert_ne!(s1, s2);
        assert_ne!(s0, s2);
    }

    #[test]
    fn shape_is_unpredictable_without_the_secret() {
        // A different community secret yields a different shape (can't predict without it).
        assert_ne!(
            epoch_shape(b"secret-a", Epoch::new(5)),
            epoch_shape(b"secret-b", Epoch::new(5))
        );
        // Deterministic for those who hold the secret.
        assert_eq!(
            epoch_shape(b"s", Epoch::new(5)),
            epoch_shape(b"s", Epoch::new(5))
        );
    }

    #[test]
    fn parameters_are_in_range() {
        // Checked against the same constants `epoch_shape` draws from, not against copies of them: a
        // literal here would agree with a widened range only by luck, and MAX_WIRE_OVERHEAD depends on
        // these bounds holding.
        for e in 0u64..1024 {
            for secret in [b"s".as_slice(), b"another-community".as_slice()] {
                let shape = epoch_shape(secret, Epoch::new(e));
                assert!((1..=MAX_JUNK_COUNT).contains(&shape.junk_count));
                assert!((MIN_JUNK_SIZE..=MAX_JUNK_SIZE).contains(&shape.junk_size));
                assert!(
                    (MIN_PADDING_MULTIPLE..=MAX_PADDING_MULTIPLE).contains(&shape.padding_multiple)
                );
                assert!(shape.junk_len() <= MAX_JUNK_LEN);
            }
        }
    }
}
