//! The protocol epoch — one canonical newtype for the beacon-round time window.
//!
//! An *epoch* is the monotonically advancing time-window index (the randomness-beacon round) that a
//! coordinate assignment, a service descriptor, and a rendezvous line are all bound to (spec §L0/§L3,
//! §5.6): when the beacon advances, coordinates reshuffle and descriptors roll over. Before this type
//! the concept was spelled as a bare `u32` in some crates and a bare `u64` in others — for the *same*
//! descriptor epoch — so the compiler could not catch a `(cell_id, epoch)` roll-up that mixed the two,
//! and a `u64` descriptor epoch silently truncated when fed to a `u32` key-derivation input (audit A3).
//!
//! [`Epoch`] fixes both: it is one 64-bit type the compiler forbids mixing with any other integer, and
//! it pins **one** canonical wire width (8 bytes) — with a single documented [`Epoch::low32_be_bytes`]
//! escape for the one KAT-pinned exception, the 32-bit VRF `coord_input` encoding, so the byte-for-byte
//! test vectors stay stable while the *type* unifies.

/// A protocol epoch: the beacon-round index a coordinate, descriptor, or rendezvous line is bound to.
///
/// Ordering is by round (`e0 < e1` ⇔ `e0` is the older window), so "is this descriptor newer than the
/// one I hold" is a `>` comparison. `Hash`/`Eq` make it a sound map key (the `(cell_id, epoch)` roll-up).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Epoch(pub u64);

impl Epoch {
    /// The genesis epoch (round 0 — "before the first beacon advance").
    pub const ZERO: Self = Self(0);

    /// Construct from a raw beacon-round index.
    #[must_use]
    pub const fn new(round: u64) -> Self {
        Self(round)
    }

    /// The raw beacon-round index.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next epoch. Saturating: an epoch counter never wraps silently back to `ZERO` (which would
    /// re-derive a *past* window's coordinates — a coordinate-replay hazard).
    #[must_use]
    pub const fn next(self) -> Self {
        self.saturating_add(1)
    }

    /// The epoch `n` rounds later (saturating). Models a validity window's upper bound
    /// `valid_until = issued + lifetime` (a signing-cert / delegation lifetime, spec §L4-Balance).
    #[must_use]
    pub const fn saturating_add(self, n: u64) -> Self {
        Self(self.0.saturating_add(n))
    }

    /// The epoch `n` rounds earlier (saturating at [`ZERO`](Self::ZERO)). Models a validity window's
    /// lower bound `valid_from = issued − grace`.
    #[must_use]
    pub const fn saturating_sub(self, n: u64) -> Self {
        Self(self.0.saturating_sub(n))
    }

    /// The canonical 8-byte **big-endian** wire encoding (the default for every epoch on the wire).
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Decode from the canonical 8-byte **big-endian** wire form.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

    /// The canonical 8-byte **little-endian** wire encoding — for the descriptor/framing codepaths that
    /// serialize their scalars little-endian (kept per-site so the existing wire bytes are unchanged).
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Decode from the 8-byte **little-endian** wire form.
    #[must_use]
    pub const fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_le_bytes(bytes))
    }

    /// The low 32 bits, **big-endian** — the KAT-pinned VRF `coord_input` encoding *only* (spec §L3).
    ///
    /// The VRF coordinate input is a fixed 36-byte `node ‖ epoch` whose published test vectors pin a
    /// 4-byte epoch; this is the single documented exception to the 8-byte canonical width. All other
    /// wire uses [`to_be_bytes`](Self::to_be_bytes). Epochs stay far below `u32::MAX` for the life of the
    /// network (one round per beacon interval), so the truncation is lossless in practice and, crucially,
    /// is now *explicit and named* rather than an accidental `as u32` at a `u64`/`u32` seam.
    #[must_use]
    pub const fn low32_be_bytes(self) -> [u8; 4] {
        (self.0 as u32).to_be_bytes()
    }

    /// Decode from a 4-byte **big-endian** field — the inverse of [`low32_be_bytes`](Self::low32_be_bytes),
    /// widening the 32-bit wire value back to the full epoch. Use it at the 4-byte decode sites (the
    /// beacon frame, the calypso balance certs) so the widen is explicit and named rather than a bare
    /// `u32::from_be_bytes(..) as u64` that silently re-introduces the width seam this newtype removes.
    #[must_use]
    pub const fn from_low32_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes) as u64)
    }
}

impl From<u64> for Epoch {
    fn from(round: u64) -> Self {
        Self(round)
    }
}

impl From<Epoch> for u64 {
    fn from(epoch: Epoch) -> Self {
        epoch.0
    }
}

impl core::fmt::Display for Epoch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "e{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_both_endian_wire_forms() {
        let e = Epoch::new(0x0102_0304_0506_0708);
        assert_eq!(Epoch::from_be_bytes(e.to_be_bytes()), e);
        assert_eq!(Epoch::from_le_bytes(e.to_le_bytes()), e);
        // BE and LE are genuinely different byte orders (guards against a copy-paste swap).
        assert_ne!(e.to_be_bytes(), e.to_le_bytes());
    }

    #[test]
    fn low32_matches_the_kat_pinned_vrf_encoding() {
        // The VRF coord_input historically wrote `(epoch as u32).to_be_bytes()`; low32_be_bytes must be
        // byte-identical to that so the coordinate KATs are unchanged by the newtype.
        let e = Epoch::new(42);
        assert_eq!(e.low32_be_bytes(), 42u32.to_be_bytes());
        // The low-32 escape drops the high word, as documented (lossless for real epochs).
        let big = Epoch::new(0xABCD_0000_0000_0007);
        assert_eq!(big.low32_be_bytes(), 7u32.to_be_bytes());
        // The 4-byte decoder inverts the 4-byte encoder for any in-range epoch.
        assert_eq!(Epoch::from_low32_be_bytes(e.low32_be_bytes()), e);
        assert_eq!(
            Epoch::from_low32_be_bytes(7u32.to_be_bytes()),
            Epoch::new(7)
        );
    }

    #[test]
    fn orders_by_round_and_advances_saturating() {
        assert!(Epoch::new(4) < Epoch::new(5));
        assert_eq!(Epoch::new(4).next(), Epoch::new(5));
        assert_eq!(Epoch::ZERO, Epoch::new(0));
        // Never wraps to ZERO (coordinate-replay guard).
        assert_eq!(Epoch::new(u64::MAX).next(), Epoch::new(u64::MAX));
        // Window arithmetic saturates at both ends.
        assert_eq!(Epoch::new(10).saturating_add(2), Epoch::new(12));
        assert_eq!(Epoch::new(10).saturating_sub(3), Epoch::new(7));
        assert_eq!(Epoch::new(1).saturating_sub(5), Epoch::ZERO);
        assert_eq!(Epoch::new(u64::MAX).saturating_add(9), Epoch::new(u64::MAX));
    }

    #[test]
    fn converts_to_and_from_u64_explicitly() {
        assert_eq!(u64::from(Epoch::from(7u64)), 7);
        assert_eq!(Epoch::from(9u64).get(), 9);
    }
}
