//! Protocol version and capability negotiation (spec §7.4).
//!
//! A FANOS link agrees two things beyond the frame codec itself: a `version` — "a single
//! monotonically-increasing profile number" — and a `capabilities` bitfield of the optional
//! feature families a node offers. Two peers then operate at `min(version)` and the
//! **intersection** of capabilities: "a minimal FANOS node (DHT-only, Direct profile)
//! interoperates with a full node; the full node simply does not offer NYX/CALYPSO frames to it."
//! This module is the pure negotiation math; [`crate::frame::FrameType::Hello`] /
//! [`HelloAck`](crate::frame::FrameType::HelloAck) carry it on the wire (the handshake state
//! machine that uses it lives in the driver, e.g. `fanos-quic`, since it alone knows which
//! optional modules a running node actually wires up).

/// This build's protocol version (spec §7.4).
pub const PROTOCOL_VERSION: u16 = 1;

/// The oldest peer version this build still interoperates with. Equal to [`PROTOCOL_VERSION`]
/// today — the first shipped version, nothing older exists yet — and widens only when a future
/// version's wire form becomes genuinely unreadable by this build, not on every version bump
/// (§7.4's whole point is graceful cross-version operation at the lower of the two versions).
pub const MIN_SUPPORTED_VERSION: u16 = 1;

/// Negotiate the session version (spec §7.4: "two peers operate at `min(version)`"): the lower of
/// `mine` and `theirs`, or `None` if that minimum predates [`MIN_SUPPORTED_VERSION`] — this build's
/// version-incompatibility condition (spec §7.3 state diagram: `HELLO_SENT → CLOSED`).
#[must_use]
pub const fn negotiate_version(mine: u16, theirs: u16) -> Option<u16> {
    let v = if mine < theirs { mine } else { theirs };
    if v >= MIN_SUPPORTED_VERSION {
        Some(v)
    } else {
        None
    }
}

/// The wire capability bitfield (spec §7.4): which optional feature families a node offers, beyond
/// the mandatory baseline every conformant node provides. Two peers negotiate to the bitwise AND
/// ([`intersect`](Self::intersect)) — a full node simply withholds the frames an absent bit means
/// the peer would not handle, exactly as §7.4 describes.
///
/// [`CORE`](Self::CORE) is the one **non-optional** bit: every conformant FANOS node sets it
/// (baseline DHT + Direct-profile routing, spec §7.6 bootstrap). An intersection that comes out
/// empty therefore means the peer does not even claim baseline FANOS conformance — not merely
/// "does not support NYX" (a peer lacking [`APHANTOS_FULL`](Self::APHANTOS_FULL) is ordinary and
/// handled by feature degradation, per §7.4's own example) — and is the handshake's *capability*
/// incompatibility condition, distinct from a version mismatch.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub struct Capabilities(u32);

impl Capabilities {
    /// Baseline DHT + Direct-profile routing (spec §7.6) — mandatory; every conformant node sets it.
    pub const CORE: Self = Self(1 << 0);
    /// APHANTOS-Lite: `NyxNode` onion + mix (docs/design-platform.md §1 anonymity dial — the
    /// middle rung between Direct and Full).
    pub const APHANTOS_LITE: Self = Self(1 << 1);
    /// APHANTOS-Full: `ThresholdRouter` line-onion + Poisson delay + cover traffic.
    pub const APHANTOS_FULL: Self = Self(1 << 2);
    /// CALYPSO hidden services: rendezvous + threshold-hosted descriptors (spec Part XII).
    pub const CALYPSO: Self = Self(1 << 3);
    /// This node advertises PQ-only transport — it refuses a classical-only fallback (spec Part
    /// VIII harvest-now/decrypt-later mitigation; the transport is hybrid PQ from day one
    /// regardless, this bit is the advertised *guarantee* a peer can rely on).
    pub const PQ_ONLY: Self = Self(1 << 4);
    /// This node's plane is a binary extension field `GF(2^m)`, as opposed to a prime field
    /// `GF(p)` — informational; the exact order accompanies this bitfield as the HELLO's separate
    /// `field_q` value (an intersection is meaningless for a scalar order, only for a boolean).
    pub const GF_2M: Self = Self(1 << 5);
    /// Optional peripheral blockchain-anchoring interop (one of spec §7.4's own example flags).
    /// FANOS's core protocol is an L0 anonymity overlay, **not** a blockchain; this bit exists only
    /// for a deployment that bolts on an external ledger-anchoring extension and wants peers to
    /// know it is present — it does not indicate anything about FANOS itself.
    pub const BLOCKCHAIN: Self = Self(1 << 6);

    /// No capabilities set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// The raw bitfield, for wire encoding.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Reconstruct from a raw wire bitfield. Every `u32` is a valid (if possibly peer-future)
    /// bitfield — unrecognized bits are preserved (so a byte-identical round trip holds) but never
    /// matched by this build's named constants, which is exactly the forward-compatible behaviour
    /// capability negotiation needs: an unknown optional bit simply never intersects.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether every bit of `flags` is set.
    #[must_use]
    pub const fn contains(self, flags: Self) -> bool {
        self.0 & flags.0 == flags.0
    }

    /// The union (every bit set in either).
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The negotiated capability set (spec §7.4: "the **intersection** of capabilities") — the
    /// bitwise AND, i.e. only what both peers offer.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Whether no bit is set — the handshake's capability-incompatibility condition when computed
    /// as an [`intersect`](Self::intersect) of two peers' advertised sets.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for Capabilities {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::ops::BitAnd for Capabilities {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        self.intersect(rhs)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn version_negotiates_to_the_minimum() {
        assert_eq!(negotiate_version(1, 1), Some(1));
        // Symmetric: order of the two arguments does not matter.
        assert_eq!(negotiate_version(3, 5), Some(3));
        assert_eq!(negotiate_version(5, 3), Some(3));
    }

    #[test]
    fn a_version_older_than_supported_is_incompatible() {
        // A peer advertising version 0 (older than MIN_SUPPORTED_VERSION) cannot be negotiated.
        assert_eq!(negotiate_version(PROTOCOL_VERSION, 0), None);
        assert_eq!(negotiate_version(0, PROTOCOL_VERSION), None);
    }

    #[test]
    fn a_minimal_node_interoperates_with_a_full_node_on_their_shared_baseline() {
        // Spec §7.4's own example: DHT-only interoperates with a full node — the intersection is
        // exactly the minimal node's offer (CORE), not empty.
        let minimal = Capabilities::CORE;
        let full = Capabilities::CORE
            | Capabilities::APHANTOS_LITE
            | Capabilities::APHANTOS_FULL
            | Capabilities::CALYPSO;
        assert_eq!(minimal.intersect(full), Capabilities::CORE);
        assert!(!minimal.intersect(full).is_empty());
        // Symmetric.
        assert_eq!(full.intersect(minimal), Capabilities::CORE);
    }

    #[test]
    fn a_peer_claiming_no_baseline_conformance_intersects_empty() {
        // Two peers with disjoint optional-only sets (neither sets CORE) intersect to empty — the
        // genuine incompatibility condition, distinct from ordinary feature degradation.
        let a = Capabilities::APHANTOS_LITE;
        let b = Capabilities::APHANTOS_FULL;
        assert!(a.intersect(b).is_empty());
    }

    #[test]
    fn bits_round_trip_through_from_bits() {
        let caps = Capabilities::CORE | Capabilities::CALYPSO;
        assert_eq!(Capabilities::from_bits(caps.bits()), caps);
    }

    #[test]
    fn contains_checks_every_bit_of_the_query() {
        let full = Capabilities::CORE | Capabilities::APHANTOS_FULL;
        assert!(full.contains(Capabilities::CORE));
        assert!(full.contains(Capabilities::APHANTOS_FULL));
        assert!(full.contains(Capabilities::CORE | Capabilities::APHANTOS_FULL));
        assert!(!full.contains(Capabilities::CALYPSO));
    }
}
