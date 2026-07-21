//! The FANOS frame and its message-type registry (spec §7.2).
//!
//! All control traffic is a sequence of frames `type:varint ‖ length:varint ‖ body[length]`.
//! Types are grouped by high nibble so a router can dispatch on the group without a full
//! table; unknown non-critical types are skipped by `length` (forward-compatible).

use alloc::vec::Vec;

use crate::error::WireError;
use crate::varint;

/// The message-type registry (spec §7.2). Discriminants encode the group in the high nibble.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u64)]
#[allow(missing_docs)] // the registry names are documented by the specification's §7.2 table
pub enum FrameType {
    // 0x0* Session
    Hello = 0x00,
    HelloAck = 0x01,
    Ping = 0x02,
    Pong = 0x03,
    Goaway = 0x04,
    Error = 0x05,
    /// A peer reports the source address it **observes** this node's connection arriving from — the
    /// reflexive/public address for NAT traversal (#119). Body: the observed [`SocketAddr`] encoded as
    /// `family(1B: 4|6) ‖ ip(4|16) ‖ port(2B BE)`. A node aggregates these across peers
    /// (`fanos_quic::ReflexiveAddr`) to learn the address it should advertise / be reached at.
    ObservedAddr = 0x06,
    /// A client asks a **common hub** to coordinate a hole-punch to a peer it cannot reach directly
    /// (NAT traversal #119): body is the target's coordinate (12B). The hub — which observed both
    /// parties' public addresses when they dialed in — replies to *both* with a [`PunchTo`](Self::PunchTo).
    ConnectReq = 0x07,
    /// A hub tells a node to dial a peer at its observed public address, for a coordinated simultaneous
    /// open (NAT traversal #119): body is `peer_coord(12B) ‖ family(1B) ‖ ip(4|16) ‖ port(2B BE)`. Both
    /// endpoints dial at once, so each NAT sees an outbound packet first and admits the inbound reply.
    PunchTo = 0x08,
    /// A node asks a **common hub** to forward an inner frame to a `target` it cannot reach directly — the
    /// symmetric-NAT relay fallback (NAT traversal #119): body is `target_coord(12B) ‖ inner frame`. The
    /// hub, reachable from both ends (each dialed in), writes the inner frame on to the target. Used only
    /// when a direct connection / hole-punch cannot be made, so any pair behind NAT can still communicate.
    Relay = 0x09,
    // 0x1* Membership
    Join = 0x10,
    Announce = 0x11,
    BeaconReq = 0x12,
    Beacon = 0x13,
    DkgDeal = 0x14,
    DkgJustify = 0x15,
    DkgCommit = 0x16,
    DkgComplaint = 0x17,
    /// One anchor's distributed-VRF **beacon partial** for an epoch (audit E5): flooded among the
    /// beacon group; a threshold of them assemble the epoch's [`Beacon`](Self::Beacon) round.
    BeaconPartial = 0x18,
    /// A cell's **epoch-number agreement** gossip — a bare 4-byte `epoch_low32_be`, flooded adopt-max so
    /// the cell converges on the current epoch counter (spec §L3). This is deliberately **not** the
    /// [`Beacon`](Self::Beacon): the beacon carries a full threshold-DVRF *randomness* round, whereas this
    /// carries only the epoch ordinal. A node with no beacon configured uses this to advance its epoch;
    /// under a live beacon the DVRF round is authoritative and the composite suppresses this flood (audit
    /// #102 — previously the overlay overloaded the `Beacon` code with this 4-byte payload, colliding with
    /// a real round on the wire).
    EpochAgree = 0x19,
    // 0x2* Overlay / storage
    Lookup = 0x20,
    Value = 0x21,
    Publish = 0x22,
    Ack = 0x23,
    Bridge = 0x24,
    // 0x3* Direct route
    Route = 0x30,
    StreamOpen = 0x31,
    StreamData = 0x32,
    StreamFin = 0x33,
    /// Hierarchical route: `HierAddr(dst) ‖ payload` — forwarded cell-to-cell toward a multi-level
    /// destination (§L1 recursion). Degenerates to `Route` for a depth-1 (single-plane) address.
    RouteHier = 0x34,
    // 0x4* APHANTOS / NYX
    Tessera = 0x40,
    PartialDec = 0x41,
    Cover = 0x42,
    // 0x5* Rendezvous / CALYPSO
    RdvIntro = 0x50,
    RdvReply = 0x51,
    SvcAnnounce = 0x52,
    /// A client registers its coordinate with a [rendezvous relay] so the relay forwards anonymous
    /// replies delivered at its combiner to the client (audit #54; the sender is the client).
    RdvRegister = 0x53,
    /// A threshold-hosted service's combiner asks a co-line member for its PartialDec of an intro
    /// (spec §12.3, audit #99): body is the `SealedIntro` bytes (from `fanos_calypso::hosting`); the
    /// member replies with a [`SvcPartial`](Self::SvcPartial). No single host reads an intro alone.
    SvcShareReq = 0x54,
    /// A service-line member's PartialDec reply to its combiner (spec §12.3, audit #99): body is the
    /// 32-byte intro id ‖ the member's Shamir share (`x(1B) ‖ y`). The combiner Lagrange-combines `t`.
    SvcPartial = 0x55,
    // 0x6* DIAKRISIS
    DiagGossip = 0x60,
    DiagSyndrome = 0x61,
    DiagVerdict = 0x62,
    /// A node's live polar-class cross-attestation (audit #98, spec §6.4): the rates it honestly
    /// reports for the 3 channels it mediates (`fanos_diakrisis::polar::polar_class`), flooded on
    /// the heartbeat like [`DiagGossip`](Self::DiagGossip). Feeds the 14 free polar sum-rule
    /// alarms (§6.2) live — an equivocating mediator's own report disagrees with itself and is
    /// localized by [`fanos_diakrisis::polar::violated_classes`].
    DiagAttest = 0x63,
    /// A node's measured **per-neighbour loss vector** (spec §6.3 grey detection, #106): the fraction of its
    /// pings to each Fano point that went unanswered, one `u8` per point (`loss × 255`), flooded on the
    /// heartbeat like [`DiagGossip`](Self::DiagGossip). Assembled cell-wide into a channel-rate matrix whose
    /// polar minimum-incident reading (`fanos_diakrisis::polar::grey_endpoint`) localizes a grey node — one
    /// heartbeat-present but lossy on every channel, which the liveness and equivocation checks cannot see.
    DiagLoss = 0x64,
    // 0x7* Application overlays (Kernel/Protocol split, design-platform.md §Kernel): a system Protocol
    // runs on port 0 and application overlays multiplex under one length-skippable outer type.
    App = 0x70,
}

impl FrameType {
    /// The dispatch group (high nibble) of the type (spec §7.2).
    #[must_use]
    pub fn group(self) -> u8 {
        (self as u64 >> 4) as u8
    }

    /// The registry entry for a numeric type code, or `None` if unknown to this build.
    #[must_use]
    pub fn from_code(code: u64) -> Option<Self> {
        // Exhaustive match keeps the registry and this decoder in lock-step.
        Some(match code {
            0x00 => Self::Hello,
            0x01 => Self::HelloAck,
            0x02 => Self::Ping,
            0x03 => Self::Pong,
            0x04 => Self::Goaway,
            0x05 => Self::Error,
            0x06 => Self::ObservedAddr,
            0x07 => Self::ConnectReq,
            0x08 => Self::PunchTo,
            0x09 => Self::Relay,
            0x10 => Self::Join,
            0x11 => Self::Announce,
            0x12 => Self::BeaconReq,
            0x13 => Self::Beacon,
            0x14 => Self::DkgDeal,
            0x15 => Self::DkgJustify,
            0x16 => Self::DkgCommit,
            0x17 => Self::DkgComplaint,
            0x18 => Self::BeaconPartial,
            0x19 => Self::EpochAgree,
            0x20 => Self::Lookup,
            0x21 => Self::Value,
            0x22 => Self::Publish,
            0x23 => Self::Ack,
            0x24 => Self::Bridge,
            0x30 => Self::Route,
            0x31 => Self::StreamOpen,
            0x32 => Self::StreamData,
            0x33 => Self::StreamFin,
            0x34 => Self::RouteHier,
            0x40 => Self::Tessera,
            0x41 => Self::PartialDec,
            0x42 => Self::Cover,
            0x50 => Self::RdvIntro,
            0x51 => Self::RdvReply,
            0x52 => Self::SvcAnnounce,
            0x53 => Self::RdvRegister,
            0x54 => Self::SvcShareReq,
            0x55 => Self::SvcPartial,
            0x60 => Self::DiagGossip,
            0x61 => Self::DiagSyndrome,
            0x62 => Self::DiagVerdict,
            0x63 => Self::DiagAttest,
            0x64 => Self::DiagLoss,
            0x70 => Self::App,
            _ => return None,
        })
    }

    /// The numeric type code.
    #[must_use]
    pub fn code(self) -> u64 {
        self as u64
    }
}

/// The **inner-session** frame registry — the frame types carried *inside* one AEAD-encrypted DIAULOS
/// cell (spec §L2), a deliberately distinct layer from the outer overlay-transport [`FrameType`]. Like
/// QUIC frames inside a packet, these reuse the small `0x0*` range with no collision because they live
/// **behind the cell's encryption**, never on the cleartext wire. Keeping both registries in this one
/// crate makes `fanos-wire` the single frame-code numbering authority (audit A1): `fanos_diaulos::frame`
/// derives its `ftype` bytes from this enum rather than from private constants.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum SessionFrameType {
    /// A pure cover cell — no payload (byte-indistinguishable from [`Data`](Self::Data) once sealed).
    Padding = 0x00,
    /// A reliability segment (stream data).
    Data = 0x01,
    /// A selective acknowledgement with receive credit.
    Ack = 0x02,
    /// Abort a stream in both directions, reclaiming its slot immediately.
    Reset = 0x03,
}

impl SessionFrameType {
    /// The numeric `ftype` byte this frame is tagged with inside the cell.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }

    /// The registry entry for an inner-session `ftype` byte, or `None` if unknown to this build.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0x00 => Self::Padding,
            0x01 => Self::Data,
            0x02 => Self::Ack,
            0x03 => Self::Reset,
            _ => return None,
        })
    }
}

/// A decoded frame: its numeric type code (which may be unknown to this build) and its body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Frame<'a> {
    /// The numeric type code; resolve with [`FrameType::from_code`].
    pub type_code: u64,
    /// The frame body.
    pub body: &'a [u8],
}

impl Frame<'_> {
    /// The registry entry for this frame's type, if known.
    #[must_use]
    pub fn frame_type(&self) -> Option<FrameType> {
        FrameType::from_code(self.type_code)
    }
}

/// Encode a frame `type:varint ‖ length:varint ‖ body`.
pub fn encode_frame(type_code: u64, body: &[u8], out: &mut Vec<u8>) {
    varint::encode(type_code, out);
    varint::encode(body.len() as u64, out);
    out.extend_from_slice(body);
}

/// Decode one frame from the front of `buf`, returning the frame and bytes consumed. Unknown
/// type codes are returned intact so a caller can skip them by `length` (spec §7.2).
pub fn decode_frame(buf: &[u8]) -> Result<(Frame<'_>, usize), WireError> {
    let (type_code, n0) = varint::decode(buf)?;
    let rest = buf.get(n0..).ok_or(WireError::UnexpectedEnd)?;
    let (len, n1) = varint::decode(rest)?;
    // Convert through `usize::try_from` (not `as usize`): on a 32-bit target (wasm32 is a declared
    // build target) a 64-bit length would silently truncate, so a 64-bit and a 32-bit node would
    // disagree on the same bytes — a canonical-encoding violation. Reject instead.
    let len = usize::try_from(len).map_err(|_| WireError::FrameLengthOverflow)?;
    let body_start = n0 + n1;
    let end = body_start
        .checked_add(len)
        .ok_or(WireError::FrameLengthOverflow)?;
    let body = buf
        .get(body_start..end)
        .ok_or(WireError::FrameLengthOverflow)?;
    Ok((Frame { type_code, body }, end))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn groups_match_high_nibble() {
        assert_eq!(FrameType::Hello.group(), 0x0);
        assert_eq!(FrameType::Join.group(), 0x1);
        assert_eq!(FrameType::Tessera.group(), 0x4);
        assert_eq!(FrameType::DiagVerdict.group(), 0x6);
    }

    #[test]
    fn registry_round_trips() {
        for code in [0x00u64, 0x05, 0x13, 0x24, 0x40, 0x62, 0x63] {
            let ft = FrameType::from_code(code).unwrap();
            assert_eq!(ft.code(), code);
        }
        assert_eq!(FrameType::from_code(0xFF), None);
    }

    #[test]
    fn an_absurd_length_is_rejected_not_wrapped() {
        // A length that overflows the address space (or a 32-bit `usize`) must be rejected, never
        // truncated or wrapped into a valid-looking slice (canonical-encoding safety on wasm32).
        let mut buf = Vec::new();
        varint::encode(FrameType::Publish.code(), &mut buf);
        varint::encode(1u64 << 40, &mut buf); // ~1 TB body length — exceeds a 32-bit usize
        buf.extend_from_slice(b"short");
        assert!(matches!(
            decode_frame(&buf),
            Err(WireError::FrameLengthOverflow)
        ));
    }

    #[test]
    fn frame_round_trips() {
        let mut buf = Vec::new();
        encode_frame(FrameType::Publish.code(), b"payload", &mut buf);
        let (frame, n) = decode_frame(&buf).unwrap();
        assert_eq!(frame.frame_type(), Some(FrameType::Publish));
        assert_eq!(frame.body, b"payload");
        assert_eq!(n, buf.len());
    }

    #[test]
    fn unknown_type_is_skippable_not_fatal() {
        // A frame of unknown type still decodes with its body, so a router can skip it.
        let mut buf = Vec::new();
        encode_frame(0xAB, b"future", &mut buf);
        let (frame, n) = decode_frame(&buf).unwrap();
        assert_eq!(frame.frame_type(), None);
        assert_eq!(frame.type_code, 0xAB);
        assert_eq!(frame.body, b"future");
        assert_eq!(n, buf.len());
    }

    #[test]
    fn rejects_body_length_overflow() {
        // type=0x02, length=100, but no body.
        let mut buf = Vec::new();
        varint::encode(0x02, &mut buf);
        varint::encode(100, &mut buf);
        assert_eq!(decode_frame(&buf), Err(WireError::FrameLengthOverflow));
    }
}
