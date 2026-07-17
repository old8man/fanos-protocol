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
    // 0x1* Membership
    Join = 0x10,
    Announce = 0x11,
    BeaconReq = 0x12,
    Beacon = 0x13,
    DkgDeal = 0x14,
    DkgResp = 0x15,
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
    // 0x4* APHANTOS / NYX
    Tessera = 0x40,
    PartialDec = 0x41,
    Cover = 0x42,
    // 0x5* Rendezvous / CALYPSO
    RdvIntro = 0x50,
    RdvReply = 0x51,
    SvcAnnounce = 0x52,
    // 0x6* DIAKRISIS
    DiagGossip = 0x60,
    DiagSyndrome = 0x61,
    DiagVerdict = 0x62,
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
            0x10 => Self::Join,
            0x11 => Self::Announce,
            0x12 => Self::BeaconReq,
            0x13 => Self::Beacon,
            0x14 => Self::DkgDeal,
            0x15 => Self::DkgResp,
            0x20 => Self::Lookup,
            0x21 => Self::Value,
            0x22 => Self::Publish,
            0x23 => Self::Ack,
            0x24 => Self::Bridge,
            0x30 => Self::Route,
            0x31 => Self::StreamOpen,
            0x32 => Self::StreamData,
            0x33 => Self::StreamFin,
            0x40 => Self::Tessera,
            0x41 => Self::PartialDec,
            0x42 => Self::Cover,
            0x50 => Self::RdvIntro,
            0x51 => Self::RdvReply,
            0x52 => Self::SvcAnnounce,
            0x60 => Self::DiagGossip,
            0x61 => Self::DiagSyndrome,
            0x62 => Self::DiagVerdict,
            _ => return None,
        })
    }

    /// The numeric type code.
    #[must_use]
    pub fn code(self) -> u64 {
        self as u64
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
        for code in [0x00u64, 0x05, 0x13, 0x24, 0x40, 0x62] {
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
