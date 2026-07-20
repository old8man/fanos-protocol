//! Decode errors and the protocol error taxonomy (spec §7.5).

use alloc::vec::Vec;

use crate::varint;

/// A decoding failure. Canonical encoding means there is exactly one valid byte sequence for
/// every object, so a decoder rejects everything else — that is what makes signatures and
/// hashes portable across implementations (spec §7.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    /// The buffer ended before a complete object was read.
    UnexpectedEnd,
    /// A variable-length integer used a longer-than-minimal encoding.
    NonCanonicalVarint,
    /// A field element encoded a value `≥ q` (outside the field).
    FieldElementOutOfRange,
    /// A projective triple was the zero vector or not in canonical form (first non-zero
    /// coordinate not `1`).
    NonCanonicalProjective,
    /// A frame declared a body length exceeding the remaining input.
    FrameLengthOverflow,
    /// A critical frame type is not understood by this implementation.
    UnknownCriticalFrame,
    /// A value did not fit the target width.
    ValueTooLarge,
    /// A packet or frame declared a version this build does not support.
    UnsupportedVersion,
    /// Bytes remained after a complete object was decoded — a canonical decoder consumes its input
    /// exactly, so trailing bytes are a (non-canonical) error.
    TrailingBytes,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::UnexpectedEnd => "unexpected end of input",
            Self::NonCanonicalVarint => "non-canonical varint (non-minimal length)",
            Self::FieldElementOutOfRange => "field element out of range",
            Self::NonCanonicalProjective => "non-canonical projective coordinate",
            Self::FrameLengthOverflow => "frame length exceeds input",
            Self::UnknownCriticalFrame => "unknown critical frame type",
            Self::ValueTooLarge => "value too large for target width",
            Self::UnsupportedVersion => "unsupported format version",
            Self::TrailingBytes => "trailing bytes after a complete object",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for WireError {}

/// The protocol-level error codes exchanged in `ERROR` frames (spec §7.5), grouped by class
/// so a caller can react without a full table. The numeric value is the `varint code` on the
/// wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum ProtocolError {
    // 1xx protocol — drop peer / bug; never retry verbatim.
    /// An unsupported feature or version was requested.
    Unsupported = 100,
    /// A message was malformed.
    Malformed = 101,
    /// A non-canonical encoding was received.
    NonCanonical = 102,
    // 2xx membership — re-sync beacon, re-admit.
    /// A coordinate proof failed to verify.
    BadCoord = 200,
    /// The peer's epoch is stale relative to the beacon.
    EpochStale = 201,
    /// Sybil admission rejected the peer.
    SybilReject = 202,
    // 3xx routing — reroute via mediator, widen quorum / lower threshold.
    /// No route to the destination.
    NoRoute = 300,
    /// A required quorum-line was unavailable.
    QuorumUnavail = 301,
    /// The threshold `t` of a line could not be met.
    ThresholdUnmet = 302,
    // 4xx privacy — rebuild circuit, escalate to DIAKRISIS.
    /// A NYX path broke mid-circuit.
    PathBroken = 400,
    /// The holonomy authenticator failed.
    HolonomyFail = 401,
    /// Cover traffic was starved.
    CoverStarved = 402,
    // 5xx service — rotate rendezvous line, attach PoW.
    /// A hidden service was unreachable.
    SvcUnreachable = 500,
    /// A rendezvous line expired (epoch rolled).
    RdvExpired = 501,
    /// Proof-of-work is required for this request.
    PowRequired = 502,
}

impl ProtocolError {
    /// The error class digit (`1..=5`) — the caller's coarse reaction bucket (spec §7.5).
    #[must_use]
    pub fn class(self) -> u8 {
        (self as u16 / 100) as u8
    }

    /// The `varint code` carried on the wire.
    #[must_use]
    pub fn code(self) -> u64 {
        self as u16 as u64
    }

    /// The taxonomy entry for a numeric wire code, or `None` if this build does not recognize it
    /// (a forward-compatible peer's new error class, or a malformed/garbage code). Exhaustive match
    /// keeps the taxonomy and this decoder in lock-step, mirroring [`crate::FrameType::from_code`].
    #[must_use]
    pub fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            100 => Self::Unsupported,
            101 => Self::Malformed,
            102 => Self::NonCanonical,
            200 => Self::BadCoord,
            201 => Self::EpochStale,
            202 => Self::SybilReject,
            300 => Self::NoRoute,
            301 => Self::QuorumUnavail,
            302 => Self::ThresholdUnmet,
            400 => Self::PathBroken,
            401 => Self::HolonomyFail,
            402 => Self::CoverStarved,
            500 => Self::SvcUnreachable,
            501 => Self::RdvExpired,
            502 => Self::PowRequired,
            _ => return None,
        })
    }
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Unsupported => "unsupported feature or version",
            Self::Malformed => "malformed message",
            Self::NonCanonical => "non-canonical encoding",
            Self::BadCoord => "coordinate proof failed to verify",
            Self::EpochStale => "peer epoch is stale relative to the beacon",
            Self::SybilReject => "Sybil admission rejected the peer",
            Self::NoRoute => "no route to the destination",
            Self::QuorumUnavail => "required quorum line unavailable",
            Self::ThresholdUnmet => "line threshold could not be met",
            Self::PathBroken => "NYX path broke mid-circuit",
            Self::HolonomyFail => "holonomy authenticator failed",
            Self::CoverStarved => "cover traffic starved",
            Self::SvcUnreachable => "hidden service unreachable",
            Self::RdvExpired => "rendezvous line expired (epoch rolled)",
            Self::PowRequired => "proof-of-work required for this request",
        };
        // Prefix the numeric wire code so a log line carries both (spec §7.5).
        write!(f, "[{}] {msg}", self.code())
    }
}

impl core::error::Error for ProtocolError {}

/// Encode an `ERROR` frame body (spec §7.5): `code:varint ‖ reason:bytes`. `reason` is optional
/// UTF-8 explanatory text (may be empty) — its length is bounded by the enclosing frame's own
/// `length` field (spec §7.2), so no redundant inner length prefix is needed; this mirrors
/// [`crate::frame::encode_frame`]'s own trailing-field convention (e.g. `Publish`'s trailing value).
#[must_use]
pub fn encode_error(err: ProtocolError, reason: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + reason.len());
    varint::encode(err.code(), &mut out);
    out.extend_from_slice(reason);
    out
}

/// Decode an `ERROR` frame body into its raw wire code and reason bytes. Returns the numeric code
/// **unresolved** (not a [`ProtocolError`]) — exactly like [`crate::Frame::type_code`] versus
/// [`crate::Frame::frame_type`] — so a caller can log/react to a future error class this build does
/// not yet name; resolve it with [`ProtocolError::from_code`] when a known code is expected.
///
/// # Errors
/// [`WireError::UnexpectedEnd`] if the body is shorter than its varint code.
pub fn decode_error(body: &[u8]) -> Result<(u64, &[u8]), WireError> {
    let (code, n) = varint::decode(body)?;
    let reason = body.get(n..).ok_or(WireError::UnexpectedEnd)?;
    Ok((code, reason))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn error_body_round_trips_with_a_reason() {
        let body = encode_error(ProtocolError::BadCoord, b"impostor cert");
        let (code, reason) = decode_error(&body).unwrap();
        assert_eq!(ProtocolError::from_code(code), Some(ProtocolError::BadCoord));
        assert_eq!(reason, b"impostor cert");
    }

    #[test]
    fn error_body_round_trips_with_an_empty_reason() {
        let body = encode_error(ProtocolError::Unsupported, b"");
        // Code 100 needs the 2-byte varint form (≥ 64); no reason bytes follow.
        assert_eq!(body, [0x40, 0x64]);
        let (code, reason) = decode_error(&body).unwrap();
        assert_eq!(ProtocolError::from_code(code), Some(ProtocolError::Unsupported));
        assert!(reason.is_empty());
    }

    #[test]
    fn from_code_is_the_exact_inverse_of_code_for_every_taxonomy_entry() {
        let all = [
            ProtocolError::Unsupported,
            ProtocolError::Malformed,
            ProtocolError::NonCanonical,
            ProtocolError::BadCoord,
            ProtocolError::EpochStale,
            ProtocolError::SybilReject,
            ProtocolError::NoRoute,
            ProtocolError::QuorumUnavail,
            ProtocolError::ThresholdUnmet,
            ProtocolError::PathBroken,
            ProtocolError::HolonomyFail,
            ProtocolError::CoverStarved,
            ProtocolError::SvcUnreachable,
            ProtocolError::RdvExpired,
            ProtocolError::PowRequired,
        ];
        for err in all {
            assert_eq!(ProtocolError::from_code(err.code()), Some(err), "{err:?}");
        }
    }

    #[test]
    fn an_unrecognized_code_decodes_but_does_not_resolve() {
        // Forward compatibility: a future error class this build does not know still decodes as a
        // raw code (with its reason bytes intact), it just does not resolve to a named variant.
        let mut body = Vec::new();
        varint::encode(999, &mut body);
        body.extend_from_slice(b"future class");
        let (code, reason) = decode_error(&body).unwrap();
        assert_eq!(code, 999);
        assert_eq!(reason, b"future class");
        assert_eq!(ProtocolError::from_code(code), None);
    }

    #[test]
    fn decode_rejects_a_body_shorter_than_its_varint_code() {
        assert_eq!(decode_error(&[]), Err(WireError::UnexpectedEnd));
    }
}
