//! Decode errors and the protocol error taxonomy (spec §7.5).

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
}
