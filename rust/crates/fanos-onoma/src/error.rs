//! The ONOMA error taxonomy.

/// An error decoding, parsing, or resolving an ONOMA name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OnomaError {
    /// The input was empty.
    Empty,
    /// The data length was wrong (too short/long, or not a whole payload).
    BadLength,
    /// A character outside the bech32 charset (or an invalid label character).
    BadChar,
    /// Mixed upper/lower case — bech32 forbids it to avoid transcription ambiguity.
    MixedCase,
    /// The bech32m checksum did not verify (a transcription error or a bech32-vs-bech32m mismatch).
    BadChecksum,
    /// The human-readable part / TLD was not the expected one.
    WrongTld,
    /// The address version is not supported by this implementation.
    Unsupported(u8),
    /// A readable label was invalid (empty, too long, or a disallowed character).
    BadLabel,
    /// A zone/delegation chain exceeded the maximum depth (loop or abuse guard).
    TooDeep,
    /// The name was not found in the zone/registry.
    NotFound,
    /// A record or delegation signature failed to verify.
    BadSignature,
}

impl core::fmt::Display for OnomaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Empty => "empty input",
            Self::BadLength => "wrong data length",
            Self::BadChar => "invalid character",
            Self::MixedCase => "mixed-case input is not allowed",
            Self::BadChecksum => "checksum verification failed",
            Self::WrongTld => "unexpected TLD / human-readable part",
            Self::Unsupported(_) => "unsupported address version",
            Self::BadLabel => "invalid name label",
            Self::TooDeep => "delegation chain too deep",
            Self::NotFound => "name not found",
            Self::BadSignature => "signature verification failed",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OnomaError {}
