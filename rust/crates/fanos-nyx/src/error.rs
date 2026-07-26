//! The crate's error type.
//!
//! Lives here rather than inside the transparent-onion module so that module can be feature-gated without taking the error
//! every other module returns with it — a construction being optional should not make the vocabulary optional.

use fanos_primitives::shamir::ShamirError;

/// A NYX error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NyxError {
    /// AEAD sealing or opening failed (below-threshold reconstruction manifests here: the
    /// wrong key fails authentication).
    Aead,
    /// Secret-sharing parameters or shares were invalid.
    Sharing(ShamirError),
    /// A reconstructed key was the wrong length.
    KeyLength,
}

impl From<ShamirError> for NyxError {
    fn from(e: ShamirError) -> Self {
        Self::Sharing(e)
    }
}

impl core::fmt::Display for NyxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Aead => f.write_str("AEAD sealing/opening failed (wrong key or below threshold)"),
            Self::Sharing(e) => write!(f, "secret sharing failed: {e}"),
            Self::KeyLength => f.write_str("reconstructed key was the wrong length"),
        }
    }
}

impl core::error::Error for NyxError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Sharing(e) => Some(e),
            _ => None,
        }
    }
}
