//! The [`Dialer`] seam — how a target is actually reached.
//!
//! The proxy is generic over a `Dialer`, so the reachability policy (resolve a `.fanos` service
//! over the overlay, refuse the clear net until an exit exists) is entirely pluggable and testable
//! in isolation. [`EchoDialer`] is the in-process loopback used by the SOCKS5 tests.

use std::future::Future;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::target::Target;

/// Why a dial failed — mapped to the corresponding SOCKS5 reply code.
#[derive(Debug)]
pub enum DialError {
    /// The connection is not allowed by policy (e.g. clear net with no exit configured).
    Refused,
    /// The target could not be reached (service not found / unreachable).
    Unreachable,
    /// This kind of target is not supported (e.g. an address type the dialer won't handle).
    Unsupported(String),
    /// An underlying I/O error.
    Io(std::io::Error),
}

impl DialError {
    /// The SOCKS5 reply code for this failure (RFC 1928 §6).
    #[must_use]
    pub fn socks5_reply_code(&self) -> u8 {
        match self {
            Self::Refused => 0x02,        // connection not allowed by ruleset
            Self::Unreachable => 0x04,    // host unreachable
            Self::Unsupported(_) => 0x08, // address type not supported
            Self::Io(_) => 0x01,          // general SOCKS server failure
        }
    }
}

impl core::fmt::Display for DialError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Refused => f.write_str("connection refused by policy"),
            Self::Unreachable => f.write_str("target unreachable"),
            Self::Unsupported(what) => write!(f, "unsupported target: {what}"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for DialError {}

impl From<std::io::Error> for DialError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Establishes a byte stream to a SOCKS5 [`Target`]. Implementors decide reachability policy.
pub trait Dialer {
    /// The duplex byte stream returned on a successful dial.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Attempt to reach `target`, returning a connected duplex stream.
    fn dial(&self, target: &Target)
    -> impl Future<Output = Result<Self::Stream, DialError>> + Send;
}

/// A loopback dialer whose stream echoes everything written to it — the SOCKS5 test fixture.
#[derive(Clone, Copy, Default, Debug)]
pub struct EchoDialer;

impl Dialer for EchoDialer {
    type Stream = tokio::io::DuplexStream;

    fn dial(
        &self,
        _target: &Target,
    ) -> impl Future<Output = Result<Self::Stream, DialError>> + Send {
        let (client_side, server_side) = tokio::io::duplex(8192);
        // Echo: copy the server side's reads back to its writes (what the client reads).
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(server_side);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        std::future::ready(Ok(client_side))
    }
}

/// A dialer that refuses every target — a safe default before any transport is wired.
#[derive(Clone, Copy, Default, Debug)]
pub struct RefuseDialer;

impl Dialer for RefuseDialer {
    type Stream = tokio::io::DuplexStream;

    fn dial(
        &self,
        _target: &Target,
    ) -> impl Future<Output = Result<Self::Stream, DialError>> + Send {
        std::future::ready(Err(DialError::Refused))
    }
}
