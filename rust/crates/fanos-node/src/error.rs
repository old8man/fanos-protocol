//! The node error taxonomy.

/// An error starting or running a FANOS node.
#[derive(Debug)]
pub enum NodeError {
    /// An I/O error (identity file, socket bind).
    Io(std::io::Error),
    /// The QUIC transport driver failed to bring the node up.
    Quic(fanos_quic::QuicError),
    /// The persisted identity could not be generated, read, or parsed.
    Identity,
    /// A configuration value was invalid (bad address, coordinate, or role).
    Config(String),
    /// A `.fanos` name could not be resolved (not published, malformed, or failed verification).
    Resolve(String),
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Quic(e) => write!(f, "transport error: {e}"),
            Self::Identity => f.write_str("node identity could not be loaded or generated"),
            Self::Config(msg) => write!(f, "invalid configuration: {msg}"),
            Self::Resolve(msg) => write!(f, "name resolution failed: {msg}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<std::io::Error> for NodeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<fanos_quic::QuicError> for NodeError {
    fn from(e: fanos_quic::QuicError) -> Self {
        Self::Quic(e)
    }
}

/// An environment that does not say where this user's files live is a **configuration** problem, and lands in
/// that variant rather than in a new one (#312).
///
/// `HOME` configures this run exactly as `--config` does — it is the input from which the whole path layout is
/// derived — and the operator's next action is the same kind of action. A separate variant would widen the
/// taxonomy for one cause without giving any caller a decision it can make differently, and
/// [`setup::HomeUnknown`](crate::setup::HomeUnknown)'s own `Display` already carries which of the two cases it
/// is and what to do about it.
impl From<crate::setup::HomeUnknown> for NodeError {
    fn from(e: crate::setup::HomeUnknown) -> Self {
        Self::Config(e.to_string())
    }
}
