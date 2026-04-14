use core::fmt;

/// Errors from packet handling or the session state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Datagram shorter than the fixed ATEM header.
    TooShort,
    /// Declared packet length is inconsistent with buffer or below header size.
    InvalidLength,
    /// Unknown or malformed control opcode.
    BadControl,
    /// I/O or timer wrapper reported a failure (see `Display`).
    Other(&'static str),
    /// Timed out waiting for the switcher during handshake or operation.
    Timeout,
    /// Switcher sent `ConnectNack`.
    ConnectRejected,
    /// Unexpected control or session stage.
    UnexpectedState,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer too short for ATEM header"),
            Self::InvalidLength => write!(f, "invalid ATEM packet length field"),
            Self::BadControl => write!(f, "invalid ATEM control payload"),
            Self::Other(s) => write!(f, "{s}"),
            Self::Timeout => write!(f, "timeout waiting for ATEM"),
            Self::ConnectRejected => write!(f, "ATEM rejected connection (ConnectNack)"),
            Self::UnexpectedState => write!(f, "unexpected ATEM protocol state"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
