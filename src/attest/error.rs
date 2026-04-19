use std::fmt;

/// Attestation-specific error type.
///
/// Kept separate from the main VigilError to keep the verification path
/// small and self-contained.
#[derive(Debug)]
pub enum AttestError {
    /// I/O failure (file unreadable, write failed, etc.)
    Io(std::io::Error),
    /// Invalid attestation file (bad magic, unknown version, corrupt CBOR)
    InvalidFormat(String),
    /// Content hash does not match recomputed value
    ContentHashMismatch {
        declared: String,
        recomputed: String,
    },
    /// Signature verification failed
    SignatureInvalid(String),
    /// Signing key not found
    KeyNotFound(String),
    /// Audit chain link broken inside the attestation
    ChainBroken(String),
    /// General attestation error
    Other(String),
}

impl fmt::Display for AttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestError::Io(e) => write!(f, "I/O error: {}", e),
            AttestError::InvalidFormat(msg) => write!(f, "invalid attestation: {}", msg),
            AttestError::ContentHashMismatch {
                declared,
                recomputed,
            } => {
                write!(
                    f,
                    "content hash mismatch: declared={}, recomputed={}",
                    declared, recomputed
                )
            }
            AttestError::SignatureInvalid(msg) => write!(f, "signature invalid: {}", msg),
            AttestError::KeyNotFound(msg) => write!(f, "signing key not found: {}", msg),
            AttestError::ChainBroken(msg) => write!(f, "audit chain broken: {}", msg),
            AttestError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AttestError {}

impl From<std::io::Error> for AttestError {
    fn from(e: std::io::Error) -> Self {
        AttestError::Io(e)
    }
}

impl From<AttestError> for crate::error::VigilError {
    fn from(e: AttestError) -> Self {
        match e {
            AttestError::Io(io_err) => crate::error::VigilError::Io(io_err),
            other => crate::error::VigilError::Attest(other.to_string()),
        }
    }
}

pub type AttestResult<T> = std::result::Result<T, AttestError>;
