//! Central error type: `VigilError` covers I/O, database, config, and domain errors.

use std::path::PathBuf;
use thiserror::Error;

/// Central error type for Vigil.
#[derive(Error, Debug)]
pub enum VigilError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hash error: {0}")]
    Hash(String),

    #[error("fanotify error: {0}")]
    Fanotify(String),

    #[error("inotify error: {0}")]
    Inotify(String),

    #[error("monitor error: {0}")]
    Monitor(String),

    #[error("baseline error: {0}")]
    Baseline(String),

    #[error("alert error: {0}")]
    Alert(String),

    #[error("D-Bus error: {0}")]
    DBus(String),

    #[error("HMAC verification failed: {0}")]
    HmacVerification(String),

    #[error("package manager error: {0}")]
    PackageManager(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("daemon error: {0}")]
    Daemon(String),

    #[error("path error: {0}")]
    Path(String),

    #[error("syslog error: {0}")]
    Syslog(String),

    #[error("control socket error: {0}")]
    Control(String),

    #[error("glob pattern error: {0}")]
    GlobPattern(#[from] globset::Error),

    #[error("WAL error: {0}")]
    Wal(String),

    #[error("attestation error: {0}")]
    Attest(String),
}

pub type Result<T> = std::result::Result<T, VigilError>;

impl VigilError {
    /// Prepend context to a string-based error variant.
    pub fn with_context(self, ctx: &str) -> Self {
        match self {
            VigilError::Config(msg) => VigilError::Config(format!("{}: {}", ctx, msg)),
            VigilError::Daemon(msg) => VigilError::Daemon(format!("{}: {}", ctx, msg)),
            VigilError::Baseline(msg) => VigilError::Baseline(format!("{}: {}", ctx, msg)),
            VigilError::Alert(msg) => VigilError::Alert(format!("{}: {}", ctx, msg)),
            VigilError::Monitor(msg) => VigilError::Monitor(format!("{}: {}", ctx, msg)),
            VigilError::Fanotify(msg) => VigilError::Fanotify(format!("{}: {}", ctx, msg)),
            VigilError::Inotify(msg) => VigilError::Inotify(format!("{}: {}", ctx, msg)),
            VigilError::Hash(msg) => VigilError::Hash(format!("{}: {}", ctx, msg)),
            VigilError::Control(msg) => VigilError::Control(format!("{}: {}", ctx, msg)),
            VigilError::HmacVerification(msg) => {
                VigilError::HmacVerification(format!("{}: {}", ctx, msg))
            }
            VigilError::Wal(msg) => VigilError::Wal(format!("{}: {}", ctx, msg)),
            VigilError::Attest(msg) => VigilError::Attest(format!("{}: {}", ctx, msg)),
            VigilError::DBus(msg) => VigilError::DBus(format!("{}: {}", ctx, msg)),
            VigilError::PackageManager(msg) => {
                VigilError::PackageManager(format!("{}: {}", ctx, msg))
            }
            VigilError::PermissionDenied(msg) => {
                VigilError::PermissionDenied(format!("{}: {}", ctx, msg))
            }
            VigilError::Path(msg) => VigilError::Path(format!("{}: {}", ctx, msg)),
            VigilError::Syslog(msg) => VigilError::Syslog(format!("{}: {}", ctx, msg)),
            VigilError::Io(e) => VigilError::Daemon(format!("{}: I/O error: {}", ctx, e)),
            VigilError::Database(e) => {
                VigilError::Daemon(format!("{}: database error: {}", ctx, e))
            }
            VigilError::TomlParse(e) => {
                VigilError::Config(format!("{}: TOML parse error: {}", ctx, e))
            }
            VigilError::Json(e) => VigilError::Daemon(format!("{}: JSON error: {}", ctx, e)),
            VigilError::GlobPattern(e) => {
                VigilError::Config(format!("{}: glob pattern error: {}", ctx, e))
            }
        }
    }
}

/// A structured warning collected during scanning operations.
#[derive(Debug, Clone)]
pub struct ScanWarning {
    pub path: PathBuf,
    pub detail: String,
    pub severity: WarningSeverity,
}

/// Severity level for scan warnings.
#[derive(Debug, Clone, Copy)]
pub enum WarningSeverity {
    Info,
    Warning,
    Error,
}

impl PartialEq for VigilError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // Io and Database are never structurally comparable
            (VigilError::Io(_), VigilError::Io(_)) => false,
            (VigilError::Database(_), VigilError::Database(_)) => false,
            // String-based variants compare by string value
            (VigilError::Config(a), VigilError::Config(b)) => a == b,
            (VigilError::Hash(a), VigilError::Hash(b)) => a == b,
            (VigilError::Fanotify(a), VigilError::Fanotify(b)) => a == b,
            (VigilError::Inotify(a), VigilError::Inotify(b)) => a == b,
            (VigilError::Monitor(a), VigilError::Monitor(b)) => a == b,
            (VigilError::Baseline(a), VigilError::Baseline(b)) => a == b,
            (VigilError::Alert(a), VigilError::Alert(b)) => a == b,
            (VigilError::DBus(a), VigilError::DBus(b)) => a == b,
            (VigilError::HmacVerification(a), VigilError::HmacVerification(b)) => a == b,
            (VigilError::PackageManager(a), VigilError::PackageManager(b)) => a == b,
            (VigilError::PermissionDenied(a), VigilError::PermissionDenied(b)) => a == b,
            (VigilError::Daemon(a), VigilError::Daemon(b)) => a == b,
            (VigilError::Path(a), VigilError::Path(b)) => a == b,
            (VigilError::Syslog(a), VigilError::Syslog(b)) => a == b,
            (VigilError::Control(a), VigilError::Control(b)) => a == b,
            (VigilError::Wal(a), VigilError::Wal(b)) => a == b,
            (VigilError::Attest(a), VigilError::Attest(b)) => a == b,
            // TomlParse and Json compare by Display output
            (VigilError::TomlParse(a), VigilError::TomlParse(b)) => a.to_string() == b.to_string(),
            (VigilError::Json(a), VigilError::Json(b)) => a.to_string() == b.to_string(),
            // Different variants are never equal
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_equality_config() {
        assert_eq!(
            VigilError::Config("test".into()),
            VigilError::Config("test".into()),
        );
        assert_ne!(
            VigilError::Config("a".into()),
            VigilError::Config("b".into()),
        );
    }

    #[test]
    fn error_io_never_equal() {
        let a = VigilError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "x"));
        let b = VigilError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "x"));
        assert_ne!(a, b);
    }

    #[test]
    fn error_different_variants_not_equal() {
        assert_ne!(
            VigilError::Config("test".into()),
            VigilError::Hash("test".into()),
        );
    }

    #[test]
    fn error_string_variants_equal() {
        assert_eq!(
            VigilError::Hash("bad hash".into()),
            VigilError::Hash("bad hash".into()),
        );
        assert_eq!(
            VigilError::Baseline("missing".into()),
            VigilError::Baseline("missing".into()),
        );
    }

    #[test]
    fn with_context_prepends_message() {
        let err = VigilError::Config("missing field".into());
        let contexted = err.with_context("loading config");
        assert!(contexted.to_string().contains("loading config: "));
        assert!(contexted.to_string().contains("missing field"));
    }

    #[test]
    fn with_context_io_becomes_daemon() {
        let err = VigilError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        let contexted = err.with_context("opening file");
        match contexted {
            VigilError::Daemon(msg) => {
                assert!(msg.contains("opening file"));
                assert!(msg.contains("I/O error"));
            }
            other => panic!("expected Daemon variant, got {:?}", other),
        }
    }
}
