//! Central error type: `VigilError` covers I/O, database, config, and domain errors.

use std::path::PathBuf;
use thiserror::Error;

/// Central error type for Vigil.
#[derive(Error, Debug)]
pub enum VigilError {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Database(#[from] rusqlite::Error),

    #[error("{0}")]
    Config(String),

    #[error("configuration file parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("{0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Hash(String),

    #[error("{0}")]
    Fanotify(String),

    #[error("{0}")]
    Inotify(String),

    #[error("{0}")]
    Monitor(String),

    #[error("{0}")]
    Baseline(String),

    #[error("{0}")]
    Alert(String),

    #[error("{0}")]
    DBus(String),

    #[error("{0}")]
    HmacVerification(String),

    #[error("{0}")]
    PackageManager(String),

    #[error("{0}")]
    PermissionDenied(String),

    #[error("{0}")]
    Daemon(String),

    #[error("{0}")]
    Path(String),

    #[error("{0}")]
    Syslog(String),

    #[error("{0}")]
    Control(String),

    #[error("{0}")]
    GlobPattern(#[from] globset::Error),

    #[error("{0}")]
    Wal(String),

    #[error("{0}")]
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

    /// Returns sample error messages for every string-based VigilError variant.
    fn sample_errors() -> Vec<VigilError> {
        vec![
            VigilError::Config("invalid watch path: /nonexistent does not exist".into()),
            VigilError::Hash("BLAKE3 hash mismatch for /etc/passwd".into()),
            VigilError::Fanotify("kernel rejected fanotify_init at /dev/fanotify; check CAP_SYS_ADMIN or run `vigil doctor`".into()),
            VigilError::Inotify("inotify watch limit reached; increase /proc/sys/fs/inotify/max_user_watches".into()),
            VigilError::Monitor("monitor thread exited; run `vigil doctor` for diagnostics".into()),
            VigilError::Baseline("baseline at /var/lib/vigil/baseline.db was previously initialized but is now empty; possible tampering. Run `vigil doctor`".into()),
            VigilError::Alert("desktop notification failed; notify-send not found at /usr/bin/notify-send".into()),
            VigilError::DBus("D-Bus session bus unavailable; desktop notifications disabled. Check /run/user/$UID/bus".into()),
            VigilError::HmacVerification("HMAC key file /etc/vigil/hmac.key has unsafe permissions 0644; fix with: sudo chmod 600 /etc/vigil/hmac.key".into()),
            VigilError::PackageManager("pacman query timed out after 5s; check `pacman -Qi` manually".into()),
            VigilError::PermissionDenied("cannot open /var/lib/vigil/baseline.db; run with elevated privileges: sudo vigil doctor".into()),
            VigilError::Daemon("Another vigild is running. Stop it first: `sudo systemctl stop vigild`.".into()),
            VigilError::Path("path /var/lib/vigil/baseline.db is not a regular file".into()),
            VigilError::Syslog("cannot open /dev/log; journald may not be running".into()),
            VigilError::Control("Another vigild is running (control socket /run/vigil/control.sock already in use). Stop it first: `sudo systemctl stop vigild`.".into()),
            VigilError::Wal("The detection log is full. Run `vigil status` and `vigil doctor` to investigate.".into()),
            VigilError::Attest("attestation key not found at /etc/vigil/attest.key; run `vigil setup attest`".into()),
        ]
    }

    #[test]
    fn error_messages_are_human_readable() {
        let forbidden_jargon = ["unwrap", "Result", "Option", "Box", "panic", "dyn", "serde"];
        let forbidden_marketing = [
            "leverage",
            "robust",
            "comprehensive",
            "seamless",
            "powerful",
            "intuitive",
        ];
        let forbidden_phrases = [
            "live your life",
            "hang tight",
            "don't worry",
            "you got this",
            "whoops",
            "oops",
            "uh oh",
            "you're fine",
        ];

        for err in sample_errors() {
            let msg = err.to_string();

            // Length under 250 characters
            assert!(
                msg.len() <= 250,
                "error message too long ({} chars): {}",
                msg.len(),
                msg
            );

            // Contains a CLI command in backticks, a file path, or both
            let has_backtick_cmd = msg.contains('`');
            let has_path = msg.contains('/');
            assert!(
                has_backtick_cmd || has_path,
                "error message must contain a command or path: {}",
                msg
            );

            // No Rust jargon
            for word in &forbidden_jargon {
                assert!(
                    !msg.to_lowercase().contains(&word.to_lowercase()),
                    "error message contains forbidden jargon '{}': {}",
                    word,
                    msg
                );
            }

            // No marketing words
            for word in &forbidden_marketing {
                assert!(
                    !msg.to_lowercase().contains(&word.to_lowercase()),
                    "error message contains forbidden marketing word '{}': {}",
                    word,
                    msg
                );
            }

            // No forbidden phrases
            for phrase in &forbidden_phrases {
                assert!(
                    !msg.to_lowercase().contains(phrase),
                    "error message contains forbidden phrase '{}': {}",
                    phrase,
                    msg
                );
            }
        }
    }
}
