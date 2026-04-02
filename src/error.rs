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
}

pub type Result<T> = std::result::Result<T, VigilError>;
