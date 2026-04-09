pub mod diff;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Result, VigilError};
use crate::types::{MonitorBackend, PackageBackend, ScanMode, Severity};

pub use diff::diff_config;

/// Supported hash algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Blake3,
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Blake3 => write!(f, "blake3"),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogFormat::Text => write!(f, "text"),
            LogFormat::Json => write!(f, "json"),
        }
    }
}

/// Log verbosity level.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Error => write!(f, "error"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Trace => write!(f, "trace"),
        }
    }
}

/// Syslog transport protocol.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogProtocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for SyslogProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyslogProtocol::Tcp => write!(f, "tcp"),
            SyslogProtocol::Udp => write!(f, "udp"),
        }
    }
}

/// Syslog facility.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFacility {
    Auth,
    Authpriv,
    Daemon,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl std::fmt::Display for SyslogFacility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyslogFacility::Auth => write!(f, "auth"),
            SyslogFacility::Authpriv => write!(f, "authpriv"),
            SyslogFacility::Daemon => write!(f, "daemon"),
            SyslogFacility::Local0 => write!(f, "local0"),
            SyslogFacility::Local1 => write!(f, "local1"),
            SyslogFacility::Local2 => write!(f, "local2"),
            SyslogFacility::Local3 => write!(f, "local3"),
            SyslogFacility::Local4 => write!(f, "local4"),
            SyslogFacility::Local5 => write!(f, "local5"),
            SyslogFacility::Local6 => write!(f, "local6"),
            SyslogFacility::Local7 => write!(f, "local7"),
        }
    }
}

/// SQLite synchronous mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncMode {
    Off,
    Normal,
    Full,
    Extra,
}

impl std::fmt::Display for SyncMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncMode::Off => write!(f, "off"),
            SyncMode::Normal => write!(f, "normal"),
            SyncMode::Full => write!(f, "full"),
            SyncMode::Extra => write!(f, "extra"),
        }
    }
}

impl SyncMode {
    /// Return the pragma value string for SQLite.
    pub fn as_pragma(&self) -> &str {
        match self {
            SyncMode::Off => "OFF",
            SyncMode::Normal => "NORMAL",
            SyncMode::Full => "FULL",
            SyncMode::Extra => "EXTRA",
        }
    }
}

/// Top-level Vigil configuration, deserialized from TOML.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_config_version")]
    pub config_version: u32,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub scanner: ScannerConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub exclusions: ExclusionsConfig,
    #[serde(default)]
    pub package_manager: PackageManagerConfig,
    #[serde(default)]
    pub hooks: HooksConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub watch: HashMap<String, WatchGroup>,
}

fn default_config_version() -> u32 {
    2
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: LogLevel,
    #[serde(default = "default_monitor_backend")]
    pub monitor_backend: MonitorBackend,
    #[serde(default = "default_worker_threads")]
    pub worker_threads: u32,
    #[serde(default = "default_log_format")]
    pub log_format: LogFormat,
    #[serde(default = "default_runtime_dir")]
    pub runtime_dir: PathBuf,
    #[serde(default = "default_control_socket")]
    pub control_socket: PathBuf,
    #[serde(default = "default_debounce_ms")]
    pub debounce_ms: u64,
    /// Event channel capacity. Higher values reduce event drops under load.
    #[serde(default = "default_event_channel_capacity")]
    pub event_channel_capacity: usize,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: default_pid_file(),
            db_path: default_db_path(),
            log_level: default_log_level(),
            monitor_backend: default_monitor_backend(),
            worker_threads: default_worker_threads(),
            log_format: default_log_format(),
            runtime_dir: default_runtime_dir(),
            control_socket: default_control_socket(),
            debounce_ms: default_debounce_ms(),
            event_channel_capacity: default_event_channel_capacity(),
        }
    }
}

fn default_worker_threads() -> u32 {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(2);
    (cpus / 2).clamp(2, 16)
}

fn default_log_format() -> LogFormat {
    LogFormat::Text
}

fn default_runtime_dir() -> PathBuf {
    PathBuf::from("/run/vigil")
}

fn default_pid_file() -> PathBuf {
    PathBuf::from("/run/vigil/vigild.pid")
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/vigil/baseline.db")
}

fn default_log_level() -> LogLevel {
    LogLevel::Info
}

fn default_control_socket() -> PathBuf {
    PathBuf::from("/run/vigil/control.sock")
}

fn default_debounce_ms() -> u64 {
    100
}

fn default_event_channel_capacity() -> usize {
    4096
}

fn default_monitor_backend() -> MonitorBackend {
    MonitorBackend::Fanotify
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScannerConfig {
    #[serde(default = "default_schedule")]
    pub schedule: String,
    #[serde(default = "default_scan_mode")]
    pub mode: ScanMode,
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: HashAlgorithm,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
    #[serde(default = "default_mmap_threshold")]
    pub mmap_threshold: u64,
    /// Scheduled scan mode. Full mode rehashes every file regardless of mtime,
    /// providing protection against mtime-reset attacks at a cost of higher I/O.
    /// Users with very large baselines can set this to `incremental` in their config.
    #[serde(default = "default_scheduled_mode")]
    pub scheduled_mode: ScanMode,
    #[serde(default)]
    pub parallel: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            schedule: default_schedule(),
            mode: default_scan_mode(),
            hash_algorithm: default_hash_algorithm(),
            max_file_size: default_max_file_size(),
            mmap_threshold: default_mmap_threshold(),
            scheduled_mode: ScanMode::Full,
            parallel: false,
        }
    }
}

fn default_mmap_threshold() -> u64 {
    1_048_576
}

fn default_schedule() -> String {
    "0 3 * * *".to_string()
}

fn default_scan_mode() -> ScanMode {
    ScanMode::Incremental
}

fn default_scheduled_mode() -> ScanMode {
    ScanMode::Full
}

fn default_hash_algorithm() -> HashAlgorithm {
    HashAlgorithm::Blake3
}

fn default_max_file_size() -> u64 {
    2_147_483_648
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertsConfig {
    #[serde(default = "default_true")]
    pub desktop_notifications: bool,
    #[serde(default = "default_true")]
    pub syslog: bool,
    #[serde(default = "default_log_file")]
    pub log_file: PathBuf,
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,
    #[serde(default)]
    pub severity_filter: SeverityFilterConfig,
    #[serde(default = "default_notification_rate_limit")]
    pub notification_rate_limit: u32,
    #[serde(default = "default_notification_rate_window")]
    pub notification_rate_window_secs: u64,
    #[serde(default)]
    pub remote_syslog: RemoteSyslogConfig,
    #[serde(default = "default_max_alerts_per_minute")]
    pub max_alerts_per_minute: u32,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            desktop_notifications: true,
            syslog: true,
            log_file: default_log_file(),
            webhook_url: String::new(),
            rate_limit: default_rate_limit(),
            cooldown_seconds: default_cooldown(),
            severity_filter: SeverityFilterConfig::default(),
            notification_rate_limit: default_notification_rate_limit(),
            notification_rate_window_secs: default_notification_rate_window(),
            remote_syslog: RemoteSyslogConfig::default(),
            max_alerts_per_minute: default_max_alerts_per_minute(),
        }
    }
}

fn default_notification_rate_limit() -> u32 {
    5
}

fn default_notification_rate_window() -> u64 {
    10
}

fn default_log_file() -> PathBuf {
    PathBuf::from("/var/log/vigil/alerts.json")
}

fn default_rate_limit() -> u32 {
    10
}

fn default_cooldown() -> u64 {
    300
}

fn default_max_alerts_per_minute() -> u32 {
    10_000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SeverityFilterConfig {
    #[serde(default = "default_dbus_min_severity")]
    pub dbus_min_severity: Severity,
    #[serde(default = "default_log_min_severity")]
    pub log_min_severity: Severity,
}

impl Default for SeverityFilterConfig {
    fn default() -> Self {
        Self {
            dbus_min_severity: default_dbus_min_severity(),
            log_min_severity: default_log_min_severity(),
        }
    }
}

fn default_dbus_min_severity() -> Severity {
    Severity::Medium
}

fn default_log_min_severity() -> Severity {
    Severity::Low
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExclusionsConfig {
    #[serde(default = "default_exclusion_patterns")]
    pub patterns: Vec<String>,
    #[serde(default = "default_system_exclusions")]
    pub system_exclusions: Vec<String>,
}

impl Default for ExclusionsConfig {
    fn default() -> Self {
        Self {
            patterns: default_exclusion_patterns(),
            system_exclusions: default_system_exclusions(),
        }
    }
}

fn default_exclusion_patterns() -> Vec<String> {
    vec![
        "*.swp".into(),
        "*.swx".into(),
        "*~".into(),
        "*.tmp".into(),
        "*.log".into(),
        "*.cache".into(),
        ".git/*".into(),
        "__pycache__/*".into(),
    ]
}

/// Default system exclusions. Note: `/run/*` is intentionally NOT blanket-excluded.
/// Attackers can persist via transient systemd units in `/run/systemd/transient/`.
/// Blanket exclusion of `/run/*` creates a monitoring blind spot.
/// Vigil's own runtime directory (`/run/vigil/`) is excluded via the self_paths
/// mechanism in ExclusionFilter.
fn default_system_exclusions() -> Vec<String> {
    vec![
        "/proc/*".into(),
        "/sys/*".into(),
        "/dev/*".into(),
        "/run/user/*".into(),
        "/run/lock/*".into(),
        "/run/utmp".into(),
        "/tmp/*".into(),
    ]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackageManagerConfig {
    #[serde(default = "default_true")]
    pub auto_rebaseline: bool,
    #[serde(default = "default_pkg_backend")]
    pub backend: PackageBackend,
}

impl Default for PackageManagerConfig {
    fn default() -> Self {
        Self {
            auto_rebaseline: true,
            backend: default_pkg_backend(),
        }
    }
}

fn default_pkg_backend() -> PackageBackend {
    PackageBackend::Auto
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HooksConfig {
    #[serde(default)]
    pub signal_socket: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub hmac_signing: bool,
    #[serde(default = "default_hmac_key_path")]
    pub hmac_key_path: PathBuf,
    #[serde(default = "default_true")]
    pub verify_config_integrity: bool,
    /// Enable challenge-response authentication on the control socket.
    /// Requires hmac_signing to be enabled.
    #[serde(default = "default_true")]
    pub control_socket_auth: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            hmac_signing: false,
            hmac_key_path: default_hmac_key_path(),
            verify_config_integrity: true,
            control_socket_auth: true,
        }
    }
}

fn default_hmac_key_path() -> PathBuf {
    PathBuf::from("/etc/vigil/hmac.key")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_true")]
    pub wal_mode: bool,
    #[serde(default = "default_audit_rotation_size")]
    pub audit_rotation_size: u64,
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u32,
    #[serde(default = "default_sync_mode")]
    pub sync_mode: SyncMode,
    #[serde(default = "default_busy_timeout_ms")]
    pub busy_timeout_ms: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            wal_mode: true,
            audit_rotation_size: default_audit_rotation_size(),
            audit_retention_days: default_audit_retention_days(),
            sync_mode: default_sync_mode(),
            busy_timeout_ms: default_busy_timeout_ms(),
        }
    }
}

fn default_sync_mode() -> SyncMode {
    SyncMode::Normal
}

fn default_busy_timeout_ms() -> u32 {
    5000
}

fn default_audit_rotation_size() -> u64 {
    104_857_600
}

fn default_audit_retention_days() -> u32 {
    90
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemoteSyslogConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server: String,
    #[serde(default = "default_syslog_port")]
    pub port: u16,
    #[serde(default = "default_syslog_protocol")]
    pub protocol: SyslogProtocol,
    #[serde(default = "default_syslog_facility")]
    pub facility: SyslogFacility,
}

impl Default for RemoteSyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: String::new(),
            port: default_syslog_port(),
            protocol: default_syslog_protocol(),
            facility: default_syslog_facility(),
        }
    }
}

fn default_syslog_port() -> u16 {
    514
}

fn default_syslog_protocol() -> SyslogProtocol {
    SyslogProtocol::Udp
}

fn default_syslog_facility() -> SyslogFacility {
    SyslogFacility::Authpriv
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatchGroup {
    pub severity: Severity,
    pub paths: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Config file search order (highest priority first):
/// 1. explicit CLI path
/// 2. VIGIL_CONFIG
/// 3. ~/.config/vigil/vigil.toml
/// 4. /etc/vigil/vigil.toml
pub fn load_config(explicit_path: Option<&Path>) -> Result<Config> {
    let paths = config_search_paths(explicit_path);

    for path in &paths {
        if path.exists() {
            tracing::info!(path = %path.display(), "loading config");
            let content = std::fs::read_to_string(path).map_err(|e| {
                VigilError::Config(format!("cannot read {}: {}", path.display(), e))
            })?;
            let mut config: Config = toml::from_str(&content)?;
            migrate_config(&mut config);
            validate_config(&config)?;
            return Ok(config);
        }
    }

    let config = default_config();
    validate_config(&config)?;
    Ok(config)
}

pub fn migrate_config(config: &mut Config) {
    if config.config_version < 2 {
        tracing::info!(
            from = config.config_version,
            to = 2,
            "migrating config version"
        );
        config.config_version = 2;
    }
}

fn config_search_paths(explicit_path: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(p) = explicit_path {
        paths.push(p.to_path_buf());
    }
    // VIGIL_CONFIG env var is only allowed in test/debug builds.
    // In production, require the config file to be in a standard location
    // or passed explicitly via CLI.
    #[cfg(any(test, debug_assertions))]
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        paths.push(PathBuf::from(env_path));
    }
    #[cfg(not(any(test, debug_assertions)))]
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        // In production, validate ownership: file must be owned by root with mode <= 0644
        let p = PathBuf::from(&env_path);
        if p.exists() {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::metadata(&p) {
                let mode = meta.mode() & 0o777;
                if meta.uid() == 0 && mode <= 0o644 {
                    paths.push(p);
                } else {
                    tracing::error!(
                        path = %p.display(),
                        uid = meta.uid(),
                        mode = format!("{:04o}", mode),
                        "VIGIL_CONFIG target rejected: must be owned by root with mode <= 0644"
                    );
                }
            }
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".config/vigil/vigil.toml"));
    }
    paths.push(PathBuf::from("/etc/vigil/vigil.toml"));

    paths
}

pub fn validate_config(config: &Config) -> Result<()> {
    if config.watch.is_empty() {
        return Err(VigilError::Config(
            "at least one [watch.*] group must be defined".into(),
        ));
    }

    for pattern in &config.exclusions.patterns {
        globset::Glob::new(pattern).map_err(|e| {
            VigilError::Config(format!("invalid exclusion glob '{}': {}", pattern, e))
        })?;
    }

    if config.scanner.max_file_size == 0 {
        return Err(VigilError::Config("max_file_size must be > 0".into()));
    }

    if config.alerts.rate_limit == 0 {
        return Err(VigilError::Config("rate_limit must be > 0".into()));
    }

    if config.daemon.worker_threads == 0 || config.daemon.worker_threads > 16 {
        return Err(VigilError::Config(
            "worker_threads must be between 1 and 16".into(),
        ));
    }

    if croner::Cron::new(&config.scanner.schedule).parse().is_err() {
        return Err(VigilError::Config(format!(
            "invalid cron schedule '{}'",
            config.scanner.schedule
        )));
    }

    if config.security.hmac_signing && !config.security.hmac_key_path.exists() {
        return Err(VigilError::Config(format!(
            "HMAC signing enabled but key file not found: {}",
            config.security.hmac_key_path.display()
        )));
    }

    Ok(())
}

pub fn validate_config_deep(config: &Config) -> Result<Vec<String>> {
    let mut warnings = Vec::new();

    if let Some(parent) = config.alerts.log_file.parent() {
        if !parent.exists() {
            warnings.push(format!(
                "alert log directory {} does not exist yet",
                parent.display()
            ));
        }
    }

    if let Some(parent) = config.daemon.db_path.parent() {
        if !parent.exists() {
            warnings.push(format!(
                "database directory {} does not exist yet",
                parent.display()
            ));
        }
    }

    let mut any_exists = false;
    for (group_name, group) in &config.watch {
        let expanded = expand_user_paths(&group.paths);
        for p in &expanded {
            if p.exists() {
                any_exists = true;
            } else {
                warnings.push(format!(
                    "watch.{}: path {} does not exist yet",
                    group_name,
                    p.display()
                ));
            }
        }
    }

    if !any_exists && !config.watch.is_empty() {
        return Err(VigilError::Config(
            "no watch paths resolve to existing files or directories".into(),
        ));
    }

    // Check if vigl config file is covered by any watch group
    let config_path_str = "/etc/vigil/vigil.toml";
    let config_covered = config.watch.values().any(|group| {
        group
            .paths
            .iter()
            .any(|p| config_path_str.starts_with(p.trim_end_matches('/')) || p == config_path_str)
    });
    if !config_covered {
        warnings.push("vigil config file is not covered by any watch group".into());
    }

    Ok(warnings)
}

/// Expand `~` prefixed paths to the current HOME directory.
pub fn expand_user_paths(paths: &[String]) -> Vec<PathBuf> {
    let mut expanded = Vec::new();

    let home = std::env::var_os("HOME").map(PathBuf::from);

    for path_str in paths {
        if let Some(suffix) = path_str.strip_prefix("~/") {
            if let Some(ref home_dir) = home {
                expanded.push(home_dir.join(suffix));
            }
        } else {
            expanded.push(PathBuf::from(path_str));
        }
    }

    expanded
}

pub fn default_config() -> Config {
    let mut watch = HashMap::new();

    watch.insert(
        "system_critical".into(),
        WatchGroup {
            severity: Severity::Critical,
            paths: vec![
                "/etc/passwd".into(),
                "/etc/shadow".into(),
                "/etc/sudoers".into(),
                "/boot/".into(),
                "/usr/bin/".into(),
                "/usr/sbin/".into(),
            ],
        },
    );

    watch.insert(
        "persistence".into(),
        WatchGroup {
            severity: Severity::High,
            paths: vec![
                "/etc/crontab".into(),
                "/etc/cron.d/".into(),
                "/etc/systemd/system/".into(),
                "/etc/profile".into(),
            ],
        },
    );

    watch.insert(
        "user_space".into(),
        WatchGroup {
            severity: Severity::High,
            paths: vec!["~/.bashrc".into(), "~/.ssh/".into()],
        },
    );

    watch.insert(
        "network".into(),
        WatchGroup {
            severity: Severity::Medium,
            paths: vec!["/etc/hosts".into(), "/etc/resolv.conf".into()],
        },
    );

    watch.insert(
        "vigil_self".into(),
        WatchGroup {
            severity: Severity::Critical,
            paths: vec![
                "/etc/vigil/vigil.toml".into(),
                "/etc/vigil/hmac.key".into(),
                "/usr/bin/vigil".into(),
                "/usr/bin/vigild".into(),
            ],
        },
    );

    Config {
        config_version: 2,
        daemon: DaemonConfig::default(),
        scanner: ScannerConfig::default(),
        alerts: AlertsConfig::default(),
        exclusions: ExclusionsConfig::default(),
        package_manager: PackageManagerConfig::default(),
        hooks: HooksConfig::default(),
        security: SecurityConfig::default(),
        database: DatabaseConfig::default(),
        watch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml_str = r#"
            [watch.test]
            severity = "high"
            paths = ["/tmp/test"]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.watch.contains_key("test"));
        assert_eq!(config.watch["test"].severity, Severity::High);
    }

    #[test]
    fn default_config_validates() {
        let config = default_config();
        validate_config(&config).unwrap();
    }

    #[test]
    fn validate_rejects_no_watch_groups() {
        let mut config = default_config();
        config.watch.clear();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn expand_user_paths_absolute_passthrough() {
        let paths = vec!["/etc/passwd".into()];
        let expanded = expand_user_paths(&paths);
        assert_eq!(expanded[0], PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn invalid_enum_value_produces_serde_error() {
        let toml_str = r#"
            [daemon]
            log_level = "verbose"

            [watch.test]
            severity = "high"
            paths = ["/tmp/test"]
        "#;
        let result: std::result::Result<Config, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn default_scheduled_mode_is_full() {
        let config = default_config();
        assert_eq!(config.scanner.scheduled_mode, ScanMode::Full);
    }

    #[test]
    fn default_config_includes_vigil_self_watch_group() {
        let config = default_config();
        assert!(
            config.watch.contains_key("vigil_self"),
            "default config must include vigil_self watch group"
        );
        let group = &config.watch["vigil_self"];
        assert_eq!(group.severity, Severity::Critical);
        assert!(group.paths.iter().any(|p| p.contains("vigil.toml")));
    }

    #[test]
    fn validate_deep_warns_when_config_not_watched() {
        let mut config = default_config();
        config.watch.clear();
        // Keep at least one watch group with an existing path so deep validation doesn't fail
        config.watch.insert(
            "test".into(),
            WatchGroup {
                severity: Severity::Low,
                paths: vec!["/usr/bin/".into()],
            },
        );
        let warnings = validate_config_deep(&config).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("vigil config file is not covered")),
            "should warn when config file is not watched: {:?}",
            warnings,
        );
    }
}
