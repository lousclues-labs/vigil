pub mod diff;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Result, VigilError};
use crate::types::{MonitorBackend, PackageBackend, ScanMode, Severity};

pub use diff::diff_config;

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
    pub log_level: String,
    #[serde(default = "default_monitor_backend")]
    pub monitor_backend: MonitorBackend,
    #[serde(default = "default_worker_threads")]
    pub worker_threads: u32,
    #[serde(default = "default_log_format")]
    pub log_format: String,
    #[serde(default = "default_runtime_dir")]
    pub runtime_dir: PathBuf,
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
        }
    }
}

fn default_worker_threads() -> u32 {
    2
}

fn default_log_format() -> String {
    "text".to_string()
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

fn default_log_level() -> String {
    "info".to_string()
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
    pub hash_algorithm: String,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
    #[serde(default = "default_mmap_threshold")]
    pub mmap_threshold: u64,
    #[serde(default = "default_scan_mode")]
    pub scheduled_mode: ScanMode,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            schedule: default_schedule(),
            mode: default_scan_mode(),
            hash_algorithm: default_hash_algorithm(),
            max_file_size: default_max_file_size(),
            mmap_threshold: default_mmap_threshold(),
            scheduled_mode: default_scan_mode(),
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

fn default_hash_algorithm() -> String {
    "blake3".to_string()
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

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ExclusionsConfig {
    #[serde(default = "default_exclusion_patterns")]
    pub patterns: Vec<String>,
    #[serde(default = "default_system_exclusions")]
    pub system_exclusions: Vec<String>,
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

fn default_system_exclusions() -> Vec<String> {
    vec![
        "/proc/*".into(),
        "/sys/*".into(),
        "/dev/*".into(),
        "/run/*".into(),
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
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            hmac_signing: false,
            hmac_key_path: default_hmac_key_path(),
            verify_config_integrity: true,
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
    pub sync_mode: String,
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

fn default_sync_mode() -> String {
    "normal".to_string()
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
    pub protocol: String,
    #[serde(default = "default_syslog_facility")]
    pub facility: String,
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

fn default_syslog_protocol() -> String {
    "udp".to_string()
}

fn default_syslog_facility() -> String {
    "authpriv".to_string()
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
            let content = std::fs::read_to_string(path)
                .map_err(|e| VigilError::Config(format!("cannot read {}: {}", path.display(), e)))?;
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
        tracing::info!(from = config.config_version, to = 2, "migrating config version");
        config.config_version = 2;
    }
}

fn config_search_paths(explicit_path: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(p) = explicit_path {
        paths.push(p.to_path_buf());
    }
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        paths.push(PathBuf::from(env_path));
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

    match config.database.sync_mode.to_lowercase().as_str() {
        "off" | "normal" | "full" | "extra" => {}
        other => {
            return Err(VigilError::Config(format!(
                "invalid sync_mode '{}', must be one of: off, normal, full, extra",
                other
            )));
        }
    }

    match config.daemon.log_level.to_lowercase().as_str() {
        "error" | "warn" | "info" | "debug" | "trace" => {}
        other => {
            return Err(VigilError::Config(format!(
                "invalid log_level '{}', must be one of: error, warn, info, debug, trace",
                other
            )));
        }
    }

    if config.scanner.hash_algorithm.to_lowercase() != "blake3" {
        return Err(VigilError::Config(format!(
            "unsupported hash algorithm '{}', only 'blake3' is supported",
            config.scanner.hash_algorithm
        )));
    }

    match config.daemon.log_format.to_lowercase().as_str() {
        "text" | "json" => {}
        other => {
            return Err(VigilError::Config(format!(
                "invalid log_format '{}', must be one of: text, json",
                other
            )));
        }
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
}
