use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Result, VigilError};
use crate::types::{MonitorBackend, PackageBackend, ScanMode, Severity};

/// Top-level Vigil configuration, deserialized from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "DaemonConfig::default")]
    pub daemon: DaemonConfig,
    #[serde(default = "ScannerConfig::default")]
    pub scanner: ScannerConfig,
    #[serde(default = "AlertsConfig::default")]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub exclusions: ExclusionsConfig,
    #[serde(default = "PackageManagerConfig::default")]
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

// ── Daemon ─────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_monitor_backend")]
    pub monitor_backend: MonitorBackend,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: default_pid_file(),
            db_path: default_db_path(),
            log_level: default_log_level(),
            monitor_backend: default_monitor_backend(),
        }
    }
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

// ── Scanner ────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ScannerConfig {
    #[serde(default = "default_schedule")]
    pub schedule: String,
    #[serde(default = "default_scan_mode")]
    pub mode: ScanMode,
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            schedule: default_schedule(),
            mode: default_scan_mode(),
            hash_algorithm: default_hash_algorithm(),
            max_file_size: default_max_file_size(),
        }
    }
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
    2_147_483_648 // 2 GB
}

// ── Alerts ─────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
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
        }
    }
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

#[derive(Debug, Clone, Deserialize)]
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

// ── Exclusions ─────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
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

// ── Package Manager ────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
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

// ── Hooks ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct HooksConfig {
    #[serde(default)]
    pub signal_socket: String,
}

// ── Security ───────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
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

// ── Database ───────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_true")]
    pub wal_mode: bool,
    #[serde(default = "default_audit_rotation_size")]
    pub audit_rotation_size: u64,
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            wal_mode: true,
            audit_rotation_size: default_audit_rotation_size(),
            audit_retention_days: default_audit_retention_days(),
        }
    }
}

fn default_audit_rotation_size() -> u64 {
    104_857_600 // 100 MB
}
fn default_audit_retention_days() -> u32 {
    90
}

// ── Watch Groups ───────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct WatchGroup {
    pub severity: Severity,
    pub paths: Vec<String>,
}

// ── Helpers ────────────────────────────────────────────────

fn default_true() -> bool {
    true
}

// ── Config Loading ─────────────────────────────────────────

/// Config file search order (highest priority first):
/// 1. VIGIL_CONFIG env var
/// 2. ~/.config/vigil/vigil.toml
/// 3. /etc/vigil/vigil.toml
pub fn load_config(explicit_path: Option<&Path>) -> Result<Config> {
    let paths = config_search_paths(explicit_path);

    let mut base: Option<Config> = None;

    // Load from lowest to highest priority so higher overrides lower
    for path in paths.iter().rev() {
        if path.exists() {
            log::info!("Loading config from: {}", path.display());
            let content = std::fs::read_to_string(path).map_err(|e| {
                VigilError::Config(format!("cannot read {}: {}", path.display(), e))
            })?;
            let config: Config = toml::from_str(&content)?;
            base = Some(config);
        }
    }

    let config = base.unwrap_or_else(|| {
        log::warn!("No config file found, using defaults with built-in watch paths");
        default_config()
    });

    validate_config(&config)?;
    Ok(config)
}

fn config_search_paths(explicit_path: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Priority 3 (lowest): system config
    paths.push(PathBuf::from("/etc/vigil/vigil.toml"));

    // Priority 2: user config
    if let Some(home) = std::env::var_os("HOME") {
        let mut user_config = PathBuf::from(home);
        user_config.push(".config/vigil/vigil.toml");
        paths.push(user_config);
    }

    // Priority 1: env var
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        paths.push(PathBuf::from(env_path));
    }

    // Priority 0 (highest): explicit CLI path
    if let Some(p) = explicit_path {
        paths.push(p.to_path_buf());
    }

    paths
}

fn validate_config(config: &Config) -> Result<()> {
    // At least one watch group must be defined
    if config.watch.is_empty() {
        return Err(VigilError::Config(
            "at least one [watch.*] group must be defined".into(),
        ));
    }

    // Validate exclusion patterns are valid globs
    for pattern in &config.exclusions.patterns {
        glob::Pattern::new(pattern).map_err(|e| {
            VigilError::Config(format!("invalid exclusion glob '{}': {}", pattern, e))
        })?;
    }

    // max_file_size > 0
    if config.scanner.max_file_size == 0 {
        return Err(VigilError::Config("max_file_size must be > 0".into()));
    }

    // rate_limit > 0
    if config.alerts.rate_limit == 0 {
        return Err(VigilError::Config("rate_limit must be > 0".into()));
    }

    // Validate log_level is a recognized value
    match config.daemon.log_level.to_lowercase().as_str() {
        "error" | "warn" | "info" | "debug" | "trace" => {}
        other => {
            return Err(VigilError::Config(format!(
                "invalid log_level '{}', must be one of: error, warn, info, debug, trace",
                other
            )));
        }
    }

    // Validate hash_algorithm is supported
    if config.scanner.hash_algorithm.to_lowercase() != "blake3" {
        return Err(VigilError::Config(format!(
            "unsupported hash algorithm '{}', only 'blake3' is supported",
            config.scanner.hash_algorithm
        )));
    }

    // Validate cron schedule expression (basic format check)
    {
        let parts: Vec<&str> = config.scanner.schedule.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(VigilError::Config(format!(
                "invalid cron schedule '{}': expected 5 fields (minute hour day month weekday)",
                config.scanner.schedule
            )));
        }
    }

    // HMAC key must exist if signing is enabled
    if config.security.hmac_signing && !config.security.hmac_key_path.exists() {
        return Err(VigilError::Config(format!(
            "HMAC signing enabled but key file not found: {}",
            config.security.hmac_key_path.display()
        )));
    }

    // Warn about watch paths that don't exist
    for (group_name, group) in &config.watch {
        for path_str in &group.paths {
            if path_str.starts_with('~') || path_str.contains('*') {
                continue; // expanded at runtime
            }
            let p = Path::new(path_str);
            if !p.exists() {
                log::warn!("watch.{}: path does not exist: {}", group_name, path_str);
            }
        }
    }

    // Warn if log file parent directory is not writable
    if let Some(parent) = config.alerts.log_file.parent() {
        if parent.exists() {
            // Check if writable by attempting metadata
            if std::fs::metadata(parent).is_err() {
                log::warn!(
                    "Log file directory may not be writable: {}",
                    parent.display()
                );
            }
        }
    }

    Ok(())
}

/// Returns a config with built-in defaults and standard watch paths.
fn default_config() -> Config {
    let mut watch = HashMap::new();

    watch.insert(
        "system_critical".into(),
        WatchGroup {
            severity: Severity::Critical,
            paths: vec![
                "/etc/passwd".into(),
                "/etc/shadow".into(),
                "/etc/group".into(),
                "/etc/gshadow".into(),
                "/etc/sudoers".into(),
                "/etc/sudoers.d/".into(),
                "/etc/pam.d/".into(),
                "/etc/ssh/sshd_config".into(),
                "/etc/ld.so.preload".into(),
                "/etc/ld.so.conf".into(),
                "/etc/ld.so.conf.d/".into(),
                "/boot/".into(),
                "/usr/bin/".into(),
                "/usr/sbin/".into(),
                "/usr/lib/systemd/system/".into(),
                "/lib/modules/".into(),
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
                "/etc/cron.daily/".into(),
                "/etc/cron.hourly/".into(),
                "/var/spool/cron/".into(),
                "/etc/systemd/system/".into(),
                "/etc/xdg/autostart/".into(),
                "/etc/init.d/".into(),
                "/etc/rc.local".into(),
                "/etc/profile".into(),
                "/etc/profile.d/".into(),
                "/etc/bash.bashrc".into(),
                "/etc/environment".into(),
            ],
        },
    );

    watch.insert(
        "user_space".into(),
        WatchGroup {
            severity: Severity::High,
            paths: vec![
                "~/.bashrc".into(),
                "~/.bash_profile".into(),
                "~/.profile".into(),
                "~/.zshrc".into(),
                "~/.ssh/".into(),
                "~/.gnupg/".into(),
                "~/.config/autostart/".into(),
                "~/.local/share/applications/".into(),
            ],
        },
    );

    watch.insert(
        "network".into(),
        WatchGroup {
            severity: Severity::Medium,
            paths: vec![
                "/etc/hosts".into(),
                "/etc/resolv.conf".into(),
                "/etc/nsswitch.conf".into(),
                "/etc/NetworkManager/".into(),
                "/etc/iptables/".into(),
                "/etc/nftables.conf".into(),
            ],
        },
    );

    Config {
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

/// Expand `~` prefixed paths to actual user home directories.
/// Reads /etc/passwd and expands for UIDs 1000..65533.
pub fn expand_user_paths(paths: &[String]) -> Vec<PathBuf> {
    let mut expanded = Vec::new();

    let home_dirs = enumerate_home_dirs();

    for path_str in paths {
        if let Some(suffix) = path_str.strip_prefix("~/") {
            if home_dirs.is_empty() {
                // Fallback: use $HOME
                if let Ok(home) = std::env::var("HOME") {
                    expanded.push(PathBuf::from(home).join(suffix));
                }
            } else {
                for home in &home_dirs {
                    let full = home.join(suffix);
                    if full.exists() || full.parent().is_some_and(|p| p.exists()) {
                        expanded.push(full);
                    } else {
                        log::warn!("Expanded path does not exist: {}", full.display());
                    }
                }
            }
        } else {
            expanded.push(PathBuf::from(path_str));
        }
    }

    expanded
}

/// Read /etc/passwd to find home directories for real users (UID 1000..65533).
fn enumerate_home_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    let content = match std::fs::read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(e) => {
            log::warn!(
                "Cannot read /etc/passwd for home directory expansion: {}",
                e
            );
            return dirs;
        }
    };

    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 {
            if let Ok(uid) = fields[2].parse::<u32>() {
                if (1000..65534).contains(&uid) {
                    let home = PathBuf::from(fields[5]);
                    if home.is_dir() {
                        dirs.push(home);
                    }
                }
            }
        }
    }

    dirs
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
    fn parse_full_config() {
        let toml_str = r#"
            [daemon]
            log_level = "debug"
            monitor_backend = "inotify"

            [scanner]
            mode = "full"
            max_file_size = 1000000

            [alerts]
            rate_limit = 5
            cooldown_seconds = 60
            desktop_notifications = false

            [alerts.severity_filter]
            dbus_min_severity = "high"
            log_min_severity = "low"

            [exclusions]
            patterns = ["*.swp", "*.tmp"]
            system_exclusions = ["/proc/*"]

            [watch.critical]
            severity = "critical"
            paths = ["/etc/passwd", "/etc/shadow"]

            [watch.low]
            severity = "low"
            paths = ["/tmp/"]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.daemon.log_level, "debug");
        assert_eq!(config.daemon.monitor_backend, MonitorBackend::Inotify);
        assert_eq!(config.scanner.mode, ScanMode::Full);
        assert_eq!(config.alerts.rate_limit, 5);
        assert_eq!(config.alerts.cooldown_seconds, 60);
        assert!(!config.alerts.desktop_notifications);
        assert_eq!(config.exclusions.patterns.len(), 2);
        assert_eq!(config.watch.len(), 2);
        assert_eq!(config.watch["critical"].severity, Severity::Critical);
    }

    #[test]
    fn defaults_populated_when_missing() {
        let toml_str = r#"
            [watch.test]
            severity = "medium"
            paths = ["/tmp/test"]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.daemon.monitor_backend, MonitorBackend::Fanotify);
        assert_eq!(config.scanner.max_file_size, 2_147_483_648);
        assert_eq!(config.alerts.rate_limit, 10);
        assert_eq!(config.alerts.cooldown_seconds, 300);
        assert!(config.alerts.desktop_notifications);
        assert!(config.database.wal_mode);
    }

    #[test]
    fn validate_rejects_no_watch_groups() {
        let config = Config {
            daemon: DaemonConfig::default(),
            scanner: ScannerConfig::default(),
            alerts: AlertsConfig::default(),
            exclusions: ExclusionsConfig::default(),
            package_manager: PackageManagerConfig::default(),
            hooks: HooksConfig::default(),
            security: SecurityConfig::default(),
            database: DatabaseConfig::default(),
            watch: HashMap::new(),
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_rejects_zero_rate_limit() {
        let mut config = default_config();
        config.alerts.rate_limit = 0;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_rejects_zero_max_file_size() {
        let mut config = default_config();
        config.scanner.max_file_size = 0;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_rejects_invalid_glob() {
        let mut config = default_config();
        config.exclusions.patterns = vec!["[invalid".into()];
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_accepts_default_config() {
        let config = default_config();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn default_config_has_four_watch_groups() {
        let config = default_config();
        assert_eq!(config.watch.len(), 4);
        assert!(config.watch.contains_key("system_critical"));
        assert!(config.watch.contains_key("persistence"));
        assert!(config.watch.contains_key("user_space"));
        assert!(config.watch.contains_key("network"));
    }

    #[test]
    fn default_config_severity_levels() {
        let config = default_config();
        assert_eq!(config.watch["system_critical"].severity, Severity::Critical);
        assert_eq!(config.watch["persistence"].severity, Severity::High);
        assert_eq!(config.watch["user_space"].severity, Severity::High);
        assert_eq!(config.watch["network"].severity, Severity::Medium);
    }

    #[test]
    fn expand_user_paths_absolute_passthrough() {
        let paths = vec!["/etc/passwd".into(), "/usr/bin/".into()];
        let expanded = expand_user_paths(&paths);
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0], PathBuf::from("/etc/passwd"));
        assert_eq!(expanded[1], PathBuf::from("/usr/bin/"));
    }

    #[test]
    fn default_exclusion_patterns_are_valid_globs() {
        let patterns = default_exclusion_patterns();
        for p in &patterns {
            assert!(glob::Pattern::new(p).is_ok(), "Invalid glob: {}", p);
        }
    }

    #[test]
    fn severity_filter_defaults() {
        let filter = SeverityFilterConfig::default();
        assert_eq!(filter.dbus_min_severity, Severity::Medium);
        assert_eq!(filter.log_min_severity, Severity::Low);
    }

    #[test]
    fn load_config_from_explicit_path() {
        let dir = std::env::temp_dir().join(format!("vigil-cfg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("test.toml");
        std::fs::write(
            &cfg_path,
            r#"
            [watch.test]
            severity = "low"
            paths = ["/tmp/"]
        "#,
        )
        .unwrap();

        let config = load_config(Some(&cfg_path)).unwrap();
        assert!(config.watch.contains_key("test"));
        assert_eq!(config.watch["test"].severity, Severity::Low);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_invalid_log_level() {
        let mut config = default_config();
        config.daemon.log_level = "verbose".to_string();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_accepts_valid_log_levels() {
        for level in &["error", "warn", "info", "debug", "trace", "INFO", "Debug"] {
            let mut config = default_config();
            config.daemon.log_level = level.to_string();
            assert!(
                validate_config(&config).is_ok(),
                "Should accept log_level '{}'",
                level
            );
        }
    }

    #[test]
    fn validate_rejects_unsupported_hash_algorithm() {
        let mut config = default_config();
        config.scanner.hash_algorithm = "sha256".to_string();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_accepts_blake3_hash_algorithm() {
        let mut config = default_config();
        config.scanner.hash_algorithm = "blake3".to_string();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn validate_rejects_invalid_cron_schedule() {
        let mut config = default_config();
        config.scanner.schedule = "invalid cron".to_string();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_accepts_valid_cron_schedule() {
        let mut config = default_config();
        config.scanner.schedule = "0 3 * * *".to_string();
        assert!(validate_config(&config).is_ok());
    }
}
