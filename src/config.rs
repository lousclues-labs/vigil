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
            let content = std::fs::read_to_string(path)
                .map_err(|e| VigilError::Config(format!("cannot read {}: {}", path.display(), e)))?;
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
                log::warn!(
                    "watch.{}: path does not exist: {}",
                    group_name,
                    path_str
                );
            }
        }
    }

    // Warn if log file parent directory is not writable
    if let Some(parent) = config.alerts.log_file.parent() {
        if parent.exists() {
            // Check if writable by attempting metadata
            if let Err(_) = std::fs::metadata(parent) {
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
                    if full.exists() || full.parent().map_or(false, |p| p.exists()) {
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
            log::warn!("Cannot read /etc/passwd for home directory expansion: {}", e);
            return dirs;
        }
    };

    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 {
            if let Ok(uid) = fields[2].parse::<u32>() {
                if uid >= 1000 && uid < 65534 {
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
