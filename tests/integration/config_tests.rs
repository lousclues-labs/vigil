// Integration tests: configuration loading and validation.

use vigil::config::*;
use vigil::types::*;

use crate::common::fixtures::*;

#[test]
fn load_config_from_toml_file() {
    let tmp = TempDir::new("cfg-load");
    let cfg_path = tmp.create_file(
        "vigil.toml",
        br#"
[daemon]
log_level = "warn"

[scanner]
mode = "full"

[alerts]
rate_limit = 20
cooldown_seconds = 600

[watch.system]
severity = "critical"
paths = ["/etc/passwd", "/etc/shadow"]

[watch.user]
severity = "high"
paths = ["~/.bashrc"]
"#,
    );

    let config = load_config(Some(&cfg_path)).unwrap();
    assert_eq!(config.daemon.log_level, "warn");
    assert_eq!(config.scanner.mode, ScanMode::Full);
    assert_eq!(config.alerts.rate_limit, 20);
    assert_eq!(config.alerts.cooldown_seconds, 600);
    assert_eq!(config.watch.len(), 2);
}

#[test]
fn invalid_toml_rejected() {
    let tmp = TempDir::new("cfg-invalid");
    let cfg_path = tmp.create_file("bad.toml", b"this is not valid toml [[[");

    let result = load_config(Some(&cfg_path));
    assert!(result.is_err());
}

#[test]
fn config_without_watch_groups_rejected() {
    let tmp = TempDir::new("cfg-no-watch");
    let cfg_path = tmp.create_file(
        "empty.toml",
        br#"
[daemon]
log_level = "info"
"#,
    );

    let result = load_config(Some(&cfg_path));
    assert!(result.is_err());
}

#[test]
fn config_with_invalid_exclusion_glob_rejected() {
    let tmp = TempDir::new("cfg-bad-glob");
    let cfg_path = tmp.create_file(
        "badglob.toml",
        br#"
[exclusions]
patterns = ["[unclosed"]

[watch.test]
severity = "low"
paths = ["/tmp/"]
"#,
    );

    let result = load_config(Some(&cfg_path));
    assert!(result.is_err());
}

#[test]
fn config_with_zero_rate_limit_rejected() {
    let tmp = TempDir::new("cfg-zero-rate");
    let cfg_path = tmp.create_file(
        "zerorate.toml",
        br#"
[alerts]
rate_limit = 0

[watch.test]
severity = "low"
paths = ["/tmp/"]
"#,
    );

    let result = load_config(Some(&cfg_path));
    assert!(result.is_err());
}

#[test]
fn expand_absolute_paths_unchanged() {
    let paths = vec!["/etc/passwd".into(), "/usr/bin/".into()];
    let expanded = expand_user_paths(&paths);
    assert!(expanded.contains(&std::path::PathBuf::from("/etc/passwd")));
    assert!(expanded.contains(&std::path::PathBuf::from("/usr/bin/")));
}
