use vigil::config::default_config;
use vigil::filter::exclusion::ExclusionFilter;

/// Verify that ExclusionFilter does NOT exclude the vigil config file.
#[test]
fn exclusion_filter_allows_config_file() {
    let cfg = default_config();
    let filter = ExclusionFilter::new(&cfg);
    assert!(
        !filter.is_excluded("/etc/vigil/vigil.toml"),
        "vigil config file should not be excluded from monitoring"
    );
}

/// Verify that ExclusionFilter does NOT exclude the HMAC key file.
#[test]
fn exclusion_filter_allows_hmac_key() {
    let cfg = default_config();
    let filter = ExclusionFilter::new(&cfg);
    assert!(
        !filter.is_excluded("/etc/vigil/hmac.key"),
        "HMAC key file should not be excluded from monitoring"
    );
}

/// Verify that default_config() includes the vigil_self watch group.
#[test]
fn default_config_has_vigil_self_watch_group() {
    let cfg = default_config();
    assert!(cfg.watch.contains_key("vigil_self"));
    let group = &cfg.watch["vigil_self"];
    assert_eq!(group.severity, vigil::types::Severity::Critical);
    assert!(
        group.paths.iter().any(|p| p.contains("vigil.toml")),
        "vigil_self should watch config file"
    );
    assert!(
        group.paths.iter().any(|p| p.contains("hmac.key")),
        "vigil_self should watch HMAC key"
    );
}

/// Verify that vigil's mutable state files ARE excluded (DB, logs, runtime).
#[test]
fn exclusion_filter_excludes_mutable_state() {
    let cfg = default_config();
    let filter = ExclusionFilter::new(&cfg);

    // Database files should be excluded
    assert!(
        filter.is_excluded("/var/lib/vigil/baseline.db"),
        "baseline.db should be excluded"
    );
    assert!(
        filter.is_excluded("/var/lib/vigil/audit.db"),
        "audit.db should be excluded"
    );
    // Runtime dir should be excluded
    assert!(
        filter.is_excluded("/run/vigil/vigild.pid"),
        "runtime dir should be excluded"
    );
}
