use vigil::filter::exclusion::ExclusionFilter;

#[test]
fn test_filter_excludes_self_paths() {
    let mut cfg = vigil::config::default_config();
    // Set up db and log paths so the filter knows about them
    cfg.daemon.db_path = "/var/lib/vigil/baseline.db".into();
    cfg.alerts.log_file = "/var/log/vigil/alerts.json".into();

    let filter = ExclusionFilter::new(&cfg);

    // The database path and alert log path should be excluded
    assert!(
        filter.is_excluded("/var/lib/vigil/baseline.db"),
        "baseline db path should be excluded"
    );
    assert!(
        filter.is_excluded("/var/log/vigil/alerts.json"),
        "alert log path should be excluded"
    );

    // Audit db path (sibling of baseline.db) should also be excluded
    assert!(
        filter.is_excluded("/var/lib/vigil/audit.db"),
        "audit db path should be excluded"
    );

    // An unrelated path should NOT be excluded
    assert!(
        !filter.is_excluded("/etc/passwd"),
        "/etc/passwd should not be excluded by self-paths"
    );
}
