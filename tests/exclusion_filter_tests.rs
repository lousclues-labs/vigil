use vigil::filter::exclusion::ExclusionFilter;

fn naive_excluded(
    system_exclusions: &[String],
    matchers: &[globset::GlobMatcher],
    path: &str,
) -> bool {
    for prefix in system_exclusions {
        let p = prefix.trim_end_matches('*');
        if path.starts_with(p) {
            return true;
        }
    }

    for matcher in matchers {
        if matcher.is_match(path) {
            return true;
        }
    }

    false
}

#[test]
fn exclusion_filter_matches_naive_logic() {
    let mut cfg = vigil::config::default_config();
    cfg.exclusions.system_exclusions =
        vec!["/proc/*".into(), "/sys/*".into(), "/tmp/cache/*".into()];

    cfg.exclusions.patterns = (0..40).map(|i| format!("**/*.tmp{}", i)).collect();
    cfg.exclusions.patterns.push("**/*.swp".into());

    let filter = ExclusionFilter::new(&cfg);
    let matchers: Vec<globset::GlobMatcher> = cfg
        .exclusions
        .patterns
        .iter()
        .filter_map(|p| globset::Glob::new(p).ok())
        .map(|g| g.compile_matcher())
        .collect();

    let mut paths = Vec::new();
    for i in 0..1_000 {
        paths.push(format!("/tmp/file-{}.txt", i));
    }
    paths.push("/proc/1/status".into());
    paths.push("/sys/kernel/debug".into());
    paths.push("/home/user/test.swp".into());

    for path in &paths {
        assert_eq!(
            filter.is_excluded(path),
            naive_excluded(&cfg.exclusions.system_exclusions, &matchers, path),
            "mismatch for path {}",
            path
        );
    }
}

/// Overlapping exclusion rules must not disable each other.
///
/// Prefix matching previously checked only the two entries adjacent to the
/// binary-search insertion point. A non-matching entry can sort *between* the
/// matching prefix and the path, taking that slot and hiding the real match:
/// with `["/var/*", "/var/cache/*"]`, `/var/log/syslog` has insertion point 2,
/// so `idx - 1` is `/var/cache/` and `idx == len` — `/var/` was never tested.
///
/// Adding a narrower rule silently disabled a broader one, so paths the
/// operator could see were excluded got scanned and alerted on. The shipped
/// defaults contain no overlapping pair, which is why this stayed dormant.
#[test]
fn an_overlapping_narrower_rule_does_not_disable_a_broader_one() {
    let mut cfg = vigil::config::default_config();
    cfg.exclusions.system_exclusions = vec!["/var/*".to_string(), "/var/cache/*".to_string()];
    let filter = vigil::filter::exclusion::ExclusionFilter::new(&cfg);

    assert!(
        filter.is_excluded("/var/log/syslog"),
        "/var/* must still exclude /var/log/syslog when /var/cache/* is also present"
    );
    assert!(filter.is_excluded("/var/cache/x"));
    assert!(filter.is_excluded("/var/aaa"));
}

/// Several overlapping rules at different depths all keep working.
#[test]
fn deeply_overlapping_rules_all_match() {
    let mut cfg = vigil::config::default_config();
    cfg.exclusions.system_exclusions = vec![
        "/a/*".to_string(),
        "/a/b/*".to_string(),
        "/a/b/c/*".to_string(),
    ];
    let filter = vigil::filter::exclusion::ExclusionFilter::new(&cfg);

    for path in ["/a/x", "/a/b/x", "/a/b/c/x", "/a/zzz/deep/file"] {
        assert!(
            filter.is_excluded(path),
            "{path} should be excluded by an overlapping rule set"
        );
    }
    assert!(!filter.is_excluded("/b/x"));
}

/// A non-matching path must still not be excluded, so the backward walk
/// cannot be over-matching.
#[test]
fn unrelated_paths_are_not_excluded_by_the_backward_walk() {
    let mut cfg = vigil::config::default_config();
    cfg.exclusions.system_exclusions = vec!["/var/*".to_string(), "/var/cache/*".to_string()];
    let filter = vigil::filter::exclusion::ExclusionFilter::new(&cfg);

    assert!(!filter.is_excluded("/etc/passwd"));
    assert!(!filter.is_excluded("/usr/bin/gs"));
    assert!(!filter.is_excluded("/vary/x"));
}
