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
