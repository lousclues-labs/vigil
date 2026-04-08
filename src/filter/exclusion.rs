use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::config::Config;

/// Fast exclusion matcher:
/// - system prefixes: sorted vector + binary search
/// - glob patterns: compiled GlobSet automaton
#[derive(Debug, Clone)]
pub struct ExclusionFilter {
    /// System exclusion prefixes sorted lexicographically.
    system_prefixes: Vec<String>,
    /// Compiled glob patterns.
    glob_set: Option<GlobSet>,
    /// Self-exclusion paths (vigil DB, logs, runtime files).
    self_paths: Vec<String>,
}

impl ExclusionFilter {
    pub fn new(config: &Config) -> Self {
        let mut builder = GlobSetBuilder::new();
        for pat in &config.exclusions.patterns {
            match Glob::new(pat) {
                Ok(glob) => {
                    builder.add(glob);
                }
                Err(e) => {
                    tracing::warn!(pattern = %pat, error = %e, "invalid exclusion glob ignored");
                }
            }
        }

        let glob_set = match builder.build() {
            Ok(set) => Some(set),
            Err(e) => {
                tracing::warn!(error = %e, "failed to build globset; glob exclusions disabled");
                None
            }
        };

        let mut system_prefixes: Vec<String> = config
            .exclusions
            .system_exclusions
            .iter()
            .map(|s| s.trim_end_matches('*').to_string())
            .collect();
        system_prefixes.sort();
        system_prefixes.dedup();

        let self_paths = vec![
            config.daemon.db_path.to_string_lossy().to_string(),
            crate::db::audit_db_path(config)
                .to_string_lossy()
                .to_string(),
            config.alerts.log_file.to_string_lossy().to_string(),
            config.daemon.runtime_dir.to_string_lossy().to_string(),
        ];

        Self {
            system_prefixes,
            glob_set,
            self_paths,
        }
    }

    /// O(log n) prefix check + O(1)-ish automaton glob check.
    pub fn is_excluded(&self, path: &str) -> bool {
        if self.is_system_prefix_excluded(path) {
            return true;
        }

        if self
            .self_paths
            .iter()
            .any(|p| !p.is_empty() && path.starts_with(p))
        {
            return true;
        }

        self.glob_set
            .as_ref()
            .map(|set| set.is_match(path))
            .unwrap_or(false)
    }

    fn is_system_prefix_excluded(&self, path: &str) -> bool {
        if self.system_prefixes.is_empty() {
            return false;
        }

        // Find insertion point, then verify closest predecessor/successor.
        let idx = match self
            .system_prefixes
            .binary_search_by(|probe| probe.as_str().cmp(path))
        {
            Ok(i) => i,
            Err(i) => i,
        };

        if idx > 0 {
            let prev = &self.system_prefixes[idx - 1];
            if path.starts_with(prev) {
                return true;
            }
        }

        if idx < self.system_prefixes.len() {
            let cur = &self.system_prefixes[idx];
            if path.starts_with(cur) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_exclusions() -> crate::config::Config {
        let mut cfg = crate::config::default_config();
        cfg.exclusions.system_exclusions = vec!["/proc/*".into(), "/sys/*".into()];
        cfg.exclusions.patterns = vec!["*.swp".into(), "**/.git/**".into()];
        cfg
    }

    #[test]
    fn system_prefix_match() {
        let cfg = config_with_exclusions();
        let f = ExclusionFilter::new(&cfg);
        assert!(f.is_excluded("/proc/123/status"));
        assert!(f.is_excluded("/sys/kernel"));
        assert!(!f.is_excluded("/etc/passwd"));
    }

    #[test]
    fn glob_match() {
        let cfg = config_with_exclusions();
        let f = ExclusionFilter::new(&cfg);
        assert!(f.is_excluded("/tmp/file.swp"));
        assert!(f.is_excluded("/home/u/repo/.git/config"));
    }

    #[test]
    fn run_systemd_transient_not_excluded_by_default() {
        let cfg = crate::config::default_config();
        let f = ExclusionFilter::new(&cfg);
        assert!(
            !f.is_excluded("/run/systemd/transient/evil.service"),
            "/run/systemd/transient/ should NOT be excluded by default"
        );
    }

    #[test]
    fn run_vigil_excluded_via_self_paths() {
        let cfg = crate::config::default_config();
        let f = ExclusionFilter::new(&cfg);
        assert!(
            f.is_excluded("/run/vigil/state.json"),
            "/run/vigil/ should be excluded via self_paths"
        );
    }

    #[test]
    fn run_user_excluded_by_default() {
        let cfg = crate::config::default_config();
        let f = ExclusionFilter::new(&cfg);
        assert!(
            f.is_excluded("/run/user/1000/bus"),
            "/run/user/* should be excluded"
        );
    }

    #[test]
    fn tmp_excluded_by_default() {
        let cfg = crate::config::default_config();
        let f = ExclusionFilter::new(&cfg);
        assert!(f.is_excluded("/tmp/foo"), "/tmp/* should be excluded");
    }

    #[test]
    fn proc_excluded_by_default() {
        let cfg = crate::config::default_config();
        let f = ExclusionFilter::new(&cfg);
        assert!(
            f.is_excluded("/proc/1/status"),
            "/proc/* should be excluded"
        );
    }

    #[test]
    fn vigil_config_not_excluded() {
        let cfg = crate::config::default_config();
        let f = ExclusionFilter::new(&cfg);
        assert!(
            !f.is_excluded("/etc/vigil/vigil.toml"),
            "vigil config should NOT be excluded"
        );
    }
}
