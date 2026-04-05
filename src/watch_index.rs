use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::types::Severity;

/// An index for efficient watch group lookups by path prefix.
///
/// Paths are sorted longest-first so that a binary search followed by a
/// linear scan of equal-length prefixes always returns the most-specific
/// match. For example, given watch paths `/usr/bin/` and `/usr/`, a lookup
/// for `/usr/bin/ls` correctly returns `/usr/bin/`.
#[derive(Debug, Clone)]
pub struct WatchGroupIndex {
    /// Entries sorted by path length (longest first), then lexicographically.
    entries: Vec<WatchGroupEntry>,
}

#[derive(Debug, Clone)]
struct WatchGroupEntry {
    path: PathBuf,
    group_name: String,
    severity: Severity,
}

impl WatchGroupIndex {
    /// Build the index from a config's watch groups.
    ///
    /// Expands user paths (`~`) and sorts entries longest-prefix-first
    /// so that lookups always return the most-specific match.
    pub fn from_config(config: &Config) -> Self {
        let mut entries: Vec<WatchGroupEntry> = config
            .watch
            .iter()
            .flat_map(|(group_name, group)| {
                let expanded = crate::config::expand_user_paths(&group.paths);
                expanded.into_iter().map(move |p| WatchGroupEntry {
                    path: p,
                    group_name: group_name.clone(),
                    severity: group.severity,
                })
            })
            .collect();

        // Sort by path component count (descending) to ensure most-specific
        // prefixes come first, then lexicographically for determinism.
        entries.sort_by(|a, b| {
            let a_len = a.path.as_os_str().len();
            let b_len = b.path.as_os_str().len();
            b_len.cmp(&a_len).then_with(|| a.path.cmp(&b.path))
        });

        Self { entries }
    }

    /// Build the index from pre-expanded entries.
    pub fn from_expanded(expanded: Vec<(PathBuf, String, Severity)>) -> Self {
        let mut entries: Vec<WatchGroupEntry> = expanded
            .into_iter()
            .map(|(path, group_name, severity)| WatchGroupEntry {
                path,
                group_name,
                severity,
            })
            .collect();

        entries.sort_by(|a, b| {
            let a_len = a.path.as_os_str().len();
            let b_len = b.path.as_os_str().len();
            b_len.cmp(&a_len).then_with(|| a.path.cmp(&b.path))
        });

        Self { entries }
    }

    /// Look up which watch group a path belongs to.
    ///
    /// Returns the most-specific (longest prefix) match, or `None` if the
    /// path is not under any watch group.
    pub fn lookup(&self, path: &Path) -> Option<(&str, Severity)> {
        // Since entries are sorted longest-first, the first match we find
        // is the most-specific prefix.
        for entry in &self.entries {
            if path.starts_with(&entry.path) || path == entry.path {
                return Some((&entry.group_name, entry.severity));
            }
        }
        None
    }

    /// Return the number of entries in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the entries as a slice of (path, group_name, severity) for
    /// backward compatibility with code that iterates over expanded groups.
    pub fn iter(&self) -> impl Iterator<Item = (&Path, &str, Severity)> {
        self.entries
            .iter()
            .map(|e| (e.path.as_path(), e.group_name.as_str(), e.severity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_index(paths: &[(&str, &str, Severity)]) -> WatchGroupIndex {
        let expanded: Vec<(PathBuf, String, Severity)> = paths
            .iter()
            .map(|(p, g, s)| (PathBuf::from(p), g.to_string(), *s))
            .collect();
        WatchGroupIndex::from_expanded(expanded)
    }

    #[test]
    fn most_specific_prefix_wins() {
        let index = make_index(&[
            ("/usr/", "system", Severity::High),
            ("/usr/bin/", "binaries", Severity::Critical),
        ]);

        // /usr/bin/ls should match /usr/bin/ (more specific), not /usr/
        let result = index.lookup(Path::new("/usr/bin/ls"));
        assert_eq!(result, Some(("binaries", Severity::Critical)));

        // /usr/lib/foo should match /usr/
        let result = index.lookup(Path::new("/usr/lib/foo"));
        assert_eq!(result, Some(("system", Severity::High)));
    }

    #[test]
    fn no_match_returns_none() {
        let index = make_index(&[("/etc/", "config", Severity::Medium)]);
        let result = index.lookup(Path::new("/var/log/syslog"));
        assert_eq!(result, None);
    }

    #[test]
    fn exact_path_match() {
        let index = make_index(&[("/etc/passwd", "critical", Severity::Critical)]);
        let result = index.lookup(Path::new("/etc/passwd"));
        assert_eq!(result, Some(("critical", Severity::Critical)));
    }

    #[test]
    fn overlapping_prefixes_three_levels() {
        let index = make_index(&[
            ("/", "root", Severity::Low),
            ("/etc/", "config", Severity::Medium),
            ("/etc/ssh/", "ssh", Severity::Critical),
        ]);

        assert_eq!(
            index.lookup(Path::new("/etc/ssh/sshd_config")),
            Some(("ssh", Severity::Critical))
        );
        assert_eq!(
            index.lookup(Path::new("/etc/passwd")),
            Some(("config", Severity::Medium))
        );
        assert_eq!(
            index.lookup(Path::new("/var/log/test")),
            Some(("root", Severity::Low))
        );
    }

    #[test]
    fn empty_index_returns_none() {
        let index = WatchGroupIndex::from_expanded(vec![]);
        assert!(index.is_empty());
        assert_eq!(index.lookup(Path::new("/etc/passwd")), None);
    }
}
