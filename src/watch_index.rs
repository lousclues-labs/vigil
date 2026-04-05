use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::types::Severity;

/// An index for efficient watch group lookups by path prefix.
///
/// Uses a BTreeMap for O(log n) lookups via range queries. The
/// `.range(..=path).rev()` pattern walks backwards from the query path,
/// and the first entry where `path.starts_with(key)` is the most-specific
/// match.
#[derive(Debug, Clone)]
pub struct WatchGroupIndex {
    tree: BTreeMap<PathBuf, (String, Severity)>,
}

impl WatchGroupIndex {
    /// Build the index from a config's watch groups.
    pub fn from_config(config: &Config) -> Self {
        let mut tree = BTreeMap::new();
        for (group_name, group) in &config.watch {
            let expanded = crate::config::expand_user_paths(&group.paths);
            for p in expanded {
                tree.insert(p, (group_name.clone(), group.severity));
            }
        }
        Self { tree }
    }

    /// Build the index from pre-expanded entries.
    pub fn from_expanded(expanded: Vec<(PathBuf, String, Severity)>) -> Self {
        let mut tree = BTreeMap::new();
        for (path, group_name, severity) in expanded {
            tree.insert(path, (group_name, severity));
        }
        Self { tree }
    }

    /// Look up which watch group a path belongs to.
    ///
    /// Returns the most-specific (longest prefix) match, or `None` if the
    /// path is not under any watch group.
    pub fn lookup(&self, path: &Path) -> Option<(&str, Severity)> {
        // Walk backwards from the query path to find longest prefix match
        for (key, (group_name, severity)) in self.tree.range(..=path.to_path_buf()).rev() {
            if path.starts_with(key) || path == key {
                return Some((group_name.as_str(), *severity));
            }
        }
        None
    }

    /// Return the number of entries in the index.
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Return whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Return the entries as an iterator of (path, group_name, severity) for
    /// backward compatibility with code that iterates over expanded groups.
    pub fn iter(&self) -> impl Iterator<Item = (&Path, &str, Severity)> {
        self.tree
            .iter()
            .map(|(path, (group_name, severity))| (path.as_path(), group_name.as_str(), *severity))
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
