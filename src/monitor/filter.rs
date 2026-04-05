use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::types::FsEvent;

/// Maximum debounce entries before emergency pruning.
const MAX_DEBOUNCE_ENTRIES: usize = 50_000;

/// Event filter that applies exclusion patterns, path membership checks,
/// and per-path debounce logic.
pub struct EventFilter {
    /// Per-path debounce timers (last event time).
    debounce_timers: HashMap<PathBuf, Instant>,
    /// Debounce window duration.
    debounce_window: Duration,
    /// Compiled exclusion glob patterns.
    exclusion_patterns: Vec<glob::Pattern>,
    /// System exclusion prefixes.
    system_exclusion_prefixes: Vec<String>,
    /// Paths whose final event was debounced away and need re-checking
    /// after the debounce window expires.
    pending_paths: HashSet<PathBuf>,
}

impl EventFilter {
    pub fn new(config: &Config) -> Self {
        let exclusion_patterns = config
            .exclusions
            .patterns
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        let system_exclusion_prefixes = config
            .exclusions
            .system_exclusions
            .iter()
            .map(|s| s.trim_end_matches('*').to_string())
            .collect();

        Self {
            debounce_timers: HashMap::new(),
            debounce_window: Duration::from_millis(100),
            exclusion_patterns,
            system_exclusion_prefixes,
            pending_paths: HashSet::new(),
        }
    }

    /// Returns true if the event should be processed (not filtered out).
    pub fn should_process(&mut self, event: &FsEvent) -> bool {
        let path_str = event.path.to_string_lossy();

        // System exclusion (prefix match)
        for prefix in &self.system_exclusion_prefixes {
            if path_str.starts_with(prefix.as_str()) {
                return false;
            }
        }

        // Pattern exclusion (glob match)
        let file_name = event
            .path
            .file_name()
            .map(|f| f.to_string_lossy())
            .unwrap_or(std::borrow::Cow::Borrowed(""));

        for pattern in &self.exclusion_patterns {
            if pattern.matches(&file_name) || pattern.matches(&path_str) {
                return false;
            }
        }

        // Self-exclusion: skip Vigil's own database and log paths
        if path_str.contains("/vigil/baseline.db")
            || path_str.contains("/vigil/alerts.json")
            || path_str.ends_with(".db-wal")
            || path_str.ends_with(".db-shm")
        {
            return false;
        }

        // Per-path debounce
        let now = Instant::now();

        // Bound debounce map to prevent unbounded memory growth
        if self.debounce_timers.len() >= MAX_DEBOUNCE_ENTRIES {
            log::warn!(
                "Debounce map exceeded {} entries, running emergency prune",
                MAX_DEBOUNCE_ENTRIES
            );
            self.prune_debounce();
        }

        if let Some(last) = self.debounce_timers.get(&event.path) {
            if now.duration_since(*last) < self.debounce_window {
                // Update timer to latest event (we want the final state after debounce)
                self.debounce_timers.insert(event.path.clone(), now);
                // Track this path so drain_pending() can re-check it after
                // the debounce window expires, ensuring the trailing edge
                // of a burst is never permanently missed.
                self.pending_paths.insert(event.path.clone());
                return false;
            }
        }
        self.debounce_timers.insert(event.path.clone(), now);
        // Path is being processed now, remove from pending
        self.pending_paths.remove(&event.path);

        true
    }

    /// Prune stale debounce entries to prevent unbounded memory growth.
    /// Call periodically (e.g., every 60 seconds).
    pub fn prune_debounce(&mut self) {
        let now = Instant::now();
        let cutoff = Duration::from_secs(60);
        let removed_paths: Vec<PathBuf> = self
            .debounce_timers
            .iter()
            .filter(|(_, last)| now.duration_since(**last) >= cutoff)
            .map(|(path, _)| path.clone())
            .collect();
        for path in &removed_paths {
            self.debounce_timers.remove(path);
            self.pending_paths.remove(path);
        }
    }

    /// Drain paths whose debounce window has expired. These are paths where
    /// the final modification in a burst was debounced away. The caller
    /// should re-process each returned path as if a new event arrived.
    pub fn drain_pending(&mut self) -> Vec<PathBuf> {
        let now = Instant::now();
        let expired: Vec<PathBuf> = self
            .pending_paths
            .iter()
            .filter(|path| {
                self.debounce_timers
                    .get(*path)
                    .map(|last| now.duration_since(*last) >= self.debounce_window)
                    .unwrap_or(true) // no timer entry = definitely expired
            })
            .cloned()
            .collect();
        for path in &expired {
            self.pending_paths.remove(path);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FsEvent, FsEventType};
    use chrono::Utc;

    fn test_config() -> Config {
        Config {
            daemon: Default::default(),
            scanner: Default::default(),
            alerts: Default::default(),
            exclusions: crate::config::ExclusionsConfig {
                patterns: vec![],
                system_exclusions: vec![],
            },
            package_manager: Default::default(),
            hooks: Default::default(),
            security: Default::default(),
            database: Default::default(),
            watch: Default::default(),
        }
    }

    fn make_event(path: &str) -> FsEvent {
        FsEvent {
            path: PathBuf::from(path),
            event_type: FsEventType::Modify,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn drain_pending_returns_debounced_paths_after_window_expires() {
        let config = test_config();
        let mut filter = EventFilter::new(&config);

        // Override debounce window to a very short duration for testing
        filter.debounce_window = Duration::from_millis(10);

        let event = make_event("/tmp/test.txt");

        // First event should pass through
        assert!(filter.should_process(&event));

        // Immediate repeat should be debounced
        assert!(!filter.should_process(&event));

        // Should now be in pending
        assert!(filter
            .pending_paths
            .contains(&PathBuf::from("/tmp/test.txt")));

        // drain_pending should return nothing yet (debounce window hasn't expired)
        let _pending = filter.drain_pending();
        // It may or may not have expired depending on timing. With 10ms window,
        // it's likely still within the window.

        // Wait for debounce window to expire
        std::thread::sleep(Duration::from_millis(15));

        // Now drain_pending should return the path
        let pending = filter.drain_pending();
        assert!(
            pending.contains(&PathBuf::from("/tmp/test.txt")),
            "drain_pending should return debounced paths after window expires"
        );

        // Second call should return empty (already drained)
        let pending = filter.drain_pending();
        assert!(
            !pending.contains(&PathBuf::from("/tmp/test.txt")),
            "drain_pending should not return already-drained paths"
        );
    }
}
