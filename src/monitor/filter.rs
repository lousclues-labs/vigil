use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::types::FsEvent;

/// Event filter that applies exclusion patterns, path membership checks,
/// and per-path debounce logic.
pub struct EventFilter {
    /// Per-path debounce timers (last event time).
    debounce_timers: HashMap<String, Instant>,
    /// Debounce window duration.
    debounce_window: Duration,
    /// Compiled exclusion glob patterns.
    exclusion_patterns: Vec<glob::Pattern>,
    /// System exclusion prefixes.
    system_exclusion_prefixes: Vec<String>,
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
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();

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
        let key = path_str.into_owned();
        let now = Instant::now();
        if let Some(last) = self.debounce_timers.get(&key) {
            if now.duration_since(*last) < self.debounce_window {
                // Update timer to latest event (we want the final state after debounce)
                self.debounce_timers.insert(key, now);
                return false;
            }
        }
        self.debounce_timers.insert(key, now);

        true
    }

    /// Prune stale debounce entries to prevent unbounded memory growth.
    /// Call periodically (e.g., every 60 seconds).
    pub fn prune_debounce(&mut self) {
        let now = Instant::now();
        let cutoff = Duration::from_secs(60);
        self.debounce_timers
            .retain(|_, last| now.duration_since(*last) < cutoff);
    }
}
