pub mod exclusion;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::metrics::Metrics;
use crate::types::FsEvent;

use self::exclusion::ExclusionFilter;

/// Event filter: exclusion matching + per-path debounce.
pub struct EventFilter {
    debounce_timers: HashMap<PathBuf, Instant>,
    pending_paths: HashSet<PathBuf>,
    debounce_window: Duration,
    exclusion: ExclusionFilter,
    metrics: Option<Arc<Metrics>>,
}

impl EventFilter {
    pub fn new(config: &Config) -> Self {
        Self::with_metrics(config, None)
    }

    pub fn with_metrics(config: &Config, metrics: Option<Arc<Metrics>>) -> Self {
        Self {
            debounce_timers: HashMap::new(),
            pending_paths: HashSet::new(),
            debounce_window: Duration::from_millis(100),
            exclusion: ExclusionFilter::new(config),
            metrics,
        }
    }

    /// Returns true if event should be processed.
    pub fn should_process(&mut self, event: &FsEvent) -> bool {
        let path_str = event.path.to_string_lossy();

        if self.exclusion.is_excluded(&path_str) {
            if let Some(metrics) = &self.metrics {
                metrics
                    .events_filtered
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return false;
        }

        let now = Instant::now();
        if let Some(last) = self.debounce_timers.get(&event.path) {
            if now.duration_since(*last) < self.debounce_window {
                self.debounce_timers.insert(event.path.clone(), now);
                self.pending_paths.insert(event.path.clone());
                if let Some(metrics) = &self.metrics {
                    metrics
                        .events_debounced
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                return false;
            }
        }

        self.debounce_timers.insert(event.path.clone(), now);
        self.pending_paths.remove(&event.path);
        true
    }

    pub fn prune_debounce(&mut self) {
        let now = Instant::now();
        let cutoff = Duration::from_secs(60);
        let stale: Vec<PathBuf> = self
            .debounce_timers
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) >= cutoff)
            .map(|(path, _)| path.clone())
            .collect();

        for path in stale {
            self.debounce_timers.remove(&path);
            self.pending_paths.remove(&path);
        }
    }

    /// Drain paths whose debounce window has expired.
    pub fn drain_pending(&mut self) -> Vec<PathBuf> {
        let now = Instant::now();
        let expired: Vec<PathBuf> = self
            .pending_paths
            .iter()
            .filter(|path| {
                self.debounce_timers
                    .get(*path)
                    .map(|ts| now.duration_since(*ts) >= self.debounce_window)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();

        for p in &expired {
            self.pending_paths.remove(p);
        }

        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn event(path: &str) -> FsEvent {
        FsEvent {
            path: PathBuf::from(path),
            event_type: crate::types::FsEventType::Modify,
            timestamp: Utc::now(),
            event_fd: None,
            process: None,
        }
    }

    #[test]
    fn debounces_rapid_events() {
        let cfg = crate::config::default_config();
        let mut filter = EventFilter::new(&cfg);

        let e = event("/etc/passwd");
        assert!(filter.should_process(&e));
        assert!(!filter.should_process(&e));
    }

    #[test]
    fn exclusion_blocks_event() {
        let mut cfg = crate::config::default_config();
        cfg.exclusions.patterns = vec!["*.swp".into()];
        let mut filter = EventFilter::new(&cfg);

        let e = event("/tmp/test.swp");
        assert!(!filter.should_process(&e));
    }
}
