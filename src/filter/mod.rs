//! Event filtering: exclusions and per-path debouncing.

pub mod exclusion;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::metrics::Metrics;
use crate::types::FsEvent;

use self::exclusion::ExclusionFilter;

const PRUNE_INTERVAL: Duration = Duration::from_secs(30);

/// Event filter: exclusion matching + per-path debounce.
pub struct EventFilter {
    debounce_timers: HashMap<PathBuf, Instant>,
    pending_paths: HashSet<PathBuf>,
    debounce_window: Duration,
    exclusion: ExclusionFilter,
    metrics: Option<Arc<Metrics>>,
    last_prune: Instant,
}

impl EventFilter {
    pub fn new(config: &Config) -> Self {
        Self::with_metrics(config, None)
    }

    pub fn with_metrics(config: &Config, metrics: Option<Arc<Metrics>>) -> Self {
        Self {
            debounce_timers: HashMap::new(),
            pending_paths: HashSet::new(),
            debounce_window: Duration::from_millis(config.daemon.debounce_ms),
            exclusion: ExclusionFilter::new(config),
            metrics,
            last_prune: Instant::now(),
        }
    }

    /// Returns true if event should be processed.
    pub fn should_process(&mut self, event: &FsEvent) -> bool {
        if self.last_prune.elapsed() >= PRUNE_INTERVAL {
            self.prune_debounce();
            self.last_prune = Instant::now();
        }

        let path_str = event.path.to_string_lossy();

        if self.exclusion.is_excluded(&path_str) {
            if let Some(metrics) = &self.metrics {
                metrics
                    .events_filtered
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return false;
        }

        let path_key = event.path.as_ref().clone();
        let now = Instant::now();
        if let Some(last) = self.debounce_timers.get(&path_key) {
            if now.duration_since(*last) < self.debounce_window {
                self.debounce_timers.insert(path_key.clone(), now);
                self.pending_paths.insert(path_key);
                if let Some(metrics) = &self.metrics {
                    metrics
                        .events_debounced
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                return false;
            }
        }

        self.debounce_timers.insert(path_key.clone(), now);
        self.pending_paths.remove(&path_key);
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
            path: Arc::new(PathBuf::from(path)),
            event_type: crate::types::FsEventType::Modify,
            timestamp: Utc::now(),
            event_fd: None,
            process: None,
            bloom_generation: 0,
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

    #[test]
    fn prune_runs_periodically() {
        let cfg = crate::config::default_config();
        let mut filter = EventFilter::new(&cfg);

        // Insert many stale entries with old timestamps
        for i in 0..100 {
            let path = PathBuf::from(format!("/tmp/stale-{}", i));
            filter
                .debounce_timers
                .insert(path.clone(), Instant::now() - Duration::from_secs(120));
            filter.pending_paths.insert(path);
        }

        assert_eq!(filter.debounce_timers.len(), 100);
        assert_eq!(filter.pending_paths.len(), 100);

        // Force prune interval to have elapsed
        filter.last_prune = Instant::now() - PRUNE_INTERVAL - Duration::from_secs(1);

        // Trigger should_process which will call prune
        let e = event("/etc/new-file");
        filter.should_process(&e);

        // Stale entries should have been pruned (only the new one remains)
        assert_eq!(filter.debounce_timers.len(), 1);
        assert!(filter
            .debounce_timers
            .contains_key(&PathBuf::from("/etc/new-file")));
    }
}
