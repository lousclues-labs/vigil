use std::path::PathBuf;

use crate::alert::AlertEngine;
use crate::config::Config;
use crate::db;
use crate::error::Result;
use crate::scanner::{self, ScanResult};
use crate::types::ScanMode;

/// Fluent builder for running integrity checks from library code.
pub struct CheckBuilder<'a> {
    config: &'a Config,
    mode: ScanMode,
    filter_paths: Option<Vec<PathBuf>>,
    progress: Option<&'a dyn Fn(&str)>,
    quiet: bool,
}

impl<'a> CheckBuilder<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self {
            config,
            mode: ScanMode::Incremental,
            filter_paths: None,
            progress: None,
            quiet: false,
        }
    }

    pub fn mode(mut self, mode: ScanMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn filter_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.filter_paths = Some(paths);
        self
    }

    pub fn on_progress(mut self, cb: &'a dyn Fn(&str)) -> Self {
        self.progress = Some(cb);
        self
    }

    pub fn quiet(mut self) -> Self {
        self.quiet = true;
        self
    }

    pub fn run(self) -> Result<ScanResult> {
        let conn = db::open_db(self.config)?;
        let alert_engine = AlertEngine::new(self.config)?;

        scanner::run_scan(&conn, self.config, &alert_engine, self.mode, self.progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults() {
        // We can't actually run a scan without a real config/db, but
        // we can verify the builder sets defaults correctly.
        let config = crate::config::Config {
            daemon: Default::default(),
            scanner: Default::default(),
            alerts: Default::default(),
            exclusions: Default::default(),
            package_manager: Default::default(),
            hooks: Default::default(),
            security: Default::default(),
            database: Default::default(),
            watch: {
                let mut w = std::collections::HashMap::new();
                w.insert(
                    "test".into(),
                    crate::config::WatchGroup {
                        severity: crate::types::Severity::Low,
                        paths: vec!["/tmp/vigil-test-nonexistent".into()],
                    },
                );
                w
            },
        };

        let builder = CheckBuilder::new(&config);
        assert!(!builder.quiet);
        assert!(builder.filter_paths.is_none());
        assert!(builder.progress.is_none());
    }

    #[test]
    fn builder_chaining() {
        let config = crate::config::Config {
            daemon: Default::default(),
            scanner: Default::default(),
            alerts: Default::default(),
            exclusions: Default::default(),
            package_manager: Default::default(),
            hooks: Default::default(),
            security: Default::default(),
            database: Default::default(),
            watch: {
                let mut w = std::collections::HashMap::new();
                w.insert(
                    "test".into(),
                    crate::config::WatchGroup {
                        severity: crate::types::Severity::Low,
                        paths: vec!["/tmp/vigil-test-nonexistent".into()],
                    },
                );
                w
            },
        };

        let builder = CheckBuilder::new(&config)
            .mode(ScanMode::Full)
            .filter_paths(vec![PathBuf::from("/etc")])
            .quiet();

        assert!(builder.quiet);
        assert_eq!(builder.filter_paths.as_ref().unwrap().len(), 1);
    }
}
