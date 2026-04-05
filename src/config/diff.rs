use std::collections::HashSet;

use crate::config::Config;

/// Compare two configs and return human-readable descriptions of changes.
pub fn diff_config(old: &Config, new: &Config) -> Vec<String> {
    let mut diffs = Vec::new();

    if old.daemon.log_level != new.daemon.log_level {
        diffs.push(format!(
            "log_level changed: {} -> {}",
            old.daemon.log_level, new.daemon.log_level
        ));
    }
    if old.daemon.monitor_backend != new.daemon.monitor_backend {
        diffs.push(format!(
            "monitor_backend changed: {} -> {}",
            old.daemon.monitor_backend, new.daemon.monitor_backend
        ));
    }

    if old.scanner.max_file_size != new.scanner.max_file_size {
        diffs.push(format!(
            "max_file_size changed: {} -> {}",
            old.scanner.max_file_size, new.scanner.max_file_size
        ));
    }
    if old.scanner.mode != new.scanner.mode {
        diffs.push(format!(
            "scanner.mode changed: {} -> {}",
            old.scanner.mode, new.scanner.mode
        ));
    }

    if old.alerts.rate_limit != new.alerts.rate_limit {
        diffs.push(format!(
            "rate_limit changed: {} -> {}",
            old.alerts.rate_limit, new.alerts.rate_limit
        ));
    }
    if old.alerts.cooldown_seconds != new.alerts.cooldown_seconds {
        diffs.push(format!(
            "cooldown_seconds changed: {} -> {}",
            old.alerts.cooldown_seconds, new.alerts.cooldown_seconds
        ));
    }

    for group_name in new.watch.keys() {
        if !old.watch.contains_key(group_name) {
            diffs.push(format!("watch group '{}' added", group_name));
        }
    }
    for group_name in old.watch.keys() {
        if !new.watch.contains_key(group_name) {
            diffs.push(format!("watch group '{}' removed", group_name));
        }
    }

    for (group_name, new_group) in &new.watch {
        if let Some(old_group) = old.watch.get(group_name) {
            if old_group.severity != new_group.severity {
                diffs.push(format!(
                    "watch.{}.severity changed: {} -> {}",
                    group_name, old_group.severity, new_group.severity
                ));
            }

            let old_paths: HashSet<&String> = old_group.paths.iter().collect();
            let new_paths: HashSet<&String> = new_group.paths.iter().collect();
            for p in new_paths.difference(&old_paths) {
                diffs.push(format!("watch.{}: path '{}' added", group_name, p));
            }
            for p in old_paths.difference(&new_paths) {
                diffs.push(format!("watch.{}: path '{}' removed", group_name, p));
            }
        }
    }

    let old_excl: HashSet<&String> = old.exclusions.patterns.iter().collect();
    let new_excl: HashSet<&String> = new.exclusions.patterns.iter().collect();
    for p in new_excl.difference(&old_excl) {
        diffs.push(format!("exclusion pattern '{}' added", p));
    }
    for p in old_excl.difference(&new_excl) {
        diffs.push(format!("exclusion pattern '{}' removed", p));
    }

    diffs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_simple_changes() {
        let mut old = crate::config::default_config();
        let mut new = old.clone();
        new.alerts.rate_limit = 99;

        let diffs = diff_config(&old, &new);
        assert!(diffs.iter().any(|d| d.contains("rate_limit changed")));

        old.watch.insert(
            "temp".into(),
            crate::config::WatchGroup {
                severity: crate::types::Severity::Low,
                paths: vec!["/tmp".into()],
            },
        );
        let diffs = diff_config(&old, &new);
        assert!(diffs.iter().any(|d| d.contains("watch group 'temp' removed")));
    }
}
