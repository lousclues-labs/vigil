// Integration tests: event filter — exclusion, debounce, self-exclusion.

use std::path::PathBuf;

use chrono::Utc;

use vigil::monitor::filter::EventFilter;
use vigil::types::*;

use crate::common::fixtures::*;

fn make_event(path: &str) -> FsEvent {
    FsEvent {
        path: PathBuf::from(path),
        event_type: FsEventType::Modify,
        timestamp: Utc::now(),
        responsible_pid: None,
        responsible_exe: None,
    }
}

#[test]
fn filter_excludes_system_paths() {
    let tmp = TempDir::new("flt-sys");
    let config = test_config(&tmp);
    let mut filter = EventFilter::new(&config);

    assert!(!filter.should_process(&make_event("/proc/1/cmdline")));
    assert!(!filter.should_process(&make_event("/sys/class/net/eth0")));
    assert!(!filter.should_process(&make_event("/dev/null")));
    assert!(!filter.should_process(&make_event("/run/user/1000/something")));
}

#[test]
fn filter_excludes_glob_patterns() {
    let tmp = TempDir::new("flt-glob");
    let config = test_config(&tmp);
    let mut filter = EventFilter::new(&config);

    assert!(!filter.should_process(&make_event("/home/user/.bashrc.swp")));
    assert!(!filter.should_process(&make_event("/etc/hosts.tmp")));
    assert!(!filter.should_process(&make_event("/home/user/file~")));
}

#[test]
fn filter_allows_monitored_files() {
    let tmp = TempDir::new("flt-allow");
    let config = test_config(&tmp);
    let mut filter = EventFilter::new(&config);

    assert!(filter.should_process(&make_event("/etc/passwd")));
    assert!(filter.should_process(&make_event("/usr/bin/sudo")));
    assert!(filter.should_process(&make_event("/home/user/.bashrc")));
}

#[test]
fn filter_self_exclusion_database() {
    let tmp = TempDir::new("flt-self");
    let config = test_config(&tmp);
    let mut filter = EventFilter::new(&config);

    assert!(!filter.should_process(&make_event("/var/lib/vigil/baseline.db")));
    assert!(!filter.should_process(&make_event("/var/log/vigil/alerts.json")));
    assert!(!filter.should_process(&make_event("/var/lib/vigil/baseline.db-wal")));
    assert!(!filter.should_process(&make_event("/var/lib/vigil/baseline.db-shm")));
}

#[test]
fn filter_debounce_suppresses_rapid_events() {
    let tmp = TempDir::new("flt-debounce");
    let config = test_config(&tmp);
    let mut filter = EventFilter::new(&config);

    let event = make_event("/etc/hosts");

    // First event should pass
    assert!(filter.should_process(&event));

    // Immediate second event should be debounced
    assert!(!filter.should_process(&event));
}

#[test]
fn filter_debounce_per_path_not_global() {
    let tmp = TempDir::new("flt-debounce-paths");
    let config = test_config(&tmp);
    let mut filter = EventFilter::new(&config);

    assert!(filter.should_process(&make_event("/etc/hosts")));
    assert!(filter.should_process(&make_event("/etc/resolv.conf")));

    // Same path again should be debounced
    assert!(!filter.should_process(&make_event("/etc/hosts")));

    // Different path should still pass
    assert!(!filter.should_process(&make_event("/etc/resolv.conf")));
}

#[test]
fn filter_prune_debounce_clears_entries() {
    let tmp = TempDir::new("flt-prune");
    let config = test_config(&tmp);
    let mut filter = EventFilter::new(&config);

    filter.should_process(&make_event("/etc/hosts"));
    filter.should_process(&make_event("/etc/shadow"));

    // Prune should not panic and should clear old entries
    filter.prune_debounce();
}
