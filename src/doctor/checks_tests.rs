//! Unit tests for the diagnostic checks in `src/doctor/checks.rs`.
//!
//! Each test here pins a correction where a *failed* or *unreadable* signal
//! used to render as a clean result. They exist because reverting any one of
//! those fixes left the whole suite green.
//!
//! Extracted from `src/doctor/checks.rs` to keep that file under the
//! 1500-line architectural invariant. Mounted from `checks.rs` via
//! `#[path = "checks_tests.rs"]`.

use super::*;

fn config_with_runtime_dir(dir: &Path) -> Config {
    let mut config = crate::config::default_config();
    config.daemon.runtime_dir = dir.to_path_buf();
    config
}

#[test]
fn unreadable_metrics_is_unknown_not_full_coverage() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // No metrics.json written: "we could not look" must not render as
    // the all-clear, because 0 degraded mounts is itself the all-clear
    // value and the default would have asserted it.
    let check = check_realtime_coverage(&config_with_runtime_dir(tmp.path()), true);
    assert_eq!(check.status, CheckStatus::Unknown);
    assert!(
        !check.detail.contains("full event coverage"),
        "absent metrics claimed full coverage: {}",
        check.detail
    );
}

#[test]
fn metrics_without_coverage_fields_is_unknown_not_full_coverage() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // A metrics.json written by a daemon that predates these counters.
    std::fs::write(
        tmp.path().join("metrics.json"),
        br#"{"changes_detected":7,"last_scan_total":100}"#,
    )
    .expect("write metrics");

    let check = check_realtime_coverage(&config_with_runtime_dir(tmp.path()), true);
    assert_eq!(check.status, CheckStatus::Unknown);
    assert!(
        !check.detail.contains("full event coverage"),
        "absent counters claimed full coverage: {}",
        check.detail
    );
}

#[test]
fn metrics_written_by_this_daemon_are_understood_by_this_reader() {
    // Pins the writer/reader field-name contract across
    // `MetricsSnapshot` (serialised by the coordinator) and
    // `RuntimeMetrics` (deserialised by doctor). A rename on one side
    // would otherwise surface as a permanent, silent "Unknown".
    let tmp = tempfile::tempdir().expect("tempdir");
    let metrics = crate::metrics::Metrics::new();
    std::fs::write(
        tmp.path().join("metrics.json"),
        serde_json::to_vec(&metrics.snapshot()).expect("serialise"),
    )
    .expect("write metrics");

    let check = check_realtime_coverage(&config_with_runtime_dir(tmp.path()), true);
    assert_eq!(
        check.status,
        CheckStatus::Ok,
        "doctor could not read metrics this daemon just wrote: {}",
        check.detail
    );
    assert!(check.detail.contains("full event coverage"));
}

#[test]
fn degraded_coverage_is_reported_as_a_warning() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("metrics.json"),
        br#"{"fanotify_mark_reduced_coverage":3,"fanotify_tier":1}"#,
    )
    .expect("write metrics");

    let check = check_realtime_coverage(&config_with_runtime_dir(tmp.path()), true);
    assert_eq!(check.status, CheckStatus::Warning);
    assert!(check.detail.contains('3'), "count hidden: {}", check.detail);
}

#[test]
fn unreadable_hook_verdict_is_unknown_not_ok() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = config_with_runtime_dir(tmp.path());
    for labels in [HOOK_LABELS_PACMAN, HOOK_LABELS_APT] {
        let (status, detail, _) = hook_trigger_check(&config, HookTriggerResult::Unknown, labels);
        assert_eq!(
            status,
            CheckStatus::Unknown,
            "unreadable hook verdict reported as {:?} for {}",
            status,
            labels.installed
        );
        assert!(
            detail.contains("unavailable"),
            "detail hides the unavailability: {}",
            detail
        );
    }
}

#[test]
fn failed_hook_trigger_is_not_ok() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = config_with_runtime_dir(tmp.path());
    let (status, _, _) = hook_trigger_check(
        &config,
        HookTriggerResult::Failure("2025-01-01 00:00:00".into(), "vigil-apt".into()),
        HOOK_LABELS_APT,
    );
    assert_eq!(status, CheckStatus::Warning);
}

#[test]
fn hook_labels_are_distinct_per_backend() {
    // Guards the de-duplication: one shared mapping must still produce
    // backend-specific text and acknowledgement keys.
    assert_ne!(HOOK_LABELS_PACMAN.installed, HOOK_LABELS_APT.installed);
    assert_ne!(HOOK_LABELS_PACMAN.ack_key, HOOK_LABELS_APT.ack_key);
    assert_ne!(HOOK_LABELS_PACMAN.journal_cmd, HOOK_LABELS_APT.journal_cmd);
}

#[test]
fn notify_check_warns_when_no_channel_is_reachable() {
    // `command_exists("notify-send")` says nothing about deliverability.
    // If no channel is reachable the check must not report Ok, whether or
    // not the binary happens to be installed on this machine.
    if crate::alert::dbus::notification_channel_available() {
        return;
    }
    let check = check_notify_send();
    assert_ne!(
        check.status,
        CheckStatus::Ok,
        "undeliverable notifications reported healthy: {}",
        check.detail
    );
}
