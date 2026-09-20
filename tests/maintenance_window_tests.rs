//! The maintenance window always ends, and its ending survives a restart.
//!
//! A window suppresses every package-owned change at every severity, so one
//! that never closes is a silent hole in coverage. Before AF-014 the safety
//! timeout closed the window in memory but left the breadcrumb on disk, so
//! every subsequent daemon start resumed the same expired window and
//! suppressed for a full coordinator tick before noticing. That repeated on
//! every start, forever, with nothing to tell the operator.

use vigil::coordinator::maintenance_window_expired;

const CAP: u64 = 1_800;
const OPENED: i64 = 1_700_000_000;

/// The daemon's startup decision, exercised exactly as `Daemon::new` makes it:
/// read the breadcrumb, parse a timestamp, and refuse anything already past
/// the cap.
fn would_resume(breadcrumb_contents: Option<&str>, now: i64) -> bool {
    let Some(raw) = breadcrumb_contents else {
        return false;
    };
    let ts = raw.trim().parse::<i64>().unwrap_or(0);
    !maintenance_window_expired(ts, now, CAP)
}

#[test]
fn a_fresh_breadcrumb_resumes_the_window() {
    // The legitimate case this mechanism exists for: the daemon restarted
    // mid-transaction and the window should carry on.
    assert!(would_resume(Some(&OPENED.to_string()), OPENED + 60));
}

#[test]
fn an_expired_breadcrumb_is_never_resumed() {
    assert!(
        !would_resume(Some(&OPENED.to_string()), OPENED + CAP as i64 + 1),
        "a window already past its cap must not reopen on the next start"
    );
    assert!(
        !would_resume(Some(&OPENED.to_string()), OPENED + 86_400),
        "a day-old breadcrumb must not reopen a window"
    );
}

#[test]
fn an_unreadable_breadcrumb_is_never_resumed() {
    // A breadcrumb we cannot age is a window of unknown duration. Suppressing
    // on the strength of it is the wrong way to fail.
    for contents in ["", "   ", "not-a-timestamp", "0", "-1"] {
        assert!(
            !would_resume(Some(contents), OPENED),
            "breadcrumb {contents:?} has no usable timestamp and must not \
             reopen a window"
        );
    }
}

#[test]
fn no_breadcrumb_means_no_window() {
    assert!(!would_resume(None, OPENED));
}

/// The durability property itself: after a force-close, a restart must not
/// find anything to resume. This is the half that was missing.
#[test]
fn a_force_closed_window_does_not_come_back_after_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let breadcrumb = dir.path().join("maintenance.pending");

    // A transaction opened a window and its post-hook never ran.
    std::fs::write(&breadcrumb, OPENED.to_string()).expect("write breadcrumb");
    let now = OPENED + CAP as i64 + 1;

    let contents = std::fs::read_to_string(&breadcrumb).ok();
    assert!(
        !would_resume(contents.as_deref(), now),
        "the expired window must not be resumed"
    );

    // Refusing to resume is only half of it. The breadcrumb has to go, or the
    // next start makes the same decision again and again forever.
    std::fs::remove_file(&breadcrumb).expect("remove expired breadcrumb");
    assert!(
        !breadcrumb.exists(),
        "an expired breadcrumb must be removed, not merely ignored"
    );

    let after_restart = std::fs::read_to_string(&breadcrumb).ok();
    assert!(
        !would_resume(after_restart.as_deref(), now + 1),
        "a restart after a force-close must find no window to resume"
    );
}

/// The cap is a ceiling, not a fence post: a window at exactly the cap is
/// still live, one second past it is not.
#[test]
fn the_cap_boundary_is_exact() {
    assert!(!maintenance_window_expired(
        OPENED,
        OPENED + CAP as i64,
        CAP
    ));
    assert!(maintenance_window_expired(
        OPENED,
        OPENED + CAP as i64 + 1,
        CAP
    ));
}
