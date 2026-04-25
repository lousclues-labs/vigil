//! Process-level helpers: PID file reading and liveness checks.

use std::fs;
use std::path::Path;

/// Read a PID from a file (newline-terminated integer).
pub fn read_pid(path: &Path) -> Option<i32> {
    let raw = fs::read_to_string(path).ok()?;
    raw.trim().parse::<i32>().ok()
}

/// Check whether a process with the given PID is alive.
#[allow(unsafe_code)]
pub fn is_pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }

    if Path::new(&format!("/proc/{}/exe", pid)).exists() {
        return true;
    }

    // SAFETY: kill(pid, 0) probes whether the process exists; no signal
    // is delivered. pid comes from a parsed PID file (i32). If the process
    // does not exist, kill returns -1 with ESRCH.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }

    let err = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or_default();
    err == libc::EPERM
}
