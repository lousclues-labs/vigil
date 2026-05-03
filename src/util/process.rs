//! Process-level helpers: PID file reading, liveness checks, and identity.

use std::fs;
use std::path::Path;

/// Return the process's effective UID. Cached in a OnceLock to avoid
/// repeated syscalls (VIGIL-VULN-073). The cached value is only valid
/// for processes that do not change credentials at runtime; vigild does
/// not, so this is safe. If a future vigil binary needs to drop
/// privileges, this assumption needs revisiting.
#[allow(unsafe_code)]
pub fn current_euid() -> u32 {
    static EUID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *EUID.get_or_init(|| {
        // SAFETY: geteuid returns the effective uid with no side effects.
        // Cannot fail and has no memory safety implications.
        unsafe { libc::geteuid() }
    })
}

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
