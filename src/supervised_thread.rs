//! Supervised thread restart with bounded retries.
//!
//! Wraps a fallible thread body in a supervisor that restarts it on
//! recoverable failures, with bounded retry count. After the retry limit,
//! the supervisor stops and returns the last exit reason.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Why a supervised thread body exited.
#[derive(Debug, Clone)]
pub enum ExitReason {
    /// Clean shutdown requested (e.g. shutdown flag set).
    Shutdown,
    /// Recoverable error. The supervisor will restart the body.
    Recoverable(String),
    /// Non-recoverable error. The supervisor will not restart.
    Fatal(String),
}

/// Result of running the supervisor loop.
#[derive(Debug)]
pub struct SupervisorResult {
    pub restarts: u32,
    pub final_reason: ExitReason,
}

/// Run `body_fn` in a loop with bounded restarts on recoverable failures.
///
/// - On `ExitReason::Shutdown`, returns immediately.
/// - On `ExitReason::Recoverable`, waits `restart_delay` and retries up to
///   `max_restarts` times.
/// - On `ExitReason::Fatal` or after exhausting retries, returns.
///
/// `restart_counter` is incremented on each restart for metrics.
pub fn run_supervised<F>(
    body_fn: F,
    max_restarts: u32,
    restart_delay: Duration,
    restart_counter: &Arc<AtomicU64>,
) -> SupervisorResult
where
    F: Fn() -> ExitReason,
{
    let mut consecutive_failures = 0u32;

    loop {
        let reason = body_fn();

        match &reason {
            ExitReason::Shutdown => {
                return SupervisorResult {
                    restarts: consecutive_failures,
                    final_reason: reason,
                };
            }
            ExitReason::Fatal(_) => {
                return SupervisorResult {
                    restarts: consecutive_failures,
                    final_reason: reason,
                };
            }
            ExitReason::Recoverable(msg) => {
                consecutive_failures += 1;
                if consecutive_failures > max_restarts {
                    return SupervisorResult {
                        restarts: consecutive_failures,
                        final_reason: ExitReason::Fatal(format!(
                            "max restarts ({}) exceeded. last error: {}",
                            max_restarts, msg
                        )),
                    };
                }
                restart_counter.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    attempt = consecutive_failures,
                    max = max_restarts,
                    error = %msg,
                    "supervised thread restarting after recoverable error"
                );
                std::thread::sleep(restart_delay);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[test]
    fn shutdown_exits_immediately() {
        let counter = Arc::new(AtomicU64::new(0));
        let result = run_supervised(
            || ExitReason::Shutdown,
            3,
            Duration::from_millis(1),
            &counter,
        );
        assert!(matches!(result.final_reason, ExitReason::Shutdown));
        assert_eq!(result.restarts, 0);
    }

    #[test]
    fn fatal_exits_immediately() {
        let counter = Arc::new(AtomicU64::new(0));
        let result = run_supervised(
            || ExitReason::Fatal("bad".into()),
            3,
            Duration::from_millis(1),
            &counter,
        );
        assert!(matches!(result.final_reason, ExitReason::Fatal(_)));
        assert_eq!(result.restarts, 0);
    }

    #[test]
    fn recoverable_retries_up_to_max() {
        let counter = Arc::new(AtomicU64::new(0));
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = call_count.clone();

        let result = run_supervised(
            move || {
                cc.fetch_add(1, Ordering::Relaxed);
                ExitReason::Recoverable("read error".into())
            },
            3,
            Duration::from_millis(1),
            &counter,
        );

        assert!(matches!(result.final_reason, ExitReason::Fatal(_)));
        // 1 initial + 3 retries = 4 calls
        assert_eq!(call_count.load(Ordering::Relaxed), 4);
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn recoverable_then_shutdown_stops() {
        let counter = Arc::new(AtomicU64::new(0));
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = call_count.clone();

        let result = run_supervised(
            move || {
                let n = cc.fetch_add(1, Ordering::Relaxed);
                if n < 2 {
                    ExitReason::Recoverable("transient".into())
                } else {
                    ExitReason::Shutdown
                }
            },
            5,
            Duration::from_millis(1),
            &counter,
        );

        assert!(matches!(result.final_reason, ExitReason::Shutdown));
        assert_eq!(call_count.load(Ordering::Relaxed), 3);
    }
}
