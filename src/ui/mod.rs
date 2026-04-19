//! UI layer; progress rendering for multi-step CLI operations.
//!
//! Provides a terminal-aware progress renderer with cargo-style status lines,
//! elapsed timing, spinners (TTY), and plain-text fallback (non-TTY/CI).
//! Respects `NO_COLOR`, `TERM=dumb`, and `VIGIL_PROGRESS` env vars.

pub mod progress;

pub use progress::{Plan, Progress, ProgressMode, UpdateStep};
