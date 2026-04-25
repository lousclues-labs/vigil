//! Vigil: a lightweight file integrity monitor for Linux desktops.
//!
//! The crate root declares all modules and re-exports the public API.
//! Daemon orchestration lives in `crate::daemon`.

#![deny(unsafe_code)]

pub mod ack;
pub mod alert;
pub mod attest;
pub mod baseline_diff;
pub mod bloom;
pub mod cli;
pub mod config;
pub mod control;
pub mod coordinator;
pub mod daemon;
pub mod db;
pub mod detection;
pub mod display;
pub mod doctor;
pub mod error;
pub mod filter;
pub mod hash;
pub mod hmac;
pub mod metrics;
pub mod monitor;
pub mod package;
pub mod receipt;
pub mod scan_scheduler;
pub mod scanner;
pub mod supervised_thread;
pub mod types;
pub mod ui;
pub mod util;
pub mod wal;
pub mod watch_index;
pub mod worker;

pub use daemon::Daemon;
pub use error::{Result, VigilError};
