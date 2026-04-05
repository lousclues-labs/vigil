// Integration test binary for Vigil.

mod common;

#[path = "integration/audit_chain_tests.rs"]
mod audit_chain_tests;
#[path = "integration/baseline_tests.rs"]
mod baseline_tests;
#[path = "integration/comparison_tests.rs"]
mod comparison_tests;
#[path = "integration/config_tests.rs"]
mod config_tests;
#[path = "integration/daemon_tests.rs"]
mod daemon_tests;
#[path = "integration/db_tests.rs"]
mod db_tests;
#[path = "integration/filter_tests.rs"]
mod filter_tests;
#[path = "integration/snapshot_tests.rs"]
mod snapshot_tests;
