/// VigilBaseline Chaos Engineering Test Suite
///
/// Validates resilience under real environmental faults:
/// filesystem churn, time anomalies, resource starvation, and crash recovery.
///
/// Run with: `cargo test --test chaos -- --nocapture`
/// Or specific tier: `CHAOS_TIER=A cargo test --test chaos`

pub mod chaos_common;
pub mod harness;
pub mod scenarios;
