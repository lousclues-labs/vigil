// tests/chaos.rs — Entry point for the chaos engineering test suite.
//
// Run all: `cargo test --test chaos -- --nocapture`
// Run one: `cargo test --test chaos wal_concurrency -- --nocapture`
// Run tier B: `CHAOS_TIER=B cargo test --test chaos -- --nocapture`
// Run with seed: `CHAOS_SEED=12345 cargo test --test chaos -- --nocapture`

#[path = "chaos/chaos_common.rs"]
mod chaos_common;
#[path = "chaos/harness.rs"]
mod harness;

#[path = "chaos/scenarios/wal_concurrency.rs"]
mod wal_concurrency;
#[path = "chaos/scenarios/pipeline_recovery.rs"]
mod pipeline_recovery;
#[path = "chaos/scenarios/coordinator_adversarial_tick.rs"]
mod coordinator_adversarial_tick;
#[path = "chaos/scenarios/worker_pool_chaos.rs"]
mod worker_pool_chaos;
#[path = "chaos/scenarios/config_reload_storm.rs"]
mod config_reload_storm;
#[path = "chaos/scenarios/sink_determinism.rs"]
mod sink_determinism;
#[path = "chaos/scenarios/clock_warfare.rs"]
mod clock_warfare;
#[path = "chaos/scenarios/coordinated_attack.rs"]
mod coordinated_attack;

