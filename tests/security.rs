// Security test binary for Vigil.

mod common;

#[path = "security/integrity_tests.rs"]
mod integrity_tests;
#[path = "security/permission_tests.rs"]
mod permission_tests;
#[path = "security/race_tests.rs"]
mod race_tests;
