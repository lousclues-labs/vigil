#![no_main]

use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use vigil::attest;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|data: &[u8]| {
    let mut path = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    path.push(format!(
        "vigil-fuzz-attest-verify-{}-{}",
        std::process::id(),
        id
    ));

    if std::fs::write(&path, data).is_ok() {
        // Verify path should never panic on adversarial input.
        let _ = attest::verify::verify_attestation(&path, None);
    }

    let _ = std::fs::remove_file(&path);
});
