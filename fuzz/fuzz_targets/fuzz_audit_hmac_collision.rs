#![no_main]

//! Fuzz target for VIGIL-VULN-076: adversarial inputs targeting the v2
//! canonical CBOR HMAC encoder. Must not panic, overflow, or produce
//! identical bytes for distinct inputs.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    ts: i64,
    path: Vec<u8>,
    change: String,
    severity: String,
    old_hash: Option<String>,
    new_hash: Option<String>,
    prev: String,
}

fuzz_target!(|input: FuzzInput| {
    // Must not panic on any input
    let _ = vigil::hmac::build_audit_hmac_data_v2(
        input.ts,
        &String::from_utf8_lossy(&input.path),
        &input.change,
        &input.severity,
        input.old_hash.as_deref(),
        input.new_hash.as_deref(),
        &input.prev,
    );
});
