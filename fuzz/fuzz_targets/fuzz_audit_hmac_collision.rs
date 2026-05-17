#![no_main]

//! Fuzz target for VIGIL-VULN-076: adversarial inputs targeting the v2
//! canonical CBOR HMAC encoder.
//!
//! Two properties are checked per input:
//!   (1) Liveness: must not panic, overflow, or abort on any input.
//!   (2) Local collision resistance: perturbing any single field by one
//!       byte (or flipping the presence of an Option) must produce a
//!       different canonical encoding. If even a 1-byte change at a
//!       given field can collide, then the canonical encoder is broken
//!       at that decision point and a real attacker can construct a
//!       full collision. This pins each field's contribution to the
//!       output bytes.
//!
//! Note: libFuzzer has no global state across invocations, so this is
//! not a brute-force "build a HashSet of all outputs" test (which would
//! need its own infrastructure). It is a per-input contract check that
//! catches the v1-style bugs VIGIL-VULN-076 was filed against (path
//! delimiter collision, missing-vs-empty-string ambiguity).

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    ts: i64,
    path: Vec<u8>,
    change: String,
    severity: String,
    old_hash: Option<String>,
    new_hash: Option<String>,
    prev: String,
}

fn encode(input: &FuzzInput) -> Vec<u8> {
    vigil::hmac::build_audit_hmac_data_v2(
        input.ts,
        &String::from_utf8_lossy(&input.path),
        &input.change,
        &input.severity,
        input.old_hash.as_deref(),
        input.new_hash.as_deref(),
        &input.prev,
    )
}

fuzz_target!(|input: FuzzInput| {
    // (1) Liveness: must not panic on any input.
    let baseline = encode(&input);

    // (2) Per-field perturbation. Each branch perturbs exactly one field
    // and asserts the canonical encoding changes. A collision here is a
    // canonicalization bug.
    let mut perturbed = input.clone();
    perturbed.ts = input.ts.wrapping_add(1);
    assert_ne!(
        encode(&perturbed),
        baseline,
        "ts perturbation produced identical canonical bytes"
    );

    let mut perturbed = input.clone();
    perturbed.path.push(0x00);
    assert_ne!(
        encode(&perturbed),
        baseline,
        "path perturbation produced identical canonical bytes"
    );

    let mut perturbed = input.clone();
    perturbed.change.push('~');
    assert_ne!(
        encode(&perturbed),
        baseline,
        "change perturbation produced identical canonical bytes"
    );

    let mut perturbed = input.clone();
    perturbed.severity.push('~');
    assert_ne!(
        encode(&perturbed),
        baseline,
        "severity perturbation produced identical canonical bytes"
    );

    let mut perturbed = input.clone();
    perturbed.prev.push('~');
    assert_ne!(
        encode(&perturbed),
        baseline,
        "prev perturbation produced identical canonical bytes"
    );

    // Optional-field presence: None vs Some("") must always differ.
    // This pins the bug where a missing field could collide with an
    // empty-string field in pipe-delimited v1.
    let mut perturbed = input.clone();
    perturbed.old_hash = match input.old_hash.clone() {
        None => Some(String::new()),
        Some(_) => None,
    };
    assert_ne!(
        encode(&perturbed),
        baseline,
        "old_hash presence flip produced identical canonical bytes"
    );

    let mut perturbed = input.clone();
    perturbed.new_hash = match input.new_hash.clone() {
        None => Some(String::new()),
        Some(_) => None,
    };
    assert_ne!(
        encode(&perturbed),
        baseline,
        "new_hash presence flip produced identical canonical bytes"
    );
});
