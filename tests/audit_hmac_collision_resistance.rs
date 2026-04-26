// tests/audit_hmac_collision_resistance.rs
//
// Regression test for VIGIL-VULN-076: the v1 pipe-delimited HMAC format
// could produce collisions when paths contained the `|` delimiter.
// The v2 canonical CBOR encoding must be immune to delimiter injection.

use proptest::prelude::*;

// proptest: no two distinct v2 input tuples produce the same HMAC input bytes.
// Tests paths containing `|`, `\n`, and various delimiters.
proptest! {
    #[test]
    fn v2_hmac_no_collision(
        ts1 in 1_000_000_000i64..2_000_000_000i64,
        ts2 in 1_000_000_000i64..2_000_000_000i64,
        path1 in "[/a-z|\\n]{1,30}",
        path2 in "[/a-z|\\n]{1,30}",
        change1 in "[a-z|_]{1,15}",
        change2 in "[a-z|_]{1,15}",
        sev1 in prop::sample::select(vec!["low", "medium", "high", "critical"]),
        sev2 in prop::sample::select(vec!["low", "medium", "high", "critical"]),
        old1 in prop::option::of("[a-f0-9]{8}"),
        old2 in prop::option::of("[a-f0-9]{8}"),
        new1 in prop::option::of("[a-f0-9]{8}"),
        new2 in prop::option::of("[a-f0-9]{8}"),
        prev1 in "[a-f0-9]{16}",
        prev2 in "[a-f0-9]{16}",
    ) {
        let tuple1 = (ts1, &path1, &change1, &sev1, &old1, &new1, &prev1);
        let tuple2 = (ts2, &path2, &change2, &sev2, &old2, &new2, &prev2);

        // If all fields are equal, bytes must be equal; if any differ, bytes must differ
        if tuple1 != tuple2 {
            let data1 = vigil::hmac::build_audit_hmac_data_v2(
                ts1, &path1, &change1, sev1,
                old1.as_deref(), new1.as_deref(), &prev1,
            );
            let data2 = vigil::hmac::build_audit_hmac_data_v2(
                ts2, &path2, &change2, sev2,
                old2.as_deref(), new2.as_deref(), &prev2,
            );
            prop_assert_ne!(data1, data2, "distinct tuples must produce distinct CBOR bytes");
        }
    }
}

/// Demonstrate the v1 collision: two distinct inputs produce identical v1 bytes.
#[test]
fn v1_collision_demonstrated() {
    // Path "/etc/foo|bar" with change_type "modified" should NOT equal
    // path "/etc/foo" with change_type "bar|modified" — but in v1 it does.
    let data_a = vigil::hmac::build_audit_hmac_data(
        1700000000,
        "/etc/foo|bar",
        "modified",
        "high",
        None,
        None,
        "genesis",
    );
    let data_b = vigil::hmac::build_audit_hmac_data(
        1700000000,
        "/etc/foo",
        "bar|modified",
        "high",
        None,
        None,
        "genesis",
    );
    // v1 COLLIDES — this proves the bug existed
    assert_eq!(
        data_a, data_b,
        "v1 pipe format should collide (proving the vulnerability)"
    );
}

/// Confirm v2 is immune to the same collision.
#[test]
fn v2_immune_to_v1_collision() {
    let data_a = vigil::hmac::build_audit_hmac_data_v2(
        1700000000,
        "/etc/foo|bar",
        "modified",
        "high",
        None,
        None,
        "genesis",
    );
    let data_b = vigil::hmac::build_audit_hmac_data_v2(
        1700000000,
        "/etc/foo",
        "bar|modified",
        "high",
        None,
        None,
        "genesis",
    );
    assert_ne!(
        data_a, data_b,
        "v2 CBOR format must NOT collide on pipe-containing paths"
    );
}

/// NUL bytes in paths are rejected by the filesystem but encoded correctly
/// by CBOR (byte string, not text).
#[test]
fn v2_handles_embedded_nul() {
    // Paths with NUL bytes don't exist on Linux, but the encoder must not panic
    let data = vigil::hmac::build_audit_hmac_data_v2(
        1700000000,
        "/etc/test\x00evil",
        "modified",
        "high",
        None,
        None,
        "genesis",
    );
    assert!(!data.is_empty(), "encoder should not panic on NUL bytes");
}
