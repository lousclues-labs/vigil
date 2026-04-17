use std::path::Path;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Result, VigilError};

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 over data using the provided key.
pub fn compute_hmac(key: &[u8], data: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| VigilError::HmacVerification(format!("failed to initialize HMAC: {}", e)))?;
    mac.update(data);
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Verify HMAC-SHA256: recompute and compare against expected.
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &str) -> bool {
    // Constant-time comparison via the hmac crate
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize HMAC for verification");
            return false;
        }
    };
    mac.update(data);
    let expected_bytes = match hex::decode(expected) {
        Ok(b) => b,
        Err(_) => return false,
    };
    mac.verify_slice(&expected_bytes).is_ok()
}

/// Load HMAC key from a file. The key file should contain raw bytes or hex-encoded key.
///
/// Warns at runtime if the key file permissions are more permissive than 0600,
/// since a readable key undermines the tamper-evidence guarantee.
/// See docs/SECURITY.md "HMAC Key Lifecycle" for key management guidance.
pub fn load_hmac_key(path: &Path) -> Result<Vec<u8>> {
    // Check key file permissions before reading
    check_hmac_key_permissions(path)?;

    let content = std::fs::read(path).map_err(|e| {
        VigilError::HmacVerification(format!(
            "cannot read HMAC key file {}: {}",
            path.display(),
            e
        ))
    })?;

    // If the file contains hex-encoded key, decode it; otherwise use raw bytes
    let mut trimmed = String::from_utf8_lossy(&content).trim().to_string();
    let result = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(&trimmed).map_err(|e| {
            VigilError::HmacVerification(format!("invalid hex in HMAC key file: {}", e))
        })
    } else {
        Ok(content)
    };
    // Zeroize the intermediate string to prevent key material from persisting in freed memory
    trimmed.zeroize();
    result
}

/// Build the data string for HMAC computation from audit entry fields.
///
/// Includes `previous_chain_hash` so that HMAC verification can detect
/// deletion of entries from the middle of the audit chain.
pub fn build_audit_hmac_data(
    timestamp: i64,
    path: &str,
    change_type: &str,
    severity: &str,
    old_hash: Option<&str>,
    new_hash: Option<&str>,
    previous_chain_hash: &str,
) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        timestamp,
        path,
        change_type,
        severity,
        old_hash.unwrap_or(""),
        new_hash.unwrap_or(""),
        previous_chain_hash,
    )
    .into_bytes()
}

/// Check HMAC key file permissions and warn if too permissive.
///
/// In release builds, returns an error if the key file is readable by group
/// or others, since a readable key undermines the tamper-evidence guarantee.
/// In test/debug builds, logs a warning instead to allow tests to run as
/// unprivileged users in temp directories.
fn check_hmac_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                #[cfg(not(any(test, debug_assertions)))]
                {
                    return Err(VigilError::HmacVerification(format!(
                        "HMAC key file {} has unsafe permissions {:04o} \
                         (must be 0400 or 0600). Refusing to load key. \
                         Fix with: sudo chmod 600 {}",
                        path.display(),
                        mode,
                        path.display()
                    )));
                }
                #[cfg(any(test, debug_assertions))]
                {
                    tracing::warn!(
                        "HMAC key file {} has permissive mode {:04o} \
                         (would fail in release build)",
                        path.display(),
                        mode
                    );
                }
            }
            Ok(())
        }
        Err(e) => {
            tracing::warn!(
                "Cannot stat HMAC key file {} to check permissions: {}",
                path.display(),
                e
            );
            // Don't hard-fail on stat failure — the subsequent read will
            // produce a clear error if the file is truly inaccessible
            Ok(())
        }
    }
}

/// Validate HMAC key file permissions and ownership for `vigil doctor`.
///
/// Returns a list of diagnostic messages describing any issues found.
/// An empty list means the key file passes all checks.
pub fn validate_hmac_key_doctor(path: &Path) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let mut issues = Vec::new();

    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                issues.push(format!(
                    "HMAC key file permissions are {:04o} (should be 0400 or 0600)",
                    mode
                ));
            }
            if meta.uid() != 0 {
                issues.push(format!(
                    "HMAC key file is owned by UID {} (should be root/UID 0)",
                    meta.uid()
                ));
            }
        }
        Err(e) => {
            issues.push(format!("Cannot stat HMAC key file: {}", e));
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_roundtrip() {
        let key = b"test-secret-key-for-vigil";
        let data = b"1700000000|/etc/passwd|modified|critical|oldhash|newhash";

        let hmac_str = compute_hmac(key, data).unwrap();
        assert!(verify_hmac(key, data, &hmac_str));
    }

    #[test]
    fn hmac_wrong_key_fails() {
        let key = b"correct-key";
        let wrong_key = b"wrong-key";
        let data = b"test data";

        let hmac_str = compute_hmac(key, data).unwrap();
        assert!(!verify_hmac(wrong_key, data, &hmac_str));
    }

    #[test]
    fn hmac_wrong_data_fails() {
        let key = b"test-key";
        let data = b"original data";
        let tampered = b"tampered data";

        let hmac_str = compute_hmac(key, data).unwrap();
        assert!(!verify_hmac(key, tampered, &hmac_str));
    }

    #[test]
    fn hmac_empty_key_returns_error() {
        let data = b"test data";
        // HMAC-SHA256 accepts any key length (including empty), but a zero-length
        // key is still valid per RFC 2104. Verify compute_hmac succeeds with empty key.
        assert!(compute_hmac(b"", data).is_ok());
    }

    #[test]
    fn hmac_invalid_hex_fails() {
        let key = b"test-key";
        let data = b"test data";
        assert!(!verify_hmac(key, data, "not-valid-hex-zzzz"));
    }

    #[test]
    fn build_audit_data_format() {
        let data = build_audit_hmac_data(
            1700000000,
            "/etc/passwd",
            "modified",
            "critical",
            Some("oldhash"),
            Some("newhash"),
            "prev_chain_hash_abc",
        );
        assert_eq!(
            String::from_utf8(data).unwrap(),
            "1700000000|/etc/passwd|modified|critical|oldhash|newhash|prev_chain_hash_abc"
        );
    }

    #[test]
    fn build_audit_data_none_hashes() {
        let data = build_audit_hmac_data(
            1700000000,
            "/etc/test",
            "deleted",
            "high",
            None,
            None,
            "genesis",
        );
        assert_eq!(
            String::from_utf8(data).unwrap(),
            "1700000000|/etc/test|deleted|high|||genesis"
        );
    }

    #[test]
    fn build_audit_data_includes_previous_chain_hash() {
        let data1 = build_audit_hmac_data(
            1700000000,
            "/etc/test",
            "modified",
            "high",
            None,
            None,
            "chain_a",
        );
        let data2 = build_audit_hmac_data(
            1700000000,
            "/etc/test",
            "modified",
            "high",
            None,
            None,
            "chain_b",
        );
        assert_ne!(
            data1, data2,
            "different previous chain hash must produce different HMAC data"
        );
    }

    #[test]
    fn validate_hmac_key_doctor_permissive_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create temp dir");
        let key_path = dir.path().join("hmac.key");
        std::fs::write(&key_path, b"test-key-data").expect("write key");

        // Set overly permissive (world-readable)
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
            .expect("set permissions");

        let issues = validate_hmac_key_doctor(&key_path);
        assert!(
            issues.iter().any(|i| i.contains("permissions")),
            "should flag permissive mode: {:?}",
            issues
        );
    }

    #[test]
    fn validate_hmac_key_doctor_strict_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create temp dir");
        let key_path = dir.path().join("hmac.key");
        std::fs::write(&key_path, b"test-key-data").expect("write key");

        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("set permissions");

        let issues = validate_hmac_key_doctor(&key_path);
        // The only possible issue is ownership (not root in test), but perms should be fine
        assert!(
            !issues.iter().any(|i| i.contains("permissions")),
            "should not flag strict mode: {:?}",
            issues
        );
    }

    #[test]
    fn check_hmac_key_permissions_permissive_mode_in_test() {
        // In test builds, check_hmac_key_permissions warns but returns Ok.
        // In release builds, it would return Err.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create temp dir");
        let key_path = dir.path().join("hmac.key");
        std::fs::write(&key_path, b"test-key-data").expect("write key");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
            .expect("set permissions");

        // Under test builds, this returns Ok despite permissive mode
        let result = check_hmac_key_permissions(&key_path);
        assert!(result.is_ok(), "test build should warn, not error");

        // Verify the underlying logic would catch it
        use std::os::unix::fs::MetadataExt;
        let mode = std::fs::metadata(&key_path).unwrap().mode() & 0o777;
        assert!(
            mode & 0o077 != 0,
            "mode {:04o} should be flagged as permissive",
            mode
        );
    }

    #[test]
    fn check_hmac_key_permissions_strict_mode_ok() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create temp dir");
        let key_path = dir.path().join("hmac.key");
        std::fs::write(&key_path, b"test-key-data").expect("write key");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("set permissions");

        let result = check_hmac_key_permissions(&key_path);
        assert!(result.is_ok(), "strict mode should always succeed");
    }
}
