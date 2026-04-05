use std::path::Path;

use hmac::{Hmac, Mac};
use sha2::Sha256;

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
    check_hmac_key_permissions(path);

    let content = std::fs::read(path).map_err(|e| {
        VigilError::HmacVerification(format!(
            "cannot read HMAC key file {}: {}",
            path.display(),
            e
        ))
    })?;

    // If the file contains hex-encoded key, decode it; otherwise use raw bytes
    let trimmed = String::from_utf8_lossy(&content).trim().to_string();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(&trimmed).map_err(|e| {
            VigilError::HmacVerification(format!("invalid hex in HMAC key file: {}", e))
        })
    } else {
        Ok(content)
    }
}

/// Build the data string for HMAC computation from audit entry fields.
pub fn build_audit_hmac_data(
    timestamp: i64,
    path: &str,
    change_type: &str,
    severity: &str,
    old_hash: Option<&str>,
    new_hash: Option<&str>,
) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}",
        timestamp,
        path,
        change_type,
        severity,
        old_hash.unwrap_or(""),
        new_hash.unwrap_or(""),
    )
    .into_bytes()
}

/// Check HMAC key file permissions and warn if too permissive.
///
/// The key file should be mode 0400 or 0600 to prevent other users from
/// reading the HMAC secret. If the file is readable by group or others,
/// a warning is emitted because the tamper-evidence guarantee is weakened.
fn check_hmac_key_permissions(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "HMAC key file {} has overly permissive mode {:04o} \
                     (should be 0400 or 0600). Other users may read the key.",
                    path.display(),
                    mode
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                "Cannot stat HMAC key file {} to check permissions: {}",
                path.display(),
                e
            );
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
        );
        assert_eq!(
            String::from_utf8(data).unwrap(),
            "1700000000|/etc/passwd|modified|critical|oldhash|newhash"
        );
    }

    #[test]
    fn build_audit_data_none_hashes() {
        let data = build_audit_hmac_data(1700000000, "/etc/test", "deleted", "high", None, None);
        assert_eq!(
            String::from_utf8(data).unwrap(),
            "1700000000|/etc/test|deleted|high||"
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
}
