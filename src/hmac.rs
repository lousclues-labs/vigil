use std::path::Path;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Result, VigilError};

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 over data using the provided key.
pub fn compute_hmac(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Verify HMAC-SHA256: recompute and compare against expected.
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &str) -> bool {
    // Constant-time comparison via the hmac crate
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let expected_bytes = match hex::decode(expected) {
        Ok(b) => b,
        Err(_) => return false,
    };
    mac.verify_slice(&expected_bytes).is_ok()
}

/// Load HMAC key from a file. The key file should contain raw bytes or hex-encoded key.
pub fn load_hmac_key(path: &Path) -> Result<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_roundtrip() {
        let key = b"test-secret-key-for-vigil";
        let data = b"1700000000|/etc/passwd|modified|critical|oldhash|newhash";

        let hmac_str = compute_hmac(key, data);
        assert!(verify_hmac(key, data, &hmac_str));
    }

    #[test]
    fn hmac_wrong_key_fails() {
        let key = b"correct-key";
        let wrong_key = b"wrong-key";
        let data = b"test data";

        let hmac_str = compute_hmac(key, data);
        assert!(!verify_hmac(wrong_key, data, &hmac_str));
    }

    #[test]
    fn hmac_wrong_data_fails() {
        let key = b"test-key";
        let data = b"original data";
        let tampered = b"tampered data";

        let hmac_str = compute_hmac(key, data);
        assert!(!verify_hmac(key, tampered, &hmac_str));
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
}
