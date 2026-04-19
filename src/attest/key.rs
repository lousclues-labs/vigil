//! Attestation signing key management.
//!
//! The attestation key is distinct from the audit chain HMAC key:
//! - The audit chain HMAC key signs the live audit chain on this host.
//! - The attestation signing key signs portable artifacts designed to leave the host.
//! - Compromise of one does not compromise the other.
//!
//! Key file format: 1 byte version tag (0x01 = HMAC-BLAKE3), then 32 bytes of key material.
//! The `signing_key_id` is the first 8 bytes of BLAKE3("vigil-attest-key-id-v1" || key).

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::error::{AttestError, AttestResult};

/// Version tag for HMAC-BLAKE3 attestation keys.
const KEY_VERSION_HMAC_BLAKE3: u8 = 0x01;

/// Total key file size: 1 version byte + 32 key bytes.
const KEY_FILE_SIZE: usize = 33;

/// Domain separation string for key ID derivation.
const KEY_ID_DOMAIN: &[u8] = b"vigil-attest-key-id-v1";

/// Load an attestation signing key from file.
///
/// Returns `(key_material, signing_key_id)`.
pub fn load_attest_key(path: &Path) -> AttestResult<(Zeroizing<Vec<u8>>, [u8; 8])> {
    check_key_permissions(path)?;

    let data = std::fs::read(path).map_err(|e| {
        AttestError::KeyNotFound(format!(
            "cannot read attestation key {}: {}",
            path.display(),
            e
        ))
    })?;

    if data.len() != KEY_FILE_SIZE {
        return Err(AttestError::InvalidFormat(format!(
            "attestation key file has wrong size ({} bytes, expected {})",
            data.len(),
            KEY_FILE_SIZE
        )));
    }

    if data[0] != KEY_VERSION_HMAC_BLAKE3 {
        return Err(AttestError::InvalidFormat(format!(
            "unsupported attestation key version: 0x{:02x}",
            data[0]
        )));
    }

    let key = Zeroizing::new(data[1..].to_vec());
    let key_id = derive_key_id(&key);
    Ok((key, key_id))
}

/// Generate a new attestation signing key and write it to `path`.
///
/// The key file is written with mode 0600 and consists of:
///   - 1 byte: version tag (0x01 for HMAC-BLAKE3)
///   - 32 bytes: CSPRNG output
pub fn generate_attest_key(path: &Path) -> AttestResult<[u8; 8]> {
    use std::io::Read;

    let mut key_bytes = Zeroizing::new([0u8; 32]);
    {
        let mut urandom = std::fs::File::open("/dev/urandom")?;
        urandom.read_exact(key_bytes.as_mut())?;
    }

    let mut file_bytes = vec![KEY_VERSION_HMAC_BLAKE3];
    file_bytes.extend_from_slice(key_bytes.as_ref());

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Atomic write: write to tmp, fsync, rename
    let tmp_path = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(&file_bytes)?;
        f.sync_all()?;
    }

    // Set permissions to 0600 before rename
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;

    std::fs::rename(&tmp_path, path)?;

    let key_id = derive_key_id(key_bytes.as_ref());
    Ok(key_id)
}

/// Derive the signing key ID: first 8 bytes of BLAKE3(domain || key).
pub fn derive_key_id(key: &[u8]) -> [u8; 8] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(key);
    let hash = hasher.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&hash.as_bytes()[..8]);
    id
}

/// Compute HMAC-BLAKE3 signature over a content hash.
pub fn sign_hmac_blake3(key: &[u8], content_hash: &[u8; 32]) -> Vec<u8> {
    let sig_key = blake3::derive_key("vigil-attest-sign-v1", key);
    let mut hasher = blake3::Hasher::new_keyed(&sig_key);
    hasher.update(content_hash);
    hasher.finalize().as_bytes().to_vec()
}

/// Verify HMAC-BLAKE3 signature over a content hash.
pub fn verify_hmac_blake3(key: &[u8], content_hash: &[u8; 32], signature: &[u8]) -> bool {
    let expected = sign_hmac_blake3(key, content_hash);
    constant_time_eq::constant_time_eq(&expected, signature)
}

/// Format a signing key ID as colon-separated hex for display.
pub fn format_key_id(id: &[u8; 8]) -> String {
    id.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Search for attestation key in standard locations.
/// Returns the first found path, or None.
pub fn find_attest_key() -> Option<PathBuf> {
    let candidates = attest_key_search_paths();
    candidates.into_iter().find(|p| p.exists())
}

/// Default attestation key search paths (highest priority first).
pub fn attest_key_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/vigil/attest.key")];
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".config/vigil/attest.key"));
    }
    paths
}

fn check_key_permissions(path: &Path) -> AttestResult<()> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                #[cfg(not(any(test, debug_assertions)))]
                {
                    return Err(AttestError::Other(format!(
                        "attestation key file {} has unsafe permissions {:04o} \
                         (must be 0600 or more restrictive). \
                         Fix with: sudo chmod 600 {}",
                        path.display(),
                        mode,
                        path.display()
                    )));
                }
                #[cfg(any(test, debug_assertions))]
                {
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:04o}", mode),
                        "attestation key file has permissive permissions"
                    );
                }
            }
            Ok(())
        }
        Err(e) => Err(AttestError::KeyNotFound(format!(
            "cannot stat attestation key file {}: {}",
            path.display(),
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_and_load_key() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("attest.key");

        let key_id = generate_attest_key(&key_path).unwrap();
        assert_ne!(key_id, [0u8; 8]);

        let (key, loaded_id) = load_attest_key(&key_path).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(key_id, loaded_id);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = vec![0x42u8; 32];
        let content_hash = [0xaa; 32];
        let sig = sign_hmac_blake3(&key, &content_hash);
        assert!(verify_hmac_blake3(&key, &content_hash, &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key = vec![0x42u8; 32];
        let wrong_key = vec![0x43u8; 32];
        let content_hash = [0xaa; 32];
        let sig = sign_hmac_blake3(&key, &content_hash);
        assert!(!verify_hmac_blake3(&wrong_key, &content_hash, &sig));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let key = vec![0x42u8; 32];
        let content_hash = [0xaa; 32];
        let mut sig = sign_hmac_blake3(&key, &content_hash);
        sig[0] ^= 0xff;
        assert!(!verify_hmac_blake3(&key, &content_hash, &sig));
    }

    #[test]
    fn key_id_format() {
        let id = [0x3a, 0x7b, 0xc2, 0x01, 0x9f, 0xe2, 0x11, 0x84];
        assert_eq!(format_key_id(&id), "3a:7b:c2:01:9f:e2:11:84");
    }

    #[test]
    fn key_id_is_deterministic() {
        let key = vec![0x55u8; 32];
        let id1 = derive_key_id(&key);
        let id2 = derive_key_id(&key);
        assert_eq!(id1, id2);
    }

    #[test]
    fn reject_wrong_version_tag() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("attest.key");
        let mut data = vec![0x99]; // wrong version
        data.extend_from_slice(&[0u8; 32]);
        std::fs::write(&key_path, &data).unwrap();

        let result = load_attest_key(&key_path);
        assert!(result.is_err());
    }

    #[test]
    fn reject_wrong_file_size() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("attest.key");
        std::fs::write(&key_path, [0x01, 0x00]).unwrap();

        let result = load_attest_key(&key_path);
        assert!(result.is_err());
    }
}
