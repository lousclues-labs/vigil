//! Random byte generation via the getrandom syscall.
//!
//! Avoids /dev/urandom fd churn under load by using the kernel CSPRNG
//! directly via the getrandom(2) syscall.

use crate::error::{Result, VigilError};

/// Generate `n` random bytes using the getrandom syscall.
#[allow(unsafe_code)]
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    // SAFETY: getrandom fills `buf` from the kernel CSPRNG. Pointer and
    // length are valid for the heap-allocated Vec. flags=0 blocks until
    // the entropy pool is seeded. A short or negative return would leave
    // the buffer partially random; the check below rejects that.
    let ret = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, n, 0) };
    if ret < 0 || ret as usize != n {
        return Err(VigilError::Daemon(format!(
            "getrandom failed: {}",
            if ret < 0 {
                std::io::Error::last_os_error().to_string()
            } else {
                format!("short read: {} of {} bytes", ret, n)
            }
        )));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_returns_requested_length() {
        let buf = random_bytes(32).unwrap();
        assert_eq!(buf.len(), 32);
        // Non-zero check (probability of all zeros is negligible).
        assert!(buf.iter().any(|&b| b != 0));
    }
}
