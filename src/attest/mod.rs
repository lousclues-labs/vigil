//! Portable attestation files (.vatt) for offline integrity verification.
//!
//! Submodules handle creation, verification, diffing, key management,
//! and CBOR wire format. Verification depends only on BLAKE3 and the
//! signing key -- no daemon, no database, no config required.

pub mod create;
pub mod diff;
pub mod error;
pub mod format;
pub mod key;
pub mod list;
pub mod show;
pub mod verify;
