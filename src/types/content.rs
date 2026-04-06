use serde::{Deserialize, Serialize};

/// Content fingerprint — hash and size of file content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ContentFingerprint {
    pub hash: String,
    pub size: u64,
}
