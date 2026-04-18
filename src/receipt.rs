use crate::db::audit_ops;
use crate::error::Result;
use crate::scanner::ScanResult;
use crate::types::ScanMode;

/// A verification receipt recording that a check was performed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CheckReceipt {
    pub started_at: i64,
    pub completed_at: i64,
    pub mode: String,
    pub paths_considered: u64,
    pub paths_hashed: u64,
    pub paths_compared: u64,
    pub paths_skipped: u64,
    pub paths_failed: u64,
    pub deviations_found: u64,
    pub receipt_hash: String,
    pub result: String,
}

impl CheckReceipt {
    /// Build a receipt from scan results.
    pub fn from_scan(
        started_at: i64,
        completed_at: i64,
        mode: ScanMode,
        result: &ScanResult,
    ) -> Self {
        let deviations = result.changes_found;
        let result_label = if deviations == 0 {
            "clean"
        } else {
            "deviations_detected"
        };

        let mode_str = match mode {
            ScanMode::Full => "full",
            ScanMode::Incremental => "incremental",
        };

        // Deterministic receipt hash over the check parameters
        let receipt_input = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            mode_str,
            result.total_checked,
            result.changes_found,
            result.errors,
            started_at,
            completed_at,
            env!("CARGO_PKG_VERSION"),
            result_label,
        );
        let receipt_hash = blake3::hash(receipt_input.as_bytes()).to_hex().to_string();

        Self {
            started_at,
            completed_at,
            mode: mode_str.to_string(),
            paths_considered: result.total_checked,
            paths_hashed: result.total_checked.saturating_sub(result.errors),
            paths_compared: result.total_checked,
            paths_skipped: 0,
            paths_failed: result.errors,
            deviations_found: deviations,
            receipt_hash,
            result: result_label.to_string(),
        }
    }

    /// Record this receipt as an audit entry.
    pub fn record(
        &self,
        conn: &rusqlite::Connection,
        previous_chain_hash: &str,
        hmac_key: Option<&[u8]>,
    ) -> Result<String> {
        let payload = serde_json::to_string(self)?;
        audit_ops::insert_receipt_entry(conn, self, &payload, previous_chain_hash, hmac_key)
    }
}
