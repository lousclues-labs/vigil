//! Typed discriminators for non-detection records in the audit log.
//!
//! The audit log's `path` column doubles as a type discriminator for
//! records that don't correspond to a filesystem path. These are stored
//! as `"vigil:..."` strings. This enum is the single source of truth for
//! all such discriminators — bare-string usage elsewhere is forbidden
//! (enforced by test).

/// Type discriminator for non-detection records in the audit log.
///
/// Stored in the `path` column. The string value is the on-disk
/// representation; the enum is the in-memory representation.
/// All consumers (writers, queries, doctor renderers) use this
/// enum exclusively. Bare-string usage is forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditEventPath {
    OperatorAcknowledgment,
    HookFailure,
    BaselineRefreshFailure,
    AuditChainBreak,
    RetentionSweepFailure,
    DaemonDegraded,
    HooksDisable,
    HooksEnable,
    CheckCompleted,
    SelfCheck,
    TestAlert,
    Attestation,
}

impl AuditEventPath {
    /// Return the on-disk string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperatorAcknowledgment => "vigil:operator_acknowledgment",
            Self::HookFailure => "vigil:hook_failure",
            Self::BaselineRefreshFailure => "vigil:baseline_refresh_failure",
            Self::AuditChainBreak => "vigil:audit_chain_break",
            Self::RetentionSweepFailure => "vigil:retention_sweep_failure",
            Self::DaemonDegraded => "vigil:daemon_degraded",
            Self::HooksDisable => "vigil:hooks_disable",
            Self::HooksEnable => "vigil:hooks_enable",
            Self::CheckCompleted => "vigil:check_completed",
            Self::SelfCheck => "vigil:self_check",
            Self::TestAlert => "vigil:test_alert",
            Self::Attestation => "vigil://attestation",
        }
    }

    /// Build the checkpoint path string for a given sequence range.
    pub fn checkpoint_path(first_seq: i64, last_seq: i64) -> String {
        format!("vigil:checkpoint:{}-{}", first_seq, last_seq)
    }

    /// Parse an on-disk string into the enum, if recognized.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "vigil:operator_acknowledgment" => Some(Self::OperatorAcknowledgment),
            "vigil:hook_failure" => Some(Self::HookFailure),
            "vigil:baseline_refresh_failure" => Some(Self::BaselineRefreshFailure),
            "vigil:audit_chain_break" => Some(Self::AuditChainBreak),
            "vigil:retention_sweep_failure" => Some(Self::RetentionSweepFailure),
            "vigil:daemon_degraded" => Some(Self::DaemonDegraded),
            "vigil:hooks_disable" => Some(Self::HooksDisable),
            "vigil:hooks_enable" => Some(Self::HooksEnable),
            "vigil:check_completed" => Some(Self::CheckCompleted),
            "vigil:self_check" => Some(Self::SelfCheck),
            "vigil:test_alert" => Some(Self::TestAlert),
            "vigil://attestation" => Some(Self::Attestation),
            _ => None,
        }
    }
}

impl std::fmt::Display for AuditEventPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_path_round_trip() {
        let variants = [
            AuditEventPath::OperatorAcknowledgment,
            AuditEventPath::HookFailure,
            AuditEventPath::BaselineRefreshFailure,
            AuditEventPath::AuditChainBreak,
            AuditEventPath::RetentionSweepFailure,
            AuditEventPath::DaemonDegraded,
            AuditEventPath::HooksDisable,
            AuditEventPath::HooksEnable,
            AuditEventPath::CheckCompleted,
            AuditEventPath::SelfCheck,
            AuditEventPath::TestAlert,
            AuditEventPath::Attestation,
        ];

        for variant in variants {
            let s = variant.as_str();
            let parsed = AuditEventPath::parse(s)
                .unwrap_or_else(|| panic!("from_str failed for {:?} ({})", variant, s));
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn audit_event_path_strings_match_pre_15_format() {
        assert_eq!(
            AuditEventPath::OperatorAcknowledgment.as_str(),
            "vigil:operator_acknowledgment"
        );
        assert_eq!(AuditEventPath::HookFailure.as_str(), "vigil:hook_failure");
        assert_eq!(
            AuditEventPath::BaselineRefreshFailure.as_str(),
            "vigil:baseline_refresh_failure"
        );
        assert_eq!(
            AuditEventPath::AuditChainBreak.as_str(),
            "vigil:audit_chain_break"
        );
        assert_eq!(
            AuditEventPath::RetentionSweepFailure.as_str(),
            "vigil:retention_sweep_failure"
        );
        assert_eq!(
            AuditEventPath::DaemonDegraded.as_str(),
            "vigil:daemon_degraded"
        );
        assert_eq!(AuditEventPath::HooksDisable.as_str(), "vigil:hooks_disable");
        assert_eq!(AuditEventPath::HooksEnable.as_str(), "vigil:hooks_enable");
        assert_eq!(
            AuditEventPath::CheckCompleted.as_str(),
            "vigil:check_completed"
        );
        assert_eq!(AuditEventPath::SelfCheck.as_str(), "vigil:self_check");
        assert_eq!(AuditEventPath::TestAlert.as_str(), "vigil:test_alert");
    }

    #[test]
    fn audit_event_path_from_str_returns_none_for_unknown() {
        assert!(AuditEventPath::parse("vigil:unknown").is_none());
        assert!(AuditEventPath::parse("not-vigil").is_none());
        assert!(AuditEventPath::parse("").is_none());
    }
}
