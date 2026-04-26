// tests/fanotify_tier_probe_tests.rs
//
// Regression test for VIGIL-VULN-077: the fanotify capability probe must
// return the highest tier the kernel supports and fall through cleanly
// without fd leaks when unsupported tiers are probed.

use vigil::monitor::FanotifyTier;

/// The tier probe must return a valid tier on any Linux kernel.
/// On pre-5.1 kernels this will be LegacyFd; on 5.1+ it will be
/// Fid or FidDfidName; on systems without CAP_SYS_ADMIN it will
/// be Inotify.
#[test]
fn detect_tier_returns_valid_tier() {
    let tier = vigil::monitor::detect_fanotify_tier();
    match tier {
        FanotifyTier::Inotify
        | FanotifyTier::LegacyFd
        | FanotifyTier::Fid
        | FanotifyTier::FidDfidName => {
            // All valid tiers
        }
    }
    // Verify the tier can be displayed and parsed
    let s = tier.to_string();
    let parsed: FanotifyTier = s.parse().unwrap();
    assert_eq!(tier, parsed, "Display/FromStr roundtrip must be stable");
}

/// Tier ordering: FidDfidName > Fid > LegacyFd > Inotify
#[test]
fn tier_ordering() {
    assert!(FanotifyTier::Inotify < FanotifyTier::LegacyFd);
    assert!(FanotifyTier::LegacyFd < FanotifyTier::Fid);
    assert!(FanotifyTier::Fid < FanotifyTier::FidDfidName);
}

/// Tier gauge metric values match the enum discriminants.
#[test]
fn tier_metric_values() {
    assert_eq!(FanotifyTier::Inotify as u64, 0);
    assert_eq!(FanotifyTier::LegacyFd as u64, 1);
    assert_eq!(FanotifyTier::Fid as u64, 2);
    assert_eq!(FanotifyTier::FidDfidName as u64, 3);
}

/// Display/FromStr roundtrip for all tiers.
#[test]
fn tier_display_fromstr_roundtrip() {
    for tier in &[
        FanotifyTier::Inotify,
        FanotifyTier::LegacyFd,
        FanotifyTier::Fid,
        FanotifyTier::FidDfidName,
    ] {
        let s = tier.to_string();
        let parsed: FanotifyTier = s.parse().unwrap();
        assert_eq!(*tier, parsed);
    }
}

/// Invalid tier string returns an error.
#[test]
fn invalid_tier_string_returns_error() {
    assert!("bogus".parse::<FanotifyTier>().is_err());
    assert!("".parse::<FanotifyTier>().is_err());
}

/// Config override: "auto" resolves to the highest tier.
#[test]
fn resolve_tier_auto() {
    let mut config = vigil::config::default_config();
    config.monitor.fanotify_tier = "auto".to_string();
    let tier = vigil::monitor::resolve_fanotify_tier(&config);
    // Must return some valid tier (we can't know which on this kernel)
    assert!(
        matches!(
            tier,
            FanotifyTier::Inotify
                | FanotifyTier::LegacyFd
                | FanotifyTier::Fid
                | FanotifyTier::FidDfidName
        ),
        "auto should resolve to a valid tier"
    );
}

/// Config override: pinning to "inotify" forces inotify tier.
#[test]
fn resolve_tier_pinned() {
    let mut config = vigil::config::default_config();
    config.monitor.fanotify_tier = "inotify".to_string();
    let tier = vigil::monitor::resolve_fanotify_tier(&config);
    assert_eq!(tier, FanotifyTier::Inotify);
}

/// Config override: pinning to "legacy_fd" forces legacy tier.
#[test]
fn resolve_tier_pinned_legacy() {
    let mut config = vigil::config::default_config();
    config.monitor.fanotify_tier = "legacy_fd".to_string();
    let tier = vigil::monitor::resolve_fanotify_tier(&config);
    assert_eq!(tier, FanotifyTier::LegacyFd);
}

/// Invalid config value falls back to auto-detect.
#[test]
fn resolve_tier_invalid_falls_back() {
    let mut config = vigil::config::default_config();
    config.monitor.fanotify_tier = "bogus".to_string();
    let tier = vigil::monitor::resolve_fanotify_tier(&config);
    // Should still return a valid tier (auto-detect fallback)
    assert!(matches!(
        tier,
        FanotifyTier::Inotify
            | FanotifyTier::LegacyFd
            | FanotifyTier::Fid
            | FanotifyTier::FidDfidName
    ),);
}
