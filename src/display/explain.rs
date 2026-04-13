use std::path::Path;

use crate::types::Change;

/// Produce a human-readable explanation of why a change matters.
/// Structural inference only — no heuristics (Principle III).
/// Returns `None` if no specific explanation applies beyond the raw change data.
pub fn explain(change: &Change, path: &Path) -> Option<String> {
    let path_str = path.to_string_lossy();

    match change {
        Change::PermissionsChanged { old, new } => explain_permission_change(*old, *new),

        Change::ContentModified { .. } => explain_content_change(&path_str),

        Change::OwnerChanged {
            old_uid,
            new_uid,
            old_gid: _,
            new_gid: _,
        } => {
            if *old_uid == 0 && *new_uid != 0 && path_str.starts_with("/usr/") {
                Some("system binary ownership changed to non-root".into())
            } else if *old_uid != 0 && *new_uid == 0 {
                Some("ownership changed to root".into())
            } else {
                None
            }
        }

        Change::CapabilitiesChanged { old, new } => {
            let had_caps = old.is_some();
            let has_caps = new.is_some();
            if !had_caps && has_caps {
                Some("file capabilities added (privilege escalation surface)".into())
            } else if had_caps && !has_caps {
                Some("file capabilities removed".into())
            } else {
                Some("file capabilities modified (privilege escalation surface)".into())
            }
        }

        Change::Deleted => {
            if path_str.starts_with("/usr/bin/") || path_str.starts_with("/usr/sbin/") {
                Some("system binary removed".into())
            } else {
                None
            }
        }

        Change::Created => {
            if path_str.starts_with("/usr/bin/") || path_str.starts_with("/usr/sbin/") {
                Some("new binary in system path".into())
            } else {
                None
            }
        }

        Change::SecurityContextChanged { .. } => {
            Some("mandatory access control label changed".into())
        }

        _ => None,
    }
}

/// Explain a permission mode change.
fn explain_permission_change(old: u32, new: u32) -> Option<String> {
    let old_setuid = old & 0o4000 != 0;
    let new_setuid = new & 0o4000 != 0;
    let old_setgid = old & 0o2000 != 0;
    let new_setgid = new & 0o2000 != 0;
    let old_world_writable = old & 0o002 != 0;
    let new_world_writable = new & 0o002 != 0;

    if !old_setuid && new_setuid {
        return Some("setuid bit added — investigate".into());
    }
    if old_setuid && !new_setuid {
        return Some("setuid bit removed".into());
    }
    if !old_setgid && new_setgid {
        return Some("setgid bit added".into());
    }
    if old_setgid && !new_setgid {
        return Some("setgid bit removed".into());
    }
    if !old_world_writable && new_world_writable {
        return Some("file became world-writable".into());
    }
    if old_world_writable && !new_world_writable {
        return Some("world-writable permission removed".into());
    }
    None
}

/// Explain a content change based on path context.
fn explain_content_change(path: &str) -> Option<String> {
    // Exact high-value file matches
    if path == "/etc/shadow" || path == "/etc/shadow-" {
        return Some("authentication credentials changed".into());
    }
    if path == "/etc/passwd" || path == "/etc/passwd-" {
        return Some("user accounts modified".into());
    }
    if path == "/etc/group" || path == "/etc/group-" {
        return Some("group membership modified".into());
    }
    if path == "/etc/sudoers" || path.starts_with("/etc/sudoers.d/") {
        return Some("privilege escalation rules modified".into());
    }
    if path == "/etc/pam.d" || path.starts_with("/etc/pam.d/") {
        return Some("authentication module configuration changed".into());
    }

    // Path-pattern matches
    if path.ends_with("/authorized_keys") || path.ends_with("/authorized_keys2") {
        return Some("SSH authorized keys changed".into());
    }
    if path.ends_with("/sshd_config") {
        return Some("SSH daemon configuration changed".into());
    }
    if path.contains("/.ssh/") && (path.ends_with("_key") || path.ends_with(".pub")) {
        return Some("SSH key material changed".into());
    }
    if path.contains("/.gnupg/") {
        return Some("GPG keyring modified".into());
    }
    if path.starts_with("/etc/cron") || path.starts_with("/var/spool/cron") {
        return Some("scheduled task configuration modified".into());
    }
    if path.starts_with("/etc/systemd/") && path.ends_with(".service") {
        return Some("systemd service unit modified".into());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn setuid_added() {
        let change = Change::PermissionsChanged {
            old: 0o100755,
            new: 0o104755,
        };
        let result = explain(&change, Path::new("/usr/bin/test"));
        assert_eq!(result.unwrap(), "setuid bit added — investigate");
    }

    #[test]
    fn setuid_removed() {
        let change = Change::PermissionsChanged {
            old: 0o104755,
            new: 0o100755,
        };
        let result = explain(&change, Path::new("/usr/bin/sudo"));
        assert_eq!(result.unwrap(), "setuid bit removed");
    }

    #[test]
    fn world_writable() {
        let change = Change::PermissionsChanged {
            old: 0o100644,
            new: 0o100666,
        };
        let result = explain(&change, Path::new("/etc/config"));
        assert_eq!(result.unwrap(), "file became world-writable");
    }

    #[test]
    fn shadow_content() {
        let change = Change::ContentModified {
            old_hash: "aaa".into(),
            new_hash: "bbb".into(),
        };
        let result = explain(&change, Path::new("/etc/shadow"));
        assert_eq!(result.unwrap(), "authentication credentials changed");
    }

    #[test]
    fn ssh_authorized_keys() {
        let change = Change::ContentModified {
            old_hash: "aaa".into(),
            new_hash: "bbb".into(),
        };
        let result = explain(&change, &PathBuf::from("/home/user/.ssh/authorized_keys"));
        assert_eq!(result.unwrap(), "SSH authorized keys changed");
    }

    #[test]
    fn capabilities_added() {
        let change = Change::CapabilitiesChanged {
            old: None,
            new: Some("cap_net_admin".into()),
        };
        let result = explain(&change, Path::new("/usr/bin/test"));
        assert_eq!(
            result.unwrap(),
            "file capabilities added (privilege escalation surface)"
        );
    }

    #[test]
    fn owner_changed_from_root() {
        let change = Change::OwnerChanged {
            old_uid: 0,
            new_uid: 1000,
            old_gid: 0,
            new_gid: 1000,
        };
        let result = explain(&change, Path::new("/usr/bin/sudo"));
        assert_eq!(
            result.unwrap(),
            "system binary ownership changed to non-root"
        );
    }

    #[test]
    fn no_explanation_for_simple_content() {
        let change = Change::ContentModified {
            old_hash: "aaa".into(),
            new_hash: "bbb".into(),
        };
        let result = explain(&change, Path::new("/opt/myapp/config.toml"));
        assert!(result.is_none());
    }

    #[test]
    fn no_explanation_for_owner_in_non_system_path() {
        let change = Change::OwnerChanged {
            old_uid: 0,
            new_uid: 1000,
            old_gid: 0,
            new_gid: 1000,
        };
        let result = explain(&change, Path::new("/home/user/file"));
        assert!(result.is_none());
    }
}
