//! Architecture invariant tests for structural rules established in 1.5.0.
//!
//! These tests enforce the rules documented in docs/ARCHITECTURE.md.
//! They are compile-time-free and run as part of the normal test suite.

use std::fs;
use std::path::Path;

/// Count non-comment, non-blank lines in a Rust source file.
fn code_lines(path: &Path) -> usize {
    let content = fs::read_to_string(path).expect("read source file");
    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with("//")
        })
        .count()
}

/// Collect all .rs files under a directory recursively.
fn collect_rs_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if !dir.is_dir() {
        return files;
    }
    for entry in fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_rs_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files
}

#[test]
fn no_source_file_exceeds_line_limit() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = collect_rs_files(&src);
    assert!(!files.is_empty(), "should find source files");

    // Coordinator has a higher limit due to guardian+maintenance thread dual-loop
    // structure and control socket self-check (1.11.0). See E.4 in release notes.
    let exceptions: &[(&str, usize)] = &[("coordinator/mod.rs", 1900)];

    let limit = 1500;
    let mut violations = Vec::new();

    for file in &files {
        let lines = code_lines(file);
        let rel = file
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(file)
            .display()
            .to_string();
        let rel_path = rel.trim_start_matches('/');

        // Check if this file has an exception with a higher limit
        let effective_limit = exceptions
            .iter()
            .find(|(p, _)| rel_path.ends_with(p))
            .map(|(_, l)| *l)
            .unwrap_or(limit);

        if lines > effective_limit {
            violations.push(format!(
                "{}: {} lines (limit {})",
                rel_path, lines, effective_limit
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "source files exceed line limit:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn no_bare_audit_discriminator_strings_outside_audit_path() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = manifest_dir.join("src");
    let files = collect_rs_files(&src);

    // The canonical location for discriminator strings
    let canonical = "src/db/audit_path.rs";

    // Known exceptions: these files construct discriminators from
    // AuditEventPath or use checkpoint format strings that contain
    // dynamic segments not representable as enum variants.
    let exceptions: &[&str] = &[
        // None — all bare strings have been replaced with AuditEventPath usage.
    ];

    let mut violations = Vec::new();

    for file in &files {
        let rel = file
            .strip_prefix(manifest_dir)
            .unwrap_or(file)
            .display()
            .to_string();
        let rel_path = rel.trim_start_matches('/');

        if rel_path.ends_with(canonical) {
            continue;
        }
        if exceptions.iter().any(|e| rel_path.ends_with(e)) {
            continue;
        }

        let content = fs::read_to_string(file).expect("read file");
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            // Skip comments
            if trimmed.starts_with("//") {
                continue;
            }
            if line.contains("\"vigil:") {
                violations.push(format!("{}:{}: {}", rel_path, i + 1, trimmed));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "bare \"vigil:\" discriminator strings found outside {}:\n  {}",
        canonical,
        violations.join("\n  ")
    );
}

#[test]
fn cross_module_import_rules() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Rule: doctor/ must NOT import from commands/
    check_no_import(manifest_dir, "src/doctor", "use crate::commands");

    // Rule: coordinator/ must NOT import from commands/ or doctor/
    check_no_import(manifest_dir, "src/coordinator", "use crate::commands");
    check_no_import(manifest_dir, "src/coordinator", "use crate::doctor");

    // Rule: util/ must NOT import from feature modules
    for forbidden in &[
        "use crate::commands",
        "use crate::doctor",
        "use crate::coordinator",
        "use crate::control",
        "use crate::wal",
    ] {
        check_no_import(manifest_dir, "src/util", forbidden);
    }

    // Rule: display/ must NOT import from feature modules
    for forbidden in &[
        "use crate::commands",
        "use crate::doctor",
        "use crate::coordinator",
        "use crate::control",
        "use crate::wal",
    ] {
        check_no_import(manifest_dir, "src/display", forbidden);
    }
}

fn check_no_import(manifest_dir: &Path, dir: &str, pattern: &str) {
    let dir_path = manifest_dir.join(dir);
    let files = collect_rs_files(&dir_path);

    let mut violations = Vec::new();

    for file in &files {
        let content = fs::read_to_string(file).expect("read file");
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.contains(pattern) {
                let rel = file
                    .strip_prefix(manifest_dir)
                    .unwrap_or(file)
                    .display()
                    .to_string();
                violations.push(format!("{}:{}: {}", rel, i + 1, trimmed));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "forbidden import '{}' in {}:\n  {}",
        pattern,
        dir,
        violations.join("\n  ")
    );
}

#[test]
fn lib_rs_is_module_declarations_only() {
    let lib_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let lines = code_lines(&lib_path);
    assert!(
        lines < 200,
        "src/lib.rs should be <200 lines of code, got {}",
        lines
    );
}

#[test]
fn ack_rs_is_reexport_shim() {
    let ack_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ack.rs");
    let content = fs::read_to_string(&ack_path).expect("read ack.rs");
    let total_lines = content.lines().count();
    assert!(
        total_lines < 50,
        "src/ack.rs should be <50 lines, got {}",
        total_lines
    );

    // Should contain no function/struct/enum definitions (only pub use)
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.is_empty() {
            continue;
        }
        assert!(
            !trimmed.starts_with("pub fn ")
                && !trimmed.starts_with("fn ")
                && !trimmed.starts_with("pub struct ")
                && !trimmed.starts_with("struct ")
                && !trimmed.starts_with("pub enum ")
                && !trimmed.starts_with("enum "),
            "src/ack.rs should only contain re-exports, found: {}",
            trimmed
        );
    }
}

/// INVARIANT: the AUR package verifies what it downloads, and its generated
/// `.SRCINFO` agrees with its `PKGBUILD`.
///
/// `sha256sums=('SKIP')` disables integrity verification of the release
/// tarball. That is defensible for a VCS package tracking a moving branch; it
/// is not defensible for a fixed tag, and it is especially not defensible for
/// a file integrity monitor.
///
/// This exists because the drift already happened: the published AUR package
/// pinned a real checksum from 1.11.x onward while the in-repo copy had
/// reverted to `SKIP`, so anyone copying the repo copy to the AUR would have
/// silently turned off verification for every Arch user.
///
/// `.SRCINFO` is generated by `makepkg --printsrcinfo` and is what the AUR
/// actually reads. If it disagrees with the `PKGBUILD`, the AUR publishes
/// metadata that does not match what users build.
/// CATEGORY: packaging
#[test]
fn aur_package_pins_a_real_checksum_and_srcinfo_agrees() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("aur");
    let pkgbuild = fs::read_to_string(dir.join("PKGBUILD")).expect("read aur/PKGBUILD");
    let srcinfo = fs::read_to_string(dir.join(".SRCINFO")).expect("read aur/.SRCINFO");

    let field = |src: &str, key: &str| -> Option<String> {
        src.lines()
            .find(|l| l.trim_start().starts_with(&format!("{key} = ")))
            .and_then(|l| l.split_once(" = ").map(|(_, v)| v.trim().to_string()))
    };

    // A 64-char lowercase hex digest, not SKIP.
    let sum = pkgbuild
        .lines()
        .find(|l| l.starts_with("sha256sums="))
        .expect("PKGBUILD must declare sha256sums");
    assert!(
        !sum.contains("SKIP"),
        "aur/PKGBUILD uses sha256sums=('SKIP'), which disables verification of \
         the downloaded release tarball. Pin the digest of the tagged archive."
    );
    // Take the quoted value, not every hex-looking character on the line:
    // the literal "sha256sums" itself contains a, 2, 5 and 6.
    let digest = sum
        .split('\'')
        .nth(1)
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    assert_eq!(
        digest.len(),
        64,
        "aur/PKGBUILD sha256sums is not a single 64-character hex digest: {sum}"
    );

    // .SRCINFO is what the AUR reads; it must not disagree with the PKGBUILD.
    let pkgver = pkgbuild
        .lines()
        .find_map(|l| l.strip_prefix("pkgver="))
        .expect("PKGBUILD must declare pkgver")
        .trim()
        .to_string();
    assert_eq!(
        field(&srcinfo, "pkgver").as_deref(),
        Some(pkgver.as_str()),
        "aur/.SRCINFO pkgver disagrees with aur/PKGBUILD; regenerate with \
         `makepkg --printsrcinfo > .SRCINFO`"
    );
    assert_eq!(
        field(&srcinfo, "sha256sums").map(|s| s.to_lowercase()),
        Some(digest.clone()),
        "aur/.SRCINFO sha256sums disagrees with aur/PKGBUILD"
    );

    // The source line must point at the tag matching pkgver.
    let source = field(&srcinfo, "source").expect(".SRCINFO must declare source");
    assert!(
        source.contains(&format!("v{pkgver}.tar.gz")),
        "aur/.SRCINFO source does not reference the v{pkgver} tag: {source}"
    );

    // The install script the PKGBUILD names has to exist, or the build fails
    // on the user's machine rather than here.
    if let Some(install) = pkgbuild.lines().find_map(|l| l.strip_prefix("install=")) {
        let install = install.trim();
        assert!(
            dir.join(install).is_file(),
            "aur/PKGBUILD declares install={install}, but aur/{install} does not exist"
        );
    }
}

/// One name per change dimension, defined once.
///
/// `Change::name()` is the single source of truth. Three byte-identical
/// `change_to_name` helpers previously existed in `src/alert/mod.rs`,
/// `src/wal/audit_writer.rs` and `src/wal/sink_runner.rs`, so adding a
/// `Change` variant required editing all three. Missing one would make the
/// audit log and an alert sink disagree about what a detection was, and
/// anything correlating the two would silently fail to match.
#[test]
fn change_dimension_names_are_defined_once() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let canonical = "src/types/change.rs";

    // The literal wire names may appear only where they are defined, plus the
    // audit module that maps legacy stored discriminators back to them.
    let legacy_mapper = "src/db/audit_ops.rs";

    // The vocabulary Change::name() owns.
    const WIRE_NAMES: &[&str] = &[
        "content_modified",
        "permissions_changed",
        "owner_changed",
        "inode_changed",
        "type_changed",
        "symlink_target_changed",
        "link_text_changed",
        "symlink_target_replaced",
        "capabilities_changed",
        "xattr_changed",
        "security_context_changed",
        "size_changed",
        "device_changed",
    ];

    let mut offenders = Vec::new();
    for file in collect_rs_files(&src) {
        let rel = file
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&file)
            .display()
            .to_string();
        let rel = rel.trim_start_matches('/').to_string();
        if rel.ends_with(canonical) || rel.ends_with(legacy_mapper) {
            continue;
        }

        let content = fs::read_to_string(&file).expect("read file");
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            // A match arm mapping a Change variant to one of the canonical
            // wire names. Arms mapping to some other label (a human-facing
            // dimension name such as "mode") are a different vocabulary and
            // are not duplication of this one.
            if trimmed.starts_with("Change::") {
                if let Some(rest) = trimmed.split("=> \"").nth(1) {
                    let value = rest.split('"').next().unwrap_or("");
                    if WIRE_NAMES.contains(&value) {
                        offenders.push(format!("{}:{}: {}", rel, i + 1, trimmed));
                    }
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "change dimension names must come from Change::name(), not a local \
         mapping. Duplicates drift, and a drifted name means the audit log and \
         the alert sinks describe the same detection differently:\n  {}",
        offenders.join("\n  ")
    );
}
