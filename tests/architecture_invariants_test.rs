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

    // No exceptions — all files are under the limit after the 1.5.0 split.
    let exceptions: &[(&str, usize)] = &[];

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
