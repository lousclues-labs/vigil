use std::path::{Path, PathBuf};

use vigil::db::baseline_ops;
use vigil::doctor;
use vigil::types::OutputFormat;

use super::common::format_count;

pub(crate) fn cmd_inspect(
    config_path: Option<&Path>,
    target_path: &Path,
    baseline_db: Option<&Path>,
    recursive: bool,
    root_prefix: Option<&str>,
    brief: bool,
    format: OutputFormat,
) -> vigil::Result<()> {
    // Open the baseline DB
    let cfg = vigil::config::load_config(config_path).ok();

    let db_path = if let Some(explicit) = baseline_db {
        if !explicit.exists() {
            return Err(vigil::VigilError::Config(format!(
                "baseline database not found: {}",
                explicit.display()
            )));
        }
        explicit.to_path_buf()
    } else if let Some(ref c) = cfg {
        if !c.daemon.db_path.exists() {
            return Err(vigil::VigilError::Config(
                "no baseline database found. Use --baseline-db to specify one.".to_string(),
            ));
        }
        c.daemon.db_path.clone()
    } else {
        return Err(vigil::VigilError::Config(
            "no baseline database found. Use --baseline-db to specify one.".to_string(),
        ));
    };

    let conn = doctor::open_existing_db_pub(&db_path).map_err(|e| {
        vigil::VigilError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("cannot open baseline database: {}", e),
        ))
    })?;

    let paths_to_inspect = if recursive && target_path.is_dir() {
        collect_paths_recursive(target_path)
    } else {
        vec![target_path.to_path_buf()]
    };

    let mut deviations: Vec<InspectDeviation> = Vec::new();
    let mut clean_count = 0u64;
    let mut error_count = 0u64;
    let mut missing_in_baseline = 0u64;

    for path in &paths_to_inspect {
        // Map the filesystem path to a baseline path using root prefix
        let baseline_path = if let Some(prefix) = root_prefix {
            let prefix = prefix.trim_end_matches('/');
            let path_str = path.to_string_lossy();
            if let Some(suffix) = path_str.strip_prefix(prefix) {
                suffix.to_string()
            } else {
                path_str.to_string()
            }
        } else {
            path.to_string_lossy().to_string()
        };

        match baseline_ops::get_by_path(&conn, &baseline_path) {
            Ok(Some(entry)) => {
                match inspect_file(path, &entry, &baseline_path) {
                    Ok(Some(dev)) => deviations.push(dev),
                    Ok(None) => clean_count += 1,
                    Err(e) => {
                        deviations.push(InspectDeviation {
                            path: path.display().to_string(),
                            baseline_path: baseline_path.clone(),
                            differences: vec![format!("error: {}", e)],
                        });
                        error_count += 1;
                    }
                }
            }
            Ok(None) => {
                missing_in_baseline += 1;
                deviations.push(InspectDeviation {
                    path: path.display().to_string(),
                    baseline_path: baseline_path.clone(),
                    differences: vec!["not in baseline (addition)".to_string()],
                });
            }
            Err(e) => {
                error_count += 1;
                deviations.push(InspectDeviation {
                    path: path.display().to_string(),
                    baseline_path: baseline_path.clone(),
                    differences: vec![format!("database error: {}", e)],
                });
            }
        }
    }

    if format == OutputFormat::Json {
        let json = serde_json::json!({
            "target": target_path.display().to_string(),
            "baseline_db": db_path.display().to_string(),
            "root_prefix": root_prefix,
            "total_inspected": paths_to_inspect.len(),
            "clean": clean_count,
            "deviations": deviations.len(),
            "errors": error_count,
            "missing_in_baseline": missing_in_baseline,
            "details": deviations.iter().map(|d| serde_json::json!({
                "path": d.path,
                "baseline_path": d.baseline_path,
                "differences": d.differences,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    if brief {
        if deviations.is_empty() {
            println!(
                "● clean ({} files inspected against {})",
                format_count(paths_to_inspect.len() as u64),
                db_path.display()
            );
        } else {
            println!(
                "✗ {} deviations in {} files (baseline: {})",
                deviations.len(),
                format_count(paths_to_inspect.len() as u64),
                db_path.display()
            );
        }
        return Ok(());
    }

    // Full output
    for dev in &deviations {
        println!("{}", dev.path);
        println!("  baseline:     {} (from {})", dev.baseline_path, db_path.display());
        for diff in &dev.differences {
            println!("  {}", diff);
        }
        println!("  conclusion:   structural deviation");
        println!();
    }

    println!(
        "Inspected {} files. {} clean, {} deviations, {} errors.",
        format_count(paths_to_inspect.len() as u64),
        format_count(clean_count),
        deviations.len(),
        error_count
    );

    Ok(())
}

#[derive(Debug)]
struct InspectDeviation {
    path: String,
    baseline_path: String,
    differences: Vec<String>,
}

fn inspect_file(
    path: &Path,
    baseline: &vigil::types::BaselineEntry,
    baseline_path: &str,
) -> vigil::Result<Option<InspectDeviation>> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Ok(Some(InspectDeviation {
                path: path.display().to_string(),
                baseline_path: baseline_path.to_string(),
                differences: vec!["permission denied".to_string()],
            }));
        }
        Err(e) => return Err(vigil::VigilError::Io(e)),
    };

    let mut diffs = Vec::new();

    // Compare mode
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current_mode = meta.mode() & 0o7777;
        if current_mode != baseline.permissions.mode {
            diffs.push(format!(
                "mode:         changed (baseline {:04o} actual {:04o})",
                baseline.permissions.mode, current_mode
            ));
        } else {
            diffs.push(format!("mode:         unchanged ({:04o})", current_mode));
        }

        // Compare owner
        if meta.uid() != baseline.permissions.owner_uid || meta.gid() != baseline.permissions.owner_gid {
            diffs.push(format!(
                "owner:        changed (baseline {}:{} actual {}:{})",
                baseline.permissions.owner_uid, baseline.permissions.owner_gid,
                meta.uid(), meta.gid()
            ));
        } else {
            diffs.push(format!(
                "owner:        unchanged ({}:{})",
                meta.uid(), meta.gid()
            ));
        }

        // Compare inode
        if meta.ino() != baseline.identity.inode {
            diffs.push(format!(
                "inode:        replaced (baseline {} actual {})",
                baseline.identity.inode, meta.ino()
            ));
        }

        // Compare mtime
        let current_mtime = meta.mtime();
        if current_mtime != baseline.mtime {
            diffs.push(format!(
                "mtime:        changed (baseline {} actual {})",
                baseline.mtime, current_mtime
            ));
        }
    }

    // Compare hash if it's a regular file
    if meta.is_file() {
        match std::fs::File::open(path).and_then(|f| {
            let size = f.metadata()?.len();
            vigil::hash::blake3_hash_fd(&f, size, 1_048_576).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
            })
        }) {
            Ok(hash) => {
                if hash != baseline.content.hash {
                    diffs.push(format!(
                        "hash:         changed (baseline {} actual {})",
                        &baseline.content.hash[..16.min(baseline.content.hash.len())],
                        &hash[..16.min(hash.len())]
                    ));
                } else {
                    diffs.push("hash:         unchanged".to_string());
                }
            }
            Err(e) => {
                diffs.push(format!("hash:         error ({})", e));
            }
        }
    }

    // If all lines contain "unchanged" and no "changed"/"replaced"/"error", it's clean
    let has_deviation = diffs.iter().any(|d| {
        d.contains("changed") || d.contains("replaced") || d.contains("error") || d.contains("permission denied")
    });

    if has_deviation {
        Ok(Some(InspectDeviation {
            path: path.display().to_string(),
            baseline_path: baseline_path.to_string(),
            differences: diffs,
        }))
    } else {
        Ok(None)
    }
}

fn collect_paths_recursive(dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                paths.extend(collect_paths_recursive(&path));
            } else {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths
}
