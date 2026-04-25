//! Filesystem walking helpers: data directory usage analysis.

use std::fs;
use std::path::Path;

/// Breakdown of disk usage by category in a vigil data directory.
#[derive(Debug, Default)]
pub struct DataDirUsage {
    pub total: u64,
    pub audit: u64,
    pub baseline: u64,
    pub backups: u64,
    pub wal: u64,
    pub other: u64,
}

impl DataDirUsage {
    /// Render a parenthesized breakdown of non-zero categories.
    pub fn breakdown_string(&self) -> String {
        let mut parts = Vec::new();
        if self.audit > 0 {
            parts.push(format!("audit: {}", crate::display::fmt_size(self.audit)));
        }
        if self.baseline > 0 {
            parts.push(format!(
                "baseline: {}",
                crate::display::fmt_size(self.baseline)
            ));
        }
        if self.backups > 0 {
            parts.push(format!(
                "backups: {}",
                crate::display::fmt_size(self.backups)
            ));
        }
        if self.wal > 0 {
            parts.push(format!("WAL: {}", crate::display::fmt_size(self.wal)));
        }
        if self.other > 0 {
            parts.push(format!("other: {}", crate::display::fmt_size(self.other)));
        }
        if parts.is_empty() {
            "empty".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Walk a data directory recursively and sum file sizes by category.
pub fn walk_data_dir_usage(dir: &Path) -> std::result::Result<DataDirUsage, String> {
    let mut usage = DataDirUsage::default();
    walk_data_dir_inner(dir, dir, &mut usage)
        .map_err(|e| format!("cannot read {}: {}", dir.display(), e))?;
    Ok(usage)
}

fn walk_data_dir_inner(base: &Path, dir: &Path, usage: &mut DataDirUsage) -> std::io::Result<()> {
    let entries = fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            walk_data_dir_inner(base, &entry.path(), usage)?;
        } else if meta.is_file() {
            let size = meta.len();
            usage.total += size;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let rel = entry.path();
            let rel_path = rel.strip_prefix(base).unwrap_or(&rel);
            let in_backups = rel_path
                .components()
                .any(|c| c.as_os_str() == "binary-backups");

            if in_backups {
                usage.backups += size;
            } else if name_str.starts_with("audit.db") {
                usage.audit += size;
            } else if name_str.starts_with("baseline.db") {
                usage.baseline += size;
            } else if name_str.ends_with(".wal") {
                usage.wal += size;
            } else {
                usage.other += size;
            }
        }
    }
    Ok(())
}
