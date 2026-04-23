//! `vigil config` subcommand: display, validate, and modify configuration.

use std::path::Path;

use super::common::resolve_config_path;

pub(crate) fn cmd_config(
    config_path: Option<&Path>,
    action: vigil::cli::ConfigAction,
) -> vigil::Result<()> {
    match action {
        vigil::cli::ConfigAction::Show => {
            let cfg = vigil::config::load_config(config_path)?;
            println!(
                "{}",
                toml::to_string_pretty(&cfg)
                    .map_err(|e| vigil::VigilError::Config(e.to_string()))?
            );
        }
        vigil::cli::ConfigAction::Validate => {
            let cfg = vigil::config::load_config(config_path)?;
            vigil::config::validate_config(&cfg)?;
            let warnings = vigil::config::validate_config_deep(&cfg)?;

            println!();
            println!("  ● Configuration is valid.");

            if !warnings.is_empty() {
                println!();
                println!(
                    "  {} {}:",
                    warnings.len(),
                    if warnings.len() == 1 {
                        "warning"
                    } else {
                        "warnings"
                    }
                );
                for w in &warnings {
                    println!("    ─ {}", w);
                }
            }
            println!();
        }
        vigil::cli::ConfigAction::Watch { action } => {
            cmd_config_watch(config_path, action)?;
        }
        vigil::cli::ConfigAction::Set {
            key,
            value,
            dry_run,
        } => {
            cmd_config_set(config_path, &key, &value, dry_run)?;
        }
        vigil::cli::ConfigAction::Get { key } => {
            cmd_config_get(config_path, &key)?;
        }
    }

    Ok(())
}

/// `vigil config watch add` / `vigil config watch remove`
fn cmd_config_watch(
    config_path: Option<&Path>,
    action: vigil::cli::ConfigWatchAction,
) -> vigil::Result<()> {
    let toml_path = resolve_config_path(config_path).ok_or_else(|| {
        vigil::VigilError::Config("no config file found; specify with --config".into())
    })?;

    let content = if toml_path.exists() {
        std::fs::read_to_string(&toml_path)?
    } else {
        return Err(vigil::VigilError::Config(format!(
            "config file not found at {}",
            toml_path.display()
        )));
    };

    let mut doc: toml_edit::DocumentMut = content.parse().map_err(|e| {
        vigil::VigilError::Config(format!("failed to parse {}: {}", toml_path.display(), e))
    })?;

    match action {
        vigil::cli::ConfigWatchAction::Add { path, group } => {
            let section_key = format!("watch.{}", group);

            // Ensure [watch.<group>] exists
            if doc.get("watch").is_none() {
                doc["watch"] = toml_edit::Item::Table(toml_edit::Table::new());
            }
            let watch_table = doc["watch"].as_table_mut().ok_or_else(|| {
                vigil::VigilError::Config("[watch] is not a table in config".into())
            })?;

            if watch_table.get(&group).is_none() {
                // Create new group with severity = "high"
                let mut group_table = toml_edit::Table::new();
                group_table["severity"] = toml_edit::value("high");
                let mut paths_arr = toml_edit::Array::new();
                paths_arr.push(&path);
                group_table["paths"] = toml_edit::value(paths_arr);
                watch_table[&group] = toml_edit::Item::Table(group_table);

                write_config_atomic(&toml_path, &doc)?;
                validate_and_reload(&toml_path, config_path)?;
                println!(
                    "created watch group '{}' with path '{}'; daemon reloaded.",
                    group, path
                );
                return Ok(());
            }

            // Group exists -- add path to its paths array if not already present
            let group_item = &mut watch_table[&group];
            let group_table = group_item.as_table_mut().ok_or_else(|| {
                vigil::VigilError::Config(format!("{} is not a table in config", section_key))
            })?;

            if group_table.get("paths").is_none() {
                let mut arr = toml_edit::Array::new();
                arr.push(&path);
                group_table["paths"] = toml_edit::value(arr);
            } else {
                let paths_item = &mut group_table["paths"];
                let arr = paths_item
                    .as_value_mut()
                    .and_then(|v| v.as_array_mut())
                    .ok_or_else(|| {
                        vigil::VigilError::Config(format!(
                            "{}.paths is not an array in config",
                            section_key
                        ))
                    })?;

                // Check for duplicate (idempotent)
                let already_present = arr.iter().any(|v| v.as_str() == Some(&path));
                if already_present {
                    println!(
                        "'{}' is already in watch group '{}'; no changes made.",
                        path, group
                    );
                    return Ok(());
                }

                arr.push(&path);
            }

            write_config_atomic(&toml_path, &doc)?;
            validate_and_reload(&toml_path, config_path)?;
            println!(
                "added '{}' to watch group '{}'; daemon reloaded.",
                path, group
            );
        }

        vigil::cli::ConfigWatchAction::Remove { path, group } => {
            let section_key = format!("watch.{}", group);

            let watch_table = doc
                .get_mut("watch")
                .and_then(|w| w.as_table_mut())
                .ok_or_else(|| {
                    vigil::VigilError::Config("[watch] section not found in config".into())
                })?;

            let group_table = watch_table
                .get_mut(&group)
                .and_then(|g| g.as_table_mut())
                .ok_or_else(|| {
                    vigil::VigilError::Config(format!(
                        "watch group '{}' not found in config",
                        group
                    ))
                })?;

            let paths_arr = group_table
                .get_mut("paths")
                .and_then(|p| p.as_value_mut())
                .and_then(|v| v.as_array_mut())
                .ok_or_else(|| {
                    vigil::VigilError::Config(format!(
                        "{}.paths is not an array in config",
                        section_key
                    ))
                })?;

            let idx = paths_arr.iter().position(|v| v.as_str() == Some(&path));

            match idx {
                Some(i) => {
                    paths_arr.remove(i);
                    write_config_atomic(&toml_path, &doc)?;
                    validate_and_reload(&toml_path, config_path)?;
                    println!(
                        "removed '{}' from watch group '{}'; daemon reloaded.",
                        path, group
                    );
                }
                None => {
                    return Err(vigil::VigilError::Config(format!(
                        "'{}' is not in watch group '{}'. \
                         Run `vigil config show` to see current watch groups.",
                        path, group
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Known top-level config sections and their settable keys with expected types.
/// Returns (section, key, type_hint) or an error for unknown/unsafe keys.
fn parse_config_key(dotted: &str) -> vigil::Result<(&str, &str)> {
    let parts: Vec<&str> = dotted.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(vigil::VigilError::Config(format!(
            "invalid config key '{}'; expected format: section.key (e.g. daemon.detection_wal_persistent)",
            dotted
        )));
    }

    let section = parts[0];
    let key = parts[1];

    // Reject keys that require special handling
    let unsafe_keys = [
        "security.hmac_key_path",
        "daemon.db_path",
        "daemon.pid_file",
    ];
    if unsafe_keys.contains(&dotted) {
        return Err(vigil::VigilError::Config(format!(
            "'{}' cannot be changed via `vigil config set`. \
             Use `vigil setup` or edit vigil.toml directly.",
            dotted
        )));
    }

    // Validate section exists
    let known_sections = [
        "daemon",
        "scanner",
        "alerts",
        "exclusions",
        "package_manager",
        "hooks",
        "security",
        "database",
        "monitor",
        "maintenance",
        "update",
        "notifications",
    ];
    if !known_sections.contains(&section) {
        return Err(vigil::VigilError::Config(format!(
            "unknown config section '{}'. Known sections: {}",
            section,
            known_sections.join(", ")
        )));
    }

    Ok((section, key))
}

/// `vigil config set <key> <value>`
fn cmd_config_set(
    config_path: Option<&Path>,
    dotted_key: &str,
    raw_value: &str,
    dry_run: bool,
) -> vigil::Result<()> {
    let (section, key) = parse_config_key(dotted_key)?;

    let toml_path = resolve_config_path(config_path).ok_or_else(|| {
        vigil::VigilError::Config("no config file found; specify with --config".into())
    })?;

    let content = if toml_path.exists() {
        std::fs::read_to_string(&toml_path)?
    } else {
        return Err(vigil::VigilError::Config(format!(
            "config file not found at {}",
            toml_path.display()
        )));
    };

    let mut doc: toml_edit::DocumentMut = content.parse().map_err(|e| {
        vigil::VigilError::Config(format!("failed to parse {}: {}", toml_path.display(), e))
    })?;

    // Ensure section exists
    if doc.get(section).is_none() {
        doc[section] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    // Parse the value as a TOML literal
    let parsed_value: toml_edit::Value = raw_value.parse().map_err(|e: toml_edit::TomlError| {
        vigil::VigilError::Config(format!(
            "invalid value '{}' for {}: {}. \
                 Use TOML syntax: true/false for bools, 42 for ints, \"string\" for strings.",
            raw_value, dotted_key, e
        ))
    })?;

    let old_value = doc
        .get(section)
        .and_then(|s| s.get(key))
        .map(|v| v.to_string());

    doc[section][key] = toml_edit::value(parsed_value);

    let new_content = doc.to_string();

    // Validate the resulting config by re-parsing
    let test_cfg: vigil::config::Config = toml::from_str(&new_content).map_err(|e| {
        vigil::VigilError::Config(format!(
            "resulting config is invalid after setting {} = {}: {}",
            dotted_key, raw_value, e
        ))
    })?;
    vigil::config::validate_config(&test_cfg)?;

    if dry_run {
        println!("dry run: would set {} = {}", dotted_key, raw_value);
        if let Some(old) = &old_value {
            println!("  current: {}", old.trim());
        } else {
            println!("  current: (not set)");
        }
        println!("  new:     {}", raw_value);
        println!("\nNo changes written.");
        return Ok(());
    }

    write_config_atomic_str(&toml_path, &new_content)?;

    // Print side-effect warnings for keys that need a restart
    let restart_keys = [
        "daemon.detection_wal_persistent",
        "daemon.detection_wal",
        "daemon.monitor_backend",
        "daemon.worker_threads",
        "daemon.event_channel_capacity",
    ];
    if restart_keys.contains(&dotted_key) {
        println!(
            "set {} = {}; this setting requires a daemon restart to take effect.",
            dotted_key, raw_value
        );
        println!("  run: sudo systemctl restart vigild");
    } else {
        // Try to signal reload
        reload_daemon_if_running();
        println!("set {} = {}; daemon reloaded.", dotted_key, raw_value);
    }

    Ok(())
}

/// `vigil config get <key>`
fn cmd_config_get(config_path: Option<&Path>, dotted_key: &str) -> vigil::Result<()> {
    let (section, key) = parse_config_key(dotted_key)?;

    let cfg = vigil::config::load_config(config_path)?;
    let toml_str =
        toml::to_string_pretty(&cfg).map_err(|e| vigil::VigilError::Config(e.to_string()))?;
    let doc: toml_edit::DocumentMut = toml_str
        .parse()
        .map_err(|e| vigil::VigilError::Config(format!("failed to serialize config: {}", e)))?;

    match doc.get(section).and_then(|s| s.get(key)) {
        Some(value) => {
            // Print value without trailing newline decorations
            let display = value.to_string();
            println!("{}", display.trim());
        }
        None => {
            return Err(vigil::VigilError::Config(format!(
                "key '{}' not found in section [{}]. \
                 Run `vigil config show` to see all current values.",
                key, section
            )));
        }
    }

    Ok(())
}

/// Write config atomically: write to .new, fsync, rename over original.
/// Preserves the original file's permissions.
fn write_config_atomic(path: &Path, doc: &toml_edit::DocumentMut) -> vigil::Result<()> {
    write_config_atomic_str(path, &doc.to_string())
}

fn write_config_atomic_str(path: &Path, content: &str) -> vigil::Result<()> {
    use std::io::Write;

    let tmp_path = path.with_extension("toml.new");

    // Preserve original permissions
    let perms = std::fs::metadata(path).ok().map(|m| m.permissions());

    let mut f = std::fs::File::create(&tmp_path).map_err(|e| {
        vigil::VigilError::Config(format!("cannot write to {}: {}", tmp_path.display(), e))
    })?;
    f.write_all(content.as_bytes())?;
    f.sync_all()?;

    if let Some(p) = perms {
        std::fs::set_permissions(&tmp_path, p).ok();
    }

    std::fs::rename(&tmp_path, path).map_err(|e| {
        // Clean up temp file on rename failure
        let _ = std::fs::remove_file(&tmp_path);
        vigil::VigilError::Config(format!("failed to replace {}: {}", path.display(), e))
    })?;

    Ok(())
}

/// Validate the config file we just wrote, and signal the daemon to reload.
fn validate_and_reload(toml_path: &Path, config_path: Option<&Path>) -> vigil::Result<()> {
    // Re-parse and validate the written config
    let new_cfg = vigil::config::load_config(config_path.or(Some(toml_path)))?;
    vigil::config::validate_config(&new_cfg)?;

    reload_daemon_if_running();
    Ok(())
}

/// Send SIGHUP to vigild if it is running.
fn reload_daemon_if_running() {
    // Try control socket reload first (preferred)
    let socket = std::path::Path::new("/run/vigil/control.sock");
    if socket.exists() {
        if let Ok(resp) = super::common::query_control_socket(
            socket,
            &serde_json::json!({"method": "reload"}).to_string(),
        ) {
            if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                return;
            }
        }
    }

    // Fallback: send SIGHUP via systemctl
    let _ = std::process::Command::new("/usr/bin/systemctl")
        .args(["reload", "vigild"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}
