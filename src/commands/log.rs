use std::path::PathBuf;
use std::process::Command as ProcessCommand;

use vigil::cli::LogAction;

/// Resolve the absolute path to `journalctl` to avoid PATH-injection.
fn journalctl_binary() -> PathBuf {
    for cand in ["/usr/bin/journalctl", "/bin/journalctl"] {
        let p = PathBuf::from(cand);
        if p.is_file() {
            return p;
        }
    }
    PathBuf::from("journalctl")
}

pub(crate) fn cmd_log(action: LogAction) -> vigil::Result<()> {
    match action {
        LogAction::Show {
            lines,
            level,
            follow,
            since,
            grep,
        } => {
            let mut args: Vec<String> =
                vec!["--no-pager".into(), "-u".into(), "vigild.service".into()];

            if follow {
                args.push("-f".into());
            } else {
                args.push("-n".into());
                args.push(lines.to_string());
            }

            if let Some(ref s) = since {
                args.push("--since".into());
                args.push(s.clone());
            }

            if let Some(ref lvl) = level {
                let priority = match lvl.to_lowercase().as_str() {
                    "error" | "err" => "3",
                    "warn" | "warning" => "4",
                    "info" | "notice" => "6",
                    "debug" => "7",
                    other => {
                        eprintln!(
                            "error: unknown log level '{}' (use: error, warn, info, debug)",
                            other
                        );
                        return Ok(());
                    }
                };
                args.push("-p".into());
                args.push(format!("0..{}", priority));
            }

            if let Some(ref pattern) = grep {
                args.push("--grep".into());
                args.push(pattern.clone());
            }

            args.push("-o".into());
            args.push("short-iso".into());

            let status = ProcessCommand::new(journalctl_binary())
                .args(&args)
                .status()
                .map_err(vigil::VigilError::Io)?;

            if !status.success() {
                eprintln!("journalctl exited with status {}", status);
                eprintln!("hint: you may need to run this command with sudo");
            }
        }
        LogAction::Errors { lines, since } => {
            let mut args: Vec<String> = vec![
                "--no-pager".into(),
                "-u".into(),
                "vigild.service".into(),
                "-p".into(),
                "0..4".into(),
                "-n".into(),
                lines.to_string(),
                "-o".into(),
                "short-iso".into(),
            ];

            if let Some(ref s) = since {
                args.push("--since".into());
                args.push(s.clone());
            }

            let status = ProcessCommand::new(journalctl_binary())
                .args(&args)
                .status()
                .map_err(vigil::VigilError::Io)?;

            if !status.success() {
                eprintln!("journalctl exited with status {}", status);
                eprintln!("hint: you may need to run this command with sudo");
            }
        }
    }

    Ok(())
}
