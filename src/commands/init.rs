use std::io::{self, Write};
use std::path::Path;

use vigil::display;
use vigil::types::OutputFormat;

pub(crate) fn cmd_init(
    config_path: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_baseline_db(&cfg)?;

    let existing = vigil::db::baseline_ops::count(&conn).unwrap_or(0);
    if existing > 0 && !force {
        println!(
            "⚠ Existing baseline found ({} entries).",
            display::fmt_count(existing as u64)
        );
        println!("  Reinitializing will trust the current filesystem state as truth.");
        print!("  Proceed? [y/N] ");
        io::stdout().flush()?;

        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        let accepted = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        if !accepted {
            println!("Baseline initialization cancelled.");
            return Ok(());
        }
    }

    eprintln!("  Scanning watch paths...");
    let result = vigil::scanner::build_initial_baseline(&conn, &cfg)?;
    vigil::db::baseline_ops::set_config_state(&conn, "baseline_initialized", "true")?;

    // Gather baseline metadata for report
    let baseline_fingerprint = vigil::db::baseline_ops::get_baseline_fingerprint(&conn);
    let hmac_signed = cfg.security.hmac_signing;
    let profile = vigil::db::baseline_ops::compute_baseline_profile(&conn).ok();

    let init_report = display::InitReport {
        result,
        baseline_fingerprint,
        hmac_signed,
        db_path: cfg.daemon.db_path.clone(),
        profile,
    };

    let term = display::term::TermInfo::detect();
    let output = display::render_init(&init_report, format, &term);
    print!("{}", output);

    Ok(())
}
