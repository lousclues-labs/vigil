use std::path::Path;

pub(crate) fn cmd_config(config_path: Option<&Path>, action: vigil::cli::ConfigAction) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;

    match action {
        vigil::cli::ConfigAction::Show => {
            println!(
                "{}",
                toml::to_string_pretty(&cfg)
                    .map_err(|e| vigil::VigilError::Config(e.to_string()))?
            );
        }
        vigil::cli::ConfigAction::Validate => {
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
    }

    Ok(())
}
