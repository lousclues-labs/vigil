use std::path::Path;

use vigil::attest;
use vigil::attest::error::AttestError;
use vigil::cli::AttestAction;

pub(crate) fn cmd_attest(config_path: Option<&Path>, action: AttestAction) -> vigil::Result<i32> {
    match action {
        AttestAction::Create {
            scope,
            out,
            key_path,
            deterministic_time,
        } => {
            let scope: attest::format::Scope = match scope.parse() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {}", e);
                    return Ok(2);
                }
            };

            let cfg = vigil::config::load_config(config_path)?;

            let opts = attest::create::CreateOpts {
                scope,
                out_path: out.as_deref(),
                key_path: key_path.as_deref(),
                deterministic_time: deterministic_time.as_deref(),
            };

            let result = attest::create::create_attestation(&cfg, &opts)?;

            // Record audit entry for attestation creation
            record_attest_audit(&cfg, &result.content_hash);

            // Print one-line summary
            eprintln!(
                "{} scope={} hash={} key={}",
                result.path.display(),
                result.scope,
                hex::encode(&result.content_hash[..8]),
                attest::key::format_key_id(&result.signing_key_id),
            );

            Ok(0)
        }

        AttestAction::Verify { file, key_path } => {
            match attest::verify::verify_attestation(&file, key_path.as_deref()) {
                Ok((report, attestation)) => {
                    attest::verify::print_report(&report, &attestation);
                    if report.valid {
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                Err(AttestError::Io(e)) => {
                    eprintln!("error: verification I/O failure: {}", e);
                    Ok(3)
                }
                Err(AttestError::InvalidFormat(msg)) => {
                    eprintln!("Verification:");
                    eprintln!("  Parse:             FAIL");
                    eprintln!("                     {}", msg);
                    eprintln!();
                    eprintln!("Result: INVALID");
                    Ok(1)
                }
                Err(e) => {
                    eprintln!("Verification:");
                    eprintln!("  Signature:         FAIL");
                    eprintln!("                     {}", e);
                    eprintln!();
                    eprintln!("Result: INVALID");
                    Ok(1)
                }
            }
        }

        AttestAction::Diff { file, against } => {
            // Parse the attestation file
            let data = std::fs::read(&file)?;
            let attestation = attest::format::deserialize_attestation(&data).map_err(|e| {
                vigil::VigilError::Attest(format!("cannot parse {}: {}", file.display(), e))
            })?;

            if against == "current" {
                let cfg = vigil::config::load_config(config_path)?;
                let report = attest::diff::diff_against_current(&attestation, &cfg)?;
                eprintln!(
                    "Comparing attestation {} against current baseline:",
                    file.display()
                );
                eprintln!();
                attest::diff::print_diff_report(&report, "attestation", "current");
            } else {
                // Compare against another attestation file
                let other_path = std::path::Path::new(&against);
                let other_data = std::fs::read(other_path)?;
                let other = attest::format::deserialize_attestation(&other_data).map_err(|e| {
                    vigil::VigilError::Attest(format!(
                        "cannot parse {}: {}",
                        other_path.display(),
                        e
                    ))
                })?;

                let report = attest::diff::diff_attestations(&attestation, &other)?;
                eprintln!(
                    "Comparing {} against {}:",
                    file.display(),
                    other_path.display(),
                );
                eprintln!();
                attest::diff::print_diff_report(
                    &report,
                    &file.display().to_string(),
                    &other_path.display().to_string(),
                );
            }

            Ok(0)
        }

        AttestAction::Show { file, verbose } => {
            attest::show::show_attestation(&file, verbose)?;
            Ok(0)
        }

        AttestAction::List { dir } => {
            attest::list::list_attestations(&dir)?;
            Ok(0)
        }
    }
}

/// Record an `attestation_created` audit entry after successful creation.
fn record_attest_audit(config: &vigil::config::Config, content_hash: &[u8; 32]) {
    let conn = match vigil::db::open_audit_db(config) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cannot open audit DB to record attestation: {}", e);
            return;
        }
    };

    let prev = vigil::db::audit_ops::get_last_chain_hash(&conn)
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            blake3::hash(b"vigil-audit-chain-genesis")
                .to_hex()
                .to_string()
        });

    let timestamp = chrono::Utc::now().timestamp();
    let path = "vigil://attestation";
    let changes_json = serde_json::json!([{
        "type": "attestation_created",
        "content_hash": hex::encode(content_hash),
    }])
    .to_string();
    let severity = "info";

    let chain_hash =
        vigil::db::audit_ops::compute_chain_hash(&prev, timestamp, path, &changes_json, severity);

    let result = conn.execute(
        "INSERT INTO audit_log (
            timestamp, path, changes_json, severity, monitored_group,
            process_json, package, maintenance, suppressed, hmac, chain_hash
        ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, 0, 0, NULL, ?5)",
        rusqlite::params![timestamp, path, changes_json, severity, chain_hash],
    );

    if let Err(e) = result {
        tracing::warn!("failed to record attestation audit entry: {}", e);
    }
}
