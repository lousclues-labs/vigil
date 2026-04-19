use std::path::Path;

use super::common::{resolve_config_path, update_config_toml};

use vigil::cli::SetupAction;

pub(crate) fn cmd_setup(config_path: Option<&Path>, action: SetupAction) -> vigil::Result<()> {
    match action {
        SetupAction::Hmac { key_path, force } => cmd_setup_hmac(config_path, &key_path, force),
        SetupAction::Socket { path, disable } => cmd_setup_socket(config_path, &path, disable),
        SetupAction::Attest { key_path, force } => cmd_setup_attest(&key_path, force),
    }
}

fn cmd_setup_hmac(config_path: Option<&Path>, key_path: &Path, force: bool) -> vigil::Result<()> {
    use std::io::{self, Write};

    // Must be root to write to /etc/vigil
    if !nix::unistd::geteuid().is_root() {
        return Err(vigil::VigilError::Config(
            "HMAC key setup requires root. Run with sudo.".into(),
        ));
    }

    if key_path.exists() && !force {
        print!(
            "HMAC key file {} already exists. Overwrite? [y/N] ",
            key_path.display()
        );
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("HMAC key setup cancelled.");
            return Ok(());
        }
    }

    // Generate 32 random bytes from /dev/urandom
    let mut key_bytes = [0u8; 32];
    {
        use std::io::Read;
        let mut urandom = std::fs::File::open("/dev/urandom")?;
        urandom.read_exact(&mut key_bytes)?;
    }
    let hex_key = hex::encode(key_bytes);

    // Write key file
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(key_path, &hex_key)?;

    // Set permissions to 0400 (owner read-only)
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o400))?;

    // Set ownership to root:root
    nix::unistd::chown(
        key_path,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(0)),
    )
    .map_err(|e| vigil::VigilError::Config(format!("failed to chown key file: {}", e)))?;

    // Update the config file
    let toml_path = resolve_config_path(config_path);
    if let Some(ref toml_path) = toml_path {
        update_config_toml(
            toml_path,
            &[
                ("security", "hmac_signing", "true"),
                (
                    "security",
                    "hmac_key_path",
                    &format!("\"{}\"", key_path.display()),
                ),
            ],
        )?;
    }

    println!();
    println!("  ● HMAC key written to {}", key_path.display());
    println!("    Permissions: 0400 (owner read-only)");
    println!("    Owner: root:root");
    println!("    Config updated: hmac_signing = true");
    println!();
    println!("  Restart vigild for changes to take effect:");
    println!("    sudo systemctl restart vigild.service");

    Ok(())
}

fn cmd_setup_socket(
    config_path: Option<&Path>,
    socket_path: &Path,
    disable: bool,
) -> vigil::Result<()> {
    let toml_path = resolve_config_path(config_path);

    if disable {
        if let Some(ref toml_path) = toml_path {
            update_config_toml(toml_path, &[("hooks", "signal_socket", "\"\"")])?;
        }
        println!("Socket sink disabled in config.");
        println!("Restart vigild for changes to take effect.");
        return Ok(());
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            println!("Created directory: {}", parent.display());
        }
    }

    if let Some(ref toml_path) = toml_path {
        update_config_toml(
            toml_path,
            &[(
                "hooks",
                "signal_socket",
                &format!("\"{}\"", socket_path.display()),
            )],
        )?;
    }

    println!();
    println!("  ● Socket sink configured: {}", socket_path.display());
    println!();
    println!("  Restart vigild for changes to take effect:");
    println!("    sudo systemctl restart vigild.service");
    println!();
    println!("  To listen for alerts:");
    println!("    socat UNIX-LISTEN:{} -", socket_path.display());

    Ok(())
}

fn cmd_setup_attest(key_path: &Path, force: bool) -> vigil::Result<()> {
    use std::io::{self, Write};

    if key_path.exists() && !force {
        print!(
            "Attestation key file {} already exists. Overwrite? [y/N] ",
            key_path.display()
        );
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Attestation key setup cancelled.");
            return Ok(());
        }
    }

    let key_id = vigil::attest::key::generate_attest_key(key_path).map_err(|e| {
        vigil::VigilError::Attest(format!("failed to generate attestation key: {}", e))
    })?;

    // Set ownership to root:root if we're root
    if nix::unistd::geteuid().is_root() {
        let _ = nix::unistd::chown(
            key_path,
            Some(nix::unistd::Uid::from_raw(0)),
            Some(nix::unistd::Gid::from_raw(0)),
        );
    }

    println!();
    println!("  ● Attestation key written to {}", key_path.display());
    println!(
        "    Key ID:      {}",
        vigil::attest::key::format_key_id(&key_id)
    );
    println!("    Permissions: 0600");
    println!();
    println!("  This key is separate from the audit chain HMAC key.");
    println!("  It signs portable attestation files created with `vigil attest create`.");
    println!("  Back it up securely — it is needed to verify attestations.");

    Ok(())
}
