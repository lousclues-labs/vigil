//! `vigil man <page>` — render a man page to stdout in roff format.
//!
//! Used by packaging (pkg/build.sh) to produce vigil(1), vigild(8), and
//! vigil.toml(5) without committing generated files. The CLI surface is
//! hidden from end-user help; man pages ship pre-rendered in the package.

use std::io::Write;

use clap::{ArgAction, CommandFactory};
use clap_mangen::Man;

use vigil::cli::Cli;

/// Embedded roff source for vigil.toml(5). Hand-authored because the
/// config schema isn't a clap Command tree.
const VIGIL_TOML_5: &str = include_str!("../../man/vigil.toml.5.in");

pub(crate) fn cmd_man(page: &str) -> vigil::Result<i32> {
    let mut stdout = std::io::stdout().lock();
    match page {
        "vigil" => {
            let cmd = <Cli as CommandFactory>::command()
                .name("vigil")
                .version(env!("CARGO_PKG_VERSION"));
            Man::new(cmd).render(&mut stdout)?;
            Ok(0)
        }
        "vigild" => {
            let cmd = vigild_synthetic_command();
            Man::new(cmd).section("8").render(&mut stdout)?;
            Ok(0)
        }
        "vigil.toml" => {
            stdout.write_all(VIGIL_TOML_5.as_bytes())?;
            Ok(0)
        }
        other => {
            eprintln!(
                "error: unknown man page '{other}'; expected one of: vigil, vigild, vigil.toml"
            );
            Ok(2)
        }
    }
}

/// Build a synthetic clap::Command describing vigild so clap_mangen can
/// render a section-8 man page. vigild itself takes no CLI arguments; it
/// reads configuration via VIGIL_CONFIG and is normally launched by systemd.
fn vigild_synthetic_command() -> clap::Command {
    clap::Command::new("vigild")
        .version(env!("CARGO_PKG_VERSION"))
        .about("vigil file-integrity monitoring daemon")
        .long_about(
            "vigild is the long-running daemon component of vigil. It watches \
             the configured paths via inotify, hashes changes, compares against \
             the baseline, writes audit records, and dispatches alerts.\n\n\
             vigild reads its configuration from the path given by the \
             environment variable VIGIL_CONFIG (default: /etc/vigil/vigil.toml). \
             It accepts no command-line flags; runtime tuning is done through \
             the configuration file. Log verbosity is controlled by the RUST_LOG \
             environment variable (e.g. RUST_LOG=info).\n\n\
             vigild is normally started by systemd via the vigild.service unit. \
             Operators interact with the daemon through the vigil(1) command, \
             which speaks to vigild over a Unix-domain control socket.",
        )
        .arg(
            clap::Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .help("Print help"),
        )
        .arg(
            clap::Arg::new("version")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .help("Print version"),
        )
}
