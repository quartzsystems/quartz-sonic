//! quartz-sonic — Quartz Command fleet-management agent for SONiC switches.
//!
//! One binary at /usr/bin/quartz-sonic:
//!
//!   enroll '<TOKEN>'  — enroll this switch into Quartz Command
//!   status [--json]   — device ID, enrollment, gateway, cert, connectivity
//!   run               — the daemon (quartz-sonic.service's entry point)

use clap::{Parser, Subcommand};

mod cli;
mod control;
mod enrollment;
mod identity;
mod sonic;
mod state;

/// Generated tonic stubs for the QuartzCommand protos (see build.rs).
pub mod proto {
    pub mod enrollment {
        tonic::include_proto!("quartzcommand.enrollment.v1");
    }
    pub mod device {
        tonic::include_proto!("quartzcommand.device.v1");
    }
}

/// Agent version, from the VERSION file at the repo root (see build.rs —
/// Cargo.toml is checked against it at build time).
pub const VERSION: &str = env!("QS_VERSION");

#[derive(Parser)]
#[command(name = "quartz-sonic", version, about = "Quartz Command fleet-management agent for SONiC")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll this switch into Quartz Command with a console-issued token.
    Enroll {
        /// The enrollment token (quote it: the token contains '|').
        token: String,
        /// Re-attempt enrollment even though local state says enrolled
        /// (after the device was revoked in the console).
        #[arg(long)]
        force: bool,
    },
    /// Show enrollment / control-channel status.
    Status {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Run the agent daemon (the systemd unit's entry point).
    Run,
}

fn main() {
    // Structured logs to stderr; journald tags them via SyslogIdentifier.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("quartz_sonic=info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Cli::parse();
    let code = match args.command {
        Command::Enroll { token, force } => cli::enroll_cmd(&token, force),
        Command::Status { json } => cli::status(json),
        Command::Run => match control::daemon::run() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("quartz-sonic: {e:#}");
                1
            }
        },
    };
    std::process::exit(code);
}
