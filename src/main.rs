mod cli;
mod config;
mod error;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command};
use error::{AtvError, ErrorKind};

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{}", err.to_json());
            err.exit_code()
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<(), AtvError> {
    let credential_dir = config::credential_dir_from_env()?;
    tracing::debug!(
        dir = %credential_dir.display(),
        host = %cli.command.args().host,
        port = cli.command.port(),
        "resolved credential directory and target"
    );

    match cli.command {
        Command::Pair(_) => Err(AtvError::new(
            ErrorKind::ProtocolError,
            "pair is not implemented yet (Phase 1)",
        )),
        Command::Status(_) | Command::On(_) | Command::Off(_) => {
            config::ensure_paired(&credential_dir)?;
            Err(AtvError::new(
                ErrorKind::ProtocolError,
                "session commands are not implemented yet (Phase 2)",
            ))
        }
    }
}
