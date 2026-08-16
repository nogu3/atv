mod cli;
mod config;
mod discover;
mod error;
mod framing;
mod identity;
mod output;
mod pairing;
mod proto;
mod session;
mod tls;
mod wol;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command};
use error::AtvError;

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
    let port = cli.command.port();
    if let Some(args) = cli.command.args() {
        tracing::debug!(host = %args.host, port, "target");
    }

    match cli.command {
        Command::Pair(args) => {
            let out = pairing::pair(args.host, port)?;
            output::emit(&out);
            Ok(())
        }
        Command::Status(args) => {
            let out = session::status(args.host, port)?;
            output::emit(&out);
            Ok(())
        }
        Command::On(args) => {
            let out = session::set_power_with_wake(args.target.host, port, true, args.mac)?;
            output::emit(&out);
            Ok(())
        }
        Command::Off(args) => {
            let out = session::set_power(args.host, port, false)?;
            output::emit(&out);
            Ok(())
        }
        Command::Key(args) => {
            let out = session::send_keys(args.target.host, port, &args.keys)?;
            output::emit(&out);
            Ok(())
        }
        Command::Launch(args) => {
            let out = session::send_app_link(args.target.host, port, &args.app_link)?;
            output::emit(&out);
            Ok(())
        }
        Command::Discover(args) => {
            let out = discover::discover(args.timeout)?;
            output::emit(&out);
            Ok(())
        }
    }
}
