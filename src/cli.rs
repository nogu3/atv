use std::net::IpAddr;

use clap::{Args, Parser, Subcommand};

const PAIRING_PORT: u16 = 6467;
const SESSION_PORT: u16 = 6466;

#[derive(Debug, Parser)]
#[command(
    name = "atv",
    version,
    about = "Android TV Remote v2 power control CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// One-time pairing with a TV (reads the on-screen code from stdin)
    Pair(HostArgs),
    /// Report the device's power state
    Status(HostArgs),
    /// Power on (idempotent)
    On(HostArgs),
    /// Power off (idempotent)
    Off(HostArgs),
}

impl Command {
    pub fn args(&self) -> &HostArgs {
        match self {
            Command::Pair(a) | Command::Status(a) | Command::On(a) | Command::Off(a) => a,
        }
    }

    pub fn port(&self) -> u16 {
        let default = match self {
            Command::Pair(_) => PAIRING_PORT,
            _ => SESSION_PORT,
        };
        self.args().port.unwrap_or(default)
    }
}

#[derive(Debug, Args)]
pub struct HostArgs {
    /// TV address as an IP (no name resolution)
    #[arg(long)]
    pub host: IpAddr,

    /// TCP port (default: 6467 for pair, 6466 otherwise)
    #[arg(long)]
    pub port: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::net::{IpAddr, Ipv4Addr};

    const HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

    #[test]
    fn parses_status_with_host() {
        let cli = Cli::try_parse_from(["atv", "status", "--host", "192.0.2.10"]).unwrap();
        let Command::Status(args) = cli.command else {
            panic!("expected status");
        };
        assert_eq!(args.host, HOST);
    }

    #[test]
    fn session_commands_default_to_port_6466() {
        for sub in ["status", "on", "off"] {
            let cli = Cli::try_parse_from(["atv", sub, "--host", "192.0.2.10"]).unwrap();
            assert_eq!(cli.command.port(), 6466, "subcommand {sub}");
        }
    }

    #[test]
    fn pair_defaults_to_port_6467() {
        let cli = Cli::try_parse_from(["atv", "pair", "--host", "192.0.2.10"]).unwrap();
        assert_eq!(cli.command.port(), 6467);
    }

    #[test]
    fn explicit_port_overrides_default() {
        let cli =
            Cli::try_parse_from(["atv", "pair", "--host", "192.0.2.10", "--port", "7000"]).unwrap();
        assert_eq!(cli.command.port(), 7000);
    }

    #[test]
    fn host_is_required() {
        assert!(Cli::try_parse_from(["atv", "status"]).is_err());
    }

    #[test]
    fn host_must_be_an_ip_address_not_a_name() {
        assert!(Cli::try_parse_from(["atv", "status", "--host", "tv.local"]).is_err());
    }
}
