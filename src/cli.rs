use std::net::IpAddr;

use clap::{Args, Parser, Subcommand};

use crate::proto::remote::RemoteKeyCode;

const PAIRING_PORT: u16 = 6467;
const SESSION_PORT: u16 = 6466;

/// Parses a keycode argument: a name with or without the `KEYCODE_` prefix
/// (case-insensitive), or a numeric value. Validated against the vendored
/// protocol enum.
fn parse_keycode(s: &str) -> Result<i32, String> {
    if let Ok(n) = s.parse::<i32>() {
        return RemoteKeyCode::try_from(n)
            .map(|k| k as i32)
            .map_err(|_| format!("{n} is not a known Android keycode"));
    }
    let upper = s.to_ascii_uppercase();
    let name = if upper.starts_with("KEYCODE_") {
        upper
    } else {
        format!("KEYCODE_{upper}")
    };
    RemoteKeyCode::from_str_name(&name)
        .map(|k| k as i32)
        .ok_or_else(|| format!("unknown keycode {s:?} (expected e.g. VOLUME_UP or KEYCODE_POWER)"))
}

#[derive(Debug, Parser)]
#[command(
    name = "atv",
    version,
    about = "Android TV Remote v2 CLI — power, keys, app launch, discovery"
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
    /// Power on (idempotent; --mac enables a Wake-on-LAN fallback)
    On(OnArgs),
    /// Power off (idempotent)
    Off(HostArgs),
    /// Send one or more key presses (e.g. VOLUME_UP, DPAD_CENTER)
    Key(KeyArgs),
    /// Launch an app via an app link / deeplink
    Launch(LaunchArgs),
    /// Discover Android TV remote devices on the LAN via mDNS
    Discover(DiscoverArgs),
}

impl Command {
    pub fn args(&self) -> Option<&HostArgs> {
        match self {
            Command::Pair(a) | Command::Status(a) | Command::Off(a) => Some(a),
            Command::On(o) => Some(&o.target),
            Command::Key(k) => Some(&k.target),
            Command::Launch(l) => Some(&l.target),
            Command::Discover(_) => None,
        }
    }

    pub fn port(&self) -> u16 {
        let default = match self {
            Command::Pair(_) => PAIRING_PORT,
            _ => SESSION_PORT,
        };
        self.args().and_then(|a| a.port).unwrap_or(default)
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

#[derive(Debug, Args)]
pub struct OnArgs {
    #[command(flatten)]
    pub target: HostArgs,

    /// TV MAC address; when set and the TV is unreachable (deep standby),
    /// send a Wake-on-LAN magic packet and retry
    #[arg(long, value_parser = crate::wol::parse_mac)]
    pub mac: Option<[u8; 6]>,
}

#[derive(Debug, Args)]
pub struct KeyArgs {
    #[command(flatten)]
    pub target: HostArgs,

    /// Keycodes: names with or without the KEYCODE_ prefix, or numeric values
    #[arg(required = true, value_parser = parse_keycode)]
    pub keys: Vec<i32>,
}

#[derive(Debug, Args)]
pub struct LaunchArgs {
    #[command(flatten)]
    pub target: HostArgs,

    /// App link to launch (e.g. https://www.youtube.com)
    pub app_link: String,
}

#[derive(Debug, Args)]
pub struct DiscoverArgs {
    /// How long to browse for devices, in seconds
    #[arg(long, default_value_t = 3)]
    pub timeout: u64,
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
    fn on_accepts_an_optional_mac_for_wake_on_lan() {
        let cli = Cli::try_parse_from([
            "atv",
            "on",
            "--host",
            "192.0.2.10",
            "--mac",
            "e4:3b:c9:97:84:77",
        ])
        .unwrap();
        let Command::On(args) = cli.command else {
            panic!("expected on");
        };
        assert_eq!(args.mac, Some([0xe4, 0x3b, 0xc9, 0x97, 0x84, 0x77]));

        let cli = Cli::try_parse_from(["atv", "on", "--host", "192.0.2.10"]).unwrap();
        let Command::On(args) = cli.command else {
            panic!("expected on");
        };
        assert_eq!(args.mac, None);
    }

    #[test]
    fn on_rejects_invalid_macs() {
        assert!(
            Cli::try_parse_from(["atv", "on", "--host", "192.0.2.10", "--mac", "nope"]).is_err()
        );
    }

    #[test]
    fn key_accepts_names_with_and_without_prefix_and_numbers() {
        let cli = Cli::try_parse_from([
            "atv",
            "key",
            "--host",
            "192.0.2.10",
            "VOLUME_UP",
            "KEYCODE_DPAD_CENTER",
            "26",
        ])
        .unwrap();
        let Command::Key(args) = cli.command else {
            panic!("expected key");
        };
        assert_eq!(args.keys, vec![24, 23, 26]);
    }

    #[test]
    fn key_rejects_unknown_names_and_invalid_numbers() {
        for bad in ["NOT_A_KEY", "99999"] {
            assert!(
                Cli::try_parse_from(["atv", "key", "--host", "192.0.2.10", bad]).is_err(),
                "key {bad:?}"
            );
        }
    }

    #[test]
    fn key_requires_at_least_one_keycode() {
        assert!(Cli::try_parse_from(["atv", "key", "--host", "192.0.2.10"]).is_err());
    }

    #[test]
    fn launch_takes_an_app_link() {
        let cli = Cli::try_parse_from([
            "atv",
            "launch",
            "--host",
            "192.0.2.10",
            "https://www.youtube.com",
        ])
        .unwrap();
        let Command::Launch(args) = cli.command else {
            panic!("expected launch");
        };
        assert_eq!(args.app_link, "https://www.youtube.com");
    }

    #[test]
    fn discover_needs_no_host_and_defaults_to_3s() {
        let cli = Cli::try_parse_from(["atv", "discover"]).unwrap();
        assert!(cli.command.args().is_none());
        let Command::Discover(args) = cli.command else {
            panic!("expected discover");
        };
        assert_eq!(args.timeout, 3);
    }

    #[test]
    fn key_and_launch_default_to_session_port() {
        let cli = Cli::try_parse_from(["atv", "key", "--host", "192.0.2.10", "VOLUME_UP"]).unwrap();
        assert_eq!(cli.command.port(), 6466);
        let cli = Cli::try_parse_from(["atv", "launch", "--host", "192.0.2.10", "x"]).unwrap();
        assert_eq!(cli.command.port(), 6466);
    }

    #[test]
    fn host_must_be_an_ip_address_not_a_name() {
        assert!(Cli::try_parse_from(["atv", "status", "--host", "tv.local"]).is_err());
    }
}
