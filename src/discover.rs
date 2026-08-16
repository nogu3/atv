use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::error::{AtvError, ErrorKind};

const SERVICE_TYPE: &str = "_androidtvremote2._tcp.local.";

/// One discovered Android TV remote endpoint.
#[derive(Debug, Serialize)]
pub struct Device {
    pub name: String,
    pub host: String,
    pub port: u16,
}

/// stdout payload for `atv discover`.
#[derive(Debug, Serialize)]
pub struct DiscoverOutput {
    pub timestamp: String,
    pub devices: Vec<Device>,
}

/// Browses the LAN for `_androidtvremote2._tcp` services for
/// `timeout_secs`, returning every resolved device (deduplicated by
/// address and port; IPv4 preferred when a device advertises both).
pub fn discover(timeout_secs: u64) -> Result<DiscoverOutput, AtvError> {
    let mdns_err = |what: &str, e: &dyn std::fmt::Display| {
        AtvError::new(ErrorKind::ProtocolError, format!("{what}: {e}"))
    };
    let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| mdns_err("mDNS daemon failed", &e))?;
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| mdns_err("mDNS browse failed", &e))?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut devices: BTreeMap<String, Device> = BTreeMap::new();
    while let Some(remaining) = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
    {
        match receiver.recv_timeout(remaining) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                let addrs = info.get_addresses();
                let Some(addr) = addrs
                    .iter()
                    .find(|a| a.is_ipv4())
                    .or_else(|| addrs.iter().next())
                else {
                    continue;
                };
                let name = info
                    .get_fullname()
                    .strip_suffix(&format!(".{SERVICE_TYPE}"))
                    .unwrap_or(info.get_fullname())
                    .to_string();
                let device = Device {
                    name,
                    host: addr.to_string(),
                    port: info.get_port(),
                };
                devices.insert(format!("{}:{}", device.host, device.port), device);
            }
            Ok(_) => {}
            Err(_) => break, // timeout or channel closed: browsing is done
        }
    }
    daemon.shutdown().ok();
    Ok(DiscoverOutput {
        timestamp: crate::output::timestamp(),
        devices: devices.into_values().collect(),
    })
}
