use std::net::UdpSocket;

use crate::error::{AtvError, ErrorKind};

/// Parses a MAC address in `aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff`
/// form (case-insensitive) into its six bytes.
pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let err = || format!("invalid MAC address {s:?} (expected aa:bb:cc:dd:ee:ff)");
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return Err(err());
    }
    let mut mac = [0u8; 6];
    for (byte, part) in mac.iter_mut().zip(&parts) {
        if part.len() != 2 {
            return Err(err());
        }
        *byte = u8::from_str_radix(part, 16).map_err(|_| err())?;
    }
    Ok(mac)
}

/// Builds a Wake-on-LAN magic packet: six 0xff bytes followed by the MAC
/// repeated sixteen times.
pub fn magic_packet(mac: [u8; 6]) -> [u8; 102] {
    let mut pkt = [0xffu8; 102];
    for i in 0..16 {
        pkt[6 + i * 6..12 + i * 6].copy_from_slice(&mac);
    }
    pkt
}

/// Broadcasts a Wake-on-LAN magic packet for `mac` (UDP port 9).
pub fn send_magic_packet(mac: [u8; 6]) -> Result<(), AtvError> {
    let io_err = |e: std::io::Error| {
        AtvError::new(
            ErrorKind::ProtocolError,
            format!("wake-on-lan send failed: {e}"),
        )
    };
    let socket = UdpSocket::bind(("0.0.0.0", 0)).map_err(io_err)?;
    socket.set_broadcast(true).map_err(io_err)?;
    socket
        .send_to(&magic_packet(mac), ("255.255.255.255", 9))
        .map_err(io_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_dash_and_uppercase_macs() {
        let want = [0xe4, 0x3b, 0xc9, 0x97, 0x84, 0x77];
        assert_eq!(parse_mac("e4:3b:c9:97:84:77").unwrap(), want);
        assert_eq!(parse_mac("E4-3B-C9-97-84-77").unwrap(), want);
    }

    #[test]
    fn rejects_malformed_macs() {
        for bad in [
            "",
            "e4:3b:c9:97:84",
            "e4:3b:c9:97:84:77:00",
            "zz:3b:c9:97:84:77",
            "e43b:c9:97:84:77:00",
            "e:3b:c9:97:84:77",
        ] {
            assert!(parse_mac(bad).is_err(), "mac {bad:?}");
        }
    }

    #[test]
    fn magic_packet_is_6xff_plus_16_mac_repeats() {
        let mac = [0xe4, 0x3b, 0xc9, 0x97, 0x84, 0x77];
        let pkt = magic_packet(mac);
        assert_eq!(pkt.len(), 102);
        assert!(pkt[..6].iter().all(|&b| b == 0xff));
        for i in 0..16 {
            assert_eq!(&pkt[6 + i * 6..12 + i * 6], &mac, "repeat {i}");
        }
    }
}
