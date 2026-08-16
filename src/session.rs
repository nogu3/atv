use serde::Serialize;

use crate::error::{AtvError, ErrorKind};
use crate::proto::remote::{
    RemoteConfigure, RemoteDeviceInfo, RemoteDirection, RemoteKeyCode, RemoteKeyInject,
    RemoteMessage, RemotePingResponse, RemoteSetActive,
};

/// Feature bits this client supports:
/// PING (1) | KEY (2) | POWER (32) | APP_LINK (512).
pub const FEATURES: i32 = 1 | 2 | 32 | 512;

/// Grace period between the session becoming ready (`remote_start`) and
/// sending a key inject. TVs silently drop keys that arrive too early
/// (see the comment in [`set_power`]); one second gives a comfortable
/// margin over the measured threshold.
const KEY_INJECT_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Tracks the state of the Remote v2 session handshake (configure /
/// set_active / ping / start) as messages arrive from the TV.
pub struct SessionHandshake {
    pub power: Option<bool>,
    active_features: i32,
}

impl SessionHandshake {
    pub fn new() -> Self {
        Self {
            power: None,
            active_features: FEATURES,
        }
    }

    /// Handles one inbound `RemoteMessage`, returning the reply to send
    /// back (if any) or an error when the TV reports a protocol error.
    pub fn handle(&mut self, msg: RemoteMessage) -> Result<Option<RemoteMessage>, AtvError> {
        if let Some(configure) = msg.remote_configure {
            let code1 = if configure.code1 != 0 {
                self.active_features & configure.code1
            } else {
                self.active_features
            };
            self.active_features = code1;
            return Ok(Some(RemoteMessage {
                remote_configure: Some(RemoteConfigure {
                    code1,
                    device_info: Some(RemoteDeviceInfo {
                        model: String::new(),
                        vendor: String::new(),
                        unknown1: 1,
                        unknown2: "1".to_string(),
                        package_name: "atv".to_string(),
                        app_version: env!("CARGO_PKG_VERSION").to_string(),
                    }),
                }),
                ..Default::default()
            }));
        }

        if msg.remote_set_active.is_some() {
            return Ok(Some(RemoteMessage {
                remote_set_active: Some(RemoteSetActive {
                    active: self.active_features,
                }),
                ..Default::default()
            }));
        }

        if let Some(ping) = msg.remote_ping_request {
            return Ok(Some(RemoteMessage {
                remote_ping_response: Some(RemotePingResponse { val1: ping.val1 }),
                ..Default::default()
            }));
        }

        if let Some(start) = msg.remote_start {
            self.power = Some(start.started);
            return Ok(None);
        }

        if msg.remote_error.is_some() {
            return Err(AtvError::new(
                ErrorKind::ProtocolError,
                "TV reported a remote error",
            ));
        }

        Ok(None)
    }
}

impl Default for SessionHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds the `RemoteMessage` that injects a short press of `key_code`.
pub fn key_message(key_code: i32) -> RemoteMessage {
    RemoteMessage {
        remote_key_inject: Some(RemoteKeyInject {
            key_code,
            direction: RemoteDirection::Short as i32,
        }),
        ..Default::default()
    }
}

/// Builds the `RemoteMessage` that injects a short press of the power key.
pub fn power_key_message() -> RemoteMessage {
    key_message(RemoteKeyCode::KeycodePower as i32)
}

/// Builds the `RemoteMessage` that asks the TV to launch an app link.
pub fn app_link_message(app_link: &str) -> RemoteMessage {
    RemoteMessage {
        remote_app_link_launch_request: Some(crate::proto::remote::RemoteAppLinkLaunchRequest {
            app_link: app_link.to_string(),
        }),
        ..Default::default()
    }
}

/// Canonical `KEYCODE_*` name for a keycode, falling back to the number
/// itself for values the vendored proto does not name.
pub fn keycode_name(key_code: i32) -> String {
    RemoteKeyCode::try_from(key_code)
        .map(|k| k.as_str_name().to_string())
        .unwrap_or_else(|_| key_code.to_string())
}

/// Translates an I/O error from the session read loop into the appropriate
/// `AtvError`: a closed connection before any message flowed means the TV
/// rejected the client certificate; a timeout or other error after messages
/// flowed means the handshake stalled or the TV misbehaved mid-session.
pub(crate) fn map_session_read_error(e: std::io::Error, got_any_message: bool) -> AtvError {
    if !got_any_message {
        return AtvError::new(
            ErrorKind::AuthRejected,
            format!(
                "TV closed the session immediately — client certificate rejected, re-pair needed ({e})"
            ),
        );
    }
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => AtvError::new(
            ErrorKind::ProtocolError,
            "TV stopped responding during session handshake",
        ),
        _ => AtvError::new(ErrorKind::ProtocolError, e.to_string()),
    }
}

/// Connects to the session port and pumps messages through
/// `SessionHandshake` until the TV's power state is known. Returns the
/// power state alongside the live connection and handshake state so
/// callers (e.g. `on`/`off`) can keep talking to the TV without
/// reconnecting.
pub fn read_power(
    host: std::net::IpAddr,
    port: u16,
) -> Result<(bool, crate::tls::Conn, SessionHandshake), AtvError> {
    let dir = crate::config::credential_dir_from_env()?;
    let tls = crate::tls::TlsClient::from_credential_dir(&dir)?;
    let mut conn = tls.connect(host, port, std::time::Duration::from_secs(5))?;
    let mut hs = SessionHandshake::new();
    let mut got_any = false;
    while hs.power.is_none() {
        let msg: crate::proto::remote::RemoteMessage = crate::framing::read_message(&mut conn)
            .map_err(|e| map_session_read_error(e, got_any))?;
        got_any = true;
        tracing::debug!(?msg, "session message received");
        if let Some(reply) = hs.handle(msg)? {
            crate::framing::write_message(&mut conn, &reply).map_err(|e| {
                AtvError::new(
                    ErrorKind::ProtocolError,
                    format!("session write failed: {e}"),
                )
            })?;
        }
    }
    let power = hs.power.expect("loop exits only with power set");
    Ok((power, conn, hs))
}

/// Maps a boolean power state to the documented `"on"`/`"off"` string.
pub fn power_str(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}

/// stdout payload for `atv status`.
#[derive(Debug, Serialize)]
pub struct StatusOutput {
    pub timestamp: String,
    pub host: String,
    pub power: &'static str,
}

/// Connects to the TV, reads its power state, and builds the `status`
/// output. The connection and handshake are dropped once the state is
/// known — `status` is one-shot.
pub fn status(host: std::net::IpAddr, port: u16) -> Result<StatusOutput, AtvError> {
    let (on, _conn, _hs) = read_power(host, port)?;
    Ok(StatusOutput {
        timestamp: crate::output::timestamp(),
        host: host.to_string(),
        power: power_str(on),
    })
}

/// Gap between successive key presses in one `key` invocation.
const KEY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Settle time after the last inject before the connection is dropped, so
/// the TV has processed the message before we close on it.
const SEND_SETTLE: std::time::Duration = std::time::Duration::from_millis(250);

/// stdout payload for `atv key`.
#[derive(Debug, Serialize)]
pub struct KeysOutput {
    pub timestamp: String,
    pub host: String,
    pub keys: Vec<String>,
}

/// Connects to the TV and injects the given key presses in order, with the
/// same post-handshake grace period the power path needs (see
/// [`KEY_INJECT_GRACE`]).
pub fn send_keys(host: std::net::IpAddr, port: u16, keys: &[i32]) -> Result<KeysOutput, AtvError> {
    let (_on, mut conn, _hs) = read_power(host, port)?;
    std::thread::sleep(KEY_INJECT_GRACE);
    for (i, &code) in keys.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(KEY_INTERVAL);
        }
        crate::framing::write_message(&mut conn, &key_message(code)).map_err(|e| {
            AtvError::new(
                ErrorKind::ProtocolError,
                format!("failed to send {}: {e}", keycode_name(code)),
            )
        })?;
    }
    std::thread::sleep(SEND_SETTLE);
    Ok(KeysOutput {
        timestamp: crate::output::timestamp(),
        host: host.to_string(),
        keys: keys.iter().map(|&c| keycode_name(c)).collect(),
    })
}

/// stdout payload for `atv launch`.
#[derive(Debug, Serialize)]
pub struct LaunchOutput {
    pub timestamp: String,
    pub host: String,
    pub app_link: String,
}

/// Connects to the TV and asks it to launch the given app link.
pub fn send_app_link(
    host: std::net::IpAddr,
    port: u16,
    app_link: &str,
) -> Result<LaunchOutput, AtvError> {
    let (_on, mut conn, _hs) = read_power(host, port)?;
    std::thread::sleep(KEY_INJECT_GRACE);
    crate::framing::write_message(&mut conn, &app_link_message(app_link)).map_err(|e| {
        AtvError::new(
            ErrorKind::ProtocolError,
            format!("failed to send app link: {e}"),
        )
    })?;
    std::thread::sleep(SEND_SETTLE);
    Ok(LaunchOutput {
        timestamp: crate::output::timestamp(),
        host: host.to_string(),
        app_link: app_link.to_string(),
    })
}

/// Whether a power key press is required to move from `current_on` to
/// `want_on`. Idempotent: same state on both sides means no-op.
pub fn needs_power_key(current_on: bool, want_on: bool) -> bool {
    current_on != want_on
}

/// stdout payload for `atv on` / `atv off`.
#[derive(Debug, Serialize)]
pub struct PowerOutput {
    pub timestamp: String,
    pub host: String,
    pub power: &'static str,
    pub changed: bool,
    /// Present (true) only when a Wake-on-LAN magic packet was needed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol: Option<bool>,
}

/// Connects to the TV, reads its current power state, and — only if it
/// differs from `want_on` — sends a power key press. Idempotent: an
/// already-matching state is a no-op (`changed: false`).
///
/// After sending the key, best-effort waits for the TV to confirm the new
/// state via a fresh `remote_start` message, bounded to ~5 s total (each
/// read has its own 3 s timeout, but a chattering TV that keeps sending
/// other messages — pings, etc. — without ever confirming is still cut off
/// by the overall deadline). On timeout, deadline expiry, or connection
/// close (typical when the TV powers off), the assumed target state is
/// reported instead of blocking indefinitely.
pub fn set_power(
    host: std::net::IpAddr,
    port: u16,
    want_on: bool,
) -> Result<PowerOutput, AtvError> {
    let (current, mut conn, mut hs) = read_power(host, port)?;
    let changed = needs_power_key(current, want_on);
    let mut resulting = current;
    if changed {
        // Key injects sent right after `remote_start` are silently dropped by
        // some TVs (measured on a TOSHIBA REGZA 65X8900K / Hisense "SmartTV
        // FFM" firmware: keys within ~100 ms of remote_start are lost, ~300 ms
        // works). The reference implementation never hits this because a human
        // presses buttons long after connecting. Wait a grace period before
        // injecting.
        std::thread::sleep(KEY_INJECT_GRACE);
        crate::framing::write_message(&mut conn, &power_key_message()).map_err(|e| {
            AtvError::new(
                ErrorKind::ProtocolError,
                format!("failed to send power key: {e}"),
            )
        })?;
        // Best effort: wait for the TV to confirm the new state via
        // remote_start, bounded to ~5 s total. Each read has its own 3 s
        // timeout, but that alone isn't a deadline — a chattering TV (e.g.
        // periodic pings) that never sends remote_start would keep resetting
        // the per-read clock and hold this one-shot CLI open indefinitely.
        // The wall-clock deadline below is what actually bounds the loop.
        // On timeout, deadline expiry, or connection close (typical when
        // turning off), assume the key worked and report the target state.
        conn.sock
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .ok();
        hs.power = None; // any Some(...) from here on is a fresh observation
        resulting = want_on;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        // Err(_) (timeout or connection close) ends the loop, leaving the
        // pre-seeded assumed target state in place.
        while std::time::Instant::now() < deadline {
            let Ok(msg) =
                crate::framing::read_message::<crate::proto::remote::RemoteMessage, _>(&mut conn)
            else {
                break;
            };
            tracing::debug!(?msg, "message received while awaiting power confirmation");
            match hs.handle(msg) {
                Ok(Some(reply)) => {
                    let _ = crate::framing::write_message(&mut conn, &reply);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!(
                        "ignoring error while awaiting power confirmation: {}",
                        e.to_json()
                    );
                }
            }
            if hs.power == Some(want_on) {
                break;
            }
        }
        if let Some(observed) = hs.power {
            resulting = observed;
        }
    }
    Ok(PowerOutput {
        timestamp: crate::output::timestamp(),
        host: host.to_string(),
        power: power_str(resulting),
        changed,
        wol: None,
    })
}

/// How long to wait for the TV's network stack to come back after a
/// Wake-on-LAN magic packet (measured ~5 s on the REGZA).
const WOL_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// Like [`set_power`], but when turning on an unreachable TV with a known
/// MAC address, falls back to a Wake-on-LAN magic packet: send it, wait for
/// the session port to come back, then run the normal power-on flow. TVs in
/// deep standby (after ~10 min off on the REGZA) drop off the network
/// entirely and can only be woken this way.
pub fn set_power_with_wake(
    host: std::net::IpAddr,
    port: u16,
    want_on: bool,
    mac: Option<[u8; 6]>,
) -> Result<PowerOutput, AtvError> {
    let first = set_power(host, port, want_on);
    let Some(mac) = mac else {
        return first;
    };
    match first {
        Err(e) if want_on && e.kind() == ErrorKind::Unreachable => {
            tracing::debug!("TV unreachable — sending wake-on-lan magic packet");
            crate::wol::send_magic_packet(mac)?;
            wait_for_port(host, port, WOL_WAIT)?;
            let mut out = set_power(host, port, want_on)?;
            out.wol = Some(true);
            Ok(out)
        }
        other => other,
    }
}

/// Polls the TCP port until it accepts a connection or `budget` runs out.
fn wait_for_port(
    host: std::net::IpAddr,
    port: u16,
    budget: std::time::Duration,
) -> Result<(), AtvError> {
    let addr = std::net::SocketAddr::new(host, port);
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(1)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(AtvError::new(
        ErrorKind::Unreachable,
        format!("{addr} still unreachable after a wake-on-lan magic packet — wrong MAC, or WoL disabled on the TV?"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::remote::*;

    #[test]
    fn replies_to_configure_with_intersected_features() {
        let mut hs = SessionHandshake::new();
        let msg = RemoteMessage {
            remote_configure: Some(RemoteConfigure {
                code1: 3, // server supports only PING|KEY
                device_info: None,
            }),
            ..Default::default()
        };
        let reply = hs.handle(msg).unwrap().unwrap();
        let cfg = reply.remote_configure.unwrap();
        assert_eq!(cfg.code1, 3); // 35 & 3
        let info = cfg.device_info.unwrap();
        assert_eq!(info.package_name, "atv");
        assert_eq!(info.unknown1, 1);
        assert_eq!(info.unknown2, "1");
    }

    #[test]
    fn replies_to_set_active_with_features() {
        let mut hs = SessionHandshake::new();
        let msg = RemoteMessage {
            remote_set_active: Some(RemoteSetActive { active: 0 }),
            ..Default::default()
        };
        let reply = hs.handle(msg).unwrap().unwrap();
        assert_eq!(reply.remote_set_active.unwrap().active, FEATURES);
    }

    #[test]
    fn set_active_reply_uses_features_intersected_by_prior_configure() {
        let mut hs = SessionHandshake::new();
        let configure_msg = RemoteMessage {
            remote_configure: Some(RemoteConfigure {
                code1: 3, // server supports only PING|KEY
                device_info: None,
            }),
            ..Default::default()
        };
        hs.handle(configure_msg).unwrap();

        let set_active_msg = RemoteMessage {
            remote_set_active: Some(RemoteSetActive { active: 0 }),
            ..Default::default()
        };
        let reply = hs.handle(set_active_msg).unwrap().unwrap();
        assert_eq!(reply.remote_set_active.unwrap().active, 3);
    }

    #[test]
    fn echoes_ping_val1() {
        let mut hs = SessionHandshake::new();
        let msg = RemoteMessage {
            remote_ping_request: Some(RemotePingRequest { val1: 42, val2: 7 }),
            ..Default::default()
        };
        let reply = hs.handle(msg).unwrap().unwrap();
        assert_eq!(reply.remote_ping_response.unwrap().val1, 42);
    }

    #[test]
    fn remote_start_sets_power_and_needs_no_reply() {
        let mut hs = SessionHandshake::new();
        let msg = RemoteMessage {
            remote_start: Some(RemoteStart { started: true }),
            ..Default::default()
        };
        assert!(hs.handle(msg).unwrap().is_none());
        assert_eq!(hs.power, Some(true));
    }

    #[test]
    fn remote_start_transitions_power_from_true_to_false() {
        let mut hs = SessionHandshake::new();
        hs.handle(RemoteMessage {
            remote_start: Some(RemoteStart { started: true }),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(hs.power, Some(true));

        hs.handle(RemoteMessage {
            remote_start: Some(RemoteStart { started: false }),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(hs.power, Some(false));
    }

    #[test]
    fn unknown_messages_are_ignored() {
        let mut hs = SessionHandshake::new();
        assert!(hs.handle(RemoteMessage::default()).unwrap().is_none());
        assert_eq!(hs.power, None);
    }

    #[test]
    fn remote_error_is_protocol_error() {
        let mut hs = SessionHandshake::new();
        let msg = RemoteMessage {
            remote_error: Some(Box::new(RemoteError {
                value: true,
                message: None,
            })),
            ..Default::default()
        };
        assert!(hs
            .handle(msg)
            .unwrap_err()
            .to_json()
            .contains("protocol_error"));
    }

    #[test]
    fn power_key_message_is_short_power() {
        let msg = power_key_message();
        let inject = msg.remote_key_inject.unwrap();
        assert_eq!(inject.key_code, RemoteKeyCode::KeycodePower as i32);
        assert_eq!(inject.direction, RemoteDirection::Short as i32);
    }

    #[test]
    fn eof_before_any_message_means_auth_rejected() {
        let e = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let json = map_session_read_error(e, false).to_json();
        assert!(json.contains("auth_rejected"));
        assert!(json.contains("eof"));
    }

    #[test]
    fn timeout_after_messages_is_protocol_error() {
        let e = std::io::Error::new(std::io::ErrorKind::TimedOut, "t");
        assert!(map_session_read_error(e, true)
            .to_json()
            .contains("protocol_error"));
    }

    #[test]
    fn power_str_maps_bool() {
        assert_eq!(power_str(true), "on");
        assert_eq!(power_str(false), "off");
    }

    #[test]
    fn features_include_app_link() {
        assert_eq!(FEATURES, 1 | 2 | 32 | 512);
    }

    #[test]
    fn key_message_builds_short_press_for_any_code() {
        let msg = key_message(RemoteKeyCode::KeycodeVolumeUp as i32);
        let inject = msg.remote_key_inject.unwrap();
        assert_eq!(inject.key_code, 24);
        assert_eq!(inject.direction, RemoteDirection::Short as i32);
    }

    #[test]
    fn keycode_name_maps_code_to_canonical_name() {
        assert_eq!(keycode_name(24), "KEYCODE_VOLUME_UP");
        assert_eq!(keycode_name(26), "KEYCODE_POWER");
    }

    #[test]
    fn app_link_message_carries_the_link() {
        let msg = app_link_message("https://www.youtube.com");
        assert_eq!(
            msg.remote_app_link_launch_request.unwrap().app_link,
            "https://www.youtube.com"
        );
    }

    #[test]
    fn power_key_sent_only_when_state_differs() {
        assert!(!needs_power_key(true, true)); // on → on: no-op
        assert!(!needs_power_key(false, false)); // off → off: no-op
        assert!(needs_power_key(false, true));
        assert!(needs_power_key(true, false));
    }
}
