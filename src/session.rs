use serde::Serialize;

use crate::error::{AtvError, ErrorKind};
use crate::proto::remote::{
    RemoteConfigure, RemoteDeviceInfo, RemoteDirection, RemoteKeyCode, RemoteKeyInject,
    RemoteMessage, RemotePingResponse, RemoteSetActive,
};

/// Feature bits this client supports: PING (1) | KEY (2) | POWER (32).
pub const FEATURES: i32 = 1 | 2 | 32;

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
                FEATURES & configure.code1
            } else {
                FEATURES
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

/// Builds the `RemoteMessage` that injects a short press of the power key.
#[cfg_attr(not(test), expect(dead_code))]
pub fn power_key_message() -> RemoteMessage {
    RemoteMessage {
        remote_key_inject: Some(RemoteKeyInject {
            key_code: RemoteKeyCode::KeycodePower as i32,
            direction: RemoteDirection::Short as i32,
        }),
        ..Default::default()
    }
}

/// Translates an I/O error from the session read loop into the appropriate
/// `AtvError`: a closed connection before any message flowed means the TV
/// rejected the client certificate; a timeout or other error after messages
/// flowed means the handshake stalled or the TV misbehaved mid-session.
pub(crate) fn map_session_read_error(e: std::io::Error, got_any_message: bool) -> AtvError {
    if !got_any_message {
        return AtvError::new(
            ErrorKind::AuthRejected,
            "TV closed the session immediately — client certificate rejected, re-pair needed",
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
        assert!(map_session_read_error(e, false)
            .to_json()
            .contains("auth_rejected"));
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
}
