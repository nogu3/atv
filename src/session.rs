use crate::error::{AtvError, ErrorKind};
use crate::proto::remote::{
    RemoteConfigure, RemoteDeviceInfo, RemoteDirection, RemoteKeyCode, RemoteKeyInject,
    RemoteMessage, RemotePingResponse, RemoteSetActive,
};

/// Feature bits this client supports: PING (1) | KEY (2) | POWER (32).
#[cfg_attr(not(test), expect(dead_code))]
pub const FEATURES: i32 = 1 | 2 | 32;

/// Tracks the state of the Remote v2 session handshake (configure /
/// set_active / ping / start) as messages arrive from the TV.
#[cfg_attr(not(test), expect(dead_code))]
pub struct SessionHandshake {
    pub power: Option<bool>,
    active_features: i32,
}

#[cfg_attr(not(test), expect(dead_code))]
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
}
