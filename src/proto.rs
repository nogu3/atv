// The generated modules cover the full protocol surface described by the
// vendored `.proto` files; later phases (pairing, status, power) consume
// more of these types incrementally, so most are unused for now.
#[allow(dead_code)]
pub mod polo {
    include!(concat!(env!("OUT_DIR"), "/polo.wire.protobuf.rs"));
}
#[allow(dead_code)]
pub mod remote {
    include!(concat!(env!("OUT_DIR"), "/remote.rs"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn outer_message_roundtrips() {
        let msg = polo::OuterMessage {
            protocol_version: 2,
            status: polo::outer_message::Status::Ok as i32,
            ..Default::default()
        };
        let bytes = msg.encode_to_vec();
        let back = polo::OuterMessage::decode(&bytes[..]).unwrap();
        assert_eq!(back.protocol_version, 2);
    }

    #[test]
    fn remote_message_roundtrips() {
        let msg = remote::RemoteMessage {
            remote_start: Some(remote::RemoteStart { started: true }),
            ..Default::default()
        };
        let back = remote::RemoteMessage::decode(&msg.encode_to_vec()[..]).unwrap();
        assert!(back.remote_start.unwrap().started);
    }
}
