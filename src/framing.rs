use std::io::{self, Read, Write};

use prost::Message;

const MAX_FRAME: u64 = 1024 * 1024;

#[allow(dead_code)]
pub fn write_message<M: Message, W: Write>(w: &mut W, msg: &M) -> io::Result<()> {
    let body = msg.encode_to_vec();
    let mut frame = Vec::with_capacity(body.len() + 5);
    let mut len = body.len() as u64;
    loop {
        let byte = (len & 0x7f) as u8;
        len >>= 7;
        if len == 0 {
            frame.push(byte);
            break;
        }
        frame.push(byte | 0x80);
    }
    frame.extend_from_slice(&body);
    w.write_all(&frame)
}

#[allow(dead_code)]
pub fn read_message<M: Message + Default, R: Read>(r: &mut R) -> io::Result<M> {
    let mut len: u64 = 0;
    for shift in 0..5u32 {
        let mut byte = [0u8; 1];
        r.read_exact(&mut byte)?;
        len |= u64::from(byte[0] & 0x7f) << (7 * shift);
        if byte[0] & 0x80 == 0 {
            break;
        }
        if shift == 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint too long",
            ));
        }
    }
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds 1 MiB",
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    M::decode(&body[..]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::remote::{RemoteMessage, RemoteStart};
    use std::io::Cursor;

    fn start_msg(started: bool) -> RemoteMessage {
        RemoteMessage {
            remote_start: Some(RemoteStart { started }),
            ..Default::default()
        }
    }

    #[test]
    fn roundtrips_a_message() {
        let mut buf = Vec::new();
        write_message(&mut buf, &start_msg(true)).unwrap();
        let back: RemoteMessage = read_message(&mut Cursor::new(&buf)).unwrap();
        assert!(back.remote_start.unwrap().started);
    }

    #[test]
    fn length_prefix_is_a_varint() {
        // Small frame with single field → payload fits in 1 byte → 1-byte varint prefix
        let msg = RemoteMessage {
            remote_ping_response: Some(crate::proto::remote::RemotePingResponse { val1: 1 }),
            ..Default::default()
        };
        let mut one = Vec::new();
        write_message(&mut one, &msg).unwrap();
        // first byte of a small frame == payload length
        assert_eq!(one[0] as usize, one.len() - 1);
    }

    #[test]
    fn reads_two_consecutive_messages() {
        let mut buf = Vec::new();
        write_message(&mut buf, &start_msg(true)).unwrap();
        write_message(&mut buf, &start_msg(false)).unwrap();
        let mut cur = Cursor::new(&buf);
        let a: RemoteMessage = read_message(&mut cur).unwrap();
        let b: RemoteMessage = read_message(&mut cur).unwrap();
        assert!(a.remote_start.unwrap().started);
        assert!(!b.remote_start.unwrap().started);
    }

    #[test]
    fn rejects_oversized_frames() {
        // varint 0x80 0x80 0x80 0x01 = 2_097_152 (> 1 MiB cap)
        let buf = [0x80u8, 0x80, 0x80, 0x01, 0x00];
        let err = read_message::<RemoteMessage, _>(&mut Cursor::new(&buf)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn multi_byte_varint_prefix_roundtrips() {
        // Create a RemoteMessage with long strings to force payload > 127 bytes
        // This requires a multi-byte varint prefix (≥2 bytes)
        let long_string = "x".repeat(150);
        let msg = RemoteMessage {
            remote_configure: Some(crate::proto::remote::RemoteConfigure {
                code1: 1,
                device_info: Some(crate::proto::remote::RemoteDeviceInfo {
                    model: long_string.clone(),
                    vendor: long_string.clone(),
                    unknown1: 0,
                    unknown2: String::new(),
                    package_name: String::new(),
                    app_version: String::new(),
                }),
            }),
            ..Default::default()
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).unwrap();

        // Verify that the first byte has the continuation bit set (multi-byte varint)
        assert_ne!(
            buf[0] & 0x80,
            0,
            "first byte should have continuation bit set"
        );

        // Round-trip: write and read back
        let back: RemoteMessage = read_message(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(
            back.remote_configure.unwrap().device_info.unwrap().model,
            long_string
        );
    }

    #[test]
    fn accepts_frame_at_1mib_boundary() {
        // Test that a frame length of exactly MAX_FRAME passes the boundary check.
        // Create a small buffer and verify it reads without hitting "frame exceeds 1 MiB" error.
        let mut buf = Vec::new();

        // Encode MAX_FRAME (1_048_576) as a varint
        let mut len = MAX_FRAME;
        loop {
            let byte = (len & 0x7f) as u8;
            len >>= 7;
            if len == 0 {
                buf.push(byte);
                break;
            }
            buf.push(byte | 0x80);
        }

        // Append a default empty RemoteMessage encoded (will be small, but pad with zeros)
        let empty_payload = RemoteMessage::default().encode_to_vec();
        buf.extend_from_slice(&empty_payload);
        // Pad with zeros to complete the promised MAX_FRAME bytes in a small test
        // We won't actually allocate MAX_FRAME, just verify the length check logic works
        // by checking that a message claiming to be MAX_FRAME bytes doesn't trigger
        // the "exceeds 1 MiB" error before trying to read_exact
        //
        // Since read_exact will fail anyway (not enough data), we just check the error
        // is not about exceeding the frame size limit
        let result: io::Result<RemoteMessage> = read_message(&mut Cursor::new(&buf));

        // We expect an error (incomplete read), but not "frame exceeds 1 MiB"
        match result {
            Ok(_) => {
                // Empty message decoded OK - ideal case, passes test
            }
            Err(e) => {
                // Should be EOF or incomplete, not "frame exceeds 1 MiB"
                let err_str = e.to_string();
                assert!(
                    !err_str.contains("frame exceeds 1 MiB"),
                    "should accept length == MAX_FRAME, but got error: {}",
                    err_str
                );
            }
        }
    }

    #[test]
    fn rejects_frame_exceeding_1mib() {
        // Create a frame with payload exceeding MAX_FRAME by 1 byte
        // Varint for 1_048_577 (MAX_FRAME + 1): 0x81 0x80 0x80 0x04
        let buf = vec![0x81u8, 0x80, 0x80, 0x04];

        // This should fail with InvalidData before trying to read that many bytes
        let err = read_message::<RemoteMessage, _>(&mut Cursor::new(&buf)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("frame exceeds 1 MiB"));
    }
}
