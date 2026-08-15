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
}
