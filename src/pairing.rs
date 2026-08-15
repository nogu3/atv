use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use crate::error::{AtvError, ErrorKind};
use crate::proto::polo::{
    options, outer_message::Status, Configuration, Options, OuterMessage, PairingRequest, Secret,
};

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// Returns `(modulus, exponent)` of the certificate's RSA public key, as
/// unsigned big-endian bytes with leading `0x00` bytes stripped (DER
/// integers carry a leading `0x00` when the top bit is set; the reference
/// implementation hashes the stripped form, so this must match).
fn rsa_numbers(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AtvError> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        AtvError::new(
            ErrorKind::ProtocolError,
            format!("cannot parse certificate: {e}"),
        )
    })?;
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => Ok((
            strip_leading_zeros(rsa.modulus).to_vec(),
            strip_leading_zeros(rsa.exponent).to_vec(),
        )),
        _ => Err(AtvError::new(
            ErrorKind::ProtocolError,
            "certificate public key is not RSA",
        )),
    }
}

/// Computes the Android TV Remote v2 pairing secret: SHA-256 over
/// client-modulus ‖ client-exponent ‖ server-modulus ‖ server-exponent ‖
/// nonce (all big-endian, leading zero bytes stripped), where `code` is the
/// 6-hex-digit string shown on the TV screen (`code[0..2]` is a checksum
/// byte equal to `digest[0]`, `code[2..6]` is the nonce).
pub fn compute_pairing_secret(
    client_cert_der: &[u8],
    server_cert_der: &[u8],
    code: &str,
) -> Result<Vec<u8>, AtvError> {
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AtvError::new(
            ErrorKind::PairingFailed,
            format!("pairing code must be exactly 6 hex digits, got {code:?}"),
        ));
    }
    let checksum = u8::from_str_radix(&code[..2], 16).expect("validated hex");
    let nonce = [
        u8::from_str_radix(&code[2..4], 16).expect("validated hex"),
        u8::from_str_radix(&code[4..6], 16).expect("validated hex"),
    ];
    let (client_mod, client_exp) = rsa_numbers(client_cert_der)?;
    let (server_mod, server_exp) = rsa_numbers(server_cert_der)?;
    let mut hasher = Sha256::new();
    hasher.update(&client_mod);
    hasher.update(&client_exp);
    hasher.update(&server_mod);
    hasher.update(&server_exp);
    hasher.update(nonce);
    let digest = hasher.finalize().to_vec();
    if digest[0] != checksum {
        return Err(AtvError::new(
            ErrorKind::PairingFailed,
            "pairing code checksum mismatch — was the code mistyped?",
        ));
    }
    Ok(digest)
}

/// The fixed encoding this client advertises and later configures: a
/// 6-hex-digit code, matching [`compute_pairing_secret`]'s expectations.
fn hex6_encoding() -> options::Encoding {
    options::Encoding {
        r#type: options::encoding::EncodingType::Hexadecimal as i32,
        symbol_length: 6,
    }
}

/// Drives the polo (pairing) message exchange: given each message received
/// from the TV, produces at most one reply. Stateless beyond tracking
/// whether the configuration phase is done and the TV is now showing the
/// on-screen code.
pub struct PairingFlow {
    awaiting_code: bool,
}

impl PairingFlow {
    pub fn new() -> Self {
        Self {
            awaiting_code: false,
        }
    }

    /// The first message this client sends, opening the pairing request.
    pub fn initial_message() -> OuterMessage {
        OuterMessage {
            protocol_version: 2,
            status: Status::Ok as i32,
            pairing_request: Some(PairingRequest {
                service_name: "atvremote".to_string(),
                client_name: Some("atv".to_string()),
            }),
            ..Default::default()
        }
    }

    /// True once the configuration phase has been acknowledged and the TV
    /// is now displaying the on-screen code for the user to read.
    pub fn awaiting_code(&self) -> bool {
        self.awaiting_code
    }

    /// Consumes one message from the TV, returning the reply to send back
    /// (if any).
    pub fn handle(&mut self, msg: &OuterMessage) -> Result<Option<OuterMessage>, AtvError> {
        if msg.status != Status::Ok as i32 {
            return Err(AtvError::new(
                ErrorKind::PairingFailed,
                format!(
                    "TV reported pairing status {} — wrong code or user declined?",
                    msg.status
                ),
            ));
        }
        if msg.pairing_request_ack.is_some() {
            Ok(Some(OuterMessage {
                protocol_version: 2,
                status: Status::Ok as i32,
                options: Some(Options {
                    input_encodings: vec![hex6_encoding()],
                    output_encodings: Vec::new(),
                    preferred_role: None,
                }),
                ..Default::default()
            }))
        } else if msg.options.is_some() {
            Ok(Some(OuterMessage {
                protocol_version: 2,
                status: Status::Ok as i32,
                configuration: Some(Configuration {
                    encoding: hex6_encoding(),
                    client_role: options::RoleType::Input as i32,
                }),
                ..Default::default()
            }))
        } else if msg.configuration_ack.is_some() {
            self.awaiting_code = true;
            Ok(None)
        } else if msg.secret_ack.is_some() {
            Ok(None)
        } else {
            Err(AtvError::new(
                ErrorKind::ProtocolError,
                "unexpected pairing message",
            ))
        }
    }

    /// The final message, carrying the computed pairing secret.
    pub fn secret_message(secret: Vec<u8>) -> OuterMessage {
        OuterMessage {
            protocol_version: 2,
            status: Status::Ok as i32,
            secret: Some(Secret { secret }),
            ..Default::default()
        }
    }
}

impl Default for PairingFlow {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a successful `pair` run.
#[derive(Debug, Serialize)]
pub struct PairOutput {
    pub timestamp: String,
    pub host: String,
    pub paired: bool,
}

/// Runs the full pairing flow against `host:port`: ensures a local client
/// identity exists, connects over TLS, exchanges the polo handshake, reads
/// the on-screen code from stdin, and sends the computed secret.
pub fn pair(host: std::net::IpAddr, port: u16) -> Result<PairOutput, AtvError> {
    let dir = crate::config::credential_dir_from_env()?;
    crate::identity::ensure_identity(&dir)?;
    let tls = crate::tls::TlsClient::from_credential_dir(&dir)?;
    let mut conn = tls.connect(host, port, std::time::Duration::from_secs(5))?;

    let proto_err = |e: std::io::Error| {
        AtvError::new(ErrorKind::ProtocolError, format!("pairing I/O failed: {e}"))
    };
    let mut flow = PairingFlow::new();
    crate::framing::write_message(&mut conn, &PairingFlow::initial_message()).map_err(proto_err)?;
    while !flow.awaiting_code() {
        let msg: OuterMessage = crate::framing::read_message(&mut conn).map_err(proto_err)?;
        if let Some(reply) = flow.handle(&msg)? {
            crate::framing::write_message(&mut conn, &reply).map_err(proto_err)?;
        }
    }

    // The TV is now showing the code. stdout stays pure JSON; the human
    // prompt goes to stderr (diagnostics stream).
    eprintln!("Enter the 6-digit code shown on the TV:");
    let mut code = String::new();
    std::io::stdin().read_line(&mut code).map_err(|e| {
        AtvError::new(
            ErrorKind::PairingFailed,
            format!("could not read code from stdin: {e}"),
        )
    })?;
    let code = code.trim().to_lowercase();

    let server_der = crate::tls::peer_cert_der(&conn)?;
    let secret = compute_pairing_secret(&tls.client_cert_der, &server_der, &code)?;
    crate::framing::write_message(&mut conn, &PairingFlow::secret_message(secret))
        .map_err(proto_err)?;
    let ack: OuterMessage = crate::framing::read_message(&mut conn).map_err(|e| {
        AtvError::new(
            ErrorKind::PairingFailed,
            format!("TV closed the connection after the secret — wrong code? ({e})"),
        )
    })?;
    flow.handle(&ack)?; // errors if status != OK (e.g. STATUS_BAD_SECRET)

    Ok(PairOutput {
        timestamp: crate::output::timestamp(),
        host: host.to_string(),
        paired: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_PEM: &str = include_str!("../tests/fixtures/pairing/client-cert.pem");
    const SERVER_PEM: &str = include_str!("../tests/fixtures/pairing/server-cert.pem");
    const EXPECTED: &str = include_str!("../tests/fixtures/pairing/expected.txt");

    fn der(pem_str: &str) -> Vec<u8> {
        // Fully qualified from the crate root: `use x509_parser::prelude::*`
        // above (pulled in here via `use super::*`) also re-exports
        // x509_parser's internal `pem` module, which would otherwise shadow
        // the external `pem` crate.
        ::pem::parse(pem_str).unwrap().into_contents()
    }

    #[test]
    fn matches_reference_implementation_fixture() {
        let mut lines = EXPECTED.lines();
        let code = lines.next().unwrap();
        let want: Vec<u8> = hex_decode(lines.next().unwrap());
        let got = compute_pairing_secret(&der(CLIENT_PEM), &der(SERVER_PEM), code).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn rejects_wrong_checksum() {
        let mut lines = EXPECTED.lines();
        let code = lines.next().unwrap();
        // flip the checksum byte
        let bad = format!(
            "{:02x}{}",
            u8::from_str_radix(&code[..2], 16).unwrap() ^ 0xff,
            &code[2..]
        );
        let err = compute_pairing_secret(&der(CLIENT_PEM), &der(SERVER_PEM), &bad).unwrap_err();
        assert!(err.to_json().contains("pairing_failed"));
    }

    #[test]
    fn rejects_malformed_codes() {
        for bad in ["", "12345", "1234567", "zzzzzz"] {
            let err = compute_pairing_secret(&der(CLIENT_PEM), &der(SERVER_PEM), bad).unwrap_err();
            assert!(err.to_json().contains("pairing_failed"), "code {bad:?}");
        }
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod flow_tests {
    use super::*;
    use crate::proto::polo::{self, outer_message::Status, OuterMessage};

    fn ok_msg() -> OuterMessage {
        OuterMessage {
            protocol_version: 2,
            status: Status::Ok as i32,
            ..Default::default()
        }
    }

    #[test]
    fn happy_path_message_sequence() {
        let mut flow = PairingFlow::new();
        let init = PairingFlow::initial_message();
        let req = init.pairing_request.unwrap();
        assert_eq!(req.service_name, "atvremote");

        let mut ack = ok_msg();
        ack.pairing_request_ack = Some(polo::PairingRequestAck::default());
        let reply = flow.handle(&ack).unwrap().unwrap();
        let opts = reply.options.unwrap();
        assert_eq!(opts.input_encodings.len(), 1);
        assert_eq!(opts.input_encodings[0].symbol_length, 6);

        let mut server_opts = ok_msg();
        server_opts.options = Some(polo::Options::default());
        let reply = flow.handle(&server_opts).unwrap().unwrap();
        assert!(reply.configuration.is_some());

        let mut cfg_ack = ok_msg();
        cfg_ack.configuration_ack = Some(polo::ConfigurationAck::default());
        assert!(flow.handle(&cfg_ack).unwrap().is_none());
        assert!(flow.awaiting_code());
    }

    #[test]
    fn non_ok_status_is_pairing_failed() {
        let mut flow = PairingFlow::new();
        let mut bad = ok_msg();
        bad.status = Status::BadSecret as i32;
        let err = flow.handle(&bad).unwrap_err();
        assert!(err.to_json().contains("pairing_failed"));
    }
}
