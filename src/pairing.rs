use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use crate::error::{AtvError, ErrorKind};

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// Returns `(modulus, exponent)` of the certificate's RSA public key, as
/// unsigned big-endian bytes with leading `0x00` bytes stripped (DER
/// integers carry a leading `0x00` when the top bit is set; the reference
/// implementation hashes the stripped form, so this must match).
#[cfg_attr(not(test), expect(dead_code))]
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
#[cfg_attr(not(test), expect(dead_code))]
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
