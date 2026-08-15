use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

use crate::config;
use crate::error::{AtvError, ErrorKind};

pub type Conn = StreamOwned<ClientConnection, TcpStream>;

/// Accepts any server certificate: the trust decision was made at pairing
/// time (the TV verified physical access); we pin nothing by design.
#[derive(Debug)]
pub struct AcceptAnyServerCert {
    schemes: Vec<SignatureScheme>,
}

impl AcceptAnyServerCert {
    pub fn new() -> Self {
        let provider = rustls::crypto::ring::default_provider();
        Self {
            schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

impl Default for AcceptAnyServerCert {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

#[derive(Debug)]
pub struct TlsClient {
    #[cfg_attr(not(test), expect(dead_code))]
    pub client_cert_der: Vec<u8>,
    config: Arc<ClientConfig>,
}

impl TlsClient {
    #[cfg_attr(not(test), expect(dead_code))]
    pub fn from_credential_dir(dir: &Path) -> Result<Self, AtvError> {
        config::ensure_paired(dir)?; // not_paired if files missing
        let cert_pem = std::fs::read(dir.join("cert.pem")).map_err(|e| {
            AtvError::new(ErrorKind::ConfigIo, format!("cannot read cert.pem: {e}"))
        })?;
        let key_pem = std::fs::read(dir.join("key.pem"))
            .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("cannot read key.pem: {e}")))?;
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<_, _>>()
            .map_err(|e| {
                AtvError::new(
                    ErrorKind::ConfigIo,
                    format!("cert.pem is not valid PEM: {e}"),
                )
            })?;
        let key: PrivateKeyDer = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| {
                AtvError::new(
                    ErrorKind::ConfigIo,
                    format!("key.pem is not valid PEM: {e}"),
                )
            })?
            .ok_or_else(|| AtvError::new(ErrorKind::ConfigIo, "key.pem contains no private key"))?;
        let client_cert_der = certs
            .first()
            .ok_or_else(|| AtvError::new(ErrorKind::ConfigIo, "cert.pem contains no certificate"))?
            .to_vec();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("TLS config: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::new()))
            .with_client_auth_cert(certs, key)
            .map_err(|e| {
                AtvError::new(
                    ErrorKind::ConfigIo,
                    format!("client cert rejected by rustls: {e}"),
                )
            })?;
        Ok(Self {
            client_cert_der,
            config: Arc::new(config),
        })
    }

    #[cfg_attr(not(test), expect(dead_code))]
    pub fn connect(&self, host: IpAddr, port: u16, timeout: Duration) -> Result<Conn, AtvError> {
        let addr = SocketAddr::new(host, port);
        let unreachable = |e: &dyn std::fmt::Display| {
            AtvError::new(
                ErrorKind::Unreachable,
                format!("{addr} unreachable — TV powered off without network standby? ({e})"),
            )
        };
        let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(|e| unreachable(&e))?;
        tcp.set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| unreachable(&e))?;
        tcp.set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| unreachable(&e))?;
        tcp.set_nodelay(true).ok();
        let server_name = ServerName::from(host);
        let conn = ClientConnection::new(self.config.clone(), server_name).map_err(|e| {
            AtvError::new(ErrorKind::ProtocolError, format!("TLS setup failed: {e}"))
        })?;
        Ok(StreamOwned::new(conn, tcp))
    }
}

#[cfg_attr(not(test), expect(dead_code))]
pub fn peer_cert_der(conn: &Conn) -> Result<Vec<u8>, AtvError> {
    conn.conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.to_vec())
        .ok_or_else(|| AtvError::new(ErrorKind::ProtocolError, "server sent no certificate"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_accepts_arbitrary_self_signed_cert() {
        let pem = include_str!("../tests/fixtures/pairing/server-cert.pem");
        let der = ::pem::parse(pem).unwrap().into_contents();
        let verifier = AcceptAnyServerCert::new();
        use rustls::client::danger::ServerCertVerifier;
        let result = verifier.verify_server_cert(
            &rustls::pki_types::CertificateDer::from(der),
            &[],
            &rustls::pki_types::ServerName::try_from("192.0.2.10").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn missing_store_is_not_paired() {
        let dir = std::env::temp_dir().join(format!("atv-tls-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let err = TlsClient::from_credential_dir(&dir).unwrap_err();
        assert!(err.to_json().contains("not_paired"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// End-to-end sanity check for `connect` and `peer_cert_der` against a
    /// real (loopback) TLS server: exercises the handshake, the accept-any
    /// verifier in a live connection (not just direct verifier calls), the
    /// client certificate load path, and that the exposed peer certificate
    /// DER matches what the server actually presented.
    #[test]
    fn connect_completes_handshake_and_exposes_peer_cert() {
        use std::io::{Read, Write};
        use std::net::{Ipv4Addr, TcpListener};

        // Server identity: any self-signed cert works, `generate_identity`
        // (Task 3) is a convenient source and already unit-tested.
        let (server_cert_pem, server_key_pem) = crate::identity::generate_identity().unwrap();
        let server_certs: Vec<CertificateDer> =
            rustls_pemfile::certs(&mut server_cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();
        let server_key: PrivateKeyDer = rustls_pemfile::private_key(&mut server_key_pem.as_bytes())
            .unwrap()
            .unwrap();
        let expected_peer_der = server_certs[0].to_vec();

        let server_provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = rustls::ServerConfig::builder_with_provider(server_provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_certs, server_key)
            .unwrap();
        let server_config = Arc::new(server_config);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(conn, tcp);
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).unwrap();
            stream.write_all(b"pong").unwrap();
        });

        let client_dir =
            std::env::temp_dir().join(format!("atv-tls-e2e-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&client_dir);
        crate::identity::ensure_identity(&client_dir).unwrap();

        let client = TlsClient::from_credential_dir(&client_dir).unwrap();
        let stored_cert_pem = std::fs::read(client_dir.join("cert.pem")).unwrap();
        let expected_client_der: Vec<u8> = rustls_pemfile::certs(&mut stored_cert_pem.as_slice())
            .next()
            .unwrap()
            .unwrap()
            .to_vec();
        assert_eq!(client.client_cert_der, expected_client_der);

        let mut conn = client
            .connect(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                Duration::from_secs(2),
            )
            .unwrap();
        conn.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");

        let peer_der = peer_cert_der(&conn).unwrap();
        assert_eq!(peer_der, expected_peer_der);

        server.join().unwrap();
        std::fs::remove_dir_all(&client_dir).unwrap();
    }
}
