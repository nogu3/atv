use std::path::Path;

use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;

use crate::error::{AtvError, ErrorKind};

/// Generates a fresh RSA-2048 (e=65537) private key and a self-signed
/// certificate (CN "atv") for it, returning `(cert_pem, key_pem)`.
///
/// Note: rcgen 0.13's supported RSA-signing backends (`ring` and
/// `aws_lc_rs`) both hard-reject RSA keys under 2048 bits when importing
/// for signing, so this is not parameterized by key size — 2048 is the
/// only size that works, in tests as well as production.
pub fn generate_identity() -> Result<(String, String), AtvError> {
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).map_err(|e| {
        AtvError::new(
            ErrorKind::ConfigIo,
            format!("RSA key generation failed: {e}"),
        )
    })?;
    let key_der = key
        .to_pkcs8_der()
        .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("PKCS#8 encoding failed: {e}")))?;
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(key_der.as_bytes()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("rcgen key import failed: {e}")))?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "atv");
    let cert = params.self_signed(&key_pair).map_err(|e| {
        AtvError::new(
            ErrorKind::ConfigIo,
            format!("certificate build failed: {e}"),
        )
    })?;
    let key_pem = key_der
        .to_pem("PRIVATE KEY", rsa::pkcs8::LineEnding::LF)
        .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("PEM encoding failed: {e}")))?
        .to_string();
    Ok((cert.pem(), key_pem))
}

/// Writes the private key PEM to `path` with mode 0600 from creation on
/// unix (via `OpenOptions::mode`, not a post-hoc `chmod`) so there is no
/// window where the key is readable at the umask-default mode. On
/// non-unix platforms this is a plain write — no equivalent primitive.
fn write_key_file(path: &Path, contents: &str) -> Result<(), AtvError> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                AtvError::new(
                    ErrorKind::ConfigIo,
                    format!("cannot create {}: {e}", path.display()),
                )
            })?;
        file.write_all(contents.as_bytes()).map_err(|e| {
            AtvError::new(
                ErrorKind::ConfigIo,
                format!("cannot write {}: {e}", path.display()),
            )
        })
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents).map_err(|e| {
            AtvError::new(
                ErrorKind::ConfigIo,
                format!("cannot write {}: {e}", path.display()),
            )
        })
    }
}

/// Idempotently ensures `dir/cert.pem` and `dir/key.pem` exist, generating a
/// new RSA-2048 identity only if either file is missing. The key file is
/// written with mode 0600 from creation on unix (see [`write_key_file`]).
///
/// Note: the existence short-circuit below only checks that both files are
/// present — it does not re-verify or repair the key file's permissions on
/// an existing identity (e.g. one created before this 0600-on-creation
/// behavior, or manually widened by an operator).
pub fn ensure_identity(dir: &Path) -> Result<(), AtvError> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    if cert_path.is_file() && key_path.is_file() {
        return Ok(());
    }
    std::fs::create_dir_all(dir).map_err(|e| {
        AtvError::new(
            ErrorKind::ConfigIo,
            format!("cannot create {}: {e}", dir.display()),
        )
    })?;
    let (cert_pem, key_pem) = generate_identity()?;
    std::fs::write(&cert_path, cert_pem).map_err(|e| {
        AtvError::new(
            ErrorKind::ConfigIo,
            format!("cannot write {}: {e}", cert_path.display()),
        )
    })?;
    write_key_file(&key_path, &key_pem)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_identity_creates_valid_identity_once_idempotently() {
        let dir = std::env::temp_dir().join(format!("atv-id-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        ensure_identity(&dir).unwrap();

        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let cert_pem = std::fs::read(&cert_path).unwrap();
        let key_pem = std::fs::read(&key_path).unwrap();
        assert!(cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        ensure_identity(&dir).unwrap(); // second call: no regeneration
        assert_eq!(std::fs::read(&cert_path).unwrap(), cert_pem);
        assert_eq!(std::fs::read(&key_path).unwrap(), key_pem);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
