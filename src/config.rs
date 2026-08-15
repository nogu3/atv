use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::{AtvError, ErrorKind};

/// Resolve the credential directory from environment values, in priority
/// order: `ATV_CONFIG_DIR`, `$XDG_CONFIG_HOME/atv`, `$HOME/.config/atv`.
/// Empty values count as unset (XDG convention).
pub fn resolve_credential_dir(
    atv_config_dir: Option<OsString>,
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, AtvError> {
    let set = |v: Option<OsString>| v.filter(|s| !s.is_empty());
    if let Some(dir) = set(atv_config_dir) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(xdg) = set(xdg_config_home) {
        return Ok(PathBuf::from(xdg).join("atv"));
    }
    if let Some(home) = set(home) {
        return Ok(PathBuf::from(home).join(".config").join("atv"));
    }
    Err(AtvError::new(
        ErrorKind::ConfigIo,
        "cannot resolve credential directory — none of ATV_CONFIG_DIR, XDG_CONFIG_HOME, HOME are set",
    ))
}

/// Resolve from the real process environment.
pub fn credential_dir_from_env() -> Result<PathBuf, AtvError> {
    resolve_credential_dir(
        std::env::var_os("ATV_CONFIG_DIR"),
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

/// Verify the credential store (client certificate + key from `pair`)
/// exists; otherwise the TV cannot be talked to and re-pairing is needed.
pub fn ensure_paired(credential_dir: &std::path::Path) -> Result<(), AtvError> {
    let cert = credential_dir.join("cert.pem");
    let key = credential_dir.join("key.pem");
    if cert.is_file() && key.is_file() {
        Ok(())
    } else {
        Err(AtvError::new(
            ErrorKind::NotPaired,
            format!(
                "no client certificate in {} — run `atv pair --host <ip>` first",
                credential_dir.display()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn s(v: &str) -> Option<std::ffi::OsString> {
        Some(std::ffi::OsString::from(v))
    }

    #[test]
    fn atv_config_dir_overrides_everything() {
        let dir = resolve_credential_dir(s("/custom/atv"), s("/xdg"), s("/home/u")).unwrap();
        assert_eq!(dir, PathBuf::from("/custom/atv"));
    }

    #[test]
    fn xdg_config_home_used_when_no_override() {
        let dir = resolve_credential_dir(None, s("/xdg"), s("/home/u")).unwrap();
        assert_eq!(dir, PathBuf::from("/xdg/atv"));
    }

    #[test]
    fn falls_back_to_home_dot_config() {
        let dir = resolve_credential_dir(None, None, s("/home/u")).unwrap();
        assert_eq!(dir, PathBuf::from("/home/u/.config/atv"));
    }

    #[test]
    fn empty_env_values_are_treated_as_unset() {
        let dir = resolve_credential_dir(s(""), s(""), s("/home/u")).unwrap();
        assert_eq!(dir, PathBuf::from("/home/u/.config/atv"));
    }

    #[test]
    fn no_usable_location_is_config_io_error() {
        let err = resolve_credential_dir(None, None, None).unwrap_err();
        let v: serde_json::Value = serde_json::from_str(&err.to_json()).unwrap();
        assert_eq!(v["error"]["kind"], "config_io");
    }
}
