use serde::Serialize;

/// Stable error kinds documented in the README; keep names and exit codes
/// stable once shipped (casa depends on them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Unreachable,
    NotPaired,
    AuthRejected,
    PairingFailed,
    ProtocolError,
    ConfigIo,
}

#[derive(Debug, Serialize)]
pub struct AtvError {
    kind: ErrorKind,
    detail: String,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: &'a AtvError,
}

impl AtvError {
    pub fn new(kind: ErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&ErrorEnvelope { error: self })
            .expect("error serialization cannot fail")
    }

    pub fn exit_code(&self) -> i32 {
        match self.kind {
            ErrorKind::ProtocolError | ErrorKind::ConfigIo => 1,
            ErrorKind::Unreachable => 3,
            ErrorKind::NotPaired | ErrorKind::AuthRejected => 4,
            ErrorKind::PairingFailed => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_to_documented_error_shape() {
        let err = AtvError::new(ErrorKind::NotPaired, "no client certificate found");
        let v: serde_json::Value = serde_json::from_str(&err.to_json()).unwrap();
        assert_eq!(v["error"]["kind"], "not_paired");
        assert_eq!(v["error"]["detail"], "no client certificate found");
    }

    #[test]
    fn all_kinds_serialize_to_documented_names() {
        let cases = [
            (ErrorKind::Unreachable, "unreachable"),
            (ErrorKind::NotPaired, "not_paired"),
            (ErrorKind::AuthRejected, "auth_rejected"),
            (ErrorKind::PairingFailed, "pairing_failed"),
            (ErrorKind::ProtocolError, "protocol_error"),
            (ErrorKind::ConfigIo, "config_io"),
        ];
        for (kind, name) in cases {
            let v: serde_json::Value =
                serde_json::from_str(&AtvError::new(kind, "x").to_json()).unwrap();
            assert_eq!(v["error"]["kind"], name);
        }
    }

    #[test]
    fn maps_kinds_to_documented_exit_codes() {
        assert_eq!(AtvError::new(ErrorKind::ProtocolError, "").exit_code(), 1);
        assert_eq!(AtvError::new(ErrorKind::ConfigIo, "").exit_code(), 1);
        assert_eq!(AtvError::new(ErrorKind::Unreachable, "").exit_code(), 3);
        assert_eq!(AtvError::new(ErrorKind::NotPaired, "").exit_code(), 4);
        assert_eq!(AtvError::new(ErrorKind::AuthRejected, "").exit_code(), 4);
        assert_eq!(AtvError::new(ErrorKind::PairingFailed, "").exit_code(), 5);
    }
}
