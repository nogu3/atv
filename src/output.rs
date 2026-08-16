use serde::Serialize;

/// Local ISO 8601 timestamp (with UTC offset) at the moment `atv` built the
/// response — required on every stdout success object.
pub fn timestamp() -> String {
    jiff::Zoned::now().strftime("%FT%T%:z").to_string()
}

/// Prints one JSON object to stdout, followed by a newline. stdout stays
/// pure structured JSON — this is the only thing `atv` ever writes there.
/// A write failure (e.g. a closed pipe) is ignored rather than panicking,
/// keeping the exit-code contract intact.
pub fn emit<T: Serialize>(value: &T) {
    use std::io::Write;
    let json = serde_json::to_string(value).expect("output serialization cannot fail");
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{json}");
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_is_iso8601_with_utc_offset() {
        let ts = timestamp();
        // e.g. "2026-08-15T12:34:56+09:00"
        let bytes = ts.as_bytes();
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
        assert_eq!(bytes[10], b'T');
        assert_eq!(bytes[13], b':');
        assert_eq!(bytes[16], b':');
        let offset = &ts[19..];
        assert!(
            offset.starts_with('+') || offset.starts_with('-'),
            "expected a UTC offset suffix, got {ts:?}"
        );
        assert_eq!(offset.len(), 6, "expected +HH:MM / -HH:MM, got {ts:?}");
    }
}
