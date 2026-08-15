use std::path::PathBuf;
use std::process::{Command, Output};

fn empty_credential_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_atv(args: &[&str], credential_dir: &PathBuf) -> Output {
    Command::new(env!("CARGO_BIN_EXE_atv"))
        .args(args)
        .env("ATV_CONFIG_DIR", credential_dir)
        .env_remove("RUST_LOG")
        .output()
        .unwrap()
}

fn stderr_error(output: &Output) -> serde_json::Value {
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    let line = stderr.lines().last().unwrap_or_else(|| {
        panic!("expected an error JSON line on stderr, got empty stderr");
    });
    serde_json::from_str(line).unwrap_or_else(|e| panic!("stderr line is not JSON ({e}): {line}"))
}

#[test]
fn session_commands_without_credential_store_exit_4_with_not_paired() {
    let dir = empty_credential_dir("no-store-session");
    for sub in ["status", "on", "off"] {
        let out = run_atv(&[sub, "--host", "192.0.2.10"], &dir);
        assert_eq!(out.status.code(), Some(4), "subcommand {sub}");
        assert!(out.stdout.is_empty(), "stdout must stay pure: {sub}");
        let err = stderr_error(&out);
        assert_eq!(err["error"]["kind"], "not_paired", "subcommand {sub}");
        assert!(
            err["error"]["detail"].as_str().unwrap().contains("pair"),
            "detail should point at re-pairing: {sub}"
        );
    }
}

#[test]
fn pair_against_unreachable_host_creates_identity_and_reports_unreachable() {
    let dir = empty_credential_dir("pair-unreachable");
    // RFC 5737 TEST-NET-1 address, port 1: not routable / refused fast, so
    // this exercises identity generation + the connect failure path without
    // waiting out the full connect timeout.
    let out = run_atv(&["pair", "--host", "192.0.2.10", "--port", "1"], &dir);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    let err = stderr_error(&out);
    assert_eq!(err["error"]["kind"], "unreachable");
    // Identity generation happens before connect, so the credential files
    // exist even though pairing itself never got off the ground.
    assert!(dir.join("cert.pem").is_file());
    assert!(dir.join("key.pem").is_file());
}

#[test]
fn session_commands_with_credential_store_report_phase2_unimplemented() {
    let dir = empty_credential_dir("with-store");
    std::fs::write(dir.join("cert.pem"), "dummy").unwrap();
    std::fs::write(dir.join("key.pem"), "dummy").unwrap();
    let out = run_atv(&["status", "--host", "192.0.2.10"], &dir);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr_error(&out);
    assert_eq!(err["error"]["kind"], "protocol_error");
}

#[test]
fn argument_errors_exit_2() {
    let dir = empty_credential_dir("arg-error");
    let out = run_atv(&["status"], &dir); // missing --host
    assert_eq!(out.status.code(), Some(2));
    let out = run_atv(&["bogus"], &dir);
    assert_eq!(out.status.code(), Some(2));
}
