# atv Phases 1-3: Pairing, Status, Idempotent Power — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement pairing (Phase 1), power status (Phase 2), and idempotent on/off (Phase 3) for the Android TV Remote protocol v2, on top of the existing Phase 0 CLI skeleton.

**Architecture:** Blocking `std::net` + rustls TLS, length-prefixed (varint) protobuf framing via prost. Protocol logic is written as pure, connection-free state machines (`PairingFlow`, `SessionHandshake`) that are unit-tested against scripted message sequences; thin drivers wire them to sockets. One client RSA identity is generated at first `pair` and reused for every TV.

**Tech Stack:** Rust, clap, prost + protox (no protoc binary needed), rustls 0.23 (ring provider), rcgen (cert build) + rsa (RSA-2048 keygen), x509-parser, sha2, jiff (timestamps), serde/serde_json.

**Spec:** `CLAUDE.md` (design rules, output conventions, exit codes, roadmap). Protocol facts were verified against the reference implementation `tronikos/androidtvremote2` (Python, files `base.py`, `pairing.py`, `remote.py`, `polo.proto`, `remotemessage.proto`); the relevant facts are embedded verbatim in each task below.

## Global Constraints

- stdout is pure structured JSON only — one object on success, with a required ISO 8601 `timestamp` field. No prompts, no progress on stdout.
- Diagnostics go to stderr (`tracing`); on failure, the **last stderr line** is `{"error":{"kind":"...","detail":"..."}}`.
- Stable error kinds: `unreachable`, `not_paired`, `auth_rejected`, `pairing_failed`, `protocol_error`, `config_io` (already implemented in `src/error.rs` as `ErrorKind`).
- Exit codes: 0 success, 1 internal/protocol, 2 CLI args (clap), 3 unreachable/timeout, 4 not paired / cert rejected, 5 pairing failed. Mapping lives in `AtvError::exit_code()` — do not change it.
- One-shot execution: connect, do one thing, print JSON, exit. No daemon, no cache, no state other than the credential store (`cert.pem` + `key.pem` under the dir from `config::credential_dir_from_env()`).
- Everything in the repo is English (OSS). Never commit real credentials or real IPs; tests use RFC 5737 addresses (`192.0.2.0/24`). Dummy fixture *certificates* (public halves only, no private keys) generated purely for tests are allowed under `tests/fixtures/` and must be labeled as such.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` must pass at every commit.
- Commit after every task (English conventional commits). Trailer:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01LABWXvirtHvjeTUmXMMaen`.

## Protocol facts (authoritative for all tasks)

- **Framing (both ports):** every protobuf message is prefixed by its byte length encoded as a **protobuf varint** (LEB128, little-endian 7-bit groups, high bit = continuation). Reference: `base.py` uses `_EncodeVarint(write, msg.ByteSize())` then the serialized bytes.
- **Pairing (TCP 6467, TLS):** messages are `polo.wire.protobuf.OuterMessage` (proto2, `proto/polo.proto`). Client flow:
  1. send `pairing_request{service_name:"atvremote", client_name:<name>}`
  2. recv `pairing_request_ack` → send `options{preferred_role:ROLE_TYPE_INPUT, input_encodings:[{type:ENCODING_TYPE_HEXADECIMAL, symbol_length:6}]}`
  3. recv `options` → send `configuration{client_role:ROLE_TYPE_INPUT, encoding:{type:ENCODING_TYPE_HEXADECIMAL, symbol_length:6}}`
  4. recv `configuration_ack` → TV now displays a 6-hex-digit code; read it from stdin
  5. send `secret{secret:<32-byte SHA-256 digest>}` → recv `secret_ack` → paired.
  Every sent message has `protocol_version:2, status:STATUS_OK(200)`. Any received `status != 200` aborts (402 = bad secret).
- **Pairing secret:** SHA-256 over: client RSA modulus ‖ client exponent ‖ server modulus ‖ server exponent ‖ `hex_decode(code[2..6])`. Moduli/exponents are unsigned big-endian bytes **with leading 0x00 bytes stripped** (Python reference hashes `bytes.fromhex(f"{n:X}")`). `digest[0]` must equal `hex_decode(code[0..2])` (checksum); the whole 32-byte digest is the secret.
- **Session (TCP 6466, TLS):** messages are `remote.RemoteMessage` (proto3, `proto/remotemessage.proto`). Server drives:
  - `remote_configure{code1:<supported feature bits>, device_info}` → reply `remote_configure{code1:<active features>, device_info{unknown1:1, unknown2:"1", package_name:"atv", app_version:<crate version>}}` where active = ours ∩ server's code1 (reference: `active &= supported`).
  - `remote_set_active` → reply `remote_set_active{active:<active features>}`
  - `remote_ping_request{val1}` → reply `remote_ping_response{val1:<same val1>}` (always, immediately)
  - `remote_start{started:bool}` → **this is the power state**. Sent after handshake and whenever power changes.
  - `remote_error` → treat as protocol error.
  - Feature bits (`Feature` in reference): PING=1, KEY=2, IME=4, VOICE=8, POWER=32, VOLUME=64, APP_LINK=512. atv uses **PING|KEY|POWER = 35**.
- **Power key:** `remote_key_inject{key_code:KEYCODE_POWER(26), direction:SHORT(3)}`.
- **TLS:** both ports use TLS with mutual self-signed certs. Client must present its cert; server cert must be accepted without verification (trust decision = pairing; pin nothing). The client certificate **must be RSA** (secret computation needs modulus/exponent). Reference generates RSA-2048, exponent 65537, CN-only subject, 10-year validity.
- The server closes the 6466 connection right after the TLS handshake (or fails the handshake) when the client cert is unknown → map to `auth_rejected`.

## File Structure

- `proto/polo.proto`, `proto/remotemessage.proto` — vendored protocol definitions (Task 1)
- `build.rs` — prost codegen via protox (Task 1)
- `src/proto.rs` — includes generated modules (Task 1)
- `src/framing.rs` — varint-length-prefixed protobuf read/write over `Read`/`Write` (Task 2)
- `src/identity.rs` — RSA identity generation, store/load in credential dir (Task 3)
- `src/pairing.rs` — secret computation (Task 4) + pairing state machine and driver (Task 6)
- `src/tls.rs` — rustls client config with accept-any-server verifier (Task 5)
- `src/output.rs` — success JSON emission with timestamp (Task 6)
- `src/session.rs` — session handshake state machine + drivers for status/power (Tasks 7-9)
- `src/main.rs`, `src/cli.rs`, `src/config.rs`, `src/error.rs` — existing, extended
- `scripts/gen-pairing-fixtures.py`, `tests/fixtures/` — reference-derived fixtures (Task 4)

Existing interfaces you may use anywhere: `error::{AtvError, ErrorKind}` (`AtvError::new(kind, detail)`, `.to_json()`, `.exit_code()`), `config::credential_dir_from_env() -> Result<PathBuf, AtvError>`, `config::ensure_paired(&Path) -> Result<(), AtvError>`, `cli::{Cli, Command, HostArgs}` (`Command::args() -> &HostArgs`, `Command::port() -> u16`).

---

### Task 1: Vendor protos and generate Rust types with prost

**Files:**
- Create: `proto/polo.proto`, `proto/remotemessage.proto` (copy from scratchpad: `/tmp/claude-1000/-home-noguk-ghq-github-com-nogu3-atv/791247b2-f1ca-44e6-94ee-51fb41c08741/scratchpad/{polo.proto,remotemessage.proto}` — they already carry source-attribution comments; keep them)
- Create: `build.rs`, `src/proto.rs`
- Modify: `Cargo.toml`, `src/main.rs` (add `mod proto;`)
- Test: inline `#[cfg(test)]` in `src/proto.rs`

**Interfaces:**
- Produces: `proto::polo::{OuterMessage, PairingRequest, Options, Configuration, Secret, outer_message::Status, options::{Encoding, RoleType}, options::encoding::EncodingType}` and `proto::remote::{RemoteMessage, RemoteConfigure, RemoteSetActive, RemoteDeviceInfo, RemoteKeyInject, RemotePingResponse, RemoteStart, RemoteKeyCode, RemoteDirection}` (prost-generated; exact nesting/names come from the generated file — verify in Step 4).

- [ ] **Step 1: Add dependencies**

In `Cargo.toml` add:

```toml
[dependencies]
prost = "0.13"

[build-dependencies]
prost-build = "0.13"
protox = "0.7"
```

- [ ] **Step 2: Copy the two proto files into `proto/`**

```bash
mkdir -p proto
cp /tmp/claude-1000/-home-noguk-ghq-github-com-nogu3-atv/791247b2-f1ca-44e6-94ee-51fb41c08741/scratchpad/polo.proto proto/
cp /tmp/claude-1000/-home-noguk-ghq-github-com-nogu3-atv/791247b2-f1ca-44e6-94ee-51fb41c08741/scratchpad/remotemessage.proto proto/
```

- [ ] **Step 3: Write the failing test**

`src/proto.rs`:

```rust
pub mod polo {
    include!(concat!(env!("OUT_DIR"), "/polo.wire.protobuf.rs"));
}
pub mod remote {
    include!(concat!(env!("OUT_DIR"), "/remote.rs"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn outer_message_roundtrips() {
        let mut msg = polo::OuterMessage::default();
        msg.protocol_version = 2;
        msg.status = polo::outer_message::Status::Ok as i32;
        let bytes = msg.encode_to_vec();
        let back = polo::OuterMessage::decode(&bytes[..]).unwrap();
        assert_eq!(back.protocol_version, 2);
    }

    #[test]
    fn remote_message_roundtrips() {
        let msg = remote::RemoteMessage {
            remote_start: Some(remote::RemoteStart { started: true }),
            ..Default::default()
        };
        let back = remote::RemoteMessage::decode(&msg.encode_to_vec()[..]).unwrap();
        assert!(back.remote_start.unwrap().started);
    }
}
```

Add `mod proto;` to `src/main.rs`. Note: prost may generate proto2 required fields as plain fields or `Option` depending on version; if the test does not compile, inspect the generated file (Step 4) and adjust field access (e.g. `msg.status = ...` vs setter) — the *semantic* content above is what matters.

- [ ] **Step 4: Write `build.rs` and make the test pass**

```rust
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/");
    let fds = protox::compile(
        ["proto/polo.proto", "proto/remotemessage.proto"],
        ["proto/"],
    )?;
    prost_build::Config::new().compile_fds(fds)?;
    let _ = PathBuf::new();
    Ok(())
}
```

(Drop the `PathBuf` line if unused.) Run `cargo test` — inspect `target/debug/build/atv-*/out/*.rs` if field shapes need adjusting. Expected: both tests pass.

- [ ] **Step 5: Full gate and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
git add proto build.rs src/proto.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "feat: vendor Remote v2 protos and generate types with prost/protox"
```

---

### Task 2: Varint length-prefixed framing

**Files:**
- Create: `src/framing.rs`
- Modify: `src/main.rs` (add `mod framing;`)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `framing::write_message<M: prost::Message, W: Write>(w: &mut W, msg: &M) -> Result<(), AtvError>`
  - `framing::read_message<M: prost::Message + Default, R: Read>(r: &mut R) -> Result<M, AtvError>`
  - I/O errors map to `ErrorKind::ProtocolError` **except**: the caller needs to distinguish timeouts/EOF, so surface raw `std::io::Error` instead — final signatures:
  - `framing::write_message(...) -> std::io::Result<()>`
  - `framing::read_message(...) -> std::io::Result<M>` where a decode failure becomes `io::Error::new(InvalidData, e)` and an over-long frame (> 1 MiB) becomes `InvalidData`.

- [ ] **Step 1: Write failing tests**

```rust
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
        // 200 one-byte fields → payload > 127 bytes → 2-byte varint prefix
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
```

- [ ] **Step 2: Run, watch fail** (`cargo test framing` — compile error: functions missing)

- [ ] **Step 3: Implement**

```rust
use std::io::{self, Read, Write};

use prost::Message;

const MAX_FRAME: u64 = 1024 * 1024;

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
            return Err(io::Error::new(io::ErrorKind::InvalidData, "varint too long"));
        }
    }
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds 1 MiB"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    M::decode(&body[..]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
```

- [ ] **Step 4: Run tests, all green; fmt/clippy gate**

- [ ] **Step 5: Commit** — `git add src/framing.rs src/main.rs && git commit -m "feat: varint length-prefixed protobuf framing"`

---

### Task 3: Client identity (RSA-2048 self-signed certificate)

**Files:**
- Create: `src/identity.rs`
- Modify: `Cargo.toml`, `src/main.rs` (add `mod identity;`)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `identity::ensure_identity(dir: &Path) -> Result<(), AtvError>` — generates `cert.pem` (self-signed, CN "atv") + `key.pem` (PKCS#8) with RSA-2048/e=65537 if either is missing; no-op if both exist. Key file mode 0600. Maps I/O failures to `ErrorKind::ConfigIo`.
  - `identity::generate_identity_with_bits(bits: usize) -> Result<(String, String), AtvError>` — returns `(cert_pem, key_pem)`; the 2048 default goes through this (tests use 512 for speed).

- [ ] **Step 1: Add dependencies**

```toml
rcgen = "0.13"
rsa = { version = "0.9", features = ["sha2"] }
rand = "0.8"
```

- [ ] **Step 2: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_rsa_cert_and_pkcs8_key() {
        let (cert_pem, key_pem) = generate_identity_with_bits(512).unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn ensure_identity_creates_files_once() {
        let dir = std::env::temp_dir().join(format!("atv-id-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        ensure_identity_with_bits(&dir, 512).unwrap();
        let first = std::fs::read(dir.join("cert.pem")).unwrap();
        ensure_identity_with_bits(&dir, 512).unwrap(); // second call: no regeneration
        assert_eq!(std::fs::read(dir.join("cert.pem")).unwrap(), first);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
```

(Expose `ensure_identity_with_bits(dir, bits)`; `ensure_identity(dir)` = `ensure_identity_with_bits(dir, 2048)`.)

- [ ] **Step 3: Run, watch fail**

- [ ] **Step 4: Implement**

```rust
use std::path::Path;

use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;

use crate::error::{AtvError, ErrorKind};

pub fn generate_identity_with_bits(bits: usize) -> Result<(String, String), AtvError> {
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), bits)
        .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("RSA key generation failed: {e}")))?;
    let key_der = key
        .to_pkcs8_der()
        .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("PKCS#8 encoding failed: {e}")))?;
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rcgen::PrivatePkcs8KeyDer::from(key_der.as_bytes()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("rcgen key import failed: {e}")))?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "atv");
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("certificate build failed: {e}")))?;
    let key_pem = key_der
        .to_pem("PRIVATE KEY", rsa::pkcs8::LineEnding::LF)
        .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("PEM encoding failed: {e}")))?
        .to_string();
    Ok((cert.pem(), key_pem))
}

pub fn ensure_identity_with_bits(dir: &Path, bits: usize) -> Result<(), AtvError> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    if cert_path.is_file() && key_path.is_file() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("cannot create {}: {e}", dir.display())))?;
    let (cert_pem, key_pem) = generate_identity_with_bits(bits)?;
    std::fs::write(&cert_path, cert_pem)
        .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("cannot write {}: {e}", cert_path.display())))?;
    std::fs::write(&key_path, key_pem)
        .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("cannot write {}: {e}", key_path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("cannot chmod key: {e}")))?;
    }
    Ok(())
}

pub fn ensure_identity(dir: &Path) -> Result<(), AtvError> {
    ensure_identity_with_bits(dir, 2048)
}
```

Note: `rsa::pkcs8::LineEnding` re-exports from `pkcs8` crate; if the `to_pem` helper on `SecretDocument` differs, use `key_der.to_pem("PRIVATE KEY", LineEnding::LF)` from `pkcs8::SecretDocument` or `key.to_pkcs8_pem(LineEnding::LF)` directly — any route producing a `-----BEGIN PRIVATE KEY-----` PKCS#8 PEM is correct.

- [ ] **Step 5: Run tests green, fmt/clippy gate, commit** — `feat: RSA client identity generation and storage`

---

### Task 4: Pairing secret computation with reference fixtures

**Files:**
- Create: `src/pairing.rs` (secret computation half), `scripts/gen-pairing-fixtures.py`, `tests/fixtures/pairing/client-cert.pem`, `tests/fixtures/pairing/server-cert.pem`, `tests/fixtures/pairing/expected.txt`, `tests/fixtures/pairing/README.md`
- Modify: `Cargo.toml` (`sha2 = "0.10"`, `x509-parser = "0.16"`), `src/main.rs` (add `mod pairing;`)
- Test: inline `#[cfg(test)]` reading the fixtures via `include_str!`/`include_bytes!`

**Interfaces:**
- Produces: `pairing::compute_pairing_secret(client_cert_der: &[u8], server_cert_der: &[u8], code: &str) -> Result<Vec<u8>, AtvError>` — validates the code (exactly 6 hex chars, else `ErrorKind::PairingFailed`), computes the digest, verifies the checksum byte (`digest[0] == code[0..2]`, else `PairingFailed` "code mismatch — was the code mistyped?"), returns the 32-byte digest.
- Also produces internal helper `rsa_numbers(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AtvError>` returning (modulus, exponent) big-endian **with leading 0x00 bytes stripped** (`ErrorKind::ProtocolError` if the cert is not RSA).

- [ ] **Step 1: Generate fixtures with the reference algorithm**

`scripts/gen-pairing-fixtures.py` (stdlib + `openssl` CLI only; mirror of `androidtvremote2/pairing.py` lines 111-117):

```python
#!/usr/bin/env python3
"""Generate pairing-secret test fixtures.

Creates two throwaway RSA certs and computes the expected pairing secret
exactly like the reference implementation (tronikos/androidtvremote2,
pairing.py): sha256(client_mod | client_exp | server_mod | server_exp |
nonce), where the displayed code is hex(digest[0]) + nonce_hex.
"""
import hashlib
import pathlib
import subprocess
import tempfile

OUT = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "pairing"
OUT.mkdir(parents=True, exist_ok=True)
NONCE_HEX = "2b4a"  # arbitrary fixed 2-byte nonce (last 4 code digits)


def gen_cert(name: str) -> tuple[bytes, int, int]:
    with tempfile.TemporaryDirectory() as td:
        key = f"{td}/key.pem"
        crt = f"{td}/crt.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
             "-out", crt, "-days", "36500", "-subj", f"/CN={name}"],
            check=True, capture_output=True)
        pem = pathlib.Path(crt).read_bytes()
        mod_out = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-modulus"],
                                 check=True, capture_output=True, text=True).stdout
        modulus = int(mod_out.strip().split("=", 1)[1], 16)
        return pem, modulus, 65537


client_pem, client_n, client_e = gen_cert("atv-fixture-client")
server_pem, server_n, server_e = gen_cert("atv-fixture-server")

h = hashlib.sha256()
h.update(bytes.fromhex(f"{client_n:X}"))
h.update(bytes.fromhex(f"0{client_e:X}"))
h.update(bytes.fromhex(f"{server_n:X}"))
h.update(bytes.fromhex(f"0{server_e:X}"))
h.update(bytes.fromhex(NONCE_HEX))
digest = h.digest()
code = f"{digest[0]:02x}{NONCE_HEX}"

(OUT / "client-cert.pem").write_bytes(client_pem)
(OUT / "server-cert.pem").write_bytes(server_pem)
(OUT / "expected.txt").write_text(f"{code}\n{digest.hex()}\n")
print(f"code={code} digest={digest.hex()}")
```

Run it: `python3 scripts/gen-pairing-fixtures.py`. Also write `tests/fixtures/pairing/README.md`:

```markdown
Throwaway certificates generated by `scripts/gen-pairing-fixtures.py` purely
for unit-testing the pairing-secret computation. They contain no private
keys and are not credentials for anything. `expected.txt` line 1 is the
pairing code, line 2 the expected SHA-256 secret (hex), computed with the
reference algorithm (tronikos/androidtvremote2 `pairing.py`).
```

- [ ] **Step 2: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_PEM: &str = include_str!("../tests/fixtures/pairing/client-cert.pem");
    const SERVER_PEM: &str = include_str!("../tests/fixtures/pairing/server-cert.pem");
    const EXPECTED: &str = include_str!("../tests/fixtures/pairing/expected.txt");

    fn der(pem: &str) -> Vec<u8> {
        pem::parse(pem).unwrap().into_contents()
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
        let bad = format!("{:02x}{}", u8::from_str_radix(&code[..2], 16).unwrap() ^ 0xff, &code[2..]);
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
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
```

Add dev-dependency `pem = "3"` for the test-side PEM→DER (or reuse `x509_parser::pem`; either is fine).

- [ ] **Step 3: Run, watch fail**

- [ ] **Step 4: Implement**

```rust
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::error::{AtvError, ErrorKind};

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

fn rsa_numbers(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AtvError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| AtvError::new(ErrorKind::ProtocolError, format!("cannot parse certificate: {e}")))?;
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => Ok((
            strip_leading_zeros(rsa.modulus).to_vec(),
            strip_leading_zeros(rsa.exponent).to_vec(),
        )),
        _ => Err(AtvError::new(ErrorKind::ProtocolError, "certificate public key is not RSA")),
    }
}

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
```

- [ ] **Step 5: Run tests green, fmt/clippy gate, commit** — `feat: pairing secret computation verified against reference fixtures` (include `scripts/`, `tests/fixtures/`)

---

### Task 5: TLS client plumbing

**Files:**
- Create: `src/tls.rs`
- Modify: `Cargo.toml`, `src/main.rs` (add `mod tls;`)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: fixture certs from Task 4 for tests; `identity` files (`cert.pem`, `key.pem`) at runtime.
- Produces:
  - `tls::TlsClient { pub client_cert_der: Vec<u8>, config: Arc<rustls::ClientConfig> }`
  - `tls::TlsClient::from_credential_dir(dir: &Path) -> Result<TlsClient, AtvError>` — loads PEMs; missing files → `ErrorKind::NotPaired` (reuse message style of `config::ensure_paired`); unparsable → `ConfigIo`.
  - `tls::TlsClient::connect(&self, host: IpAddr, port: u16, timeout: Duration) -> Result<tls::Conn, AtvError>` where `Conn = rustls::StreamOwned<rustls::ClientConnection, TcpStream>` — connect errors map to `ErrorKind::Unreachable` with detail `"<ip>:<port> unreachable — TV powered off without network standby?"`; sets read/write timeouts (10 s) on the socket.
  - `tls::peer_cert_der(conn: &Conn) -> Result<Vec<u8>, AtvError>` — first peer certificate (available after first read/write completes the handshake), `ProtocolError` if absent.

- [ ] **Step 1: Add dependencies**

```toml
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12", "logging"] }
rustls-pemfile = "2"
```

(ring provider, not aws-lc-rs: musl cross-build friendliness.)

- [ ] **Step 2: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_accepts_arbitrary_self_signed_cert() {
        let pem = include_str!("../tests/fixtures/pairing/server-cert.pem");
        let der = pem::parse(pem).unwrap().into_contents();
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
}
```

- [ ] **Step 3: Run, watch fail**

- [ ] **Step 4: Implement**

```rust
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
            schemes: provider.signature_verification_algorithms.supported_schemes(),
        }
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

pub struct TlsClient {
    pub client_cert_der: Vec<u8>,
    config: Arc<ClientConfig>,
}

impl TlsClient {
    pub fn from_credential_dir(dir: &Path) -> Result<Self, AtvError> {
        config::ensure_paired(dir)?; // not_paired if files missing
        let cert_pem = std::fs::read(dir.join("cert.pem"))
            .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("cannot read cert.pem: {e}")))?;
        let key_pem = std::fs::read(dir.join("key.pem"))
            .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("cannot read key.pem: {e}")))?;
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<_, _>>()
            .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("cert.pem is not valid PEM: {e}")))?;
        let key: PrivateKeyDer = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("key.pem is not valid PEM: {e}")))?
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
            .map_err(|e| AtvError::new(ErrorKind::ConfigIo, format!("client cert rejected by rustls: {e}")))?;
        Ok(Self {
            client_cert_der,
            config: Arc::new(config),
        })
    }

    pub fn connect(&self, host: IpAddr, port: u16, timeout: Duration) -> Result<Conn, AtvError> {
        let addr = SocketAddr::new(host, port);
        let unreachable = |e: &dyn std::fmt::Display| {
            AtvError::new(
                ErrorKind::Unreachable,
                format!("{addr} unreachable — TV powered off without network standby? ({e})"),
            )
        };
        let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(|e| unreachable(&e))?;
        tcp.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| unreachable(&e))?;
        tcp.set_write_timeout(Some(Duration::from_secs(10))).map_err(|e| unreachable(&e))?;
        tcp.set_nodelay(true).ok();
        let server_name = ServerName::from(host);
        let conn = ClientConnection::new(self.config.clone(), server_name)
            .map_err(|e| AtvError::new(ErrorKind::ProtocolError, format!("TLS setup failed: {e}")))?;
        Ok(StreamOwned::new(conn, tcp))
    }
}

pub fn peer_cert_der(conn: &Conn) -> Result<Vec<u8>, AtvError> {
    conn.conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.to_vec())
        .ok_or_else(|| AtvError::new(ErrorKind::ProtocolError, "server sent no certificate"))
}
```

Move `pem = "3"` from dev-dependencies if the test needs it here too (it is already a dev-dependency from Task 4). If `ServerName::from(IpAddr)` doesn't exist in the pinned rustls version, use `ServerName::IpAddress(host.into())`.

- [ ] **Step 5: Run tests green, fmt/clippy gate, commit** — `feat: rustls client with pairing-based trust (accept-any server cert)`

---

### Task 6: Pairing flow, `pair` command, JSON output — completes Phase 1 code

**Files:**
- Create: `src/output.rs`
- Modify: `src/pairing.rs` (add flow + driver), `src/main.rs` (dispatch `pair`), `Cargo.toml` (`jiff = "0.2"`), `README.md`, `tests/cli.rs`
- Test: inline `#[cfg(test)]` for the flow; keep existing integration tests green (the `pair` unimplemented-error test will be **replaced** — see Step 6)

**Interfaces:**
- Consumes: `framing::{read_message, write_message}`, `identity::ensure_identity`, `tls::{TlsClient, peer_cert_der}`, `pairing::compute_pairing_secret`, `proto::polo::*`.
- Produces:
  - `output::emit<T: Serialize>(value: &T)` — prints `serde_json::to_string(value)` + newline to stdout.
  - `output::timestamp() -> String` — local ISO 8601 via `jiff::Zoned::now().strftime("%FT%T%:z").to_string()`.
  - `pairing::PairingFlow` with `fn new() -> Self`, `fn initial_message() -> OuterMessage`, `fn handle(&mut self, msg: &OuterMessage) -> Result<Option<OuterMessage>, AtvError>`, `fn awaiting_code(&self) -> bool` (true after configuration_ack), `fn secret_message(secret: Vec<u8>) -> OuterMessage`.
  - `pairing::pair(host: IpAddr, port: u16) -> Result<PairOutput, AtvError>` and `struct PairOutput { timestamp: String, host: String, paired: bool }`.

- [ ] **Step 1: Write failing flow tests**

The flow (client sends, then for each received message produces at most one reply). Message constructors follow the protocol facts section. Tests:

```rust
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
```

(Adjust `Status::Ok` naming to the prost-generated variant, e.g. `Status::StatusOk`, by inspecting the generated code; prost strips the enum-name prefix when it can.)

- [ ] **Step 2: Run, watch fail**

- [ ] **Step 3: Implement flow + driver + output**

`PairingFlow::handle`: if `msg.status != 200` → `Err(PairingFailed, "TV reported pairing status {status} — wrong code or user declined?")`. Then match which optional field is set: `pairing_request_ack` → build options reply; `options` → build configuration reply; `configuration_ack` → set internal `awaiting_code = true`, return `None`; `secret_ack` → mark done, return `None`; anything else → `Err(ProtocolError, "unexpected pairing message")`. All outgoing messages get `protocol_version: 2, status: STATUS_OK`. Encoding constants: `EncodingType::Hexadecimal`, `symbol_length: 6`, `RoleType::Input`.

Driver `pair(host, port)`:

```rust
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
    std::io::stdin()
        .read_line(&mut code)
        .map_err(|e| AtvError::new(ErrorKind::PairingFailed, format!("could not read code from stdin: {e}")))?;
    let code = code.trim().to_lowercase();

    let server_der = crate::tls::peer_cert_der(&conn)?;
    let secret = compute_pairing_secret(&tls.client_cert_der, &server_der, &code)?;
    crate::framing::write_message(&mut conn, &PairingFlow::secret_message(secret)).map_err(proto_err)?;
    let ack: OuterMessage = crate::framing::read_message(&mut conn).map_err(|e| {
        AtvError::new(ErrorKind::PairingFailed, format!("TV closed the connection after the secret — wrong code? ({e})"))
    })?;
    flow.handle(&ack)?; // errors if status != OK (e.g. STATUS_BAD_SECRET)

    Ok(PairOutput {
        timestamp: crate::output::timestamp(),
        host: host.to_string(),
        paired: true,
    })
}
```

Note the ordering trap: `TlsClient::from_credential_dir` requires the store, and `ensure_identity` creates it first — so `pair` works on a fresh machine, while `status`/`on`/`off` (which never call `ensure_identity`) still fail with `not_paired`.

`src/output.rs`:

```rust
use serde::Serialize;

pub fn timestamp() -> String {
    jiff::Zoned::now().strftime("%FT%T%:z").to_string()
}

pub fn emit<T: Serialize>(value: &T) {
    println!("{}", serde_json::to_string(value).expect("output serialization cannot fail"));
}
```

`main.rs` dispatch: `Command::Pair(args) => { let out = pairing::pair(args.host, cli.command.port())?; output::emit(&out); Ok(()) }` — note `cli.command.port()` borrows, so capture `let port = cli.command.port();` before matching on `cli.command`.

- [ ] **Step 4: Update the integration test**

In `tests/cli.rs` replace `pair_reports_unimplemented_as_documented_error_shape` with: run `pair --host 192.0.2.10 --port 1` (RFC 5737 address, port 1 → refused/timeout fast) with a fresh `ATV_CONFIG_DIR`; expect exit 3 and `kind == "unreachable"`, and expect `cert.pem`/`key.pem` to have been created in the credential dir (identity generation happens before connect). Note: RSA-2048 generation in a debug binary takes seconds — keep this single test, don't loop it.

- [ ] **Step 5: Run all tests green, fmt/clippy gate**

- [ ] **Step 6: Update README**

- Remove the "Phase 0 skeleton" status note for `pair`; document: `pair` prompts on stderr and reads the 6-hex-digit code from stdin (`echo CODE | atv pair --host IP` also works if the code is already known — not typical).
- Move `pairing_failed` and `unreachable` from "Reserved" to active kinds with meanings.

- [ ] **Step 7: Commit** — `feat: implement pairing (Phase 1) — TLS identity, polo handshake, secret exchange`

**After this task the main loop (not a subagent) performs the Phase 1 real-TV E2E: cross-build, deploy to jarvis, pair against the real TV with the user reading the PIN, then document the E2E in README.**

---

### Task 7: Session handshake state machine

**Files:**
- Create: `src/session.rs`
- Modify: `src/main.rs` (add `mod session;`)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `proto::remote::*`.
- Produces:
  - `session::FEATURES: i32 = 35` (PING=1 | KEY=2 | POWER=32)
  - `session::SessionHandshake` with `fn new() -> Self`, `fn handle(&mut self, msg: RemoteMessage) -> Result<Option<RemoteMessage>, AtvError>`, `pub power: Option<bool>` (set by every `remote_start`).
  - `session::power_key_message() -> RemoteMessage` (KEYCODE_POWER 26, direction SHORT 3).

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::remote::*;

    #[test]
    fn replies_to_configure_with_intersected_features() {
        let mut hs = SessionHandshake::new();
        let msg = RemoteMessage {
            remote_configure: Some(RemoteConfigure {
                code1: 3, // server supports only PING|KEY
                device_info: None,
            }),
            ..Default::default()
        };
        let reply = hs.handle(msg).unwrap().unwrap();
        let cfg = reply.remote_configure.unwrap();
        assert_eq!(cfg.code1, 3); // 35 & 3
        let info = cfg.device_info.unwrap();
        assert_eq!(info.package_name, "atv");
        assert_eq!(info.unknown1, 1);
        assert_eq!(info.unknown2, "1");
    }

    #[test]
    fn replies_to_set_active_with_features() {
        let mut hs = SessionHandshake::new();
        let msg = RemoteMessage {
            remote_set_active: Some(RemoteSetActive { active: 0 }),
            ..Default::default()
        };
        let reply = hs.handle(msg).unwrap().unwrap();
        assert_eq!(reply.remote_set_active.unwrap().active, FEATURES);
    }

    #[test]
    fn echoes_ping_val1() {
        let mut hs = SessionHandshake::new();
        let msg = RemoteMessage {
            remote_ping_request: Some(RemotePingRequest { val1: 42, val2: 7 }),
            ..Default::default()
        };
        let reply = hs.handle(msg).unwrap().unwrap();
        assert_eq!(reply.remote_ping_response.unwrap().val1, 42);
    }

    #[test]
    fn remote_start_sets_power_and_needs_no_reply() {
        let mut hs = SessionHandshake::new();
        let msg = RemoteMessage {
            remote_start: Some(RemoteStart { started: true }),
            ..Default::default()
        };
        assert!(hs.handle(msg).unwrap().is_none());
        assert_eq!(hs.power, Some(true));
    }

    #[test]
    fn unknown_messages_are_ignored() {
        let mut hs = SessionHandshake::new();
        assert!(hs.handle(RemoteMessage::default()).unwrap().is_none());
        assert_eq!(hs.power, None);
    }

    #[test]
    fn remote_error_is_protocol_error() {
        let mut hs = SessionHandshake::new();
        let msg = RemoteMessage {
            remote_error: Some(RemoteError { value: true, message: None }),
            ..Default::default()
        };
        assert!(hs.handle(msg).unwrap_err().to_json().contains("protocol_error"));
    }

    #[test]
    fn power_key_message_is_short_power() {
        let msg = power_key_message();
        let inject = msg.remote_key_inject.unwrap();
        assert_eq!(inject.key_code, RemoteKeyCode::KeycodePower as i32);
        assert_eq!(inject.direction, RemoteDirection::Short as i32);
    }
}
```

(`RemoteError.message` is `Option<Box<RemoteMessage>>` in prost — adjust to the generated shape. Same for enum variant names, e.g. `RemoteKeyCode::KeycodePower`.)

- [ ] **Step 2: Run, watch fail**

- [ ] **Step 3: Implement**

`FEATURES = 1 | 2 | 32`. Handshake behavior exactly as the tests: configure → reply configure with `code1 = if server.code1 != 0 { FEATURES & server.code1 } else { FEATURES }` and device_info `{unknown1: 1, unknown2: "1", package_name: "atv", app_version: env!("CARGO_PKG_VERSION"), model/vendor default}`; set_active → reply with FEATURES (the intersected value stored from configure, if seen); ping → echo `val1`; remote_start → record `power = Some(started)`, no reply; remote_error → `Err(ProtocolError, "TV reported a remote error")`; everything else → `Ok(None)`.

- [ ] **Step 4: Tests green, fmt/clippy gate, commit** — `feat: session handshake state machine`

---

### Task 8: `status` command — completes Phase 2 code

**Files:**
- Modify: `src/session.rs` (add driver), `src/main.rs` (dispatch `status`), `README.md`, `tests/cli.rs`
- Test: inline `#[cfg(test)]` + integration

**Interfaces:**
- Consumes: `tls::TlsClient`, `framing`, `SessionHandshake`, `output::{emit, timestamp}`.
- Produces:
  - `session::read_power(host: IpAddr, port: u16) -> Result<(bool, Conn, SessionHandshake), AtvError>` — connects (via `TlsClient::from_credential_dir` + `connect`), pumps messages through `SessionHandshake` until `power` is known, returns state plus the live connection (Task 9 reuses it).
  - `session::StatusOutput { timestamp: String, host: String, power: &'static str }` and `session::status(host, port) -> Result<StatusOutput, AtvError>`.
  - `session::power_str(on: bool) -> &'static str` ("on"/"off").

- [ ] **Step 1: Failing unit test for error mapping helper**

The read loop must translate I/O errors:

```rust
pub(crate) fn map_session_read_error(e: std::io::Error, got_any_message: bool) -> AtvError
```

- `UnexpectedEof` (or any error) **before any message was received** → `ErrorKind::AuthRejected`, detail: `"TV closed the session immediately — client certificate rejected, re-pair needed"`.
- `TimedOut` / `WouldBlock` after messages flowed → `ErrorKind::ProtocolError`, `"TV stopped responding during session handshake"`.
- other errors after messages flowed → `ProtocolError` with the error text.

```rust
#[test]
fn eof_before_any_message_means_auth_rejected() {
    let e = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
    assert!(map_session_read_error(e, false).to_json().contains("auth_rejected"));
}

#[test]
fn timeout_after_messages_is_protocol_error() {
    let e = std::io::Error::new(std::io::ErrorKind::TimedOut, "t");
    assert!(map_session_read_error(e, true).to_json().contains("protocol_error"));
}
```

- [ ] **Step 2: Run, watch fail; implement helper; green**

- [ ] **Step 3: Implement the driver**

```rust
pub fn read_power(
    host: std::net::IpAddr,
    port: u16,
) -> Result<(bool, crate::tls::Conn, SessionHandshake), AtvError> {
    let dir = crate::config::credential_dir_from_env()?;
    let tls = crate::tls::TlsClient::from_credential_dir(&dir)?;
    let mut conn = tls.connect(host, port, std::time::Duration::from_secs(5))?;
    let mut hs = SessionHandshake::new();
    let mut got_any = false;
    while hs.power.is_none() {
        let msg: crate::proto::remote::RemoteMessage =
            crate::framing::read_message(&mut conn).map_err(|e| map_session_read_error(e, got_any))?;
        got_any = true;
        if let Some(reply) = hs.handle(msg)? {
            crate::framing::write_message(&mut conn, &reply)
                .map_err(|e| AtvError::new(ErrorKind::ProtocolError, format!("session write failed: {e}")))?;
        }
    }
    let power = hs.power.expect("loop exits only with power set");
    Ok((power, conn, hs))
}

pub fn status(host: std::net::IpAddr, port: u16) -> Result<StatusOutput, AtvError> {
    let (on, _conn, _hs) = read_power(host, port)?;
    Ok(StatusOutput {
        timestamp: crate::output::timestamp(),
        host: host.to_string(),
        power: power_str(on),
    })
}
```

Wire `Command::Status` in `main.rs` to `output::emit(&session::status(...)?)`. Remove the Phase-2 "unimplemented" error path for `status` only (keep `on`/`off` erroring until Task 9 — adjust the existing integration test to cover only `on`/`off`, and change the with-credential-store test to use `on`).

- [ ] **Step 4: Unit test for `power_str`**

Do NOT add network-touching integration tests (failure timing is not portable across CI environments); the without-store exit-4 integration test already covers the CLI wiring. Instead add this unit test to `session.rs`:

```rust
#[test]
fn power_str_maps_bool() {
    assert_eq!(power_str(true), "on");
    assert_eq!(power_str(false), "off");
}
```

- [ ] **Step 5: All green, fmt/clippy gate; update README (`status` implemented; `auth_rejected` now active), commit** — `feat: implement status (Phase 2) — session connect and power state`

**After this task the main loop performs the Phase 2 real-TV E2E (status while on / standby) and documents it in README.**

---

### Task 9: Idempotent `on` / `off` — completes Phase 3 code

**Files:**
- Modify: `src/session.rs`, `src/main.rs` (dispatch `on`/`off`), `README.md`, `tests/cli.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `read_power`, `power_key_message`, `SessionHandshake`, `framing`, `output`.
- Produces:
  - `session::needs_power_key(current_on: bool, want_on: bool) -> bool`
  - `session::PowerOutput { timestamp: String, host: String, power: &'static str, changed: bool }`
  - `session::set_power(host: IpAddr, port: u16, want_on: bool) -> Result<PowerOutput, AtvError>`

- [ ] **Step 1: Failing tests for the decision logic**

```rust
#[test]
fn power_key_sent_only_when_state_differs() {
    assert!(!needs_power_key(true, true));   // on → on: no-op
    assert!(!needs_power_key(false, false)); // off → off: no-op
    assert!(needs_power_key(false, true));
    assert!(needs_power_key(true, false));
}
```

- [ ] **Step 2: Run, watch fail; implement `needs_power_key` (`current_on != want_on`); green**

- [ ] **Step 3: Implement `set_power`**

```rust
pub fn set_power(host: std::net::IpAddr, port: u16, want_on: bool) -> Result<PowerOutput, AtvError> {
    let (current, mut conn, mut hs) = read_power(host, port)?;
    let changed = needs_power_key(current, want_on);
    let mut resulting = current;
    if changed {
        crate::framing::write_message(&mut conn, &power_key_message())
            .map_err(|e| AtvError::new(ErrorKind::ProtocolError, format!("failed to send power key: {e}")))?;
        // Best effort: wait up to ~3 s for the TV to confirm the new state via
        // remote_start. On timeout or connection close (typical when turning
        // off), assume the key worked and report the target state.
        conn.sock.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok();
        hs.power = None; // any Some(...) from here on is a fresh observation
        resulting = want_on;
        loop {
            match crate::framing::read_message::<crate::proto::remote::RemoteMessage, _>(&mut conn) {
                Ok(msg) => {
                    if let Ok(Some(reply)) = hs.handle(msg) {
                        let _ = crate::framing::write_message(&mut conn, &reply);
                    }
                    if hs.power == Some(want_on) {
                        break;
                    }
                }
                Err(_) => break, // timeout or close: accept assumed state
            }
        }
        if let Some(observed) = hs.power {
            resulting = observed;
        }
    }
    Ok(PowerOutput {
        timestamp: crate::output::timestamp(),
        host: host.to_string(),
        power: power_str(resulting),
        changed,
    })
}
```

`hs.power` is reset to `None` right after the key is sent, so the final `if let Some(observed)` only fires on a fresh `remote_start` observation; otherwise the pre-seeded `want_on` (assumed success) is reported.

- [ ] **Step 4: Wire `on`/`off` in `main.rs`**

`Command::On(args) => output::emit(&session::set_power(args.host, port, true)?)`, same for `Off` with `false`. Delete the now-dead "Phase 2 unimplemented" error and the `config::ensure_paired` call in `run()` (the TLS loader raises `not_paired` itself). Update `tests/cli.rs`: the without-store test still expects exit 4 for all three session commands (now raised by `TlsClient::from_credential_dir`); delete the with-store "phase2 unimplemented" test (a with-store run would hit the network; do not test that path in integration).

- [ ] **Step 5: All green, fmt/clippy gate; README (`on`/`off` implemented, `changed` semantics, best-effort confirmation note), commit** — `feat: implement idempotent power control (Phase 3)`

**After this task the main loop performs the Phase 3 real-TV E2E (on→on no-op, on→off, off→off no-op, off→on) and documents it in README, then deploys the final binary to jarvis.**

---

## E2E checkpoints (main loop, not subagents)

1. **Phase 1:** `cross build --release --target aarch64-unknown-linux-musl`, deploy to `jarvis:~/.local/bin/atv` (atomic `.new` + `install`), then on jarvis: `tail -f /tmp/atv-pin.txt | atv pair --host <TV_IP>` in background, ask the user for the on-screen code, `echo <code> >> /tmp/atv-pin.txt`, expect `{"paired": true}` and exit 0. Record in README ("Verified against TOSHIBA REGZA 65X8900K").
2. **Phase 2:** `atv status --host <TV_IP>` → `{"power":"on"}` with TV on; standby test after Phase 3 off.
3. **Phase 3:** four transitions with user confirmation of the actual TV state; `off` twice to confirm `changed:false` idempotency; unplugged/`unreachable` case optional (skip if disruptive).

TV on the LAN: discovered via mDNS at deploy time (avahi-browse from jarvis). Do not hardcode the TV IP in the repo — real IPs never land in committed files; README documents the mDNS discovery command instead.
