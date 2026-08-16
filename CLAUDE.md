# CLAUDE.md

`atv` — a thin CLI for controlling Android TV / Google TV devices over the
**Android TV Remote protocol v2** (the protocol the official Google TV mobile
remote uses). It is a sibling CLI of `enl` / `swb` / `mat`, designed to be
called by [casa](https://github.com/nogu3/casa) as a subprocess.

> Name: **`atv`** — decided (follows the casa sibling-CLI naming convention;
> no PATH collision: pyatv installs `atvremote`, not `atv`).
> Repository: **public / standalone repository**.

---

## Purpose and scope

The concrete driving use case is a TOSHIBA REGZA 65X8900K (an Android TV
REGZA) that speaks Remote v2 on the LAN but not ECHONET Lite. The initial
scope is deliberately tiny:

- **`pair`** — one-time pairing with a TV (PIN shown on screen).
- **`status`** — report the device's power state.
- **`on` / `off`** — **idempotent** power control. The Remote v2 session
  reports the current power state on connect; `atv` sends the power keycode
  only when the state actually needs to change. Never blind-toggle.

That's it. Everything else is deferred (see "Explicitly deferred").

## Protocol facts (reference)

- Pairing: TCP **6467**, session: TCP **6466**. Both TLS with mutual
  self-signed certificates; messages are length-prefixed protobuf.
- Pairing proves physical access: the TV shows a 6-hex-digit code; the client
  hashes both certificates' public-key moduli/exponents with part of the code
  and sends the digest ("secret") to finish.
- After pairing the TV trusts the client certificate; no per-host session
  state is needed between runs.
- The TV advertises `_androidtvremote2._tcp` via mDNS.
- Reference implementations (no Rust crate exists; the protocol is
  reverse-engineered — vendor the `.proto` files into this repo):
  [androidtvremote2 (Python)](https://github.com/tronikos/androidtvremote2),
  [atvremote (Go)](https://github.com/drosoCode/atvremote),
  [androidtv-remote (TS)](https://github.com/kud/androidtv-remote).

## Design rules (never break)

1. **stdout is pure structured JSON only.** No color, no progress, no
   prompts. The one stdin interaction is `pair` reading the on-screen code as
   a plain line from stdin (documented below).
2. **Diagnostics go to stderr as structured logs** (`tracing`, level via
   `RUST_LOG`).
3. **Hold no state except the credential store.** One client certificate +
   key generated at first `pair`, stored under
   `$XDG_CONFIG_HOME/atv/` (default `~/.config/atv/`, overridable via
   `ATV_CONFIG_DIR`). No cache DB, no daemon, no scheduler. The same client
   identity is reused for every TV; pairing registers it per device.
4. **One-shot execution.** Connect, do one thing, print JSON, exit. Resident
   behavior (state subscriptions etc.) belongs to `casad`, not here.
5. **Address by `--host <ip>` (optional `--port`).** No name resolution, no
   device registry — that is casa's job (`devices.toml`).

## CLI surface (initial)

```
atv pair   --host <ip>            # TV shows code; atv reads it from stdin
atv status --host <ip>            # {"power": "on" | "off", ...}
atv on     --host <ip> [--mac <mac>]  # idempotent; --mac = WoL fallback for deep standby
atv off    --host <ip>
atv key    --host <ip> <KEY>...   # short key presses (VOLUME_UP, DPAD_*, ...)
atv launch --host <ip> <link>     # app link / deeplink
atv discover [--timeout <secs>]   # mDNS browse (no --host, no credentials)
```

(`key`, `launch`, and `discover` were originally deferred and were added
after Phases 0-3 shipped, at the user's request.)

## Output conventions

### stdout
- On success, one JSON object. A **`timestamp` field is required** (ISO 8601,
  the time `atv` built the response). Example:
  ```json
  {
    "timestamp": "2026-08-15T12:34:56+09:00",
    "host": "192.0.2.10",
    "power": "on",
    "changed": false
  }
  ```
  (`changed` on `on`/`off`: whether a keycode was actually sent.)

### stderr
- Errors use `{"error": {"kind": "...", "detail": "..."}}`, `detail` specific
  enough for an AI to decide recovery (e.g. `"192.0.2.10:6466 unreachable —
  TV powered off without network standby?"`).
- Stable `kind` values (document in README as they land): `unreachable`,
  `not_paired`, `auth_rejected`, `pairing_failed`, `protocol_error`,
  `config_io`.

### exit codes
| code | meaning |
|---|---|
| 0 | Success (including a no-op `on` when already on) |
| 1 | Internal / protocol error |
| 2 | CLI argument error (clap default) |
| 3 | Network unreachable / timeout |
| 4 | Not paired, or certificate rejected by the TV (re-`pair` needed) |
| 5 | Pairing failed (wrong code, user declined) |

casa propagates these as-is; keep them stable once shipped.

## casa integration (for context; implemented on the casa side)

- casa gains an `androidtv` protocol variant (Phase 3 adapter pattern:
  enum variant + adapter + tests, handlers untouched).
- `devices.toml`: `protocol = "androidtv"`, `host = "192.0.2.10"`.
- `casa on/off` → `atv on/off --host <host>` (`on` should also pass
  `--mac <mac>` from `devices.toml` so deep-standby TVs wake via WoL);
  `casa get/set/describe` stay
  unsupported for this protocol (casa exits 14).
- Binary resolved from `PATH`, overridable via `CASA_ATV_BIN`.

## Tech stack

| Area | Choice | Notes |
|---|---|---|
| Language | Rust | Same as enl / mat / casa |
| CLI | `clap` (derive) | |
| TLS | `rustls` | Client cert auth; custom verifier that accepts the TV's self-signed server cert (pin nothing — pairing is the trust decision) |
| Certificates | `rcgen` | Generate the client identity at first `pair` |
| Protobuf | `prost` (+ `prost-build`) | Vendored `.proto` files (`pairingmessage.proto`, `remotemessage.proto`) |
| JSON | `serde` + `serde_json` | |
| mDNS | `mdns-sd` | `discover` only; pure Rust |
| Logging | `tracing` + `tracing-subscriber` | stderr |
| Async | none — `std::net` + blocking TLS is enough for one-shot ops | Add tokio only if a real need appears |

Keep dependencies minimal.

## Credentials and the repo

- The repo is **public**. Never commit certificates, keys, real IPs, or real
  MACs. Samples/tests use RFC 5737 addresses (`192.0.2.0/24`).
- The credential directory is excluded via `.gitignore` discipline (it lives
  outside the repo anyway).

## Explicitly deferred (do not implement without discussion)

- Voice, IME, casting, media metadata.
- Any resident / subscription mode (that is `casad`'s territory).
- Long-press key injection (`RemoteDirection` START_LONG / END_LONG).

## Roadmap

Proceed through phases **in order**; do not start the next until the current
one is fully done (tests pass, acceptance criteria met).

### Phase 0 — Skeleton
CLI skeleton with `clap`, JSON/stderr/exit-code conventions wired, credential
dir resolution (`ATV_CONFIG_DIR` / XDG), `--host`/`--port` parsing. No
network yet.
**Acceptance:** `cargo build` / `cargo test` / `cargo clippy -- -D warnings`
pass; running any subcommand without a credential store produces the
documented error shape.

### Phase 1 — Pairing
TLS client with generated identity, pairing handshake on 6467 (`pair`),
including the certificate-hash secret computation. Code read from stdin.
**Acceptance:** unit tests for message framing and the pairing-secret
computation against fixtures from a reference implementation; manual E2E
against the real TV documented in README.

### Phase 2 — Status
Session connect on 6466, parse the initial state messages, emit `status`.
**Acceptance:** unit tests for frame parsing; real-TV E2E documented
(on, standby, and unplugged → exit 3).

### Phase 3 — Idempotent power
`on` / `off` built on Phase 2's state read + conditional power keycode.
**Acceptance:** unit tests for the decision logic (already-on → no send,
`changed: false`); real-TV E2E for all four transitions documented.

### Phase 4 — casa adapter (in the casa repo, not here)
Add the `androidtv` adapter to casa per its Phase 3 pattern, then wire the
device into `devices.toml` on jarvis.

## Known environment caveats (operational, keep in README)

- Power-on over LAN requires the TV's **network standby** setting; without it
  the TV drops off the network when off and `on` exits 3.
- The TV may rotate IPs via DHCP; prefer a DHCP reservation for the TV.

## Development commands

```bash
cargo build
cargo test
cargo clippy -- -D warnings
RUST_LOG=debug cargo run -- status --host 192.0.2.10
```
