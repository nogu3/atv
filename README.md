# atv

A thin CLI for controlling Android TV / Google TV devices over the
**Android TV Remote protocol v2** — the protocol the official Google TV
mobile remote uses. Designed to be called by
[casa](https://github.com/nogu3/casa) as a subprocess.

## Usage

```
atv pair   --host <ip>            # TV shows a code; atv reads it from stdin
atv status --host <ip>            # {"power": "on" | "off", ...}
atv on     --host <ip>            # idempotent; reports resulting state
atv off    --host <ip>
```

`--port` overrides the default port (6467 for `pair`, 6466 otherwise).
`--host` takes an IP address only; no name resolution.

> Status: Phase 0 (CLI skeleton). Pairing and session commands are not
> implemented yet and report `protocol_error`.

## Output conventions

- **stdout** is pure structured JSON: one object on success, always with an
  ISO 8601 `timestamp` field.
- **stderr** carries diagnostics (`tracing`, enable via `RUST_LOG`) and, on
  failure, one error object:

  ```json
  {"error": {"kind": "not_paired", "detail": "no client certificate in ~/.config/atv — run `atv pair --host <ip>` first"}}
  ```

### Error kinds

| kind | meaning |
|---|---|
| `not_paired` | No credential store yet, or certificate rejected — run `atv pair` |
| `protocol_error` | Internal / protocol failure (also: not-yet-implemented commands) |
| `config_io` | Credential directory could not be resolved or accessed |

Reserved for upcoming phases: `unreachable`, `auth_rejected`,
`pairing_failed`.

### Exit codes

| code | meaning |
|---|---|
| 0 | Success (including a no-op `on` when already on) |
| 1 | Internal / protocol error |
| 2 | CLI argument error |
| 3 | Network unreachable / timeout |
| 4 | Not paired, or certificate rejected by the TV (re-`pair` needed) |
| 5 | Pairing failed (wrong code, user declined) |

## Credentials

One client certificate + key, generated at first `pair`, stored under
`$XDG_CONFIG_HOME/atv/` (default `~/.config/atv/`), overridable via
`ATV_CONFIG_DIR`. No other state is held.

## Development

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
RUST_LOG=debug cargo run -- status --host 192.0.2.10
```

## Operational notes

- Power-on over LAN requires the TV's **network standby** setting; without
  it the TV drops off the network when off and `on` exits 3.
- The TV may rotate IPs via DHCP; prefer a DHCP reservation for the TV.
