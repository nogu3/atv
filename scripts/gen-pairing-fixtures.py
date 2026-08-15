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
