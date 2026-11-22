"""Genera tokens JWT de prueba firmados con la clave LOCAL (RS256).

Casos para los escenarios AUTH-01..05 del protocolo:
    admin        -> válido, grupo Admin           (AUTH-01 => 200)
    participante -> válido, sin Admin              (AUTH-05 => 403)
    expired      -> válido pero exp en el pasado   (AUTH-04 => 401)
    tampered     -> firma alterada                 (AUTH-03 => 401)
  (AUTH-02 "sin token" no requiere generar nada.)

Uso:
    python3 tools/mint_token.py admin
    python3 tools/mint_token.py all        # imprime los 4
"""
import base64
import hashlib
import json
import os
import sys
import time

_KEYS = os.path.join(os.path.dirname(__file__), "..", "keys")
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

ISSUER = os.environ.get("PADDOCK_ISS", "https://paddock-lab.local/userpool")
AUDIENCE = os.environ.get("PADDOCK_AUD", "paddock-app-client")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _priv():
    p = json.load(open(os.path.join(_KEYS, "private.json")))
    return p["kid"], int(p["n"]), int(p["e"]), int(p["d"])


def _sign(signing_input: bytes, n: int, d: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    digest = hashlib.sha256(signing_input).digest()
    t = _SHA256_PREFIX + digest
    ps_len = k - len(t) - 3
    em = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
    m = int.from_bytes(em, "big")
    s = pow(m, d, n)                       # RSA private op
    return s.to_bytes(k, "big")


def mint(kind: str) -> str:
    kid, n, e, d = _priv()
    now = int(time.time())
    exp = now + 3600
    groups = ["Admin"] if kind == "admin" else ["Participante"]
    if kind == "expired":
        exp = now - 60
        groups = ["Admin"]
    claims = {
        "sub": f"local-{kind}-0001",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "token_use": "access",
        "cognito:groups": groups,
        "iat": now,
        "exp": exp,
        "username": kind,
    }
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    si = (_b64u(json.dumps(header).encode()) + "." +
          _b64u(json.dumps(claims).encode()))
    sig = _sign(si.encode("ascii"), n, d)
    tok = si + "." + _b64u(sig)
    if kind == "tampered":
        # invierte el último char de la firma -> firma inválida
        tok = si + "." + _b64u(sig[:-1] + bytes([sig[-1] ^ 0xFF]))
    return tok


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "admin"
    kinds = ["admin", "participante", "expired", "tampered"] if which == "all" else [which]
    for k in kinds:
        print(f"# {k}\n{mint(k)}\n")
