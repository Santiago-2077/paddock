"""Verificación JWT (RS256) contra JWKS LOCAL — Python puro, cero dependencias.

Replica lo que el protocolo (§4.3) exige para rutas protegidas:
  - firma válida (RS256 contra la clave del JWKS por 'kid')
  - iss (issuer) esperado
  - aud / client_id
  - exp vigente
  - token_use == "access"
  - grupo requerido en cognito:groups (p. ej. "Admin")

Para migrar a Amazon Cognito real: cambiar ISSUER y AUDIENCE abajo y apuntar
JWKS_PATH al JWKS del User Pool (o descargarlo). El resto no cambia.
"""
import base64
import hashlib
import json
import os
import time

_KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
JWKS_PATH = os.environ.get("PADDOCK_JWKS", os.path.join(_KEYS_DIR, "jwks.json"))

# Config "tipo Cognito" para el stub local (intercambiable por el real)
ISSUER = os.environ.get("PADDOCK_ISS", "https://paddock-lab.local/userpool")
AUDIENCE = os.environ.get("PADDOCK_AUD", "paddock-app-client")

# SHA-256 DigestInfo prefix para PKCS#1 v1.5 (RFC 8017)
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64u_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64u_int(s: str) -> int:
    return int.from_bytes(_b64u_decode(s), "big")


def _load_jwks():
    with open(JWKS_PATH) as f:
        return {k["kid"]: k for k in json.load(f)["keys"]}


def _rsa_pkcs1v15_verify(msg: bytes, sig: bytes, n: int, e: int) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    m = pow(s, e, n)                      # RSA public op
    em = m.to_bytes(k, "big")
    # EM esperado: 0x00 0x01 PS(0xff..) 0x00 DigestInfo
    digest = hashlib.sha256(msg).digest()
    t = _SHA256_PREFIX + digest
    ps_len = k - len(t) - 3
    if ps_len < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
    # comparación en tiempo constante
    import hmac as _hmac
    return _hmac.compare_digest(em, expected)


def verify(token: str, require_group: str | None = None):
    """Devuelve (ok: bool, claims: dict, error: str).

    error ∈ {"", "no_token", "malformed", "bad_alg", "unknown_kid",
             "bad_signature", "bad_iss", "bad_aud", "bad_token_use",
             "expired", "forbidden"}.
    'forbidden' => autenticado pero sin el grupo requerido (HTTP 403).
    """
    if not token:
        return False, {}, "no_token"
    parts = token.split(".")
    if len(parts) != 3:
        return False, {}, "malformed"
    try:
        header = json.loads(_b64u_decode(parts[0]))
        claims = json.loads(_b64u_decode(parts[1]))
        sig = _b64u_decode(parts[2])
    except Exception:
        return False, {}, "malformed"

    if header.get("alg") != "RS256":
        return False, {}, "bad_alg"

    jwks = _load_jwks()
    jwk = jwks.get(header.get("kid"))
    if not jwk:
        return False, {}, "unknown_kid"

    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    n, e = _b64u_int(jwk["n"]), _b64u_int(jwk["e"])
    if not _rsa_pkcs1v15_verify(signing_input, sig, n, e):
        return False, claims, "bad_signature"

    if claims.get("iss") != ISSUER:
        return False, claims, "bad_iss"
    aud = claims.get("aud") or claims.get("client_id")
    if aud != AUDIENCE:
        return False, claims, "bad_aud"
    if claims.get("token_use") != "access":
        return False, claims, "bad_token_use"
    if int(claims.get("exp", 0)) < int(time.time()):
        return False, claims, "expired"

    if require_group:
        groups = claims.get("cognito:groups", []) or []
        if require_group not in groups:
            return False, claims, "forbidden"

    return True, claims, ""
