"""Cert Generator Pal remote relay: the sealed envelope (docs/cert-generator-pal.md §8).

A PC away from the LAN sends its *whole signed LAN request* sealed to the server's relay
key, through a Cloudflare Worker mailbox the server collects from. This module is the
envelope only: both directions, so the server can open requests and seal replies, and the
tests (and test vectors shared with the Pal) can play the PC's side.

- Key agreement: a one-time P-256 key per request (the PC's device key only signs), ECDH
  with the relay key, HKDF-SHA256 → one key for the request, one for the reply.
- The outer envelope is signed by the device key in IEEE P1363 form (raw r‖s), which the
  Worker verifies with WebCrypto without being able to read anything.
- AES-256-GCM, with the device id, time and nonce as associated data.
"""
from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import UserError

VERSION = 1
SALT = b"CGP1-RELAY"
SIGN_LABEL = "CGP1-RELAY"
REQ_LABEL = "CGP1-RELAY-REQ"
REP_LABEL = "CGP1-RELAY-REP"
MAX_ENVELOPE = 300 * 1024  # a CSR request is a few KB; the reply with a chain somewhat more
_FIELDS = ("v", "d", "t", "n", "e", "i", "c", "s")


class RelayError(UserError):
    """An envelope that can't be accepted. The message is safe to show."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or len(text) > 2 * MAX_ENVELOPE:
        raise RelayError("Bad envelope field")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as e:
        raise RelayError("Bad envelope field") from e


# ── Keys ────────────────────────────────────────────────────────────

def new_relay_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def private_key_der(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_private_key(der: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_der_private_key(der, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise RelayError("The relay key must be P-256")
    return key


def public_raw(key: ec.EllipticCurvePublicKey) -> bytes:
    """SEC1 uncompressed point (65 bytes): what the Pal pins and the envelope carries."""
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _load_point(raw: bytes) -> ec.EllipticCurvePublicKey:
    if len(raw) != 65 or raw[0] != 4:
        raise RelayError("Bad one-time key")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as e:
        raise RelayError("Bad one-time key") from e


def _keys(shared: bytes, epk: bytes, relay_pub: bytes) -> tuple[bytes, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=SALT, info=epk + relay_pub).derive(shared)
    return okm[:32], okm[32:]


# ── Strings both sides compute ──────────────────────────────────────

def signing_string(env: dict[str, Any]) -> bytes:
    return "\n".join([SIGN_LABEL, env["d"], str(env["t"]), env["n"], env["e"], env["i"], env["c"]]).encode()


def request_aad(device_id: str, timestamp: int, nonce: str) -> bytes:
    return f"{REQ_LABEL}\n{device_id}\n{timestamp}\n{nonce}".encode()


def reply_aad(device_id: str, nonce: str) -> bytes:
    return f"{REP_LABEL}\n{device_id}\n{nonce}".encode()


def p1363_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise RelayError("Bad envelope signature")
    return encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))


def der_to_p1363(signature: bytes) -> bytes:
    r, s = decode_dss_signature(signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ── The server's side ───────────────────────────────────────────────

@dataclass(frozen=True)
class Request:
    """A parsed, not yet trusted, request envelope."""
    raw: dict[str, Any]
    device_id: str
    timestamp: int
    nonce: str


def parse_request(data: bytes) -> Request:
    """Structure only: nothing here is verified yet."""
    if len(data) > MAX_ENVELOPE:
        raise RelayError("Envelope too large")
    try:
        env = json.loads(data)
    except ValueError as e:
        raise RelayError("Envelope is not JSON") from e
    if not isinstance(env, dict) or set(env) != set(_FIELDS) or env["v"] != VERSION:
        raise RelayError("Not a CGP1 relay envelope")
    if not all(isinstance(env[k], str) for k in ("d", "n", "e", "i", "c", "s")) or type(env["t"]) is not int:
        raise RelayError("Not a CGP1 relay envelope")
    if len(env["d"]) != 32 or not 16 <= len(env["n"]) <= 64:
        raise RelayError("Not a CGP1 relay envelope")
    return Request(raw=env, device_id=env["d"], timestamp=env["t"], nonce=env["n"])


def verify_request(req: Request, device_public_key_der: bytes) -> bool:
    """The device key's outer signature (the same check the Worker makes)."""
    try:
        key = serialization.load_der_public_key(device_public_key_der)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            return False
        key.verify(p1363_to_der(b64url_decode(req.raw["s"])), signing_string(req.raw), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, RelayError, ValueError):
        return False
    return True


def open_request(req: Request, relay_key: ec.EllipticCurvePrivateKey) -> tuple[dict[str, Any], bytes]:
    """Decrypt the inner request. Returns (inner, reply key)."""
    epk = b64url_decode(req.raw["e"])
    relay_pub = public_raw(relay_key.public_key())
    k_req, k_rep = _keys(relay_key.exchange(ec.ECDH(), _load_point(epk)), epk, relay_pub)
    iv = b64url_decode(req.raw["i"])
    if len(iv) != 12:
        raise RelayError("Bad envelope IV")
    try:
        plain = AESGCM(k_req).decrypt(iv, b64url_decode(req.raw["c"]), request_aad(req.device_id, req.timestamp, req.nonce))
        inner = json.loads(plain)
    except (InvalidTag, ValueError) as e:
        raise RelayError("Envelope does not open with this server's relay key") from e
    if not isinstance(inner, dict):
        raise RelayError("Bad inner request")
    return inner, k_rep


def reply_key(req: Request, relay_key: ec.EllipticCurvePrivateKey) -> bytes:
    """The reply key alone, to answer an envelope the server refuses (only its sender can read it)."""
    epk = b64url_decode(req.raw["e"])
    return _keys(relay_key.exchange(ec.ECDH(), _load_point(epk)), epk, public_raw(relay_key.public_key()))[1]


def seal_reply(k_rep: bytes, device_id: str, nonce: str, inner: dict[str, Any], *, iv: bytes | None = None) -> bytes:
    iv = iv or secrets.token_bytes(12)
    ct = AESGCM(k_rep).encrypt(iv, json.dumps(inner, separators=(",", ":")).encode(), reply_aad(device_id, nonce))
    return json.dumps({"v": VERSION, "n": nonce, "i": b64url(iv), "c": b64url(ct)}, separators=(",", ":")).encode()


# ── The PC's side (the Pal does this in C#; here for tests and vectors) ──

def seal_request(device_key: ec.EllipticCurvePrivateKey, device_id: str, relay_pub: bytes, inner: dict[str, Any],
                 *, timestamp: int, nonce: str, one_time: ec.EllipticCurvePrivateKey | None = None,
                 iv: bytes | None = None) -> tuple[bytes, bytes]:
    """Returns (envelope, reply key)."""
    one_time = one_time or ec.generate_private_key(ec.SECP256R1())
    epk = public_raw(one_time.public_key())
    k_req, k_rep = _keys(one_time.exchange(ec.ECDH(), _load_point(relay_pub)), epk, relay_pub)
    iv = iv or secrets.token_bytes(12)
    ct = AESGCM(k_req).encrypt(iv, json.dumps(inner, separators=(",", ":")).encode(),
                               request_aad(device_id, timestamp, nonce))
    env: dict[str, Any] = {"v": VERSION, "d": device_id, "t": timestamp, "n": nonce,
                           "e": b64url(epk), "i": b64url(iv), "c": b64url(ct)}
    env["s"] = b64url(der_to_p1363(device_key.sign(signing_string(env), ec.ECDSA(hashes.SHA256()))))
    return json.dumps(env, separators=(",", ":")).encode(), k_rep


def open_reply(k_rep: bytes, device_id: str, nonce: str, data: bytes) -> dict[str, Any]:
    try:
        env = json.loads(data)
        if not isinstance(env, dict) or env.get("v") != VERSION or env.get("n") != nonce:
            raise RelayError("Not the reply to this request")
        plain = AESGCM(k_rep).decrypt(b64url_decode(env["i"]), b64url_decode(env["c"]), reply_aad(device_id, nonce))
        inner = json.loads(plain)
    except (InvalidTag, ValueError, KeyError, TypeError) as e:
        raise RelayError("The reply did not come from this PC's server") from e
    if not isinstance(inner, dict):
        raise RelayError("Bad inner reply")
    return inner
