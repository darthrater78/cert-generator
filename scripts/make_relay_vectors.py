"""Write the relay envelope test vectors the Python and C# tests both check
(pal/tests/CertGeneratorPal.Tests/relay-vectors.json).

Fixed keys and IVs make the ciphertexts reproducible, so each side proves it seals and opens
exactly the same bytes as the other. The keys are test-only, derived from fixed numbers.

Usage: python scripts/make_relay_vectors.py
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import relay  # noqa: E402

OUT = ROOT / "pal" / "tests" / "CertGeneratorPal.Tests" / "relay-vectors.json"


def _key(n: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(n, ec.SECP256R1())


def build() -> dict:
    device, relay_key, one_time = _key(0x1111_1111_1111), _key(0x2222_2222_2222), _key(0x3333_3333_3333)
    device_id, nonce, timestamp = "0123456789abcdef0123456789abcdef", "bm9uY2Utb2YtdGhlLXRlc3Q", 1790000000
    inner_request = json.dumps({"method": "GET", "path": "/api/pal/v1/device", "headers": {"X-Pal-Device": device_id},
                                "body": ""}, separators=(",", ":")).encode()
    iv_request, iv_reply = bytes(range(12)), bytes(range(12, 24))
    envelope, k_rep = relay.seal_request(device, device_id, relay.public_raw(relay_key.public_key()),
                                         json.loads(inner_request), timestamp=timestamp, nonce=nonce,
                                         one_time=one_time, iv=iv_request)
    inner_reply = {"status": 200, "headers": {"Content-Type": "application/json"}, "body": relay.b64url(b'{"ok":true}')}
    reply = relay.seal_reply(k_rep, device_id, nonce, inner_reply, iv=iv_reply)
    b64 = lambda data: base64.b64encode(data).decode()  # noqa: E731
    return {
        "comment": "Test-only keys. Regenerate with scripts/make_relay_vectors.py; both test suites check this file.",
        "device_private_pkcs8": b64(relay.private_key_der(device)),
        "relay_private_pkcs8": b64(relay.private_key_der(relay_key)),
        "one_time_private_pkcs8": b64(relay.private_key_der(one_time)),
        "device_id": device_id, "nonce": nonce, "timestamp": timestamp,
        "iv_request": relay.b64url(iv_request), "iv_reply": relay.b64url(iv_reply),
        "inner_request": b64(inner_request),
        "envelope": json.loads(envelope),
        "inner_reply": b64(json.dumps(inner_reply, separators=(",", ":")).encode()),
        "reply": json.loads(reply),
    }


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
