"""Cert Generator Pal remote relay, phase R1: the sealed envelope and the server's dispatch
(docs/cert-generator-pal.md §8). No Cloudflare: envelopes are handed to relay_dispatch directly,
as the collector will."""
from __future__ import annotations

import json
import secrets
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from app import db, pal, relay, server
from app.routes import pal as pal_routes

from .test_pal_api import FakePal, _code, _make_ca, csr_pem
from .test_security import _enable_encryption


def _nonce() -> str:
    return pal.b64url(secrets.token_bytes(16))


# ── Envelope ────────────────────────────────────────────────────────

def _keys():
    return ec.generate_private_key(ec.SECP256R1()), relay.new_relay_key()


def test_envelope_round_trip():
    device_key, relay_key = _keys()
    relay_pub = relay.public_raw(relay_key.public_key())
    nonce, now = _nonce(), int(time.time())
    inner = {"method": "GET", "path": "/api/pal/v1/device", "headers": {"X-Pal-Device": "d" * 32}, "body": ""}
    envelope, k_rep_pc = relay.seal_request(device_key, "d" * 32, relay_pub, inner, timestamp=now, nonce=nonce)

    req = relay.parse_request(envelope)
    assert relay.verify_request(req, _spki(device_key))
    opened, k_rep_server = relay.open_request(req, relay_key)
    assert opened == inner and k_rep_server == k_rep_pc

    reply = relay.seal_reply(k_rep_server, "d" * 32, nonce, {"status": 200, "headers": {}, "body": "e30"})
    assert relay.open_reply(k_rep_pc, "d" * 32, nonce, reply) == {"status": 200, "headers": {}, "body": "e30"}


def _spki(key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.mark.parametrize("field", ["d", "t", "n", "e", "i", "c"])
def test_any_changed_field_breaks_the_signature(field):
    device_key, relay_key = _keys()
    envelope, _ = relay.seal_request(device_key, "d" * 32, relay.public_raw(relay_key.public_key()), {"x": 1},
                                     timestamp=int(time.time()), nonce=_nonce())
    env = json.loads(envelope)
    # A value that already ends in "AA" (about 1 in 1000 for the point) must still change.
    tail = "BB" if str(env[field]).endswith("AA") else "AA"
    env[field] = env[field] + 1 if field == "t" else ("e" * 32 if field == "d" else env[field][:-2] + tail)
    assert not relay.verify_request(relay.parse_request(json.dumps(env).encode()), _spki(device_key))


def test_only_the_relay_key_opens_a_request():
    device_key, relay_key = _keys()
    envelope, _ = relay.seal_request(device_key, "d" * 32, relay.public_raw(relay_key.public_key()), {"x": 1},
                                     timestamp=int(time.time()), nonce=_nonce())
    with pytest.raises(relay.RelayError, match="does not open"):
        relay.open_request(relay.parse_request(envelope), relay.new_relay_key())


def test_a_reply_for_another_request_does_not_open():
    device_key, relay_key = _keys()
    relay_pub = relay.public_raw(relay_key.public_key())
    first, k_first = relay.seal_request(device_key, "d" * 32, relay_pub, {}, timestamp=1, nonce="a" * 22)
    _, k_second = relay.seal_request(device_key, "d" * 32, relay_pub, {}, timestamp=1, nonce="b" * 22)
    reply = relay.seal_reply(k_first, "d" * 32, "a" * 22, {"status": 200})
    with pytest.raises(relay.RelayError):
        relay.open_reply(k_second, "d" * 32, "a" * 22, reply)  # another one-time key
    with pytest.raises(relay.RelayError):
        relay.open_reply(k_first, "d" * 32, "b" * 22, reply)  # another nonce


# Short ids: pytest puts the test id in an environment variable, which Windows caps at 32,767 characters.
@pytest.mark.parametrize("raw", [b"not json", b"[]", b'{"v": 2}', b"{" + b" " * relay.MAX_ENVELOPE + b"}"],
                         ids=["not-json", "list", "other-version", "too-large"])
def test_malformed_envelopes_are_refused(raw):
    with pytest.raises(relay.RelayError):
        relay.parse_request(raw)


# ── Dispatch through the device API ─────────────────────────────────

class RemotePal:
    """FakePal's signed requests, sealed for the relay instead of sent over the LAN."""

    def __init__(self, pc: FakePal):
        self.pc = pc
        self.relay_pub = relay.public_raw(relay.load_private_key(db.get_pal_relay_key()).public_key())

    def send(self, method: str, path: str, payload=None, *, inner_device=None, timestamp=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        ts, nonce = str(int(time.time())), _nonce()
        signature = self.pc.device_key.sign(pal.request_signing_string(method, path, ts, nonce, body), ec.ECDSA(hashes.SHA256()))
        inner = {"method": method, "path": path, "body": relay.b64url(body),
                 "headers": {"X-Pal-Device": inner_device or self.pc.device_id, "X-Pal-Time": ts, "X-Pal-Nonce": nonce,
                             "X-Pal-Signature": pal.b64url(signature), "User-Agent": "CertGeneratorPal/9.9.9"}}
        outer_nonce = _nonce()
        envelope, k_rep = relay.seal_request(self.pc.device_key, self.pc.device_id, self.relay_pub, inner,
                                             timestamp=timestamp or int(time.time()), nonce=outer_nonce)
        self.last = (envelope, k_rep, outer_nonce)
        return envelope, self.open(envelope, k_rep, outer_nonce)

    def open(self, envelope, k_rep, outer_nonce):
        with server.app.app_context():
            sealed = pal_routes.relay_dispatch(envelope)
        if sealed is None:
            return None
        reply = relay.open_reply(k_rep, self.pc.device_id, outer_nonce, sealed)
        reply["json"] = json.loads(relay.b64url_decode(reply["body"]) or b"null")
        return reply


@pytest.fixture
def remote(admin_client):
    _enable_encryption(admin_client)
    db.create_pal_relay_key(relay.private_key_der(relay.new_relay_key()))
    ca_id = _make_ca(admin_client)
    pc = FakePal(admin_client, _code(admin_client, ca_id, crl_dps=["server", "none"]).get_json()["pairing_code"])
    assert pc.enroll().status_code == 201
    return admin_client, pc, RemotePal(pc)


def test_remote_access_is_off_until_allowed(remote):
    _, pc, link = remote
    _, reply = link.send("GET", "/api/pal/v1/device")
    assert reply["status"] == 403 and reply["json"]["error"].startswith("Remote access is off.")
    assert db.set_pal_remote_allowed(pc.device_id, True)
    _, reply = link.send("GET", "/api/pal/v1/device")
    assert reply["status"] == 200 and reply["json"]["device_id"] == pc.device_id
    device = db.get_pal_device(pc.device_id)
    assert device["last_via"] == "relay" and device["pal_version"] == "9.9.9"
    assert pc.signed("GET", "/api/pal/v1/device").status_code == 200
    assert db.get_pal_device(pc.device_id)["last_via"] == "lan"


def test_a_certificate_can_be_requested_through_the_relay(remote):
    _, pc, link = remote
    db.set_pal_remote_allowed(pc.device_id, True)
    _, reply = link.send("POST", "/api/pal/v1/requests", {"use_case": "web-server", "names": {"dns": ["pc01.lan"]},
                                                         "csr": csr_pem(ec.generate_private_key(ec.SECP256R1())),
                                                         "crl_dp": "server"})
    assert reply["status"] == 201 and reply["json"]["status"] == "issued" and "BEGIN CERTIFICATE" in reply["json"]["cert"]


def test_a_relayed_request_cannot_be_replayed(remote):
    _, pc, link = remote
    db.set_pal_remote_allowed(pc.device_id, True)
    _, reply = link.send("GET", "/api/pal/v1/device")
    assert reply["status"] == 200
    again = link.open(*link.last)  # the same envelope, collected twice
    assert again["status"] == 401 and again["json"]["error"].startswith("Request replayed.")


@pytest.mark.parametrize("path", ["/api/pal/v1/enroll", "/api/pal/codes", "/pal/CertGeneratorPal.exe",
                                  "/api/pal/v1/../codes", "/api/pal/v1/device?x=1"])
def test_only_the_signed_device_api_goes_through(remote, path):
    _, pc, link = remote
    db.set_pal_remote_allowed(pc.device_id, True)
    _, reply = link.send("GET", path)
    assert reply["status"] == 400 and reply["json"]["error"] == "Not a device API request"


def test_inner_request_must_be_from_the_same_pc(remote):
    _, pc, link = remote
    db.set_pal_remote_allowed(pc.device_id, True)
    _, reply = link.send("GET", "/api/pal/v1/device", inner_device="f" * 32)
    assert reply["status"] == 400 and "another PC" in reply["json"]["error"]


def test_strangers_get_no_answer(remote):
    _, pc, link = remote
    db.set_pal_remote_allowed(pc.device_id, True)
    stranger = ec.generate_private_key(ec.SECP256R1())
    envelope, _ = relay.seal_request(stranger, pc.device_id, link.relay_pub, {"method": "GET"},
                                     timestamp=int(time.time()), nonce=_nonce())
    with server.app.app_context():
        assert pal_routes.relay_dispatch(envelope) is None
        assert pal_routes.relay_dispatch(b"garbage") is None


def test_stale_envelope_and_disconnected_pc_are_refused(remote):
    client, pc, link = remote
    db.set_pal_remote_allowed(pc.device_id, True)
    _, reply = link.send("GET", "/api/pal/v1/device", timestamp=int(time.time()) - 3600)
    assert reply["status"] == 401 and reply["json"]["error"].startswith("Clock wrong.")
    client.post(f"/api/pal/devices/{pc.device_id}/revoke", json={})
    _, reply = link.send("GET", "/api/pal/v1/device")
    assert reply["status"] == 403 and reply["json"]["error"].startswith("Disconnected.")
    assert db.list_pal_remote_keys() == []


def test_relay_key_needs_encryption_and_blocks_turning_it_off(admin_client):
    with pytest.raises(Exception, match="encryption"):
        db.create_pal_relay_key(b"x")
    _enable_encryption(admin_client)
    db.create_pal_relay_key(relay.private_key_der(relay.new_relay_key()))
    with pytest.raises(Exception, match="already has a relay key"):
        db.create_pal_relay_key(b"x")
    resp = admin_client.post("/api/settings/encryption/disable", json={"password": "x"})
    assert resp.status_code == 400 and "relay" in resp.get_json()["error"]


def test_remote_keys_list_only_allowed_connected_pcs(remote):
    _, pc, _ = remote
    assert db.list_pal_remote_keys() == []
    db.set_pal_remote_allowed(pc.device_id, True)
    [(device_id, key)] = db.list_pal_remote_keys()
    assert device_id == pc.device_id and key == db.get_pal_device(pc.device_id)["public_key"]


# ── Vectors shared with the Pal's C# tests ──────────────────────────

def test_vectors_file_is_current_and_valid():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).parents[1]
    spec = importlib.util.spec_from_file_location("make_relay_vectors", root / "scripts" / "make_relay_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    committed = json.loads(module.OUT.read_text(encoding="utf-8"))
    fresh = module.build()
    # Everything but the ECDSA signature is deterministic; the committed signature must still verify.
    signature = committed["envelope"].pop("s")
    fresh["envelope"].pop("s")
    assert committed == fresh, "run scripts/make_relay_vectors.py"
    committed["envelope"]["s"] = signature
    device = relay.load_private_key(__import__("base64").b64decode(committed["device_private_pkcs8"]))
    req = relay.parse_request(json.dumps(committed["envelope"]).encode())
    assert relay.verify_request(req, _spki(device))
