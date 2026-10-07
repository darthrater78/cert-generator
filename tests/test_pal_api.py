"""Cert Generator Pal API: pairing, signed requests, policy, approvals, status, revocation."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import db, pal, server
from app.routes import pal as pal_routes

LAN = {"REMOTE_ADDR": "10.0.0.50"}


@pytest.fixture(autouse=True)
def _reset_pal_limiters():
    pal_routes.reset_limiters()
    yield
    pal_routes.reset_limiters()


def _make_ca(client, algorithm="ecdsa-p256", domain="lan", name="Home Root CA"):
    resp = client.post("/api/ca", json={"domain": domain, "name": name, "algorithm": algorithm})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["id"]


def _code(client, ca_id, **overrides):
    body = {
        "label": "pc01", "ca_id": ca_id, "server_url": "http://10.0.0.252:5000",
        "use_cases": {"web-server": "auto", "computer": "auto", "user": "approve", "code-signing": "off"},
        "dns": ["*.lan", "10.0.0.0/24"], "users": ["*@lan"], "max_days": 90, "crl_dp": "placeholder",
    }
    body.update(overrides)
    return client.post("/api/pal/codes", json=body)


class FakePal:
    """What the Windows app does on the wire."""

    def __init__(self, client, pairing_code: str):
        self.client = client
        self.code = pal.parse_pairing_code(pairing_code)
        self.key = base64.urlsafe_b64decode(self.code["k"] + "==")
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        self.device_id = None
        self.chain = None

    def enroll_body(self, **overrides) -> bytes:
        spki = self.device_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        body = {"code_id": self.code["i"], "device_key": base64.b64encode(spki).decode(),
                "hostname": "pc01", "fqdn": "pc01.lan", "os": "Windows 11", "ts": int(time.time()),
                "nonce": pal.b64url(secrets.token_bytes(16))}
        body.update(overrides)
        return json.dumps(body).encode()

    def enroll(self, body: bytes | None = None, key: bytes | None = None, environ=LAN):
        body = body or self.enroll_body()
        proof = pal.enroll_proof(key or self.key, body)
        resp = self.client.post("/api/pal/v1/enroll", data=body, content_type="application/json",
                                headers={"X-Pal-Proof": proof}, environ_base=environ)
        if resp.status_code == 201:
            assert resp.headers["X-Pal-Mac"] == pal.enrolled_mac(self.key, resp.get_data())
            data = resp.get_json()
            self.device_id = data["device_id"]
            self.chain = data["chain"]
        return resp

    def signed(self, method: str, path: str, payload=None, *, timestamp=None, nonce=None, sign_with=None, agent=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        timestamp = str(timestamp if timestamp is not None else int(time.time()))
        nonce = nonce or pal.b64url(secrets.token_bytes(16))
        message = pal.request_signing_string(method, path, timestamp, nonce, body)
        signature = (sign_with or self.device_key).sign(message, ec.ECDSA(hashes.SHA256()))
        headers = {"X-Pal-Device": self.device_id, "X-Pal-Time": timestamp, "X-Pal-Nonce": nonce,
                   "X-Pal-Signature": pal.b64url(signature)}
        if agent:
            headers["User-Agent"] = agent
        return self.client.open(path, method=method, data=body, headers=headers,
                                content_type="application/json", environ_base=LAN)

    def request(self, use_case, names, key=None, **extra):
        key = key or ec.generate_private_key(ec.SECP256R1())
        return self.signed("POST", "/api/pal/v1/requests",
                           {"use_case": use_case, "names": names, "csr": csr_pem(key), **extra}), key


def _near_expiry(cert_id: int, days_left: int = 5) -> None:
    """Move a certificate into its renewal window (the server reads the dates it stored)."""
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    with db._connect() as conn:
        conn.execute("UPDATE certificates SET not_before = ?, not_after = ? WHERE id = ?",
                     ((now - timedelta(days=360)).isoformat(), (now + timedelta(days=days_left)).isoformat(), cert_id))


def csr_pem(key, cn="ignored-by-server") -> str:
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
           .sign(key, algorithm))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def paired(admin_client):
    ca_id = _make_ca(admin_client)
    resp = _code(admin_client, ca_id)
    assert resp.status_code == 201, resp.get_json()
    device = FakePal(admin_client, resp.get_json()["pairing_code"])
    assert device.enroll().status_code == 201
    return admin_client, device, ca_id


# ── Pairing ─────────────────────────────────────────────────────────

def test_pairing_code_pins_root_and_never_lists_key(admin_client):
    ca_id = _make_ca(admin_client)
    data = _code(admin_client, ca_id).get_json()
    fields = pal.parse_pairing_code(data["pairing_code"])
    root_pem = db.get_ca_cert_chain(ca_id)[-1]
    root_der = x509.load_pem_x509_certificate(root_pem).public_bytes(serialization.Encoding.DER)
    assert fields["r"] == hashlib.sha256(root_der).hexdigest()
    assert fields["u"] == "http://10.0.0.252:5000" and fields["i"] == data["id"]
    listed = admin_client.get("/api/pal/codes").get_json()
    assert listed[0]["state"] == "unused" and "key" not in listed[0]
    # stored encrypted when encryption is on, but never in the listing either way
    assert fields["k"] not in json.dumps(listed)


def test_enroll_returns_chain_matching_pin_and_code_is_single_use(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id).get_json()["pairing_code"])
    resp = device.enroll()
    assert resp.status_code == 201
    root = x509.load_pem_x509_certificate(device.chain[0].encode())
    assert hashlib.sha256(root.public_bytes(serialization.Encoding.DER)).hexdigest() == device.code["r"]
    assert resp.get_json()["policy"]["use_cases"]["code-signing"] == "off"
    assert device.enroll(device.enroll_body()).status_code == 403
    assert admin_client.get("/api/pal/codes").get_json()[0]["state"] == "used"


def test_enroll_with_wrong_key_fails_and_locks_out(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id).get_json()["pairing_code"])
    for _ in range(5):
        assert device.enroll(key=secrets.token_bytes(32)).status_code == 403
    assert device.enroll().status_code == 429  # even the right key, until the lockout ends


def test_enroll_body_tampering_breaks_proof(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id).get_json()["pairing_code"])
    body = device.enroll_body()
    proof = pal.enroll_proof(device.key, body)
    attacker_key = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    swapped = json.loads(body)
    swapped["device_key"] = base64.b64encode(attacker_key).decode()
    resp = admin_client.post("/api/pal/v1/enroll", data=json.dumps(swapped), content_type="application/json",
                             headers={"X-Pal-Proof": proof}, environ_base=LAN)
    assert resp.status_code == 403


def test_revoked_expired_and_used_codes_say_why(admin_client):
    ca_id = _make_ca(admin_client)
    data = _code(admin_client, ca_id).get_json()
    assert admin_client.post(f"/api/pal/codes/{data['id']}/revoke").status_code == 200
    resp = FakePal(admin_client, data["pairing_code"]).enroll()
    assert resp.status_code == 403 and resp.get_json()["error"].startswith("Code revoked.")
    data = _code(admin_client, ca_id).get_json()
    with db._connect() as conn:
        conn.execute("UPDATE pal_codes SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?", (data["id"],))
    resp = FakePal(admin_client, data["pairing_code"]).enroll()
    assert resp.status_code == 403 and resp.get_json()["error"] == (
        "Code expired. This pairing code expired 01 Jan 2000 00:00 UTC. Ask your admin for a new one")
    data = _code(admin_client, ca_id).get_json()
    assert FakePal(admin_client, data["pairing_code"]).enroll().status_code == 201
    resp = FakePal(admin_client, data["pairing_code"]).enroll()
    assert resp.status_code == 403 and resp.get_json()["error"].startswith("Code already used.")


def test_code_state_is_only_told_to_the_code_holder(admin_client):
    ca_id = _make_ca(admin_client)
    data = _code(admin_client, ca_id).get_json()
    admin_client.post(f"/api/pal/codes/{data['id']}/revoke")
    resp = FakePal(admin_client, data["pairing_code"]).enroll(key=secrets.token_bytes(32))  # wrong key
    assert resp.get_json()["error"].startswith("Code not accepted.")


def test_enroll_rejects_stale_clock(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id).get_json()["pairing_code"])
    resp = device.enroll(device.enroll_body(ts=int(time.time()) - 3600))
    assert resp.status_code == 403 and "clock" in resp.get_json()["error"]


def test_device_api_is_lan_only(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id).get_json()["pairing_code"])
    assert device.enroll(environ={"REMOTE_ADDR": "8.8.8.8"}).status_code == 404
    assert device.enroll(environ={"REMOTE_ADDR": "192.168.1.20"}).status_code == 201


def test_device_api_sets_no_cookies(paired):
    _, device, _ = paired
    resp = device.signed("GET", "/api/pal/v1/device")
    assert resp.status_code == 200 and "Set-Cookie" not in resp.headers


# ── Admin side ──────────────────────────────────────────────────────

def test_admin_api_requires_login(client):
    assert client.get("/api/pal/codes").status_code in (302, 401)
    assert client.post("/api/pal/codes", json={}).status_code in (302, 401)
    assert client.delete("/api/pal/devices/abc").status_code in (302, 401)
    assert client.get("/api/pal/binds").status_code in (302, 401)
    assert client.post("/api/pal/binds/1/approve").status_code in (302, 401)
    assert client.post("/api/pal/binds/1/deny", json={}).status_code in (302, 401)


@pytest.mark.parametrize("overrides, message", [
    ({"server_url": "http://8.8.8.8:5000"}, "LAN only"),
    ({"server_url": "ftp://pki.lan"}, "http(s)"),
    ({"dns": ["not a name"]}, "Not a DNS name"),
    ({"dns": []}, "at least one allowed DNS name"),
    ({"use_cases": {"web-server": "off"}}, "at least one use case"),
    ({"use_cases": {"web-server": "sometimes"}}, "choose one of"),
    ({"max_days": 0}, "Maximum lifetime"),
    ({"expires_hours": 1000}, "expire within"),
    ({"label": "x" * 65}, "note"),
])
def test_code_form_validation(admin_client, overrides, message):
    ca_id = _make_ca(admin_client)
    resp = _code(admin_client, ca_id, **overrides)
    assert resp.status_code == 400 and message in resp.get_json()["error"]


def test_ed25519_ca_refused(admin_client):
    ca_id = _make_ca(admin_client, algorithm="ed25519")
    resp = _code(admin_client, ca_id)
    assert resp.status_code == 400 and "Ed25519" in resp.get_json()["error"]


def test_desktop_mode_has_no_pal(admin_client):
    server.set_app_token("tok")
    try:
        admin_client.set_cookie("_app_token", "tok")
        assert admin_client.get("/api/pal/codes").status_code == 404
    finally:
        server.set_app_token(None)


# ── Requests ────────────────────────────────────────────────────────

def test_auto_issue_web_server_uses_pc_key(paired):
    client, device, _ = paired
    resp, key = device.request("web-server", {"dns": ["PC01.lan", "10.0.0.50", "pc01.lan"]})
    assert resp.status_code == 201, resp.get_json()
    data = resp.get_json()
    cert = x509.load_pem_x509_certificate(data["cert"].encode())
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "pc01.lan"
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["pc01.lan"]
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["10.0.0.50"]
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 90  # capped by max_days
    assert data["chain"] == device.chain
    stored = db.get_cert(data["cert_id"])
    assert stored["key_pem"] == b"" and stored["pal_device_id"] == device.device_id
    # the private key never reached the server, so it can't be exported
    resp = client.post(f"/api/export/cert/{data['cert_id']}", json={"part": "both", "format": "pem"})
    assert resp.status_code == 400 and "never left the PC" in resp.get_json()["error"]
    resp = client.post(f"/api/export/cert/{data['cert_id']}", json={"part": "public", "format": "pem"})
    assert resp.status_code == 200


def test_csr_subject_and_extensions_are_ignored(paired):
    _, device, _ = paired
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.example.com")]))
           .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("evil.example.com")]), critical=False)
           .sign(key, hashes.SHA256()))
    resp = device.signed("POST", "/api/pal/v1/requests", {
        "use_case": "web-server", "names": {"dns": ["pc01.lan"]},
        "csr": csr.public_bytes(serialization.Encoding.PEM).decode()})
    cert = x509.load_pem_x509_certificate(resp.get_json()["cert"].encode())
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == ["pc01.lan"]


@pytest.mark.parametrize("names", [
    {"dns": ["pc01.example.com"]},
    {"dns": ["lan"]},
    {"dns": ["*.lan"]},
    {"dns": ["10.0.1.5"]},
    {"dns": ["bad name.lan"]},
    {"dns": []},
])
def test_names_outside_policy_refused(paired, names):
    _, device, _ = paired
    resp, _ = device.request("web-server", names)
    assert resp.status_code == 400


def test_use_case_off_refused(paired):
    _, device, _ = paired
    resp, _ = device.request("code-signing", {"cn": "Me"})
    assert resp.status_code == 403


def test_bad_csrs_refused(paired):
    _, device, _ = paired
    resp = device.signed("POST", "/api/pal/v1/requests",
                         {"use_case": "web-server", "names": {"dns": ["pc01.lan"]}, "csr": "garbage"})
    assert resp.status_code == 400
    resp, _ = device.request("web-server", {"dns": ["pc01.lan"]}, key=ed25519.Ed25519PrivateKey.generate())
    assert resp.status_code == 400 and "Unsupported key type" in resp.get_json()["error"]
    resp, _ = device.request("web-server", {"dns": ["pc01.lan"]},
                             key=rsa.generate_private_key(public_exponent=65537, key_size=1024))
    assert resp.status_code == 400


def test_rsa_3072_csr_accepted(paired):
    _, device, _ = paired
    resp, _ = device.request("computer", {},
                             key=rsa.generate_private_key(public_exponent=65537, key_size=3072))
    assert resp.status_code == 201
    assert db.get_cert(resp.get_json()["cert_id"])["algorithm"] == "rsa-3072"


def test_approval_flow_and_renewal(paired):
    client, device, _ = paired
    resp, _ = device.request("user", {"upn": "alice@lan"})
    assert resp.status_code == 202 and resp.get_json()["status"] == "pending"
    request_id = resp.get_json()["id"]
    assert device.signed("GET", f"/api/pal/v1/requests/{request_id}").get_json()["status"] == "pending"
    pending = client.get("/api/pal/requests?status=pending").get_json()
    assert [r["id"] for r in pending] == [request_id] and pending[0]["names"]["upn"] == "alice@lan"
    assert client.post(f"/api/pal/requests/{request_id}/approve").status_code == 200
    assert client.post(f"/api/pal/requests/{request_id}/approve").status_code == 404  # signed once
    view = device.signed("GET", f"/api/pal/v1/requests/{request_id}").get_json()
    assert view["status"] == "issued"
    cert = x509.load_pem_x509_certificate(view["cert"].encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert len(san.get_values_for_type(x509.OtherName)) == 1 and san.get_values_for_type(x509.RFC822Name) == []
    # renewal opens near expiry only
    resp, _ = device.request("user", {"upn": "alice@lan"}, renew_of=view["cert_id"])
    assert resp.status_code == 409 and resp.get_json()["error"].startswith("Too early to renew.")
    _near_expiry(view["cert_id"])
    # renewing the approved names needs no new approval
    resp, _ = device.request("user", {"upn": "alice@lan"}, renew_of=view["cert_id"])
    assert resp.status_code == 201
    # other names are a new request
    resp, _ = device.request("user", {"upn": "bob@lan"}, renew_of=view["cert_id"])
    assert resp.status_code == 400


def test_deny(paired):
    client, device, _ = paired
    resp, _ = device.request("user", {"upn": "alice@lan"})
    request_id = resp.get_json()["id"]
    assert client.post(f"/api/pal/requests/{request_id}/deny", json={"reason": "who?"}).status_code == 200
    view = device.signed("GET", f"/api/pal/v1/requests/{request_id}").get_json()
    assert view["status"] == "denied" and view["reason"] == "who?" and "cert" not in view


def test_renew_of_someone_elses_cert_refused(paired):
    client, device, ca_id = paired
    other = client.post(f"/api/ca/{ca_id}/certs", json={"common_name": "pc01.lan"}).get_json()
    resp, _ = device.request("web-server", {"dns": ["pc01.lan"]}, renew_of=other["id"])
    assert resp.status_code == 400


def test_locked_database_keeps_request_pending(paired, monkeypatch):
    client, device, _ = paired
    resp, _ = device.request("user", {"upn": "alice@lan"})
    request_id = resp.get_json()["id"]

    def locked(_):
        raise db.DatabaseLocked("Database is locked")

    monkeypatch.setattr(db, "get_ca", locked)
    assert client.post(f"/api/pal/requests/{request_id}/approve").status_code == 423
    assert db.get_pal_request(request_id)["status"] == "pending"


# ── Signatures ──────────────────────────────────────────────────────

def test_signature_checks(paired):
    _, device, _ = paired
    assert device.signed("GET", "/api/pal/v1/device").status_code == 200
    assert device.signed("GET", "/api/pal/v1/device",
                         sign_with=ec.generate_private_key(ec.SECP256R1())).status_code == 401
    assert device.signed("GET", "/api/pal/v1/device", timestamp=int(time.time()) - 3600).status_code == 401
    nonce = pal.b64url(secrets.token_bytes(16))
    assert device.signed("GET", "/api/pal/v1/device", nonce=nonce).status_code == 200
    assert device.signed("GET", "/api/pal/v1/device", nonce=nonce).status_code == 401  # replay


def test_signature_covers_body(paired):
    _, device, _ = paired
    body = json.dumps({"use_case": "web-server", "names": {"dns": ["pc01.lan"]},
                       "csr": csr_pem(ec.generate_private_key(ec.SECP256R1()))}).encode()
    timestamp, nonce = str(int(time.time())), pal.b64url(secrets.token_bytes(16))
    signature = device.device_key.sign(
        pal.request_signing_string("POST", "/api/pal/v1/requests", timestamp, nonce, body),
        ec.ECDSA(hashes.SHA256()))
    tampered = body.replace(b"pc01.lan", b"pc02.lan")
    resp = device.client.post("/api/pal/v1/requests", data=tampered, content_type="application/json",
                              environ_base=LAN, headers={
                                  "X-Pal-Device": device.device_id, "X-Pal-Time": timestamp, "X-Pal-Nonce": nonce,
                                  "X-Pal-Signature": pal.b64url(signature)})
    assert resp.status_code == 401


# ── Revocation and status ───────────────────────────────────────────

def test_revoke_device_stops_requests_and_revokes_certs(paired):
    client, device, _ = paired
    issued, _ = device.request("web-server", {"dns": ["pc01.lan"]})
    pending, _ = device.request("user", {"upn": "alice@lan"})
    resp = client.post(f"/api/pal/devices/{device.device_id}/revoke", json={})
    assert resp.get_json() == {"ok": True, "revoked_certs": 1}
    assert db.get_cert_summary(issued.get_json()["cert_id"])["revoked"] == 1
    assert db.get_pal_request(pending.get_json()["id"])["status"] == "denied"
    resp = device.signed("GET", "/api/pal/v1/device")
    assert resp.status_code == 403 and resp.get_json()["error"].startswith("Disconnected.")


def test_status_lookup(paired):
    client, device, ca_id = paired
    good = device.request("web-server", {"dns": ["pc01.lan"]})[0].get_json()
    bad = device.request("web-server", {"dns": ["pc02.lan"]})[0].get_json()
    client.post(f"/api/certs/{bad['cert_id']}/revoke")
    manual = client.post(f"/api/ca/{ca_id}/certs", json={"common_name": "nas.lan"}).get_json()
    other_ca = _make_ca(client, name="Other Root", domain="other")
    foreign = client.post(f"/api/ca/{other_ca}/certs", json={"common_name": "x.other"}).get_json()
    root_serial = db.get_ca(ca_id)["serial"]

    def windows_style(serial: str) -> str:  # uppercase, zero-padded, no 0x
        hexpart = serial[2:].upper()
        return hexpart.rjust(len(hexpart) + len(hexpart) % 2, "0")

    serials = [windows_style(good["serial"]), bad["serial"], manual["serial"], foreign["serial"],
               root_serial, "zz", "DEADBEEF"]
    status = device.signed("POST", "/api/pal/v1/status", {"serials": serials}).get_json()["status"]
    assert status == {
        serials[0]: "valid", bad["serial"]: "revoked", manual["serial"]: "valid",
        foreign["serial"]: "unknown", root_serial: "valid", "zz": "unknown", "DEADBEEF": "unknown",
    }


def test_status_limits(paired):
    _, device, _ = paired
    resp = device.signed("POST", "/api/pal/v1/status", {"serials": ["01"] * (pal.MAX_SERIALS + 1)})
    assert resp.status_code == 400


# ── Pure helpers ────────────────────────────────────────────────────

@pytest.mark.parametrize("name, allowed", [
    ("pc01.lan", True), ("a.b.lan", True), ("lan", False), ("pc01.lan.evil.com", False),
    ("evillan", False), ("10.0.0.9", True), ("10.0.1.9", False), ("*.lan", False), ("*.x.lan", False),
])
def test_dns_name_allowed(name, allowed):
    assert pal.dns_name_allowed(name, ["*.lan", "10.0.0.0/24"]) is allowed


@pytest.mark.parametrize("address, private", [
    ("10.1.2.3", True), ("172.16.0.1", True), ("172.32.0.1", False), ("192.168.0.1", True),
    ("127.0.0.1", True), ("169.254.1.1", True), ("8.8.8.8", False), ("100.64.0.1", True),
    ("100.127.255.254", True), ("100.63.255.255", False), ("100.128.0.1", False), ("::ffff:100.100.1.1", True),
    ("fd00::1", True), ("fe80::1%eth0", True), ("2001:db8::1", False), ("::ffff:10.0.0.1", True),
    ("::ffff:8.8.8.8", False), ("", False), ("nonsense", False), (None, False),
])
def test_is_private_address(address, private):
    assert pal.is_private_address(address) is private


@pytest.mark.parametrize("raw, normalized", [
    ("0x1a2b", "0x1a2b"), ("1A2B", "0x1a2b"), ("00:1a:2b", "0x1a2b"), ("001A2B", "0x1a2b"),
    ("", None), ("xyz", None), ("1" * 65, None), (12, None),
])
def test_normalize_serial(raw, normalized):
    assert pal.normalize_serial(raw) == normalized


def test_oversized_device_bodies_refused(paired):
    client, device, _ = paired
    big = {"serials": ["01"], "pad": "x" * (pal_routes.MAX_REQUEST_BODY + 1)}
    assert device.signed("POST", "/api/pal/v1/status", big).status_code == 413
    resp = client.post("/api/pal/v1/enroll", data=b"{" + b" " * pal_routes.MAX_ENROLL_BODY + b"}",
                       content_type="application/json", environ_base=LAN)
    assert resp.status_code == 413


def test_computer_cert_uses_fqdn_from_pairing(paired):
    _, device, _ = paired
    # whatever the PC asks for, a "This computer" cert is issued to the name recorded at pairing
    resp, _ = device.request("computer", {"dns": ["nas.lan", "10.0.0.9"]})
    assert resp.status_code == 201
    cert = x509.load_pem_x509_certificate(resp.get_json()["cert"].encode())
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "pc01.lan"
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["pc01.lan"] and not san.get_values_for_type(x509.IPAddress)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert set(eku) == {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH}
    assert device.signed("GET", "/api/pal/v1/device").get_json()["fqdn"] == "pc01.lan"


@pytest.mark.parametrize("fqdn, message", [
    ("pc01.example.com", "Wrong domain. This PC is pc01.example.com, but this pairing code only allows *.lan, 10.0.0.0/24. "
                         "Ask your admin for a new code that allows *.example.com"),
    ("", "No DNS suffix."),
    ("bad name.lan", "No DNS suffix."),
])
def test_enroll_requires_fqdn_in_policy(admin_client, fqdn, message):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id).get_json()["pairing_code"])
    resp = device.enroll(device.enroll_body(fqdn=fqdn))
    assert resp.status_code == 400 and message in resp.get_json()["error"]
    # the code is still unused: the PC can fix its name and pair again
    assert admin_client.get("/api/pal/codes").get_json()[0]["state"] == "unused"


def test_fqdn_not_checked_when_no_machine_certs(admin_client):
    ca_id = _make_ca(admin_client)
    code = _code(admin_client, ca_id, use_cases={"user": "auto"}, dns=[]).get_json()["pairing_code"]
    device = FakePal(admin_client, code)
    assert device.enroll(device.enroll_body(fqdn="laptop.home.example")).status_code == 201


# ── Download ────────────────────────────────────────────────────────

def _write_exe(folder, data: bytes):
    """Write the EXE, then make it and its folder read-only, as the Docker image does."""
    folder.mkdir(exist_ok=True)
    folder.chmod(0o755)
    exe = folder / "CertGeneratorPal.exe"
    if exe.exists():
        exe.chmod(0o644)
    exe.write_bytes(data)
    exe.chmod(0o444)
    folder.chmod(0o555)
    return exe


@pytest.fixture
def fake_exe(tmp_path, monkeypatch):
    if sys.platform == "win32":
        pytest.skip("serving the EXE relies on POSIX read-only permissions (the Docker image)")
    exe = _write_exe(tmp_path / "pal", b"MZ" + b"\0" * 1000)
    monkeypatch.setattr(pal_routes, "PAL_EXE", exe)
    yield exe
    exe.parent.chmod(0o755)


def test_download_is_public_on_lan_without_cookies(client, fake_exe):
    client.post("/setup", data={"username": "a", "password": "correct-horse-battery", "confirm": "correct-horse-battery"})
    anonymous = server.app.test_client()
    resp = anonymous.get("/pal/CertGeneratorPal.exe", environ_base=LAN)
    assert resp.status_code == 200 and resp.data.startswith(b"MZ")
    assert "attachment" in resp.headers["Content-Disposition"]
    assert resp.headers["X-Checksum-SHA256"] == hashlib.sha256(fake_exe.read_bytes()).hexdigest()
    assert "Set-Cookie" not in resp.headers


def test_download_is_lan_only(client, fake_exe):
    assert client.get("/pal/CertGeneratorPal.exe", environ_base={"REMOTE_ADDR": "8.8.8.8"}).status_code == 404


def test_download_missing_exe(client, tmp_path, monkeypatch):
    monkeypatch.setattr(pal_routes, "PAL_EXE", tmp_path / "nope.exe")
    assert client.get("/pal/CertGeneratorPal.exe", environ_base=LAN).status_code == 404


def test_download_info_for_admin(admin_client, fake_exe):
    info = admin_client.get("/api/pal/download").get_json()
    assert info == {"available": True, "path": "/pal/CertGeneratorPal.exe", "size": 1002,
                    "sha256": hashlib.sha256(fake_exe.read_bytes()).hexdigest()}
    _write_exe(fake_exe.parent, b"MZ changed")  # a rebuilt EXE gets a fresh checksum
    assert admin_client.get("/api/pal/download").get_json()["sha256"] == hashlib.sha256(b"MZ changed").hexdigest()


def test_download_info_requires_login(client, fake_exe):
    client.post("/setup", data={"username": "a", "password": "correct-horse-battery", "confirm": "correct-horse-battery"})
    assert server.app.test_client().get("/api/pal/download").status_code == 401


def test_pc_names_itself(admin_client):
    ca_id = _make_ca(admin_client)
    data = _code(admin_client, ca_id, label="").get_json()  # no name typed by the admin
    device = FakePal(admin_client, data["pairing_code"])
    resp = device.enroll(device.enroll_body(hostname="nscriven", fqdn="nscriven.lan"))
    assert resp.get_json()["label"] == "nscriven" and resp.get_json()["fqdn"] == "nscriven.lan"
    assert admin_client.get("/api/pal/devices").get_json()[0]["label"] == "nscriven"
    code = admin_client.get("/api/pal/codes").get_json()[0]
    assert code["label"] == "" and code["device_name"] == "nscriven" and code["device_fqdn"] == "nscriven.lan"


def test_no_second_live_certificate(paired):
    client, device, _ = paired
    first, _ = device.request("computer", {})
    assert first.status_code == 201
    again, _ = device.request("computer", {})
    assert again.status_code == 409 and again.get_json()["error"].startswith("Already issued.")
    # another name is another certificate
    assert device.request("web-server", {"dns": ["pc01.lan", "www.lan"]})[0].status_code == 201
    assert device.request("web-server", {"dns": ["intranet.lan"]})[0].status_code == 201
    # once the admin revokes the lost one, the PC may ask again
    client.post(f"/api/certs/{first.get_json()['cert_id']}/revoke")
    assert device.request("computer", {})[0].status_code == 201


def test_no_duplicate_pending_request(paired):
    _, device, _ = paired
    assert device.request("user", {"upn": "alice@lan"})[0].status_code == 202
    resp, _ = device.request("user", {"upn": "alice@lan"})
    assert resp.status_code == 409 and resp.get_json()["error"].startswith("Already requested.")
    assert device.request("user", {"upn": "bob@lan"})[0].status_code == 202


def test_renewal_window_and_single_renewal(paired):
    _, device, _ = paired
    issued = device.request("computer", {})[0].get_json()
    info = device.signed("GET", "/api/pal/v1/device").get_json()
    assert info["certs"][0]["renew_from"] > info["certs"][0]["not_before"][:19]
    resp, _ = device.request("computer", {}, renew_of=issued["cert_id"])
    assert resp.status_code == 409 and "Renewal opens" in resp.get_json()["error"]
    _near_expiry(issued["cert_id"])
    assert device.request("computer", {}, renew_of=issued["cert_id"])[0].status_code == 201
    resp, _ = device.request("computer", {}, renew_of=issued["cert_id"])
    assert resp.status_code == 409 and resp.get_json()["error"].startswith("Already renewed.")


def test_renew_window_rule():
    from datetime import datetime, timedelta, timezone
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert pal.renew_opens(start, start + timedelta(days=365)) == start + timedelta(days=335)
    assert pal.renew_opens(start, start + timedelta(days=30)) == start + timedelta(days=20)


@pytest.mark.skipif(getattr(os, "geteuid", lambda: -1)() == 0, reason="root can write anything")
def test_writable_exe_is_not_served(client, fake_exe):
    fake_exe.parent.chmod(0o755)  # the folder is writable: someone could swap the EXE
    assert client.get("/pal/CertGeneratorPal.exe", environ_base=LAN).status_code == 404
    fake_exe.parent.chmod(0o555)
    fake_exe.chmod(0o644)  # the file itself is writable
    assert client.get("/pal/CertGeneratorPal.exe", environ_base=LAN).status_code == 404
    fake_exe.chmod(0o444)
    assert client.get("/pal/CertGeneratorPal.exe", environ_base=LAN).status_code == 200


# ── Endpoint-hosted CRL ─────────────────────────────────────────────────

def test_self_hosted_crls(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id, crl_dp="placeholder").get_json()["pairing_code"])
    device.enroll()
    issued = device.request("computer", {})[0].get_json()
    cert = x509.load_pem_x509_certificate(issued["cert"].encode())
    dp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0].full_name[0].value
    data = device.signed("GET", "/api/pal/v1/crls").get_json()["crls"]
    assert [c["url"] for c in data] == [dp] and data[0]["host"] == "pki.lan" and data[0]["file"].endswith(".crl")
    assert device.signed("GET", "/api/pal/v1/device").get_json()["crl_dp"] == "placeholder"
    admin_client.post(f"/api/certs/{issued['cert_id']}/revoke")
    crl = x509.load_der_x509_crl(base64.b64decode(device.signed("GET", "/api/pal/v1/crls").get_json()["crls"][0]["crl"]))
    assert crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None


def test_a_pc_can_have_the_crl_published_now(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id, crl_dp="placeholder").get_json()["pairing_code"])
    device.enroll()
    resp = device.signed("POST", "/api/pal/v1/crl/publish", {})
    assert resp.status_code == 409 and "Nothing to publish" in resp.get_json()["error"]  # nothing names this server yet

    served = FakePal(admin_client, _code(admin_client, ca_id, crl_dp="server").get_json()["pairing_code"])
    assert served.enroll(served.enroll_body(hostname="pc02", fqdn="pc02.lan")).status_code == 201
    issued = served.request("computer", {})[0].get_json()
    before = x509.load_der_x509_crl(admin_client.get(f"/crl/{ca_id}.crl").data)
    admin_client.post(f"/api/certs/{issued['cert_id']}/revoke")
    reply = served.signed("POST", "/api/pal/v1/crl/publish", {})
    assert reply.status_code == 200 and reply.get_json()["revoked"] == 1 and reply.get_json()["cloudflare"] is None
    after = x509.load_der_x509_crl(admin_client.get(f"/crl/{ca_id}.crl").data)
    assert len(before) == 0 and len(after) == 1 and reply.get_json()["next_update"]
    assert any("asked for the CRL to be published now" in e["message"] for e in admin_client.get("/api/activity").get_json())
    # Each publish signs a CRL and may call Cloudflare: a PC can't loop on it.
    assert served.signed("POST", "/api/pal/v1/crl/publish", {}).status_code == 200
    again = served.signed("POST", "/api/pal/v1/crl/publish", {})
    assert again.status_code == 429 and "Just published" in again.get_json()["error"]


def test_self_hosted_crls_need_unlocked_server(paired, monkeypatch):
    _, device, _ = paired

    def locked(_):
        raise db.DatabaseLocked("Database is locked")

    monkeypatch.setattr(db, "get_ca", locked)
    assert device.signed("GET", "/api/pal/v1/crls").status_code == 423


def test_pal_listener_script_matches_server_copy():
    """The Pal installs the same listener the v2.7 install bundles use; one copy of the truth."""
    from pathlib import Path

    from app.crl_local_server import SERVE_PS1
    pal_copy = Path(__file__).resolve().parents[1] / "pal" / "src" / "CertGeneratorPal" / "serve-crl.ps1"
    assert pal_copy.read_text(encoding="utf-8") == SERVE_PS1


def test_self_hosted_covers_the_whole_chain(admin_client):
    root_id = _make_ca(admin_client)
    resp = admin_client.post(f"/api/ca/{root_id}/intermediate", json={"domain": "lan", "name": "Issuing CA", "algorithm": "ecdsa-p256"})
    issuing_id = resp.get_json()["id"]
    device = FakePal(admin_client, _code(admin_client, issuing_id, crl_dp="placeholder").get_json()["pairing_code"])
    assert device.enroll().status_code == 201
    info = device.signed("GET", "/api/pal/v1/device").get_json()
    assert [a["ca_name"] for a in info["self_hosted"]] == ["Issuing CA", "Home Root CA"]
    assert len(info["chain"]) == 2
    crls = device.signed("GET", "/api/pal/v1/crls").get_json()["crls"]
    assert [c["ca_name"] for c in crls] == ["Issuing CA", "Home Root CA"]


def test_devices_page_reflects_what_the_pc_holds(paired):
    client, device, _ = paired
    computer = device.request("computer", {})[0].get_json()
    web = device.request("web-server", {"dns": ["pc01.lan", "www.lan"]})[0].get_json()
    states = lambda: {c["use_case"]: c["state"] for c in client.get("/api/pal/devices").get_json()[0]["certs"]}
    assert states() == {"computer": "unchecked", "web-server": "unchecked"}
    device.signed("POST", "/api/pal/v1/status", {"serials": [computer["serial"], web["serial"]]})
    assert states() == {"computer": "installed", "web-server": "installed"}
    device.signed("POST", "/api/pal/v1/status", {"serials": [computer["serial"]]})  # the PC deleted the web cert
    assert states() == {"computer": "installed", "web-server": "removed"}
    client.post(f"/api/certs/{computer['cert_id']}/revoke")
    assert states()["computer"] == "revoked"


def test_removed_copy_can_be_replaced_and_is_revoked(paired):
    client, device, _ = paired
    first = device.request("computer", {})[0].get_json()
    device.signed("POST", "/api/pal/v1/status", {"serials": [first["serial"]]})  # on the PC
    assert device.request("computer", {})[0].status_code == 409
    device.signed("POST", "/api/pal/v1/status", {"serials": []})  # the PC removed it (e.g. switched profile)
    second = device.request("computer", {})[0]
    assert second.status_code == 201
    assert db.get_cert_summary(first["cert_id"])["revoked"] == 1  # superseded: only one live copy
    assert db.get_cert_summary(second.get_json()["cert_id"])["revoked"] == 0


def test_enroll_reports_revocation_setting(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id, crl_dp="placeholder").get_json()["pairing_code"])
    assert device.enroll().get_json()["crl_dp"] == "placeholder"


def test_code_can_allow_several_revocation_types(admin_client):
    ca_id = _make_ca(admin_client)
    code = _code(admin_client, ca_id, crl_dps=["placeholder", "server"]).get_json()["pairing_code"]
    device = FakePal(admin_client, code)
    info = device.enroll().get_json()
    assert info["crl_dps"] == ["placeholder", "server"] and info["crl_dp"] == "placeholder"  # first ticked = default

    def dp(resp):
        cert = x509.load_pem_x509_certificate(resp.get_json()["cert"].encode())
        return cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0].full_name[0].value

    assert dp(device.request("computer", {}, crl_dp="server")[0]).startswith("http://10.0.0.252:5000/crl/")
    assert dp(device.request("web-server", {"dns": ["pc01.lan", "www.lan"]})[0]).startswith("http://pki.lan/crl/")
    resp, _ = device.request("web-server", {"dns": ["web.lan"]}, crl_dp="cloudflare")
    assert resp.status_code == 403 and resp.get_json()["error"].startswith("Revocation type not allowed.")


def test_approval_keeps_the_requested_revocation_type(admin_client):
    ca_id = _make_ca(admin_client)
    code = _code(admin_client, ca_id, crl_dps=["server", "placeholder"]).get_json()["pairing_code"]
    device = FakePal(admin_client, code)
    device.enroll()
    request_id = device.request("user", {"upn": "alice@lan"}, crl_dp="placeholder")[0].get_json()["id"]
    assert admin_client.get("/api/pal/requests?status=pending").get_json()[0]["crl_dp"] == "placeholder"
    admin_client.post(f"/api/pal/requests/{request_id}/approve")
    view = device.signed("GET", f"/api/pal/v1/requests/{request_id}").get_json()
    cert = x509.load_pem_x509_certificate(view["cert"].encode())
    assert cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0].full_name[0].value.startswith("http://pki.lan/")


def test_old_single_type_policies_still_load():
    policy = pal.Policy.from_json('{"use_cases":{},"dns":[],"users":[],"max_days":30,"crl_dp":"server","crl_base_url":null}')
    assert policy.crl_dps == ["server"] and policy.crl_dp == "server"


def test_delete_device_disconnects_and_forgets_it(paired):
    client, device, _ = paired
    issued, _ = device.request("web-server", {"dns": ["pc01.lan"]})
    resp = client.delete(f"/api/pal/devices/{device.device_id}")
    assert resp.get_json() == {"ok": True, "revoked_certs": 1}
    assert db.get_pal_device(device.device_id) is None
    assert all(d["id"] != device.device_id for d in client.get("/api/pal/devices").get_json())
    assert client.get("/api/pal/codes").get_json() == []
    cert = db.get_cert_summary(issued.get_json()["cert_id"])
    assert cert["revoked"] == 1  # the certificate stays, revoked
    assert client.delete(f"/api/pal/devices/{device.device_id}").status_code == 404
    assert device.signed("GET", "/api/pal/v1/device").status_code in (401, 403)


def test_device_info_lists_a_test_address_per_revocation_type(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id, crl_dps=["server", "placeholder", "none"]).get_json()["pairing_code"])
    assert device.enroll().status_code == 201
    urls = device.signed("GET", "/api/pal/v1/device").get_json()["crl_urls"]
    assert set(urls) == {"server", "placeholder"}
    assert urls["server"].endswith(f"/crl/{ca_id}.crl")
    assert urls["placeholder"].startswith("http://pki.lan/crl/")


def test_pal_version_is_recorded_and_compared_with_the_server(paired):
    from app import __version__
    client, device, _ = paired
    info = device.signed("GET", "/api/pal/v1/device").get_json()
    assert info["server_version"] == __version__
    [row] = client.get("/api/pal/devices").get_json()
    assert row["pal_version"] is None and row["version_matches"]  # not reported yet: no warning
    device.signed("GET", "/api/pal/v1/device", agent=f"CertGeneratorPal/{__version__}")
    [row] = client.get("/api/pal/devices").get_json()
    assert row["pal_version"] == __version__ and row["version_matches"]
    device.signed("GET", "/api/pal/v1/device", agent="CertGeneratorPal/2.7.0")
    [row] = client.get("/api/pal/devices").get_json()
    assert row["pal_version"] == "2.7.0" and not row["version_matches"]
    device.signed("GET", "/api/pal/v1/device", agent="CertGeneratorPal/<script>")  # not a version: ignored
    assert client.get("/api/pal/devices").get_json()[0]["pal_version"] == "2.7.0"


def test_pal_takes_its_version_from_the_server():
    props = (Path(__file__).parents[1] / "pal" / "Directory.Build.props").read_text(encoding="utf-8")
    assert "../app/__init__.py" in props and "<Version>2" not in props


# ── Key storage (TPM) ───────────────────────────────────────────────

def test_key_storage_is_recorded_as_the_pal_reports_it(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id).get_json()["pairing_code"])
    assert device.enroll(device.enroll_body(key_storage="tpm")).status_code == 201
    in_tpm = device.request("computer", {}, key_storage="tpm")[0].get_json()
    waiting = device.request("user", {"upn": "alice@lan"}, key_storage="software")[0].get_json()
    old_pal = device.request("web-server", {"dns": ["pc01.lan", "www.lan"]}, key_storage="in a drawer")[0].get_json()
    admin_client.post(f"/api/pal/requests/{waiting['id']}/approve")  # the storage survives the wait for approval

    listed = admin_client.get("/api/pal/devices").get_json()[0]
    assert listed["key_storage"] == "tpm"
    assert {c["use_case"]: c["key_storage"] for c in listed["certs"]} == {
        "computer": "tpm", "user": "software", "web-server": None}
    assert {c["template"]: c["pal_key_storage"] for c in admin_client.get(f"/api/ca/{ca_id}/certs").get_json()} == {
        "computer": "tpm", "user": "software", "web-server": None}

    # A later store audit fills in what wasn't reported at request time, for this PC's own certificates only.
    device.signed("POST", "/api/pal/v1/status", {
        "serials": [old_pal["serial"]], "device_key_storage": "software",
        "keys": {old_pal["serial"].upper(): "tpm", in_tpm["serial"]: "nonsense", "DEADBEEF": "tpm"}})
    listed = admin_client.get("/api/pal/devices").get_json()[0]
    assert listed["key_storage"] == "software"
    assert {c["use_case"]: c["key_storage"] for c in listed["certs"]} == {
        "computer": "tpm", "user": "software", "web-server": "tpm"}


def test_a_pal_that_reports_no_key_storage_still_works(paired):
    client, device, _ = paired
    cert = device.request("computer", {})[0].get_json()
    device.signed("POST", "/api/pal/v1/status", {"serials": [cert["serial"]]})
    listed = client.get("/api/pal/devices").get_json()[0]
    assert listed["key_storage"] is None and listed["certs"][0]["key_storage"] is None


# ── Editing a connected PC, and the activity log ────────────────────

def test_a_connected_pcs_permissions_can_be_edited(paired):
    client, device, _ = paired
    assert device.request("code-signing", {"cn": "Scripts"})[0].status_code == 403  # off in the pairing code
    body = {"use_cases": {"web-server": "auto", "computer": "auto", "user": "approve", "code-signing": "auto"},
            "dns": ["*.lan"], "users": ["*@lan"], "max_days": 30, "crl_dps": ["none"]}
    resp = client.put(f"/api/pal/devices/{device.device_id}/policy", json=body)
    assert resp.status_code == 200, resp.get_json()
    assert device.signed("GET", "/api/pal/v1/device").get_json()["policy"]["use_cases"]["code-signing"] == "auto"
    assert device.request("code-signing", {"cn": "Scripts"})[0].status_code == 201

    # The PC's own name must still fit, and a disconnected PC can't be edited.
    resp = client.put(f"/api/pal/devices/{device.device_id}/policy", json={**body, "dns": ["*.example.com"]})
    assert resp.status_code == 400 and "Wrong domain" in resp.get_json()["error"]
    client.post(f"/api/pal/devices/{device.device_id}/revoke", json={})
    assert client.put(f"/api/pal/devices/{device.device_id}/policy", json=body).status_code == 404


def test_editing_keeps_the_remote_switch_as_it_was(paired):
    client, device, _ = paired
    body = {"use_cases": {"computer": "auto"}, "dns": ["*.lan"], "users": [], "max_days": 90, "crl_dps": ["none"],
            "allow_remote": True}
    assert client.put(f"/api/pal/devices/{device.device_id}/policy", json=body).status_code == 200
    assert client.get("/api/pal/devices").get_json()[0]["policy"]["allow_remote"] is False


def test_activity_log_records_who_did_what(paired):
    client, device, ca_id = paired
    cert = device.request("computer", {}, key_storage="tpm")[0].get_json()
    client.post(f"/api/certs/{cert['cert_id']}/revoke")
    entries = client.get("/api/activity").get_json()
    messages = [e["message"] for e in entries]
    assert any(m.startswith("Certificate issued to PC pc01: computer for pc01.lan (key: tpm)") for m in messages)
    assert any(m.startswith("Certificate revoked: pc01.lan") for m in messages)
    assert any(m.startswith("PC connected: pc01") for m in messages)
    assert not any(" /api/" in m for m in messages)  # no access lines
    by_message = {e["message"]: e for e in entries}
    revoked = next(e for m, e in by_message.items() if m.startswith("Certificate revoked"))
    assert revoked["actor"] == "admin" and revoked["at"].endswith("Z")
    issued = next(e for m, e in by_message.items() if m.startswith("Certificate issued to PC"))
    assert issued["actor"] == "a PC"
    assert entries == sorted(entries, key=lambda e: e["id"], reverse=True)


# ── Remove in the Pal revokes ───────────────────────────────────────

def test_a_pc_revokes_the_certificates_it_removes_and_only_its_own(paired):
    client, device, ca_id = paired
    mine = device.request("computer", {})[0].get_json()
    kept = device.request("web-server", {"dns": ["pc01.lan", "www.lan"]})[0].get_json()
    manual = client.post(f"/api/ca/{ca_id}/certs", json={"common_name": "manual.lan"}).get_json()
    other = FakePal(client, _code(client, ca_id).get_json()["pairing_code"])
    assert other.enroll(other.enroll_body(hostname="pc02", fqdn="pc02.lan")).status_code == 201
    theirs = other.request("computer", {})[0].get_json()

    resp = device.signed("POST", "/api/pal/v1/revoke",
                         {"serials": [mine["serial"].upper(), manual["serial"], theirs["serial"], "zz"]})
    assert resp.status_code == 200 and resp.get_json()["revoked"] == [mine["serial"]]
    revoked = {c["serial"]: c["revoked"] for c in client.get(f"/api/ca/{ca_id}/certs").get_json()}
    assert revoked[mine["serial"]] == 1
    assert revoked[kept["serial"]] == revoked[manual["serial"]] == revoked[theirs["serial"]] == 0
    assert any(m.startswith("PC pc01 removed its computer certificate for pc01.lan: revoked")
               for m in [e["message"] for e in client.get("/api/activity").get_json()])
    # Revoking again is harmless, and the name is free for a new request.
    assert device.signed("POST", "/api/pal/v1/revoke", {"serials": [mine["serial"]]}).get_json()["revoked"] == []
    assert device.request("computer", {})[0].status_code == 201


def test_a_certificate_with_no_crl_is_never_revoked(admin_client):
    ca_id = _make_ca(admin_client)
    device = FakePal(admin_client, _code(admin_client, ca_id, crl_dp="none").get_json()["pairing_code"])
    assert device.enroll().status_code == 201
    cert = device.request("computer", {})[0].get_json()
    listed = admin_client.get("/api/pal/devices").get_json()[0]["certs"][0]
    assert listed["revocable"] is False

    # Removed in the Pal: recorded as gone (the name is free again), not revoked.
    resp = device.signed("POST", "/api/pal/v1/revoke", {"serials": [cert["serial"]]})
    assert resp.status_code == 200 and resp.get_json()["revoked"] == []
    assert device.request("computer", {})[0].status_code == 201
    # Disconnecting the PC revokes nothing either, and the admin can't revoke by hand.
    assert admin_client.post(f"/api/pal/devices/{device.device_id}/revoke", json={}).get_json()["revoked_certs"] == 0
    certs = admin_client.get(f"/api/ca/{ca_id}/certs").get_json()
    assert len(certs) == 2 and not any(c["revoked"] for c in certs)
    assert admin_client.post(f"/api/certs/{certs[0]['id']}/revoke").status_code == 409


def test_a_crl_profile_can_be_added_to_a_connected_pc(paired):
    client, device, _ = paired
    assert device.request("computer", {}, crl_dp="none")[0].status_code == 403  # not allowed by the pairing code
    body = {"use_cases": {"computer": "auto"}, "dns": ["*.lan"], "users": [], "max_days": 90,
            "crl_dps": ["placeholder", "none"]}
    assert client.put(f"/api/pal/devices/{device.device_id}/policy", json=body).status_code == 200
    assert device.signed("GET", "/api/pal/v1/device").get_json()["crl_dps"] == ["placeholder", "none"]  # default kept first
    assert device.request("computer", {}, crl_dp="none")[0].status_code == 201


def test_a_certificate_that_disappears_from_a_pc_is_flagged_not_revoked(paired):
    client, device, ca_id = paired
    cert = device.request("computer", {})[0].get_json()
    device.signed("POST", "/api/pal/v1/status", {"serials": [cert["serial"]]})
    device.signed("POST", "/api/pal/v1/status", {"serials": []})  # deleted outside the Pal
    listed = client.get(f"/api/ca/{ca_id}/certs").get_json()[0]
    assert listed["pal_present"] == 0 and listed["revoked"] == 0
    messages = [e["message"] for e in client.get("/api/activity").get_json()]
    assert "PC pc01 no longer holds its computer certificate for pc01.lan (not revoked)" in messages
    device.signed("POST", "/api/pal/v1/status", {"serials": []})
    assert [m for m in [e["message"] for e in client.get("/api/activity").get_json()]].count(
        "PC pc01 no longer holds its computer certificate for pc01.lan (not revoked)") == 1  # said once


# ── User ("Me") certificates ────────────────────────────────────────

def _auto_user_device(client):
    ca_id = _make_ca(client)
    code = _code(client, ca_id, use_cases={"web-server": "off", "computer": "auto", "user": "auto", "code-signing": "auto"})
    device = FakePal(client, code.get_json()["pairing_code"])
    assert device.enroll().status_code == 201
    return device, ca_id


def _key_usage(pem: str) -> x509.KeyUsage:
    return x509.load_pem_x509_certificate(pem.encode()).extensions.get_extension_for_class(x509.KeyUsage).value


def test_user_certificate_carries_the_upn_and_no_invented_email(admin_client):
    device, _ = _auto_user_device(admin_client)
    resp, _ = device.request("user", {"upn": "Alice@LAN"})
    assert resp.status_code == 201, resp.get_json()
    cert = x509.load_pem_x509_certificate(resp.get_json()["cert"].encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [n.type_id.dotted_string for n in san.get_values_for_type(x509.OtherName)] == ["1.3.6.1.4.1.311.20.2.3"]
    assert san.get_values_for_type(x509.RFC822Name) == []  # a sign-in name is not a mailbox
    assert cert.subject.rfc4514_string() == "CN=alice@lan"


def test_user_certificate_takes_an_email_only_when_one_is_sent(admin_client):
    device, _ = _auto_user_device(admin_client)
    resp, _ = device.request("user", {"upn": "alice@lan", "email": "alice.smith@lan"})
    cert = x509.load_pem_x509_certificate(resp.get_json()["cert"].encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.RFC822Name) == ["alice.smith@lan"]
    assert device.request("user", {"upn": "bob@lan", "email": "bob@elsewhere.test"})[0].status_code == 400


@pytest.mark.parametrize("upn", ["alice@elsewhere.test", "alice", "", None, "a b@lan"])
def test_user_names_outside_the_policy_are_refused(admin_client, upn):
    device, _ = _auto_user_device(admin_client)
    assert device.request("user", {"upn": upn})[0].status_code == 400


def test_key_usage_fits_the_key(admin_client):
    device, _ = _auto_user_device(admin_client)
    ecdsa = _key_usage(device.request("user", {"upn": "alice@lan"})[0].get_json()["cert"])
    assert ecdsa.digital_signature and not ecdsa.key_encipherment  # an ECDSA key can't encipher keys
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with_rsa = _key_usage(device.request("user", {"upn": "bob@lan"}, key=rsa_key)[0].get_json()["cert"])
    assert with_rsa.digital_signature and with_rsa.key_encipherment


def test_the_windows_account_that_asked_is_recorded_and_shown(paired):
    client, device, ca_id = paired
    resp, _ = device.request("user", {"upn": "alice@lan"}, windows_user="PC01\\alice")
    assert resp.status_code == 202
    pending = client.get("/api/pal/requests?status=pending").get_json()
    assert pending[0]["windows_user"] == "PC01\\alice"
    assert client.post(f"/api/pal/requests/{pending[0]['id']}/approve").status_code == 200
    assert client.get(f"/api/ca/{ca_id}/certs").get_json()[0]["pal_user"] == "PC01\\alice"
    assert client.get("/api/pal/devices").get_json()[0]["certs"][0]["asked_by"] == "PC01\\alice"
    messages = [e["message"] for e in client.get("/api/activity").get_json()]
    assert any("alice@lan (Windows account: PC01\\alice): waiting for approval" in m for m in messages)


@pytest.mark.parametrize("bad", ["", "   ", "a\nb", "x" * 105, 7, None, ["PC01\\alice"]])
def test_an_implausible_windows_account_is_not_recorded(paired, bad):
    client, device, _ = paired
    assert device.request("user", {"upn": "alice@lan"}, windows_user=bad)[0].status_code == 202
    assert client.get("/api/pal/requests?status=pending").get_json()[0]["windows_user"] is None


def test_another_windows_account_cannot_report_a_user_certificate_missing(admin_client):
    """Two people share a PC. Bob's check-in can't see Alice's store, so it says nothing about her certificate."""
    device, ca_id = _auto_user_device(admin_client)
    alice = device.request("user", {"upn": "alice@lan"}, windows_user="PC01\\alice")[0].get_json()
    status = "/api/pal/v1/status"
    device.signed("POST", status, {"serials": [alice["serial"]], "windows_user": "PC01\\alice"})
    device.signed("POST", status, {"serials": [], "windows_user": "PC01\\bob"})
    device.signed("POST", status, {"serials": []})  # an older Pal, which doesn't say who it runs as
    assert db.get_cert_summary(alice["cert_id"])["pal_present"] == 1
    assert not any("no longer holds" in e["message"] for e in admin_client.get("/api/activity").get_json())
    # so a second copy for the same name is still refused, and nothing revokes hers
    assert device.request("user", {"upn": "alice@lan"}, windows_user="PC01\\bob")[0].status_code == 409
    assert db.get_cert_summary(alice["cert_id"])["revoked"] == 0


def test_the_account_that_asked_can_report_its_own_certificate_missing(admin_client):
    device, _ = _auto_user_device(admin_client)
    first = device.request("user", {"upn": "alice@lan"}, windows_user="PC01\\alice")[0].get_json()
    status = "/api/pal/v1/status"
    device.signed("POST", status, {"serials": [first["serial"]], "windows_user": "PC01\\alice"})
    device.signed("POST", status, {"serials": [], "windows_user": "pc01\\Alice"})  # Windows account names ignore case
    assert db.get_cert_summary(first["cert_id"])["pal_present"] == 0
    second = device.request("user", {"upn": "alice@lan"}, windows_user="PC01\\alice")[0]
    assert second.status_code == 201
    assert db.get_cert_summary(first["cert_id"])["revoked"] == 1  # superseded: only one live copy


def test_a_user_certificate_from_before_accounts_were_recorded_is_adopted_when_found(admin_client):
    device, _ = _auto_user_device(admin_client)
    old = device.request("code-signing", {"cn": "Alice Smith"})[0].get_json()  # no windows_user: an older Pal
    status = "/api/pal/v1/status"
    device.signed("POST", status, {"serials": [], "windows_user": "PC01\\bob"})
    assert db.get_cert_summary(old["cert_id"])["pal_present"] is None  # nobody has said whose it is
    device.signed("POST", status, {"serials": [old["serial"]], "windows_user": "PC01\\alice"})
    assert db.get_cert_summary(old["cert_id"])["pal_user"] == "PC01\\alice"
    device.signed("POST", status, {"serials": [], "windows_user": "PC01\\bob"})
    assert db.get_cert_summary(old["cert_id"])["pal_present"] == 1


def test_a_machine_certificate_is_still_reported_missing_by_any_account(admin_client):
    device, _ = _auto_user_device(admin_client)
    cert = device.request("computer", {}, windows_user="PC01\\alice")[0].get_json()
    status = "/api/pal/v1/status"
    device.signed("POST", status, {"serials": [cert["serial"]], "windows_user": "PC01\\alice"})
    device.signed("POST", status, {"serials": [], "windows_user": "PC01\\bob"})  # everyone sees the computer's store
    assert db.get_cert_summary(cert["cert_id"])["pal_present"] == 0


def test_a_note_typed_at_the_pc_reaches_the_admin(paired):
    client, device, _ = paired
    resp, _ = device.request("user", {"upn": "alice@lan"}, note="  New laptop,\n replaces  PC07 ")
    assert resp.status_code == 202
    assert client.get("/api/pal/requests?status=pending").get_json()[0]["note"] == "New laptop, replaces PC07"


@pytest.mark.parametrize("note, status", [("", 202), ("   ", 202), (None, 202), ("x" * 200, 202), ("x" * 201, 400), (7, 400), (["a"], 400)])
def test_notes_are_optional_short_and_text(paired, note, status):
    client, device, _ = paired
    assert device.request("user", {"upn": "alice@lan"}, note=note)[0].status_code == status
    if status == 202 and not (note or "").strip():
        assert client.get("/api/pal/requests?status=pending").get_json()[0]["note"] is None


# ── Binds: putting an installed certificate to work ─────────────────

def _bind_device(client, **binds):
    ca_id = _make_ca(client)
    code = _code(client, ca_id, binds=binds) if binds else _code(client, ca_id)
    device = FakePal(client, code.get_json()["pairing_code"])
    assert device.enroll().status_code == 201
    return device, ca_id


def _ask_bind(device, serial, *targets, **extra):
    return device.signed("POST", "/api/pal/v1/binds",
                         {"serial": serial, "binds": [{"target": t, "detail": f"{t} detail"} for t in targets], **extra})


def test_a_pairing_from_before_bind_switches_may_bind_everything():
    policy = pal.Policy.from_json('{"use_cases":{"computer":"auto"},"dns":["*.lan"],"users":[],"max_days":30,'
                                  '"crl_dps":["none"],"crl_base_url":null}')
    assert policy.binds == dict.fromkeys(pal.BIND_TARGETS, "auto")
    assert policy.public()["binds"]["rdp"] == "auto"


def test_bind_switches_are_validated_and_told_to_the_pc(admin_client):
    ca_id = _make_ca(admin_client)
    assert _code(admin_client, ca_id, binds={"rdp": "sometimes"}).status_code == 400
    assert _code(admin_client, ca_id, binds="all").status_code == 400
    device, _ = _bind_device(admin_client, rdp="approve", iis="off")
    binds = device.signed("GET", "/api/pal/v1/device").get_json()["policy"]["binds"]
    assert binds == {"rdp": "approve", "winrm": "auto", "iis": "off", "rd-gateway": "auto", "rd-broker": "auto"}


def test_an_allowed_bind_is_allowed_at_once(admin_client):
    device, _ = _bind_device(admin_client)
    cert = device.request("computer", {})[0].get_json()
    resp = _ask_bind(device, cert["serial"], "rdp", "winrm")
    assert resp.status_code == 201
    assert [(b["target"], b["status"]) for b in resp.get_json()["binds"]] == [("rdp", "approved"), ("winrm", "approved")]
    assert admin_client.get("/api/pal/binds?status=pending").get_json() == []


def test_a_bind_that_needs_approval_waits_for_the_admin(admin_client):
    device, _ = _bind_device(admin_client, rdp="approve")
    cert = device.request("computer", {})[0].get_json()
    resp = _ask_bind(device, cert["serial"], "rdp", windows_user="PC01\\alice", note="for the helpdesk")
    assert resp.status_code == 202
    bind_id = resp.get_json()["binds"][0]["id"]
    assert _ask_bind(device, cert["serial"], "rdp").get_json()["binds"][0]["id"] == bind_id  # not asked twice
    waiting = admin_client.get("/api/pal/binds?status=pending").get_json()
    assert [(w["id"], w["target_label"], w["cert_name"], w["windows_user"], w["note"], w["detail"]) for w in waiting] == [
        (bind_id, "Remote Desktop", "pc01.lan", "PC01\\alice", "for the helpdesk", "rdp detail")]
    assert admin_client.get("/api/pal/devices").get_json()[0]["pending"] == 1
    assert device.signed("GET", f"/api/pal/v1/binds/{bind_id}").get_json()["status"] == "pending"
    assert admin_client.post(f"/api/pal/binds/{bind_id}/approve").status_code == 200
    assert admin_client.post(f"/api/pal/binds/{bind_id}/approve").status_code == 404  # decided once
    assert device.signed("GET", f"/api/pal/v1/binds/{bind_id}").get_json()["status"] == "approved"


def test_a_denied_bind_says_why(admin_client):
    device, _ = _bind_device(admin_client, winrm="approve")
    cert = device.request("computer", {})[0].get_json()
    bind_id = _ask_bind(device, cert["serial"], "winrm").get_json()["binds"][0]["id"]
    assert admin_client.post(f"/api/pal/binds/{bind_id}/deny", json={"reason": "not on servers"}).status_code == 200
    view = device.signed("GET", f"/api/pal/v1/binds/{bind_id}").get_json()
    assert view["status"] == "denied" and view["reason"] == "not on servers"


def test_a_bind_the_admin_turned_off_is_refused_whole(admin_client):
    device, _ = _bind_device(admin_client, iis="off")
    cert = device.request("computer", {})[0].get_json()
    resp = _ask_bind(device, cert["serial"], "rdp", "iis")
    assert resp.status_code == 403 and "IIS site" in resp.get_json()["error"]
    assert admin_client.get("/api/pal/binds").get_json() == []  # nothing half-recorded


def test_only_this_cas_live_tls_certificates_can_be_bound(admin_client):
    device, _ = _bind_device(admin_client)
    assert _ask_bind(device, "00ff", "rdp").status_code == 404
    client_cert = device.request("user", {"upn": "alice@lan"})[0]
    assert client_cert.status_code == 202  # needs approval: nothing to bind yet
    cert = device.request("computer", {})[0].get_json()
    assert _ask_bind(device, cert["serial"]).status_code == 400  # no roles
    assert _ask_bind(device, cert["serial"], "telnet").status_code == 400
    db.revoke_cert(cert["cert_id"])
    assert _ask_bind(device, cert["serial"], "rdp").status_code == 409


def test_another_pcs_bind_cannot_be_read(admin_client):
    device, ca_id = _bind_device(admin_client, rdp="approve")
    cert = device.request("computer", {})[0].get_json()
    bind_id = _ask_bind(device, cert["serial"], "rdp").get_json()["binds"][0]["id"]
    other = FakePal(admin_client, _code(admin_client, ca_id, label="pc02").get_json()["pairing_code"])
    assert other.enroll(other.enroll_body(hostname="pc02", fqdn="pc02.lan")).status_code == 201
    assert other.signed("GET", f"/api/pal/v1/binds/{bind_id}").status_code == 404


def test_disconnecting_a_pc_denies_its_waiting_binds(admin_client):
    device, _ = _bind_device(admin_client, rdp="approve")
    cert = device.request("computer", {})[0].get_json()
    bind_id = _ask_bind(device, cert["serial"], "rdp").get_json()["binds"][0]["id"]
    assert admin_client.post(f"/api/pal/devices/{device.device_id}/revoke", json={}).status_code == 200
    assert db.get_pal_bind(bind_id)["status"] == "denied"
    assert admin_client.post(f"/api/pal/binds/{bind_id}/approve").status_code == 409  # the PC is disconnected


def test_what_uses_a_certificate_is_reported_and_shown(admin_client):
    device, ca_id = _bind_device(admin_client)
    cert = device.request("computer", {})[0].get_json()
    status = "/api/pal/v1/status"
    device.signed("POST", status, {"serials": [cert["serial"]], "binds": {cert["serial"]: ["Remote Desktop", "WinRM"]}})
    assert admin_client.get("/api/pal/devices").get_json()[0]["certs"][0]["used_for"] == ["Remote Desktop", "WinRM"]
    assert json.loads(admin_client.get(f"/api/ca/{ca_id}/certs").get_json()[0]["pal_binds"]) == ["Remote Desktop", "WinRM"]
    device.signed("POST", status, {"serials": [cert["serial"]]})  # an older Pal says nothing: nothing changes
    assert admin_client.get("/api/pal/devices").get_json()[0]["certs"][0]["used_for"] == ["Remote Desktop", "WinRM"]
    device.signed("POST", status, {"serials": [cert["serial"]], "binds": {}})  # unbound
    assert admin_client.get("/api/pal/devices").get_json()[0]["certs"][0]["used_for"] == []


def test_a_web_server_request_the_computer_certificate_covers_is_pointed_to_bind(admin_client):
    device, _ = _bind_device(admin_client)
    assert device.request("web-server", {"dns": ["pc01.lan"]})[0].status_code == 201  # no This computer certificate yet
    device2, _ = _bind_device(admin_client)
    computer = device2.request("computer", {})[0].get_json()
    resp = device2.request("web-server", {"dns": ["pc01.lan"]})[0]
    assert resp.status_code == 409 and resp.get_json()["error"].startswith("Already covered.")
    assert device2.request("web-server", {"dns": ["pc01.lan", "www.lan"]})[0].status_code == 201  # other names: its own certificate
    # once the PC reports the This computer certificate gone, the name is free again
    device2.signed("POST", "/api/pal/v1/status", {"serials": [computer["serial"]]})
    device2.signed("POST", "/api/pal/v1/status", {"serials": []})
    assert device2.request("web-server", {"dns": ["pc01.lan"]})[0].status_code == 201


def test_binding_again_keeps_one_row_per_certificate_and_role(admin_client):
    device, _ = _bind_device(admin_client)
    cert = device.request("computer", {})[0].get_json()
    for _ in range(5):
        assert _ask_bind(device, cert["serial"], "rdp", "winrm").status_code == 201
    assert sorted(b["target"] for b in admin_client.get("/api/pal/binds").get_json()) == ["rdp", "winrm"]
