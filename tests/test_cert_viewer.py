"""The certificate viewer's details endpoint."""
from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding



def _issue(client, **fields) -> tuple[int, int]:
    ca_id = client.post("/api/ca", json={"domain": "viewer.test", "algorithm": "ecdsa-p256"}).get_json()["id"]
    resp = client.post(f"/api/ca/{ca_id}/certs", json={"algorithm": "ecdsa-p256", **fields})
    assert resp.status_code == 201
    return ca_id, resp.get_json()["id"]


def _ext(details, name):
    return next(e for e in details["extensions"] if e["name"] == name)


def test_details_describe_the_certificate(admin_client):
    ca_id, cert_id = _issue(admin_client, common_name="www.viewer.test",
                            san_domains="www.viewer.test,10.0.0.5", include_crl_dp=True)
    resp = admin_client.get(f"/api/certs/{cert_id}/details")
    assert resp.status_code == 200
    d = resp.get_json()

    assert d["ca_id"] == ca_id and d["template"] == "web-server" and not d["revoked"]
    assert d["subject"] == [{"name": "Common name", "value": "www.viewer.test"}]
    assert d["issuer"][0]["name"] == "Common name"
    assert d["self_signed"] is False
    assert d["version"] == 3
    assert d["public_key"].startswith("ECDSA secp256r1")
    assert _ext(d, "Subject Alternative Name")["values"] == ["DNS: www.viewer.test", "IP: 10.0.0.5"]
    assert _ext(d, "Extended Key Usage")["values"] == ["Server Authentication"]
    assert _ext(d, "Key Usage")["critical"] is True
    assert set(_ext(d, "Key Usage")["values"]) == {"Digital Signature", "Key Encipherment"}
    assert _ext(d, "Basic Constraints")["values"] == ["CA: no"]
    assert _ext(d, "CRL Distribution Points")["values"][0].startswith("URI: http://pki.viewer.test/crl/")

    cert = x509.load_pem_x509_certificate(d["pem"].encode())
    der = cert.public_bytes(Encoding.DER)
    assert d["fingerprints"]["sha256"] == hashlib.sha256(der).digest().hex(":").upper()
    assert int(d["serial"].replace(":", ""), 16) == cert.serial_number


def test_details_never_include_the_private_key(admin_client):
    _, cert_id = _issue(admin_client, common_name="secret.viewer.test")
    body = admin_client.get(f"/api/certs/{cert_id}/details").get_data(as_text=True)
    assert "PRIVATE KEY" not in body
    assert "key_pem" not in body


def test_details_show_revocation(admin_client):
    _, cert_id = _issue(admin_client, common_name="gone.viewer.test")
    admin_client.post(f"/api/certs/{cert_id}/revoke")
    d = admin_client.get(f"/api/certs/{cert_id}/details").get_json()
    assert d["revoked"] and d["revoked_at"]


def test_details_decode_upn_and_email(admin_client):
    _, cert_id = _issue(admin_client, common_name="Jane Doe", template="user",
                        email="jane@viewer.test", upn="jane@corp.viewer.test")
    d = admin_client.get(f"/api/certs/{cert_id}/details").get_json()
    sans = _ext(d, "Subject Alternative Name")["values"]
    assert "UPN: jane@corp.viewer.test" in sans
    assert "Smart Card Logon" in _ext(d, "Extended Key Usage")["values"]


def test_details_missing_cert_is_404(admin_client):
    assert admin_client.get("/api/certs/9999/details").status_code == 404


def test_details_require_login(client):
    assert client.get("/api/certs/1/details").status_code in (302, 401)


# ── CRL section ─────────────────────────────────────────────────────

def _crl(client, cert_id):
    resp = client.get(f"/api/certs/{cert_id}/crl")
    assert resp.status_code == 200
    return resp.get_json()


def test_crl_section_lists_revoked_serials(admin_client):
    ca_id, cert_id = _issue(admin_client, common_name="crl.viewer.test", include_crl_dp=True)
    c = _crl(admin_client, cert_id)
    assert c["cert_revoked"] is False and c["revoked"] == [] and c["next_update"] is None
    assert c["distribution_points"][0].startswith("http://pki.viewer.test/crl/")

    admin_client.post(f"/api/certs/{cert_id}/revoke")
    admin_client.get(f"/api/ca/{ca_id}/crl")
    c = _crl(admin_client, cert_id)
    assert c["cert_revoked"] is True and c["next_update"]
    assert len(c["revoked"]) == 1 and c["revoked"][0]["this"] is True
    detail = admin_client.get(f"/api/certs/{cert_id}/details").get_json()
    assert c["revoked"][0]["serial"] == detail["serial"]


def test_crl_section_without_distribution_point(admin_client):
    _, cert_id = _issue(admin_client, common_name="nodp.viewer.test")
    assert _crl(admin_client, cert_id)["distribution_points"] == []


def test_crl_status_missing_cert_is_404(admin_client):
    assert admin_client.get("/api/certs/9999/crl").status_code == 404
