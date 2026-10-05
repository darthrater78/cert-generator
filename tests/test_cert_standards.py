"""What goes into certificates and CRLs, held to RFC 5280 and to what clients accept."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509

from app import crypto_engine
from app.errors import UserError
from app.routes.pki import normalize_san


def _ca(client, **fields) -> int:
    resp = client.post("/api/ca", json={"domain": "standards.test", "algorithm": "ecdsa-p256", **fields})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["id"]


def _issue(client, ca_id: int, **fields):
    return client.post(f"/api/ca/{ca_id}/certs", json={"algorithm": "ecdsa-p256", **fields})


def _cert(client, cert_id: int) -> x509.Certificate:
    return x509.load_pem_x509_certificate(client.get(f"/api/certs/{cert_id}/details").get_json()["pem"].encode())


def _root(lifetime_days: int = 3650):
    cert, key, *_ = crypto_engine.create_ca("standards.test", "Standards Root", "ecdsa-p256", lifetime_days)
    return cert, key


# ── Validity ────────────────────────────────────────────────────────

def test_certificate_is_dated_a_little_in_the_past():
    cert_pem, *_ = crypto_engine.issue_certificate(*_root(), "pc.standards.test", ["pc.standards.test"], "ecdsa-p256", 30)
    cert = x509.load_pem_x509_certificate(cert_pem)
    now = datetime.now(timezone.utc)
    assert timedelta(minutes=4) < now - cert.not_valid_before_utc < timedelta(minutes=6)
    assert abs(cert.not_valid_after_utc - (now + timedelta(days=30))) < timedelta(minutes=1)


def test_nothing_outlives_the_ca_that_signs_it():
    root_pem, root_key = _root(lifetime_days=10)
    root = x509.load_pem_x509_certificate(root_pem)
    inter_pem, inter_key, _, _, reported = crypto_engine.create_intermediate_ca(
        root_pem, root_key, "standards.test", "Standards Issuing", "ecdsa-p256", 1825)
    inter = x509.load_pem_x509_certificate(inter_pem)
    assert inter.not_valid_after_utc == root.not_valid_after_utc
    assert datetime.fromisoformat(reported) == inter.not_valid_after_utc
    assert inter.not_valid_before_utc >= root.not_valid_before_utc

    leaf_pem, *_ = crypto_engine.issue_certificate(inter_pem, inter_key, "pc.standards.test", [], "ecdsa-p256", 365)
    assert x509.load_pem_x509_certificate(leaf_pem).not_valid_after_utc == root.not_valid_after_utc


# ── Names ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("given, expected", [
    ("pc.standards.test", "pc.standards.test"),
    ("pc.standards.test.", "pc.standards.test"),
    ("*.standards.test", "*.standards.test"),
    ("_svc.standards.test", "_svc.standards.test"),
    ("bücher.standards.test", "xn--bcher-kva.standards.test"),
    ("10.0.0.5", "10.0.0.5"),
    ("fd00::1", "fd00::1"),
    ("a*b.standards.test", None),
    ("*.*.standards.test", None),
    ("pc.*.standards.test", None),
    ("-pc.standards.test", None),
    ("pc..standards.test", None),
    ("pc standards.test", None),
    ("x" * 64 + ".test", None),
])
def test_subject_alternative_names_are_checked_and_normalised(given, expected):
    assert normalize_san(given) == expected


def test_international_name_is_issued_in_its_ascii_form(admin_client):
    ca_id = _ca(admin_client)
    resp = _issue(admin_client, ca_id, common_name="bücher.standards.test")
    assert resp.status_code == 201
    san = _cert(admin_client, resp.get_json()["id"]).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["xn--bcher-kva.standards.test"]


def test_long_host_name_keeps_its_full_name_in_the_san(admin_client):
    ca_id = _ca(admin_client)
    name = "build-agent-0001." + ".".join(["department"] * 5) + ".standards.test"
    assert len(name) > 64
    resp = _issue(admin_client, ca_id, common_name=name)
    assert resp.status_code == 201
    cert = _cert(admin_client, resp.get_json()["id"])
    assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "build-agent-0001"
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == [name]


def test_long_sign_in_name_is_shortened_in_the_subject_only():
    upn = "a" * 60 + "@standards.test"
    cert_pem, *_ = crypto_engine.issue_certificate(*_root(), upn, [], "ecdsa-p256", 30, template="user", upn=upn)
    cert = x509.load_pem_x509_certificate(cert_pem)
    assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "a" * 60
    other = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.OtherName)
    assert other[0].value.endswith(upn.encode())


@pytest.mark.parametrize("fields, message", [
    ({"common_name": "A" * 65, "template": "code-signing"}, "at most 64 characters"),
    ({"common_name": "www.standards.test", "san_domains": "a*b.standards.test"}, "valid DNS name"),
    ({"common_name": "Alice", "template": "email", "email": "not an address"}, "e-mail address"),
    ({"common_name": "Alice", "template": "email", "email": "Alice <alice@standards.test>"}, "e-mail address"),
    ({"common_name": "Alice", "template": "user", "upn": "alice"}, "UPN"),
])
def test_names_a_certificate_cannot_carry_are_refused(admin_client, fields, message):
    resp = _issue(admin_client, _ca(admin_client), **fields)
    assert resp.status_code == 400
    assert message in resp.get_json()["error"]


@pytest.mark.parametrize("fields", [
    {"name": "N" * 65},
    {"domain": "d" * 63 + ".test"},
    {"domain": "bad..test"},
    {"domain": "*.standards.test"},
])
def test_ca_names_that_do_not_fit_are_refused(admin_client, fields):
    resp = admin_client.post("/api/ca", json={"domain": "standards.test", "algorithm": "ecdsa-p256", **fields})
    assert resp.status_code == 400


def test_intermediate_cannot_share_its_issuers_name(admin_client):
    ca_id = _ca(admin_client, name="Standards Root")
    resp = admin_client.post(f"/api/ca/{ca_id}/intermediate",
                             json={"domain": "standards.test", "name": "Standards Root", "algorithm": "ecdsa-p256"})
    assert resp.status_code == 400
    assert "different name" in resp.get_json()["error"]


def test_expired_ca_signs_nothing(monkeypatch):
    root_pem, root_key = _root(lifetime_days=1)
    later = datetime.now(timezone.utc) + timedelta(days=2)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return later

    monkeypatch.setattr(crypto_engine, "datetime", Later)
    with pytest.raises(UserError, match="expired"):
        crypto_engine.issue_certificate(root_pem, root_key, "pc.standards.test", [], "ecdsa-p256", 30)


# ── Key usage ───────────────────────────────────────────────────────

@pytest.mark.parametrize("algorithm, encipher, agree", [
    ("rsa-2048", True, False),
    ("ecdsa-p256", False, True),
    ("ed25519", False, False),
])
def test_mail_certificate_can_be_encrypted_to_with_its_kind_of_key(algorithm, encipher, agree):
    cert_pem, *_ = crypto_engine.issue_certificate(*_root(), "Alice", [], algorithm, 30, template="email",
                                                   email="alice@standards.test")
    usage = x509.load_pem_x509_certificate(cert_pem).extensions.get_extension_for_class(x509.KeyUsage).value
    assert (usage.key_encipherment, usage.key_agreement) == (encipher, agree)
    assert usage.digital_signature and usage.content_commitment


def test_server_certificate_on_an_elliptic_curve_key_only_signs():
    cert_pem, *_ = crypto_engine.issue_certificate(*_root(), "pc.standards.test", ["pc.standards.test"], "ecdsa-p256", 30)
    usage = x509.load_pem_x509_certificate(cert_pem).extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature and not usage.key_encipherment and not usage.key_agreement


# ── CRLs ────────────────────────────────────────────────────────────

def test_crl_names_its_signer_and_is_numbered():
    root_pem, root_key = _root()
    root = x509.load_pem_x509_certificate(root_pem)
    first = x509.load_der_x509_crl(crypto_engine.generate_crl(root_pem, root_key, [], 7))
    second = x509.load_der_x509_crl(crypto_engine.generate_crl(root_pem, root_key, [("0x1234", "2026-10-01T00:00:00Z")], 7))

    aki = first.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    assert aki.value.key_identifier == ski.value.digest and not aki.critical
    number = first.extensions.get_extension_for_class(x509.CRLNumber)
    assert not number.critical
    assert second.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number > number.value.crl_number
    assert first.is_signature_valid(root.public_key())
