"""CRL distribution point: this server (serves a CRL it keeps current) or the offline placeholder."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509

from app import crl_publisher, db, server
from app.routes import pki  # noqa: F401 (limiter is patched)
from app.routes.pki import parse_crl_base_url

from .conftest import ENCRYPTION_PASSWORD

BASE = "http://pki.example.lan:5000"


def _ca(client) -> int:
    resp = client.post("/api/ca", json={"domain": "crl.test", "algorithm": "ecdsa-p256"})
    assert resp.status_code == 201
    return resp.get_json()["id"]


def _issue(client, ca_id: int, **fields):
    return client.post(f"/api/ca/{ca_id}/certs", json={"common_name": "www.crl.test", "algorithm": "ecdsa-p256", **fields})


def _dp_urls(client, cert_id: int) -> list[str]:
    return client.get(f"/api/certs/{cert_id}/crl").get_json()["distribution_points"]


def test_server_distribution_point_uses_the_given_address(admin_client):
    ca_id = _ca(admin_client)
    resp = _issue(admin_client, ca_id, crl_dp="server", crl_base_url=BASE + "/")
    assert resp.status_code == 201
    assert _dp_urls(admin_client, resp.get_json()["id"]) == [f"{BASE}/crl/{ca_id}.crl"]


def test_placeholder_and_legacy_flag_keep_the_offline_url(admin_client):
    ca_id = _ca(admin_client)
    for fields in ({"crl_dp": "placeholder"}, {"include_crl_dp": True}):
        cert_id = _issue(admin_client, ca_id, **fields).get_json()["id"]
        assert _dp_urls(admin_client, cert_id) == ["http://pki.crl.test/crl/crl.test_Root_CA.crl"]
    cert_id = _issue(admin_client, ca_id).get_json()["id"]
    assert _dp_urls(admin_client, cert_id) == []


@pytest.mark.parametrize("url", [
    "", "pki.example.lan", "ftp://pki.example.lan", "javascript:alert(1)", "http://user:pw@pki.example.lan",
    "http://pki.example.lan/?x=1", "http://pki.example.lan/#f", "http://pki.example.lan:99999", "http://pki example.lan",
    "http://" + "a" * 200 + ".lan",
])
def test_invalid_server_addresses_are_rejected(admin_client, url):
    ca_id = _ca(admin_client)
    resp = _issue(admin_client, ca_id, crl_dp="server", crl_base_url=url)
    assert resp.status_code == 400
    assert parse_crl_base_url(url) is None


def test_valid_server_addresses(admin_client):
    assert parse_crl_base_url("https://pki.example.lan") == "https://pki.example.lan"
    assert parse_crl_base_url(" http://10.0.0.5:8080/pki/ ") == "http://10.0.0.5:8080/pki"


def test_unknown_mode_is_rejected(admin_client):
    assert _issue(admin_client, _ca(admin_client), crl_dp="elsewhere").status_code == 400


def test_desktop_mode_cannot_use_this_server(fresh_app):
    server.set_app_token("desktop-token")
    client = fresh_app.test_client()
    client.get("/_auth?token=desktop-token")
    ca_id = _ca(client)
    assert _issue(client, ca_id, crl_dp="server", crl_base_url=BASE).status_code == 400
    assert _issue(client, ca_id, crl_dp="placeholder").status_code == 201


def _served_ca(client) -> tuple[int, int]:
    """A CA opted in to /crl/ by issuing a certificate that points at this server."""
    ca_id = _ca(client)
    resp = _issue(client, ca_id, crl_dp="server", crl_base_url=BASE)
    assert resp.status_code == 201
    return ca_id, resp.get_json()["id"]


def _served(client, ca_id) -> x509.CertificateRevocationList:
    resp = client.get(f"/crl/{ca_id}.crl")
    assert resp.status_code == 200
    return x509.load_der_x509_crl(resp.data)


def test_crl_is_served_as_soon_as_a_certificate_points_here(admin_client, fresh_app):
    ca_id, _ = _served_ca(admin_client)
    anon = fresh_app.test_client()
    resp = anon.get(f"/crl/{ca_id}.crl")
    assert resp.status_code == 200 and resp.content_type == "application/pkix-crl"
    crl = x509.load_der_x509_crl(resp.data)
    assert crl.next_update_utc - crl.last_update_utc == timedelta(days=crl_publisher.PUBLISHED_CRL_DAYS)

    ca = admin_client.get(f"/api/ca/{ca_id}").get_json()
    assert ca["crl_served"] is True and "crl_der" not in ca
    assert ca["crl_served_next_update"] == crl.next_update_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert ca["crl_next_update"] is None  # nothing exported for offline import yet
    assert anon.get("/crl/9999.crl").status_code == 404
    assert anon.get(f"/api/ca/{ca_id}").status_code == 401


def test_revoking_republishes_the_served_crl(admin_client, fresh_app):
    ca_id, cert_id = _served_ca(admin_client)
    anon = fresh_app.test_client()
    assert len(_served(anon, ca_id)) == 0
    resp = admin_client.post(f"/api/certs/{cert_id}/revoke").get_json()
    assert resp["crl_dp"] == "server" and resp["download_crl"] is False
    assert "serves an updated CRL" in resp["note"]
    assert len(_served(anon, ca_id)) == 1
    assert admin_client.get(f"/api/certs/{cert_id}/crl").get_json()["published_path"] == f"/crl/{ca_id}.crl"


@pytest.mark.parametrize(("fields", "kind"), [
    ({"crl_dp": "placeholder"}, "placeholder"),
    ({}, "none"),
])
def test_revoking_without_this_server_asks_for_an_import(admin_client, fields, kind):
    ca_id = _ca(admin_client)
    cert_id = _issue(admin_client, ca_id, **fields).get_json()["id"]
    resp = admin_client.post(f"/api/certs/{cert_id}/revoke").get_json()
    assert resp["crl_dp"] == kind and resp["download_crl"] is True
    assert "import" in resp["note"].lower()


def test_placeholder_on_a_served_ca_still_republishes(admin_client, fresh_app):
    ca_id, _ = _served_ca(admin_client)
    cert_id = _issue(admin_client, ca_id, crl_dp="placeholder").get_json()["id"]
    assert admin_client.post(f"/api/certs/{cert_id}/revoke").get_json()["download_crl"] is True
    assert len(_served(fresh_app.test_client(), ca_id)) == 1


def test_exporting_does_not_replace_the_served_crl(admin_client, fresh_app):
    ca_id, _ = _served_ca(admin_client)
    served = fresh_app.test_client().get(f"/crl/{ca_id}.crl").data
    exported = admin_client.get(f"/api/ca/{ca_id}/crl?days=3650").data
    assert exported != served
    assert fresh_app.test_client().get(f"/crl/{ca_id}.crl").data == served
    assert admin_client.get(f"/api/ca/{ca_id}").get_json()["crl_next_update"] is not None


def test_renewal_resigns_only_crls_that_are_due(admin_client, fresh_app):
    ca_id, _ = _served_ca(admin_client)
    anon = fresh_app.test_client()
    first = _served(anon, ca_id)
    now = datetime.now(timezone.utc)
    assert crl_publisher.renew_due(now) == []
    later = first.next_update_utc - crl_publisher.RENEW_WHEN_LEFT + timedelta(minutes=1)
    assert crl_publisher.renew_due(later) == [ca_id]
    assert _served(anon, ca_id).last_update_utc >= first.last_update_utc


def test_renewal_waits_while_the_database_is_locked(admin_client, fresh_app):
    ca_id, _ = _served_ca(admin_client)
    resp = admin_client.post("/api/settings/encryption/enable",
                             json={"password": ENCRYPTION_PASSWORD, "confirm": ENCRYPTION_PASSWORD})
    assert resp.status_code == 200
    db.set_master_key(None)  # simulate a restart
    assert crl_publisher.renew_due(datetime.now(timezone.utc) + timedelta(days=30)) == []
    assert fresh_app.test_client().get(f"/crl/{ca_id}.crl").status_code == 200  # still served


def test_revoking_on_a_served_ca_needs_the_database_unlocked(admin_client, fresh_app):
    ca_id, cert_id = _served_ca(admin_client)
    other_ca = _ca(admin_client)
    placeholder_id = _issue(admin_client, other_ca, crl_dp="placeholder").get_json()["id"]
    admin_client.post("/api/settings/encryption/enable",
                      json={"password": ENCRYPTION_PASSWORD, "confirm": ENCRYPTION_PASSWORD})
    db.set_master_key(None)
    assert admin_client.post(f"/api/certs/{cert_id}/revoke").status_code == 423
    assert db.get_cert_summary(cert_id)["revoked"] == 0  # failed before revoking
    assert admin_client.post(f"/api/certs/{placeholder_id}/revoke").status_code == 200


def test_backup_restore_keeps_the_served_crl(admin_client, fresh_app):
    ca_id, _ = _served_ca(admin_client)
    served = fresh_app.test_client().get(f"/crl/{ca_id}.crl").data
    backup = admin_client.post("/api/backup", json={"password": "backup-password"}).data
    resp = admin_client.post("/api/restore", json={
        "password": "backup-password", "file_data": base64.b64encode(backup).decode()})
    assert resp.status_code == 200
    assert fresh_app.test_client().get(f"/crl/{ca_id}.crl").data == served


# ── Hardening of the public endpoint ───────────────────────────────

def test_ca_that_did_not_opt_in_is_not_served(admin_client, fresh_app):
    ca_id = _ca(admin_client)
    _issue(admin_client, ca_id, crl_dp="placeholder")
    admin_client.get(f"/api/ca/{ca_id}/crl")
    anon = fresh_app.test_client()
    hidden, unknown = anon.get(f"/crl/{ca_id}.crl"), anon.get("/crl/9999.crl")
    assert hidden.status_code == unknown.status_code == 404
    assert hidden.data == unknown.data
    assert admin_client.get(f"/api/ca/{ca_id}").get_json()["crl_served"] is False


def test_public_endpoint_is_narrow(admin_client, fresh_app):
    ca_id, _ = _served_ca(admin_client)
    anon = fresh_app.test_client()
    for method in ("post", "put", "delete", "patch", "options"):
        assert getattr(anon, method)(f"/crl/{ca_id}.crl").status_code == 405
    for path in ("/crl/", f"/crl/{ca_id}", "/crl/-1.crl", "/crl/1.crl.bak", "/crl/../api/ca", "/crl/x.crl"):
        assert anon.get(path).status_code in (404, 302, 308), path
    resp = anon.get(f"/crl/{ca_id}.crl")
    assert "Set-Cookie" not in resp.headers
    assert resp.headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Content-Disposition"] == f'attachment; filename="{ca_id}.crl"'
    head = anon.head(f"/crl/{ca_id}.crl")
    assert head.status_code == 200 and head.data == b""


def test_public_endpoint_ignores_session_and_trust_cookies(admin_client):
    ca_id, _ = _served_ca(admin_client)
    resp = admin_client.get(f"/crl/{ca_id}.crl")  # a signed-in browser
    assert resp.status_code == 200 and "Set-Cookie" not in resp.headers


def test_public_endpoint_supports_conditional_requests(admin_client, fresh_app):
    ca_id, _ = _served_ca(admin_client)
    anon = fresh_app.test_client()
    etag = anon.get(f"/crl/{ca_id}.crl").headers["ETag"]
    assert anon.get(f"/crl/{ca_id}.crl", headers={"If-None-Match": etag}).status_code == 304


def test_public_endpoint_is_rate_limited(admin_client, fresh_app, monkeypatch):
    ca_id, _ = _served_ca(admin_client)
    monkeypatch.setattr(pki, "_crl_limiter", pki.RateLimiter(3))
    anon = fresh_app.test_client()
    codes = [anon.get(f"/crl/{ca_id}.crl").status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_rate_limiter_bounds_its_memory():
    limiter = pki.RateLimiter(5, max_keys=2)
    assert limiter.allow("a") and limiter.allow("b")
    assert limiter.allow("c") is False  # table full within the window: fail closed
    assert limiter.allow("a")


# ── CRL note on certificates ───────────────────────────────────────

def test_certificates_report_their_distribution_point(admin_client):
    ca_id, served_id = _served_ca(admin_client)
    placeholder_id = _issue(admin_client, ca_id, crl_dp="placeholder").get_json()["id"]
    none_id = _issue(admin_client, ca_id).get_json()["id"]

    by_id = {c["id"]: c["crl_dp"] for c in admin_client.get(f"/api/ca/{ca_id}/certs").get_json()}
    assert by_id[served_id] == {"kind": "server", "url": f"{BASE}/crl/{ca_id}.crl", "published": True}
    assert by_id[placeholder_id]["kind"] == "placeholder" and by_id[placeholder_id]["published"] is False
    assert by_id[none_id] == {"kind": "none", "url": None, "published": False}
    details = admin_client.get(f"/api/certs/{served_id}/details").get_json()
    assert details["crl_dp"]["published"] is True


def test_legacy_certificates_are_backfilled(admin_client):
    ca_id = _ca(admin_client)
    cert_id = _issue(admin_client, ca_id, crl_dp="placeholder").get_json()["id"]
    with db._connect() as conn:
        conn.execute("UPDATE certificates SET crl_dp_url = NULL WHERE id = ?", (cert_id,))
    db.init_db()
    certs = admin_client.get(f"/api/ca/{ca_id}/certs").get_json()
    assert certs[0]["crl_dp"]["kind"] == "placeholder"


# ── Deleting certificates never un-revokes them ────────────────────

def _crl_serials(client, ca_id) -> set[int]:
    return {e.serial_number for e in x509.load_der_x509_crl(client.get(f"/api/ca/{ca_id}/crl").data)}


def test_deleted_revoked_certificate_stays_on_the_crl(admin_client):
    ca_id, cert_id = _served_ca(admin_client)
    serial = int(admin_client.get(f"/api/certs/{cert_id}").get_json()["serial"], 16)
    admin_client.post(f"/api/certs/{cert_id}/revoke")
    assert admin_client.delete(f"/api/certs/{cert_id}").status_code == 200
    assert serial in _crl_serials(admin_client, ca_id)
    other_id = _issue(admin_client, ca_id).get_json()["id"]
    entries = admin_client.get(f"/api/certs/{other_id}/crl").get_json()["revoked"]
    assert entries[0]["deleted"] is True and entries[0]["this"] is False


def test_deleted_revocation_drops_off_after_expiry(admin_client):
    ca_id, cert_id = _served_ca(admin_client)
    admin_client.post(f"/api/certs/{cert_id}/revoke")
    admin_client.delete(f"/api/certs/{cert_id}")
    with db._connect() as conn:
        conn.execute("UPDATE deleted_revocations SET not_after = '2020-01-01T00:00:00+00:00'")
    assert _crl_serials(admin_client, ca_id) == set()


def test_deleting_an_unrevoked_certificate_adds_nothing(admin_client):
    ca_id, cert_id = _served_ca(admin_client)
    admin_client.delete(f"/api/certs/{cert_id}")
    assert _crl_serials(admin_client, ca_id) == set()


def test_deleting_the_ca_removes_its_crl_and_tombstones(admin_client, fresh_app):
    ca_id, cert_id = _served_ca(admin_client)
    admin_client.post(f"/api/certs/{cert_id}/revoke")
    admin_client.delete(f"/api/certs/{cert_id}")
    admin_client.get(f"/api/ca/{ca_id}/crl")
    assert admin_client.delete(f"/api/ca/{ca_id}").status_code == 200
    assert fresh_app.test_client().get(f"/crl/{ca_id}.crl").status_code == 404
    with db._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM deleted_revocations").fetchone()[0] == 0


def test_backup_restore_keeps_deleted_revocations(admin_client):
    ca_id, cert_id = _served_ca(admin_client)
    serial = int(admin_client.get(f"/api/certs/{cert_id}").get_json()["serial"], 16)
    admin_client.post(f"/api/certs/{cert_id}/revoke")
    admin_client.delete(f"/api/certs/{cert_id}")
    backup = admin_client.post("/api/backup", json={"password": "backup-password"}).data
    resp = admin_client.post("/api/restore", json={
        "password": "backup-password", "file_data": base64.b64encode(backup).decode()})
    assert resp.status_code == 200
    assert serial in _crl_serials(admin_client, ca_id)


# ── CRL viewer ─────────────────────────────────────────────────────

def test_crl_viewer_shows_the_served_crl(admin_client):
    ca_id, cert_id = _served_ca(admin_client)
    admin_client.post(f"/api/certs/{cert_id}/revoke")
    view = admin_client.get(f"/api/ca/{ca_id}/crl/view").get_json()
    assert view["source"] == "served" and view["published_path"] == f"/crl/{ca_id}.crl"
    assert view["crl"]["pem"].startswith("-----BEGIN X509 CRL-----") and view["out_of_date"] is False
    assert [(e["cert_id"], e["common_name"], e["deleted"]) for e in view["entries"]] == [(cert_id, "www.crl.test", False)]


def test_crl_viewer_lists_pending_entries_for_unserved_cas(admin_client):
    ca_id = _ca(admin_client)
    cert_id = _issue(admin_client, ca_id, crl_dp="placeholder").get_json()["id"]
    admin_client.post(f"/api/certs/{cert_id}/revoke")
    admin_client.delete(f"/api/certs/{cert_id}")
    view = admin_client.get(f"/api/ca/{ca_id}/crl/view").get_json()
    assert view["source"] == "current" and view["crl"] is None
    assert [(e["cert_id"], e["deleted"]) for e in view["entries"]] == [(None, True)]


def test_crl_viewer_needs_sign_in_and_a_real_ca(admin_client, fresh_app):
    ca_id, _ = _served_ca(admin_client)
    assert fresh_app.test_client().get(f"/api/ca/{ca_id}/crl/view").status_code == 401
    assert admin_client.get("/api/ca/9999/crl/view").status_code == 404
