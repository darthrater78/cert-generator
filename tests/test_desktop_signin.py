"""Desktop sign-in (username + master password), guide pop-out pages (v2.6.1)."""
from __future__ import annotations

import pytest

from app import db, server

from .conftest import ENCRYPTION_PASSWORD

NEW_PASSWORD = "brand-new-password"


@pytest.fixture
def desktop_client(fresh_app):
    server.set_app_token("desktop-token")
    client = fresh_app.test_client()
    client.get("/_auth?token=desktop-token")
    return client


def _enable(client, username: str = "Steve") -> str:
    resp = client.post("/api/settings/encryption/enable",
                       json={"username": username, "password": ENCRYPTION_PASSWORD, "confirm": ENCRYPTION_PASSWORD})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["recovery_key"]


def _unlock(client, username: str, password: str = ENCRYPTION_PASSWORD):
    return client.post("/api/settings/encryption/unlock", json={"username": username, "password": password})


def test_sign_in_needs_the_username_and_password(desktop_client):
    _enable(desktop_client)
    db.set_master_key(None)
    status = desktop_client.get("/api/settings/encryption").get_json()
    assert status["username_required"] is True
    assert status["username"] is None  # not revealed while locked

    assert _unlock(desktop_client, "").get_json()["error"] == "Username is required"
    wrong_name = _unlock(desktop_client, "someone")
    wrong_password = _unlock(desktop_client, "Steve", "wrong-password-1")
    assert wrong_name.status_code == wrong_password.status_code == 400
    assert wrong_name.get_json()["error"] == wrong_password.get_json()["error"] == "Wrong username or password"
    assert not db.is_unlocked()

    assert _unlock(desktop_client, " steve ").status_code == 200  # case and spacing don't matter
    assert desktop_client.get("/api/settings/encryption").get_json()["username"] == "Steve"


def test_recovery_key_resets_password_and_reminds_the_username(desktop_client):
    recovery_key = _enable(desktop_client)
    db.set_master_key(None)
    resp = desktop_client.post("/api/settings/encryption/recover",
                               json={"recovery_key": recovery_key, "password": NEW_PASSWORD, "confirm": NEW_PASSWORD})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "Steve"
    db.set_master_key(None)
    assert _unlock(desktop_client, "steve", NEW_PASSWORD).status_code == 200


def test_disabling_encryption_removes_the_sign_in(desktop_client):
    _enable(desktop_client)
    resp = desktop_client.post("/api/settings/encryption/disable", json={"password": ENCRYPTION_PASSWORD})
    assert resp.status_code == 200
    assert db.get_login_username() is None
    assert desktop_client.get("/api/settings/encryption").get_json()["username_required"] is False


def test_username_is_optional_and_validated(desktop_client):
    resp = desktop_client.post("/api/settings/encryption/enable",
                               json={"username": "x" * 65, "password": ENCRYPTION_PASSWORD, "confirm": ENCRYPTION_PASSWORD})
    assert resp.status_code == 400
    _enable(desktop_client, "")
    db.set_master_key(None)
    assert desktop_client.get("/api/settings/encryption").get_json()["username_required"] is False
    assert _unlock(desktop_client, "").status_code == 200


def test_server_mode_ignores_a_username(admin_client):
    _enable(admin_client)
    assert db.get_login_username() is None
    db.set_master_key(None)
    assert admin_client.get("/api/settings/encryption").get_json()["username_required"] is False


def test_guide_pages(admin_client):
    for kind, title in (("cert", "Certificate Import Guide"), ("ssh", "SSH Key Guide")):
        resp = admin_client.get(f"/guide/{kind}")
        assert resp.status_code == 200
        assert title in resp.get_data(as_text=True)
    assert admin_client.get("/guide/other").status_code == 404


def test_guide_pages_need_sign_in(admin_client, fresh_app):
    assert fresh_app.test_client().get("/guide/cert").status_code == 302


def test_guide_pages_carry_the_security_headers(admin_client):
    resp = admin_client.get("/guide/cert")
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "same-origin"
    for path in ("/guide/..%2f..%2fetc", "/guide/_guide_cert.html", "/guide/index"):
        assert admin_client.get(path).status_code == 404


def test_desktop_guide_pages_need_the_app_token(fresh_app):
    server.set_app_token("desktop-token")
    assert fresh_app.test_client().get("/guide/cert").status_code == 403
    client = fresh_app.test_client()
    assert client.get("/_auth?token=wrong&next=/guide/cert").status_code == 403
    client.get("/_auth?token=desktop-token&next=/guide/cert")
    assert client.get("/guide/cert").status_code == 200


def test_desktop_auth_redirects_only_to_known_pages(fresh_app):
    server.set_app_token("desktop-token")
    client = fresh_app.test_client()
    resp = client.get("/_auth?token=desktop-token&next=/guide/ssh")
    assert resp.headers["Location"] == "/guide/ssh"
    for target in ("https://evil.example/", "//evil.example", "/api/ca"):
        resp = client.get("/_auth", query_string={"token": "desktop-token", "next": target})
        assert resp.headers["Location"] == "/"
