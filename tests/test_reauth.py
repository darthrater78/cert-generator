"""Releasing key material (private keys, backups) or replacing it (restore) needs a recent sign-in."""
from __future__ import annotations

import sqlite3
import time

import pyotp
import pytest

from app import db, server
from app.routes.auth import TRUST_COOKIE_NAME
from app.web import REAUTH_WINDOW_SECONDS

from .conftest import ADMIN, ADMIN_PASSWORD, login


def _forget_reauth(client, age: int | None = None) -> None:
    with client.session_transaction() as sess:
        if age is None:
            sess.pop("reauth_at", None)
        else:
            sess["reauth_at"] = int(time.time()) - age


def _keys(client) -> tuple[int, int, int]:
    ca_id = client.post("/api/ca", json={"domain": "reauth.test", "algorithm": "ecdsa-p256"}).get_json()["id"]
    cert_id = client.post(f"/api/ca/{ca_id}/certs", json={"common_name": "a.reauth.test"}).get_json()["id"]
    ssh_id = client.post("/api/ssh-keys", json={"name": "k", "algorithm": "ed25519"}).get_json()["id"]
    return ca_id, cert_id, ssh_id


def _guarded_requests(ca_id: int, cert_id: int, ssh_id: int):
    return [
        ("post", f"/api/export/ca/{ca_id}", {"part": "both"}),
        ("post", f"/api/export/ca/{ca_id}", {"part": "private"}),
        ("post", f"/api/export/cert/{cert_id}", {"part": "both"}),
        ("post", f"/api/export/cert/{cert_id}", {"part": "private"}),
        ("post", f"/api/export/ssh-key/{ssh_id}", {"part": "private"}),
        ("get", f"/api/ssh-keys/{ssh_id}/private", None),
        ("post", "/api/backup", {"password": "backup-pass"}),
        ("post", "/api/restore", {"password": "backup-pass", "file_data": "AAAA"}),
    ]


def _send(client, method: str, url: str, body):
    return client.get(url) if method == "get" else client.post(url, json=body)


def test_fresh_sign_in_counts_as_recent(admin_client):
    ca_id, cert_id, ssh_id = _keys(admin_client)
    assert admin_client.get(f"/api/ssh-keys/{ssh_id}/private").status_code == 200
    assert admin_client.post(f"/api/export/cert/{cert_id}", json={"part": "private"}).status_code == 200


def test_key_material_needs_reauth_once_the_window_passes(admin_client):
    ids = _keys(admin_client)
    _forget_reauth(admin_client, age=REAUTH_WINDOW_SECONDS + 1)
    for method, url, body in _guarded_requests(*ids):
        resp = _send(admin_client, method, url, body)
        assert resp.status_code == 403, url
        assert resp.get_json() == {"error": "Confirm it's you to continue", "reauth_required": True, "mfa": False}


def test_public_parts_never_need_reauth(admin_client):
    ca_id, cert_id, ssh_id = _keys(admin_client)
    _forget_reauth(admin_client)
    assert admin_client.post(f"/api/export/ca/{ca_id}", json={"part": "public"}).status_code == 200
    assert admin_client.post(f"/api/export/cert/{cert_id}", json={"part": "public"}).status_code == 200
    assert admin_client.post(f"/api/export/cert/{cert_id}", json={"part": "chain"}).status_code == 200
    assert admin_client.post(f"/api/export/ssh-key/{ssh_id}", json={"part": "public"}).status_code == 200


def test_password_reauth_unlocks_key_material(admin_client):
    _, _, ssh_id = _keys(admin_client)
    _forget_reauth(admin_client)
    assert admin_client.post("/api/reauth", json={"secret": "wrong"}).status_code == 400
    assert admin_client.get(f"/api/ssh-keys/{ssh_id}/private").status_code == 403
    assert admin_client.post("/api/reauth", json={"secret": ADMIN_PASSWORD}).status_code == 200
    assert admin_client.get(f"/api/ssh-keys/{ssh_id}/private").status_code == 200


def test_reauth_requires_a_session(client):
    client.post("/setup", data={"username": ADMIN, "password": ADMIN_PASSWORD, "confirm": ADMIN_PASSWORD})
    client.post("/logout")
    assert client.post("/api/reauth", json={"secret": ADMIN_PASSWORD}).status_code == 401


def test_reauth_shares_the_login_lockout(admin_client, fresh_app):
    _forget_reauth(admin_client)
    for _ in range(5):
        assert admin_client.post("/api/reauth", json={"secret": "wrong"}).status_code == 400
    assert admin_client.post("/api/reauth", json={"secret": ADMIN_PASSWORD}).status_code == 429
    # the sign-in page is locked too: re-auth adds no extra guesses
    assert login(fresh_app.test_client()).status_code == 429


def test_trusted_device_sign_in_is_not_recent(admin_client, fresh_app):
    _, _, ssh_id = _keys(admin_client)
    browser = fresh_app.test_client()
    login(browser, trust_device="1")
    returning = fresh_app.test_client()
    returning.set_cookie(TRUST_COOKIE_NAME, browser.get_cookie(TRUST_COOKIE_NAME).value)
    assert returning.get("/api/ca").status_code == 200  # signed in by the trusted device
    assert returning.get(f"/api/ssh-keys/{ssh_id}/private").status_code == 403


def test_authenticator_code_is_accepted_once_with_mfa(admin_client):
    _, _, ssh_id = _keys(admin_client)
    secret = admin_client.post("/api/mfa/setup", json={}).get_json()["secret"]
    assert admin_client.post("/api/mfa/confirm", json={"code": pyotp.TOTP(secret).now()}).status_code == 200
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.execute("UPDATE users SET totp_last_step = 0")
    _forget_reauth(admin_client)
    assert admin_client.get(f"/api/ssh-keys/{ssh_id}/private").get_json()["mfa"] is True
    code = pyotp.TOTP(secret).now()
    assert admin_client.post("/api/reauth", json={"secret": code}).status_code == 200
    assert admin_client.get(f"/api/ssh-keys/{ssh_id}/private").status_code == 200
    _forget_reauth(admin_client)
    assert admin_client.post("/api/reauth", json={"secret": code}).status_code == 400  # no replay


@pytest.mark.parametrize("value", ["not-a-number", int(time.time()) + 3600])
def test_odd_timestamps_are_not_recent(admin_client, value):
    _, _, ssh_id = _keys(admin_client)
    with admin_client.session_transaction() as sess:
        sess["reauth_at"] = value
    assert admin_client.get(f"/api/ssh-keys/{ssh_id}/private").status_code == 403


def test_desktop_mode_never_asks(fresh_app):
    server.set_app_token("desktop-token")
    client = fresh_app.test_client()
    client.get("/_auth?token=desktop-token")
    _, _, ssh_id = _keys(client)
    assert client.get(f"/api/ssh-keys/{ssh_id}/private").status_code == 200
