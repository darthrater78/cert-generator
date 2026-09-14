"""Regression tests for the security and quality audit fixes."""
from __future__ import annotations

import base64
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pyotp
import pytest
from cryptography import x509

from app import crypto_engine, db, security, server
from app.serve import _run_admin_resets

from .conftest import ADMIN, ADMIN_PASSWORD, ENCRYPTION_PASSWORD, login


def _enable_mfa(client) -> str:
    secret = client.post("/api/mfa/setup", json={}).get_json()["secret"]
    resp = client.post("/api/mfa/confirm", json={"code": pyotp.TOTP(secret).now()})
    assert resp.status_code == 200
    # confirm consumed the current step; clear it so tests can log in again right away
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.execute("UPDATE users SET totp_last_step = 0")
    return secret


def _enable_encryption(client) -> None:
    resp = client.post("/api/settings/encryption/enable",
                       json={"password": ENCRYPTION_PASSWORD, "confirm": ENCRYPTION_PASSWORD})
    assert resp.status_code == 200


def _create_ca(client, domain: str = "example.test", parent: int | None = None) -> int:
    url = f"/api/ca/{parent}/intermediate" if parent else "/api/ca"
    resp = client.post(url, json={"domain": domain, "algorithm": "ecdsa-p256"})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["id"]


# ── Encryption at rest ──────────────────────────────────────────────

def test_locked_database_refuses_to_store_plaintext_keys(admin_client):
    _enable_encryption(admin_client)
    db.set_master_key(None)  # simulate a restart

    resp = admin_client.post("/api/ca", json={"domain": "locked.test"})
    assert resp.status_code == 423
    assert resp.get_json()["locked"] is True
    resp = admin_client.post("/api/ssh-keys", json={"name": "k", "algorithm": "ed25519"})
    assert resp.status_code == 423
    with sqlite3.connect(db.DB_PATH) as conn:
        assert conn.execute("SELECT COUNT(*) FROM certificate_authorities").fetchone()[0] == 0


def test_encryption_password_change_keeps_data_readable(admin_client):
    ca_id = _create_ca(admin_client)
    _enable_encryption(admin_client)
    resp = admin_client.post("/api/settings/encryption/change-password", json={
        "old_password": ENCRYPTION_PASSWORD, "new_password": "new-encryption-pass", "confirm": "new-encryption-pass"})
    assert resp.status_code == 200
    db.set_master_key(None)
    assert not db.unlock(ENCRYPTION_PASSWORD)
    assert db.unlock("new-encryption-pass")
    assert db.get_ca(ca_id)["key_pem"].startswith(b"-----BEGIN")
    resp = admin_client.post("/api/settings/encryption/disable", json={"password": "new-encryption-pass"})
    assert resp.status_code == 200
    with sqlite3.connect(db.DB_PATH) as conn:
        raw = conn.execute("SELECT key_pem FROM certificate_authorities").fetchone()[0]
    assert raw.startswith(b"-----BEGIN")


def test_mfa_login_after_restart_with_encryption(admin_client, fresh_app):
    secret = _enable_mfa(admin_client)
    _enable_encryption(admin_client)
    db.set_master_key(None)

    browser = fresh_app.test_client()
    assert login(browser).headers["Location"] == "/mfa"
    page = browser.get("/mfa")
    assert page.status_code == 200
    assert b"encryption_password" in page.data

    resp = browser.post("/mfa", data={"code": pyotp.TOTP(secret).now()})
    assert b"Encryption password is required" in resp.data
    resp = browser.post("/mfa", data={"code": pyotp.TOTP(secret).now(), "encryption_password": "wrong-password"})
    assert b"Invalid encryption password" in resp.data
    resp = browser.post("/mfa", data={"code": pyotp.TOTP(secret).now(), "encryption_password": ENCRYPTION_PASSWORD})
    assert resp.status_code == 302 and resp.headers["Location"] == "/"
    assert db.is_unlocked()
    assert browser.get("/api/mfa/status").get_json()["enabled"] is True


def test_reset_mfa_works_while_database_locked(admin_client, monkeypatch):
    _enable_mfa(admin_client)
    _enable_encryption(admin_client)
    db.set_master_key(None)
    monkeypatch.setenv("RESET_MFA", ADMIN)
    monkeypatch.delenv("RESET_PASSWORD", raising=False)
    _run_admin_resets()
    assert db.get_user(ADMIN)["totp_enabled"] == 0


# ── Authentication hardening ────────────────────────────────────────

def test_login_is_rate_limited(admin_client, fresh_app):
    browser = fresh_app.test_client()
    for _ in range(5):
        assert b"Invalid username or password" in login(browser, password="wrong-password").data
    locked = login(browser)
    assert locked.status_code == 429
    server._auth_limiter.reset()
    assert login(browser).status_code == 302


def test_attempt_limiter_escalates_and_resets():
    limiter = security.AttemptLimiter(max_failures=2, base_lockout=10, max_lockout=40)
    limiter.failure("k")
    assert limiter.retry_after("k") == 0
    limiter.failure("k")
    assert 9 < limiter.retry_after("k") <= 10
    limiter.failure("k")
    assert 19 < limiter.retry_after("k") <= 20
    limiter.success("k")
    assert limiter.retry_after("k") == 0


def test_totp_code_cannot_be_replayed(admin_client, fresh_app):
    secret = _enable_mfa(admin_client)
    code = pyotp.TOTP(secret).now()

    first = fresh_app.test_client()
    login(first)
    assert first.post("/mfa", data={"code": code}).status_code == 302

    second = fresh_app.test_client()
    login(second)
    resp = second.post("/mfa", data={"code": code})
    assert b"Invalid verification code" in resp.data


def test_long_password_does_not_crash_login(admin_client, fresh_app):
    resp = login(fresh_app.test_client(), password="a" * 100)
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data


def test_existing_long_password_hash_still_verifies(admin_client):
    # bcrypt<5 silently used only the first 72 bytes when hashing.
    long_password = "p" * 80
    legacy_hash = db._bcrypt.hashpw(long_password.encode()[:72], db._bcrypt.gensalt()).decode()
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (legacy_hash, ADMIN))
    assert db.verify_user(ADMIN, long_password)


def test_setup_token_is_enforced_when_configured(client, monkeypatch):
    monkeypatch.setenv("SETUP_TOKEN", "let-me-in")
    form = {"username": ADMIN, "password": ADMIN_PASSWORD, "confirm": ADMIN_PASSWORD}
    assert b"setup_token" in client.get("/setup").data
    assert client.post("/setup", data=form).status_code == 403
    assert client.post("/setup", data={**form, "setup_token": "let-me-in"}).status_code == 302
    assert db.has_users()


def test_setup_cannot_create_a_second_admin(admin_client, fresh_app):
    other = fresh_app.test_client()
    other.post("/setup", data={"username": "intruder", "password": "password123", "confirm": "password123"})
    assert db.get_user("intruder") is None


# ── CSRF and headers ────────────────────────────────────────────────

@pytest.mark.parametrize("headers", [
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
])
def test_cross_site_writes_are_blocked(admin_client, headers):
    resp = admin_client.post("/api/mfa/revoke-devices", headers=headers)
    assert resp.status_code == 403


@pytest.mark.parametrize("headers", [
    {"Sec-Fetch-Site": "same-origin"},
    {"Origin": "http://localhost"},
    {"Origin": "https://certs.example", "X-Forwarded-Host": "certs.example"},
    {},
])
def test_same_site_writes_are_allowed(admin_client, headers):
    resp = admin_client.post("/api/mfa/revoke-devices", headers=headers)
    assert resp.status_code == 200


def test_login_form_rejects_cross_site_post(admin_client, fresh_app):
    resp = fresh_app.test_client().post(
        "/login", data={"username": ADMIN, "password": ADMIN_PASSWORD}, headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403


def test_security_headers(admin_client):
    resp = admin_client.get("/")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert admin_client.get("/api/ca").headers["Cache-Control"] == "no-store"
    cookie = admin_client.get_cookie("session")
    assert cookie is not None and cookie.same_site == "Lax"


def test_desktop_mode_origin_check_is_exact(fresh_app):
    server.set_app_token("desktop-token")
    server.set_bound_port(5174)
    client = fresh_app.test_client()
    client.get("/_auth?token=desktop-token")
    bad = client.post("/api/ca", json={"domain": "x.test"}, headers={"Origin": "http://127.0.0.1:5174.evil.example"})
    assert bad.status_code == 403
    good = client.post("/api/ca", json={"domain": "x.test"}, headers={"Origin": "http://127.0.0.1:5174"})
    assert good.status_code == 201
    assert "X-Frame-Options" not in good.headers


# ── Sessions ────────────────────────────────────────────────────────

def test_logout_requires_post(admin_client):
    admin_client.get("/logout")
    assert admin_client.get("/api/ca").status_code == 200
    admin_client.post("/logout")
    assert admin_client.get("/api/ca").status_code == 401


def test_password_reset_ends_existing_sessions(admin_client, monkeypatch):
    assert admin_client.get("/api/ca").status_code == 200
    monkeypatch.setenv("RESET_PASSWORD", f"{ADMIN}:brand-new-password")
    monkeypatch.delenv("RESET_MFA", raising=False)
    _run_admin_resets()
    assert admin_client.get("/api/ca").status_code == 401


def test_revoking_devices_ends_other_sessions_only(admin_client, fresh_app):
    other = fresh_app.test_client()
    login(other)
    assert other.get("/api/ca").status_code == 200
    assert admin_client.post("/api/mfa/revoke-devices").status_code == 200
    assert admin_client.get("/api/ca").status_code == 200
    assert other.get("/api/ca").status_code == 401


def test_sessions_from_before_upgrade_stay_valid(admin_client):
    with admin_client.session_transaction() as sess:
        sess.pop("sv", None)  # cookies issued by older versions have no session version
    assert admin_client.get("/api/ca").status_code == 200


def test_logout_forgets_trusted_device(admin_client, fresh_app):
    browser = fresh_app.test_client()
    login(browser, trust_device="1")
    user_id = db.get_user(ADMIN)["id"]
    assert db.count_trusted_devices(user_id) == 1
    browser.post("/logout")
    assert db.count_trusted_devices(user_id) == 0


# ── Exports ─────────────────────────────────────────────────────────

def test_server_mode_exports_stream_and_never_touch_disk(admin_client, tmp_path):
    ca_id = _create_ca(admin_client)
    resp = admin_client.post(f"/api/export/ca/{ca_id}", json={"format": "pem", "part": "private"})
    assert resp.status_code == 200
    assert "attachment" in resp.headers["Content-Disposition"]
    assert resp.data.startswith(b"-----BEGIN PRIVATE KEY")
    assert resp.headers["Cache-Control"] == "no-store"
    crl = admin_client.get(f"/api/ca/{ca_id}/crl")
    assert crl.status_code == 200 and "attachment" in crl.headers["Content-Disposition"]
    backup = admin_client.post("/api/backup", json={"password": "backup-password"})
    assert backup.data.startswith(b"CERTBAK")
    exports = tmp_path / "exports"
    assert not exports.exists() or not any(exports.iterdir())


def test_desktop_mode_exports_still_save_to_folder(fresh_app, tmp_path):
    server.set_app_token("desktop-token")
    client = fresh_app.test_client()
    client.get("/_auth?token=desktop-token")
    ca_id = _create_ca(client)
    resp = client.post(f"/api/export/ca/{ca_id}", json={"format": "pem", "part": "public"})
    path = Path(resp.get_json()["path"])
    assert path.parent == tmp_path / "exports" and path.is_file()


def test_pkcs12_export_requires_password(admin_client):
    ca_id = _create_ca(admin_client)
    cert_id = admin_client.post(f"/api/ca/{ca_id}/certs", json={"common_name": "host.example.test"}).get_json()["id"]
    resp = admin_client.post(f"/api/export/cert/{cert_id}", json={"format": "pkcs12"})
    assert resp.status_code == 400
    resp = admin_client.post(f"/api/export/cert/{cert_id}", json={"format": "pkcs12", "password": "changeit"})
    assert resp.status_code == 200


def test_backup_restore_round_trip_keeps_current_session(admin_client):
    ca_id = _create_ca(admin_client)
    backup = admin_client.post("/api/backup", json={"password": "backup-password"}).data
    admin_client.delete(f"/api/ca/{ca_id}")
    resp = admin_client.post("/api/restore", json={
        "password": "backup-password", "file_data": base64.b64encode(backup).decode()})
    assert resp.status_code == 200
    assert resp.get_json()["counts"]["cas"] == 1
    assert admin_client.get(f"/api/ca/{ca_id}").status_code == 200


def test_restore_rejects_malformed_backup_content(admin_client):
    bad = crypto_engine.encrypt_backup(b'{"version": 1, "certificate_authorities": [{"id": 1}]}', "pw")
    resp = admin_client.post("/api/restore", json={"password": "pw", "file_data": base64.b64encode(bad).decode()})
    assert resp.status_code == 400


# ── Certificates and CAs ────────────────────────────────────────────

def test_intermediate_under_intermediate_is_rejected(admin_client):
    root = _create_ca(admin_client, "root.test")
    intermediate = _create_ca(admin_client, "int.test", parent=root)
    resp = admin_client.post(f"/api/ca/{intermediate}/intermediate", json={"domain": "deeper.test"})
    assert resp.status_code == 400


def test_deleting_root_removes_deep_hierarchy(admin_client):
    root = _create_ca(admin_client, "root.test")
    intermediate = _create_ca(admin_client, "int.test", parent=root)
    # Older versions allowed a third level; build one directly.
    parent = db.get_ca(intermediate)
    cert_pem, key_pem, serial, nb, na = crypto_engine.create_intermediate_ca(
        parent["cert_pem"], parent["key_pem"], "deep.test", "deep", "ecdsa-p256", 30)
    deep = db.save_ca("deep", "deep.test", "ecdsa-p256", nb, na, serial, cert_pem, key_pem, parent_ca_id=intermediate)
    admin_client.post(f"/api/ca/{deep}/certs", json={"common_name": "leaf.test"})

    assert admin_client.delete(f"/api/ca/{root}").status_code == 200
    assert db.list_cas() == [] and db.list_certs() == []


def test_chain_export_includes_every_issuer(admin_client):
    root = _create_ca(admin_client, "root.test")
    intermediate = _create_ca(admin_client, "int.test", parent=root)
    cert_id = admin_client.post(f"/api/ca/{intermediate}/certs", json={"common_name": "leaf.test"}).get_json()["id"]
    chain = admin_client.post(f"/api/export/cert/{cert_id}", json={"part": "chain"}).data
    assert chain.count(b"BEGIN CERTIFICATE") == 3


def test_san_handling(admin_client):
    ca_id = _create_ca(admin_client)
    resp = admin_client.post(f"/api/ca/{ca_id}/certs",
                             json={"common_name": "host.test", "san_domains": "host.test, 10.0.0.5, ::1"})
    assert resp.status_code == 201
    cert = x509.load_pem_x509_certificate(db.get_cert(resp.get_json()["id"])["cert_pem"])
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["host.test"]
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["10.0.0.5", "::1"]

    bad = admin_client.post(f"/api/ca/{ca_id}/certs", json={"common_name": "x.test", "san_domains": "not a host"})
    assert bad.status_code == 400
    person = admin_client.post(f"/api/ca/{ca_id}/certs",
                               json={"common_name": "Jane Doe", "template": "user", "email": "jane@example.test"})
    assert person.status_code == 201


def test_crl_uses_revocation_time(admin_client):
    ca_id = _create_ca(admin_client)
    cert_id = admin_client.post(f"/api/ca/{ca_id}/certs", json={"common_name": "leaf.test"}).get_json()["id"]
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.execute("UPDATE certificates SET created_at = '2020-01-01T00:00:00Z' WHERE id = ?", (cert_id,))
    admin_client.post(f"/api/certs/{cert_id}/revoke")
    crl = x509.load_der_x509_crl(admin_client.get(f"/api/ca/{ca_id}/crl").data)
    revoked = list(crl)[0].revocation_date_utc
    assert revoked.year == datetime.now(timezone.utc).year


# ── Input handling and configuration ────────────────────────────────

@pytest.mark.parametrize("body", ["[]", "null", '{"domain": 5}'])
def test_malformed_json_returns_400(admin_client, body):
    resp = admin_client.post("/api/ca", data=body, content_type="application/json")
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_oversized_request_is_rejected(admin_client):
    resp = admin_client.post("/api/restore", data=b"x" * (33 * 1024 * 1024), content_type="application/json")
    assert resp.status_code == 413


def test_empty_secret_key_falls_back_to_random(tmp_path):
    env = {**os.environ, "SECRET_KEY": "", "DB_DIR": str(tmp_path)}
    code = "from app.server import app; print(len(app.secret_key))"
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True,
                         cwd=Path(__file__).resolve().parents[1], check=True)
    assert int(out.stdout.strip()) == 64


def test_schema_migration_from_older_database(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy" / "certs.db"
    legacy.parent.mkdir()
    with sqlite3.connect(legacy) as conn:
        conn.executescript("""
            CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
                                password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT '');
            CREATE TABLE certificates (id INTEGER PRIMARY KEY AUTOINCREMENT, ca_id INTEGER NOT NULL,
                common_name TEXT NOT NULL, san_domains TEXT NOT NULL, algorithm TEXT NOT NULL,
                template TEXT NOT NULL DEFAULT 'web-server', not_before TEXT NOT NULL, not_after TEXT NOT NULL,
                serial TEXT NOT NULL UNIQUE, cert_pem BLOB NOT NULL, key_pem BLOB NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT '');
        """)
    monkeypatch.setattr(db, "DB_DIR", legacy.parent)
    monkeypatch.setattr(db, "DB_PATH", legacy)
    db.init_db()
    with sqlite3.connect(legacy) as conn:
        user_cols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
        cert_cols = {r[1] for r in conn.execute("PRAGMA table_info(certificates)")}
    assert {"totp_secret", "totp_last_step", "session_version"} <= user_cols
    assert "revoked_at" in cert_cols
