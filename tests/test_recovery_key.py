"""Envelope encryption and the one-time recovery key (v2.6.0)."""
from __future__ import annotations

import re
import secrets
import sqlite3

import pyotp

from app import crypto_engine, db

from .conftest import ENCRYPTION_PASSWORD, login
from .test_security import _create_ca, _enable_mfa

NEW_PASSWORD = "brand-new-password"
KEY_PATTERN = re.compile(r"^([0-9A-HJKMNP-TV-Z]{5}-){4}[0-9A-HJKMNP-TV-Z]{5}$")


def _enable(client) -> str:
    resp = client.post("/api/settings/encryption/enable",
                       json={"password": ENCRYPTION_PASSWORD, "confirm": ENCRYPTION_PASSWORD})
    assert resp.status_code == 200
    return resp.get_json()["recovery_key"]


def _recover(client, recovery_key: str, password: str = NEW_PASSWORD):
    return client.post("/api/settings/encryption/recover",
                       json={"recovery_key": recovery_key, "password": password, "confirm": password})


def _raw_ca_key() -> bytes:
    with sqlite3.connect(db.DB_PATH) as conn:
        return conn.execute("SELECT key_pem FROM certificate_authorities").fetchone()[0]


# ── Key format ──────────────────────────────────────────────────────

def test_recovery_key_format_and_normalization():
    key = crypto_engine.generate_recovery_key()
    assert KEY_PATTERN.match(key)
    canonical = key.replace("-", "")
    assert crypto_engine.normalize_recovery_key(key) == canonical
    assert crypto_engine.normalize_recovery_key(" " + key.lower().replace("-", " ") + " ") == canonical
    # O, I and L are read as the digits they look like
    assert crypto_engine.normalize_recovery_key("O" * 25) == "0" * 25
    assert crypto_engine.normalize_recovery_key("iL" + "1" * 23) == "1" * 25
    assert crypto_engine.normalize_recovery_key("U" * 25) is None
    assert crypto_engine.normalize_recovery_key(key[:-1]) is None
    assert crypto_engine.derive_recovery_kek("not a key", b"s" * 32) is None


def test_unwrap_rejects_the_wrong_key():
    data_key = crypto_engine.new_data_key()
    wrapped = crypto_engine.wrap_key(data_key, b"k" * 32)
    assert crypto_engine.unwrap_key(wrapped, b"k" * 32) == data_key
    assert crypto_engine.unwrap_key(wrapped, b"x" * 32) is None
    assert crypto_engine.unwrap_key(b"garbage", b"k" * 32) is None


# ── Enable, unlock, change, disable ─────────────────────────────────

def test_enable_returns_a_recovery_key_that_unlocks(admin_client):
    ca_id = _create_ca(admin_client)
    recovery_key = _enable(admin_client)
    assert KEY_PATTERN.match(recovery_key)
    assert crypto_engine.is_column_encrypted(_raw_ca_key())
    status = admin_client.get("/api/settings/encryption").get_json()
    assert status["recovery_key"] is True
    # the data key is random: it is not the password-derived key
    salt = db.get_setting("encryption_salt")
    assert db.derive_key_if_valid(ENCRYPTION_PASSWORD) != crypto_engine.derive_master_key(ENCRYPTION_PASSWORD, salt)

    db.set_master_key(None)
    resp = _recover(admin_client, recovery_key.lower().replace("-", " "))
    assert resp.status_code == 200, resp.get_json()
    replacement = resp.get_json()["recovery_key"]
    assert replacement != recovery_key and KEY_PATTERN.match(replacement)
    assert db.is_unlocked()
    assert db.get_ca(ca_id)["key_pem"].startswith(b"-----BEGIN")

    # the new password works, the old one and the used key don't
    db.set_master_key(None)
    assert not db.unlock(ENCRYPTION_PASSWORD)
    assert db.unlock(NEW_PASSWORD)
    db.set_master_key(None)
    assert _recover(admin_client, recovery_key).get_json()["error"] == "Wrong recovery key"
    assert _recover(admin_client, replacement, "third-password").status_code == 200


def test_change_password_keeps_the_recovery_key(admin_client):
    ca_id = _create_ca(admin_client)
    recovery_key = _enable(admin_client)
    before = _raw_ca_key()
    resp = admin_client.post("/api/settings/encryption/change-password", json={
        "old_password": ENCRYPTION_PASSWORD, "new_password": NEW_PASSWORD, "confirm": NEW_PASSWORD})
    assert resp.status_code == 200
    # only the data key's wrapping changed, not the encrypted columns
    assert _raw_ca_key() == before
    db.set_master_key(None)
    assert _recover(admin_client, recovery_key, "after-change-pw").status_code == 200
    assert db.get_ca(ca_id)["key_pem"].startswith(b"-----BEGIN")


def test_disable_clears_every_key_setting(admin_client):
    _create_ca(admin_client)
    _enable(admin_client)
    resp = admin_client.post("/api/settings/encryption/disable", json={"password": ENCRYPTION_PASSWORD})
    assert resp.status_code == 200
    assert _raw_ca_key().startswith(b"-----BEGIN")
    for name in db._KEY_SETTINGS:
        assert db.get_setting(name) is None, name
    assert admin_client.get("/api/settings/encryption").get_json()["recovery_key"] is False


def test_wrong_input_is_rejected_and_rate_limited(admin_client):
    _enable(admin_client)
    db.set_master_key(None)
    assert _recover(admin_client, "").get_json()["error"] == "Recovery key is required"
    assert _recover(admin_client, crypto_engine.generate_recovery_key(), "short").get_json()["error"] \
        == "Password must be at least 8 characters"
    for _ in range(5):
        assert _recover(admin_client, crypto_engine.generate_recovery_key()).status_code == 400
    assert _recover(admin_client, crypto_engine.generate_recovery_key()).status_code == 429
    assert not db.is_unlocked()


# ── Creating and replacing the key ──────────────────────────────────

def test_replacing_the_key_needs_the_password_and_revokes_the_old_one(admin_client):
    old_key = _enable(admin_client)
    resp = admin_client.post("/api/settings/encryption/recovery-key", json={})
    assert resp.get_json()["error"] == "Password is required to replace the recovery key"
    resp = admin_client.post("/api/settings/encryption/recovery-key", json={"password": "wrong-password"})
    assert resp.get_json()["error"] == "Wrong password"
    resp = admin_client.post("/api/settings/encryption/recovery-key", json={"password": ENCRYPTION_PASSWORD})
    assert resp.status_code == 200
    new_key = resp.get_json()["recovery_key"]
    db.set_master_key(None)
    assert db.key_for_recovery_key(old_key) is None
    assert db.key_for_recovery_key(new_key) is not None


def test_recovery_key_endpoint_needs_recent_sign_in(admin_client):
    _enable(admin_client)
    with admin_client.session_transaction() as sess:
        sess.pop("reauth_at", None)
    resp = admin_client.post("/api/settings/encryption/recovery-key", json={"password": ENCRYPTION_PASSWORD})
    assert resp.status_code == 403 and resp.get_json()["reauth_required"] is True


# ── Databases encrypted before 2.6.0 ────────────────────────────────

def _make_legacy(client) -> int:
    """An encrypted database as 2.5.0 wrote it: column key derived straight from the password."""
    ca_id = _create_ca(client)
    salt = secrets.token_bytes(32)
    key = crypto_engine.derive_master_key(ENCRYPTION_PASSWORD, salt)
    with db._connect() as conn:
        db._reencrypt_all(conn, None, key)
        db._set_setting(conn, "encryption_salt", salt)
        db._set_setting(conn, "encryption_verify", crypto_engine.encrypt_column(db._VERIFY_PLAINTEXT, key))
    db.set_master_key(None)
    return ca_id


def test_legacy_database_upgrades_on_unlock_then_gets_a_key(admin_client):
    ca_id = _make_legacy(admin_client)
    legacy_raw = _raw_ca_key()
    status = admin_client.get("/api/settings/encryption").get_json()
    assert status["enabled"] and not status["unlocked"] and status["recovery_key"] is False

    resp = admin_client.post("/api/settings/encryption/unlock", json={"password": ENCRYPTION_PASSWORD})
    assert resp.status_code == 200
    assert db.get_setting("encryption_verify") is None
    assert db.get_setting("encryption_wrapped_key") is not None
    assert _raw_ca_key() != legacy_raw  # re-encrypted under the new data key
    assert db.get_ca(ca_id)["key_pem"].startswith(b"-----BEGIN")
    assert admin_client.get("/api/settings/encryption").get_json()["recovery_key"] is False

    # the first key needs no password: the database is already unlocked
    resp = admin_client.post("/api/settings/encryption/recovery-key", json={})
    assert resp.status_code == 200
    recovery_key = resp.get_json()["recovery_key"]
    db.set_master_key(None)
    assert _recover(admin_client, recovery_key).status_code == 200
    assert db.get_ca(ca_id)["key_pem"].startswith(b"-----BEGIN")


def test_legacy_database_password_change_and_disable(admin_client):
    ca_id = _make_legacy(admin_client)
    db.change_password(ENCRYPTION_PASSWORD, NEW_PASSWORD)
    db.set_master_key(None)
    assert db.unlock(NEW_PASSWORD)
    assert db.get_ca(ca_id)["key_pem"].startswith(b"-----BEGIN")

    # disabling straight from the legacy format, with no unlock in between
    db.disable_encryption(NEW_PASSWORD)
    _make_legacy(admin_client)
    db.disable_encryption(ENCRYPTION_PASSWORD)
    with sqlite3.connect(db.DB_PATH) as conn:
        rows = conn.execute("SELECT key_pem FROM certificate_authorities").fetchall()
    assert all(r[0].startswith(b"-----BEGIN") for r in rows)


def test_locked_database_cannot_mint_a_first_key(admin_client):
    _make_legacy(admin_client)
    resp = admin_client.post("/api/settings/encryption/recovery-key", json={})
    assert resp.get_json()["error"] == "Encryption is not enabled"


# ── MFA sign-in while locked ────────────────────────────────────────

def test_mfa_sign_in_with_the_recovery_key(admin_client, fresh_app):
    secret = _enable_mfa(admin_client)
    ca_id = _create_ca(admin_client)
    recovery_key = _enable(admin_client)
    db.set_master_key(None)

    browser = fresh_app.test_client()
    assert login(browser).headers["Location"] == "/mfa"
    code = pyotp.TOTP(secret).now()
    resp = browser.post("/mfa", data={"code": code, "recovery_key": recovery_key, "new_password": "short",
                                      "confirm_password": "short"})
    assert b"Password must be at least 8 characters" in resp.data
    resp = browser.post("/mfa", data={"code": code, "recovery_key": crypto_engine.generate_recovery_key(),
                                      "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
    assert b"Invalid recovery key" in resp.data
    resp = browser.post("/mfa", data={"code": "000000", "recovery_key": recovery_key,
                                      "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
    assert b"Invalid verification code" in resp.data
    assert not db.is_unlocked()
    # nothing changed by the failed attempts: the old password still works
    assert db.derive_key_if_valid(ENCRYPTION_PASSWORD) is not None

    resp = browser.post("/mfa", data={"code": code, "recovery_key": recovery_key,
                                      "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "no-store"
    shown = re.search(rb'class="recovery-key">([^<]+)<', resp.data).group(1).decode()
    assert KEY_PATTERN.match(shown) and shown != recovery_key
    assert db.is_unlocked()
    assert db.get_ca(ca_id)["key_pem"].startswith(b"-----BEGIN")
    assert db.derive_key_if_valid(ENCRYPTION_PASSWORD) is None
    assert db.derive_key_if_valid(NEW_PASSWORD) is not None
    assert db.key_for_recovery_key(shown) is not None


def test_mfa_sign_in_upgrades_a_legacy_database(admin_client, fresh_app):
    secret = _enable_mfa(admin_client)
    ca_id = _make_legacy(admin_client)
    browser = fresh_app.test_client()
    login(browser)
    resp = browser.post("/mfa", data={"code": pyotp.TOTP(secret).now(), "encryption_password": ENCRYPTION_PASSWORD})
    assert resp.status_code == 302
    assert db.get_setting("encryption_wrapped_key") is not None
    assert db.get_ca(ca_id)["key_pem"].startswith(b"-----BEGIN")
    assert db.get_totp_secret(db.get_user("admin")["id"]) == secret


def test_concurrent_unlocks_of_a_legacy_database_agree_on_one_key(admin_client):
    import threading

    ca_id = _make_legacy(admin_client)
    keys: list[bytes | None] = []
    threads = [threading.Thread(target=lambda: keys.append(db.open_with_password(ENCRYPTION_PASSWORD)))
               for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    final = db.derive_key_if_valid(ENCRYPTION_PASSWORD)
    assert final is not None and keys == [final] * 3
    db.set_master_key(final)
    assert db.get_ca(ca_id)["key_pem"].startswith(b"-----BEGIN")
