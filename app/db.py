from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import bcrypt as _bcrypt

from . import crypto_engine


DB_DIR = Path(os.environ.get("DB_DIR", str(Path.home() / ".cert-generator")))
DB_PATH = DB_DIR / "certs.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS certificate_authorities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_ca_id  INTEGER REFERENCES certificate_authorities(id),
    name          TEXT    NOT NULL,
    domain        TEXT    NOT NULL,
    algorithm     TEXT    NOT NULL,
    not_before    TEXT    NOT NULL,
    not_after     TEXT    NOT NULL,
    serial        TEXT    NOT NULL UNIQUE,
    cert_pem      BLOB    NOT NULL,
    key_pem       BLOB    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    algorithm       TEXT    NOT NULL,
    comment         TEXT    NOT NULL DEFAULT '',
    fingerprint     TEXT    NOT NULL,
    public_key      BLOB    NOT NULL,
    private_key     BLOB    NOT NULL,
    has_passphrase  INTEGER NOT NULL DEFAULT 0,
    imported        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value BLOB
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS trusted_devices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id       INTEGER NOT NULL REFERENCES certificate_authorities(id),
    common_name TEXT    NOT NULL,
    san_domains TEXT    NOT NULL,
    algorithm   TEXT    NOT NULL,
    template    TEXT    NOT NULL DEFAULT 'web-server',
    not_before  TEXT    NOT NULL,
    not_after   TEXT    NOT NULL,
    serial      TEXT    NOT NULL UNIQUE,
    cert_pem    BLOB    NOT NULL,
    key_pem     BLOB    NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""


def _connect() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    try:
        DB_DIR.chmod(0o700)
    except OSError:
        pass
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(certificate_authorities)").fetchall()}
        if "parent_ca_id" not in cols:
            conn.execute("ALTER TABLE certificate_authorities ADD COLUMN parent_ca_id INTEGER REFERENCES certificate_authorities(id)")
        ssh_cols = {r[1] for r in conn.execute("PRAGMA table_info(ssh_keys)").fetchall()}
        if "imported" not in ssh_cols:
            conn.execute("ALTER TABLE ssh_keys ADD COLUMN imported INTEGER NOT NULL DEFAULT 0")
        user_cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "totp_secret" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
            conn.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
            conn.execute("ALTER TABLE users ADD COLUMN require_password INTEGER NOT NULL DEFAULT 0")


_master_key: bytes | None = None


def set_master_key(key: bytes | None) -> None:
    global _master_key
    _master_key = key


def _maybe_encrypt(data: bytes) -> bytes:
    if _master_key is None or not isinstance(data, bytes):
        return data
    return crypto_engine.encrypt_column(data, _master_key)


def _maybe_decrypt(data: bytes) -> bytes:
    if not isinstance(data, bytes) or not crypto_engine.is_column_encrypted(data):
        return data
    if _master_key is None:
        raise RuntimeError("Database is encrypted but no master key is set")
    return crypto_engine.decrypt_column(data, _master_key)


def _decrypt_row(row: dict[str, Any]) -> dict[str, Any]:
    for col in ("key_pem", "private_key", "totp_secret"):
        if col in row and isinstance(row[col], bytes):
            row[col] = _maybe_decrypt(row[col])
    return row


def get_setting(key: str) -> bytes | None:
    with _connect() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None


def set_setting(key: str, value: bytes | None) -> None:
    with _connect() as conn:
        if value is None:
            conn.execute("DELETE FROM app_settings WHERE key = ?", (key,))
        else:
            conn.execute(
                "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)",
                (key, value),
            )


def is_encryption_enabled() -> bool:
    return get_setting("encryption_salt") is not None


_VERIFY_PLAINTEXT = b"cert-generator-verify-token"


def enable_encryption(password: str) -> None:
    if is_encryption_enabled():
        raise ValueError("Encryption is already enabled")
    salt = secrets.token_bytes(32)
    key = crypto_engine.derive_master_key(password, salt)
    verify_token = crypto_engine.encrypt_column(_VERIFY_PLAINTEXT, key)
    set_setting("encryption_salt", salt)
    set_setting("encryption_verify", verify_token)
    set_master_key(key)
    _encrypt_all_sensitive_columns()


def disable_encryption(password: str) -> None:
    if not is_encryption_enabled():
        raise ValueError("Encryption is not enabled")
    if not unlock(password):
        raise ValueError("Wrong password")
    _decrypt_all_sensitive_columns()
    set_setting("encryption_salt", None)
    set_setting("encryption_verify", None)
    set_master_key(None)


def unlock(password: str) -> bool:
    salt = get_setting("encryption_salt")
    if salt is None:
        return False
    verify_token = get_setting("encryption_verify")
    if verify_token is None:
        return False
    key = crypto_engine.derive_master_key(password, salt)
    try:
        result = crypto_engine.decrypt_column(verify_token, key)
        if result != _VERIFY_PLAINTEXT:
            return False
    except Exception:
        return False
    set_master_key(key)
    return True


def change_password(old_password: str, new_password: str) -> None:
    if not unlock(old_password):
        raise ValueError("Wrong current password")
    _decrypt_all_sensitive_columns()
    salt = secrets.token_bytes(32)
    key = crypto_engine.derive_master_key(new_password, salt)
    verify_token = crypto_engine.encrypt_column(_VERIFY_PLAINTEXT, key)
    set_setting("encryption_salt", salt)
    set_setting("encryption_verify", verify_token)
    set_master_key(key)
    _encrypt_all_sensitive_columns()


def _encrypt_all_sensitive_columns() -> None:
    with _connect() as conn:
        for row in conn.execute("SELECT id, key_pem FROM certificate_authorities").fetchall():
            enc = _maybe_encrypt(row[1])
            if enc != row[1]:
                conn.execute("UPDATE certificate_authorities SET key_pem = ? WHERE id = ?", (enc, row[0]))
        for row in conn.execute("SELECT id, key_pem FROM certificates").fetchall():
            enc = _maybe_encrypt(row[1])
            if enc != row[1]:
                conn.execute("UPDATE certificates SET key_pem = ? WHERE id = ?", (enc, row[0]))
        for row in conn.execute("SELECT id, private_key FROM ssh_keys").fetchall():
            enc = _maybe_encrypt(row[1])
            if enc != row[1]:
                conn.execute("UPDATE ssh_keys SET private_key = ? WHERE id = ?", (enc, row[0]))
        for row in conn.execute("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL").fetchall():
            raw = row[1].encode() if isinstance(row[1], str) else row[1]
            enc = _maybe_encrypt(raw)
            if enc != raw:
                conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (enc, row[0]))


def _decrypt_all_sensitive_columns() -> None:
    with _connect() as conn:
        for row in conn.execute("SELECT id, key_pem FROM certificate_authorities").fetchall():
            dec = _maybe_decrypt(row[1])
            if dec != row[1]:
                conn.execute("UPDATE certificate_authorities SET key_pem = ? WHERE id = ?", (dec, row[0]))
        for row in conn.execute("SELECT id, key_pem FROM certificates").fetchall():
            dec = _maybe_decrypt(row[1])
            if dec != row[1]:
                conn.execute("UPDATE certificates SET key_pem = ? WHERE id = ?", (dec, row[0]))
        for row in conn.execute("SELECT id, private_key FROM ssh_keys").fetchall():
            dec = _maybe_decrypt(row[1])
            if dec != row[1]:
                conn.execute("UPDATE ssh_keys SET private_key = ? WHERE id = ?", (dec, row[0]))
        for row in conn.execute("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL").fetchall():
            val = row[1]
            if isinstance(val, bytes):
                dec = _maybe_decrypt(val)
                if dec != val:
                    conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (dec.decode(), row[0]))


def save_ca(
    name: str,
    domain: str,
    algorithm: str,
    not_before: str,
    not_after: str,
    serial: str,
    cert_pem: bytes,
    key_pem: bytes,
    parent_ca_id: int | None = None,
) -> int:
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO certificate_authorities
               (parent_ca_id, name, domain, algorithm, not_before, not_after, serial, cert_pem, key_pem)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (parent_ca_id, name, domain, algorithm, not_before, not_after, serial, cert_pem, _maybe_encrypt(key_pem)),
        )
        return cursor.lastrowid


def list_cas() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, parent_ca_id, name, domain, algorithm, not_before, not_after, serial, created_at "
            "FROM certificate_authorities ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_ca(ca_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)
        ).fetchone()
        return _decrypt_row(dict(row)) if row else None


def delete_ca(ca_id: int) -> bool:
    with _connect() as conn:
        child_ids = [r[0] for r in conn.execute(
            "SELECT id FROM certificate_authorities WHERE parent_ca_id = ?", (ca_id,)
        ).fetchall()]
        for child_id in child_ids:
            conn.execute("DELETE FROM certificates WHERE ca_id = ?", (child_id,))
            conn.execute("DELETE FROM certificate_authorities WHERE id = ?", (child_id,))
        conn.execute("DELETE FROM certificates WHERE ca_id = ?", (ca_id,))
        cursor = conn.execute("DELETE FROM certificate_authorities WHERE id = ?", (ca_id,))
        return cursor.rowcount > 0


def save_cert(
    ca_id: int,
    common_name: str,
    san_domains: str,
    algorithm: str,
    template: str,
    not_before: str,
    not_after: str,
    serial: str,
    cert_pem: bytes,
    key_pem: bytes,
) -> int:
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO certificates
               (ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, cert_pem, key_pem)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, cert_pem, _maybe_encrypt(key_pem)),
        )
        return cursor.lastrowid


def list_certs(ca_id: int | None = None) -> list[dict[str, Any]]:
    with _connect() as conn:
        if ca_id is not None:
            rows = conn.execute(
                "SELECT id, ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, revoked, created_at "
                "FROM certificates WHERE ca_id = ? ORDER BY created_at DESC",
                (ca_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, revoked, created_at "
                "FROM certificates ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]


def get_cert(cert_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
        return _decrypt_row(dict(row)) if row else None


def revoke_cert(cert_id: int) -> bool:
    with _connect() as conn:
        cursor = conn.execute(
            "UPDATE certificates SET revoked = 1 WHERE id = ? AND revoked = 0",
            (cert_id,),
        )
        return cursor.rowcount > 0


def list_revoked_serials(ca_id: int) -> list[tuple[str, str]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT serial, created_at FROM certificates WHERE ca_id = ? AND revoked = 1",
            (ca_id,),
        ).fetchall()
        return [(r["serial"], r["created_at"]) for r in rows]


def delete_cert(cert_id: int) -> bool:
    with _connect() as conn:
        cursor = conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
        return cursor.rowcount > 0


def save_ssh_key(
    name: str,
    algorithm: str,
    comment: str,
    fingerprint: str,
    public_key: bytes,
    private_key: bytes,
    has_passphrase: bool,
    imported: bool = False,
) -> int:
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO ssh_keys
               (name, algorithm, comment, fingerprint, public_key, private_key, has_passphrase, imported)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, algorithm, comment, fingerprint, public_key, _maybe_encrypt(private_key), int(has_passphrase), int(imported)),
        )
        return cursor.lastrowid


def list_ssh_keys() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, name, algorithm, comment, fingerprint, has_passphrase, imported, created_at "
            "FROM ssh_keys ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_ssh_key(key_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM ssh_keys WHERE id = ?", (key_id,)
        ).fetchone()
        return _decrypt_row(dict(row)) if row else None


def delete_ssh_key(key_id: int) -> bool:
    with _connect() as conn:
        cursor = conn.execute("DELETE FROM ssh_keys WHERE id = ?", (key_id,))
        return cursor.rowcount > 0


_BLOB_COLUMNS = {"cert_pem", "key_pem", "public_key", "private_key"}


def _row_to_exportable(row: sqlite3.Row) -> dict[str, Any]:
    d = _decrypt_row(dict(row))
    for col in _BLOB_COLUMNS:
        if col in d and isinstance(d[col], bytes):
            d[col] = base64.b64encode(d[col]).decode("ascii")
    return d


def _decode_blobs(row: dict[str, Any]) -> dict[str, Any]:
    for col in _BLOB_COLUMNS:
        if col in row and isinstance(row[col], str):
            row[col] = base64.b64decode(row[col])
    return row


def export_all_data() -> dict[str, Any]:
    with _connect() as conn:
        cas = [_row_to_exportable(r) for r in conn.execute(
            "SELECT * FROM certificate_authorities ORDER BY id").fetchall()]
        certs = [_row_to_exportable(r) for r in conn.execute(
            "SELECT * FROM certificates ORDER BY id").fetchall()]
        ssh_keys = [_row_to_exportable(r) for r in conn.execute(
            "SELECT * FROM ssh_keys ORDER BY id").fetchall()]
        users = []
        for r in conn.execute("SELECT id, username, password_hash, totp_secret, totp_enabled, require_password, created_at FROM users ORDER BY id").fetchall():
            u = dict(r)
            if u.get("totp_secret") and isinstance(u["totp_secret"], bytes):
                u["totp_secret"] = _maybe_decrypt(u["totp_secret"]).decode()
            users.append(u)
    return {
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "certificate_authorities": cas,
        "certificates": certs,
        "ssh_keys": ssh_keys,
        "users": users,
    }


def import_all_data(data: dict[str, Any]) -> dict[str, int]:
    if data.get("version") != 1:
        raise ValueError("Unsupported backup data version")
    with _connect() as conn:
        conn.execute("DELETE FROM certificates")
        conn.execute("DELETE FROM certificate_authorities")
        conn.execute("DELETE FROM ssh_keys")

        for ca in data.get("certificate_authorities", []):
            ca = _decode_blobs(ca)
            conn.execute(
                """INSERT INTO certificate_authorities
                   (id, parent_ca_id, name, domain, algorithm, not_before, not_after, serial, cert_pem, key_pem, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ca["id"], ca.get("parent_ca_id"), ca["name"], ca["domain"],
                 ca["algorithm"], ca["not_before"], ca["not_after"], ca["serial"],
                 ca["cert_pem"], _maybe_encrypt(ca["key_pem"]), ca["created_at"]),
            )

        for cert in data.get("certificates", []):
            cert = _decode_blobs(cert)
            conn.execute(
                """INSERT INTO certificates
                   (id, ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, cert_pem, key_pem, revoked, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (cert["id"], cert["ca_id"], cert["common_name"], cert["san_domains"],
                 cert["algorithm"], cert.get("template", "web-server"),
                 cert["not_before"], cert["not_after"], cert["serial"],
                 cert["cert_pem"], _maybe_encrypt(cert["key_pem"]), cert.get("revoked", 0),
                 cert["created_at"]),
            )

        for key in data.get("ssh_keys", []):
            key = _decode_blobs(key)
            conn.execute(
                """INSERT INTO ssh_keys
                   (id, name, algorithm, comment, fingerprint, public_key, private_key, has_passphrase, imported, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (key["id"], key["name"], key["algorithm"], key.get("comment", ""),
                 key["fingerprint"], key["public_key"], _maybe_encrypt(key["private_key"]),
                 key.get("has_passphrase", 0), key.get("imported", 0), key["created_at"]),
            )

        for user in data.get("users", []):
            secret_val = user.get("totp_secret")
            if secret_val is not None and _master_key is not None:
                secret_val = _maybe_encrypt(secret_val.encode())
            conn.execute(
                """INSERT OR REPLACE INTO users
                   (id, username, password_hash, totp_secret, totp_enabled, require_password, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user["id"], user["username"], user["password_hash"],
                 secret_val, user.get("totp_enabled", 0),
                 user.get("require_password", 0), user["created_at"]),
            )

    counts = {
        "cas": len(data.get("certificate_authorities", [])),
        "certs": len(data.get("certificates", [])),
        "ssh_keys": len(data.get("ssh_keys", [])),
        "users": len(data.get("users", [])),
    }
    return counts


def has_users() -> bool:
    with _connect() as conn:
        row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return row[0] > 0


def create_user(username: str, password: str) -> int:
    pw_hash = _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )
        return cur.lastrowid


def reset_user_password(username: str, new_password: str) -> bool:
    pw_hash = _bcrypt.hashpw(new_password.encode(), _bcrypt.gensalt()).decode()
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (pw_hash, username),
        )
        return cur.rowcount > 0


def verify_user(username: str, password: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return False
        return _bcrypt.checkpw(password.encode(), row["password_hash"].encode())


def get_user(username: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, username, totp_enabled, totp_secret, require_password FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        if d.get("totp_secret") and isinstance(d["totp_secret"], bytes):
            d["totp_secret"] = _maybe_decrypt(d["totp_secret"]).decode()
        return d


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, username, totp_enabled, totp_secret, require_password FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        if d.get("totp_secret") and isinstance(d["totp_secret"], bytes):
            d["totp_secret"] = _maybe_decrypt(d["totp_secret"]).decode()
        return d


def update_user_totp(user_id: int, totp_secret: str | None, enabled: bool) -> None:
    with _connect() as conn:
        secret_val: str | bytes | None = totp_secret
        if totp_secret is not None and _master_key is not None:
            secret_val = _maybe_encrypt(totp_secret.encode())
        conn.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?",
            (secret_val, int(enabled), user_id),
        )


def update_user_require_password(user_id: int, require_password: bool) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET require_password = ? WHERE id = ?",
            (int(require_password), user_id),
        )


def create_trusted_device(user_id: int, token_hash: str, expires_at: str) -> int:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO trusted_devices (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, token_hash, expires_at),
        )
        return cur.lastrowid


def verify_trusted_device(token_hash: str) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _connect() as conn:
        row = conn.execute(
            "SELECT td.user_id, u.username, u.require_password "
            "FROM trusted_devices td JOIN users u ON u.id = td.user_id "
            "WHERE td.token_hash = ? AND td.expires_at > ?",
            (token_hash, now),
        ).fetchone()
        return dict(row) if row else None


def delete_trusted_devices(user_id: int) -> int:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM trusted_devices WHERE user_id = ?", (user_id,))
        return cur.rowcount


def count_trusted_devices(user_id: int) -> int:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM trusted_devices WHERE user_id = ? AND expires_at > ?",
            (user_id, now),
        ).fetchone()
        return row[0]


def cleanup_expired_devices() -> int:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _connect() as conn:
        cur = conn.execute("DELETE FROM trusted_devices WHERE expires_at <= ?", (now,))
        return cur.rowcount
