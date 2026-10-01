from __future__ import annotations

import base64
import os
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import cache
from pathlib import Path
from typing import Any

import bcrypt as _bcrypt

from . import crypto_engine


DB_DIR = Path(os.environ.get("DB_DIR", str(Path.home() / ".cert-generator")))
DB_PATH = DB_DIR / "certs.db"

# bcrypt only uses the first 72 bytes. bcrypt<5 truncated silently and bcrypt>=5
# raises, so truncate explicitly to keep existing hashes verifying.
BCRYPT_MAX_BYTES = 72

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

-- Revoked certificates that were deleted. Their serials stay on the CA's CRL
-- until the certificate would have expired, so deleting never un-revokes.
CREATE TABLE IF NOT EXISTS deleted_revocations (
    ca_id      INTEGER NOT NULL REFERENCES certificate_authorities(id),
    serial     TEXT    NOT NULL,
    revoked_at TEXT    NOT NULL,
    not_after  TEXT    NOT NULL,
    PRIMARY KEY (ca_id, serial)
);
"""

# (table, column, definition) added after the original schema shipped.
_MIGRATIONS = (
    ("certificate_authorities", "parent_ca_id", "INTEGER REFERENCES certificate_authorities(id)"),
    ("ssh_keys", "imported", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "totp_secret", "TEXT"),
    ("users", "totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "require_password", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "totp_last_step", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "session_version", "INTEGER NOT NULL DEFAULT 0"),
    ("trusted_devices", "label", "TEXT NOT NULL DEFAULT ''"),
    ("certificates", "revoked_at", "TEXT"),
    ("certificate_authorities", "crl_next_update", "TEXT"),
    ("certificate_authorities", "crl_der", "BLOB"),
    ("certificate_authorities", "crl_public", "INTEGER NOT NULL DEFAULT 0"),
    ("certificates", "crl_dp_url", "TEXT"),  # '' = none; NULL = not yet read from cert_pem
)

_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_trusted_devices_token ON trusted_devices(token_hash)",
    "CREATE INDEX IF NOT EXISTS idx_certificates_ca ON certificates(ca_id)",
    "CREATE INDEX IF NOT EXISTS idx_ca_parent ON certificate_authorities(parent_ca_id)",
)

# Columns holding private key material, encrypted when encryption is enabled.
_SENSITIVE_BLOBS = (
    ("certificate_authorities", "key_pem"),
    ("certificates", "key_pem"),
    ("ssh_keys", "private_key"),
)


class DatabaseLocked(RuntimeError):
    """Encryption is enabled but the database has not been unlocked."""


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Open a connection, commit on success, roll back on error, always close."""
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        with conn:
            yield conn
    finally:
        conn.close()


def init_db() -> None:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    try:
        DB_DIR.chmod(0o700)
    except OSError:
        pass
    with _connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
        for table, column, definition in _MIGRATIONS:
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if column not in cols:
                # Identifiers come from the constant _MIGRATIONS table, never from input.
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")  # nosec B608
        for statement in _INDEXES:
            conn.execute(statement)
        _backfill_crl_dp_urls(conn)


def _backfill_crl_dp_urls(conn: sqlite3.Connection) -> None:
    """Read the CRL distribution point out of certificates stored before it was recorded."""
    rows = conn.execute("SELECT id, cert_pem FROM certificates WHERE crl_dp_url IS NULL").fetchall()
    for row in rows:
        urls = crypto_engine.crl_distribution_points(row["cert_pem"])
        conn.execute("UPDATE certificates SET crl_dp_url = ? WHERE id = ?", (urls[0] if urls else "", row["id"]))


# ── Encryption at rest ──────────────────────────────────────────────

_master_key: bytes | None = None


def set_master_key(key: bytes | None) -> None:
    global _master_key
    _master_key = key


def is_unlocked() -> bool:
    return _master_key is not None


def _get_setting(conn: sqlite3.Connection, key: str) -> bytes | None:
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def _set_setting(conn: sqlite3.Connection, key: str, value: bytes | None) -> None:
    if value is None:
        conn.execute("DELETE FROM app_settings WHERE key = ?", (key,))
    else:
        conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", (key, value))


def get_setting(key: str) -> bytes | None:
    with _connect() as conn:
        return _get_setting(conn, key)


def set_setting(key: str, value: bytes | None) -> None:
    with _connect() as conn:
        _set_setting(conn, key, value)


def is_encryption_enabled() -> bool:
    return get_setting("encryption_salt") is not None


def require_unlocked() -> None:
    """Raise DatabaseLocked if encryption is enabled and no key is loaded."""
    if _master_key is None and is_encryption_enabled():
        raise DatabaseLocked("Database is locked. Unlock it with your encryption password.")


def _maybe_encrypt(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        return data
    if _master_key is None:
        # Fail closed: never write plaintext keys into an encrypted database.
        require_unlocked()
        return data
    return crypto_engine.encrypt_column(data, _master_key)


def _decrypt_with(data: bytes, key: bytes | None) -> bytes:
    if not crypto_engine.is_column_encrypted(data):
        return data
    if key is None:
        raise DatabaseLocked("Database is locked. Unlock it with your encryption password.")
    return crypto_engine.decrypt_column(data, key)


def _maybe_decrypt(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        return data
    return _decrypt_with(data, _master_key)


def _decrypt_row(row: dict[str, Any]) -> dict[str, Any]:
    for col in ("key_pem", "private_key"):
        if col in row and isinstance(row[col], bytes):
            row[col] = _maybe_decrypt(row[col])
    return row


_VERIFY_PLAINTEXT = b"cert-generator-verify-token"

# Before 2.6.0 the column key was derived straight from the password and
# checked with ``encryption_verify``. Since then the columns use a random data
# key, stored wrapped by the password and by the recovery key.
_KEY_SETTINGS = (
    "encryption_salt", "encryption_verify", "encryption_wrapped_key",
    "recovery_salt", "recovery_wrapped_key", "login_username",
)


@contextmanager
def _key_change() -> Iterator[sqlite3.Connection]:
    """A connection holding SQLite's write lock from the start.

    Every change to the key settings reads them and then rewrites them;
    taking the lock before the read stops two requests (two unlocks
    migrating the same pre-2.6.0 database, say) from interleaving.
    """
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        yield conn


def _key_for_password(conn: sqlite3.Connection, password: str) -> tuple[bytes | None, bool]:
    """(column key, still on the pre-2.6.0 format); the key is None if ``password`` is wrong."""
    salt = _get_setting(conn, "encryption_salt")
    if salt is None:
        return None, False
    kek = crypto_engine.derive_master_key(password, salt)
    wrapped = _get_setting(conn, "encryption_wrapped_key")
    if wrapped is not None:
        return crypto_engine.unwrap_key(wrapped, kek), False
    verify_token = _get_setting(conn, "encryption_verify")
    try:
        valid = verify_token is not None and crypto_engine.decrypt_column(verify_token, kek) == _VERIFY_PLAINTEXT
    except Exception:
        valid = False
    return (kek if valid else None), True


def derive_key_if_valid(password: str) -> bytes | None:
    """Return the column key for ``password`` without loading it, or None if wrong."""
    with _connect() as conn:
        return _key_for_password(conn, password)[0]


def _reencrypt_all(conn: sqlite3.Connection, old_key: bytes | None, new_key: bytes | None) -> None:
    """Rewrite every sensitive value from ``old_key`` to ``new_key`` (None = plaintext)."""
    for table, column in _SENSITIVE_BLOBS:
        # Identifiers come from the constant _SENSITIVE_BLOBS table, never from input.
        for row_id, value in conn.execute(f"SELECT id, {column} FROM {table}").fetchall():  # nosec B608
            plain = _decrypt_with(value, old_key)
            new_value = crypto_engine.encrypt_column(plain, new_key) if new_key else plain
            if new_value != value:
                conn.execute(f"UPDATE {table} SET {column} = ? WHERE id = ?", (new_value, row_id))  # nosec B608
    rows = conn.execute("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL").fetchall()
    for row_id, value in rows:
        raw = value.encode() if isinstance(value, str) else value
        plain = _decrypt_with(raw, old_key)
        new_value: str | bytes = crypto_engine.encrypt_column(plain, new_key) if new_key else plain.decode()
        if new_value != value:
            conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (new_value, row_id))


def _store_password_wrap(conn: sqlite3.Connection, password: str, data_key: bytes) -> None:
    salt = secrets.token_bytes(32)
    kek = crypto_engine.derive_master_key(password, salt)
    _set_setting(conn, "encryption_salt", salt)
    _set_setting(conn, "encryption_wrapped_key", crypto_engine.wrap_key(data_key, kek))
    _set_setting(conn, "encryption_verify", None)


def _store_recovery_wrap(conn: sqlite3.Connection, data_key: bytes) -> str:
    """Wrap ``data_key`` under a new recovery key, replacing any old one, and return it."""
    recovery_key = crypto_engine.generate_recovery_key()
    salt = secrets.token_bytes(32)
    kek = crypto_engine.derive_recovery_kek(recovery_key, salt)
    if kek is None:
        raise RuntimeError("Generated recovery key failed validation")
    _set_setting(conn, "recovery_salt", salt)
    _set_setting(conn, "recovery_wrapped_key", crypto_engine.wrap_key(data_key, kek))
    return recovery_key


def _open_with_password(conn: sqlite3.Connection, password: str) -> bytes | None:
    """Column key for ``password``, moving a pre-2.6.0 database to a data key on the way."""
    key, legacy = _key_for_password(conn, password)
    if key is None or not legacy:
        return key
    data_key = crypto_engine.new_data_key()
    _reencrypt_all(conn, key, data_key)
    _store_password_wrap(conn, password, data_key)
    return data_key


def open_with_password(password: str) -> bytes | None:
    """Like derive_key_if_valid, but upgrades a pre-2.6.0 database first."""
    with _key_change() as conn:
        return _open_with_password(conn, password)


def has_recovery_key() -> bool:
    return get_setting("recovery_wrapped_key") is not None


def get_login_username() -> str | None:
    """The desktop sign-in name set alongside the master password, if any."""
    value = get_setting("login_username")
    return value.decode("utf-8") if value else None


def enable_encryption(password: str, username: str | None = None) -> str:
    """Encrypt every sensitive column and return the recovery key, to be shown once.

    ``username`` (desktop app) turns the startup unlock into a sign-in: the name is
    asked for with the master password. It is not secret and is stored as is.
    """
    if is_encryption_enabled():
        raise ValueError("Encryption is already enabled")
    data_key = crypto_engine.new_data_key()
    with _key_change() as conn:
        if _get_setting(conn, "encryption_salt") is not None:
            raise ValueError("Encryption is already enabled")
        _reencrypt_all(conn, None, data_key)
        _store_password_wrap(conn, password, data_key)
        recovery_key = _store_recovery_wrap(conn, data_key)
        if username:
            _set_setting(conn, "login_username", username.encode("utf-8"))
    set_master_key(data_key)
    return recovery_key


def disable_encryption(password: str) -> None:
    if not is_encryption_enabled():
        raise ValueError("Encryption is not enabled")
    with _key_change() as conn:
        key = _key_for_password(conn, password)[0]
        if key is None:
            raise ValueError("Wrong password")
        _reencrypt_all(conn, key, None)
        for name in _KEY_SETTINGS:
            _set_setting(conn, name, None)
    set_master_key(None)


def unlock(password: str) -> bool:
    return unlock_if(password, True)


def unlock_if(password: str, allowed: bool) -> bool:
    """Unlock with ``password`` only when ``allowed`` (a sign-in name matched).

    The password is checked either way, so a wrong name takes as long as a wrong password.
    """
    key = open_with_password(password)
    if key is None or not allowed:
        return False
    set_master_key(key)
    return True


def change_password(old_password: str, new_password: str) -> None:
    """Re-wrap the data key under ``new_password``; the recovery key stays valid."""
    with _key_change() as conn:
        key = _open_with_password(conn, old_password)
        if key is None:
            raise ValueError("Wrong current password")
        _store_password_wrap(conn, new_password, key)
    set_master_key(key)


def create_recovery_key(password: str | None) -> str:
    """Issue a new recovery key, revoking any earlier one, and return it.

    Replacing an existing key needs the master password. The first one only
    needs the database to be unlocked, so an upgraded database can get one
    right after the unlock that upgraded it.
    """
    with _key_change() as conn:
        if _get_setting(conn, "encryption_wrapped_key") is None:
            raise ValueError("Encryption is not enabled")
        if _get_setting(conn, "recovery_wrapped_key") is None:
            key = _master_key
            if key is None:
                raise DatabaseLocked("Database is locked. Unlock it with your encryption password.")
        else:
            if not password:
                raise ValueError("Password is required to replace the recovery key")
            key = _key_for_password(conn, password)[0]
            if key is None:
                raise ValueError("Wrong password")
        return _store_recovery_wrap(conn, key)


def _key_for_recovery_key(conn: sqlite3.Connection, recovery_key: str) -> bytes | None:
    salt = _get_setting(conn, "recovery_salt")
    wrapped = _get_setting(conn, "recovery_wrapped_key")
    if salt is None or wrapped is None:
        return None
    kek = crypto_engine.derive_recovery_kek(recovery_key, salt)
    return crypto_engine.unwrap_key(wrapped, kek) if kek else None


def key_for_recovery_key(recovery_key: str) -> bytes | None:
    """Return the column key for ``recovery_key`` without loading it, or None if wrong."""
    with _connect() as conn:
        return _key_for_recovery_key(conn, recovery_key)


def recover_with_key(recovery_key: str, new_password: str) -> str:
    """Unlock with the recovery key, set ``new_password``, and return a new recovery key.

    The used key is revoked: it has been typed out, so it may have been seen.
    """
    with _key_change() as conn:
        if _get_setting(conn, "recovery_wrapped_key") is None:
            raise ValueError("This database has no recovery key")
        key = _key_for_recovery_key(conn, recovery_key)
        if key is None:
            raise ValueError("Wrong recovery key")
        _store_password_wrap(conn, new_password, key)
        new_recovery_key = _store_recovery_wrap(conn, key)
    set_master_key(key)
    return new_recovery_key


# ── Certificate authorities and certificates ───────────────────────

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
    encrypted_key = _maybe_encrypt(key_pem)
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO certificate_authorities
               (parent_ca_id, name, domain, algorithm, not_before, not_after, serial, cert_pem, key_pem)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (parent_ca_id, name, domain, algorithm, not_before, not_after, serial, cert_pem, encrypted_key),
        )
        return cursor.lastrowid


def list_cas() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, parent_ca_id, name, domain, algorithm, not_before, not_after, serial, created_at "
            "FROM certificate_authorities ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def list_child_cas(ca_id: int) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, parent_ca_id, name, domain, algorithm, not_before, not_after, serial, created_at "
            "FROM certificate_authorities WHERE parent_ca_id = ? ORDER BY created_at DESC",
            (ca_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_ca_summary(ca_id: int) -> dict[str, Any] | None:
    """id, name, domain and CRL state, without the key: readable while locked."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, name, domain, crl_public, crl_next_update FROM certificate_authorities WHERE id = ?", (ca_id,),
        ).fetchone()
        return dict(row) if row else None


def get_ca(ca_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)
        ).fetchone()
        return _decrypt_row(dict(row)) if row else None


def set_ca_crl_next_update(ca_id: int, next_update: str) -> None:
    """Next update of the CRL last exported for offline import."""
    with _connect() as conn:
        conn.execute("UPDATE certificate_authorities SET crl_next_update = ? WHERE id = ?", (next_update, ca_id))


def publish_crl(ca_id: int, crl_der: bytes) -> None:
    """Replace the CRL that /crl/<id>.crl serves (see crl_publisher)."""
    with _connect() as conn:
        conn.execute("UPDATE certificate_authorities SET crl_der = ? WHERE id = ?", (crl_der, ca_id))


def set_crl_public(ca_id: int) -> None:
    """Opt the CA in to /crl/<id>.crl: a certificate now names this server as its distribution point."""
    with _connect() as conn:
        conn.execute("UPDATE certificate_authorities SET crl_public = 1 WHERE id = ?", (ca_id,))


def is_crl_public(ca_id: int) -> bool:
    with _connect() as conn:
        row = conn.execute("SELECT crl_public FROM certificate_authorities WHERE id = ?", (ca_id,)).fetchone()
        return bool(row and row["crl_public"])


def list_public_crls() -> list[tuple[int, bytes | None]]:
    """(CA id, served CRL or None) for every CA that opted in to /crl/<id>.crl."""
    with _connect() as conn:
        rows = conn.execute("SELECT id, crl_der FROM certificate_authorities WHERE crl_public = 1").fetchall()
        return [(r["id"], r["crl_der"]) for r in rows]


def get_published_crl(ca_id: int) -> bytes | None:
    """The served CRL of a CA that opted in (public, never encrypted), readable while the
    database is locked. None for any other CA, so ids can't be probed."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT crl_der FROM certificate_authorities WHERE id = ? AND crl_public = 1", (ca_id,),
        ).fetchone()
        return row["crl_der"] if row else None


def get_ca_cert_chain(ca_id: int, max_depth: int = 16) -> list[bytes]:
    """Certificates from ``ca_id`` up to its root, nearest first."""
    chain: list[bytes] = []
    seen: set[int] = set()
    current: int | None = ca_id
    with _connect() as conn:
        while current is not None and current not in seen and len(chain) < max_depth:
            seen.add(current)
            row = conn.execute(
                "SELECT cert_pem, parent_ca_id FROM certificate_authorities WHERE id = ?", (current,)
            ).fetchone()
            if row is None:
                break
            chain.append(row["cert_pem"])
            current = row["parent_ca_id"]
    return chain


def delete_ca(ca_id: int) -> bool:
    """Delete a CA with every descendant CA and all their certificates."""
    with _connect() as conn:
        ids = [r[0] for r in conn.execute(
            """WITH RECURSIVE tree(id) AS (
                   SELECT id FROM certificate_authorities WHERE id = ?
                   UNION ALL
                   SELECT c.id FROM certificate_authorities c JOIN tree t ON c.parent_ca_id = t.id
               )
               SELECT id FROM tree""",
            (ca_id,),
        ).fetchall()]
        if not ids:
            return False
        # Descendants are discovered after their parents; delete in reverse.
        for node_id in reversed(ids):
            conn.execute("DELETE FROM certificates WHERE ca_id = ?", (node_id,))
            conn.execute("DELETE FROM deleted_revocations WHERE ca_id = ?", (node_id,))
            conn.execute("DELETE FROM certificate_authorities WHERE id = ?", (node_id,))
        return True


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
    crl_dp_url: str | None = None,
) -> int:
    encrypted_key = _maybe_encrypt(key_pem)
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO certificates
               (ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, cert_pem, key_pem,
                crl_dp_url)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, cert_pem, encrypted_key,
             crl_dp_url or ""),
        )
        return cursor.lastrowid


_CERT_LIST_COLUMNS = (
    "id, ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, revoked, created_at, "
    "crl_dp_url"
)


def list_certs(ca_id: int | None = None) -> list[dict[str, Any]]:
    with _connect() as conn:
        if ca_id is not None:
            rows = conn.execute(
                f"SELECT {_CERT_LIST_COLUMNS} FROM certificates WHERE ca_id = ? ORDER BY created_at DESC",  # nosec B608 - constant column list
                (ca_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT {_CERT_LIST_COLUMNS} FROM certificates ORDER BY created_at DESC"  # nosec B608 - constant column list
            ).fetchall()
        return [dict(r) for r in rows]


def get_cert_summary(cert_id: int) -> dict[str, Any] | None:
    """The certificate's listing columns, without its key: readable while locked."""
    with _connect() as conn:
        row = conn.execute(f"SELECT {_CERT_LIST_COLUMNS} FROM certificates WHERE id = ?", (cert_id,)).fetchone()  # nosec B608 - constant column list
        return dict(row) if row else None


def get_cert(cert_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
        return _decrypt_row(dict(row)) if row else None


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def revoke_cert(cert_id: int) -> bool:
    with _connect() as conn:
        cursor = conn.execute(
            "UPDATE certificates SET revoked = 1, revoked_at = ? WHERE id = ? AND revoked = 0",
            (_utc_now(), cert_id),
        )
        return cursor.rowcount > 0


def list_revoked_serials(ca_id: int) -> list[tuple[str, str]]:
    """(serial, revocation time) for the CA's CRL: revoked certificates, plus deleted
    revoked ones until their expiry. Certificates revoked before revoked_at existed
    use their issue time."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT serial, COALESCE(revoked_at, created_at) AS revoked_at "
            "FROM certificates WHERE ca_id = ? AND revoked = 1 "
            "UNION ALL "
            "SELECT serial, revoked_at FROM deleted_revocations "
            "WHERE ca_id = ? AND julianday(not_after) > julianday('now')",
            (ca_id, ca_id),
        ).fetchall()
        return [(r["serial"], r["revoked_at"]) for r in rows]


def list_deleted_revocations(ca_id: int) -> set[str]:
    """Serials on the CA's CRL whose certificate has been deleted."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT serial FROM deleted_revocations WHERE ca_id = ? AND julianday(not_after) > julianday('now')",
            (ca_id,),
        ).fetchall()
        return {r["serial"] for r in rows}


def delete_cert(cert_id: int) -> bool:
    """Delete a certificate. A revoked one stays on its CA's CRL until it expires."""
    with _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO deleted_revocations (ca_id, serial, revoked_at, not_after) "
            "SELECT ca_id, serial, COALESCE(revoked_at, created_at), not_after "
            "FROM certificates WHERE id = ? AND revoked = 1",
            (cert_id,),
        )
        cursor = conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
        return cursor.rowcount > 0


# ── SSH keys ────────────────────────────────────────────────────────

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
    encrypted_key = _maybe_encrypt(private_key)
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO ssh_keys
               (name, algorithm, comment, fingerprint, public_key, private_key, has_passphrase, imported)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, algorithm, comment, fingerprint, public_key, encrypted_key, int(has_passphrase), int(imported)),
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


# ── Backup and restore ──────────────────────────────────────────────

_BLOB_COLUMNS = {"cert_pem", "key_pem", "public_key", "private_key", "crl_der"}


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
    require_unlocked()
    with _connect() as conn:
        cas = [_row_to_exportable(r) for r in conn.execute(
            "SELECT * FROM certificate_authorities ORDER BY id").fetchall()]
        certs = [_row_to_exportable(r) for r in conn.execute(
            "SELECT * FROM certificates ORDER BY id").fetchall()]
        ssh_keys = [_row_to_exportable(r) for r in conn.execute(
            "SELECT * FROM ssh_keys ORDER BY id").fetchall()]
        deleted_revocations = [dict(r) for r in conn.execute(
            "SELECT * FROM deleted_revocations ORDER BY ca_id, serial").fetchall()]
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
        "deleted_revocations": deleted_revocations,
        "users": users,
    }


def _import_rows(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = data.get(key, [])
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise ValueError(f"Invalid backup data: '{key}' must be a list of objects")
    return rows


def _restore_cas(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> None:
    for ca in rows:
        ca = _decode_blobs(ca)
        conn.execute(
            """INSERT INTO certificate_authorities
               (id, parent_ca_id, name, domain, algorithm, not_before, not_after, serial, cert_pem, key_pem, created_at,
                crl_next_update, crl_der, crl_public)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ca["id"], ca.get("parent_ca_id"), ca["name"], ca["domain"],
             ca["algorithm"], ca["not_before"], ca["not_after"], ca["serial"],
             ca["cert_pem"], _maybe_encrypt(ca["key_pem"]), ca["created_at"],
             ca.get("crl_next_update"), ca.get("crl_der"), int(bool(ca.get("crl_public")))),
        )


def _restore_certs(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> None:
    for cert in rows:
        cert = _decode_blobs(cert)
        conn.execute(
            """INSERT INTO certificates
               (id, ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial,
                cert_pem, key_pem, revoked, revoked_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (cert["id"], cert["ca_id"], cert["common_name"], cert["san_domains"],
             cert["algorithm"], cert.get("template", "web-server"),
             cert["not_before"], cert["not_after"], cert["serial"],
             cert["cert_pem"], _maybe_encrypt(cert["key_pem"]), cert.get("revoked", 0),
             cert.get("revoked_at"), cert["created_at"]),
        )


def _restore_ssh_keys(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> None:
    for key in rows:
        key = _decode_blobs(key)
        conn.execute(
            """INSERT INTO ssh_keys
               (id, name, algorithm, comment, fingerprint, public_key, private_key, has_passphrase, imported, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (key["id"], key["name"], key["algorithm"], key.get("comment", ""),
             key["fingerprint"], key["public_key"], _maybe_encrypt(key["private_key"]),
             key.get("has_passphrase", 0), key.get("imported", 0), key["created_at"]),
        )


def _restore_users(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> None:
    for user in rows:
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
    # Restored credentials may differ from the current ones: end all sessions.
    conn.execute("UPDATE users SET session_version = session_version + 1")


def import_all_data(data: dict[str, Any]) -> dict[str, int]:
    if data.get("version") != 1:
        raise ValueError("Unsupported backup data version")
    require_unlocked()
    cas = _import_rows(data, "certificate_authorities")
    certs = _import_rows(data, "certificates")
    ssh_keys = _import_rows(data, "ssh_keys")
    users = _import_rows(data, "users")
    deleted_revocations = _import_rows(data, "deleted_revocations")  # absent in older backups
    try:
        with _connect() as conn:
            conn.execute("DELETE FROM certificates")
            conn.execute("DELETE FROM deleted_revocations")
            conn.execute("DELETE FROM certificate_authorities")
            conn.execute("DELETE FROM ssh_keys")
            _restore_cas(conn, cas)
            _restore_certs(conn, certs)
            _backfill_crl_dp_urls(conn)
            for row in deleted_revocations:
                conn.execute(
                    "INSERT INTO deleted_revocations (ca_id, serial, revoked_at, not_after) VALUES (?, ?, ?, ?)",
                    (row["ca_id"], row["serial"], row["revoked_at"], row["not_after"]),
                )
            _restore_ssh_keys(conn, ssh_keys)
            _restore_users(conn, users)
    except (KeyError, TypeError, AttributeError, sqlite3.IntegrityError, ValueError) as e:
        raise ValueError(f"Invalid backup data: {e}") from e
    return {"cas": len(cas), "certs": len(certs), "ssh_keys": len(ssh_keys), "users": len(users)}


# ── Users and authentication ────────────────────────────────────────

def _password_bytes(password: str) -> bytes:
    return password.encode("utf-8")[:BCRYPT_MAX_BYTES]


def password_too_long(password: str) -> bool:
    return len(password.encode("utf-8")) > BCRYPT_MAX_BYTES


def _hash_password(password: str) -> str:
    return _bcrypt.hashpw(_password_bytes(password), _bcrypt.gensalt()).decode()


@cache
def _dummy_hash() -> bytes:
    return _bcrypt.hashpw(b"timing-equalizer", _bcrypt.gensalt())


def has_users() -> bool:
    with _connect() as conn:
        row = conn.execute("SELECT EXISTS (SELECT 1 FROM users)").fetchone()
        return bool(row[0])


def create_user(username: str, password: str) -> int:
    pw_hash = _hash_password(password)
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )
        return cur.lastrowid


def create_first_user(username: str, password: str) -> bool:
    """Create the initial admin atomically; False if any user already exists."""
    pw_hash = _hash_password(password)
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash) "
            "SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)",
            (username, pw_hash),
        )
        return cur.rowcount > 0


def reset_user_password(username: str, new_password: str) -> bool:
    """Set a new password, end every session, and forget trusted devices."""
    pw_hash = _hash_password(new_password)
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE username = ?",
            (pw_hash, username),
        )
        if cur.rowcount == 0:
            return False
        conn.execute(
            "DELETE FROM trusted_devices WHERE user_id = (SELECT id FROM users WHERE username = ?)",
            (username,),
        )
        return True


def verify_user(username: str, password: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    if row is None:
        # Spend the same bcrypt time so response timing doesn't reveal valid usernames.
        _bcrypt.checkpw(_password_bytes(password), _dummy_hash())
        return False
    return _bcrypt.checkpw(_password_bytes(password), row["password_hash"].encode())


_USER_COLUMNS = "id, username, totp_enabled, require_password, totp_last_step, session_version"


def get_user(username: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(f"SELECT {_USER_COLUMNS} FROM users WHERE username = ?", (username,)).fetchone()  # nosec B608 - constant column list
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?", (user_id,)).fetchone()  # nosec B608 - constant column list
        return dict(row) if row else None


def _raw_totp_secret(user_id: int) -> str | bytes | None:
    with _connect() as conn:
        row = conn.execute("SELECT totp_secret FROM users WHERE id = ?", (user_id,)).fetchone()
        return row[0] if row else None


def totp_secret_is_locked(user_id: int) -> bool:
    """True when the user's TOTP secret is encrypted and the database is locked."""
    raw = _raw_totp_secret(user_id)
    return _master_key is None and isinstance(raw, bytes) and crypto_engine.is_column_encrypted(raw)


def get_totp_secret(user_id: int, key: bytes | None = None) -> str | None:
    """Decrypted TOTP secret, using ``key`` or the loaded master key."""
    raw = _raw_totp_secret(user_id)
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    return _decrypt_with(raw, key or _master_key).decode()


def update_user_totp(user_id: int, totp_secret: str | None, enabled: bool, last_step: int = 0) -> None:
    secret_val: str | bytes | None = totp_secret
    if totp_secret is not None:
        encrypted = _maybe_encrypt(totp_secret.encode())
        secret_val = encrypted if _master_key is not None else totp_secret
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = ?, totp_last_step = ? WHERE id = ?",
            (secret_val, int(enabled), last_step, user_id),
        )


def claim_totp_step(user_id: int, step: int) -> bool:
    """Record ``step`` as used; False if it (or a later one) was already used."""
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
            (step, user_id, step),
        )
        return cur.rowcount > 0


def bump_session_version(user_id: int) -> int:
    """Invalidate all existing sessions for the user; returns the new version."""
    with _connect() as conn:
        conn.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?", (user_id,))
        row = conn.execute("SELECT session_version FROM users WHERE id = ?", (user_id,)).fetchone()
        return row[0] if row else 0


def update_user_require_password(user_id: int, require_password: bool) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET require_password = ? WHERE id = ?",
            (int(require_password), user_id),
        )


# ── Trusted devices ─────────────────────────────────────────────────

def create_trusted_device(user_id: int, token_hash: str, expires_at: str, label: str = "") -> int:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO trusted_devices (user_id, token_hash, expires_at, label) VALUES (?, ?, ?, ?)",
            (user_id, token_hash, expires_at, label),
        )
        return cur.lastrowid


def verify_trusted_device(token_hash: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT td.user_id, u.username, u.require_password "
            "FROM trusted_devices td JOIN users u ON u.id = td.user_id "
            "WHERE td.token_hash = ? AND td.expires_at > ?",
            (token_hash, _utc_now()),
        ).fetchone()
        return dict(row) if row else None


def list_trusted_devices(user_id: int) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, label, created_at, expires_at FROM trusted_devices "
            "WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC",
            (user_id, _utc_now()),
        ).fetchall()
        return [dict(r) for r in rows]


def delete_trusted_device(device_id: int, user_id: int) -> bool:
    with _connect() as conn:
        cur = conn.execute(
            "DELETE FROM trusted_devices WHERE id = ? AND user_id = ?",
            (device_id, user_id),
        )
        return cur.rowcount > 0


def delete_trusted_device_by_token(token_hash: str) -> bool:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM trusted_devices WHERE token_hash = ?", (token_hash,))
        return cur.rowcount > 0


def delete_trusted_devices(user_id: int) -> int:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM trusted_devices WHERE user_id = ?", (user_id,))
        return cur.rowcount


def count_trusted_devices(user_id: int) -> int:
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM trusted_devices WHERE user_id = ? AND expires_at > ?",
            (user_id, _utc_now()),
        ).fetchone()
        return row[0]


def cleanup_expired_devices() -> int:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM trusted_devices WHERE expires_at <= ?", (_utc_now(),))
        return cur.rowcount
