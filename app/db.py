from __future__ import annotations

import base64
import json
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
from .errors import UserError


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

-- Cert Generator Pal (docs/cert-generator-pal.md). A pairing code connects one PC once;
-- the PC then signs its requests with its own device key.
CREATE TABLE IF NOT EXISTS pal_codes (
    id          TEXT    PRIMARY KEY,
    label       TEXT    NOT NULL,
    ca_id       INTEGER NOT NULL REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    policy      TEXT    NOT NULL,
    key         BLOB    NOT NULL,
    server_url  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at  TEXT    NOT NULL,
    used_at     TEXT,
    device_id   TEXT,
    revoked_at  TEXT
);

CREATE TABLE IF NOT EXISTS pal_devices (
    id          TEXT    PRIMARY KEY,
    label       TEXT    NOT NULL,
    hostname    TEXT    NOT NULL DEFAULT '',
    fqdn        TEXT    NOT NULL DEFAULT '',  -- recorded at pairing; "This computer" certs are issued to it
    os          TEXT    NOT NULL DEFAULT '',
    public_key  BLOB    NOT NULL,
    ca_id       INTEGER NOT NULL REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    policy      TEXT    NOT NULL,
    code_id     TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen   TEXT,
    revoked_at  TEXT
);

CREATE TABLE IF NOT EXISTS pal_requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     TEXT    NOT NULL REFERENCES pal_devices(id) ON DELETE CASCADE,
    use_case      TEXT    NOT NULL,
    names         TEXT    NOT NULL,
    csr_pem       BLOB    NOT NULL,
    lifetime_days INTEGER NOT NULL,
    status        TEXT    NOT NULL,
    cert_id       INTEGER,
    renew_of      INTEGER,
    reason        TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    decided_at    TEXT
);

CREATE TABLE IF NOT EXISTS pal_nonces (
    device_id   TEXT    NOT NULL,
    nonce       TEXT    NOT NULL,
    expires_at  REAL    NOT NULL,
    PRIMARY KEY (device_id, nonce)
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
    # The CA's Cloudflare CRL Worker (server mode); see app/cloudflare.py
    ("certificate_authorities", "cf_worker", "TEXT"),        # script name; NULL = no Worker
    ("certificate_authorities", "cf_account_id", "TEXT"),    # account the Worker lives in
    ("certificate_authorities", "cf_crl_path", "TEXT"),      # e.g. /my-root-ca.crl
    ("certificate_authorities", "cf_hostname", "TEXT"),      # custom domain or <script>.<sub>.workers.dev
    ("certificate_authorities", "cf_domain_id", "TEXT"),     # custom domain id, to detach it
    ("certificate_authorities", "cf_dp_url", "TEXT"),        # address recommended for certificates
    ("certificate_authorities", "cf_pushed_sha256", "TEXT"), # the CRL the Worker serves
    ("certificate_authorities", "cf_pushed_at", "TEXT"),
    ("certificate_authorities", "cf_push_error", "TEXT"),    # last failed push; NULL = up to date
    ("certificates", "pal_device_id", "TEXT"),  # issued to a Cert Generator Pal device; key_pem is empty
    ("certificates", "pal_present", "INTEGER"),  # 1/0: still installed on that PC at its last check; NULL = not checked
    ("certificates", "pal_checked_at", "TEXT"),
    ("pal_requests", "crl_dp", "TEXT"),
    ("pal_devices", "pal_version", "TEXT"),
    ("pal_devices", "remote_allowed", "INTEGER NOT NULL DEFAULT 0"),  # may use the remote relay (docs/cert-generator-pal.md §8)
    ("pal_devices", "last_via", "TEXT"),  # 'lan' or 'relay': how its last request arrived  # the Pal's version at its last request (it ships with the server's)  # the revocation type (profile) the PC asked with; NULL = the policy's default
)

CF_COLUMNS = ("cf_worker", "cf_account_id", "cf_crl_path", "cf_hostname", "cf_domain_id", "cf_dp_url",
              "cf_pushed_sha256", "cf_pushed_at", "cf_push_error")

_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_trusted_devices_token ON trusted_devices(token_hash)",
    "CREATE INDEX IF NOT EXISTS idx_certificates_ca ON certificates(ca_id)",
    "CREATE INDEX IF NOT EXISTS idx_ca_parent ON certificate_authorities(parent_ca_id)",
    "CREATE INDEX IF NOT EXISTS idx_pal_requests_device ON pal_requests(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_pal_requests_status ON pal_requests(status)",
    "CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial)",
)

# Columns holding private key material, encrypted when encryption is enabled.
_SENSITIVE_BLOBS = (
    ("certificate_authorities", "key_pem"),
    ("certificates", "key_pem"),
    ("ssh_keys", "private_key"),
    ("pal_codes", "key"),
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
        raise UserError("Encryption is already enabled")
    data_key = crypto_engine.new_data_key()
    with _key_change() as conn:
        if _get_setting(conn, "encryption_salt") is not None:
            raise UserError("Encryption is already enabled")
        _reencrypt_all(conn, None, data_key)
        _store_password_wrap(conn, password, data_key)
        recovery_key = _store_recovery_wrap(conn, data_key)
        if username:
            _set_setting(conn, "login_username", username.encode("utf-8"))
    set_master_key(data_key)
    return recovery_key


def disable_encryption(password: str) -> None:
    if not is_encryption_enabled():
        raise UserError("Encryption is not enabled")
    if has_cloudflare_token():
        raise UserError("Disconnect Cloudflare first: its API token is only ever stored encrypted")
    if get_setting("pal_relay_key") is not None or get_setting("pal_relay_token") is not None:
        raise UserError("Remove the remote relay first: its keys are only ever stored encrypted")
    with _key_change() as conn:
        key = _key_for_password(conn, password)[0]
        if key is None:
            raise UserError("Wrong password")
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
            raise UserError("Wrong current password")
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
            raise UserError("Encryption is not enabled")
        if _get_setting(conn, "recovery_wrapped_key") is None:
            key = _master_key
            if key is None:
                raise DatabaseLocked("Database is locked. Unlock it with your encryption password.")
        else:
            if not password:
                raise UserError("Password is required to replace the recovery key")
            key = _key_for_password(conn, password)[0]
            if key is None:
                raise UserError("Wrong password")
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
            raise UserError("This database has no recovery key")
        key = _key_for_recovery_key(conn, recovery_key)
        if key is None:
            raise UserError("Wrong recovery key")
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
            "SELECT id, parent_ca_id, name, domain, crl_public, crl_next_update, cf_worker, cf_dp_url, cf_hostname, "
            "cf_crl_path FROM certificate_authorities WHERE id = ?", (ca_id,),
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


def is_crl_maintained(ca_id: int) -> bool:
    """The app keeps a signed CRL current for this CA: served here, by a Cloudflare Worker, or both."""
    with _connect() as conn:
        row = conn.execute("SELECT crl_public, cf_worker FROM certificate_authorities WHERE id = ?",
                           (ca_id,)).fetchone()
        return bool(row and (row["crl_public"] or row["cf_worker"]))


def list_public_crls() -> list[tuple[int, bytes | None]]:
    """(CA id, current CRL or None) for every CA whose CRL the app keeps current."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, crl_der FROM certificate_authorities WHERE crl_public = 1 OR cf_worker IS NOT NULL"
        ).fetchall()
        return [(r["id"], r["crl_der"]) for r in rows]


def get_signed_crl(ca_id: int) -> bytes | None:
    """The CRL last signed for a maintained CA (what a Worker push sends)."""
    with _connect() as conn:
        row = conn.execute("SELECT crl_der FROM certificate_authorities WHERE id = ?", (ca_id,)).fetchone()
        return row["crl_der"] if row else None


# ── Cloudflare ──────────────────────────────────────────────────────

def get_ca_worker(ca_id: int) -> dict[str, Any] | None:
    """The CA's Worker fields, or None when it has no Worker."""
    with _connect() as conn:
        row = conn.execute(
            f"SELECT {', '.join(CF_COLUMNS)} FROM certificate_authorities WHERE id = ?", (ca_id,)  # nosec B608
        ).fetchone()
    return dict(row) if row and row["cf_worker"] else None


def update_ca_worker(ca_id: int, **fields: str | None) -> None:
    """Set some of the CA's cf_* columns (names checked against CF_COLUMNS)."""
    if not fields or not set(fields) <= set(CF_COLUMNS):
        raise ValueError("Unknown Cloudflare field")
    assignments = ", ".join(f"{name} = ?" for name in fields)
    with _connect() as conn:
        conn.execute(f"UPDATE certificate_authorities SET {assignments} WHERE id = ?",  # nosec B608
                     (*fields.values(), ca_id))


def clear_ca_worker(ca_id: int) -> None:
    update_ca_worker(ca_id, **dict.fromkeys(CF_COLUMNS))


def list_ca_workers() -> list[dict[str, Any]]:
    """Every CA with a Worker: id, name and its cf_* columns."""
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT id, name, {', '.join(CF_COLUMNS)} FROM certificate_authorities "  # nosec B608
            "WHERE cf_worker IS NOT NULL ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]


def count_ca_workers(ca_ids: list[int] | None = None) -> int:
    with _connect() as conn:
        if ca_ids is None:
            return conn.execute("SELECT COUNT(*) FROM certificate_authorities WHERE cf_worker IS NOT NULL").fetchone()[0]
        marks = ",".join("?" * len(ca_ids))
        return conn.execute(f"SELECT COUNT(*) FROM certificate_authorities "  # nosec B608
                            f"WHERE cf_worker IS NOT NULL AND id IN ({marks})", ca_ids).fetchone()[0]


def certs_with_crl_dp(ca_id: int, url: str) -> list[dict[str, Any]]:
    """Certificates of ``ca_id`` whose distribution point is ``url``."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, common_name, revoked FROM certificates WHERE ca_id = ? AND crl_dp_url = ? ORDER BY id",
            (ca_id, url),
        ).fetchall()
        return [dict(r) for r in rows]


def cloudflare_account_id() -> str | None:
    value = get_setting("cloudflare_account_id")
    return value.decode() if value else None


def has_cloudflare_token() -> bool:
    return get_setting("cloudflare_token") is not None


def set_cloudflare_credentials(account_id: str, token: str) -> None:
    """Store the API token encrypted with the database key. Needs encryption on and unlocked:
    the token can rewrite every CRL Worker, so it is never kept in plaintext."""
    if not is_encryption_enabled():
        raise UserError("Turn on database encryption first: the Cloudflare token is stored encrypted")
    require_unlocked()
    sealed = crypto_engine.encrypt_column(token.encode("utf-8"), _master_key)  # type: ignore[arg-type]
    with _connect() as conn:
        _set_setting(conn, "cloudflare_account_id", account_id.encode())
        _set_setting(conn, "cloudflare_token", sealed)


def get_cloudflare_credentials() -> tuple[str, str] | None:
    """(account id, token), or None when not connected. Raises DatabaseLocked while locked."""
    account_id, sealed = cloudflare_account_id(), get_setting("cloudflare_token")
    if not account_id or sealed is None:
        return None
    require_unlocked()
    return account_id, _maybe_decrypt(sealed).decode("utf-8")


def clear_cloudflare_credentials() -> None:
    with _connect() as conn:
        _set_setting(conn, "cloudflare_account_id", None)
        _set_setting(conn, "cloudflare_token", None)


def get_published_crl(ca_id: int) -> bytes | None:
    """The served CRL of a CA that opted in (public, never encrypted), readable while the
    database is locked. None for any other CA, so ids can't be probed."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT crl_der FROM certificate_authorities WHERE id = ? AND crl_public = 1", (ca_id,),
        ).fetchone()
        return row["crl_der"] if row else None


def get_ca_named_chain(ca_id: int, max_depth: int = 16) -> list[tuple[str, bytes]]:
    """(name, certificate PEM) from ``ca_id`` up to its root, nearest first. No keys."""
    chain: list[tuple[str, bytes]] = []
    seen: set[int] = set()
    current: int | None = ca_id
    with _connect() as conn:
        while current is not None and current not in seen and len(chain) < max_depth:
            seen.add(current)
            row = conn.execute(
                "SELECT name, cert_pem, parent_ca_id FROM certificate_authorities WHERE id = ?", (current,)
            ).fetchone()
            if row is None:
                break
            chain.append((row["name"], row["cert_pem"]))
            current = row["parent_ca_id"]
    return chain


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
    pal_device_id: str | None = None,
) -> int:
    """``key_pem`` is empty for a certificate whose key stays with the requester (a Pal CSR)."""
    encrypted_key = _maybe_encrypt(key_pem) if key_pem else b""
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO certificates
               (ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, cert_pem, key_pem,
                crl_dp_url, pal_device_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, cert_pem, encrypted_key,
             crl_dp_url or "", pal_device_id),
        )
        return cursor.lastrowid


_CERT_LIST_COLUMNS = (
    "id, ca_id, common_name, san_domains, algorithm, template, not_before, not_after, serial, revoked, created_at, "
    "crl_dp_url, pal_device_id, pal_present, length(key_pem) > 0 AS has_key"
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


# ── Cert Generator Pal ────────────────────────────────────────────────

def root_ca_id(ca_id: int, max_depth: int = 16) -> int | None:
    """The root above ``ca_id`` (itself when it is a root); None if ``ca_id`` doesn't exist."""
    current, seen = ca_id, set()
    with _connect() as conn:
        while len(seen) < max_depth:
            row = conn.execute("SELECT parent_ca_id FROM certificate_authorities WHERE id = ?", (current,)).fetchone()
            if row is None:
                return None
            if row["parent_ca_id"] is None or row["parent_ca_id"] in seen:
                return current
            seen.add(current)
            current = row["parent_ca_id"]
    return current


def ca_tree_ids(root_id: int) -> list[int]:
    """``root_id`` and every CA below it."""
    with _connect() as conn:
        return [r[0] for r in conn.execute(
            """WITH RECURSIVE tree(id) AS (
                   SELECT id FROM certificate_authorities WHERE id = ?
                   UNION
                   SELECT c.id FROM certificate_authorities c JOIN tree t ON c.parent_ca_id = t.id
               )
               SELECT id FROM tree""",
            (root_id,),
        ).fetchall()]


def find_serials(ca_ids: list[int], serials: list[str]) -> dict[str, dict[str, Any]]:
    """Certificates and CA certificates issued in ``ca_ids`` with one of ``serials``
    (normalized hex, as stored), plus deleted revoked ones, keyed by serial."""
    if not ca_ids or not serials:
        return {}
    ca_marks = ",".join("?" * len(ca_ids))
    serial_marks = ",".join("?" * len(serials))
    found: dict[str, dict[str, Any]] = {}
    with _connect() as conn:
        # Placeholders only: the f-string adds "?" marks, never values.
        for r in conn.execute(
            f"SELECT serial, not_after, revoked FROM certificates "  # nosec B608
            f"WHERE ca_id IN ({ca_marks}) AND serial IN ({serial_marks})", (*ca_ids, *serials)
        ).fetchall():
            found[r["serial"]] = {"not_after": r["not_after"], "revoked": bool(r["revoked"])}
        for r in conn.execute(
            f"SELECT serial, not_after FROM deleted_revocations "  # nosec B608
            f"WHERE ca_id IN ({ca_marks}) AND serial IN ({serial_marks})", (*ca_ids, *serials)
        ).fetchall():
            found[r["serial"]] = {"not_after": r["not_after"], "revoked": True}
        for r in conn.execute(
            f"SELECT serial, not_after FROM certificate_authorities "  # nosec B608
            f"WHERE id IN ({ca_marks}) AND serial IN ({serial_marks})", (*ca_ids, *serials)
        ).fetchall():
            found[r["serial"]] = {"not_after": r["not_after"], "revoked": False}
    return found


def create_pal_code(code_id: str, label: str, ca_id: int, policy: str, key: bytes, server_url: str,
                    expires_at: str) -> None:
    encrypted = _maybe_encrypt(key)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO pal_codes (id, label, ca_id, policy, key, server_url, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (code_id, label, ca_id, policy, encrypted, server_url, expires_at),
        )


_PAL_CODE_COLUMNS = "id, label, ca_id, policy, server_url, created_at, expires_at, used_at, device_id, revoked_at"


def list_pal_codes() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT c.id, c.label, c.ca_id, c.policy, c.server_url, c.created_at, c.expires_at, c.used_at, c.device_id, "
            "c.revoked_at, d.hostname AS device_name, d.fqdn AS device_fqdn "
            "FROM pal_codes c LEFT JOIN pal_devices d ON d.id = c.device_id ORDER BY c.created_at DESC LIMIT 500"
        ).fetchall()
        return [dict(r) for r in rows]


def get_pal_code(code_id: str) -> dict[str, Any] | None:
    """The code with its key decrypted (raises DatabaseLocked while locked)."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM pal_codes WHERE id = ?", (code_id,)).fetchone()
    if row is None:
        return None
    code = dict(row)
    code["key"] = _maybe_decrypt(code["key"])
    return code


def revoke_pal_code(code_id: str) -> bool:
    with _connect() as conn:
        cursor = conn.execute(
            "UPDATE pal_codes SET revoked_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL",
            (_utc_now(), code_id),
        )
        return cursor.rowcount > 0


def enroll_pal_device(code_id: str, device: dict[str, Any]) -> bool:
    """Use the code and create its device in one transaction. False if the code was used,
    revoked or expired in the meantime, so a code can never connect two devices. The device
    is named after itself (the host name it reports), not after the code's note."""
    now = _utc_now()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(
            "UPDATE pal_codes SET used_at = ?, device_id = ? "
            "WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?",
            (now, device["id"], code_id, now),
        )
        if cursor.rowcount != 1:
            return False
        conn.execute(
            "INSERT INTO pal_devices (id, label, hostname, fqdn, os, public_key, ca_id, policy, code_id, last_seen, "
            "remote_allowed) SELECT ?, ?, ?, ?, ?, ?, ca_id, policy, id, ?, ? FROM pal_codes WHERE id = ?",
            (device["id"], device["hostname"] or device["fqdn"].split(".")[0], device["hostname"], device["fqdn"],
             device["os"], device["public_key"], now, int(bool(device.get("remote_allowed"))), code_id),
        )
        return True


_PAL_DEVICE_COLUMNS = ("id, label, hostname, fqdn, os, public_key, ca_id, policy, code_id, created_at, last_seen, "
                       "revoked_at, pal_version, remote_allowed, last_via")


def get_pal_device(device_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(f"SELECT {_PAL_DEVICE_COLUMNS} FROM pal_devices WHERE id = ?", (device_id,)).fetchone()  # nosec B608 - constant column list
        return dict(row) if row else None


def list_pal_devices() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT d.id, d.label, d.hostname, d.fqdn, d.os, d.ca_id, d.policy, d.created_at, d.last_seen, d.revoked_at, d.pal_version, "
            "d.remote_allowed, d.last_via, "
            "(SELECT COUNT(*) FROM certificates c WHERE c.pal_device_id = d.id) AS cert_count, "
            "(SELECT COUNT(*) FROM pal_requests r WHERE r.device_id = d.id AND r.status = 'pending') AS pending "
            "FROM pal_devices d ORDER BY d.revoked_at IS NOT NULL, d.created_at DESC"  # disconnected PCs last
        ).fetchall()
        return [dict(r) for r in rows]


def touch_pal_device(device_id: str, pal_version: str | None = None, via: str = "lan") -> None:
    with _connect() as conn:
        conn.execute("UPDATE pal_devices SET last_seen = ?, pal_version = COALESCE(?, pal_version), last_via = ? WHERE id = ?",
                     (_utc_now(), pal_version, via, device_id))


def set_pal_remote_allowed(device_id: str, allowed: bool) -> bool:
    with _connect() as conn:
        return conn.execute("UPDATE pal_devices SET remote_allowed = ? WHERE id = ? AND revoked_at IS NULL",
                            (int(allowed), device_id)).rowcount == 1


def list_pal_remote_keys() -> list[tuple[str, bytes]]:
    """(device id, public key DER) of every connected PC allowed to use the relay: what the Worker accepts."""
    with _connect() as conn:
        rows = conn.execute("SELECT id, public_key FROM pal_devices WHERE remote_allowed = 1 AND revoked_at IS NULL "
                            "ORDER BY id").fetchall()
        return [(r["id"], bytes(r["public_key"])) for r in rows]


def get_pal_relay_key() -> bytes | None:
    """The relay key (PKCS#8 DER), or None before one is made. Raises DatabaseLocked while locked."""
    sealed = get_setting("pal_relay_key")
    if sealed is None:
        return None
    require_unlocked()
    return _maybe_decrypt(sealed)


def get_pal_relay_config() -> dict[str, Any] | None:
    """The deployed relay Worker: {"script", "url", "domain_id"?}, or None. Readable while locked."""
    raw = get_setting("pal_relay_worker")
    return json.loads(raw) if raw else None


def get_pal_relay_token() -> str | None:
    """The server's token for the relay Worker's server endpoints. Raises DatabaseLocked while locked."""
    sealed = get_setting("pal_relay_token")
    if sealed is None:
        return None
    require_unlocked()
    return _maybe_decrypt(sealed).decode()


def set_pal_relay_config(config: dict[str, Any], token: str) -> None:
    if not is_encryption_enabled():
        raise UserError("Turn on database encryption first: the relay's token is stored encrypted")
    require_unlocked()
    with _connect() as conn:
        _set_setting(conn, "pal_relay_worker", json.dumps(config).encode())
        _set_setting(conn, "pal_relay_token", crypto_engine.encrypt_column(token.encode(), _master_key))  # type: ignore[arg-type]


def clear_pal_relay_config() -> None:
    """Forget the Worker (the relay key stays: PCs keep it pinned for the next relay)."""
    with _connect() as conn:
        _set_setting(conn, "pal_relay_worker", None)
        _set_setting(conn, "pal_relay_token", None)


def create_pal_relay_key(private_der: bytes) -> None:
    """Store the relay key encrypted with the database key: like the Cloudflare token it needs
    encryption on (the relay is set up through Cloudflare, which already requires it)."""
    if not is_encryption_enabled():
        raise UserError("Turn on database encryption first: the relay key is stored encrypted")
    require_unlocked()
    with _connect() as conn:
        if _get_setting(conn, "pal_relay_key") is not None:
            raise UserError("This server already has a relay key")
        _set_setting(conn, "pal_relay_key", crypto_engine.encrypt_column(private_der, _master_key))  # type: ignore[arg-type]


def revoke_pal_device(device_id: str) -> bool:
    """Stop the device's requests: its pending ones are denied. Its certificates are untouched."""
    now = _utc_now()
    with _connect() as conn:
        cursor = conn.execute(
            "UPDATE pal_devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (now, device_id))
        if cursor.rowcount != 1:
            return False
        conn.execute(
            "UPDATE pal_requests SET status = 'denied', reason = 'Device revoked', decided_at = ? "
            "WHERE device_id = ? AND status = 'pending'", (now, device_id))
        return True


def delete_pal_device(device_id: str) -> bool:
    """Forget a disconnected device: its requests, nonces and pairing code go with it. The
    certificates it was issued stay (revoked, and listed under the CA)."""
    with _connect() as conn:
        row = conn.execute("SELECT code_id FROM pal_devices WHERE id = ? AND revoked_at IS NOT NULL",
                           (device_id,)).fetchone()
        if row is None:
            return False
        conn.execute("DELETE FROM pal_requests WHERE device_id = ?", (device_id,))
        conn.execute("DELETE FROM pal_nonces WHERE device_id = ?", (device_id,))
        conn.execute("DELETE FROM pal_devices WHERE id = ?", (device_id,))
        conn.execute("DELETE FROM pal_codes WHERE id = ?", (row["code_id"],))
        return True


def list_pal_device_certs(device_id: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT {_CERT_LIST_COLUMNS} FROM certificates WHERE pal_device_id = ? ORDER BY created_at DESC",  # nosec B608 - constant column list
            (device_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def mark_pal_presence(device_id: str, present_serials: set[str]) -> None:
    """Record which of the device's own certificates its last store audit found."""
    now = _utc_now()
    with _connect() as conn:
        for row in conn.execute("SELECT id, serial FROM certificates WHERE pal_device_id = ?", (device_id,)).fetchall():
            conn.execute("UPDATE certificates SET pal_present = ?, pal_checked_at = ? WHERE id = ?",
                         (int(row["serial"] in present_serials), now, row["id"]))


def list_pal_issued_certs() -> list[dict[str, Any]]:
    """Every certificate issued to a Pal device, for the Devices page (one query, not one per device)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT pal_device_id, template, common_name, not_after, revoked, pal_present FROM certificates "
            "WHERE pal_device_id IS NOT NULL ORDER BY not_after DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def use_pal_nonce(device_id: str, nonce: str, now: float, ttl: float) -> bool:
    """Record a request nonce; False if this device already used it within ``ttl`` seconds."""
    with _connect() as conn:
        conn.execute("DELETE FROM pal_nonces WHERE expires_at < ?", (now,))
        try:
            conn.execute("INSERT INTO pal_nonces (device_id, nonce, expires_at) VALUES (?, ?, ?)",
                         (device_id, nonce, now + ttl))
        except sqlite3.IntegrityError:
            return False
        return True


def create_pal_request(device_id: str, use_case: str, names: str, csr_pem: bytes, lifetime_days: int,
                       renew_of: int | None, crl_dp: str | None = None) -> int:
    with _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO pal_requests (device_id, use_case, names, csr_pem, lifetime_days, status, renew_of, crl_dp) "
            "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
            (device_id, use_case, names, csr_pem, lifetime_days, renew_of, crl_dp),
        )
        return cursor.lastrowid


def get_pal_request(request_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM pal_requests WHERE id = ?", (request_id,)).fetchone()
        return dict(row) if row else None


def list_pal_requests(status: str | None = None, device_id: str | None = None) -> list[dict[str, Any]]:
    clauses, params = [], []
    if status is not None:
        clauses.append("r.status = ?")
        params.append(status)
    if device_id is not None:
        clauses.append("r.device_id = ?")
        params.append(device_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT r.id, r.device_id, d.label AS device_label, d.hostname, r.use_case, r.names, r.lifetime_days, "
            "r.status, r.cert_id, r.renew_of, r.reason, r.created_at, r.decided_at, r.crl_dp "
            f"FROM pal_requests r JOIN pal_devices d ON d.id = r.device_id {where} "  # nosec B608 - constant clauses
            "ORDER BY r.created_at DESC, r.id DESC LIMIT 500",
            params,
        ).fetchall()
        return [dict(r) for r in rows]


def transition_pal_request(request_id: int, from_status: str, to_status: str, cert_id: int | None = None,
                           reason: str = "") -> bool:
    """Move a request from ``from_status`` to ``to_status``; False if it was no longer in
    ``from_status``. Issuing goes pending → issuing → issued, so two approvals of the same
    request can't both sign a certificate."""
    with _connect() as conn:
        cursor = conn.execute(
            "UPDATE pal_requests SET status = ?, cert_id = COALESCE(?, cert_id), reason = ?, decided_at = ? "
            "WHERE id = ? AND status = ?",
            (to_status, cert_id, reason, _utc_now(), request_id, from_status),
        )
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
        raise UserError(f"Invalid backup data: '{key}' must be a list of objects")
    return rows


def _restore_cas(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> None:
    for ca in rows:
        ca = _decode_blobs(ca)
        conn.execute(
            """INSERT INTO certificate_authorities
               (id, parent_ca_id, name, domain, algorithm, not_before, not_after, serial, cert_pem, key_pem, created_at,
                crl_next_update, crl_der, crl_public,
                cf_worker, cf_account_id, cf_crl_path, cf_hostname, cf_domain_id, cf_dp_url, cf_pushed_sha256,
                cf_pushed_at, cf_push_error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ca["id"], ca.get("parent_ca_id"), ca["name"], ca["domain"],
             ca["algorithm"], ca["not_before"], ca["not_after"], ca["serial"],
             ca["cert_pem"], _maybe_encrypt(ca["key_pem"]), ca["created_at"],
             ca.get("crl_next_update"), ca.get("crl_der"), int(bool(ca.get("crl_public"))),
             # The Worker link survives a restore; the token isn't in backups, so reconnect to manage it.
             *(_text_or_none(ca.get(c)) for c in CF_COLUMNS)),
        )


def _text_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


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
        raise UserError("Unsupported backup data version")
    require_unlocked()
    cas = _import_rows(data, "certificate_authorities")
    certs = _import_rows(data, "certificates")
    ssh_keys = _import_rows(data, "ssh_keys")
    users = _import_rows(data, "users")
    deleted_revocations = _import_rows(data, "deleted_revocations")  # absent in older backups
    try:
        with _connect() as conn:
            # Pairings refer to the CAs being replaced: connected PCs pair again after a restore.
            for table in ("pal_nonces", "pal_requests", "pal_devices", "pal_codes"):
                conn.execute(f"DELETE FROM {table}")  # nosec B608 - constant table names
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
        raise UserError("Invalid backup data: it does not match what this version expects") from e
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
