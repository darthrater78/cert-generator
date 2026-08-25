from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DB_DIR = Path.home() / ".cert-generator"
DB_PATH = DB_DIR / "certs.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS certificate_authorities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    domain      TEXT    NOT NULL,
    algorithm   TEXT    NOT NULL,
    not_before  TEXT    NOT NULL,
    not_after   TEXT    NOT NULL,
    serial      TEXT    NOT NULL UNIQUE,
    cert_pem    BLOB    NOT NULL,
    key_pem     BLOB    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS certificates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id       INTEGER NOT NULL REFERENCES certificate_authorities(id),
    common_name TEXT    NOT NULL,
    san_domains TEXT    NOT NULL,
    algorithm   TEXT    NOT NULL,
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


def save_ca(
    name: str,
    domain: str,
    algorithm: str,
    not_before: str,
    not_after: str,
    serial: str,
    cert_pem: bytes,
    key_pem: bytes,
) -> int:
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO certificate_authorities
               (name, domain, algorithm, not_before, not_after, serial, cert_pem, key_pem)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, domain, algorithm, not_before, not_after, serial, cert_pem, key_pem),
        )
        return cursor.lastrowid


def list_cas() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, name, domain, algorithm, not_before, not_after, serial, created_at "
            "FROM certificate_authorities ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_ca(ca_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)
        ).fetchone()
        return dict(row) if row else None


def delete_ca(ca_id: int) -> bool:
    with _connect() as conn:
        conn.execute("DELETE FROM certificates WHERE ca_id = ?", (ca_id,))
        cursor = conn.execute("DELETE FROM certificate_authorities WHERE id = ?", (ca_id,))
        return cursor.rowcount > 0


def save_cert(
    ca_id: int,
    common_name: str,
    san_domains: str,
    algorithm: str,
    not_before: str,
    not_after: str,
    serial: str,
    cert_pem: bytes,
    key_pem: bytes,
) -> int:
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO certificates
               (ca_id, common_name, san_domains, algorithm, not_before, not_after, serial, cert_pem, key_pem)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ca_id, common_name, san_domains, algorithm, not_before, not_after, serial, cert_pem, key_pem),
        )
        return cursor.lastrowid


def list_certs(ca_id: int | None = None) -> list[dict[str, Any]]:
    with _connect() as conn:
        if ca_id is not None:
            rows = conn.execute(
                "SELECT id, ca_id, common_name, san_domains, algorithm, not_before, not_after, serial, revoked, created_at "
                "FROM certificates WHERE ca_id = ? ORDER BY created_at DESC",
                (ca_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, ca_id, common_name, san_domains, algorithm, not_before, not_after, serial, revoked, created_at "
                "FROM certificates ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]


def get_cert(cert_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
        return dict(row) if row else None


def revoke_cert(cert_id: int) -> bool:
    with _connect() as conn:
        cursor = conn.execute(
            "UPDATE certificates SET revoked = 1 WHERE id = ? AND revoked = 0",
            (cert_id,),
        )
        return cursor.rowcount > 0


def delete_cert(cert_id: int) -> bool:
    with _connect() as conn:
        cursor = conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
        return cursor.rowcount > 0
