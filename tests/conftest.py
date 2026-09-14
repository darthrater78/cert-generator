from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Point the app at throwaway directories before it is imported: app.server
# initialises the database at import time.
_SESSION_DIR = Path(tempfile.mkdtemp(prefix="cert-generator-tests-"))
os.environ["DB_DIR"] = str(_SESSION_DIR / "db")
os.environ["EXPORT_DIR"] = str(_SESSION_DIR / "exports")
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ.pop("SETUP_TOKEN", None)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import db, server  # noqa: E402

ADMIN = "admin"
ADMIN_PASSWORD = "correct-horse-battery"
ENCRYPTION_PASSWORD = "encryption-pass-123"


@pytest.fixture
def fresh_app(tmp_path, monkeypatch):
    """A server-mode app with an empty database and export directory."""
    monkeypatch.setattr(db, "DB_DIR", tmp_path / "db")
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "db" / "certs.db")
    monkeypatch.setenv("EXPORT_DIR", str(tmp_path / "exports"))
    db.init_db()
    db.set_master_key(None)
    server.set_app_token(None)
    server._auth_limiter.reset()
    yield server.app
    db.set_master_key(None)
    server.set_app_token(None)
    server._auth_limiter.reset()


@pytest.fixture
def client(fresh_app):
    return fresh_app.test_client()


@pytest.fixture
def admin_client(client):
    """Client signed in as the admin account."""
    resp = client.post("/setup", data={"username": ADMIN, "password": ADMIN_PASSWORD, "confirm": ADMIN_PASSWORD})
    assert resp.status_code == 302
    return client


def login(client, username: str = ADMIN, password: str = ADMIN_PASSWORD, **extra):
    return client.post("/login", data={"username": username, "password": password, **extra})
