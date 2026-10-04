"""Encryption settings, backup and restore, and legacy export cleanup."""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
from collections.abc import Callable
from typing import Any

from flask import Blueprint, g, jsonify, session

from .. import crypto_engine, db, legacy_exports, state
from ..errors import UserError
from ..security import lockout_message
from ..web import (
    auth_limiter,
    deliver_export,
    error,
    json_body,
    new_password_error,
    recent_auth_required,
    str_field,
    value_error,
)

log = logging.getLogger("cert-generator")

bp = Blueprint("settings", __name__)


# ── Encryption ──────────────────────────────────────────────────────

def _encryption_limit_key() -> str:
    return f"unlock:{g.user['id']}" if g.get("user") else "unlock:desktop"


def _password_attempt(check: Callable[[], dict[str, Any] | None]):
    """Run a password- or recovery-key-checking action under the shared attempt limiter.

    Whatever ``check`` returns is added to the success response.
    """
    limit_key = _encryption_limit_key()
    wait = auth_limiter.retry_after(limit_key)
    if wait:
        return error(lockout_message(wait), 429)
    try:
        extra = check()
    except ValueError as e:
        if str(e).startswith("Wrong "):
            auth_limiter.failure(limit_key)
        return value_error(e)
    auth_limiter.success(limit_key)
    return jsonify({"ok": True, **(extra or {})})


_USERNAME_MAX = 64


def _desktop_username() -> str | None:
    """The desktop sign-in name. Server mode has real accounts and never uses one."""
    return db.get_login_username() if state.desktop_mode() else None


def _username_error(username: str) -> str | None:
    if len(username) > _USERNAME_MAX:
        return f"Username must be at most {_USERNAME_MAX} characters"
    if any(not ch.isprintable() for ch in username):
        return "Username can't contain control characters"
    return None


def _same_username(given: str, expected: str) -> bool:
    return hmac.compare_digest(given.casefold().encode("utf-8"), expected.casefold().encode("utf-8"))


@bp.get("/api/settings/encryption")
def get_encryption_status():
    enabled = db.is_encryption_enabled()
    unlocked = db.is_unlocked() or not enabled
    dismissed = db.get_setting("encryption_dismissed") is not None
    username = _desktop_username() if enabled else None
    return jsonify({
        "enabled": enabled,
        "unlocked": unlocked,
        "dismissed": dismissed,
        "recovery_key": enabled and db.has_recovery_key(),
        "username_required": username is not None,
        # Shown in Settings once unlocked; the locked screen only learns that one is needed.
        "username": username if unlocked else None,
    })


@bp.post("/api/settings/encryption/enable")
def enable_encryption():
    data = json_body()
    password = str_field(data, "password").strip()
    password_error = new_password_error(password, str_field(data, "confirm").strip(), "Password is required")
    if password_error:
        return error(password_error)
    username = str_field(data, "username").strip() if state.desktop_mode() else ""
    username_error = _username_error(username)
    if username_error:
        return error(username_error)
    try:
        recovery_key = db.enable_encryption(password, username or None)
    except ValueError as e:
        return value_error(e)
    log.info("Encryption enabled%s", " with a sign-in name" if username else "")
    return jsonify({"ok": True, "recovery_key": recovery_key})


@bp.post("/api/settings/encryption/disable")
def disable_encryption():
    password = str_field(json_body(), "password").strip()
    if not password:
        return error("Password is required")
    return _password_attempt(lambda: db.disable_encryption(password))


@bp.post("/api/settings/encryption/unlock")
def unlock_encryption():
    data = json_body()
    password = str_field(data, "password").strip()
    username = str_field(data, "username").strip()
    expected_username = _desktop_username()
    if expected_username is not None and not username:
        return error("Username is required")
    if not password:
        return error("Password is required")

    def check() -> None:
        # Check both before answering, so the reply doesn't say which one was wrong.
        name_ok = expected_username is None or _same_username(username, expected_username)
        if not db.unlock_if(password, name_ok):
            raise UserError("Wrong username or password" if expected_username is not None else "Wrong password")

    return _password_attempt(check)


@bp.post("/api/settings/encryption/change-password")
def change_encryption_password():
    data = json_body()
    old_password = str_field(data, "old_password").strip()
    new_password = str_field(data, "new_password").strip()
    if not old_password:
        return error("Both passwords are required")
    password_error = new_password_error(new_password, str_field(data, "confirm").strip(), "Both passwords are required")
    if password_error:
        return error(password_error.replace("Passwords do not match", "New passwords do not match"))
    return _password_attempt(lambda: db.change_password(old_password, new_password))


@bp.post("/api/settings/encryption/recovery-key")
@recent_auth_required
def create_recovery_key():
    """Issue a recovery key. Replacing an existing one needs the master password."""
    password = str_field(json_body(), "password").strip() or None

    def create() -> dict[str, Any]:
        recovery_key = db.create_recovery_key(password)
        log.info("Encryption recovery key issued")
        return {"recovery_key": recovery_key}

    return _password_attempt(create)


@bp.post("/api/settings/encryption/recover")
def recover_encryption():
    """Unlock with the recovery key and set a new master password; a new recovery key replaces the used one."""
    data = json_body()
    recovery_key = str_field(data, "recovery_key").strip()
    new_password = str_field(data, "password").strip()
    if not recovery_key:
        return error("Recovery key is required")
    password_error = new_password_error(new_password, str_field(data, "confirm").strip(), "New password is required")
    if password_error:
        return error(password_error)

    def recover() -> dict[str, Any]:
        replacement = db.recover_with_key(recovery_key, new_password)
        log.warning("Encryption password reset with the recovery key")
        # The recovery key proves ownership, so remind a desktop user of a forgotten sign-in name too.
        return {"recovery_key": replacement, "username": _desktop_username()}

    return _password_attempt(recover)


@bp.post("/api/settings/encryption/dismiss")
def dismiss_encryption_prompt():
    db.set_setting("encryption_dismissed", b"1")
    return jsonify({"ok": True})


# ── Backup and restore ──────────────────────────────────────────────

@bp.post("/api/backup")
@recent_auth_required
def create_backup():
    password = str_field(json_body(), "password").strip()
    if not password:
        return error("Password is required")
    plaintext = json.dumps(db.export_all_data()).encode("utf-8")
    encrypted = crypto_engine.encrypt_backup(plaintext, password)
    log.info("Backup created")
    return deliver_export(encrypted, "cert-generator-backup.certbak")


def _decode_backup(password: str, file_data: str) -> tuple[dict | None, str | None]:
    try:
        raw = base64.b64decode(file_data)
    except (binascii.Error, ValueError):
        return None, "Invalid file data"
    try:
        plaintext = crypto_engine.decrypt_backup(raw, password)
    except UserError as e:
        return None, e.user_message
    except ValueError as e:
        log.warning("Restore failed: %s", type(e).__name__)
        return None, "That backup couldn't be read"
    try:
        backup = json.loads(plaintext)
    except json.JSONDecodeError:
        return None, "Corrupted backup data"
    if not isinstance(backup, dict):
        return None, "Corrupted backup data"
    return backup, None


@bp.post("/api/restore")
@recent_auth_required
def restore_backup():
    data = json_body()
    password = str_field(data, "password").strip()
    file_data = str_field(data, "file_data")
    if not password:
        return error("Password is required")
    if not file_data:
        return error("No backup file provided")
    backup, decode_error = _decode_backup(password, file_data)
    if decode_error:
        return error(decode_error)
    try:
        counts = db.import_all_data(backup)
    except ValueError as e:
        return value_error(e)
    # Every session was revoked by the restore; keep this one if its user still exists.
    if g.get("user"):
        restored = db.get_user(g.user["username"])
        if restored is not None:
            session["sv"] = restored["session_version"]
        else:
            session.clear()
    log.info("Backup restored: %s", counts)
    return jsonify({"ok": True, "counts": counts})


# ── Legacy exports (server mode) ────────────────────────────────────

@bp.get("/api/settings/legacy-exports")
def legacy_exports_status():
    if state.desktop_mode():
        return jsonify({"directory": None, "files": []})
    directory = legacy_exports.legacy_export_dir()
    files = legacy_exports.find_legacy_exports()
    return jsonify({"directory": str(directory) if directory else None, "files": [f.name for f in files]})


@bp.post("/api/settings/legacy-exports/delete")
def delete_legacy_exports():
    if state.desktop_mode():
        return error("Not available in desktop mode", 404)
    deleted, failed = legacy_exports.delete_legacy_exports()
    log.warning("Deleted %d legacy export files from %s (%d failed)",
                deleted, legacy_exports.legacy_export_dir(), len(failed))
    return jsonify({"ok": not failed, "deleted": deleted, "failed": failed})
