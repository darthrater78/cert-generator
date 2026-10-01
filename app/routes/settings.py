"""Encryption settings, backup and restore, and legacy export cleanup."""
from __future__ import annotations

import base64
import binascii
import json
import logging
from collections.abc import Callable
from typing import Any

from flask import Blueprint, g, jsonify, session

from .. import crypto_engine, db, legacy_exports, state
from ..security import lockout_message
from ..web import (
    auth_limiter,
    deliver_export,
    error,
    json_body,
    new_password_error,
    recent_auth_required,
    str_field,
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
        return error(str(e))
    auth_limiter.success(limit_key)
    return jsonify({"ok": True, **(extra or {})})


@bp.get("/api/settings/encryption")
def get_encryption_status():
    enabled = db.is_encryption_enabled()
    dismissed = db.get_setting("encryption_dismissed") is not None
    return jsonify({
        "enabled": enabled,
        "unlocked": db.is_unlocked() or not enabled,
        "dismissed": dismissed,
        "recovery_key": enabled and db.has_recovery_key(),
    })


@bp.post("/api/settings/encryption/enable")
def enable_encryption():
    data = json_body()
    password = str_field(data, "password").strip()
    password_error = new_password_error(password, str_field(data, "confirm").strip(), "Password is required")
    if password_error:
        return error(password_error)
    try:
        recovery_key = db.enable_encryption(password)
    except ValueError as e:
        return error(str(e))
    log.info("Encryption enabled")
    return jsonify({"ok": True, "recovery_key": recovery_key})


@bp.post("/api/settings/encryption/disable")
def disable_encryption():
    password = str_field(json_body(), "password").strip()
    if not password:
        return error("Password is required")
    return _password_attempt(lambda: db.disable_encryption(password))


@bp.post("/api/settings/encryption/unlock")
def unlock_encryption():
    password = str_field(json_body(), "password").strip()
    if not password:
        return error("Password is required")

    def check() -> None:
        if not db.unlock(password):
            raise ValueError("Wrong password")

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
        return {"recovery_key": replacement}

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
    except ValueError as e:
        return None, str(e)
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
        return error(str(e))
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
