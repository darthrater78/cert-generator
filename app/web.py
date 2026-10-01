"""Helpers shared by the route blueprints: request parsing, auth, sessions, exports."""
from __future__ import annotations

import functools
import hashlib
import io
import os
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from flask import Response, abort, g, jsonify, request, send_file, session

from . import state
from .security import AttemptLimiter

# Shared by login, MFA, and password re-entry endpoints.
auth_limiter = AttemptLimiter()

# How long a password or code entry unlocks key material for this session.
REAUTH_WINDOW_SECONDS = 300


# ── Request parsing ─────────────────────────────────────────────────

def json_body() -> dict[str, Any]:
    data = request.get_json()  # 415 for a non-JSON content type, 400 for malformed JSON
    if not isinstance(data, dict):
        abort(400, "Request body must be a JSON object")
    return data


def str_field(data: dict[str, Any], key: str, default: str = "") -> str:
    value = data.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        abort(400, f"'{key}' must be a string")
    return value


def parse_int(value: Any, default: int) -> int | None:
    if value is None:
        return default
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def error(message: str, status: int = 400) -> tuple[Response, int]:
    return jsonify({"error": message}), status


# ── Authentication and sessions ─────────────────────────────────────

def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if g.get("user") is None:
            return error("Not authenticated", 401)
        return view(*args, **kwargs)
    return wrapper


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(user: dict[str, Any], *, authenticated_now: bool = False) -> None:
    """``authenticated_now``: the user just typed a password or code (not a trusted-device
    sign-in), which counts as the re-authentication that releasing key material needs."""
    session.clear()
    session["user"] = user["username"]
    session["sv"] = user["session_version"]
    session.permanent = True
    if authenticated_now:
        mark_reauthenticated()


def mark_reauthenticated() -> None:
    session["reauth_at"] = int(time.time())


def reauth_rejection() -> tuple[Response, int] | None:
    """None when this session may receive private keys or backups; otherwise a 403 that
    tells the page to ask for the password (or an authenticator code) and retry.
    Desktop mode has no accounts: the app token already limits it to this machine's window."""
    if state.desktop_mode():
        return None
    reauth_at = session.get("reauth_at")
    if isinstance(reauth_at, int) and 0 <= time.time() - reauth_at < REAUTH_WINDOW_SECONDS:
        return None
    user = g.get("user") or {}
    return jsonify({"error": "Confirm it's you to continue", "reauth_required": True,
                    "mfa": bool(user.get("totp_enabled"))}), 403


def recent_auth_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        rejection = reauth_rejection()
        if rejection is not None:
            return rejection
        return view(*args, **kwargs)
    return wrapper


# ── Exports ─────────────────────────────────────────────────────────

def downloads_dir() -> Path:
    downloads = Path(os.environ.get("EXPORT_DIR", str(Path.home() / "Downloads")))
    downloads.mkdir(parents=True, exist_ok=True)
    return downloads


def safe_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).strip('. ') or "export"


def _save_export(data: bytes, filename: str) -> str:
    safe_name = safe_filename(filename)
    target_dir = downloads_dir()
    out = target_dir / safe_name
    counter = 1
    while out.exists():
        stem = Path(safe_name).stem
        suffix = Path(safe_name).suffix
        out = target_dir / f"{stem} ({counter}){suffix}"
        counter += 1
    out.write_bytes(data)
    return str(out)


def deliver_export(data: bytes, filename: str, extra: dict[str, str] | None = None) -> Response:
    """Desktop mode saves to the Downloads folder and returns JSON; server mode
    streams the file to the browser and never writes key material to disk.

    ``extra`` values go into the JSON body (desktop) or X- headers (server).
    """
    extra = extra or {}
    if state.desktop_mode():
        return jsonify({"path": _save_export(data, filename), **extra})
    response = send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=safe_filename(filename),
        mimetype="application/octet-stream",
        max_age=0,
    )
    for key, value in extra.items():
        response.headers["X-" + key.replace("_", "-").title()] = value
    return response
