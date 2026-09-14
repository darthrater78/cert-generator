"""Sign-in pages: desktop app token, login, first-run setup, MFA, logout."""
from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, Response, current_app, redirect, render_template, request, session

from .. import db, state
from ..security import lockout_message, verify_totp
from ..web import auth_limiter, hash_token, start_session

log = logging.getLogger("cert-generator")

bp = Blueprint("auth", __name__)

TRUST_COOKIE_NAME = "_trust_token"
TRUST_DURATION_DAYS = 30


# ── Trusted devices ─────────────────────────────────────────────────

def _device_label_from_ua(ua: str) -> str:
    if not ua:
        return "Unknown device"
    ua_lower = ua.lower()
    browser = "Browser"
    for name in ("Firefox", "Edg", "Chrome", "Safari", "Opera"):
        if name.lower() in ua_lower:
            browser = "Edge" if name == "Edg" else name
            break
    os_name = "Unknown OS"
    for pattern, label in [
        ("windows", "Windows"), ("iphone", "iOS"), ("ipad", "iPadOS"),
        ("android", "Android"), ("macintosh", "macOS"), ("mac os", "macOS"),
        ("linux", "Linux"), ("cros", "ChromeOS"),
    ]:
        if pattern in ua_lower:
            os_name = label
            break
    return f"{browser} on {os_name}"


def _create_trust_cookie(user_id: int, response: Response) -> Response:
    raw_token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(days=TRUST_DURATION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    label = _device_label_from_ua(request.headers.get("User-Agent", ""))
    db.create_trusted_device(user_id, hash_token(raw_token), expires_at, label)
    response.set_cookie(
        TRUST_COOKIE_NAME, raw_token,
        max_age=TRUST_DURATION_DAYS * 86400,
        httponly=True, samesite="Strict",
        secure=current_app.config["SESSION_COOKIE_SECURE"],
    )
    return response


def auto_login_from_trust_cookie() -> dict[str, Any] | None:
    trust_token = request.cookies.get(TRUST_COOKIE_NAME)
    if not trust_token:
        return None
    device = db.verify_trusted_device(hash_token(trust_token))
    if not device or device.get("require_password"):
        return None
    user = db.get_user(device["username"])
    if user is None:
        return None
    start_session(user)
    log.info("Auto-login via trusted device: %s", user["username"])
    return user


# ── Desktop app token ───────────────────────────────────────────────

@bp.get("/_auth")
def app_token_cookie() -> Response:
    if not state.desktop_mode():
        return Response("Not in app mode", status=404)
    token = request.args.get("token", "")
    if not secrets.compare_digest(token, state.app_token):
        return Response("Forbidden", status=403)
    resp = current_app.make_response("")
    resp.status_code = 302
    resp.headers["Location"] = "/"
    resp.set_cookie("_app_token", state.app_token, httponly=True, samesite="Strict")
    return resp


# ── Login and setup ─────────────────────────────────────────────────

@bp.route("/login", methods=["GET", "POST"])
def login():
    if state.desktop_mode():
        return redirect("/")
    if request.method == "GET":
        return render_template("login.html", error=None)
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    trust_device = request.form.get("trust_device") == "1"
    if not username or not password:
        return render_template("login.html", error="Username and password are required")

    limit_key = f"login:{username.lower()}"
    wait = auth_limiter.retry_after(limit_key)
    if wait:
        return render_template("login.html", error=lockout_message(wait)), 429
    if not db.verify_user(username, password):
        auth_limiter.failure(limit_key)
        log.warning("Failed login for %r from %s", username, request.remote_addr)
        return render_template("login.html", error="Invalid username or password")
    auth_limiter.success(limit_key)

    user = db.get_user(username)
    if user is None:
        return render_template("login.html", error="Invalid username or password")
    db.cleanup_expired_devices()

    if user.get("totp_enabled"):
        session.clear()
        session["mfa_pending"] = user["id"]
        session["mfa_trust"] = trust_device
        return redirect("/mfa")

    start_session(user)
    log.info("User logged in: %s", username)
    resp = current_app.make_response(redirect("/"))
    if trust_device:
        _create_trust_cookie(user["id"], resp)
    return resp


def _setup_page(error: str | None, username: str | None = None, status: int = 200):
    token_required = bool(os.environ.get("SETUP_TOKEN"))
    return render_template("setup.html", error=error, username=username,
                           setup_token_required=token_required), status


def _setup_form_error(username: str, password: str, confirm: str) -> str | None:
    if not username or len(username) > 100:
        return "Username is required (max 100 chars)"
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if db.password_too_long(password):
        return "Password must be at most 72 bytes"
    if password != confirm:
        return "Passwords do not match"
    return None


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    if state.desktop_mode() or db.has_users():
        return redirect("/")
    if request.method == "GET":
        return _setup_page(None)
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""
    expected_token = os.environ.get("SETUP_TOKEN")
    if expected_token:
        given = (request.form.get("setup_token") or "").encode()
        if not secrets.compare_digest(given, expected_token.encode()):
            log.warning("Setup attempt with invalid SETUP_TOKEN from %s", request.remote_addr)
            return _setup_page("Invalid setup token", username, 403)
    form_error = _setup_form_error(username, password, confirm)
    if form_error:
        return _setup_page(form_error, username)
    if not db.create_first_user(username, password):
        return redirect("/login")
    user = db.get_user(username)
    if user is not None:
        start_session(user)
    log.info("Admin account created: %s", username)
    return redirect("/")


@bp.route("/logout", methods=["GET", "POST"])
def logout():
    # GET only returns home, so a cross-site link or image can't sign anyone out.
    if request.method == "GET":
        return redirect("/")
    trust_token = request.cookies.get(TRUST_COOKIE_NAME)
    if trust_token:
        db.delete_trusted_device_by_token(hash_token(trust_token))
    session.clear()
    resp = current_app.make_response(redirect("/login"))
    resp.delete_cookie(TRUST_COOKIE_NAME)
    return resp


# ── MFA verification ────────────────────────────────────────────────

def _mfa_page(error: str | None, locked: bool, status: int = 200):
    return render_template("mfa.html", error=error, locked=locked), status


def _check_mfa_submission(user: dict[str, Any], locked: bool) -> tuple[str | None, bytes | None]:
    """Validate the posted code (and encryption password when locked).

    Returns (error message, encryption key). The key is set only when the
    database was locked and the encryption password was correct.
    """
    limit_key = f"mfa:{user['id']}"
    code = (request.form.get("code") or "").strip()
    if not code:
        return "Verification code is required", None

    enc_key = None
    if locked:
        enc_password = (request.form.get("encryption_password") or "").strip()
        if not enc_password:
            return "Encryption password is required", None
        enc_key = db.derive_key_if_valid(enc_password)
        if enc_key is None:
            auth_limiter.failure(limit_key)
            return "Invalid encryption password", None

    secret = db.get_totp_secret(user["id"], key=enc_key)
    step = verify_totp(secret, code, user["totp_last_step"]) if secret else None
    if step is None or not db.claim_totp_step(user["id"], step):
        auth_limiter.failure(limit_key)
        log.warning("Failed MFA verification for %s from %s", user["username"], request.remote_addr)
        return "Invalid verification code", None
    auth_limiter.success(limit_key)
    return None, enc_key


@bp.route("/mfa", methods=["GET", "POST"])
def mfa_verify():
    if state.desktop_mode():
        return redirect("/")
    user_id = session.get("mfa_pending")
    if not user_id:
        return redirect("/login")
    user = db.get_user_by_id(user_id)
    if not user or not user.get("totp_enabled"):
        session.clear()
        return redirect("/login")
    # With encryption enabled and the database locked (e.g. after a restart) the
    # TOTP secret can only be read with the encryption password, so ask for it here.
    locked = db.totp_secret_is_locked(user_id)
    if request.method == "GET":
        return _mfa_page(None, locked)

    wait = auth_limiter.retry_after(f"mfa:{user_id}")
    if wait:
        return _mfa_page(lockout_message(wait), locked, 429)
    trust_device = request.form.get("trust_device") == "1" or session.get("mfa_trust", False)
    error, enc_key = _check_mfa_submission(user, locked)
    if error:
        return _mfa_page(error, locked)

    if enc_key is not None:
        db.set_master_key(enc_key)
        log.info("Database unlocked during MFA verification for user: %s", user["username"])
    start_session(user)
    log.info("MFA verified for user: %s", user["username"])
    resp = current_app.make_response(redirect("/"))
    if trust_device:
        _create_trust_cookie(user["id"], resp)
    return resp
