from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pyotp
import qrcode
import qrcode.image.svg
from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, send_file, session
from werkzeug.exceptions import HTTPException

from . import crypto_engine, db
from .security import AttemptLimiter, is_cross_site_request, lockout_message, verify_totp

log = logging.getLogger("cert-generator")

VALID_FORMATS = ("pem", "der", "crt", "pkcs12")
VALID_CA_PARTS = ("both", "public", "private")
VALID_CERT_PARTS = ("both", "public", "private", "chain")
DOMAIN_RE = re.compile(r"^[\w.*-]{1,253}$")

_bound_port: int | None = None
_app_token: str | None = None


def set_bound_port(port: int) -> None:
    global _bound_port
    _bound_port = port


def set_app_token(token: str | None) -> None:
    global _app_token
    _app_token = token


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)
# `or` rather than a get() default: Docker Compose passes an unset variable as "".
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_env_flag("COOKIE_SECURE"),
    MAX_CONTENT_LENGTH=32 * 1024 * 1024,
)

with app.app_context():
    db.init_db()


_PUBLIC_PATHS = {"/login", "/setup", "/logout", "/mfa", "/favicon.ico"}
_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

TRUST_COOKIE_NAME = "_trust_token"
TRUST_DURATION_DAYS = 30

# Same keys are shared by login, MFA, and password re-entry endpoints.
_auth_limiter = AttemptLimiter()

_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


# ── Request hooks ───────────────────────────────────────────────────

@app.before_request
def _start_timer():
    request._start_time = time.monotonic()


@app.after_request
def _finish_response(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if _app_token is None:
        # Server mode only: the desktop window injects its own scripts.
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("X-Frame-Options", "DENY")
    if request.path.startswith("/api/"):
        # Overwrite, not setdefault: send_file sets its own cacheable header.
        response.headers["Cache-Control"] = "no-store"
    if not request.path.startswith("/static/"):
        duration_ms = (time.monotonic() - getattr(request, "_start_time", time.monotonic())) * 1000
        log.info("%s %s %s %.0fms", request.method, request.path, response.status_code, duration_ms)
    return response


@app.errorhandler(HTTPException)
def _http_error(exc: HTTPException):
    if request.path.startswith("/api/"):
        return jsonify({"error": exc.description}), exc.code
    return exc


@app.errorhandler(db.DatabaseLocked)
def _database_locked(exc: db.DatabaseLocked):
    return jsonify({"error": str(exc), "locked": True}), 423


def _app_token_check() -> Response | None:
    if request.path == "/_auth":
        return None
    if not secrets.compare_digest(request.cookies.get("_app_token", ""), _app_token or ""):
        return Response("Forbidden", status=403, content_type="text/plain")
    if request.method not in _SAFE_METHODS:
        origin = request.headers.get("Origin")
        if origin:
            port = _bound_port or 5174
            if origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
                return jsonify({"error": "Forbidden"}), 403
    return None


def _auto_login_from_trust_cookie() -> dict[str, Any] | None:
    trust_token = request.cookies.get(TRUST_COOKIE_NAME)
    if not trust_token:
        return None
    device = db.verify_trusted_device(_hash_token(trust_token))
    if not device or device.get("require_password"):
        return None
    user = db.get_user(device["username"])
    if user is None:
        return None
    _start_session(user)
    log.info("Auto-login via trusted device: %s", user["username"])
    return user


@app.before_request
def _auth_check() -> Response | None:
    g.user = None

    # --- pywebview mode: app token auth ---
    if _app_token is not None:
        return _app_token_check()

    # --- server mode: session auth ---
    if request.method not in _SAFE_METHODS and is_cross_site_request(request.host, request.headers):
        log.warning("Blocked cross-site %s %s (Origin=%r)", request.method, request.path,
                    request.headers.get("Origin"))
        if request.path.startswith("/api/"):
            return jsonify({"error": "Cross-site request blocked"}), 403
        return Response("Cross-site request blocked", status=403, content_type="text/plain")

    if request.path in _PUBLIC_PATHS or request.path.startswith("/static/"):
        return None

    if not db.has_users():
        return redirect("/setup")

    # MFA pending: user authenticated with password but hasn't completed MFA yet
    if session.get("mfa_pending"):
        return redirect("/mfa")

    username = session.get("user")
    if username:
        user = db.get_user(username)
        if user is not None and user["session_version"] == session.get("sv", 0):
            g.user = user
            return None
        # Password reset, MFA change, restore, or deleted user: this session is revoked.
        session.clear()

    g.user = _auto_login_from_trust_cookie()
    if g.user is not None:
        return None

    if request.path.startswith("/api/"):
        return Response("Unauthorized", status=401, content_type="text/plain")
    return redirect("/login")


def _login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if g.get("user") is None:
            return jsonify({"error": "Not authenticated"}), 401
        return view(*args, **kwargs)
    return wrapper


# ── Request parsing helpers ─────────────────────────────────────────

def _json_body() -> dict[str, Any]:
    data = request.get_json()  # 415 for a non-JSON content type, 400 for malformed JSON
    if not isinstance(data, dict):
        abort(400, "Request body must be a JSON object")
    return data


def _str_field(data: dict[str, Any], key: str, default: str = "") -> str:
    value = data.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        abort(400, f"'{key}' must be a string")
    return value


def _parse_int(value: Any, default: int) -> int | None:
    if value is None:
        return default
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _is_valid_san(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(DOMAIN_RE.match(value))


def _parse_san_list(raw: str, common_name: str) -> list[str] | None:
    """Explicit SANs must be valid; None signals an invalid entry.

    With no explicit SANs the common name is used, but only when it is a valid
    DNS name or IP — "John Smith" on a user certificate gets no DNS SAN.
    """
    if not raw:
        return [common_name] if _is_valid_san(common_name) else []
    entries = [s.strip() for s in raw.split(",") if s.strip()]
    if not all(_is_valid_san(s) for s in entries):
        return None
    return entries


# ── Sessions and trusted devices ────────────────────────────────────

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _start_session(user: dict[str, Any]) -> None:
    session.clear()
    session["user"] = user["username"]
    session["sv"] = user["session_version"]
    session.permanent = True


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
    db.create_trusted_device(user_id, _hash_token(raw_token), expires_at, label)
    response.set_cookie(
        TRUST_COOKIE_NAME, raw_token,
        max_age=TRUST_DURATION_DAYS * 86400,
        httponly=True, samesite="Strict",
        secure=app.config["SESSION_COOKIE_SECURE"],
    )
    return response


def _revoke_other_sessions(user_id: int) -> None:
    """End every other session for the user while keeping the current one."""
    session["sv"] = db.bump_session_version(user_id)


def _limited(key: str) -> float:
    return _auth_limiter.retry_after(key)


# ── Desktop app token ───────────────────────────────────────────────

@app.get("/_auth")
def _auth_set_cookie() -> Response:
    if _app_token is None:
        return Response("Not in app mode", status=404)
    token = request.args.get("token", "")
    if not secrets.compare_digest(token, _app_token):
        return Response("Forbidden", status=403)
    resp = app.make_response("")
    resp.status_code = 302
    resp.headers["Location"] = "/"
    resp.set_cookie("_app_token", _app_token, httponly=True, samesite="Strict")
    return resp


# ── Login, setup, MFA ───────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if _app_token is not None:
        return redirect("/")
    if request.method == "GET":
        return render_template("login.html", error=None)
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    trust_device = request.form.get("trust_device") == "1"
    if not username or not password:
        return render_template("login.html", error="Username and password are required")

    limit_key = f"login:{username.lower()}"
    wait = _limited(limit_key)
    if wait:
        return render_template("login.html", error=lockout_message(wait)), 429
    if not db.verify_user(username, password):
        _auth_limiter.failure(limit_key)
        log.warning("Failed login for %r from %s", username, request.remote_addr)
        return render_template("login.html", error="Invalid username or password")
    _auth_limiter.success(limit_key)

    user = db.get_user(username)
    if user is None:
        return render_template("login.html", error="Invalid username or password")
    db.cleanup_expired_devices()

    if user.get("totp_enabled"):
        session.clear()
        session["mfa_pending"] = user["id"]
        session["mfa_trust"] = trust_device
        return redirect("/mfa")

    _start_session(user)
    log.info("User logged in: %s", username)
    resp = app.make_response(redirect("/"))
    if trust_device:
        _create_trust_cookie(user["id"], resp)
    return resp


def _setup_page(error: str | None, username: str | None = None, status: int = 200):
    token_required = bool(os.environ.get("SETUP_TOKEN"))
    return render_template("setup.html", error=error, username=username,
                           setup_token_required=token_required), status


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if _app_token is not None or db.has_users():
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
    if not username or len(username) > 100:
        return _setup_page("Username is required (max 100 chars)", username)
    if len(password) < 8:
        return _setup_page("Password must be at least 8 characters", username)
    if db.password_too_long(password):
        return _setup_page("Password must be at most 72 bytes", username)
    if password != confirm:
        return _setup_page("Passwords do not match", username)
    if not db.create_first_user(username, password):
        return redirect("/login")
    user = db.get_user(username)
    if user is not None:
        _start_session(user)
    log.info("Admin account created: %s", username)
    return redirect("/")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    # GET only returns home, so a cross-site link or image can't sign anyone out.
    if request.method == "GET":
        return redirect("/")
    trust_token = request.cookies.get(TRUST_COOKIE_NAME)
    if trust_token:
        db.delete_trusted_device_by_token(_hash_token(trust_token))
    session.clear()
    resp = app.make_response(redirect("/login"))
    resp.delete_cookie(TRUST_COOKIE_NAME)
    return resp


def _mfa_page(error: str | None, locked: bool, status: int = 200):
    return render_template("mfa.html", error=error, locked=locked), status


@app.route("/mfa", methods=["GET", "POST"])
def mfa_verify():
    if _app_token is not None:
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

    limit_key = f"mfa:{user_id}"
    wait = _limited(limit_key)
    if wait:
        return _mfa_page(lockout_message(wait), locked, 429)
    code = (request.form.get("code") or "").strip()
    trust_device = request.form.get("trust_device") == "1" or session.get("mfa_trust", False)
    if not code:
        return _mfa_page("Verification code is required", locked)

    enc_key = None
    if locked:
        enc_password = (request.form.get("encryption_password") or "").strip()
        if not enc_password:
            return _mfa_page("Encryption password is required", locked)
        enc_key = db.derive_key_if_valid(enc_password)
        if enc_key is None:
            _auth_limiter.failure(limit_key)
            return _mfa_page("Invalid encryption password", locked)

    secret = db.get_totp_secret(user_id, key=enc_key)
    step = verify_totp(secret, code, user["totp_last_step"]) if secret else None
    if step is None or not db.claim_totp_step(user_id, step):
        _auth_limiter.failure(limit_key)
        log.warning("Failed MFA verification for %s from %s", user["username"], request.remote_addr)
        return _mfa_page("Invalid verification code", locked)
    _auth_limiter.success(limit_key)

    if enc_key is not None:
        db.set_master_key(enc_key)
        log.info("Database unlocked during MFA verification for user: %s", user["username"])
    _start_session(user)
    log.info("MFA verified for user: %s", user["username"])
    resp = app.make_response(redirect("/"))
    if trust_device:
        _create_trust_cookie(user["id"], resp)
    return resp


@app.post("/api/mfa/setup")
@_login_required
def mfa_setup():
    user = g.user
    if user.get("totp_enabled"):
        return jsonify({"error": "MFA is already enabled"}), 400

    secret = pyotp.random_base32()
    session["mfa_setup_secret"] = secret
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user["username"], issuer_name="Cert Generator")

    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    qr_svg = buf.getvalue().decode()

    return jsonify({"secret": secret, "qr_svg": qr_svg, "provisioning_uri": uri})


@app.post("/api/mfa/confirm")
@_login_required
def mfa_confirm():
    user = g.user
    secret = session.get("mfa_setup_secret")
    if not secret:
        return jsonify({"error": "No MFA setup in progress"}), 400

    code = _str_field(_json_body(), "code").strip()
    if not code:
        return jsonify({"error": "Verification code is required"}), 400

    step = verify_totp(secret, code, 0)
    if step is None:
        return jsonify({"error": "Invalid verification code. Check your authenticator app and try again."}), 400

    db.update_user_totp(user["id"], secret, True, last_step=step)
    db.delete_trusted_devices(user["id"])
    _revoke_other_sessions(user["id"])
    session.pop("mfa_setup_secret", None)
    log.info("MFA enabled for user: %s", user["username"])
    return jsonify({"ok": True})


@app.post("/api/mfa/disable")
@_login_required
def mfa_disable():
    user = g.user
    if not user.get("totp_enabled"):
        return jsonify({"error": "MFA is not enabled"}), 400

    data = _json_body()
    password = _str_field(data, "password")
    code = _str_field(data, "code").strip()
    if not password or not code:
        return jsonify({"error": "Password and verification code are required"}), 400

    limit_key = f"mfa:{user['id']}"
    wait = _limited(limit_key)
    if wait:
        return jsonify({"error": lockout_message(wait)}), 429
    if not db.verify_user(user["username"], password):
        _auth_limiter.failure(limit_key)
        return jsonify({"error": "Invalid password"}), 400
    secret = db.get_totp_secret(user["id"])
    step = verify_totp(secret, code, user["totp_last_step"]) if secret else None
    if step is None or not db.claim_totp_step(user["id"], step):
        _auth_limiter.failure(limit_key)
        return jsonify({"error": "Invalid verification code"}), 400
    _auth_limiter.success(limit_key)

    db.update_user_totp(user["id"], None, False)
    db.delete_trusted_devices(user["id"])
    _revoke_other_sessions(user["id"])
    log.info("MFA disabled for user: %s", user["username"])
    return jsonify({"ok": True})


@app.get("/api/mfa/status")
@_login_required
def mfa_status():
    user = g.user
    return jsonify({
        "enabled": bool(user.get("totp_enabled")),
        "require_password": bool(user.get("require_password")),
        "trusted_device_count": db.count_trusted_devices(user["id"]),
    })


@app.post("/api/mfa/require-password")
@app.post("/api/account/require-password")
@_login_required
def account_require_password():
    user = g.user
    require = bool(_json_body().get("require_password"))
    db.update_user_require_password(user["id"], require)
    log.info("Require-password set to %s for user: %s", require, user["username"])
    return jsonify({"ok": True})


@app.post("/api/mfa/revoke-devices")
@_login_required
def mfa_revoke_devices():
    user = g.user
    count = db.delete_trusted_devices(user["id"])
    _revoke_other_sessions(user["id"])
    log.info("Revoked %d trusted devices and other sessions for user: %s", count, user["username"])
    return jsonify({"ok": True, "revoked": count})


@app.get("/api/account/status")
@_login_required
def account_status():
    user = g.user
    return jsonify({
        "require_password": bool(user.get("require_password")),
        "mfa_enabled": bool(user.get("totp_enabled")),
    })


@app.get("/api/devices")
@_login_required
def list_devices():
    return jsonify({"devices": db.list_trusted_devices(g.user["id"])})


@app.delete("/api/devices/<int:device_id>")
@_login_required
def delete_device(device_id: int):
    user = g.user
    if not db.delete_trusted_device(device_id, user["id"]):
        return jsonify({"error": "Device not found"}), 404
    log.info("Revoked trusted device %d for user: %s", device_id, user["username"])
    return jsonify({"ok": True})


# ── Exports ─────────────────────────────────────────────────────────

def _downloads_dir() -> Path:
    downloads = Path(os.environ.get("EXPORT_DIR", str(Path.home() / "Downloads")))
    downloads.mkdir(parents=True, exist_ok=True)
    return downloads


def _safe_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).strip('. ') or "export"


def _save_export(data: bytes, filename: str) -> str:
    safe_name = _safe_filename(filename)
    out = _downloads_dir() / safe_name
    counter = 1
    while out.exists():
        stem = Path(safe_name).stem
        suffix = Path(safe_name).suffix
        out = _downloads_dir() / f"{stem} ({counter}){suffix}"
        counter += 1
    out.write_bytes(data)
    return str(out)


def _deliver_export(data: bytes, filename: str) -> Response:
    """Desktop mode saves to the Downloads folder; server mode streams the file
    to the browser and never writes key material to the server's disk."""
    if _app_token is not None:
        return jsonify({"path": _save_export(data, filename)})
    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=_safe_filename(filename),
        mimetype="application/octet-stream",
        max_age=0,
    )


# ── Certificate authorities and certificates ───────────────────────

@app.get("/")
def index():
    return render_template(
        "index.html",
        server_mode=_app_token is None,
        username=g.user["username"] if g.get("user") else None,
    )


@app.get("/api/algorithms")
def get_algorithms():
    return jsonify(crypto_engine.ALGORITHMS)


@app.get("/api/templates")
def get_templates():
    return jsonify({
        k: {"label": v["label"], "description": v["description"], "default_days": v["default_days"],
             "include_email": v.get("include_email", False)}
        for k, v in crypto_engine.CERT_TEMPLATES.items()
    })


def _validate_ca_request(data: dict[str, Any], default_days: int, name_suffix: str):
    """Returns (domain, name, algorithm, lifetime_days) or an error response tuple."""
    domain = _str_field(data, "domain").strip()
    name = _str_field(data, "name").strip()
    algorithm = _str_field(data, "algorithm", "ecdsa-p384")
    lifetime_days = _parse_int(data.get("lifetime_days"), default_days)

    if not domain or not DOMAIN_RE.match(domain):
        return None, (jsonify({"error": "A valid domain name is required"}), 400)
    if not name:
        name = f"{domain} {name_suffix}"
    if len(name) > 200:
        return None, (jsonify({"error": "CA name too long"}), 400)
    if algorithm not in crypto_engine.ALGORITHMS:
        return None, (jsonify({"error": f"Invalid algorithm. Choose from: {crypto_engine.ALGORITHMS}"}), 400)
    if lifetime_days is None or lifetime_days < 1 or lifetime_days > 36500:
        return None, (jsonify({"error": "Lifetime must be an integer between 1 and 36500 days"}), 400)
    return (domain, name, algorithm, lifetime_days), None


@app.post("/api/ca")
def create_ca():
    fields, error = _validate_ca_request(_json_body(), 3650, "Root CA")
    if error:
        return error
    domain, name, algorithm, lifetime_days = fields
    db.require_unlocked()

    cert_pem, key_pem, serial, not_before, not_after = crypto_engine.create_ca(
        domain=domain,
        name=name,
        algorithm=algorithm,
        lifetime_days=lifetime_days,
    )

    ca_id = db.save_ca(
        name=name,
        domain=domain,
        algorithm=algorithm,
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        cert_pem=cert_pem,
        key_pem=key_pem,
    )

    log.info("CA created: %s (domain=%s, algo=%s)", name, domain, algorithm)
    return jsonify({"id": ca_id, "name": name, "domain": domain, "serial": serial}), 201


@app.get("/api/ca")
def list_cas():
    return jsonify(db.list_cas())


@app.get("/api/ca/<int:ca_id>")
def get_ca(ca_id: int):
    ca = db.get_ca(ca_id)
    if not ca:
        return jsonify({"error": "CA not found"}), 404
    safe = {k: v for k, v in ca.items() if k not in ("cert_pem", "key_pem")}
    safe["child_cas"] = db.list_child_cas(ca_id)
    safe["is_root"] = ca.get("parent_ca_id") is None
    return jsonify(safe)


@app.delete("/api/ca/<int:ca_id>")
def delete_ca(ca_id: int):
    if db.delete_ca(ca_id):
        log.info("CA deleted: id=%d", ca_id)
        return jsonify({"ok": True})
    return jsonify({"error": "CA not found"}), 404


@app.post("/api/ca/<int:ca_id>/intermediate")
def create_intermediate(ca_id: int):
    parent = db.get_ca(ca_id)
    if not parent:
        return jsonify({"error": "Parent CA not found"}), 404
    if not crypto_engine.ca_allows_subordinate_ca(parent["cert_pem"]):
        return jsonify({"error": "This CA's path length constraint does not allow issuing intermediate CAs. "
                                 "Create the intermediate under the root CA instead."}), 400

    fields, error = _validate_ca_request(_json_body(), 1825, "Intermediate CA")
    if error:
        return error
    domain, name, algorithm, lifetime_days = fields

    cert_pem, key_pem, serial, not_before, not_after = crypto_engine.create_intermediate_ca(
        parent_cert_pem=parent["cert_pem"],
        parent_key_pem=parent["key_pem"],
        domain=domain,
        name=name,
        algorithm=algorithm,
        lifetime_days=lifetime_days,
    )

    ca_id_new = db.save_ca(
        name=name,
        domain=domain,
        algorithm=algorithm,
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        cert_pem=cert_pem,
        key_pem=key_pem,
        parent_ca_id=ca_id,
    )

    log.info("Intermediate CA created: %s (parent=%d, algo=%s)", name, ca_id, algorithm)
    return jsonify({"id": ca_id_new, "name": name, "domain": domain, "serial": serial}), 201


@app.post("/api/ca/<int:ca_id>/certs")
def issue_cert(ca_id: int):
    ca = db.get_ca(ca_id)
    if not ca:
        return jsonify({"error": "CA not found"}), 404

    data = _json_body()
    common_name = _str_field(data, "common_name").strip()
    san_domains_raw = _str_field(data, "san_domains").strip()
    algorithm = _str_field(data, "algorithm", "ecdsa-p384")
    template = _str_field(data, "template", "web-server")
    email = _str_field(data, "email").strip() or None
    upn = _str_field(data, "upn").strip() or None
    include_crl_dp = bool(data.get("include_crl_dp", False))
    lifetime_days = _parse_int(data.get("lifetime_days"), 365)

    if not common_name or len(common_name) > 253:
        return jsonify({"error": "A valid common name is required (max 253 chars)"}), 400
    if algorithm not in crypto_engine.ALGORITHMS:
        return jsonify({"error": f"Invalid algorithm. Choose from: {crypto_engine.ALGORITHMS}"}), 400
    if template not in crypto_engine.CERT_TEMPLATES:
        return jsonify({"error": f"Invalid template. Choose from: {list(crypto_engine.CERT_TEMPLATES.keys())}"}), 400
    if lifetime_days is None or lifetime_days < 1 or lifetime_days > 36500:
        return jsonify({"error": "Lifetime must be an integer between 1 and 36500 days"}), 400

    san_list = _parse_san_list(san_domains_raw, common_name)
    if san_list is None:
        return jsonify({"error": "Each SAN must be a valid DNS name or IP address"}), 400

    crl_dp_url = None
    if include_crl_dp:
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', ca["name"])
        crl_dp_url = f"http://pki.{ca['domain']}/crl/{safe_name}.crl"

    cert_pem, key_pem, serial, not_before, not_after = crypto_engine.issue_certificate(
        ca_cert_pem=ca["cert_pem"],
        ca_key_pem=ca["key_pem"],
        common_name=common_name,
        san_domains=san_list,
        algorithm=algorithm,
        lifetime_days=lifetime_days,
        template=template,
        email=email,
        upn=upn,
        crl_dp_url=crl_dp_url,
    )

    cert_id = db.save_cert(
        ca_id=ca_id,
        common_name=common_name,
        san_domains=",".join(san_list),
        algorithm=algorithm,
        template=template,
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        cert_pem=cert_pem,
        key_pem=key_pem,
    )

    log.info("Certificate issued: %s (ca=%d, template=%s, algo=%s)", common_name, ca_id, template, algorithm)
    return jsonify({"id": cert_id, "common_name": common_name, "serial": serial}), 201


@app.get("/api/ca/<int:ca_id>/certs")
def list_certs_for_ca(ca_id: int):
    return jsonify(db.list_certs(ca_id))


@app.get("/api/certs")
def list_all_certs():
    return jsonify(db.list_certs())


@app.get("/api/certs/<int:cert_id>")
def get_cert(cert_id: int):
    cert = db.get_cert(cert_id)
    if not cert:
        return jsonify({"error": "Certificate not found"}), 404
    safe = {k: v for k, v in cert.items() if k not in ("cert_pem", "key_pem")}
    return jsonify(safe)


@app.post("/api/certs/<int:cert_id>/revoke")
def revoke_cert(cert_id: int):
    if db.revoke_cert(cert_id):
        log.info("Certificate revoked: id=%d", cert_id)
        return jsonify({"ok": True, "note": "Re-export the CA's CRL to update revocation status on endpoints."})
    return jsonify({"error": "Certificate not found or already revoked"}), 404


@app.get("/api/ca/<int:ca_id>/crl")
def download_crl(ca_id: int):
    ca = db.get_ca(ca_id)
    if not ca:
        return jsonify({"error": "CA not found"}), 404

    revoked = db.list_revoked_serials(ca_id)
    crl_der = crypto_engine.generate_crl(
        ca_cert_pem=ca["cert_pem"],
        ca_key_pem=ca["key_pem"],
        revoked_serials=revoked,
    )

    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', ca["name"])
    return _deliver_export(crl_der, f"{safe_name}.crl")


@app.delete("/api/certs/<int:cert_id>")
def delete_cert(cert_id: int):
    if db.delete_cert(cert_id):
        log.info("Certificate deleted: id=%d", cert_id)
        return jsonify({"ok": True})
    return jsonify({"error": "Certificate not found"}), 404


@app.post("/api/export/ca/<int:ca_id>")
def export_ca(ca_id: int):
    ca = db.get_ca(ca_id)
    if not ca:
        return jsonify({"error": "CA not found"}), 404

    data = _json_body()
    fmt = _str_field(data, "format", "pem")
    part = _str_field(data, "part", "both")
    password = _str_field(data, "password") or None

    if fmt not in VALID_FORMATS:
        return jsonify({"error": f"Invalid format. Choose from: {VALID_FORMATS}"}), 400
    if part not in VALID_CA_PARTS:
        return jsonify({"error": f"Invalid part. Choose from: {VALID_CA_PARTS}"}), 400

    try:
        if part == "public":
            export_data, filename = crypto_engine.export_public_only(ca["cert_pem"], fmt)
        elif part == "private":
            export_data, filename = crypto_engine.export_private_only(ca["key_pem"], fmt)
        else:
            export_data, filename = crypto_engine.export_certificate(
                ca["cert_pem"], ca["key_pem"], fmt, password=password,
            )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return _deliver_export(export_data, f"ca-{ca['domain']}-{filename}")


@app.post("/api/export/cert/<int:cert_id>")
def export_cert(cert_id: int):
    cert = db.get_cert(cert_id)
    if not cert:
        return jsonify({"error": "Certificate not found"}), 404

    data = _json_body()
    fmt = _str_field(data, "format", "pem")
    part = _str_field(data, "part", "both")
    password = _str_field(data, "password") or None
    include_chain = bool(data.get("include_chain", False))

    if fmt not in VALID_FORMATS:
        return jsonify({"error": f"Invalid format. Choose from: {VALID_FORMATS}"}), 400
    if part not in VALID_CERT_PARTS:
        return jsonify({"error": f"Invalid part. Choose from: {VALID_CERT_PARTS}"}), 400

    ca_chain = db.get_ca_cert_chain(cert["ca_id"])
    issuer_pem = ca_chain[0] if ca_chain else None

    try:
        if part == "public":
            export_data, filename = crypto_engine.export_public_only(cert["cert_pem"], fmt)
        elif part == "private":
            export_data, filename = crypto_engine.export_private_only(cert["key_pem"], fmt)
        elif part == "chain":
            export_data, filename = b"".join([cert["cert_pem"], *ca_chain]), "fullchain.pem"
        else:
            export_data, filename = crypto_engine.export_certificate(
                cert["cert_pem"], cert["key_pem"], fmt,
                ca_cert_pem=issuer_pem if include_chain else None,
                password=password,
            )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return _deliver_export(export_data, f"{cert['common_name']}-{filename}")


# ── SSH keys ────────────────────────────────────────────────────────

VALID_SSH_FORMATS = ("openssh", "pem")


@app.get("/api/ssh-keys")
def list_ssh_keys():
    return jsonify(db.list_ssh_keys())


@app.get("/api/ssh-keys/<int:key_id>")
def get_ssh_key(key_id: int):
    key = db.get_ssh_key(key_id)
    if not key:
        return jsonify({"error": "SSH key not found"}), 404
    safe = {k: v for k, v in key.items() if k != "private_key"}
    safe["public_key"] = key["public_key"].decode("utf-8") if isinstance(key["public_key"], bytes) else key["public_key"]
    return jsonify(safe)


@app.post("/api/ssh-keys")
def create_ssh_key():
    data = _json_body()
    name = _str_field(data, "name").strip()
    algorithm = _str_field(data, "algorithm", "rsa-4096")
    comment = _str_field(data, "comment").strip()
    passphrase = _str_field(data, "passphrase").strip() or None

    if not name or len(name) > 200:
        return jsonify({"error": "A name is required (max 200 chars)"}), 400
    if algorithm not in crypto_engine.SSH_ALGORITHMS:
        return jsonify({"error": f"Invalid algorithm. Choose from: {crypto_engine.SSH_ALGORITHMS}"}), 400
    db.require_unlocked()

    private_bytes, public_bytes, fingerprint = crypto_engine.generate_ssh_key(
        algorithm=algorithm,
        passphrase=passphrase,
        comment=comment,
    )

    key_id = db.save_ssh_key(
        name=name,
        algorithm=algorithm,
        comment=comment,
        fingerprint=fingerprint,
        public_key=public_bytes,
        private_key=private_bytes,
        has_passphrase=bool(passphrase),
    )

    log.info("SSH key generated: %s (algo=%s)", name, algorithm)
    return jsonify({"id": key_id, "name": name, "fingerprint": fingerprint}), 201


@app.post("/api/ssh-keys/import")
def import_ssh_key():
    data = _json_body()
    name = _str_field(data, "name").strip()
    private_key_text = _str_field(data, "private_key").strip()
    passphrase = _str_field(data, "passphrase").strip() or None
    comment = _str_field(data, "comment").strip()

    if not name or len(name) > 200:
        return jsonify({"error": "A name is required (max 200 chars)"}), 400
    if not private_key_text:
        return jsonify({"error": "Private key is required"}), 400

    try:
        private_bytes, public_bytes, algorithm, fingerprint, has_passphrase = (
            crypto_engine.parse_ssh_key(private_key_text, passphrase=passphrase)
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if comment:
        public_bytes = public_bytes.rstrip() + b" " + comment.encode("utf-8") + b"\n"

    key_id = db.save_ssh_key(
        name=name,
        algorithm=algorithm,
        comment=comment,
        fingerprint=fingerprint,
        public_key=public_bytes,
        private_key=private_bytes,
        has_passphrase=has_passphrase,
        imported=True,
    )

    algo_label = crypto_engine.SSH_ALGORITHM_LABELS.get(algorithm, algorithm)
    log.info("SSH key imported: %s (algo=%s)", name, algorithm)
    return jsonify({"id": key_id, "name": name, "fingerprint": fingerprint, "algorithm": algo_label}), 201


@app.delete("/api/ssh-keys/<int:key_id>")
def delete_ssh_key(key_id: int):
    if db.delete_ssh_key(key_id):
        log.info("SSH key deleted: id=%d", key_id)
        return jsonify({"ok": True})
    return jsonify({"error": "SSH key not found"}), 404


@app.post("/api/export/ssh-key/<int:key_id>")
def export_ssh_key(key_id: int):
    key = db.get_ssh_key(key_id)
    if not key:
        return jsonify({"error": "SSH key not found"}), 404

    data = _json_body()
    part = _str_field(data, "part", "private")
    fmt = _str_field(data, "format", "openssh")
    passphrase = _str_field(data, "passphrase").strip() or None
    original_passphrase = _str_field(data, "original_passphrase").strip() or None
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', key["name"])

    if part == "public":
        pub = key["public_key"]
        if isinstance(pub, str):
            pub = pub.encode("utf-8")
        return _deliver_export(pub, f"{safe_name}.pub")

    if fmt not in VALID_SSH_FORMATS:
        return jsonify({"error": f"Invalid format. Choose from: {VALID_SSH_FORMATS}"}), 400

    try:
        export_data, filename = crypto_engine.export_ssh_private_key(
            key["private_key"], fmt, passphrase=passphrase,
            original_passphrase=original_passphrase,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return _deliver_export(export_data, f"{safe_name}-{filename}")


@app.get("/api/ssh-keys/<int:key_id>/private")
def get_ssh_private_key(key_id: int):
    key = db.get_ssh_key(key_id)
    if not key:
        return jsonify({"error": "SSH key not found"}), 404
    priv = key["private_key"]
    if isinstance(priv, bytes):
        priv = priv.decode("utf-8")
    return jsonify({"private_key": priv})


# ── Encryption settings ─────────────────────────────────────────────

def _encryption_limit_key() -> str:
    return f"unlock:{g.user['id']}" if g.get("user") else "unlock:desktop"


@app.get("/api/settings/encryption")
def get_encryption_status():
    enabled = db.is_encryption_enabled()
    unlocked = db.is_unlocked()
    dismissed = db.get_setting("encryption_dismissed") is not None
    return jsonify({"enabled": enabled, "unlocked": unlocked or not enabled, "dismissed": dismissed})


def _password_attempt(check: Callable[[], None]):
    """Run a password-checking action under the shared attempt limiter."""
    limit_key = _encryption_limit_key()
    wait = _limited(limit_key)
    if wait:
        return jsonify({"error": lockout_message(wait)}), 429
    try:
        check()
    except ValueError as e:
        if "password" in str(e).lower():
            _auth_limiter.failure(limit_key)
        return jsonify({"error": str(e)}), 400
    _auth_limiter.success(limit_key)
    return jsonify({"ok": True})


@app.post("/api/settings/encryption/enable")
def enable_encryption():
    data = _json_body()
    password = _str_field(data, "password").strip()
    confirm = _str_field(data, "confirm").strip()
    if not password:
        return jsonify({"error": "Password is required"}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    try:
        db.enable_encryption(password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True})


@app.post("/api/settings/encryption/disable")
def disable_encryption():
    password = _str_field(_json_body(), "password").strip()
    if not password:
        return jsonify({"error": "Password is required"}), 400
    return _password_attempt(lambda: db.disable_encryption(password))


@app.post("/api/settings/encryption/unlock")
def unlock_encryption():
    password = _str_field(_json_body(), "password").strip()
    if not password:
        return jsonify({"error": "Password is required"}), 400

    def check() -> None:
        if not db.unlock(password):
            raise ValueError("Wrong password")

    return _password_attempt(check)


@app.post("/api/settings/encryption/change-password")
def change_encryption_password():
    data = _json_body()
    old_password = _str_field(data, "old_password").strip()
    new_password = _str_field(data, "new_password").strip()
    confirm = _str_field(data, "confirm").strip()
    if not old_password or not new_password:
        return jsonify({"error": "Both passwords are required"}), 400
    if new_password != confirm:
        return jsonify({"error": "New passwords do not match"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    return _password_attempt(lambda: db.change_password(old_password, new_password))


@app.post("/api/settings/encryption/dismiss")
def dismiss_encryption_prompt():
    db.set_setting("encryption_dismissed", b"1")
    return jsonify({"ok": True})


# ── Backup and restore ──────────────────────────────────────────────

@app.post("/api/backup")
def create_backup():
    password = _str_field(_json_body(), "password").strip()
    if not password:
        return jsonify({"error": "Password is required"}), 400
    export = db.export_all_data()
    plaintext = json.dumps(export).encode("utf-8")
    encrypted = crypto_engine.encrypt_backup(plaintext, password)
    log.info("Backup created")
    return _deliver_export(encrypted, "cert-generator-backup.certbak")


@app.post("/api/restore")
def restore_backup():
    data = _json_body()
    password = _str_field(data, "password").strip()
    file_data = _str_field(data, "file_data")
    if not password:
        return jsonify({"error": "Password is required"}), 400
    if not file_data:
        return jsonify({"error": "No backup file provided"}), 400
    try:
        raw = base64.b64decode(file_data)
    except (binascii.Error, ValueError):
        return jsonify({"error": "Invalid file data"}), 400
    try:
        plaintext = crypto_engine.decrypt_backup(raw, password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    try:
        backup = json.loads(plaintext)
    except json.JSONDecodeError:
        return jsonify({"error": "Corrupted backup data"}), 400
    if not isinstance(backup, dict):
        return jsonify({"error": "Corrupted backup data"}), 400
    try:
        counts = db.import_all_data(backup)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    # Every session was revoked by the restore; keep this one if its user still exists.
    if g.get("user"):
        restored = db.get_user(g.user["username"])
        if restored is not None:
            session["sv"] = restored["session_version"]
        else:
            session.clear()
    log.info("Backup restored: %s", counts)
    return jsonify({"ok": True, "counts": counts})
