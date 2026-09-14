"""Flask application: configuration, request hooks, and blueprint registration."""
from __future__ import annotations

import logging
import os
import secrets
import time
from pathlib import Path

from flask import Flask, Response, g, jsonify, redirect, render_template, request, session
from werkzeug.exceptions import HTTPException

from . import __version__, db, state
from .routes import account, auth, pki, settings, ssh
from .security import is_cross_site_request
from .web import auth_limiter

log = logging.getLogger("cert-generator")

# Kept for callers that import these from app.server (desktop launcher, tests).
_auth_limiter = auth_limiter


def set_bound_port(port: int) -> None:
    state.bound_port = port


def set_app_token(token: str | None) -> None:
    state.app_token = token


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

for blueprint in (auth.bp, account.bp, pki.bp, ssh.bp, settings.bp):
    app.register_blueprint(blueprint)

with app.app_context():
    db.init_db()


_PUBLIC_PATHS = {"/login", "/setup", "/logout", "/mfa", "/favicon.ico"}
_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


# ── Request hooks ───────────────────────────────────────────────────

@app.context_processor
def _template_globals():
    return {"app_version": __version__}


@app.before_request
def _start_timer():
    request._start_time = time.monotonic()


@app.after_request
def _finish_response(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if not state.desktop_mode():
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
    if not secrets.compare_digest(request.cookies.get("_app_token", ""), state.app_token or ""):
        return Response("Forbidden", status=403, content_type="text/plain")
    if request.method not in _SAFE_METHODS:
        origin = request.headers.get("Origin")
        if origin:
            port = state.bound_port or 5174
            if origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
                return jsonify({"error": "Forbidden"}), 403
    return None


def _cross_site_rejection() -> Response | tuple[Response, int] | None:
    if request.method in _SAFE_METHODS or not is_cross_site_request(request.host, request.headers):
        return None
    log.warning("Blocked cross-site %s %s (Origin=%r)", request.method, request.path, request.headers.get("Origin"))
    if request.path.startswith("/api/"):
        return jsonify({"error": "Cross-site request blocked"}), 403
    return Response("Cross-site request blocked", status=403, content_type="text/plain")


def _session_user():
    username = session.get("user")
    if not username:
        return None
    user = db.get_user(username)
    if user is not None and user["session_version"] == session.get("sv", 0):
        return user
    # Password reset, MFA change, restore, or deleted user: this session is revoked.
    session.clear()
    return None


@app.before_request
def _auth_check() -> Response | None:
    g.user = None

    # --- pywebview mode: app token auth ---
    if state.desktop_mode():
        return _app_token_check()

    # --- server mode: session auth ---
    rejection = _cross_site_rejection()
    if rejection is not None:
        return rejection
    if request.path in _PUBLIC_PATHS or request.path.startswith("/static/"):
        return None
    if not db.has_users():
        return redirect("/setup")
    # MFA pending: user authenticated with password but hasn't completed MFA yet
    if session.get("mfa_pending"):
        return redirect("/mfa")

    g.user = _session_user() or auth.auto_login_from_trust_cookie()
    if g.user is not None:
        return None
    if request.path.startswith("/api/"):
        return Response("Unauthorized", status=401, content_type="text/plain")
    return redirect("/login")


@app.get("/")
def index():
    return render_template(
        "index.html",
        server_mode=not state.desktop_mode(),
        username=g.user["username"] if g.get("user") else None,
    )
