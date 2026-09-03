from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import qrcode
import qrcode.image.svg
from flask import Flask, Response, jsonify, redirect, render_template, request, send_file, session

from . import crypto_engine, db

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


def set_app_token(token: str) -> None:
    global _app_token
    _app_token = token


app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

with app.app_context():
    db.init_db()


_PUBLIC_PATHS = {"/login", "/setup", "/logout", "/mfa", "/favicon.ico"}

TRUST_COOKIE_NAME = "_trust_token"
TRUST_DURATION_DAYS = 30


@app.before_request
def _start_timer():
    request._start_time = time.monotonic()


@app.after_request
def _log_request(response):
    if request.path.startswith("/static/"):
        return response
    duration_ms = (time.monotonic() - getattr(request, "_start_time", time.monotonic())) * 1000
    log.info("%s %s %s %.0fms", request.method, request.path, response.status_code, duration_ms)
    return response


@app.before_request
def _auth_check() -> Response | None:
    # --- pywebview mode: app token auth ---
    if _app_token is not None:
        if request.path == "/_auth":
            return None
        if request.cookies.get("_app_token") != _app_token:
            return Response("Forbidden", status=403, content_type="text/plain")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("Origin", "")
            if origin:
                port = _bound_port or 5174
                if f"127.0.0.1:{port}" not in origin and f"localhost:{port}" not in origin:
                    return jsonify({"error": "Forbidden"}), 403
        return None

    # --- server mode: session auth ---
    if request.path in _PUBLIC_PATHS or request.path.startswith("/static/"):
        return None

    if not db.has_users():
        if request.path != "/setup":
            return redirect("/setup")
        return None

    # MFA pending: user authenticated with password but hasn't completed MFA yet
    if session.get("mfa_pending"):
        if request.path not in ("/mfa", "/logout"):
            return redirect("/mfa")
        return None

    if not session.get("user"):
        # Try auto-login via trust token cookie
        trust_token = request.cookies.get(TRUST_COOKIE_NAME)
        if trust_token:
            token_hash = hashlib.sha256(trust_token.encode()).hexdigest()
            device = db.verify_trusted_device(token_hash)
            if device and not device.get("require_password"):
                session["user"] = device["username"]
                session.permanent = True
                log.info("Auto-login via trusted device: %s", device["username"])
                return None

        if request.path.startswith("/api/"):
            return Response("Unauthorized", status=401, content_type="text/plain")
        return redirect("/login")

    return None


@app.get("/_auth")
def _auth_set_cookie() -> Response:
    if _app_token is None:
        return Response("Not in app mode", status=404)
    token = request.args.get("token", "")
    if token != _app_token:
        return Response("Forbidden", status=403)
    resp = app.make_response("")
    resp.status_code = 302
    resp.headers["Location"] = "/"
    resp.set_cookie("_app_token", _app_token, httponly=True, samesite="Strict")
    return resp


def _create_trust_cookie(user_id: int, response: Response) -> Response:
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=TRUST_DURATION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.create_trusted_device(user_id, token_hash, expires_at)
    response.set_cookie(
        TRUST_COOKIE_NAME, raw_token,
        max_age=TRUST_DURATION_DAYS * 86400,
        httponly=True, samesite="Strict",
    )
    return response


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
    if not db.verify_user(username, password):
        return render_template("login.html", error="Invalid username or password")

    user = db.get_user(username)
    db.cleanup_expired_devices()

    if user and user.get("totp_enabled"):
        session["mfa_pending"] = user["id"]
        session["mfa_username"] = username
        session["mfa_trust"] = trust_device
        return redirect("/mfa")

    session["user"] = username
    session.permanent = True
    log.info("User logged in: %s", username)
    resp = app.make_response(redirect("/"))
    if trust_device and user:
        _create_trust_cookie(user["id"], resp)
    return resp


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if _app_token is not None or db.has_users():
        return redirect("/")
    if request.method == "GET":
        return render_template("setup.html", error=None, username=None)
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""
    if not username or len(username) > 100:
        return render_template("setup.html", error="Username is required (max 100 chars)", username=username)
    if len(password) < 8:
        return render_template("setup.html", error="Password must be at least 8 characters", username=username)
    if password != confirm:
        return render_template("setup.html", error="Passwords do not match", username=username)
    db.create_user(username, password)
    session["user"] = username
    log.info("Admin account created: %s", username)
    return redirect("/")


@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    resp = app.make_response(redirect("/login"))
    resp.delete_cookie(TRUST_COOKIE_NAME)
    return resp


@app.route("/mfa", methods=["GET", "POST"])
def mfa_verify():
    if _app_token is not None:
        return redirect("/")
    user_id = session.get("mfa_pending")
    if not user_id:
        return redirect("/login")
    if request.method == "GET":
        return render_template("mfa.html", error=None)
    code = (request.form.get("code") or "").strip()
    trust_device = request.form.get("trust_device") == "1" or session.get("mfa_trust", False)
    if not code:
        return render_template("mfa.html", error="Verification code is required")
    user = db.get_user_by_id(user_id)
    if not user or not user.get("totp_secret"):
        session.clear()
        return redirect("/login")
    totp = pyotp.TOTP(user["totp_secret"])
    if not totp.verify(code, valid_window=1):
        return render_template("mfa.html", error="Invalid verification code")

    username = session.pop("mfa_username", user["username"])
    session.pop("mfa_pending", None)
    session.pop("mfa_trust", None)
    session["user"] = username
    session.permanent = True
    log.info("MFA verified for user: %s", username)
    resp = app.make_response(redirect("/"))
    if trust_device:
        _create_trust_cookie(user["id"], resp)
    return resp


@app.post("/api/mfa/setup")
def mfa_setup():
    username = session.get("user")
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    user = db.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.get("totp_enabled"):
        return jsonify({"error": "MFA is already enabled"}), 400

    secret = pyotp.random_base32()
    session["mfa_setup_secret"] = secret
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="Cert Generator")

    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    qr_svg = buf.getvalue().decode()

    return jsonify({"secret": secret, "qr_svg": qr_svg, "provisioning_uri": uri})


@app.post("/api/mfa/confirm")
def mfa_confirm():
    username = session.get("user")
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    user = db.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    secret = session.get("mfa_setup_secret")
    if not secret:
        return jsonify({"error": "No MFA setup in progress"}), 400

    data = request.get_json()
    code = (data.get("code") or "").strip()
    if not code:
        return jsonify({"error": "Verification code is required"}), 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid verification code. Check your authenticator app and try again."}), 400

    db.update_user_totp(user["id"], secret, True)
    db.delete_trusted_devices(user["id"])
    session.pop("mfa_setup_secret", None)
    log.info("MFA enabled for user: %s", username)
    return jsonify({"ok": True})


@app.post("/api/mfa/disable")
def mfa_disable():
    username = session.get("user")
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    user = db.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if not user.get("totp_enabled"):
        return jsonify({"error": "MFA is not enabled"}), 400

    data = request.get_json()
    password = (data.get("password") or "").strip()
    code = (data.get("code") or "").strip()
    if not password or not code:
        return jsonify({"error": "Password and verification code are required"}), 400
    if not db.verify_user(username, password):
        return jsonify({"error": "Invalid password"}), 400
    totp = pyotp.TOTP(user["totp_secret"])
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid verification code"}), 400

    db.update_user_totp(user["id"], None, False)
    db.delete_trusted_devices(user["id"])
    log.info("MFA disabled for user: %s", username)
    return jsonify({"ok": True})


@app.get("/api/mfa/status")
def mfa_status():
    username = session.get("user")
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    user = db.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "enabled": bool(user.get("totp_enabled")),
        "require_password": bool(user.get("require_password")),
        "trusted_device_count": db.count_trusted_devices(user["id"]),
    })


@app.post("/api/mfa/require-password")
def mfa_require_password():
    username = session.get("user")
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    user = db.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    data = request.get_json()
    require = bool(data.get("require_password"))
    db.update_user_require_password(user["id"], require)
    log.info("Require-password set to %s for user: %s", require, username)
    return jsonify({"ok": True})


@app.post("/api/mfa/revoke-devices")
def mfa_revoke_devices():
    username = session.get("user")
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    user = db.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    count = db.delete_trusted_devices(user["id"])
    log.info("Revoked %d trusted devices for user: %s", count, username)
    return jsonify({"ok": True, "revoked": count})


@app.get("/api/download")
def download_file():
    path = request.args.get("path", "")
    if not path:
        return jsonify({"error": "No path specified"}), 400
    file_path = Path(path).resolve()
    export_dir = _downloads_dir().resolve()
    if not str(file_path).startswith(str(export_dir)):
        return jsonify({"error": "Access denied"}), 403
    if not file_path.is_file():
        return jsonify({"error": "File not found"}), 404
    return send_file(file_path, as_attachment=True)


def _parse_int(value, default: int) -> int | None:
    try:
        return int(value) if value is not None else default
    except (ValueError, TypeError):
        return None


@app.get("/")
def index():
    return render_template(
        "index.html",
        server_mode=_app_token is None,
        username=session.get("user") if _app_token is None else None,
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


@app.post("/api/ca")
def create_ca():
    data = request.get_json()
    domain: str = data.get("domain", "").strip()
    name: str = data.get("name", "").strip()
    algorithm: str = data.get("algorithm", "ecdsa-p384")
    lifetime_days = _parse_int(data.get("lifetime_days"), 3650)

    if not domain or not DOMAIN_RE.match(domain):
        return jsonify({"error": "A valid domain name is required"}), 400
    if not name:
        name = f"{domain} Root CA"
    if len(name) > 200:
        return jsonify({"error": "CA name too long"}), 400
    if algorithm not in crypto_engine.ALGORITHMS:
        return jsonify({"error": f"Invalid algorithm. Choose from: {crypto_engine.ALGORITHMS}"}), 400
    if lifetime_days is None or lifetime_days < 1 or lifetime_days > 36500:
        return jsonify({"error": "Lifetime must be an integer between 1 and 36500 days"}), 400

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
    child_cas = [c for c in db.list_cas() if c.get("parent_ca_id") == ca_id]
    safe["child_cas"] = child_cas
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

    data = request.get_json()
    domain: str = data.get("domain", "").strip()
    name: str = data.get("name", "").strip()
    algorithm: str = data.get("algorithm", "ecdsa-p384")
    lifetime_days = _parse_int(data.get("lifetime_days"), 1825)

    if not domain or not DOMAIN_RE.match(domain):
        return jsonify({"error": "A valid domain name is required"}), 400
    if not name:
        name = f"{domain} Intermediate CA"
    if len(name) > 200:
        return jsonify({"error": "CA name too long"}), 400
    if algorithm not in crypto_engine.ALGORITHMS:
        return jsonify({"error": f"Invalid algorithm. Choose from: {crypto_engine.ALGORITHMS}"}), 400
    if lifetime_days is None or lifetime_days < 1 or lifetime_days > 36500:
        return jsonify({"error": "Lifetime must be an integer between 1 and 36500 days"}), 400

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

    data = request.get_json()
    common_name: str = data.get("common_name", "").strip()
    san_domains_raw: str = data.get("san_domains", "").strip()
    algorithm: str = data.get("algorithm", "ecdsa-p384")
    template: str = data.get("template", "web-server")
    email: str = data.get("email", "").strip() or None
    upn: str = data.get("upn", "").strip() or None
    include_crl_dp: bool = data.get("include_crl_dp", False)
    lifetime_days = _parse_int(data.get("lifetime_days"), 365)

    if not common_name or len(common_name) > 253:
        return jsonify({"error": "A valid common name is required (max 253 chars)"}), 400
    if algorithm not in crypto_engine.ALGORITHMS:
        return jsonify({"error": f"Invalid algorithm. Choose from: {crypto_engine.ALGORITHMS}"}), 400
    if template not in crypto_engine.CERT_TEMPLATES:
        return jsonify({"error": f"Invalid template. Choose from: {list(crypto_engine.CERT_TEMPLATES.keys())}"}), 400
    if lifetime_days is None or lifetime_days < 1 or lifetime_days > 36500:
        return jsonify({"error": "Lifetime must be an integer between 1 and 36500 days"}), 400

    san_list = [s.strip() for s in san_domains_raw.split(",") if s.strip()] if san_domains_raw else [common_name]

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
    filename = f"{safe_name}.crl"
    saved = _save_export(crl_der, filename)
    return jsonify({"path": saved})


@app.delete("/api/certs/<int:cert_id>")
def delete_cert(cert_id: int):
    if db.delete_cert(cert_id):
        log.info("Certificate deleted: id=%d", cert_id)
        return jsonify({"ok": True})
    return jsonify({"error": "Certificate not found"}), 404


def _downloads_dir() -> Path:
    downloads = Path(os.environ.get("EXPORT_DIR", str(Path.home() / "Downloads")))
    downloads.mkdir(parents=True, exist_ok=True)
    return downloads


def _safe_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).strip('. ')


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


@app.post("/api/export/ca/<int:ca_id>")
def export_ca(ca_id: int):
    ca = db.get_ca(ca_id)
    if not ca:
        return jsonify({"error": "CA not found"}), 404

    data = request.get_json()
    fmt = data.get("format", "pem")
    part = data.get("part", "both")
    password = data.get("password") or None

    if fmt not in VALID_FORMATS:
        return jsonify({"error": f"Invalid format. Choose from: {VALID_FORMATS}"}), 400
    if part not in VALID_CA_PARTS:
        return jsonify({"error": f"Invalid part. Choose from: {VALID_CA_PARTS}"}), 400

    if part == "public":
        export_data, filename = crypto_engine.export_public_only(ca["cert_pem"], fmt)
    elif part == "private":
        export_data, filename = crypto_engine.export_private_only(ca["key_pem"], fmt)
    else:
        export_data, filename = crypto_engine.export_certificate(
            ca["cert_pem"], ca["key_pem"], fmt, password=password,
        )

    saved = _save_export(export_data, f"ca-{ca['domain']}-{filename}")
    return jsonify({"path": saved})


@app.post("/api/export/cert/<int:cert_id>")
def export_cert(cert_id: int):
    cert = db.get_cert(cert_id)
    if not cert:
        return jsonify({"error": "Certificate not found"}), 404

    data = request.get_json()
    fmt = data.get("format", "pem")
    part = data.get("part", "both")
    password = data.get("password") or None
    include_chain = data.get("include_chain", False)

    if fmt not in VALID_FORMATS:
        return jsonify({"error": f"Invalid format. Choose from: {VALID_FORMATS}"}), 400
    if part not in VALID_CERT_PARTS:
        return jsonify({"error": f"Invalid part. Choose from: {VALID_CERT_PARTS}"}), 400

    ca = db.get_ca(cert["ca_id"])
    ca_cert_pem = ca["cert_pem"] if ca else None

    if part == "public":
        export_data, filename = crypto_engine.export_public_only(cert["cert_pem"], fmt)
    elif part == "private":
        export_data, filename = crypto_engine.export_private_only(cert["key_pem"], fmt)
    elif part == "chain":
        chain = cert["cert_pem"]
        if ca_cert_pem:
            chain += ca_cert_pem
        if ca and ca.get("parent_ca_id"):
            root = db.get_ca(ca["parent_ca_id"])
            if root:
                chain += root["cert_pem"]
        export_data, filename = chain, "fullchain.pem"
    else:
        export_data, filename = crypto_engine.export_certificate(
            cert["cert_pem"], cert["key_pem"], fmt,
            ca_cert_pem=ca_cert_pem if include_chain else None,
            password=password,
        )

    saved = _save_export(export_data, f"{cert['common_name']}-{filename}")
    return jsonify({"path": saved})


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
    data = request.get_json()
    name: str = data.get("name", "").strip()
    algorithm: str = data.get("algorithm", "rsa-4096")
    comment: str = data.get("comment", "").strip()
    passphrase: str = data.get("passphrase", "").strip() or None

    if not name or len(name) > 200:
        return jsonify({"error": "A name is required (max 200 chars)"}), 400
    if algorithm not in crypto_engine.SSH_ALGORITHMS:
        return jsonify({"error": f"Invalid algorithm. Choose from: {crypto_engine.SSH_ALGORITHMS}"}), 400

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
    data = request.get_json()
    name: str = data.get("name", "").strip()
    private_key_text: str = data.get("private_key", "").strip()
    passphrase: str = data.get("passphrase", "").strip() or None
    comment: str = data.get("comment", "").strip()

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

    data = request.get_json()
    part = data.get("part", "private")
    fmt = data.get("format", "openssh")
    passphrase = data.get("passphrase", "").strip() or None
    original_passphrase = data.get("original_passphrase", "").strip() or None

    if part == "public":
        pub = key["public_key"]
        if isinstance(pub, str):
            pub = pub.encode("utf-8")
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', key["name"])
        saved = _save_export(pub, f"{safe_name}.pub")
        return jsonify({"path": saved})

    if fmt not in VALID_SSH_FORMATS:
        return jsonify({"error": f"Invalid format. Choose from: {VALID_SSH_FORMATS}"}), 400

    export_data, filename = crypto_engine.export_ssh_private_key(
        key["private_key"], fmt, passphrase=passphrase,
        original_passphrase=original_passphrase,
    )
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', key["name"])
    saved = _save_export(export_data, f"{safe_name}-{filename}")
    return jsonify({"path": saved})


@app.get("/api/ssh-keys/<int:key_id>/private")
def get_ssh_private_key(key_id: int):
    key = db.get_ssh_key(key_id)
    if not key:
        return jsonify({"error": "SSH key not found"}), 404
    priv = key["private_key"]
    if isinstance(priv, bytes):
        priv = priv.decode("utf-8")
    return jsonify({"private_key": priv})


@app.get("/api/settings/encryption")
def get_encryption_status():
    enabled = db.is_encryption_enabled()
    unlocked = db._master_key is not None
    dismissed = db.get_setting("encryption_dismissed") is not None
    return jsonify({"enabled": enabled, "unlocked": unlocked or not enabled, "dismissed": dismissed})


@app.post("/api/settings/encryption/enable")
def enable_encryption():
    data = request.get_json()
    password = (data.get("password") or "").strip()
    confirm = (data.get("confirm") or "").strip()
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
    data = request.get_json()
    password = (data.get("password") or "").strip()
    if not password:
        return jsonify({"error": "Password is required"}), 400
    try:
        db.disable_encryption(password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True})


@app.post("/api/settings/encryption/unlock")
def unlock_encryption():
    data = request.get_json()
    password = (data.get("password") or "").strip()
    if not password:
        return jsonify({"error": "Password is required"}), 400
    if db.unlock(password):
        return jsonify({"ok": True})
    return jsonify({"error": "Wrong password"}), 400


@app.post("/api/settings/encryption/change-password")
def change_encryption_password():
    data = request.get_json()
    old_password = (data.get("old_password") or "").strip()
    new_password = (data.get("new_password") or "").strip()
    confirm = (data.get("confirm") or "").strip()
    if not old_password or not new_password:
        return jsonify({"error": "Both passwords are required"}), 400
    if new_password != confirm:
        return jsonify({"error": "New passwords do not match"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    try:
        db.change_password(old_password, new_password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True})


@app.post("/api/settings/encryption/dismiss")
def dismiss_encryption_prompt():
    db.set_setting("encryption_dismissed", b"1")
    return jsonify({"ok": True})


@app.post("/api/backup")
def create_backup():
    data = request.get_json()
    password = (data.get("password") or "").strip()
    if not password:
        return jsonify({"error": "Password is required"}), 400
    export = db.export_all_data()
    plaintext = json.dumps(export).encode("utf-8")
    encrypted = crypto_engine.encrypt_backup(plaintext, password)
    saved = _save_export(encrypted, "cert-generator-backup.certbak")
    log.info("Backup created: %s", saved)
    return jsonify({"path": saved})


@app.post("/api/restore")
def restore_backup():
    data = request.get_json()
    password = (data.get("password") or "").strip()
    file_data = data.get("file_data", "")
    if not password:
        return jsonify({"error": "Password is required"}), 400
    if not file_data:
        return jsonify({"error": "No backup file provided"}), 400
    try:
        raw = base64.b64decode(file_data)
    except Exception:
        return jsonify({"error": "Invalid file data"}), 400
    try:
        plaintext = crypto_engine.decrypt_backup(raw, password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    try:
        backup = json.loads(plaintext)
    except json.JSONDecodeError:
        return jsonify({"error": "Corrupted backup data"}), 400
    try:
        counts = db.import_all_data(backup)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    log.info("Backup restored: %s", counts)
    return jsonify({"ok": True, "counts": counts})
