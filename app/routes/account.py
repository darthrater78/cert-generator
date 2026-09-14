"""Account API: MFA enrolment, require-password, trusted devices."""
from __future__ import annotations

import io
import logging

import pyotp
import qrcode
import qrcode.image.svg
from flask import Blueprint, g, jsonify, session

from .. import db
from ..security import lockout_message, verify_totp
from ..web import auth_limiter, error, json_body, login_required, str_field

log = logging.getLogger("cert-generator")

bp = Blueprint("account", __name__)


def _revoke_other_sessions(user_id: int) -> None:
    """End every other session for the user while keeping the current one."""
    session["sv"] = db.bump_session_version(user_id)


@bp.post("/api/mfa/setup")
@login_required
def mfa_setup():
    user = g.user
    if user.get("totp_enabled"):
        return error("MFA is already enabled")

    secret = pyotp.random_base32()
    session["mfa_setup_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="Cert Generator")

    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return jsonify({"secret": secret, "qr_svg": buf.getvalue().decode(), "provisioning_uri": uri})


@bp.post("/api/mfa/confirm")
@login_required
def mfa_confirm():
    user = g.user
    secret = session.get("mfa_setup_secret")
    if not secret:
        return error("No MFA setup in progress")

    code = str_field(json_body(), "code").strip()
    if not code:
        return error("Verification code is required")

    step = verify_totp(secret, code, 0)
    if step is None:
        return error("Invalid verification code. Check your authenticator app and try again.")

    db.update_user_totp(user["id"], secret, True, last_step=step)
    db.delete_trusted_devices(user["id"])
    _revoke_other_sessions(user["id"])
    session.pop("mfa_setup_secret", None)
    log.info("MFA enabled for user: %s", user["username"])
    return jsonify({"ok": True})


@bp.post("/api/mfa/disable")
@login_required
def mfa_disable():
    user = g.user
    if not user.get("totp_enabled"):
        return error("MFA is not enabled")

    data = json_body()
    password = str_field(data, "password")
    code = str_field(data, "code").strip()
    if not password or not code:
        return error("Password and verification code are required")

    limit_key = f"mfa:{user['id']}"
    wait = auth_limiter.retry_after(limit_key)
    if wait:
        return error(lockout_message(wait), 429)
    if not db.verify_user(user["username"], password):
        auth_limiter.failure(limit_key)
        return error("Invalid password")
    secret = db.get_totp_secret(user["id"])
    step = verify_totp(secret, code, user["totp_last_step"]) if secret else None
    if step is None or not db.claim_totp_step(user["id"], step):
        auth_limiter.failure(limit_key)
        return error("Invalid verification code")
    auth_limiter.success(limit_key)

    db.update_user_totp(user["id"], None, False)
    db.delete_trusted_devices(user["id"])
    _revoke_other_sessions(user["id"])
    log.info("MFA disabled for user: %s", user["username"])
    return jsonify({"ok": True})


@bp.get("/api/mfa/status")
@login_required
def mfa_status():
    user = g.user
    return jsonify({
        "enabled": bool(user.get("totp_enabled")),
        "require_password": bool(user.get("require_password")),
        "trusted_device_count": db.count_trusted_devices(user["id"]),
    })


@bp.post("/api/mfa/require-password")
@bp.post("/api/account/require-password")
@login_required
def account_require_password():
    user = g.user
    require = bool(json_body().get("require_password"))
    db.update_user_require_password(user["id"], require)
    log.info("Require-password set to %s for user: %s", require, user["username"])
    return jsonify({"ok": True})


@bp.post("/api/mfa/revoke-devices")
@login_required
def mfa_revoke_devices():
    user = g.user
    count = db.delete_trusted_devices(user["id"])
    _revoke_other_sessions(user["id"])
    log.info("Revoked %d trusted devices and other sessions for user: %s", count, user["username"])
    return jsonify({"ok": True, "revoked": count})


@bp.get("/api/account/status")
@login_required
def account_status():
    user = g.user
    return jsonify({
        "require_password": bool(user.get("require_password")),
        "mfa_enabled": bool(user.get("totp_enabled")),
    })


@bp.get("/api/devices")
@login_required
def list_devices():
    return jsonify({"devices": db.list_trusted_devices(g.user["id"])})


@bp.delete("/api/devices/<int:device_id>")
@login_required
def delete_device(device_id: int):
    user = g.user
    if not db.delete_trusted_device(device_id, user["id"]):
        return error("Device not found", 404)
    log.info("Revoked trusted device %d for user: %s", device_id, user["username"])
    return jsonify({"ok": True})
