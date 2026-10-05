"""Cloudflare account connection and each CA's CRL Worker (server mode only)."""
from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

from .. import cloudflare, crl_worker, crypto_engine, db, state
from ..cloudflare import CloudflareError, Credentials
from ..errors import UserError
from ..web import error, json_body, login_required, recent_auth_required, str_field

log = logging.getLogger("cert-generator")

bp = Blueprint("cloudflare", __name__)

MAX_TOKEN_LEN = 200


@bp.before_request
def _server_mode_only():
    if state.desktop_mode():
        return error("Cloudflare publishing needs the Docker version", 404)
    return None


@bp.errorhandler(CloudflareError)
def _cloudflare_error(exc: CloudflareError):
    return error(exc.user_message, 502)


# ── Account ─────────────────────────────────────────────────────────

@bp.get("/api/cloudflare")
@login_required
def get_connection():
    return jsonify({
        "connected": db.has_cloudflare_token(),
        "account_id": db.cloudflare_account_id(),
        "encryption_enabled": db.is_encryption_enabled(),
        "workers": db.count_ca_workers(),
    })


@bp.post("/api/cloudflare/connect")
@login_required
@recent_auth_required
def connect():
    data = json_body()
    token = str_field(data, "token").strip()
    account_id = str_field(data, "account_id").strip().lower()
    if not token or len(token) > MAX_TOKEN_LEN or any(ch.isspace() for ch in token):
        return error("Paste the API token Cloudflare showed you")
    if not db.is_encryption_enabled():
        return error("Turn on database encryption first: the Cloudflare token is stored encrypted")
    connected = db.cloudflare_account_id()
    if connected and connected != account_id and db.count_ca_workers():
        return error("Workers are deployed in the connected account. Tear them down before switching accounts")
    found = cloudflare.check_credentials(Credentials(token=token, account_id=account_id))
    db.set_cloudflare_credentials(account_id, token)
    log.warning("Cloudflare account connected (%s)", account_id)
    return jsonify({"ok": True, **found})


@bp.post("/api/cloudflare/disconnect")
@login_required
@recent_auth_required
def disconnect():
    if db.count_ca_workers():
        return error("Delete every CA's Worker first, or the app can no longer update or remove them", 409)
    db.clear_cloudflare_credentials()
    log.warning("Cloudflare account disconnected")
    return jsonify({"ok": True})


@bp.get("/api/cloudflare/zones")
@login_required
def zones():
    return jsonify(cloudflare.list_zones(crl_worker.credentials()))


@bp.get("/api/cloudflare/check")
@login_required
def check():
    return jsonify(cloudflare.check_credentials(crl_worker.credentials()))


@bp.get("/api/cloudflare/workers")
@login_required
def workers():
    return jsonify(crl_worker.inventory())


@bp.delete("/api/cloudflare/workers/<name>")
@login_required
@recent_auth_required
def delete_worker(name: str):
    try:
        return jsonify({"ok": True, **crl_worker.delete_by_name(name)})
    except UserError as e:
        return error(e.user_message, 404)


# ── A CA's Worker ───────────────────────────────────────────────────

def _ca_or_404(ca_id: int):
    return db.get_ca_summary(ca_id)


@bp.get("/api/ca/<int:ca_id>/cloudflare")
@login_required
def worker_status(ca_id: int):
    if _ca_or_404(ca_id) is None:
        return error("CA not found", 404)
    if request.args.get("refresh"):
        return jsonify(crl_worker.refresh(ca_id))
    return jsonify(crl_worker.status(ca_id))


@bp.post("/api/ca/<int:ca_id>/cloudflare/deploy")
@login_required
def deploy(ca_id: int):
    if _ca_or_404(ca_id) is None:
        return error("CA not found", 404)
    data = json_body()
    hostname = str_field(data, "hostname").strip() or None
    zone_id = str_field(data, "zone_id").strip() or None
    if hostname and zone_id not in {z["id"] for z in cloudflare.list_zones(crl_worker.credentials())}:
        return error("Choose one of your Cloudflare zones for the custom domain")
    if hostname and zone_id:
        zone = next(z for z in cloudflare.list_zones(crl_worker.credentials()) if z["id"] == zone_id)
        if not (hostname.lower().rstrip(".") + ".").endswith("." + zone["name"] + "."):
            return error(f"The hostname must be under {zone['name']}, e.g. crl.{zone['name']}")
    try:
        result = crl_worker.deploy(ca_id, hostname, zone_id)
    except UserError as e:
        return error(e.user_message)
    return jsonify(result)


@bp.post("/api/ca/<int:ca_id>/cloudflare/push")
@login_required
def push(ca_id: int):
    worker = db.get_ca_worker(ca_id)
    if worker is None:
        return error("This CA has no Worker", 404)
    db.require_unlocked()
    from .. import crl_publisher

    crl_publisher.publish(ca_id)  # re-sign, then push
    return jsonify(crl_worker.status(ca_id))


@bp.post("/api/ca/<int:ca_id>/cloudflare/test")
@login_required
def test(ca_id: int):
    try:
        return jsonify(crl_worker.test(ca_id))
    except UserError as e:
        return error(e.user_message, 404)


@bp.get("/api/ca/<int:ca_id>/cloudflare/crl/view")
@login_required
def view_live_crl(ca_id: int):
    """The CRL the Worker serves right now, in the CRL viewer's shape."""
    ca = db.get_ca_summary(ca_id)
    if ca is None:
        return error("CA not found", 404)
    try:
        crl_der, url = crl_worker.fetch_live(ca_id)
    except UserError as e:
        return error(e.user_message, 404)
    try:
        crl = crypto_engine.describe_crl(crl_der)
    except ValueError:
        return error("The Worker's answer isn't a CRL", 502)
    entries = crl.pop("entries")
    certs = {int(c["serial"], 16): c for c in db.list_certs(ca_id)}
    deleted = {int(s, 16) for s in db.list_deleted_revocations(ca_id)}
    current = {int(serial, 16) for serial, _ in db.list_revoked_serials(ca_id)}
    for entry in entries:
        number = int(entry.pop("serial_hex"), 16)
        cert = certs.get(number)
        entry.update(cert_id=cert["id"] if cert else None, common_name=cert["common_name"] if cert else None,
                     deleted=number in deleted)
    return jsonify({
        "ca_id": ca_id,
        "ca_name": ca["name"],
        "source": "cloudflare",
        "published_path": None,
        "public_url": url,
        "crl": crl,
        "entries": entries,
        "out_of_date": {int(e["serial"].replace(":", ""), 16) for e in entries} != current,
        "exported_next_update": ca.get("crl_next_update"),
    })


@bp.delete("/api/ca/<int:ca_id>/cloudflare")
@login_required
@recent_auth_required
def teardown(ca_id: int):
    try:
        return jsonify({"ok": True, **crl_worker.teardown(ca_id)})
    except UserError as e:
        return error(e.user_message, 404)
