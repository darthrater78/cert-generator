"""Cert Generator Pal: the device API PCs call, and the admin API behind the Devices page.

Device API (/api/pal/v1/*): no session or cookies; LAN source addresses only; pairing is
HMAC-authenticated both ways and every later request is signed by the device key.
Admin API (/api/pal/*): the signed-in admin, like every other /api/ route.
Both are server mode only. Protocol: docs/cert-generator-pal.md.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from flask import Blueprint, Response, g, jsonify, request

from .. import crl_publisher, crypto_engine, db, pal, state
from ..errors import UserError
from ..pal import PalError, Policy
from ..security import AttemptLimiter, RateLimiter
from ..web import error, json_body, parse_int, str_field
from .pki import CRL_DP_MODES, MAX_LIFETIME_DAYS, crl_dp_url_for, parse_crl_base_url, publish_after_issue

log = logging.getLogger("cert-generator")

bp = Blueprint("pal", __name__)

DEVICE_PREFIX = "/api/pal/v1/"
MAX_ENROLL_BODY = 8 * 1024
MAX_REQUEST_BODY = 64 * 1024
DEFAULT_CODE_HOURS = 24
MAX_CODE_HOURS = 7 * 24
MAX_LABEL_LEN = 64
# A PC makes a handful of calls per action; the limit only stops floods.
DEVICE_RATE_LIMIT_PER_MINUTE = 120
_device_limiter = RateLimiter(DEVICE_RATE_LIMIT_PER_MINUTE)
# Wrong pairing proofs, per code id and per address.
_enroll_limiter = AttemptLimiter()

PAIRING_FAILED = "Pairing failed. Check the code, or ask your admin for a new one"
DEVICE_UNKNOWN = "This PC is not connected. Connect it again with a new pairing code"
DEVICE_REVOKED = "Your admin has disconnected this PC. Connect it again with a new pairing code"


def reset_limiters() -> None:
    _device_limiter.reset()
    _enroll_limiter.reset()


@bp.before_request
def _gate() -> Any:
    if state.desktop_mode():
        return error("Not found", 404)
    if request.path.startswith(DEVICE_PREFIX):
        # LAN design: anything that isn't a private address doesn't learn the API exists.
        if not pal.is_private_address(request.remote_addr):
            return error("Not found", 404)
        if not _device_limiter.allow(request.remote_addr or ""):
            return error("Too many requests. Try again in a minute", 429)
        # Refused while reading (413), before a large body is buffered for the signature check.
        request.max_content_length = MAX_ENROLL_BODY if request.path == DEVICE_PREFIX + "enroll" else MAX_REQUEST_BODY
    return None


# ── Shared ──────────────────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _chain_root_first(ca_id: int) -> list[str]:
    return [pem.decode() for pem in reversed(db.get_ca_cert_chain(ca_id))]


def _chain_supported(ca_id: int) -> bool:
    """Windows can't build chains through Ed25519 CAs."""
    for pem in db.get_ca_cert_chain(ca_id):
        if crypto_engine.public_key_algorithm(x509.load_pem_x509_certificate(pem).public_key()) is None:
            return False
    return True


def _crls(ca_id: int) -> list[dict[str, str]]:
    """The signed CRLs of the device's CA chain, for the PC to install alongside the CAs."""
    crls = []
    current: int | None = ca_id
    seen: set[int] = set()
    while current is not None and current not in seen:
        seen.add(current)
        ca = db.get_ca_summary(current)
        if ca is None:
            break
        der = db.get_signed_crl(current) if db.is_crl_maintained(current) else None
        if der:
            crls.append({"ca_name": ca["name"], "crl": base64.b64encode(der).decode()})
        current = ca.get("parent_ca_id")
    return crls


def _request_view(row: dict[str, Any], with_cert: bool) -> dict[str, Any]:
    view = {k: row[k] for k in ("id", "use_case", "status", "reason", "created_at", "decided_at", "renew_of")}
    view["names"] = json.loads(row["names"])
    view["cert_id"] = row["cert_id"]
    if with_cert and row["status"] == "issued" and row["cert_id"]:
        cert = db.get_cert_summary(row["cert_id"])
        full = db.get_cert(row["cert_id"]) if cert else None
        if full:
            view["cert"] = full["cert_pem"].decode()
            view["serial"] = cert["serial"]
            view["not_after"] = cert["not_after"]
            view["chain"] = _chain_root_first(cert["ca_id"])
    return view


def _issue(request_id: int, device: dict[str, Any]) -> dict[str, Any]:
    """Sign a pending request's CSR. pending → issuing → issued, so a request is signed once
    even when two approvals race; any failure puts it back to pending."""
    if not db.transition_pal_request(request_id, "pending", "issuing"):
        row = db.get_pal_request(request_id)
        if row is None:
            raise PalError("Request not found")
        return row
    try:
        row = db.get_pal_request(request_id)
        ca = db.get_ca(device["ca_id"])  # raises DatabaseLocked while locked
        if row is None or ca is None:
            raise PalError("The CA for this PC no longer exists")
        policy = Policy.from_json(device["policy"])
        names = json.loads(row["names"])
        public_key, algorithm = crypto_engine.load_csr(row["csr_pem"])
        crl_dp_url = crl_dp_url_for(ca, policy.crl_dp, policy.crl_base_url)
        if policy.crl_dp == "cloudflare" and not crl_dp_url:
            raise PalError("The CA's Cloudflare CRL Worker is gone. Ask your admin to fix the PC's settings")
        cert_pem, _, serial, not_before, not_after = crypto_engine.issue_certificate(
            ca_cert_pem=ca["cert_pem"], ca_key_pem=ca["key_pem"],
            # algorithm is unused when public_key is given: the key comes from the CSR
            common_name=names["common_name"], san_domains=names["san"], algorithm="ecdsa-p256",
            lifetime_days=row["lifetime_days"], template=pal.USE_CASES[row["use_case"]],
            email=names.get("email"), upn=names.get("upn"), crl_dp_url=crl_dp_url, public_key=public_key,
        )
        cert_id = db.save_cert(
            ca_id=ca["id"], common_name=names["common_name"], san_domains=",".join(names["san"]),
            algorithm=algorithm, template=pal.USE_CASES[row["use_case"]], not_before=not_before,
            not_after=not_after, serial=serial, cert_pem=cert_pem, key_pem=b"", crl_dp_url=crl_dp_url,
            pal_device_id=device["id"],
        )
    except BaseException:
        db.transition_pal_request(request_id, "issuing", "pending")
        raise
    db.transition_pal_request(request_id, "issuing", "issued", cert_id=cert_id)
    publish_after_issue(ca, policy.crl_dp)
    log.info("Pal certificate issued: request=%d device=%s use_case=%s", request_id, device["id"], row["use_case"])
    return db.get_pal_request(request_id) or row


# ── Device API: pairing ─────────────────────────────────────────────

@bp.post(DEVICE_PREFIX + "enroll")
def enroll():
    address = request.remote_addr or ""
    body = request.get_data(cache=True)
    try:
        data = json.loads(body)
    except ValueError:
        return error("Request body must be JSON")
    if not isinstance(data, dict) or not isinstance(data.get("code_id"), str):
        return error(PAIRING_FAILED, 403)
    code_id = data["code_id"][:64]
    keys = (f"pal-code:{code_id}", f"pal-ip:{address}")
    if any(_enroll_limiter.retry_after(k) > 0 for k in keys):
        return error("Too many failed attempts. Wait a few minutes and try again", 429)

    def failed() -> tuple[Response, int]:
        for k in keys:
            _enroll_limiter.failure(k)
        log.warning("Pal pairing failed from %s", address)
        return error(PAIRING_FAILED, 403)

    code = db.get_pal_code(code_id)
    now = _utc_now()
    if code is None or code["used_at"] or code["revoked_at"] or code["expires_at"] <= _iso(now):
        return failed()
    if not pal.verify_enroll_proof(code["key"], body, request.headers.get("X-Pal-Proof", "")):
        return failed()
    try:
        timestamp = int(data.get("ts"))
    except (TypeError, ValueError):
        return failed()
    if abs(time.time() - timestamp) > pal.CLOCK_SKEW_SECONDS:
        return error("This PC's clock is more than 5 minutes off. Fix the time and try again", 403)
    try:
        device_key = pal.load_device_key(data.get("device_key", ""))
    except PalError as e:
        return error(e.user_message)
    hostname = str(data.get("hostname") or "")[:253]
    os_name = str(data.get("os") or "")[:100]
    try:
        fqdn = pal.parse_fqdn(data.get("fqdn"), Policy.from_json(code["policy"]))
    except PalError as e:
        return error(e.user_message)

    device_id = pal.new_device_id()
    if not db.enroll_pal_device(code_id, {"id": device_id, "hostname": hostname, "fqdn": fqdn, "os": os_name,
                                          "public_key": device_key}):
        return failed()
    for k in keys:
        _enroll_limiter.success(k)
    log.info("Pal device connected: %s (%s) with code %s", device_id, hostname, code_id[:8])
    return _enrolled_response(code, device_id, fqdn)


def _enrolled_response(code: dict[str, Any], device_id: str, fqdn: str) -> Response:
    """The new device's settings, MACed with the pairing key so the PC knows this server
    holds the code (and so the chain it is about to trust came from it)."""
    ca = db.get_ca_summary(code["ca_id"]) or {}
    payload = json.dumps({
        "device_id": device_id,
        "label": code["label"],
        "fqdn": fqdn,
        "ca_name": ca.get("name", ""),
        "policy": Policy.from_json(code["policy"]).public(),
        "chain": _chain_root_first(code["ca_id"]),
        "crls": _crls(code["ca_id"]),
    }, separators=(",", ":")).encode()
    response = Response(payload, status=201, mimetype="application/json")
    response.headers["X-Pal-Mac"] = pal.enrolled_mac(code["key"], payload)
    return response


# ── Device API: signed requests ─────────────────────────────────────

def _signed_device() -> tuple[dict[str, Any] | None, tuple[Response, int] | None]:
    """The device whose key signed this request, or the error to return."""
    headers = request.headers
    device_id = headers.get("X-Pal-Device", "")
    timestamp = headers.get("X-Pal-Time", "")
    nonce = headers.get("X-Pal-Nonce", "")
    signature = headers.get("X-Pal-Signature", "")
    device = db.get_pal_device(device_id) if len(device_id) == 32 else None
    if device is None or not timestamp.isdigit() or not pal.valid_nonce(nonce):
        return None, error(DEVICE_UNKNOWN, 401)
    message = pal.request_signing_string(request.method, request.path, timestamp, nonce, request.get_data(cache=True))
    if not pal.verify_device_signature(device["public_key"], message, signature):
        return None, error(DEVICE_UNKNOWN, 401)
    if abs(time.time() - int(timestamp)) > pal.CLOCK_SKEW_SECONDS:
        return None, error("This PC's clock is more than 5 minutes off. Fix the time and try again", 401)
    if not db.use_pal_nonce(device_id, nonce, time.time(), pal.NONCE_TTL_SECONDS):
        return None, error("Request replayed", 401)
    if device["revoked_at"]:
        return None, error(DEVICE_REVOKED, 403)
    db.touch_pal_device(device_id)
    return device, None


def _device_json() -> tuple[dict[str, Any] | None, tuple[Response, int] | None]:
    try:
        data = json.loads(request.get_data(cache=True) or b"{}")
    except ValueError:
        return None, error("Request body must be JSON")
    if not isinstance(data, dict):
        return None, error("Request body must be a JSON object")
    return data, None


@bp.get(DEVICE_PREFIX + "device")
def device_info():
    device, err = _signed_device()
    if err:
        return err
    ca = db.get_ca_summary(device["ca_id"]) or {}
    return jsonify({
        "device_id": device["id"],
        "label": device["label"],
        "fqdn": device["fqdn"],
        "ca_name": ca.get("name", ""),
        "policy": Policy.from_json(device["policy"]).public(),
        "chain": _chain_root_first(device["ca_id"]),
        "crls": _crls(device["ca_id"]),
        "requests": [_request_view(r, False) for r in db.list_pal_requests(device_id=device["id"])[:100]],
        "certs": [{k: c[k] for k in ("id", "common_name", "san_domains", "template", "serial", "not_before",
                                     "not_after", "revoked")}
                  for c in db.list_pal_device_certs(device["id"])],
    })


@bp.post(DEVICE_PREFIX + "requests")
def create_request():
    device, err = _signed_device()
    if err:
        return err
    data, err = _device_json()
    if err:
        return err
    policy = Policy.from_json(device["policy"])
    use_case = data.get("use_case")
    if use_case not in pal.USE_CASES:
        return error(f"use_case must be one of: {', '.join(pal.USE_CASES)}")
    mode = policy.use_cases.get(use_case, "off")
    if mode == "off":
        return error("Your admin hasn't allowed this kind of certificate for this PC", 403)
    try:
        names = pal.parse_names(use_case, data.get("names"), policy, device["fqdn"])
        csr = data.get("csr")
        if not isinstance(csr, str):
            raise PalError("csr must be a PEM certificate request")
        crypto_engine.load_csr(csr.encode())
    except UserError as e:  # PalError and the CSR checks
        return error(e.user_message)
    lifetime = parse_int(data.get("lifetime_days"), policy.max_days)
    if lifetime is None or lifetime < 1:
        return error("lifetime_days must be a positive integer")
    lifetime = min(lifetime, policy.max_days)

    renew_of = data.get("renew_of")
    if renew_of is not None and not _renewable(renew_of, device, use_case, names):
        return error("renew_of must be a certificate this PC holds, for the same use case and names")

    request_id = db.create_pal_request(device["id"], use_case, names.to_json(), csr.encode(), lifetime, renew_of)
    # A renewal of the same names was approved once and needs no new approval.
    if mode == "approve" and renew_of is None:
        log.info("Pal request %d waiting for approval (device=%s, use_case=%s)", request_id, device["id"], use_case)
        return jsonify(_request_view(db.get_pal_request(request_id), False)), 202
    try:
        row = _issue(request_id, device)
    except PalError as e:
        return error(e.user_message, 409)
    return jsonify(_request_view(row, True)), 201


def _renewable(cert_id: Any, device: dict[str, Any], use_case: str, names: pal.Names) -> bool:
    """``cert_id`` is an unrevoked certificate issued to this device for the same use case and names."""
    if not isinstance(cert_id, int) or isinstance(cert_id, bool):
        return False
    old = db.get_cert_summary(cert_id)
    return (old is not None and old["pal_device_id"] == device["id"] and not old["revoked"]
            and old["template"] == pal.USE_CASES[use_case] and old["common_name"] == names.common_name
            and old["san_domains"] == ",".join(names.san))


@bp.get(DEVICE_PREFIX + "requests/<int:request_id>")
def get_request(request_id: int):
    device, err = _signed_device()
    if err:
        return err
    row = db.get_pal_request(request_id)
    if row is None or row["device_id"] != device["id"]:
        return error("Request not found", 404)
    return jsonify(_request_view(row, True))


@bp.post(DEVICE_PREFIX + "status")
def cert_status():
    """Status of certificates the PC found in its stores that chain to its CA. Only serials
    under the device's own CA tree are answered; anything else is 'unknown'."""
    device, err = _signed_device()
    if err:
        return err
    data, err = _device_json()
    if err:
        return err
    serials = data.get("serials")
    if not isinstance(serials, list) or len(serials) > pal.MAX_SERIALS:
        return error(f"serials must be a list of at most {pal.MAX_SERIALS} hex strings")
    normalized = {raw: pal.normalize_serial(raw) for raw in serials if isinstance(raw, str)}
    root = db.root_ca_id(device["ca_id"])
    tree = db.ca_tree_ids(root) if root is not None else []
    found = db.find_serials(tree, [s for s in set(normalized.values()) if s])
    now = _utc_now()
    result = {}
    for raw, serial in normalized.items():
        entry = found.get(serial) if serial else None
        if entry is None:
            result[raw] = "unknown"
        elif entry["revoked"]:
            result[raw] = "revoked"
        elif _parse_time(entry["not_after"]) <= now:
            result[raw] = "expired"
        else:
            result[raw] = "valid"
    return jsonify({"status": result})


# ── Admin API ───────────────────────────────────────────────────────

def _code_state(code: dict[str, Any], now: str) -> str:
    if code["used_at"]:
        return "used"
    if code["revoked_at"]:
        return "revoked"
    if code["expires_at"] <= now:
        return "expired"
    return "unused"


def _server_url_error(url: str | None) -> str | None:
    if url is None:
        return "The server address must be an http(s) URL such as http://pki.lan:5000"
    host = urlsplit(url).hostname or ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None  # a name: the PC checks that it resolves to a LAN address
    if not pal.is_private_address(host):
        return "Cert Generator Pal is LAN only: use the server's LAN address or name"
    return None


@bp.get("/api/pal/codes")
def list_codes():
    now = _iso(_utc_now())
    codes = []
    for code in db.list_pal_codes():
        code["state"] = _code_state(code, now)
        code["policy"] = Policy.from_json(code["policy"]).public()
        codes.append(code)
    return jsonify(codes)


def _set_crl_dp(policy: Policy, data: dict[str, Any], ca_id: int, server_url: str) -> str | None:
    """Put the form's CRL distribution point on ``policy``; the error message, if any."""
    mode = str_field(data, "crl_dp", "none")
    if mode not in CRL_DP_MODES:
        return f"Invalid CRL distribution point. Choose from: {CRL_DP_MODES}"
    if mode == "server":
        base = parse_crl_base_url(str_field(data, "crl_base_url") or server_url)
        if base is None:
            return "The CRL server address must be an http(s) URL such as http://pki.lan:5000"
        policy.crl_base_url = base
    if mode == "cloudflare" and not (db.get_ca_worker(ca_id) or {}).get("cf_dp_url"):
        return "This CA has no Cloudflare CRL Worker. Deploy one from the CA page first"
    policy.crl_dp = mode
    return None


@bp.post("/api/pal/codes")
def create_code():
    data = json_body()
    ca_id = parse_int(data.get("ca_id"), 0)
    ca = db.get_ca_summary(ca_id) if ca_id else None
    if ca is None:
        return error("Choose a CA")
    if not _chain_supported(ca_id):
        return error("Windows can't use Ed25519 CAs. Choose an ECDSA or RSA CA")
    label = str_field(data, "label").strip()
    if not label or len(label) > MAX_LABEL_LEN:
        return error(f"A label of 1-{MAX_LABEL_LEN} characters is required")
    try:
        policy = pal.parse_policy(data, MAX_LIFETIME_DAYS)
    except PalError as e:
        return error(e.user_message)

    server_url = parse_crl_base_url(str_field(data, "server_url"))
    url_error = _server_url_error(server_url)
    if url_error:
        return error(url_error)
    crl_error = _set_crl_dp(policy, data, ca_id, server_url)
    if crl_error:
        return error(crl_error)
    hours = parse_int(data.get("expires_hours"), DEFAULT_CODE_HOURS)
    if hours is None or not 1 <= hours <= MAX_CODE_HOURS:
        return error(f"The code must expire within 1-{MAX_CODE_HOURS} hours")

    chain = db.get_ca_cert_chain(ca_id)
    root_sha256 = crypto_engine.cert_der_sha256(chain[-1])
    code_id, key = pal.new_code_id(), pal.new_code_key()
    expires_at = _iso(_utc_now() + timedelta(hours=hours))
    db.create_pal_code(code_id, label, ca_id, policy.to_json(), key, server_url, expires_at)
    log.info("Pal pairing code created: %s for CA %d by %s", code_id[:8], ca_id, (g.get("user") or {}).get("username"))
    return jsonify({
        "id": code_id,
        "pairing_code": pal.pairing_code(server_url, code_id, key, root_sha256),
        "expires_at": expires_at,
    }), 201


@bp.post("/api/pal/codes/<code_id>/revoke")
def revoke_code(code_id: str):
    if not db.revoke_pal_code(code_id):
        return error("Code not found, or already used or revoked", 404)
    log.info("Pal pairing code revoked: %s", code_id[:8])
    return jsonify({"ok": True})


@bp.get("/api/pal/devices")
def list_devices():
    devices = db.list_pal_devices()
    for device in devices:
        device["policy"] = Policy.from_json(device["policy"]).public()
    return jsonify(devices)


@bp.post("/api/pal/devices/<device_id>/revoke")
def revoke_device(device_id: str):
    data = json_body()
    revoke_certs = data.get("revoke_certs", True) is not False
    device = db.get_pal_device(device_id)
    if device is None or device["revoked_at"]:
        return error("Device not found or already revoked", 404)
    certs = [c for c in db.list_pal_device_certs(device_id) if not c["revoked"]] if revoke_certs else []
    if certs:
        db.require_unlocked()  # re-signing CRLs needs the CA keys: fail before changing anything
    db.revoke_pal_device(device_id)
    for cert in certs:
        db.revoke_cert(cert["id"])
    for ca_id in {c["ca_id"] for c in certs}:
        crl_publisher.publish(ca_id)
    log.info("Pal device revoked: %s (%d certificates revoked)", device_id, len(certs))
    return jsonify({"ok": True, "revoked_certs": len(certs)})


@bp.get("/api/pal/requests")
def list_requests():
    status = request.args.get("status")
    if status not in (None, "pending", "issued", "denied"):
        return error("status must be pending, issued or denied")
    rows = db.list_pal_requests(status=status)
    for row in rows:
        row["names"] = json.loads(row["names"])
    return jsonify(rows)


@bp.post("/api/pal/requests/<int:request_id>/approve")
def approve_request(request_id: int):
    row = db.get_pal_request(request_id)
    if row is None or row["status"] != "pending":
        return error("Request not found or not waiting for approval", 404)
    device = db.get_pal_device(row["device_id"])
    if device is None or device["revoked_at"]:
        return error("This PC has been disconnected", 409)
    try:
        row = _issue(request_id, device)
    except PalError as e:
        return error(e.user_message, 409)
    log.info("Pal request %d approved by %s", request_id, (g.get("user") or {}).get("username"))
    return jsonify({"ok": True, "status": row["status"], "cert_id": row["cert_id"]})


@bp.post("/api/pal/requests/<int:request_id>/deny")
def deny_request(request_id: int):
    reason = str_field(json_body(), "reason").strip()[:200]
    if not db.transition_pal_request(request_id, "pending", "denied", reason=reason or "Denied by your admin"):
        return error("Request not found or not waiting for approval", 404)
    log.info("Pal request %d denied by %s", request_id, (g.get("user") or {}).get("username"))
    return jsonify({"ok": True})
