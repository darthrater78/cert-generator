"""Cert Generator Pal: the device API PCs call, and the admin API behind the Devices page.

Device API (/api/pal/v1/*): no session or cookies; LAN source addresses only; pairing is
HMAC-authenticated both ways and every later request is signed by the device key.
Admin API (/api/pal/*): the signed-in admin, like every other /api/ route.
Both are server mode only. Protocol: docs/cert-generator-pal.md.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from flask import Blueprint, Response, current_app, g, jsonify, request, send_file

from .. import __version__, crl_publisher, crypto_engine, db, pal, state
from ..errors import UserError
from ..pal import PalError, Policy
from ..security import AttemptLimiter, RateLimiter
from ..web import error, json_body, parse_int, str_field
from .. import crl_local_server, relay, relay_collector
from .pki import (CRL_DP_MODES, DEFAULT_CRL_DAYS, MAX_LIFETIME_DAYS, _placeholder_crl_url, crl_dp_url_for,
                  parse_crl_base_url, publish_after_issue, revocable)

log = logging.getLogger("cert-generator")

bp = Blueprint("pal", __name__)

DEVICE_PREFIX = "/api/pal/v1/"
DOWNLOAD_PATH = "/pal/CertGeneratorPal.exe"
# Built into the Docker image (see Dockerfile); PAL_EXE points elsewhere for development.
PAL_EXE = Path(os.environ.get("PAL_EXE") or Path(__file__).resolve().parents[2] / "pal" / "CertGeneratorPal.exe")
MAX_ENROLL_BODY = 8 * 1024
MAX_REQUEST_BODY = 64 * 1024
RELAY_ENVIRON = "certgen.pal_relay"  # WSGI key set only by relay_dispatch
DEFAULT_CODE_HOURS = 24
MAX_CODE_HOURS = 7 * 24
MAX_LABEL_LEN = 64
# A PC makes a handful of calls per action; the limit only stops floods.
DEVICE_RATE_LIMIT_PER_MINUTE = 120
_device_limiter = RateLimiter(DEVICE_RATE_LIMIT_PER_MINUTE)
# Publish now, per CA: each one signs a CRL and may call Cloudflare.
PUBLISH_RATE_LIMIT_PER_MINUTE = 2
_publish_limiter = RateLimiter(PUBLISH_RATE_LIMIT_PER_MINUTE)
# Wrong pairing proofs, per code id and per address.
_enroll_limiter = AttemptLimiter()

# Every message starts with a short headline naming the problem ("Wrong domain."); the Pal shows
# it as the dialog title.
PAIRING_FAILED = "Code not accepted. Check you copied all of it, or ask your admin for a new one"
DEVICE_UNKNOWN = "Not connected. This server doesn't know this PC. Connect it again with a new pairing code"
DEVICE_REVOKED = "Disconnected. Your admin has disconnected this PC. Connect it again with a new pairing code"
CLOCK_WRONG = "Clock wrong. This PC's clock is more than 5 minutes off the server's. Fix the time and try again"


def reset_limiters() -> None:
    _device_limiter.reset()
    _publish_limiter.reset()
    _enroll_limiter.reset()


@bp.before_request
def _gate() -> Any:
    if state.desktop_mode():
        return error("Not found", 404)
    if request.environ.get(RELAY_ENVIRON):
        # Opened from a relay envelope by relay_dispatch: its device signature was checked, and
        # the signed request inside is checked again below like any LAN request. (Only server
        # code can set this WSGI key; client headers arrive as HTTP_*.)
        request.max_content_length = MAX_REQUEST_BODY
        return None
    if request.path.startswith(DEVICE_PREFIX) or request.path == DOWNLOAD_PATH:
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
            raise PalError("CA deleted. The CA this PC was connected to no longer exists")
        policy = Policy.from_json(device["policy"])
        names = json.loads(row["names"])
        public_key, algorithm = crypto_engine.load_csr(row["csr_pem"])
        mode = row.get("crl_dp") or policy.crl_dp
        crl_dp_url = crl_dp_url_for(ca, mode, policy.crl_base_url)
        if mode == "cloudflare" and not crl_dp_url:
            raise PalError("Revocation setup broken. The CA's Cloudflare CRL Worker is gone. Ask your admin to fix it")
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
            pal_device_id=device["id"], pal_key_storage=row.get("key_storage"), pal_user=row.get("windows_user"),
        )
    except BaseException as e:
        db.transition_pal_request(request_id, "issuing", "pending")
        if isinstance(e, UserError) and not isinstance(e, PalError):
            # the CA can't sign this (it has expired, say): a refusal like any other
            raise PalError(e.user_message) from e
        raise
    db.transition_pal_request(request_id, "issuing", "issued", cert_id=cert_id)
    _revoke_superseded(device, row, cert_id)
    publish_after_issue(ca, mode)
    log.info("Certificate issued to PC %s: %s for %s (key: %s)", device["label"], pal.USE_CASE_LABELS[row["use_case"]],
             names["common_name"], row.get("key_storage") or "not reported")
    return db.get_pal_request(request_id) or row


# ── Download ────────────────────────────────────────────────────────

@functools.lru_cache(maxsize=4)
def _exe_digest(path: str, mtime_ns: int, size: int) -> str:
    """SHA-256 of the EXE, computed once per file version (the key includes mtime and size)."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exe_info() -> dict[str, Any] | None:
    try:
        stat = PAL_EXE.stat()
    except OSError:
        return None
    # PCs run this EXE as administrator: never serve a copy this process could have replaced.
    if os.access(PAL_EXE, os.W_OK) or os.access(PAL_EXE.parent, os.W_OK):
        log.error("Not serving %s: the server process can write to it or its folder. Make both read-only "
                  "and owned by another user (the Docker image does this)", PAL_EXE)
        return None
    return {"size": stat.st_size, "sha256": _exe_digest(str(PAL_EXE), stat.st_mtime_ns, stat.st_size)}


@bp.get(DOWNLOAD_PATH)
def download_pal():
    """The Windows app, for the PC to download straight from this server. Public on the LAN:
    the EXE is no secret, and the person at the PC usually has no admin login."""
    info = _exe_info()
    if info is None:
        return Response("Cert Generator Pal isn't included in this server's image.", status=404, content_type="text/plain")
    response = send_file(PAL_EXE, as_attachment=True, download_name="CertGeneratorPal.exe",
                         mimetype="application/vnd.microsoft.portable-executable", max_age=0)
    response.headers["X-Checksum-SHA256"] = info["sha256"]
    return response


@bp.get("/api/pal/download")
def download_info():
    info = _exe_info()
    return jsonify({"available": info is not None, "path": DOWNLOAD_PATH, **(info or {})})


# ── Device API: pairing ─────────────────────────────────────────────

@bp.post(DEVICE_PREFIX + "enroll")
def enroll():
    if request.environ.get(RELAY_ENVIRON):
        return error("Not found", 404)  # pairing is LAN only, never through the relay
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
        return error("Too many attempts. Wait a few minutes and try again", 429)

    def failed() -> tuple[Response, int]:
        for k in keys:
            _enroll_limiter.failure(k)
        log.warning("Pal pairing failed from %s", address)
        return error(PAIRING_FAILED, 403)

    code = db.get_pal_code(code_id)
    if code is None or not pal.verify_enroll_proof(code["key"], body, request.headers.get("X-Pal-Proof", "")):
        return failed()
    # Past the proof, the caller holds this code: tell them exactly what's wrong with it.
    state = _code_state(code, _iso(_utc_now()))
    if state != "unused":
        return error(_CODE_STATE_MESSAGES[state].format(date=_friendly_date(code["expires_at"])), 403)
    try:
        timestamp = int(data.get("ts"))
    except (TypeError, ValueError):
        return failed()
    if abs(time.time() - timestamp) > pal.CLOCK_SKEW_SECONDS:
        return error(CLOCK_WRONG, 403)
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
    remote = Policy.from_json(code["policy"]).allow_remote
    if not db.enroll_pal_device(code_id, {"id": device_id, "hostname": hostname, "fqdn": fqdn, "os": os_name,
                                          "public_key": device_key, "remote_allowed": remote,
                                          "key_storage": pal.key_storage(data.get("key_storage"))}):
        return failed()
    for k in keys:
        _enroll_limiter.success(k)
    if remote:
        relay_collector.poke()  # the relay learns the new PC's key now
    log.info("PC connected: %s (%s, %s; device key: %s)", hostname or fqdn, fqdn, os_name,
             pal.key_storage(data.get("key_storage")) or "not reported")
    return _enrolled_response(code, device_id, fqdn)


def _enrolled_response(code: dict[str, Any], device_id: str, fqdn: str) -> Response:
    """The new device's settings, MACed with the pairing key so the PC knows this server
    holds the code (and so the chain it is about to trust came from it)."""
    ca = db.get_ca_summary(code["ca_id"]) or {}
    payload = json.dumps({
        "device_id": device_id,
        "label": (db.get_pal_device(device_id) or {}).get("label", ""),
        "crl_dp": Policy.from_json(code["policy"]).crl_dp,
        "crl_dps": Policy.from_json(code["policy"]).crl_dps,
        "fqdn": fqdn,
        "ca_name": ca.get("name", ""),
        "policy": Policy.from_json(code["policy"]).public(),
        "chain": _chain_root_first(code["ca_id"]),
        "crls": _crls(code["ca_id"]),
        **_relay_info(Policy.from_json(code["policy"]).allow_remote),
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
        return None, error(CLOCK_WRONG, 401)
    if not db.use_pal_nonce(device_id, nonce, time.time(), pal.NONCE_TTL_SECONDS):
        return None, error("Request replayed. The same request arrived twice; try again", 401)
    if device["revoked_at"]:
        return None, error(DEVICE_REVOKED, 403)
    db.touch_pal_device(device_id, _pal_version(), via="relay" if request.environ.get(RELAY_ENVIRON) else "lan")
    return device, None


_PAL_AGENT = re.compile(r"\bCertGeneratorPal/([0-9A-Za-z.+-]{1,40})(?:\s|$)")


def _pal_version() -> str | None:
    """The Pal's version from its User-Agent (informational: it is not signed)."""
    match = _PAL_AGENT.search(request.headers.get("User-Agent", ""))
    return match.group(1) if match else None


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
        "server_version": __version__,
        "label": device["label"],
        "fqdn": device["fqdn"],
        "ca_name": ca.get("name", ""),
        "policy": Policy.from_json(device["policy"]).public(),
        "crl_dp": Policy.from_json(device["policy"]).crl_dp,
        "crl_dps": Policy.from_json(device["policy"]).crl_dps,
        "self_hosted": _self_hosted_addresses(device["ca_id"]),
        **_relay_info(bool(device["remote_allowed"])),
        "crl_urls": _crl_test_urls(device),
        "chain": _chain_root_first(device["ca_id"]),
        "crls": _crls(device["ca_id"]),
        "requests": [_request_view(r, False) for r in db.list_pal_requests(device_id=device["id"])[:100]],
        "certs": [{**{k: c[k] for k in ("id", "common_name", "san_domains", "template", "serial", "not_before",
                                        "not_after", "revoked")}, "renew_from": _renew_from(c),
                   "key_storage": c["pal_key_storage"]}
                  for c in db.list_pal_device_certs(device["id"])],
    })


def _relay_info(allowed: bool) -> dict[str, Any]:
    """The relay's address and public key, for a PC allowed to use it (it pins the key when
    it hears it over the LAN). Nothing while no relay is set up, or the database is locked."""
    config = db.get_pal_relay_config()
    if not allowed or not config:
        return {}
    try:
        key = relay_collector.relay_public_key()
    except db.DatabaseLocked:
        return {}
    return {"relay": {"url": config["url"], "public_key": key}} if key else {}


def _crl_test_urls(device: dict[str, Any]) -> dict[str, str]:
    """For each revocation type the PC may use, the CRL address its certificates would name,
    so the Pal can show whether each one answers."""
    ca = db.get_ca_summary(device["ca_id"])
    if ca is None:
        return {}
    policy = Policy.from_json(device["policy"])
    urls = {}
    for mode in policy.crl_dps:
        if mode == "none" or (mode == "server" and not policy.crl_base_url):
            continue
        url = crl_dp_url_for(ca, mode, policy.crl_base_url)
        if url:
            urls[mode] = url
    return urls


def _self_hosted_addresses(ca_id: int) -> list[dict[str, str]]:
    """Where a PC's local CRL server answers for each CA in its chain (no CA key needed)."""
    out = []
    current: int | None = ca_id
    seen: set[int] = set()
    while current is not None and current not in seen:
        seen.add(current)
        ca = db.get_ca_summary(current)
        if ca is None:
            break
        url = _placeholder_crl_url(ca)
        host, name = crl_local_server.placeholder_parts(url)
        out.append({"ca_name": ca["name"], "url": url, "host": host, "file": name})
        current = ca.get("parent_ca_id")
    return out


@bp.get(DEVICE_PREFIX + "crls")
def self_hosted_crls():
    """Freshly signed CRLs for the device's CA chain, with the placeholder address each is served
    at, for the PC's own local CRL server (the "endpoint-hosted" revocation option). Signing needs
    the CA keys, so a locked server answers 423."""
    device, err = _signed_device()
    if err:
        return err
    crls = []
    current: int | None = device["ca_id"]
    seen: set[int] = set()
    while current is not None and current not in seen:
        seen.add(current)
        ca = db.get_ca(current)  # raises DatabaseLocked while locked
        if ca is None:
            break
        der = crypto_engine.generate_crl(ca_cert_pem=ca["cert_pem"], ca_key_pem=ca["key_pem"],
                                         revoked_serials=db.list_revoked_serials(ca["id"]), crl_lifetime_days=DEFAULT_CRL_DAYS)
        db.set_ca_crl_next_update(ca["id"], crypto_engine.crl_next_update(der))
        url = _placeholder_crl_url(ca)
        host, name = crl_local_server.placeholder_parts(url)
        crls.append({"ca_name": ca["name"], "url": url, "host": host, "file": name,
                     "crl": base64.b64encode(der).decode(), "next_update": crypto_engine.crl_next_update(der)})
        current = ca.get("parent_ca_id")
    return jsonify({"crls": crls})


@bp.post(DEVICE_PREFIX + "crl/publish")
def publish_crl_now():
    """A PC asks for its CA's CRL to be signed and published again now (Publish now in the Pal):
    the one this server serves and the one its Cloudflare Worker serves. Signing needs the CA
    key, so a locked server answers 423."""
    device, err = _signed_device()
    if err:
        return err
    ca_id = device["ca_id"]
    if not db.is_crl_maintained(ca_id):
        return error("Nothing to publish. This CA's CRL isn't published by the server or a Cloudflare Worker", 409)
    if not _publish_limiter.allow(str(ca_id)):
        return error("Just published. The CRL was published a moment ago: try again in a minute", 429)
    next_update = crl_publisher.publish(ca_id)  # raises DatabaseLocked while locked
    worker = db.get_ca_worker(ca_id)
    log.info("PC %s asked for the CRL to be published now", device["label"])
    return jsonify({
        "next_update": next_update,
        "revoked": len(db.list_revoked_serials(ca_id)),
        "cloudflare": None if worker is None else {"pushed": not worker["cf_push_error"], "error": worker["cf_push_error"]},
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
        return error("Not allowed. Your admin hasn't allowed this kind of certificate for this PC", 403)
    try:
        names = pal.parse_names(use_case, data.get("names"), policy, device["fqdn"])
        csr = data.get("csr")
        if not isinstance(csr, str):
            raise PalError("csr must be a PEM certificate request")
        crypto_engine.load_csr(csr.encode())
        note = pal.request_note(data.get("note"))
    except UserError as e:  # PalError and the CSR checks
        return error(e.user_message)
    crl_dp = data.get("crl_dp", policy.crl_dp)
    if crl_dp not in policy.crl_dps:
        return error(f"Revocation type not allowed. This PC may use: {', '.join(policy.crl_dps)}", 403)
    lifetime = parse_int(data.get("lifetime_days"), policy.max_days)
    if lifetime is None or lifetime < 1:
        return error("lifetime_days must be a positive integer")
    lifetime = min(lifetime, policy.max_days)

    renew_of = data.get("renew_of")
    if renew_of is not None and not _renewable(renew_of, device, use_case, names):
        return error("Can't renew. That certificate isn't one this PC holds for the same names. Request a new one instead")
    refusal = _covered_refusal(device, use_case, names, renew_of) or _duplicate_refusal(device, use_case, names, renew_of)
    if refusal:
        return error(refusal, 409)

    asked_by = pal.windows_user(data.get("windows_user"))
    request_id = db.create_pal_request(device["id"], use_case, names.to_json(), csr.encode(), lifetime, renew_of, crl_dp,
                                       pal.key_storage(data.get("key_storage")), asked_by, note)
    # A renewal of the same names was approved once and needs no new approval.
    if mode == "approve" and renew_of is None:
        log.info("PC %s asked for a %s certificate for %s (Windows account: %s): waiting for approval", device["label"],
                 pal.USE_CASE_LABELS[use_case], names.common_name, asked_by or "not reported")
        return jsonify(_request_view(db.get_pal_request(request_id), False)), 202
    try:
        row = _issue(request_id, device)
    except PalError as e:
        return error(e.user_message, 409)
    return jsonify(_request_view(row, True)), 201


def _cert_times(cert: dict[str, Any]) -> tuple[datetime, datetime]:
    return _parse_time(cert["not_before"]), _parse_time(cert["not_after"])


def _renew_from(cert: dict[str, Any]) -> str:
    return _iso(pal.renew_opens(*_cert_times(cert)))


def _covered_refusal(device: dict[str, Any], use_case: str, names: pal.Names, renew_of: int | None) -> str | None:
    """A web server certificate for nothing but the PC's own name, when the PC already holds a
    This computer certificate: that one carries the name and serves TLS too, so it only needs
    binding. Extra names still get a web server certificate, and one issued before this rule renews."""
    fqdn = device["fqdn"]
    if use_case != "web-server" or renew_of is not None or names.san != [fqdn]:
        return None
    held = [c for c in _live_certs(device, "computer", pal.Names(fqdn, [fqdn])) if c["pal_present"] != 0]
    if not held:
        return None
    return (f"Already covered. This PC's This computer certificate already carries {fqdn} and can serve it: "
            "choose Bind… on that certificate. Ask for a Web server certificate only when you need other names too")


def _duplicate_refusal(device: dict[str, Any], use_case: str, names: pal.Names, renew_of: int | None) -> str | None:
    """One live certificate per PC, kind and main name: no second copy while one is valid or
    waiting for approval, and no renewal before its window opens."""
    template = pal.USE_CASES[use_case]
    now = _utc_now()
    live = _live_certs(device, use_case, names)
    label = pal.USE_CASE_LABELS[use_case]
    if renew_of is None:
        # Only a copy the PC still holds blocks a new one (its store audit reports what it holds):
        # one it removed, e.g. when switching profiles, is revoked as superseded once the new one is issued.
        live = [c for c in live if c["pal_present"] != 0]
        if live:
            until = max(_parse_time(c["not_after"]) for c in live)
            return (f"Already issued. This PC already has a {label} certificate for {names.common_name}, valid until "
                    f"{until:%d %b %Y}. Renew it near expiry, or ask your admin to revoke or delete it if it was lost")
        pending = [r for r in db.list_pal_requests(status="pending", device_id=device["id"])
                   if r["use_case"] == use_case and json.loads(r["names"]).get("common_name") == names.common_name]
        if pending:
            return f"Already requested. A {label} certificate for {names.common_name} is waiting for your admin's approval"
        return None
    old = db.get_cert_summary(renew_of)
    opens = pal.renew_opens(*_cert_times(old)) if old else now
    if now < opens:
        return f"Too early to renew. Renewal opens {opens:%d %b %Y}, near the end of the certificate's life"
    if any(c["id"] != renew_of and _parse_time(c["not_after"]) > _parse_time(old["not_after"]) for c in live):
        return f"Already renewed. This PC already has a newer {label} certificate for {names.common_name}"
    return None


def _live_certs(device: dict[str, Any], use_case: str, names: pal.Names) -> list[dict[str, Any]]:
    """The device's unrevoked, unexpired certificates of this kind for this main name."""
    template = pal.USE_CASES[use_case]
    now = _utc_now()
    return [c for c in db.list_pal_device_certs(device["id"])
            if c["template"] == template and c["common_name"] == names.common_name and not c["revoked"]
            and _parse_time(c["not_after"]) > now]


def _revoke_superseded(device: dict[str, Any], row: dict[str, Any], new_cert_id: int) -> None:
    """A new certificate replaces copies the PC no longer holds: revoke them, so only one is ever live."""
    names = json.loads(row["names"])
    gone = [c for c in _live_certs(device, row["use_case"], pal.Names(names["common_name"], names["san"]))
            if c["id"] != new_cert_id and c["pal_present"] == 0 and revocable(c)]
    for cert in gone:
        db.revoke_cert(cert["id"])
        log.info("Pal certificate %d revoked: superseded by %d (no longer on device %s)", cert["id"], new_cert_id, device["id"])
    for ca_id in {c["ca_id"] for c in gone}:
        crl_publisher.publish(ca_id)


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
    # The serials are the PC's store audit: note which of its own certificates are still installed.
    for cert in db.mark_pal_presence(device["id"], {s for s in normalized.values() if s},
                                      pal.windows_user(data.get("windows_user")), pal.USER_TEMPLATES):
        log.warning("PC %s no longer holds its %s certificate for %s (not revoked)", device["label"],
                    pal.TEMPLATE_USE_CASES.get(cert["template"], cert["template"]), cert["common_name"])
    # Where the PC says its keys live (an older Pal sends neither): the device key, and each certificate's key.
    keys = data.get("keys") if isinstance(data.get("keys"), dict) else {}
    db.set_pal_key_storage(device["id"], pal.key_storage(data.get("device_key_storage")), {
        pal.normalize_serial(raw): storage for raw, storage in list(keys.items())[:pal.MAX_SERIALS]
        if isinstance(raw, str) and pal.normalize_serial(raw) and pal.key_storage(storage)})
    # What uses each certificate on the PC now (an older Pal doesn't say, and then nothing changes).
    uses = data.get("binds")
    if isinstance(uses, dict):
        db.set_pal_cert_binds(device["id"], {
            pal.normalize_serial(raw): [u[:80] for u in labels if isinstance(u, str)][:20]
            for raw, labels in list(uses.items())[:pal.MAX_SERIALS]
            if isinstance(raw, str) and pal.normalize_serial(raw) and isinstance(labels, list)})
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


# Kinds of certificate that can serve TLS, and so be bound to a role.
_BINDABLE_TEMPLATES = (pal.USE_CASES["web-server"], pal.USE_CASES["computer"])


def _bind_view(row: dict[str, Any]) -> dict[str, Any]:
    return {k: row[k] for k in ("id", "serial", "target", "detail", "status", "reason", "created_at", "decided_at")}


@bp.post(DEVICE_PREFIX + "binds")
def create_binds():
    """A PC asks to put one installed certificate to work for one or more roles. The admin's
    switch for each role decides: off refuses the whole ask, auto allows it now, approve queues
    it. The server allows; the bind itself happens on the PC, which asks first every time."""
    device, err = _signed_device()
    if err:
        return err
    data, err = _device_json()
    if err:
        return err
    policy = Policy.from_json(device["policy"])
    try:
        wanted = pal.parse_binds(data.get("binds"))
        note = pal.request_note(data.get("note"))
    except PalError as e:
        return error(e.user_message)
    serial = pal.normalize_serial(data.get("serial")) if isinstance(data.get("serial"), str) else None
    root = db.root_ca_id(device["ca_id"])
    cert = db.get_pal_cert_by_serial(db.ca_tree_ids(root) if root is not None else [], serial) if serial else None
    if cert is None:
        return error("Not one of ours. That certificate wasn't issued by this PC's CA", 404)
    if cert["revoked"] or _parse_time(cert["not_after"]) <= _utc_now():
        return error("Not usable. That certificate is revoked or has expired: renew it first", 409)
    if cert["template"] not in _BINDABLE_TEMPLATES:
        return error("Wrong kind. Only a This computer or Web server certificate can be bound")
    refused = [pal.BIND_TARGETS[t] for t, _ in wanted if policy.binds.get(t, "off") == "off"]
    if refused:
        return error(f"Not allowed. Your admin hasn't allowed binding to: {', '.join(refused)}", 403)
    asked_by = pal.windows_user(data.get("windows_user"))
    rows = []
    for target, detail in wanted:
        status = "pending" if policy.binds[target] == "approve" else "approved"
        bind_id = db.create_pal_bind(device["id"], serial, cert["common_name"], target, detail, status, asked_by, note)
        rows.append(db.get_pal_bind(bind_id))
        log.info("PC %s asked to bind %s to %s%s (Windows account: %s): %s", device["label"], cert["common_name"],
                 pal.BIND_TARGETS[target], f" [{detail}]" if detail else "", asked_by or "not reported",
                 "waiting for approval" if status == "pending" else "allowed")
    waiting = any(r["status"] == "pending" for r in rows)
    return jsonify({"binds": [_bind_view(r) for r in rows]}), 202 if waiting else 201


@bp.get(DEVICE_PREFIX + "binds/<int:bind_id>")
def get_bind(bind_id: int):
    device, err = _signed_device()
    if err:
        return err
    row = db.get_pal_bind(bind_id)
    if row is None or row["device_id"] != device["id"]:
        return error("Bind not found", 404)
    return jsonify(_bind_view(row))


@bp.post(DEVICE_PREFIX + "revoke")
def revoke_own_certs():
    """A PC revokes certificates it removed (Remove in the Pal). Only its own unrevoked
    certificates are touched; any other serial is ignored."""
    device, err = _signed_device()
    if err:
        return err
    data, err = _device_json()
    if err:
        return err
    serials = data.get("serials")
    if not isinstance(serials, list) or len(serials) > pal.MAX_SERIALS:
        return error(f"serials must be a list of at most {pal.MAX_SERIALS} hex strings")
    wanted = {pal.normalize_serial(raw) for raw in serials if isinstance(raw, str)} - {None}
    removed = [c for c in db.list_pal_device_certs(device["id"]) if c["serial"] in wanted and not c["revoked"]]
    certs = [c for c in removed if revocable(c)]  # one that names no CRL is only recorded as removed
    cas = {c["ca_id"] for c in certs}
    if any((db.get_ca_summary(ca_id) or {}).get("crl_public") or (db.get_ca_summary(ca_id) or {}).get("cf_worker") for ca_id in cas):
        db.require_unlocked()  # re-signing a published CRL needs the CA key: fail before revoking
    for cert in certs:
        db.revoke_cert(cert["id"])
        log.info("PC %s removed its %s certificate for %s: revoked", device["label"],
                 pal.TEMPLATE_USE_CASES.get(cert["template"], cert["template"]), cert["common_name"])
    db.mark_pal_removed([c["id"] for c in removed])
    for ca_id in cas:
        crl_publisher.publish(ca_id)
    return jsonify({"revoked": [c["serial"] for c in certs]})


# ── Admin API ───────────────────────────────────────────────────────

_CODE_STATE_MESSAGES = {
    "used": "Code already used. This pairing code has already connected a PC. Ask your admin for a new one",
    "revoked": "Code revoked. Your admin revoked this pairing code. Ask them for a new one",
    "expired": "Code expired. This pairing code expired {date}. Ask your admin for a new one",
}


def _friendly_date(iso: str) -> str:
    return _parse_time(iso).strftime("%d %b %Y %H:%M UTC")


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


_CRL_ORDER = ("server", "cloudflare", "placeholder", "none")


def _set_crl_dp(policy: Policy, data: dict[str, Any], ca_id: int, server_url: str) -> str | None:
    """Put the revocation types the admin allowed (one, several or all) on ``policy``; the error, if any."""
    raw = data.get("crl_dps")
    if raw is None:
        raw = [str_field(data, "crl_dp", "none")]  # one type, as older forms send it
    if not isinstance(raw, list) or not raw or not all(isinstance(m, str) for m in raw):
        return "Choose at least one revocation type"
    if any(m not in CRL_DP_MODES for m in raw):
        return f"Invalid revocation type. Choose from: {CRL_DP_MODES}"
    if "server" in raw:
        base = parse_crl_base_url(str_field(data, "crl_base_url") or server_url)
        if base is None:
            return "The CRL server address must be an http(s) URL such as http://pki.lan:5000"
        policy.crl_base_url = base
    if "cloudflare" in raw and not (db.get_ca_worker(ca_id) or {}).get("cf_dp_url"):
        return "This CA has no Cloudflare CRL Worker. Deploy one from the CA page first, or untick Cloudflare"
    first = raw[0]
    policy.crl_dps = [first] + [m for m in _CRL_ORDER if m in raw and m != first]  # the first ticked is the default
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
    label = str_field(data, "label").strip()  # an optional note; the PC names itself when it connects
    if len(label) > MAX_LABEL_LEN:
        return error(f"Keep the note to {MAX_LABEL_LEN} characters")
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
    log.info("Pairing code created%s for CA %s (expires in %d hours)", f" ({label})" if label else "", ca["name"], hours)
    return jsonify({
        "id": code_id,
        "pairing_code": pal.pairing_code(server_url, code_id, key, root_sha256),
        "expires_at": expires_at,
    }), 201


@bp.post("/api/pal/codes/<code_id>/revoke")
def revoke_code(code_id: str):
    if not db.revoke_pal_code(code_id):
        return error("Code not found, or already used or revoked", 404)
    code = next((c for c in db.list_pal_codes() if c["id"] == code_id), {})
    log.info("Pairing code revoked%s", f" ({code['label']})" if code.get("label") else "")
    return jsonify({"ok": True})


@bp.get("/api/pal/devices")
def list_devices():
    devices = db.list_pal_devices()
    by_device: dict[str, list[dict[str, Any]]] = {}
    now = _utc_now()
    for cert in db.list_pal_issued_certs():
        by_device.setdefault(cert["pal_device_id"], []).append({
            "use_case": pal.TEMPLATE_USE_CASES.get(cert["template"], cert["template"]),
            "name": cert["common_name"],
            "state": _cert_state(cert, now),
            "revocable": revocable(cert),
            "key_storage": cert["pal_key_storage"],
            "asked_by": cert["pal_user"],
            "used_for": json.loads(cert["pal_binds"]) if cert["pal_binds"] else [],
            "issued_at": cert["created_at"],
        })
    for device in devices:
        device["policy"] = Policy.from_json(device["policy"]).public()
        device["certs"] = by_device.get(device["id"], [])
        device["version_matches"] = device["pal_version"] in (None, __version__)
    return jsonify(devices)


def _cert_state(cert: dict[str, Any], now: datetime) -> str:
    if cert["revoked"]:
        return "revoked"
    if _parse_time(cert["not_after"]) <= now:
        return "expired"
    return {1: "installed", 0: "removed"}.get(cert["pal_present"], "unchecked")


@bp.post("/api/pal/devices/<device_id>/revoke")
def revoke_device(device_id: str):
    data = json_body()
    revoke_certs = data.get("revoke_certs", True) is not False
    device = db.get_pal_device(device_id)
    if device is None or device["revoked_at"]:
        return error("Device not found or already revoked", 404)
    return jsonify({"ok": True, "revoked_certs": _disconnect(device_id, revoke_certs)})


def _disconnect(device_id: str, revoke_certs: bool) -> int:
    """Stop the device's requests, and revoke its certificates; how many were revoked."""
    certs = [c for c in db.list_pal_device_certs(device_id) if not c["revoked"] and revocable(c)] if revoke_certs else []
    if certs:
        db.require_unlocked()  # re-signing CRLs needs the CA keys: fail before changing anything
    db.revoke_pal_device(device_id)
    for cert in certs:
        db.revoke_cert(cert["id"])
    for ca_id in {c["ca_id"] for c in certs}:
        crl_publisher.publish(ca_id)
    log.info("PC disconnected: %s (%d certificates revoked)", (db.get_pal_device(device_id) or {}).get("label", device_id), len(certs))
    return len(certs)


@bp.put("/api/pal/devices/<device_id>/policy")
def edit_device_policy(device_id: str):
    """Change what a connected PC may request: its certificate kinds, allowed names, longest
    lifetime and revocation types. The PC picks it up at its next check-in. Remote access has
    its own switch and is left as it is."""
    device = db.get_pal_device(device_id)
    if device is None or device["revoked_at"]:
        return error("This PC is not connected", 404)
    data = json_body()
    old = Policy.from_json(device["policy"])
    try:
        policy = pal.parse_policy({**data, "allow_remote": old.allow_remote}, MAX_LIFETIME_DAYS)
        pal.parse_fqdn(device["fqdn"], policy)  # the PC's own name must still fit
    except PalError as e:
        return error(e.user_message)
    code = next((c for c in db.list_pal_codes() if c["id"] == device["code_id"]), {})
    crl_error = _set_crl_dp(policy, {**data, "crl_base_url": str_field(data, "crl_base_url") or old.crl_base_url or ""},
                            device["ca_id"], code.get("server_url") or old.crl_base_url or "")
    if crl_error:
        return error(crl_error)
    if not db.set_pal_device_policy(device_id, policy.to_json()):
        return error("This PC is not connected", 404)
    kinds = ", ".join(f"{pal.USE_CASE_LABELS[c]}: {m}" for c, m in policy.use_cases.items() if m != "off")
    binds = ", ".join(f"{pal.BIND_TARGETS[t]}: {m}" for t, m in policy.binds.items() if m != "auto") or "all allowed"
    log.info("PC %s: what it may request was changed (%s; binds: %s; CRL: %s; up to %d days)", device["label"], kinds,
             binds, ", ".join(policy.crl_dps), policy.max_days)
    return jsonify({"ok": True, "policy": policy.public()})


@bp.delete("/api/pal/devices/<device_id>")
def delete_device(device_id: str):
    """Remove a PC from the list. A connected one is disconnected first and its certificates revoked."""
    device = db.get_pal_device(device_id)
    if device is None:
        return error("Device not found", 404)
    revoked_certs = 0 if device["revoked_at"] else _disconnect(device_id, revoke_certs=True)
    db.delete_pal_device(device_id)
    log.info("PC deleted from the list: %s", device["label"])
    return jsonify({"ok": True, "revoked_certs": revoked_certs})


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
    log.info("Request approved: %s certificate for %s on PC %s", pal.USE_CASE_LABELS.get(row["use_case"], row["use_case"]),
             json.loads(row["names"]).get("common_name", ""), device["label"])
    return jsonify({"ok": True, "status": row["status"], "cert_id": row["cert_id"]})


@bp.get("/api/pal/binds")
def list_binds():
    status = request.args.get("status")
    if status not in (None, "pending", "approved", "denied"):
        return error("status must be pending, approved or denied")
    rows = db.list_pal_binds(status=status)
    for row in rows:
        row["target_label"] = pal.BIND_TARGETS.get(row["target"], row["target"])
    return jsonify(rows)


def _decide_bind(bind_id: int, status: str, reason: str = ""):
    row = db.get_pal_bind(bind_id)
    if row is None or not db.decide_pal_bind(bind_id, status, reason):
        return error("Bind not found or not waiting for approval", 404)
    device = db.get_pal_device(row["device_id"]) or {}
    log.info("Bind %s: %s to %s on PC %s%s", status, row["cert_name"], pal.BIND_TARGETS.get(row["target"], row["target"]),
             device.get("label", ""), f" ({reason})" if reason and status == "denied" else "")
    return jsonify({"ok": True})


@bp.post("/api/pal/binds/<int:bind_id>/approve")
def approve_bind(bind_id: int):
    row = db.get_pal_bind(bind_id)
    device = db.get_pal_device(row["device_id"]) if row else None
    if row is not None and (device is None or device["revoked_at"]):
        return error("This PC has been disconnected", 409)
    return _decide_bind(bind_id, "approved")


@bp.post("/api/pal/binds/<int:bind_id>/deny")
def deny_bind(bind_id: int):
    reason = str_field(json_body(), "reason").strip()[:200]
    return _decide_bind(bind_id, "denied", reason or "Denied by your admin")


@bp.post("/api/pal/requests/<int:request_id>/deny")
def deny_request(request_id: int):
    reason = str_field(json_body(), "reason").strip()[:200]
    row = db.get_pal_request(request_id)
    if not db.transition_pal_request(request_id, "pending", "denied", reason=reason or "Denied by your admin"):
        return error("Request not found or not waiting for approval", 404)
    device = db.get_pal_device(row["device_id"]) or {}
    log.info("Request denied: %s certificate for %s on PC %s%s", pal.USE_CASE_LABELS.get(row["use_case"], row["use_case"]),
             json.loads(row["names"]).get("common_name", ""), device.get("label", ""), f" ({reason})" if reason else "")
    return jsonify({"ok": True})


# ── Remote relay (docs/cert-generator-pal.md §8) ────────────────────

_RELAY_HEADERS = ("X-Pal-Device", "X-Pal-Time", "X-Pal-Nonce", "X-Pal-Signature", "User-Agent")
_RELAY_REPLY_HEADERS = ("X-Pal-Mac", "Content-Type")
_RELAY_METHODS = ("GET", "POST")


def _relay_refusal(req: relay.Request, key, status: int, message: str) -> bytes:
    """A refusal only the sender can read (it holds the one-time key), so nothing about this
    server or its PCs reaches anyone else."""
    body = json.dumps({"error": message}).encode()
    return relay.seal_reply(relay.reply_key(req, key), req.device_id, req.nonce,
                            {"status": status, "headers": {"Content-Type": "application/json"}, "body": relay.b64url(body)})


def relay_dispatch(envelope: bytes) -> bytes | None:
    """Open a request envelope collected from the relay, run the signed request inside through
    the device API exactly as if it came over the LAN, and seal the reply. None means drop it
    unanswered (not signed by a known PC, or no relay key): nothing is sent back to a stranger.
    Needs an application context; raises DatabaseLocked while locked."""
    try:
        req = relay.parse_request(envelope)
    except relay.RelayError as e:
        log.info("Relay envelope dropped: %s", e)
        return None
    device = db.get_pal_device(req.device_id)
    if device is None or not relay.verify_request(req, device["public_key"]):
        log.info("Relay envelope dropped: not signed by a known PC")
        return None
    key_der = db.get_pal_relay_key()
    if key_der is None:
        log.warning("Relay envelope dropped: this server has no relay key")
        return None
    key = relay.load_private_key(key_der)
    if device["revoked_at"]:
        return _relay_refusal(req, key, 403, DEVICE_REVOKED)
    if not device["remote_allowed"]:
        return _relay_refusal(req, key, 403, "Remote access is off. Your admin hasn't allowed this PC to use the relay")
    if abs(time.time() - req.timestamp) > pal.CLOCK_SKEW_SECONDS:
        return _relay_refusal(req, key, 401, CLOCK_WRONG)
    try:
        inner, k_rep = relay.open_request(req, key)
        method, path = inner.get("method"), inner.get("path")
        headers = inner.get("headers") or {}
        body = relay.b64url_decode(inner.get("body") or "")
        if (method not in _RELAY_METHODS or not isinstance(path, str) or not path.startswith(DEVICE_PREFIX)
                or path == DEVICE_PREFIX + "enroll" or "?" in path or ".." in path or not isinstance(headers, dict)):
            raise relay.RelayError("Not a device API request")
        if headers.get("X-Pal-Device") != req.device_id:
            raise relay.RelayError("The inner request is from another PC")
    except relay.RelayError as e:
        log.info("Relay envelope from %s refused: %s", req.device_id[:8], e)
        return _relay_refusal(req, key, 400, str(e))
    sent = {h: str(headers[h])[:512] for h in _RELAY_HEADERS if isinstance(headers.get(h), str)}
    client = current_app.test_client(use_cookies=False)
    response = client.open(path, method=method, headers=sent, data=body, content_type="application/json",
                           environ_base={RELAY_ENVIRON: True, "REMOTE_ADDR": "127.0.0.1"})
    reply = {"status": response.status_code,
             "headers": {h: response.headers[h] for h in _RELAY_REPLY_HEADERS if h in response.headers},
             "body": relay.b64url(response.get_data())}
    return relay.seal_reply(k_rep, req.device_id, req.nonce, reply)


# ── Remote relay: admin (docs/cert-generator-pal.md §8) ─────────────

def _relay_admin(action: Any) -> tuple[Response, int] | Response:
    from ..cloudflare import CloudflareError

    try:
        action()
    except (UserError, CloudflareError) as e:
        return error(e.user_message)
    return relay_status()


@bp.get("/api/pal/relay")
def relay_status():
    """What the Windows PCs page shows about the relay."""
    config = db.get_pal_relay_config()
    collector = relay_collector.status()
    worker: dict[str, Any] | None = None
    if config and request.args.get("live") == "1":
        try:
            token = db.get_pal_relay_token()
            worker = relay_collector.HttpLink(config["url"], token).worker_status() if token else None
        except relay_collector.RelayError as e:
            worker = {"error": e.user_message}
        except db.DatabaseLocked:
            worker = {"error": "Database is locked"}
    return jsonify({
        "configured": config is not None,
        "url": config["url"] if config else None,
        "encryption": db.is_encryption_enabled(),
        "cloudflare": db.has_cloudflare_token(),
        "remote_pcs": len(db.list_pal_remote_keys()),
        "collector": {k: collector.get(k) for k in ("running", "last_ok", "last_error", "handled", "dropped")},
        "worker": worker,
    })


@bp.post("/api/pal/relay/setup")
def relay_setup():
    return _relay_admin(relay_collector.set_up)


@bp.post("/api/pal/relay/update")
def relay_update():
    return _relay_admin(relay_collector.update)


@bp.post("/api/pal/relay/teardown")
def relay_teardown():
    return _relay_admin(relay_collector.tear_down)


@bp.post("/api/pal/devices/<device_id>/remote")
def device_remote(device_id: str):
    allowed = json_body().get("allowed")
    if not isinstance(allowed, bool):
        return error("allowed must be true or false")
    if not db.set_pal_remote_allowed(device_id, allowed):
        return error("Device not found or disconnected", 404)
    relay_collector.poke()  # the relay's list of allowed PCs follows at once
    log.info("PC %s: remote connection %s", (db.get_pal_device(device_id) or {}).get("label", device_id[:8]),
             "allowed" if allowed else "turned off")
    return jsonify({"ok": True, "remote_allowed": allowed})
