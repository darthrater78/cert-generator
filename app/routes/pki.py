"""Certificate authorities, certificates, CRLs, and their exports."""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from flask import Blueprint, Response, jsonify, request

from .. import crl_publisher, crl_worker, crypto_engine, db, install_bundle, state
from ..errors import UserError
from ..security import RateLimiter
from ..web import deliver_export, error, export_password_error, json_body, parse_int, reauth_rejection, str_field

log = logging.getLogger("cert-generator")

bp = Blueprint("pki", __name__)

VALID_FORMATS = ("pem", "der", "crt", "pkcs12")
VALID_CA_PARTS = ("both", "public", "private")
VALID_CERT_PARTS = ("both", "public", "private", "chain")
DOMAIN_RE = re.compile(r"^[\w.*-]{1,253}$")
MAX_LIFETIME_DAYS = 36500
DEFAULT_CRL_DAYS = 3650
CRL_DP_MODES = ("none", "placeholder", "server", "cloudflare")
# Clients cache a CRL until its next update, so real traffic is a trickle. Behind a
# reverse proxy every client shares the proxy's address, hence the generous limit.
CRL_RATE_LIMIT_PER_MINUTE = 300
_crl_limiter = RateLimiter(CRL_RATE_LIMIT_PER_MINUTE)
_CRL_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
MAX_BASE_URL_LEN = 200
KEY_ON_DEVICE = ("This certificate's private key never left the PC that requested it (Cert Generator Pal). "
                 "Only its public parts can be exported here")


def _safe_name(value: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', value)


def _is_valid_san(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(DOMAIN_RE.match(value))


def parse_san_list(raw: str, common_name: str) -> list[str] | None:
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


def parse_crl_base_url(raw: str) -> str | None:
    """'http(s)://host[:port][/prefix]' with no credentials, query or fragment; None if invalid."""
    raw = raw.strip().rstrip("/")
    if not raw or len(raw) > MAX_BASE_URL_LEN or any(c.isspace() for c in raw):
        return None
    try:
        parts = urlsplit(raw)
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    if parts.username or parts.password or parts.query or parts.fragment:
        return None
    return raw


def _lifetime_error(lifetime_days: int | None) -> str | None:
    if lifetime_days is None or lifetime_days < 1 or lifetime_days > MAX_LIFETIME_DAYS:
        return f"Lifetime must be an integer between 1 and {MAX_LIFETIME_DAYS} days"
    return None


# ── Certificate authorities ─────────────────────────────────────────

def _validate_ca_request(data: dict[str, Any], default_days: int, name_suffix: str):
    """Returns ((domain, name, algorithm, lifetime_days), None) or (None, error response)."""
    domain = str_field(data, "domain").strip()
    name = str_field(data, "name").strip()
    algorithm = str_field(data, "algorithm", "ecdsa-p384")
    lifetime_days = parse_int(data.get("lifetime_days"), default_days)

    if not domain or not DOMAIN_RE.match(domain):
        return None, error("A valid domain name is required")
    name = name or f"{domain} {name_suffix}"
    if len(name) > 200:
        return None, error("CA name too long")
    if algorithm not in crypto_engine.ALGORITHMS:
        return None, error(f"Invalid algorithm. Choose from: {crypto_engine.ALGORITHMS}")
    lifetime_error = _lifetime_error(lifetime_days)
    if lifetime_error:
        return None, error(lifetime_error)
    return (domain, name, algorithm, lifetime_days), None


@bp.get("/api/algorithms")
def get_algorithms():
    return jsonify(crypto_engine.ALGORITHMS)


@bp.get("/api/templates")
def get_templates():
    return jsonify({
        k: {"label": v["label"], "description": v["description"], "default_days": v["default_days"],
             "include_email": v.get("include_email", False)}
        for k, v in crypto_engine.CERT_TEMPLATES.items()
    })


@bp.post("/api/ca")
def create_ca():
    fields, err = _validate_ca_request(json_body(), 3650, "Root CA")
    if err:
        return err
    domain, name, algorithm, lifetime_days = fields
    db.require_unlocked()

    cert_pem, key_pem, serial, not_before, not_after = crypto_engine.create_ca(
        domain=domain, name=name, algorithm=algorithm, lifetime_days=lifetime_days,
    )
    ca_id = db.save_ca(
        name=name, domain=domain, algorithm=algorithm, not_before=not_before, not_after=not_after,
        serial=serial, cert_pem=cert_pem, key_pem=key_pem,
    )
    log.info("CA created: %s (domain=%s, algo=%s)", name, domain, algorithm)
    return jsonify({"id": ca_id, "name": name, "domain": domain, "serial": serial}), 201


@bp.get("/api/ca")
def list_cas():
    return jsonify(db.list_cas())


@bp.get("/api/ca/<int:ca_id>")
def get_ca(ca_id: int):
    ca = db.get_ca(ca_id)
    if not ca:
        return error("CA not found", 404)
    safe = {k: v for k, v in ca.items() if k not in ("cert_pem", "key_pem", "crl_der") and not k.startswith("cf_")}
    safe["cloudflare"] = None if state.desktop_mode() else crl_worker.status(ca_id)
    safe["crl_published"] = ca.get("crl_der") is not None
    safe["crl_served"] = _crl_served(ca)
    safe["crl_served_next_update"] = crypto_engine.crl_next_update(ca["crl_der"]) if safe["crl_served"] else None
    safe["child_cas"] = db.list_child_cas(ca_id)
    safe["is_root"] = ca.get("parent_ca_id") is None
    safe["can_issue_intermediate"] = crypto_engine.ca_allows_subordinate_ca(ca["cert_pem"])
    return jsonify(safe)


def _descendant_ids(ca_id: int) -> list[int]:
    ids, pending = [], [ca_id]
    while pending:
        current = pending.pop()
        ids.append(current)
        pending.extend(child["id"] for child in db.list_child_cas(current) if child["id"] not in ids)
    return ids


@bp.delete("/api/ca/<int:ca_id>")
def delete_ca(ca_id: int):
    if db.count_ca_workers(_descendant_ids(ca_id)):
        return error("Tear down the Cloudflare CRL Worker of this CA (and of any intermediate under it) first", 409)
    if db.delete_ca(ca_id):
        log.info("CA deleted: id=%d", ca_id)
        return jsonify({"ok": True})
    return error("CA not found", 404)


@bp.post("/api/ca/<int:ca_id>/intermediate")
def create_intermediate(ca_id: int):
    parent = db.get_ca(ca_id)
    if not parent:
        return error("Parent CA not found", 404)
    if not crypto_engine.ca_allows_subordinate_ca(parent["cert_pem"]):
        return error("This CA's path length constraint does not allow issuing intermediate CAs. "
                     "Create the intermediate under the root CA instead.")

    fields, err = _validate_ca_request(json_body(), 1825, "Intermediate CA")
    if err:
        return err
    domain, name, algorithm, lifetime_days = fields

    cert_pem, key_pem, serial, not_before, not_after = crypto_engine.create_intermediate_ca(
        parent_cert_pem=parent["cert_pem"], parent_key_pem=parent["key_pem"],
        domain=domain, name=name, algorithm=algorithm, lifetime_days=lifetime_days,
    )
    new_id = db.save_ca(
        name=name, domain=domain, algorithm=algorithm, not_before=not_before, not_after=not_after,
        serial=serial, cert_pem=cert_pem, key_pem=key_pem, parent_ca_id=ca_id,
    )
    log.info("Intermediate CA created: %s (parent=%d, algo=%s)", name, ca_id, algorithm)
    return jsonify({"id": new_id, "name": name, "domain": domain, "serial": serial}), 201


# ── Certificates ────────────────────────────────────────────────────

@dataclass
class IssueRequest:
    common_name: str
    san_list: list[str]
    algorithm: str
    template: str
    email: str | None
    upn: str | None
    crl_dp_mode: str
    crl_base_url: str | None
    lifetime_days: int


def _parse_issue_request(data: dict[str, Any]) -> tuple[IssueRequest | None, str | None]:
    common_name = str_field(data, "common_name").strip()
    algorithm = str_field(data, "algorithm", "ecdsa-p384")
    template = str_field(data, "template", "web-server")
    lifetime_days = parse_int(data.get("lifetime_days"), 365)

    if not common_name or len(common_name) > 253:
        return None, "A valid common name is required (max 253 chars)"
    if algorithm not in crypto_engine.ALGORITHMS:
        return None, f"Invalid algorithm. Choose from: {crypto_engine.ALGORITHMS}"
    if template not in crypto_engine.CERT_TEMPLATES:
        return None, f"Invalid template. Choose from: {list(crypto_engine.CERT_TEMPLATES.keys())}"
    lifetime_error = _lifetime_error(lifetime_days)
    if lifetime_error:
        return None, lifetime_error
    san_list = parse_san_list(str_field(data, "san_domains").strip(), common_name)
    if san_list is None:
        return None, "Each SAN must be a valid DNS name or IP address"

    # include_crl_dp (bool) predates the choice of distribution point and means the placeholder.
    default_mode = "placeholder" if data.get("include_crl_dp") else "none"
    crl_dp_mode = str_field(data, "crl_dp", default_mode)
    crl_base_url = None
    if crl_dp_mode not in CRL_DP_MODES:
        return None, f"Invalid CRL distribution point. Choose from: {CRL_DP_MODES}"
    if crl_dp_mode in ("server", "cloudflare") and state.desktop_mode():
        return None, "The desktop app offers the endpoint-hosted distribution point only; the others need Docker"
    if crl_dp_mode == "server":
        crl_base_url = parse_crl_base_url(str_field(data, "crl_base_url"))
        if crl_base_url is None:
            return None, "The CRL server address must be an http(s) URL such as http://pki.example.lan:5000"

    return IssueRequest(
        common_name=common_name,
        san_list=san_list,
        algorithm=algorithm,
        template=template,
        email=str_field(data, "email").strip() or None,
        upn=str_field(data, "upn").strip() or None,
        crl_dp_mode=crl_dp_mode,
        crl_base_url=crl_base_url,
        lifetime_days=lifetime_days,
    ), None


def _placeholder_crl_url(ca: dict[str, Any]) -> str:
    return f"http://pki.{ca['domain']}/crl/{_safe_name(ca['name'])}.crl"


def _crl_served(ca: dict[str, Any]) -> bool:
    """/crl/<id>.crl answers for this CA: it opted in and has a published CRL."""
    return bool(ca.get("crl_public")) and ca.get("crl_der") is not None


def crl_dp_url_for(ca: dict[str, Any], mode: str, base_url: str | None) -> str | None:
    """The distribution point a new certificate gets for ``mode`` (one of CRL_DP_MODES)."""
    if mode == "cloudflare":
        return ca.get("cf_dp_url") or None
    if mode == "server":
        return f"{base_url}/crl/{ca['id']}.crl"
    if mode == "placeholder":
        return _placeholder_crl_url(ca)
    return None


def _crl_dp_url(ca: dict[str, Any], req: IssueRequest) -> str | None:
    return crl_dp_url_for(ca, req.crl_dp_mode, req.crl_base_url)


def publish_after_issue(ca: dict[str, Any], mode: str) -> None:
    """A certificate pointing at this server's CRL makes the CRL public; the first one for a
    restored Worker makes sure the Worker has a CRL."""
    if mode == "server":
        db.set_crl_public(ca["id"])
        crl_publisher.publish(ca["id"])
    elif mode == "cloudflare" and not ca.get("cf_pushed_sha256"):
        crl_publisher.publish(ca["id"])


def crl_dp_kind(url: str | None, ca: dict[str, Any]) -> str:
    """'none', 'placeholder' (nothing answers there), 'cloudflare' (the CA's Worker), 'server'
    (this server's /crl/<id>.crl) or 'other'."""
    if not url:
        return "none"
    if ca.get("cf_dp_url") and url == ca["cf_dp_url"]:
        return "cloudflare"
    if url == _placeholder_crl_url(ca):
        return "placeholder"
    if urlsplit(url).path.endswith(f"/crl/{ca['id']}.crl"):
        return "server"
    return "other"


def _worker_published(ca_id: int) -> bool:
    """The CA's Worker serves its latest CRL (the last push succeeded)."""
    worker = db.get_ca_worker(ca_id) or {}
    return bool(worker.get("cf_pushed_sha256")) and not worker.get("cf_push_error")


def _crl_dp_info(url: str | None, ca: dict[str, Any], served: bool, worker_published: bool) -> dict[str, Any]:
    """``served``: this server serves the CA's CRL; ``worker_published``: its Worker does."""
    kind = crl_dp_kind(url, ca)
    published = (kind == "server" and served) or (kind == "cloudflare" and worker_published)
    return {"kind": kind, "url": url or None, "published": published}


@bp.post("/api/ca/<int:ca_id>/certs")
def issue_cert(ca_id: int):
    ca = db.get_ca(ca_id)
    if not ca:
        return error("CA not found", 404)
    req, err = _parse_issue_request(json_body())
    if err:
        return error(err)

    crl_dp_url = _crl_dp_url(ca, req)
    if req.crl_dp_mode == "cloudflare" and not crl_dp_url:
        return error("This CA has no Cloudflare CRL Worker. Deploy one from the CA page first")
    cert_pem, key_pem, serial, not_before, not_after = crypto_engine.issue_certificate(
        ca_cert_pem=ca["cert_pem"], ca_key_pem=ca["key_pem"],
        common_name=req.common_name, san_domains=req.san_list, algorithm=req.algorithm,
        lifetime_days=req.lifetime_days, template=req.template, email=req.email, upn=req.upn,
        crl_dp_url=crl_dp_url,
    )
    cert_id = db.save_cert(
        ca_id=ca_id, common_name=req.common_name, san_domains=",".join(req.san_list),
        algorithm=req.algorithm, template=req.template, not_before=not_before, not_after=not_after,
        serial=serial, cert_pem=cert_pem, key_pem=key_pem, crl_dp_url=crl_dp_url,
    )
    publish_after_issue(ca, req.crl_dp_mode)
    log.info("Certificate issued: %s (ca=%d, template=%s, algo=%s)", req.common_name, ca_id, req.template, req.algorithm)
    return jsonify({"id": cert_id, "common_name": req.common_name, "serial": serial}), 201


@bp.get("/api/ca/<int:ca_id>/certs")
def list_certs_for_ca(ca_id: int):
    ca = db.get_ca_summary(ca_id)
    certs = db.list_certs(ca_id)
    if ca:
        served = db.get_published_crl(ca_id) is not None  # only for CAs that opted in
        worker_published = _worker_published(ca_id)
        for cert in certs:
            cert["crl_dp"] = _crl_dp_info(cert.pop("crl_dp_url", None), ca, served, worker_published)
    return jsonify(certs)


@bp.get("/api/certs")
def list_all_certs():
    return jsonify(db.list_certs())


@bp.get("/api/certs/<int:cert_id>")
def get_cert(cert_id: int):
    cert = db.get_cert(cert_id)
    if not cert:
        return error("Certificate not found", 404)
    return jsonify({k: v for k, v in cert.items() if k not in ("cert_pem", "key_pem")})


@bp.get("/api/certs/<int:cert_id>/details")
def get_cert_details(cert_id: int):
    """The parsed certificate (subject, extensions, fingerprints, PEM) for the viewer. Never the key."""
    cert = db.get_cert(cert_id)
    if not cert:
        return error("Certificate not found", 404)
    details = crypto_engine.describe_certificate(cert["cert_pem"])
    details.update({k: cert.get(k) for k in ("id", "ca_id", "common_name", "template", "revoked", "revoked_at")})
    ca = db.get_ca(cert["ca_id"])
    if ca:
        details["crl_dp"] = _crl_dp_info(cert.get("crl_dp_url"), ca, _crl_served(ca), _worker_published(ca["id"]))
    return jsonify(details)


@bp.get("/api/certs/<int:cert_id>/crl")
def get_cert_crl_status(cert_id: int):
    """Read-only view of the issuing CA's CRL contents as they relate to this certificate."""
    cert = db.get_cert(cert_id)
    if not cert:
        return error("Certificate not found", 404)
    ca = db.get_ca(cert["ca_id"])
    if not ca:
        return error("CA not found", 404)
    deleted = db.list_deleted_revocations(ca["id"])
    revoked = [
        {"serial": crypto_engine.format_serial(serial), "revoked_at": revoked_at,
         "this": serial == cert["serial"], "deleted": serial in deleted}
        for serial, revoked_at in db.list_revoked_serials(ca["id"])
    ]
    return jsonify({
        "ca_id": ca["id"],
        "ca_name": ca["name"],
        "distribution_points": crypto_engine.crl_distribution_points(cert["cert_pem"]),
        "next_update": ca.get("crl_next_update"),
        "served_next_update": crypto_engine.crl_next_update(ca["crl_der"]) if _crl_served(ca) else None,
        "published_path": f"/crl/{ca['id']}.crl" if _crl_served(ca) else None,
        "served": bool(ca.get("crl_public")),
        "revoked": revoked,
        "cert_revoked": bool(cert["revoked"]),
    })


_REVOKE_NOTES = {
    "server": "This server now serves an updated CRL. Clients see the revocation when their cached "
              f"copy expires, within {crl_publisher.PUBLISHED_CRL_DAYS} days.",
    "cloudflare": "The updated CRL was published to this CA's Cloudflare Worker. Clients see the revocation "
                  f"when their cached copy expires, within {crl_publisher.PUBLISHED_CRL_DAYS} days.",
    "placeholder": "Its CRL is endpoint-hosted, so a machine only sees the revocation once it gets the updated CRL: "
                   "run a new install .zip from Export / install, or import the CRL by hand.",
    "none": "It has no CRL distribution point, so clients don't check it. Import an updated CRL on "
            "machines that should stop trusting it.",
    "other": "Its CRL distribution point is an address this app doesn't manage. Publish an updated CRL there.",
}


@bp.get("/api/ca/<int:ca_id>/crl/view")
def view_crl(ca_id: int):
    """The CA's CRL for the CRL viewer: the one this server serves, or, for a CA that
    doesn't serve one, the entries an export would contain now. Needs no CA key."""
    ca = db.get_ca_summary(ca_id)
    if not ca:
        return error("CA not found", 404)
    current = {int(serial, 16): revoked_at for serial, revoked_at in db.list_revoked_serials(ca_id)}
    served = db.get_published_crl(ca_id)
    if served is not None:
        crl = crypto_engine.describe_crl(served)
        entries = crl.pop("entries")
    else:
        crl = None
        entries = [{"serial": crypto_engine.format_serial(hex(n)), "serial_hex": hex(n), "revoked_at": at}
                   for n, at in current.items()]
    certs = {int(c["serial"], 16): c for c in db.list_certs(ca_id)}
    deleted = {int(s, 16) for s in db.list_deleted_revocations(ca_id)}
    for entry in entries:
        number = int(entry.pop("serial_hex"), 16)
        cert = certs.get(number)
        entry.update(cert_id=cert["id"] if cert else None, common_name=cert["common_name"] if cert else None,
                     deleted=number in deleted)
    return jsonify({
        "ca_id": ca_id,
        "ca_name": ca["name"],
        "source": "served" if crl else "current",
        "published_path": f"/crl/{ca_id}.crl" if crl else None,
        "crl": crl,
        "entries": entries,
        # the served CRL should always match; a difference means it is waiting for an unlock
        "out_of_date": crl is not None and {int(e["serial"].replace(":", ""), 16) for e in entries} != set(current),
        "exported_next_update": ca.get("crl_next_update"),
    })


@bp.post("/api/certs/<int:cert_id>/revoke")
def revoke_cert(cert_id: int):
    cert = db.get_cert_summary(cert_id)
    ca = db.get_ca_summary(cert["ca_id"]) if cert else None
    if not cert or not ca or cert["revoked"]:
        return error("Certificate not found or already revoked", 404)
    if ca.get("crl_public") or ca.get("cf_worker"):
        db.require_unlocked()  # re-signing the published CRL needs the CA key: fail before revoking
    db.revoke_cert(cert_id)
    log.info("Certificate revoked: id=%d", cert_id)
    crl_publisher.publish(ca["id"])  # also pushes to the CA's Worker, if it has one
    kind = crl_dp_kind(cert.get("crl_dp_url"), ca)
    worker = db.get_ca_worker(ca["id"])
    result: dict[str, Any] = {"ok": True, "crl_dp": kind, "note": _REVOKE_NOTES[kind],
                              "download_crl": kind not in ("server", "cloudflare")}
    if worker is not None:
        result["cloudflare"] = {"pushed": not worker["cf_push_error"], "error": worker["cf_push_error"]}
        if kind == "cloudflare" and worker["cf_push_error"]:
            result["note"] = ("The certificate is revoked, but publishing the updated CRL to Cloudflare failed. "
                              "The app retries every hour; use Push now on the CA page to retry sooner.")
    # served or Worker: nothing to do; otherwise the page offers the updated CRL for import
    return jsonify(result)


@bp.delete("/api/certs/<int:cert_id>")
def delete_cert(cert_id: int):
    if db.delete_cert(cert_id):
        log.info("Certificate deleted: id=%d", cert_id)
        return jsonify({"ok": True})
    return error("Certificate not found", 404)


# ── CRL and exports ─────────────────────────────────────────────────

@bp.get("/api/ca/<int:ca_id>/crl")
def download_crl(ca_id: int):
    ca = db.get_ca(ca_id)
    if not ca:
        return error("CA not found", 404)
    days = parse_int(request.args.get("days"), DEFAULT_CRL_DAYS)
    if days is None or days < 1 or days > DEFAULT_CRL_DAYS:
        return error(f"CRL lifetime must be between 1 and {DEFAULT_CRL_DAYS} days")

    crl_der = crypto_engine.generate_crl(
        ca_cert_pem=ca["cert_pem"],
        ca_key_pem=ca["key_pem"],
        revoked_serials=db.list_revoked_serials(ca_id),
        crl_lifetime_days=days,
    )
    next_update = crypto_engine.crl_next_update(crl_der)
    db.set_ca_crl_next_update(ca_id, next_update)
    log.info("CRL exported for CA %d (next update %s)", ca_id, next_update)
    return deliver_export(crl_der, f"{_safe_name(ca['name'])}.crl", extra={"next_update": next_update})


@bp.post("/api/export/ca/<int:ca_id>")
def export_ca(ca_id: int):
    ca = db.get_ca(ca_id)
    if not ca:
        return error("CA not found", 404)

    data = json_body()
    fmt = str_field(data, "format", "pem")
    part = str_field(data, "part", "both")
    password = str_field(data, "password") or None
    password_error = export_password_error(password)
    if password_error:
        return error(password_error)
    if fmt not in VALID_FORMATS:
        return error(f"Invalid format. Choose from: {VALID_FORMATS}")
    if part not in VALID_CA_PARTS:
        return error(f"Invalid part. Choose from: {VALID_CA_PARTS}")
    if part != "public":
        rejection = reauth_rejection()
        if rejection is not None:
            return rejection

    try:
        if part == "public":
            export_data, filename = crypto_engine.export_public_only(ca["cert_pem"], fmt)
        elif part == "private":
            export_data, filename = crypto_engine.export_private_only(ca["key_pem"], fmt)
        else:
            export_data, filename = crypto_engine.export_certificate(ca["cert_pem"], ca["key_pem"], fmt, password=password)
    except ValueError as e:
        return error(str(e))
    return deliver_export(export_data, f"ca-{_safe_name(ca['name'])}-{filename}")


@bp.post("/api/export/cert/<int:cert_id>")
def export_cert(cert_id: int):
    cert = db.get_cert(cert_id)
    if not cert:
        return error("Certificate not found", 404)

    data = json_body()
    fmt = str_field(data, "format", "pem")
    part = str_field(data, "part", "both")
    password = str_field(data, "password") or None
    password_error = export_password_error(password)
    if password_error:
        return error(password_error)
    include_chain = bool(data.get("include_chain", False))
    if fmt not in VALID_FORMATS:
        return error(f"Invalid format. Choose from: {VALID_FORMATS}")
    if part not in VALID_CERT_PARTS:
        return error(f"Invalid part. Choose from: {VALID_CERT_PARTS}")
    if part not in ("public", "chain"):  # the others carry the private key
        if not cert["key_pem"]:
            return error(KEY_ON_DEVICE)
        rejection = reauth_rejection()
        if rejection is not None:
            return rejection

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
        return error(str(e))
    return deliver_export(export_data, f"{cert['common_name']}-{filename}")


@bp.post("/api/export/cert/<int:cert_id>/bundle")
def export_install_bundle(cert_id: int):
    """A .zip with the certificate (and key), optionally its CA chain, and an install script."""
    cert = db.get_cert(cert_id)
    if not cert:
        return error("Certificate not found", 404)
    data = json_body()
    os_name = str_field(data, "os")
    if os_name not in install_bundle.OSES:
        return error(f"Invalid OS. Choose from: {install_bundle.OSES}")
    if not cert["key_pem"]:
        return error(KEY_ON_DEVICE)
    rejection = reauth_rejection()  # the bundle carries the private key
    if rejection is not None:
        return rejection
    chain = db.get_ca_named_chain(cert["ca_id"])
    crl = None
    issuer = db.get_ca(cert["ca_id"])
    if issuer and crl_dp_kind(cert.get("crl_dp_url"), issuer) == "placeholder":
        # Nothing answers at a placeholder address: ship the CRL, as Export CRL would.
        crl_der = crypto_engine.generate_crl(
            ca_cert_pem=issuer["cert_pem"], ca_key_pem=issuer["key_pem"],
            revoked_serials=db.list_revoked_serials(issuer["id"]), crl_lifetime_days=DEFAULT_CRL_DAYS)
        db.set_ca_crl_next_update(issuer["id"], crypto_engine.crl_next_update(crl_der))
        crl = (issuer["name"], crl_der)
    password_error = export_password_error(str_field(data, "password") or None)
    if password_error:
        return error(password_error)
    try:
        bundle, filename = install_bundle.build(
            cert_pem=cert["cert_pem"], key_pem=cert["key_pem"], template=cert["template"],
            common_name=cert["common_name"], os_name=os_name,
            ca_chain=chain if data.get("include_ca") else [], chain_for_pfx=chain, crl=crl,
            placeholder_url=cert.get("crl_dp_url") if crl else None,
            password=str_field(data, "password") or None,
        )
    except UserError as e:
        return error(e.user_message)
    log.info("Install bundle exported: cert=%d os=%s with_ca=%s", cert_id, os_name, bool(data.get("include_ca")))
    return deliver_export(bundle, filename)


@bp.route("/crl/<int:ca_id>.crl", methods=["GET", "HEAD"], provide_automatic_options=False)
def published_crl(ca_id: int):
    """Public and unauthenticated: the published CRL of a CA whose certificates name
    this server as their distribution point. It is the one path meant to be exposed through
    an ingress, so it reads nothing but that blob, never touches the session or a cookie,
    answers 404 alike for unknown and unpublished CAs, and is rate limited per client."""
    if not _crl_limiter.allow(request.remote_addr or "unknown"):
        resp = Response("Too many requests", status=429, content_type="text/plain")
        resp.headers["Retry-After"] = "60"
        return resp
    crl_der = db.get_published_crl(ca_id)
    if crl_der is None:
        return Response("Not found", status=404, content_type="text/plain")
    resp = Response(crl_der, content_type="application/pkix-crl")
    resp.headers["Content-Disposition"] = f'attachment; filename="{ca_id}.crl"'
    resp.headers["Cache-Control"] = "public, max-age=300"
    resp.headers["Content-Security-Policy"] = _CRL_CSP
    resp.add_etag()
    return resp.make_conditional(request)
