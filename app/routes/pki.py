"""Certificate authorities, certificates, CRLs, and their exports."""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any

from flask import Blueprint, jsonify, request

from .. import crypto_engine, db
from ..web import deliver_export, error, json_body, parse_int, str_field

log = logging.getLogger("cert-generator")

bp = Blueprint("pki", __name__)

VALID_FORMATS = ("pem", "der", "crt", "pkcs12")
VALID_CA_PARTS = ("both", "public", "private")
VALID_CERT_PARTS = ("both", "public", "private", "chain")
DOMAIN_RE = re.compile(r"^[\w.*-]{1,253}$")
MAX_LIFETIME_DAYS = 36500
DEFAULT_CRL_DAYS = 3650


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
    safe = {k: v for k, v in ca.items() if k not in ("cert_pem", "key_pem")}
    safe["child_cas"] = db.list_child_cas(ca_id)
    safe["is_root"] = ca.get("parent_ca_id") is None
    safe["can_issue_intermediate"] = crypto_engine.ca_allows_subordinate_ca(ca["cert_pem"])
    return jsonify(safe)


@bp.delete("/api/ca/<int:ca_id>")
def delete_ca(ca_id: int):
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
    include_crl_dp: bool
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

    return IssueRequest(
        common_name=common_name,
        san_list=san_list,
        algorithm=algorithm,
        template=template,
        email=str_field(data, "email").strip() or None,
        upn=str_field(data, "upn").strip() or None,
        include_crl_dp=bool(data.get("include_crl_dp", False)),
        lifetime_days=lifetime_days,
    ), None


@bp.post("/api/ca/<int:ca_id>/certs")
def issue_cert(ca_id: int):
    ca = db.get_ca(ca_id)
    if not ca:
        return error("CA not found", 404)
    req, err = _parse_issue_request(json_body())
    if err:
        return error(err)

    crl_dp_url = f"http://pki.{ca['domain']}/crl/{_safe_name(ca['name'])}.crl" if req.include_crl_dp else None
    cert_pem, key_pem, serial, not_before, not_after = crypto_engine.issue_certificate(
        ca_cert_pem=ca["cert_pem"], ca_key_pem=ca["key_pem"],
        common_name=req.common_name, san_domains=req.san_list, algorithm=req.algorithm,
        lifetime_days=req.lifetime_days, template=req.template, email=req.email, upn=req.upn,
        crl_dp_url=crl_dp_url,
    )
    cert_id = db.save_cert(
        ca_id=ca_id, common_name=req.common_name, san_domains=",".join(req.san_list),
        algorithm=req.algorithm, template=req.template, not_before=not_before, not_after=not_after,
        serial=serial, cert_pem=cert_pem, key_pem=key_pem,
    )
    log.info("Certificate issued: %s (ca=%d, template=%s, algo=%s)", req.common_name, ca_id, req.template, req.algorithm)
    return jsonify({"id": cert_id, "common_name": req.common_name, "serial": serial}), 201


@bp.get("/api/ca/<int:ca_id>/certs")
def list_certs_for_ca(ca_id: int):
    return jsonify(db.list_certs(ca_id))


@bp.get("/api/certs")
def list_all_certs():
    return jsonify(db.list_certs())


@bp.get("/api/certs/<int:cert_id>")
def get_cert(cert_id: int):
    cert = db.get_cert(cert_id)
    if not cert:
        return error("Certificate not found", 404)
    return jsonify({k: v for k, v in cert.items() if k not in ("cert_pem", "key_pem")})


@bp.post("/api/certs/<int:cert_id>/revoke")
def revoke_cert(cert_id: int):
    if db.revoke_cert(cert_id):
        log.info("Certificate revoked: id=%d", cert_id)
        return jsonify({"ok": True, "note": "Re-export the CA's CRL to update revocation status on endpoints."})
    return error("Certificate not found or already revoked", 404)


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
    if fmt not in VALID_FORMATS:
        return error(f"Invalid format. Choose from: {VALID_FORMATS}")
    if part not in VALID_CA_PARTS:
        return error(f"Invalid part. Choose from: {VALID_CA_PARTS}")

    try:
        if part == "public":
            export_data, filename = crypto_engine.export_public_only(ca["cert_pem"], fmt)
        elif part == "private":
            export_data, filename = crypto_engine.export_private_only(ca["key_pem"], fmt)
        else:
            export_data, filename = crypto_engine.export_certificate(ca["cert_pem"], ca["key_pem"], fmt, password=password)
    except ValueError as e:
        return error(str(e))
    return deliver_export(export_data, f"ca-{ca['domain']}-{filename}")


@bp.post("/api/export/cert/<int:cert_id>")
def export_cert(cert_id: int):
    cert = db.get_cert(cert_id)
    if not cert:
        return error("Certificate not found", 404)

    data = json_body()
    fmt = str_field(data, "format", "pem")
    part = str_field(data, "part", "both")
    password = str_field(data, "password") or None
    include_chain = bool(data.get("include_chain", False))
    if fmt not in VALID_FORMATS:
        return error(f"Invalid format. Choose from: {VALID_FORMATS}")
    if part not in VALID_CERT_PARTS:
        return error(f"Invalid part. Choose from: {VALID_CERT_PARTS}")

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
