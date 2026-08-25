from __future__ import annotations

import io
import re
import secrets
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, send_file

from . import crypto_engine, db

VALID_FORMATS = ("pem", "der", "pkcs12")
VALID_CA_PARTS = ("both", "public", "private")
VALID_CERT_PARTS = ("both", "public", "private", "chain")
DOMAIN_RE = re.compile(r"^[\w.*-]{1,253}$")

_bound_port: int | None = None


def set_bound_port(port: int) -> None:
    global _bound_port
    _bound_port = port


app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)
app.secret_key = secrets.token_hex(32)

with app.app_context():
    db.init_db()


@app.before_request
def _csrf_check() -> Response | None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    origin = request.headers.get("Origin", "")
    if not origin:
        return None
    port = _bound_port or 5174
    if f"127.0.0.1:{port}" not in origin and f"localhost:{port}" not in origin:
        return jsonify({"error": "Forbidden"}), 403
    return None


def _parse_int(value, default: int) -> int | None:
    try:
        return int(value) if value is not None else default
    except (ValueError, TypeError):
        return None


@app.get("/")
def index():
    return render_template("index.html")


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

    cert_pem, key_pem, serial, not_before, not_after = crypto_engine.issue_certificate(
        ca_cert_pem=ca["cert_pem"],
        ca_key_pem=ca["key_pem"],
        common_name=common_name,
        san_domains=san_list,
        algorithm=algorithm,
        lifetime_days=lifetime_days,
        template=template,
        email=email,
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
        return jsonify({"ok": True})
    return jsonify({"error": "Certificate not found or already revoked"}), 404


@app.delete("/api/certs/<int:cert_id>")
def delete_cert(cert_id: int):
    if db.delete_cert(cert_id):
        return jsonify({"ok": True})
    return jsonify({"error": "Certificate not found"}), 404


def _downloads_dir() -> Path:
    downloads = Path.home() / "Downloads"
    downloads.mkdir(exist_ok=True)
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
            ca_cert_pem=ca_cert_pem, password=password,
        )

    saved = _save_export(export_data, f"{cert['common_name']}-{filename}")
    return jsonify({"path": saved})
