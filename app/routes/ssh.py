"""SSH key generation, import, and export."""
from __future__ import annotations

import logging
import re

from flask import Blueprint, jsonify

from .. import crypto_engine, db
from ..web import deliver_export, error, json_body, str_field

log = logging.getLogger("cert-generator")

bp = Blueprint("ssh", __name__)

VALID_SSH_FORMATS = ("openssh", "pem")


def _safe_name(value: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', value)


@bp.get("/api/ssh-keys")
def list_ssh_keys():
    return jsonify(db.list_ssh_keys())


@bp.get("/api/ssh-keys/<int:key_id>")
def get_ssh_key(key_id: int):
    key = db.get_ssh_key(key_id)
    if not key:
        return error("SSH key not found", 404)
    safe = {k: v for k, v in key.items() if k != "private_key"}
    safe["public_key"] = key["public_key"].decode("utf-8") if isinstance(key["public_key"], bytes) else key["public_key"]
    return jsonify(safe)


@bp.post("/api/ssh-keys")
def create_ssh_key():
    data = json_body()
    name = str_field(data, "name").strip()
    algorithm = str_field(data, "algorithm", "rsa-4096")
    comment = str_field(data, "comment").strip()
    passphrase = str_field(data, "passphrase").strip() or None

    if not name or len(name) > 200:
        return error("A name is required (max 200 chars)")
    if algorithm not in crypto_engine.SSH_ALGORITHMS:
        return error(f"Invalid algorithm. Choose from: {crypto_engine.SSH_ALGORITHMS}")
    db.require_unlocked()

    private_bytes, public_bytes, fingerprint = crypto_engine.generate_ssh_key(
        algorithm=algorithm, passphrase=passphrase, comment=comment,
    )
    key_id = db.save_ssh_key(
        name=name, algorithm=algorithm, comment=comment, fingerprint=fingerprint,
        public_key=public_bytes, private_key=private_bytes, has_passphrase=bool(passphrase),
    )
    log.info("SSH key generated: %s (algo=%s)", name, algorithm)
    return jsonify({"id": key_id, "name": name, "fingerprint": fingerprint}), 201


@bp.post("/api/ssh-keys/import")
def import_ssh_key():
    data = json_body()
    name = str_field(data, "name").strip()
    private_key_text = str_field(data, "private_key").strip()
    passphrase = str_field(data, "passphrase").strip() or None
    comment = str_field(data, "comment").strip()

    if not name or len(name) > 200:
        return error("A name is required (max 200 chars)")
    if not private_key_text:
        return error("Private key is required")

    try:
        private_bytes, public_bytes, algorithm, fingerprint, has_passphrase = (
            crypto_engine.parse_ssh_key(private_key_text, passphrase=passphrase)
        )
    except ValueError as e:
        return error(str(e))

    if comment:
        public_bytes = public_bytes.rstrip() + b" " + comment.encode("utf-8") + b"\n"

    key_id = db.save_ssh_key(
        name=name, algorithm=algorithm, comment=comment, fingerprint=fingerprint,
        public_key=public_bytes, private_key=private_bytes, has_passphrase=has_passphrase, imported=True,
    )
    algo_label = crypto_engine.SSH_ALGORITHM_LABELS.get(algorithm, algorithm)
    log.info("SSH key imported: %s (algo=%s)", name, algorithm)
    return jsonify({"id": key_id, "name": name, "fingerprint": fingerprint, "algorithm": algo_label}), 201


@bp.delete("/api/ssh-keys/<int:key_id>")
def delete_ssh_key(key_id: int):
    if db.delete_ssh_key(key_id):
        log.info("SSH key deleted: id=%d", key_id)
        return jsonify({"ok": True})
    return error("SSH key not found", 404)


@bp.post("/api/export/ssh-key/<int:key_id>")
def export_ssh_key(key_id: int):
    key = db.get_ssh_key(key_id)
    if not key:
        return error("SSH key not found", 404)

    data = json_body()
    part = str_field(data, "part", "private")
    fmt = str_field(data, "format", "openssh")
    passphrase = str_field(data, "passphrase").strip() or None
    original_passphrase = str_field(data, "original_passphrase").strip() or None
    safe_name = _safe_name(key["name"])

    if part == "public":
        pub = key["public_key"]
        if isinstance(pub, str):
            pub = pub.encode("utf-8")
        return deliver_export(pub, f"{safe_name}.pub")

    if fmt not in VALID_SSH_FORMATS:
        return error(f"Invalid format. Choose from: {VALID_SSH_FORMATS}")
    try:
        export_data, filename = crypto_engine.export_ssh_private_key(
            key["private_key"], fmt, passphrase=passphrase, original_passphrase=original_passphrase,
        )
    except ValueError as e:
        return error(str(e))
    return deliver_export(export_data, f"{safe_name}-{filename}")


@bp.get("/api/ssh-keys/<int:key_id>/private")
def get_ssh_private_key(key_id: int):
    key = db.get_ssh_key(key_id)
    if not key:
        return error("SSH key not found", 404)
    priv = key["private_key"]
    if isinstance(priv, bytes):
        priv = priv.decode("utf-8")
    return jsonify({"private_key": priv})
