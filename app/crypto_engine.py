from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

Algorithm = Literal["ed25519", "ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-4096"]

ALGORITHMS: list[Algorithm] = ["ed25519", "ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-4096"]


CERT_TEMPLATES: dict[str, dict] = {
    "web-server": {
        "label": "Web Server",
        "description": "Server Authentication",
        "key_usage": {
            "digital_signature": True,
            "key_encipherment": True,
            "content_commitment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usage": [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH],
        "default_days": 365,
    },
    "computer": {
        "label": "Computer",
        "description": "Client Authentication, Server Authentication",
        "key_usage": {
            "digital_signature": True,
            "key_encipherment": True,
            "content_commitment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usage": [
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        ],
        "default_days": 365,
    },
    "client-auth": {
        "label": "Client Authentication",
        "description": "Client Authentication",
        "key_usage": {
            "digital_signature": True,
            "key_encipherment": False,
            "content_commitment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usage": [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH],
        "default_days": 365,
    },
    "code-signing": {
        "label": "Code Signing",
        "description": "Code Signing",
        "key_usage": {
            "digital_signature": True,
            "key_encipherment": False,
            "content_commitment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usage": [x509.oid.ExtendedKeyUsageOID.CODE_SIGNING],
        "default_days": 365,
    },
    "email": {
        "label": "Email (S/MIME)",
        "description": "Email Protection",
        "key_usage": {
            "digital_signature": True,
            "key_encipherment": True,
            "content_commitment": True,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usage": [x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION],
        "default_days": 365,
        "include_email": True,
    },
}


def _generate_key(algorithm: Algorithm):
    if algorithm == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if algorithm == "ecdsa-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == "ecdsa-p384":
        return ec.generate_private_key(ec.SECP384R1())
    if algorithm == "rsa-2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if algorithm == "rsa-4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    raise ValueError(f"Unknown algorithm: {algorithm}")


def _signing_hash(algorithm: Algorithm) -> hashes.HashAlgorithm | None:
    if algorithm == "ed25519":
        return None
    if algorithm in ("ecdsa-p384", "rsa-4096"):
        return hashes.SHA384()
    return hashes.SHA256()


def _serial_number() -> int:
    raw = int.from_bytes(secrets.token_bytes(20), "big")
    return raw >> 1


def create_ca(
    domain: str,
    name: str,
    algorithm: Algorithm,
    lifetime_days: int,
) -> tuple[bytes, bytes, str, str, str]:
    key = _generate_key(algorithm)
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=lifetime_days)
    serial = _serial_number()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    )

    hash_alg = _signing_hash(algorithm)
    cert = builder.sign(key, hash_alg)

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    return (
        cert_pem,
        key_pem,
        hex(serial),
        now.isoformat(),
        not_after.isoformat(),
    )


def issue_certificate(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    common_name: str,
    san_domains: list[str],
    algorithm: Algorithm,
    lifetime_days: int,
    template: str = "web-server",
    email: str | None = None,
) -> tuple[bytes, bytes, str, str, str]:
    tmpl = CERT_TEMPLATES.get(template, CERT_TEMPLATES["web-server"])

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    leaf_key = _generate_key(algorithm)
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=lifetime_days)
    serial = _serial_number()

    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if email and tmpl.get("include_email"):
        name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

    subject = x509.Name(name_attrs)

    san_entries: list[x509.GeneralName] = []
    for d in san_domains:
        san_entries.append(x509.DNSName(d))
    if email and tmpl.get("include_email"):
        san_entries.append(x509.RFC822Name(email))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(**tmpl["key_usage"]),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(tmpl["extended_key_usage"]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )

    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )

    ca_algorithm = _detect_algorithm(ca_key)
    hash_alg = _signing_hash(ca_algorithm)
    cert = builder.sign(ca_key, hash_alg)

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    return (
        cert_pem,
        key_pem,
        hex(serial),
        now.isoformat(),
        not_after.isoformat(),
    )


def _detect_algorithm(key) -> Algorithm:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "ed25519"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        curve = key.curve
        if isinstance(curve, ec.SECP256R1):
            return "ecdsa-p256"
        return "ecdsa-p384"
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size <= 2048:
            return "rsa-2048"
        return "rsa-4096"
    raise ValueError("Unknown key type")


ExportFormat = Literal["pem", "der", "pkcs12"]


def export_certificate(
    cert_pem: bytes,
    key_pem: bytes,
    fmt: ExportFormat,
    ca_cert_pem: bytes | None = None,
    password: str | None = None,
) -> tuple[bytes, str]:
    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)

    if fmt == "pem":
        if password:
            encrypted_key = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password.encode("utf-8")),
            )
            return cert_pem + encrypted_key, "certificate.pem"
        return cert_pem + key_pem, "certificate.pem"

    if fmt == "der":
        return cert.public_bytes(serialization.Encoding.DER), "certificate.der"

    if fmt == "pkcs12":
        ca_certs = None
        if ca_cert_pem:
            ca_certs = [x509.load_pem_x509_certificate(ca_cert_pem)]

        enc = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        )
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=None,
            key=key,
            cert=cert,
            cas=ca_certs,
            encryption_algorithm=enc,
        )
        return pfx_data, "certificate.pfx"

    raise ValueError(f"Unknown format: {fmt}")


def export_public_only(cert_pem: bytes, fmt: ExportFormat) -> tuple[bytes, str]:
    cert = x509.load_pem_x509_certificate(cert_pem)

    if fmt == "pem":
        return cert_pem, "certificate.pem"
    if fmt == "der":
        return cert.public_bytes(serialization.Encoding.DER), "certificate.der"

    raise ValueError(f"Cannot export public-only as {fmt}")


def export_private_only(key_pem: bytes, fmt: str) -> tuple[bytes, str]:
    key = serialization.load_pem_private_key(key_pem, password=None)

    if fmt == "pem":
        return key_pem, "private_key.pem"
    if fmt == "der":
        der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return der, "private_key.der"

    raise ValueError(f"Cannot export private key as {fmt}")
