from __future__ import annotations

import base64
import hashlib
import ipaddress
import secrets
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Literal

from cryptography import x509
from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import pkcs12

from .errors import UserError
from cryptography.x509.oid import NameOID

from .errors import UserError

MS_UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
SMARTCARD_LOGON_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")

Algorithm = Literal["ed25519", "ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-4096"]

ALGORITHMS: list[Algorithm] = ["ed25519", "ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-4096"]


_KEY_USAGE_FLAGS = (
    "digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
    "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only",
)


def _key_usage(**enabled: bool) -> dict[str, bool]:
    flags = dict.fromkeys(_KEY_USAGE_FLAGS, False)
    flags.update(enabled)
    return flags


CERT_TEMPLATES: dict[str, dict] = {
    "web-server": {
        "label": "Web Server",
        "description": "Server Authentication",
        "key_usage": _key_usage(digital_signature=True, key_encipherment=True),
        "extended_key_usage": [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH],
        "default_days": 365,
    },
    "computer": {
        "label": "Computer",
        "description": "Client Authentication, Server Authentication",
        "key_usage": _key_usage(digital_signature=True, key_encipherment=True),
        "extended_key_usage": [
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        ],
        "default_days": 365,
    },
    "client-auth": {
        "label": "Client Authentication",
        "description": "Client Authentication",
        "key_usage": _key_usage(digital_signature=True),
        "extended_key_usage": [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH],
        "default_days": 365,
    },
    "code-signing": {
        "label": "Code Signing",
        "description": "Code Signing",
        "key_usage": _key_usage(digital_signature=True),
        "extended_key_usage": [x509.oid.ExtendedKeyUsageOID.CODE_SIGNING],
        "default_days": 365,
    },
    "email": {
        "label": "Email (S/MIME)",
        "description": "Email Protection",
        "key_usage": _key_usage(digital_signature=True, key_encipherment=True, content_commitment=True),
        "extended_key_usage": [x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION],
        "default_days": 365,
        "include_email": True,
    },
    "user": {
        "label": "User",
        "description": "Client Authentication, Smart Card Logon",
        "key_usage": _key_usage(digital_signature=True, key_encipherment=True),
        "extended_key_usage": [
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            SMARTCARD_LOGON_OID,
        ],
        "default_days": 365,
        "include_email": True,
        "include_upn": True,
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
    raise UserError(f"Unknown algorithm: {algorithm}")


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
            x509.BasicConstraints(ca=True, path_length=None),
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


def create_intermediate_ca(
    parent_cert_pem: bytes,
    parent_key_pem: bytes,
    domain: str,
    name: str,
    algorithm: Algorithm,
    lifetime_days: int,
) -> tuple[bytes, bytes, str, str, str]:
    parent_cert = x509.load_pem_x509_certificate(parent_cert_pem)
    parent_key = serialization.load_pem_private_key(parent_key_pem, password=None)

    key = _generate_key(algorithm)
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=lifetime_days)
    serial = _serial_number()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent_cert.subject)
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
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_cert.public_key()),
            critical=False,
        )
    )

    parent_algorithm = _detect_algorithm(parent_key)
    hash_alg = _signing_hash(parent_algorithm)
    cert = builder.sign(parent_key, hash_alg)

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
    upn: str | None = None,
    crl_dp_url: str | None = None,
    public_key: CertificatePublicKey | None = None,
) -> tuple[bytes, bytes, str, str, str]:
    """Sign a leaf certificate. With ``public_key`` (from a CSR, see ``load_csr``) no key is
    generated here and the returned key PEM is empty: the private key stays with the requester."""
    tmpl = CERT_TEMPLATES.get(template, CERT_TEMPLATES["web-server"])

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    leaf_key = _generate_key(algorithm) if public_key is None else None
    leaf_public = public_key if public_key is not None else leaf_key.public_key()
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=lifetime_days)
    serial = _serial_number()

    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if email and tmpl.get("include_email"):
        name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

    subject = x509.Name(name_attrs)

    san_entries: list[x509.GeneralName] = []
    for d in san_domains:
        san_entries.append(_san_name(d))
    if email and tmpl.get("include_email"):
        san_entries.append(x509.RFC822Name(email))
    if upn and tmpl.get("include_upn"):
        san_entries.append(x509.OtherName(MS_UPN_OID, _encode_utf8_string(upn)))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_public)
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
            x509.SubjectKeyIdentifier.from_public_key(leaf_public),
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

    if crl_dp_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_dp_url)],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                ),
            ]),
            critical=False,
        )

    ca_algorithm = _detect_algorithm(ca_key)
    hash_alg = _signing_hash(ca_algorithm)
    cert = builder.sign(ca_key, hash_alg)

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = b"" if leaf_key is None else leaf_key.private_bytes(
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


CertificatePublicKey = ec.EllipticCurvePublicKey | rsa.RSAPublicKey

# Keys a certificate signing request may carry: what Windows CNG creates and Schannel uses.
CSR_KEY_TYPES = ("ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096")
MAX_CSR_BYTES = 16 * 1024


def public_key_algorithm(key) -> str | None:
    """'ecdsa-p256', 'rsa-3072', … for a key a CSR may carry; None for anything else."""
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"secp256r1": "ecdsa-p256", "secp384r1": "ecdsa-p384"}.get(key.curve.name)
    if isinstance(key, rsa.RSAPublicKey) and key.key_size in (2048, 3072, 4096):
        return f"rsa-{key.key_size}"
    return None


def load_csr(csr_pem: bytes) -> tuple[CertificatePublicKey, str]:
    """The public key of a PEM CSR whose self-signature verifies (proof that the requester
    holds the private key), with its algorithm label. Raises ValueError otherwise. Only the
    key is used: the subject and extensions in the CSR are ignored by the caller."""
    if len(csr_pem) > MAX_CSR_BYTES:
        raise UserError("The certificate request is too large")
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
        valid = csr.is_signature_valid
        key = csr.public_key()
    except (ValueError, UnsupportedAlgorithm) as e:
        raise UserError("The certificate request could not be read") from e
    if not valid:
        raise UserError("The certificate request's signature does not verify")
    algorithm = public_key_algorithm(key)
    if algorithm is None:
        raise UserError(f"Unsupported key type. Use one of: {', '.join(CSR_KEY_TYPES)}")
    return key, algorithm


def cert_der_sha256(cert_pem: bytes) -> str:
    """SHA-256 of the certificate's DER encoding, lowercase hex (what Windows calls the SHA-256 thumbprint)."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _san_name(value: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        return x509.DNSName(value)


def ca_allows_subordinate_ca(ca_cert_pem: bytes) -> bool:
    """False when the CA's basicConstraints path length forbids issuing further CAs."""
    cert = x509.load_pem_x509_certificate(ca_cert_pem)
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False
    return constraints.ca and constraints.path_length != 0


_NAME_LABELS = {
    "commonName": "Common name", "emailAddress": "Email", "organizationName": "Organization",
    "organizationalUnitName": "Organizational unit", "countryName": "Country",
    "stateOrProvinceName": "State / province", "localityName": "Locality",
}
_OID_LABELS = {
    SMARTCARD_LOGON_OID.dotted_string: "Smart Card Logon",
    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: "Server Authentication",
    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: "Client Authentication",
    x509.oid.ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: "Code Signing",
    x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: "Email Protection",
    x509.oid.ExtensionOID.BASIC_CONSTRAINTS.dotted_string: "Basic Constraints",
    x509.oid.ExtensionOID.KEY_USAGE.dotted_string: "Key Usage",
    x509.oid.ExtensionOID.EXTENDED_KEY_USAGE.dotted_string: "Extended Key Usage",
    x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string: "Subject Key Identifier",
    x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string: "Authority Key Identifier",
    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string: "Subject Alternative Name",
    x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS.dotted_string: "CRL Distribution Points",
}


def _oid_label(oid: x509.ObjectIdentifier) -> str:
    return _OID_LABELS.get(oid.dotted_string) or getattr(oid, "_name", None) or oid.dotted_string


def _colon_hex(data: bytes) -> str:
    return data.hex(":").upper()


def _describe_name(name: x509.Name) -> list[dict[str, str]]:
    return [
        {"name": _NAME_LABELS.get(_oid_label(attr.oid), _oid_label(attr.oid)), "value": str(attr.value)}
        for attr in name
    ]


def _decode_utf8_string(der: bytes) -> str | None:
    if not der or der[0] != 0x0C or len(der) < 2:
        return None
    if der[1] < 0x80:
        start = 2
    else:
        start = 2 + (der[1] & 0x7F)
    return der[start:].decode("utf-8", errors="replace")


def _describe_general_name(gn: x509.GeneralName) -> str:
    if isinstance(gn, x509.DNSName):
        return f"DNS: {gn.value}"
    if isinstance(gn, x509.IPAddress):
        return f"IP: {gn.value}"
    if isinstance(gn, x509.RFC822Name):
        return f"Email: {gn.value}"
    if isinstance(gn, x509.UniformResourceIdentifier):
        return f"URI: {gn.value}"
    if isinstance(gn, x509.OtherName) and gn.type_id == MS_UPN_OID:
        return f"UPN: {_decode_utf8_string(gn.value) or gn.value.hex()}"
    if isinstance(gn, x509.DirectoryName):
        return f"DirName: {gn.value.rfc4514_string()}"
    return str(gn.value)


def _describe_key_usage(ku: x509.KeyUsage) -> list[str]:
    labels = {
        "digital_signature": "Digital Signature", "content_commitment": "Non-Repudiation",
        "key_encipherment": "Key Encipherment", "data_encipherment": "Data Encipherment",
        "key_agreement": "Key Agreement", "key_cert_sign": "Certificate Sign", "crl_sign": "CRL Sign",
        "encipher_only": "Encipher Only", "decipher_only": "Decipher Only",
    }
    out = []
    for attr, label in labels.items():
        try:
            if getattr(ku, attr):
                out.append(label)
        except ValueError:  # encipher/decipher_only are undefined without key_agreement
            pass
    return out


def _describe_extension(ext: x509.Extension) -> list[str]:
    value = ext.value
    if isinstance(value, x509.SubjectAlternativeName):
        return [_describe_general_name(gn) for gn in value]
    if isinstance(value, x509.KeyUsage):
        return _describe_key_usage(value)
    if isinstance(value, x509.ExtendedKeyUsage):
        return [_oid_label(oid) for oid in value]
    if isinstance(value, x509.BasicConstraints):
        out = ["CA: " + ("yes" if value.ca else "no")]
        if value.path_length is not None:
            out.append(f"Path length: {value.path_length}")
        return out
    if isinstance(value, x509.SubjectKeyIdentifier):
        return [_colon_hex(value.digest)]
    if isinstance(value, x509.AuthorityKeyIdentifier):
        return [_colon_hex(value.key_identifier)] if value.key_identifier else []
    if isinstance(value, x509.CRLDistributionPoints):
        return [_describe_general_name(gn) for dp in value for gn in (dp.full_name or [])]
    return [_colon_hex(value.public_bytes())] if hasattr(value, "public_bytes") else [str(value)]


def _describe_public_key(key) -> str:
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA {key.curve.name} ({key.key_size} bits)"
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size} bits (e={key.public_numbers().e})"
    return type(key).__name__


def describe_certificate(cert_pem: bytes) -> dict:
    """A human-readable breakdown of a certificate, for the certificate viewer."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    return {
        "version": cert.version.value + 1,
        "serial": format_serial(hex(cert.serial_number)),
        "subject": _describe_name(cert.subject),
        "issuer": _describe_name(cert.issuer),
        "self_signed": cert.subject == cert.issuer,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "public_key": _describe_public_key(cert.public_key()),
        "signature_algorithm": _oid_label(cert.signature_algorithm_oid),
        "extensions": [
            {"name": _oid_label(ext.oid), "critical": ext.critical, "values": _describe_extension(ext)}
            for ext in cert.extensions
        ],
        "fingerprints": {
            "sha256": _colon_hex(hashlib.sha256(der).digest()),
            "sha1": _colon_hex(hashlib.sha1(der, usedforsecurity=False).digest()),
        },
        "pem": cert_pem.decode("ascii"),
    }


def _parse_timestamp(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _encode_utf8_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    length = len(encoded)
    if length < 128:
        return b"\x0c" + bytes([length]) + encoded
    if length < 256:
        return b"\x0c\x81" + bytes([length]) + encoded
    return b"\x0c\x82" + length.to_bytes(2, "big") + encoded


def generate_crl(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    revoked_serials: list[tuple[str, str]],
    crl_lifetime_days: int = 3650,
) -> bytes:
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=crl_lifetime_days))
    )

    for serial_hex, revoked_at in revoked_serials:
        serial_int = int(serial_hex, 16)
        try:
            rev_date = _parse_timestamp(revoked_at)
        except (ValueError, TypeError):
            rev_date = now
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_int)
            .revocation_date(rev_date)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    ca_algorithm = _detect_algorithm(ca_key)
    hash_alg = _signing_hash(ca_algorithm)
    crl = builder.sign(ca_key, hash_alg)
    return crl.public_bytes(serialization.Encoding.DER)


def crl_next_update(crl_der: bytes) -> str:
    """The CRL's nextUpdate as an ISO 8601 UTC timestamp."""
    crl = x509.load_der_x509_crl(crl_der)
    return crl.next_update_utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def describe_crl(crl_der: bytes) -> dict:
    """A human-readable breakdown of a CRL, for the CRL viewer, like `openssl crl -text`."""
    crl = x509.load_der_x509_crl(crl_der)
    return {
        "issuer": _describe_name(crl.issuer),
        "last_update": crl.last_update_utc.isoformat(),
        "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
        "signature_algorithm": _oid_label(crl.signature_algorithm_oid),
        "entries": [
            {"serial": format_serial(hex(entry.serial_number)), "serial_hex": hex(entry.serial_number),
             "revoked_at": entry.revocation_date_utc.isoformat()}
            for entry in crl
        ],
        "fingerprints": {
            "sha256": _colon_hex(hashlib.sha256(crl_der).digest()),
            "sha1": _colon_hex(hashlib.sha1(crl_der, usedforsecurity=False).digest()),
        },
        "pem": crl.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    }


def format_serial(serial_hex: str) -> str:
    """"0x7cff…" → "7C:FF:…", the colon form the certificate viewer shows."""
    value = int(serial_hex, 16)
    return _colon_hex(value.to_bytes((value.bit_length() + 7) // 8 or 1, "big"))


def crl_distribution_points(cert_pem: bytes) -> list[str]:
    cert = x509.load_pem_x509_certificate(cert_pem)
    try:
        ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return []
    return [gn.value for dp in ext.value for gn in (dp.full_name or [])
            if isinstance(gn, x509.UniformResourceIdentifier)]


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
    raise UserError("Unknown key type")


ExportFormat = Literal["pem", "der", "crt", "pkcs12"]


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

    if fmt == "crt":
        return cert.public_bytes(serialization.Encoding.DER), "certificate.crt"

    if fmt == "pkcs12":
        ca_certs = None
        if ca_cert_pem:
            ca_certs = [x509.load_pem_x509_certificate(ca_cert_pem)]

        if not password:
            raise UserError("A password is required for PKCS#12 export")
        pfx_password = password.encode("utf-8")
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=None,
            key=key,
            cert=cert,
            cas=ca_certs,
            encryption_algorithm=serialization.BestAvailableEncryption(pfx_password),
        )
        return pfx_data, "certificate.pfx"

    raise UserError(f"Unknown format: {fmt}")


def export_public_only(cert_pem: bytes, fmt: ExportFormat) -> tuple[bytes, str]:
    cert = x509.load_pem_x509_certificate(cert_pem)

    if fmt == "pem":
        return cert_pem, "certificate.pem"
    if fmt == "der":
        return cert.public_bytes(serialization.Encoding.DER), "certificate.der"
    if fmt == "crt":
        return cert.public_bytes(serialization.Encoding.DER), "certificate.crt"

    raise UserError(f"Cannot export public-only as {fmt}")


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

    raise UserError(f"Cannot export private key as {fmt}")


SSHAlgorithm = Literal["rsa-4096", "rsa-2048", "ed25519", "ecdsa-p256", "ecdsa-p384"]

SSH_ALGORITHMS: list[SSHAlgorithm] = ["rsa-4096", "ed25519", "ecdsa-p256", "ecdsa-p384", "rsa-2048"]

SSH_ALGORITHM_LABELS: dict[str, str] = {
    "rsa-4096": "RSA 4096",
    "rsa-2048": "RSA 2048",
    "ed25519": "Ed25519",
    "ecdsa-p256": "ECDSA P-256",
    "ecdsa-p384": "ECDSA P-384",
}

SSHKeyFormat = Literal["openssh", "pem"]


def generate_ssh_key(
    algorithm: SSHAlgorithm,
    passphrase: str | None = None,
    comment: str = "",
) -> tuple[bytes, bytes, str]:
    key = _generate_key(algorithm)

    enc: serialization.KeySerializationEncryption
    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        enc = serialization.NoEncryption()

    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        enc,
    )

    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    )
    if comment:
        public_bytes = public_bytes.rstrip() + b" " + comment.encode("utf-8") + b"\n"

    fingerprint = _ssh_fingerprint(key.public_key())

    return private_bytes, public_bytes, fingerprint


def parse_ssh_key(
    private_key_text: str,
    passphrase: str | None = None,
) -> tuple[bytes, bytes, SSHAlgorithm, str, bool]:
    raw = private_key_text.encode("utf-8") if isinstance(private_key_text, str) else private_key_text

    key = None
    detected_passphrase = False

    loaders: list[tuple[str, Callable[..., object]]] = [
        ("ssh", serialization.load_ssh_private_key),
        ("pem", serialization.load_pem_private_key),
        ("der", serialization.load_der_private_key),
    ]

    for label, loader in loaders:
        if passphrase:
            try:
                key = loader(raw, password=passphrase.encode("utf-8"))
                detected_passphrase = True
                break
            except (TypeError, ValueError, UnsupportedAlgorithm):
                pass
        try:
            key = loader(raw, password=None)
            break
        except (TypeError, ValueError, UnsupportedAlgorithm):
            pass
        try:
            key = loader(raw, password=b"")
            break
        except (TypeError, ValueError, UnsupportedAlgorithm):
            pass

    if key is None:
        if passphrase:
            raise UserError("Cannot parse private key — wrong passphrase or unsupported format")
        raise UserError("Cannot parse private key — unsupported format or passphrase required")

    algorithm = _detect_algorithm(key)

    enc: serialization.KeySerializationEncryption
    if detected_passphrase and passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        enc = serialization.NoEncryption()

    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        enc,
    )

    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    )

    fingerprint = _ssh_fingerprint(key.public_key())

    return private_bytes, public_bytes, algorithm, fingerprint, detected_passphrase


def export_ssh_private_key(
    private_key_pem: bytes,
    fmt: SSHKeyFormat,
    passphrase: str | None = None,
    original_passphrase: str | None = None,
) -> tuple[bytes, str]:
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("utf-8")
    passwords_to_try: list[bytes | None] = [None, b""]
    if original_passphrase:
        passwords_to_try.insert(0, original_passphrase.encode("utf-8"))
    for trial_pass in passwords_to_try:
        try:
            key = serialization.load_ssh_private_key(private_key_pem, password=trial_pass)
            break
        except (TypeError, ValueError):
            continue
    else:
        raise UserError("Cannot load private key — wrong or missing original passphrase")

    enc: serialization.KeySerializationEncryption
    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        enc = serialization.NoEncryption()

    if fmt == "openssh":
        data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            enc,
        )
        return data, "id_key"
    if fmt == "pem":
        data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc,
        )
        return data, "id_key.pem"

    raise UserError(f"Unknown SSH key format: {fmt}")


def _ssh_fingerprint(public_key) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    )
    key_data = raw.split(None, 1)[-1] if b" " in raw else raw
    decoded = base64.b64decode(key_data)
    digest = hashlib.sha256(decoded).digest()
    b64 = base64.b64encode(digest).rstrip(b"=").decode("ascii")
    return f"SHA256:{b64}"


_COLUMN_ENC_PREFIX = b"ENC\x01"


# Each scrypt derivation uses ~128 MB; cap how many run at once.
_KDF_SLOTS = threading.BoundedSemaphore(2)


def _scrypt(password: str, salt: bytes) -> bytes:
    with _KDF_SLOTS:
        kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
        return kdf.derive(password.encode("utf-8"))


def derive_master_key(password: str, salt: bytes) -> bytes:
    return _scrypt(password, salt)


def encrypt_column(data: bytes, key: bytes) -> bytes:
    if data.startswith(_COLUMN_ENC_PREFIX):
        return data
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return _COLUMN_ENC_PREFIX + nonce + ciphertext


def decrypt_column(data: bytes, key: bytes) -> bytes:
    if not data.startswith(_COLUMN_ENC_PREFIX):
        return data
    nonce = data[4:16]
    ciphertext = data[16:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def is_column_encrypted(data: bytes) -> bool:
    return isinstance(data, bytes) and data.startswith(_COLUMN_ENC_PREFIX)


# ── Data key wrapping and the recovery key ─────────────────────────
# The columns are encrypted with a random data key. That key is stored twice,
# wrapped by a key derived from the master password and by one derived from
# the recovery key, so either can unlock the database.

_WRAP_PREFIX = b"DEK\x01"
_WRAP_AAD = b"cert-generator data key"
_RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32
_RECOVERY_GROUPS = 5
_RECOVERY_GROUP_LEN = 5
_RECOVERY_LEN = _RECOVERY_GROUPS * _RECOVERY_GROUP_LEN  # 125 bits
_RECOVERY_ALIASES = str.maketrans({"O": "0", "I": "1", "L": "1"})


def new_data_key() -> bytes:
    return secrets.token_bytes(32)


def wrap_key(data_key: bytes, kek: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return _WRAP_PREFIX + nonce + AESGCM(kek).encrypt(nonce, data_key, _WRAP_AAD)


def unwrap_key(wrapped: bytes, kek: bytes) -> bytes | None:
    """Return the data key, or None when ``kek`` is wrong or the blob is damaged."""
    if not wrapped.startswith(_WRAP_PREFIX):
        return None
    nonce = wrapped[4:16]
    try:
        return AESGCM(kek).decrypt(nonce, wrapped[16:], _WRAP_AAD)
    except InvalidTag:
        return None


def generate_recovery_key() -> str:
    chars = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_LEN))
    return "-".join(chars[i:i + _RECOVERY_GROUP_LEN] for i in range(0, _RECOVERY_LEN, _RECOVERY_GROUP_LEN))


def normalize_recovery_key(text: str) -> str | None:
    """Canonical form of a typed recovery key, or None if it can't be one.

    Case, spaces and dashes are ignored, and the letters Crockford base32
    leaves out for looking like digits (O, I, L) are read as those digits.
    """
    chars = "".join(text.split()).replace("-", "").upper().translate(_RECOVERY_ALIASES)
    if len(chars) != _RECOVERY_LEN or any(c not in _RECOVERY_ALPHABET for c in chars):
        return None
    return chars


def derive_recovery_kek(recovery_key: str, salt: bytes) -> bytes | None:
    """Key-encryption key for a recovery key, or None if it isn't well formed.

    The recovery key is 125 random bits, so a fast KDF is enough; scrypt's
    cost only matters for human-chosen passwords.
    """
    canonical = normalize_recovery_key(recovery_key)
    if canonical is None:
        return None
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"cert-generator recovery key")
    return hkdf.derive(canonical.encode("ascii"))


_BACKUP_MAGIC = b"CERTBAK"
_BACKUP_VERSION = 1


def encrypt_backup(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(32)
    key = _scrypt(password, salt)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return _BACKUP_MAGIC + bytes([_BACKUP_VERSION]) + salt + nonce + ciphertext


def decrypt_backup(data: bytes, password: str) -> bytes:
    if len(data) < 52 or data[:7] != _BACKUP_MAGIC:
        raise UserError("Not a valid backup file")
    if data[7] != _BACKUP_VERSION:
        raise UserError("Unsupported backup version")
    salt = data[8:40]
    nonce = data[40:52]
    ciphertext = data[52:]
    key = _scrypt(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise UserError("Wrong password or corrupted backup")
