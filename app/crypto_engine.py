from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

MS_UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
SMARTCARD_LOGON_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")

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
    "user": {
        "label": "User",
        "description": "Client Authentication, Smart Card Logon",
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
    if upn and tmpl.get("include_upn"):
        san_entries.append(x509.OtherName(MS_UPN_OID, _encode_utf8_string(upn)))

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
            rev_date = datetime.fromisoformat(revoked_at).replace(tzinfo=timezone.utc)
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

        pfx_password = (password or "changeit").encode("utf-8")
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=None,
            key=key,
            cert=cert,
            cas=ca_certs,
            encryption_algorithm=serialization.BestAvailableEncryption(pfx_password),
        )
        return pfx_data, "certificate.pfx"

    raise ValueError(f"Unknown format: {fmt}")


def export_public_only(cert_pem: bytes, fmt: ExportFormat) -> tuple[bytes, str]:
    cert = x509.load_pem_x509_certificate(cert_pem)

    if fmt == "pem":
        return cert_pem, "certificate.pem"
    if fmt == "der":
        return cert.public_bytes(serialization.Encoding.DER), "certificate.der"
    if fmt == "crt":
        return cert.public_bytes(serialization.Encoding.DER), "certificate.crt"

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
        raise ValueError("Cannot load private key — wrong or missing original passphrase")

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

    raise ValueError(f"Unknown SSH key format: {fmt}")


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


def derive_master_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


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


_BACKUP_MAGIC = b"CERTBAK"
_BACKUP_VERSION = 1


def encrypt_backup(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(32)
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    key = kdf.derive(password.encode("utf-8"))
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return _BACKUP_MAGIC + bytes([_BACKUP_VERSION]) + salt + nonce + ciphertext


def decrypt_backup(data: bytes, password: str) -> bytes:
    if len(data) < 52 or data[:7] != _BACKUP_MAGIC:
        raise ValueError("Not a valid backup file")
    if data[7] != _BACKUP_VERSION:
        raise ValueError("Unsupported backup version")
    salt = data[8:40]
    nonce = data[40:52]
    ciphertext = data[52:]
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    key = kdf.derive(password.encode("utf-8"))
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Wrong password or corrupted backup")
