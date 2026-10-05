"""Cert Generator Pal: pairing codes, request signatures and device policies.

The wire format is specified in docs/cert-generator-pal.md; the Windows app in pal/
implements the other side, and tests/test_pal_api.py pins both to the same bytes.
Nothing here touches Flask or the database.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .errors import UserError

PAIRING_PREFIX = "CGP1."
ENROLL_PROOF_LABEL = "CGP1-ENROLL"
ENROLLED_MAC_LABEL = "CGP1-ENROLLED"
REQUEST_LABEL = "CGP1-REQ"

# How far a request's timestamp may be from the server clock, and how long its nonce is kept.
CLOCK_SKEW_SECONDS = 300
NONCE_TTL_SECONDS = 2 * CLOCK_SKEW_SECONDS

# Use case -> certificate template. Email (S/MIME) is left out on purpose: a key that can't
# leave the PC would make old encrypted mail unreadable when the PC dies.
USE_CASES = {
    "web-server": "web-server",
    "computer": "computer",
    "user": "user",
    "code-signing": "code-signing",
}
USE_CASE_LABELS = {"web-server": "web server", "computer": "computer", "user": "user", "code-signing": "code-signing"}
TEMPLATE_USE_CASES = {template: case for case, template in USE_CASES.items()}
MACHINE_USE_CASES = ("web-server", "computer")
APPROVAL_MODES = ("off", "auto", "approve")
DEFAULT_APPROVALS = {"web-server": "auto", "computer": "auto", "user": "approve", "code-signing": "off"}

MAX_PATTERNS = 32
MAX_PATTERN_LEN = 253
MAX_NAMES = 20
MAX_CN_LEN = 64
MAX_SERIALS = 500

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EMAIL_RE = re.compile(r"^[a-z0-9._%+'-]{1,64}@[a-z0-9.-]{1,253}$")
_CN_RE = re.compile(r"^[\w .,'()&-]{1,64}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")


class PalError(UserError):
    """A request the Pal API refuses, with a message safe to show the caller."""


# ── Encoding helpers ────────────────────────────────────────────────

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not _B64URL_RE.match(text):
        raise PalError("Malformed base64url value")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Pairing codes ───────────────────────────────────────────────────

def new_code_id() -> str:
    return secrets.token_hex(16)


# Where the PC says a key it made lives: the TPM, or Windows' software key store. Self-reported.
KEY_STORAGES = ("tpm", "software")


def key_storage(value: Any) -> str | None:
    """A key storage the Pal reported, or None when it is missing or not one we know."""
    return value if value in KEY_STORAGES else None


def new_device_id() -> str:
    return secrets.token_hex(16)


def new_code_key() -> bytes:
    return secrets.token_bytes(32)


def pairing_code(server_url: str, code_id: str, key: bytes, root_sha256: str) -> str:
    """The one string the admin copies to the PC. ``key`` never travels on its own: the PC
    proves it holds it with an HMAC, and the server answers the same way."""
    payload = {"v": 1, "u": server_url, "i": code_id, "k": b64url(key), "r": root_sha256}
    return PAIRING_PREFIX + b64url(json.dumps(payload, separators=(",", ":")).encode())


def parse_pairing_code(code: str) -> dict[str, Any]:
    """The pairing code's fields (for tests and support tooling; the server never receives it)."""
    if not code.startswith(PAIRING_PREFIX):
        raise PalError("Not a Cert Generator Pal pairing code")
    payload = json.loads(b64url_decode(code[len(PAIRING_PREFIX):]))
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise PalError("Unsupported pairing code version")
    return payload


def _mac(key: bytes, label: str, body: bytes) -> bytes:
    return hmac.new(key, f"{label}\n{sha256_hex(body)}".encode(), hashlib.sha256).digest()


def enroll_proof(key: bytes, body: bytes) -> str:
    return b64url(_mac(key, ENROLL_PROOF_LABEL, body))


def enrolled_mac(key: bytes, body: bytes) -> str:
    return b64url(_mac(key, ENROLLED_MAC_LABEL, body))


def verify_enroll_proof(key: bytes, body: bytes, proof: str) -> bool:
    try:
        given = b64url_decode(proof)
    except PalError:
        return False
    return hmac.compare_digest(given, _mac(key, ENROLL_PROOF_LABEL, body))


# ── Device keys and request signatures ──────────────────────────────

def load_device_key(spki_b64: str) -> bytes:
    """Validate a device public key (base64 SPKI DER, ECDSA P-256) and return its DER."""
    try:
        der = base64.b64decode(spki_b64, validate=True)
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        raise PalError("The device key could not be read") from e
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise PalError("The device key must be ECDSA P-256")
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def request_signing_string(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    return f"{REQUEST_LABEL}\n{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{sha256_hex(body)}".encode()


def verify_device_signature(public_key_der: bytes, message: bytes, signature_b64url: str) -> bool:
    """DER (RFC 3279) ECDSA-SHA256 signature by the device key."""
    try:
        signature = b64url_decode(signature_b64url)
        key = serialization.load_der_public_key(public_key_der)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            return False
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except (PalError, InvalidSignature, ValueError):
        return False
    return True


def valid_nonce(nonce: str) -> bool:
    return isinstance(nonce, str) and 16 <= len(nonce) <= 64 and bool(_B64URL_RE.match(nonce))


# ── Name patterns and policies ──────────────────────────────────────

def _is_dns_name(name: str) -> bool:
    labels = name.split(".")
    return 1 <= len(name) <= 253 and len(labels) >= 1 and all(_LABEL_RE.match(label) for label in labels)


def _parse_dns_pattern(raw: Any) -> str:
    if not isinstance(raw, str):
        raise PalError("Each allowed DNS name must be a string")
    pattern = raw.strip().lower().rstrip(".")
    if not pattern or len(pattern) > MAX_PATTERN_LEN:
        raise PalError("Allowed DNS names must be 1-253 characters")
    try:
        ipaddress.ip_network(pattern, strict=False)
        return pattern
    except ValueError:
        pass
    host = pattern[2:] if pattern.startswith("*.") else pattern
    if not _is_dns_name(host):
        raise PalError(f"Not a DNS name, *.domain, IP address or network: {raw!r}")
    return pattern


def _parse_user_pattern(raw: Any) -> str:
    if not isinstance(raw, str):
        raise PalError("Each allowed user name must be a string")
    pattern = raw.strip().lower()
    if pattern.startswith("*@") and _is_dns_name(pattern[2:]):
        return pattern
    if _EMAIL_RE.match(pattern):
        return pattern
    raise PalError(f"Allowed user names are user@domain or *@domain: {raw!r}")


def _is_requestable_name(name: str) -> bool:
    """A DNS name or an IP address. Never a wildcard: a PC allowed ``*.lan`` must not get a
    certificate that impersonates every host on the LAN (an admin can issue one in the UI)."""
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        pass
    return _is_dns_name(name)


def dns_name_allowed(name: str, patterns: list[str]) -> bool:
    """``*.lan`` covers any name under ``lan`` (any depth, not ``lan`` itself); an IP must
    equal an allowed address or sit in an allowed network. Wildcard names are never allowed."""
    name = name.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        address = None
    if "*" in name:
        return False
    for pattern in patterns:
        if address is not None:
            try:
                if address in ipaddress.ip_network(pattern, strict=False):
                    return True
            except ValueError:
                continue
        elif name == pattern:
            return True
        elif pattern.startswith("*.") and "*" not in name and name.endswith(pattern[1:]):
            return True
    return False


def user_name_allowed(name: str, patterns: list[str]) -> bool:
    name = name.lower()
    return any(name == p or (p.startswith("*@") and name.endswith(p[1:])) for p in patterns)


@dataclass
class Policy:
    use_cases: dict[str, str]
    dns: list[str]
    users: list[str]
    max_days: int
    crl_dps: list[str]          # revocation types the PC may choose from: one profile each in the Pal
    crl_base_url: str | None
    allow_remote: bool = False  # may use the remote relay once paired (docs/cert-generator-pal.md §8)

    @property
    def crl_dp(self) -> str:
        """The default revocation type: the first allowed."""
        return self.crl_dps[0] if self.crl_dps else "none"

    def to_json(self) -> str:
        return json.dumps(self.__dict__, separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> Policy:
        data = json.loads(text)
        if "crl_dp" in data:  # one revocation type, before a code could allow several
            data["crl_dps"] = [data.pop("crl_dp")]
        return cls(**data)

    def public(self) -> dict[str, Any]:
        """What the PC is told: which tiles to offer, which names will be accepted, which revocation types."""
        return {"use_cases": self.use_cases, "dns": self.dns, "users": self.users, "max_days": self.max_days,
                "crl_dps": self.crl_dps, "allow_remote": self.allow_remote}


def parse_policy(data: dict[str, Any], max_lifetime: int) -> Policy:
    """The policy part of an admin's Add-a-PC form. CRL settings are checked by the caller."""
    raw_cases = data.get("use_cases", DEFAULT_APPROVALS)
    if not isinstance(raw_cases, dict):
        raise PalError("use_cases must be an object")
    use_cases = {}
    for case in USE_CASES:
        mode = raw_cases.get(case, "off")
        if mode not in APPROVAL_MODES:
            raise PalError(f"Use case {case}: choose one of {', '.join(APPROVAL_MODES)}")
        use_cases[case] = mode
    if all(mode == "off" for mode in use_cases.values()):
        raise PalError("Turn on at least one use case")
    dns_raw = data.get("dns", [])
    users_raw = data.get("users", [])
    if not isinstance(dns_raw, list) or not isinstance(users_raw, list):
        raise PalError("Allowed names must be lists")
    if len(dns_raw) > MAX_PATTERNS or len(users_raw) > MAX_PATTERNS:
        raise PalError(f"At most {MAX_PATTERNS} allowed names of each kind")
    dns = [_parse_dns_pattern(p) for p in dns_raw]
    users = [_parse_user_pattern(p) for p in users_raw]
    if any(use_cases[c] != "off" for c in MACHINE_USE_CASES) and not dns:
        raise PalError("Web server and computer certificates need at least one allowed DNS name")
    if use_cases["user"] != "off" and not users:
        raise PalError("User certificates need at least one allowed user name")
    max_days = data.get("max_days", 365)
    if isinstance(max_days, bool) or not isinstance(max_days, int) or not 1 <= max_days <= max_lifetime:
        raise PalError(f"Maximum lifetime must be between 1 and {max_lifetime} days")
    allow_remote = data.get("allow_remote", False)
    if not isinstance(allow_remote, bool):
        raise PalError("allow_remote must be true or false")
    return Policy(use_cases=use_cases, dns=dns, users=users, max_days=max_days, crl_dps=["none"], crl_base_url=None,
                  allow_remote=allow_remote)


@dataclass
class Names:
    common_name: str
    san: list[str]
    upn: str | None = None
    email: str | None = None

    def to_json(self) -> str:
        return json.dumps(self.__dict__, separators=(",", ":"))


def parse_fqdn(raw: Any, policy: Policy) -> str:
    """The PC's FQDN as reported at pairing. Like a Windows CA's Computer template, which
    builds the subject from the directory, "This computer" certificates are issued to this
    name only, so it must already fit the policy when machine certificates are allowed."""
    fqdn = raw.strip().lower().rstrip(".") if isinstance(raw, str) else ""
    if not fqdn or not _is_dns_name(fqdn):
        raise PalError("No DNS suffix. This PC's name has no domain (like pc01.lan), so a CA can't name it. "
                       "Set the PC's primary DNS suffix and try again")
    if any(policy.use_cases[c] != "off" for c in MACHINE_USE_CASES) and not dns_name_allowed(fqdn, policy.dns):
        suffix = fqdn.split(".", 1)[1] if "." in fqdn else fqdn
        raise PalError(f"Wrong domain. This PC is {fqdn}, but this pairing code only allows {', '.join(policy.dns)}. "
                       f"Ask your admin for a new code that allows *.{suffix}")
    return fqdn


def parse_names(use_case: str, data: Any, policy: Policy, device_fqdn: str) -> Names:
    """The names for a request, checked against the policy. "This computer" ignores what the
    PC sends and uses the FQDN recorded at pairing; "Web server" starts from it and may add
    names the policy allows."""
    if use_case == "computer":
        return Names(common_name=device_fqdn, san=[device_fqdn])
    if not isinstance(data, dict):
        raise PalError("names must be an object")
    if use_case in MACHINE_USE_CASES:
        dns = data.get("dns")
        if not isinstance(dns, list) or not 1 <= len(dns) <= MAX_NAMES or not all(isinstance(n, str) for n in dns):
            raise PalError(f"names.dns must list 1-{MAX_NAMES} names")
        cleaned = [n.strip().lower().rstrip(".") for n in dns]
        for name in cleaned:
            if not _is_requestable_name(name):
                raise PalError(f"Not a valid name. {name!r} isn't a DNS name or IP address")
            if not dns_name_allowed(name, policy.dns):
                raise PalError(f"Wrong domain. {name} isn't allowed for this PC (allowed: {', '.join(policy.dns)})")
        unique = list(dict.fromkeys(cleaned))
        return Names(common_name=unique[0], san=unique)
    if use_case == "user":
        upn = data.get("upn")
        email = data.get("email") or None
        if not isinstance(upn, str) or not _EMAIL_RE.match(upn.strip().lower()):
            raise PalError("names.upn must be user@domain")
        upn = upn.strip().lower()
        if not user_name_allowed(upn, policy.users):
            raise PalError(f"Name not allowed. {upn} isn't allowed for this PC (allowed: {', '.join(policy.users)})")
        if email is not None:
            if not isinstance(email, str) or not _EMAIL_RE.match(email.strip().lower()):
                raise PalError("names.email must be an e-mail address")
            email = email.strip().lower()
            if not user_name_allowed(email, policy.users):
                raise PalError(f"Name not allowed. {email} isn't allowed for this PC (allowed: {', '.join(policy.users)})")
        return Names(common_name=upn, san=[], upn=upn, email=email or upn)
    if use_case == "code-signing":
        cn = data.get("cn")
        if not isinstance(cn, str) or not _CN_RE.match(cn.strip()):
            raise PalError(f"names.cn must be 1-{MAX_CN_LEN} letters, digits, spaces or .,'()&-")
        return Names(common_name=cn.strip(), san=[])
    raise PalError("Unknown use case")


RENEW_WINDOW_DAYS = 30


def renew_opens(not_before: datetime, not_after: datetime) -> datetime:
    """When a certificate may be renewed: its last 30 days, or its last third if it lives
    less than 90 days. Earlier renewals are refused, so a PC can't stockpile certificates."""
    window = min(timedelta(days=RENEW_WINDOW_DAYS), (not_after - not_before) / 3)
    return not_after - window


def normalize_serial(raw: Any) -> str | None:
    """A serial as the database stores it (``hex(n)``: '0x' + lowercase, no leading zeros),
    from hex with or without '0x', colons or spaces. None if it isn't one."""
    if not isinstance(raw, str):
        return None
    text = raw.strip().lower().replace(":", "").replace(" ", "")
    if text.startswith("0x"):
        text = text[2:]
    if not text or len(text) > 64 or not _HEX_RE.match(text):
        return None
    return hex(int(text, 16))


def is_private_address(address: str | None) -> bool:
    """LAN-only API: loopback, RFC 1918, CGNAT / shared address space (100.64.0.0/10, used by
    SSE and ZTNA overlays such as Tailscale or Zscaler), link-local, IPv6 ULA (and IPv4-mapped
    forms of them)."""
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local:
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in _PRIVATE_V4)
    return ip in _ULA_V6


_PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))
_ULA_V6 = ipaddress.ip_network("fc00::/7")
