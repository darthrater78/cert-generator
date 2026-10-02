"""Cloudflare API client for the per-CA CRL Worker (server mode only).

Every call goes to api.cloudflare.com over verified HTTPS with the user's API token. The
token is passed in, never logged, and never part of an error message. Each CA gets its own
Worker whose code is fixed (WORKER_JS) and whose CRL is bundled with it as a data module,
so publishing a new CRL is a redeploy and the token needs only Workers Scripts: Edit
(plus Workers Routes / DNS on one zone for a custom domain).
"""
from __future__ import annotations

import json
import re
import secrets
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

API = "https://api.cloudflare.com/client/v4"
TIMEOUT_SECONDS = 20
COMPATIBILITY_DATE = "2025-09-01"

ACCOUNT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SCRIPT_NAME_RE = re.compile(r"^certgen-crl-[a-z0-9-]{1,40}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
CRL_PATH_RE = re.compile(r"^/[a-z0-9-]{1,64}\.crl$")

# The whole Worker. It answers GET and HEAD for its one CRL path and nothing else: no write
# route, no secrets, no cookies, no CORS. The CRL arrives as the bundled data module.
WORKER_JS = """\
import crl from "./crl.bin";

const SECURITY = {
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'; sandbox",
  "referrer-policy": "no-referrer",
};

function text(status, body, extra) {
  return new Response(body, { status, headers: { "content-type": "text/plain", ...SECURITY, ...extra } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== env.CRL_PATH) return text(404, "Not found");
    if (request.method !== "GET" && request.method !== "HEAD") {
      return text(405, "Method not allowed", { allow: "GET, HEAD" });
    }
    return new Response(request.method === "HEAD" ? null : crl, {
      headers: {
        "content-type": "application/pkix-crl",
        "content-length": String(crl.byteLength),
        "cache-control": "public, max-age=300",
        "content-disposition": "attachment; filename=\\"" + env.CRL_PATH.slice(1) + "\\"",
        ...SECURITY,
      },
    });
  },
};
"""


class CloudflareError(RuntimeError):
    """A Cloudflare API call failed; the message is safe to show (it never holds the token)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.user_message = message


@dataclass(frozen=True)
class Credentials:
    token: str
    account_id: str


def _messages(payload: Any) -> str:
    errors = payload.get("errors") if isinstance(payload, dict) else None
    if not isinstance(errors, list):
        return ""
    parts = []
    for item in errors[:3]:
        if isinstance(item, dict):
            code, message = item.get("code"), str(item.get("message", ""))[:200]
            parts.append(f"{message} ({code})" if code else message)
    return "; ".join(p for p in parts if p)


def _request(token: str, method: str, path: str, *, body: bytes | None = None,
             content_type: str = "application/json") -> Any:
    request = urllib.request.Request(API + path, data=body, method=method)  # noqa: S310 - fixed https host
    request.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS,  # nosec B310 - fixed https host
                                    context=ssl.create_default_context()) as response:
            raw = response.read()
    except urllib.error.HTTPError as e:
        try:
            detail = _messages(json.loads(e.read() or b"{}"))
        except (ValueError, OSError):
            detail = ""
        if e.code in (401, 403):
            raise CloudflareError("Cloudflare refused the API token for this action"
                                  + (f": {detail}" if detail else "")) from None
        raise CloudflareError(f"Cloudflare returned HTTP {e.code}" + (f": {detail}" if detail else "")) from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise CloudflareError(f"Couldn't reach Cloudflare: {reason}") from None
    try:
        payload = json.loads(raw or b"{}")
    except ValueError:
        raise CloudflareError("Cloudflare sent an unreadable reply") from None
    if not isinstance(payload, dict) or not payload.get("success", False):
        raise CloudflareError("Cloudflare reported an error: " + (_messages(payload) or "unknown"))
    return payload.get("result")


# ── Account and token ───────────────────────────────────────────────

def check_credentials(creds: Credentials) -> dict[str, Any]:
    """Confirm the token is active and can manage Workers on the account.

    Returns what the app could see: the account's workers.dev subdomain (None if the
    account hasn't chosen one) and how many zones the token can read (only a custom
    domain needs any).
    """
    if not ACCOUNT_ID_RE.match(creds.account_id):
        raise CloudflareError("The account ID is 32 hexadecimal characters (Workers & Pages overview, right side)")
    try:
        status = _request(creds.token, "GET", f"/accounts/{creds.account_id}/tokens/verify")
    except CloudflareError:
        status = _request(creds.token, "GET", "/user/tokens/verify")  # a user-owned token
    if not isinstance(status, dict) or status.get("status") != "active":
        raise CloudflareError("The API token isn't active")
    _request(creds.token, "GET", f"/accounts/{creds.account_id}/workers/scripts")
    return {"workers_subdomain": workers_subdomain(creds), "zones": len(list_zones(creds, quiet=True))}


def workers_subdomain(creds: Credentials) -> str | None:
    try:
        result = _request(creds.token, "GET", f"/accounts/{creds.account_id}/workers/subdomain")
    except CloudflareError:
        return None
    sub = result.get("subdomain") if isinstance(result, dict) else None
    return sub if isinstance(sub, str) and re.fullmatch(r"[a-z0-9-]{1,63}", sub) else None


def list_zones(creds: Credentials, *, quiet: bool = False) -> list[dict[str, str]]:
    """Active zones the token can read, for choosing a custom domain."""
    try:
        result = _request(creds.token, "GET", f"/zones?account.id={creds.account_id}&status=active&per_page=50")
    except CloudflareError:
        if quiet:
            return []
        raise
    zones = []
    for zone in result if isinstance(result, list) else []:
        if isinstance(zone, dict) and isinstance(zone.get("id"), str) and isinstance(zone.get("name"), str):
            zones.append({"id": zone["id"], "name": zone["name"]})
    return zones


# ── Workers ─────────────────────────────────────────────────────────

def new_script_name(ca_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", ca_name.lower()).strip("-")[:24].strip("-") or "ca"
    return f"certgen-crl-{slug}-{secrets.token_hex(3)}"


def crl_path_for(ca_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", ca_name.lower()).strip("-")[:48].strip("-") or "ca"
    return f"/{slug}.crl"


def _multipart(parts: list[tuple[str, str, str, bytes]]) -> tuple[bytes, str]:
    boundary = "certgen" + secrets.token_hex(16)
    out = bytearray()
    for name, filename, content_type, data in parts:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                f"Content-Type: {content_type}\r\n\r\n").encode()
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


def deploy(creds: Credentials, script_name: str, crl_path: str, crl_der: bytes) -> None:
    """Create or replace the CA's Worker with ``crl_der`` bundled in it."""
    if not SCRIPT_NAME_RE.match(script_name) or not CRL_PATH_RE.match(crl_path):
        raise CloudflareError("Invalid Worker name or CRL path")
    metadata = {
        "main_module": "worker.js",
        "compatibility_date": COMPATIBILITY_DATE,
        "bindings": [{"type": "plain_text", "name": "CRL_PATH", "text": crl_path}],
    }
    body, content_type = _multipart([
        ("metadata", "metadata.json", "application/json", json.dumps(metadata).encode()),
        ("worker.js", "worker.js", "application/javascript+module", WORKER_JS.encode()),
        ("crl.bin", "crl.bin", "application/octet-stream", crl_der),
    ])
    _request(creds.token, "PUT", f"/accounts/{creds.account_id}/workers/scripts/{script_name}",
             body=body, content_type=content_type)


def set_workers_dev(creds: Credentials, script_name: str, enabled: bool) -> None:
    """Turn the Worker's *.workers.dev address on or off (off when a custom domain serves it)."""
    _request(creds.token, "POST", f"/accounts/{creds.account_id}/workers/scripts/{script_name}/subdomain",
             body=json.dumps({"enabled": enabled, "previews_enabled": False}).encode())


def attach_domain(creds: Credentials, script_name: str, hostname: str, zone_id: str) -> str:
    """Serve the Worker on ``hostname`` (Cloudflare creates the DNS record); returns the domain id."""
    if not HOSTNAME_RE.match(hostname):
        raise CloudflareError("Invalid hostname")
    result = _request(creds.token, "PUT", f"/accounts/{creds.account_id}/workers/domains", body=json.dumps({
        "environment": "production", "hostname": hostname, "service": script_name, "zone_id": zone_id,
    }).encode())
    domain_id = result.get("id") if isinstance(result, dict) else None
    if not isinstance(domain_id, str):
        raise CloudflareError("Cloudflare didn't return the custom domain")
    return domain_id


DOMAIN_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def detach_domain(creds: Credentials, domain_id: str) -> None:
    if not DOMAIN_ID_RE.match(domain_id):
        raise CloudflareError("Invalid custom domain id")
    try:
        _request(creds.token, "DELETE", f"/accounts/{creds.account_id}/workers/domains/{domain_id}")
    except CloudflareError as e:
        if "HTTP 404" not in str(e):  # already gone is fine
            raise


def list_app_workers(creds: Credentials) -> list[dict[str, Any]]:
    """Workers in the account that this app created (named certgen-crl-…), with the custom
    domains that serve each one."""
    result = _request(creds.token, "GET", f"/accounts/{creds.account_id}/workers/scripts")
    workers = {}
    for script in result if isinstance(result, list) else []:
        name = script.get("id") if isinstance(script, dict) else None
        if isinstance(name, str) and SCRIPT_NAME_RE.match(name):
            workers[name] = {"name": name, "modified_on": str(script.get("modified_on") or ""), "domains": []}
    try:
        domains = _request(creds.token, "GET", f"/accounts/{creds.account_id}/workers/domains")
    except CloudflareError:
        domains = []  # a token without zone access can't list them; nothing is attached then either
    for domain in domains if isinstance(domains, list) else []:
        if isinstance(domain, dict) and domain.get("service") in workers and isinstance(domain.get("id"), str):
            workers[domain["service"]]["domains"].append({"id": domain["id"], "hostname": str(domain.get("hostname", ""))})
    return sorted(workers.values(), key=lambda w: w["name"])


def delete_worker(creds: Credentials, script_name: str) -> None:
    if not SCRIPT_NAME_RE.match(script_name):
        raise CloudflareError("Invalid Worker name")
    try:
        _request(creds.token, "DELETE", f"/accounts/{creds.account_id}/workers/scripts/{script_name}?force=true")
    except CloudflareError as e:
        if "HTTP 404" not in str(e):  # already gone is fine
            raise


# ── Cert Generator Pal relay Worker (docs/cert-generator-pal.md §8) ──

RELAY_SCRIPT_RE = re.compile(r"^certgen-relay-[a-z0-9]{8,16}$")
RELAY_MIGRATION_TAG = "v1"


def new_relay_script_name() -> str:
    return "certgen-relay-" + secrets.token_hex(5)


def _migration_tag(creds: Credentials, script_name: str) -> str | None:
    """The Durable Object migration already applied to the script, or None (new script)."""
    result = _request(creds.token, "GET", f"/accounts/{creds.account_id}/workers/scripts")
    for script in result if isinstance(result, list) else []:
        if isinstance(script, dict) and script.get("id") == script_name:
            tag = script.get("migration_tag")
            return tag if isinstance(tag, str) else None
    return None


def deploy_relay(creds: Credentials, script_name: str, server_token: str) -> None:
    """Create or update the relay Worker: fixed code (app/relay_worker.py), one Durable Object
    mailbox, and the server's token as a Worker secret. The mailbox's migration is sent only
    the first time (Cloudflare refuses one that is already applied)."""
    from .relay_worker import RELAY_WORKER_JS

    if not RELAY_SCRIPT_RE.match(script_name) or len(server_token) < 32:
        raise CloudflareError("Invalid relay Worker name or token")
    metadata: dict[str, Any] = {
        "main_module": "worker.js",
        "compatibility_date": COMPATIBILITY_DATE,
        "bindings": [
            {"type": "durable_object_namespace", "name": "MAILBOX", "class_name": "Mailbox"},
            {"type": "secret_text", "name": "SERVER_TOKEN", "text": server_token},
        ],
    }
    if _migration_tag(creds, script_name) != RELAY_MIGRATION_TAG:
        metadata["migrations"] = {"new_tag": RELAY_MIGRATION_TAG, "new_sqlite_classes": ["Mailbox"]}
    body, content_type = _multipart([
        ("metadata", "metadata.json", "application/json", json.dumps(metadata).encode()),
        ("worker.js", "worker.js", "application/javascript+module", RELAY_WORKER_JS.encode()),
    ])
    _request(creds.token, "PUT", f"/accounts/{creds.account_id}/workers/scripts/{script_name}",
             body=body, content_type=content_type)


def delete_relay(creds: Credentials, script_name: str) -> None:
    if not RELAY_SCRIPT_RE.match(script_name):
        raise CloudflareError("Invalid relay Worker name")
    _request(creds.token, "DELETE", f"/accounts/{creds.account_id}/workers/scripts/{script_name}?force=true")
