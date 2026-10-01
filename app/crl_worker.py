"""Each CA's Cloudflare CRL Worker: deploy, push, test, tear down (server mode only).

The app signs the CRL (crl_publisher) and pushes it here by redeploying the CA's Worker
with the CRL bundled in. Pushes run on issue, revoke and the hourly renewal; a failed push
is recorded on the CA (cf_push_error) and retried by the next renewal pass.
"""
from __future__ import annotations

import hashlib
import logging
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from cryptography import x509

from . import cloudflare, crl_publisher, db, state
from .cloudflare import CloudflareError, Credentials

log = logging.getLogger("cert-generator")

FETCH_TIMEOUT_SECONDS = 10
MAX_CRL_BYTES = 10 * 1024 * 1024


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def credentials() -> Credentials:
    if state.desktop_mode():
        raise CloudflareError("Cloudflare publishing needs the Docker version")
    stored = db.get_cloudflare_credentials()  # DatabaseLocked while locked
    if stored is None:
        raise CloudflareError("Connect Cloudflare first (Tools › Cloudflare)")
    return Credentials(token=stored[1], account_id=stored[0])


def _worker_credentials(worker: dict[str, Any]) -> Credentials:
    creds = credentials()
    if worker.get("cf_account_id") != creds.account_id:
        # A restored backup from another install, or a different account connected since.
        raise CloudflareError("This CA's Worker belongs to a different Cloudflare account than the one connected")
    return creds


# ── Deploy and tear down ────────────────────────────────────────────

def deploy(ca_id: int, hostname: str | None = None, zone_id: str | None = None) -> dict[str, Any]:
    """Create the CA's Worker, push its CRL and pick the address for certificates."""
    ca = db.get_ca_summary(ca_id)
    if ca is None:
        raise ValueError("CA not found")
    if db.get_ca_worker(ca_id):
        raise ValueError("This CA already has a Worker")
    creds = credentials()
    db.require_unlocked()  # signing needs the CA key
    if hostname:
        hostname = hostname.strip().lower().rstrip(".")
        if not cloudflare.HOSTNAME_RE.match(hostname) or not zone_id:
            raise ValueError("Choose a hostname in one of your Cloudflare zones")
    else:
        subdomain = cloudflare.workers_subdomain(creds)
        if subdomain is None:
            raise CloudflareError("This Cloudflare account has no workers.dev subdomain yet. Pick one under "
                                  "Workers & Pages in the Cloudflare dashboard, or use a custom domain")

    script = cloudflare.new_script_name(ca["name"])
    path = cloudflare.crl_path_for(ca["name"])
    db.update_ca_worker(ca_id, cf_worker=script, cf_account_id=creds.account_id, cf_crl_path=path)
    try:
        crl_publisher.sign(ca_id)
        crl_der = db.get_signed_crl(ca_id)
        cloudflare.deploy(creds, script, path, crl_der)
        if hostname:
            domain_id = cloudflare.attach_domain(creds, script, hostname, zone_id)
            db.update_ca_worker(ca_id, cf_domain_id=domain_id)
            cloudflare.set_workers_dev(creds, script, False)  # served on the custom domain only
        else:
            cloudflare.set_workers_dev(creds, script, True)
            hostname = f"{script}.{subdomain}.workers.dev"
    except Exception:
        _undo_deploy(creds, ca_id, script)
        raise
    db.update_ca_worker(ca_id, cf_hostname=hostname, cf_dp_url=f"http://{hostname}{path}",
                        cf_pushed_sha256=hashlib.sha256(crl_der).hexdigest(), cf_pushed_at=_now(),
                        cf_push_error=None)
    log.info("Cloudflare CRL Worker %s deployed for CA %d on %s", script, ca_id, hostname)
    return status(ca_id)


def _undo_deploy(creds: Credentials, ca_id: int, script: str) -> None:
    worker = db.get_ca_worker(ca_id) or {}
    try:
        if worker.get("cf_domain_id"):
            cloudflare.detach_domain(creds, worker["cf_domain_id"])
        cloudflare.delete_worker(creds, script)
    except CloudflareError:
        log.warning("Couldn't remove the half-created Worker %s; delete it in the Cloudflare dashboard", script)
    db.clear_ca_worker(ca_id)


def teardown(ca_id: int) -> dict[str, Any]:
    """Delete the CA's Worker (and custom domain). Returns the certificates that named it."""
    worker = db.get_ca_worker(ca_id)
    if worker is None:
        raise ValueError("This CA has no Worker")
    affected = db.certs_with_crl_dp(ca_id, worker["cf_dp_url"]) if worker["cf_dp_url"] else []
    creds = _worker_credentials(worker)
    if worker.get("cf_domain_id"):
        cloudflare.detach_domain(creds, worker["cf_domain_id"])
    cloudflare.delete_worker(creds, worker["cf_worker"])
    db.clear_ca_worker(ca_id)
    log.warning("Cloudflare CRL Worker %s removed for CA %d (%d certificates named it)",
                worker["cf_worker"], ca_id, len(affected))
    return {"affected": len(affected)}


def inventory() -> dict[str, Any]:
    """Every Worker this app created in the connected account, matched to the CAs here.

    ``unlinked``: in Cloudflare but no CA here uses it (a deleted CA, a failed setup, a
    restore, or another install of the app). ``missing``: a CA here names a Worker that
    isn't in Cloudflare any more.
    """
    creds = credentials()
    remote = {w["name"]: w for w in cloudflare.list_app_workers(creds)}
    local = {w["cf_worker"]: w for w in db.list_ca_workers() if w["cf_account_id"] == creds.account_id}
    workers = []
    for name in sorted(set(remote) | set(local)):
        ca = local.get(name)
        found = remote.get(name)
        workers.append({
            "name": name,
            "ca_id": ca["id"] if ca else None,
            "ca_name": ca["name"] if ca else None,
            "hostnames": [d["hostname"] for d in found["domains"]] if found else [],
            "address": ca["cf_dp_url"] if ca else None,
            "modified_on": found["modified_on"] if found else None,
            "state": "missing" if not found else "linked" if ca else "unlinked",
        })
    return {"workers": workers}


def delete_by_name(name: str) -> dict[str, Any]:
    """Remove a Worker this app created: a CA's own goes through teardown(), so the CA
    forgets it; an unlinked one is deleted with its custom domains."""
    if not cloudflare.SCRIPT_NAME_RE.match(name):
        raise ValueError("Not a Worker this app created")
    creds = credentials()
    linked = next((w for w in db.list_ca_workers()
                   if w["cf_worker"] == name and w["cf_account_id"] == creds.account_id), None)
    if linked:
        return {"ca_id": linked["id"], **teardown(linked["id"])}
    found = next((w for w in cloudflare.list_app_workers(creds) if w["name"] == name), None)
    if found is None:
        raise ValueError("No such Worker in the connected account")
    for domain in found["domains"]:
        cloudflare.detach_domain(creds, domain["id"])
    cloudflare.delete_worker(creds, name)
    log.warning("Unlinked Cloudflare Worker %s deleted", name)
    return {"ca_id": None, "affected": 0}


def refresh(ca_id: int) -> dict[str, Any]:
    """status() plus whether the Worker still exists in Cloudflare."""
    result = status(ca_id)
    if result.get("deployed") and result.get("account_matches"):
        names = {w["name"] for w in cloudflare.list_app_workers(credentials())}
        result["exists"] = result["worker"] in names
    return result


# ── Push ────────────────────────────────────────────────────────────

def push(ca_id: int) -> bool:
    """Send the CA's current signed CRL to its Worker. Records the outcome on the CA;
    True on success. Does nothing (True) for a CA without a Worker."""
    worker = db.get_ca_worker(ca_id)
    if worker is None:
        return True
    try:
        creds = _worker_credentials(worker)
        crl_der = db.get_signed_crl(ca_id)
        if crl_der is None:
            raise CloudflareError("No signed CRL to publish yet")
        cloudflare.deploy(creds, worker["cf_worker"], worker["cf_crl_path"], crl_der)
    except (CloudflareError, db.DatabaseLocked) as e:
        db.update_ca_worker(ca_id, cf_push_error=f"{_now()}: {e}"[:500])
        log.error("CRL push to Cloudflare failed for CA %d: %s", ca_id, e)
        return False
    db.update_ca_worker(ca_id, cf_pushed_sha256=hashlib.sha256(crl_der).hexdigest(), cf_pushed_at=_now(),
                        cf_push_error=None)
    log.info("CRL pushed to Cloudflare for CA %d", ca_id)
    return True


# ── Status, test, live fetch ────────────────────────────────────────

def status(ca_id: int) -> dict[str, Any]:
    worker = db.get_ca_worker(ca_id)
    if worker is None:
        return {"deployed": False}
    affected = db.certs_with_crl_dp(ca_id, worker["cf_dp_url"]) if worker["cf_dp_url"] else []
    return {
        "deployed": True,
        "worker": worker["cf_worker"],
        "hostname": worker["cf_hostname"],
        "custom_domain": bool(worker["cf_domain_id"]),
        "crl_path": worker["cf_crl_path"],
        "dp_url": worker["cf_dp_url"],
        "pushed_at": worker["cf_pushed_at"],
        "push_error": worker["cf_push_error"],
        "certificates": len(affected),
        "account_matches": worker.get("cf_account_id") == db.cloudflare_account_id(),
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - report, don't follow
        return None


def _fetch(url: str) -> dict[str, Any]:
    """One GET without following redirects: status, redirect target, body (capped)."""
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"User-Agent": "cert-generator-crl-test"})  # noqa: S310
    try:
        with opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # nosec B310 - our Worker's URL
            return {"status": response.status, "body": response.read(MAX_CRL_BYTES + 1),
                    "content_type": response.headers.get("Content-Type", "")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "location": e.headers.get("Location")}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"status": None, "error": str(getattr(e, "reason", e))[:200]}


def _check_crl(body: bytes, ca_cert_pem: bytes, pushed_sha256: str | None) -> list[str]:
    """Problems with a fetched CRL; empty when it is the one pushed, signed by the CA and current."""
    if len(body) > MAX_CRL_BYTES:
        return ["the response is too large to be this CA's CRL"]
    try:
        crl = x509.load_der_x509_crl(body)
    except ValueError:
        return ["the response isn't a DER CRL"]
    problems = []
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    if crl.issuer != ca_cert.subject or not crl.is_signature_valid(ca_cert.public_key()):
        problems.append("it isn't signed by this CA")
    if crl.next_update_utc is None or crl.next_update_utc <= datetime.now(timezone.utc):
        problems.append("it has expired")
    if pushed_sha256 and hashlib.sha256(body).hexdigest() != pushed_sha256:
        problems.append("it isn't the latest CRL the app pushed (Cloudflare may still be updating; retry in a minute)")
    return problems


def _host_and_path(worker: dict[str, Any]) -> tuple[str, str]:
    host, path = worker.get("cf_hostname") or "", worker.get("cf_crl_path") or ""
    # Both were written by deploy(); check them again before the server fetches anything.
    if not cloudflare.HOSTNAME_RE.match(host) or not cloudflare.CRL_PATH_RE.match(path):
        raise ValueError("The Worker's stored address is invalid")
    return host, path


def test(ca_id: int) -> dict[str, Any]:
    """Fetch the CRL over HTTP and HTTPS from this server, check it, and recommend the
    address certificates should carry (plain HTTP with no redirect is the safest for
    Windows, which fetches CRLs without trusting anything new)."""
    worker = db.get_ca_worker(ca_id)
    ca = db.get_ca_summary(ca_id)
    if worker is None or ca is None:
        raise ValueError("This CA has no Worker")
    host, path = _host_and_path(worker)
    ca_cert_pem = db.get_ca_cert_chain(ca_id, max_depth=1)[0]
    results = {}
    for scheme in ("http", "https"):
        url = f"{scheme}://{host}{path}"
        got = _fetch(url)
        entry: dict[str, Any] = {"url": url, "status": got.get("status")}
        if got.get("error"):
            entry["problems"] = [f"no answer: {got['error']}"]
        elif got.get("location"):
            entry["problems"] = [f"redirects to {got['location'][:200]}"]
        elif got.get("status") != 200:
            entry["problems"] = [f"HTTP {got.get('status')}"]
        else:
            entry["problems"] = _check_crl(got["body"], ca_cert_pem, worker["cf_pushed_sha256"])
        entry["ok"] = not entry["problems"]
        results[scheme] = entry

    if results["http"]["ok"]:
        recommended, note = results["http"]["url"], "Plain HTTP works with no redirect: the best choice for CRLs."
    elif results["https"]["ok"]:
        recommended = results["https"]["url"]
        note = ("Only HTTPS works" + (" (HTTP redirects to it)" if any("redirects" in p for p in results["http"]["problems"]) else "")
                + ". Clients accept an HTTPS distribution point; for plain HTTP on a custom domain, turn off "
                  "Always Use HTTPS for that hostname in Cloudflare and test again.")
    else:
        recommended, note = None, ("The Worker didn't serve a valid CRL yet. A new Worker can take a minute to "
                                   "appear; test again shortly.")
    if recommended and recommended != worker["cf_dp_url"] and not db.certs_with_crl_dp(ca_id, worker["cf_dp_url"] or ""):
        db.update_ca_worker(ca_id, cf_dp_url=recommended)  # nothing issued with the old address yet
    elif recommended and recommended != worker["cf_dp_url"]:
        note += (" Certificates already issued name " + str(worker["cf_dp_url"]) + "; new ones keep that address "
                 "so they all behave the same.")
    return {"results": results, "recommended": recommended, "note": note, "dp_url": db.get_ca_worker(ca_id)["cf_dp_url"]}


def fetch_live(ca_id: int) -> tuple[bytes, str]:
    """The CRL the Worker serves right now, for the viewer: (DER, the URL it came from)."""
    worker = db.get_ca_worker(ca_id)
    if worker is None:
        raise ValueError("This CA has no Worker")
    host, path = _host_and_path(worker)
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}{path}"
        got = _fetch(url)
        if got.get("status") == 200 and len(got["body"]) <= MAX_CRL_BYTES:
            return got["body"], url
    raise CloudflareError("The Worker didn't answer with a CRL")
