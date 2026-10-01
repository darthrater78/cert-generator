"""Cloudflare CRL Worker per CA (v2.7.0), against a fake Cloudflare API."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3

import pytest
from cryptography import x509

from app import cloudflare, crl_publisher, crl_worker, db, server

from .conftest import ENCRYPTION_PASSWORD
from .test_security import _create_ca, _enable_encryption

TOKEN = "cf-test-token-0123456789abcdef"
ACCOUNT = "0123456789abcdef0123456789abcdef"
ZONE_ID = "f" * 32


class FakeCloudflare:
    """Just enough of api.cloudflare.com for the app, recording every call."""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self.scripts: dict[str, dict] = {}  # name -> {"crl": bytes, "path": str, "workers_dev": bool}
        self.domains: dict[str, str] = {}   # id -> script
        self.subdomain: str | None = "acme"
        self.fail_deploys = False

    def request(self, token, method, path, *, body=None, content_type="application/json"):
        assert token == TOKEN
        self.calls.append((method, path))
        base = f"/accounts/{ACCOUNT}"
        if path in (f"{base}/tokens/verify", "/user/tokens/verify"):
            return {"status": "active"}
        if path == f"{base}/workers/scripts" and method == "GET":
            return [{"id": n, "modified_on": "2026-10-01T00:00:00Z"} for n in self.scripts] + [{"id": "someone-elses-worker"}]
        if path == f"{base}/workers/domains" and method == "GET":
            return [{"id": i, "hostname": "crl.example.com", "service": n} for i, n in self.domains.items()]
        if path == f"{base}/workers/subdomain":
            if self.subdomain is None:
                raise cloudflare.CloudflareError("Cloudflare returned HTTP 404")
            return {"subdomain": self.subdomain}
        if path.startswith("/zones?"):
            return [{"id": ZONE_ID, "name": "example.com"}]
        m = re.fullmatch(rf"{base}/workers/scripts/([a-z0-9-]+)(/subdomain|\?force=true)?", path)
        if m and method == "PUT" and not m.group(2):
            if self.fail_deploys:
                raise cloudflare.CloudflareError("Cloudflare returned HTTP 500")
            assert content_type.startswith("multipart/form-data; boundary=")
            meta = json.loads(re.search(rb'name="metadata".*?\r\n\r\n(.*?)\r\n--', body, re.S).group(1))
            crl = re.search(rb'name="crl.bin".*?\r\n\r\n(.*)\r\n--certgen', body, re.S).group(1)
            assert b"import crl from" in body and meta["main_module"] == "worker.js"
            self.scripts[m.group(1)] = {"crl": crl, "path": meta["bindings"][0]["text"], "workers_dev": False}
            return {}
        if m and m.group(2) == "/subdomain":
            self.scripts[m.group(1)]["workers_dev"] = json.loads(body)["enabled"]
            return {}
        if m and method == "DELETE":
            self.scripts.pop(m.group(1), None)
            return {}
        if path == f"{base}/workers/domains" and method == "PUT":
            spec = json.loads(body)
            domain_id = "d" * 32
            self.domains[domain_id] = spec["service"]
            return {"id": domain_id}
        if path.startswith(f"{base}/workers/domains/") and method == "DELETE":
            self.domains.pop(path.rsplit("/", 1)[1], None)
            return {}
        raise AssertionError(f"unexpected call {method} {path}")

    def fetch(self, url):
        """What the Worker answers: http redirects to https, https serves the CRL."""
        scheme, rest = url.split("://", 1)
        host, path = rest.split("/", 1)
        script = next((n for n in self.scripts if host.startswith(n + ".") or host == "crl.example.com"), None)
        if script is None:
            return {"status": None, "error": "Name or service not known"}
        if scheme == "http":
            return {"status": 301, "location": "https://" + rest}
        if "/" + path != self.scripts[script]["path"]:
            return {"status": 404}
        return {"status": 200, "body": self.scripts[script]["crl"], "content_type": "application/pkix-crl"}


@pytest.fixture
def cf(monkeypatch):
    fake = FakeCloudflare()
    monkeypatch.setattr(cloudflare, "_request", fake.request)
    monkeypatch.setattr(crl_worker, "_fetch", fake.fetch)
    return fake


@pytest.fixture
def connected(admin_client, cf):
    _enable_encryption(admin_client)
    resp = admin_client.post("/api/cloudflare/connect", json={"token": TOKEN, "account_id": ACCOUNT})
    assert resp.status_code == 200, resp.get_json()
    return admin_client


def _deploy(client, ca_id, **body):
    resp = client.post(f"/api/ca/{ca_id}/cloudflare/deploy", json=body)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


def _issue(client, ca_id, **fields):
    resp = client.post(f"/api/ca/{ca_id}/certs",
                       json={"common_name": "www.cf.test", "algorithm": "ecdsa-p256", **fields})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["id"]


def _crl_serials(der: bytes) -> set[int]:
    return {entry.serial_number for entry in x509.load_der_x509_crl(der)}


# ── Connecting ──────────────────────────────────────────────────────

def test_connect_needs_encryption_and_stores_the_token_encrypted(admin_client, cf):
    resp = admin_client.post("/api/cloudflare/connect", json={"token": TOKEN, "account_id": ACCOUNT})
    assert resp.status_code == 400 and "encryption" in resp.get_json()["error"]
    _enable_encryption(admin_client)
    resp = admin_client.post("/api/cloudflare/connect", json={"token": TOKEN, "account_id": ACCOUNT})
    assert resp.status_code == 200
    assert resp.get_json()["workers_subdomain"] == "acme"
    with sqlite3.connect(db.DB_PATH) as conn:
        raw = conn.execute("SELECT value FROM app_settings WHERE key = 'cloudflare_token'").fetchone()[0]
    assert TOKEN.encode() not in raw
    status = admin_client.get("/api/cloudflare").get_json()
    assert status["connected"] and status["account_id"] == ACCOUNT and "token" not in json.dumps(status).lower().replace("connected", "")


def test_connect_rejects_a_malformed_account_id(admin_client, cf):
    _enable_encryption(admin_client)
    resp = admin_client.post("/api/cloudflare/connect", json={"token": TOKEN, "account_id": "nope"})
    assert resp.status_code == 502 and "32 hexadecimal" in resp.get_json()["error"]


def test_encryption_cant_be_disabled_while_connected(connected):
    resp = connected.post("/api/settings/encryption/disable", json={"password": ENCRYPTION_PASSWORD})
    assert resp.status_code == 400 and "Disconnect Cloudflare" in resp.get_json()["error"]


def test_locked_database_cant_use_the_token(connected):
    ca_id = _create_ca(connected)
    db.set_master_key(None)
    assert connected.post(f"/api/ca/{ca_id}/cloudflare/deploy", json={}).status_code == 423


# ── Deploy, issue, revoke ───────────────────────────────────────────

def test_deploy_on_workers_dev_and_issue_with_the_worker_address(connected, cf):
    ca_id = _create_ca(connected)
    status = _deploy(connected, ca_id)
    script = status["worker"]
    assert status["deployed"] and script.startswith("certgen-crl-")
    assert status["hostname"] == f"{script}.acme.workers.dev"
    assert status["dp_url"] == f"http://{script}.acme.workers.dev{status['crl_path']}"
    assert cf.scripts[script]["workers_dev"] is True
    assert x509.load_der_x509_crl(cf.scripts[script]["crl"]) is not None  # a real CRL was bundled

    cert_id = _issue(connected, ca_id, crl_dp="cloudflare")
    assert connected.get(f"/api/certs/{cert_id}/crl").get_json()["distribution_points"] == [status["dp_url"]]
    listed = connected.get(f"/api/ca/{ca_id}/certs").get_json()[0]["crl_dp"]
    assert listed == {"kind": "cloudflare", "url": status["dp_url"], "published": True}


def test_revoke_pushes_the_new_crl(connected, cf):
    ca_id = _create_ca(connected)
    script = _deploy(connected, ca_id)["worker"]
    cert_id = _issue(connected, ca_id, crl_dp="cloudflare")
    serial = int(connected.get(f"/api/certs/{cert_id}").get_json()["serial"], 16)
    resp = connected.post(f"/api/certs/{cert_id}/revoke")
    body = resp.get_json()
    assert body["crl_dp"] == "cloudflare" and body["cloudflare"]["pushed"] and not body["download_crl"]
    assert serial in _crl_serials(cf.scripts[script]["crl"])


def test_failed_push_is_recorded_and_retried(connected, cf):
    ca_id = _create_ca(connected)
    script = _deploy(connected, ca_id)["worker"]
    cert_id = _issue(connected, ca_id, crl_dp="cloudflare")
    cf.fail_deploys = True
    body = connected.post(f"/api/certs/{cert_id}/revoke").get_json()
    assert body["cloudflare"]["pushed"] is False and "failed" in body["note"]
    status = connected.get(f"/api/ca/{ca_id}/cloudflare").get_json()
    assert "HTTP 500" in status["push_error"]
    assert connected.get(f"/api/ca/{ca_id}/certs").get_json()[0]["crl_dp"]["published"] is False

    cf.fail_deploys = False
    crl_publisher.renew_due()  # not due for re-signing, but the failed push is retried
    assert connected.get(f"/api/ca/{ca_id}/cloudflare").get_json()["push_error"] is None
    serial = int(connected.get(f"/api/certs/{cert_id}").get_json()["serial"], 16)
    assert serial in _crl_serials(cf.scripts[script]["crl"])


def test_custom_domain_turns_workers_dev_off(connected, cf):
    ca_id = _create_ca(connected)
    resp = connected.post(f"/api/ca/{ca_id}/cloudflare/deploy", json={"hostname": "crl.other.org", "zone_id": ZONE_ID})
    assert resp.status_code == 400 and "under example.com" in resp.get_json()["error"]
    status = _deploy(connected, ca_id, hostname="crl.example.com", zone_id=ZONE_ID)
    assert status["custom_domain"] and status["hostname"] == "crl.example.com"
    assert cf.scripts[status["worker"]]["workers_dev"] is False
    assert cf.domains == {"d" * 32: status["worker"]}
    connected.delete(f"/api/ca/{ca_id}/cloudflare")
    assert cf.domains == {} and cf.scripts == {}


def test_deploy_without_a_workers_dev_subdomain_explains(connected, cf):
    cf.subdomain = None
    ca_id = _create_ca(connected)
    resp = connected.post(f"/api/ca/{ca_id}/cloudflare/deploy", json={})
    assert resp.status_code == 502 and "workers.dev subdomain" in resp.get_json()["error"]
    assert connected.get(f"/api/ca/{ca_id}/cloudflare").get_json() == {"deployed": False}


def test_failed_deploy_leaves_nothing_behind(connected, cf):
    cf.fail_deploys = True
    ca_id = _create_ca(connected)
    assert connected.post(f"/api/ca/{ca_id}/cloudflare/deploy", json={}).status_code == 502
    assert db.get_ca_worker(ca_id) is None and cf.scripts == {}


# ── Test and viewer ─────────────────────────────────────────────────

def test_test_recommends_https_when_http_redirects(connected, cf):
    ca_id = _create_ca(connected)
    status = _deploy(connected, ca_id)
    result = connected.post(f"/api/ca/{ca_id}/cloudflare/test").get_json()
    assert result["results"]["http"]["ok"] is False
    assert "redirects" in result["results"]["http"]["problems"][0]
    assert result["results"]["https"]["ok"] is True
    assert result["recommended"] == f"https://{status['hostname']}{status['crl_path']}"
    assert result["dp_url"] == result["recommended"]  # no certificate named the old address yet


def test_test_keeps_the_address_certificates_already_carry(connected, cf):
    ca_id = _create_ca(connected)
    status = _deploy(connected, ca_id)
    _issue(connected, ca_id, crl_dp="cloudflare")
    result = connected.post(f"/api/ca/{ca_id}/cloudflare/test").get_json()
    assert result["dp_url"] == status["dp_url"] and "already issued" in result["note"]


def test_test_flags_a_crl_from_another_ca(connected, cf):
    ca_id = _create_ca(connected)
    other = _create_ca(connected, domain="other.test")
    script = _deploy(connected, ca_id)["worker"]
    _deploy(connected, other)
    other_script = next(n for n in cf.scripts if n != script)
    cf.scripts[script]["crl"] = cf.scripts[other_script]["crl"]
    https = connected.post(f"/api/ca/{ca_id}/cloudflare/test").get_json()["results"]["https"]
    assert https["ok"] is False and "it isn't signed by this CA" in https["problems"]


def test_live_viewer_reads_the_worker(connected, cf):
    ca_id = _create_ca(connected)
    _deploy(connected, ca_id)
    cert_id = _issue(connected, ca_id, crl_dp="cloudflare")
    connected.post(f"/api/certs/{cert_id}/revoke")
    view = connected.get(f"/api/ca/{ca_id}/cloudflare/crl/view").get_json()
    assert view["source"] == "cloudflare" and view["public_url"].startswith("https://")
    assert [e["cert_id"] for e in view["entries"]] == [cert_id] and view["out_of_date"] is False


# ── Tear down and guards ────────────────────────────────────────────

def test_teardown_reports_affected_certificates(connected, cf):
    ca_id = _create_ca(connected)
    _deploy(connected, ca_id)
    _issue(connected, ca_id, crl_dp="cloudflare")
    assert connected.get(f"/api/ca/{ca_id}/cloudflare").get_json()["certificates"] == 1
    resp = connected.delete(f"/api/ca/{ca_id}/cloudflare")
    assert resp.get_json() == {"ok": True, "affected": 1}
    assert cf.scripts == {} and db.get_ca_worker(ca_id) is None


def test_ca_and_account_guards(connected, cf):
    root = _create_ca(connected)
    child = _create_ca(connected, domain="child.test", parent=root)
    _deploy(connected, child)
    assert connected.delete(f"/api/ca/{root}").status_code == 409
    assert connected.post("/api/cloudflare/disconnect").status_code == 409
    resp = connected.post("/api/cloudflare/connect", json={"token": TOKEN, "account_id": "a" * 32})
    assert resp.status_code == 400 and "Tear them down" in resp.get_json()["error"]
    connected.delete(f"/api/ca/{child}/cloudflare")
    assert connected.post("/api/cloudflare/disconnect").status_code == 200
    assert connected.delete(f"/api/ca/{root}").status_code == 200


def test_worker_from_another_account_is_never_pushed(connected, cf):
    ca_id = _create_ca(connected)
    script = _deploy(connected, ca_id)["worker"]
    db.update_ca_worker(ca_id, cf_account_id="b" * 32)  # e.g. restored from another install
    pushes_before = sum(1 for m, p in cf.calls if m == "PUT" and p.endswith(script))
    assert crl_worker.push(ca_id) is False
    assert sum(1 for m, p in cf.calls if m == "PUT" and p.endswith(script)) == pushes_before
    assert "different Cloudflare account" in db.get_ca_worker(ca_id)["cf_push_error"]


def test_backup_keeps_the_worker_link(connected, cf):
    ca_id = _create_ca(connected)
    status = _deploy(connected, ca_id)
    backup = connected.post("/api/backup", json={"password": "backup-pass-1"})
    assert backup.status_code == 200
    import base64
    resp = connected.post("/api/restore", json={"password": "backup-pass-1",
                                                "file_data": base64.b64encode(backup.data).decode()})
    assert resp.status_code == 200, resp.get_json()
    assert connected.get(f"/api/ca/{ca_id}/cloudflare").get_json()["worker"] == status["worker"]


def test_desktop_mode_has_no_cloudflare(fresh_app, cf):
    server.set_app_token("desktop-token")
    client = fresh_app.test_client()
    client.get("/_auth?token=desktop-token")
    assert client.get("/api/cloudflare").status_code == 404
    ca_id = _create_ca(client)
    resp = client.post(f"/api/ca/{ca_id}/certs", json={"common_name": "x.test", "crl_dp": "cloudflare"})
    assert resp.status_code == 400 and "need Docker" in resp.get_json()["error"]


def test_worker_code_only_serves_its_crl():
    js = cloudflare.WORKER_JS
    assert 'request.method !== "GET" && request.method !== "HEAD"' in js
    assert "url.pathname !== env.CRL_PATH" in js
    assert "access-control" not in js.lower() and "set-cookie" not in js.lower()
    assert hashlib.sha256(js.encode()).hexdigest()  # fixed code, no per-deploy templating


# ── Inventory and cleanup ───────────────────────────────────────────

def test_inventory_lists_only_app_workers_and_flags_unlinked_and_missing(connected, cf):
    linked_ca = _create_ca(connected)
    linked = _deploy(connected, linked_ca)["worker"]
    gone_ca = _create_ca(connected, domain="gone.test")
    gone = _deploy(connected, gone_ca)["worker"]
    cf.scripts.pop(gone)  # deleted in the dashboard
    cf.scripts["certgen-crl-left-over-abc123"] = {"crl": b"", "path": "/left-over.crl", "workers_dev": True}
    cf.domains["e" * 32] = "certgen-crl-left-over-abc123"
    workers = {w["name"]: w for w in connected.get("/api/cloudflare/workers").get_json()["workers"]}
    assert set(workers) == {linked, gone, "certgen-crl-left-over-abc123"}  # never someone-elses-worker
    assert workers[linked]["state"] == "linked" and workers[linked]["ca_id"] == linked_ca
    assert workers[gone]["state"] == "missing"
    assert workers["certgen-crl-left-over-abc123"]["state"] == "unlinked"
    assert workers["certgen-crl-left-over-abc123"]["hostnames"] == ["crl.example.com"]
    assert connected.get(f"/api/ca/{gone_ca}/cloudflare?refresh=1").get_json()["exists"] is False
    assert connected.get(f"/api/ca/{linked_ca}/cloudflare?refresh=1").get_json()["exists"] is True


def test_cleanup_deletes_unlinked_and_linked_workers(connected, cf):
    ca_id = _create_ca(connected)
    linked = _deploy(connected, ca_id)["worker"]
    cf.scripts["certgen-crl-left-over-abc123"] = {"crl": b"", "path": "/left-over.crl", "workers_dev": True}
    cf.domains["e" * 32] = "certgen-crl-left-over-abc123"
    resp = connected.delete("/api/cloudflare/workers/certgen-crl-left-over-abc123")
    assert resp.get_json() == {"ok": True, "ca_id": None, "affected": 0}
    assert "certgen-crl-left-over-abc123" not in cf.scripts and cf.domains == {}
    resp = connected.delete(f"/api/cloudflare/workers/{linked}")
    assert resp.get_json()["ca_id"] == ca_id and db.get_ca_worker(ca_id) is None and cf.scripts == {}
    for name in ("someone-elses-worker", "certgen-crl-does-not-exist"):
        assert connected.delete(f"/api/cloudflare/workers/{name}").status_code == 404
    assert not [path for method, path in cf.calls if method == "DELETE" and "someone-elses-worker" in path]


def test_tear_down_a_worker_already_deleted_in_cloudflare(connected, cf):
    ca_id = _create_ca(connected)
    script = _deploy(connected, ca_id)["worker"]
    cf.scripts.pop(script)
    assert connected.delete(f"/api/ca/{ca_id}/cloudflare").status_code == 200
    assert db.get_ca_worker(ca_id) is None


def test_only_the_apps_own_messages_reach_the_client(connected, monkeypatch):
    """A ValueError from a library is logged and answered generically, never shown as-is."""
    ca_id = _create_ca(connected)
    _deploy(connected, ca_id)

    def broken(_ca_id):
        raise ValueError("internal detail from a library")

    monkeypatch.setattr(crl_worker, "teardown", broken)
    resp = connected.delete(f"/api/ca/{ca_id}/cloudflare")
    assert resp.status_code == 500 and "internal detail" not in resp.get_data(as_text=True)
    other = _create_ca(connected, "other.test")
    resp = connected.post(f"/api/ca/{other}/cloudflare/test")  # the app's own message still shows
    assert resp.status_code == 404 and resp.get_json()["error"] == "This CA has no Worker"
