"""The server's relay collector and the relay Worker's deploy (phase R2), against fakes:
a stand-in for the Worker's server endpoints and a recorded Cloudflare API."""
from __future__ import annotations

import json
import secrets
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from app import cloudflare, db, pal, relay, relay_collector, server

from .test_pal_relay import remote  # noqa: F401 - fixture


class FakeLink:
    def __init__(self):
        self.keys_pushed: list[dict] = []
        self.queue: list[dict] = []
        self.replies: list[dict] = []

    def put_keys(self, keys):
        self.keys_pushed.append(keys)

    def pull(self):
        batch, self.queue = self.queue, []
        return batch

    def reply(self, replies):
        self.replies.extend(replies)


def _sealed_get(pc, relay_pub, path="/api/pal/v1/device"):
    ts, nonce = str(int(time.time())), pal.b64url(secrets.token_bytes(16))
    sig = pc.device_key.sign(pal.request_signing_string("GET", path, ts, nonce, b""), ec.ECDSA(hashes.SHA256()))
    inner = {"method": "GET", "path": path, "body": "",
             "headers": {"X-Pal-Device": pc.device_id, "X-Pal-Time": ts, "X-Pal-Nonce": nonce, "X-Pal-Signature": pal.b64url(sig)}}
    outer = pal.b64url(secrets.token_bytes(16))
    envelope, k_rep = relay.seal_request(pc.device_key, pc.device_id, relay_pub, inner, timestamp=int(time.time()), nonce=outer)
    return {"n": outer, "d": pc.device_id, "env": envelope.decode()}, k_rep


@pytest.fixture(autouse=True)
def _fresh_limiter():
    relay_collector._limiter.reset()


def test_collector_syncs_keys_and_answers_requests(remote):  # noqa: F811
    _, pc, link = remote
    fake = FakeLink()
    pushed = relay_collector.run_once(fake, server.app, None)
    assert fake.keys_pushed == [{}]  # nobody allowed yet
    assert relay_collector.run_once(fake, server.app, pushed) == pushed and len(fake.keys_pushed) == 1  # unchanged: not pushed

    db.set_pal_remote_allowed(pc.device_id, True)
    item, k_rep = _sealed_get(pc, link.relay_pub)
    fake.queue.append(item)
    relay_collector.run_once(fake, server.app, pushed)
    assert list(fake.keys_pushed[-1]) == [pc.device_id]
    [answer] = fake.replies
    assert answer["n"] == item["n"] and answer["d"] == pc.device_id
    reply = relay.open_reply(k_rep, pc.device_id, item["n"], answer["reply"].encode())
    assert reply["status"] == 200


def test_collector_drops_what_it_cannot_answer(remote):  # noqa: F811
    _, pc, _ = remote
    fake = FakeLink()
    fake.queue += [{"n": "x" * 22, "d": pc.device_id, "env": "garbage"}, {"n": 1, "d": None, "env": None}]
    before = relay_collector.status()["dropped"]
    relay_collector.run_once(fake, server.app, None)
    assert fake.replies == [] and relay_collector.status()["dropped"] == before + 1


def test_collector_rate_limits_each_pc(remote):  # noqa: F811
    _, pc, link = remote
    db.set_pal_remote_allowed(pc.device_id, True)
    fake = FakeLink()
    fake.queue += [_sealed_get(pc, link.relay_pub)[0] for _ in range(32)]
    relay_collector.run_once(fake, server.app, None)
    assert len(fake.replies) == 30


def test_http_link_is_https_only():
    with pytest.raises(relay_collector.RelayError):
        relay_collector.HttpLink("http://relay.example", "t" * 40)


# ── Deploy ──────────────────────────────────────────────────────────

@pytest.fixture
def cf_calls(monkeypatch):
    calls: list[tuple[str, str, bytes | None]] = []
    scripts: list[dict] = []

    def fake_request(token, method, path, *, body=None, content_type="application/json"):
        calls.append((method, path, body))
        if method == "GET" and path.endswith("/workers/scripts"):
            return scripts
        return {}

    monkeypatch.setattr(cloudflare, "_request", fake_request)
    return calls, scripts


def _metadata(body: bytes) -> dict:
    part = body.split(b'name="metadata"; filename="metadata.json"\r\nContent-Type: application/json\r\n\r\n', 1)[1]
    return json.loads(part.split(b"\r\n--certgen", 1)[0])


def test_relay_deploy_sends_the_migration_only_once(cf_calls):
    calls, scripts = cf_calls
    creds = cloudflare.Credentials(token="t", account_id="a" * 32)
    name = cloudflare.new_relay_script_name()
    cloudflare.deploy_relay(creds, name, "s" * 43)
    meta = _metadata(calls[-1][2])
    assert meta["migrations"] == {"new_tag": "v1", "new_sqlite_classes": ["Mailbox"]}
    assert {"type": "durable_object_namespace", "name": "MAILBOX", "class_name": "Mailbox"} in meta["bindings"]
    assert {"type": "secret_text", "name": "SERVER_TOKEN", "text": "s" * 43} in meta["bindings"]
    assert b"export class Mailbox" in calls[-1][2]

    scripts.append({"id": name, "migration_tag": "v1"})
    cloudflare.deploy_relay(creds, name, "s" * 43)
    assert "migrations" not in _metadata(calls[-1][2])


@pytest.mark.parametrize("name, token", [("certgen-crl-x", "s" * 43), ("certgen-relay-abcdef12", "short")])
def test_relay_deploy_validates(cf_calls, name, token):
    with pytest.raises(cloudflare.CloudflareError):
        cloudflare.deploy_relay(cloudflare.Credentials(token="t", account_id="a" * 32), name, token)


def test_relay_config_needs_encryption_and_is_sealed(admin_client):
    from .test_security import _enable_encryption
    with pytest.raises(Exception, match="encryption"):
        db.set_pal_relay_config({"script": "x", "url": "https://x"}, "t" * 40)
    _enable_encryption(admin_client)
    db.set_pal_relay_config({"script": "certgen-relay-abcdef12", "url": "https://r.example.workers.dev"}, "t" * 40)
    assert db.get_pal_relay_config()["url"] == "https://r.example.workers.dev"
    assert db.get_pal_relay_token() == "t" * 40
    assert b"t" * 40 not in db.get_setting("pal_relay_token")  # stored encrypted


def test_set_up_and_tear_down(admin_client, cf_calls, monkeypatch):
    from .test_security import _enable_encryption
    calls, _ = cf_calls
    with pytest.raises(Exception, match="Connect Cloudflare first"):
        relay_collector.set_up()
    _enable_encryption(admin_client)
    db.set_cloudflare_credentials("a" * 32, "cf-token")
    monkeypatch.setattr(cloudflare, "workers_subdomain", lambda creds: None)
    with pytest.raises(Exception, match="workers.dev subdomain"):
        relay_collector.set_up()
    monkeypatch.setattr(cloudflare, "workers_subdomain", lambda creds: "home")
    config = relay_collector.set_up()
    assert config["url"] == f"https://{config['script']}.home.workers.dev"
    assert any(m == "PUT" and p.endswith("/workers/scripts/" + config["script"]) for m, p, _ in calls)
    assert any(m == "POST" and p.endswith(config["script"] + "/subdomain") for m, p, _ in calls)
    key = relay_collector.relay_public_key()
    assert key and len(relay.b64url_decode(key)) == 65
    with pytest.raises(Exception, match="already set up"):
        relay_collector.set_up()

    relay_collector.tear_down()
    assert ("DELETE", f"/accounts/{'a' * 32}/workers/scripts/{config['script']}?force=true", None) in calls
    assert db.get_pal_relay_config() is None and db.get_pal_relay_token() is None
    assert relay_collector.relay_public_key() == key  # the key stays pinned for a new relay
