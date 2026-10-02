"""The relay Worker's own code (app/relay_worker.py), run in Node against envelopes sealed by
app/relay.py, with an in-memory stand-in for Durable Object storage. Skipped without Node."""
from __future__ import annotations

import base64
import json
import secrets
import shutil
import subprocess
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import relay
from app.relay_worker import RELAY_WORKER_JS

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="needs Node.js")

TOKEN = "server-token-" + "x" * 32

HARNESS = r"""
import { Mailbox, default as worker } from "./worker.mjs";

class Storage {
  constructor() { this.data = new Map(); this.alarmAt = null; }
  async get(k) { return this.data.has(k) ? structuredClone(this.data.get(k)) : undefined; }
  async put(k, v) {
    if (typeof k === "object") { for (const [kk, vv] of Object.entries(k)) this.data.set(kk, structuredClone(vv)); }
    else this.data.set(k, structuredClone(v));
  }
  async delete(k) {
    const keys = Array.isArray(k) ? k : [k];
    if (keys.length > 128) throw new Error("more than 128 keys");
    keys.forEach((kk) => this.data.delete(kk));
  }
  async list({ prefix = "", limit } = {}) {
    const out = new Map();
    for (const k of [...this.data.keys()].sort()) {
      if (k.startsWith(prefix)) out.set(k, structuredClone(this.data.get(k)));
      if (limit && out.size >= limit) break;
    }
    return out;
  }
  async getAlarm() { return this.alarmAt; }
  async setAlarm(t) { this.alarmAt = t; }
}

const input = JSON.parse(await new Promise((resolve) => { let s = ""; process.stdin.on("data", (c) => (s += c)); process.stdin.on("end", () => resolve(s)); }));
const box = new Mailbox({ storage: new Storage() }, { SERVER_TOKEN: input.token });
const env = { MAILBOX: { idFromName: () => "relay", get: () => box } };
const base = "https://relay.example.workers.dev";
const call = (method, path, { body, token } = {}) => worker.fetch(new Request(base + path, {
  method, body, headers: token ? { authorization: "Bearer " + token } : {},
}), env);
const result = async (res) => ({ status: res.status, body: res.status === 204 ? null : await res.json().catch(() => null), headers: Object.fromEntries(res.headers) });
const out = {};
const T = input.token;

out.health = await result(await call("GET", "/v1/health"));
out.other = await result(await call("GET", "/nope"));
out.sendNoKeys = await result(await call("POST", "/v1/send", { body: input.good }));
out.keysWrongToken = await result(await call("PUT", "/v1/server/keys", { body: JSON.stringify({ keys: input.keys }), token: "wrong" }));
out.keys = await result(await call("PUT", "/v1/server/keys", { body: JSON.stringify({ keys: input.keys }), token: T }));
out.send = await result(await call("POST", "/v1/send", { body: input.good }));
out.again = await result(await call("POST", "/v1/send", { body: input.good }));
out.forged = await result(await call("POST", "/v1/send", { body: input.forged }));
out.stale = await result(await call("POST", "/v1/send", { body: input.stale }));
out.garbage = await result(await call("POST", "/v1/send", { body: "{\"v\":1}" }));
out.pull = await result(await call("GET", "/v1/server/pull", { token: T }));
out.pullEmpty = await result(await call("GET", "/v1/server/pull", { token: T }));
out.replyUnknown = await result(await call("POST", "/v1/server/reply", { body: JSON.stringify({ replies: [{ n: "z".repeat(22), d: input.device, reply: "{}" }] }), token: T }));
out.replyWrongDevice = await result(await call("POST", "/v1/server/reply", { body: JSON.stringify({ replies: [{ n: input.goodNonce, d: "f".repeat(32), reply: "{}" }] }), token: T }));
out.reply = await result(await call("POST", "/v1/server/reply", { body: JSON.stringify({ replies: [{ n: input.goodNonce, d: input.device, reply: input.sealedReply }] }), token: T }));
out.pickUp = await result(await call("GET", `/v1/reply?d=${input.device}&n=${input.goodNonce}`));
out.pickUpAgain = await result(await call("GET", `/v1/reply?d=${input.device}&n=${input.goodNonce}`));

// Long polls: the server waits for work, the PC waits for its answer, both in one round trip.
const pulling = call("GET", "/v1/server/pull?wait=1", { token: T });
const sending = call("POST", "/v1/send", { body: input.second });
const pulled = await result(await pulling);
await call("POST", "/v1/server/reply", { body: JSON.stringify({ replies: [{ n: input.secondNonce, d: input.device, reply: input.sealedReply }] }), token: T });
out.longPollPull = pulled;
out.longPollSend = await result(await sending);

// Taking a PC off the list drops what it had waiting.
await call("POST", "/v1/send", { body: input.third });
await call("PUT", "/v1/server/keys", { body: JSON.stringify({ keys: {} }), token: T });
out.afterRemoval = await result(await call("GET", "/v1/server/status", { token: T }));
out.removedSend = await result(await call("POST", "/v1/send", { body: input.fourth }));
console.log(JSON.stringify(out));
"""


def _envelope(key, device_id, relay_pub, *, timestamp=None):
    nonce = relay.b64url(secrets.token_bytes(16))
    env, _ = relay.seal_request(key, device_id, relay_pub, {"method": "GET"}, timestamp=timestamp or int(time.time()), nonce=nonce)
    return env.decode(), nonce


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    folder = tmp_path_factory.mktemp("relay-worker")
    (folder / "worker.mjs").write_text(RELAY_WORKER_JS.replace("const WAIT_MS = 25 * 1000;", "const WAIT_MS = 300;"), encoding="utf-8")
    (folder / "harness.mjs").write_text(HARNESS, encoding="utf-8")
    device, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    device_id = "0123456789abcdef0123456789abcdef"
    relay_pub = relay.public_raw(relay.new_relay_key().public_key())
    spki = device.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    good, good_nonce = _envelope(device, device_id, relay_pub)
    second, second_nonce = _envelope(device, device_id, relay_pub)
    forged, _ = _envelope(other, device_id, relay_pub)
    stale, _ = _envelope(device, device_id, relay_pub, timestamp=int(time.time()) - 3600)
    payload = {
        "token": TOKEN, "device": device_id, "keys": {device_id: base64.b64encode(spki).decode()},
        "good": good, "goodNonce": good_nonce, "second": second, "secondNonce": second_nonce,
        "third": _envelope(device, device_id, relay_pub)[0], "fourth": _envelope(device, device_id, relay_pub)[0],
        "forged": forged, "stale": stale, "sealedReply": '{"v":1,"n":"x","i":"y","c":"z"}',
    }
    proc = subprocess.run(["node", "harness.mjs"], cwd=folder, input=json.dumps(payload), capture_output=True,
                          text=True, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout), payload


def test_health_and_unknown_paths(run):
    out, _ = run
    assert out["health"]["status"] == 200 and out["health"]["body"]["service"] == "cert-generator-relay"
    assert out["other"]["status"] == 404
    assert out["health"]["headers"]["cache-control"] == "no-store"


def test_only_listed_pcs_with_valid_signatures_get_in(run):
    out, _ = run
    assert out["sendNoKeys"]["status"] == 403
    assert out["forged"]["status"] == 403
    assert out["stale"]["status"] == 401
    assert out["garbage"]["status"] == 400


def test_server_endpoints_need_the_token(run):
    out, _ = run
    assert out["keysWrongToken"]["status"] == 401
    assert out["keys"]["status"] == 200 and out["keys"]["body"]["keys"] == 1


def test_request_waits_for_the_server_then_is_handed_over_once(run):
    out, payload = run
    assert out["send"]["status"] == 202 and out["send"]["body"] == {"pending": True, "n": payload["goodNonce"]}
    assert out["again"]["status"] == 409  # the same envelope twice
    [request] = out["pull"]["body"]["requests"]
    assert request == {"n": payload["goodNonce"], "d": payload["device"], "env": payload["good"]}
    assert out["pullEmpty"]["body"] == {"requests": []}


def test_replies_go_only_to_the_request_they_answer(run):
    out, payload = run
    assert out["replyUnknown"]["body"]["stored"] == 0
    assert out["replyWrongDevice"]["body"]["stored"] == 0
    assert out["reply"]["body"]["stored"] == 1
    assert out["pickUp"]["status"] == 200 and out["pickUp"]["body"] == json.loads(payload["sealedReply"])
    assert out["pickUpAgain"]["status"] == 204  # handed over once


def test_long_polls_answer_in_one_round_trip(run):
    out, payload = run
    assert [r["n"] for r in out["longPollPull"]["body"]["requests"]] == [payload["secondNonce"]]
    assert out["longPollSend"]["status"] == 200


def test_removing_a_pc_drops_its_waiting_requests(run):
    out, _ = run
    assert out["afterRemoval"]["body"]["queued"] == 0 and out["afterRemoval"]["body"]["keys"] == 0
    assert out["removedSend"]["status"] == 403
