"""The Cert Generator Pal relay Worker (docs/cert-generator-pal.md §8), deployed by the app.

Fixed code, like the CRL Workers. One Durable Object ("Mailbox") holds everything: the public
keys of the PCs allowed to use the relay (pushed by the server), the sealed requests waiting for
the server to collect them, and the sealed replies waiting for their PCs. It can read none of
them: requests and replies are end-to-end encrypted (app/relay.py).

PC side (no token: the envelope's device signature is the credential)
  POST /v1/send          a request envelope; answered with the reply if the server answers within
                         ~25 s, else 202 and the PC asks again at
  GET  /v1/reply?d=&n=   the reply to its request (204 while still waiting)
  GET  /v1/health        that the relay is up (no details)

Server side (Authorization: Bearer <the server's token, a Worker secret>)
  PUT  /v1/server/keys   {"keys": {device id: SPKI base64}}: the PCs allowed, replacing the list
  GET  /v1/server/pull   waiting requests (long poll, ~25 s), removed as they are handed over
  POST /v1/server/reply  {"replies": [{"n", "d", "reply"}]}
  GET  /v1/server/status queue sizes, for the admin page
"""
from __future__ import annotations

RELAY_WORKER_JS = r"""
const VERSION = 1;
const MAX_ENVELOPE = 300 * 1024;
const MAX_KEYS_BODY = 2 * 1024 * 1024;
const SKEW_SECONDS = 300;
const TTL_MS = 10 * 60 * 1000;
const WAIT_MS = 25 * 1000;
const PER_DEVICE = 20;
const PULL_BATCH = 20;
const ID = /^[0-9a-f]{32}$/;
const NONCE = /^[A-Za-z0-9_-]{16,64}$/;
const B64URL = /^[A-Za-z0-9_-]*$/;

const SECURITY = {
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'; sandbox",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
};

function json(status, body) {
  return new Response(body === null ? null : JSON.stringify(body), {
    status, headers: { "content-type": "application/json", ...SECURITY },
  });
}

function b64urlBytes(text) {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function readLimited(request, limit) {
  const declared = Number(request.headers.get("content-length") || "0");
  if (declared > limit) return null;
  const body = await request.text();
  return body.length > limit ? null : body;
}

// Compare the server's token without leaking where it differs.
async function sameSecret(given, expected) {
  if (!expected) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", crypto.getRandomValues(new Uint8Array(32)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const [a, b] = await Promise.all([crypto.subtle.sign("HMAC", key, enc.encode(given)), crypto.subtle.sign("HMAC", key, enc.encode(expected))]);
  const x = new Uint8Array(a), y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// Durable Object storage deletes at most 128 keys per call.
async function deleteAll(storage, keys) {
  for (let i = 0; i < keys.length; i += 128) await storage.delete(keys.slice(i, i + 128));
}

function parseEnvelope(text) {
  let env;
  try { env = JSON.parse(text); } catch { return null; }
  const fields = ["v", "d", "t", "n", "e", "i", "c", "s"];
  if (!env || typeof env !== "object" || Array.isArray(env)) return null;
  if (Object.keys(env).length !== fields.length || !fields.every((f) => f in env)) return null;
  if (env.v !== VERSION || !Number.isInteger(env.t) || !ID.test(env.d) || !NONCE.test(env.n)) return null;
  if (!["e", "i", "c", "s"].every((f) => typeof env[f] === "string" && B64URL.test(env[f]))) return null;
  return env;
}

async function signedByDevice(env, spkiB64) {
  try {
    const key = await crypto.subtle.importKey("spki", Uint8Array.from(atob(spkiB64), (c) => c.charCodeAt(0)),
      { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const message = new TextEncoder().encode(["CGP1-RELAY", env.d, String(env.t), env.n, env.e, env.i, env.c].join("\n"));
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64urlBytes(env.s), message);
  } catch {
    return false;
  }
}

export class Mailbox {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.serverWaiters = [];
    this.replyWaiters = new Map();
  }

  now() { return Date.now(); }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path.startsWith("/v1/server/")) {
      const auth = request.headers.get("authorization") || "";
      if (!auth.startsWith("Bearer ") || !(await sameSecret(auth.slice(7), this.env.SERVER_TOKEN))) {
        return json(401, { error: "Not the server" });
      }
      if (path === "/v1/server/keys" && request.method === "PUT") return this.putKeys(request);
      if (path === "/v1/server/pull" && request.method === "GET") return this.pull(url);
      if (path === "/v1/server/reply" && request.method === "POST") return this.reply(request);
      if (path === "/v1/server/status" && request.method === "GET") return this.status();
      return json(404, { error: "Not found" });
    }
    if (path === "/v1/send" && request.method === "POST") return this.send(request);
    if (path === "/v1/reply" && request.method === "GET") return this.pickUp(url);
    return json(404, { error: "Not found" });
  }

  // ── PC side ──

  async send(request) {
    const text = await readLimited(request, MAX_ENVELOPE);
    if (text === null) return json(413, { error: "Too large" });
    const env = parseEnvelope(text);
    if (!env) return json(400, { error: "Not a relay envelope" });
    const keys = (await this.state.storage.get("keys")) || {};
    if (!keys[env.d] || !(await signedByDevice(env, keys[env.d]))) {
      return json(403, { error: "This PC isn't allowed to use the relay" });
    }
    if (Math.abs(this.now() / 1000 - env.t) > SKEW_SECONDS) return json(401, { error: "Clock wrong" });
    if (await this.state.storage.get("s:" + env.n)) return json(409, { error: "Already sent" });
    const pending = await this.state.storage.list({ prefix: "q:" + env.d + ":" });
    if (pending.size >= PER_DEVICE) return json(429, { error: "Too many requests waiting" });
    const at = this.now();
    await this.state.storage.put({ ["s:" + env.n]: { d: env.d, at }, ["q:" + env.d + ":" + env.n]: { d: env.d, n: env.n, env: text, at } });
    await this.ensureAlarm();
    this.wakeServer();
    return this.awaitReply(env.d, env.n, 202);
  }

  async pickUp(url) {
    const d = url.searchParams.get("d") || "", n = url.searchParams.get("n") || "";
    if (!ID.test(d) || !NONCE.test(n)) return json(400, { error: "Bad request" });
    return this.awaitReply(d, n, 204);
  }

  async awaitReply(d, n, otherwise) {
    const ready = await this.takeReply(d, n);
    if (ready) return ready;
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, WAIT_MS);
      this.replyWaiters.set(n, () => { clearTimeout(timer); resolve(); });
    });
    this.replyWaiters.delete(n);
    return (await this.takeReply(d, n)) || json(otherwise, otherwise === 204 ? null : { pending: true, n });
  }

  async takeReply(d, n) {
    const reply = await this.state.storage.get("r:" + n);
    if (!reply || reply.d !== d) return null;
    await this.state.storage.delete("r:" + n);
    return new Response(reply.reply, { status: 200, headers: { "content-type": "application/json", ...SECURITY } });
  }

  // ── Server side ──

  async putKeys(request) {
    const text = await readLimited(request, MAX_KEYS_BODY);
    let body;
    try { body = JSON.parse(text || ""); } catch { return json(400, { error: "Bad keys" }); }
    const keys = body && body.keys;
    if (!keys || typeof keys !== "object" || Array.isArray(keys)) return json(400, { error: "Bad keys" });
    for (const [d, spki] of Object.entries(keys)) {
      if (!ID.test(d) || typeof spki !== "string" || spki.length > 400) return json(400, { error: "Bad keys" });
    }
    await this.state.storage.put("keys", keys);
    // A PC taken off the list loses whatever it had waiting.
    const queued = await this.state.storage.list({ prefix: "q:" });
    const drop = [...queued.keys()].filter((k) => !keys[k.split(":")[1]]);
    if (drop.length) await deleteAll(this.state.storage, drop);
    return json(200, { ok: true, keys: Object.keys(keys).length });
  }

  async pull(url) {
    let batch = await this.state.storage.list({ prefix: "q:", limit: PULL_BATCH });
    if (batch.size === 0 && url.searchParams.get("wait") === "1") {
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, WAIT_MS);
        this.serverWaiters.push(() => { clearTimeout(timer); resolve(); });
      });
      batch = await this.state.storage.list({ prefix: "q:", limit: PULL_BATCH });
    }
    const requests = [...batch.values()].map((q) => ({ n: q.n, d: q.d, env: q.env }));
    if (batch.size) await deleteAll(this.state.storage, [...batch.keys()]);
    await this.state.storage.put("lastPull", this.now());
    return json(200, { requests });
  }

  async reply(request) {
    const text = await readLimited(request, MAX_ENVELOPE * PULL_BATCH);
    let body;
    try { body = JSON.parse(text || ""); } catch { return json(400, { error: "Bad replies" }); }
    if (!body || !Array.isArray(body.replies)) return json(400, { error: "Bad replies" });
    let stored = 0;
    for (const r of body.replies) {
      if (!r || !ID.test(r.d) || !NONCE.test(r.n) || typeof r.reply !== "string" || r.reply.length > MAX_ENVELOPE) continue;
      const sent = await this.state.storage.get("s:" + r.n);
      if (!sent || sent.d !== r.d) continue;  // only for a request this mailbox took in
      await this.state.storage.put("r:" + r.n, { d: r.d, reply: r.reply, at: this.now() });
      const wake = this.replyWaiters.get(r.n);
      if (wake) wake();
      stored++;
    }
    return json(200, { ok: true, stored });
  }

  async status() {
    const [queued, replies, keys, lastPull] = await Promise.all([
      this.state.storage.list({ prefix: "q:" }), this.state.storage.list({ prefix: "r:" }),
      this.state.storage.get("keys"), this.state.storage.get("lastPull"),
    ]);
    return json(200, { version: VERSION, queued: queued.size, replies: replies.size, keys: Object.keys(keys || {}).length, last_pull: lastPull || null });
  }

  wakeServer() {
    const waiters = this.serverWaiters.splice(0);
    for (const wake of waiters) wake();
  }

  // ── Housekeeping: nothing stays longer than TTL_MS ──

  async ensureAlarm() {
    if ((await this.state.storage.getAlarm()) === null) await this.state.storage.setAlarm(this.now() + TTL_MS);
  }

  async alarm() {
    const cutoff = this.now() - TTL_MS;
    let more = false;
    for (const prefix of ["q:", "r:", "s:"]) {
      const entries = await this.state.storage.list({ prefix });
      const old = [...entries].filter(([, v]) => !v || v.at < cutoff).map(([k]) => k);
      if (old.length) await deleteAll(this.state.storage, old);
      if (entries.size > old.length) more = true;
    }
    if (more) await this.state.storage.setAlarm(this.now() + TTL_MS);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/v1/health" && (request.method === "GET" || request.method === "HEAD")) {
      return json(200, { ok: true, service: "cert-generator-relay", version: VERSION });
    }
    if (!url.pathname.startsWith("/v1/")) return json(404, { error: "Not found" });
    const mailbox = env.MAILBOX.get(env.MAILBOX.idFromName("relay"));
    return mailbox.fetch(request);
  },
};
"""
