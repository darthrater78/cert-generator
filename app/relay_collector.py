"""The server's side of the Pal relay: it connects *out* to the relay Worker, collects sealed
requests, runs each through the device API (routes/pal.relay_dispatch) and posts the sealed
replies back. Nothing on the LAN listens for the relay (docs/cert-generator-pal.md §8).

One background thread. It idles while no relay is set up or the database is locked, keeps the
Worker's list of allowed PCs in step with the database, and backs off when the Worker can't
be reached. ``status()`` is what the admin page shows.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Protocol

from . import db
from .errors import UserError
from .security import RateLimiter

log = logging.getLogger("cert-generator")

PULL_TIMEOUT = 40  # the Worker holds a pull up to 25 s
IDLE_SECONDS = 30
MAX_BACKOFF = 300
_limiter = RateLimiter(30, window=60)  # per PC, like the LAN API's per-address limit

_state: dict[str, Any] = {"running": False, "last_ok": None, "last_error": None, "handled": 0, "dropped": 0}
_state_lock = threading.Lock()
_wake = threading.Event()


def status() -> dict[str, Any]:
    with _state_lock:
        return dict(_state)


def _note(**changes: Any) -> None:
    with _state_lock:
        _state.update(changes)


def poke() -> None:
    """Re-check now (after setup, or when a PC's remote access changed)."""
    _wake.set()


class Link(Protocol):
    def put_keys(self, keys: dict[str, str]) -> None: ...
    def pull(self) -> list[dict[str, Any]]: ...
    def reply(self, replies: list[dict[str, str]]) -> None: ...


class RelayError(RuntimeError):
    pass


class HttpLink:
    """The Worker's server endpoints, over verified HTTPS with the server's token."""

    def __init__(self, base_url: str, token: str) -> None:
        if not base_url.startswith("https://"):
            raise RelayError("The relay must be an https:// address")
        self.base = base_url.rstrip("/")
        self.token = token

    def _call(self, method: str, path: str, body: Any = None, timeout: float = 20) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method)  # noqa: S310 - https only (checked above)
        request.add_header("Authorization", "Bearer " + self.token)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:  # nosec B310
                return json.loads(response.read() or b"null")
        except urllib.error.HTTPError as e:
            raise RelayError(f"The relay answered HTTP {e.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            raise RelayError(f"Can't reach the relay: {getattr(e, 'reason', e)}") from None

    def put_keys(self, keys: dict[str, str]) -> None:
        self._call("PUT", "/v1/server/keys", {"keys": keys})

    def pull(self) -> list[dict[str, Any]]:
        result = self._call("GET", "/v1/server/pull?wait=1", timeout=PULL_TIMEOUT)
        requests = result.get("requests") if isinstance(result, dict) else None
        return [r for r in requests or [] if isinstance(r, dict)]

    def reply(self, replies: list[dict[str, str]]) -> None:
        self._call("POST", "/v1/server/reply", {"replies": replies})

    def worker_status(self) -> dict[str, Any]:
        result = self._call("GET", "/v1/server/status")
        return result if isinstance(result, dict) else {}


def allowed_keys() -> dict[str, str]:
    return {device_id: base64.b64encode(key).decode() for device_id, key in db.list_pal_remote_keys()}


def run_once(link: Link, app: Any, pushed: str | None) -> str:
    """Sync the allowed PCs, take one batch of requests and answer it. Returns the hash of the
    key list now on the Worker, so it is only pushed again when it changes."""
    from .routes.pal import relay_dispatch

    keys = allowed_keys()
    digest = hashlib.sha256(json.dumps(keys, sort_keys=True).encode()).hexdigest()
    if digest != pushed:
        link.put_keys(keys)
        pushed = digest
    replies = []
    for item in link.pull():
        device_id, nonce, envelope = item.get("d"), item.get("n"), item.get("env")
        if not all(isinstance(v, str) for v in (device_id, nonce, envelope)):
            continue
        if not _limiter.allow(f"relay:{device_id}"):
            _note(dropped=status()["dropped"] + 1)
            continue
        with app.app_context():
            sealed = relay_dispatch(envelope.encode())
        if sealed is None:
            _note(dropped=status()["dropped"] + 1)
            continue
        replies.append({"n": nonce, "d": device_id, "reply": sealed.decode()})
    if replies:
        link.reply(replies)
        _note(handled=status()["handled"] + len(replies))
    _note(last_ok=time.time(), last_error=None)
    return pushed


def _link() -> HttpLink | None:
    config = db.get_pal_relay_config()
    if not config or (db.is_encryption_enabled() and not db.is_unlocked()):
        return None
    token = db.get_pal_relay_token()
    return HttpLink(config["url"], token) if token else None


def start(app: Any) -> threading.Thread:
    """The collector thread (server mode). Safe to start with no relay set up: it waits."""

    def loop() -> None:
        _note(running=True)
        pushed: str | None = None
        backoff = 5
        while True:
            try:
                link = _link()
                if link is None:
                    pushed = None
                    _wake.wait(IDLE_SECONDS)
                    _wake.clear()
                    continue
                pushed = run_once(link, app, pushed)
                backoff = 5
                if _wake.is_set():
                    _wake.clear()
                    pushed = None  # a PC's remote access changed: push the list now
            except Exception as e:  # noqa: BLE001 - the collector must survive anything and retry
                _note(last_error=str(e) if isinstance(e, RelayError) else type(e).__name__)
                log.warning("Pal relay: %s; retrying in %d s", e if isinstance(e, RelayError) else type(e).__name__, backoff)
                pushed = None
                _wake.wait(backoff)
                _wake.clear()
                backoff = min(backoff * 2, MAX_BACKOFF)

    thread = threading.Thread(target=loop, name="pal-relay", daemon=True)
    thread.start()
    return thread


# ── Set up and tear down (the admin page's buttons call these) ─────

def _credentials() -> Any:
    from .cloudflare import Credentials

    found = db.get_cloudflare_credentials()
    if found is None:
        raise UserError("Connect Cloudflare first (Tools › Cloudflare)")
    account_id, token = found
    return Credentials(token=token, account_id=account_id)


def set_up() -> dict[str, Any]:
    """Deploy the relay Worker and remember it. Makes the relay key the first time; PCs pin
    its public half when they next connect on the LAN."""
    import secrets as _secrets

    from . import cloudflare, relay

    if db.get_pal_relay_config() is not None:
        raise UserError("The relay is already set up. Tear it down first to make a new one")
    creds = _credentials()
    subdomain = cloudflare.workers_subdomain(creds)
    if subdomain is None:
        raise UserError("This Cloudflare account has no workers.dev subdomain yet. Open Workers & Pages once in "
                           "the Cloudflare dashboard to choose one, then try again")
    if db.get_pal_relay_key() is None:
        db.create_pal_relay_key(relay.private_key_der(relay.new_relay_key()))
    script = cloudflare.new_relay_script_name()
    token = _secrets.token_urlsafe(32)
    cloudflare.deploy_relay(creds, script, token)
    cloudflare.set_workers_dev(creds, script, True)
    config = {"script": script, "url": f"https://{script}.{subdomain}.workers.dev"}
    db.set_pal_relay_config(config, token)
    log.info("Pal relay set up: %s", config["url"])
    poke()
    return config


def update() -> None:
    """Redeploy the Worker's fixed code (after an app update), keeping its address and mailbox."""
    from . import cloudflare

    config, token = db.get_pal_relay_config(), db.get_pal_relay_token()
    if not config or not token:
        raise UserError("No relay is set up")
    cloudflare.deploy_relay(_credentials(), config["script"], token)
    poke()


def tear_down() -> None:
    """Delete the Worker and forget it. The relay key stays, so PCs can use a new relay without
    connecting on the LAN again."""
    from . import cloudflare

    config = db.get_pal_relay_config()
    if not config:
        return
    try:
        cloudflare.delete_relay(_credentials(), config["script"])
    except cloudflare.CloudflareError as e:
        if "HTTP 404" not in str(e):
            raise
    db.clear_pal_relay_config()
    log.info("Pal relay torn down: %s", config["script"])
    poke()


def relay_public_key() -> str | None:
    """The relay key's public half (base64url SEC1 point) for the Pal to pin, or None."""
    from . import relay

    der = db.get_pal_relay_key()
    return relay.b64url(relay.public_raw(relay.load_private_key(der).public_key())) if der else None
