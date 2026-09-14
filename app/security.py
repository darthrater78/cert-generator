"""Request-level security helpers: attempt limiting, TOTP verification, CSRF checks."""
from __future__ import annotations

import hmac
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import pyotp


class AttemptLimiter:
    """Temporary lockout after repeated failures, keyed by an arbitrary string.

    After ``max_failures`` failures the key is locked for ``base_lockout`` seconds,
    doubling with each further failure up to ``max_lockout``. The failure count
    resets on success, or once ``window`` seconds pass without a failure.
    State is in memory, which matches the single-process Waitress deployment.
    """

    def __init__(
        self,
        max_failures: int = 5,
        base_lockout: float = 60.0,
        max_lockout: float = 900.0,
        window: float = 900.0,
        max_keys: int = 10_000,
    ) -> None:
        self._max_failures = max_failures
        self._base_lockout = base_lockout
        self._max_lockout = max_lockout
        self._window = window
        self._max_keys = max_keys
        self._lock = threading.Lock()
        # key -> (failure count, last failure time, locked until)
        self._state: dict[str, tuple[int, float, float]] = {}

    def retry_after(self, key: str) -> float:
        """Seconds until ``key`` may try again; 0 when not locked."""
        with self._lock:
            entry = self._state.get(key)
            if entry is None:
                return 0.0
            return max(0.0, entry[2] - time.monotonic())

    def failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            count, last, _ = self._state.get(key, (0, now, 0.0))
            if now - last > self._window:
                count = 0
            count += 1
            locked_until = 0.0
            if count >= self._max_failures:
                exponent = count - self._max_failures
                locked_until = now + min(self._base_lockout * (2 ** exponent), self._max_lockout)
            self._state[key] = (count, now, locked_until)
            if len(self._state) > self._max_keys:
                self._prune(now)

    def success(self, key: str) -> None:
        with self._lock:
            self._state.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._state.clear()

    def _prune(self, now: float) -> None:
        stale = [k for k, (_, last, until) in self._state.items()
                 if until <= now and now - last > self._window]
        for k in stale:
            del self._state[k]
        overflow = len(self._state) - self._max_keys
        if overflow > 0:
            oldest = sorted(self._state, key=lambda k: self._state[k][1])[:overflow]
            for k in oldest:
                del self._state[k]


def lockout_message(seconds: float) -> str:
    minutes = max(1, round(seconds / 60))
    unit = "minute" if minutes == 1 else "minutes"
    return f"Too many failed attempts. Try again in {minutes} {unit}."


def verify_totp(secret: str, code: str, last_step: int) -> int | None:
    """Return the matched time step for ``code``, or None.

    Accepts one step of clock drift either side, and rejects any step at or
    before ``last_step`` so a code cannot be replayed.
    """
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = totp.timecode(datetime.now(timezone.utc))
    for step in (current - 1, current, current + 1):
        if step <= last_step:
            continue
        if hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def is_cross_site_request(host: str, headers) -> bool:
    """True when a browser request did not come from this site's own pages.

    Prefers ``Sec-Fetch-Site``, which proxies do not rewrite. Falls back to
    comparing ``Origin`` with the Host (or X-Forwarded-Host, for reverse
    proxies that rewrite Host). Requests with neither header come from
    non-browser clients and are allowed.
    """
    fetch_site = headers.get("Sec-Fetch-Site")
    if fetch_site is not None:
        return fetch_site not in ("same-origin", "none")
    origin = headers.get("Origin")
    if origin is None:
        return False
    if origin == "null":
        return True
    allowed = {host}
    forwarded = headers.get("X-Forwarded-Host")
    if forwarded:
        allowed.update(h.strip() for h in forwarded.split(","))
    return urlparse(origin).netloc not in allowed
