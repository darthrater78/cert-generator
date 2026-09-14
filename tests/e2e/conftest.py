"""Browser tests: run the real server and drive the UI with Playwright.

Run with:  python -m pytest -m e2e --browser chromium --browser firefox --browser webkit
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

pytest.importorskip("playwright")

ROOT = Path(__file__).resolve().parents[2]
ADMIN = "admin"
ADMIN_PASSWORD = "e2e-password-123"


@dataclass
class LiveServer:
    url: str
    db_dir: Path
    export_dir: Path
    process: subprocess.Popen = field(repr=False)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_server(base: Path) -> LiveServer:
    port = _free_port()
    db_dir, export_dir = base / "db", base / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "HOST": "127.0.0.1", "PORT": str(port), "DB_DIR": str(db_dir),
           "EXPORT_DIR": str(export_dir), "SECRET_KEY": "e2e-secret", "LOG_LEVEL": "WARNING"}
    log_file = open(base / "server.log", "wb")  # noqa: SIM115 - closed with the process
    proc = subprocess.Popen([sys.executable, "-m", "app.serve"], cwd=ROOT, env=env,
                            stdout=log_file, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url + "/login", timeout=1)  # noqa: S310 - local test server
            return LiveServer(url, db_dir, export_dir, proc)
        except OSError:
            if proc.poll() is not None:
                break
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError("server did not start:\n" + (base / "server.log").read_text(errors="replace"))


@pytest.fixture
def live_server(tmp_path) -> Iterator[LiveServer]:
    server = _start_server(tmp_path)
    try:
        yield server
    finally:
        server.process.terminate()
        server.process.wait(timeout=10)


@pytest.fixture
def browser_errors(page) -> list[str]:
    """Collects JavaScript errors and CSP violations; asserted empty after each test."""
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
    page.on("console", lambda msg: errors.append(f"console.{msg.type}: {msg.text}")
            if msg.type == "error" else None)
    page.on("dialog", lambda dialog: dialog.accept())
    yield errors
    real = [e for e in errors if "favicon" not in e]
    assert not real, "browser errors:\n" + "\n".join(real)


@pytest.fixture
def signed_in(page, live_server, browser_errors) -> Callable[[], None]:
    """Create the admin account through the setup page; the page is then signed in."""
    page.goto(live_server.url + "/")
    page.fill("#username", ADMIN)
    page.fill("#password", ADMIN_PASSWORD)
    page.fill("#confirm", ADMIN_PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(live_server.url + "/")
    page.wait_for_selector("#caList", state="attached")
    return page
