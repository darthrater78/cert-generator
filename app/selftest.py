"""Packaging self-test for the desktop build, run by CI against the built EXE.

    CertGenerator.exe --self-test result.json      core checks, no window
    CertGenerator.exe --self-test-gui result.json  also opens the real window

Everything runs against a throwaway database and export folder, never the
user's own data. The windowed EXE has no console, so results go to a JSON file;
the exit code is 0 only when every check passed.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import traceback
from collections.abc import Callable
from pathlib import Path

GUI_TIMEOUT_SECONDS = 60


class _Checks:
    def __init__(self) -> None:
        self.results: list[dict[str, object]] = []

    def run(self, name: str, check: Callable[[], object]) -> object:
        try:
            detail = check()
            self.results.append({"name": name, "ok": True, "detail": detail})
            return detail
        except Exception as exc:  # report every failure, keep checking
            self.results.append({"name": name, "ok": False, "detail": f"{exc!r}",
                                 "traceback": traceback.format_exc()})
            return None

    @property
    def ok(self) -> bool:
        return bool(self.results) and all(r["ok"] for r in self.results)


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _core_checks(checks: _Checks, workdir: Path, export_dir: Path) -> None:
    import webview

    from . import __version__, db, server

    checks.run("pywebview importable", lambda: getattr(webview, "__version__", "unknown"))
    checks.run("database in self-test dir", lambda: _expect(Path(db.DB_PATH).is_relative_to(workdir), str(db.DB_PATH)))

    server.set_app_token("self-test-token")
    server.set_bound_port(5174)
    client = server.app.test_client()

    def auth() -> str:
        resp = client.get("/_auth?token=self-test-token")
        _expect(resp.status_code == 302, f"/_auth returned {resp.status_code}")
        return "token cookie set"

    def page() -> str:
        html = client.get("/").get_data(as_text=True)
        _expect(f"v{__version__}" in html, "version label missing")
        _expect(f"/static/app.js?v={__version__}" in html, "app.js reference missing")
        return __version__

    def static_files() -> str:
        for path in ("/static/app.js", "/static/icon.ico"):
            resp = client.get(path)
            _expect(resp.status_code == 200 and resp.data, f"{path} returned {resp.status_code}")
        return "app.js, icon.ico"

    def pki() -> str:
        ca = client.post("/api/ca", json={"domain": "selftest.example", "algorithm": "ecdsa-p256"})
        _expect(ca.status_code == 201, f"create CA: {ca.status_code} {ca.get_data(as_text=True)}")
        ca_id = ca.get_json()["id"]
        cert = client.post(f"/api/ca/{ca_id}/certs", json={"common_name": "host.selftest.example"})
        _expect(cert.status_code == 201, f"issue cert: {cert.status_code}")
        export = client.post(f"/api/export/cert/{cert.get_json()['id']}", json={"format": "pkcs12", "password": "x"})  # nosec B105 - throwaway self-test database
        path = Path(export.get_json()["path"])
        _expect(path.parent == export_dir and path.stat().st_size > 0, f"export path {path}")
        crl = client.get(f"/api/ca/{ca_id}/crl?days=30").get_json()
        _expect(bool(crl.get("next_update")), "CRL next_update missing")
        return "CA, certificate, PKCS#12 export, CRL"

    def encryption() -> str:
        enable = client.post("/api/settings/encryption/enable", json={"password": "selftest-pass", "confirm": "selftest-pass"})  # nosec B105 - throwaway self-test database
        _expect(enable.status_code == 200, f"enable: {enable.status_code}")
        db.set_master_key(None)
        _expect(client.post("/api/ca", json={"domain": "locked.example"}).status_code == 423, "locked write allowed")
        unlock = client.post("/api/settings/encryption/unlock", json={"password": "selftest-pass"})  # nosec B105 - throwaway self-test database
        _expect(unlock.status_code == 200, f"unlock: {unlock.status_code}")
        return "enable, locked refusal, unlock"

    checks.run("desktop token auth", auth)
    checks.run("index page renders", page)
    checks.run("static files bundled", static_files)
    checks.run("certificate operations", pki)
    checks.run("database encryption", encryption)


def _gui_check(checks: _Checks) -> None:
    import webview

    from .main import WINDOW_OPTIONS, Api, start_desktop_server

    server, url = start_desktop_server()
    outcome: dict[str, object] = {}
    window = webview.create_window("Cert Generator self-test", url, js_api=Api(), **WINDOW_OPTIONS)

    def inspect() -> None:
        try:
            outcome["version"] = window.evaluate_js("document.querySelector('.version').textContent")
            outcome["actions"] = window.evaluate_js("typeof runAction === 'function' && UI_ACTIONS.size")
            # The JS bridge is injected asynchronously; give it a few seconds.
            for _ in range(50):
                outcome["bridge"] = window.evaluate_js("!!(window.pywebview && window.pywebview.api)")
                if outcome["bridge"] is True:
                    break
                time.sleep(0.2)
        except Exception as exc:
            outcome["error"] = repr(exc)
        finally:
            window.destroy()

    started = threading.Event()

    def on_loaded() -> None:
        if not started.is_set():
            started.set()
            threading.Thread(target=inspect, daemon=True).start()

    def give_up() -> None:
        outcome.setdefault("error", f"window did not load within {GUI_TIMEOUT_SECONDS}s")
        window.destroy()

    window.events.loaded += on_loaded
    timer = threading.Timer(GUI_TIMEOUT_SECONDS, give_up)
    timer.start()
    webview.start()
    timer.cancel()
    server.shutdown()

    def verify() -> dict[str, object]:
        _expect("error" not in outcome, str(outcome.get("error")))
        _expect(str(outcome.get("version", "")).startswith("v"), f"version label: {outcome.get('version')!r}")
        _expect(bool(outcome.get("actions")), "app.js did not initialise")
        _expect(outcome.get("bridge") is True, "pywebview JS bridge missing")
        return outcome

    checks.run("webview window loads UI", verify)


def run(gui: bool, output: str | None) -> int:
    workdir = Path(tempfile.mkdtemp(prefix="certgen-selftest-"))
    export_dir = workdir / "exports"
    export_dir.mkdir()
    os.environ["DB_DIR"] = str(workdir / "db")
    os.environ["EXPORT_DIR"] = str(export_dir)
    checks = _Checks()
    try:
        _core_checks(checks, workdir, export_dir)
        if gui:
            _gui_check(checks)
    finally:
        report = {"ok": checks.ok, "frozen": getattr(sys, "frozen", False), "checks": checks.results}
        text = json.dumps(report, indent=2, default=str)
        if output:
            Path(output).write_text(text, encoding="utf-8")
        elif sys.stdout is not None:
            print(text)
        shutil.rmtree(workdir, ignore_errors=True)
    return 0 if checks.ok else 1
