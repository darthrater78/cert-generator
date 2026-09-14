"""Tests for the follow-up issues: CRL lifetime (#15), inline-script-free UI (#16),
legacy export cleanup (#17), blueprint split (#18), and SIGTERM handling (#19)."""
from __future__ import annotations

import os
import re
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509

from app import db, legacy_exports, server

from .conftest import ADMIN, ADMIN_PASSWORD

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "templates"
APP_JS = ROOT / "app" / "static" / "app.js"


def _create_ca(client, domain: str = "example.test") -> int:
    resp = client.post("/api/ca", json={"domain": domain, "algorithm": "ecdsa-p256"})
    assert resp.status_code == 201
    return resp.get_json()["id"]


# ── #15 CRL lifetime ────────────────────────────────────────────────

def _crl_days(der: bytes) -> float:
    crl = x509.load_der_x509_crl(der)
    return (crl.next_update_utc - crl.last_update_utc).total_seconds() / 86400


def test_crl_lifetime_defaults_to_ten_years(admin_client):
    ca_id = _create_ca(admin_client)
    resp = admin_client.get(f"/api/ca/{ca_id}/crl")
    assert resp.status_code == 200
    assert round(_crl_days(resp.data)) == 3650
    next_update = resp.headers["X-Next-Update"]
    assert admin_client.get(f"/api/ca/{ca_id}").get_json()["crl_next_update"] == next_update


def test_crl_lifetime_is_configurable(admin_client):
    ca_id = _create_ca(admin_client)
    resp = admin_client.get(f"/api/ca/{ca_id}/crl?days=30")
    assert round(_crl_days(resp.data)) == 30
    expected = datetime.now(timezone.utc) + timedelta(days=30)
    reported = datetime.strptime(resp.headers["X-Next-Update"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert abs((reported - expected).total_seconds()) < 60


@pytest.mark.parametrize("days", ["0", "3651", "abc", "-5"])
def test_crl_lifetime_rejects_out_of_range(admin_client, days):
    ca_id = _create_ca(admin_client)
    assert admin_client.get(f"/api/ca/{ca_id}/crl?days={days}").status_code == 400


def test_desktop_crl_export_reports_next_update(fresh_app):
    server.set_app_token("desktop-token")
    client = fresh_app.test_client()
    client.get("/_auth?token=desktop-token")
    ca_id = _create_ca(client)
    body = client.get(f"/api/ca/{ca_id}/crl?days=7").get_json()
    assert Path(body["path"]).is_file()
    assert body["next_update"].endswith("Z")


# ── #16 no inline script ────────────────────────────────────────────

def test_templates_have_no_inline_script_or_handlers():
    for template in TEMPLATES.glob("*.html"):
        text = template.read_text(encoding="utf-8")
        assert not re.search(r"\son[a-z]+\s*=", text), f"inline event handler in {template.name}"
        assert not re.search(r"<script(?![^>]*\ssrc=)[^>]*>", text), f"inline <script> in {template.name}"
        assert "javascript:" not in text, f"javascript: URL in {template.name}"


def test_every_ui_action_is_allowlisted_and_defined():
    js = APP_JS.read_text(encoding="utf-8")
    markup = "".join(t.read_text(encoding="utf-8") for t in TEMPLATES.glob("*.html")) + js
    used = set(re.findall(r'data-(?:action|change|enter)="(\w+)"', markup))
    allowlist = set(re.findall(r"'(\w+)'", js.split("const UI_ACTIONS = new Set([", 1)[1].split("]);", 1)[0]))
    assert used, "no data-action attributes found"
    assert used <= allowlist, f"not allowlisted: {sorted(used - allowlist)}"
    undefined = {name for name in allowlist if not re.search(rf"function\s+{name}\s*\(", js)}
    assert not undefined, f"allowlisted but undefined: {sorted(undefined)}"
    assert not re.search(r'\bon[a-z]+=\\?"', js), "inline handler markup built in JavaScript"


def test_app_script_is_served_and_referenced(admin_client):
    page = admin_client.get("/").get_data(as_text=True)
    assert re.search(r'<script src="/static/app\.js\?v=[\d.]+"></script>', page)
    assert 'data-server-mode="true"' in page
    resp = admin_client.get("/static/app.js")
    assert resp.status_code == 200
    assert b"UI_ACTIONS" in resp.data


# ── #17 legacy exports ──────────────────────────────────────────────

LEGACY_NAMES = [
    "ca-example.test-certificate.pfx",
    "ca-example.test-private_key.pem",
    "host.test-certificate (1).pem",
    "host.test-fullchain.pem",
    "Root_CA.crl",
    "deploy-key.pub",
    "deploy-key-id_key",
    "deploy-key-id_key (2).pem",
    "cert-generator-backup.certbak",
    "cert-generator-backup (3).certbak",
]
UNRELATED_NAMES = ["notes.txt", "vacation.jpg", "certificate.pem", "backup.certbak"]


@pytest.fixture
def export_dir(tmp_path, monkeypatch):
    directory = tmp_path / "exports"
    directory.mkdir()
    for name in LEGACY_NAMES + UNRELATED_NAMES:
        (directory / name).write_text("x", encoding="utf-8")
    (directory / "subdir").mkdir()
    (directory / "subdir" / "nested-certificate.pem").write_text("x", encoding="utf-8")
    outside = tmp_path / "outside-certificate.pem"
    outside.write_text("keep", encoding="utf-8")
    try:
        (directory / "link-certificate.pem").symlink_to(outside)
    except OSError:
        pass  # Windows without symlink privilege: the symlink case is covered on Linux
    monkeypatch.setenv("EXPORT_DIR", str(directory))
    return directory


def test_legacy_exports_match_only_old_export_names(export_dir):
    assert sorted(p.name for p in legacy_exports.find_legacy_exports()) == sorted(LEGACY_NAMES)


def test_legacy_export_cleanup_via_api(admin_client, export_dir):
    status = admin_client.get("/api/settings/legacy-exports").get_json()
    assert sorted(status["files"]) == sorted(LEGACY_NAMES)
    result = admin_client.post("/api/settings/legacy-exports/delete").get_json()
    assert result == {"ok": True, "deleted": len(LEGACY_NAMES), "failed": []}
    remaining = sorted(p.name for p in export_dir.iterdir())
    expected = UNRELATED_NAMES + ["subdir"]
    if (export_dir / "link-certificate.pem").is_symlink():
        expected.append("link-certificate.pem")
    assert remaining == sorted(expected)
    assert (export_dir.parent / "outside-certificate.pem").read_text(encoding="utf-8") == "keep"


def test_legacy_exports_ignored_without_explicit_export_dir(admin_client, monkeypatch):
    monkeypatch.delenv("EXPORT_DIR", raising=False)
    assert admin_client.get("/api/settings/legacy-exports").get_json()["files"] == []


def test_legacy_exports_never_touched_in_desktop_mode(fresh_app, export_dir):
    server.set_app_token("desktop-token")
    client = fresh_app.test_client()
    client.get("/_auth?token=desktop-token")
    assert client.get("/api/settings/legacy-exports").get_json()["files"] == []
    assert client.post("/api/settings/legacy-exports/delete").status_code == 404
    assert (export_dir / LEGACY_NAMES[0]).exists()


def test_legacy_cleanup_requires_login(client, export_dir):
    client.post("/setup", data={"username": ADMIN, "password": ADMIN_PASSWORD, "confirm": ADMIN_PASSWORD})
    client.post("/logout")
    assert client.post("/api/settings/legacy-exports/delete").status_code == 401
    assert (export_dir / LEGACY_NAMES[0]).exists()


# ── #18 structure ───────────────────────────────────────────────────

def test_routes_are_split_into_blueprints():
    assert {"auth", "account", "pki", "ssh", "settings"} <= set(server.app.blueprints)
    lines = (ROOT / "app" / "server.py").read_text(encoding="utf-8").count("\n")
    assert lines < 250


def test_intermediate_button_flag(admin_client):
    root = _create_ca(admin_client, "root.test")
    intermediate = admin_client.post(f"/api/ca/{root}/intermediate", json={"domain": "int.test"}).get_json()["id"]
    assert admin_client.get(f"/api/ca/{root}").get_json()["can_issue_intermediate"] is True
    assert admin_client.get(f"/api/ca/{intermediate}").get_json()["can_issue_intermediate"] is False


# ── #19 SIGTERM ─────────────────────────────────────────────────────

@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_server_exits_promptly_on_sigterm(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {**os.environ, "DB_DIR": str(tmp_path), "HOST": "127.0.0.1", "PORT": str(port), "SECRET_KEY": "x"}
    env.pop("EXPORT_DIR", None)
    proc = subprocess.Popen([sys.executable, "-m", "app.serve"], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.fail("server did not start")
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=5) == 0
        assert time.monotonic() - started < 3
    finally:
        if proc.poll() is None:
            proc.kill()


# ── Release notes: the changelog picks which deliverables ship ──────

sys.path.insert(0, str(ROOT / "scripts"))
import release_notes  # noqa: E402

BOTH = """## Version history

### v2.1.0 — 2026-09-20

Shared intro.

#### Docker
- Server change

#### Windows EXE
- Desktop change

### v2.0.0 — 2026-09-14

- Older entry
"""

DOCKER_ONLY = """## Version history

### v2.2.0 — 2026-09-25

#### Docker
- Server-only change

""" + BOTH.split("## Version history\n\n", 1)[1]

EXE_ONLY = """## Version history

### v2.2.0 — 2026-09-25

#### Windows EXE
- Desktop-only change

""" + BOTH.split("## Version history\n\n", 1)[1]


def test_release_notes_have_separate_docker_and_exe_sections():
    notes = release_notes.build_notes("2.1.0", BOTH, "sha256:abc", "deadbeef")
    docker = notes.index("## 🐳 Docker")
    exe = notes.index("## 🪟 Windows EXE")
    assert docker < exe
    assert "- Server change" in notes[docker:exe] and "- Desktop change" not in notes[docker:exe]
    assert "- Desktop change" in notes[exe:]
    assert "docker pull ghcr.io/darthrater78/cert-generator:2.1.0" in notes
    assert "`sha256:abc`" in notes and "`deadbeef`" in notes
    assert "compare/v2.0.0...v2.1.0" in notes


def test_release_notes_require_at_least_one_deliverable_section():
    readme = BOTH.replace("#### Docker\n- Server change\n\n", "").replace(
        "#### Windows EXE\n- Desktop change\n", "")
    with pytest.raises(release_notes.NotesError, match="nothing to release"):
        release_notes.build_notes("2.1.0", readme, None, None)
    with pytest.raises(release_notes.NotesError, match="v9.9.9"):
        release_notes.build_notes("9.9.9", BOTH, None, None)


def test_docker_only_release_reports_the_exe_as_unchanged():
    notes = release_notes.build_notes("2.2.0", DOCKER_ONLY, "sha256:abc", None)
    assert "- Server-only change" in notes
    assert "Windows EXE unchanged (2.1.0)" in notes
    assert "releases/download/v2.1.0/CertGenerator.exe" in notes
    assert "Download` CertGenerator.exe` from the assets" not in notes


def test_exe_only_release_reports_the_docker_image_as_unchanged():
    notes = release_notes.build_notes("2.2.0", EXE_ONLY, None, "deadbeef")
    assert "- Desktop-only change" in notes
    assert "Docker image unchanged (2.1.0)" in notes
    assert "docker pull ghcr.io/darthrater78/cert-generator:2.1.0" in notes
    assert "docker pull ghcr.io/darthrater78/cert-generator:2.2.0" not in notes


def test_entries_predating_the_split_count_as_both_deliverables():
    # Strip v2.1.0's subsections so it looks like a pre-split entry: it shipped
    # the image and the EXE together, so it is the last release of each.
    readme = EXE_ONLY.replace("#### Docker\n- Server change\n\n", "").replace(
        "#### Windows EXE\n- Desktop change\n", "")
    assert release_notes.previous_release_of(readme, "2.2.0", release_notes.DOCKER) == "2.1.0"
    assert release_notes.previous_release_of(readme, "2.2.0", release_notes.EXE) == "2.1.0"


def test_components_output_lists_what_the_version_ships(monkeypatch, capsys, tmp_path):
    for readme, expected in ((BOTH, "docker=true\nexe=true\n"),
                             (DOCKER_ONLY, "docker=true\nexe=false\n"),
                             (EXE_ONLY, "docker=false\nexe=true\n")):
        (tmp_path / "README.md").write_text(readme, encoding="utf-8")
        monkeypatch.setattr(release_notes, "ROOT", tmp_path)
        version = "2.1.0" if readme is BOTH else "2.2.0"
        assert release_notes.main([f"v{version}", "--components"]) == 0
        assert capsys.readouterr().out == expected
