"""Endpoint import install bundles: certificate, optional CA chain, and an install script."""
from __future__ import annotations

import io
import shutil
import subprocess
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

from app import crypto_engine, install_bundle

from .test_security import _create_ca


def _issue(client, ca_id: int, cn: str = "host.bundle.test", template: str = "web-server", **extra) -> int:
    resp = client.post(f"/api/ca/{ca_id}/certs",
                       json={"common_name": cn, "algorithm": "ecdsa-p256", "template": template, **extra})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["id"]


def _bundle(client, cert_id: int, **body):
    return client.post(f"/api/export/cert/{cert_id}/bundle", json={"password": "Bundle-pass-1", **body})


def _open(resp) -> zipfile.ZipFile:
    """The bundle; its files sit at the top, with no folder inside ("Extract All" makes one)."""
    assert resp.status_code == 200, resp.get_json()
    zf = zipfile.ZipFile(io.BytesIO(resp.data))
    assert not [n for n in zf.namelist() if "/" in n]
    return zf


def test_windows_bundle_with_ca_chain(admin_client):
    root = _create_ca(admin_client, "bundle.test")
    inter = _create_ca(admin_client, "inter.bundle.test", parent=root)
    cert_id = _issue(admin_client, inter)
    resp = _bundle(admin_client, cert_id, os="windows", include_ca=True)
    assert "host.bundle.test-install-windows.zip" in resp.headers["Content-Disposition"]
    zf = _open(resp)
    names = sorted(n for n in zf.namelist())
    assert names == ["README.txt", "ca-bundle.test_Root_CA.der", "ca-inter.bundle.test_Intermediate_CA.der",
                     "host.bundle.test.pfx", "install.cmd", "install.ps1", "uninstall.cmd", "uninstall.ps1"]
    script = zf.read("install.ps1").decode()
    assert "Start-Process -FilePath 'powershell.exe' -Verb RunAs" in script  # relaunches itself elevated
    # Easy to run: finds its folder, echoes each command, waits before the window closes
    assert "$here = $PSScriptRoot" in script and "PS> " in script and "Press Enter to close" in script
    assert "FAILED: " in script
    launcher = zf.read("install.cmd").decode()
    assert 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"' in launcher
    # root before the intermediate, each to its store, then the certificate
    assert script.index("ca-bundle.test_Root_CA.der") < script.index("ca-inter.bundle.test_Intermediate_CA.der")
    assert "'ca-bundle.test_Root_CA.der') -CertStoreLocation Cert:\\LocalMachine\\Root" in script
    assert "-CertStoreLocation Cert:\\LocalMachine\\CA" in script
    assert "Cert:\\LocalMachine\\My" in script and "$PSScriptRoot" in script
    readme = zf.read("README.txt").decode()
    assert "Double-click install.cmd" in readme and "running scripts is disabled" in readme
    key, cert, extra = pkcs12.load_key_and_certificates(zf.read("host.bundle.test.pfx"), b"Bundle-pass-1")
    assert cert.subject.rfc4514_string() == "CN=host.bundle.test" and len(extra) == 1  # issuer included


def test_windows_bundle_for_a_user_cert_without_ca_needs_no_admin(admin_client):
    ca_id = _create_ca(admin_client)
    cert_id = _issue(admin_client, ca_id, "alice", template="user")
    zf = _open(_bundle(admin_client, cert_id, os="windows", include_ca=False))
    script = zf.read("install.ps1").decode()
    assert "Start-Process -FilePath 'powershell.exe' -Verb RunAs" not in script and "run it as yourself" in script
    assert "Cert:\\CurrentUser\\My" in script and "LocalMachine" not in script
    assert not [n for n in zf.namelist() if n.startswith("ca-")]


def test_linux_server_bundle_has_chain_and_key_and_needs_no_password(admin_client):
    ca_id = _create_ca(admin_client, "lx.test")
    cert_id = _issue(admin_client, ca_id, "web.lx.test")
    resp = admin_client.post(f"/api/export/cert/{cert_id}/bundle", json={"os": "linux", "include_ca": True})
    zf = _open(resp)
    names = sorted(n for n in zf.namelist())
    assert names == ["README.txt", "ca-lx.test_Root_CA.pem", "install.sh", "web.lx.test-fullchain.pem", "web.lx.test.key"]
    script = zf.read("install.sh").decode()
    assert "update-ca-certificates" in script and "update-ca-trust" in script
    assert "/etc/ssl/private/'web.lx.test.key'" in script
    assert zf.getinfo("install.sh").external_attr >> 16 == 0o755
    assert zf.getinfo("web.lx.test.key").external_attr >> 16 == 0o600
    chain = x509.load_pem_x509_certificates(zf.read("web.lx.test-fullchain.pem"))
    assert len(chain) == 2


def test_macos_bundle(admin_client):
    ca_id = _create_ca(admin_client, "mac.test")
    cert_id = _issue(admin_client, ca_id, "mac.host")
    zf = _open(_bundle(admin_client, cert_id, os="macos", include_ca=True))
    script = zf.read("install.sh").decode()
    assert "add-trusted-cert -d -r trustRoot" in script and "sudo security import 'mac.host.pfx'" in script


def test_bundle_validation_and_odd_names(admin_client):
    ca_id = _create_ca(admin_client)
    cert_id = _issue(admin_client, ca_id, "x'; rm -rf /")
    assert _bundle(admin_client, cert_id, os="beos").status_code == 400
    resp = admin_client.post(f"/api/export/cert/{cert_id}/bundle", json={"os": "windows"})
    assert resp.status_code == 400 and "PFX password" in resp.get_json()["error"]
    zf = _open(_bundle(admin_client, cert_id, os="macos"))
    assert all("'" not in n and " " not in n for n in zf.namelist())
    script = zf.read("install.sh").decode()
    assert "rm -rf /'" not in script.split("security import", 1)[1].split("\n")[0]


def test_bundle_needs_a_recent_sign_in(admin_client):
    ca_id = _create_ca(admin_client)
    cert_id = _issue(admin_client, ca_id)
    with admin_client.session_transaction() as sess:
        sess.pop("reauth_at", None)
    resp = _bundle(admin_client, cert_id, os="windows")
    assert resp.status_code == 403 and resp.get_json()["reauth_required"]


def _parse_powershell(shell: str, script: str, label: str) -> None:
    check = ("$errs = $null; [System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(), "
             "[ref]$null, [ref]$errs) | Out-Null; if ($errs) { $errs | ForEach-Object { $_.Message }; exit 1 }")
    result = subprocess.run([shell, "-NoProfile", "-Command", check], input=script, capture_output=True, text=True,
                            timeout=60)
    assert result.returncode == 0, (label, result.stdout, result.stderr)


def test_powershell_scripts_parse():
    """Every .ps1 in a Windows bundle, parsed by PowerShell itself where it exists (CI's
    Windows job); skipped elsewhere."""
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        pytest.skip("PowerShell isn't installed here")
    ca_pem, ca_key, *_ = crypto_engine.create_ca(domain="ps.test", name="PS Root", algorithm="ecdsa-p256", lifetime_days=30)
    crl = crypto_engine.generate_crl(ca_cert_pem=ca_pem, ca_key_pem=ca_key, revoked_serials=[], crl_lifetime_days=30)
    for template in ("web-server", "user", "code-signing"):
        cert_pem, key_pem, *_ = crypto_engine.issue_certificate(
            ca_cert_pem=ca_pem, ca_key_pem=ca_key, common_name="o'brien.ps.test", san_domains=["ps.test"],
            algorithm="ecdsa-p256", lifetime_days=30, template=template)
        data, _ = install_bundle.build(cert_pem=cert_pem, key_pem=key_pem, template=template, common_name="o'brien.ps.test",
                                       os_name="windows", ca_chain=[("PS Root", ca_pem)], password="x",
                                       crl=("PS Root", crl), placeholder_url="http://pki.ps.test/crl/PS_Root.crl")
        zf = zipfile.ZipFile(io.BytesIO(data))
        for name in (n for n in zf.namelist() if n.endswith(".ps1")):
            _parse_powershell(shell, zf.read(name).decode(), f"{template} {name}")


def test_placeholder_certificate_bundles_the_crl(admin_client):
    ca_id = _create_ca(admin_client, "ph.test")
    revoked = _issue(admin_client, ca_id, "old.ph.test", crl_dp="placeholder")
    admin_client.post(f"/api/certs/{revoked}/revoke")
    cert_id = _issue(admin_client, ca_id, "user.ph.test", template="user", crl_dp="placeholder")
    zf = _open(_bundle(admin_client, cert_id, os="windows", include_ca=False))
    crl_name = "ph.test_Root_CA.crl"
    crl = x509.load_der_x509_crl(zf.read(crl_name))
    assert len(list(crl)) == 1  # the revoked certificate is on it
    script = zf.read("install.ps1").decode()
    # a CRL goes to the Local Machine store, so even a user certificate's script needs elevation
    assert "certutil.exe -f -addstore CA (Join-Path $here 'ph.test_Root_CA.crl')" in script
    assert "Start-Process -FilePath 'powershell.exe' -Verb RunAs" in script
    # ...and this machine answers the placeholder address itself
    assert "$crlHost = 'pki.ph.test'" in script and "$crlFile = 'ph.test_Root_CA.crl'" in script
    assert "sddl='D:(A;;GX;;;LS)'" in script and "-UserId 'LOCALSERVICE'" in script
    assert "'*S-1-5-19:(OI)(CI)RX'" in script  # the listener's account only reads the folder
    assert "serve-crl.ps1" in zf.namelist()
    serve = zf.read("serve-crl.ps1").decode()
    assert "'^/crl/([A-Za-z0-9._-]{1,120}\\.crl)$'" in serve and "StatusCode = 404" in serve
    undo = zf.read("uninstall.ps1").decode()
    assert "Remove-Cert 'Certificate' 'Cert:\\CurrentUser\\My\\" in undo
    assert "certutil.exe -delstore CA " in undo and "netsh.exe http delete urlacl" in undo
    assert "Unregister-ScheduledTask" in undo and "127.0.0.1 $crlHost # cert-generator" in undo
    readme = zf.read("README.txt").decode()
    for section in ("UNDO (BACK OUT)", "LOCAL CRL SERVER", "AFTER A REVOCATION", "TROUBLESHOOTING"):
        assert section in readme
    assert admin_client.get(f"/api/ca/{ca_id}").get_json()["crl_next_update"]  # recorded like Export CRL
    zf = _open(_bundle(admin_client, cert_id, os="linux"))
    assert "ph.test_Root_CA.crl" in zf.namelist()
    assert "no store for imported CRLs" in zf.read("install.sh").decode()


def test_local_crl_folder_made_by_someone_else_is_not_reused(admin_client):
    """Any user can create C:\\ProgramData\\CertGenerator first and keep owning it, then swap the
    script the listener runs as LOCAL SERVICE; the install moves such a folder (or a link) aside."""
    ca_id = _create_ca(admin_client, "own.test")
    cert_id = _issue(admin_client, ca_id, "host.own.test", crl_dp="placeholder")
    script = _open(_bundle(admin_client, cert_id, os="windows", include_ca=False)).read("install.ps1").decode()
    check = script.index("GetOwner([System.Security.Principal.SecurityIdentifier])")
    assert "$owner -ne 'S-1-5-32-544' -and $owner -ne 'S-1-5-18'" in script
    assert "[System.IO.FileAttributes]::ReparsePoint" in script
    assert "Rename-Item -LiteralPath $base -NewName $aside" in script and "Remove-Item -LiteralPath $base" not in script
    create = script.index("New-Item -ItemType Directory -Force -Path $crlDir")
    owner = script.index("icacls.exe $base /setowner '*S-1-5-32-544'")
    copy = script.index("'serve-crl.ps1') -Destination")
    assert check < create < owner < copy  # checked before use, owned by Administrators before the script lands


def test_uninstall_removes_only_what_the_bundle_installed(admin_client):
    root = _create_ca(admin_client, "un.test")
    cert_id = _issue(admin_client, root, "un.host")
    zf = _open(_bundle(admin_client, cert_id, os="windows", include_ca=True))
    undo = zf.read("uninstall.ps1").decode()
    assert "Cert:\\LocalMachine\\My\\" in undo
    assert "Cert:\\LocalMachine\\Root\\" in undo and "-RemoveCA" in undo and "Read-Host" in undo
    assert "CertGenerator" not in undo  # no local CRL server here: nothing of it to remove
    zf = _open(_bundle(admin_client, cert_id, os="windows", include_ca=False))
    assert "Cert:\\LocalMachine\\Root" not in zf.read("uninstall.ps1").decode()


def test_no_crl_without_a_placeholder(admin_client):
    ca_id = _create_ca(admin_client, "np.test")
    cert_id = _issue(admin_client, ca_id, "np.host")
    zf = _open(_bundle(admin_client, cert_id, os="windows"))
    assert not [n for n in zf.namelist() if n.endswith(".crl")]


def test_no_default_password(admin_client):
    ca_id = _create_ca(admin_client)
    cert_id = _issue(admin_client, ca_id)
    for url, body in ((f"/api/export/cert/{cert_id}/bundle", {"os": "windows"}),
                      (f"/api/export/cert/{cert_id}", {"format": "pkcs12", "part": "both"}),
                      (f"/api/export/ca/{ca_id}", {"format": "pkcs12", "part": "both"})):
        for password in ("changeit", " ChangeIt "):
            resp = admin_client.post(url, json={**body, "password": password})
            assert resp.status_code == 400 and "changeit" in resp.get_json()["error"], url
        assert admin_client.post(url, json=body).status_code == 400  # and none at all
