"""Install bundles: one .zip with a certificate, optionally its CA chain, and an install
script for Windows (PowerShell), macOS or Linux (sh) that runs from the extracted folder.

The script does what the Endpoint import panel shows, with paths next to the script
instead of in Downloads. Every file name in the zip is reduced to [A-Za-z0-9._-], so
nothing in a script can be broken out of by a CA or certificate name.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import crl_local_server, crypto_engine, windows_scripts
from .errors import UserError

OSES = ("windows", "macos", "linux")
MACHINE_TEMPLATES = {"web-server", "computer"}


@dataclass(frozen=True)
class CaFile:
    name: str      # CA display name, for comments
    file: str      # file name in the zip
    data: bytes
    is_root: bool


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._") or "file"


def _ps(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _sh(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _comment(s: str) -> str:
    return re.sub(r"[\r\n]+", " ", s)  # a name can't end the comment line early


def needs_admin(template: str, include_ca: bool, include_crl: bool = False) -> bool:
    """Windows: the commands write to a Local Machine store, so PowerShell must run as Administrator."""
    return include_ca or include_crl or template in MACHINE_TEMPLATES or template == "code-signing"


def _sh_header(cn: str, template: str) -> list[str]:
    return [
        "#!/bin/sh",
        f"# Installs {_comment(cn)} ({template}), exported by Cert Generator.",
        "# Run it from anywhere: sh install.sh  (sudo asks for your password)",
        "set -eu",
        'cd "$(dirname "$0")"   # this script\'s folder, wherever the zip was extracted',
        "step() { printf '\\n==> %s\\n' \"$1\"; }",
        "run() { printf '    $ %s\\n' \"$*\"; \"$@\"; }   # show each command, then run it",
        "trap 'rc=$?; if [ $rc -ne 0 ]; then printf \"\\nFAILED (exit %s): nothing after the failed step ran. Fix it and run sh install.sh again; it is safe to re-run.\\n\" \"$rc\" >&2; fi' EXIT",
        "",
    ]


_CRL_NOTE = ("# {crl} is this CA's revocation list. This system has no store for imported CRLs: "
             "give it to software that checks revocation itself, if any.")


def _macos_script(cn: str, template: str, cas: list[CaFile], pfx: str, crl: str | None) -> str:
    machine = template in MACHINE_TEMPLATES
    keychain = "/Library/Keychains/System.keychain" if machine else '"$HOME/Library/Keychains/login.keychain-db"'
    lines = _sh_header(cn, template)
    for ca in cas:
        lines.append(f"step {_sh(('Root' if ca.is_root else 'Intermediate') + ' CA ' + _comment(ca.name) + ' -> System keychain')}")
        lines.append(f"run sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {_sh(ca.file)}"
                     if ca.is_root else f"run sudo security add-certificates -k /Library/Keychains/System.keychain {_sh(ca.file)}")
    lines += [f"step {_sh('Certificate and key -> ' + ('System keychain' if machine else 'your login keychain') + ' (asks for the PFX password)')}",
              f"run {'sudo ' if machine else ''}security import {_sh(pfx)} -k {keychain}"
              + (" -T /usr/bin/codesign" if template == "code-signing" else "")]
    if crl:
        lines.append(_CRL_NOTE.format(crl=_comment(crl)))
    lines += [f"printf '\\n%s\\n' {_sh('Installed ' + _comment(cn) + '.')}", ""]
    return "\n".join(lines)


def _linux_script(cn: str, template: str, root: CaFile | None, files: dict[str, str], crl: str | None) -> str:
    lines = _sh_header(cn, template)
    if root:
        anchor = _sh("cert-generator-" + _safe(root.name) + ".crt")
        lines += [f"step {_sh('Root CA ' + _comment(root.name) + ' -> system trust store')}",
                  "if command -v update-ca-certificates >/dev/null 2>&1; then",
                  f"  run sudo cp {_sh(root.file)} /usr/local/share/ca-certificates/{anchor}",
                  "  run sudo update-ca-certificates",
                  "elif command -v update-ca-trust >/dev/null 2>&1; then",
                  f"  run sudo cp {_sh(root.file)} /etc/pki/ca-trust/source/anchors/{anchor}",
                  "  run sudo update-ca-trust",
                  "else",
                  "  echo 'FAILED: no update-ca-certificates or update-ca-trust here. Add the CA to the trust store by hand.' >&2",
                  "  exit 1",
                  "fi"]
    if template in MACHINE_TEMPLATES:
        base = _safe(cn)
        lines += ["step 'Certificate chain and key -> /etc/ssl (point nginx or Apache at these paths)'",
                  f"run sudo install -m 644 {_sh(files['fullchain'])} /etc/ssl/certs/{_sh(base + '.pem')}",
                  f"run sudo install -m 600 {_sh(files['key'])} /etc/ssl/private/{_sh(base + '.key')}"]
    elif template != "code-signing":
        lines += ["step 'Certificate and key -> Chrome / Chromium (Firefox: Settings > Certificates > Import)'",
                  "if ! command -v pk12util >/dev/null 2>&1; then",
                  "  echo 'FAILED: pk12util is missing. Install libnss3-tools (Debian/Ubuntu) or nss-tools (RHEL/Fedora).' >&2",
                  "  exit 1",
                  "fi",
                  'run mkdir -p "$HOME/.pki/nssdb"',
                  f'run pk12util -d "sql:$HOME/.pki/nssdb" -i {_sh(files["pfx"])}']
    else:
        lines.append(f"# Code signing: use {_comment(files['pfx'])} with your signing tool, such as osslsigncode.")
    if crl:
        lines.append(_CRL_NOTE.format(crl=_comment(crl)))
    lines += [f"printf '\\n%s\\n' {_sh('Installed ' + _comment(cn) + '.')}", ""]
    return "\n".join(lines)


def _readme(cn: str, os_name: str, admin: bool, names: list[str], local_server: tuple[str, str] | None,
            has_crl: bool) -> str:
    shell = ("PowerShell as Administrator (Start, type PowerShell, right-click it, Run as administrator)"
             if admin else "PowerShell normally, not as administrator")
    if os_name == "windows":
        text = [f"Install {cn}", "",
                "INSTALL",
                "1. Optional, avoids a warning: right-click the .zip, Properties, tick Unblock, OK.",
                "2. Extract the .zip (anywhere).",
                "3. Double-click install.cmd." + (" Windows asks for administrator rights; say Yes." if admin else
                                                  " It runs as you: no administrator rights needed."),
                "   If Windows says the publisher could not be verified, choose Run.",
                "   It shows each command as it runs, stops with an explanation if a step fails, and waits",
                "   for Enter before closing. It asks for the PFX password you chose when downloading.",
                "   Safe to run again.",
                "",
                "UNDO (BACK OUT)",
                "   Double-click uninstall.cmd in this folder. It removes the certificate" +
                (", the imported CRL" if has_crl else "") + (" and the local CRL server" if local_server else "") +
                ",",
                "   then asks before removing any CA certificate this bundle installed. From PowerShell:",
                "   powershell -ExecutionPolicy Bypass -File .\\uninstall.ps1 -RemoveCA   (removes them without asking)",
                "   Keep this folder: uninstall.ps1 knows exactly what this bundle installed.",
                "",
                "IF WINDOWS REFUSES TO RUN THE SCRIPT",
                "- \"running scripts is disabled on this system\": you ran install.ps1 directly. Use install.cmd,",
                "  or:  powershell -ExecutionPolicy Bypass -File .\\install.ps1   (bypasses the policy for this run only).",
                "- \"... is not digitally signed\" even with install.cmd: a Group Policy enforces AllSigned and",
                "  overrides Bypass. Run the commands by hand (Cert Generator shows them under Export / install),",
                "  or ask your administrator.",
                "- SmartScreen or \"publisher could not be verified\": choose Run, or unblock the .zip (step 1)."]
        if local_server:
            host, crl_file = local_server
            text += ["",
                     "LOCAL CRL SERVER",
                     f"This certificate's CRL is endpoint-hosted: its address, http://{host}/crl/{crl_file},",
                     "is one no server on the network answers. So that programs which download the CRL still find it, install.ps1",
                     "makes this machine answer that address itself, with only what Windows already has:",
                     f"  - hosts file: adds  127.0.0.1 {host} {crl_local_server.MARK}",
                     f"    ({host} then resolves to this machine only, here; if it ever becomes a real site, this",
                     "    machine won't reach it until you undo this)",
                     f"  - C:\\ProgramData\\CertGenerator: the CRL, serve-crl.ps1 and crl-hosts.txt; only Administrators",
                     "    and SYSTEM can change it, so nobody can swap the script or restore an older CRL",
                     f"  - netsh http urlacl: reserves only http://{host}:80/crl/ for the LOCAL SERVICE account",
                     f"  - scheduled task '{crl_local_server.TASK_NAME}': runs serve-crl.ps1 at boot as LOCAL SERVICE.",
                     "    It answers GET/HEAD for /crl/<name>.crl from that folder and 404 for anything else.",
                     "Port 80 is shared with IIS (both use Windows' HTTP.sys). No firewall rule is added, so",
                     "other machines can't reach it unless you open port 80 yourself.",
                     "",
                     "Check it:  certutil -verify -urlfetch <certificate.cer>   or open the address in a browser.",
                     "",
                     "AFTER A REVOCATION",
                     "Nothing updates this copy by itself. Download a new bundle from Cert Generator and run its",
                     "install.cmd: it replaces the CRL and restarts the server. Until then this machine doesn't",
                     "see the revocation.",
                     "",
                     "UNDO BY HAND (if uninstall.cmd can't run)",
                     f"  - hosts file: delete the line ending in {crl_local_server.MARK}",
                     f"  - netsh http delete urlacl url=http://{host}:80/crl/",
                     f"  - Task Scheduler: delete '{crl_local_server.TASK_NAME}', then delete C:\\ProgramData\\CertGenerator",
                     "  - certlm.msc: remove the certificate (Personal) and the CRL (Intermediate Certification",
                     "    Authorities > Certificate Revocation List)",
                     "",
                     "TROUBLESHOOTING",
                     "- 'didn't answer': another program owns port 80 without HTTP.sys (e.g. Apache, nginx).",
                     "  netstat -ano | findstr :80   shows which one.",
                     "- A proxy: Windows' revocation check skips the proxy for this name only if WinHTTP does;",
                     "  netsh winhttp show proxy  -- add the host to the bypass list if one is set.",
                     "- Security tools may report the hosts-file change and the new startup task. That is this",
                     "  install; undo it with uninstall.cmd."]
        elif has_crl:
            text += ["", "CRL",
                     "The certificate's CRL is endpoint-hosted. install.ps1 imports the CRL into the",
                     "Intermediate Certification Authorities store, where Windows' own revocation check finds it.",
                     "After a revocation, run a new bundle's install.cmd to import the updated CRL."]
        text += ["", "FILES", *("  " + n for n in names), ""]
        return "\r\n".join(text)
    where = "Terminal" if os_name == "macos" else "a shell"
    text = [f"Install {cn}", "", "1. Extract this zip.", f"2. In {where}, go to the extracted folder.", "3. Run:  sh install.sh"]
    if has_crl:
        text += ["", "CRL",
                 "The certificate's CRL is endpoint-hosted. The CRL is in this folder; this system has no",
                 "store for imported CRLs, and the local CRL server is Windows-only for now."]
    text += ["", "FILES", *("  " + n for n in names), ""]
    return "\n".join(text)


def build(*, cert_pem: bytes, key_pem: bytes, template: str, common_name: str,
          os_name: str, ca_chain: list[tuple[str, bytes]], password: str | None,
          chain_for_pfx: list[tuple[str, bytes]] | None = None,
          crl: tuple[str, bytes] | None = None, placeholder_url: str | None = None) -> tuple[bytes, str]:
    """The bundle zip and its file name. ``ca_chain``: (name, cert PEM), issuing CA first,
    root last, to install; empty to leave the CAs out (already trusted). ``chain_for_pfx``:
    the full chain, so the .pfx and the server full chain always carry the issuer. ``crl``:
    (issuing CA name, DER) for a certificate whose distribution point is the placeholder,
    so the endpoint gets the revocation list it can't fetch. ``placeholder_url``: that address;
    on Windows the bundle then also sets up a local CRL server answering it (crl_local_server)."""
    chain_for_pfx = chain_for_pfx if chain_for_pfx is not None else ca_chain
    if os_name not in OSES:
        raise UserError(f"Choose an OS: {', '.join(OSES)}")
    cn = _safe(common_name)
    stem = f"{cn}-install-{os_name}"
    linux_server = os_name == "linux" and template in MACHINE_TEMPLATES
    if not linux_server and not password:
        raise UserError("Choose a PFX password: the install script asks for it")

    der_fmt = os_name != "linux"
    cas: list[CaFile] = []
    for i, (name, pem) in enumerate(reversed(ca_chain)):  # root first: trust it before the rest
        cert = x509.load_pem_x509_certificate(pem)
        data = cert.public_bytes(serialization.Encoding.DER) if der_fmt else pem
        cas.append(CaFile(name=name, file=f"ca-{_safe(name)}.{'der' if der_fmt else 'pem'}", data=data, is_root=i == 0))
    if os_name == "linux":
        cas = cas[:1]  # the system bundle needs only the root

    files: dict[str, bytes] = {}
    names = {"pfx": f"{cn}.pfx", "der": f"{cn}.der", "fullchain": f"{cn}-fullchain.pem", "key": f"{cn}.key"}
    if linux_server:
        files[names["fullchain"]] = b"".join([cert_pem, *(pem for _, pem in chain_for_pfx)])
        files[names["key"]] = crypto_engine.export_private_only(key_pem, "pem")[0]
    else:
        issuer = chain_for_pfx[0][1] if chain_for_pfx else None
        files[names["pfx"]] = crypto_engine.export_certificate(cert_pem, key_pem, "pkcs12",
                                                               ca_cert_pem=issuer, password=password)[0]
    win_der = os_name == "windows" and template == "code-signing"
    if win_der:
        files[names["der"]] = crypto_engine.export_public_only(cert_pem, "der")[0]
    local_server = None
    if crl and os_name == "windows" and placeholder_url:
        local_server = crl_local_server.placeholder_parts(placeholder_url)
    # On Windows the CRL keeps the name the address asks for, so the server can serve it as is.
    crl_name = (local_server[1] if local_server else f"{_safe(crl[0])}.crl") if crl else None
    if crl:
        files[crl_name] = crl[1]
    if local_server:
        files["serve-crl.ps1"] = crl_local_server.SERVE_PS1.replace("\n", "\r\n").encode("utf-8")

    if os_name == "windows":
        script_name = "install.ps1"
        script = windows_scripts.install_script(
            cn=common_name, template=template, admin=needs_admin(template, bool(cas), bool(crl)), cas=cas,
            pfx=names["pfx"], der=names["der"] if win_der else None, crl=crl_name, local_server=local_server,
            machine=template in MACHINE_TEMPLATES)
        files["install.cmd"] = windows_scripts.launcher("install.ps1", "install")
        files["uninstall.cmd"] = windows_scripts.launcher("uninstall.ps1", "undo the install")
        thumb = lambda der: hashlib.sha1(der, usedforsecurity=False).hexdigest().upper()  # noqa: E731 - Windows thumbprint
        cert_der = x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER)
        files["uninstall.ps1"] = windows_scripts.uninstall_script(
            cn=common_name, cert_thumb=thumb(cert_der),
            cert_store="LocalMachine" if template in MACHINE_TEMPLATES else "CurrentUser",
            publisher_thumb=thumb(cert_der) if win_der else None,
            ca_thumbs=[(ca.name, "Root" if ca.is_root else "CA", thumb(ca.data)) for ca in cas],
            crl_hash=thumb(crl[1]).lower() if crl else None,
            host=local_server[0] if local_server else None, crl_file=local_server[1] if local_server else None,
        ).encode("utf-8")
    elif os_name == "macos":
        script_name, script = "install.sh", _macos_script(common_name, template, cas, names["pfx"], crl_name)
    else:
        script_name, script = "install.sh", _linux_script(common_name, template, cas[0] if cas else None, names, crl_name)

    all_names = [script_name, *(c.file for c in cas), *files]
    readme = _readme(common_name, os_name, needs_admin(template, bool(cas), bool(crl)), all_names, local_server, bool(crl))
    out = io.BytesIO()
    stamp = datetime.now(timezone.utc).timetuple()[:6]
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        def add(name: str, data: bytes, mode: int = 0o644) -> None:
            # Files at the top: "Extract All" already makes the folder (named after the zip).
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
        add("README.txt", readme.encode("utf-8"))
        add(script_name, script.encode("utf-8"), 0o755)
        for ca in cas:
            add(ca.file, ca.data)
        for name, data in files.items():
            add(name, data, 0o600 if name.endswith((".key", ".pfx")) else 0o755 if name.endswith(".ps1") else 0o644)
    return out.getvalue(), f"{stem}.zip"
