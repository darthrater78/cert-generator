"""PowerShell install / uninstall scripts and their .cmd launchers for Windows bundles.

Every script: finds its own folder ($PSScriptRoot), relaunches itself elevated when it
needs administrator rights, echoes each command before running it, stops at the first
failure with a plain explanation, and waits for Enter before the window closes. The .cmd
launchers exist because Windows refuses to run an unsigned .ps1 by default: a .cmd isn't
subject to the PowerShell execution policy, and it starts the script with the policy
bypassed for that one run.
"""
from __future__ import annotations

import re

from . import crl_local_server


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _c(s: str) -> str:
    return re.sub(r"[\r\n]+", " ", s)


_HELPERS = r"""$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot            # this script's folder, wherever the zip was extracted
Set-Location -LiteralPath $here

function Step([string]$what) { Write-Host ''; Write-Host "==> $what" -ForegroundColor Cyan }
function Run([scriptblock]$command) {
  # Show the command, run it, and turn a failing native command (certutil, netsh...) into an error.
  Write-Host ('    PS> ' + $command.ToString().Trim()) -ForegroundColor DarkGray
  $global:LASTEXITCODE = 0
  & $command
  if ($LASTEXITCODE -ne 0) { throw "The command above failed (exit code $LASTEXITCODE)." }
}
function Finish([int]$code) {
  Write-Host ''
  Read-Host 'Press Enter to close this window' | Out-Null
  exit $code
}
"""

_ELEVATE = r"""$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Host 'This needs administrator rights. Windows will ask for them now; the rest runs in a new window.' -ForegroundColor Yellow
  $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"')) + $passArgs
  try {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
  } catch {
    Write-Host "Couldn't get administrator rights: $($_.Exception.Message)" -ForegroundColor Red
    Finish 1
  }
  exit 0
}
"""


def launcher(script: str, what: str) -> bytes:
    """A double-click .cmd that runs ``script`` from its own folder, policy bypassed."""
    return "\r\n".join([
        "@echo off",
        f"rem Double-click to {what}. Runs {script} from this folder. The script is unsigned, so the",
        "rem PowerShell execution policy is bypassed for this one run (your setting doesn't change).",
        "rem The script asks for administrator rights itself when it needs them.",
        f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0{script}" %*',
        "if errorlevel 1 pause",
        "",
    ]).encode("ascii")


def install_script(*, cn: str, template: str, admin: bool, cas: list, pfx: str, der: str | None,
                   crl: str | None, local_server: tuple[str, str] | None, machine: bool) -> str:
    """install.ps1. ``cas``: objects with .name, .file, .is_root, root first."""
    store = "LocalMachine" if machine else "CurrentUser"
    lines = [
        f"# Installs {_c(cn)} ({template}), exported by Cert Generator.",
        "# Easiest: double-click install.cmd in this folder. Or, in PowerShell:",
        "#   powershell -ExecutionPolicy Bypass -File .\\install.ps1",
        "# Safe to run again (after a revocation, to update the CRL). Undo: uninstall.cmd.",
        "param()",
        _HELPERS,
        "$passArgs = @()",
    ]
    if admin:
        lines.append(_ELEVATE)
    else:
        lines.append("# No administrator rights needed: it installs into your own user store, so run it as yourself.")
    lines.append("try {")
    body: list[str] = []
    for ca in cas:
        target, label = ("Root", "Trusted Root Certification Authorities") if ca.is_root else \
            ("CA", "Intermediate Certification Authorities")
        body += [f"Step {_q(('Root' if ca.is_root else 'Intermediate') + ' CA ' + _c(ca.name) + ' -> ' + label)}",
                 f"Run {{ Import-Certificate -FilePath (Join-Path $here {_q(ca.file)}) -CertStoreLocation Cert:\\LocalMachine\\{target} | Out-Null }}"]
    body += [
        f"Step {_q('Certificate and key -> ' + ('Local Computer' if machine else 'Current User') + ' > Personal')}",
        "for ($try = 1; ; $try++) {",
        "  $pw = Read-Host -AsSecureString 'PFX password (the one you chose when downloading)'",
        "  try {",
        f"    Run {{ Import-PfxCertificate -FilePath (Join-Path $here {_q(pfx)}) -CertStoreLocation Cert:\\{store}\\My -Password $pw | Out-Null }}",
        "    break",
        "  } catch {",
        "    if ($try -ge 3) { throw }",
        "    Write-Host \"  That didn't work: $($_.Exception.Message) Try again ($try of 3).\" -ForegroundColor Yellow",
        "  }",
        "}",
    ]
    if crl:
        body += ["Step 'Revocation list -> Intermediate Certification Authorities (used by the Windows revocation check)'",
                 f"Run {{ certutil.exe -f -addstore CA (Join-Path $here {_q(crl)}) }}"]
    if der:
        body += ["Step 'Code signing: trust this publisher on this machine -> Trusted Publishers'",
                 f"Run {{ Import-Certificate -FilePath (Join-Path $here {_q(der)}) -CertStoreLocation Cert:\\LocalMachine\\TrustedPublisher | Out-Null }}"]
    if crl and local_server:
        body += crl_local_server.install_lines(local_server[0], local_server[1], crl)
    body += ["Write-Host ''",
             f"Write-Host {_q('Installed ' + _c(cn) + '.')} -ForegroundColor Green",
             "Write-Host 'To undo: double-click uninstall.cmd in this folder (README.txt explains what it removes).'"]
    lines += ["  " + line if line else "" for line in body]
    lines += [
        "} catch {",
        "  Write-Host ''",
        "  Write-Host ('FAILED: ' + $_.Exception.Message) -ForegroundColor Red",
        "  Write-Host 'Nothing after the failed step ran. README.txt (TROUBLESHOOTING) covers the usual causes;' -ForegroundColor Red",
        "  Write-Host 'fix it and run install.cmd again: it is safe to re-run.' -ForegroundColor Red",
        "  Finish 1",
        "}",
        "Finish 0",
        "",
    ]
    return "\r\n".join(lines)


def uninstall_script(*, cn: str, cert_thumb: str, cert_store: str, publisher_thumb: str | None,
                     ca_thumbs: list[tuple[str, str, str]], crl_hash: str | None,
                     host: str | None, crl_file: str | None) -> str:
    """uninstall.ps1: undoes what install.ps1 did, carrying on past failures and listing them.
    ``ca_thumbs``: (name, store, thumbprint) of CAs the bundle installed; removed only when
    confirmed (or -RemoveCA), since other certificates may rely on them."""
    lines = [
        f"# Removes what install.ps1 added for {_c(cn)}.",
        "# Easiest: double-click uninstall.cmd in this folder. Or, in PowerShell:",
        "#   powershell -ExecutionPolicy Bypass -File .\\uninstall.ps1 [-RemoveCA]",
        "# -RemoveCA also removes the CA certificates this bundle installed, without asking.",
        "param([switch]$RemoveCA)",
        _HELPERS,
        "$passArgs = @(if ($RemoveCA) { '-RemoveCA' })",
        _ELEVATE,
        "$failures = @()",
        "function Undo([string]$what, [scriptblock]$command) {",
        "  Step $what",
        "  try { Run $command } catch {",
        "    Write-Host \"    failed: $($_.Exception.Message)\" -ForegroundColor Yellow",
        "    $script:failures += $what",
        "  }",
        "}",
        "function Remove-Cert([string]$what, [string]$path) {",
        "  if (Test-Path -LiteralPath $path) { Undo $what ([scriptblock]::Create(\"Remove-Item -LiteralPath '$path'\")) }",
        "  else { Step $what; Write-Host '    not installed, nothing to remove' -ForegroundColor DarkGray }",
        "}",
        "",
        f"Remove-Cert 'Certificate' {_q('Cert:' + chr(92) + cert_store + chr(92) + 'My' + chr(92) + cert_thumb)}",
    ]
    if publisher_thumb:
        lines.append(f"Remove-Cert 'Trusted publisher' {_q('Cert:' + chr(92) + 'LocalMachine' + chr(92) + 'TrustedPublisher' + chr(92) + publisher_thumb)}")
    if crl_hash:
        lines += [
            "Step 'Revocation list (Intermediate Certification Authorities)'",
            f"& certutil.exe -store CA {crl_hash} 2>&1 | Out-Null",
            "if ($LASTEXITCODE -eq 0) {",
            f"  Undo '    remove it' {{ certutil.exe -delstore CA {crl_hash} }}",
            "} else {",
            "  Write-Host '    not installed, nothing to remove' -ForegroundColor DarkGray",
            "}",
        ]
    if host and crl_file:
        lines += crl_local_server.uninstall_lines(host, crl_file)
    if ca_thumbs:
        names = ", ".join(_c(n) for n, _, _ in ca_thumbs)
        lines += [
            "",
            "$removeCa = [bool]$RemoveCA",
            "if (-not $removeCa) {",
            f"  Write-Host ''",
            f"  $removeCa = (Read-Host {_q('Also remove the CA certificates this bundle installed (' + names + ')? Other certificates they issued stop being trusted on this machine. [y/N]')}) -match '^[yY]'",
            "}",
            "if ($removeCa) {",
        ]
        for name, store, thumb in ca_thumbs:
            lines.append(f"  Remove-Cert {_q('CA ' + _c(name))} {_q('Cert:' + chr(92) + 'LocalMachine' + chr(92) + store + chr(92) + thumb)}")
        lines += ["} else {", "  Write-Host '    CA certificates kept' -ForegroundColor DarkGray", "}"]
    lines += [
        "",
        "Write-Host ''",
        "if ($failures.Count) {",
        "  Write-Host ('Done, but these steps failed: ' + ($failures -join '; ')) -ForegroundColor Red",
        "  Write-Host 'README.txt shows how to remove them by hand.' -ForegroundColor Red",
        "  Finish 1",
        "}",
        f"Write-Host {_q('Removed ' + _c(cn) + '.')} -ForegroundColor Green",
        "Finish 0",
        "",
    ]
    return "\r\n".join(lines)
