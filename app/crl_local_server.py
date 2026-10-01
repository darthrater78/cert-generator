"""A local CRL server for Windows endpoints, for certificates whose CRL distribution point
is the placeholder (http://pki.<domain>/crl/<CA>.crl) when the endpoint can reach neither
this app's server nor a Cloudflare Worker.

Everything is built into Windows: a hosts-file entry sends the placeholder hostname to
127.0.0.1, and a PowerShell HttpListener (on HTTP.sys, shared with IIS) answers GET/HEAD
for /crl/<name>.crl from C:\\ProgramData\\CertGenerator\\crl and 404s everything else. A
scheduled task starts it at boot as LOCAL SERVICE, which may use only the reserved
/crl/ address. Admins alone can change the folder, so a user can't swap the script (which
runs as that account) or put back an older CRL that hides a revocation.

One listener serves every placeholder host installed on the machine (crl-hosts.txt), so
several CAs can share it; uninstall removes a host and stops the listener with the last one.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .errors import UserError

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
FILE_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}\.crl$")
TASK_NAME = "Cert Generator CRL server"
MARK = "# cert-generator"

# The listener. It reads its hosts and files from the protected folder on every start.
SERVE_PS1 = r"""# Cert Generator local CRL server: answers GET/HEAD http://<host>/crl/<name>.crl from
# C:\ProgramData\CertGenerator\crl for each host in crl-hosts.txt, 404 for anything else.
# Started at boot by the 'Cert Generator CRL server' scheduled task as LOCAL SERVICE.
$ErrorActionPreference = 'Stop'
$base = Join-Path $env:ProgramData 'CertGenerator'
$crlDir = Join-Path $base 'crl'
$hosts = @(Get-Content -LiteralPath (Join-Path $base 'crl-hosts.txt') | Where-Object { $_ -match '^[a-z0-9.-]+$' })
if (-not $hosts) { exit 0 }
$listener = New-Object System.Net.HttpListener
foreach ($h in $hosts) { $listener.Prefixes.Add("http://$($h):80/crl/") }
$listener.Start()
while ($listener.IsListening) {
  $ctx = $listener.GetContext()
  try {
    $req = $ctx.Request
    $res = $ctx.Response
    $path = $req.Url.AbsolutePath
    $file = $null
    if ($path -match '^/crl/([A-Za-z0-9._-]{1,120}\.crl)$') { $file = Join-Path $crlDir $Matches[1] }
    if (($req.HttpMethod -eq 'GET' -or $req.HttpMethod -eq 'HEAD') -and $file -and (Test-Path -LiteralPath $file -PathType Leaf)) {
      $bytes = [System.IO.File]::ReadAllBytes($file)
      $res.ContentType = 'application/pkix-crl'
      $res.ContentLength64 = $bytes.Length
      $res.AddHeader('Cache-Control', 'public, max-age=300')
      if ($req.HttpMethod -eq 'GET') { $res.OutputStream.Write($bytes, 0, $bytes.Length) }
    } else {
      $res.StatusCode = 404
    }
  } catch {
  } finally {
    $ctx.Response.Close()
  }
}
"""


def placeholder_parts(url: str) -> tuple[str, str]:
    """(host, CRL file name) of a placeholder distribution point, checked for script use."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    name = parts.path.rsplit("/", 1)[-1]
    if parts.scheme != "http" or parts.port not in (None, 80) or not parts.path.startswith("/crl/") \
            or not HOST_RE.match(host) or not FILE_RE.match(name) or parts.path != f"/crl/{name}":
        raise UserError("This certificate's placeholder CRL address can't be served locally")
    return host, name


def install_lines(host: str, crl_file: str, bundled_crl: str) -> list[str]:
    """install.ps1 steps (inside its try block, elevated; Step/Run/$here come from windows_scripts)."""
    q = lambda s: "'" + s.replace("'", "''") + "'"  # noqa: E731
    return [
        "",
        f"# Local CRL server: nothing on the network answers http://{host}/crl/{crl_file},",
        "# so this machine answers it itself. README.txt lists every change and how to undo it.",
        f"$crlHost = {q(host)}",
        f"$crlFile = {q(crl_file)}",
        "$base = Join-Path $env:ProgramData 'CertGenerator'",
        "$crlDir = Join-Path $base 'crl'",
        "Step \"Local CRL server: folder $base (Administrators change it, the listener only reads it)\"",
        # Any user can create folders in ProgramData. One they made in advance (or a junction
        # to somewhere else) would stay theirs, and they could then swap the script the
        # listener runs as LOCAL SERVICE, so it is moved aside, not reused or followed.
        "if (Test-Path -LiteralPath $base) {",
        "  try {",
        "    $item = Get-Item -LiteralPath $base -Force",
        "    $owner = (Get-Acl -LiteralPath $base).GetOwner([System.Security.Principal.SecurityIdentifier]).Value",
        "    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { $owner = 'a link' }",
        "  } catch { $owner = 'unreadable' }",
        "  if ($owner -ne 'S-1-5-32-544' -and $owner -ne 'S-1-5-18') {",
        "    $aside = 'CertGenerator.untrusted-' + (Get-Date -Format 'yyyyMMddHHmmss')",
        "    Write-Host \"    $base isn't owned by Administrators ($owner): moving it aside as $aside\" -ForegroundColor Yellow",
        "    Run { Rename-Item -LiteralPath $base -NewName $aside }",
        "  }",
        "}",
        "Run { New-Item -ItemType Directory -Force -Path $crlDir | Out-Null }",
        "Run { icacls.exe $base /setowner '*S-1-5-32-544' | Out-Null }",
        "Run { icacls.exe $base /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' | Out-Null }",
        f"Run {{ Copy-Item -LiteralPath (Join-Path $here {q(bundled_crl)}) -Destination (Join-Path $crlDir $crlFile) -Force }}",
        "Run { Copy-Item -LiteralPath (Join-Path $here 'serve-crl.ps1') -Destination (Join-Path $base 'serve-crl.ps1') -Force }",
        "$hostList = Join-Path $base 'crl-hosts.txt'",
        "$known = @(if (Test-Path -LiteralPath $hostList) { Get-Content -LiteralPath $hostList })",
        "if ($known -notcontains $crlHost) { Run { Add-Content -LiteralPath $hostList -Value $crlHost } }",
        "Step \"Local CRL server: hosts file sends $crlHost to this machine\"",
        "$hostsFile = Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'",
        f"$entry = \"127.0.0.1 $crlHost {MARK}\"",
        "if (Select-String -LiteralPath $hostsFile -SimpleMatch $entry -Quiet) {",
        "  Write-Host '    already there' -ForegroundColor DarkGray",
        "} else {",
        "  $raw = [System.IO.File]::ReadAllText($hostsFile)",
        "  if ($raw.Length -gt 0 -and -not $raw.EndsWith(\"`n\")) { Run { Add-Content -LiteralPath $hostsFile -Value '' } }  # don't join the last line",
        "  Run { Add-Content -LiteralPath $hostsFile -Value $entry }",
        "}",
        "Step \"Local CRL server: reserve http://$($crlHost):80/crl/ for LOCAL SERVICE only\"",
        "& netsh.exe http delete urlacl url=\"http://$($crlHost):80/crl/\" 2>&1 | Out-Null  # an earlier install's reservation",
        "Run { netsh.exe http add urlacl url=\"http://$($crlHost):80/crl/\" sddl='D:(A;;GX;;;LS)' | Out-Null }",
        f"$task = {q(TASK_NAME)}",
        "Step \"Local CRL server: scheduled task '$task' starts the listener at boot as LOCAL SERVICE\"",
        "$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "
        "('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"' + (Join-Path $base 'serve-crl.ps1') + '\"')",
        "$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        "-ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)",
        "$principal = New-ScheduledTaskPrincipal -UserId 'LOCALSERVICE' -LogonType ServiceAccount",
        "Run { Register-ScheduledTask -TaskName $task -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) "
        "-Principal $principal -Settings $settings -Force | Out-Null }",
        "Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue  # restart: it reads the host list on start",
        "Run { Start-ScheduledTask -TaskName $task }",
        "Step \"Local CRL server: check that http://$crlHost/crl/$crlFile answers\"",
        "$url = \"http://$crlHost/crl/$crlFile\"",
        "$wc = New-Object System.Net.WebClient",
        "$wc.Proxy = $null  # straight to this machine, like a hosts entry",
        "$served = $null",
        "foreach ($attempt in 1..10) {",
        "  Start-Sleep -Seconds 1",
        "  try { $served = $wc.DownloadData($url); break } catch { $lastError = $_.Exception.Message }",
        "}",
        "$expected = [System.IO.File]::ReadAllBytes((Join-Path $crlDir $crlFile))",
        "if (-not $served -or $served.Length -ne $expected.Length) {",
        "  throw \"The local CRL server didn't answer at $url ($lastError). Is another program using port 80? See README.txt.\"",
        "}",
        "Write-Host \"    answers: $url ($($served.Length) bytes)\" -ForegroundColor DarkGray",
    ]


def uninstall_lines(host: str, crl_file: str) -> list[str]:
    """uninstall.ps1 steps for the local CRL server (Undo/Step come from windows_scripts)."""
    q = lambda s: "'" + s.replace("'", "''") + "'"  # noqa: E731
    return [
        "",
        f"# Local CRL server for {host}",
        f"$crlHost = {q(host)}",
        "$base = Join-Path $env:ProgramData 'CertGenerator'",
        "$hostList = Join-Path $base 'crl-hosts.txt'",
        f"Undo 'Local CRL server: CRL file' {{ Remove-Item -LiteralPath (Join-Path (Join-Path $base 'crl') {q(crl_file)}) -ErrorAction SilentlyContinue }}",
        "$hostsFile = Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'",
        f"$entry = \"127.0.0.1 $crlHost {MARK}\"",
        "Undo \"Local CRL server: hosts entry for $crlHost\" {",
        "  $kept = @(Get-Content -LiteralPath $hostsFile | Where-Object { $_ -ne $entry })",
        "  Set-Content -LiteralPath $hostsFile -Value $kept -Encoding ASCII",
        "}",
        "Step \"Local CRL server: address reservation for $crlHost\"",
        "& netsh.exe http delete urlacl url=\"http://$($crlHost):80/crl/\" 2>&1 | Out-Null  # already gone is fine",
        "$left = @(if (Test-Path -LiteralPath $hostList) { Get-Content -LiteralPath $hostList | Where-Object { $_ -and $_ -ne $crlHost } })",
        f"$task = {q(TASK_NAME)}",
        "Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue",
        "if ($left.Count -eq 0) {",
        "  Undo \"Local CRL server: scheduled task '$task' (no other domains use it)\" {",
        "    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $task -Confirm:$false }",
        "  }",
        "  Undo \"Local CRL server: folder $base\" { if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force } }",
        "} else {",
        "  Undo \"Local CRL server: keep serving $($left -join ', ')\" {",
        "    Set-Content -LiteralPath $hostList -Value $left",
        "    Start-ScheduledTask -TaskName $task",
        "  }",
        "}",
    ]
