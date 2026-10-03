# Cert Generator local CRL server: answers GET/HEAD http://<host>/crl/<name>.crl from
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
