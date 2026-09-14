# Run the packaged EXE's self-tests. Used by CI and runnable on any Windows machine:
#   pwsh scripts/test-exe.ps1 -Exe dist/CertGenerator.exe
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
$exePath = (Resolve-Path $Exe).Path
$failed = $false

foreach ($mode in @('self-test', 'self-test-gui')) {
    $report = Join-Path (Get-Location) "selftest-$mode.json"
    Remove-Item $report -ErrorAction SilentlyContinue
    Write-Host "== $mode"

    $proc = Start-Process -FilePath $exePath -ArgumentList "--$mode", "`"$report`"" -PassThru
    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        $proc.Kill()
        Write-Host "::error::$mode did not finish within $TimeoutSeconds seconds"
        $failed = $true
        continue
    }

    if (Test-Path $report) {
        $result = Get-Content $report -Raw | ConvertFrom-Json
        foreach ($check in $result.checks) {
            $mark = if ($check.ok) { 'PASS' } else { 'FAIL' }
            Write-Host "$mark  $($check.name): $($check.detail)"
            if (-not $check.ok -and $check.traceback) { Write-Host $check.traceback }
        }
    } else {
        Write-Host "::error::$mode wrote no report"
    }

    if ($proc.ExitCode -ne 0) {
        Write-Host "::error::$mode exited with code $($proc.ExitCode)"
        $failed = $true
    }
}

$size = (Get-Item $exePath).Length
Write-Host ("EXE size: {0:N1} MB" -f ($size / 1MB))
if ($failed) { exit 1 }
