<#
.SYNOPSIS
    Signs published Windows binaries with Authenticode.

.DESCRIPTION
    Signs every executable and library the publish produced, then verifies each signature. The
    certificate is supplied through the release pipeline's secret store and never lives in this
    repository.

.PARAMETER Path
    The publish directory to sign.

.PARAMETER TimestampUrl
    RFC 3161 timestamp authority. A timestamp keeps signatures valid after the certificate expires.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [string] $TimestampUrl = $env:TIMESTAMP_URL
)

$ErrorActionPreference = 'Stop'

if (-not $env:SIGNING_CERTIFICATE) {
    throw 'SIGNING_CERTIFICATE is not set. Signing requires the release pipeline secrets.'
}

if (-not $TimestampUrl) {
    $TimestampUrl = 'http://timestamp.digicert.com'
}

$certificatePath = Join-Path ([System.IO.Path]::GetTempPath()) "signing-$([guid]::NewGuid()).pfx"

try {
    [System.IO.File]::WriteAllBytes(
        $certificatePath,
        [Convert]::FromBase64String($env:SIGNING_CERTIFICATE))

    $targets = Get-ChildItem -Path $Path -Recurse -Include *.exe, *.dll |
        Where-Object { $_.Length -gt 0 }

    Write-Host "Signing $($targets.Count) file(s) in $Path"

    foreach ($target in $targets) {
        & signtool.exe sign `
            /f $certificatePath `
            /p $env:SIGNING_PASSWORD `
            /fd SHA256 `
            /tr $TimestampUrl `
            /td SHA256 `
            /d 'Identity Posture Assessor' `
            $target.FullName

        if ($LASTEXITCODE -ne 0) {
            throw "Signing failed for $($target.FullName)."
        }
    }

    # Every signature is verified after the fact, so a silently unsigned file cannot ship.
    foreach ($target in $targets) {
        & signtool.exe verify /pa /q $target.FullName

        if ($LASTEXITCODE -ne 0) {
            throw "Signature verification failed for $($target.FullName)."
        }
    }

    Write-Host 'All files signed and verified.'
}
finally {
    if (Test-Path $certificatePath) {
        Remove-Item $certificatePath -Force
    }
}
