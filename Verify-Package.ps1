# Read-only package review. Does not execute the CLI, install services, or change policy.
[CmdletBinding()]
param(
    [string]$PackageDirectory = '',
    [string]$ExpectedSourceCommit = '',
    [string]$ExpectedPublisherThumbprint = ''
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
if (-not $PackageDirectory) { $PackageDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path }
$report = [ordered]@{
    schemaVersion = 'hitl-connect.package-review.v1'
    ok = $false
    code = 'PACKAGE_REVIEW_FAILED'
    sourceCommit = $null
    version = $null
    integrityVerified = $false
    signaturesVerified = $false
    publisherVerified = $false
    installationApproved = $false
    endpointProtectionApproved = $false
    files = @()
}
function Assert-RegularFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'PACKAGE_UNSAFE_PATH'
    }
}
try {
    if ($ExpectedSourceCommit -and $ExpectedSourceCommit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'INVALID_EXPECTED_COMMIT'
    }
    if ($ExpectedPublisherThumbprint -and $ExpectedPublisherThumbprint -notmatch '^[0-9a-fA-F]{40}$') {
        throw 'INVALID_EXPECTED_PUBLISHER'
    }
    $root = Get-Item -LiteralPath $PackageDirectory -Force
    if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'PACKAGE_UNSAFE_PATH'
    }
    $manifestPath = Join-Path $root.FullName 'manifest.json'
    Assert-RegularFile $manifestPath
    if ((Get-Item -LiteralPath $manifestPath).Length -gt 1048576) { throw 'PACKAGE_INVALID_MANIFEST' }
    $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    if ($manifest.product -cne 'HITL Connect' -or $manifest.platform -cne 'windows-amd64' -or
        $manifest.sourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'PACKAGE_INVALID_MANIFEST' }
    $report.sourceCommit = $manifest.sourceCommit
    $report.version = $manifest.version
    if ($ExpectedSourceCommit -and $ExpectedSourceCommit -cne $manifest.sourceCommit) {
        throw 'PACKAGE_SOURCE_MISMATCH'
    }
    $required = @('HITL-Connect.exe', 'hitl-connect-cli.exe', 'AGENTS.md', 'README.md',
        'SECURITY-REVIEW.md', 'Verify-Package.ps1')
    $names = @($manifest.files.PSObject.Properties.Name)
    foreach ($name in $required) {
        if ($names -cnotcontains $name) { throw 'PACKAGE_INCOMPLETE_MANIFEST' }
    }
    foreach ($file in Get-ChildItem -LiteralPath $root.FullName -Force) {
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            ($names + @('manifest.json')) -cnotcontains $file.Name) { throw 'PACKAGE_UNEXPECTED_FILE' }
    }
    $integrity = $true
    $signed = $true
    $publisher = [bool]$ExpectedPublisherThumbprint
    $unsigned = $false
    foreach ($name in $names) {
        if (($required + @('validation.json','HITL-Connect.ico')) -cnotcontains $name) { throw 'PACKAGE_UNEXPECTED_FILE' }
        $entry = $manifest.files.$name
        if ($entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $entry.bytes -isnot [ValueType] -or $entry.bytes -lt 0) {
            throw 'PACKAGE_INVALID_MANIFEST'
        }
        $path = Join-Path $root.FullName $name
        Assert-RegularFile $path
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $matches = ($hash -ceq $entry.sha256) -and ((Get-Item -LiteralPath $path).Length -eq $entry.bytes)
        $item = [ordered]@{ name = $name; sha256 = $hash; matchesManifest = $matches }
        $integrity = $integrity -and $matches
        if ($name.EndsWith('.exe') -or $name.EndsWith('.ps1')) {
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            $valid = $signature.Status -eq 'Valid'
            $signed = $signed -and $valid
            $unsigned = $unsigned -or ($signature.Status -eq 'NotSigned')
            $thumbprint = $null
            if ($signature.SignerCertificate) { $thumbprint = $signature.SignerCertificate.Thumbprint }
            $item.signatureStatus = [string]$signature.Status
            $item.signerThumbprint = $thumbprint
            $publisher = $publisher -and $valid -and ($thumbprint -eq $ExpectedPublisherThumbprint)
        }
        $report.files += [pscustomobject]$item
    }
    $report.integrityVerified = $integrity
    $report.signaturesVerified = $signed
    $report.publisherVerified = $publisher
    if (-not $integrity) { $report.code = 'PACKAGE_INTEGRITY_FAILED' }
    elseif ($unsigned) { $report.code = 'PACKAGE_UNSIGNED' }
    elseif (-not $signed) { $report.code = 'PACKAGE_SIGNATURE_INVALID' }
    elseif (-not $ExpectedPublisherThumbprint) { $report.code = 'PACKAGE_PUBLISHER_UNCONFIRMED' }
    elseif (-not $publisher) { $report.code = 'PACKAGE_PUBLISHER_MISMATCH' }
    else { $report.ok = $true; $report.code = 'PACKAGE_VERIFIED' }
} catch {
    # No arbitrary file contents, exception text, credentials, or environment in output.
    $code = $_.Exception.Message
    if ($code -cmatch '^(PACKAGE_[A-Z_]+|INVALID_EXPECTED_[A-Z_]+)$') { $report.code = $code }
}
$report | ConvertTo-Json -Depth 6
if (-not $report.ok) { exit 2 }
exit 0
