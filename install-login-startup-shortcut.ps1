param(
    [Parameter(Mandatory=$true)][string]$Pythonw,
    [Parameter(Mandatory=$true)][string]$StartupRoot,
    [switch]$ReplaceExisting
)
$ErrorActionPreference = 'Stop'
$runtime = (Resolve-Path -LiteralPath $Pythonw).ProviderPath
$root = (Resolve-Path -LiteralPath $StartupRoot).ProviderPath
# Packaged callers can silently write AppData into their package LocalCache.
# Explorer at logon then sees a different directory. Keep launcher/runtime out
# of AppData and verify them again from a native Windows process before rollout.
$appDataRoot = Join-Path $env:USERPROFILE 'AppData'
foreach ($path in @($root, $runtime)) {
    if ($path.Equals($appDataRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $path.StartsWith($appDataRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'APPDATA_STARTUP_DEPENDENCY_UNSUPPORTED'
    }
}
$launcher = Join-Path $root 'launch_hitl.pyw'
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw 'LAUNCHER_MISSING' }
if (-not (Test-Path -LiteralPath (Join-Path $root 'startup-config.json') -PathType Leaf)) { throw 'CONFIG_MISSING' }
if ([IO.Path]::GetFileName($runtime) -ine 'pythonw.exe') { throw 'PYTHONW_REQUIRED' }
$startup = [Environment]::GetFolderPath('Startup')
$link = Join-Path $startup 'HITL Connect Startup.lnk'
$cmd = Join-Path $startup 'hitl-connect.cmd'
if ((Test-Path -LiteralPath $link) -and -not $ReplaceExisting) { throw 'STARTUP_SHORTCUT_ALREADY_EXISTS' }
$backupRoot = Join-Path $root ('backup-' + (Get-Date -Format 'yyyyMMddTHHmmssfff'))
New-Item -ItemType Directory -Path $backupRoot -ErrorAction Stop | Out-Null
foreach ($entry in @($link, $cmd)) {
    if (Test-Path -LiteralPath $entry -PathType Leaf) {
        $backup = Join-Path $backupRoot ([IO.Path]::GetFileName($entry))
        Copy-Item -LiteralPath $entry -Destination $backup -ErrorAction Stop
        if ((Get-FileHash -LiteralPath $backup).Hash -ne (Get-FileHash -LiteralPath $entry).Hash) {
            throw 'BACKUP_MISMATCH'
        }
    }
}
$candidate = Join-Path $root 'HITL Connect Startup.pending.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($candidate)
$shortcut.TargetPath = $runtime
$shortcut.Arguments = '"' + $launcher + '"'
$shortcut.WorkingDirectory = $root
$shortcut.WindowStyle = 7
$shortcut.Description = 'HITL Connect: current-user login startup with normal Windows administrator authorization'
$shortcut.Save()
$check = $shell.CreateShortcut($candidate)
if ($check.TargetPath -ne $runtime -or $check.Arguments -ne ('"' + $launcher + '"') -or $check.WorkingDirectory -ne $root) {
    throw 'SHORTCUT_VERIFICATION_FAILED'
}
try {
    Copy-Item -LiteralPath $candidate -Destination $link -Force -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $link).Hash -ne (Get-FileHash -LiteralPath $candidate).Hash) {
        throw 'INSTALLED_SHORTCUT_MISMATCH'
    }
    if (Test-Path -LiteralPath $cmd -PathType Leaf) { Remove-Item -LiteralPath $cmd }
} catch {
    $previous = Join-Path $backupRoot 'HITL Connect Startup.lnk'
    if (Test-Path -LiteralPath $previous -PathType Leaf) {
        Copy-Item -LiteralPath $previous -Destination $link -Force
    } elseif (Test-Path -LiteralPath $link -PathType Leaf) {
        Remove-Item -LiteralPath $link
    }
    throw
}
Remove-Item -LiteralPath $candidate
[pscustomobject]@{ shortcut=$link; runtime=$runtime; launcher=$launcher; workingDirectory=$root; backupDirectory=$backupRoot; nativeLogonVerificationRequired=$true } | ConvertTo-Json
