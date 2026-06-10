Write-Host "=== PrintNightmare Posture Check ===" -ForegroundColor Cyan

# 1. Print Spooler service state
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
Write-Host "`n[Print Spooler Service]"
if ($null -eq $spooler) {
    Write-Host "  Spooler service not found on this host (lowest risk)." -ForegroundColor Green
} else {
    Write-Host "  Status     : $($spooler.Status)"
    Write-Host "  StartType  : $($spooler.StartType)"
    if ($spooler.Status -eq 'Running') {
        Write-Host "  -> Spooler is RUNNING. If this host does not need to print/share printers, disabling it fully removes the attack surface." -ForegroundColor Yellow
    } else {
        Write-Host "  -> Spooler is not running (lowest risk)." -ForegroundColor Green
    }
}

# 2. Point and Print / driver install restrictions
$pp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

function Get-RegVal($path, $name) {
    try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name }
    catch { $null }
}

$ppKeyExists   = Test-Path $pp
$restrictAdmin = $null
$noWarnInstall = $null
$updatePrompt  = $null

Write-Host "`n[Point and Print Registry Settings] ($pp)"
if (-not $ppKeyExists) {
    Write-Host "  Policy key not present - Point and Print policies are at default." -ForegroundColor Yellow
    Write-Host "  On a patched system the default restricts driver installation to administrators." -ForegroundColor Green
} else {
    $restrictAdmin = Get-RegVal $pp "RestrictDriverInstallationToAdministrators"
    $noWarnInstall = Get-RegVal $pp "NoWarningNoElevationOnInstall"
    $updatePrompt  = Get-RegVal $pp "UpdatePromptSettings"

    Write-Host "  RestrictDriverInstallationToAdministrators : $(if ($null -eq $restrictAdmin) {'(not set)'} else {$restrictAdmin})"
    Write-Host "  NoWarningNoElevationOnInstall              : $(if ($null -eq $noWarnInstall) {'(not set)'} else {$noWarnInstall})"
    Write-Host "  UpdatePromptSettings                       : $(if ($null -eq $updatePrompt)  {'(not set)'} else {$updatePrompt})"
}

# 3. Evaluate
Write-Host "`n[Assessment]"
$vulnerable = $false

# The key mitigation: driver installs restricted to admins. Absent values ($null) fall
# through to the safe branch, matching the patched default.
if ($restrictAdmin -eq 0) {
    Write-Host "  RestrictDriverInstallationToAdministrators = 0 -> non-admins can install drivers. EXPOSED." -ForegroundColor Red
    $vulnerable = $true
} else {
    Write-Host "  Driver installation restricted to administrators (value 1 or not set). Good." -ForegroundColor Green
}

# These two being 1 weakens Point and Print and reintroduces risk
if ($noWarnInstall -eq 1) {
    Write-Host "  NoWarningNoElevationOnInstall = 1 -> elevation prompts suppressed on install. RISK." -ForegroundColor Red
    $vulnerable = $true
}
if ($updatePrompt -eq 1) {
    Write-Host "  UpdatePromptSettings = 1 -> elevation prompts suppressed on update. RISK." -ForegroundColor Red
    $vulnerable = $true
}

Write-Host ""
if ($vulnerable) {
    Write-Host "RESULT: Configuration leaves this host EXPOSED to PrintNightmare-style abuse." -ForegroundColor Red
} else {
    Write-Host "RESULT: Registry mitigations look correct. Confirm OS patch level separately." -ForegroundColor Green
}

# 4. OS build / patch context
Write-Host "`n[OS / Patch Context]"
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "  $($os.Caption) - Build $([System.Environment]::OSVersion.Version)"
Write-Host "  Most recent hotfixes:"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, InstalledOn | Format-Table -AutoSize
