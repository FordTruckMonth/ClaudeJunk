<#
.SYNOPSIS
    PrintNightmare posture check — verifies installed updates AND the Point and Print
    registry mitigations in one pass, then prints a single definitive result.

.DESCRIPTION
    Read-only. Combines the old two-step "Run1st + Run2nd" workflow so you get, in one run:

      1. Print Spooler service state.
      2. Installed updates / patch context. Lists ALL installed updates (newest first),
         flags PrintNightmare-era KBs by number, surfaces the true OS build (Build.UBR),
         and decides a patch verdict from the most recent update date. This is the
         "Run1st / printnightmarecheck" output, no longer truncated to five rows.
      3. Point and Print registry mitigations, ending in the clear safe/exposed
         confirmation that "Run2nd" produced.
      4. A single combined RESULT covering both patch and registry posture.

    Makes no changes to the system.

    Background: PrintNightmare is CVE-2021-1675 (the original Spooler elevation-of-
    privilege, June 8 2021) and CVE-2021-34527 (the out-of-band Spooler RCE, July 6-7
    2021). A related default-behaviour change shipped August 10 2021 (CVE-2021-34481).
    Every cumulative/rollup update from 2021-07-06 onward carries the Spooler RCE fix,
    so this script treats "newest installed update is dated 2021-07-06 or later" as the
    patch signal and verifies the registry hardening separately.

.PARAMETER IncludeUpdateHistory
    Also query the Windows Update agent history (COM) for a fuller list of installed
    updates than Get-HotFix returns (Get-HotFix only sees CBS-serviced updates). Slower
    and noisier; off by default.

.PARAMETER ExportJson
    Optional path to write the structured result object as JSON (for fleet/automation use).

.EXAMPLE
    .\printnightmare-check.ps1

.EXAMPLE
    .\printnightmare-check.ps1 -IncludeUpdateHistory -ExportJson .\posture.json

.NOTES
    Read-only. Run in an elevated session for the most complete update inventory.
    KB references verified against Microsoft MSRC / Support (KB5005010, KB5005652).
#>
[CmdletBinding()]
param(
    [switch]$IncludeUpdateHistory,
    [string]$ExportJson
)

$ErrorActionPreference = 'SilentlyContinue'

# Key dates. Any cumulative/rollup update from the out-of-band date onward contains the
# CVE-2021-34527 Spooler fix; the August date is when the admin-only driver-install
# default (RestrictDriverInstallationToAdministrators) flipped from 0 to 1.
$oobPatchDate    = [datetime]'2021-07-06'
$augDefaultDate  = [datetime]'2021-08-10'

Write-Host "=== PrintNightmare Posture Check ===" -ForegroundColor Cyan

# Structured result, also used for the optional JSON export.
$result = [ordered]@{
    ComputerName    = $env:COMPUTERNAME
    OS              = $null
    OSBuild         = $null
    Spooler         = [ordered]@{}
    PatchVerdict    = $null
    LatestUpdate    = $null
    RelevantUpdates = @()
    Registry        = [ordered]@{}
    RegistrySafe    = $true
    Exposed         = $false
    Notes           = @()
}

function Get-RegVal($path, $name) {
    try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name }
    catch { $null }
}

# --------------------------------------------------------------------------
# 1. Print Spooler service state
# --------------------------------------------------------------------------
Write-Host "`n[Print Spooler Service]"
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($null -eq $spooler) {
    Write-Host "  Spooler service not found on this host (lowest risk)." -ForegroundColor Green
    $result.Spooler.Status    = 'NotPresent'
    $result.Spooler.StartType = 'NotPresent'
} else {
    Write-Host "  Status     : $($spooler.Status)"
    Write-Host "  StartType  : $($spooler.StartType)"
    $result.Spooler.Status    = "$($spooler.Status)"
    $result.Spooler.StartType = "$($spooler.StartType)"
    if ($spooler.Status -eq 'Running') {
        Write-Host "  -> Spooler is RUNNING. If this host does not need to print or share printers," -ForegroundColor Yellow
        Write-Host "     disabling it fully removes the PrintNightmare attack surface." -ForegroundColor Yellow
    } else {
        Write-Host "  -> Spooler is not running (lowest risk)." -ForegroundColor Green
    }
}

# --------------------------------------------------------------------------
# 2. Installed updates / patch context
# --------------------------------------------------------------------------
Write-Host "`n[Installed Updates / Patch Context]"

# True OS build is Build.UBR. Win32_OperatingSystem.Version and OSVersion omit the UBR
# (the revision cumulative updates increment), so read CurrentBuild/UBR from the registry.
# Note: the CurrentVersion *value* is frozen at 6.3 for back-compat and must not be used.
$os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$osv = [System.Environment]::OSVersion.Version
$build = if ($cv -and $cv.CurrentBuildNumber) { $cv.CurrentBuildNumber } else { $osv.Build }
$ubr   = if ($cv) { $cv.UBR } else { $null }
$buildString = if ($ubr) { "$($osv.Major).$($osv.Minor).$build.$ubr" } else { "$($osv.Major).$($osv.Minor).$build" }
$release = if ($cv) { if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId } } else { $null }

$result.OS      = if ($os) { $os.Caption } else { 'Unknown' }
$result.OSBuild = $buildString
$relLabel = if ($release) { " ($release)" } else { "" }
Write-Host "  $($result.OS)$relLabel - Build $buildString"

# Known PrintNightmare-remediation KBs (CVE-2021-1675 / CVE-2021-34527 out-of-band, and
# the Aug 2021 driver-install default change). INFORMATIONAL ONLY: modern Windows ships
# these fixes inside the monthly Cumulative Update, which SUPERSEDES the individual KBs,
# so a missing KB number here does NOT mean unpatched. The latest-update date and OS
# build below are the authoritative patch signal.
$relevantKbs = @(
    'KB5004945', # Win10 2004/20H2/21H1
    'KB5004946', # Win10 1909
    'KB5004947', # Win10 1809 / Server 2019
    'KB5004948', # Win10 1607 / Server 2016
    'KB5004950', # Win10 1507
    'KB5004954', # Win8.1 / Server 2012 R2 (Monthly Rollup)
    'KB5004958', # Win8.1 / Server 2012 R2 (Security-only)
    'KB5004956', # Server 2012 (Monthly Rollup)
    'KB5004960', # Server 2012 (Security-only)
    'KB5004953', # Win7 SP1 / Server 2008 R2 SP1 (Monthly Rollup, ESU)
    'KB5004951', # Win7 SP1 / Server 2008 R2 SP1 (Security-only, ESU)
    'KB5004955', # Server 2008 SP2 (Monthly Rollup)
    'KB5004959'  # Server 2008 SP2 (Security-only)
)

# All installed hotfixes, newest first. InstalledOn is a fragile ScriptProperty that is
# frequently null, so coerce null to DateTime.MinValue for a stable sort instead of
# letting null-dated rows order randomly or drop out.
$hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue |
    Sort-Object @{ Expression = { if ($_.InstalledOn) { [datetime]$_.InstalledOn } else { [datetime]::MinValue } } } -Descending)

$latest = $null
if ($hotfixes.Count -eq 0) {
    Write-Host "  Get-HotFix returned no entries (it only reports CBS-serviced updates, and may" -ForegroundColor Yellow
    Write-Host "  need an elevated session). Use -IncludeUpdateHistory or check the build above." -ForegroundColor Yellow
    $result.Notes += 'Get-HotFix returned no entries.'
} else {
    Write-Host "  Total updates reported by Get-HotFix (CBS): $($hotfixes.Count)"

    # Flag any relevant KBs still listed by number (usually superseded away by a CU).
    $foundRelevant = @($hotfixes | Where-Object { $relevantKbs -contains $_.HotFixID })
    $result.RelevantUpdates = @($foundRelevant | ForEach-Object { $_.HotFixID })
    if ($foundRelevant.Count -gt 0) {
        Write-Host "`n  PrintNightmare-era updates present by KB number:" -ForegroundColor Green
        $foundRelevant |
            Select-Object HotFixID, Description,
                @{ N = 'InstalledOn'; E = { if ($_.InstalledOn) { ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') } else { '(date n/a)' } } } |
            Format-Table -AutoSize
    } else {
        Write-Host "`n  No PrintNightmare-era KB present by number. On modern Windows the fix is rolled" -ForegroundColor Yellow
        Write-Host "  into the monthly Cumulative Update (which supersedes those KBs), so this is" -ForegroundColor Yellow
        Write-Host "  expected on a current host - confirm via the update date below, not the KB list." -ForegroundColor Yellow
        $result.Notes += 'No PrintNightmare-era KB present by number (expected when superseded by a CU).'
    }

    # Most recent dated update overall - the practical "is this box current" signal.
    $latest = $hotfixes | Where-Object { $_.InstalledOn } | Select-Object -First 1
    if ($latest) {
        $latestDate = [datetime]$latest.InstalledOn
        $result.LatestUpdate = [ordered]@{
            HotFixID    = $latest.HotFixID
            Description = "$($latest.Description)"
            InstalledOn = $latestDate.ToString('yyyy-MM-dd')
        }
        Write-Host "`n  Most recent update: $($latest.HotFixID) ($($latest.Description)) installed $($latestDate.ToString('yyyy-MM-dd'))"
    } else {
        Write-Host "`n  Updates are present but none carry a usable InstalledOn date (a known Get-HotFix" -ForegroundColor Yellow
        Write-Host "  quirk). Use the OS build above to confirm patch level." -ForegroundColor Yellow
        $result.Notes += 'Hotfixes present but InstalledOn unavailable on all of them.'
    }

    Write-Host "`n  All installed updates (most recent first):"
    $hotfixes |
        Select-Object HotFixID, Description,
            @{ N = 'InstalledOn'; E = { if ($_.InstalledOn) { ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') } else { '(date n/a)' } } } |
        Format-Table -AutoSize
}

# Optional fuller history via the Windows Update agent (COM).
if ($IncludeUpdateHistory) {
    Write-Host "  [Windows Update agent history]"
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $count    = $searcher.GetTotalHistoryCount()   # must be > 0 before QueryHistory
        if ($count -gt 0) {
            # Operation 1 = install; ResultCode 2 = Succeeded, 3 = SucceededWithErrors.
            # ResultCode can throw on rare entries, and the log is noisy with Defender
            # definition updates, so guard the access and filter that noise out.
            $history = $searcher.QueryHistory(0, $count) | ForEach-Object {
                $rc = try { $_.ResultCode } catch { $null }
                if ($_.Operation -eq 1 -and ($rc -eq 2 -or $rc -eq 3) -and $_.Title -and
                    $_.Title -notmatch 'Defender|Security Intelligence|Definition Update|Antivirus|Antimalware') {
                    [PSCustomObject]@{ Date = $_.Date; Title = $_.Title }
                }
            } | Sort-Object Date -Descending
            $shown = @($history | Select-Object -First 25)
            Write-Host "  $(@($history).Count) installed updates in agent history (excluding definition updates; most recent 25 shown):"
            $shown |
                Select-Object @{ N = 'Date'; E = { $_.Date.ToString('yyyy-MM-dd') } }, Title |
                Format-Table -AutoSize -Wrap
        } else {
            Write-Host "  Windows Update agent reported no history." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Could not query the Windows Update agent: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Patch verdict from the most recent update date.
Write-Host "`n  [Patch Assessment]"
$patchedOOB = $false
$patchedAug = $false
if ($latest) {
    $latestDate = [datetime]$latest.InstalledOn
    $patchedOOB = $latestDate -ge $oobPatchDate
    $patchedAug = $latestDate -ge $augDefaultDate
}
if ($patchedOOB) {
    $result.PatchVerdict = 'Patched'
    Write-Host "  Newest update is dated $((([datetime]$latest.InstalledOn)).ToString('yyyy-MM-dd')), on/after the 2021-07-06 out-of-band fix." -ForegroundColor Green
    Write-Host "  Every cumulative/rollup update from that date onward includes the CVE-2021-34527" -ForegroundColor Green
    Write-Host "  Spooler RCE fix, so this host carries the PrintNightmare patch." -ForegroundColor Green
} else {
    $result.PatchVerdict = 'Unconfirmed'
    Write-Host "  Could not confirm the PrintNightmare patch from update dates. Verify the OS build" -ForegroundColor Yellow
    Write-Host "  ($buildString) meets your patch baseline (2021-07-06 out-of-band update or later)." -ForegroundColor Yellow
    $result.Notes += 'Patch presence not confirmable from update dates; verify build against baseline.'
}

# --------------------------------------------------------------------------
# 3. Point and Print registry mitigations
# --------------------------------------------------------------------------
$pp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
Write-Host "`n[Point and Print Registry Mitigations]"
Write-Host "  ($pp)"

$ppExists      = Test-Path $pp
$restrictAdmin = $null
$noWarnInstall = $null
$updatePrompt  = $null

if (-not $ppExists) {
    Write-Host "  Policy key not present - Point and Print policies are at their OS default." -ForegroundColor Yellow
} else {
    $restrictAdmin = Get-RegVal $pp "RestrictDriverInstallationToAdministrators"
    $noWarnInstall = Get-RegVal $pp "NoWarningNoElevationOnInstall"
    $updatePrompt  = Get-RegVal $pp "UpdatePromptSettings"

    Write-Host "  RestrictDriverInstallationToAdministrators : $(if ($null -eq $restrictAdmin) {'(not set)'} else {$restrictAdmin})"
    Write-Host "  NoWarningNoElevationOnInstall              : $(if ($null -eq $noWarnInstall) {'(not set)'} else {$noWarnInstall})"
    Write-Host "  UpdatePromptSettings                       : $(if ($null -eq $updatePrompt)  {'(not set)'} else {$updatePrompt})"
}
$result.Registry.RestrictDriverInstallationToAdministrators = $restrictAdmin
$result.Registry.NoWarningNoElevationOnInstall              = $noWarnInstall
$result.Registry.UpdatePromptSettings                       = $updatePrompt

# Registry assessment (Run2nd-style confirmation), with the nuance the original scripts
# missed: a *missing* RestrictDriverInstallationToAdministrators is only the safe
# (admin-only) default on hosts patched 2021-08-10 or later. On a July-2021-only host the
# default is 0 (exposed). We resolve that ambiguity using the patch date computed above.
Write-Host "`n  [Registry Assessment]"
$registrySafe = $true
if ($restrictAdmin -eq 0) {
    Write-Host "  RestrictDriverInstallationToAdministrators = 0 -> non-admins can install drivers. EXPOSED." -ForegroundColor Red
    $registrySafe = $false
} elseif ($restrictAdmin -eq 1) {
    Write-Host "  RestrictDriverInstallationToAdministrators = 1 -> driver install restricted to" -ForegroundColor Green
    Write-Host "  administrators (the strongest setting; overrides Point and Print policy). Good." -ForegroundColor Green
} else {
    # Value not set / key absent -> relying on the OS default.
    if ($patchedAug) {
        Write-Host "  RestrictDriverInstallationToAdministrators not set, but this host has updates from" -ForegroundColor Green
        Write-Host "  2021-08-10 or later, where the default is 1 (admin-only). Good." -ForegroundColor Green
    } else {
        Write-Host "  RestrictDriverInstallationToAdministrators not set. The secure admin-only default" -ForegroundColor Yellow
        Write-Host "  only applies on hosts patched 2021-08-10 or later, which could not be confirmed" -ForegroundColor Yellow
        Write-Host "  here. For a guaranteed-safe posture, set this value explicitly to 1 (DWORD)." -ForegroundColor Yellow
        $registrySafe = $false
        $result.Notes += 'RestrictDriverInstallationToAdministrators not set and Aug-2021 patch level unconfirmed; set it to 1.'
    }
}
# Safe value for these two is 0 or not defined; any non-zero value suppresses the prompt.
if ($null -ne $noWarnInstall -and $noWarnInstall -ne 0) {
    Write-Host "  NoWarningNoElevationOnInstall = $noWarnInstall -> elevation prompt suppressed on install. RISK." -ForegroundColor Red
    $registrySafe = $false
}
if ($null -ne $updatePrompt -and $updatePrompt -ne 0) {
    Write-Host "  UpdatePromptSettings = $updatePrompt -> elevation prompt suppressed on update. RISK." -ForegroundColor Red
    $registrySafe = $false
}
$result.RegistrySafe = $registrySafe

Write-Host ""
if ($registrySafe) {
    Write-Host "  RESULT: Registry settings are in a safe configuration." -ForegroundColor Green
} else {
    Write-Host "  RESULT: Registry settings leave this host EXPOSED (or unconfirmed) - see above." -ForegroundColor Red
}

# --------------------------------------------------------------------------
# 4. Combined overall result
# --------------------------------------------------------------------------
$result.Exposed = -not $registrySafe
Write-Host "`n=== Overall Result ===" -ForegroundColor Cyan
$patchColor = if ($result.PatchVerdict -eq 'Patched') { 'Green' } else { 'Yellow' }
$latestLine = if ($result.LatestUpdate) {
    "latest update $($result.LatestUpdate.HotFixID) on $($result.LatestUpdate.InstalledOn)"
} else {
    "no dated update found via Get-HotFix"
}
Write-Host "  Patch posture        : $($result.PatchVerdict) ($latestLine)" -ForegroundColor $patchColor
Write-Host "  OS build             : $($result.OS) - $buildString" -ForegroundColor $patchColor
if ($registrySafe) {
    Write-Host "  Registry mitigations : SAFE (driver install restricted to administrators)" -ForegroundColor Green
} else {
    Write-Host "  Registry mitigations : EXPOSED / UNCONFIRMED" -ForegroundColor Red
}
Write-Host ""
if ($registrySafe -and $result.PatchVerdict -eq 'Patched') {
    Write-Host "  RESULT: Host carries the PrintNightmare patch AND the Point and Print registry" -ForegroundColor Green
    Write-Host "          mitigations are in a safe configuration. Protected." -ForegroundColor Green
} elseif (-not $registrySafe) {
    Write-Host "  RESULT: This host is EXPOSED to PrintNightmare-style driver-install abuse." -ForegroundColor Red
    Write-Host "          Correct the registry settings flagged above (and confirm patch level)." -ForegroundColor Red
} else {
    Write-Host "  RESULT: Registry mitigations are safe, but the patch level could not be confirmed" -ForegroundColor Yellow
    Write-Host "          from update history. Verify the OS build meets your baseline, then re-run." -ForegroundColor Yellow
}

# Optional structured export.
if ($ExportJson) {
    try {
        $result | ConvertTo-Json -Depth 6 | Set-Content -Path $ExportJson -Encoding UTF8
        Write-Host "`n  Structured result written to $ExportJson" -ForegroundColor Cyan
    } catch {
        Write-Host "`n  Failed to write JSON to ${ExportJson}: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
