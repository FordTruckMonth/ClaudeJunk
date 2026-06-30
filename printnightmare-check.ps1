<#
.SYNOPSIS
    PrintNightmare posture check — verifies the installed patch level AND the Point and
    Print registry mitigations in one pass, then prints a single definitive result.

.DESCRIPTION
    Read-only. Combines the old two-step "Run1st + Run2nd" workflow so you get, in one run:

      1. Print Spooler service state.
      2. Installed updates / patch context. Lists ALL installed updates (newest first,
         no five-row truncation) and decides a patch verdict by comparing the true OS
         build revision (Build.UBR) against the per-build patched revision Microsoft
         shipped the fix in. This is the "Run1st / printnightmarecheck" output, made
         authoritative.
      3. Point and Print registry mitigations, ending in the clear safe/exposed
         confirmation that "Run2nd" produced.
      4. A single combined RESULT covering both patch and registry posture.

    Makes no changes to the system.

    Background. PrintNightmare is CVE-2021-1675 (the original Spooler elevation of
    privilege, June 8 2021) and CVE-2021-34527 (the out-of-band Spooler RCE, July 6-7
    2021). A related Point and Print default-behaviour change shipped August 10 2021
    (CVE-2021-34481): from that update on, RestrictDriverInstallationToAdministrators
    defaults to 1 (admin-only). Both facts matter, so this script keys its verdicts off
    the OS Build.UBR — not off update install dates, which a recent unrelated package
    (e.g. a .NET rollup) could otherwise spoof into a false "patched" reading.

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
    Build/UBR thresholds verified against Microsoft Support KB pages (KB5004945/46/47/48/50,
    KB5005033/31/30/43/40) and KB5005652 (the Aug 2021 default-behaviour change).
#>
[CmdletBinding()]
param(
    [switch]$IncludeUpdateHistory,
    [string]$ExportJson
)

$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=== PrintNightmare Posture Check ===" -ForegroundColor Cyan

# Structured result, also used for the optional JSON export.
$result = [ordered]@{
    ComputerName    = $env:COMPUTERNAME
    OS              = $null
    OSBuild         = $null
    Spooler         = [ordered]@{}
    PatchVerdict    = $null
    HasRceFix       = $false
    HasAugDefault   = $false
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

function Resolve-HotfixDate($hotfix) {
    # Get-HotFix's InstalledOn is a fragile ScriptProperty: usually a [datetime], sometimes
    # $null, and on some locales a non-parseable string. Return a [datetime] or $null and
    # NEVER throw, so the sort key and the "latest" filter always agree on a row's date.
    $v = $hotfix.InstalledOn
    if ($null -eq $v) { return $null }
    if ($v -is [datetime]) { return $v }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$v, [ref]$parsed)) { return $parsed }
    return $null
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
$build = if ($cv -and $cv.CurrentBuildNumber) { $cv.CurrentBuildNumber } else { "$($osv.Build)" }
$ubr   = if ($cv) { $cv.UBR } else { $null }
$buildString = if ($null -ne $ubr) { "$($osv.Major).$($osv.Minor).$build.$ubr" } else { "$($osv.Major).$($osv.Minor).$build" }
$release = if ($cv) { if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId } } else { $null }

$buildNum = 0; [void][int]::TryParse([string]$build, [ref]$buildNum)
$ubrNum   = 0; if ($null -ne $ubr) { [void][int]::TryParse([string]$ubr, [ref]$ubrNum) }

$result.OS      = if ($os) { $os.Caption } else { 'Unknown' }
$result.OSBuild = $buildString
$relLabel = if ($release) { " ($release)" } else { "" }
Write-Host "  $($result.OS)$relLabel - Build $buildString"

# Minimum patched OS Build.UBR per affected build, verified against the Microsoft KB pages.
# JULY 6-7 2021 out-of-band = first build carrying the CVE-2021-34527 Spooler RCE fix.
$julyMinUbr = @{ 10240 = 18969; 14393 = 4470; 17763 = 2029; 18363 = 1646; 19041 = 1083; 19042 = 1083; 19043 = 1083 }
# AUGUST 10 2021 cumulative = first build where RestrictDriverInstallationToAdministrators
# defaults to 1 (admin-only) when the value is absent.
$augMinUbr  = @{ 10240 = 19022; 14393 = 4583; 17763 = 2114; 18363 = 1734; 19041 = 1165; 19042 = 1165; 19043 = 1165 }
# Any build numbered above the highest affected build first shipped after Aug 10 2021
# (Win10 21H2/22H2, Win11, Server 2022, ...), so it inherently contains both fixes.
$highestAffectedBuild = 19043

# Known PrintNightmare-era out-of-band KBs. INFORMATIONAL ONLY: modern Windows ships the
# fix inside the monthly Cumulative Update, which SUPERSEDES these, so a missing KB number
# here does NOT mean unpatched. The Build.UBR comparison below is the authoritative signal.
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

# All installed hotfixes, projected onto a stable shape with one non-throwing date, newest
# first. Using the same resolved date for sorting AND for picking "latest" keeps them in
# agreement even when a row's InstalledOn is an unparseable string.
$hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            HotFixID    = $_.HotFixID
            Description = "$($_.Description)"
            Date        = (Resolve-HotfixDate $_)
        }
    } | Sort-Object @{ Expression = { if ($_.Date) { $_.Date } else { [datetime]::MinValue } } } -Descending)

if ($hotfixes.Count -eq 0) {
    Write-Host "  Get-HotFix returned no entries (it only reports CBS-serviced updates, and may" -ForegroundColor Yellow
    Write-Host "  need an elevated session). The build-based verdict below does not depend on it." -ForegroundColor Yellow
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
                @{ N = 'InstalledOn'; E = { if ($_.Date) { $_.Date.ToString('yyyy-MM-dd') } else { '(date n/a)' } } } |
            Format-Table -AutoSize
    } else {
        Write-Host "`n  No PrintNightmare-era KB present by number - expected on a current host, where" -ForegroundColor Gray
        Write-Host "  the fix is rolled into a later Cumulative Update that supersedes those KBs." -ForegroundColor Gray
        $result.Notes += 'No PrintNightmare-era KB present by number (expected when superseded by a CU).'
    }

    # Most recent dated update overall - shown for context only; the verdict is build-based.
    $latest = $hotfixes | Where-Object { $_.Date } | Select-Object -First 1
    if ($latest) {
        $result.LatestUpdate = [ordered]@{
            HotFixID    = $latest.HotFixID
            Description = $latest.Description
            InstalledOn = $latest.Date.ToString('yyyy-MM-dd')
        }
        Write-Host "`n  Most recent dated update (context): $($latest.HotFixID) ($($latest.Description)) on $($latest.Date.ToString('yyyy-MM-dd'))"
    }

    Write-Host "`n  All installed updates (most recent first):"
    $hotfixes |
        Select-Object HotFixID, Description,
            @{ N = 'InstalledOn'; E = { if ($_.Date) { $_.Date.ToString('yyyy-MM-dd') } else { '(date n/a)' } } } |
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
            # definition updates, so guard the access and filter that noise out. Wrap in
            # @() so an all-filtered result counts as 0, not 1.
            $history = @($searcher.QueryHistory(0, $count) | ForEach-Object {
                    $rc = try { $_.ResultCode } catch { $null }
                    if ($_.Operation -eq 1 -and ($rc -eq 2 -or $rc -eq 3) -and $_.Title -and
                        $_.Title -notmatch 'Defender|Security Intelligence|Definition Update|Antivirus|Antimalware') {
                        [PSCustomObject]@{ Date = $_.Date; Title = $_.Title }
                    }
                } | Sort-Object Date -Descending)
            Write-Host "  $($history.Count) installed updates in agent history (excluding definition updates; most recent 25 shown):"
            $history | Select-Object -First 25 @{ N = 'Date'; E = { $_.Date.ToString('yyyy-MM-dd') } }, Title |
                Format-Table -AutoSize -Wrap
        } else {
            Write-Host "  Windows Update agent reported no history." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Could not query the Windows Update agent: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Patch verdict from the OS build revision (authoritative; independent of install dates).
Write-Host "`n  [Patch Assessment]"
$patchVerdict = 'Unconfirmed'
if ($julyMinUbr.ContainsKey($buildNum)) {
    if ($ubrNum -le 0) {
        # Every shipped Win10/11 build has UBR >= 1; a 0 here means the revision could not
        # be read (e.g. blocked registry access), which is "unknown", not "below the floor".
        # Treat it as Unconfirmed rather than wrongly declaring a patched host Vulnerable.
        $patchVerdict = 'Unconfirmed'
        Write-Host "  Build $buildString maps to an affected version, but its revision (UBR) could not be" -ForegroundColor Yellow
        Write-Host "  read, so patch level is unconfirmed. Verify it meets $buildNum.$($julyMinUbr[$buildNum]) or later." -ForegroundColor Yellow
        $result.Notes += "UBR unreadable for affected build $buildNum; patch level unconfirmed."
    } else {
        $result.HasRceFix     = $ubrNum -ge $julyMinUbr[$buildNum]
        $result.HasAugDefault = $augMinUbr.ContainsKey($buildNum) -and ($ubrNum -ge $augMinUbr[$buildNum])
        if ($result.HasRceFix) {
            $patchVerdict = 'Patched'
            Write-Host "  OS build $buildString meets/exceeds $buildNum.$($julyMinUbr[$buildNum]), the revision that first" -ForegroundColor Green
            Write-Host "  carried the CVE-2021-34527 Spooler RCE fix. Patched." -ForegroundColor Green
        } else {
            $patchVerdict = 'Vulnerable'
            Write-Host "  OS build $buildString is BELOW $buildNum.$($julyMinUbr[$buildNum]), the revision that first carried" -ForegroundColor Red
            Write-Host "  the CVE-2021-34527 fix. This host is MISSING the PrintNightmare patch." -ForegroundColor Red
            $result.Notes += "OS build $buildString is below the patched revision $buildNum.$($julyMinUbr[$buildNum])."
        }
    }
} elseif ($buildNum -gt $highestAffectedBuild) {
    $result.HasRceFix     = $true
    $result.HasAugDefault = $true
    $patchVerdict = 'Patched'
    Write-Host "  OS build $buildString first shipped after the August 10 2021 updates, so it" -ForegroundColor Green
    Write-Host "  inherently contains both the CVE-2021-34527 fix and the admin-only default. Patched." -ForegroundColor Green
} else {
    $patchVerdict = 'Unconfirmed'
    Write-Host "  Could not map build $buildString to a known patched revision (legacy/EOL or" -ForegroundColor Yellow
    Write-Host "  unrecognised build). Verify it meets the 2021-07-06 out-of-band level manually." -ForegroundColor Yellow
    $result.Notes += "Build $buildString not in the known-patched table; verify against baseline."
}
$result.PatchVerdict = $patchVerdict

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
# (admin-only) default once the August 10 2021 update is installed. On a July-2021-only
# host the absent default is 0 (exposed). We resolve that from the build (HasAugDefault),
# not from an install date.
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
    if ($result.HasAugDefault) {
        Write-Host "  RestrictDriverInstallationToAdministrators not set, but this build is at/after the" -ForegroundColor Green
        Write-Host "  August 10 2021 update, where the default is 1 (admin-only). Good." -ForegroundColor Green
    } else {
        Write-Host "  RestrictDriverInstallationToAdministrators not set, and this build is not confirmed" -ForegroundColor Yellow
        Write-Host "  at the August 10 2021 level where the admin-only default applies. For a guaranteed" -ForegroundColor Yellow
        Write-Host "  posture, set this value explicitly to 1 (DWORD)." -ForegroundColor Yellow
        $registrySafe = $false
        $result.Notes += 'RestrictDriverInstallationToAdministrators not set and Aug-2021 default not confirmed; set it to 1.'
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
$result.Exposed = (-not $registrySafe) -or ($patchVerdict -eq 'Vulnerable')
Write-Host "`n=== Overall Result ===" -ForegroundColor Cyan
$patchColor = switch ($patchVerdict) { 'Patched' { 'Green' } 'Vulnerable' { 'Red' } default { 'Yellow' } }
Write-Host "  Patch posture        : $patchVerdict ($($result.OS) - $buildString)" -ForegroundColor $patchColor
if ($registrySafe) {
    Write-Host "  Registry mitigations : SAFE (driver install restricted to administrators)" -ForegroundColor Green
} else {
    Write-Host "  Registry mitigations : EXPOSED / UNCONFIRMED" -ForegroundColor Red
}
Write-Host ""
if ($registrySafe -and $patchVerdict -eq 'Patched') {
    Write-Host "  RESULT: Host carries the PrintNightmare patch AND the Point and Print registry" -ForegroundColor Green
    Write-Host "          mitigations are in a safe configuration. Protected." -ForegroundColor Green
} elseif ($patchVerdict -eq 'Vulnerable' -or -not $registrySafe) {
    Write-Host "  RESULT: This host is EXPOSED to PrintNightmare." -ForegroundColor Red
    if ($patchVerdict -eq 'Vulnerable') {
        Write-Host "          Install the latest cumulative update (it is below the patched revision)." -ForegroundColor Red
    }
    if (-not $registrySafe) {
        Write-Host "          Correct the registry settings flagged above." -ForegroundColor Red
    }
} else {
    Write-Host "  RESULT: Registry mitigations are safe, but the patch level could not be confirmed" -ForegroundColor Yellow
    Write-Host "          from the build. Verify the OS build meets your baseline, then re-run." -ForegroundColor Yellow
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
