<#
.SYNOPSIS
    Checks whether this Windows computer is protected against the PrintNightmare
    vulnerability, and prints a single Protected / Exposed / Unconfirmed result.

.DESCRIPTION
    PrintNightmare is a Windows Print Spooler vulnerability (CVE-2021-1675 and
    CVE-2021-34527). A computer is protected when BOTH of these are true:
      * the Windows security update that fixes it is installed, AND
      * the Point and Print printer-driver settings are configured safely.

    This script checks both in one read-only pass and reports where the computer
    stands. It makes no changes to the system.

    WHAT IT CHECKS
      1. Print Spooler service - whether the service the exploit abuses is present
         and running.
      2. Patch level - the installed Windows updates plus the exact OS build and
         revision (Build.UBR), compared against the revision Microsoft first shipped
         the fix in, to confirm the PrintNightmare update is present.
      3. Point and Print registry settings - the three values that decide whether a
         non-administrator can install printer drivers:
           - RestrictDriverInstallationToAdministrators: should be 1 (or absent on a
             computer patched Aug 2021 or later) - restricts driver installs to admins.
           - NoWarningNoElevationOnInstall: should be 0 or absent - a 1 suppresses the
             elevation prompt when installing a driver.
           - UpdatePromptSettings: should be 0 or absent - a 1 suppresses the elevation
             prompt when updating a driver.

    WHAT YOU GET
      * A readable report for each section, ending in one overall result:
        Protected, Exposed, or Unconfirmed (the patch level could not be determined).
      * With -AsJson, a single JSON object is written to stdout instead, for automated
        or fleet use. In normal mode a one-line summary is also printed:
        "PrintNightmare: Status=...; Patch=...; Registry=...; Build=...; Computer=...".
      * Exit codes: 0 = ran successfully (read the Status for the verdict),
        3 = the script hit an error. With -FailOnExposed it exits 1 when Exposed.

    HOW TO RUN
      Open PowerShell as Administrator (for the most complete update inventory), then:
        .\printnightmare-check.ps1
      For automated collection that captures and parses output:
        .\printnightmare-check.ps1 -AsJson

.PARAMETER AsJson
    Emit only a single JSON result object to stdout and suppress the readable report.
    Use when output is captured and parsed centrally (automated or fleet runs).

.PARAMETER FailOnExposed
    Exit 1 when the overall verdict is EXPOSED. Off by default, so a healthy run does
    not look like a failed task to a remote runner. Script errors always exit 3.

.PARAMETER IncludeUpdateHistory
    Also list the Windows Update agent history (a fuller list than Get-HotFix, which
    only sees CBS-serviced updates). Slower and noisier; off by default. Ignored under -AsJson.

.PARAMETER ExportJson
    Optional path to also write the structured result to a JSON file.

.EXAMPLE
    .\printnightmare-check.ps1
    Runs the check and prints the readable report.

.EXAMPLE
    .\printnightmare-check.ps1 -AsJson
    Prints a single JSON result object to stdout, for automated collection.

.NOTES
    Read-only; makes no changes. Run as Administrator (or SYSTEM) for the most complete
    update inventory.
    PrintNightmare: CVE-2021-1675 / CVE-2021-34527 (plus the Aug 2021 Point and Print
    default change, CVE-2021-34481). Build/UBR thresholds verified against Microsoft
    Support KB pages (KB5004945/46/47/48/50, KB5005033/31/30/43/40, KB5005652).
#>
[CmdletBinding()]
param(
    [switch]$AsJson,
    [switch]$FailOnExposed,
    [switch]$IncludeUpdateHistory,
    [string]$ExportJson
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Quiet = [bool]$AsJson

# Any unexpected terminating error is reported on stdout (the channel a remote runner
# captures) and exits 3, so it is never mistaken for a posture verdict.
trap {
    if ($script:Quiet) {
        Write-Output ([pscustomobject]@{ OverallStatus = 'Error'; Error = "$($_.Exception.Message)" } | ConvertTo-Json -Compress)
    } else {
        Write-Output "PrintNightmare: Status=Error; Detail=$($_.Exception.Message)"
    }
    exit 3
}

# Human-readable output helper. Auto-suppressed under -AsJson so stdout stays pure JSON.
function Say {
    param([string]$Text = '', [string]$Color)
    if ($script:Quiet) { return }
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

Say "=== PrintNightmare Posture Check ===" 'Cyan'

# Structured result, used for -AsJson stdout and the optional JSON file export.
$result = [ordered]@{
    ComputerName    = $env:COMPUTERNAME
    OS              = $null
    OSBuild         = $null
    OverallStatus   = $null
    PatchVerdict    = $null
    HasRceFix       = $false
    HasAugDefault   = $false
    Spooler         = [ordered]@{}
    UpdateCount     = 0
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
Say "`n[Print Spooler Service]"
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($null -eq $spooler) {
    Say "  Spooler service not found on this host (lowest risk)." 'Green'
    $result.Spooler.Status    = 'NotPresent'
    $result.Spooler.StartType = 'NotPresent'
} else {
    Say "  Status     : $($spooler.Status)"
    Say "  StartType  : $($spooler.StartType)"
    $result.Spooler.Status    = "$($spooler.Status)"
    $result.Spooler.StartType = "$($spooler.StartType)"
    if ($spooler.Status -eq 'Running') {
        Say "  -> Spooler is RUNNING. If this host does not need to print or share printers," 'Yellow'
        Say "     disabling it fully removes the PrintNightmare attack surface." 'Yellow'
    } else {
        Say "  -> Spooler is not running (lowest risk)." 'Green'
    }
}

# --------------------------------------------------------------------------
# 2. Installed updates / patch context
# --------------------------------------------------------------------------
Say "`n[Installed Updates / Patch Context]"

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
Say "  $($result.OS)$relLabel - Build $buildString"

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
$result.UpdateCount = $hotfixes.Count

if ($hotfixes.Count -eq 0) {
    Say "  Get-HotFix returned no entries (it only reports CBS-serviced updates, and may" 'Yellow'
    Say "  need an elevated session). The build-based verdict below does not depend on it." 'Yellow'
    $result.Notes += 'Get-HotFix returned no entries.'
} else {
    Say "  Total updates reported by Get-HotFix (CBS): $($hotfixes.Count)"

    # Flag any relevant KBs still listed by number (usually superseded away by a CU).
    $foundRelevant = @($hotfixes | Where-Object { $relevantKbs -contains $_.HotFixID })
    $result.RelevantUpdates = @($foundRelevant | ForEach-Object { $_.HotFixID })
    if ($foundRelevant.Count -gt 0) {
        Say "`n  PrintNightmare-era updates present by KB number:" 'Green'
        Say ($foundRelevant |
                Select-Object HotFixID, Description,
                    @{ N = 'InstalledOn'; E = { if ($_.Date) { $_.Date.ToString('yyyy-MM-dd') } else { '(date n/a)' } } } |
                Format-Table -AutoSize | Out-String)
    } else {
        Say "`n  No PrintNightmare-era KB present by number - expected on a current host, where" 'Gray'
        Say "  the fix is rolled into a later Cumulative Update that supersedes those KBs." 'Gray'
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
        Say "`n  Most recent dated update (context): $($latest.HotFixID) ($($latest.Description)) on $($latest.Date.ToString('yyyy-MM-dd'))"
    }

    Say "`n  All installed updates (most recent first):"
    Say ($hotfixes |
            Select-Object HotFixID, Description,
                @{ N = 'InstalledOn'; E = { if ($_.Date) { $_.Date.ToString('yyyy-MM-dd') } else { '(date n/a)' } } } |
            Format-Table -AutoSize | Out-String)
}

# Optional fuller history via the Windows Update agent (COM). Display-only, so skip under -AsJson.
if ($IncludeUpdateHistory -and -not $script:Quiet) {
    Say "  [Windows Update agent history]"
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
            Say "  $($history.Count) installed updates in agent history (excluding definition updates; most recent 25 shown):"
            Say ($history | Select-Object -First 25 @{ N = 'Date'; E = { $_.Date.ToString('yyyy-MM-dd') } }, Title |
                Format-Table -AutoSize -Wrap | Out-String)
        } else {
            Say "  Windows Update agent reported no history." 'Yellow'
        }
    } catch {
        Say "  Could not query the Windows Update agent: $($_.Exception.Message)" 'Yellow'
    }
}

# Patch verdict from the OS build revision (authoritative; independent of install dates).
Say "`n  [Patch Assessment]"
$patchVerdict = 'Unconfirmed'
if ($julyMinUbr.ContainsKey($buildNum)) {
    if ($ubrNum -le 0) {
        # Every shipped Win10/11 build has UBR >= 1; a 0 here means the revision could not
        # be read (e.g. blocked registry access), which is "unknown", not "below the floor".
        # Treat it as Unconfirmed rather than wrongly declaring a patched host Vulnerable.
        $patchVerdict = 'Unconfirmed'
        Say "  Build $buildString maps to an affected version, but its revision (UBR) could not be" 'Yellow'
        Say "  read, so patch level is unconfirmed. Verify it meets $buildNum.$($julyMinUbr[$buildNum]) or later." 'Yellow'
        $result.Notes += "UBR unreadable for affected build $buildNum; patch level unconfirmed."
    } else {
        $result.HasRceFix     = $ubrNum -ge $julyMinUbr[$buildNum]
        $result.HasAugDefault = $augMinUbr.ContainsKey($buildNum) -and ($ubrNum -ge $augMinUbr[$buildNum])
        if ($result.HasRceFix) {
            $patchVerdict = 'Patched'
            Say "  OS build $buildString meets/exceeds $buildNum.$($julyMinUbr[$buildNum]), the revision that first" 'Green'
            Say "  carried the CVE-2021-34527 Spooler RCE fix. Patched." 'Green'
        } else {
            $patchVerdict = 'Vulnerable'
            Say "  OS build $buildString is BELOW $buildNum.$($julyMinUbr[$buildNum]), the revision that first carried" 'Red'
            Say "  the CVE-2021-34527 fix. This host is MISSING the PrintNightmare patch." 'Red'
            $result.Notes += "OS build $buildString is below the patched revision $buildNum.$($julyMinUbr[$buildNum])."
        }
    }
} elseif ($buildNum -gt $highestAffectedBuild) {
    $result.HasRceFix     = $true
    $result.HasAugDefault = $true
    $patchVerdict = 'Patched'
    Say "  OS build $buildString first shipped after the August 10 2021 updates, so it" 'Green'
    Say "  inherently contains both the CVE-2021-34527 fix and the admin-only default. Patched." 'Green'
} else {
    $patchVerdict = 'Unconfirmed'
    Say "  Could not map build $buildString to a known patched revision (legacy/EOL or" 'Yellow'
    Say "  unrecognised build). Verify it meets the 2021-07-06 out-of-band level manually." 'Yellow'
    $result.Notes += "Build $buildString not in the known-patched table; verify against baseline."
}
$result.PatchVerdict = $patchVerdict

# --------------------------------------------------------------------------
# 3. Point and Print registry mitigations
# --------------------------------------------------------------------------
$pp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
Say "`n[Point and Print Registry Mitigations]"
Say "  ($pp)"

$ppExists      = Test-Path $pp
$restrictAdmin = $null
$noWarnInstall = $null
$updatePrompt  = $null

if (-not $ppExists) {
    Say "  Policy key not present - Point and Print policies are at their OS default." 'Yellow'
} else {
    $restrictAdmin = Get-RegVal $pp "RestrictDriverInstallationToAdministrators"
    $noWarnInstall = Get-RegVal $pp "NoWarningNoElevationOnInstall"
    $updatePrompt  = Get-RegVal $pp "UpdatePromptSettings"

    Say "  RestrictDriverInstallationToAdministrators : $(if ($null -eq $restrictAdmin) {'(not set)'} else {$restrictAdmin})"
    Say "  NoWarningNoElevationOnInstall              : $(if ($null -eq $noWarnInstall) {'(not set)'} else {$noWarnInstall})"
    Say "  UpdatePromptSettings                       : $(if ($null -eq $updatePrompt)  {'(not set)'} else {$updatePrompt})"
}
$result.Registry.RestrictDriverInstallationToAdministrators = $restrictAdmin
$result.Registry.NoWarningNoElevationOnInstall              = $noWarnInstall
$result.Registry.UpdatePromptSettings                       = $updatePrompt

# Registry assessment. Note the nuance: a *missing*
# RestrictDriverInstallationToAdministrators is only the safe (admin-only) default once
# the August 10 2021 update is installed. On a July-2021-only host the absent default is 0
# (exposed). We resolve that from the build (HasAugDefault), not from an install date.
Say "`n  [Registry Assessment]"
$registrySafe = $true
if ($restrictAdmin -eq 0) {
    Say "  RestrictDriverInstallationToAdministrators = 0 -> non-admins can install drivers. EXPOSED." 'Red'
    $registrySafe = $false
} elseif ($restrictAdmin -eq 1) {
    Say "  RestrictDriverInstallationToAdministrators = 1 -> driver install restricted to" 'Green'
    Say "  administrators (the strongest setting; overrides Point and Print policy). Good." 'Green'
} else {
    # Value not set / key absent -> relying on the OS default.
    if ($result.HasAugDefault) {
        Say "  RestrictDriverInstallationToAdministrators not set, but this build is at/after the" 'Green'
        Say "  August 10 2021 update, where the default is 1 (admin-only). Good." 'Green'
    } else {
        Say "  RestrictDriverInstallationToAdministrators not set, and this build is not confirmed" 'Yellow'
        Say "  at the August 10 2021 level where the admin-only default applies. For a guaranteed" 'Yellow'
        Say "  posture, set this value explicitly to 1 (DWORD)." 'Yellow'
        $registrySafe = $false
        $result.Notes += 'RestrictDriverInstallationToAdministrators not set and Aug-2021 default not confirmed; set it to 1.'
    }
}
# Safe value for these two is 0 or not defined; any non-zero value suppresses the prompt.
if ($null -ne $noWarnInstall -and $noWarnInstall -ne 0) {
    Say "  NoWarningNoElevationOnInstall = $noWarnInstall -> elevation prompt suppressed on install. RISK." 'Red'
    $registrySafe = $false
}
if ($null -ne $updatePrompt -and $updatePrompt -ne 0) {
    Say "  UpdatePromptSettings = $updatePrompt -> elevation prompt suppressed on update. RISK." 'Red'
    $registrySafe = $false
}
$result.RegistrySafe = $registrySafe

Say ""
if ($registrySafe) {
    Say "  RESULT: Registry settings are in a safe configuration." 'Green'
} else {
    Say "  RESULT: Registry settings leave this host EXPOSED (or unconfirmed) - see above." 'Red'
}

# --------------------------------------------------------------------------
# 4. Combined overall result
# --------------------------------------------------------------------------
$overall = 'Unconfirmed'
if ($registrySafe -and $patchVerdict -eq 'Patched') {
    $overall = 'Protected'
} elseif ($patchVerdict -eq 'Vulnerable' -or -not $registrySafe) {
    $overall = 'Exposed'
}
$result.OverallStatus = $overall
$result.Exposed = ($overall -eq 'Exposed')

Say "`n=== Overall Result ===" 'Cyan'
$patchColor = switch ($patchVerdict) { 'Patched' { 'Green' } 'Vulnerable' { 'Red' } default { 'Yellow' } }
Say "  Patch posture        : $patchVerdict ($($result.OS) - $buildString)" $patchColor
if ($registrySafe) {
    Say "  Registry mitigations : SAFE (driver install restricted to administrators)" 'Green'
} else {
    Say "  Registry mitigations : EXPOSED / UNCONFIRMED" 'Red'
}
Say ""
if ($overall -eq 'Protected') {
    Say "  RESULT: Host carries the PrintNightmare patch AND the Point and Print registry" 'Green'
    Say "          mitigations are in a safe configuration. Protected." 'Green'
} elseif ($overall -eq 'Exposed') {
    Say "  RESULT: This host is EXPOSED to PrintNightmare." 'Red'
    if ($patchVerdict -eq 'Vulnerable') {
        Say "          Install the latest cumulative update (it is below the patched revision)." 'Red'
    }
    if (-not $registrySafe) {
        Say "          Correct the registry settings flagged above." 'Red'
    }
} else {
    Say "  RESULT: Registry mitigations are safe, but the patch level could not be confirmed" 'Yellow'
    Say "          from the build. Verify the OS build meets your baseline, then re-run." 'Yellow'
}

# --------------------------------------------------------------------------
# 5. Machine-readable output + exit (the channel a remote runner captures)
# --------------------------------------------------------------------------
if ($script:Quiet) {
    Write-Output ($result | ConvertTo-Json -Depth 6)
} else {
    Write-Output "PrintNightmare: Status=$overall; Patch=$patchVerdict; Registry=$(if ($registrySafe) {'Safe'} else {'Exposed'}); Build=$buildString; Computer=$($env:COMPUTERNAME)"
}

if ($ExportJson) {
    try {
        $result | ConvertTo-Json -Depth 6 | Set-Content -Path $ExportJson -Encoding UTF8
        Say "`n  Structured result written to $ExportJson" 'Cyan'
    } catch {
        Say "`n  Failed to write JSON to ${ExportJson}: $($_.Exception.Message)" 'Yellow'
    }
}

$exitCode = 0
if ($FailOnExposed -and $overall -eq 'Exposed') { $exitCode = 1 }
exit $exitCode
