<#
.SYNOPSIS
    Detects and removes known PUPs: Wave Browser, Blazer Browser, and Crystal PDF.

.DESCRIPTION
    Sweeps running processes, scheduled tasks, per-user install folders
    (AppData / profile root), leftover installers in Downloads, registry
    persistence (Run/RunOnce values, vendor keys, uninstall entries), and
    Desktop / Start Menu shortcuts for each targeted PUP, then removes what
    it finds.

    Run elevated to clean every profile on the machine; a non-elevated run
    is limited to the current user's profile and hive.

.PARAMETER DetectOnly
    Report findings without removing anything (dry run).

.PARAMETER Target
    Subset of PUPs to process. Default: all three.

.EXAMPLE
    .\remove-pups.ps1 -DetectOnly

.EXAMPLE
    .\remove-pups.ps1 -Target WaveBrowser, CrystalPDF

.NOTES
    Exit codes: 0 = clean, or all found artifacts were removed;
                1 = -DetectOnly run found artifacts;
                2 = one or more removals failed (reboot and re-run).
#>
[CmdletBinding()]
param(
    [switch]$DetectOnly,

    [ValidateSet('WaveBrowser', 'Blazer', 'CrystalPDF')]
    [string[]]$Target = @('WaveBrowser', 'Blazer', 'CrystalPDF')
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# PUP definitions.
#
# MatchPattern is the single source of truth for "does this string belong to
# the PUP" and is applied to task names/actions, registry names/values,
# uninstall entries, installer names, and shortcuts. Patterns are kept
# deliberately narrow: bare 'wave' would hit Waves MaxxAudio (WavesSvc*) on
# Dell machines and bare 'blazer' would hit anything named Trailblazer, so
# 'wave' requires the full brand names and 'blazer' forbids a preceding
# letter. FolderNames are matched EXACTLY under each profile root — no
# wildcards touch the filesystem.
# ---------------------------------------------------------------------------
$PupDefinitions = @(
    @{
        # WaveBrowser ships with an Omaha-fork updater ("Wavesor SWUpdater")
        # that reinstalls it via per-SID scheduled tasks, and is commonly
        # co-installed with its sibling PUP WebNavigatorBrowser (same
        # Wavesor/Polarity lineage) — both are covered here.
        Name             = 'WaveBrowser'
        # 'webnavigator' MUST keep its 'browser' suffix requirement: bare
        # 'webnavigator' matches Siemens SIMATIC WinCC WebNavigator (SCADA).
        ProcessPattern   = '(?i)^(wavebrowser|webnavigatorbrowser)'
        MatchPattern     = '(?i)(?<![a-z])wave[\s_-]*browser|wavesor|swupdatertaskuser|webnavigator[\s_-]*browser|wavebrws'
        FolderNames      = @('WaveBrowser', 'Wavesor Software', 'WaveSor', 'WebNavigatorBrowser')
        ProfileRootFolderNames = @('WaveBrowser', 'Wavesor Software', 'WaveSor', 'WebNavigatorBrowser')
        MachineFolders   = @("$env:ProgramFiles\Wavesor", "${env:ProgramFiles(x86)}\Wavesor")
        RegistrySubKeys  = @(
            'Software\WaveBrowser',
            'Software\Wavesor',
            'Software\WebNavigatorBrowser',
            'Software\Microsoft\Windows\CurrentVersion\App Paths\wavebrowser.exe',
            'Software\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser',
            'Software\Microsoft\Windows\CurrentVersion\Uninstall\WebNavigatorBrowser',
            'Software\Classes\CLSID\{9CD78CBC-FD21-4FFF-B452-9D792A58B7C4}'  # SWUpdater COM class
        )
        MachineRegistryKeys = @(
            'HKLM:\SOFTWARE\Wavesor',
            'HKLM:\SOFTWARE\WOW6432Node\Wavesor',
            'HKLM:\SOFTWARE\Policies\Wavesor'
        )
    },
    @{
        # PUP.Optional.BlazerBrowser (Malwarebytes). Chromium PUP browser;
        # its browser process is new_blazer.exe / new_blazer_proxy.exe, its
        # updater blazer_updater.exe runs via the BlazerBrowserUpdateTask
        # scheduled task. MatchPattern never matches a standalone 'Blazer'
        # word — a user's own C:\Users\<x>\Blazer folder, 'Chevy Blazer'
        # shortcuts, trailblazer gems and BlazeRush all stay untouched.
        # It requires browser context ('blazer...browser'), an attested
        # compound (blazer_updater / blazer_installer / blazer.exe), or the
        # install path shape \Blazer\Application / \Blazer\User Data. The
        # bare install folder and registry keys are handled by the exact
        # FolderNames / RegistrySubKeys lists instead. Generic helpers
        # (notification_helper.exe, setup.exe) are caught by their image
        # path under ...\Blazer\Application\ instead of by name.
        Name             = 'Blazer'
        ProcessPattern   = '(?i)^(new_)?blazer(?=browser|[\s\\/._-]|$)'
        MatchPattern     = '(?i)(?<![a-z])blazer[\s_-]*browser|(?<![a-z])blazer_(updater|installer)|[\\/]blazer[\\/](application|user data)|(?<![a-z])blazer\.exe$'
        FolderNames      = @('Blazer', 'BlazerBrowser', 'Blazer Browser')
        ProfileRootFolderNames = @()
        MachineFolders   = @()
        RegistrySubKeys  = @(
            'Software\Blazer',
            'Software\BlazerBrowser',
            'Software\Classes\BlazerHTML',
            'Software\Clients\StartMenuInternet\Blazer',
            'Software\Microsoft\Windows\CurrentVersion\App Paths\blazer.exe',
            'Software\Microsoft\Windows\CurrentVersion\Uninstall\Blazer',
            'Software\Microsoft\Windows\CurrentVersion\Uninstall\BlazerBrowser'
        )
        MachineRegistryKeys = @()
        RegisteredAppNames  = @('Blazer')
    },
    @{
        # Crystal PDF is worse than a bundler PUP: 2025 vendor writeups
        # (Microsoft Defender Experts, CIS, GDATA) describe it as a
        # trojanized fake PDF editor / infostealer. Its own uninstaller is
        # fake — it removes shortcuts and uninstall keys but leaves the
        # payload (%LOCALAPPDATA%\Temp\crys\CrystalPDF.exe) and its
        # 'Crystal_updater' scheduled task running.
        Name             = 'CrystalPDF'
        ProcessPattern   = '(?i)^crystal[\s_-]*pdf'
        MatchPattern     = '(?i)crystal[\s_-]*pdf|(?<![a-z])crystal_updater(?![a-z])'  # 'pdf' token required — skips Crystal Reports / CrystalDiskInfo
        FolderNames      = @('CrystalPDF', 'Crystal PDF')
        # Temp\crys is only removed when the attested payload is inside it —
        # the folder name alone is too generic to delete blind.
        GuardedFolders   = @(@{ Path = 'Temp\crys'; Marker = 'CrystalPDF*.exe' })
        ProfileRootFolderNames = @()
        MachineFolders   = @()
        RegistrySubKeys  = @(
            'Software\CrystalPDF',
            'Software\Crystal PDF',
            'Software\Microsoft\Windows\CurrentVersion\Uninstall\CrystalPDF',
            'Software\Microsoft\Windows\CurrentVersion\Uninstall\Crystal PDF'
        )
        MachineRegistryKeys = @()
        PostRemovalNote  = 'Crystal PDF is a credential-stealing trojan, not just adware. Treat this machine as compromised: reset the user''s passwords, revoke active browser sessions, and review sign-in logs.'
    }
)

# ---------------------------------------------------------------------------
# Setup: findings log, elevation check, profile + hive enumeration
# ---------------------------------------------------------------------------
$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param([string]$Pup, [string]$Category, [string]$Item, [string]$Status, [string]$Detail = '')
    $findings.Add([PSCustomObject]@{
        PUP      = $Pup
        Category = $Category
        Item     = $Item
        Status   = $Status
        Detail   = $Detail
    })
    $color = switch ($Status) {
        'Removed'  { 'Green' }
        'Detected' { 'Yellow' }
        'Failed'   { 'Red' }
        default    { 'Gray' }
    }
    Write-Host ("  [{0}] {1}: {2}" -f $Status, $Category, $Item) -ForegroundColor $color
    if ($Detail -and $Status -eq 'Failed') { Write-Host ("          {0}" -f $Detail) -ForegroundColor DarkRed }
}

# Runs $Action unless -DetectOnly; records the outcome either way.
function Invoke-Action {
    param([string]$Pup, [string]$Category, [string]$Item, [scriptblock]$Action)
    if ($DetectOnly) {
        Add-Finding -Pup $Pup -Category $Category -Item $Item -Status 'Detected'
        return
    }
    try {
        & $Action
        Add-Finding -Pup $Pup -Category $Category -Item $Item -Status 'Removed'
    }
    catch {
        Add-Finding -Pup $Pup -Category $Category -Item $Item -Status 'Failed' -Detail $_.Exception.Message
    }
}

function Write-Section([string]$Name) {
    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'Not elevated — sweeping the current user profile only. Run as admin to clean all profiles.'
}

# Profile folders to sweep for files/shortcuts.
$profileDirs = @(
    if ($isAdmin) {
        Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Directory |
            Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |
            Select-Object -ExpandProperty FullName
    }
    else {
        $env:USERPROFILE
    }
)

# Registry user hives to sweep. HKCU always; when elevated, every loaded
# user hive under HKEY_USERS as well (skipping the current user's SID so we
# don't sweep the same hive twice). Hives of logged-off users aren't loaded
# and are not touched.
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$userHives  = @('HKCU:')
if ($isAdmin) {
    $userHives += Get-ChildItem -Path 'Registry::HKEY_USERS' |
        Where-Object { $_.PSChildName -like 'S-1-5-21-*' -and
                       $_.PSChildName -notlike '*_Classes' -and
                       $_.PSChildName -ne $currentSid } |
        ForEach-Object { "Registry::HKEY_USERS\$($_.PSChildName)" }
}

$activePups = @($PupDefinitions | Where-Object { $_.Name -in $Target })

$mode = if ($DetectOnly) { 'DETECT ONLY' } else { 'DETECT + REMOVE' }
Write-Host ("PUP sweep [{0}] — targets: {1}" -f $mode, (($activePups | ForEach-Object { $_.Name }) -join ', '))

# ---------------------------------------------------------------------------
# 1. Processes — kill anything matching by name or by executable path
# ---------------------------------------------------------------------------
Write-Section 'Processes'
$allProcs = @(Get-Process | Select-Object Id, Name, Path)
$killedAny = $false
foreach ($pup in $activePups) {
    $hits = @($allProcs | Where-Object {
        $_.Name -match $pup.ProcessPattern -or ($_.Path -and $_.Path -match $pup.MatchPattern)
    })
    foreach ($p in $hits) {
        $procId = $p.Id
        Invoke-Action -Pup $pup.Name -Category 'Process' -Item ("{0} (PID {1}) {2}" -f $p.Name, $p.Id, $p.Path) -Action {
            Stop-Process -Id $procId -Force -ErrorAction Stop
        }.GetNewClosure()
        $killedAny = $true
    }
}
if ($killedAny -and -not $DetectOnly) { Start-Sleep -Seconds 2 }  # let file locks release

# ---------------------------------------------------------------------------
# 2. Scheduled tasks — match on task name, path, or action command line
# ---------------------------------------------------------------------------
Write-Section 'Scheduled Tasks'
if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    Write-Warning 'ScheduledTasks module unavailable — task sweep skipped. WaveBrowser reinstalls via its tasks; remove them with schtasks.exe manually.'
}
# Blob fields are joined with ' | ' (never a bare space) so a pattern like
# 'crystal[\s_-]*pdf' cannot match across two adjacent fields. Only the
# action's executable path is included — matching on arguments would flag
# legit tasks that merely mention a PUP path (e.g. a backup job).
$allTasks = @(Get-ScheduledTask | ForEach-Object {
    $actStr = ($_.Actions | ForEach-Object { $_.Execute }) -join ' | '
    [PSCustomObject]@{ Task = $_; Blob = "$($_.TaskName) | $($_.TaskPath) | $actStr" }
})
foreach ($pup in $activePups) {
    foreach ($t in @($allTasks | Where-Object { $_.Blob -match $pup.MatchPattern })) {
        $taskName = $t.Task.TaskName
        $taskPath = $t.Task.TaskPath
        Invoke-Action -Pup $pup.Name -Category 'ScheduledTask' -Item "$taskPath$taskName" -Action {
            Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
        }.GetNewClosure()
    }
}

# ---------------------------------------------------------------------------
# 3. Install folders — exact folder names under each profile's known roots.
#    Generic names (e.g. 'Blazer') are only removed from AppData install
#    scopes; the profile root is swept only for ProfileRootFolderNames
#    (distinctive names like 'Wavesor Software') so a user's own
#    C:\Users\<x>\Blazer folder can never match.
# ---------------------------------------------------------------------------
Write-Section 'Install Folders'
foreach ($userDir in $profileDirs) {
    $appDataRoots = @(
        (Join-Path $userDir 'AppData\Local'),
        (Join-Path $userDir 'AppData\Roaming'),
        (Join-Path $userDir 'AppData\Local\Programs')
    )
    foreach ($pup in $activePups) {
        $candidates = @(
            foreach ($root in $appDataRoots) {
                foreach ($folder in $pup.FolderNames) { Join-Path $root $folder }
            }
            foreach ($folder in $pup.ProfileRootFolderNames) { Join-Path $userDir $folder }
        )
        foreach ($path in @($candidates | Where-Object { Test-Path -LiteralPath $_ })) {
            Invoke-Action -Pup $pup.Name -Category 'Folder' -Item $path -Action {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            }.GetNewClosure()
        }
        # Guarded folders: generic names only removed when the PUP's marker
        # file is actually inside (e.g. Temp\crys must contain CrystalPDF*.exe)
        foreach ($guard in @($pup.GuardedFolders)) {
            if (-not $guard) { continue }
            $path = Join-Path (Join-Path $userDir 'AppData\Local') $guard.Path
            if ((Test-Path -LiteralPath $path) -and
                @(Get-ChildItem -LiteralPath $path -Filter $guard.Marker -ErrorAction SilentlyContinue).Count -gt 0) {
                Invoke-Action -Pup $pup.Name -Category 'Folder' -Item $path -Action {
                    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                }.GetNewClosure()
            }
        }
    }
}

# Machine-wide install folders (rare — these PUPs are usually per-user).
# The '^\\' filter drops drive-relative paths produced when an env var like
# ProgramFiles(x86) is empty (32-bit Windows).
foreach ($pup in $activePups) {
    foreach ($path in @($pup.MachineFolders | Where-Object { $_ -and $_ -notmatch '^\\' -and (Test-Path -LiteralPath $_) })) {
        Invoke-Action -Pup $pup.Name -Category 'Folder' -Item $path -Action {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        }.GetNewClosure()
    }
}

# ---------------------------------------------------------------------------
# 4. Leftover installers / dropped exes in Downloads and on the Desktop
#    (Crystal PDF drops a decoy 'Crystal PDF.exe' on the Desktop)
# ---------------------------------------------------------------------------
Write-Section 'Downloads / Desktop (installers)'
foreach ($userDir in $profileDirs) {
    foreach ($dirName in @('Downloads', 'Desktop')) {
        $dir = Join-Path $userDir $dirName
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $installers = @(Get-ChildItem -LiteralPath $dir -File |
            Where-Object { $_.Extension -in @('.exe', '.msi') })
        foreach ($pup in $activePups) {
            foreach ($f in @($installers | Where-Object { $_.Name -match $pup.MatchPattern })) {
                $filePath = $f.FullName
                Invoke-Action -Pup $pup.Name -Category 'Installer' -Item $filePath -Action {
                    Remove-Item -LiteralPath $filePath -Force -ErrorAction Stop
                }.GetNewClosure()
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Registry — vendor keys, Run/RunOnce persistence, uninstall entries
# ---------------------------------------------------------------------------
Write-Section 'Registry'
foreach ($pup in $activePups) {

    # 5a. Known vendor/uninstall keys in each user hive, plus HKLM keys
    $vendorKeys = @(
        foreach ($hive in $userHives) {
            foreach ($subKey in $pup.RegistrySubKeys) { Join-Path $hive $subKey }
        }
        $pup.MachineRegistryKeys
    )
    foreach ($keyPath in @($vendorKeys | Where-Object { $_ -and (Test-Path -LiteralPath $_) })) {
        Invoke-Action -Pup $pup.Name -Category 'RegistryKey' -Item $keyPath -Action {
            Remove-Item -LiteralPath $keyPath -Recurse -Force -ErrorAction Stop
        }.GetNewClosure()
    }

    # 5b. Run/RunOnce values (user hives + HKLM) whose name or data matches
    $runKeys = @(
        foreach ($hive in $userHives) {
            Join-Path $hive 'Software\Microsoft\Windows\CurrentVersion\Run'
            Join-Path $hive 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
        }
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($runKey in $runKeys) {
        $key = Get-Item -LiteralPath $runKey -ErrorAction SilentlyContinue
        if (-not $key) { continue }
        foreach ($valueName in $key.GetValueNames()) {
            $valueData = $key.GetValue($valueName)
            if ("$valueName | $valueData" -match $pup.MatchPattern) {
                Invoke-Action -Pup $pup.Name -Category 'RunValue' -Item "$runKey : $valueName = $valueData" -Action {
                    Remove-ItemProperty -LiteralPath $runKey `
                        -Name ([Management.Automation.WildcardPattern]::Escape($valueName)) -Force -ErrorAction Stop
                }.GetNewClosure()
            }
        }
    }

    # 5c. Uninstall entries whose DisplayName/Publisher matches
    $uninstallRoots = @(
        foreach ($hive in $userHives) {
            Join-Path $hive 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
        }
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $uninstallRoots) {
        foreach ($entry in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $entry.PSPath -ErrorAction SilentlyContinue
            $blob = @($entry.PSChildName, $props.DisplayName, $props.Publisher, $props.InstallLocation) -join ' | '
            if ($blob -match $pup.MatchPattern) {
                $entryPath = $entry.PSPath
                Invoke-Action -Pup $pup.Name -Category 'UninstallEntry' -Item ("{0} ({1})" -f $entry.PSChildName, $props.DisplayName) -Action {
                    Remove-Item -LiteralPath $entryPath -Recurse -Force -ErrorAction Stop
                }.GetNewClosure()
            }
        }
    }

    # 5d. Browser registration + leftover COM/protocol classes. These PUP
    #     browsers register under StartMenuInternet/RegisteredApplications
    #     and drop ProgId classes (WaveBrwsHTM*, WavesorSWUpdater.*), often
    #     with a random per-install hash suffix — so match subkey names by
    #     pattern instead of listing them. HKLM is included when elevated
    #     since browser registration can also land machine-wide.
    $regHives = @($userHives)
    if ($isAdmin) { $regHives += 'HKLM:' }
    foreach ($hive in $regHives) {
        foreach ($scanRoot in @('Software\Clients\StartMenuInternet', 'Software\Classes')) {
            $rootPath = Join-Path $hive $scanRoot
            foreach ($sub in @(Get-ChildItem -LiteralPath $rootPath -ErrorAction SilentlyContinue |
                               Where-Object { $_.PSChildName -match $pup.MatchPattern })) {
                $subPath = $sub.PSPath
                Invoke-Action -Pup $pup.Name -Category 'RegistryKey' -Item ($subPath -replace '^.*::', '') -Action {
                    Remove-Item -LiteralPath $subPath -Recurse -Force -ErrorAction Stop
                }.GetNewClosure()
            }
        }
        $regAppsPath = Join-Path $hive 'Software\RegisteredApplications'
        $regApps = Get-Item -LiteralPath $regAppsPath -ErrorAction SilentlyContinue
        if ($regApps) {
            foreach ($valueName in @($regApps.GetValueNames() |
                     Where-Object { $_ -match $pup.MatchPattern -or $_ -in @($pup.RegisteredAppNames) })) {
                Invoke-Action -Pup $pup.Name -Category 'RegistryValue' -Item "$regAppsPath : $valueName" -Action {
                    Remove-ItemProperty -LiteralPath $regAppsPath `
                        -Name ([Management.Automation.WildcardPattern]::Escape($valueName)) -Force -ErrorAction Stop
                }.GetNewClosure()
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 5e. MSIX/Store packages (a 'Blazer Browser' Microsoft Store listing exists)
# ---------------------------------------------------------------------------
$appxPackages = @(
    if ($isAdmin) { Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue }
    else          { Get-AppxPackage -ErrorAction SilentlyContinue }
)
# Remove-AppxPackage -AllUsers only exists on Win10 1709+; probe for it.
$removeAppxCmd = Get-Command Remove-AppxPackage -ErrorAction SilentlyContinue
$appxAllUsers  = $isAdmin -and $removeAppxCmd -and $removeAppxCmd.Parameters.ContainsKey('AllUsers')
foreach ($pup in $activePups) {
    foreach ($pkg in @($appxPackages | Where-Object { $_.Name -match $pup.MatchPattern })) {
        $pkgFullName = $pkg.PackageFullName
        Invoke-Action -Pup $pup.Name -Category 'AppxPackage' -Item $pkgFullName -Action {
            if ($appxAllUsers) { Remove-AppxPackage -Package $pkgFullName -AllUsers -ErrorAction Stop }
            else               { Remove-AppxPackage -Package $pkgFullName -ErrorAction Stop }
        }.GetNewClosure()
    }
}

# ---------------------------------------------------------------------------
# 6. Shortcuts — Desktop / Start Menu .lnk files matching the PUP name
# ---------------------------------------------------------------------------
Write-Section 'Shortcuts'
$shortcutRoots = @(
    foreach ($userDir in $profileDirs) {
        Join-Path $userDir 'Desktop'
        Join-Path $userDir 'AppData\Roaming\Microsoft\Windows\Start Menu'
        Join-Path $userDir 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch'
    }
    "$env:PUBLIC\Desktop"
    "$env:ProgramData\Microsoft\Windows\Start Menu"
) | Where-Object { Test-Path -LiteralPath $_ }

# A shortcut is removed when its resolved target is a PUP path, or when its
# name matches and the target can't be read. A matching NAME with a clean,
# readable target is left alone (e.g. a user's own 'Crystal PDF invoices.lnk'
# pointing at a documents folder).
$wsShell = $null
try { $wsShell = New-Object -ComObject WScript.Shell } catch { }
foreach ($root in $shortcutRoots) {
    $links = @(Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -Force -ErrorAction SilentlyContinue)
    foreach ($pup in $activePups) {
        foreach ($lnk in $links) {
            $target = ''
            if ($wsShell) {
                try { $target = $wsShell.CreateShortcut($lnk.FullName).TargetPath } catch { }
            }
            $nameHit   = $lnk.Name -match $pup.MatchPattern
            $targetHit = $target -and ($target -match $pup.MatchPattern)
            if (-not ($targetHit -or ($nameHit -and -not $target))) { continue }
            $lnkPath = $lnk.FullName
            Invoke-Action -Pup $pup.Name -Category 'Shortcut' -Item "$lnkPath -> $target" -Action {
                Remove-Item -LiteralPath $lnkPath -Force -ErrorAction Stop
            }.GetNewClosure()
        }
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Section 'Summary'
if ($findings.Count -eq 0) {
    Write-Host 'Clean — no PUP artifacts found.' -ForegroundColor Green
    exit 0
}

$findings | Sort-Object PUP, Category | Format-Table PUP, Category, Status, Item -AutoSize

$failed = @($findings | Where-Object { $_.Status -eq 'Failed' })
foreach ($group in ($findings | Group-Object PUP)) {
    Write-Host ("{0}: {1} artifact(s)" -f $group.Name, $group.Count)
}

# Per-PUP follow-up guidance (e.g. Crystal PDF steals credentials)
foreach ($pup in $activePups) {
    if ($pup.PostRemovalNote -and ($findings | Where-Object { $_.PUP -eq $pup.Name })) {
        Write-Warning $pup.PostRemovalNote
    }
}

if ($failed.Count -gt 0) {
    Write-Warning ("{0} removal(s) failed — see details above. A reboot may release locked files; re-run afterwards." -f $failed.Count)
    exit 2
}
if ($DetectOnly) {
    Write-Host "`nDetect-only run — nothing was removed. Re-run without -DetectOnly to remove." -ForegroundColor Yellow
    exit 1
}
exit 0
