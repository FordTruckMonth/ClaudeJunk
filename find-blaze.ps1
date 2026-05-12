# Identifies Blaze / Blazer browser artifacts on this Windows system.
# Read-only — reports matches, does not modify or delete anything.

[CmdletBinding()]
param(
    [string]$Pattern = 'blaze',
    [int]   $Depth   = 3,
    [string]$ExportCsv
)

$ErrorActionPreference = 'SilentlyContinue'
# Word-boundary match: catches 'Blaze', 'Blazer', 'BlazerBrowser' but skips 'Trailblazer'.
$rx = "(?i)\b$Pattern"
$results = [ordered]@{}

function Write-Section([string]$Name) {
    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
}

# 1. Scheduled Tasks
Write-Section 'Scheduled Tasks'
$tasks = @(Get-ScheduledTask | ForEach-Object {
    $t = $_
    $actStr = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
    if ("$($t.TaskName) $($t.TaskPath) $actStr" -match $rx) {
        [PSCustomObject]@{
            TaskName = $t.TaskName
            TaskPath = $t.TaskPath
            State    = $t.State
            Action   = $actStr.Trim()
        }
    }
})
$results.ScheduledTasks = $tasks
$tasks | Format-Table -AutoSize

# 2. Registry: Uninstall entries
Write-Section 'Registry: Uninstall Entries'
$uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)
$uninstall = @(foreach ($root in $uninstallRoots) {
    Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        $blob = @($_.PSChildName, $p.DisplayName, $p.Publisher, $p.InstallLocation, $p.UninstallString) -join ' '
        if ($blob -match $rx) {
            [PSCustomObject]@{
                KeyPath         = $_.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::', ''
                DisplayName     = $p.DisplayName
                Publisher       = $p.Publisher
                InstallLocation = $p.InstallLocation
                UninstallString = $p.UninstallString
            }
        }
    }
})
$results.UninstallEntries = $uninstall
$uninstall | Format-Table -AutoSize

# 3. Registry: Run / RunOnce + browser registration
Write-Section 'Registry: Run / RunOnce / Browser Registration'
$persistKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
$browserKeys = @(
    'HKLM:\SOFTWARE\Clients\StartMenuInternet',
    'HKCU:\SOFTWARE\Clients\StartMenuInternet',
    'HKLM:\SOFTWARE\RegisteredApplications',
    'HKCU:\SOFTWARE\RegisteredApplications'
)

$registryHits = @()
foreach ($k in $persistKeys) {
    $key = Get-Item -Path $k -ErrorAction SilentlyContinue
    if ($key) {
        foreach ($name in $key.GetValueNames()) {
            $val = $key.GetValue($name)
            if ("$name $val" -match $rx) {
                $registryHits += [PSCustomObject]@{
                    KeyPath = $k
                    Name    = $name
                    Value   = "$val"
                }
            }
        }
    }
}
foreach ($k in $browserKeys) {
    Get-ChildItem -Path $k -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $rx } |
        ForEach-Object {
            $registryHits += [PSCustomObject]@{
                KeyPath = $_.Name
                Name    = '(subkey)'
                Value   = ''
            }
        }
}
$results.RegistryHits = $registryHits
$registryHits | Format-Table -AutoSize

# 4. Services
Write-Section 'Services'
$svcs = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match $rx } |
    Select-Object Name, DisplayName, State, StartMode, PathName)
$results.Services = $svcs
$svcs | Format-Table -AutoSize

# 5. Running processes
Write-Section 'Running Processes'
$procs = @(Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $rx -or $_.Path -match $rx } |
    Select-Object Id, Name, Path)
$results.Processes = $procs
$procs | Format-Table -AutoSize

# 6. Installed files & folders (depth-limited name match, then full recurse into hits)
Write-Section "Installed Files / Folders (depth $Depth)"
$installRoots = @(
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:ProgramData,
    $env:LOCALAPPDATA,
    $env:APPDATA,
    "$env:LOCALAPPDATA\Programs"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

$files = @(foreach ($root in $installRoots) {
    $hits = Get-ChildItem -Path $root -Depth $Depth -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $rx }
    $hits
    foreach ($h in $hits) {
        if ($h.PSIsContainer) {
            Get-ChildItem -Path $h.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
})
$files = $files | Select-Object FullName, Length, LastWriteTime -Unique
$results.Files = $files
$files | Format-Table -AutoSize

# 7. Shortcuts (.lnk) on Desktop / Start Menu
Write-Section 'Shortcuts (.lnk)'
$shortcutRoots = @(
    "$env:PUBLIC\Desktop",
    "$env:USERPROFILE\Desktop",
    "$env:APPDATA\Microsoft\Windows\Start Menu",
    "$env:ProgramData\Microsoft\Windows\Start Menu"
) | Where-Object { Test-Path $_ }

$shortcuts = @(foreach ($r in $shortcutRoots) {
    Get-ChildItem -Path $r -Filter '*.lnk' -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $rx } |
        Select-Object FullName, LastWriteTime
})
$results.Shortcuts = $shortcuts
$shortcuts | Format-Table -AutoSize

# Summary
Write-Section 'Summary'
$results.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{ Section = $_.Key; Hits = @($_.Value).Count }
} | Format-Table -AutoSize

# Optional CSV export
if ($ExportCsv) {
    $flat = foreach ($section in $results.Keys) {
        foreach ($item in @($results[$section])) {
            if ($null -eq $item) { continue }
            $row = [ordered]@{ Section = $section }
            foreach ($p in $item.PSObject.Properties) { $row[$p.Name] = $p.Value }
            [PSCustomObject]$row
        }
    }
    $flat | Export-Csv -Path $ExportCsv -NoTypeInformation
    Write-Host "Exported $($flat.Count) rows to $ExportCsv" -ForegroundColor Green
}
