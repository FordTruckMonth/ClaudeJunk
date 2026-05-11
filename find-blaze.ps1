# Identifies Blaze / Blazer browser artifacts on this Windows system.
# Read-only: lists matches only, does not delete anything.

$ErrorActionPreference = 'SilentlyContinue'
$pattern = 'blaze'

# --- Scheduled Tasks ---
Write-Host "`n=== Scheduled Tasks ===" -ForegroundColor Cyan
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $actionHit = $task.Actions | Where-Object {
        $_.Execute -match $pattern -or $_.Arguments -match $pattern
    }
    if ($task.TaskName -match $pattern -or $task.TaskPath -match $pattern -or $actionHit) {
        [PSCustomObject]@{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            State    = $task.State
            Action   = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; '
        }
    }
} | Format-Table -AutoSize

# --- Registry: Uninstall entries ---
Write-Host "`n=== Registry: Uninstall Entries ===" -ForegroundColor Cyan
$uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach ($root in $uninstallRoots) {
    Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        if ($_.PSChildName    -match $pattern -or
            $p.DisplayName    -match $pattern -or
            $p.Publisher      -match $pattern -or
            $p.InstallLocation-match $pattern) {
            [PSCustomObject]@{
                KeyPath         = $_.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::', ''
                DisplayName     = $p.DisplayName
                Publisher       = $p.Publisher
                InstallLocation = $p.InstallLocation
            }
        }
    }
} | Format-Table -AutoSize

# --- Registry: Browser & app registration ---
Write-Host "`n=== Registry: Browser / App Registration ===" -ForegroundColor Cyan
$browserRoots = @(
    'HKLM:\SOFTWARE\Clients\StartMenuInternet',
    'HKCU:\SOFTWARE\Clients\StartMenuInternet',
    'HKLM:\SOFTWARE\RegisteredApplications',
    'HKCU:\SOFTWARE\RegisteredApplications'
)
foreach ($root in $browserRoots) {
    Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $pattern } |
        Select-Object -ExpandProperty Name
}

# --- Installed files / folders ---
Write-Host "`n=== Installed Files / Folders ===" -ForegroundColor Cyan
$searchPaths = @(
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:LOCALAPPDATA,
    $env:APPDATA,
    $env:ProgramData
) | Where-Object { $_ -and (Test-Path $_) }

$files = foreach ($path in $searchPaths) {
    Get-ChildItem -Path $path -Filter "*$pattern*" -Recurse -Force -ErrorAction SilentlyContinue
}
$files | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize
