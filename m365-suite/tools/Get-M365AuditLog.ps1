# Get-M365AuditLog.ps1 — Entra ID directory audit log search.
#
# The directory audit log records *changes*: role assignments, group and
# membership edits, app consent grants, credential resets, policy changes.
# This filters it by activity, actor, or category so you can answer "who
# added this guest / granted this app / reset that password, and when."
# Read-only.
#
# Needs AuditLog.Read.All.
#
#   ./Get-M365AuditLog.ps1 -Days 7 -Category RoleManagement
#   ./Get-M365AuditLog.ps1 -Contains 'Consent' -As Json -ExportPath consents.json

[CmdletBinding()]
param(
    [int]$Days = 7,
    # Filter to activityDisplayName containing this text (client-side).
    [string]$Contains,
    # Server-side category filter, e.g. RoleManagement, GroupManagement,
    # UserManagement, ApplicationManagement, Policy.
    [string]$Category,
    [string]$InitiatedBy,
    [int]$Top = 1000,
    [ValidateSet('Table', 'Csv', 'Json')][string]$As = 'Table',
    [string]$ExportPath
)

if (-not (Get-Command Invoke-M365Graph -ErrorAction SilentlyContinue)) {
    throw 'Import the suite module first:  Import-Module ../M365.psm1'
}

$since   = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filters = @("activityDateTime ge $since")
if ($Category)    { $filters += "category eq '$Category'" }
if ($InitiatedBy) { $filters += "initiatedBy/user/userPrincipalName eq '$InitiatedBy'" }

$filter = [uri]::EscapeDataString(($filters -join ' and '))
Write-Host "Querying directory audit log (last $Days days)..." -ForegroundColor Cyan
$logs = Invoke-M365Graph "/auditLogs/directoryAudits?`$filter=$filter&`$top=$Top"

$rows = foreach ($a in $logs) {
    if ($Contains -and ($a.activityDisplayName -notlike "*$Contains*")) { continue }
    $actor = $a.initiatedBy.user.userPrincipalName
    if (-not $actor) { $actor = $a.initiatedBy.app.displayName }
    $target = ($a.targetResources | ForEach-Object { $_.userPrincipalName; if (-not $_.userPrincipalName) { $_.displayName } }) -join '; '

    [PSCustomObject]@{
        Time     = ([datetime]$a.activityDateTime).ToString('yyyy-MM-dd HH:mm')
        Category = $a.category
        Activity = $a.activityDisplayName
        Actor    = $actor
        Target   = $target
        Result   = $a.result
    }
}

$rows = @($rows | Sort-Object Time -Descending)
Write-Host "`n=== Directory Audit Log ($($rows.Count) events) ===" -ForegroundColor Cyan
$rows | Export-M365Result -As $As -Path $ExportPath
