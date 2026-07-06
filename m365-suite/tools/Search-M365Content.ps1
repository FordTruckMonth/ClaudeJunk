# Search-M365Content.ps1 — eDiscovery-style content search across M365.
#
# Runs a Microsoft Purview eDiscovery (Standard) content search over mailboxes
# and/or SharePoint & OneDrive, using a KQL query. Creates a case (or reuses
# one), adds a search, kicks off the estimate, and reports the hit counts and
# size per location. Read-only: it estimates, it does not export, hold, or
# delete anything.
#
# Requires delegated eDiscovery.Read.All (or app-only equivalent) and an
# account with eDiscovery Manager rights in Purview.
#
#   Import-Module ../M365.psm1; Connect-M365 -TenantId <tenant>
#   ./Search-M365Content.ps1 -Query 'subject:"wire transfer" AND sent>=2026-01-01'

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Query,          # KQL query
    [string]$CaseName = "ClaudeJunk-Search-$([datetime]::UtcNow.ToString('yyyyMMdd-HHmmss'))",
    [ValidateSet('Mailboxes', 'Sites', 'Both')][string]$Scope = 'Both',
    [int]$PollSeconds = 15,
    [int]$TimeoutMinutes = 30,
    [ValidateSet('Table', 'Csv', 'Json')][string]$As = 'Table',
    [string]$ExportPath
)

if (-not (Get-Command Invoke-M365Graph -ErrorAction SilentlyContinue)) {
    throw 'Import the suite module first:  Import-Module ../M365.psm1'
}

# eDiscovery lives under the security namespace on the beta endpoint.
Write-Host "Creating eDiscovery case '$CaseName'..." -ForegroundColor Cyan
$case = Invoke-M365Graph -Beta -Method POST -Path '/security/cases/ediscoveryCases' -Body @{
    displayName = $CaseName
    description = 'Created by ClaudeJunk M365 suite (Search-M365Content).'
}
$caseId = $case[0].id

# dataSourceScopes is a flags enum; combine the tenant-wide sources we want.
$dataSourceScopes = switch ($Scope) {
    'Mailboxes' { 'allTenantMailboxes' }
    'Sites'     { 'allTenantSites' }
    default     { 'allTenantMailboxes,allTenantSites' }
}

Write-Host "Adding search over scope '$Scope'..." -ForegroundColor Cyan
$search = Invoke-M365Graph -Beta -Method POST -Path "/security/cases/ediscoveryCases/$caseId/searches" -Body @{
    displayName      = 'ContentSearch'
    contentQuery     = $Query
    dataSourceScopes = $dataSourceScopes
}
$searchId = $search[0].id

Write-Host "Starting estimate..." -ForegroundColor Cyan
$null = Invoke-M365Graph -Beta -Method POST -Path "/security/cases/ediscoveryCases/$caseId/searches/$searchId/estimateStatistics"

# Poll the operation until the estimate completes.
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$status = 'running'
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $PollSeconds
    $ops = Invoke-M365Graph -Beta -Path "/security/cases/ediscoveryCases/$caseId/operations"
    $est = $ops | Where-Object { $_.action -eq 'estimateStatistics' } | Select-Object -First 1
    $status = $est.status
    Write-Host "  estimate: $status" -ForegroundColor DarkGray
    if ($status -in @('succeeded', 'failed', 'partiallySucceeded')) { break }
}

if ($status -eq 'failed') { throw "Estimate failed for case $caseId." }

# Pull the finished search with its statistics.
$final = Invoke-M365Graph -Beta -Path "/security/cases/ediscoveryCases/$caseId/searches/$searchId?`$expand=lastEstimateStatisticsOperation"
$stats = $final[0].lastEstimateStatisticsOperation

$summary = [PSCustomObject]@{
    Case              = $CaseName
    CaseId            = $caseId
    Query             = $Query
    Scope             = $Scope
    Status            = $status
    MailboxItems      = $stats.indexedItemCount
    MailboxSizeMB     = if ($stats.indexedItemsSize) { [math]::Round($stats.indexedItemsSize / 1MB, 2) } else { 0 }
    MailboxesSearched = $stats.mailboxCount
    SitesSearched     = $stats.siteCount
    UnindexedItems    = $stats.unindexedItemCount
}

Write-Host "`n=== Content Search Estimate ===" -ForegroundColor Cyan
@($summary) | Export-M365Result -As $As -Path $ExportPath
Write-Host "`nCase retained in Purview as '$CaseName'. Review or export it there; this tool only estimated." -ForegroundColor DarkGray
