# Get-M365SignInLog.ps1 — hunt through Entra ID sign-in logs.
#
# Surfaces sign-ins with the fields that matter for a compromise triage:
# who, from where (IP + geo), which app, success/failure, and the MFA /
# conditional-access result. Filter to failures or risky sign-ins to cut
# straight to the interesting rows. Read-only.
#
# Needs AuditLog.Read.All. Sign-in logs require an Entra ID P1/P2 license.
#
#   ./Get-M365SignInLog.ps1 -UserPrincipalName jdoe@contoso.com -Days 7
#   ./Get-M365SignInLog.ps1 -FailuresOnly -Days 1 -As Csv -ExportPath fails.csv

[CmdletBinding()]
param(
    [string]$UserPrincipalName,
    [int]$Days = 7,
    [switch]$FailuresOnly,
    [switch]$RiskyOnly,
    [int]$Top = 1000,
    [ValidateSet('Table', 'Csv', 'Json')][string]$As = 'Table',
    [string]$ExportPath
)

if (-not (Get-Command Invoke-M365Graph -ErrorAction SilentlyContinue)) {
    throw 'Import the suite module first:  Import-Module ../M365.psm1'
}

$since   = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filters = @("createdDateTime ge $since")
if ($UserPrincipalName) { $filters += "userPrincipalName eq '$UserPrincipalName'" }
if ($FailuresOnly)      { $filters += 'status/errorCode ne 0' }
if ($RiskyOnly)         { $filters += "riskLevelDuringSignIn ne 'none'" }

$filter = [uri]::EscapeDataString(($filters -join ' and '))
Write-Host "Querying sign-ins (last $Days days)..." -ForegroundColor Cyan
$logs = Invoke-M365Graph "/auditLogs/signIns?`$filter=$filter&`$top=$Top"

$rows = foreach ($s in $logs) {
    [PSCustomObject]@{
        Time      = ([datetime]$s.createdDateTime).ToString('yyyy-MM-dd HH:mm')
        User      = $s.userPrincipalName
        App       = $s.appDisplayName
        IP        = $s.ipAddress
        Location  = ($s.location.city, $s.location.countryOrRegion | Where-Object { $_ }) -join ', '
        Status    = if ($s.status.errorCode -eq 0) { 'success' } else { "fail($($s.status.errorCode))" }
        Risk      = $s.riskLevelDuringSignIn
        MFA       = $s.authenticationRequirement
        Reason    = $s.status.failureReason
    }
}

$rows = @($rows | Sort-Object Time -Descending)
Write-Host "`n=== Sign-in Log ($($rows.Count) events) ===" -ForegroundColor Cyan
$rows | Export-M365Result -As $As -Path $ExportPath
