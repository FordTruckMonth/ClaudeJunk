# Get-M365UserReport.ps1 — tenant user inventory for audits & offboarding.
#
# Pulls every user with the account-hygiene fields an investigator or admin
# actually wants in one place: enabled/blocked, last interactive sign-in,
# assigned licenses, creation date, and whether the account is a guest.
# Read-only.
#
#   Import-Module ../M365.psm1; Connect-M365 -TenantId <tenant>
#   ./Get-M365UserReport.ps1 -StaleDays 90 -As Csv -ExportPath stale-users.csv

[CmdletBinding()]
param(
    [switch]$GuestsOnly,
    [switch]$DisabledOnly,
    # Only return users whose last sign-in is older than this many days
    # (0 = no filter). Useful for finding dormant accounts to disable.
    [int]$StaleDays = 0,
    [ValidateSet('Table', 'Csv', 'Json')][string]$As = 'Table',
    [string]$ExportPath
)

if (-not (Get-Command Invoke-M365Graph -ErrorAction SilentlyContinue)) {
    throw 'Import the suite module first:  Import-Module ../M365.psm1'
}

Write-Host 'Fetching users (with sign-in activity)...' -ForegroundColor Cyan
$select = 'id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,assignedLicenses,signInActivity'
$users  = Invoke-M365Graph "/users?`$select=$select&`$top=999"

$cutoff = if ($StaleDays -gt 0) { (Get-Date).ToUniversalTime().AddDays(-$StaleDays) } else { $null }

$rows = foreach ($u in $users) {
    if ($GuestsOnly   -and $u.userType -ne 'Guest')  { continue }
    if ($DisabledOnly -and $u.accountEnabled)        { continue }

    $lastSignIn = $u.signInActivity.lastSignInDateTime
    if ($cutoff) {
        if ($lastSignIn -and ([datetime]$lastSignIn) -ge $cutoff) { continue }
    }

    [PSCustomObject]@{
        DisplayName  = $u.displayName
        UPN          = $u.userPrincipalName
        Type         = $u.userType
        Enabled      = $u.accountEnabled
        Licenses     = $u.assignedLicenses.Count
        LastSignIn   = if ($lastSignIn) { ([datetime]$lastSignIn).ToString('yyyy-MM-dd') } else { 'never' }
        Created      = if ($u.createdDateTime) { ([datetime]$u.createdDateTime).ToString('yyyy-MM-dd') } else { '' }
    }
}

$rows = @($rows | Sort-Object LastSignIn)
Write-Host "`n=== User Report ($($rows.Count) users) ===" -ForegroundColor Cyan
$rows | Export-M365Result -As $As -Path $ExportPath
