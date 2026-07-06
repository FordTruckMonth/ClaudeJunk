# Get-M365GroupReport.ps1 — groups, membership, and guest exposure.
#
# Inventories groups with the facts that matter for access reviews: type
# (security / M365 / mail-enabled), owner count, member count, guest member
# count, and whether the group is public. Flag -GuestExposedOnly to surface
# only the groups that contain external guests — the ones worth reviewing.
# Read-only.
#
# Needs Group.Read.All + Directory.Read.All.
#
#   ./Get-M365GroupReport.ps1 -GuestExposedOnly
#   ./Get-M365GroupReport.ps1 -As Csv -ExportPath groups.csv

[CmdletBinding()]
param(
    [switch]$GuestExposedOnly,
    [ValidateSet('Table', 'Csv', 'Json')][string]$As = 'Table',
    [string]$ExportPath
)

if (-not (Get-Command Invoke-M365Graph -ErrorAction SilentlyContinue)) {
    throw 'Import the suite module first:  Import-Module ../M365.psm1'
}

Write-Host 'Fetching groups...' -ForegroundColor Cyan
$select = 'id,displayName,groupTypes,securityEnabled,mailEnabled,visibility'
$groups = Invoke-M365Graph "/groups?`$select=$select&`$top=999"

$rows = foreach ($g in $groups) {
    # Count members and guests. $count needs the ConsistencyLevel header,
    # which Invoke-M365Graph already sends.
    $members = Invoke-M365Graph "/groups/$($g.id)/members?`$select=userType&`$top=999"
    $owners  = Invoke-M365Graph "/groups/$($g.id)/owners?`$select=id&`$top=999"
    $guests  = @($members | Where-Object { $_.userType -eq 'Guest' }).Count

    if ($GuestExposedOnly -and $guests -eq 0) { continue }

    $type = if ($g.groupTypes -contains 'Unified') { 'M365' }
            elseif ($g.securityEnabled -and -not $g.mailEnabled) { 'Security' }
            elseif ($g.mailEnabled) { 'Mail' }
            else { 'Other' }

    [PSCustomObject]@{
        Name       = $g.displayName
        Type       = $type
        Visibility = $g.visibility
        Owners     = @($owners).Count
        Members    = @($members).Count
        Guests     = $guests
    }
}

$rows = @($rows | Sort-Object Guests -Descending)
Write-Host "`n=== Group Report ($($rows.Count) groups) ===" -ForegroundColor Cyan
$rows | Export-M365Result -As $As -Path $ExportPath
