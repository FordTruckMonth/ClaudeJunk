#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Interactive eDiscovery compliance search with optional soft purge.
#>

# ── Prompt user for inputs ────────────────────────────────────────────────────
$SenderEmail = Read-Host "Enter the sender email address to search for"
if ([string]::IsNullOrWhiteSpace($SenderEmail)) {
    Write-Error "Sender email cannot be empty."
    exit 1
}

$SearchName = Read-Host "Enter a name for this eDiscovery search"
if ([string]::IsNullOrWhiteSpace($SearchName)) {
    Write-Error "Search name cannot be empty."
    exit 1
}

$Query = "From:$SenderEmail"

# ── Create and start the compliance search ────────────────────────────────────
Write-Host "`nCreating compliance search '$SearchName'..." -ForegroundColor Cyan
try {
    New-ComplianceSearch -Name $SearchName -ExchangeLocation All -ContentMatchQuery $Query -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Failed to create compliance search: $_"
    exit 1
}

Write-Host "Starting compliance search..." -ForegroundColor Cyan
Start-ComplianceSearch -Identity $SearchName

# ── Poll until the search completes ──────────────────────────────────────────
Write-Host "Waiting for search to complete" -NoNewline
do {
    Start-Sleep -Seconds 5
    Write-Host "." -NoNewline
    $Search = Get-ComplianceSearch -Identity $SearchName
} while ($Search.Status -notin @("Completed", "Failed", "Stopped"))

Write-Host ""

if ($Search.Status -ne "Completed") {
    Write-Error "Search ended with status '$($Search.Status)'. Exiting."
    exit 1
}

# ── Display results ───────────────────────────────────────────────────────────
Write-Host "`n── Search Results ───────────────────────────────────────" -ForegroundColor Green
$Search | Format-List Name, Status, Items, Size, ContentMatchQuery
Write-Host "─────────────────────────────────────────────────────────`n" -ForegroundColor Green

# ── Export results to CSV in the user's Downloads folder ─────────────────────
$DownloadsPath = [System.IO.Path]::Combine($env:USERPROFILE, "Downloads")
$CsvPath       = [System.IO.Path]::Combine($DownloadsPath, "$SearchName.csv")

$Search | Select-Object Name, Status, Items, Size, ContentMatchQuery, CreatedTime, LastModifiedTime |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

Write-Host "Results exported to: $CsvPath" -ForegroundColor Yellow

# ── Offer soft purge ─────────────────────────────────────────────────────────
if ($Search.Items -eq 0) {
    Write-Host "No items found — skipping purge option." -ForegroundColor DarkGray
    exit 0
}

$PurgeChoice = Read-Host "Found $($Search.Items) item(s). Perform a soft purge? [y/N]"

if ($PurgeChoice -match '^[Yy]$') {
    Write-Host "`nInitiating soft purge..." -ForegroundColor Cyan
    try {
        New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType SoftDelete -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Host "Soft purge action submitted successfully." -ForegroundColor Green
        Write-Host "Monitor progress with: Get-ComplianceSearchAction -Identity '${SearchName}_Purge' | Format-List" -ForegroundColor DarkGray
    } catch {
        Write-Error "Failed to initiate soft purge: $_"
        exit 1
    }
} else {
    Write-Host "Purge skipped." -ForegroundColor DarkGray
}
