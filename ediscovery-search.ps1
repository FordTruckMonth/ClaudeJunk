#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Interactive eDiscovery compliance search with optional soft purge.

.DESCRIPTION
    Connects to Security & Compliance PowerShell, prompts for a sender address
    and a search name, runs a single ComplianceSearch, displays and exports the
    results to a CSV in the user's Downloads folder, then optionally performs a
    SoftDelete purge.

.NOTES
    The *-ComplianceSearch cmdlets are Security & Compliance (Microsoft Purview)
    cmdlets, NOT Exchange Online. They require Connect-IPPSSession, and since the
    2025 enforcement (MC1131771) also require -EnableSearchOnlySession, which
    needs ExchangeOnlineManagement v3.9.0+.
#>

# -- Ensure Security & Compliance (IPPS) connection ---------------------------
$MinModuleVersion = [version]'3.9.0'
$Module = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
          Sort-Object Version -Descending | Select-Object -First 1
if (-not $Module -or $Module.Version -lt $MinModuleVersion) {
    Write-Host "Installing/updating ExchangeOnlineManagement (>= $MinModuleVersion)..." -ForegroundColor Cyan
    Install-Module ExchangeOnlineManagement -MinimumVersion $MinModuleVersion `
        -Scope CurrentUser -Force -AllowClobber
}
Import-Module ExchangeOnlineManagement

# Idempotent connect: only connect if no live compliance session exists.
$ComplianceConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue |
    Where-Object { $_.ConnectionUri -like '*compliance.protection.outlook.com*' -and $_.State -eq 'Connected' }

if (-not $ComplianceConnection) {
    $UPN = Read-Host "Enter your admin UPN for Security & Compliance (e.g. admin@contoso.onmicrosoft.com)"
    if ([string]::IsNullOrWhiteSpace($UPN)) {
        Write-Error "A UPN is required to connect to Security & Compliance PowerShell."
        exit 1
    }
    try {
        Connect-IPPSSession -UserPrincipalName $UPN -EnableSearchOnlySession -ErrorAction Stop
    } catch {
        Write-Error "Failed to connect to Security & Compliance PowerShell: $_"
        exit 1
    }
}

# Belt-and-suspenders: confirm the S&C cmdlets actually imported.
if (-not (Get-Command New-ComplianceSearch -ErrorAction SilentlyContinue)) {
    Write-Error "New-ComplianceSearch is not available -- the IPPS (S&C) connection did not import correctly."
    exit 1
}

# -- Prompt user for inputs ---------------------------------------------------
$SenderEmail = Read-Host "Enter the sender email address to search for"
if ([string]::IsNullOrWhiteSpace($SenderEmail)) {
    Write-Error "Sender email cannot be empty."
    exit 1
}
if ($SenderEmail -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
    Write-Error "'$SenderEmail' does not look like a valid email address."
    exit 1
}

$SearchName = Read-Host "Enter a name for this eDiscovery search"
if ([string]::IsNullOrWhiteSpace($SearchName)) {
    Write-Error "Search name cannot be empty."
    exit 1
}

# Quote the value in the KQL to avoid tokenization surprises, then confirm it.
$Query = 'From:"{0}"' -f $SenderEmail
Write-Host "Content match query: $Query" -ForegroundColor DarkGray

# -- Create the compliance search ---------------------------------------------
$Existing = Get-ComplianceSearch -Identity $SearchName -ErrorAction SilentlyContinue
if ($Existing) {
    Write-Warning "A compliance search named '$SearchName' already exists (names are tenant-wide)."
    $Reuse = Read-Host "Reuse it (R), pick a new auto-suffixed name (N), or abort (A)? [R/N/A]"
    switch -Regex ($Reuse) {
        '^[Rr]' {
            Write-Host "Reusing existing search '$SearchName'." -ForegroundColor Cyan
        }
        '^[Nn]' {
            $SearchName = "{0}_{1}" -f $SearchName, (Get-Date -Format 'yyyyMMdd_HHmmss')
            Write-Host "Using new search name '$SearchName'." -ForegroundColor Cyan
            try {
                New-ComplianceSearch -Name $SearchName -ExchangeLocation All -ContentMatchQuery $Query -ErrorAction Stop | Out-Null
            } catch {
                Write-Error "Failed to create compliance search: $_"
                exit 1
            }
        }
        default {
            Write-Host "Aborted." -ForegroundColor DarkGray
            exit 0
        }
    }
} else {
    Write-Host "`nCreating compliance search '$SearchName'..." -ForegroundColor Cyan
    try {
        New-ComplianceSearch -Name $SearchName -ExchangeLocation All -ContentMatchQuery $Query -ErrorAction Stop | Out-Null
    } catch {
        Write-Error "Failed to create compliance search: $_"
        exit 1
    }
}

# -- Start the search ---------------------------------------------------------
Write-Host "Starting compliance search..." -ForegroundColor Cyan
try {
    Start-ComplianceSearch -Identity $SearchName -ErrorAction Stop
} catch {
    Write-Error "Failed to start compliance search: $_"
    exit 1
}

# -- Poll until the search completes ------------------------------------------
Write-Host "Waiting for search to complete" -NoNewline
$Deadline = (Get-Date).AddMinutes(30)
do {
    Start-Sleep -Seconds 5
    Write-Host "." -NoNewline
    try {
        $Search = Get-ComplianceSearch -Identity $SearchName -ErrorAction Stop
    } catch {
        Write-Host ""
        Write-Error "Lost connection while polling the search: $_"
        exit 1
    }
    if ((Get-Date) -gt $Deadline) {
        Write-Host ""
        Write-Error "Search did not complete within 30 minutes (last status: $($Search.Status)). Exiting."
        exit 1
    }
} while ($Search.Status -notin @("Completed", "Failed"))

Write-Host ""

if ($Search.Status -ne "Completed") {
    Write-Error "Search ended with status '$($Search.Status)'. Exiting."
    exit 1
}

# -- Let expensive properties (Items/SuccessResults) settle -------------------
# Items can momentarily read 0 right after Status flips to Completed.
for ($i = 0; $i -lt 6; $i++) {
    $Search = Get-ComplianceSearch -Identity $SearchName -ErrorAction SilentlyContinue
    if ($Search.SuccessResults -and $null -ne $Search.Items) { break }
    Start-Sleep -Seconds 5
}

# Cross-check Items against the count parsed from SuccessResults.
$ParsedItems = 0
if ($Search.SuccessResults -match 'Item count:\s*(\d+)') { $ParsedItems = [int]$Matches[1] }
$ItemCount = [Math]::Max([int]$Search.Items, $ParsedItems)

# -- Display results ----------------------------------------------------------
Write-Host "`n-- Search Results ---------------------------------------------------" -ForegroundColor Green
$Search | Format-List Name, Status, Items, Size, ContentMatchQuery
Write-Host "---------------------------------------------------------------------`n" -ForegroundColor Green

# -- Export results to CSV in the user's Downloads folder ---------------------
$ProfilePath = $env:USERPROFILE
if ([string]::IsNullOrWhiteSpace($ProfilePath)) { $ProfilePath = [Environment]::GetFolderPath('UserProfile') }
$DownloadsPath = [System.IO.Path]::Combine($ProfilePath, "Downloads")
if (-not (Test-Path $DownloadsPath)) {
    New-Item -ItemType Directory -Force -Path $DownloadsPath | Out-Null
}

$SafeName = $SearchName
foreach ($c in [System.IO.Path]::GetInvalidFileNameChars()) { $SafeName = $SafeName.Replace($c, '_') }
$CsvPath = [System.IO.Path]::Combine($DownloadsPath, "$SafeName.csv")

try {
    $Search | Select-Object Name, Status, Items, Size, ContentMatchQuery, CreatedTime, LastModifiedTime |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-Host "Results exported to: $CsvPath" -ForegroundColor Yellow
} catch {
    Write-Warning "Failed to export CSV to '$CsvPath': $_"
}

# -- Offer soft purge ---------------------------------------------------------
if ($ItemCount -eq 0) {
    Write-Host "No items found - skipping purge option." -ForegroundColor DarkGray
    exit 0
}

Write-Host "`nNOTE: A soft purge removes a MAXIMUM of 10 items PER MAILBOX per run." -ForegroundColor Yellow
Write-Host "      If any sender sent more than 10 items to a mailbox, you must re-run" -ForegroundColor Yellow
Write-Host "      the search + purge until the item count reaches 0." -ForegroundColor Yellow

$PurgeChoice = Read-Host "Found $ItemCount item(s). Perform a soft purge? [y/N]"

if ($PurgeChoice -match '^[Yy]$') {
    Write-Host "`nInitiating soft purge..." -ForegroundColor Cyan
    try {
        New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType SoftDelete -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Host "Soft purge action submitted (up to 10 items/mailbox this run)." -ForegroundColor Green
        Write-Host "Monitor progress with: Get-ComplianceSearchAction -Identity '${SearchName}_Purge' | Format-List" -ForegroundColor DarkGray
        Write-Host "Re-run this script if the search still returns items afterward." -ForegroundColor DarkGray
    } catch {
        Write-Error "Failed to initiate soft purge: $_"
        exit 1
    }
} else {
    Write-Host "Purge skipped." -ForegroundColor DarkGray
}
