#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Batch eDiscovery compliance searches (one per sender) with per-search soft purge.

.DESCRIPTION
    Connects to Security & Compliance PowerShell, collects a list of sender
    addresses, creates and runs one ComplianceSearch per sender (named
    "YYYY-MM-DD <sender>"), shows a summary of item counts, exports a combined
    CSV to the user's Downloads folder, then offers a SoftDelete purge for each
    search individually.

.NOTES
    The *-ComplianceSearch cmdlets are Security & Compliance (Microsoft Purview)
    cmdlets, NOT Exchange Online. They require Connect-IPPSSession, and since the
    2025 enforcement (MC1131771) also require -EnableSearchOnlySession, which
    needs ExchangeOnlineManagement v3.9.0+.

    A soft purge removes at most 10 items per mailbox per run. Re-run this
    script with the same senders until counts reach 0 -- same-day searches are
    reused and refreshed automatically.
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

# -- Collect senders -----------------------------------------------------------
$Senders = [System.Collections.Generic.List[string]]::new()
Write-Host "`nEnter the sender email addresses to search for." -ForegroundColor Cyan
Write-Host "One per line, or paste several separated by commas/spaces." -ForegroundColor DarkGray
Write-Host "Enter 'n' (or leave blank) when you're done." -ForegroundColor DarkGray

while ($true) {
    $Entry = Read-Host ("Sender {0}" -f ($Senders.Count + 1))
    if ([string]::IsNullOrWhiteSpace($Entry) -or $Entry.Trim() -match '^(n|no|done)$') { break }
    foreach ($Part in ($Entry -split '[,;\s]+')) {
        $Addr = $Part.Trim().Trim('<', '>', '"', "'").ToLowerInvariant()
        if (-not $Addr) { continue }
        if ($Addr -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
            Write-Warning "'$Addr' does not look like a valid email address - skipped."
            continue
        }
        if ($Senders.Contains($Addr)) {
            Write-Host "  (duplicate '$Addr' ignored)" -ForegroundColor DarkGray
        } else {
            $Senders.Add($Addr)
            Write-Host "  + $Addr" -ForegroundColor DarkGray
        }
    }
}

if ($Senders.Count -eq 0) {
    Write-Error "No senders entered. Exiting."
    exit 1
}

$Today = Get-Date -Format 'yyyy-MM-dd'
Write-Host "`n$($Senders.Count) sender(s) to search. Searches will be named '$Today <sender>'." -ForegroundColor Cyan

# -- Create and start one search per sender ------------------------------------
$Searches = foreach ($Sender in $Senders) {
    [pscustomobject]@{
        Sender    = $Sender
        Name      = "$Today $Sender"
        Query     = 'From:"{0}"' -f $Sender
        Started   = $false
        Done      = $false
        Search    = $null
        ItemCount = $null
        Note      = $null
        Purged    = $false
    }
}

foreach ($Entry in $Searches) {
    $Existing = Get-ComplianceSearch -Identity $Entry.Name -ErrorAction SilentlyContinue
    if ($Existing) {
        Write-Host "'$($Entry.Name)' already exists - reusing it and refreshing results." -ForegroundColor DarkGray
        try {
            Set-ComplianceSearch -Identity $Entry.Name -ContentMatchQuery $Entry.Query -ErrorAction Stop
        } catch {
            Write-Warning "Could not update query on existing search '$($Entry.Name)': $_"
        }
    } else {
        Write-Host "Creating '$($Entry.Name)'..." -ForegroundColor Cyan
        try {
            New-ComplianceSearch -Name $Entry.Name -ExchangeLocation All -ContentMatchQuery $Entry.Query -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning "Failed to create search for $($Entry.Sender): $_"
            $Entry.Note = "create failed"
            continue
        }
    }
    try {
        Start-ComplianceSearch -Identity $Entry.Name -ErrorAction Stop
        $Entry.Started = $true
    } catch {
        # A search that is already running is fine to poll.
        if ($_ -match 'already|in progress') {
            $Entry.Started = $true
        } else {
            Write-Warning "Failed to start search for $($Entry.Sender): $_"
            $Entry.Note = "start failed"
        }
    }
}

$Running = @($Searches | Where-Object Started)
if ($Running.Count -eq 0) {
    Write-Error "No searches could be started. Exiting."
    exit 1
}

# -- Poll until all searches complete ------------------------------------------
Write-Host "`nWaiting for $($Running.Count) search(es) to complete..."
$Deadline = (Get-Date).AddMinutes(60)
while ($true) {
    $Remaining = @($Running | Where-Object { -not $_.Done })
    if ($Remaining.Count -eq 0) { break }
    if ((Get-Date) -gt $Deadline) {
        Write-Host ""
        Write-Warning "Timed out after 60 minutes; $($Remaining.Count) search(es) still running will be skipped."
        foreach ($Entry in $Remaining) { $Entry.Note = "timed out" }
        break
    }
    Start-Sleep -Seconds 10
    foreach ($Entry in $Remaining) {
        try {
            $s = Get-ComplianceSearch -Identity $Entry.Name -ErrorAction Stop
        } catch {
            continue   # transient failure; retry on the next pass
        }
        if ($s.Status -in @('Completed', 'Failed')) {
            $Entry.Done   = $true
            $Entry.Search = $s
            if ($s.Status -eq 'Failed') { $Entry.Note = 'search failed' }
        }
    }
    $DoneCount = @($Running | Where-Object Done).Count
    Write-Host ("`r  {0}/{1} complete " -f $DoneCount, $Running.Count) -NoNewline
}
Write-Host ""

# -- Let expensive properties (Items/SuccessResults) settle, then count --------
# Items can momentarily read 0 right after Status flips to Completed.
foreach ($Entry in ($Running | Where-Object { $_.Done -and $_.Search.Status -eq 'Completed' })) {
    for ($i = 0; $i -lt 6; $i++) {
        $s = Get-ComplianceSearch -Identity $Entry.Name -ErrorAction SilentlyContinue
        if ($s -and $s.SuccessResults -and $null -ne $s.Items) { break }
        Start-Sleep -Seconds 5
    }
    if ($s) { $Entry.Search = $s }

    # SuccessResults lists an "Item count" per location; sum them as a
    # cross-check against the Items property (which can lag after completion).
    $Parsed = 0
    foreach ($m in [regex]::Matches([string]$Entry.Search.SuccessResults, 'Item count:\s*(\d+)')) {
        $Parsed += [int]$m.Groups[1].Value
    }
    $Entry.ItemCount = [Math]::Max([int]$Entry.Search.Items, $Parsed)
}

# -- Display summary ------------------------------------------------------------
Write-Host "`n-- Search Results ---------------------------------------------------" -ForegroundColor Green
$Searches |
    Select-Object @{n = 'Search'; e = { $_.Name } },
                  @{n = 'Items';  e = { if ($null -ne $_.ItemCount) { $_.ItemCount } else { '-' } } },
                  @{n = 'Size';   e = { $_.Search.Size } },
                  @{n = 'Status'; e = { if ($_.Note) { $_.Note } elseif ($_.Search) { $_.Search.Status } else { 'not started' } } } |
    Format-Table -AutoSize
Write-Host "---------------------------------------------------------------------" -ForegroundColor Green

# -- Export combined results CSV to the user's Downloads folder -----------------
$ProfilePath = $env:USERPROFILE
if ([string]::IsNullOrWhiteSpace($ProfilePath)) { $ProfilePath = [Environment]::GetFolderPath('UserProfile') }
$DownloadsPath = [System.IO.Path]::Combine($ProfilePath, "Downloads")
if (-not (Test-Path $DownloadsPath)) {
    New-Item -ItemType Directory -Force -Path $DownloadsPath | Out-Null
}
$CsvPath = [System.IO.Path]::Combine($DownloadsPath, "$Today eDiscovery Results.csv")

try {
    $Searches |
        Select-Object @{n = 'SearchName'; e = { $_.Name } },
                      Sender,
                      @{n = 'Items';  e = { $_.ItemCount } },
                      @{n = 'Size';   e = { $_.Search.Size } },
                      @{n = 'Status'; e = { if ($_.Note) { $_.Note } elseif ($_.Search) { $_.Search.Status } else { 'not started' } } },
                      Query,
                      @{n = 'CreatedTime';      e = { $_.Search.CreatedTime } },
                      @{n = 'LastModifiedTime'; e = { $_.Search.LastModifiedTime } } |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-Host "Results exported to: $CsvPath" -ForegroundColor Yellow
} catch {
    Write-Warning "Failed to export CSV to '$CsvPath': $_"
}

# -- Offer soft purge per search --------------------------------------------------
$Purgeable = @($Searches | Where-Object { $_.Done -and $_.Search -and $_.Search.Status -eq 'Completed' -and $_.ItemCount -gt 0 })
if ($Purgeable.Count -eq 0) {
    Write-Host "`nNo searches returned items - nothing to purge." -ForegroundColor DarkGray
    exit 0
}

Write-Host "`nNOTE: A soft purge removes a MAXIMUM of 10 items PER MAILBOX per run." -ForegroundColor Yellow
Write-Host "      Re-run this script with the same senders until counts reach 0" -ForegroundColor Yellow
Write-Host "      (same-day searches are reused and refreshed automatically).`n" -ForegroundColor Yellow

foreach ($Entry in $Searches) {
    if (-not $Entry.Done -or -not $Entry.Search -or $Entry.Search.Status -ne 'Completed') {
        $Reason = if ($Entry.Note) { $Entry.Note } else { 'not completed' }
        Write-Host "$($Entry.Name) - skipped ($Reason)." -ForegroundColor DarkGray
        continue
    }
    if ($Entry.ItemCount -eq 0) {
        Write-Host "$($Entry.Name) - 0 found, nothing to purge." -ForegroundColor DarkGray
        continue
    }

    $Choice = Read-Host "$($Entry.Name) - $($Entry.ItemCount) found. Soft purge? [y/N]"
    if ($Choice -notmatch '^[Yy]') {
        Write-Host "  Purge skipped." -ForegroundColor DarkGray
        continue
    }

    # A previous run leaves a "<name>_Purge" action behind, which blocks a new
    # purge of the same search until it is removed.
    $OldAction = Get-ComplianceSearchAction -Identity "$($Entry.Name)_Purge" -ErrorAction SilentlyContinue
    if ($OldAction) {
        try {
            Remove-ComplianceSearchAction -Identity "$($Entry.Name)_Purge" -Confirm:$false -ErrorAction Stop
        } catch {
            Write-Warning "  Could not remove the previous purge action for '$($Entry.Name)': $_"
            continue
        }
    }

    try {
        New-ComplianceSearchAction -SearchName $Entry.Name -Purge -PurgeType SoftDelete -Confirm:$false -ErrorAction Stop | Out-Null
        $Entry.Purged = $true
        Write-Host "  Soft purge submitted (up to 10 items/mailbox this run)." -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to initiate soft purge: $_"
    }
}

# -- Recap -----------------------------------------------------------------------
$PurgedCount = @($Searches | Where-Object Purged).Count
Write-Host "`n$PurgedCount purge action(s) submitted." -ForegroundColor Cyan
if ($PurgedCount -gt 0) {
    Write-Host "Monitor with: Get-ComplianceSearchAction | Where-Object { `$_.Name -like '*_Purge' } | Format-Table Name, Status" -ForegroundColor DarkGray
    Write-Host "Re-run this script with the same senders to purge remaining items until counts reach 0." -ForegroundColor DarkGray
}
