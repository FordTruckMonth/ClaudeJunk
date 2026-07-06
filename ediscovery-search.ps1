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

    A soft purge removes at most 10 items per mailbox per run, and purged items
    move to Recoverable Items, WHICH SEARCHES STILL COUNT. Re-run this script
    with the same senders until counts STOP CHANGING -- they will generally not
    reach 0 until the deleted-item retention period expires. Same-day searches
    are reused and refreshed automatically, and the previous run's counts are
    read back from the CSV so each prompt shows the change since last run.
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

$ComplianceConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue |
    Where-Object { $_.ConnectionUri -like '*compliance.protection.outlook.com*' -and $_.State -eq 'Connected' } |
    Select-Object -First 1

# A session opened WITHOUT -EnableSearchOnlySession imports the eDiscovery
# cmdlets but fails at invocation (MC1131771), and no connection property
# reveals search-only mode -- so probe before trusting an existing session.
$ProbeOk = $false
if ($ComplianceConnection) {
    try {
        $null = Get-ComplianceSearch -ErrorAction Stop
        $ProbeOk = $true
    } catch {
        Write-Host "Existing compliance session cannot run eDiscovery cmdlets - reconnecting..." -ForegroundColor Yellow
        try {
            Disconnect-ExchangeOnline -ConnectionId $ComplianceConnection.ConnectionId -Confirm:$false -ErrorAction SilentlyContinue
        } catch { }
        $ComplianceConnection = $null
    }
}

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

if (-not (Get-Command New-ComplianceSearch -ErrorAction SilentlyContinue)) {
    Write-Error "New-ComplianceSearch is not available -- the IPPS (S&C) connection did not import correctly."
    exit 1
}
if (-not $ProbeOk) {
    try {
        $null = Get-ComplianceSearch -ErrorAction Stop
    } catch {
        if ("$_" -match 'EnableSearchOnlySession') {
            Write-Error "This session still cannot run eDiscovery cmdlets. Open a NEW PowerShell window and re-run this script."
        } else {
            Write-Error "eDiscovery cmdlet probe failed: $_"
        }
        exit 1
    }
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

# Echo the collected list and confirm, so a paste truncated by a stray blank
# line is caught before any searches are created.
Write-Host "`nCollected $($Senders.Count) sender(s):" -ForegroundColor Cyan
$Senders | ForEach-Object { Write-Host "  $_" }
try { $Host.UI.RawUI.FlushInputBuffer() } catch { }
$Confirm = Read-Host "Create $($Senders.Count) search(es) named '$Today <sender>'? [y/N]"
if ($Confirm.Trim() -notin @('y', 'yes')) {
    Write-Host "Aborted." -ForegroundColor DarkGray
    exit 0
}

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
        if ($_ -match 'already|in ?progress|still running') {
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
    $s = $null
    $Settled = $false
    for ($i = 0; $i -lt 6; $i++) {
        try {
            $s = Get-ComplianceSearch -Identity $Entry.Name -ErrorAction Stop
        } catch {
            $s = $null   # a dropped session must not leak the previous sender's object
        }
        if ($s -and $s.SuccessResults -and $null -ne $s.Items) { $Settled = $true; break }
        Start-Sleep -Seconds 5
    }
    if ($s) { $Entry.Search = $s }

    if (-not $Settled -and $null -eq $Entry.Search.Items -and -not $Entry.Search.SuccessResults) {
        Write-Warning "'$($Entry.Name)': item count never settled; count unknown - re-run to refresh."
        $Entry.Note = 'count unsettled'
        continue   # leave ItemCount $null so the summary shows '-'
    }

    # SuccessResults lists an "Item count" per location; sum them as a
    # cross-check against the Items property (which can lag after completion).
    $Parsed = 0
    foreach ($m in [regex]::Matches([string]$Entry.Search.SuccessResults, 'Item count:\s*(\d+)')) {
        $Parsed += [int]$m.Groups[1].Value
    }
    $Entry.ItemCount = [Math]::Max([int]$Entry.Search.Items, $Parsed)
}

# -- Load the previous run's counts (if any) for comparison ---------------------
$ProfilePath = $env:USERPROFILE
if ([string]::IsNullOrWhiteSpace($ProfilePath)) { $ProfilePath = [Environment]::GetFolderPath('UserProfile') }
$DownloadsPath = [System.IO.Path]::Combine($ProfilePath, "Downloads")
if (-not (Test-Path $DownloadsPath)) {
    New-Item -ItemType Directory -Force -Path $DownloadsPath | Out-Null
}
$CsvPath = [System.IO.Path]::Combine($DownloadsPath, "$Today eDiscovery Results.csv")

$PrevCounts = @{}
if (Test-Path $CsvPath) {
    try {
        foreach ($Row in (Import-Csv $CsvPath)) {
            if ($Row.SearchName -and $Row.Items -match '^\d+$') { $PrevCounts[$Row.SearchName] = [int]$Row.Items }
        }
        Write-Host "Loaded previous run's counts from the existing CSV for comparison." -ForegroundColor DarkGray
    } catch {
        Write-Warning "Could not read previous results from '$CsvPath': $_"
    }
}

# -- Display summary ------------------------------------------------------------
Write-Host "`n-- Search Results ---------------------------------------------------" -ForegroundColor Green
$Searches |
    Select-Object @{n = 'Search';   e = { $_.Name } },
                  @{n = 'Items';    e = { if ($null -ne $_.ItemCount) { $_.ItemCount } else { '-' } } },
                  @{n = 'LastRun';  e = { if ($PrevCounts.ContainsKey($_.Name)) { $PrevCounts[$_.Name] } else { '-' } } },
                  @{n = 'Size';     e = { $_.Search.Size } },
                  @{n = 'Status';   e = { if ($_.Note) { $_.Note } elseif ($_.Search) { $_.Search.Status } else { 'not started' } } } |
    Format-Table -AutoSize
Write-Host "---------------------------------------------------------------------" -ForegroundColor Green

# -- Export combined results CSV to the user's Downloads folder -----------------
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

Write-Host "`nNOTE: A soft purge removes a MAXIMUM of 10 items PER MAILBOX per run," -ForegroundColor Yellow
Write-Host "      and purged items move to Recoverable Items, which searches STILL" -ForegroundColor Yellow
Write-Host "      count. Re-run until the count STOPS CHANGING - it will generally" -ForegroundColor Yellow
Write-Host "      not reach 0 while purged items sit in Recoverable Items.`n" -ForegroundColor Yellow

# Discard any leftover pasted lines so they cannot answer a purge prompt.
try { $Host.UI.RawUI.FlushInputBuffer() } catch { }

foreach ($Entry in $Searches) {
    if (-not $Entry.Done -or -not $Entry.Search -or $Entry.Search.Status -ne 'Completed') {
        $Reason = if ($Entry.Note) { $Entry.Note } else { 'not completed' }
        Write-Host "$($Entry.Name) - skipped ($Reason)." -ForegroundColor DarkGray
        continue
    }
    if ($null -eq $Entry.ItemCount) {
        Write-Host "$($Entry.Name) - item count unknown (never settled); skipping purge. Re-run to refresh." -ForegroundColor DarkGray
        continue
    }
    if ($Entry.ItemCount -eq 0) {
        Write-Host "$($Entry.Name) - 0 found, nothing to purge." -ForegroundColor DarkGray
        continue
    }

    $PrevText = ''
    if ($PrevCounts.ContainsKey($Entry.Name)) {
        $Prev = $PrevCounts[$Entry.Name]
        if ($Entry.ItemCount -eq $Prev) {
            $PrevText = " (unchanged from last run - likely includes already-purged items)"
        } else {
            $PrevText = " (was $Prev last run)"
        }
    }

    $Choice = Read-Host "$($Entry.Name) - $($Entry.ItemCount) found$PrevText. Soft purge? [y/N]"
    if ($Choice.Trim() -notin @('y', 'yes')) {
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
    Write-Host "Re-run this script with the same senders; stop when counts stop changing" -ForegroundColor DarkGray
    Write-Host "(purged items remain in Recoverable Items and are still counted)." -ForegroundColor DarkGray
}
