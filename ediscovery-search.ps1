<#
.SYNOPSIS
    Batch eDiscovery compliance searches (one per sender) with per-search soft purge.

.DESCRIPTION
    Connects to Security & Compliance PowerShell, collects a list of sender
    addresses (or @domains), creates and runs one ComplianceSearch per sender
    (named "YYYY-MM-DD <sender>"), shows a summary of item counts, exports a
    combined CSV to the user's Downloads folder, then offers a SoftDelete purge
    for each search individually.

.NOTES
    The *-ComplianceSearch cmdlets are Security & Compliance (Microsoft Purview)
    cmdlets, NOT Exchange Online. They require Connect-IPPSSession, and since the
    2025 enforcement (MC1131771) also require -EnableSearchOnlySession, which
    needs ExchangeOnlineManagement v3.9.0+ (installed below if missing).

    A soft purge removes at most 10 items per mailbox per run, and purged items
    move to Recoverable Items, WHICH SEARCHES STILL COUNT. Re-run this script
    with the same senders until counts STOP CHANGING -- they will generally not
    reach 0 until the deleted-item retention period expires. Same-day searches
    are reused and refreshed automatically, and the previous run's counts are
    read back from the CSV so each prompt shows the change since last run.
#>

# Flushes stale console input (e.g. leftover pasted lines) so it cannot answer
# the prompt, then requires an exact y/yes.
function Confirm-Choice([string]$Prompt) {
    try { $Host.UI.RawUI.FlushInputBuffer() } catch { }
    return (Read-Host $Prompt).Trim() -in @('y', 'yes')
}

# Returns $null when the session can run eDiscovery cmdlets, else the error text.
# A session opened WITHOUT -EnableSearchOnlySession imports the cmdlets but
# fails at invocation (MC1131771), and no connection property reveals
# search-only mode -- an invocation probe is the only reliable check.
function Test-EDiscoveryCmdlets {
    try {
        $null = Get-ComplianceSearch -ErrorAction Stop
        return $null
    } catch {
        return "$_"
    }
}

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

$ProbeOk = $false
if ($ComplianceConnection) {
    if ($null -eq (Test-EDiscoveryCmdlets)) {
        $ProbeOk = $true
    } else {
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
    $ProbeError = Test-EDiscoveryCmdlets
    if ($ProbeError) {
        if ($ProbeError -match 'EnableSearchOnlySession') {
            Write-Error "This session still cannot run eDiscovery cmdlets. Open a NEW PowerShell window and re-run this script."
        } else {
            Write-Error "eDiscovery cmdlet probe failed: $ProbeError"
        }
        exit 1
    }
}

# -- Collect senders -----------------------------------------------------------
$Senders = [System.Collections.Generic.List[string]]::new()
Write-Host "`nEnter the sender email addresses to search for." -ForegroundColor Cyan
Write-Host "One per line, or paste several separated by commas/spaces." -ForegroundColor DarkGray
Write-Host "Use '*@domain.com' (or '@domain.com') to match every sender at a domain." -ForegroundColor DarkGray
Write-Host "Enter 'n' (or leave blank) when you're done." -ForegroundColor DarkGray

while ($true) {
    $Entry = Read-Host ("Sender {0}" -f ($Senders.Count + 1))
    if ([string]::IsNullOrWhiteSpace($Entry) -or $Entry.Trim() -in @('n', 'no', 'done')) { break }
    foreach ($Part in ($Entry -split '[,;\s]+')) {
        $Addr = $Part.Trim().Trim('<', '>', '"', "'").ToLowerInvariant()
        if (-not $Addr) { continue }

        # Normalize to a canonical token: '*@domain.com' / '@domain.com' means
        # the whole domain (Microsoft's eDiscovery docs: specify "@contoso.com"
        # in From to match everyone in the domain; a leading * is not valid KQL).
        if ($Addr -match '^\*?@(.+)$') {
            if ($Matches[1] -notmatch '^[^@\s]+\.[^@\s]+$') {
                Write-Warning "'$Addr' does not look like a valid domain - skipped."
                continue
            }
            $Token  = "@$($Matches[1])"
            $Suffix = ' (entire domain)'
        } elseif ($Addr -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
            $Token  = $Addr
            $Suffix = ''
        } else {
            Write-Warning "'$Addr' does not look like a valid email address - skipped."
            continue
        }

        if ($Senders.Contains($Token)) {
            Write-Host "  (duplicate '$Token' ignored)" -ForegroundColor DarkGray
        } else {
            $Senders.Add($Token)
            Write-Host "  + $Token$Suffix" -ForegroundColor DarkGray
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
if (-not (Confirm-Choice "Create $($Senders.Count) search(es) named '$Today <sender>'? [y/N]")) {
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
        Status    = $null
        Purged    = $false
    }
}

# One listing call instead of one existence check per sender.
$ExistingNames = @{}
try {
    foreach ($cs in (Get-ComplianceSearch -ErrorAction Stop)) { $ExistingNames[$cs.Name] = $true }
} catch {
    Write-Warning "Could not list existing searches (duplicates will fail at create): $_"
}

foreach ($Entry in $Searches) {
    if ($ExistingNames.ContainsKey($Entry.Name)) {
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
# One listing call per pass covers every pending search (a bulk listing carries
# Status but not the expensive Items/SuccessResults -- those come later).
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
    $ByName = @{}
    try {
        foreach ($cs in (Get-ComplianceSearch -ErrorAction Stop)) { $ByName[$cs.Name] = $cs }
    } catch {
        continue   # transient failure; retry on the next pass
    }
    foreach ($Entry in $Remaining) {
        $s = $ByName[$Entry.Name]
        if ($s -and $s.Status -in @('Completed', 'Failed')) {
            $Entry.Done   = $true
            $Entry.Search = $s
            if ($s.Status -eq 'Failed') { $Entry.Note = 'search failed' }
        }
    }
    $DoneCount = @($Running | Where-Object Done).Count
    Write-Host ("`r  {0}/{1} complete " -f $DoneCount, $Running.Count) -NoNewline
}
Write-Host ""

# -- Fetch item counts (Items/SuccessResults need a per-identity fetch and can
#    momentarily read empty right after completion) ----------------------------
# Round-robin so the settle sleeps are shared across all searches instead of
# paid per search.
$Unsettled = [System.Collections.Generic.List[object]]::new()
foreach ($Entry in ($Running | Where-Object { $_.Done -and $_.Search.Status -eq 'Completed' })) {
    $Unsettled.Add($Entry)
}
for ($Round = 0; $Round -lt 6 -and $Unsettled.Count -gt 0; $Round++) {
    if ($Round -gt 0) { Start-Sleep -Seconds 5 }
    foreach ($Entry in @($Unsettled)) {
        try {
            $s = Get-ComplianceSearch -Identity $Entry.Name -ErrorAction Stop
        } catch {
            continue   # transient failure; retry next round
        }
        if ($s.SuccessResults -and $null -ne $s.Items) {
            $Entry.Search = $s
            # SuccessResults lists an "Item count" per location; sum them as a
            # cross-check against the Items property.
            $Parsed = 0
            foreach ($m in [regex]::Matches([string]$s.SuccessResults, 'Item count:\s*(\d+)')) {
                $Parsed += [int]$m.Groups[1].Value
            }
            $Entry.ItemCount = [Math]::Max([int]$s.Items, $Parsed)
            $null = $Unsettled.Remove($Entry)
        }
    }
}
foreach ($Entry in $Unsettled) {
    Write-Warning "'$($Entry.Name)': item count never settled; count unknown - re-run to refresh."
    $Entry.Note = 'count unsettled'
}

# Derive the display/CSV status once per entry.
foreach ($Entry in $Searches) {
    $Entry.Status = if ($Entry.Note) { $Entry.Note }
                    elseif ($Entry.Search) { $Entry.Search.Status }
                    else { 'not started' }
}

# -- Load the previous run's counts (if any) for comparison ---------------------
$DownloadsPath = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'
if (-not (Test-Path $DownloadsPath)) {
    New-Item -ItemType Directory -Force -Path $DownloadsPath | Out-Null
}
$CsvPath = Join-Path $DownloadsPath "$Today eDiscovery Results.csv"

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

# -- Display summary and export CSV ----------------------------------------------
Write-Host "`n-- Search Results ---------------------------------------------------" -ForegroundColor Green
$Searches |
    Select-Object @{n = 'Search';  e = { $_.Name } },
                  @{n = 'Items';   e = { if ($null -ne $_.ItemCount) { $_.ItemCount } else { '-' } } },
                  @{n = 'LastRun'; e = { if ($PrevCounts.ContainsKey($_.Name)) { $PrevCounts[$_.Name] } else { '-' } } },
                  @{n = 'Size';    e = { $_.Search.Size } },
                  Status |
    Format-Table -AutoSize
Write-Host "---------------------------------------------------------------------" -ForegroundColor Green

try {
    $Searches |
        Select-Object @{n = 'SearchName'; e = { $_.Name } },
                      Sender,
                      @{n = 'Items'; e = { $_.ItemCount } },
                      @{n = 'Size';  e = { $_.Search.Size } },
                      Status,
                      Query,
                      @{n = 'CreatedTime';      e = { $_.Search.CreatedTime } },
                      @{n = 'LastModifiedTime'; e = { $_.Search.LastModifiedTime } } |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-Host "Results exported to: $CsvPath" -ForegroundColor Yellow
} catch {
    Write-Warning "Failed to export CSV to '$CsvPath': $_"
}

# -- Offer soft purge per search --------------------------------------------------
# ItemCount is only ever set on completed, settled searches, so this one test
# is the full eligibility predicate.
if (-not @($Searches | Where-Object { $_.ItemCount -gt 0 })) {
    Write-Host "`nNo searches returned items - nothing to purge." -ForegroundColor DarkGray
    exit 0
}

Write-Host "`nNOTE: A soft purge removes a MAXIMUM of 10 items PER MAILBOX per run," -ForegroundColor Yellow
Write-Host "      and purged items move to Recoverable Items, which searches STILL" -ForegroundColor Yellow
Write-Host "      count. Re-run until the count STOPS CHANGING - it will generally" -ForegroundColor Yellow
Write-Host "      not reach 0 while purged items sit in Recoverable Items.`n" -ForegroundColor Yellow

foreach ($Entry in $Searches) {
    if ($null -eq $Entry.ItemCount) {
        Write-Host "$($Entry.Name) - skipped ($($Entry.Status))." -ForegroundColor DarkGray
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

    if (-not (Confirm-Choice "$($Entry.Name) - $($Entry.ItemCount) found$PrevText. Soft purge? [y/N]")) {
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
