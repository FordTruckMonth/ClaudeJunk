<#
.SYNOPSIS
    Pulls Entra ID audit logs, interactive + non-interactive sign-ins, and sent
    messages for a single user over the last N days.

.DESCRIPTION
    Signs you in interactively (Microsoft Graph + Exchange Online), then writes
    one CSV per data set into a timestamped folder.

    RETENTION LIMITS — the service, not this script, caps how far back you can go:
      * Directory audit logs .... 7 days (Entra ID Free) / 30 days (P1, P2)
      * Sign-in logs ............ 7 days (Free) / 30 days (P1, P2)
      * Message trace (V2) ...... 10 days of live query
      * Historical search ....... 90 days, async report
    Asking for 90 days still only returns ~30 days of Graph data unless you
    stream the logs to Log Analytics / Sentinel / a storage account. The script
    warns you when the window you asked for exceeds what the API can serve.

.PARAMETER UserPrincipalName
    The user to report on, e.g. jdoe@contoso.com. Prompted for if omitted.

.PARAMETER Days
    How many days back to look. Prompted for if omitted.

.PARAMETER OutputFolder
    Where to write the CSVs. Defaults to the current directory.

.EXAMPLE
    .\Get-EntraUserActivity.ps1 -UserPrincipalName jdoe@contoso.com -Days 90

.NOTES
    Requires: Microsoft.Graph.Authentication and ExchangeOnlineManagement.
        Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement -Scope CurrentUser
    Permissions: AuditLog.Read.All + Directory.Read.All (Graph), and an Exchange
    role with message trace rights (e.g. View-Only Recipients / Security Reader).
#>

[CmdletBinding()]
param(
    [string]$UserPrincipalName,
    [int]   $Days,
    [string]$OutputFolder = (Get-Location).Path,
    [switch]$SkipExchange
)

$ErrorActionPreference = 'Stop'

if (-not $UserPrincipalName) { $UserPrincipalName = Read-Host 'User email (UPN)' }
if (-not $Days)              { $Days = [int](Read-Host 'How many days back') }
if ($Days -lt 1) { throw 'Days must be at least 1.' }

$startUtc = (Get-Date).ToUniversalTime().AddDays(-$Days)
$endUtc   = (Get-Date).ToUniversalTime()
$startStr = $startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')

$stamp  = (Get-Date).ToString('yyyyMMdd-HHmmss')
$outDir = Join-Path $OutputFolder ("{0}_{1}" -f ($UserPrincipalName -replace '[^\w.-]', '_'), $stamp)
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Save-Csv {
    param([object[]]$Rows, [string]$Name)
    $path = Join-Path $outDir "$Name.csv"
    if ($Rows -and $Rows.Count) {
        $Rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Host ("  {0,-28} {1,6} rows -> {2}" -f $Name, $Rows.Count, $path) -ForegroundColor Green
    } else {
        Write-Host ("  {0,-28} {1,6} rows (nothing returned)" -f $Name, 0) -ForegroundColor DarkYellow
    }
}

# --- Microsoft Graph: audit logs + sign-ins -----------------------------------

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes 'AuditLog.Read.All', 'Directory.Read.All' -NoWelcome

if ($Days -gt 30) {
    Write-Warning "Entra keeps at most 30 days of audit and sign-in logs (7 on the Free tier). The $Days-day window will come back short unless these logs are archived to Log Analytics."
}

function Invoke-GraphPaged {
    param([string]$Uri)
    $rows = New-Object System.Collections.Generic.List[object]
    while ($Uri) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        if ($resp.value) { $rows.AddRange(@($resp.value)) }
        $Uri = $resp.'@odata.nextLink'
    }
    , $rows.ToArray()
}

$userUri = 'https://graph.microsoft.com/v1.0/users/{0}?$select=id,displayName,userPrincipalName,mail' -f [uri]::EscapeDataString($UserPrincipalName)
$user    = Invoke-MgGraphRequest -Method GET -Uri $userUri -OutputType PSObject
Write-Host ("Target: {0} <{1}>  ({2} days, since {3})" -f $user.displayName, $user.userPrincipalName, $Days, $startStr)

Write-Host "`nPulling logs..." -ForegroundColor Cyan

# Directory audit logs — the user as actor, and the user as target.
$auditFilters = @(
    "activityDateTime ge $startStr and initiatedBy/user/userPrincipalName eq '$UserPrincipalName'"
    "activityDateTime ge $startStr and targetResources/any(t: t/userPrincipalName eq '$UserPrincipalName')"
)
$audits = foreach ($f in $auditFilters) {
    try {
        Invoke-GraphPaged "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$([uri]::EscapeDataString($f))&`$top=999"
    } catch { Write-Warning "Audit query failed: $($_.Exception.Message)" }
}
$auditRows = $audits | Sort-Object id -Unique | ForEach-Object {
    [PSCustomObject]@{
        ActivityDateTime = $_.activityDateTime
        Category         = $_.category
        Activity         = $_.activityDisplayName
        Result           = $_.result
        ResultReason     = $_.resultReason
        InitiatedByUser  = $_.initiatedBy.user.userPrincipalName
        InitiatedByApp   = $_.initiatedBy.app.displayName
        IpAddress        = $_.initiatedBy.user.ipAddress
        TargetResources  = ($_.targetResources | ForEach-Object { if ($_.displayName) { $_.displayName } else { $_.userPrincipalName } }) -join '; '
        ModifiedProps    = ($_.targetResources.modifiedProperties | ForEach-Object { "$($_.displayName): $($_.oldValue) -> $($_.newValue)" }) -join ' | '
        CorrelationId    = $_.correlationId
        Id               = $_.id
    }
} | Sort-Object ActivityDateTime -Descending
Save-Csv $auditRows 'AuditLogs'

# Sign-in logs — interactive and non-interactive are separate event types.
function Get-SignIns {
    param([string]$EventType)
    $f = "createdDateTime ge $startStr and userId eq '$($user.id)' and signInEventTypes/any(t: t eq '$EventType')"
    $raw = Invoke-GraphPaged "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($f))&`$top=999"
    $raw | ForEach-Object {
        [PSCustomObject]@{
            CreatedDateTime   = $_.createdDateTime
            UserPrincipalName = $_.userPrincipalName
            AppDisplayName    = $_.appDisplayName
            ResourceDisplay   = $_.resourceDisplayName
            ClientAppUsed     = $_.clientAppUsed
            IpAddress         = $_.ipAddress
            City              = $_.location.city
            State             = $_.location.state
            Country           = $_.location.countryOrRegion
            DeviceName        = $_.deviceDetail.displayName
            OperatingSystem   = $_.deviceDetail.operatingSystem
            Browser           = $_.deviceDetail.browser
            IsCompliant       = $_.deviceDetail.isCompliant
            ErrorCode         = $_.status.errorCode
            FailureReason     = $_.status.failureReason
            ConditionalAccess = $_.conditionalAccessStatus
            RiskLevel         = $_.riskLevelDuringSignIn
            MfaDetail         = ($_.authenticationDetails | ForEach-Object { $_.authenticationMethod }) -join '; '
            CorrelationId     = $_.correlationId
            Id                = $_.id
        }
    } | Sort-Object CreatedDateTime -Descending
}

foreach ($pair in @(@{Type = 'interactiveUser'; Name = 'SignIns_Interactive' },
                    @{Type = 'nonInteractiveUser'; Name = 'SignIns_NonInteractive' })) {
    try { Save-Csv (Get-SignIns $pair.Type) $pair.Name }
    catch { Write-Warning "$($pair.Name) failed: $($_.Exception.Message)" }
}

# --- Exchange Online: messages sent -------------------------------------------

if (-not $SkipExchange) {
    $sender = if ($user.mail) { $user.mail } else { $user.userPrincipalName }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Write-Host "`nConnecting to Exchange Online..." -ForegroundColor Cyan
    Connect-ExchangeOnline -ShowBanner:$false

    # Live message trace only reaches back 10 days.
    $traceStart = if ($startUtc -lt $endUtc.AddDays(-10)) { $endUtc.AddDays(-10) } else { $startUtc }
    if ($Days -gt 10) { Write-Warning "Message trace only serves 10 days live; querying since $($traceStart.ToString('u')) and submitting a historical search for the rest." }

    $useV2 = [bool](Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue)
    $msgs  = New-Object System.Collections.Generic.List[object]
    if ($useV2) {
        # V2 pages backwards: re-query with the oldest row returned as the new end point.
        $cursorEnd = $endUtc; $cursorRcpt = $null
        for ($i = 0; $i -lt 200; $i++) {
            $p = @{ StartDate = $traceStart; EndDate = $cursorEnd; SenderAddress = $sender; ResultSize = 5000 }
            if ($cursorRcpt) { $p.StartingRecipientAddress = $cursorRcpt }
            $batch = @(Get-MessageTraceV2 @p)
            if (-not $batch.Count) { break }
            $msgs.AddRange($batch)
            if ($batch.Count -lt 5000) { break }
            $last = $batch[-1]; $cursorEnd = $last.Received; $cursorRcpt = $last.RecipientAddress
        }
    } else {
        for ($page = 1; $page -le 1000; $page++) {
            $batch = @(Get-MessageTrace -StartDate $traceStart -EndDate $endUtc -SenderAddress $sender -PageSize 5000 -Page $page)
            if (-not $batch.Count) { break }
            $msgs.AddRange($batch)
            if ($batch.Count -lt 5000) { break }
        }
    }

    Save-Csv ($msgs | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, ToIP, FromIP, Size, MessageId, MessageTraceId |
              Sort-Object Received -Descending) 'MessagesSent'

    if ($Days -gt 10) {
        $histStart = if ($Days -gt 90) { $endUtc.AddDays(-90) } else { $startUtc }
        if ($Days -gt 90) { Write-Warning 'Historical search caps out at 90 days; clamping.' }
        $notify = (Get-ConnectionInformation | Select-Object -First 1).UserPrincipalName
        try {
            $job = Start-HistoricalSearch -ReportTitle "Sent-$sender-$stamp" -StartDate $histStart -EndDate $endUtc `
                       -ReportType MessageTrace -SenderAddress $sender -NotifyAddress $notify
            Write-Host ("  Historical search submitted: JobId {0}" -f $job.JobId) -ForegroundColor Green
            Write-Host "  Results land in Defender portal > Mail flow > Message trace (usually under a few hours); $notify gets an email." -ForegroundColor DarkGray
        } catch { Write-Warning "Historical search could not be submitted: $($_.Exception.Message)" }
    }

    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}

Disconnect-MgGraph | Out-Null
Write-Host "`nDone. Files in: $outDir`n" -ForegroundColor Cyan
