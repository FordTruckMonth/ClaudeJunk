# Get-EntraUserActivity.ps1 — audit logs, interactive + non-interactive sign-ins,
# and sent mail for one user. Prompts for the email and a day count, writes CSVs.
#   Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement -Scope CurrentUser
# Service retention caps the window: 30d audit/sign-in (7d Free), 10d live message trace, 90d historical search.
param([string]$User, [int]$Days, [string]$Out = '.', [switch]$SkipExchange)
$ErrorActionPreference = 'Stop'
if (!$User) { $User = Read-Host 'User email (UPN)' }
if (!$Days) { $Days = [int](Read-Host 'How many days back') }

$now = (Get-Date).ToUniversalTime(); $from = $now.AddDays(-$Days); $since = $from.ToString('yyyy-MM-ddTHH:mm:ssZ')
$dir = Join-Path $Out ('{0}_{1}' -f ($User -replace '[^\w.-]', '_'), (Get-Date -Format yyyyMMdd-HHmmss))
New-Item -ItemType Directory $dir -Force | Out-Null

function Out-Set($Rows, $Name) {
    $n = @($Rows).Count
    if ($n) { $Rows | Export-Csv (Join-Path $dir "$Name.csv") -NoTypeInformation -Encoding UTF8 }
    Write-Host ('  {0,-24} {1,6} rows' -f $Name, $n) -Fore $(if ($n) { 'Green' } else { 'DarkYellow' })
}
function Get-Log($Set, $Filter) {   # follows @odata.nextLink to the end
    $uri = 'https://graph.microsoft.com/v1.0/auditLogs/{0}?$top=999&$filter={1}' -f $Set, [uri]::EscapeDataString($Filter)
    while ($uri) { $r = Invoke-MgGraphRequest GET $uri -OutputType PSObject; $r.value; $uri = $r.'@odata.nextLink' }
}

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes AuditLog.Read.All, Directory.Read.All -NoWelcome
if ($Days -gt 30) { Write-Warning "Entra keeps 30d of audit/sign-in logs (7d on Free) — expect less than $Days days unless they are archived to Log Analytics." }
$tgt = Invoke-MgGraphRequest GET ('https://graph.microsoft.com/v1.0/users/{0}?$select=id,displayName,userPrincipalName,mail' -f [uri]::EscapeDataString($User)) -OutputType PSObject
Write-Host ("`n{0} <{1}> — {2} days, since {3}`n" -f $tgt.displayName, $tgt.userPrincipalName, $Days, $since) -Fore Cyan

# Audit logs: the user as actor and as target, deduped.
Out-Set (@("initiatedBy/user/userPrincipalName eq '$User'", "targetResources/any(t: t/userPrincipalName eq '$User')") |
    ForEach-Object { Get-Log directoryAudits "activityDateTime ge $since and $_" } | Sort-Object id -Unique |
    Select-Object @{n = 'Time'; e = { $_.activityDateTime } }, category, activityDisplayName, result, resultReason,
        @{n = 'Actor'; e = { $_.initiatedBy.user.userPrincipalName } }, @{n = 'ActorApp'; e = { $_.initiatedBy.app.displayName } },
        @{n = 'IP'; e = { $_.initiatedBy.user.ipAddress } },
        @{n = 'Targets'; e = { ($_.targetResources | ForEach-Object { if ($_.displayName) { $_.displayName } else { $_.userPrincipalName } }) -join '; ' } },
        @{n = 'Changes'; e = { ($_.targetResources.modifiedProperties | ForEach-Object { "$($_.displayName): $($_.oldValue)->$($_.newValue)" }) -join ' | ' } },
        correlationId | Sort-Object Time -Descending) 'AuditLogs'

# Sign-ins: non-interactive is a separate event type and is omitted unless asked for by name.
foreach ($k in @{Interactive = 'interactiveUser'; NonInteractive = 'nonInteractiveUser' }.GetEnumerator()) {
    Out-Set (Get-Log signIns "createdDateTime ge $since and userId eq '$($tgt.id)' and signInEventTypes/any(t: t eq '$($k.Value)')" |
        Select-Object @{n = 'Time'; e = { $_.createdDateTime } }, userPrincipalName, appDisplayName, resourceDisplayName, clientAppUsed, ipAddress,
            @{n = 'City'; e = { $_.location.city } }, @{n = 'Country'; e = { $_.location.countryOrRegion } },
            @{n = 'Device'; e = { $_.deviceDetail.displayName } }, @{n = 'OS'; e = { $_.deviceDetail.operatingSystem } }, @{n = 'Browser'; e = { $_.deviceDetail.browser } },
            @{n = 'Error'; e = { $_.status.errorCode } }, @{n = 'Failure'; e = { $_.status.failureReason } }, conditionalAccessStatus, riskLevelDuringSignIn,
            @{n = 'AuthMethods'; e = { ($_.authenticationDetails.authenticationMethod) -join '; ' } }, correlationId |
        Sort-Object Time -Descending) "SignIns_$($k.Key)"
}

if (-not $SkipExchange) {
    $addr = if ($tgt.mail) { $tgt.mail } else { $tgt.userPrincipalName }
    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline -ShowBanner:$false
    $start = if ($from -lt $now.AddDays(-10)) { $now.AddDays(-10) } else { $from }
    if ($Days -gt 10) { Write-Warning "Message trace serves 10 days live; pulling since $($start.ToString('u')) and queueing a historical search for the rest." }

    # V2 pages backwards: each round re-queries ending at the oldest row returned.
    $msgs = [Collections.Generic.List[object]]::new(); $end = $now; $rcpt = $null
    for ($i = 0; $i -lt 200; $i++) {
        $p = @{StartDate = $start; EndDate = $end; SenderAddress = $addr; ResultSize = 5000 }
        if ($rcpt) { $p.StartingRecipientAddress = $rcpt }
        $b = @(Get-MessageTraceV2 @p)
        if (!$b.Count) { break }
        $msgs.AddRange($b)
        if ($b.Count -lt 5000) { break }
        $end = $b[-1].Received; $rcpt = $b[-1].RecipientAddress
    }
    Out-Set ($msgs | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, FromIP, ToIP, Size, MessageId | Sort-Object Received -Descending) 'MessagesSent'

    if ($Days -gt 10) {
        $j = Start-HistoricalSearch -ReportTitle "Sent-$addr-$(Get-Date -Format yyyyMMddHHmm)" -ReportType MessageTrace -SenderAddress $addr `
            -StartDate $(if ($Days -gt 90) { $now.AddDays(-90) } else { $from }) -EndDate $now -NotifyAddress (Get-ConnectionInformation)[0].UserPrincipalName
        Write-Host "  Historical search (up to 90d) queued: $($j.JobId) — collect it in Defender > Mail flow > Message trace" -Fore Green
    }
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}
Disconnect-MgGraph | Out-Null
Write-Host "`nDone: $dir`n" -Fore Cyan
