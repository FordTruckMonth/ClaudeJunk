# Get-M365MailboxRules.ps1 — find suspicious inbox rules & forwarding.
#
# Auto-forwarding to an external address and inbox rules that delete or
# file-away mail are the classic fingerprints of a compromised mailbox (an
# attacker hiding their tracks / exfiltrating). This walks mailboxes and
# flags:
#   - SMTP forwarding / redirect set on the mailbox
#   - inbox rules that forward, redirect, delete, or mark-as-read
# Read-only.
#
# Needs Mail.Read + MailboxSettings.Read (delegated: only your own mailbox;
# app-only or admin delegated: any mailbox you name).
#
#   ./Get-M365MailboxRules.ps1 -UserPrincipalName jdoe@contoso.com
#   ./Get-M365MailboxRules.ps1 -All -SuspiciousOnly -As Csv -ExportPath rules.csv

[CmdletBinding(DefaultParameterSetName = 'One')]
param(
    [Parameter(ParameterSetName = 'One', Mandatory)][string]$UserPrincipalName,
    [Parameter(ParameterSetName = 'All', Mandatory)][switch]$All,
    # Only show mailboxes that have a flagged rule/forward.
    [switch]$SuspiciousOnly,
    [ValidateSet('Table', 'Csv', 'Json')][string]$As = 'Table',
    [string]$ExportPath
)

if (-not (Get-Command Invoke-M365Graph -ErrorAction SilentlyContinue)) {
    throw 'Import the suite module first:  Import-Module ../M365.psm1'
}

if ($All) {
    Write-Host 'Enumerating mailboxes...' -ForegroundColor Cyan
    $targets = (Invoke-M365Graph "/users?`$select=userPrincipalName,mail&`$top=999" |
                Where-Object { $_.mail }).userPrincipalName
} else {
    $targets = @($UserPrincipalName)
}

$rows = foreach ($upn in $targets) {
    # Inbox rules — where forwarding/redirect/delete rules live.
    $inboxRules = @()
    try { $inboxRules = Invoke-M365Graph "/users/$upn/mailFolders/inbox/messageRules" } catch {}

    foreach ($r in $inboxRules) {
        $act = $r.actions
        $fwd = @()
        if ($act.forwardTo)             { $fwd += ($act.forwardTo.emailAddress.address) }
        if ($act.forwardAsAttachmentTo) { $fwd += ($act.forwardAsAttachmentTo.emailAddress.address) }
        if ($act.redirectTo)            { $fwd += ($act.redirectTo.emailAddress.address) }

        $flags = @()
        if ($fwd.Count)          { $flags += 'forwards' }
        if ($act.delete)         { $flags += 'deletes' }
        if ($act.markAsRead)     { $flags += 'marks-read' }
        if ($act.moveToFolder)   { $flags += 'moves' }
        # External forward target is the loudest signal.
        $extern = $fwd | Where-Object { $_ -and ($_ -notlike "*@$($upn.Split('@')[1])") }
        if ($extern) { $flags += 'EXTERNAL-FORWARD' }

        $suspicious = ($flags -match 'forwards|deletes|EXTERNAL-FORWARD').Count -gt 0
        if ($SuspiciousOnly -and -not $suspicious) { continue }

        [PSCustomObject]@{
            Mailbox    = $upn
            Rule       = $r.displayName
            Enabled    = $r.isEnabled
            Flags      = ($flags -join ', ')
            ForwardTo  = ($fwd -join '; ')
            Suspicious = $suspicious
        }
    }
}

$rows = @($rows)
Write-Host "`n=== Mailbox Rules ($($rows.Count) rules across $($targets.Count) mailboxes) ===" -ForegroundColor Cyan
$rows | Export-M365Result -As $As -Path $ExportPath
