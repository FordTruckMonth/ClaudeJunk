# m365.ps1 — single entry point for the ClaudeJunk M365 CLI suite.
#
# Imports the shared module, signs you in, and dispatches to a named tool so
# you can run the whole suite from one command instead of importing modules by
# hand. Any arguments after the command name are passed straight through.
#
# DOT-SOURCE it so the sign-in token survives between commands in your shell
# (the bearer token lives in the imported module's session state; a plain
# `./m365.ps1` runs in a child process that is discarded when it exits):
#
#   . ./m365.ps1 -TenantId contoso.onmicrosoft.com signin
#   . ./m365.ps1 users -StaleDays 90 -As Csv -ExportPath stale.csv
#   . ./m365.ps1 search -Query 'subject:"invoice"' -Scope Mailboxes
#
# Sign in once per shell session, then run as many commands as you like.

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('signin', 'search', 'users', 'signins', 'rules', 'audit', 'groups', 'help')]
    [string]$Command = 'help',

    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret,

    [Parameter(ValueFromRemainingArguments)]
    $Rest
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
# Import once and keep it: re-importing would reset the module's stored token.
if (-not (Get-Module -Name M365)) {
    Import-Module (Join-Path $root 'M365.psm1')
}

$tools = @{
    search  = 'tools/Search-M365Content.ps1'
    users   = 'tools/Get-M365UserReport.ps1'
    signins = 'tools/Get-M365SignInLog.ps1'
    rules   = 'tools/Get-M365MailboxRules.ps1'
    audit   = 'tools/Get-M365AuditLog.ps1'
    groups  = 'tools/Get-M365GroupReport.ps1'
}

function Show-Help {
    Write-Host @'

ClaudeJunk M365 Suite — read-only Microsoft Graph investigation tools.

Usage:
  ./m365.ps1 -TenantId <tenant> signin            Sign in (device code)
  ./m365.ps1 -TenantId <tenant> -ClientId <id> -ClientSecret <s> signin
                                                  Sign in (app-only)

  ./m365.ps1 search   -Query <KQL> [-Scope Both|Mailboxes|Sites]
                      eDiscovery-style content search + hit estimate
  ./m365.ps1 users    [-StaleDays N] [-GuestsOnly] [-DisabledOnly]
                      Tenant user inventory (licenses, last sign-in, status)
  ./m365.ps1 signins  [-UserPrincipalName u] [-Days N] [-FailuresOnly] [-RiskyOnly]
                      Entra sign-in log triage
  ./m365.ps1 rules    (-UserPrincipalName u | -All) [-SuspiciousOnly]
                      Inbox forwarding/delete rules (mailbox-compromise IOCs)
  ./m365.ps1 audit    [-Days N] [-Category c] [-Contains text]
                      Directory audit log (role/consent/membership changes)
  ./m365.ps1 groups   [-GuestExposedOnly]
                      Group membership & guest-exposure report

Every reporting tool accepts:  -As Table|Csv|Json  [-ExportPath <file>]

'@ -ForegroundColor Gray
}

if ($Command -eq 'help') { Show-Help; return }

if ($Command -eq 'signin') {
    if (-not $TenantId) { throw 'signin requires -TenantId.' }
    $p = @{ TenantId = $TenantId }
    if ($ClientId)     { $p.ClientId     = $ClientId }
    if ($ClientSecret) { $p.ClientSecret = $ClientSecret }
    Connect-M365 @p
    return
}

if (-not (Get-Command Assert-M365Connected -ErrorAction SilentlyContinue)) {
    throw 'Module failed to load.'
}
try { Assert-M365Connected }
catch { throw "Not signed in. Run:  ./m365.ps1 -TenantId <tenant> signin" }

$script = Join-Path $root $tools[$Command]
& $script @Rest
