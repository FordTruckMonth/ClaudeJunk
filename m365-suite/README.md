# ClaudeJunk M365 Suite

A small suite of **read-only** PowerShell CLI tools for investigating a
Microsoft 365 tenant over Microsoft Graph. It grew out of the eDiscovery
content-search idea and expands it into the adjacent things you actually reach
for during an audit or an incident: user inventory, sign-in triage, mailbox
compromise indicators, directory change history, and guest exposure.

Everything here **reads**. Nothing creates, holds, exports, or deletes tenant
data. The one exception is `search`, which creates a Purview eDiscovery *case*
so it can run an estimate — it never exports content, and the case is left in
Purview for you to review or delete.

## Layout

```
m365-suite/
  M365.psm1                     Shared module: auth, Graph REST (paging + throttle), output
  m365.ps1                      Dispatcher / single entry point
  tools/
    Search-M365Content.ps1      eDiscovery-style KQL content search + hit estimate
    Get-M365UserReport.ps1      User inventory: licenses, last sign-in, status, guests
    Get-M365SignInLog.ps1       Entra sign-in log triage (failures / risky / by user)
    Get-M365MailboxRules.ps1    Inbox forwarding & delete rules (mailbox-compromise IOCs)
    Get-M365AuditLog.ps1        Directory audit log (role / consent / membership changes)
    Get-M365GroupReport.ps1     Group membership & guest-exposure report
```

## Requirements

- PowerShell 7+ (recommended) or Windows PowerShell 5.1. No extra modules —
  the suite talks to Graph over raw REST, so you don't need the Microsoft.Graph
  SDK installed.
- An account with the right Graph permissions (see each tool's header). The
  reporting tools need directory/audit read scopes; `search` needs
  `eDiscovery.Read.All` plus eDiscovery Manager rights in Purview.

## Sign in

By default the suite uses **device-code** sign-in against the first-party
"Microsoft Graph Command Line Tools" public client, so you don't have to
register your own app:

```powershell
# dot-source so the token persists across commands in your shell
. ./m365.ps1 -TenantId contoso.onmicrosoft.com signin
```

For unattended runs, register your own app and use **app-only**:

```powershell
. ./m365.ps1 -TenantId <guid> -ClientId <guid> -ClientSecret <secret> signin
```

Prefer the module directly? That works too and is what the dispatcher does
under the hood:

```powershell
Import-Module ./M365.psm1
Connect-M365 -TenantId contoso.onmicrosoft.com
./tools/Get-M365UserReport.ps1 -StaleDays 90
```

## Examples

```powershell
# eDiscovery: estimate how many items match a KQL query, mailboxes only
. ./m365.ps1 search -Query 'subject:"wire transfer" AND sent>=2026-01-01' -Scope Mailboxes

# Dormant accounts not seen in 90 days, to CSV
. ./m365.ps1 users -StaleDays 90 -As Csv -ExportPath stale-users.csv

# Failed sign-ins in the last day
. ./m365.ps1 signins -FailuresOnly -Days 1

# Every mailbox with a suspicious forwarding/delete rule
. ./m365.ps1 rules -All -SuspiciousOnly -As Csv -ExportPath rules.csv

# Who granted app consent in the last week
. ./m365.ps1 audit -Days 7 -Contains Consent

# Groups that contain external guests
. ./m365.ps1 groups -GuestExposedOnly
```

## Output

Every reporting tool accepts `-As Table|Csv|Json` and an optional
`-ExportPath <file>`. Default is a console table.

## Notes

- `search` uses the Graph **beta** eDiscovery endpoints, which is where
  content-search estimation lives today.
- Sign-in logs require an Entra ID P1/P2 license on the tenant.
- Device-code tokens are held in memory for the shell session only; app-only
  re-authenticates automatically when the token ages out.
