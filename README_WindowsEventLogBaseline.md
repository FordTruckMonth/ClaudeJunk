# Windows Event Log Baseline GPO (`New-WindowsEventLogBaselineGpo.ps1`)

Creates and links an Active Directory GPO implementing the Windows event logging baseline
merged from two sources:

- **MA** — Malware Archaeology [Windows Logging Cheat Sheet](https://www.malwarearchaeology.com/cheat-sheets), Feb 2019 ver 2.3 (Win 7 – Server 2019)
- **Huntress** — [Collecting Microsoft Windows Event Logs (WEL)](https://support.huntress.io/hc/en-us/articles/36005287194259-Collecting-Microsoft-Windows-Event-Logs-WEL) (Huntress Managed SIEM device configuration guide)

**Scope:** the GPO carries the Advanced Audit Policy, the event log sizes/retention, and
the "force audit policy subcategory settings" security option — nothing else. For the
remaining baseline items (PowerShell logging, command line in 4688, extra channels) and
for non-domain machines, see the step-by-step
[manual configuration guide](README_WindowsEventLogBaseline_Manual.md).

**Merge rule:** wherever the Huntress table marks a subcategory *No Auditing* because "all
process activity is covered by the Huntress EDR" (or defers to other telemetry), the
Malware Archaeology recommendation is used instead — the point of this baseline is that
the *logs themselves* capture the activity, EDR or not. Everywhere else the newer
Huntress value wins, since it corrects several MA-era settings against subcategories that
generate no events or only exist for deprecated features.

## Usage

Run as a user with GPO-creation rights (e.g. Domain Admins) on a DC or an admin
workstation with RSAT (GroupPolicy + ActiveDirectory modules):

```powershell
# Preview without touching AD or SYSVOL
.\New-WindowsEventLogBaselineGpo.ps1 -WhatIf

# Create the GPO and link it at the domain root (includes DCs)
.\New-WindowsEventLogBaselineGpo.ps1 -LinkTo 'DC=corp,DC=example,DC=com'

# Custom name, multiple OU links, bigger Security log, WFP success auditing
.\New-WindowsEventLogBaselineGpo.ps1 -GpoName 'SEC - Logging Baseline' `
    -LinkTo 'OU=Workstations,DC=corp,DC=example,DC=com','OU=Servers,DC=corp,DC=example,DC=com' `
    -SecurityLogSizeKB 1024000 -EnableWfpSuccessAuditing
```

| Parameter | Default | Purpose |
|---|---|---|
| `-GpoName` | `Windows Event Log Baseline` | GPO to create or update. |
| `-LinkTo` | *(unlinked)* | One or more DNs to link the GPO to (domain root or OUs). |
| `-SecurityLogSizeKB` | `512000` | Security log max size (both sources). MA: `1024000` if SACL/WFP auditing is on. |
| `-AppSystemLogSizeKB` | `256000` | Application and System log max size (MA). |
| `-EnableProcessTermination` | off | Audit Process Termination = Success (off in both base documents). |
| `-EnableWfpSuccessAuditing` | off | Add Success to Filtering Platform Connection (5156) per MA. ~9–10k events/hour/system. |
| `-SkipSaclAuditing` | off | Follow Huntress instead of MA for File System / Registry auditing (see table). |
| `-EnableCertificationServicesAuditing` | off | Certification Services S+F — only when the GPO's scope includes AD CS servers. |
| `-Force` | off | Overwrite audit/security-template settings already present in the target GPO. |

## How the GPO is built

Advanced Audit Policy in a GPO is not registry-based, so the script builds the GPO the
same way GPMC does:

1. `New-GPO` (or reuse by name — refuses to overwrite existing audit/security settings
   without `-Force`).
2. Writes **`Machine\Microsoft\Windows NT\Audit\audit.csv`** into the GPO's SYSVOL
   folder — the full merged audit table, all 59 subcategories. "No Auditing" rows are
   written explicitly (Setting Value `0`) so stale audit policy gets overridden, per the
   MA warning about unconfigured rows.
3. Writes **`Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`** —
   `SCENoApplyLegacyAuditPolicy=4,1` (*Audit: Force audit policy subcategory settings* =
   Enabled) plus `[Security Log]`/`[Application Log]`/`[System Log]` sections with
   `MaximumLogSize` (KB) and `AuditLogRetentionPeriod=0` (*Overwrite events as needed*).
4. Registers the required client-side extensions in `gPCMachineExtensionNames`
   (Security CSE `{827D319E-…}` and Advanced Audit Policy CSE `{F3CCC681-…}`) and bumps
   the GPO version (AD `versionNumber` + `GPT.ini`) so clients pick up the change.
5. Links the GPO to each `-LinkTo` target (skipping existing links).

## Merged Advanced Audit Policy table

*Applied* = what the GPO sets by default. **Bold** rows are where the two sources disagree.

| Category / Subcategory | MA Feb 2019 | Huntress | Applied | Why |
|---|---|---|---|---|
| **Account Logon** | | | | |
| Credential Validation | S+F | S+F | S+F | Agree |
| **Kerberos Authentication Service** | No Audit (WA) | S+F | S+F | Huntress (DC visibility; MA deferred to Advanced sheet) |
| **Kerberos Service Ticket Operations** | No Audit (WA) | S+F | S+F | Huntress |
| **Other Account Logon Events** | S+F | No Audit | No Audit | Huntress — subcategory generates no events |
| **Account Management** | | | | |
| **Application Group Management** | S+F | No Audit | No Audit | Huntress — deprecated Authorization Manager only |
| Computer Account Management | S+F | S+F | S+F | Agree |
| Distribution Group Management | S+F | S+F | S+F | Agree |
| **Other Account Management Events** | S+F | S | S | Huntress — no failure events exist |
| Security Group Management | S+F | S+F | S+F | Agree |
| User Account Management | S+F | S+F | S+F | Agree |
| **Detailed Tracking** | | | | |
| DPAPI Activity | No Audit | No Audit | No Audit | Agree |
| PNP Activity | S | S | S | Agree |
| **Process Creation** | **S+F** | No Audit — *"covered by the Huntress EDR"* | **S+F** | **MA per merge rule — keep 4688 in the log** |
| Process Termination | No Audit (WA) | No Audit — *EDR-covered* | No Audit¹ | Agree at base; `-EnableProcessTermination` flips to S |
| **RPC Events** | S+F | No Audit | No Audit | Huntress — generates no events |
| **Token Right Adjusted** | S (N) | No Audit | No Audit | Huntress — 4703 volume dilutes value on Win10+ |
| **DS Access** (DCs) | | | | |
| Detailed Directory Service Replication | No Audit | No Audit | No Audit | Agree |
| **Directory Service Access** | No Audit (WA) | S+F | S+F | Huntress |
| **Directory Service Changes** | S+F | S | S | Huntress — no failure events exist |
| Directory Service Replication | No Audit | No Audit | No Audit | Agree |
| **Logon/Logoff** | | | | |
| **Account Lockout** | S (WA) | F | F | Huntress — lockouts only produce failure events |
| **Group Membership** | S | No Audit | No Audit | Huntress — per-session membership dump is excessive |
| IPsec Extended/Main/Quick Mode | No Audit | No Audit | No Audit | Agree |
| Logoff | S | S | S | Agree |
| Logon | S+F | S+F | S+F | Agree |
| Network Policy Server | S+F | S+F | S+F | Agree |
| Other Logon/Logoff Events | S+F | S+F | S+F | Agree |
| **Special Logon** | S+F | S | S | Huntress — no failure events exist |
| User / Device Claims | No Audit | No Audit | No Audit | Agree |
| **Object Access** | | | | |
| **Application Generated** | S+F | No Audit | No Audit | Huntress — deprecated Authorization Manager only |
| Central Access Policy Staging | No Audit | No Audit | No Audit | Agree |
| **Certification Services** | S+F | S+F *if AD CS* | Off² | Huntress — enable for GPOs scoped to AD CS servers |
| **Detailed File Share** | S | S+F | S+F | Huntress (5145 — can be loud on busy file servers/DCs) |
| File Share | S+F | S+F | S+F | Agree |
| **File System** | **S** | No Audit (SACL-dependent) | **S** | **MA per merge rule** — emits nothing until SACLs exist (see MA File Auditing Cheat Sheet), so zero-noise; `-SkipSaclAuditing` reverts |
| **Filtering Platform Connection** | S (N)(WA) | F | F³ | Huntress default; `-EnableWfpSuccessAuditing` adds MA's Success (5156, very noisy) |
| Filtering Platform Packet Drop | No Audit | No Audit | No Audit | Agree |
| Handle Manipulation | No Audit | No Audit | No Audit | Agree |
| **Kernel Object** | No Audit (WA) | S+F | S+F | Huntress — keep *"Audit access of global system objects"* disabled |
| **Other Object Access Events** | No Audit (WA) | S+F | S+F | Huntress — scheduled-task ops (4698–4702) |
| **Registry** | **S** | No Audit (SACL-dependent) | **S** | **MA per merge rule** — same reasoning as File System; `-SkipSaclAuditing` reverts |
| Removable Storage | S+F | S+F | S+F | Agree |
| **SAM** | S | No Audit | No Audit | Huntress — data available via Account Management events |
| **Policy Change** | | | | |
| **Audit Policy Change** | S+F | S | S | Huntress — no failure events exist |
| **Authentication Policy Change** | S+F | S | S | Huntress |
| **Authorization Policy Change** | S+F | S | S | Huntress |
| Filtering Platform Policy Change | S | S | S | Agree |
| **MPSSVC Rule-Level Policy Change** | No Audit | S+F | S+F | Huntress — Windows Firewall rule changes |
| **Other Policy Change Events** | No Audit (WA) | S+F | S+F | Huntress |
| **Privilege Use** | | | | |
| Non Sensitive / Other Privilege Use | No Audit | No Audit | No Audit | Agree |
| Sensitive Privilege Use | S+F | S+F | S+F | Agree (high volume — both keep it anyway) |
| **System** | | | | |
| **IPsec Driver** | S (WA) | No Audit | No Audit | Huntress — IPsec troubleshooting only |
| **Other System Events** | F (WA) | S+F | S+F | Huntress |
| **Security State Change** | S+F | S | S | Huntress — no failure events exist |
| **Security System Extension** | S+F | S | S | Huntress |
| System Integrity | S+F | S+F | S+F | Agree |

¹ Both base documents leave Process Termination off; use `-EnableProcessTermination` if you want 4689 correlation without relying on EDR telemetry.
² Use `-EnableCertificationServicesAuditing` for a GPO whose scope includes AD CS servers.
³ Not literally an "EDR-covered" row — Huntress says success-connection value "is available through other mechanisms" — so the noisy MA setting is opt-in rather than default.

`(WA)` = MA's pointer to their *Windows Advanced Logging Cheat Sheet*. `(N)` = MA noise marker.

## Log sizes set by the GPO

| Log | Size | Retention | Source |
|---|---|---|---|
| Security | 512,000 KB (param; MA allows 1,024,000) | Overwrite events as needed | Both |
| Application / System | 256,000 KB | Overwrite events as needed | MA |

## Deliberately out of scope

These baseline items are **not** in the GPO this script builds — apply them per the
[manual guide](README_WindowsEventLogBaseline_Manual.md) (steps 4–7) or a separate GPO:

- **Command line in 4688** (`Administrative Templates > System > Audit Process Creation`),
  or as a one-liner against this same GPO:
  `Set-GPRegistryValue -Name 'Windows Event Log Baseline' -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ValueName ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 1`
- **PowerShell Module/ScriptBlock logging** (`Administrative Templates > Windows Components > Windows PowerShell`)
- **Task Scheduler / CAPI2 operational channels** and their sizes (per-machine `wevtutil`)
- **PowerShell log sizes** (classic + Operational — per-machine, Event Viewer or `wevtutil`)
- **DNS server debug logging** (DNS Manager, DNS servers only)

Huntress-specific notes:

- The Huntress agent auto-applies its Advanced Audit Policy on SIEM-enabled endpoints;
  this GPO matches it except for the deliberate MA overrides above. **GPO always wins**
  over agent/local settings — keeping the GPO aligned to this table avoids Huntress
  escalation noise.
- Huntress sets the NTDS diagnostics keys (`Field Engineering = 5`, search thresholds) on
  SIEM-enabled domain controllers itself — the script doesn't touch those.
- Huntress does **not** set Security log size/retention; that's exactly what this GPO's
  `GptTmpl.inf` covers.

## Verify

```powershell
Get-GPOReport -Name 'Windows Event Log Baseline' -ReportType Html -Path .\baseline-gpo.html   # inspect settings
gpupdate /force                  # on a client in scope
auditpol /get /category:*        # should match the Applied column above
wevtutil gl Security             # maxSize + retention
```

Worth watching once collected (MA "HARVEST" highlights): 4688 (new process), 4624/4625
logon types, 4720/4724/4738 account changes, 4732 group membership, 7045/4697 new
services, 4698 new scheduled task, 1102/104 log cleared, 4719 audit policy changed,
4657/4663 registry/file writes (needs SACLs), 5156 WFP connections (if enabled).
