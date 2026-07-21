# Windows Event Log Baseline (`Set-WindowsEventLogBaseline.ps1`)

Automates the Windows event logging configuration merged from two sources:

- **MA** — Malware Archaeology [Windows Logging Cheat Sheet](https://www.malwarearchaeology.com/cheat-sheets), Feb 2019 ver 2.3 (Win 7 – Server 2019)
- **Huntress** — [Collecting Microsoft Windows Event Logs (WEL)](https://support.huntress.io/hc/en-us/articles/36005287194259-Collecting-Microsoft-Windows-Event-Logs-WEL) (Huntress Managed SIEM device configuration guide)

Prefer to configure this by hand (GPO / Local Security Policy / Event Viewer)? See the
step-by-step [manual configuration guide](README_WindowsEventLogBaseline_Manual.md).

**Merge rule:** wherever the Huntress table marks a subcategory *No Auditing* because "all
process activity is covered by the Huntress EDR" (or defers to other telemetry), the Malware
Archaeology recommendation is used instead — the point of this baseline is that the *logs
themselves* capture the activity, EDR or not. Everywhere else the newer Huntress value wins,
since it corrects several MA-era settings against subcategories that generate no events or
only exist for deprecated features.

## Usage

Run elevated (Windows PowerShell 5.1+):

```powershell
# Preview every change without applying
.\Set-WindowsEventLogBaseline.ps1 -WhatIf

# Apply the baseline
.\Set-WindowsEventLogBaseline.ps1

# Bigger Security log (MA guidance when file/registry/WFP auditing are on),
# plus WFP Success auditing and the resulting policy printed at the end
.\Set-WindowsEventLogBaseline.ps1 -SecurityLogSizeKB 1024000 -EnableWfpSuccessAuditing -ShowResultingPolicy
```

| Parameter | Default | Purpose |
|---|---|---|
| `-SecurityLogSizeKB` | `512000` | Security log max size (both sources). MA: `1024000` if File/Registry/WFP/Process auditing all enabled. |
| `-AppSystemLogSizeKB` | `256000` | Application and System log max size (MA). |
| `-PowerShellLogSizeKB` | `256000` | Classic *Windows PowerShell* log and `Microsoft-Windows-PowerShell/Operational` (MA). |
| `-Capi2LogSizeKB` | `102400` | Size for `Microsoft-Windows-CAPI2/Operational`, which the script enables (MA — watch event 81). |
| `-EnableProcessTermination` | off | Audit Process Termination = Success (MA Advanced sheet territory; Huntress: EDR-covered). |
| `-EnableWfpSuccessAuditing` | off | Add Success to Filtering Platform Connection (5156) per MA. ~9–10k events/hour/system. |
| `-SkipSaclAuditing` | off | Follow Huntress instead of MA for File System / Registry auditing (see table). |
| `-EnableCertificationServicesAuditing` | auto | Certification Services S+F. Auto-enabled when the `CertSvc` service is present (Huntress note). |
| `-SkipDisables` | off | Only enable auditing; never turn a subcategory off. |
| `-SkipPowerShellLogging` | off | Don't set Module/ScriptBlock logging registry values. |
| `-EnableDnsDebugLogging` | off | Windows DNS Server role only: MA DNS debug packet logging to `%SystemRoot%\System32\Dns\Dns.log`. |
| `-ShowResultingPolicy` | off | Print `auditpol /get /category:*` when done. |

Subcategories are set by **GUID**, so the script works on non-English Windows.

## What it configures

1. **Force Advanced Audit Policy** — `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy = 1`
   (MA: *"Audit: Force audit policy subcategory settings" = ENABLE*).
2. **Advanced Audit Policy** — the merged table below via `auditpol.exe`.
3. **Log sizes/retention** — via `wevtutil sl` (overwrite as needed / `/rt:false`), and enables the
   Task Scheduler (`129` created / `141` deleted) and CAPI2 (`81` failed trust) operational channels.
4. **Command line in 4688** — `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`.
5. **PowerShell logging** (Huntress + MA agree) — under both
   `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell` and the `Wow6432Node` mirror:
   `ModuleLogging\EnableModuleLogging = 1`, `ModuleLogging\ModuleNames\* = *`,
   `ScriptBlockLogging\EnableScriptBlockLogging = 1`.
6. **Optional DNS Server debug logging** — MA "ENABLE: DNS LOGS" (queries/responses,
   send/receive, UDP/TCP, updates).

## Merged Advanced Audit Policy table

*Applied* = what the script sets by default. **Bold** rows are where the two sources disagree.

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
| **Certification Services** | S+F | S+F *if AD CS* | Auto² | Huntress — S+F when `CertSvc` present |
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
² Auto-detected: S+F when the AD CS service exists, else No Audit. Force with `-EnableCertificationServicesAuditing`.
³ Not literally an "EDR-covered" row — Huntress says success-connection value "is available through other mechanisms" — so the noisy MA setting is opt-in rather than default.

`(WA)` = MA's pointer to their *Windows Advanced Logging Cheat Sheet*. `(N)` = MA noise marker.

## Log sizes and additional channels

| Log | Size | Retention | Source |
|---|---|---|---|
| Security | 512,000 KB (param; MA allows 1,024,000) | Overwrite as needed | Both |
| Application / System | 256,000 KB | Overwrite as needed | MA |
| Windows PowerShell (classic) | 256,000 KB | Overwrite as needed | MA |
| Microsoft-Windows-PowerShell/Operational | 256,000 KB | default | MA |
| Microsoft-Windows-TaskScheduler/Operational | default | enabled | MA (harvest 129/141) |
| Microsoft-Windows-CAPI2/Operational | 102,400 KB | enabled | MA (harvest 81) |

## Doing it via Group Policy instead

On domain-joined fleets, set the same values in GPO — **GPO always wins over local/agent
settings** (Huntress will raise an escalation if a GPO fights its baseline):

- Audit policy: `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration`
- Log size/retention: `... > Security Settings > Event Log` (Security: max size `512000`, retention *Overwrite events as needed*)
- Force subcategory override: `... > Security Settings > Local Policies > Security Options > "Audit: Force audit policy subcategory settings..." = Enabled`
- PowerShell logging: `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell` → *Turn on Module Logging* (`*`) and *Turn on PowerShell Script Block Logging*
- Command line in 4688: `... > Administrative Templates > System > Audit Process Creation > Include command line in process creation events = Enabled`

Huntress-specific notes:

- The Huntress agent auto-applies its Advanced Audit Policy on SIEM-enabled endpoints; this
  script's audit table matches it except for the deliberate MA overrides above, so expect the
  agent and script to coexist quietly. Keep any GPO aligned to avoid escalation noise.
- Huntress sets the NTDS diagnostics keys (`Field Engineering = 5`, search thresholds) on
  SIEM-enabled domain controllers itself — the script doesn't touch those.
- Huntress does **not** set Security log size/retention or PowerShell logging; those must come
  from this script or GPO.

## Verify

```powershell
auditpol /get /category:*        # audit policy actually in effect
wevtutil gl Security             # log size/retention
Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-CAPI2/Operational' | Format-Table LogName, IsEnabled, MaximumSizeInBytes
```

Worth watching once collected (MA "HARVEST" highlights): 4688 (new process + command line),
4624/4625 logon types, 4720/4724/4738 account changes, 4732 group membership, 7045/4697 new
services, 4698 new scheduled task, 1102/104 log cleared, 4719 audit policy changed, 4657/4663
registry/file writes (needs SACLs), 5156 WFP connections (if enabled).
