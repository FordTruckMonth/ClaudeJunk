# Windows Event Log Baseline — Manual Setup Guide

How to apply the logging baseline by hand, without the script. Where the values come
from (Malware Archaeology vs. Huntress) is covered in
[README_WindowsEventLogBaseline.md](README_WindowsEventLogBaseline.md) — this guide is
just the steps.

**Pick your tool first:**

| Your situation | Use |
|---|---|
| Domain-joined fleet | Group Policy Management (`gpmc.msc`) — make one GPO, link it to your workstation/server OUs. **GPO always beats local settings.** |
| Standalone machine | Local Group Policy Editor (`gpedit.msc`) + Event Viewer (`eventvwr.msc`) |
| Windows Home (no gpedit) | The `reg add` / `wevtutil` commands shown in each step |

All GPO paths below start at **Computer Configuration → Policies** (in `gpedit.msc`,
skip the "Policies" node).

**The whole job is six steps, plus two optional ones:**

- [ ] 1. Set log sizes and retention
- [ ] 2. Force Advanced Audit Policy (do this before step 3)
- [ ] 3. Set the audit policy (the big one)
- [ ] 4. Capture command lines in process events
- [ ] 5. Turn on PowerShell logging
- [ ] 6. Enable the Task Scheduler and CAPI2 logs
- [ ] 7. *(Optional)* DNS server debug logging
- [ ] 8. Verify

---

## Step 1 — Set log sizes and retention

**Where:** `Windows Settings → Security Settings → Event Log` (GPO), or in Event Viewer:
right-click each log → **Properties**.

| Log | Max size (KB) | Retention |
|---|---|---|
| Security | **512000** | Overwrite events as needed |
| Application | 256000 | Overwrite events as needed |
| System | 256000 | Overwrite events as needed |
| Windows PowerShell | 256000 | Overwrite events as needed |
| Microsoft → Windows → PowerShell → Operational | 256000 | (default) |

The GPO Event Log section only covers the first three — set the two PowerShell logs in
Event Viewer (under *Applications and Services Logs*) or with `wevtutil`.

> Bump Security to **1024000** KB if you later enable the noisy options in step 3
> (file/registry SACL auditing, WFP success connections).

Command line (size is in **bytes** here): `wevtutil sl Security /ms:524288000 /rt:false`

## Step 2 — Force Advanced Audit Policy

Without this switch, the old category-level audit settings can silently override
everything you do in step 3. Flip it first.

**Where:** `Windows Settings → Security Settings → Local Policies → Security Options`

**Set:** *"Audit: Force audit policy subcategory settings (Windows Vista or later) to
override audit policy category settings"* → **Enabled**

Command line:
`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f`

## Step 3 — Set the audit policy

**Where:** `Windows Settings → Security Settings → Advanced Audit Policy Configuration →
Audit Policies` (locally: `secpol.msc` → *Advanced Audit Policy Configuration*).

For each subcategory: double-click it → tick **"Configure the following audit events"**
→ tick the boxes for the setting shown → OK.

> ⚠ **The "No Auditing" lists below still need clicks.** Tick *Configure* and leave both
> boxes empty — that enforces "no auditing." If you skip the row entirely, it stays
> whatever it was before, and the baseline isn't really applied.

### Account Logon

| Subcategory | Setting |
|---|---|
| Credential Validation | Success + Failure |
| Kerberos Authentication Service | Success + Failure |
| Kerberos Service Ticket Operations | Success + Failure |

**No Auditing:** Other Account Logon Events

### Account Management

| Subcategory | Setting |
|---|---|
| Computer Account Management | Success + Failure |
| Distribution Group Management | Success + Failure |
| Security Group Management | Success + Failure |
| User Account Management | Success + Failure |
| Other Account Management Events | Success only |

**No Auditing:** Application Group Management

### Detailed Tracking

| Subcategory | Setting |
|---|---|
| **Process Creation** | **Success + Failure** ← the 4688 events; the core of this baseline |
| PNP Activity | Success only |

**No Auditing:** DPAPI Activity, Process Termination, RPC Events, Token Right Adjusted Events

> Optional: set **Process Termination → Success** if you want process-exit (4689)
> correlation without relying on EDR telemetry.

### DS Access — matters on Domain Controllers, harmless elsewhere

| Subcategory | Setting |
|---|---|
| Directory Service Access | Success + Failure |
| Directory Service Changes | Success only |

**No Auditing:** Detailed Directory Service Replication, Directory Service Replication

### Logon/Logoff

| Subcategory | Setting |
|---|---|
| Logon | Success + Failure |
| Logoff | Success only |
| Account Lockout | Failure only |
| Special Logon | Success only |
| Network Policy Server | Success + Failure |
| Other Logon/Logoff Events | Success + Failure |

**No Auditing:** User/Device Claims, Group Membership, IPsec Extended Mode, IPsec Main Mode, IPsec Quick Mode

### Object Access

| Subcategory | Setting |
|---|---|
| File Share | Success + Failure |
| Detailed File Share | Success + Failure |
| File System | Success only *(silent until you add SACLs — see note)* |
| Registry | Success only *(silent until you add SACLs — see note)* |
| Kernel Object | Success + Failure |
| Other Object Access Events | Success + Failure |
| Removable Storage | Success + Failure |
| Filtering Platform Connection | Failure only |

**No Auditing:** Application Generated, Central Access Policy Staging, Certification
Services, Filtering Platform Packet Drop, Handle Manipulation, SAM

Notes for this category:

- **File System / Registry** produce nothing until you put SACLs on the folders and keys
  you care about (Malware Archaeology's *File Auditing* and *Registry Auditing* cheat
  sheets tell you which). Enabling them now costs nothing and means the SACLs work the
  moment you add them.
- **Certification Services:** on an AD CS server, set Success + Failure instead.
- **Filtering Platform Connection:** optionally add Success to log every allowed
  connection (event 5156). Expect ~9–10k events/hour per machine — only with a big
  Security log and a plan to collect it.
- Keep Security Options → *"Audit: Audit the access of global system objects"*
  **Disabled** (the default), or Kernel Object auditing gets extremely noisy.

### Policy Change

| Subcategory | Setting |
|---|---|
| Audit Policy Change | Success only |
| Authentication Policy Change | Success only |
| Authorization Policy Change | Success only |
| Filtering Platform Policy Change | Success only |
| MPSSVC Rule-Level Policy Change | Success + Failure |
| Other Policy Change Events | Success + Failure |

### Privilege Use

| Subcategory | Setting |
|---|---|
| Sensitive Privilege Use | Success + Failure |

**No Auditing:** Non Sensitive Privilege Use, Other Privilege Use Events

### System

| Subcategory | Setting |
|---|---|
| Security State Change | Success only |
| Security System Extension | Success only |
| System Integrity | Success + Failure |
| Other System Events | Success + Failure |

**No Auditing:** IPsec Driver

## Step 4 — Capture command lines in process events

Makes every 4688 event include the full command line — one of the highest-value settings
in the whole baseline.

**Where:** `Administrative Templates → System → Audit Process Creation`

**Set:** *"Include command line in process creation events"* → **Enabled**

Command line:
`reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f`

> Command lines sometimes contain secrets admins typed (passwords as arguments). Treat
> the Security log as sensitive data.

## Step 5 — Turn on PowerShell logging

**Where:** `Administrative Templates → Windows Components → Windows PowerShell`

1. **Turn on Module Logging** → Enabled → click **Show...** next to *Module Names* → add
   one entry: `*`
2. **Turn on PowerShell Script Block Logging** → Enabled. Leave *"Log script block
   invocation start/stop events"* unchecked — it roughly doubles the volume for little
   value.

Command line (on 64-bit Windows, repeat with `SOFTWARE\Wow6432Node\Policies\...`):

```bat
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

## Step 6 — Enable the Task Scheduler and CAPI2 logs

**Where:** Event Viewer → *Applications and Services Logs → Microsoft → Windows*

| Log | Action | Worth watching |
|---|---|---|
| TaskScheduler → Operational | Right-click → **Enable Log** | 129 task created, 141 task deleted |
| CAPI2 → Operational | Right-click → **Enable Log**, then Properties → max size **102400** KB | 81 failed trust validation |

Command line:

```bat
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true /ms:104857600
```

## Step 7 — (Optional) DNS server debug logging

Only on machines running the Windows DNS Server role.

**Where:** DNS Manager (`dnsmgmt.msc`) → right-click the server → **Properties** →
**Debug Logging** tab.

Tick **"Log packets for debugging"**, then:

- Packet direction: **Outgoing** + **Incoming**
- Transport protocol: **UDP** + **TCP**
- Packet contents: **Queries/Transfers** + **Updates**
- Packet type: **Request** + **Response**
- File path: `%SystemRoot%\System32\Dns\Dns.log`, with a sane max size

DHCP servers need nothing — audit logging (`%windir%\System32\Dhcp`, event 10 = new
lease) is already on by default; just collect it.

## Step 8 — Verify

```bat
gpupdate /force                 :: domain-joined, after GPO edits
auditpol /get /category:*       :: should match the step 3 tables exactly
wevtutil gl Security            :: maxSize and retention
```

Then spot-check in Event Viewer:

- A new 4688 event shows a populated **Process Command Line** field (step 4 works)
- `Microsoft-Windows-PowerShell/Operational` shows 4103/4104 events after running any
  PowerShell (step 5 works)

---

**If Huntress is deployed:** the agent applies step 3's audit policy automatically on
SIEM-enabled endpoints, and raises an escalation when a GPO conflicts with it — so keep
your GPO matched to these tables. Steps 1, 4 and 5 (sizes/retention, command line in
4688, PowerShell logging) are **never** set by the agent; they always need this manual or
GPO configuration.
