# Windows Event Log Baseline — Manual Configuration Guide

Step-by-step instructions to apply the same baseline as `Set-WindowsEventLogBaseline.ps1`
by hand, without running the script. Sources and merge logic are documented in
[README_WindowsEventLogBaseline.md](README_WindowsEventLogBaseline.md) — this guide only
covers *how* to click/type it in.

Two ways to do everything below:

- **Domain (preferred):** Group Policy Management (`gpmc.msc`) — create a GPO (e.g.
  `SEC - Windows Logging Baseline`), link it to the OUs containing your
  workstations/servers, and edit the paths shown. Settings apply on the next
  `gpupdate /force` / refresh cycle. **GPO always overrides local settings.**
- **Standalone / non-domain:** Local Group Policy Editor (`gpedit.msc`) or Local Security
  Policy (`secpol.msc`) for the policy pieces, Event Viewer (`eventvwr.msc`) for log
  sizes/channels. Home editions have no `gpedit.msc` — use the registry commands noted
  inline instead.

All GPO paths below start at **Computer Configuration → Policies →** (in `gpedit.msc`
there is no "Policies" node — start at Computer Configuration directly).

---

## 1. Log sizes and retention

**GPO:** `Windows Settings → Security Settings → Event Log`

| Policy | Value |
|---|---|
| Maximum security log size | `512000` KB *(1024000 if you enable file/registry/WFP success auditing)* |
| Retention method for security log | Overwrite events as needed |
| Maximum application log size | `256000` KB |
| Retention method for application log | Overwrite events as needed |
| Maximum system log size | `256000` KB |
| Retention method for system log | Overwrite events as needed |

That GPO section only covers Application/Security/System. For the PowerShell logs, use
Event Viewer (below) or, in newer templates: `Administrative Templates → Windows
Components → Event Log Service → <log> → Specify the maximum log file size (KB)`.

**Event Viewer (standalone or for channels GPO doesn't cover):** right-click the log →
**Properties** → set *Maximum log size (KB)* → select *Overwrite events as needed* → OK.

| Log (Event Viewer location) | Size KB |
|---|---|
| Windows Logs → Security | 512000 |
| Windows Logs → Application | 256000 |
| Windows Logs → System | 256000 |
| Applications and Services Logs → Windows PowerShell | 256000 |
| Applications and Services Logs → Microsoft → Windows → PowerShell → Operational | 256000 |

Command-line equivalent (elevated): `wevtutil sl Security /ms:524288000 /rt:false`
(size is in **bytes** here; 524288000 = 512000 KB).

## 2. Force use of Advanced Audit Policy

**GPO / secpol.msc:** `Windows Settings → Security Settings → Local Policies → Security
Options` → **"Audit: Force audit policy subcategory settings (Windows Vista or later) to
override audit policy category settings"** → **Enabled**.

Registry equivalent:
`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f`

Do this first — without it, legacy category auditing can silently override everything in
step 3.

## 3. Advanced Audit Policy subcategories

**GPO:** `Windows Settings → Security Settings → Advanced Audit Policy Configuration →
Audit Policies`
**Local:** `secpol.msc → Advanced Audit Policy Configuration → System Audit Policies`

For **every** row below: double-click the subcategory → tick **"Configure the following
audit events"** → tick Success/Failure as shown → OK.

> ⚠ Per the Malware Archaeology sheet: tick the *Configure* box **even on the
> "No Auditing" rows** (with Success/Failure left unchecked). A configured-but-empty
> setting enforces "no auditing"; an unconfigured one is ignored and whatever was there
> before stays in effect. In a GPO, leaving rows blank that you meant to disable breaks
> the intent of the baseline.

### Account Logon

| Subcategory | Success | Failure |
|---|:-:|:-:|
| Audit Credential Validation | ✔ | ✔ |
| Audit Kerberos Authentication Service | ✔ | ✔ |
| Audit Kerberos Service Ticket Operations | ✔ | ✔ |
| Audit Other Account Logon Events | — | — |

### Account Management

| Subcategory | Success | Failure |
|---|:-:|:-:|
| Audit Application Group Management | — | — |
| Audit Computer Account Management | ✔ | ✔ |
| Audit Distribution Group Management | ✔ | ✔ |
| Audit Other Account Management Events | ✔ | — |
| Audit Security Group Management | ✔ | ✔ |
| Audit User Account Management | ✔ | ✔ |

### Detailed Tracking

| Subcategory | Success | Failure |
|---|:-:|:-:|
| Audit DPAPI Activity | — | — |
| Audit PNP Activity | ✔ | — |
| **Audit Process Creation** | ✔ | ✔ |
| Audit Process Termination ¹ | — | — |
| Audit RPC Events | — | — |
| Audit Token Right Adjusted Events | — | — |

¹ Optional: tick Success if you want 4689 process-exit correlation without relying on EDR
telemetry (script switch `-EnableProcessTermination`).

### DS Access (matters on Domain Controllers; harmless elsewhere)

| Subcategory | Success | Failure |
|---|:-:|:-:|
| Audit Detailed Directory Service Replication | — | — |
| Audit Directory Service Access | ✔ | ✔ |
| Audit Directory Service Changes | ✔ | — |
| Audit Directory Service Replication | — | — |

### Logon/Logoff

| Subcategory | Success | Failure |
|---|:-:|:-:|
| Audit Account Lockout | — | ✔ |
| Audit User / Device Claims | — | — |
| Audit Group Membership | — | — |
| Audit IPsec Extended Mode | — | — |
| Audit IPsec Main Mode | — | — |
| Audit IPsec Quick Mode | — | — |
| Audit Logoff | ✔ | — |
| Audit Logon | ✔ | ✔ |
| Audit Network Policy Server | ✔ | ✔ |
| Audit Other Logon/Logoff Events | ✔ | ✔ |
| Audit Special Logon | ✔ | — |

### Object Access

| Subcategory | Success | Failure |
|---|:-:|:-:|
| Audit Application Generated | — | — |
| Audit Central Access Policy Staging | — | — |
| Audit Certification Services ² | — | — |
| Audit Detailed File Share | ✔ | ✔ |
| Audit File Share | ✔ | ✔ |
| **Audit File System** ³ | ✔ | — |
| Audit Filtering Platform Connection ⁴ | — | ✔ |
| Audit Filtering Platform Packet Drop | — | — |
| Audit Handle Manipulation | — | — |
| Audit Kernel Object ⁵ | ✔ | ✔ |
| Audit Other Object Access Events | ✔ | ✔ |
| **Audit Registry** ³ | ✔ | — |
| Audit Removable Storage | ✔ | ✔ |
| Audit SAM | — | — |

² On AD CS servers (Certificate Services installed): Success ✔ Failure ✔.
³ Emits nothing until you add SACLs to the folders/keys you care about (see the Malware
Archaeology *Windows File Auditing* and *Windows Registry Auditing* cheat sheets), so
enabling it is zero-noise until then.
⁴ Optional: add Success per Malware Archaeology to log every permitted connection (event
5156). Very noisy — ~9–10k events/hour/system — budget log size accordingly.
⁵ Keep Security Options → *"Audit: Audit the access of global system objects"* **Disabled**
(the default) or this becomes extremely noisy.

### Policy Change

| Subcategory | Success | Failure |
|---|:-:|:-:|
| Audit Audit Policy Change | ✔ | — |
| Audit Authentication Policy Change | ✔ | — |
| Audit Authorization Policy Change | ✔ | — |
| Audit Filtering Platform Policy Change | ✔ | — |
| Audit MPSSVC Rule-Level Policy Change | ✔ | ✔ |
| Audit Other Policy Change Events | ✔ | ✔ |

### Privilege Use

| Subcategory | Success | Failure |
|---|:-:|:-:|
| Audit Non Sensitive Privilege Use | — | — |
| Audit Other Privilege Use Events | — | — |
| Audit Sensitive Privilege Use | ✔ | ✔ |

### System

| Subcategory | Success | Failure |
|---|:-:|:-:|
| Audit IPsec Driver | — | — |
| Audit Other System Events | ✔ | ✔ |
| Audit Security State Change | ✔ | — |
| Audit Security System Extension | ✔ | — |
| Audit System Integrity | ✔ | ✔ |

## 4. Command line in process creation events (4688)

**GPO/gpedit:** `Administrative Templates → System → Audit Process Creation` →
**"Include command line in process creation events"** → **Enabled**.

Registry equivalent (Home editions / one-off):
`reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f`

Note: command lines can contain secrets typed by admins (e.g. passwords passed as
arguments) — treat the Security log as sensitive.

## 5. PowerShell logging

**GPO/gpedit:** `Administrative Templates → Windows Components → Windows PowerShell`

1. **Turn on Module Logging** → Enabled → click **Show...** next to Module Names → add a
   single entry: `*`
2. **Turn on PowerShell Script Block Logging** → Enabled. Leave *"Log script block
   invocation start / stop events"* unchecked (it roughly doubles volume for little value).

Registry equivalent (as documented by Huntress; on 64-bit systems set the same values
under both `HKLM\SOFTWARE\Policies\...` and `HKLM\SOFTWARE\Wow6432Node\Policies\...`):

```bat
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

## 6. Enable additional logs

**Event Viewer → Applications and Services Logs → Microsoft → Windows →**

- **TaskScheduler → Operational** → right-click → **Enable Log**
  (watch event 129 = task created, 141 = task deleted)
- **CAPI2 → Operational** → right-click → **Enable Log**, then Properties → Maximum log
  size = `102400` KB (watch event 81 = failed trust validation)

Command-line equivalent:

```bat
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true /ms:104857600
```

## 7. DNS debug logging (Windows DNS Server role only — optional)

DNS Manager (`dnsmgmt.msc`) → right-click the server → **Properties** → **Debug Logging**
tab → tick **"Log packets for debugging"**, then:

- Packet direction: **Outgoing** and **Incoming**
- Transport protocol: **UDP** and **TCP**
- Packet contents: **Queries/Transfers** and **Updates**
- Packet type: **Request** and **Response**
- File path: `%SystemRoot%\System32\Dns\Dns.log`, with a sane max size

DHCP server audit logging (`%windir%\System32\Dhcp`, event 10 = new lease) is on by
default on Windows DHCP servers — nothing to enable, just collect it.

## 8. Verify

```bat
gpupdate /force                 (domain-joined, after GPO edits)
auditpol /get /category:*       (every row should match the tables above)
wevtutil gl Security            (maxSize + retention)
```

In Event Viewer, confirm 4688 events now show a populated *Process Command Line* field,
and `Microsoft-Windows-PowerShell/Operational` shows 4103/4104 events after running any
PowerShell.

If Huntress is deployed: the agent applies the audit policy of step 3 automatically on
SIEM-enabled endpoints and will raise an escalation if a GPO conflicts — keep the GPO
matched to these tables. Steps 1, 4 and 5 (sizes/retention, 4688 command line,
PowerShell logging) are **not** set by the agent and always need this manual/GPO
configuration.
