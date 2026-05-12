# PhantomRPC — Privilege Escalation POC

**For authorized security research, internal demonstrations, and mitigation
development only.**

---

## Background

PhantomRPC is a Windows RPC architectural weakness discovered by **Haidar Kabibo**
at Kaspersky Security Services, disclosed at **Black Hat Asia 2026** (April 24, 2026).

The official Kaspersky research repository (MIT licensed) is at:
**https://github.com/klsecservices/PhantomRPC**

The full technical write-up is at:
**https://securelist.com/phantomrpc-rpc-vulnerability/119428/**

Microsoft triaged the report (submitted 2025-09-19) as **moderate severity**,
noting that exploitation requires `SeImpersonatePrivilege` — a right held by
default by `NETWORK SERVICE` and `LOCAL SERVICE` accounts. No CVE was assigned;
no patch is planned.

---

## How PhantomRPC Works

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. Target service (e.g. TermService) is stopped/disabled.          │
│     Its ncalrpc endpoint ("TermSrvApi") is now vacant.              │
│                                                                     │
│  2. Attacker (SeImpersonatePrivilege) registers the same endpoint.  │
│     Windows RPC runtime does NOT authenticate the registrant.       │
│                                                                     │
│  3. A SYSTEM-level caller (e.g. Group Policy Client during          │
│     gpupdate /force) connects to the endpoint, expecting the        │
│     real service.                                                   │
│                                                                     │
│  4. Fake server calls RpcImpersonateClient() → obtains SYSTEM token.│
│                                                                     │
│  5. Token is duplicated → CreateProcessAsUserW() → SYSTEM cmd.exe. │
└─────────────────────────────────────────────────────────────────────┘
```

### Key APIs

| API | Role |
|-----|------|
| `RpcServerUseProtseqEpW` | Registers the fake endpoint (ncalrpc or named pipe) |
| `RpcServerRegisterIf2` | Registers the spoofed interface UUID |
| `RpcImpersonateClient` | Assumes the calling client's security context |
| `OpenThreadToken` | Captures the resulting SYSTEM impersonation token |
| `DuplicateTokenEx` | Converts impersonation → primary token |
| `CreateProcessAsUserW` | Spawns cmd.exe in the SYSTEM security context |

### Root Cause

`rpcrt4.dll` does not verify that the process registering a well-known ncalrpc
endpoint is the expected service. The check that *is* present (whether the
caller holds `SeImpersonatePrivilege`) is insufficient because that privilege
is widely distributed to service accounts by design.

---

## Repository Structure

```
phantomrpc-poc/
├── POCs/
│   ├── TERM/                  ← gpupdate coercion (TermSrvApi, UUID bde95fdf-…)
│   │   ├── ExampleInterface.idl
│   │   ├── server.c
│   │   └── build.bat
│   └── DHCP/                  ← DHCP Client coercion (dhcpcsvc6, UUID 3c4728c5-…)
│       ├── ExampleInterface.idl
│       ├── server.c
│       └── build.bat
└── toolset/
    ├── check_mitigations.ps1  ← audit exposed endpoints + recommendations
    └── find_vulnerable_rpcs.ps1 ← enumerate vacant ncalrpc endpoints
```

---

## Attack Scenarios Included

### 1. TERM — gpupdate Coercion (highest-impact scenario)

- **Interface UUID**: `bde95fdf-eee0-45de-9e12-e5a61cd0d4fe` (TermSrvApi v1.0)
- **Endpoint**: `ncalrpc:TermSrvApi`
- **Trigger procedure**: `Proc8`
- **SYSTEM caller**: `gpsvc` (Group Policy Client service)

**Steps**:
```cmd
:: 1. Compile (VS Developer Command Prompt)
cd POCs\TERM
build.bat

:: 2. Stop TermService (Remote Desktop Services)
sc stop TermService

:: 3. Run fake server (needs SeImpersonatePrivilege)
server.exe

:: 4. Trigger from any session
gpupdate /force

:: 5. SYSTEM cmd.exe appears on active console
```

**Log file**: `C:\Windows\Temp\PhantomRPC_TERM.log`

---

### 2. DHCP — DHCP Client Coercion

- **Interface UUID**: `3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6` (v1.0)
- **Endpoint**: `ncalrpc:dhcpcsvc6`
- **Trigger procedure**: `Proc11`
- **SYSTEM caller**: `svchost.exe` hosting the DHCP Client

**Steps**:
```cmd
:: 1. Compile
cd POCs\DHCP
build.bat

:: 2. Stop Dhcp service
sc stop Dhcp

:: 3. Run fake server
server.exe

:: 4. Trigger a DHCP operation (e.g. from an elevated prompt)
ipconfig /renew
```

**Log file**: `C:\Windows\Temp\PhantomRPC_DHCP.log`

---

## Build Requirements

- Windows 10/11 or Windows Server 2016+
- Visual Studio Build Tools (any version with `cl.exe` and `midl.exe`)
- Run `build.bat` from a **VS Developer Command Prompt** so the tools are on PATH

```cmd
"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
```

---

## Mitigation Tooling

### Audit Exposed Endpoints

```powershell
# Enumerate all vacant ncalrpc endpoints on the local machine
.\toolset\find_vulnerable_rpcs.ps1
```

### Full Mitigation Audit

```powershell
# Check service states, SeImpersonatePrivilege holders, and get recommendations
.\toolset\check_mitigations.ps1
```

---

## Mitigations

Microsoft's position is that this is by-design behaviour. The following
mitigations can be applied internally:

| # | Mitigation | Notes |
|---|-----------|-------|
| 1 | **Keep vulnerable services running** | TermService, Dhcp, W32Time must not be stopped except for maintenance windows |
| 2 | **RPC endpoint DACLs** | Restrict who can register well-known endpoints via DCOM Machine Access Restrictions (Group Policy) |
| 3 | **Restrict SeImpersonatePrivilege** | Audit `User Rights Assignment → Impersonate a client after authentication`; remove any non-essential accounts |
| 4 | **ETW monitoring** | Monitor provider `{6ad52b32-d609-4be9-ae07-ce8dae937e39}` for unexpected `RpcServerRegisterIf2` calls |
| 5 | **Protected Users group** | Add sensitive service accounts to Protected Users to prevent certain token impersonation paths |
| 6 | **Privileged Access Workstations (PAW)** | Isolate high-value management traffic to prevent lateral movement after token capture |

### Detection (SIEM / EDR)

Look for these patterns:

```
1. Process not in {TermService, svchost, lsass, …} calls
   RpcServerUseProtseqEpW with endpoint = "TermSrvApi" or "dhcpcsvc6"

2. Low-privileged process (NETWORK SERVICE / LOCAL SERVICE) calls
   RpcImpersonateClient immediately followed by CreateProcessAsUserW

3. Service state: TermService or Dhcp transitions to Stopped, and
   within 60 seconds a non-svchost process calls RpcServerListen
```

---

## References

- Kaspersky official POC (MIT): https://github.com/klsecservices/PhantomRPC
- Securelist deep-dive: https://securelist.com/phantomrpc-rpc-vulnerability/119428/
- Kaspersky press release: https://www.kaspersky.com/about/press-releases/kaspersky-has-discovered-phantomrpc-a-windows-rpc-vulnerability-that-allows-attackers-to-create-a-fake-server-and-escalate-privileges
- Dark Reading coverage: https://www.darkreading.com/vulnerabilities-threats/unpatched-phantomrpc-flaw-windows-privilege-escalation
- SecurityWeek: https://www.securityweek.com/no-patch-for-new-phantomrpc-privilege-escalation-technique-in-windows/

---

## License

MIT — same as the upstream Kaspersky research repository.

This POC is derived from `klsecservices/PhantomRPC` with additional
commentary, a second scenario (DHCP), and a mitigation toolkit.
