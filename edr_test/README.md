# EDR Test - RedSun Refactored PoC

A Windows C++ proof-of-concept for testing Endpoint Detection and Response (EDR) and antivirus detection capabilities. Demonstrates a sequence of techniques commonly flagged by security tooling.

## What It Does

1. **Privilege check** — Queries the current token to see if the process is running as `SYSTEM`.
2. **Workspace setup** — Creates a temporary working directory (`%TEMP%\ExploitDir`).
3. **EICAR file drop** — Writes the standard EICAR antivirus test string to a file named `TieringEngineService.exe` to trigger AV scan events.
4. **Cloud Files placeholder** — Registers a Windows Cloud Files sync root and creates a placeholder file, exercising kernel-mode `CfApi` callbacks.
5. **Junction helper** — Includes a `CreateJunction` utility that can redirect a directory to an arbitrary NT path via `FSCTL_SET_REPARSE_POINT` (not invoked in `main` by default).
6. **Cleanup** — Deletes the test file and workspace directory before exit.

The intent is to generate a realistic stream of suspicious-but-detectable events so EDR logs can be reviewed for coverage gaps.

## Build Requirements

| Requirement | Details |
|---|---|
| Platform | Windows 10/11 (x64) |
| Compiler | MSVC (Visual Studio 2019+) |
| SDK | Windows SDK with `cfapi.h` / `CldApi.lib` |
| Libs linked | `synchronization.lib`, `ntdll.lib`, `CldApi.lib` |

## Compiling

**Option A — Visual Studio Developer Command Prompt (recommended)**

1. Install [Visual Studio](https://visualstudio.microsoft.com/) with the **Desktop development with C++** workload. This includes the compiler (`cl.exe`) and the Windows SDK.
2. Open the **Start Menu** and search for *"Developer Command Prompt for VS"* — launch it.
3. Navigate to the folder containing `edr_test_cleaned.cpp`:
   ```
   cd path\to\edr_test
   ```
4. Compile:
   ```
   cl /EHsc /W4 edr_test_cleaned.cpp /link synchronization.lib ntdll.lib CldApi.lib
   ```
5. This produces `edr_test_cleaned.exe` in the same directory.

**Option B — Visual Studio IDE**

1. Open Visual Studio and choose **Create a new project → Console App (C++)**.
2. Replace the generated `.cpp` with `edr_test_cleaned.cpp`.
3. Go to **Project → Properties → Linker → Input → Additional Dependencies** and add:
   ```
   synchronization.lib;ntdll.lib;CldApi.lib
   ```
4. Press **Ctrl+B** to build. The `.exe` will appear under `x64\Debug\` or `x64\Release\`.

## Usage

Run from an elevated (Administrator) prompt. The binary will print status lines to stdout and clean up after itself.

```
edr_test_cleaned.exe
```

Expected output:

```
[*] Starting EDR Test - RedSun Refactored PoC...
[*] Not running as SYSTEM.
[+] Workspace created: C:\Users\...\AppData\Local\Temp\ExploitDir
[+] EICAR test file created: ...\ExploitDir\TieringEngineService.exe
[*] Bait file created. Waiting for system interaction...
[+] Cloud placeholder setup successful.
[!] Redirection active. EDR should detect suspicious activity.
[*] Test complete. Check EDR logs for detection events.
```

## Techniques Demonstrated

| Technique | API / Mechanism |
|---|---|
| Token privilege inspection | `OpenProcessToken`, `GetTokenInformation`, `IsWellKnownSid` |
| EICAR AV trigger | Standard test string written via `CreateFile` / `WriteFile` |
| Cloud Files sync root | `CfRegisterSyncRoot`, `CfConnectSyncRoot`, `CfCreatePlaceholders` |
| Directory junction (util) | `DeviceIoControl(FSCTL_SET_REPARSE_POINT)` with `IO_REPARSE_TAG_MOUNT_POINT` |
| Oplock-based race (stub) | Described in comments; not fully implemented in this cleaned version |

## Intended Use

This tool is for **authorized security testing only** — red team exercises, EDR validation in lab environments, or CTF/research work where you own or have explicit permission to test the target system. Do not run it on systems you do not control.
