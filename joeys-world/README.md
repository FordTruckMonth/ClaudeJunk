# Joey's World — Redsun Vortex

Oplock-based TOCTOU junction pivot for internal red team / EDR hardening tests.

## Prerequisites

- Windows 10/11 (x64)
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) with the **Desktop development with C++** workload, **or** a full Visual Studio install

## Compile (PowerShell)

Locate and invoke the MSVC compiler directly from PowerShell — no need to open a Developer Command Prompt:

```powershell
# Find cl.exe from whichever VS install is present
$cl = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio" -Recurse -Filter cl.exe -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -match "Hostx64\\x64" } |
      Select-Object -First 1 -ExpandProperty FullName

# Load the VS environment, then compile
$vcvars = Join-Path (Split-Path $cl -Parent | Split-Path -Parent | Split-Path -Parent | Split-Path -Parent | Split-Path -Parent) "vcvarsall.bat"
cmd /c "`"$vcvars`" x64 && cl /EHsc /O2 /W3 main.cpp /Fe:redsun_vortex.exe"
```

Or if `cl.exe` is already on your PATH:

```powershell
cl /EHsc /O2 /W3 main.cpp /Fe:redsun_vortex.exe
```

## Compile (MSVC — Developer Command Prompt)

Open a **Developer Command Prompt for VS** and run:

```cmd
cl /EHsc /O2 /W3 main.cpp /Fe:redsun_vortex.exe
```

## Compile (MinGW / g++)

If you have MinGW-w64 installed:

```powershell
g++ -O2 -std=c++17 main.cpp -o redsun_vortex.exe -lkernel32
```

## Run

```powershell
.\redsun_vortex.exe
```

The binary must run on the target machine with a vulnerable SYSTEM-level service present to trigger the oplock break. `C:\Temp\Redsun_Vortex` is created automatically.

## Cleanup

Remove the working directory after testing:

```powershell
Remove-Item -Recurse -Force C:\Temp\Redsun_Vortex
```
