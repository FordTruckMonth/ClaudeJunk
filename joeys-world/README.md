# Joey's World — Redsun Vortex

Oplock-based TOCTOU junction pivot for internal red team / EDR hardening tests.

## Prerequisites

- Windows 10/11 (x64)
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) with the **Desktop development with C++** workload, **or** a full Visual Studio install

## Compile (MSVC)

Open a **Developer Command Prompt for VS** and run:

```cmd
cl /EHsc /O2 /W3 main.cpp /Fe:redsun_vortex.exe
```

The output binary will be `redsun_vortex.exe` in the same directory.

## Compile (MinGW / g++)

If you have MinGW-w64 installed:

```cmd
g++ -O2 -std=c++17 main.cpp -o redsun_vortex.exe -lkernel32
```

## Run

```cmd
redsun_vortex.exe
```

The binary must run on the target machine with a vulnerable SYSTEM-level service present to trigger the oplock break. `C:\Temp\Redsun_Vortex` is created automatically.

## Cleanup

Remove the working directory after testing:

```cmd
rmdir /S /Q C:\Temp\Redsun_Vortex
```
