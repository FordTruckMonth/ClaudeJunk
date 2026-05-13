#!/usr/bin/env python3
"""
ClaudeJunk Super Suite — unified curses TUI for all ClaudeJunk programs.

Included programs
  find-blaze.ps1       Blaze browser forensic detection tool
  change-password.ps1  Windows password change reference
  edr_test/            Windows C++ EDR/AV test suite (info + build)
  YellowKey/           BitLocker bypass research PoC (info)
  greenplasma-poc/     CTFMON elevation-of-privilege research (info)
  phantomrpc-poc/      RPC privilege escalation PoC (info)
  joeys-world/         VORTEX oplock race-condition PoC (info)
  hello-world.ps1      Hello World

Usage
  python3 super_suite.py
"""

import curses

# ─── Feature content functions ─────────────────────────────────────────────────

def _static(text):
    """Wrap a multi-line string as a no-arg callable returning a list of lines."""
    stripped = text.strip()
    return lambda: [ln.rstrip() for ln in stripped.split("\n")]


_content_blaze = _static("""
BLAZE BROWSER DETECTOR  —  find-blaze.ps1
==========================================

Forensic detection tool. Read-only: reports matches,
does not modify or delete anything.

WHAT IT SCANS
  1. Scheduled Tasks         name, path, and action strings
  2. Registry Uninstall      HKLM + HKCU uninstall keys
  3. Registry Persistence    Run/RunOnce + browser registration keys
  4. Windows Services        name, display name, executable path
  5. Running Processes       matched by name or executable path
  6. Installed Files/Folders depth-limited filesystem search
  7. Shortcuts (.lnk)        Desktop and Start Menu

PARAMETERS
  -Pattern  <string>   Word-boundary regex (default: 'blaze')
                       Matches: Blaze, Blazer, BlazerBrowser
                       Skips:   Trailblazer
  -Depth    <int>      Filesystem recursion depth (default: 3)
  -ExportCsv <path>    Optional CSV export path

USAGE  (Windows PowerShell)
  .\\find-blaze.ps1
  .\\find-blaze.ps1 -Pattern 'blazer' -Depth 5
  .\\find-blaze.ps1 -ExportCsv C:\\Reports\\blaze_findings.csv

OUTPUT
  • Formatted tables per section in the console
  • Optional CSV export of all findings
  • Summary table showing hit count per section

NOTE
  Requires Windows. The script uses Get-ScheduledTask, Get-CimInstance,
  Get-Process, and registry provider cmdlets — all built into PowerShell.
""")

_content_password = _static("""
PASSWORD CHANGER REFERENCE  —  change-password.ps1
===================================================

Common PowerShell commands for changing Windows passwords.
Most operations require running PowerShell as Administrator.

METHOD 1: Change a LOCAL user's password
  Interactive:
    $pw = Read-Host -AsSecureString "Enter new password"
    Set-LocalUser -Name "username" -Password $pw

  Non-interactive (avoid in source control):
    $pw = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
    Set-LocalUser -Name "username" -Password $pw

METHOD 2: Change the CURRENT user's password
    net user $env:USERNAME *
    (PowerShell prompts twice for the new password.)

METHOD 3: Change a DOMAIN user's password  (RSAT required)
    $pw = Read-Host -AsSecureString "Enter new password"
    Set-ADAccountPassword -Identity "username" -NewPassword $pw -Reset

  Force change at next logon:
    Set-ADUser -Identity "username" -ChangePasswordAtLogon $true

METHOD 4: Change YOUR OWN domain password  (no admin needed)
    $old = Read-Host -AsSecureString "Current password"
    $new = Read-Host -AsSecureString "New password"
    Set-ADAccountPassword -Identity $env:USERNAME `
        -OldPassword $old -NewPassword $new

INTERACTIVE HELPER
    .\\change-password.ps1
    .\\change-password.ps1 -UserName alice
    Prompts for username and new password, updates local account.
    Requires Administrator. Confirms passwords match before applying.
""")

_content_edr = _static("""
EDR TEST SUITE  —  edr_test/
==============================

Windows C++ proof-of-concept for validating EDR and antivirus
detection capabilities. Runs real attack techniques against a
live Windows system to confirm sensors fire as expected.

TECHNIQUES DEMONSTRATED
  • Token privilege inspection
      OpenProcessToken + GetTokenInformation
      Confirms the process is running as SYSTEM

  • EICAR test file creation
      Drops the standard AV test string to trigger AV detection
      Path: %TEMP%\\ExploitDir\\eicar.com

  • Cloud Files API integration
      CfRegisterSyncRoot + CfCreatePlaceholders
      Exercises the Cloud Files filter driver (cldflt.sys) hooks

  • Directory junction creation
      FSCTL_SET_REPARSE_POINT via DeviceIoControl
      IO_REPARSE_TAG_MOUNT_POINT redirect to arbitrary NT path

  • Automatic cleanup on exit
      Deletes all artifacts from %TEMP%\\ExploitDir\\

REQUIREMENTS
  • Windows 10 / 11 x64
  • Run as SYSTEM or Administrator
  • MSVC / Visual Studio 2019+
  • Windows SDK (cfapi.h required)
  • Link: synchronization.lib  ntdll.lib  CldApi.lib

BUILD  (Developer Command Prompt)
  cd edr_test
  cl /EHsc /W3 edr_test_cleaned.cpp ^
      synchronization.lib ntdll.lib CldApi.lib ^
      /Fe:edr_test.exe

RUN
  edr_test.exe
  (Running as SYSTEM gives the fullest sensor coverage.)
""")

_content_yellowkey = _static("""
YELLOWKEY  —  BitLocker Bypass Research
=========================================

Publicly disclosed exploit for Windows 11 / Server 2022 / 2025.
Bypasses BitLocker via crafted KTM filesystem transaction logs
placed where Windows Recovery Environment (WinRE) can load them.

Coordinated disclosure with Microsoft MORSE, MSTIC, and GHOST teams.

AFFECTED SYSTEMS
  • Windows 11  (all editions)
  • Windows Server 2022
  • Windows Server 2025
  ✗ Windows 10  (not affected)

ROOT CAUSE
  The Kernel Transaction Manager (KTM) / Common Log File System (CLFS)
  component behaves differently in WinRE vs. normal Windows. The
  component appears to exist in a modified form only in WinRE —
  suggesting an intentional design difference that creates an
  exploitable state when crafted transaction logs are present.

ATTACK FLOW
  1. Place the FsTx artifact on a USB drive (FAT32/exFAT/NTFS)
     or directly on the target's EFI partition
  2. Boot the target into WinRE  (Shift + Restart → Troubleshoot)
  3. Hold Ctrl during the WinRE restart to trigger exploitation
  4. WinRE spawns an unrestricted shell with full read-write access
     to the BitLocker-protected volume
  5. No recovery key required

KEY ARTIFACTS  (placed in  <drive>:\\System Volume Information\\FsTx\\<GUID>\\)
  FsTxKtmLog.blf         KTM log base file
  FsTxKtmLogContainer*   KTM log container files
  FsTxLog.blf            FsTx log base file
  FsTxLogContainer*      FsTx log container files
  FsTxTemp\\<marker>      Marker file in temp subdirectory

DEPLOYMENT SCRIPT
  deploy.ps1  — copies artifacts to a chosen drive or USB device
  Parameters: target drive letter, optional USB-eject flag
""")

_content_greenplasma = _static("""
GREENPLASMA  —  CTFMON Elevation-of-Privilege Research
========================================================

Windows privilege escalation targeting a race condition in the
CTF (Windows Text Services Framework) monitor process (ctfmon.exe).

TECHNIQUE
  Object Manager symlink planting + named section race condition

ATTACK FLOW
  1. Plant an Object Manager symlink at:
         CTF.AsmListCache.FMPWinlogon{session-id}
     redirecting it to an attacker-controlled NT object path

  2. Trigger a UAC elevation event via ShellExecuteEx runas.
     This causes CTFMON to create the raced section object.

  3. Spin at THREAD_PRIORITY_TIME_CRITICAL with YieldProcessor()
     until the section is created through the planted symlink.

  4. Open the section with a writable mapping before CTFMON
     opens it with its expected permissions.

  5. Walk processes via CreateToolhelp32Snapshot.
     Steal a SYSTEM token using SeDebugPrivilege.

  6. CreateProcessWithTokenW  →  SYSTEM cmd.exe is spawned.

BONUS
  An optional registry symlink prevents session locking (policy mod).

FILES
  GreenPlasma.cpp   Production exploit targeting CTFMON
  JoeysCode.cpp     Generic section-race research harness
                    (configurable target section name and flag offset)

REQUIREMENTS
  • Windows 10 / 11  (non-Session 0 desktop session only)
  • Local Administrator account
  • SeDebugPrivilege + SeImpersonatePrivilege
  • MSVC compiler + CMake 3.16+

BUILD
  cd greenplasma-poc
  cmake -B build
  cmake --build build
""")

_content_phantomrpc = _static("""
PHANTOMRPC  —  RPC Privilege Escalation
=========================================

Escalation from SeImpersonatePrivilege to SYSTEM by registering
a fake ncalrpc endpoint. Discovered by Haidar Kabibo (Kaspersky).
Disclosed at Black Hat Asia 2026.

ROOT CAUSE
  rpcrt4.dll does not verify which process registers a well-known
  ncalrpc endpoint. It only checks that the caller holds
  SeImpersonatePrivilege — which is widely distributed to service
  accounts: IIS_IUSRS, LOCAL SERVICE, network service accounts, etc.

ATTACK FLOW
  1. Stop or disable the service that owns the target endpoint
  2. Call RpcServerUseProtseqEpW + RpcServerRegisterIf2 to register
     the same endpoint name with a spoofed interface UUID
  3. Coerce or wait for a SYSTEM process to connect
  4. Call RpcImpersonateClient()  →  obtain the SYSTEM token
  5. DuplicateTokenEx  →  convert impersonation token to primary
  6. CreateProcessAsUserW  →  SYSTEM cmd.exe

SCENARIO 1: TERM  (highest impact — gpupdate coercion)
  UUID:      bde95fdf-eee0-45de-9e12-e5a61cd0d4fe  (TermSrvApi v1.0)
  Endpoint:  ncalrpc:TermSrvApi
  Trigger:   gpupdate /force  (gpsvc runs as SYSTEM and connects)
  Log file:  C:\\Windows\\Temp\\PhantomRPC_TERM.log

SCENARIO 2: DHCP Client coercion
  UUID:      3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6  (v1.0)
  Endpoint:  ncalrpc:dhcpcsvc6
  Trigger:   ipconfig /renew
  Log file:  C:\\Windows\\Temp\\PhantomRPC_DHCP.log

MICROSOFT TRIAGE
  Moderate severity. No patch planned.
  Rationale: SeImpersonatePrivilege is already a privileged right.

MITIGATIONS
  • Keep vulnerable services running (no vacant endpoints)
  • Apply DCOM Machine Access Restrictions to RPC endpoints
  • Restrict who holds SeImpersonatePrivilege
  • Monitor ETW events from RpcServerRegisterIf2 in unusual processes
  • Enroll high-value accounts in the Protected Users group
  • Use Privileged Access Workstations for sensitive admin traffic

BUILD
  cd phantomrpc-poc\\POCs\\TERM && build.bat
  cd phantomrpc-poc\\POCs\\DHCP && build.bat

TOOLSET
  toolset\\find_vulnerable_rpcs.ps1   Enumerate currently vacant endpoints
  toolset\\check_mitigations.ps1      Audit exposed endpoints and mitigations
""")

_content_joeys = _static("""
JOEY'S WORLD  —  VORTEX Oplock Race Condition
===============================================

Oplock-based race condition exploit for NTFS directory hijacking
and privilege escalation via a filesystem timing attack.

TECHNIQUE
  Level-1 Opportunistic Lock (Oplock) + NTFS junction creation

ATTACK FLOW
  1. Create a bait file in C:\\Temp\\Redsun_Vortex\\
     opened with FILE_FLAG_OVERLAPPED

  2. Request a Level 1 Oplock on the file via
     FSCTL_REQUEST_OPLOCK_LEVEL_1

  3. A privileged process accesses the bait file.
     The oplock breaks: the OS notifies our thread and the
     privileged process is suspended at the file-open call,
     waiting for the oplock acknowledgement.

  4. In this microsecond pause window, call ForceJunction() to
     convert the directory into an NTFS mount-point junction:
         C:\\Temp\\Redsun_Vortex  →  \\??\\C:\\Windows\\System32

  5. Acknowledge the oplock break; the privileged process resumes.
     Its file access now traverses the hijacked junction into System32.

  6. Depending on what the privileged process does next, this enables
     arbitrary file writes, DLL planting, or full privilege escalation.

KEY FUNCTIONS
  ForceJunction(dir, ntTarget)
    Builds _REPARSE_DATA_BUFFER with IO_REPARSE_TAG_MOUNT_POINT
    Applies it via FSCTL_SET_REPARSE_POINT / DeviceIoControl

  ArmRace()
    Thread running at THREAD_PRIORITY_TIME_CRITICAL
    Sets oplock, blocks on IOCTL, fires junction on break
    Calls ExitProcess on success

  main()
    Creates working directory; spawns 15 concurrent ArmRace threads.
    More threads = higher probability of winning the race window.

REQUIREMENTS
  • Windows 10 / 11
  • C++17 / MSVC  (cl /EHsc /std:c++17)
  • Windows.h

BUILD
  cd joeys-world
  cl /EHsc /std:c++17 main.cpp /Fe:vortex.exe
""")

_content_hello = _static("""
HELLO WORLD  —  hello-world.ps1
=================================

The timeless classic, now part of the suite.

SOURCE
  Write-Host "Hello, World!"

OUTPUT
  Hello, World!

A single PowerShell line that greets the world.

  • No dependencies
  • No elevated privileges required
  • No side effects
  • Compatible with PowerShell 5.1+ on any Windows system

TO RUN ON WINDOWS
  .\\hello-world.ps1

  (Pro tip: this is the one program in ClaudeJunk that will
   definitely not get you a CVE, a CVE advisory, or a call
   from Microsoft MORSE.)
""")

# ─── Menu and tag configuration ───────────────────────────────────────────────

# curses color pair indices
_CP_TITLE  = 1   # cyan      — banner / selected item
_CP_FUN    = 2   # green     — fun/utility
_CP_FOR    = 3   # blue      — forensics
_CP_WIN    = 4   # red       — windows admin
_CP_SEC    = 5   # magenta   — security research
_CP_HDR    = 6   # bold cyan — section headers in pager

_TAG_COLOR = {
    "FUN": _CP_FUN,
    "FOR": _CP_FOR,
    "WIN": _CP_WIN,
    "SEC": _CP_SEC,
}

_TAG_LABEL = {
    "FUN": "Fun / Utility",
    "FOR": "Forensics",
    "WIN": "Windows Admin",
    "SEC": "Security Research",
}

# (display name, category tag, content callable)
_MENU = [
    ("Blaze Browser Detector",  "FOR", _content_blaze),
    ("Password Changer Ref",    "WIN", _content_password),
    ("EDR Test Suite",          "SEC", _content_edr),
    ("YellowKey",               "SEC", _content_yellowkey),
    ("GreenPlasma",             "SEC", _content_greenplasma),
    ("PhantomRPC",              "SEC", _content_phantomrpc),
    ("Joey's World",            "SEC", _content_joeys),
    ("Hello World",             "FUN", _content_hello),
]

_BANNER = [
    "  ┌─────────────────────────────────────────────────────┐",
    "  │                                                     │",
    "  │      C L A U D E J U N K   S U P E R   S U I T E  │",
    "  │                                                     │",
    "  │       8 programs  ·  1 interface  ·  all features  │",
    "  │                                                     │",
    "  └─────────────────────────────────────────────────────┘",
]

# ─── UI helpers ────────────────────────────────────────────────────────────────

def _init_colors():
    curses.use_default_colors()
    curses.init_pair(_CP_TITLE, curses.COLOR_CYAN,    -1)
    curses.init_pair(_CP_FUN,   curses.COLOR_GREEN,   -1)
    curses.init_pair(_CP_FOR,   curses.COLOR_BLUE,    -1)
    curses.init_pair(_CP_WIN,   curses.COLOR_RED,     -1)
    curses.init_pair(_CP_SEC,   curses.COLOR_MAGENTA, -1)
    curses.init_pair(_CP_HDR,   curses.COLOR_CYAN,    -1)


def _put(win, y, x, text, attr=0):
    """Safely write text at (y, x), clipping to window bounds."""
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    avail = w - x - 1
    if avail <= 0:
        return
    try:
        win.addstr(y, x, text[:avail], attr)
    except curses.error:
        pass


def _line_attr(line, has_color):
    """Choose a display attribute for a pager line based on its content."""
    if not has_color:
        return 0
    s = line.lstrip()
    if not s:
        return 0
    # All-uppercase section headers (e.g. "ATTACK FLOW", "ROOT CAUSE")
    if (len(s) >= 4 and s[0].isalpha()
            and s == s.upper()
            and not s.startswith("•")):
        return curses.color_pair(_CP_HDR) | curses.A_BOLD
    # Roman numeral sub-headings  I.  II.  III.  etc.
    if s[:4] in ("I.  ", "II. ", "III.", "IV. ", "V.  ", "VI. ", "VII.", "VIII"):
        return curses.color_pair(_CP_HDR) | curses.A_BOLD
    # Separator lines
    if s.startswith("===") or s.startswith("───") or s.startswith("---"):
        return curses.A_DIM
    # Bullet points
    if s.startswith("•") or s.startswith("✗"):
        return curses.color_pair(_CP_FUN)
    # Indented code-like lines (commands, paths)
    if line.startswith("    ") and any(c in line for c in r"\/.$%"):
        return curses.A_DIM
    return 0

# ─── Pager ────────────────────────────────────────────────────────────────────

def _pager(stdscr, lines, title):
    """Full-screen scrollable pager. Returns when user presses Q or Esc."""
    has_color = curses.has_colors()
    scroll = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        content_rows = max(1, h - 5)
        max_scroll = max(0, len(lines) - content_rows)
        scroll = min(scroll, max_scroll)

        try:
            stdscr.border()
        except curses.error:
            pass

        hdr_attr = (curses.color_pair(_CP_TITLE) | curses.A_BOLD) if has_color else curses.A_BOLD
        hdr = f" {title} "
        _put(stdscr, 1, max(1, (w - len(hdr)) // 2), hdr, hdr_attr)
        _put(stdscr, 2, 1, "─" * (w - 2), curses.A_DIM)

        for i, line in enumerate(lines[scroll: scroll + content_rows]):
            attr = _line_attr(line, has_color)
            _put(stdscr, 3 + i, 2, line, attr)

        pct = int(100 * min(scroll + content_rows, len(lines)) / max(len(lines), 1))
        footer = f" ↑/↓/PgUp/PgDn  Scroll    Q/Esc  Back    {pct:3d}% "
        _put(stdscr, h - 2, max(1, (w - len(footer)) // 2), footer, curses.A_DIM)

        stdscr.refresh()
        key = stdscr.getch()

        if key in (ord("q"), ord("Q"), 27):
            break
        elif key == curses.KEY_UP:
            scroll = max(0, scroll - 1)
        elif key == curses.KEY_DOWN:
            scroll = min(max_scroll, scroll + 1)
        elif key == curses.KEY_PPAGE:
            scroll = max(0, scroll - content_rows)
        elif key == curses.KEY_NPAGE:
            scroll = min(max_scroll, scroll + content_rows)
        elif key == curses.KEY_HOME:
            scroll = 0
        elif key == curses.KEY_END:
            scroll = max_scroll

# ─── Main menu ────────────────────────────────────────────────────────────────

def _draw_menu(stdscr, selected, has_color):
    stdscr.erase()
    h, w = stdscr.getmaxyx()

    try:
        stdscr.border()
    except curses.error:
        pass

    title_attr = (curses.color_pair(_CP_TITLE) | curses.A_BOLD) if has_color else curses.A_BOLD

    # Banner
    for bi, bline in enumerate(_BANNER):
        _put(stdscr, 1 + bi, max(1, (w - len(bline)) // 2), bline, title_attr)

    sep_y = 1 + len(_BANNER)
    _put(stdscr, sep_y, 1, "─" * (w - 2), curses.A_DIM)

    # Menu items
    for i, (label, tag, _fn) in enumerate(_MENU):
        y = sep_y + 2 + i
        if y >= h - 3:
            break
        num = str(i + 1) if i < 9 else "0"
        tag_label = _TAG_LABEL[tag]
        tag_attr = curses.color_pair(_TAG_COLOR[tag]) if has_color else 0
        row_text = f" [{num}] {label:<28}"

        if i == selected:
            sel_attr = (curses.color_pair(_CP_TITLE) | curses.A_REVERSE) if has_color else curses.A_REVERSE
            _put(stdscr, y, 2, row_text, sel_attr)
            _put(stdscr, y, 2 + len(row_text), f"  {tag_label}", sel_attr)
        else:
            _put(stdscr, y, 2, row_text)
            _put(stdscr, y, 2 + len(row_text), f"  {tag_label}", tag_attr)

    footer = " ↑/↓ Navigate   Enter Select   1-0 Jump   Q Quit "
    _put(stdscr, h - 2, max(1, (w - len(footer)) // 2), footer, curses.A_DIM)

    stdscr.refresh()

# ─── Curses entry point ───────────────────────────────────────────────────────

def _main(stdscr):
    curses.curs_set(0)
    has_color = curses.has_colors()
    if has_color:
        _init_colors()

    n = len(_MENU)
    selected = 0

    while True:
        _draw_menu(stdscr, selected, has_color)
        key = stdscr.getch()

        if key in (ord("q"), ord("Q"), 27):
            break
        elif key in (curses.KEY_UP,):
            selected = (selected - 1) % n
        elif key in (curses.KEY_DOWN,):
            selected = (selected + 1) % n
        elif key in (curses.KEY_ENTER, 10, 13):
            label, _tag, fn = _MENU[selected]
            _pager(stdscr, fn(), label)
        elif key == curses.KEY_RESIZE:
            pass  # just redraw on next iteration
        elif ord("1") <= key <= ord("9"):
            idx = key - ord("1")
            if idx < n:
                selected = idx
        elif key == ord("0"):
            selected = min(9, n - 1)


if __name__ == "__main__":
    try:
        curses.wrapper(_main)
        print("Thanks for using ClaudeJunk Super Suite.")
    except KeyboardInterrupt:
        print()
