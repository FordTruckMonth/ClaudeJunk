# check_mitigations.ps1
# PhantomRPC mitigation checker
#
# Audits the local Windows machine for conditions that make PhantomRPC exploitable:
#   1. Services with vulnerable RPC endpoints that are stopped/disabled
#   2. Processes running as Network Service / Local Service (SeImpersonatePrivilege holders)
#   3. Whether DACL-based endpoint protection is configured
#
# Run as Administrator for accurate service state.
# Output goes to stdout and to %TEMP%\PhantomRPC_audit.txt
#
# Reference: https://github.com/klsecservices/PhantomRPC

$outFile = "$env:TEMP\PhantomRPC_audit.txt"
$results = @()

function Log($msg) {
    Write-Host $msg
    $script:results += $msg
}

Log "=== PhantomRPC Mitigation Audit ==="
Log "Host   : $env:COMPUTERNAME"
Log "Date   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log ""

# ─── Known vulnerable (service → ncalrpc endpoint) ───────────────────────────
$knownTargets = @(
    [PSCustomObject]@{ ServiceName = "TermService"; Endpoint = "TermSrvApi";  UUID = "bde95fdf-eee0-45de-9e12-e5a61cd0d4fe"; Trigger = "gpupdate /force" }
    [PSCustomObject]@{ ServiceName = "Dhcp";        Endpoint = "dhcpcsvc6";   UUID = "3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6"; Trigger = "Network operation" }
    [PSCustomObject]@{ ServiceName = "W32Time";     Endpoint = "\\PIPE\\W32TIME"; UUID = "8fb6d884-2388-11d0-8c35-00c04fda2795"; Trigger = "Time sync" }
)

Log "── Service exposure check ──────────────────────────────────────────────"
foreach ($t in $knownTargets) {
    $svc = Get-Service -Name $t.ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Log "  [?] $($t.ServiceName): not found on this system"
        continue
    }

    $state  = $svc.Status
    $start  = (Get-WmiObject Win32_Service -Filter "Name='$($t.ServiceName)'" -ErrorAction SilentlyContinue).StartMode

    if ($state -ne "Running") {
        Log "  [EXPOSED] $($t.ServiceName) is $state (StartMode=$start)"
        Log "            Endpoint : $($t.Endpoint)"
        Log "            UUID     : $($t.UUID)"
        Log "            Trigger  : $($t.Trigger)"
        Log "            Action   : Ensure service is Running, or restrict DACL on endpoint"
    } else {
        Log "  [OK]      $($t.ServiceName) is Running — endpoint occupied by legitimate service"
    }
}

Log ""

# ─── SeImpersonatePrivilege holders ──────────────────────────────────────────
Log "── Processes with SeImpersonatePrivilege (potential attackers) ─────────"

$impersonateAccounts = @(
    "NT AUTHORITY\NETWORK SERVICE",
    "NT AUTHORITY\LOCAL SERVICE"
)

$impersonateProcs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    try {
        $owner = $_.GetOwner()
        $fullName = "$($owner.Domain)\$($owner.User)"
        $impersonateAccounts -contains $fullName
    } catch { $false }
}

if ($impersonateProcs) {
    foreach ($p in $impersonateProcs) {
        $o = $p.GetOwner()
        Log "  [INFO] PID $($p.ProcessId) $($p.Name) running as $($o.Domain)\$($o.User)"
    }
    Log ""
    Log "  NOTE: Processes above hold SeImpersonatePrivilege by default."
    Log "        If compromised, they can deploy a PhantomRPC fake server."
} else {
    Log "  [OK] No NETWORK SERVICE / LOCAL SERVICE processes detected (unusual)"
}

Log ""

# ─── Recommendations ─────────────────────────────────────────────────────────
Log "── Recommendations ─────────────────────────────────────────────────────"
Log "  1. Keep TermService, Dhcp, and W32Time in Running state."
Log "     A stopped service vacates its ncalrpc endpoint, making it squattable."
Log ""
Log "  2. Apply RPC endpoint DACLs via Group Policy:"
Log "     Computer Configuration > Windows Settings > Security Settings >"
Log "     Local Policies > Security Options >"
Log "     'DCOM: Machine Access Restrictions' — restrict to Administrators."
Log ""
Log "  3. Monitor ETW provider {6ad52b32-d609-4be9-ae07-ce8dae937e39} for"
Log "     unexpected RpcServerRegisterIf2 calls from non-service processes."
Log ""
Log "  4. Reduce SeImpersonatePrivilege scope: ensure only required service"
Log "     accounts hold this right (User Rights Assignment GPO)."
Log ""
Log "  5. Enable Windows Defender Credential Guard and Protected Users group"
Log "     to limit token impersonation paths."

Log ""
Log "=== Audit complete ==="
Log "Full output written to: $outFile"

$results | Out-File -FilePath $outFile -Encoding UTF8
