# find_vulnerable_rpcs.ps1
# Enumerate ncalrpc endpoints and identify those whose owning service is stopped.
# A stopped service means the endpoint is unoccupied and squattable by any
# process with SeImpersonatePrivilege — the core PhantomRPC condition.
#
# Requires: rpctools (portqry / rpcdump) OR uses built-in sc.exe / WMI.
# Run as Administrator for complete results.
#
# Reference: https://github.com/klsecservices/PhantomRPC

Write-Host "=== PhantomRPC — Vacant ncalrpc Endpoint Finder ==="
Write-Host "Querying service states for known RPC endpoint owners..."
Write-Host ""

# Map of ncalrpc endpoint name → owning service name
$endpointMap = @{
    "TermSrvApi"          = "TermService"
    "dhcpcsvc6"           = "Dhcp"
    "dhcpcsvc"            = "Dhcp"
    "epmapper"            = "RpcEptMapper"
    "W32TIME_ALT"         = "W32Time"
    "spoolss"             = "Spooler"
    "LSM_API_service"     = "LSM"
    "ntsvcs"              = "PlugPlay"
    "eventlog"            = "EventLog"
    "lsasspirpc"          = "lsass"
    "samss"               = "SamSs"
    "svcctl"              = "SCMR"
    "wkssvc"              = "LanmanWorkstation"
    "srvsvc"              = "LanmanServer"
    "browser"             = "Browser"
    "winreg"              = "RemoteRegistry"
    "atsvc"               = "Schedule"
    "tapsrv"              = "TapiSrv"
}

$vacant = @()

foreach ($ep in $endpointMap.Keys) {
    $svcName = $endpointMap[$ep]
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($null -eq $svc) { continue }

    if ($svc.Status -ne "Running") {
        $vacant += [PSCustomObject]@{
            Endpoint    = $ep
            Service     = $svcName
            Status      = $svc.Status.ToString()
        }
    }
}

if ($vacant.Count -eq 0) {
    Write-Host "[OK] No vacant ncalrpc endpoints found. All mapped services are Running."
} else {
    Write-Host "[!] VACANT ENDPOINTS (service not running — endpoint is squattable):"
    Write-Host ""
    $vacant | Format-Table -AutoSize
    Write-Host "Any of the above can be registered by a process with SeImpersonatePrivilege."
    Write-Host "A fake RPC server on these endpoints can impersonate any SYSTEM caller."
}

Write-Host ""
Write-Host "Note: This script checks a static map. Use ETW tracing (provider"
Write-Host "{6ad52b32-d609-4be9-ae07-ce8dae937e39}) for a dynamic, exhaustive audit."
