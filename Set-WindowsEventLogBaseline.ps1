<#
.SYNOPSIS
    Applies a Windows event logging baseline merged from the Malware Archaeology
    "Windows Logging Cheat Sheet" (Feb 2019, ver 2.3) and the Huntress
    "Collecting Microsoft Windows Event Logs (WEL)" guidance.

.DESCRIPTION
    Configures local event log sizes/retention, Advanced Audit Policy
    subcategories (by GUID, so it works on non-English systems), command-line
    capture in 4688 events, PowerShell Module/ScriptBlock logging, and enables
    additional useful logs (Task Scheduler, CAPI2).

    Merge rule used to build the audit table:
      - Wherever the Huntress article says the activity is "covered by the
        Huntress EDR" (or skips a setting in favor of other telemetry), the
        Malware Archaeology recommendation is applied instead.
      - Everywhere else the newer Huntress recommendation wins.
    See README_WindowsEventLogBaseline.md for the per-subcategory comparison.

    Notes:
      - Run elevated. Windows PowerShell 5.1 or later.
      - On domain-joined machines, matching GPO settings always win over what
        this script sets locally. Prefer GPO for enterprise-wide enforcement
        (Computer Configuration > Policies > Windows Settings > Security
        Settings > Advanced Audit Policy Configuration); this script is for
        non-domain endpoints, baselining, or generating the reference config.
      - The Huntress agent already attempts to apply its audit policy
        automatically on SIEM-enabled endpoints; this script aligns the rest
        (log sizes, retention, PowerShell logging) and enforces the merged
        audit table where the agent defers to the EDR.

.PARAMETER SecurityLogSizeKB
    Maximum Security log size in KB. Default 512000 (both sources). Malware
    Archaeology suggests 1024000 if File/Registry auditing, Windows Firewall
    (WFP) and Process Create auditing are all enabled.

.PARAMETER AppSystemLogSizeKB
    Maximum Application and System log size in KB. Default 256000 (MA: "256k or larger").

.PARAMETER PowerShellLogSizeKB
    Maximum size in KB for the classic "Windows PowerShell" log and the
    Microsoft-Windows-PowerShell/Operational channel. Default 256000.

.PARAMETER Capi2LogSizeKB
    Maximum size in KB for Microsoft-Windows-CAPI2/Operational (enabled by this
    script; disabled by default in Windows). Default 102400.

.PARAMETER EnableProcessTermination
    Audit Process Termination = Success. Both base sheets leave this off
    (Huntress: EDR-covered; MA base sheet defers to the Advanced sheet).

.PARAMETER EnableWfpSuccessAuditing
    Adds Success to Filtering Platform Connection auditing (event 5156) per
    Malware Archaeology. VERY noisy (~9-10k events/hour/system); default is
    Failure-only per Huntress.

.PARAMETER SkipSaclAuditing
    Skip enabling File System and Registry auditing (Success). Those
    subcategories emit nothing until SACLs are configured, so the default (on,
    per Malware Archaeology) is zero-noise until you add SACLs; pass this to
    follow the Huntress "No Auditing" recommendation instead.

.PARAMETER EnableCertificationServicesAuditing
    Force Certification Services auditing (Success+Failure). Otherwise applied
    automatically only when the AD CS service (CertSvc) is present, per the
    Huntress note.

.PARAMETER SkipDisables
    Only enable auditing; do not turn OFF subcategories the baseline marks
    "No Auditing". Use when another standard in your environment requires
    subcategories this baseline disables.

.PARAMETER SkipPowerShellLogging
    Do not set PowerShell ModuleLogging/ScriptBlockLogging registry values.

.PARAMETER EnableDnsDebugLogging
    On Windows DNS Servers only: enable DNS debug packet logging
    (queries/responses, send/receive, UDP/TCP, updates) per Malware
    Archaeology. Ignored when the DnsServer module is not present.

.PARAMETER ShowResultingPolicy
    Print "auditpol /get /category:*" after applying.

.EXAMPLE
    .\Set-WindowsEventLogBaseline.ps1

.EXAMPLE
    .\Set-WindowsEventLogBaseline.ps1 -WhatIf
    Show every change that would be made without applying anything.

.EXAMPLE
    .\Set-WindowsEventLogBaseline.ps1 -SecurityLogSizeKB 1024000 -EnableWfpSuccessAuditing -ShowResultingPolicy

.LINK
    https://www.malwarearchaeology.com/cheat-sheets

.LINK
    https://support.huntress.io/hc/en-us/articles/36005287194259-Collecting-Microsoft-Windows-Event-Logs-WEL
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(20480, 4194240)]
    [int]$SecurityLogSizeKB = 512000,

    [ValidateRange(20480, 4194240)]
    [int]$AppSystemLogSizeKB = 256000,

    [ValidateRange(20480, 4194240)]
    [int]$PowerShellLogSizeKB = 256000,

    [ValidateRange(1024, 4194240)]
    [int]$Capi2LogSizeKB = 102400,

    [switch]$EnableProcessTermination,
    [switch]$EnableWfpSuccessAuditing,
    [switch]$SkipSaclAuditing,
    [switch]$EnableCertificationServicesAuditing,
    [switch]$SkipDisables,
    [switch]$SkipPowerShellLogging,
    [switch]$EnableDnsDebugLogging,
    [switch]$ShowResultingPolicy
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'This script configures Windows Event Log / audit policy and must run on Windows.'
}

$script:Applied = New-Object System.Collections.Generic.List[string]
$script:Failed  = New-Object System.Collections.Generic.List[string]
$script:Skipped = New-Object System.Collections.Generic.List[string]

function Invoke-NativeChange {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    if (-not $PSCmdlet.ShouldProcess($Target, $Action)) {
        $script:Skipped.Add("$Target -- $Action")
        return
    }
    # PS 5.1 turns native stderr into terminating errors when EAP=Stop and
    # stderr is redirected; failures are handled via $LASTEXITCODE instead.
    $ErrorActionPreference = 'Continue'
    $output = & $Exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $script:Failed.Add("$Target -- $Action")
        Write-Warning ("{0} failed for '{1}': {2}" -f $Exe, $Target, ($output -join ' '))
    }
    else {
        $script:Applied.Add("$Target -- $Action")
        Write-Verbose "$Target -- $Action"
    }
}

function Set-RegistryValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord', 'String')]
        [string]$Type = 'DWord'
    )
    $target = "$Path\$Name"
    if (-not $PSCmdlet.ShouldProcess($target, "Set to '$Value' ($Type)")) {
        $script:Skipped.Add("$target = $Value")
        return
    }
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        $script:Applied.Add("$target = $Value")
        Write-Verbose "$target = $Value"
    }
    catch {
        $script:Failed.Add("$target = $Value")
        Write-Warning "Failed to set $target : $_"
    }
}

# ---------------------------------------------------------------------------
# Environment context
# ---------------------------------------------------------------------------
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$isDomainJoined = [bool]$computerSystem.PartOfDomain
$isDomainController = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType -eq 2
$hasAdcs = $null -ne (Get-Service -Name CertSvc -ErrorAction SilentlyContinue)

Write-Host 'Windows Event Log baseline (Malware Archaeology Feb 2019 + Huntress WEL merge)'
Write-Host ("Host: {0}  DomainJoined: {1}  DomainController: {2}  ADCS: {3}" -f
    $env:COMPUTERNAME, $isDomainJoined, $isDomainController, $hasAdcs)

if ($isDomainJoined) {
    Write-Warning ('This machine is domain-joined. GPO settings take precedence over anything set ' +
        'locally here and will re-apply on refresh. Mirror this baseline in GPO for durable enforcement.')
}

# ---------------------------------------------------------------------------
# Advanced Audit Policy - merged table
# Source key:  Both      = MA and Huntress agree
#              Huntress  = newer Huntress value wins over MA
#              MA        = MA value used because Huntress defers to their EDR
# Subcategories are addressed by GUID so this works regardless of OS language.
# ---------------------------------------------------------------------------
$auditPolicy = @(
    # --- Account Logon ---
    @{ Category = 'Account Logon';     Name = 'Credential Validation';                  Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
    @{ Category = 'Account Logon';     Name = 'Kerberos Authentication Service';        Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Huntress' }
    @{ Category = 'Account Logon';     Name = 'Kerberos Service Ticket Operations';     Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Huntress' }
    @{ Category = 'Account Logon';     Name = 'Other Account Logon Events';             Guid = '{0CCE9241-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Huntress' } # generates no events
    # --- Account Management ---
    @{ Category = 'Account Management'; Name = 'Application Group Management';          Guid = '{0CCE9239-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Huntress' } # deprecated AzMan only
    @{ Category = 'Account Management'; Name = 'Computer Account Management';           Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
    @{ Category = 'Account Management'; Name = 'Distribution Group Management';         Guid = '{0CCE9238-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
    @{ Category = 'Account Management'; Name = 'Other Account Management Events';       Guid = '{0CCE923A-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Huntress' } # no failure events exist
    @{ Category = 'Account Management'; Name = 'Security Group Management';             Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
    @{ Category = 'Account Management'; Name = 'User Account Management';               Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
    # --- Detailed Tracking ---
    @{ Category = 'Detailed Tracking'; Name = 'DPAPI Activity';                         Guid = '{0CCE922D-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    @{ Category = 'Detailed Tracking'; Name = 'PNP Activity';                           Guid = '{0CCE9248-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Both' }
    @{ Category = 'Detailed Tracking'; Name = 'Process Creation';                       Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'MA' } # Huntress: EDR-covered; 4688 kept per MA
    @{ Category = 'Detailed Tracking'; Name = 'Process Termination';                    Guid = '{0CCE922C-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' } # -EnableProcessTermination flips to Success
    @{ Category = 'Detailed Tracking'; Name = 'RPC Events';                             Guid = '{0CCE922E-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Huntress' } # generates no events
    @{ Category = 'Detailed Tracking'; Name = 'Token Right Adjusted';                   Guid = '{0CCE924A-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Huntress' } # 4703 flood on Win10+
    # --- DS Access (meaningful on Domain Controllers; harmless elsewhere) ---
    @{ Category = 'DS Access';         Name = 'Detailed Directory Service Replication'; Guid = '{0CCE923E-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    @{ Category = 'DS Access';         Name = 'Directory Service Access';               Guid = '{0CCE923B-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Huntress' }
    @{ Category = 'DS Access';         Name = 'Directory Service Changes';              Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Huntress' } # no failure events exist
    @{ Category = 'DS Access';         Name = 'Directory Service Replication';          Guid = '{0CCE923D-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    # --- Logon/Logoff ---
    @{ Category = 'Logon/Logoff';      Name = 'Account Lockout';                        Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $true;  Source = 'Huntress' } # no success events exist
    @{ Category = 'Logon/Logoff';      Name = 'Group Membership';                       Guid = '{0CCE9249-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Huntress' } # MA said Success; Huntress: excessive
    @{ Category = 'Logon/Logoff';      Name = 'IPsec Extended Mode';                    Guid = '{0CCE921A-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    @{ Category = 'Logon/Logoff';      Name = 'IPsec Main Mode';                        Guid = '{0CCE9218-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    @{ Category = 'Logon/Logoff';      Name = 'IPsec Quick Mode';                       Guid = '{0CCE9219-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    @{ Category = 'Logon/Logoff';      Name = 'Logoff';                                 Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Both' }
    @{ Category = 'Logon/Logoff';      Name = 'Logon';                                  Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
    @{ Category = 'Logon/Logoff';      Name = 'Network Policy Server';                  Guid = '{0CCE9243-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
    @{ Category = 'Logon/Logoff';      Name = 'Other Logon/Logoff Events';              Guid = '{0CCE921C-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
    @{ Category = 'Logon/Logoff';      Name = 'Special Logon';                          Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Huntress' } # no failure events exist
    @{ Category = 'Logon/Logoff';      Name = 'User / Device Claims';                   Guid = '{0CCE9247-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    # --- Object Access ---
    @{ Category = 'Object Access';     Name = 'Application Generated';                  Guid = '{0CCE9222-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Huntress' } # deprecated AzMan only
    @{ Category = 'Object Access';     Name = 'Central Access Policy Staging';          Guid = '{0CCE9246-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    @{ Category = 'Object Access';     Name = 'Certification Services';                 Guid = '{0CCE9221-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Huntress' } # auto-enabled below when AD CS present
    @{ Category = 'Object Access';     Name = 'Detailed File Share';                    Guid = '{0CCE9244-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Huntress' } # 5145; noisy on busy file servers/DCs
    @{ Category = 'Object Access';     Name = 'File Share';                             Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
    @{ Category = 'Object Access';     Name = 'File System';                            Guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'MA' } # silent until SACLs are set; -SkipSaclAuditing disables
    @{ Category = 'Object Access';     Name = 'Filtering Platform Connection';          Guid = '{0CCE9226-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $true;  Source = 'Huntress' } # -EnableWfpSuccessAuditing adds 5156 Success per MA
    @{ Category = 'Object Access';     Name = 'Filtering Platform Packet Drop';         Guid = '{0CCE9225-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    @{ Category = 'Object Access';     Name = 'Handle Manipulation';                    Guid = '{0CCE9223-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    @{ Category = 'Object Access';     Name = 'Kernel Object';                          Guid = '{0CCE921F-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Huntress' } # keep "Audit access of global system objects" OFF
    @{ Category = 'Object Access';     Name = 'Other Object Access Events';             Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Huntress' } # scheduled task ops 4698-4702
    @{ Category = 'Object Access';     Name = 'Registry';                               Guid = '{0CCE921E-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'MA' } # silent until SACLs are set; -SkipSaclAuditing disables
    @{ Category = 'Object Access';     Name = 'Removable Storage';                      Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
    @{ Category = 'Object Access';     Name = 'SAM';                                    Guid = '{0CCE9220-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Huntress' } # MA said Success; covered by Account Management
    # --- Policy Change ---
    @{ Category = 'Policy Change';     Name = 'Audit Policy Change';                    Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Huntress' } # no failure events exist
    @{ Category = 'Policy Change';     Name = 'Authentication Policy Change';           Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Huntress' }
    @{ Category = 'Policy Change';     Name = 'Authorization Policy Change';            Guid = '{0CCE9231-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Huntress' }
    @{ Category = 'Policy Change';     Name = 'Filtering Platform Policy Change';       Guid = '{0CCE9233-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Both' }
    @{ Category = 'Policy Change';     Name = 'MPSSVC Rule-Level Policy Change';        Guid = '{0CCE9232-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Huntress' } # Windows Firewall rule changes
    @{ Category = 'Policy Change';     Name = 'Other Policy Change Events';             Guid = '{0CCE9234-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Huntress' }
    # --- Privilege Use ---
    @{ Category = 'Privilege Use';     Name = 'Non Sensitive Privilege Use';            Guid = '{0CCE9229-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    @{ Category = 'Privilege Use';     Name = 'Other Privilege Use Events';             Guid = '{0CCE922A-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Both' }
    @{ Category = 'Privilege Use';     Name = 'Sensitive Privilege Use';                Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' } # high volume; both sheets keep it
    # --- System ---
    @{ Category = 'System';            Name = 'IPsec Driver';                           Guid = '{0CCE9213-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $false; Source = 'Huntress' }
    @{ Category = 'System';            Name = 'Other System Events';                    Guid = '{0CCE9214-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Huntress' }
    @{ Category = 'System';            Name = 'Security State Change';                  Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Huntress' } # no failure events exist
    @{ Category = 'System';            Name = 'Security System Extension';              Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false; Source = 'Huntress' }
    @{ Category = 'System';            Name = 'System Integrity';                       Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true;  Source = 'Both' }
)

# Option/environment-driven adjustments
foreach ($entry in $auditPolicy) {
    switch ($entry.Name) {
        'Process Termination' {
            if ($EnableProcessTermination) { $entry.Success = $true }
        }
        'Filtering Platform Connection' {
            if ($EnableWfpSuccessAuditing) {
                $entry.Success = $true
                Write-Warning 'WFP connection Success auditing (5156) enabled - expect ~9-10k events/hour/system (Malware Archaeology estimate).'
            }
        }
        { $_ -in 'File System', 'Registry' } {
            if ($SkipSaclAuditing) { $entry.Success = $false }
        }
        'Certification Services' {
            if ($EnableCertificationServicesAuditing -or $hasAdcs) {
                $entry.Success = $true
                $entry.Failure = $true
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 1. Force use of Advanced Audit Policy over legacy category settings
#    (MA: "Audit: Force audit policy subcategory settings" = ENABLE)
# ---------------------------------------------------------------------------
Write-Host "`n[1/5] Forcing Advanced Audit Policy subcategory settings (SCENoApplyLegacyAuditPolicy)"
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1

# ---------------------------------------------------------------------------
# 2. Advanced Audit Policy subcategories
# ---------------------------------------------------------------------------
Write-Host "`n[2/5] Applying Advanced Audit Policy ($($auditPolicy.Count) subcategories)"
foreach ($entry in $auditPolicy) {
    if (-not $entry.Success -and -not $entry.Failure -and $SkipDisables) {
        $script:Skipped.Add("$($entry.Category)/$($entry.Name) -- disable skipped (-SkipDisables)")
        continue
    }
    $successFlag = if ($entry.Success) { 'enable' } else { 'disable' }
    $failureFlag = if ($entry.Failure) { 'enable' } else { 'disable' }
    Invoke-NativeChange `
        -Target "$($entry.Category)/$($entry.Name)" `
        -Action "Audit Success=$successFlag Failure=$failureFlag [$($entry.Source)]" `
        -Exe 'auditpol.exe' `
        -Arguments @('/set', "/subcategory:$($entry.Guid)", "/success:$successFlag", "/failure:$failureFlag")
}

# ---------------------------------------------------------------------------
# 3. Log sizes, retention, and additional channels
#    (wevtutil /ms: takes bytes; /rt:false = overwrite events as needed)
# ---------------------------------------------------------------------------
Write-Host "`n[3/5] Configuring log sizes and retention"
$logConfig = @(
    @{ Channel = 'Security';                                     SizeKB = $SecurityLogSizeKB;   Retention = $true }
    @{ Channel = 'Application';                                  SizeKB = $AppSystemLogSizeKB;  Retention = $true }
    @{ Channel = 'System';                                       SizeKB = $AppSystemLogSizeKB;  Retention = $true }
    @{ Channel = 'Windows PowerShell';                           SizeKB = $PowerShellLogSizeKB; Retention = $true }
    @{ Channel = 'Microsoft-Windows-PowerShell/Operational';     SizeKB = $PowerShellLogSizeKB; Retention = $false }
)
foreach ($log in $logConfig) {
    $sizeArgs = @('sl', $log.Channel, "/ms:$($log.SizeKB * 1024)")
    if ($log.Retention) { $sizeArgs += '/rt:false' }
    Invoke-NativeChange -Target $log.Channel -Action "Max size $($log.SizeKB) KB, overwrite as needed" `
        -Exe 'wevtutil.exe' -Arguments $sizeArgs
}

# Task Scheduler operational log - MA: enable and watch 129 (created) / 141 (deleted)
Invoke-NativeChange -Target 'Microsoft-Windows-TaskScheduler/Operational' -Action 'Enable channel' `
    -Exe 'wevtutil.exe' -Arguments @('sl', 'Microsoft-Windows-TaskScheduler/Operational', '/e:true')

# CAPI2 operational log - MA: enable (off by default) and watch event 81 (failed trust validation)
Invoke-NativeChange -Target 'Microsoft-Windows-CAPI2/Operational' -Action "Enable channel, max size $Capi2LogSizeKB KB" `
    -Exe 'wevtutil.exe' -Arguments @('sl', 'Microsoft-Windows-CAPI2/Operational', '/e:true', "/ms:$($Capi2LogSizeKB * 1024)")

# ---------------------------------------------------------------------------
# 4. Command line in 4688 + PowerShell logging
# ---------------------------------------------------------------------------
Write-Host "`n[4/5] Command-line process auditing and PowerShell logging"
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1

if ($SkipPowerShellLogging) {
    $script:Skipped.Add('PowerShell ModuleLogging/ScriptBlockLogging (-SkipPowerShellLogging)')
}
else {
    # Huntress documents the Wow6432Node path; policy CSE writes the native path.
    # Set both so 32-bit and 64-bit PowerShell hosts pick the policy up.
    $psPolicyRoots = @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell')
    if ([Environment]::Is64BitOperatingSystem) {
        $psPolicyRoots += 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell'
    }
    foreach ($root in $psPolicyRoots) {
        Set-RegistryValue -Path "$root\ModuleLogging" -Name 'EnableModuleLogging' -Value 1
        Set-RegistryValue -Path "$root\ModuleLogging\ModuleNames" -Name '*' -Value '*' -Type String
        Set-RegistryValue -Path "$root\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1
    }
}

# ---------------------------------------------------------------------------
# 5. Optional: DNS Server debug logging (MA "ENABLE: DNS LOGS")
# ---------------------------------------------------------------------------
Write-Host "`n[5/5] DNS Server debug logging"
if (-not $EnableDnsDebugLogging) {
    $script:Skipped.Add('DNS debug logging (pass -EnableDnsDebugLogging on Windows DNS Servers)')
    Write-Host '  Skipped (opt-in with -EnableDnsDebugLogging; applies to the Windows DNS Server role only).'
}
elseif (-not (Get-Command -Name Set-DnsServerDiagnostics -ErrorAction SilentlyContinue)) {
    $script:Skipped.Add('DNS debug logging (DnsServer module not present)')
    Write-Warning 'DnsServer module not found - is the DNS Server role installed? Skipping DNS debug logging.'
}
elseif ($PSCmdlet.ShouldProcess('DNS Server diagnostics', 'Enable debug packet logging')) {
    try {
        Set-DnsServerDiagnostics `
            -Queries $true -Answers $true `
            -SendPackets $true -ReceivePackets $true `
            -UdpPackets $true -TcpPackets $true `
            -QuestionTransactions $true -Update $true `
            -EnableLoggingToFile $true `
            -LogFilePath "$env:SystemRoot\System32\Dns\Dns.log"
        $script:Applied.Add('DNS Server debug logging -> %SystemRoot%\System32\Dns\Dns.log')
    }
    catch {
        $script:Failed.Add('DNS Server debug logging')
        Write-Warning "Failed to enable DNS debug logging: $_"
    }
}

# ---------------------------------------------------------------------------
# Summary / verification
# ---------------------------------------------------------------------------
Write-Host "`n==== Summary ===="
Write-Host ("Applied: {0}   Failed: {1}   Skipped: {2}" -f $script:Applied.Count, $script:Failed.Count, $script:Skipped.Count)
if ($script:Failed.Count -gt 0) {
    Write-Host "`nFailed items:"
    $script:Failed | ForEach-Object { Write-Host "  - $_" }
}
if ($script:Skipped.Count -gt 0) {
    Write-Verbose ("Skipped items:`n  - " + ($script:Skipped -join "`n  - "))
}

Write-Host "`nVerify with:  auditpol /get /category:*   and   wevtutil gl Security"
if ($ShowResultingPolicy -and -not $WhatIfPreference) {
    & auditpol.exe /get /category:*
}

if ($script:Failed.Count -gt 0) { exit 1 }
