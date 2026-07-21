<#
.SYNOPSIS
    Creates (and optionally links) an Active Directory GPO that implements the
    Windows event logging baseline merged from the Malware Archaeology
    "Windows Logging Cheat Sheet" (Feb 2019, ver 2.3) and the Huntress
    "Collecting Microsoft Windows Event Logs (WEL)" guidance.

.DESCRIPTION
    Scope: Advanced Audit Policy, event log sizing/retention, and the security
    option that forces subcategory auditing. Nothing else — PowerShell logging,
    command-line capture in 4688, and extra channels are documented in
    README_WindowsEventLogBaseline_Manual.md.

    What gets built inside the GPO:
      - Machine\Microsoft\Windows NT\Audit\audit.csv
            The merged Advanced Audit Policy table (all 59 subcategories,
            explicit "No Auditing" rows included so stale policy is overridden).
      - Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
            "Audit: Force audit policy subcategory settings" = Enabled, plus
            Security/Application/System log maximum sizes with
            "Overwrite events as needed" retention.
      - gPCMachineExtensionNames registration for the Security and Advanced
        Audit Policy client-side extensions, and a GPO version bump so clients
        pick the changes up.

    Merge rule for the audit table: wherever Huntress marks a subcategory
    "No Auditing" because the activity is covered by the Huntress EDR, the
    Malware Archaeology recommendation is applied instead; everywhere else the
    newer Huntress value wins. Per-subcategory comparison:
    README_WindowsEventLogBaseline.md.

    Requirements: run as a user with GPO-creation rights (e.g. Domain Admins)
    on a machine with the RSAT GroupPolicy and ActiveDirectory modules (any DC,
    or a management workstation with RSAT installed).

.PARAMETER GpoName
    Name of the GPO to create or update. Default: 'Windows Event Log Baseline'.

.PARAMETER LinkTo
    One or more distinguished names to link the GPO to, e.g.
    'DC=corp,DC=example,DC=com' for the whole domain or
    'OU=Servers,DC=corp,DC=example,DC=com'. If omitted, the GPO is created
    unlinked and the script prints how to link it.

.PARAMETER SecurityLogSizeKB
    Maximum Security log size in KB. Default 512000 (both sources). Malware
    Archaeology suggests 1024000 if SACL file/registry auditing and WFP success
    auditing are enabled.

.PARAMETER AppSystemLogSizeKB
    Maximum Application and System log size in KB. Default 256000 (MA).

.PARAMETER EnableProcessTermination
    Audit Process Termination = Success (off in both base documents).

.PARAMETER EnableWfpSuccessAuditing
    Adds Success to Filtering Platform Connection (event 5156) per Malware
    Archaeology. VERY noisy; default is Failure-only per Huntress.

.PARAMETER SkipSaclAuditing
    Follow Huntress instead of MA for File System / Registry auditing
    (No Auditing instead of Success).

.PARAMETER EnableCertificationServicesAuditing
    Certification Services = Success+Failure. Only useful when this GPO's
    scope includes AD CS servers; consider a separate scoped GPO otherwise.
    Default: No Auditing (Huntress).

.PARAMETER Force
    Overwrite an existing audit.csv / GptTmpl.inf in the target GPO. Without
    this, the script refuses to touch a GPO that already carries security
    template or audit settings, to avoid clobbering someone else's policy.

.EXAMPLE
    .\New-WindowsEventLogBaselineGpo.ps1 -WhatIf
    Show what would be created without touching AD or SYSVOL.

.EXAMPLE
    .\New-WindowsEventLogBaselineGpo.ps1 -LinkTo 'DC=corp,DC=example,DC=com'
    Create the GPO and link it at the domain root (includes DCs).

.EXAMPLE
    .\New-WindowsEventLogBaselineGpo.ps1 -GpoName 'SEC - Logging Baseline' `
        -LinkTo 'OU=Workstations,DC=corp,DC=example,DC=com','OU=Servers,DC=corp,DC=example,DC=com' `
        -SecurityLogSizeKB 1024000 -EnableWfpSuccessAuditing

.LINK
    https://www.malwarearchaeology.com/cheat-sheets

.LINK
    https://support.huntress.io/hc/en-us/articles/36005287194259-Collecting-Microsoft-Windows-Event-Logs-WEL
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateNotNullOrEmpty()]
    [string]$GpoName = 'Windows Event Log Baseline',

    [string[]]$LinkTo,

    [ValidateRange(20480, 4194240)]
    [int]$SecurityLogSizeKB = 512000,

    [ValidateRange(20480, 4194240)]
    [int]$AppSystemLogSizeKB = 256000,

    [switch]$EnableProcessTermination,
    [switch]$EnableWfpSuccessAuditing,
    [switch]$SkipSaclAuditing,
    [switch]$EnableCertificationServicesAuditing,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Client-side extensions the GPO must declare so clients process our files:
#   Security CSE (GptTmpl.inf) and Advanced Audit Policy CSE (audit.csv),
#   each paired with its admin-tool extension GUID.
$SecurityCsePair = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
$AuditCsePair    = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'

foreach ($module in 'GroupPolicy', 'ActiveDirectory') {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "The $module PowerShell module is required. Run this on a domain controller or install RSAT (Group Policy Management + AD DS tools)."
    }
}
Import-Module GroupPolicy, ActiveDirectory

# ---------------------------------------------------------------------------
# Merged Advanced Audit Policy table
# Source key:  Both     = MA and Huntress agree
#              Huntress = newer Huntress value wins over MA
#              MA       = MA value used because Huntress defers to their EDR
# ---------------------------------------------------------------------------
$auditPolicy = @(
    @{ Name = 'Audit Credential Validation';                  Guid = '{0cce923f-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Kerberos Authentication Service';        Guid = '{0cce9242-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Kerberos Service Ticket Operations';     Guid = '{0cce9240-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Other Account Logon Events';             Guid = '{0cce9241-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Application Group Management';           Guid = '{0cce9239-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Computer Account Management';            Guid = '{0cce9236-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Distribution Group Management';          Guid = '{0cce9238-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Other Account Management Events';        Guid = '{0cce923a-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit Security Group Management';              Guid = '{0cce9237-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit User Account Management';                Guid = '{0cce9235-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit DPAPI Activity';                         Guid = '{0cce922d-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit PNP Activity';                           Guid = '{0cce9248-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit Process Creation';                       Guid = '{0cce922b-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  } # MA override (Huntress: EDR-covered)
    @{ Name = 'Audit Process Termination';                    Guid = '{0cce922c-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false } # -EnableProcessTermination flips
    @{ Name = 'Audit RPC Events';                             Guid = '{0cce922e-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Token Right Adjusted Events';            Guid = '{0cce924a-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Detailed Directory Service Replication'; Guid = '{0cce923e-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Directory Service Access';               Guid = '{0cce923b-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Directory Service Changes';              Guid = '{0cce923c-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit Directory Service Replication';          Guid = '{0cce923d-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Account Lockout';                        Guid = '{0cce9217-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $true  }
    @{ Name = 'Audit User / Device Claims';                   Guid = '{0cce9247-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Group Membership';                       Guid = '{0cce9249-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit IPsec Extended Mode';                    Guid = '{0cce921a-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit IPsec Main Mode';                        Guid = '{0cce9218-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit IPsec Quick Mode';                       Guid = '{0cce9219-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Logoff';                                 Guid = '{0cce9216-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit Logon';                                  Guid = '{0cce9215-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Network Policy Server';                  Guid = '{0cce9243-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Other Logon/Logoff Events';              Guid = '{0cce921c-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Special Logon';                          Guid = '{0cce921b-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit Application Generated';                  Guid = '{0cce9222-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Central Access Policy Staging';          Guid = '{0cce9246-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Certification Services';                 Guid = '{0cce9221-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false } # -EnableCertificationServicesAuditing flips
    @{ Name = 'Audit Detailed File Share';                    Guid = '{0cce9244-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit File Share';                             Guid = '{0cce9224-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit File System';                            Guid = '{0cce921d-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false } # MA override; silent until SACLs exist
    @{ Name = 'Audit Filtering Platform Connection';          Guid = '{0cce9226-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $true  } # -EnableWfpSuccessAuditing adds Success
    @{ Name = 'Audit Filtering Platform Packet Drop';         Guid = '{0cce9225-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Handle Manipulation';                    Guid = '{0cce9223-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Kernel Object';                          Guid = '{0cce921f-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Other Object Access Events';             Guid = '{0cce9227-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Registry';                               Guid = '{0cce921e-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false } # MA override; silent until SACLs exist
    @{ Name = 'Audit Removable Storage';                      Guid = '{0cce9245-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit SAM';                                    Guid = '{0cce9220-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Audit Policy Change';                    Guid = '{0cce922f-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit Authentication Policy Change';           Guid = '{0cce9230-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit Authorization Policy Change';            Guid = '{0cce9231-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit Filtering Platform Policy Change';       Guid = '{0cce9233-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit MPSSVC Rule-Level Policy Change';        Guid = '{0cce9232-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Other Policy Change Events';             Guid = '{0cce9234-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Non Sensitive Privilege Use';            Guid = '{0cce9229-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Other Privilege Use Events';             Guid = '{0cce922a-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Sensitive Privilege Use';                Guid = '{0cce9228-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit IPsec Driver';                           Guid = '{0cce9213-69ae-11d9-bed3-505054503030}'; Success = $false; Failure = $false }
    @{ Name = 'Audit Other System Events';                    Guid = '{0cce9214-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
    @{ Name = 'Audit Security State Change';                  Guid = '{0cce9210-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit Security System Extension';              Guid = '{0cce9211-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $false }
    @{ Name = 'Audit System Integrity';                       Guid = '{0cce9212-69ae-11d9-bed3-505054503030}'; Success = $true;  Failure = $true  }
)

foreach ($entry in $auditPolicy) {
    switch ($entry.Name) {
        'Audit Process Termination'          { if ($EnableProcessTermination) { $entry.Success = $true } }
        'Audit Certification Services'       { if ($EnableCertificationServicesAuditing) { $entry.Success = $true; $entry.Failure = $true } }
        'Audit Filtering Platform Connection' {
            if ($EnableWfpSuccessAuditing) {
                $entry.Success = $true
                Write-Warning 'WFP connection Success auditing (5156) enabled - expect ~9-10k events/hour/system. Consider -SecurityLogSizeKB 1024000.'
            }
        }
        { $_ -in 'Audit File System', 'Audit Registry' } { if ($SkipSaclAuditing) { $entry.Success = $false } }
    }
}

# ---------------------------------------------------------------------------
# Compose the GPO payload files
# ---------------------------------------------------------------------------
# audit.csv: Setting Value 0=None 1=Success 2=Failure 3=Both. Explicit 0 rows
# enforce "No Auditing" so stale subcategory settings get overridden.
$inclusionText = @{ 0 = 'No Auditing'; 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
$auditCsvLines = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
foreach ($entry in $auditPolicy) {
    $value = [int]$entry.Success + 2 * [int]$entry.Failure
    $auditCsvLines += ',System,{0},{1},{2},,{3}' -f $entry.Name, $entry.Guid, $inclusionText[$value], $value
}

# GptTmpl.inf: force subcategory auditing + log sizes (KB) with
# AuditLogRetentionPeriod=0 ("overwrite events as needed").
$gptTmplLines = @(
    '[Unicode]'
    'Unicode=yes'
    '[Version]'
    'signature="$CHICAGO$"'
    'Revision=1'
    '[Registry Values]'
    'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1'
    '[Application Log]'
    "MaximumLogSize=$AppSystemLogSizeKB"
    'AuditLogRetentionPeriod=0'
    '[Security Log]'
    "MaximumLogSize=$SecurityLogSizeKB"
    'AuditLogRetentionPeriod=0'
    '[System Log]'
    "MaximumLogSize=$AppSystemLogSizeKB"
    'AuditLogRetentionPeriod=0'
)

# ---------------------------------------------------------------------------
# Create or fetch the GPO
# ---------------------------------------------------------------------------
$domain = Get-ADDomain
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($null -eq $gpo) {
    if (-not $PSCmdlet.ShouldProcess($GpoName, 'Create GPO')) {
        Write-Host "Would create GPO '$GpoName' in $($domain.DNSRoot), write audit.csv ($($auditPolicy.Count) subcategories) and GptTmpl.inf (log sizes/retention + forced subcategory auditing), register the Security and Audit CSEs, and link to: $(if ($LinkTo) { $LinkTo -join ', ' } else { '(nothing - unlinked)' })."
        return
    }
    $gpo = New-GPO -Name $GpoName -Comment 'Windows event logging baseline: Malware Archaeology Feb 2019 + Huntress WEL merge. Managed by New-WindowsEventLogBaselineGpo.ps1.'
    Write-Host "Created GPO '$GpoName' ($($gpo.Id))"
}
else {
    Write-Host "Using existing GPO '$GpoName' ($($gpo.Id))"
}

$gpoSysvolPath = '\\{0}\SYSVOL\{0}\Policies\{1}' -f $domain.DNSRoot, $gpo.Id.ToString('B').ToUpper()
$auditCsvPath  = Join-Path $gpoSysvolPath 'Machine\Microsoft\Windows NT\Audit\audit.csv'
$gptTmplPath   = Join-Path $gpoSysvolPath 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'

foreach ($existing in $auditCsvPath, $gptTmplPath) {
    if ((Test-Path -LiteralPath $existing) -and -not $Force) {
        throw "$existing already exists - this GPO already carries audit/security-template settings. Re-run with -Force to overwrite, or use a dedicated GPO name."
    }
}

# ---------------------------------------------------------------------------
# Write payload, register CSEs, bump the GPO version
# ---------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($auditCsvPath, "Write Advanced Audit Policy ($($auditPolicy.Count) subcategories)")) {
    New-Item -ItemType Directory -Path (Split-Path $auditCsvPath) -Force | Out-Null
    Set-Content -LiteralPath $auditCsvPath -Value $auditCsvLines -Encoding Ascii
}
if ($PSCmdlet.ShouldProcess($gptTmplPath, "Write log sizes (Security $SecurityLogSizeKB KB, App/System $AppSystemLogSizeKB KB) + forced subcategory auditing")) {
    New-Item -ItemType Directory -Path (Split-Path $gptTmplPath) -Force | Out-Null
    Set-Content -LiteralPath $gptTmplPath -Value $gptTmplLines -Encoding Unicode
}

if ($PSCmdlet.ShouldProcess($gpo.Path, 'Register Security + Advanced Audit Policy CSEs and increment GPO version')) {
    $adGpo = Get-ADObject -Identity $gpo.Path -Properties gPCMachineExtensionNames, versionNumber

    # Merge our two CSE pairs into any existing registrations, sorted by CSE GUID
    # (the format AD requires: [{CSE-GUID}{tool-GUID}...] groups, ascending).
    $groups = @{}
    $existingNames = ''
    if ($adGpo.PSObject.Properties['gPCMachineExtensionNames'] -and $adGpo.gPCMachineExtensionNames) {
        $existingNames = [string]$adGpo.gPCMachineExtensionNames
    }
    foreach ($match in [regex]::Matches($existingNames, '\[([^\]]+)\]')) {
        $guids = @([regex]::Matches($match.Groups[1].Value, '\{[0-9A-Fa-f-]{36}\}') | ForEach-Object { $_.Value.ToUpper() })
        if ($guids.Count -gt 0) { $groups[$guids[0]] = $guids }
    }
    foreach ($pair in $SecurityCsePair, $AuditCsePair) {
        $guids = @([regex]::Matches($pair, '\{[0-9A-Fa-f-]{36}\}') | ForEach-Object { $_.Value.ToUpper() })
        if ($groups.ContainsKey($guids[0])) {
            foreach ($tool in $guids[1..($guids.Count - 1)]) {
                if ($groups[$guids[0]] -notcontains $tool) { $groups[$guids[0]] += $tool }
            }
        }
        else {
            $groups[$guids[0]] = $guids
        }
    }
    $mergedNames = ($groups.Keys | Sort-Object | ForEach-Object { '[' + ($groups[$_] -join '') + ']' }) -join ''

    # Machine-settings change: +1 to versionNumber (low word = machine version),
    # mirrored into GPT.ini so clients detect the new version.
    $newVersion = [int]$adGpo.versionNumber + 1
    Set-ADObject -Identity $gpo.Path -Replace @{
        gPCMachineExtensionNames = $mergedNames
        versionNumber            = $newVersion
    }
    $gptIniPath = Join-Path $gpoSysvolPath 'GPT.ini'
    $gptIni = Get-Content -LiteralPath $gptIniPath
    $gptIni = $gptIni -replace '^Version=\d+', "Version=$newVersion"
    Set-Content -LiteralPath $gptIniPath -Value $gptIni -Encoding Ascii
    Write-Host "Registered CSEs and bumped GPO version to $newVersion"
}

# ---------------------------------------------------------------------------
# Link
# ---------------------------------------------------------------------------
if ($LinkTo) {
    foreach ($target in $LinkTo) {
        $existingLinks = (Get-ADObject -Identity $target -Properties gPLink -ErrorAction SilentlyContinue)
        $alreadyLinked = $existingLinks -and
            $existingLinks.PSObject.Properties['gPLink'] -and
            $existingLinks.gPLink -and
            ([string]$existingLinks.gPLink).ToUpper().Contains($gpo.Id.ToString('B').ToUpper())
        if ($alreadyLinked) {
            Write-Host "Already linked to $target"
            continue
        }
        if ($PSCmdlet.ShouldProcess($target, "Link GPO '$GpoName'")) {
            New-GPLink -Guid $gpo.Id -Target $target -LinkEnabled Yes | Out-Null
            Write-Host "Linked to $target"
        }
    }
}
else {
    Write-Warning "GPO is not linked anywhere yet. Link it with: New-GPLink -Name '$GpoName' -Target '<OU or domain DN>' -LinkEnabled Yes"
}

# ---------------------------------------------------------------------------
# Next steps
# ---------------------------------------------------------------------------
Write-Host @"

Done. Verify:
  - GPMC > '$GpoName' > Settings tab should show Advanced Audit Policy Configuration,
    Event Log sizes, and the 'Force audit policy subcategory settings' security option.
  - On a client after 'gpupdate /force':  auditpol /get /category:*
Out of scope for this GPO (see README_WindowsEventLogBaseline_Manual.md steps 4-6):
  PowerShell Module/ScriptBlock logging, command line in 4688 events, and the
  Task Scheduler / CAPI2 operational channels.
"@
