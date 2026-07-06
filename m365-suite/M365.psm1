# M365.psm1 — shared plumbing for the ClaudeJunk M365 CLI suite.
#
# Everything the tools need in common lives here: authentication against
# Microsoft Graph (interactive device-code for an admin at a keyboard, or
# app-only client-credentials for unattended runs), a REST wrapper that
# handles paging and throttling for you, and a single output helper so every
# tool exports to console / CSV / JSON the same way.
#
# Import once, then call the tools:  Import-Module ./M365.psm1
# Read-only by design — nothing in this module writes to a tenant.

$script:M365Token   = $null   # current bearer token (plain string)
$script:M365Expires = $null   # [datetime] UTC expiry
$script:M365Context = $null   # hashtable describing how we authenticated

$GraphBase = 'https://graph.microsoft.com/v1.0'

# The public "Microsoft Graph Command Line Tools" client id. It is a
# first-party, pre-consented public client, so device-code sign-in works in
# most tenants with no app registration of your own. Override with -ClientId
# when you have registered your own app.
$DefaultClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'

function Connect-M365 {
    <#
    .SYNOPSIS
        Sign in to Microsoft Graph for the current session.
    .DESCRIPTION
        Two modes:
          Device code (default) — prints a code, you finish sign-in in a
          browser. Best for an admin running the tools by hand.

          App-only — pass -ClientSecret (or -CertificateThumbprint is left as
          an exercise) with a registered app's -ClientId for unattended use.
    .EXAMPLE
        Connect-M365 -TenantId contoso.onmicrosoft.com
    .EXAMPLE
        Connect-M365 -TenantId <guid> -ClientId <guid> -ClientSecret <secret>
    #>
    [CmdletBinding(DefaultParameterSetName = 'Device')]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [string]$ClientId = $DefaultClientId,

        # App-only. When supplied, we skip the device-code dance.
        [Parameter(ParameterSetName = 'App')][string]$ClientSecret,

        # Delegated scopes to request in device-code mode. The defaults cover
        # everything the shipped tools read. App-only always uses ./default.
        [string[]]$Scopes = @(
            'User.Read.All', 'Directory.Read.All', 'AuditLog.Read.All',
            'Group.Read.All', 'Mail.Read', 'MailboxSettings.Read',
            'eDiscovery.Read.All', 'offline_access'
        )
    )

    $authority = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0"

    if ($PSCmdlet.ParameterSetName -eq 'App') {
        $body = @{
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = 'https://graph.microsoft.com/.default'
            grant_type    = 'client_credentials'
        }
        $tok = Invoke-RestMethod -Method Post -Uri "$authority/token" -Body $body -ErrorAction Stop
        $script:M365Token   = $tok.access_token
        $script:M365Expires = (Get-Date).ToUniversalTime().AddSeconds([int]$tok.expires_in - 120)
        $script:M365Context = @{ TenantId = $TenantId; ClientId = $ClientId; Mode = 'app-only'; ClientSecret = $ClientSecret; Refresh = $null }
        Write-Host "Connected to $TenantId (app-only)." -ForegroundColor Green
        return
    }

    # Device-code flow.
    $dc = Invoke-RestMethod -Method Post -Uri "$authority/devicecode" -Body @{
        client_id = $ClientId
        scope     = ($Scopes -join ' ')
    } -ErrorAction Stop

    Write-Host ""
    Write-Host $dc.message -ForegroundColor Yellow
    Write-Host ""

    $interval = [int]$dc.interval
    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            $tok = Invoke-RestMethod -Method Post -Uri "$authority/token" -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $ClientId
                device_code = $dc.device_code
            } -ErrorAction Stop
        } catch {
            # authorization_pending / slow_down come back as 400s; keep polling.
            $err = $null
            try { $err = ($_.ErrorDetails.Message | ConvertFrom-Json).error } catch {}
            if ($err -eq 'authorization_pending') { continue }
            if ($err -eq 'slow_down') { $interval += 5; continue }
            throw
        }
        $script:M365Token   = $tok.access_token
        $script:M365Expires = (Get-Date).ToUniversalTime().AddSeconds([int]$tok.expires_in - 120)
        $script:M365Context = @{ TenantId = $TenantId; ClientId = $ClientId; Mode = 'device'; Refresh = $tok.refresh_token }
        Write-Host "Connected to $TenantId." -ForegroundColor Green
        return
    }
    throw 'Device-code sign-in timed out.'
}

function Assert-M365Connected {
    if (-not $script:M365Token) {
        throw 'Not connected. Run Connect-M365 -TenantId <tenant> first.'
    }
    # Silent refresh for device-code sessions when the token has aged out.
    if ((Get-Date).ToUniversalTime() -ge $script:M365Expires) {
        $ctx = $script:M365Context
        if ($ctx.Mode -eq 'device' -and $ctx.Refresh) {
            $authority = "https://login.microsoftonline.com/$($ctx.TenantId)/oauth2/v2.0"
            $tok = Invoke-RestMethod -Method Post -Uri "$authority/token" -Body @{
                grant_type    = 'refresh_token'
                client_id     = $ctx.ClientId
                refresh_token = $ctx.Refresh
            } -ErrorAction Stop
            $script:M365Token       = $tok.access_token
            $script:M365Expires     = (Get-Date).ToUniversalTime().AddSeconds([int]$tok.expires_in - 120)
            $script:M365Context.Refresh = $tok.refresh_token
        } elseif ($ctx.Mode -eq 'app-only') {
            Connect-M365 -TenantId $ctx.TenantId -ClientId $ctx.ClientId -ClientSecret $ctx.ClientSecret
        } else {
            throw 'Token expired. Run Connect-M365 again.'
        }
    }
}

function Invoke-M365Graph {
    <#
    .SYNOPSIS
        Call a Microsoft Graph endpoint, following paging and backing off on 429.
    .DESCRIPTION
        Pass a path ('/users') or a full URL. GET requests auto-follow
        @odata.nextLink and return the concatenated .value collection (or the
        single object for non-collection responses). 429s are retried using
        the Retry-After header; transient 5xx get a short backoff.
    .EXAMPLE
        Invoke-M365Graph '/users?$select=displayName,userPrincipalName'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        $Body,
        [switch]$Beta,
        [int]$MaxRetry = 5
    )
    Assert-M365Connected

    $base = if ($Beta) { 'https://graph.microsoft.com/beta' } else { $GraphBase }
    $uri  = if ($Path -match '^https?://') { $Path } else { $base + $Path }

    $all = [System.Collections.Generic.List[object]]::new()
    while ($uri) {
        $headers = @{ Authorization = "Bearer $script:M365Token"; ConsistencyLevel = 'eventual' }
        $params  = @{ Method = $Method; Uri = $uri; Headers = $headers; ErrorAction = 'Stop' }
        if ($Body) { $params.Body = ($Body | ConvertTo-Json -Depth 12); $params.ContentType = 'application/json' }

        $attempt = 0
        while ($true) {
            try { $resp = Invoke-RestMethod @params; break }
            catch {
                $code = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
                $attempt++
                if ($code -eq 429 -and $attempt -le $MaxRetry) {
                    $wait = 5; try { $wait = [int]$_.Exception.Response.Headers['Retry-After'] } catch {}
                    Write-Verbose "Throttled; waiting ${wait}s"
                    Start-Sleep -Seconds ([Math]::Max($wait, 1)); continue
                }
                if ($code -ge 500 -and $attempt -le $MaxRetry) {
                    Start-Sleep -Seconds ([Math]::Min(2 * $attempt, 15)); continue
                }
                throw
            }
        }

        if ($null -ne $resp.value) { $all.AddRange([object[]]$resp.value) } elseif ($resp) { $all.Add($resp) }
        $uri = if ($Method -eq 'GET') { $resp.'@odata.nextLink' } else { $null }
    }
    return $all
}

function Export-M365Result {
    <#
    .SYNOPSIS
        Uniform output for every tool: console table, CSV, or JSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$InputObject,
        [ValidateSet('Table', 'Csv', 'Json')][string]$As = 'Table',
        [string]$Path
    )
    begin { $buf = [System.Collections.Generic.List[object]]::new() }
    process { foreach ($o in $InputObject) { $buf.Add($o) } }
    end {
        if ($buf.Count -eq 0) { Write-Host 'No results.' -ForegroundColor DarkGray; return }
        switch ($As) {
            'Csv'  { if ($Path) { $buf | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8; Write-Host "Wrote $($buf.Count) rows to $Path" -ForegroundColor Green } else { $buf | ConvertTo-Csv -NoTypeInformation } }
            'Json' { $json = $buf | ConvertTo-Json -Depth 8; if ($Path) { $json | Set-Content -Path $Path -Encoding UTF8; Write-Host "Wrote $($buf.Count) records to $Path" -ForegroundColor Green } else { $json } }
            default { $buf | Format-Table -AutoSize -Wrap }
        }
    }
}

Export-ModuleMember -Function Connect-M365, Assert-M365Connected, Invoke-M365Graph, Export-M365Result
