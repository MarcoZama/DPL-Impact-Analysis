<#
.SYNOPSIS
    Diagnostica: ispeziona la struttura reale degli agenti Copilot Studio in un
    environment per capire dove sono referenziati i connettori.

.DESCRIPTION
    Si autentica via Device Code (come lo script principale), fa scegliere UN
    environment e per ogni bot stampa:
      - botcomponents (componenttype, schemaname, nome, lunghezza content)
      - eventuali stringhe 'shared_' / 'connectorId' / 'connectionreference' trovate
      - relazioni bot_workflow (flow chiamati)
    Non modifica nulla. Serve solo a vedere la struttura dei dati.
#>

# ===========================================================================
# SCRIPT DIAGNOSTICO DISATTIVATO (commentato).
# Serviva solo per il reverse-engineering della struttura degli agenti
# Copilot Studio. La logica e' ora integrata in Analyze-DLPImpact.ps1.
# Per riattivarlo: rimuovere il blocco commento <# ... #> qui sotto.
# ===========================================================================
<#

param(
    [Parameter(Mandatory = $false)] [string]$TenantId,
    [Parameter(Mandatory = $false)] [int]$MaxContentDump = 1500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$settingsFile = Join-Path $PSScriptRoot "settings.json"
if (Test-Path $settingsFile) {
    $cfg = Get-Content $settingsFile -Raw | ConvertFrom-Json
    if (-not $TenantId -and $cfg.Auth.TenantId -notmatch '^0+(-0+)+$') { $TenantId = $cfg.Auth.TenantId }
}
if (-not $TenantId) { $TenantId = Read-Host "Tenant ID" }

$script:publicClientId = "1950a258-227b-4e31-a9cf-717495945fc2"
$script:refreshToken   = $null
$script:adminToken     = $null

function Invoke-DeviceCodeLogin {
    param([string]$Scope)
    $dcResp = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{ client_id = $script:publicClientId; scope = $Scope }
    Write-Host ""
    Write-Host "  $($dcResp.message)" -ForegroundColor Yellow
    Write-Host ""
    $deadline = (Get-Date).AddSeconds($dcResp.expires_in)
    do {
        Start-Sleep -Seconds $dcResp.interval
        try {
            $tok = Invoke-RestMethod -Method Post `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -ContentType "application/x-www-form-urlencoded" `
                -Body @{
                    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                    client_id   = $script:publicClientId
                    device_code = $dcResp.device_code
                }
            $script:adminToken   = $tok.access_token
            $script:refreshToken = $tok.refresh_token
            return
        } catch {
            $e = $_ | Select-Object -ExpandProperty ErrorDetails -ErrorAction SilentlyContinue
            if ($e -match "authorization_pending") { continue }
            throw
        }
    } until ((Get-Date) -gt $deadline)
    Write-Error "Autenticazione scaduta."
}

function Get-TokenForResource {
    param([string]$Resource)
    $resp = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "refresh_token"
            client_id     = $script:publicClientId
            refresh_token = $script:refreshToken
            scope         = "$Resource/.default"
        }
    $script:refreshToken = $resp.refresh_token
    return $resp.access_token
}

function Get-DvHeaders {
    param([string]$InstanceUrl)
    $token = Get-TokenForResource -Resource $InstanceUrl.TrimEnd("/")
    return @{
        Authorization      = "Bearer $token"
        "Content-Type"     = "application/json"
        "OData-MaxVersion" = "4.0"
        "OData-Version"    = "4.0"
    }
}

# ---- Login ----
Write-Host "[1/3] Login (Device Code)..." -ForegroundColor Cyan
Invoke-DeviceCodeLogin -Scope "https://service.powerapps.com/.default offline_access"
Write-Host "  OK" -ForegroundColor Green

# ---- Environment ----
Write-Host "[2/3] Environment..." -ForegroundColor Cyan
$bapH = @{ Authorization = "Bearer $script:adminToken"; "Content-Type" = "application/json" }
$bapResp = Invoke-RestMethod -Method Get `
    -Uri "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2019-05-01&`$expand=properties.linkedEnvironmentMetadata" `
    -Headers $bapH
$envs = @($bapResp.value | Where-Object { $_.properties.PSObject.Properties['linkedEnvironmentMetadata'] -and $_.properties.linkedEnvironmentMetadata.instanceUrl })

for ($i = 0; $i -lt $envs.Count; $i++) {
    Write-Host ("  {0,3}. {1}" -f ($i + 1), $envs[$i].properties.displayName)
}
$sel = [int](Read-Host "Seleziona environment")
$env = $envs[$sel - 1]
$url = $env.properties.linkedEnvironmentMetadata.instanceUrl.TrimEnd("/")
Write-Host "  -> $($env.properties.displayName)" -ForegroundColor Green

# ---- Dump POLICY connectors (id + nome + classificazione) ----
Write-Host "[POLICY] Connettori della prima DLP policy..." -ForegroundColor Cyan
try {
    $govH    = @{ Authorization = "Bearer $script:adminToken"; "Content-Type" = "application/json" }
    $govResp = Invoke-RestMethod -Method Get -Headers $govH `
        -Uri "https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v1/policies?`$top=100"
    $pol = $govResp.value | Select-Object -First 1
    Write-Host "  Policy: $($pol.displayName)" -ForegroundColor White
    foreach ($grp in $pol.connectorGroups) {
        Write-Host "  --- classification=$($grp.classification) ($($grp.connectors.Count) connettori) ---" -ForegroundColor Yellow
        foreach ($c in $grp.connectors) {
            # Mostra TUTTE le proprieta' per capire dove sta il display name
            $props = ($c.PSObject.Properties | Where-Object { $_.Name -notlike '*@*' } | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '  |  '
            if ($c.id -match 'copilot|cps|bot|knowledge|channel|skill|agent') {
                Write-Host "    [BUILTIN?] $props" -ForegroundColor Green
            } else {
                Write-Host "    $props" -ForegroundColor Gray
            }
        }
    }
} catch { Write-Host "  Errore policy: $_" -ForegroundColor Red }

# ---- Dump bots ----
Write-Host "[3/3] Ispezione bots..." -ForegroundColor Cyan
$h = Get-DvHeaders -InstanceUrl $url

$bots = Invoke-RestMethod -Method Get -Headers $h `
    -Uri "$url/api/data/v9.2/bots?`$select=botid,name,statecode,schemaname"
Write-Host "  Trovati $($bots.value.Count) bot (tutti gli stati)`n" -ForegroundColor White

foreach ($bot in $bots.value) {
    Write-Host ("=" * 80) -ForegroundColor DarkGray
    Write-Host "BOT: $($bot.name)  [state=$($bot.statecode)]  id=$($bot.botid)" -ForegroundColor Cyan

    # Tutti i componenti, con tipo e schema
    $comps = Invoke-RestMethod -Method Get -Headers $h `
        -Uri "$url/api/data/v9.2/botcomponents?`$filter=_parentbotid_value eq $($bot.botid)&`$select=name,componenttype,schemaname,content,data"
    Write-Host "  Componenti: $($comps.value.Count)" -ForegroundColor White

    $typeGroups = $comps.value | Group-Object componenttype | Sort-Object Name
    foreach ($g in $typeGroups) {
        Write-Host "    componenttype=$($g.Name): $($g.Count) componenti" -ForegroundColor Yellow
    }

    foreach ($comp in $comps.value) {
        $contentLen = if ($comp.PSObject.Properties['content'] -and $comp.content) { $comp.content.Length } else { 0 }
        $dataLen    = if ($comp.PSObject.Properties['data'] -and $comp.data) { $comp.data.Length } else { 0 }
        Write-Host "    - [$($comp.componenttype)] $($comp.name) | schema=$($comp.schemaname) | contentLen=$contentLen dataLen=$dataLen" -ForegroundColor Gray

        # Per componenti capability (knowledge/channel/file) mostra le prime righe del 'data'
        if ($dataLen -gt 0 -and $comp.schemaname -notmatch '\.topic\.') {
            $firstLines = ($comp.data -split "`n" | Select-Object -First 6) -join "`n              "
            Write-Host "        DATA(head):`n              $firstLines" -ForegroundColor DarkCyan
        }
    }

    # Relazione bot_workflow
    try {
        $wf = Invoke-RestMethod -Method Get -Headers $h `
            -Uri "$url/api/data/v9.2/bots($($bot.botid))/bot_workflow?`$select=workflowid,name,category"
        Write-Host "  bot_workflow collegati: $($wf.value.Count)" -ForegroundColor White
        foreach ($w in $wf.value) {
            Write-Host "    flow: $($w.name) (cat=$($w.category)) id=$($w.workflowid)" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  bot_workflow: relazione non disponibile ($($_.Exception.Message))" -ForegroundColor DarkYellow
    }

    # DUMP COMPLETO di un componente 'action' per scoprire dove vive il connettore
    $actionComp = $comps.value | Where-Object { $_.schemaname -match '\.action\.' } | Select-Object -First 1
    if ($actionComp) {
        Write-Host "  --- DUMP COMPLETO componente action: $($actionComp.name) ---" -ForegroundColor Magenta
        $full = Invoke-RestMethod -Method Get -Headers $h `
            -Uri "$url/api/data/v9.2/botcomponents?`$filter=schemaname eq '$($actionComp.schemaname)'"
        foreach ($rec in $full.value) {
            $rec.PSObject.Properties | Where-Object {
                $_.Value -and -not ($_.Name -like '*@*') -and "$($_.Value)".Trim() -ne ''
            } | ForEach-Object {
                $val = "$($_.Value)"
                if ($val.Length -gt 400) { $val = $val.Substring(0, 400) + '...[troncato]' }
                Write-Host "      $($_.Name) = $val" -ForegroundColor Gray
            }
        }
    }
}

Write-Host "`nFatto." -ForegroundColor Green
#>
