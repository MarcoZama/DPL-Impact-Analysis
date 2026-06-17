#Requires -Modules Microsoft.PowerApps.Administration.PowerShell

<#
.SYNOPSIS
    Analizza l'impatto di una DLP Policy su uno o piu' environment Power Platform.

.DESCRIPTION
    Flusso interattivo:
      1. Autenticazione tramite Device Code (un solo login, nessun popup)
      2. Selezione multipla degli environment da analizzare
      3. Registrazione automatica dello SPN negli environment selezionati
      4. Selezione della DLP Policy
      5. Analisi impatto su Flow e App Canvas

.PARAMETER TenantId
    ID del tenant Azure AD. Se omesso viene letto da settings.json.

.PARAMETER ApplicationId
    Client ID dello SPN. Se omesso viene letto da settings.json.

.PARAMETER ClientSecret
    Client Secret dello SPN. Se omesso viene letto da settings.json.

.PARAMETER OutputCsv
    Percorso file CSV di output. Default: cartella corrente con timestamp.

.EXAMPLE
    .\Analyze-DLPImpact.ps1
    .\Analyze-DLPImpact.ps1 -OutputCsv "C:\Reports\dlp.csv"
#>

param(
    [Parameter(Mandatory = $false)] [string]$TenantId,
    [Parameter(Mandatory = $false)] [string]$ApplicationId,
    [Parameter(Mandatory = $false)] [string]$ClientSecret,
    [Parameter(Mandatory = $false)] [string]$OutputCsv,
    [Parameter(Mandatory = $false)] [string]$DebugFolder,
    [Parameter(Mandatory = $false)] [switch]$ShowAllResources   # Include nel CSV anche risorse senza connettori
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Caricamento settings.json
# ---------------------------------------------------------------------------
$settingsFile = Join-Path $PSScriptRoot "settings.json"
if (Test-Path $settingsFile) {
    $cfg = Get-Content $settingsFile -Raw | ConvertFrom-Json
    if (-not $TenantId      -and $cfg.Auth.TenantId      -notmatch '^0+(-0+)+$') { $TenantId      = $cfg.Auth.TenantId }
    if (-not $ApplicationId -and $cfg.Auth.ApplicationId -notmatch '^0+(-0+)+$') { $ApplicationId = $cfg.Auth.ApplicationId }
    if (-not $ClientSecret  -and $cfg.Auth.ClientSecret  -ne "your-client-secret-here") { $ClientSecret = $cfg.Auth.ClientSecret }
    if (-not $OutputCsv) {
        $folder    = if ($cfg.Output.CsvFolder) { $cfg.Output.CsvFolder } else { "." }
        if (-not [System.IO.Path]::IsPathRooted($folder)) { $folder = Join-Path $PSScriptRoot $folder }
        $OutputCsv = Join-Path $folder "DLP_Impact_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    }
    if (-not $DebugFolder -and $cfg.Output.DebugFolder) { $DebugFolder = $cfg.Output.DebugFolder }
}
if (-not $OutputCsv) { $OutputCsv = ".\DLP_Impact_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
if (-not $DebugFolder) { $DebugFolder = "debug" }
if (-not [System.IO.Path]::IsPathRooted($DebugFolder)) { $DebugFolder = Join-Path $PSScriptRoot $DebugFolder }

# ---------------------------------------------------------------------------
# Avvio log di debug (transcript)
# ---------------------------------------------------------------------------
if (-not (Test-Path $DebugFolder)) { New-Item -ItemType Directory -Force -Path $DebugFolder | Out-Null }
$DebugLog = Join-Path $DebugFolder "DLP_Debug_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
try { Start-Transcript -Path $DebugLog -Force | Out-Null } catch { }

# ---------------------------------------------------------------------------
# Helpers — UI
# ---------------------------------------------------------------------------

function Show-Menu {
    # Selezione singola
    param([object[]]$Items, [string]$DisplayProp, [string]$SubProp = "", [string]$Title)

    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $sub = if ($SubProp) { " [$($Items[$i].$SubProp)]" } else { "" }
        Write-Host ("  {0,3}. {1}{2}" -f ($i + 1), $Items[$i].$DisplayProp, $sub) -ForegroundColor White
    }
    Write-Host ""
    do {
        $raw = Read-Host "  Seleziona numero (1-$($Items.Count))"
        $n   = 0
        $ok  = [int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le $Items.Count
        if (-not $ok) { Write-Host "  Input non valido, riprova." -ForegroundColor Red }
    } while (-not $ok)
    return $Items[$n - 1]
}

function Show-MultiMenu {
    # Selezione multipla: numeri separati da virgola, oppure "tutti" / "*"
    param([object[]]$Items, [string]$DisplayProp, [string]$SubProp = "", [string]$Title)

    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $sub = if ($SubProp) { " [$($Items[$i].$SubProp)]" } else { "" }
        Write-Host ("  {0,3}. {1}{2}" -f ($i + 1), $Items[$i].$DisplayProp, $sub) -ForegroundColor White
    }
    Write-Host ""
    Write-Host "  Puoi selezionare piu' voci separando i numeri con virgola (es: 1,3,5)" -ForegroundColor DarkGray
    Write-Host "  Oppure digita '*' per selezionarli tutti." -ForegroundColor DarkGray
    Write-Host ""

    do {
        $raw = Read-Host "  Selezione"
        if ($raw -eq '*') {
            return $Items
        }
        $parts  = $raw -split ',' | ForEach-Object { $_.Trim() }
        $nums   = @()
        $valid  = $true
        foreach ($p in $parts) {
            $n = 0
            if ([int]::TryParse($p, [ref]$n) -and $n -ge 1 -and $n -le $Items.Count) {
                $nums += $n
            } else {
                $valid = $false; break
            }
        }
        if (-not $valid -or $nums.Count -eq 0) {
            Write-Host "  Input non valido, riprova." -ForegroundColor Red
            $valid = $false
        }
    } while (-not $valid)

    return @($nums | Sort-Object -Unique | ForEach-Object { $Items[$_ - 1] })
}

# ---------------------------------------------------------------------------
# Helpers — Auth
# ---------------------------------------------------------------------------

$script:publicClientId = "1950a258-227b-4e31-a9cf-717495945fc2"
$script:refreshToken   = $null
$script:adminToken     = $null

function Invoke-DeviceCodeLogin {
    param([string]$Scope)

    $dcResp = Invoke-RestMethod `
        -Method Post `
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
            $tok = Invoke-RestMethod `
                -Method Post `
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
    $resp = Invoke-RestMethod `
        -Method Post `
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

# ---------------------------------------------------------------------------
# Helpers — SPN registration
# ---------------------------------------------------------------------------

function Register-SPNInEnvironment {
    param([string]$EnvDisplayName, [string]$InstanceUrl)

    $url = $InstanceUrl.TrimEnd("/")
    try { $token = Get-TokenForResource -Resource $url }
    catch {
        Write-Host "    SKIP — token non ottenuto: $_" -ForegroundColor Yellow
        return
    }

    $h = @{
        Authorization      = "Bearer $token"
        "Content-Type"     = "application/json"
        "OData-MaxVersion" = "4.0"
        "OData-Version"    = "4.0"
    }

    # Controlla se gia' registrato
    try {
        $existing = Invoke-RestMethod -Method Get `
            -Uri "$url/api/data/v9.2/systemusers?`$filter=applicationid eq '$ApplicationId'&`$select=systemuserid" `
            -Headers $h
    } catch {
        Write-Host "    SKIP — accesso Dataverse negato (aggiungi 'Dynamics CRM Application' permission allo SPN)" -ForegroundColor Yellow
        return
    }

    # Business Unit root e ruoli target
    $bu      = Invoke-RestMethod -Method Get -Uri "$url/api/data/v9.2/businessunits?`$filter=_parentbusinessunitid_value eq null&`$select=businessunitid" -Headers $h
    $rootBu  = $bu.value[0].businessunitid
    $roles   = Invoke-RestMethod -Method Get `
        -Uri "$url/api/data/v9.2/roles?`$filter=(name eq 'System Administrator' or name eq 'Environment Admin') and _businessunitid_value eq $rootBu&`$select=roleid,name" `
        -Headers $h
    $targetRoles = $roles.value

    if ($existing.value.Count -gt 0) {
        $userId = $existing.value[0].systemuserid
        $assigned = Invoke-RestMethod -Method Get `
            -Uri "$url/api/data/v9.2/systemusers($userId)/systemuserroles_association?`$select=roleid" -Headers $h
        $missing = @($targetRoles | Where-Object { $r = $_; -not ($assigned.value | Where-Object { $_.roleid -eq $r.roleid }) })
        if ($missing.Count -eq 0) {
            Write-Host "    OK — gia' registrato con tutti i ruoli" -ForegroundColor Green
        } else {
            foreach ($role in $missing) {
                $ref = @{ "@odata.id" = "$url/api/data/v9.2/roles($($role.roleid))" } | ConvertTo-Json
                Invoke-RestMethod -Method Post -Uri "$url/api/data/v9.2/systemusers($userId)/systemuserroles_association/`$ref" -Headers $h -Body $ref | Out-Null
                Write-Host "    Ruolo aggiunto: $($role.name)" -ForegroundColor Yellow
            }
            Write-Host "    OK — ruoli aggiornati" -ForegroundColor Green
        }
        return
    }

    # Crea application user
    $body = @{
        applicationid    = $ApplicationId
        firstname        = "DLP"; lastname = "Analyzer SPN"
        accessmode       = 4; isdisabled = $false
        "businessunitid@odata.bind" = "/businessunits($rootBu)"
    } | ConvertTo-Json
    $h["Prefer"] = "return=representation"
    $newUser = Invoke-RestMethod -Method Post -Uri "$url/api/data/v9.2/systemusers" -Headers $h -Body $body
    $h.Remove("Prefer")
    $userId = $newUser.systemuserid

    foreach ($role in $targetRoles) {
        $ref = @{ "@odata.id" = "$url/api/data/v9.2/roles($($role.roleid))" } | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri "$url/api/data/v9.2/systemusers($userId)/systemuserroles_association/`$ref" -Headers $h -Body $ref | Out-Null
    }
    Write-Host "    CREATO con ruoli: $(($targetRoles | ForEach-Object { $_.name }) -join ', ')" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Helpers — Dataverse resource retrieval
# ---------------------------------------------------------------------------

function Get-DataverseHeaders {
    param([string]$InstanceUrl)
    $token = Get-TokenForResource -Resource $InstanceUrl.TrimEnd("/")
    return @{
        Authorization      = "Bearer $token"
        "Content-Type"     = "application/json"
        "OData-MaxVersion" = "4.0"
        "OData-Version"    = "4.0"
    }
}

function Get-DataverseAll {
    # Recupera TUTTE le righe seguendo @odata.nextLink.
    # La Dataverse Web API NON supporta $skip: la paginazione si fa con
    # l'header 'Prefer: odata.maxpagesize' e il link @odata.nextLink nella risposta.
    param([hashtable]$Headers, [string]$Uri, [int]$PageSize = 5000)

    $h = @{} + $Headers
    $h["Prefer"] = "odata.maxpagesize=$PageSize"
    $all  = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    do {
        $resp = Invoke-RestMethod -Method Get -Headers $h -Uri $next
        if ($resp.PSObject.Properties['value'] -and $resp.value) {
            foreach ($v in $resp.value) { $all.Add($v) }
        }
        # Sotto Set-StrictMode, accedere a una proprieta' assente lancia: usa PSObject.Properties
        $linkProp = $resp.PSObject.Properties['@odata.nextLink']
        $next = if ($linkProp) { $linkProp.Value } else { $null }
    } while ($next)
    return $all
}

function Get-EnvBots {
    # Recupera gli agenti Copilot Studio (bots) via Dataverse API
    param([string]$InstanceUrl)
    $url = $InstanceUrl.TrimEnd("/")
    try {
        $h    = Get-DataverseHeaders -InstanceUrl $url
        $resp = Invoke-RestMethod -Method Get -Headers $h `
            -Uri "$url/api/data/v9.2/bots?`$select=botid,name,_ownerid_value,statecode,schemaname&`$filter=statecode eq 0"
        return @($resp.value)
    } catch {
        Write-Warning "    Impossibile recuperare bots da Dataverse: $_"
        return @()
    }
}

function Get-BotConnectorIds {
    # Estrae gli ID connettore di un agente Copilot Studio.
    #
    # Struttura reale (verificata via Dataverse):
    #   - I connettori NON sono nel campo 'content' (sempre vuoto) ma nel campo 'data' (YAML).
    #   - I componenti azione sono componenttype=9 con '.action.' nello schemaname.
    #   - Il riferimento connettore vive nel 'data' come:
    #       action:
    #         connectionReference: <prefix>.shared_<connettore>.<guid>
    #   - Esistono anche trigger esterni (componenttype=17) e altri componenti che
    #     possono referenziare connettori nel 'data'.
    #
    # Fonti:
    #   1. Campo 'data' di TUTTI i botcomponents — regex su shared_/connectorId/providers
    #   2. ExternalTriggerComponent (trigger da flow, es. "When a new email arrives")
    #   3. Flow collegati via relazione bot_workflow (fallback, spesso non disponibile)
    param([string]$BotId, [string]$InstanceUrl)
    $url = $InstanceUrl.TrimEnd("/")
    $connIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Connettore base implicito: OGNI agente Copilot Studio dipende dalla piattaforma
    # "Microsoft Copilot Studio" (shared_microsoftcopilotstudio), anche se non referenzia
    # alcun connettore esplicito. Se questo connettore e' Blocked/classificato nella policy,
    # anche un agente "vuoto" risulta correttamente impattato.
    [void]$connIds.Add("/providers/Microsoft.PowerApps/apis/shared_microsoftcopilotstudio")

    # Helper locale: estrae tutti i shared_xxx da una stringa YAML/JSON e li normalizza
    $addFromText = {
        param([string]$text)
        if (-not $text) { return }
        # a) connectionReference: prefix.shared_xxx.guid  → cattura shared_xxx
        [regex]::Matches($text, '(?i)connectionReference\s*:\s*[''"]?[^\s''".]+\.(shared_[a-z0-9]+)\.') |
            ForEach-Object { [void]$connIds.Add("/providers/Microsoft.PowerApps/apis/$($_.Groups[1].Value)") }
        # b) qualsiasi shared_xxx generico nel testo
        [regex]::Matches($text, '(?i)(?<![a-z0-9_])shared_[a-z0-9]+') |
            ForEach-Object { [void]$connIds.Add("/providers/Microsoft.PowerApps/apis/$($_.Value)") }
        # c) percorso provider completo
        [regex]::Matches($text, '(?i)/providers/Microsoft\.PowerApps/apis/shared_[a-z0-9]+') |
            ForEach-Object { [void]$connIds.Add($_.Value) }
        # d) connectorId esplicito
        [regex]::Matches($text, '(?i)connectorId[''"]?\s*:\s*[''"]?(/providers/Microsoft\.PowerApps/apis/[^\s''">\r\n,]+)') |
            ForEach-Object { [void]$connIds.Add($_.Groups[1].Value.TrimEnd('/,')) }
    }

    # Helper locale: rileva le capability BUILT-IN di Copilot Studio (knowledge source,
    # web browsing, ecc.) ed aggiunge gli ID connettore "speciali" usati nelle policy DLP.
    # Questi ID NON sono 'shared_xxx' ma identificatori dedicati (es. CSKnowledgeDocs).
    $addBuiltin = {
        param([object]$comp, [string]$data)
        $ctype  = Get-Prop $comp 'componenttype'
        $schema = [string](Get-Prop $comp 'schemaname')
        $text   = [string]$data

        # Knowledge source con DOCUMENTI: componente file (componenttype=14) oppure
        # schemaname con '.file.' (es. employee_handbook.pdf)
        if ($ctype -eq 14 -or $schema -match '(?i)\.file\.') {
            [void]$connIds.Add("CSKnowledgeDocs")
        }
        # Knowledge source con SITI WEB PUBBLICI: capability gptCapabilities.webBrowsing = true
        if ($text -match '(?i)webBrowsing\s*:\s*true') {
            [void]$connIds.Add("CSKnowledgePublicSites")
        }
        # Knowledge source pubblica per riferimenti espliciti a siti web/url
        if ($text -match '(?i)kind\s*:\s*(PublicWebsite|WebSearch|BingCustomSearch)') {
            [void]$connIds.Add("CSKnowledgePublicSites")
        }
        # Knowledge source SharePoint / OneDrive
        if ($text -match '(?i)kind\s*:\s*(SharePoint|OneDrive)' -or $text -match '(?i)sharepoint.*knowledge|knowledge.*sharepoint') {
            [void]$connIds.Add("CSKnowledgeSharePoint")
        }
    }

    try {
        $h = Get-DataverseHeaders -InstanceUrl $url

        # Fonte 1+2: tutti i botcomponents con il campo 'data' (YAML)
        $comps = Invoke-RestMethod -Method Get -Headers $h `
            -Uri "$url/api/data/v9.2/botcomponents?`$filter=_parentbotid_value eq $BotId&`$select=name,componenttype,schemaname,data"
        foreach ($comp in $comps.value) {
            $data = Get-Prop $comp 'data'
            if ($data) { & $addFromText $data }
            # alcuni componenti espongono ancora 'content'
            $content = Get-Prop $comp 'content'
            if ($content) { & $addFromText $content }
            # rileva capability built-in (knowledge source, web browsing, ...)
            & $addBuiltin $comp $data
        }

        # Fonte 3: flow collegati via relazione bot_workflow (se disponibile)
        try {
            $wfResp = Invoke-RestMethod -Method Get -Headers $h `
                -Uri "$url/api/data/v9.2/bots($BotId)/bot_workflow?`$select=workflowid,clientdata"
            foreach ($wf in $wfResp.value) {
                $cd = Get-Prop $wf 'clientdata'
                if ($cd) { & $addFromText $cd }
            }
        } catch {}

    } catch {
        Write-Warning "      Get-BotConnectorIds errore: $_"
    }

    return @($connIds)
}

function Get-BotOwnerUpn {
    # Recupera lo UPN del proprietario del bot tramite systemusers
    param([string]$OwnerId, [string]$InstanceUrl)
    if (-not $OwnerId) { return "" }
    $url = $InstanceUrl.TrimEnd("/")
    try {
        $h    = Get-DataverseHeaders -InstanceUrl $url
        $resp = Invoke-RestMethod -Method Get -Headers $h `
            -Uri "$url/api/data/v9.2/systemusers($OwnerId)?`$select=internalemailaddress"
        return $resp.internalemailaddress
    } catch { return "" }
}

# ---------------------------------------------------------------------------
# Helpers — DLP analysis
# ---------------------------------------------------------------------------

function Get-Prop {
    # Accesso sicuro a una proprieta' sotto Set-StrictMode -Version Latest:
    # restituisce $null se l'oggetto e' null o la proprieta' non esiste (invece di lanciare).
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-ConnectorIdsFromClientData {
    # Estrae gli ID connettore dalla definizione JSON di un flow/app (clientdata Dataverse)
    # Strutture supportate:
    #   A) { properties: { connectionReferences: { key: { api: { id: "..." } } } } }  — solution-aware flow
    #   B) { connectionReferences: { key: { api: { id: "..." } } } }                  — variante
    #   C) { properties: { parameters: { $connections: { value: { key: { id: "..." } } } } } } — flow diretto (non-solution)
    #   D) regex fallback su tutto il JSON
    param([string]$ClientData)
    if (-not $ClientData) { return @() }

    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $def = $null
    try { $def = $ClientData | ConvertFrom-Json -ErrorAction Stop } catch {}

    if ($def) {
        # Struttura A/B: connectionReferences
        $refs = Get-Prop (Get-Prop $def 'properties') 'connectionReferences'
        if (-not $refs) { $refs = Get-Prop $def 'connectionReferences' }
        if ($refs) {
            $refs.PSObject.Properties.Value | ForEach-Object {
                $api = Get-Prop $_ 'api'
                $apiId   = Get-Prop $api 'id'
                $apiName = Get-Prop $api 'name'
                $rawId   = Get-Prop $_ 'id'
                if ($apiId) { [void]$ids.Add($apiId) }
                elseif ($apiName -and $apiName -match '^shared_') {
                    [void]$ids.Add("/providers/Microsoft.PowerApps/apis/$apiName")
                }
                elseif ($rawId -and ($rawId -match '/providers/Microsoft\.PowerApps/apis/')) { [void]$ids.Add($rawId) }
            }
        }

        # Struttura C: parameters.$connections.value (flow con connessioni dirette/non-solution)
        $connParams = Get-Prop (Get-Prop (Get-Prop $def 'properties') 'parameters') '$connections'
        if (-not $connParams) {
            $connParams = Get-Prop (Get-Prop $def 'parameters') '$connections'
        }
        $connVal = Get-Prop $connParams 'value'
        if ($connVal) {
            $connVal.PSObject.Properties.Value | ForEach-Object {
                $rawId = Get-Prop $_ 'id'
                if ($rawId -and ($rawId -match '/providers/Microsoft\.PowerApps/apis/')) { [void]$ids.Add($rawId) }
            }
        }
    }

    # Struttura D: regex fallback — cattura qualsiasi shared_ connector nel JSON grezzo
    if ($ids.Count -eq 0) {
        [regex]::Matches($ClientData, '(?i)/providers/Microsoft\.PowerApps/apis/shared_[a-z0-9_]+') |
            ForEach-Object { [void]$ids.Add($_.Value) }
        # Formato solution-aware: "name": "shared_xxx" dentro il blocco "api"
        [regex]::Matches($ClientData, '(?i)"api"\s*:\s*\{[^{}]*"name"\s*:\s*"(shared_[a-z0-9_]+)"') |
            ForEach-Object { [void]$ids.Add("/providers/Microsoft.PowerApps/apis/$($_.Groups[1].Value)") }
    }

    return @($ids)
}

function Get-ConnectorGroup {
    param([string]$ConnectorId, [object]$Policy)
    foreach ($group in $Policy.connectorGroups) {
        if ($group.connectors | Where-Object { $_.id -eq $ConnectorId }) { return $group.classification }
    }
    return "Unclassified"
}

function Get-ConnectorName {
    # Restituisce il display name del connettore (es. "Office 365 Outlook") a partire dal suo ID.
    # La policy espone id+name per ogni connettore. Fallback: nome breve estratto dall'ID.
    param([string]$ConnectorId, [object]$Policy)
    foreach ($group in $Policy.connectorGroups) {
        $match = $group.connectors | Where-Object { $_.id -eq $ConnectorId } | Select-Object -First 1
        if ($match) {
            $nameProp = $match.PSObject.Properties['name']
            if ($nameProp -and $nameProp.Value) { return $nameProp.Value }
        }
    }
    # Fallback: ultima parte dell'ID, senza prefisso shared_
    $short = ($ConnectorId -split '/')[-1]
    return ($short -replace '^shared_', '')
}

function Test-DlpViolation {
    param([string[]]$ConnectorIds, [object]$Policy)
    $groups = @($ConnectorIds | ForEach-Object { Get-ConnectorGroup $_ $Policy } | Sort-Object -Unique)
    # Blocked e' sempre violazione
    if ("Blocked" -in $groups) { return $true }
    # Mix di gruppi classificati diversi non e' consentito (es. General + Confidential)
    $classified = @($groups | Where-Object { $_ -ne "Unclassified" -and $_ -ne "Blocked" })
    if ($classified.Count -gt 1) { return $true }
    return $false
}

function Get-ViolationReason {
    param([string[]]$ConnectorIds, [object]$Policy)
    $groups = @($ConnectorIds | ForEach-Object { Get-ConnectorGroup $_ $Policy } | Sort-Object -Unique)
    if ("Blocked" -in $groups) {
        $blockedConns = @($ConnectorIds | Where-Object { (Get-ConnectorGroup $_ $Policy) -eq "Blocked" } | ForEach-Object { Get-ConnectorName $_ $Policy })
        return "Connettore bloccato: $($blockedConns -join ', ')"
    }
    $classified = @($groups | Where-Object { $_ -ne "Unclassified" -and $_ -ne "Blocked" })
    if ($classified.Count -gt 1) {
        return "Mix gruppi non compatibili: $($classified -join ' + ')"
    }
    return ""
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   DLP Impact Analysis - Power Platform  " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# STEP 1 — Moduli
Write-Host "[1/5] Verifica moduli PowerShell..." -ForegroundColor Cyan
if (-not (Get-Module -ListAvailable -Name "Microsoft.PowerApps.Administration.PowerShell")) {
    Install-Module "Microsoft.PowerApps.Administration.PowerShell" -Scope CurrentUser -Force -AllowClobber
}
Import-Module "Microsoft.PowerApps.Administration.PowerShell" -WarningAction SilentlyContinue
Import-Module "Microsoft.PowerApps.PowerShell"                -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

# STEP 2 — Auth device code
Write-Host ""
Write-Host "[2/5] Autenticazione (Device Code)..." -ForegroundColor Cyan
if (-not $TenantId) { $TenantId = Read-Host "  Tenant ID" }
Invoke-DeviceCodeLogin -Scope "https://service.powerapps.com/.default offline_access"
Write-Host "  Login completato." -ForegroundColor Green

# Autentica anche il modulo PowerApps con SPN (per Get-AdminDlpPolicy, Get-AdminFlow, ecc.)
if ($ApplicationId -and $ClientSecret) {
    $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    try   { Add-PowerAppsAccount -TenantID $TenantId -ApplicationId $ApplicationId -ClientSecret $sec      -Endpoint "prod" }
    catch { Add-PowerAppsAccount -TenantID $TenantId -ApplicationId $ApplicationId -ClientSecret $ClientSecret -Endpoint "prod" }
}

# STEP 3 — Selezione environment (multipla)
Write-Host ""
Write-Host "[3/5] Recupero environment del tenant..." -ForegroundColor Cyan
$bapH    = @{ Authorization = "Bearer $script:adminToken"; "Content-Type" = "application/json" }
$bapResp = Invoke-RestMethod -Method Get `
    -Uri "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2019-05-01&`$expand=properties.linkedEnvironmentMetadata" `
    -Headers $bapH
$allEnvs = @($bapResp.value | ForEach-Object {
    $_ | Add-Member -NotePropertyName "DisplayLabel" `
                    -NotePropertyValue "$($_.properties.displayName) [$($_.properties.environmentSku)]" `
                    -PassThru -Force
})

if ($allEnvs.Count -eq 0) { Write-Error "Nessun environment trovato nel tenant." }
Write-Host "  Trovati $($allEnvs.Count) environment."

$selectedEnvs = Show-MultiMenu `
    -Items       $allEnvs `
    -DisplayProp "DisplayLabel" `
    -Title       "Seleziona gli environment da analizzare:"

Write-Host ""
Write-Host "  Environment selezionati:" -ForegroundColor Yellow
$selectedEnvs | ForEach-Object { Write-Host "    - $($_.properties.displayName)" -ForegroundColor White }

# STEP 4 — Registra SPN negli environment selezionati
Write-Host ""
Write-Host "[4/5] Registrazione SPN negli environment selezionati..." -ForegroundColor Cyan
foreach ($env in $selectedEnvs) {
    $instanceUrl = $env.properties.linkedEnvironmentMetadata.instanceUrl
    if (-not $instanceUrl) {
        Write-Host "  $($env.properties.displayName) — SKIP (nessuna istanza Dataverse)" -ForegroundColor DarkGray
        continue
    }
    Write-Host "  $($env.properties.displayName)" -ForegroundColor White
    Register-SPNInEnvironment -EnvDisplayName $env.properties.displayName -InstanceUrl $instanceUrl
}

# STEP 5a — Selezione DLP Policy (via governance REST API con token admin)
Write-Host ""
Write-Host "[5/5] Recupero DLP Policy del tenant..." -ForegroundColor Cyan

$govH      = @{ Authorization = "Bearer $script:adminToken"; "Content-Type" = "application/json" }
$govResp   = Invoke-RestMethod -Method Get -Headers $govH `
    -Uri "https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v1/policies?`$top=100"
$rawPolicies = @($govResp.value)

if ($rawPolicies.Count -eq 0) {
    Write-Host "  Nessuna DLP Policy trovata. Creane una su:" -ForegroundColor Red
    Write-Host "  https://admin.powerplatform.microsoft.com/dlp-policies" -ForegroundColor DarkGray
    exit 1
}

# Per ogni policy recupera i dettagli completi (connectorGroups con classificazioni)
Write-Host "  Trovate $($rawPolicies.Count) policy."

# L'oggetto restituito dalla list API contiene gia' tutto: name, displayName, connectorGroups, environments
$allPolicies = @($rawPolicies | ForEach-Object {
    [PSCustomObject]@{
        DisplayName     = $_.displayName
        PolicyName      = $_.name
        connectorGroups = $_.connectorGroups
        environments    = $_.environments
    }
})

$selectedPolicy = Show-Menu `
    -Items       $allPolicies `
    -DisplayProp "DisplayName" `
    -SubProp     "PolicyName" `
    -Title       "Seleziona la DLP Policy da analizzare:"

# Mostra scope della policy (tutti gli env o solo specifici)
$policyScope = if ($selectedPolicy.environments -and $selectedPolicy.environments.Count -gt 0) {
    "Solo $($selectedPolicy.environments.Count) environment specifici"
} else { "Tutti gli environment del tenant" }
$blockedCount  = @($selectedPolicy.connectorGroups | Where-Object { $_.classification -eq "Blocked" }  | ForEach-Object { $_.connectors }).Count
$businessCount = @($selectedPolicy.connectorGroups | Where-Object { $_.classification -eq "Business" } | ForEach-Object { $_.connectors }).Count
$nonBizCount   = @($selectedPolicy.connectorGroups | Where-Object { $_.classification -eq "NonBusiness" } | ForEach-Object { $_.connectors }).Count

Write-Host ""
Write-Host "  Policy selezionata : $($selectedPolicy.DisplayName)" -ForegroundColor Yellow
Write-Host "  Scope              : $policyScope"                   -ForegroundColor DarkGray
Write-Host "  Connettori Business: $businessCount | NonBusiness: $nonBizCount | Blocked: $blockedCount" -ForegroundColor DarkGray

# STEP 5b — Analisi impatto su tutti gli environment selezionati
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($env in $selectedEnvs) {
    $envId   = $env.name
    $envName = $env.properties.displayName

    Write-Host ""
    Write-Host "  Analisi: $envName" -ForegroundColor Cyan

    $instanceUrl = $env.properties.linkedEnvironmentMetadata.instanceUrl

    # Flow e App via Dataverse (workflows table, category=5) — API non deprecata
    $dvH   = if ($instanceUrl) { Get-DataverseHeaders -InstanceUrl $instanceUrl } else { $null }

    $flows = @()
    $apps  = @()
    $connRefLookup    = @{}   # workflowid -> [connectorId, ...]
    $connRefByLogName = @{}   # connectionreferencelogicalname -> connectorid
    if ($dvH -and $instanceUrl) {
        $url = $instanceUrl.TrimEnd("/")
        $pageSize = 250

        # Cloud flow = category 5
        try {
            $flows = @(Get-DataverseAll -Headers $dvH -PageSize $pageSize `
                -Uri "$url/api/data/v9.2/workflows?`$filter=category eq 5&`$select=workflowid,name,clientdata,_ownerid_value,statecode,modifiedon")
            Write-Host "    Trovati $($flows.Count) flow da Dataverse."
        } catch { Write-Warning "    Impossibile recuperare flows da Dataverse: $_" }

        # Canvas App = category 9
        try {
            $apps = @(Get-DataverseAll -Headers $dvH -PageSize $pageSize `
                -Uri "$url/api/data/v9.2/workflows?`$filter=category eq 9&`$select=workflowid,name,clientdata,_ownerid_value,statecode")
            Write-Host "    Trovate $($apps.Count) app Canvas da Dataverse."
        } catch { Write-Warning "    Impossibile recuperare apps da Dataverse: $_" }

        # Leggi connectionreferences in blocco — mappa connectionreferencelogicalname -> connectorId.
        # NB: la tabella 'connectionreference' NON ha un lookup diretto al workflow,
        # quindi la risoluzione avviene per logical name (riferito nel clientdata del flow/app).
        try {
            $allCR = @(Get-DataverseAll -Headers $dvH -PageSize $pageSize `
                -Uri "$url/api/data/v9.2/connectionreferences?`$select=connectorid,connectionreferencelogicalname")
            foreach ($cr in $allCR) {
                if ($cr.connectionreferencelogicalname -and $cr.connectorid) {
                    $connRefByLogName[$cr.connectionreferencelogicalname] = $cr.connectorid
                }
            }
            Write-Host "    ConnectionReferences caricate: $($allCR.Count) voci."
        } catch { Write-Warning "    Impossibile recuperare connectionreferences: $_" }
    } else {
        Write-Warning "    Environment senza Dataverse — flow e app non analizzabili"
    }

    $bots = if ($instanceUrl) { Get-EnvBots -InstanceUrl $instanceUrl } else { @() }
    Write-Host "    Flow: $($flows.Count)  |  App Canvas: $($apps.Count)  |  Agenti: $($bots.Count)"

    $total = $flows.Count + $apps.Count + $bots.Count; $counter = 0

    # --- FLOWS (da Dataverse workflows category=5, clientdata contiene connectionReferences) ---
    foreach ($flow in $flows) {
        $counter++
        Write-Progress -Activity "Analisi $envName" -Status "Flow: $($flow.name)" `
                       -PercentComplete ([math]::Round($counter / [math]::Max($total,1) * 100))
        try {
            # Priorita' 1: connectionreferences lookup (diretto, affidabile)
            $connIds = if ($connRefLookup[$flow.workflowid]) { @($connRefLookup[$flow.workflowid]) } else { @() }
            # Fallback: parse clientdata JSON (strutture A/B/C + regex)
            if (-not $connIds) { $connIds = @(Get-ConnectorIdsFromClientData -ClientData $flow.clientdata) }
            # Fallback: cerca connectionReferenceLogicalName nel clientdata e risolve tramite lookup
            if (-not $connIds -and $flow.clientdata -and $connRefByLogName.Count -gt 0) {
                $logMatches = [regex]::Matches($flow.clientdata, '"connectionReferenceLogicalName"\s*:\s*"([^"]+)"')
                $logIds = @($logMatches | ForEach-Object { $connRefByLogName[$_.Groups[1].Value] } | Where-Object { $_ })
                if ($logIds.Count -gt 0) { $connIds = $logIds }
            }

            Write-Host ("      Flow: {0,-40} connettori: {1}" -f $flow.name, $(if ($connIds) { $connIds.Count } else { "nessuno" })) -ForegroundColor $(if ($connIds) { "White" } else { "DarkGray" })

            if (-not $connIds) {
                if ($ShowAllResources) {
                    $results.Add([PSCustomObject]@{
                        PolicyName="$($selectedPolicy.DisplayName)"; PolicyId="$($selectedPolicy.PolicyName)"
                        EnvironmentName=$envName; EnvironmentId=$envId
                        ResourceType="Flow"; ResourceName=$flow.name; ResourceId=$flow.workflowid
                        Owner=""; State=if($flow.statecode -eq 1){"Active"}else{"Inactive"}
                        ConnectorsUsed=""; ConnectorGroups=""; DlpViolation=$false; ViolationReason="Nessun connettore rilevato"
                    })
                }
                continue
            }

            $ownerUpn = Get-BotOwnerUpn -OwnerId $flow._ownerid_value -InstanceUrl $instanceUrl
            $violated = Test-DlpViolation -ConnectorIds $connIds -Policy $selectedPolicy
            $results.Add([PSCustomObject]@{
                PolicyName      = $selectedPolicy.DisplayName
                PolicyId        = $selectedPolicy.PolicyName
                EnvironmentName = $envName
                EnvironmentId   = $envId
                ResourceType    = "Flow"
                ResourceName    = $flow.name
                ResourceId      = $flow.workflowid
                Owner           = $ownerUpn
                State           = if ($flow.statecode -eq 1) { "Active" } else { "Inactive" }
                ConnectorsUsed  = ($connIds | ForEach-Object { Get-ConnectorName $_ $selectedPolicy }) -join "; "
                ConnectorGroups = ($connIds | ForEach-Object { "$(Get-ConnectorName $_ $selectedPolicy)=$(Get-ConnectorGroup $_ $selectedPolicy)" }) -join "; "
                DlpViolation    = $violated
                ViolationReason = if ($violated) { Get-ViolationReason $connIds $selectedPolicy } else { "" }
            })
        } catch { Write-Warning "    Flow '$($flow.name)': $_" }
    }

    # --- APP CANVAS (da Dataverse workflows category=9) ---
    foreach ($app in $apps) {
        $counter++
        Write-Progress -Activity "Analisi $envName" -Status "App: $($app.name)" `
                       -PercentComplete ([math]::Round($counter / [math]::Max($total,1) * 100))
        try {
            $connIds = if ($connRefLookup[$app.workflowid]) { @($connRefLookup[$app.workflowid]) } else { @() }
            if (-not $connIds) { $connIds = @(Get-ConnectorIdsFromClientData -ClientData $app.clientdata) }
            if (-not $connIds -and $app.clientdata -and $connRefByLogName.Count -gt 0) {
                $logMatches = [regex]::Matches($app.clientdata, '"connectionReferenceLogicalName"\s*:\s*"([^"]+)"')
                $logIds = @($logMatches | ForEach-Object { $connRefByLogName[$_.Groups[1].Value] } | Where-Object { $_ })
                if ($logIds.Count -gt 0) { $connIds = $logIds }
            }

            Write-Host ("      App : {0,-40} connettori: {1}" -f $app.name, $(if ($connIds) { $connIds.Count } else { "nessuno" })) -ForegroundColor $(if ($connIds) { "White" } else { "DarkGray" })

            if (-not $connIds) {
                if ($ShowAllResources) {
                    $results.Add([PSCustomObject]@{
                        PolicyName="$($selectedPolicy.DisplayName)"; PolicyId="$($selectedPolicy.PolicyName)"
                        EnvironmentName=$envName; EnvironmentId=$envId
                        ResourceType="PowerApp"; ResourceName=$app.name; ResourceId=$app.workflowid
                        Owner=""; State=if($app.statecode -eq 1){"Active"}else{"Inactive"}
                        ConnectorsUsed=""; ConnectorGroups=""; DlpViolation=$false; ViolationReason="Nessun connettore rilevato"
                    })
                }
                continue
            }

            $ownerUpn = Get-BotOwnerUpn -OwnerId $app._ownerid_value -InstanceUrl $instanceUrl
            $violated = Test-DlpViolation -ConnectorIds $connIds -Policy $selectedPolicy
            $results.Add([PSCustomObject]@{
                PolicyName      = $selectedPolicy.DisplayName
                PolicyId        = $selectedPolicy.PolicyName
                EnvironmentName = $envName
                EnvironmentId   = $envId
                ResourceType    = "PowerApp"
                ResourceName    = $app.name
                ResourceId      = $app.workflowid
                Owner           = $ownerUpn
                State           = if ($app.statecode -eq 1) { "Active" } else { "Inactive" }
                ConnectorsUsed  = ($connIds | ForEach-Object { Get-ConnectorName $_ $selectedPolicy }) -join "; "
                ConnectorGroups = ($connIds | ForEach-Object { "$(Get-ConnectorName $_ $selectedPolicy)=$(Get-ConnectorGroup $_ $selectedPolicy)" }) -join "; "
                DlpViolation    = $violated
                ViolationReason = if ($violated) { Get-ViolationReason $connIds $selectedPolicy } else { "" }
            })
        } catch { Write-Warning "    App '$($app.name)': $_" }
    }

    # --- AGENTI COPILOT STUDIO ---
    foreach ($bot in $bots) {
        $counter++
        Write-Progress -Activity "Analisi $envName" -Status "Agente: $($bot.name)" `
                       -PercentComplete ([math]::Round($counter / [math]::Max($total,1) * 100))
        try {
            $connIds = @(Get-BotConnectorIds -BotId $bot.botid -InstanceUrl $instanceUrl)
            $ownerUpn = Get-BotOwnerUpn -OwnerId $bot._ownerid_value -InstanceUrl $instanceUrl
            $violated = if ($connIds) { Test-DlpViolation -ConnectorIds $connIds -Policy $selectedPolicy } else { $false }
            $results.Add([PSCustomObject]@{
                PolicyName      = $selectedPolicy.DisplayName
                PolicyId        = $selectedPolicy.PolicyName
                EnvironmentName = $envName
                EnvironmentId   = $envId
                ResourceType    = "CopilotStudioAgent"
                ResourceName    = $bot.name
                ResourceId      = $bot.botid
                Owner           = $ownerUpn
                State           = if ($bot.statecode -eq 0) { "Active" } else { "Inactive" }
                ConnectorsUsed  = ($connIds | ForEach-Object { Get-ConnectorName $_ $selectedPolicy }) -join "; "
                ConnectorGroups = ($connIds | ForEach-Object { "$(Get-ConnectorName $_ $selectedPolicy)=$(Get-ConnectorGroup $_ $selectedPolicy)" }) -join "; "
                DlpViolation    = $violated
                ViolationReason = if ($violated) { Get-ViolationReason $connIds $selectedPolicy } else { "" }
            })
        } catch { Write-Warning "    Agente '$($bot.name)': $_" }
    }

    Write-Progress -Activity "Analisi $envName" -Completed
}

# ---------------------------------------------------------------------------
# Output & riepilogo
# ---------------------------------------------------------------------------
$violated = @($results | Where-Object { $_.DlpViolation -eq $true })
$clean    = @($results | Where-Object { $_.DlpViolation -eq $false })

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   RIEPILOGO" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Policy         : $($selectedPolicy.DisplayName)"
Write-Host "  Environment    : $(($selectedEnvs | ForEach-Object { $_.properties.displayName }) -join ', ')"
Write-Host "  Risorse totali : $($results.Count)"
Write-Host "  Violazioni DLP : $($violated.Count)" -ForegroundColor $(if ($violated.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  Non impattate  : $($clean.Count)"    -ForegroundColor Green

if ($violated.Count -gt 0) {
    Write-Host ""
    Write-Host "  Dettaglio violazioni:" -ForegroundColor Red
    $violated | Format-Table EnvironmentName, ResourceType, ResourceName, Owner, ViolationReason -AutoSize
}

$outDir = Split-Path -Parent $OutputCsv
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
$results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "Report salvato in: $OutputCsv" -ForegroundColor Green
Write-Host ""
try { Stop-Transcript | Out-Null } catch { }
