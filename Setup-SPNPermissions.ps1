#Requires -Version 5.1

<#
.SYNOPSIS
    Registra lo SPN come Application User in tutti gli environment Power Platform.

.DESCRIPTION
    Usa il Device Code Flow per autenticarsi una sola volta (nessun popup browser),
    poi registra lo SPN in ogni environment Dataverse del tenant.
    Da eseguire una volta sola prima di Analyze-DLPImpact.ps1.

.EXAMPLE
    .\Setup-SPNPermissions.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Caricamento settings.json
# ---------------------------------------------------------------------------
$settingsFile = Join-Path $PSScriptRoot "settings.json"
if (-not (Test-Path $settingsFile)) {
    Write-Error "File settings.json non trovato. Copiare settings.sample.json e compilarlo."
}

$cfg           = Get-Content $settingsFile -Raw | ConvertFrom-Json
$tenantId      = $cfg.Auth.TenantId
$applicationId = $cfg.Auth.ApplicationId
$clientSecret  = $cfg.Auth.ClientSecret

if (-not $tenantId -or -not $applicationId -or -not $clientSecret) {
    Write-Error "settings.json incompleto. Compilare TenantId, ApplicationId e ClientSecret."
}

# ---------------------------------------------------------------------------
# Helper: Device Code Flow — autenticazione interattiva senza popup
# ---------------------------------------------------------------------------
$script:publicClientId = "1950a258-227b-4e31-a9cf-717495945fc2"
$script:refreshToken   = $null

function Get-UserTokenDeviceCode {
    param([string]$Scope)

    # Step 1: richiedi device code
    $dcResp = Invoke-RestMethod `
        -Method Post `
        -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{ client_id = $script:publicClientId; scope = $Scope }

    Write-Host ""
    Write-Host "  $($dcResp.message)" -ForegroundColor Yellow
    Write-Host ""

    # Step 2: polling fino a ottenere il token
    $deadline = (Get-Date).AddSeconds($dcResp.expires_in)
    do {
        Start-Sleep -Seconds $dcResp.interval
        try {
            $tokenResp = Invoke-RestMethod `
                -Method Post `
                -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
                -ContentType "application/x-www-form-urlencoded" `
                -Body @{
                    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                    client_id   = $script:publicClientId
                    device_code = $dcResp.device_code
                }
            # Salva il refresh token per riutilizzarlo sulle istanze Dataverse
            $script:refreshToken = $tokenResp.refresh_token
            return $tokenResp.access_token
        } catch {
            $errBody = $_ | Select-Object -ExpandProperty ErrorDetails -ErrorAction SilentlyContinue
            if ($errBody -match "authorization_pending") { continue }
            if ($errBody -match "expired_token")         { Write-Error "Timeout autenticazione." }
            throw
        }
    } until ((Get-Date) -gt $deadline)

    Write-Error "Timeout: codice scaduto senza completare il login."
}

function Get-UserTokenForResource {
    # Usa il refresh token per ottenere un access token per una risorsa specifica
    param([string]$Resource)
    $resp = Invoke-RestMethod `
        -Method Post `
        -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "refresh_token"
            client_id     = $script:publicClientId
            refresh_token = $script:refreshToken
            scope         = "$Resource/.default"
        }
    $script:refreshToken = $resp.refresh_token  # aggiorna il refresh token
    return $resp.access_token
}

# ---------------------------------------------------------------------------
# Helper: token SPN (client credentials) per le API Dataverse per-env
# ---------------------------------------------------------------------------
function Get-SpnToken {
    param([string]$Resource)
    $resp = Invoke-RestMethod `
        -Method Post `
        -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "client_credentials"
            client_id     = $applicationId
            client_secret = $clientSecret
            scope         = "$Resource/.default"
        }
    return $resp.access_token
}

# ---------------------------------------------------------------------------
# Helper: registra SPN in un singolo environment Dataverse
# ---------------------------------------------------------------------------
function Register-SPNInEnvironment {
    param([string]$EnvDisplayName, [string]$InstanceUrl)

    $url = $InstanceUrl.TrimEnd("/")

    # Token utente admin per quell'istanza Dataverse (via refresh token)
    try {
        $token = Get-UserTokenForResource -Resource $url
    } catch {
        Write-Host "    SKIP — impossibile ottenere token per $url : $_" -ForegroundColor Yellow
        return
    }

    $headers = @{
        Authorization      = "Bearer $token"
        "Content-Type"     = "application/json"
        "OData-MaxVersion" = "4.0"
        "OData-Version"    = "4.0"
    }

    # Controlla se lo SPN e' gia' registrato
    try {
        $existing = Invoke-RestMethod `
            -Method Get `
            -Uri "$url/api/data/v9.2/systemusers?`$filter=applicationid eq '$applicationId'&`$select=systemuserid,fullname" `
            -Headers $headers
    } catch {
        Write-Host "    SKIP — accesso Dataverse negato (verifica permesso 'Dynamics CRM - Application' nello SPN)" -ForegroundColor Yellow
        return
    }

    # Business Unit root
    $bu     = Invoke-RestMethod -Method Get -Uri "$url/api/data/v9.2/businessunits?`$filter=_parentbusinessunitid_value eq null&`$select=businessunitid" -Headers $headers
    $rootBu = $bu.value[0].businessunitid

    # Recupera ruoli da assegnare (System Administrator + Environment Admin)
    $rolesResp = Invoke-RestMethod -Method Get `
        -Uri "$url/api/data/v9.2/roles?`$filter=(name eq 'System Administrator' or name eq 'Environment Admin') and _businessunitid_value eq $rootBu&`$select=roleid,name" `
        -Headers $headers
    $targetRoles = $rolesResp.value

    if ($existing.value.Count -gt 0) {
        # Utente gia' presente — verifica se ha i ruoli
        $userId = $existing.value[0].systemuserid
        $assignedRoles = Invoke-RestMethod -Method Get `
            -Uri "$url/api/data/v9.2/systemusers($userId)/systemuserroles_association?`$select=roleid,name" `
            -Headers $headers

        $missing = @($targetRoles | Where-Object {
            $r = $_
            -not ($assignedRoles.value | Where-Object { $_.roleid -eq $r.roleid })
        })

        if ($missing.Count -eq 0) {
            Write-Host "    OK — gia' registrato con tutti i ruoli necessari" -ForegroundColor Green
        } else {
            foreach ($role in $missing) {
                $refBody = @{ "@odata.id" = "$url/api/data/v9.2/roles($($role.roleid))" } | ConvertTo-Json
                Invoke-RestMethod -Method Post -Uri "$url/api/data/v9.2/systemusers($userId)/systemuserroles_association/`$ref" -Headers $headers -Body $refBody | Out-Null
                Write-Host "    Ruolo aggiunto: $($role.name)" -ForegroundColor Yellow
            }
            Write-Host "    OK — ruoli aggiornati" -ForegroundColor Green
        }
        return
    }

    # Crea application user
    $body = @{
        applicationid    = $applicationId
        firstname        = "DLP"
        lastname         = "Analyzer SPN"
        accessmode       = 4
        isdisabled       = $false
        "businessunitid@odata.bind" = "/businessunits($rootBu)"
    } | ConvertTo-Json

    $headers["Prefer"] = "return=representation"
    $newUser = Invoke-RestMethod -Method Post -Uri "$url/api/data/v9.2/systemusers" -Headers $headers -Body $body
    $headers.Remove("Prefer")
    $userId  = $newUser.systemuserid

    # Assegna tutti i ruoli target
    foreach ($role in $targetRoles) {
        $refBody = @{ "@odata.id" = "$url/api/data/v9.2/roles($($role.roleid))" } | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri "$url/api/data/v9.2/systemusers($userId)/systemuserroles_association/`$ref" -Headers $headers -Body $refBody | Out-Null
    }

    $roleNames = ($targetRoles | ForEach-Object { $_.name }) -join ", "
    Write-Host "    CREATO con ruoli: $roleNames" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Setup SPN Permissions - Power Platform" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "TenantId     : $tenantId"
Write-Host "ApplicationId: $applicationId"
Write-Host ""

# STEP 1: autenticazione utente admin via device code (una sola volta, nessun popup)
Write-Host "[1/3] Autenticazione admin tramite Device Code..." -ForegroundColor Cyan
Write-Host "  Accedi con un account Global Admin o Power Platform Admin." -ForegroundColor DarkGray
$adminToken = Get-UserTokenDeviceCode -Scope "https://service.powerapps.com/.default offline_access"
Write-Host "  Login completato." -ForegroundColor Green

# STEP 2: lista environment via BAP API con token utente
Write-Host ""
Write-Host "[2/3] Recupero environment del tenant..." -ForegroundColor Cyan
$bapHeaders = @{ Authorization = "Bearer $adminToken"; "Content-Type" = "application/json" }
$bapResp    = Invoke-RestMethod `
    -Method Get `
    -Uri "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2019-05-01&`$expand=properties.linkedEnvironmentMetadata" `
    -Headers $bapHeaders

$allEnvs      = @($bapResp.value)
$dataverseEnvs = @($allEnvs | Where-Object {
    $_.properties.linkedEnvironmentMetadata.instanceUrl -ne $null -and
    $_.properties.linkedEnvironmentMetadata.instanceUrl -ne ""
})

Write-Host "  Trovati $($allEnvs.Count) environment totali, $($dataverseEnvs.Count) con Dataverse."

# STEP 3: registra SPN in ogni environment Dataverse
Write-Host ""
Write-Host "[3/3] Registrazione SPN negli environment..." -ForegroundColor Cyan
$ok = 0; $skip = 0

foreach ($env in $dataverseEnvs) {
    $instanceUrl = $env.properties.linkedEnvironmentMetadata.instanceUrl
    $displayName = $env.properties.displayName
    Write-Host ""
    Write-Host "  $displayName" -ForegroundColor White
    Write-Host "  $instanceUrl" -ForegroundColor DarkGray
    try {
        Register-SPNInEnvironment -EnvDisplayName $displayName -InstanceUrl $instanceUrl
        $ok++
    } catch {
        Write-Host "    ERRORE: $_" -ForegroundColor Red
        $skip++
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Completato: $ok registrati, $skip saltati" -ForegroundColor $(if ($skip -gt 0) { "Yellow" } else { "Green" })
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Prossimo passo: esegui Analyze-DLPImpact.ps1 per l'analisi DLP." -ForegroundColor Green
Write-Host ""
