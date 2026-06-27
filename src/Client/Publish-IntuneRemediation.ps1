<#
.SYNOPSIS
    Publishes (creates or updates) the Chrome Policy Manager detect/remediate pair
    as an Intune Proactive Remediation (deviceHealthScript).

.DESCRIPTION
    Reads Detect-ChromePolicy.ps1 and Remediate-ChromePolicy.ps1 from the script
    folder, base64-encodes them, and pushes them to Microsoft Intune via Graph
    (beta/deviceManagement/deviceHealthScripts).

    If a deviceHealthScript with the same DisplayName already exists it is updated
    in place (Intune auto-increments its internal version); otherwise a new one is
    created. The resulting scriptPolicyId is printed so it can be stored in the API
    app setting PushRemediation:ScriptPolicyId (used to trigger on-demand
    remediation from the portal).

    Requires the Microsoft.Graph.Authentication module and an account with the
    DeviceManagementConfiguration.ReadWrite.All scope (Intune admin).

.EXAMPLE
    .\Publish-IntuneRemediation.ps1 -TenantId 46b06a5e-8f7a-467b-bc9a-e776011fbb57 -UseDeviceCode

.EXAMPLE
    .\Publish-IntuneRemediation.ps1 -SetApiAppSetting -ResourceGroup rg-cpm-dev -ApiAppName cpm-dev-api
#>
[CmdletBinding()]
param(
    [string]$DisplayName = "Chrome Policy Manager - Remediation",
    [string]$Description = "Detects Chrome policy drift against the Chrome Policy Manager API and remediates the local registry. Managed by ChromePolicyManager.",
    [string]$Publisher   = "Chrome Policy Manager",
    [string]$ScriptDir   = $PSScriptRoot,
    [string]$DetectScript    = "Detect-ChromePolicy.ps1",
    [string]$RemediateScript = "Remediate-ChromePolicy.ps1",
    [string]$TenantId,
    [switch]$UseDeviceCode,
    # App-only (client credentials) auth — e.g. the IntuneUp-Deploy app registration.
    [string]$ClientId,
    [string]$ClientSecret,
    [ValidateSet("system", "user")]
    [string]$RunAsAccount = "system",
    [switch]$RunAs32Bit,
    [switch]$EnforceSignatureCheck,
    # Optionally persist the resulting id into the API app setting.
    [switch]$SetApiAppSetting,
    [string]$ResourceGroup = "rg-cpm-dev",
    [string]$ApiAppName    = "cpm-dev-api"
)

$ErrorActionPreference = "Stop"

function Get-Base64File([string]$Path) {
    if (-not (Test-Path $Path)) { throw "Script not found: $Path" }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    return [System.Convert]::ToBase64String($bytes)
}

$detectPath    = Join-Path $ScriptDir $DetectScript
$remediatePath = Join-Path $ScriptDir $RemediateScript

Write-Host "Detection : $detectPath" -ForegroundColor Cyan
Write-Host "Remediation: $remediatePath" -ForegroundColor Cyan

$detectB64    = Get-Base64File $detectPath
$remediateB64 = Get-Base64File $remediatePath

# --- Connect to Microsoft Graph -------------------------------------------------
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$connectParams = @{ }
if ($TenantId) { $connectParams.TenantId = $TenantId }

if ($ClientId -and $ClientSecret) {
    # App-only authentication (client credentials) — no interactive sign-in.
    if (-not $TenantId) { throw "TenantId is required for client-credentials auth." }
    $secure = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($ClientId, $secure)
    $connectParams.ClientSecretCredential = $cred
    Write-Host "Connecting to Microsoft Graph (app-only, client $ClientId)..." -ForegroundColor Yellow
}
else {
    # Delegated authentication — interactive browser or device code.
    $connectParams.Scopes = "DeviceManagementConfiguration.ReadWrite.All"
    if ($UseDeviceCode) { $connectParams.UseDeviceCode = $true }
    Write-Host "Connecting to Microsoft Graph (delegated)..." -ForegroundColor Yellow
}

Connect-MgGraph @connectParams | Out-Null
$ctx = Get-MgContext
Write-Host "Connected as $($ctx.Account ?? $ctx.AppName ?? $ClientId) (tenant $($ctx.TenantId))" -ForegroundColor Green

$baseUrl = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"

# --- Find existing script by display name --------------------------------------
$escaped = $DisplayName.Replace("'", "''")
$existing = Invoke-MgGraphRequest -Method GET -Uri "$baseUrl`?`$filter=displayName eq '$escaped'&`$select=id,displayName,version"
$existingItem = $existing.value | Select-Object -First 1

$body = @{
    "@odata.type"             = "#microsoft.graph.deviceHealthScript"
    displayName               = $DisplayName
    description               = $Description
    publisher                 = $Publisher
    detectionScriptContent    = $detectB64
    remediationScriptContent  = $remediateB64
    runAsAccount              = $RunAsAccount
    runAs32Bit                = [bool]$RunAs32Bit
    enforceSignatureCheck     = [bool]$EnforceSignatureCheck
    roleScopeTagIds           = @("0")
}

if ($existingItem) {
    $id = $existingItem.id
    Write-Host "Updating existing deviceHealthScript $id (current version $($existingItem.version))..." -ForegroundColor Yellow
    Invoke-MgGraphRequest -Method PATCH -Uri "$baseUrl/$id" -Body ($body | ConvertTo-Json -Depth 5) -ContentType "application/json" | Out-Null
    $result = Invoke-MgGraphRequest -Method GET -Uri "$baseUrl/$id`?`$select=id,displayName,version"
    Write-Host "Updated. New internal version: $($result.version)" -ForegroundColor Green
} else {
    Write-Host "Creating new deviceHealthScript '$DisplayName'..." -ForegroundColor Yellow
    $result = Invoke-MgGraphRequest -Method POST -Uri $baseUrl -Body ($body | ConvertTo-Json -Depth 5) -ContentType "application/json"
    $id = $result.id
    Write-Host "Created deviceHealthScript $id" -ForegroundColor Green
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " scriptPolicyId : $id" -ForegroundColor Cyan
Write-Host " Set PushRemediation:ScriptPolicyId = $id" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if ($SetApiAppSetting) {
    Write-Host "Setting PushRemediation__ScriptPolicyId on $ApiAppName..." -ForegroundColor Yellow
    az webapp config appsettings set -g $ResourceGroup -n $ApiAppName `
        --settings "PushRemediation__ScriptPolicyId=$id" --only-show-errors | Out-Null
    Write-Host "App setting updated." -ForegroundColor Green
}

return $id
