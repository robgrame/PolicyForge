<#
.SYNOPSIS
    Chrome Policy Manager - Azure Infrastructure Deployment Script

.DESCRIPTION
    Deploys the complete ChromePolicyManager infrastructure to Azure:
    - Resource Group
    - App Service Plan + Web App (.NET 10)
    - Azure SQL Server + Database
    - Azure Service Bus Namespace + Queue
    - Azure API Management (Consumption)
    - Azure App Configuration
    - Azure Key Vault
    - Entra ID App Registration (API + Device client)

    Run this script once to provision everything. It is idempotent (safe to re-run).

.PARAMETER EnvironmentName
    Environment name: dev, staging, prod (default: dev)

.PARAMETER Location
    Azure region (default: westeurope)

.PARAMETER SubscriptionId
    Azure subscription ID. If not provided, uses current context.

.EXAMPLE
    .\Deploy-Infrastructure.ps1 -EnvironmentName dev -Location westeurope
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("dev", "staging", "prod")]
    [string]$EnvironmentName = "dev",

    [Parameter()]
    [string]$Location = "westeurope",

    [Parameter()]
    [string]$SubscriptionId
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ============================================================
# Configuration
# ============================================================
$ProjectName = "ChromePolicyManager"
$Prefix = "cpm-$EnvironmentName"
$ResourceGroupName = "rg-$Prefix"
$Tags = @{ project = $ProjectName; environment = $EnvironmentName }

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       Chrome Policy Manager - Infrastructure Deployment      ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Environment : $($EnvironmentName.PadRight(45))║" -ForegroundColor Cyan
Write-Host "║  Location    : $($Location.PadRight(45))║" -ForegroundColor Cyan
Write-Host "║  RG          : $($ResourceGroupName.PadRight(45))║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# Prerequisites Check
# ============================================================
Write-Host "▶ Checking prerequisites..." -ForegroundColor Yellow

# Check Az CLI
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI (az) not found. Install from https://aka.ms/installazurecli"
    exit 1
}

# Check login
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "  Not logged in. Running az login..." -ForegroundColor DarkYellow
    az login
    $account = az account show | ConvertFrom-Json
}

# Set subscription
if ($SubscriptionId) {
    az account set --subscription $SubscriptionId
    $account = az account show | ConvertFrom-Json
}

Write-Host "  ✓ Logged in as: $($account.user.name)" -ForegroundColor Green
Write-Host "  ✓ Subscription: $($account.name) ($($account.id))" -ForegroundColor Green
Write-Host ""

# Confirm
$confirm = Read-Host "Proceed with deployment? (Y/n)"
if ($confirm -and $confirm -notin @("Y", "y", "yes", "")) {
    Write-Host "Deployment cancelled." -ForegroundColor Red
    exit 0
}

# ============================================================
# 1. Resource Group
# ============================================================
Write-Host ""
Write-Host "▶ [1/9] Creating Resource Group..." -ForegroundColor Yellow

az group create `
    --name $ResourceGroupName `
    --location $Location `
    --tags project=$ProjectName environment=$EnvironmentName `
    --output none

Write-Host "  ✓ Resource Group: $ResourceGroupName" -ForegroundColor Green

# ============================================================
# 2. Key Vault
# ============================================================
Write-Host "▶ [2/9] Creating Key Vault..." -ForegroundColor Yellow

$suffix = $account.id.Substring(0,6)  # Unique suffix from subscription ID
$kvName = "$Prefix-kv-$suffix"
az keyvault create `
    --name $kvName `
    --resource-group $ResourceGroupName `
    --location $Location `
    --enable-rbac-authorization true `
    --tags project=$ProjectName environment=$EnvironmentName `
    --output none
if ($LASTEXITCODE -ne 0) { Write-Host "  ⚠ Key Vault creation failed (name may be taken or soft-deleted)" -ForegroundColor Red }
else { Write-Host "  ✓ Key Vault: $kvName" -ForegroundColor Green }

# Assign Key Vault Secrets Officer to current user
$currentUserId = (az ad signed-in-user show --query id -o tsv)
az role assignment create --role "Key Vault Secrets Officer" --assignee $currentUserId `
    --scope "/subscriptions/$($account.id)/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$kvName" --output none 2>$null

# ============================================================
# 3. App Configuration
# ============================================================
Write-Host "▶ [3/9] Creating App Configuration..." -ForegroundColor Yellow

$appConfigName = "$Prefix-appconfig"
az appconfig create `
    --name $appConfigName `
    --resource-group $ResourceGroupName `
    --location $Location `
    --sku Standard `
    --output none
if ($LASTEXITCODE -ne 0) { Write-Host "  ⚠ App Configuration creation failed" -ForegroundColor Red }
else { Write-Host "  ✓ App Configuration: $appConfigName (Standard)" -ForegroundColor Green }

# Get read-only connection string for Web App
$appConfigConnStr = az appconfig credential list --name $appConfigName --resource-group $ResourceGroupName `
    --query "[?name=='Primary Read Only'].connectionString" -o tsv

# ============================================================
# 4. Azure SQL
# ============================================================
Write-Host "▶ [4/9] Creating Azure SQL Server + Database..." -ForegroundColor Yellow

$sqlServerName = "$Prefix-sql-$suffix"
$sqlDbName = "ChromePolicyManager"

# Register provider if needed
az provider register --namespace Microsoft.Sql --wait 2>$null

# Use Entra-only auth (MCAPS policy compliant)
$currentUserName = (az ad signed-in-user show --query displayName -o tsv)
az sql server create `
    --name $sqlServerName `
    --resource-group $ResourceGroupName `
    --location $Location `
    --enable-ad-only-auth `
    --external-admin-principal-type User `
    --external-admin-name $currentUserName `
    --external-admin-sid $currentUserId `
    --output none
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ⚠ SQL Server creation failed (region may be unavailable, trying northeurope)" -ForegroundColor Red
    az sql server create `
        --name $sqlServerName `
        --resource-group $ResourceGroupName `
        --location northeurope `
        --enable-ad-only-auth `
        --external-admin-principal-type User `
        --external-admin-name $currentUserName `
        --external-admin-sid $currentUserId `
        --output none
}

az sql db create `
    --name $sqlDbName `
    --resource-group $ResourceGroupName `
    --server $sqlServerName `
    --service-objective Basic `
    --output none

# Allow Azure services
az sql server firewall-rule create `
    --name "AllowAzureServices" `
    --resource-group $ResourceGroupName `
    --server $sqlServerName `
    --start-ip-address 0.0.0.0 `
    --end-ip-address 0.0.0.0 `
    --output none

Write-Host "  ✓ SQL Server: $sqlServerName" -ForegroundColor Green
Write-Host "  ✓ Database: $sqlDbName" -ForegroundColor Green

$sqlConnString = "Server=tcp:$sqlServerName.database.windows.net,1433;Database=$sqlDbName;Authentication=Active Directory Default;Encrypt=True;TrustServerCertificate=False;"

# ============================================================
# 5. Service Bus
# ============================================================
Write-Host "▶ [5/9] Creating Service Bus Namespace + Queue..." -ForegroundColor Yellow

$sbNamespace = "$Prefix-sb-$suffix"

# Register provider if needed
az provider register --namespace Microsoft.ServiceBus --wait 2>$null

az servicebus namespace create `
    --name $sbNamespace `
    --resource-group $ResourceGroupName `
    --location $Location `
    --sku Basic `
    --output none

az servicebus queue create `
    --name "device-reports" `
    --namespace-name $sbNamespace `
    --resource-group $ResourceGroupName `
    --max-delivery-count 5 `
    --default-message-time-to-live "P7D" `
    --output none

# Get connection string (retry - namespace provisioning may still be propagating)
$sbConnString = $null
for ($retry = 1; $retry -le 5; $retry++) {
    $sbConnString = (az servicebus namespace authorization-rule keys list `
        --name RootManageSharedAccessKey `
        --namespace-name $sbNamespace `
        --resource-group $ResourceGroupName `
        --query primaryConnectionString -o tsv 2>$null)
    if ($sbConnString) { break }
    Write-Host "  Waiting for Service Bus namespace to be ready... (attempt $retry/5)" -ForegroundColor DarkYellow
    Start-Sleep -Seconds 15
}

Write-Host "  ✓ Service Bus: $sbNamespace" -ForegroundColor Green
Write-Host "  ✓ Queue: device-reports" -ForegroundColor Green

# Store in Key Vault
az keyvault secret set --vault-name $kvName --name "ServiceBusConnectionString" --value $sbConnString --output none 2>$null

# ============================================================
# 6. App Service Plan + Web App
# ============================================================
Write-Host "▶ [6/9] Creating App Service Plan + Web App..." -ForegroundColor Yellow

$planName = "$Prefix-plan"
$appName = "$Prefix-api"

az appservice plan create `
    --name $planName `
    --resource-group $ResourceGroupName `
    --location $Location `
    --sku B1 `
    --output none 2>$null

az webapp create `
    --name $appName `
    --resource-group $ResourceGroupName `
    --plan $planName `
    --runtime "dotnet:10" `
    --output none 2>$null

# Enable system-assigned managed identity
$appIdentity = (az webapp identity assign `
    --name $appName `
    --resource-group $ResourceGroupName `
    --query principalId -o tsv)

Write-Host "  ✓ App Service Plan: $planName" -ForegroundColor Green
Write-Host "  ✓ Web App: $appName (Identity: $appIdentity)" -ForegroundColor Green

# ============================================================
# 7. Entra ID App Registration
# ============================================================
Write-Host "▶ [7/9] Creating Entra ID App Registrations..." -ForegroundColor Yellow

$tenantId = $account.tenantId

# Refresh token to avoid CAE challenges during Graph/Entra operations
az account get-access-token --resource https://graph.microsoft.com --output none 2>$null

# API App Registration
$apiAppExists = az ad app list --display-name "$ProjectName-API" --query "[0].appId" -o tsv 2>$null
if (-not $apiAppExists) {
    # Create app without identifier URI first (tenant policy may restrict URI format)
    $apiAppJson = az ad app create `
        --display-name "$ProjectName-API" `
        --sign-in-audience AzureADMyOrg `
        --output json 2>$null
    
    if (-not $apiAppJson) {
        Write-Host "  ⚠ Failed to create API app registration (CAE/permissions issue)" -ForegroundColor Red
        Write-Host "  Run manually: az ad app create --display-name '$ProjectName-API' --sign-in-audience AzureADMyOrg" -ForegroundColor DarkYellow
        $apiAppId = "MANUAL_SETUP_REQUIRED"
        $apiSecret = "MANUAL_SETUP_REQUIRED"
    }
    else {
        $apiApp = $apiAppJson | ConvertFrom-Json
        $apiAppId = $apiApp.appId

        # Set identifier URI using appId (always allowed by tenant policy)
        az ad app update --id $apiAppId --identifier-uris "api://$apiAppId" --output none 2>$null

        # Create service principal
        az ad sp create --id $apiAppId --output none 2>$null

        # Create client secret
        $apiSecret = (az ad app credential reset --id $apiAppId --query password -o tsv 2>$null)
    }
}
else {
    $apiAppId = $apiAppExists
    Write-Host "  (API app already exists, skipping creation)" -ForegroundColor DarkYellow
    $apiSecret = "(existing - check Key Vault)"
}

# Device Client App Registration
$deviceAppExists = az ad app list --display-name "$ProjectName-DeviceClient" --query "[0].appId" -o tsv 2>$null
if (-not $deviceAppExists) {
    $deviceAppJson = az ad app create `
        --display-name "$ProjectName-DeviceClient" `
        --sign-in-audience AzureADMyOrg `
        --public-client-redirect-uris "urn:ietf:wg:oauth:2.0:oob" `
        --output json 2>$null

    if ($deviceAppJson) {
        $deviceApp = $deviceAppJson | ConvertFrom-Json
        $deviceAppId = $deviceApp.appId
        az ad sp create --id $deviceAppId --output none 2>$null
    }
    else {
        Write-Host "  ⚠ Failed to create Device Client app (CAE/permissions issue)" -ForegroundColor Red
        $deviceAppId = "MANUAL_SETUP_REQUIRED"
    }
}
else {
    $deviceAppId = $deviceAppExists
    Write-Host "  (Device client app already exists)" -ForegroundColor DarkYellow
}

Write-Host "  ✓ API App Registration: $apiAppId" -ForegroundColor Green
Write-Host "  ✓ Device Client App: $deviceAppId" -ForegroundColor Green

# Store secrets in Key Vault
if ($apiSecret -and $apiSecret -ne "(existing - check Key Vault)") {
    az keyvault secret set --vault-name $kvName --name "ApiClientSecret" --value $apiSecret --output none 2>$null
}

# ============================================================
# 8. Configure Web App Settings
# ============================================================
Write-Host "▶ [8/9] Configuring Web App..." -ForegroundColor Yellow

# $sqlConnString already defined from step 4

az webapp config appsettings set `
    --name $appName `
    --resource-group $ResourceGroupName `
    --settings `
        "AzureAd__TenantId=$tenantId" `
        "AzureAd__ClientId=$apiAppId" `
        "AzureAd__Instance=https://login.microsoftonline.com/" `
        "AzureAd__Audience=api://$apiAppId" `
        "ServiceBus__ConnectionString=$sbConnString" `
        "ServiceBus__DeviceReportQueue=device-reports" `
        "AppConfiguration__ConnectionString=$appConfigConnStr" `
        "ASPNETCORE_ENVIRONMENT=$( if ($EnvironmentName -eq 'prod') { 'Production' } else { 'Development' })" `
    --output none

az webapp config connection-string set `
    --name $appName `
    --resource-group $ResourceGroupName `
    --connection-string-type SQLAzure `
    --settings "DefaultConnection=$sqlConnString" `
    --output none

# Store API secret as app setting (reference Key Vault in production)
if ($apiSecret -and $apiSecret -ne "(existing - check Key Vault)") {
    az webapp config appsettings set `
        --name $appName `
        --resource-group $ResourceGroupName `
        --settings "AzureAd__ClientSecret=$apiSecret" `
        --output none
}

Write-Host "  ✓ App settings configured" -ForegroundColor Green

# ============================================================
# 9. API Management (optional - Consumption tier takes ~30 min)
# ============================================================
Write-Host "▶ [9/9] Creating API Management..." -ForegroundColor Yellow
Write-Host "  ⚠ APIM Consumption tier takes 20-40 minutes to provision." -ForegroundColor DarkYellow

$deployApim = Read-Host "  Deploy APIM now? (Y/n - skip for later)"
if ($deployApim -in @("Y", "y", "yes", "")) {
    $apimName = "$Prefix-apim"

    az apim create `
        --name $apimName `
        --resource-group $ResourceGroupName `
        --location $Location `
        --publisher-name "Chrome Policy Manager" `
        --publisher-email "$($account.user.name)" `
        --sku-name Consumption `
        --output none 2>$null

    # Create Management API
    az apim api create `
        --resource-group $ResourceGroupName `
        --service-name $apimName `
        --api-id "management-api" `
        --display-name "Chrome Policy Management API" `
        --path "management" `
        --protocols https `
        --service-url "https://$appName.azurewebsites.net" `
        --subscription-required true `
        --output none 2>$null

    # Create Device API
    az apim api create `
        --resource-group $ResourceGroupName `
        --service-name $apimName `
        --api-id "device-api" `
        --display-name "Chrome Policy Device API" `
        --path "device" `
        --protocols https `
        --service-url "https://$appName.azurewebsites.net" `
        --subscription-required false `
        --output none 2>$null

    Write-Host "  ✓ APIM: $apimName" -ForegroundColor Green
}
else {
    Write-Host "  ⏭ APIM skipped (deploy later with Bicep or manually)" -ForegroundColor DarkYellow
}

# ============================================================
# Summary
# ============================================================
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              ✅ Deployment Complete!                         ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  Resources deployed:                                         ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Resource Group   : $ResourceGroupName" -ForegroundColor White
Write-Host "  Web App          : https://$appName.azurewebsites.net" -ForegroundColor White
Write-Host "  SQL Server       : $sqlServerName.database.windows.net" -ForegroundColor White
Write-Host "  Service Bus      : $sbNamespace.servicebus.windows.net" -ForegroundColor White
Write-Host "  Key Vault        : https://$kvName.vault.azure.net" -ForegroundColor White
Write-Host "  App Config       : https://$appConfigName.azconfig.io" -ForegroundColor White
Write-Host ""
Write-Host "  Entra ID:" -ForegroundColor White
Write-Host "    API App ID     : $apiAppId" -ForegroundColor White
Write-Host "    Device App ID  : $deviceAppId" -ForegroundColor White
Write-Host "    Tenant ID      : $tenantId" -ForegroundColor White
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "    1. Deploy the API code:  az webapp deploy --src-path <publish-folder>" -ForegroundColor DarkYellow
Write-Host "    2. Update client scripts with:" -ForegroundColor DarkYellow
Write-Host "       `$ApiBaseUrl = 'https://$appName.azurewebsites.net'" -ForegroundColor DarkYellow
Write-Host "       `$TenantId   = '$tenantId'" -ForegroundColor DarkYellow
Write-Host "       `$ClientId   = '$deviceAppId'" -ForegroundColor DarkYellow
Write-Host "    3. Grant Graph permissions: az ad app permission add --id $apiAppId --api 00000003-0000-0000-c000-000000000000 --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role" -ForegroundColor DarkYellow
Write-Host "    4. Deploy scripts via Intune Proactive Remediation" -ForegroundColor DarkYellow
Write-Host ""

# Save deployment output for reference
$deploymentInfo = @{
    Timestamp       = Get-Date -Format "o"
    Environment     = $EnvironmentName
    ResourceGroup   = $ResourceGroupName
    WebApp          = "https://$appName.azurewebsites.net"
    SqlServer       = "$sqlServerName.database.windows.net"
    ServiceBus      = "$sbNamespace.servicebus.windows.net"
    KeyVault        = "https://$kvName.vault.azure.net"
    AppConfig       = "https://$appConfigName.azconfig.io"
    ApiAppId        = $apiAppId
    DeviceAppId     = $deviceAppId
    TenantId        = $tenantId
}

$outputPath = Join-Path $PSScriptRoot "deployment-output-$EnvironmentName.json"
$deploymentInfo | ConvertTo-Json | Out-File $outputPath -Encoding utf8
Write-Host "  📄 Deployment info saved to: $outputPath" -ForegroundColor DarkGray
