<#
.SYNOPSIS
    Chrome Policy Manager - Unified Deployment (Infrastructure + Code).

.DESCRIPTION
    One script to provision the full Azure infrastructure via Bicep AND deploy the
    application code (API + Admin Blazor UI) to the App Services.

    SKU sizing is driven by the environment:
      - dev  : cost-optimized  (App Service B1, SQL Basic, APIM Developer, AppConfig Free)
      - prod : production-grade (App Service P1v3 x2, SQL S2, APIM Standard, AppConfig Standard, Service Bus)

    The script is idempotent (safe to re-run).

    Pipeline:
      1. Prerequisite & login checks
      2. Resource Group create
      3. Bicep deployment (infra) - uses main.<env>.bicepparam, overriding tenant/app secrets
      4. dotnet publish (API + Admin) -> zip
      5. Zip-deploy code to the App Services
      6. Summary + deployment-output-<env>.json

.PARAMETER EnvironmentName
    Target environment: dev or prod (default: dev). Selects the matching bicepparam + SKU tier.

.PARAMETER Location
    Azure region (default: westeurope).

.PARAMETER SubscriptionId
    Azure subscription ID. If omitted, uses the current az context.

.PARAMETER TenantId
    Entra ID tenant ID. If omitted, taken from the current az account.

.PARAMETER ClientId
    App registration (API) client ID. If omitted, you must set it in the bicepparam file.

.PARAMETER ClientSecret
    App registration client secret (SecureString). Prompted if not supplied and not in the param file.

.PARAMETER ResourceGroupName
    Resource group name (default: rg-cpm-<env>).

.PARAMETER SkipInfra
    Skip the Bicep infrastructure deployment (deploy code only).

.PARAMETER SkipCode
    Skip building/deploying the application code (deploy infra only).

.PARAMETER WhatIf
    Run a Bicep what-if (preview changes) instead of an actual infra deployment.

.EXAMPLE
    .\Deploy.ps1 -EnvironmentName dev -ClientId <api-app-id> -ClientSecret (Read-Host -AsSecureString)

.EXAMPLE
    .\Deploy.ps1 -EnvironmentName prod -Location westeurope -SkipCode -WhatIf
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('dev', 'prod')]
    [string]$EnvironmentName = 'dev',

    [Parameter()]
    [string]$Location = 'westeurope',

    [Parameter()]
    [string]$SubscriptionId,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$ClientId,

    [Parameter()]
    [securestring]$ClientSecret,

    [Parameter()]
    [string]$ResourceGroupName,

    [Parameter()]
    [switch]$SkipInfra,

    [Parameter()]
    [switch]$SkipCode,

    [Parameter()]
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ============================================================
# Paths & configuration
# ============================================================
$InfraDir   = $PSScriptRoot
$RepoRoot   = Split-Path $InfraDir -Parent
$ApiCsproj  = Join-Path $RepoRoot 'src\Server\ChromePolicyManager.Api\ChromePolicyManager.Api.csproj'
$AdminCsproj = Join-Path $RepoRoot 'src\Server\ChromePolicyManager.Admin\ChromePolicyManager.Admin.csproj'
$BicepFile  = Join-Path $InfraDir 'main.bicep'
$ParamFile  = Join-Path $InfraDir "main.$EnvironmentName.bicepparam"

if (-not $ResourceGroupName) { $ResourceGroupName = "rg-cpm-$EnvironmentName" }
if (-not (Test-Path $ParamFile)) { throw "Parameter file not found: $ParamFile" }

$ProjectName = 'ChromePolicyManager'

Write-Host ''
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host '   Chrome Policy Manager - Unified Deployment (Infra + Code)' -ForegroundColor Cyan
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host "   Environment : $EnvironmentName" -ForegroundColor Cyan
Write-Host "   Location    : $Location" -ForegroundColor Cyan
Write-Host "   Resource RG : $ResourceGroupName" -ForegroundColor Cyan
Write-Host "   Param file  : $(Split-Path $ParamFile -Leaf)" -ForegroundColor Cyan
Write-Host "   Mode        : $(if ($WhatIf) {'WHAT-IF (preview)'} else {'DEPLOY'})" -ForegroundColor Cyan
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host ''

# ============================================================
# Prerequisites
# ============================================================
Write-Host '> Checking prerequisites...' -ForegroundColor Yellow

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) not found. Install from https://aka.ms/installazurecli'
}
if (-not $SkipCode -and -not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'dotnet SDK not found. Install the .NET 10 SDK from https://dotnet.microsoft.com/'
}

# Login check
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host '  Not logged in. Running az login...' -ForegroundColor DarkYellow
    az login | Out-Null
    $account = az account show | ConvertFrom-Json
}
if ($SubscriptionId) {
    az account set --subscription $SubscriptionId | Out-Null
    $account = az account show | ConvertFrom-Json
}
if (-not $TenantId) { $TenantId = $account.tenantId }

Write-Host "  + Logged in as : $($account.user.name)" -ForegroundColor Green
Write-Host "  + Subscription : $($account.name) ($($account.id))" -ForegroundColor Green
Write-Host "  + Tenant       : $TenantId" -ForegroundColor Green
Write-Host ''

# ============================================================
# 1. Resource Group
# ============================================================
Write-Host '> [1/4] Ensuring Resource Group...' -ForegroundColor Yellow
az group create `
    --name $ResourceGroupName `
    --location $Location `
    --tags project=$ProjectName environment=$EnvironmentName `
    --output none
Write-Host "  + Resource Group: $ResourceGroupName" -ForegroundColor Green

# ============================================================
# 2. Infrastructure (Bicep)
# ============================================================
# Outputs we need for code deployment; resolved from the bicep deployment or
# derived from naming convention when infra is skipped.
$apiAppName   = "cpm-$EnvironmentName-api"
$adminAppName = "cpm-$EnvironmentName-admin"

if ($SkipInfra) {
    Write-Host '> [2/4] Skipping infrastructure (SkipInfra).' -ForegroundColor DarkYellow
}
else {
    Write-Host '> [2/4] Deploying infrastructure via Bicep...' -ForegroundColor Yellow

    # Build the override parameters. The bicepparam file holds placeholders; CLI overrides win.
    $overrides = @(
        "location=$Location"
        "environmentName=$EnvironmentName"
        "tenantId=$TenantId"
    )
    if ($ClientId) { $overrides += "clientId=$ClientId" }

    # Resolve client secret: param -> prompt. Skipped if neither provided (assumes param file value).
    if (-not $ClientSecret -and -not $WhatIf) {
        $needSecret = Read-Host 'Provide app registration client secret now? (leave blank to use the value in the bicepparam file) (y/N)'
        if ($needSecret -in @('y', 'Y', 'yes')) {
            $ClientSecret = Read-Host 'Client secret' -AsSecureString
        }
    }
    if ($ClientSecret) {
        $plain = [System.Net.NetworkCredential]::new('', $ClientSecret).Password
        $overrides += "clientSecret=$plain"
    }

    $deploymentName = "cpm-$EnvironmentName-$(Get-Date -Format 'yyyyMMddHHmmss')"

    if ($WhatIf) {
        az deployment group what-if `
            --resource-group $ResourceGroupName `
            --name $deploymentName `
            --template-file $BicepFile `
            --parameters $ParamFile `
            --parameters $overrides
        Write-Host ''
        Write-Host '  What-if complete. Re-run without -WhatIf to apply.' -ForegroundColor DarkYellow
        return
    }

    $deployJson = az deployment group create `
        --resource-group $ResourceGroupName `
        --name $deploymentName `
        --template-file $BicepFile `
        --parameters $ParamFile `
        --parameters $overrides `
        --output json
    if ($LASTEXITCODE -ne 0) { throw 'Bicep deployment failed. See errors above.' }

    $deploy = $deployJson | ConvertFrom-Json
    $outputs = $deploy.properties.outputs
    if ($outputs.PSObject.Properties.Name -contains 'apiAppName')   { $apiAppName   = $outputs.apiAppName.value }
    if ($outputs.PSObject.Properties.Name -contains 'adminAppName') { $adminAppName = $outputs.adminAppName.value }

    Write-Host '  + Infrastructure deployed.' -ForegroundColor Green
    Write-Host "    API app   : $apiAppName" -ForegroundColor Green
    Write-Host "    Admin app : $adminAppName" -ForegroundColor Green
}

# ============================================================
# 3 & 4. Build, publish and deploy the application code
# ============================================================
function Publish-And-Deploy {
    param(
        [string]$Name,
        [string]$Csproj,
        [string]$AppServiceName
    )

    Write-Host "  > Publishing $Name ..." -ForegroundColor Yellow
    $publishDir = Join-Path $env:TEMP "cpm-publish\$Name"
    $zipPath    = Join-Path $env:TEMP "cpm-publish\$Name.zip"
    if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }
    if (Test-Path $zipPath)    { Remove-Item $zipPath -Force }

    dotnet publish $Csproj -c Release -o $publishDir --nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $Name" }

    Write-Host "  > Packaging $Name ..." -ForegroundColor Yellow
    Compress-Archive -Path (Join-Path $publishDir '*') -DestinationPath $zipPath -Force

    Write-Host "  > Deploying $Name -> $AppServiceName ..." -ForegroundColor Yellow
    az webapp deploy `
        --resource-group $ResourceGroupName `
        --name $AppServiceName `
        --src-path $zipPath `
        --type zip `
        --output none
    if ($LASTEXITCODE -ne 0) { throw "Code deployment failed for $Name ($AppServiceName)" }

    Write-Host "  + $Name deployed to https://$AppServiceName.azurewebsites.net" -ForegroundColor Green
}

if ($SkipCode) {
    Write-Host '> [3/4] Skipping code build/deploy (SkipCode).' -ForegroundColor DarkYellow
    Write-Host '> [4/4] Skipping code build/deploy (SkipCode).' -ForegroundColor DarkYellow
}
else {
    Write-Host '> [3/4] Building & deploying API...' -ForegroundColor Yellow
    Publish-And-Deploy -Name 'api'   -Csproj $ApiCsproj   -AppServiceName $apiAppName

    Write-Host '> [4/4] Building & deploying Admin UI...' -ForegroundColor Yellow
    Publish-And-Deploy -Name 'admin' -Csproj $AdminCsproj -AppServiceName $adminAppName
}

# ============================================================
# Summary
# ============================================================
Write-Host ''
Write-Host '==============================================================' -ForegroundColor Green
Write-Host '   Deployment complete' -ForegroundColor Green
Write-Host '==============================================================' -ForegroundColor Green
Write-Host "  Environment : $EnvironmentName" -ForegroundColor White
Write-Host "  API         : https://$apiAppName.azurewebsites.net" -ForegroundColor White
Write-Host "  Admin UI    : https://$adminAppName.azurewebsites.net" -ForegroundColor White
Write-Host ''

$deploymentInfo = [ordered]@{
    Timestamp     = (Get-Date -Format 'o')
    Environment   = $EnvironmentName
    ResourceGroup = $ResourceGroupName
    ApiUrl        = "https://$apiAppName.azurewebsites.net"
    AdminUrl      = "https://$adminAppName.azurewebsites.net"
    TenantId      = $TenantId
    InfraDeployed = (-not $SkipInfra)
    CodeDeployed  = (-not $SkipCode)
}
$outputPath = Join-Path $InfraDir "deployment-output-$EnvironmentName.json"
$deploymentInfo | ConvertTo-Json | Out-File $outputPath -Encoding utf8
Write-Host "  Deployment info saved to: $outputPath" -ForegroundColor DarkGray
