<#
.SYNOPSIS
    Chrome Policy Manager - App-tier Deployment on SHARED infrastructure.

.DESCRIPTION
    Deploys the ChromePolicyManager application tier reusing existing shared Azure
    infrastructure (an existing Azure SQL Server reached over a Private Endpoint and an
    existing VNet). This is the scenario the generic Deploy.ps1 / main.bicep do NOT cover,
    because they provision SQL/VNet/Private Endpoints from scratch.

    The script is idempotent (safe to re-run) and performs the full sequence:
      1.  Prerequisite & login checks
      2.  Create / ensure a dedicated delegated subnet for App Service VNet integration
      3.  Create / ensure the resource group
      4.  Create / ensure the API app registration (v2 tokens, identifier uri, client secret)
      5.  Create / ensure the database on the existing shared SQL Server
      6.  Deploy the app-tier Bicep (UAMI, plan, API + Admin apps, LAW, App Insights, AppConfig, KV)
      7.  Add the API UAMI to the SQL admin Entra group (group-based SQL admin)
      8.  Grant the UAMI the required Microsoft Graph app roles (+ best-effort consent note)
      9.  Build, publish and zip-deploy the API + Admin application code
      10. Smoke test (/health + a DB-backed endpoint)

.NOTES
    Defaults match the dev deployment performed on 2026-06-25:
      - Shared SQL server : sql-dev-wtdu3uf7rupj6 (RG rg-edgm-dev-italynorth, italynorth)
      - Shared VNet       : vnet-dev (RG rg-edgm-dev-italynorth)
      - Dedicated subnet  : int-cpm (10.40.0.96/27, delegated Microsoft.Web/serverFarms)
      - SQL admin group   : dev-sql-admins

.EXAMPLE
    .\Deploy-AppTier.ps1 -EnvironmentName dev

.EXAMPLE
    .\Deploy-AppTier.ps1 -EnvironmentName dev -SkipCode
#>

[CmdletBinding()]
param(
    [ValidateSet('dev', 'prod')]
    [string]$EnvironmentName = 'dev',

    [string]$Location = 'italynorth',

    [string]$ResourceGroupName = "rg-cpm-$EnvironmentName",

    # ----- Shared infrastructure (existing) -----
    [string]$SharedInfraResourceGroup = 'rg-edgm-dev-italynorth',
    [string]$SqlServerName = 'sql-dev-wtdu3uf7rupj6',
    [string]$SqlDatabaseName = 'ChromePolicyManager',
    [string]$SqlDatabaseSku = 'Basic',
    [string]$SqlAdminGroupName = 'dev-sql-admins',
    [string]$VNetName = 'vnet-dev',
    [string]$SubnetName = 'int-cpm',
    [string]$SubnetPrefix = '10.40.0.96/27',

    # ----- App registration -----
    [string]$AppRegistrationName = 'cpm-dev-api',

    [switch]$SkipCode,
    [switch]$SkipInfra
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'
$repoRoot = Split-Path -Parent $PSScriptRoot
$infraDir = $PSScriptRoot
$prefix = "cpm-$EnvironmentName"

# Microsoft Graph well-known IDs
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$GraphAppRoles = @('Device.Read.All', 'GroupMember.Read.All')

function Write-Step { param([string]$Msg) Write-Host "`n=== $Msg ===" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "  + $Msg" -ForegroundColor Green }

# ============================================================
# 1. Prerequisites
# ============================================================
Write-Step '1/10 Prerequisite & login checks'
foreach ($t in 'az', 'dotnet') {
    if (-not (Get-Command $t -ErrorAction SilentlyContinue)) { throw "Required tool '$t' not found in PATH." }
}
$account = az account show -o json 2>$null | ConvertFrom-Json
if (-not $account) { throw 'Not logged in to Azure. Run: az login' }
$TenantId = $account.tenantId
Write-Ok "Subscription: $($account.name)  Tenant: $TenantId"

# ============================================================
# 2. Dedicated VNet integration subnet
# ============================================================
Write-Step "2/10 Ensuring delegated subnet '$SubnetName' in '$VNetName'"
$subnetId = az network vnet subnet show -g $SharedInfraResourceGroup --vnet-name $VNetName -n $SubnetName --query id -o tsv 2>$null
if (-not $subnetId) {
    $subnetId = az network vnet subnet create -g $SharedInfraResourceGroup --vnet-name $VNetName -n $SubnetName `
        --address-prefixes $SubnetPrefix --delegations Microsoft.Web/serverFarms --query id -o tsv
    Write-Ok "Subnet created: $SubnetName ($SubnetPrefix)"
}
else { Write-Ok "Subnet already exists: $SubnetName" }

# ============================================================
# 3. Resource group
# ============================================================
Write-Step "3/10 Ensuring resource group '$ResourceGroupName'"
az group create -n $ResourceGroupName -l $Location --tags project=ChromePolicyManager environment=$EnvironmentName -o none
Write-Ok "Resource group ready: $ResourceGroupName"

# ============================================================
# 4. App registration (v2 tokens, identifier uri, client secret)
# ============================================================
Write-Step "4/10 Ensuring app registration '$AppRegistrationName'"
$app = az ad app list --display-name $AppRegistrationName --query "[0].{appId:appId,id:id}" -o json | ConvertFrom-Json
if (-not $app) {
    $app = az ad app create --display-name $AppRegistrationName --sign-in-audience AzureADMyOrg --query "{appId:appId,id:id}" -o json | ConvertFrom-Json
    Write-Ok "App registration created: $($app.appId)"
}
else { Write-Ok "App registration exists: $($app.appId)" }
az ad app update --id $app.appId --identifier-uris "api://$($app.appId)" -o none
az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" `
    --headers "Content-Type=application/json" --body '{"api":{"requestedAccessTokenVersion":2}}' -o none
if (-not (az ad sp show --id $app.appId -o json 2>$null)) { az ad sp create --id $app.appId -o none }
$clientSecret = az ad app credential reset --id $app.appId --display-name 'deploy-secret' --years 2 --query password -o tsv
$clientId = $app.appId
Write-Ok 'Client secret (re)generated.'

# ============================================================
# 5. Database on the shared SQL Server
# ============================================================
Write-Step "5/10 Ensuring database '$SqlDatabaseName' on '$SqlServerName'"
$dbStatus = az sql db show -g $SharedInfraResourceGroup -s $SqlServerName -n $SqlDatabaseName --query status -o tsv 2>$null
if (-not $dbStatus) {
    az sql db create -g $SharedInfraResourceGroup -s $SqlServerName -n $SqlDatabaseName --service-objective $SqlDatabaseSku -o none
    Write-Ok "Database created ($SqlDatabaseSku)."
}
else { Write-Ok "Database already exists (status: $dbStatus)." }
$sqlFqdn = az sql server show -g $SharedInfraResourceGroup -n $SqlServerName --query fullyQualifiedDomainName -o tsv

# ============================================================
# 6. Deploy app-tier Bicep
# ============================================================
$apiAppName = "$prefix-api"
$adminAppName = "$prefix-admin"
if ($SkipInfra) {
    Write-Step '6/10 Skipping Bicep deployment (SkipInfra)'
    $uamiPrincipalId = az identity show -g $ResourceGroupName -n "$prefix-api-id" --query principalId -o tsv
}
else {
    Write-Step '6/10 Deploying app-tier Bicep'
    # Pull the Event Grid topic endpoint from the infra-tier topic (if present) so the API app
    # gets EventGrid__TopicEndpoint without losing it when the app-tier redeploys the app settings.
    $eventGridEndpoint = az eventgrid topic show -g $ResourceGroupName -n "$prefix-events" --query endpoint -o tsv 2>$null
    if (-not $eventGridEndpoint) { $eventGridEndpoint = '' }
    $deployOut = az deployment group create `
        --resource-group $ResourceGroupName `
        --name "cpm-apptier-$EnvironmentName" `
        --template-file (Join-Path $infraDir 'main.apptier.bicep') `
        --parameters (Join-Path $infraDir "main.apptier.$EnvironmentName.bicepparam") `
        --parameters clientSecret=$clientSecret tenantId=$TenantId clientId=$clientId `
                     location=$Location sqlServerFqdn=$sqlFqdn sqlDatabaseName=$SqlDatabaseName `
                     integrationSubnetId=$subnetId eventGridTopicEndpoint=$eventGridEndpoint `
        --query properties.outputs -o json | ConvertFrom-Json
    $uamiPrincipalId = $deployOut.apiIdentityPrincipalId.value
    $apiAppName = $deployOut.apiAppName.value
    $adminAppName = $deployOut.adminAppName.value
    Write-Ok "Infra deployed. API: $apiAppName  Admin: $adminAppName"
}

# ============================================================
# 7. Group-based SQL admin (UAMI -> dev-sql-admins)
# ============================================================
Write-Step "7/10 Adding UAMI to SQL admin group '$SqlAdminGroupName'"
$groupId = az ad group show --group $SqlAdminGroupName --query id -o tsv
if ((az ad group member check --group $groupId --member-id $uamiPrincipalId --query value -o tsv) -ne 'true') {
    az ad group member add --group $groupId --member-id $uamiPrincipalId -o none
    Write-Ok 'UAMI added to SQL admin group.'
}
else { Write-Ok 'UAMI already a member of the SQL admin group.' }

# ============================================================
# 8. Microsoft Graph app roles for the UAMI
# ============================================================
Write-Step '8/10 Granting Microsoft Graph app roles to the UAMI'
$graphSp = az ad sp show --id $GraphAppId --query "{id:id,roles:appRoles}" -o json | ConvertFrom-Json
foreach ($roleValue in $GraphAppRoles) {
    $roleId = ($graphSp.roles | Where-Object { $_.value -eq $roleValue }).id
    $existing = az rest --method GET `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$uamiPrincipalId/appRoleAssignments" `
        --query "value[?appRoleId=='$roleId'] | [0].id" -o tsv 2>$null
    if (-not $existing) {
        $body = (@{ principalId = $uamiPrincipalId; resourceId = $graphSp.id; appRoleId = $roleId } | ConvertTo-Json -Compress)
        az rest --method POST `
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$uamiPrincipalId/appRoleAssignments" `
            --headers "Content-Type=application/json" --body $body -o none
        Write-Ok "Granted $roleValue"
    }
    else { Write-Ok "$roleValue already granted." }
}
Write-Host '  ! Note: MI token cache can delay the roles claim up to ~24h. If Graph returns 401/403,' -ForegroundColor DarkYellow
Write-Host "    remove + reassign the UAMI on the API app and restart to force a fresh token." -ForegroundColor DarkYellow

# ============================================================
# 9. Build, publish & deploy application code
# ============================================================
function Publish-And-Deploy {
    param([string]$Name, [string]$Csproj, [string]$AppServiceName)
    Write-Host "  > Publishing $Name ..." -ForegroundColor Yellow
    $publishDir = Join-Path $env:TEMP "cpm-publish\$Name"
    $zipPath = Join-Path $env:TEMP "cpm-publish\$Name.zip"
    if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }
    if (Test-Path $zipPath)    { Remove-Item $zipPath -Force }
    dotnet publish $Csproj -c Release -o $publishDir --nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $Name" }
    Compress-Archive -Path (Join-Path $publishDir '*') -DestinationPath $zipPath -Force
    az webapp deploy --resource-group $ResourceGroupName --name $AppServiceName --src-path $zipPath --type zip --output none
    if ($LASTEXITCODE -ne 0) { throw "Code deployment failed for $Name ($AppServiceName)" }
    Write-Ok "$Name deployed to https://$AppServiceName.azurewebsites.net"
}

if ($SkipCode) { Write-Step '9/10 Skipping code build/deploy (SkipCode)' }
else {
    Write-Step '9/10 Building & deploying application code'
    Publish-And-Deploy -Name 'api'   -Csproj (Join-Path $repoRoot 'src\Server\ChromePolicyManager.Api\ChromePolicyManager.Api.csproj')     -AppServiceName $apiAppName
    Publish-And-Deploy -Name 'admin' -Csproj (Join-Path $repoRoot 'src\Server\ChromePolicyManager.Admin\ChromePolicyManager.Admin.csproj') -AppServiceName $adminAppName
}

# ============================================================
# 10. Smoke test
# ============================================================
Write-Step '10/10 Smoke test'
Start-Sleep -Seconds 15
try {
    $health = Invoke-RestMethod -Uri "https://$apiAppName.azurewebsites.net/health" -TimeoutSec 90
    Write-Ok "API /health: $($health.status)"
    $stats = Invoke-RestMethod -Uri "https://$apiAppName.azurewebsites.net/api/catalog/stats" -TimeoutSec 90
    Write-Ok "API DB connectivity OK (catalog entries: $($stats.totalEntries))"
}
catch { Write-Host "  ! Smoke test warning: $($_.Exception.Message)" -ForegroundColor DarkYellow }

Write-Host "`n==============================================================" -ForegroundColor Green
Write-Host '   App-tier deployment complete' -ForegroundColor Green
Write-Host '==============================================================' -ForegroundColor Green
Write-Host "  Environment : $EnvironmentName" -ForegroundColor White
Write-Host "  API         : https://$apiAppName.azurewebsites.net" -ForegroundColor White
Write-Host "  Admin UI    : https://$adminAppName.azurewebsites.net" -ForegroundColor White
Write-Host "  SQL         : $sqlFqdn / $SqlDatabaseName" -ForegroundColor White
