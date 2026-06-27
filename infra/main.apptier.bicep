// Chrome Policy Manager - App-tier Infrastructure (Bicep)
// =========================================================
// Deploys ONLY the application tier, reusing existing shared infrastructure:
//   - Existing Azure SQL Server (private endpoint + private DNS already in place)
//   - Existing VNet with a dedicated delegated subnet for App Service integration
//
// Provisions: User-Assigned Managed Identity, Log Analytics, App Insights,
//             App Service Plan, API + Admin App Services (VNet integrated),
//             App Configuration, Key Vault.
//
// Security policies enforced by subscription:
//   - No SAS authentication (Managed Identity everywhere)
//   - No public network access on data-plane (SQL reached over Private Endpoint via VNet integration)

targetScope = 'resourceGroup'

@description('Environment name (dev, staging, prod)')
param environmentName string = 'dev'

@description('Azure region for resources')
param location string = resourceGroup().location

@description('Entra ID tenant ID')
param tenantId string

@description('App registration client ID (used for inbound JWT validation)')
param clientId string

@secure()
@description('App registration client secret (inbound auth config; Graph/SQL use the UAMI)')
param clientSecret string = ''

@description('Admin portal app registration client ID (Entra SSO / OpenID Connect)')
param adminClientId string = ''

@secure()
@description('Admin portal app registration client secret (Entra SSO / OpenID Connect)')
param adminClientSecret string = ''

@description('Fully-qualified domain name of the existing Azure SQL Server')
param sqlServerFqdn string

@description('Name of the database on the existing SQL Server')
param sqlDatabaseName string = 'ChromePolicyManager'

@description('Resource ID of the existing delegated subnet for App Service VNet integration')
param integrationSubnetId string

@description('SKU tier driving resource sizing. "dev" = cost-optimized, "prod" = production-grade.')
@allowed([
  'dev'
  'prod'
])
param skuTier string = environmentName == 'prod' ? 'prod' : 'dev'

@description('Deploy the privileged-action Worker Function App (ADR-001). Requires the Service Bus namespace to exist.')
param deployWorker bool = false

@description('Existing Service Bus namespace name used by the Worker (defaults to <prefix>-sb).')
param serviceBusNamespaceName string = ''

@description('Intune deviceHealthScript policy id used by the Worker for proactive remediation.')
param pushRemediationScriptPolicyId string = ''

@description('Event Grid topic endpoint for the policy-status pipeline (from the infra tier output).')
param eventGridTopicEndpoint string = ''

var prefix = 'cpm-${environmentName}'
// Short suffix for globally-unique resource names (Key Vault, App Configuration)
var uniqueSuffix = take(uniqueString(resourceGroup().id), 6)
var tags = {
  project: 'ChromePolicyManager'
  environment: environmentName
  skuTier: skuTier
}

// ============================================================
// SKU configuration - two tiers (dev / prod)
// ============================================================
var skuConfig = {
  dev: {
    appServicePlan: { name: 'B1', tier: 'Basic', capacity: 1 }
    appConfig: { name: 'Free' }
    logRetentionDays: 30
  }
  prod: {
    appServicePlan: { name: 'P1v3', tier: 'PremiumV3', capacity: 2 }
    appConfig: { name: 'Standard' }
    logRetentionDays: 90
  }
}
var sku = skuConfig[skuTier]

// ============================================================
// Observability
// ============================================================
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${prefix}-workspace'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: sku.logRetentionDays
  }
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${prefix}-insights'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspace.id
  }
}

// ============================================================
// User-Assigned Managed Identity (API app -> Graph / SQL)
// Known principalId up-front so it can be added to the SQL admin group
// and granted Graph app roles after deployment.
// ============================================================
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-api-id'
  location: location
  tags: tags
}

// ============================================================
// App Service Plan + Apps (VNet integrated)
// ============================================================
resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${prefix}-plan'
  location: location
  tags: tags
  sku: {
    name: sku.appServicePlan.name
    tier: sku.appServicePlan.tier
    capacity: sku.appServicePlan.capacity
  }
  properties: {
    reserved: false // Windows
  }
}

resource apiAppService 'Microsoft.Web/sites@2023-12-01' = {
  name: '${prefix}-api'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${uami.id}': {}
    }
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    virtualNetworkSubnetId: integrationSubnetId
    siteConfig: {
      netFrameworkVersion: 'v10.0'
      vnetRouteAllEnabled: true // Route all traffic through VNet (needed to reach SQL Private Endpoint)
      appSettings: [
        { name: 'AzureAd__TenantId', value: tenantId }
        { name: 'AzureAd__ClientId', value: clientId }
        { name: 'AzureAd__ClientSecret', value: clientSecret }
        { name: 'AzureAd__AllowWebApiToBeAuthorizedByACL', value: 'true' }
        // DefaultAzureCredential picks this UAMI for Graph / SQL tokens
        { name: 'AZURE_CLIENT_ID', value: uami.properties.clientId }
        { name: 'ASPNETCORE_ENVIRONMENT', value: environmentName == 'prod' ? 'Production' : 'Development' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: applicationInsights.properties.ConnectionString }
        { name: 'EventGrid__TopicEndpoint', value: eventGridTopicEndpoint }
        { name: 'AppConfig__Endpoint', value: appConfig.properties.endpoint }
      ]
      connectionStrings: [
        {
          name: 'DefaultConnection'
          connectionString: 'Server=tcp:${sqlServerFqdn},1433;Database=${sqlDatabaseName};Authentication=Active Directory Default;'
          type: 'SQLAzure'
        }
      ]
    }
  }
}

resource adminAppService 'Microsoft.Web/sites@2023-12-01' = {
  name: '${prefix}-admin'
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    virtualNetworkSubnetId: integrationSubnetId
    siteConfig: {
      netFrameworkVersion: 'v10.0'
      vnetRouteAllEnabled: true
      appSettings: [
        { name: 'ASPNETCORE_ENVIRONMENT', value: environmentName == 'prod' ? 'Production' : 'Development' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: applicationInsights.properties.ConnectionString }
        { name: 'ApiBaseUrl', value: 'https://${prefix}-api.azurewebsites.net' }
        // Entra ID (Microsoft Identity Web) - portal SSO / OpenID Connect
        { name: 'AzureAd__Instance', value: 'https://login.microsoftonline.com/' }
        { name: 'AzureAd__TenantId', value: tenantId }
        { name: 'AzureAd__ClientId', value: adminClientId }
        { name: 'AzureAd__ClientSecret', value: adminClientSecret }
        { name: 'AzureAd__CallbackPath', value: '/signin-oidc' }
        { name: 'AzureAd__SignedOutCallbackPath', value: '/signout-callback-oidc' }
        { name: 'AppConfig__Endpoint', value: appConfig.properties.endpoint }
      ]
    }
  }
}

// ============================================================
// App Configuration (canonical store created by the infra-tier template).
// Referenced as existing so the app-tier never creates a duplicate store.
// ============================================================
resource appConfig 'Microsoft.AppConfiguration/configurationStores@2023-03-01' existing = {
  name: '${prefix}-config'
}

// App Configuration Data Reader for the API (UAMI) and Admin portal (system-assigned).
resource appConfigReaderApi 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appConfig.id, uami.id, 'AppConfigDataReader')
  scope: appConfig
  properties: {
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '516239f1-63e1-4d78-a4de-a74fb236a071')
  }
}

resource appConfigReaderAdmin 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appConfig.id, adminAppService.id, 'AppConfigDataReader')
  scope: appConfig
  properties: {
    principalId: adminAppService.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '516239f1-63e1-4d78-a4de-a74fb236a071')
  }
}

// ============================================================
// Key Vault
// ============================================================
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${prefix}-kv-${uniqueSuffix}'
  location: location
  tags: tags
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
  }
}

// ============================================================
// Privileged-action Worker (ADR-001) - opt-in
// ============================================================
module worker 'modules/worker.bicep' = if (deployWorker) {
  name: 'worker'
  params: {
    prefix: prefix
    location: location
    tags: tags
    appServicePlanId: appServicePlan.id
    integrationSubnetId: integrationSubnetId
    appInsightsConnectionString: applicationInsights.properties.ConnectionString
    serviceBusNamespaceName: empty(serviceBusNamespaceName) ? '${prefix}-sb' : serviceBusNamespaceName
    pushRemediationScriptPolicyId: pushRemediationScriptPolicyId
    uniqueSuffix: uniqueSuffix
  }
}

// ============================================================
// Outputs
// ============================================================
output apiUrl string = 'https://${apiAppService.properties.defaultHostName}'
output adminUrl string = 'https://${adminAppService.properties.defaultHostName}'
output appConfigEndpoint string = appConfig.properties.endpoint
output keyVaultUri string = keyVault.properties.vaultUri
output appInsightsConnectionString string = applicationInsights.properties.ConnectionString
output skuTier string = skuTier
output apiIdentityClientId string = uami.properties.clientId
output apiIdentityPrincipalId string = uami.properties.principalId
output apiAppName string = apiAppService.name
output adminAppName string = adminAppService.name
output resourceGroupName string = resourceGroup().name
output workerAppName string = deployWorker ? worker.outputs.workerAppName : ''
output workerIdentityPrincipalId string = deployWorker ? worker.outputs.workerIdentityPrincipalId : ''
