// Chrome Policy Manager - Infrastructure (Bicep)
// This file defines the Azure infrastructure for the solution.
// Components: VNet, App Service (VNet integrated), Azure SQL (Private Endpoint),
//             Service Bus (Private Endpoint, MI-only), APIM, App Configuration, Key Vault, App Insights
//
// Security policies enforced by subscription:
//   - No SAS authentication (use Managed Identity everywhere)
//   - No public network access on data-plane resources (use Private Endpoints)

targetScope = 'resourceGroup'

@description('Environment name (dev, staging, prod)')
param environmentName string = 'dev'

@description('Azure region for resources')
param location string = resourceGroup().location

@description('Entra ID tenant ID')
param tenantId string

@description('App registration client ID')
param clientId string

@secure()
@description('App registration client secret')
param clientSecret string

@description('VNet address prefix')
param vnetAddressPrefix string = '10.0.0.0/16'

@description('App Service integration subnet prefix')
param appSubnetPrefix string = '10.0.1.0/24'

@description('Private Endpoints subnet prefix')
param privateEndpointSubnetPrefix string = '10.0.2.0/24'

@description('SKU tier driving resource sizing. "dev" = cost-optimized, "prod" = production-grade.')
@allowed([
  'dev'
  'prod'
])
param skuTier string = environmentName == 'prod' ? 'prod' : 'dev'

var prefix = 'cpm-${environmentName}'
var tags = {
  project: 'ChromePolicyManager'
  environment: environmentName
  skuTier: skuTier
}

// ============================================================
// SKU configuration - two tiers (dev / prod)
// dev  : minimal cost for development & testing
// prod : production-grade for scale (100k+ devices), SLA-backed
// ============================================================
var skuConfig = {
  dev: {
    appServicePlan: {
      name: 'B1'
      tier: 'Basic'
      capacity: 1
    }
    sqlDatabase: {
      name: 'Basic'
      tier: 'Basic'
    }
    serviceBus: {
      name: 'Standard'
      tier: 'Standard'
    }
    apim: {
      name: 'Developer'
      capacity: 1
    }
    appConfig: {
      name: 'Free'
    }
    logRetentionDays: 30
  }
  prod: {
    appServicePlan: {
      name: 'P1v3'
      tier: 'PremiumV3'
      capacity: 2
    }
    sqlDatabase: {
      name: 'S2'
      tier: 'Standard'
    }
    serviceBus: {
      name: 'Standard'
      tier: 'Standard'
    }
    apim: {
      name: 'Standard'
      capacity: 1
    }
    appConfig: {
      name: 'Standard'
    }
    logRetentionDays: 90
  }
}
var sku = skuConfig[skuTier]

// ============================================================
// Networking - VNet, Subnets, Private DNS Zones
// ============================================================

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: '${prefix}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [vnetAddressPrefix]
    }
    subnets: [
      {
        name: 'app-integration'
        properties: {
          addressPrefix: appSubnetPrefix
          delegations: [
            {
              name: 'appServiceDelegation'
              properties: {
                serviceName: 'Microsoft.Web/serverFarms'
              }
            }
          ]
        }
      }
      {
        name: 'private-endpoints'
        properties: {
          addressPrefix: privateEndpointSubnetPrefix
        }
      }
    ]
  }
}

// Private DNS Zones
resource privateDnsZoneSql 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink${environment().suffixes.sqlServerHostname}'
  location: 'global'
  tags: tags
}

resource privateDnsZoneServiceBus 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.servicebus.windows.net'
  location: 'global'
  tags: tags
}

// Link DNS zones to VNet
resource dnsZoneLinkSql 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZoneSql
  name: '${prefix}-sql-link'
  location: 'global'
  properties: {
    virtualNetwork: { id: vnet.id }
    registrationEnabled: false
  }
}

resource dnsZoneLinkServiceBus 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZoneServiceBus
  name: '${prefix}-sb-link'
  location: 'global'
  properties: {
    virtualNetwork: { id: vnet.id }
    registrationEnabled: false
  }
}

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
// User-Assigned Managed Identity (shared by API app + SQL admin)
// Using a UAMI makes the principalId known up-front, which breaks the
// circular dependency between the App Service and the SQL Server AAD admin.
// ============================================================

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-api-id'
  location: location
  tags: tags
}

// ============================================================
// App Service Plan + Apps (with VNet integration)
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
    virtualNetworkSubnetId: vnet.properties.subnets[0].id
    siteConfig: {
      netFrameworkVersion: 'v10.0'
      vnetRouteAllEnabled: true // Route all traffic through VNet (needed for Private Endpoints)
      appSettings: [
        { name: 'AzureAd__TenantId', value: tenantId }
        { name: 'AzureAd__ClientId', value: clientId }
        { name: 'AzureAd__ClientSecret', value: clientSecret }
        { name: 'AzureAd__AllowWebApiToBeAuthorizedByACL', value: 'true' }
        // DefaultAzureCredential picks this UAMI for Graph / SQL / Service Bus tokens
        { name: 'AZURE_CLIENT_ID', value: uami.properties.clientId }
        { name: 'ASPNETCORE_ENVIRONMENT', value: environmentName == 'prod' ? 'Production' : 'Development' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: applicationInsights.properties.ConnectionString }
        { name: 'ServiceBus__FullyQualifiedNamespace', value: deployServiceBus ? '${serviceBusNamespace.name}.servicebus.windows.net' : '' }
        { name: 'EventGrid__TopicEndpoint', value: eventGridTopic.properties.endpoint }
        { name: 'AppConfig__Endpoint', value: appConfig.properties.endpoint }
      ]
      connectionStrings: [
        {
          name: 'DefaultConnection'
          connectionString: 'Server=tcp:${sqlServer.properties.fullyQualifiedDomainName},1433;Database=${sqlDatabase.name};Authentication=Active Directory Default;'
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
    virtualNetworkSubnetId: vnet.properties.subnets[0].id
    siteConfig: {
      netFrameworkVersion: 'v10.0'
      vnetRouteAllEnabled: true
      appSettings: [
        { name: 'ASPNETCORE_ENVIRONMENT', value: environmentName == 'prod' ? 'Production' : 'Development' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: applicationInsights.properties.ConnectionString }
        { name: 'ApiBaseUrl', value: 'https://${prefix}-api.azurewebsites.net' }
        { name: 'AppConfig__Endpoint', value: appConfig.properties.endpoint }
      ]
    }
  }
}

// ============================================================
// Azure SQL Server (Private Endpoint, no public access)
// ============================================================

resource sqlServer 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: '${prefix}-sql'
  location: location
  tags: tags
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: clientSecret // Use Key Vault in production
    publicNetworkAccess: 'Disabled'
    administrators: {
      azureADOnlyAuthentication: true
      principalType: 'Application'
      login: 'ChromePolicyManager API'
      sid: uami.properties.principalId
      tenantId: tenantId
    }
  }
}

resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sqlServer
  name: 'ChromePolicyManager'
  location: location
  tags: tags
  sku: {
    name: sku.sqlDatabase.name
    tier: sku.sqlDatabase.tier
  }
}

// SQL Server Private Endpoint
resource sqlPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${prefix}-sql-pe'
  location: location
  tags: tags
  properties: {
    subnet: { id: vnet.properties.subnets[1].id }
    privateLinkServiceConnections: [
      {
        name: '${prefix}-sql-plsc'
        properties: {
          privateLinkServiceId: sqlServer.id
          groupIds: ['sqlServer']
        }
      }
    ]
  }
}

resource sqlPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = {
  parent: sqlPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'sqlServer'
        properties: {
          privateDnsZoneId: privateDnsZoneSql.id
        }
      }
    ]
  }
}

// ============================================================
// Service Bus (Optional - for async report processing)
// Requires Standard tier for Private Endpoints (cost consideration).
// When not deployed, the API falls back to synchronous processing.
// Set deployServiceBus=true for production with async processing needs.
// ============================================================

@description('Deploy Service Bus for async processing (Standard tier required for PE, adds ~€10/month)')
param deployServiceBus bool = false

resource serviceBusNamespace 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = if (deployServiceBus) {
  name: '${prefix}-sb'
  location: location
  tags: tags
  sku: {
    name: sku.serviceBus.name
    tier: sku.serviceBus.tier
  }
  properties: {
    disableLocalAuth: true // No SAS — Managed Identity only
    publicNetworkAccess: 'Disabled'
  }
}

resource deviceReportQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = if (deployServiceBus) {
  parent: serviceBusNamespace
  name: 'device-reports'
  properties: {
    maxDeliveryCount: 5
    lockDuration: 'PT5M'
    defaultMessageTimeToLive: 'P7D'
    deadLetteringOnMessageExpiration: true
  }
}

// Decoupled privileged-action pipeline (ADR-001): commands (API -> Worker) + status (Worker -> API).
resource commandsQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = if (deployServiceBus) {
  parent: serviceBusNamespace
  name: 'cpm-commands'
  properties: {
    maxDeliveryCount: 5
    lockDuration: 'PT5M'
    defaultMessageTimeToLive: 'P14D'
    deadLetteringOnMessageExpiration: true
  }
}

resource commandStatusQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = if (deployServiceBus) {
  parent: serviceBusNamespace
  name: 'cpm-command-status'
  properties: {
    maxDeliveryCount: 5
    lockDuration: 'PT1M'
    defaultMessageTimeToLive: 'P1D'
    deadLetteringOnMessageExpiration: true
  }
}

// Service Bus Private Endpoint
resource serviceBusPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = if (deployServiceBus) {
  name: '${prefix}-sb-pe'
  location: location
  tags: tags
  properties: {
    subnet: { id: vnet.properties.subnets[1].id }
    privateLinkServiceConnections: [
      {
        name: '${prefix}-sb-plsc'
        properties: {
          privateLinkServiceId: serviceBusNamespace.id
          groupIds: ['namespace']
        }
      }
    ]
  }
}

resource serviceBusPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = if (deployServiceBus) {
  parent: serviceBusPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'serviceBus'
        properties: {
          privateDnsZoneId: privateDnsZoneServiceBus.id
        }
      }
    ]
  }
}

// RBAC: API Managed Identity → Service Bus Data Owner
resource serviceBusRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployServiceBus) {
  name: guid(serviceBusNamespace.id, uami.id, '090c5cfd-751d-490a-894a-3ce6f1109419')
  scope: serviceBusNamespace
  properties: {
    principalId: uami.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '090c5cfd-751d-490a-894a-3ce6f1109419') // Azure Service Bus Data Owner
    principalType: 'ServicePrincipal'
  }
}

// ============================================================
// Event Grid - policy-application status pipeline (feeds the portal)
// Publishers (API now; Worker later) push DevicePolicyStatusChanged events here.
// The API webhook subscriber rebroadcasts them to the portal over SignalR.
// MI-only (disableLocalAuth) — policy compliant, no SAS keys.
// ============================================================

@description('Deploy the Event Grid event subscription (webhook to the API). Enable AFTER the API code with /api/eventgrid is deployed and reachable, so the validation handshake succeeds.')
param deployEventGridSubscription bool = false

resource eventGridTopic 'Microsoft.EventGrid/topics@2023-12-15-preview' = {
  name: '${prefix}-events'
  location: location
  tags: tags
  properties: {
    inputSchema: 'EventGridSchema'
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: true // No access keys — Managed Identity only
  }
}

// RBAC: API Managed Identity → EventGrid Data Sender (publish events)
resource eventGridSenderRoleApi 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(eventGridTopic.id, uami.id, 'd5a91429-5739-47e2-a06b-3470a27159e7')
  scope: eventGridTopic
  properties: {
    principalId: uami.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'd5a91429-5739-47e2-a06b-3470a27159e7') // EventGrid Data Sender
    principalType: 'ServicePrincipal'
  }
}

// Webhook subscription → API /api/eventgrid/policy-status (opt-in; API must be live for validation)
resource policyStatusSubscription 'Microsoft.EventGrid/topics/eventSubscriptions@2023-12-15-preview' = if (deployEventGridSubscription) {
  parent: eventGridTopic
  name: 'portal-policy-status'
  properties: {
    destination: {
      endpointType: 'WebHook'
      properties: {
        endpointUrl: 'https://${apiAppService.properties.defaultHostName}/api/eventgrid/policy-status'
        maxEventsPerBatch: 10
        preferredBatchSizeInKilobytes: 64
      }
    }
    filter: {
      includedEventTypes: [
        'ChromePolicyManager.DevicePolicyStatusChanged'
      ]
    }
    eventDeliverySchema: 'EventGridSchema'
    retryPolicy: {
      maxDeliveryAttempts: 30
      eventTimeToLiveInMinutes: 1440
    }
  }
}

// ============================================================
// App Configuration
// ============================================================

resource appConfig 'Microsoft.AppConfiguration/configurationStores@2023-03-01' = {
  name: '${prefix}-config'
  location: location
  tags: tags
  sku: {
    name: sku.appConfig.name
  }
}

// App Configuration Data Reader (516239f1-63e1-4d78-a4de-a74fb236a071) so the API (UAMI)
// and the Admin portal (system-assigned identity) can read settings via Managed Identity.
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
  name: '${prefix}-kv'
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
// API Management - mTLS gateway for device traffic
// APIM (Developer SKU) is the single most expensive fixed-cost resource.
// It is optional in dev: when not deployed, devices call the backend directly
// (set CPM_USE_DIRECT_API=true on the device, and leave ApimGateway:ClientId unset
//  so the backend middleware allows direct access).
// In prod it is required (mTLS, rate limiting, edge JWT validation).
// ============================================================

@description('Deploy API Management gateway. Defaults to true only for the prod SKU tier (Developer SKU ~€45/month).')
param deployApim bool = skuTier == 'prod'

resource apim 'Microsoft.ApiManagement/service@2023-09-01-preview' = if (deployApim) {
  name: '${prefix}-apim2'
  location: location
  tags: tags
  sku: {
    name: sku.apim.name
    capacity: sku.apim.capacity
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publisherEmail: 'admin@yourdomain.com'
    publisherName: 'Chrome Policy Manager'
    hostnameConfigurations: [
      {
        type: 'Proxy'
        hostName: '${prefix}-apim2.azure-api.net'
        negotiateClientCertificate: true
        defaultSslBinding: true
        certificateSource: 'BuiltIn'
      }
    ]
  }
}

resource apimLogger 'Microsoft.ApiManagement/service/loggers@2023-09-01-preview' = if (deployApim) {
  parent: apim
  name: 'appinsights'
  properties: {
    loggerType: 'applicationInsights'
    credentials: {
      instrumentationKey: applicationInsights.properties.InstrumentationKey
    }
    isBuffered: true
  }
}

resource apimDiagnostics 'Microsoft.ApiManagement/service/diagnostics@2023-09-01-preview' = if (deployApim) {
  parent: apim
  name: 'applicationinsights'
  properties: {
    loggerId: apimLogger.id
    alwaysLog: 'allErrors'
    sampling: {
      samplingType: 'fixed'
      percentage: 100
    }
  }
}

// APIM - Device API (Client-facing, mTLS)
resource apimDeviceApi 'Microsoft.ApiManagement/service/apis@2023-09-01-preview' = if (deployApim) {
  parent: apim
  name: 'device-api'
  properties: {
    displayName: 'Chrome Policy Device API'
    path: ''
    protocols: ['https']
    serviceUrl: 'https://${apiAppService.properties.defaultHostName}/api/devices'
    subscriptionRequired: false // Auth is via mTLS client certificate
  }
}

// ============================================================
// Outputs
// ============================================================

output apiUrl string = 'https://${apiAppService.properties.defaultHostName}'
output adminUrl string = 'https://${adminAppService.properties.defaultHostName}'
output apimGatewayUrl string = deployApim ? apim.properties.gatewayUrl : ''
output appConfigEndpoint string = appConfig.properties.endpoint
output eventGridTopicEndpoint string = eventGridTopic.properties.endpoint
output keyVaultUri string = keyVault.properties.vaultUri
output serviceBusNamespace string = deployServiceBus ? serviceBusNamespace.name : ''
output appInsightsConnectionString string = applicationInsights.properties.ConnectionString
output vnetId string = vnet.id
output skuTier string = skuTier
output apiIdentityClientId string = uami.properties.clientId
output apiIdentityPrincipalId string = uami.properties.principalId
output apiAppName string = apiAppService.name
output adminAppName string = adminAppService.name
output resourceGroupName string = resourceGroup().name
