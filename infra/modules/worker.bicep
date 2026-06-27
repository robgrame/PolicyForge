// ============================================================
// Privileged-action Worker (ADR-001)
// Azure Functions (.NET isolated) hosted on the existing App Service Plan (Dedicated).
// SB-triggered CommandHandler consumes cpm-commands and reports on cpm-command-status.
// Passwordless throughout: Managed Identity for Storage, Service Bus and Graph (no SAS).
// Deployed opt-in (deployWorker=true) once the Service Bus namespace exists.
// ============================================================

@description('Resource name prefix, e.g. cpm-dev')
param prefix string

param location string = resourceGroup().location
param tags object = {}

@description('Existing App Service Plan id to host the Function App (Dedicated mode).')
param appServicePlanId string

@description('VNet integration subnet id (to reach private endpoints).')
param integrationSubnetId string

@description('Application Insights connection string.')
param appInsightsConnectionString string

@description('Existing Service Bus namespace name (same resource group).')
param serviceBusNamespaceName string

@description('Intune deviceHealthScript policy id used for proactive remediation.')
param pushRemediationScriptPolicyId string = ''

@description('Short unique suffix for the globally-unique storage account name.')
param uniqueSuffix string

// ---- Worker managed identity ----
resource workerUami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-worker-id'
  location: location
  tags: tags
}

// ---- Runtime storage (identity-based, no SAS) ----
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'cpm${uniqueSuffix}wrk'
  location: location
  tags: tags
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowSharedKeyAccess: false // policy: no SAS / shared keys
    publicNetworkAccess: 'Enabled'
  }
}

resource serviceBus 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' existing = {
  name: serviceBusNamespaceName
}

// ---- Function App (isolated worker, Dedicated plan) ----
resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: '${prefix}-worker'
  location: location
  tags: tags
  kind: 'functionapp'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${workerUami.id}': {}
    }
  }
  properties: {
    serverFarmId: appServicePlanId
    httpsOnly: true
    virtualNetworkSubnetId: integrationSubnetId
    siteConfig: {
      netFrameworkVersion: 'v10.0'
      vnetRouteAllEnabled: true
      appSettings: [
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'dotnet-isolated' }
        // Identity-based AzureWebJobsStorage (no connection string / SAS)
        { name: 'AzureWebJobsStorage__accountName', value: storage.name }
        { name: 'AzureWebJobsStorage__credential', value: 'managedidentity' }
        { name: 'AzureWebJobsStorage__clientId', value: workerUami.properties.clientId }
        // DefaultAzureCredential / identity-based bindings pick this UAMI
        { name: 'AZURE_CLIENT_ID', value: workerUami.properties.clientId }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsightsConnectionString }
        // Service Bus trigger via Managed Identity (namespace SAS disabled)
        { name: 'ServiceBus__fullyQualifiedNamespace', value: '${serviceBusNamespaceName}.servicebus.windows.net' }
        { name: 'ServiceBus__clientId', value: workerUami.properties.clientId }
        { name: 'ServiceBus:CommandQueue', value: 'cpm-commands' }
        { name: 'ServiceBus:CommandStatusQueue', value: 'cpm-command-status' }
        { name: 'PushRemediation:ScriptPolicyId', value: pushRemediationScriptPolicyId }
      ]
    }
  }
}

// ---- RBAC ----
// Storage: worker UAMI needs Blob + Queue + Table data access for the Functions host.
var storageBlobDataOwner = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
var storageQueueDataContributor = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
var storageTableDataContributor = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var serviceBusDataOwner = '090c5cfd-751d-490a-894a-3ce6f1109419'

resource roleBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, workerUami.id, storageBlobDataOwner)
  scope: storage
  properties: {
    principalId: workerUami.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwner)
    principalType: 'ServicePrincipal'
  }
}

resource roleQueue 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, workerUami.id, storageQueueDataContributor)
  scope: storage
  properties: {
    principalId: workerUami.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageQueueDataContributor)
    principalType: 'ServicePrincipal'
  }
}

resource roleTable 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, workerUami.id, storageTableDataContributor)
  scope: storage
  properties: {
    principalId: workerUami.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributor)
    principalType: 'ServicePrincipal'
  }
}

resource roleServiceBus 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(serviceBus.id, workerUami.id, serviceBusDataOwner)
  scope: serviceBus
  properties: {
    principalId: workerUami.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', serviceBusDataOwner)
    principalType: 'ServicePrincipal'
  }
}

output workerAppName string = functionApp.name
output workerUrl string = 'https://${functionApp.properties.defaultHostName}'
output workerIdentityClientId string = workerUami.properties.clientId
output workerIdentityPrincipalId string = workerUami.properties.principalId
