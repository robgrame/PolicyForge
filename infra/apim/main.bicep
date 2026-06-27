// Azure API Management - Developer tier with mTLS
// Acts as security gateway for device-facing endpoints
// Validates client certificates (PKCS/SCEP from MSLABS-SUBCA01)

@description('Azure region for APIM')
param location string = resourceGroup().location

@description('APIM instance name')
param apimName string = 'cpm-dev-apim2'

@description('Publisher email for APIM')
param publisherEmail string

@description('Publisher name for APIM')
param publisherName string = 'Chrome Policy Manager'

@description('Backend API URL')
param backendApiUrl string = 'https://cpm-dev-api.azurewebsites.net'

@description('Application Insights instrumentation key')
param appInsightsInstrumentationKey string

// APIM instance - Developer tier with client cert negotiation
resource apim 'Microsoft.ApiManagement/service@2023-09-01-preview' = {
  name: apimName
  location: location
  sku: {
    name: 'Developer'
    capacity: 1
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publisherEmail: publisherEmail
    publisherName: publisherName
    hostnameConfigurations: [
      {
        type: 'Proxy'
        hostName: '${apimName}.azure-api.net'
        negotiateClientCertificate: true
        defaultSslBinding: true
        certificateSource: 'BuiltIn'
      }
    ]
  }
}

// App Insights logger
resource appInsightsLogger 'Microsoft.ApiManagement/service/loggers@2023-09-01-preview' = {
  parent: apim
  name: 'appinsights'
  properties: {
    loggerType: 'applicationInsights'
    credentials: {
      instrumentationKey: appInsightsInstrumentationKey
    }
    isBuffered: true
  }
}

// Service-level diagnostics - log all API calls to App Insights
resource diagnostics 'Microsoft.ApiManagement/service/diagnostics@2023-09-01-preview' = {
  parent: apim
  name: 'applicationinsights'
  properties: {
    loggerId: appInsightsLogger.id
    alwaysLog: 'allErrors'
    sampling: {
      samplingType: 'fixed'
      percentage: 100
    }
    frontend: {
      request: { headers: []; body: { bytes: 0 } }
      response: { headers: []; body: { bytes: 0 } }
    }
    backend: {
      request: { headers: []; body: { bytes: 0 } }
      response: { headers: []; body: { bytes: 0 } }
    }
  }
}

// Backend definition pointing to the App Service API
resource backend 'Microsoft.ApiManagement/service/backends@2023-09-01-preview' = {
  parent: apim
  name: 'cpm-backend'
  properties: {
    title: 'Chrome Policy Manager API'
    description: 'Backend App Service hosting the CPM API'
    url: backendApiUrl
    protocol: 'http'
    credentials: {
      header: {}
      query: {}
    }
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
  }
}

// API definition for device endpoints
resource deviceApi 'Microsoft.ApiManagement/service/apis@2023-09-01-preview' = {
  parent: apim
  name: 'cpm-device-api'
  properties: {
    displayName: 'Chrome Policy Manager - Device API'
    description: 'Device-facing endpoints for Chrome policy delivery and compliance reporting'
    path: ''
    protocols: ['https']
    subscriptionRequired: false // Auth is via mTLS client certificate
    serviceUrl: '${backendApiUrl}/api/devices'
  }
}

// Operation: Get effective policy
resource getEffectivePolicy 'Microsoft.ApiManagement/service/apis/operations@2023-09-01-preview' = {
  parent: deviceApi
  name: 'get-effective-policy'
  properties: {
    displayName: 'Get Effective Policy'
    method: 'GET'
    urlTemplate: '/{deviceId}/effective-policy'
    templateParameters: [
      {
        name: 'deviceId'
        required: true
        type: 'string'
        description: 'Entra device ID'
      }
    ]
  }
}

// Operation: Submit device report
resource submitDeviceReport 'Microsoft.ApiManagement/service/apis/operations@2023-09-01-preview' = {
  parent: deviceApi
  name: 'submit-device-report'
  properties: {
    displayName: 'Submit Device Report'
    method: 'POST'
    urlTemplate: '/{deviceId}/report'
    templateParameters: [
      {
        name: 'deviceId'
        required: true
        type: 'string'
        description: 'Entra device ID'
      }
    ]
  }
}

// Operation: Ingest device logs
resource ingestDeviceLogs 'Microsoft.ApiManagement/service/apis/operations@2023-09-01-preview' = {
  parent: deviceApi
  name: 'ingest-device-logs'
  properties: {
    displayName: 'Ingest Device Logs'
    method: 'POST'
    urlTemplate: '/{deviceId}/logs'
    templateParameters: [
      {
        name: 'deviceId'
        required: true
        type: 'string'
        description: 'Entra device ID'
      }
    ]
  }
}

// Operation: Get device logs
resource getDeviceLogs 'Microsoft.ApiManagement/service/apis/operations@2023-09-01-preview' = {
  parent: deviceApi
  name: 'get-device-logs'
  properties: {
    displayName: 'Get Device Logs'
    method: 'GET'
    urlTemplate: '/{deviceId}/logs'
    templateParameters: [
      {
        name: 'deviceId'
        required: true
        type: 'string'
        description: 'Entra device ID'
      }
    ]
  }
}

// API-level policy (applies to all device operations)
resource deviceApiPolicy 'Microsoft.ApiManagement/service/apis/policies@2023-09-01-preview' = {
  parent: deviceApi
  name: 'policy'
  properties: {
    format: 'xml'
    value: loadTextContent('policies/device-api-policy.xml')
  }
}

// Output APIM managed identity for backend configuration
output apimPrincipalId string = apim.identity.principalId
output apimGatewayUrl string = apim.properties.gatewayUrl
output apimName string = apim.name
