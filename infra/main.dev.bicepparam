using './main.bicep'

// ============================================================
// DEV environment - cost-optimized SKUs
//   App Service: B1 | SQL: Basic | APIM: Developer | AppConfig: Free
// ============================================================
param environmentName = 'dev'
param skuTier = 'dev'
param location = 'westeurope'

// Service Bus is optional in dev (API falls back to synchronous processing)
param deployServiceBus = false

// APIM is the most expensive fixed-cost resource (~€45/month). Off in dev:
// devices call the backend directly (set CPM_USE_DIRECT_API=true on the device).
param deployApim = false

// Replace with your tenant/app values (or pass via --parameters on the CLI)
param tenantId = 'YOUR_TENANT_ID'
param clientId = 'YOUR_CLIENT_ID'
param clientSecret = 'REPLACE_WITH_KEYVAULT_REFERENCE'
