using './main.bicep'

// ============================================================
// PROD environment - production-grade SKUs (scale to 100k+ devices)
//   App Service: P1v3 (x2) | SQL: S2 | APIM: Standard | AppConfig: Standard
// ============================================================
param environmentName = 'prod'
param skuTier = 'prod'
param location = 'westeurope'

// Service Bus enabled in prod for async device report processing (MI-only, no SAS)
param deployServiceBus = true

// APIM required in prod: mTLS device auth, rate limiting, edge JWT validation
param deployApim = true

// Replace with your tenant/app values (or pass via --parameters on the CLI)
param tenantId = 'YOUR_TENANT_ID'
param clientId = 'YOUR_CLIENT_ID'
param clientSecret = 'REPLACE_WITH_KEYVAULT_REFERENCE'
