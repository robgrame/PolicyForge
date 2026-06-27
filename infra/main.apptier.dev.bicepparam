using './main.apptier.bicep'

// App-tier deployment for the DEV environment, reusing shared infrastructure:
//   - Existing SQL Server: sql-dev-wtdu3uf7rupj6 (Private Endpoint + DNS already in place)
//   - Existing VNet vnet-dev, dedicated subnet int-cpm (delegated to Microsoft.Web/serverFarms)

param environmentName = 'dev'
param location = 'italynorth'
param skuTier = 'dev'

param tenantId = '46b06a5e-8f7a-467b-bc9a-e776011fbb57'
param clientId = 'ae875325-6268-4736-aef0-c8f9104af2f7'
// Secret supplied at deploy time via -p clientSecret=... (kept out of source control)
param clientSecret = ''

// Admin portal SSO app registration (cpm-dev-admin)
param adminClientId = 'f95e524f-36a3-4f1b-8287-6ccc8a8316d9'
// Secret supplied at deploy time via -p adminClientSecret=... (kept out of source control)
param adminClientSecret = ''

param sqlServerFqdn = 'sql-dev-wtdu3uf7rupj6.database.windows.net'
param sqlDatabaseName = 'ChromePolicyManager'

param integrationSubnetId = '/subscriptions/b45c5b53-d8f3-4a4c-9fe5-5537818a9886/resourceGroups/rg-edgm-dev-italynorth/providers/Microsoft.Network/virtualNetworks/vnet-dev/subnets/int-cpm'
