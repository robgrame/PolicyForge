# APIM Gateway Deployment Guide

## Overview

Azure API Management (Consumption tier) acts as the security gateway for all device-facing endpoints.
Devices authenticate to APIM, which validates their JWT tokens and forwards requests to the backend
using its managed identity.

## Architecture

```
Device → APIM (validates JWT, rate limits) → Backend API (business logic)
Admin UI → Backend API directly (Entra ID JWT)
```

## Prerequisites

1. Azure CLI authenticated (`az login`)
2. Resource group exists (e.g., `cpm-dev-rg`)
3. Backend API deployed (`cpm-dev-api.azurewebsites.net`)
4. Device app registration configured (`91c07a6b-d678-48d0-b3fa-f0828aca761b`)

## Deployment Steps

### 1. Deploy APIM via Bicep

```bash
az deployment group create \
  --resource-group cpm-dev-rg \
  --template-file infra/apim/main.bicep \
  --parameters infra/apim/main.parameters.json
```

This creates:
- APIM Consumption instance with system-assigned managed identity
- Backend pointing to the App Service
- Device API with operations (GET effective-policy, POST report)
- Inbound policies (JWT validation, rate limiting, header manipulation)

### 2. Grant APIM Managed Identity Access to Backend

After deployment, get the APIM principal ID and grant it access to the backend API app registration:

```bash
# Get APIM managed identity object ID
APIM_PRINCIPAL_ID=$(az apim show -n cpm-dev-apim2 -g rg-cpm-dev --query identity.principalId -o tsv)

# Create an app role assignment for APIM to call the backend API
az ad app show --id 633d147e-7e43-42b1-abd7-15853f4a8b4b --query id -o tsv
# Use the object ID from above to assign an app role
```

### 3. Configure Backend API

Set the APIM managed identity client ID in the backend app settings:

```bash
# Get APIM managed identity client ID
APIM_CLIENT_ID=$(az ad sp show --id $APIM_PRINCIPAL_ID --query appId -o tsv)

# Set in backend App Service
az webapp config appsettings set \
  --resource-group cpm-dev-rg \
  --name cpm-dev-api \
  --settings ApimGateway__ClientId=$APIM_CLIENT_ID ApimGateway__Enabled=true
```

### 4. (Optional) Restrict Backend Direct Access

To prevent bypassing APIM, restrict the App Service to only accept traffic from APIM:

```bash
# Get APIM outbound IPs (for Consumption, use service tag)
az webapp config access-restriction add \
  --resource-group cpm-dev-rg \
  --name cpm-dev-api \
  --rule-name "AllowAPIM" \
  --priority 100 \
  --service-tag ApiManagement

# Allow Admin UI to access directly
az webapp config access-restriction add \
  --resource-group cpm-dev-rg \
  --name cpm-dev-api \
  --rule-name "AllowAdminUI" \
  --priority 200 \
  --ip-address <admin-ui-outbound-ip>/32
```

### 5. Update DNS/Client Configuration

Devices will now call:
- `https://cpm-dev-apim2.azure-api.net/api/devices/{deviceId}/effective-policy`

Instead of:
- `https://cpm-dev-api.azurewebsites.net/api/devices/{deviceId}/effective-policy`

The PowerShell scripts are already configured with the APIM URL.

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| GET /effective-policy | 30 calls | per hour per device |
| POST /report | 30 calls | per hour per device |

Devices receive `429 Too Many Requests` with `Retry-After` header when exceeded.
The client script handles this with exponential backoff + jitter.

## Monitoring

APIM provides built-in analytics:
- Request count / latency / errors
- Rate-limit hits (429s)
- JWT validation failures (401s)
- Per-device usage patterns

View in Azure Portal → APIM → Analytics, or export to Application Insights.

## Fallback Mode

If APIM is not yet deployed or is experiencing issues:
- Set environment variable `CPM_USE_DIRECT_API=true` on devices to bypass APIM
- The backend middleware allows direct access when `ApimGateway:ClientId` is not configured

## Security Considerations

- **No shared secrets**: APIM uses managed identity (token-based) to authenticate to backend
- **Anti-spoofing**: APIM strips all `X-Forwarded-*` headers from client requests before setting trusted values
- **Rate limiting**: Prevents compromised devices from overwhelming the backend
- **Token validation**: Double-checked — APIM validates device JWT, backend validates APIM identity
- **Rotation**: Managed identity credentials rotate automatically (no manual key rotation needed)
