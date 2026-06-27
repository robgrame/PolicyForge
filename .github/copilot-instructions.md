# Chrome Policy Manager - Copilot Instructions

## Subscription Security Policies

The Azure subscription enforces the following security policies via Azure Policy. These constraints are **non-negotiable** and will be auto-remediated if violated:

1. **No SAS authentication** — Shared Access Signatures are prohibited on all resources (Service Bus, Storage, etc.). Always use **Managed Identity** with `DefaultAzureCredential`.

2. **No Public Network Access** — All data-plane resources (SQL Server, Service Bus, Storage, etc.) must have `publicNetworkAccess: Disabled`. Use **Private Endpoints** for connectivity from Azure services.

## Architecture Constraints

- **SQL Server**: Must be accessed via Private Endpoint. The App Service must have VNet integration enabled to reach SQL over the private link.
- **Service Bus**: Basic tier with `disableLocalAuth: true` (MI only, no SAS — policy compliant). Private Endpoints require Premium (~€670/month), not viable for dev. Public network access remains enabled on SB but auth is locked to Managed Identity only. For production at scale, evaluate Premium tier or Storage Queue (supports PE on Standard at ~€0.05/month).
- **API Gateway (APIM)**: Handles external device traffic with mTLS client certificate auth.
- **App Services**: Must use VNet integration to access backend resources over private endpoints. `vnetRouteAllEnabled: true` ensures all outbound traffic goes through VNet.

## Key Technical Notes

- Detection script sends `deviceId` (Entra registration ID from `dsregcmd`), not the Entra object ID. The API resolves this via Graph filter `devices?$filter=deviceId eq '{id}'`.
- Intune `runRemediationScript` flag cannot be reliably set via Graph API. We use inline remediation in the detection script as a workaround.
- `Microsoft.Identity.Web` ACL validation (`AllowWebApiToBeAuthorizedByACL=true`) is required for MI tokens without roles claim.
- App registration `accessTokenAcceptedVersion` must be `2` for v2.0 tokens.
