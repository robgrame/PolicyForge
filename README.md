# PolicyForge

> ⚠️ **Repository in evoluzione.** PolicyForge nasce come *clone evolutivo* di
> ChromePolicyManager e lo generalizza in una **piattaforma universale di desired-state
> configuration per device Intune** (qualunque ADMX + registry, servizi Windows, scheduled
> task, file, gruppi locali, variabili d'ambiente — stile *Group Policy Preferences*).
> Il codice qui sotto è ancora quello Chrome-specifico ereditato; il refactor è descritto
> in **[`docs/adr-002-policyforge-piattaforma-configurazione-universale.md`](docs/adr-002-policyforge-piattaforma-configurazione-universale.md)**.

---

## Eredità: Chrome Policy Manager

> **Server-side Chrome policy delivery for Entra ID–only (Azure AD joined) devices — bypassing the Group Policy dependency that breaks ADMX-based Chrome settings on cloud-managed endpoints.**

[![.NET 10](https://img.shields.io/badge/.NET-10.0-purple)](https://dotnet.microsoft.com/)
[![Azure](https://img.shields.io/badge/Azure-Deployed-blue)](https://azure.microsoft.com/)
[![Intune](https://img.shields.io/badge/Intune-Proactive%20Remediation-green)](https://learn.microsoft.com/en-us/mem/intune/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🎯 The Problem

Chrome policies deployed via **Intune Settings Catalog** (ADMX-backed) **fail silently** on Entra ID–only joined devices. This happens because:

1. **GP Notification dependency** — Chrome's `PolicyLoaderWin` calls `RegisterGPNotification()` which requires a domain-joined machine
2. **Domain join gate** — `mdm_utils.cc` checks `IsEnrolledToDomain()` before applying policies
3. **ADMX registry mirroring** — Intune writes to `HKLM:\SOFTWARE\Microsoft\PolicyManager\providers\...` but the GP Client Service never mirrors them to `HKLM:\SOFTWARE\Policies\Google\Chrome` on cloud-only devices

This affects **ALL Chrome policies equally** on cloud-only joined devices — not just specific ones.

## 💡 The Solution

Chrome Policy Manager implements a **server-side policy resolution engine** that delivers Chrome policies directly to device registries via Intune Proactive Remediation scripts, completely bypassing the broken GP pipeline.

```
┌─────────────────────────────────────────────────────────────────┐
│                        ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐    ┌───────────┐    ┌──────────────────────────┐  │
│  │  Admin   │───▶│  REST API │◀───│  Intune Remediation      │  │
│  │  UI      │    │  (.NET 9) │    │  (PowerShell scripts)    │  │
│  │ (Blazor) │    └─────┬─────┘    └──────────────────────────┘  │
│  └──────────┘          │                                         │
│                   ┌────┴────┐                                    │
│                   │ SQL DB  │  ← PolicySets, Versions,           │
│                   │  (S2)   │    Assignments, DeviceState         │
│                   └────┬────┘                                    │
│                        │                                         │
│              ┌─────────┼─────────┐                               │
│              │         │         │                               │
│         ┌────┴────┐ ┌──┴───┐ ┌──┴──────────┐                   │
│         │ MS Graph│ │ Svc  │ │ Graph Change │                   │
│         │ (delta) │ │ Bus  │ │ Webhooks     │                   │
│         └─────────┘ └──────┘ └─────────────┘                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **ADMX Catalog Ingestion** | Parse Chrome ADMX/ADML templates → browse 700+ policies with descriptions, types, categories |
| **PolicySet Versioning** | Immutable versions (Draft → Active → Archived) with hash-based change detection |
| **Group-Based Targeting** | Assign policies to Entra ID security groups with priority-based conflict resolution |
| **Mandatory & Recommended** | Support both Chrome policy scopes per assignment |
| **Effective Policy Resolution** | Server resolves device → groups → assignments → merged settings (lower priority wins) |
| **Device Observability** | Real-time compliance dashboard, offline detection, error tracking |
| **Device Log Ingestion** | Centralized log collection from detection/remediation scripts with level filtering |
| **Policy Validation** | Schema-based validation of policy values against known Chrome policy types |
| **Intune Delivery** | Proactive Remediation hourly check → detect drift → apply policies via registry |
| **Inline Remediation** | Detection script optionally remediates drift without waiting for Intune remediation cycle |
| **Push Remediation Trigger** | Optional Windows-style push: cycle assignment group devices and invoke on-demand remediation commands (batched) |
| **Audit Trail** | Full audit logging for all policy changes and device interactions |

## 🏗️ Project Structure

```
ChromePolicyManager/
├── src/
│   ├── Server/
│   │   ├── ChromePolicyManager.Api/        # REST API (.NET 10 Minimal API)
│   │   │   ├── Data/                       # EF Core DbContext + models
│   │   │   ├── Endpoints/                  # Policy, Assignment, Device, Catalog, Monitoring, Webhook
│   │   │   ├── Middleware/                 # APIM Gateway authentication middleware
│   │   │   ├── Models/                     # PolicySet, Version, Assignment, CatalogEntry, DeviceLog
│   │   │   └── Services/                   # AdmxParser, EffectivePolicy, Graph, Reporting, Validator
│   │   └── ChromePolicyManager.Admin/      # Blazor Server Admin UI (MudBlazor)
│   │       └── Components/Pages/           # Dashboard, Catalog, Policies, Assignments, Devices
│   └── Client/
│       ├── Detect-ChromePolicy.ps1         # Intune detection script (supports inline remediation)
│       └── Remediate-ChromePolicy.ps1      # Intune remediation script
├── infra/
│   ├── Deploy.ps1                          # Unified deploy: infra (Bicep) + code (API + Admin)
│   ├── Deploy-Infrastructure.ps1           # Imperative az-CLI provisioning (alternative)
│   ├── main.bicep                          # Infrastructure-as-Code (Bicep), dev/prod SKU tiers
│   ├── main.dev.bicepparam                 # Dev parameters (cost-optimized SKUs)
│   ├── main.prod.bicepparam                # Prod parameters (production-grade SKUs)
│   └── apim/                               # API Management policies
└── tools/                                  # ADMX template downloads (gitignored)
```

## 🚀 Quick Start

### Prerequisites

- .NET 10 SDK
- Azure subscription (with Intune license for remediation)
- `az` CLI authenticated
- `gh` CLI (optional, for repo operations)

### 1. Deploy Infrastructure + Code

The unified `Deploy.ps1` script provisions the Azure infrastructure (Bicep) **and** builds/deploys the API + Admin code in one pass. SKUs are sized automatically per environment.

```powershell
cd infra

# Dev (cost-optimized SKUs)
.\Deploy.ps1 -EnvironmentName dev -ClientId <api-app-id> -ClientSecret (Read-Host -AsSecureString)

# Prod (production-grade SKUs, Service Bus enabled)
.\Deploy.ps1 -EnvironmentName prod -ClientId <api-app-id> -ClientSecret (Read-Host -AsSecureString)

# Preview infra changes without applying (Bicep what-if)
.\Deploy.ps1 -EnvironmentName prod -SkipCode -WhatIf
```

Useful switches: `-SkipInfra` (deploy code only), `-SkipCode` (deploy infra only), `-SubscriptionId`, `-Location`.

This creates: Resource Group, VNet (App Service VNet integration), SQL Server (Private Endpoint, Entra-only auth), App Service Plan + Web Apps (API + Admin), Key Vault, App Configuration, API Management, Application Insights, and (prod) Service Bus with Private Endpoint.

#### SKU tiers (dev vs prod)

| Resource | `dev` | `prod` |
|----------|-------|--------|
| App Service Plan | B1 (Basic) | P1v3 ×2 (PremiumV3) |
| SQL Database | Basic (5 DTU) | S2 (Standard, 50 DTU) |
| API Management | off (direct API) | Standard |
| App Configuration | Free | Standard |
| Service Bus | off by default | Standard (Private Endpoint) |
| Log Analytics retention | 30 days | 90 days |

The tier is selected by the `skuTier` Bicep parameter (defaults from `environmentName`) and the matching parameter files: `main.dev.bicepparam` / `main.prod.bicepparam`.

> **APIM in dev:** APIM is the most expensive fixed-cost resource (~€45/month). It is **off by default in dev** (`deployApim=false`). Devices then call the backend directly — set `CPM_USE_DIRECT_API=true` on the device and leave `ApimGateway:ClientId` unset so the backend middleware allows direct access. This skips mTLS, rate limiting and edge JWT validation, so device endpoints are unauthenticated in dev — acceptable for development, **not** for prod.

> **Note:** `Deploy-Infrastructure.ps1` (imperative az-CLI variant) remains available for step-by-step provisioning without Bicep.

### 2. Import Chrome Policy Catalog

Download the [Chrome ADMX templates](https://chromeenterprise.google/browser/download/#manage-policies-tab) and upload via the Admin UI or API:

```bash
# Via API (multipart upload)
curl -X POST https://your-api.azurewebsites.net/api/catalog/import \
  -F "admxZip=@policy_templates.zip" \
  -F "version=136.0"
```

### 3. Create Policy Sets

Use the Admin UI at `https://your-admin.azurewebsites.net/catalog` to:
1. Browse the catalog → filter by category/type → view descriptions
2. Select policies and configure values
3. Create PolicySets (e.g., "Security Baseline", "User Experience")
4. Add versions with specific settings
5. Assign to Entra ID groups with priority

### 4. Deploy Intune Remediation

The deployment script automatically creates a Proactive Remediation in Intune that:
- Runs **hourly** on targeted devices
- **Detects** drift by comparing local policy hash vs server hash
- **Remediates** by writing Chrome registry policies directly to `HKLM:\SOFTWARE\Policies\Google\Chrome`
- Supports **inline remediation** in the detection script (configurable via `$EnableInlineRemediation`) for faster drift correction without waiting for Intune's remediation cycle

## 🔧 API Endpoints

### Policy Catalog
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/catalog` | Browse policy catalog (filter: `?category=&search=&dataType=&recommended=`) |
| `GET` | `/api/catalog/{id}` | Get full details for a single catalog entry |
| `GET` | `/api/catalog/categories` | List available categories |
| `GET` | `/api/catalog/stats` | Import statistics |
| `POST` | `/api/catalog/import` | Import ADMX zip (multipart/form-data) |
| `POST` | `/api/catalog/import-from-url` | Download and import ADMX templates from a URL |
| `POST` | `/api/catalog/import-local` | Import ADMX from a local server path |

### Policy Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/policies` | List all PolicySets with versions |
| `GET` | `/api/policies/{id}` | Get a single PolicySet with its versions |
| `POST` | `/api/policies` | Create new PolicySet |
| `POST` | `/api/policies/{id}/versions` | Add version with settings JSON |
| `POST` | `/api/policies/versions/{id}/promote` | Promote Draft → Active |
| `POST` | `/api/policies/{id}/rollback/{versionId}` | Rollback to previous version |
| `POST` | `/api/policies/{id}/add-setting` | Add a single setting to the current draft |
| `GET` | `/api/policies/{id}/draft-settings` | Get settings from the current draft version |

### Assignments
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/assignments` | List all assignments |
| `POST` | `/api/assignments` | Create group assignment (priority + scope + optional push remediation) |
| `PUT` | `/api/assignments/{id}/priority` | Update assignment priority |
| `PUT` | `/api/assignments/{id}/push-remediation` | Enable/disable push remediation for assignment (optional immediate trigger) |
| `POST` | `/api/assignments/{id}/push-remediation/trigger` | Manually trigger push remediation command dispatch |
| `DELETE` | `/api/assignments/{id}` | Remove assignment |
| `GET` | `/api/groups/search` | Search Entra ID groups (for assignment UI) |

### Device Operations
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/devices/{id}/effective-policy` | Resolve effective policy for device (supports ETag/304) |
| `POST` | `/api/devices/{id}/report` | Device reports compliance status (202 Accepted) |
| `GET` | `/api/devices/{id}/history` | Get device compliance history |
| `POST` | `/api/devices/{id}/logs` | Batch ingest device logs (detection/remediation) |
| `GET` | `/api/devices/{id}/logs` | Query device logs (filter by level, script type) |

### Monitoring
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/monitoring/dashboard` | Compliance dashboard data |
| `GET` | `/api/monitoring/offline-devices` | Devices offline >24 hours |
| `GET` | `/api/monitoring/error-devices` | Devices with recent errors |

### Webhooks
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/webhooks/group-change` | Microsoft Graph change notification receiver |
| `GET` | `/api/webhooks/changed-groups` | List groups with pending membership changes |
| `POST` | `/api/webhooks/acknowledge/{groupId}` | Acknowledge a group change (clear dirty flag) |

### Health
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |

## 📊 How Policy Resolution Works

```
Client Device → API: "What policies apply to me?" (GET /devices/{id}/effective-policy)
                      │
                      ▼
              MS Graph: devices/{id}/memberOf → [Group1, Group2, ...]
                      │
                      ▼
              Match groups → Active PolicyAssignments
                      │
                      ▼
              Sort by Priority (ascending: lower = higher priority)
                      │
                      ▼
              Merge settings (first-writer-wins per key, separated by scope)
                      │
                      ▼
              Return: { mandatory: {...}, recommended: {...}, hash: "abc123" }
```

## 🔬 Root Cause Analysis

### Why Intune Settings Catalog Fails for Chrome

1. **Intune ADMX ingestion** writes to `HKLM\SOFTWARE\Microsoft\PolicyManager\providers\{GUID}\...`
2. This relies on **GP Client Service** to mirror to `HKLM\SOFTWARE\Policies\Google\Chrome`
3. On Entra ID–only devices, GP Client mirroring is **broken** (no `RegisterGPNotification`, no domain join)
4. Chrome reads **only** from `HKLM\SOFTWARE\Policies\Google\Chrome` — policies never arrive

### Why Direct Registry Write Works

- Chrome's `PolicyLoaderWin` reads `HKLM\SOFTWARE\Policies\Google\Chrome` **unconditionally**
- No domain-join check gates registry policy reading
- Chrome polls registry every 15 minutes (`kReloadInterval = base::Minutes(15)`)
- Entra ID–only devices get `FULLY_TRUSTED` management authority — no policy filtering

### Source Code Evidence (Chromium)

- `PolicyLoaderWin::InitOnBackgroundThread()` — requires `RegisterGPNotification()` success
- `mdm_utils.cc::IsEnrolledToDomain()` — GP registry path check fails on cloud-only devices
- `WinGPOListProvider` — depends on Active Directory infrastructure not present on Entra-only devices

## 🛡️ Security

### API Gateway (Azure API Management)

Device-facing endpoints are protected by **Azure API Management** acting as a security gateway. The backend API never receives unauthenticated device traffic.

```
┌──────────────┐     OAuth2 Token     ┌──────────────┐   Managed Identity   ┌──────────────┐
│   Device     │ ───────────────────▶ │    APIM      │ ────────────────────▶ │  Backend API │
│ (PowerShell) │                      │   Gateway    │                       │  (.NET 9)    │
└──────────────┘                      └──────────────┘                       └──────────────┘
                                            │
                                      ┌─────┴─────┐
                                      │ Validates  │
                                      │ device JWT │
                                      │ Rate limits│
                                      │ Strips     │
                                      │ spoofable  │
                                      │ headers    │
                                      └───────────┘
```

**Security flow:**
1. Device acquires OAuth2 token (client credentials + device certificate) from Entra ID
2. APIM validates JWT (issuer, audience, expiry, required claims)
3. APIM rate-limits per device identity (30 calls/hour/device)
4. APIM strips any client-supplied identity headers (anti-spoofing)
5. APIM sets trusted `X-Forwarded-Device-Id` from validated JWT claims
6. APIM authenticates to backend using its **managed identity** (no shared secrets)
7. Backend middleware verifies the request's `appid` claim matches APIM's identity

**Separation of concerns:**
| Layer | Responsibility |
|-------|---------------|
| APIM | Device auth, rate limiting, DDoS protection, request logging |
| Backend | Business logic, policy resolution, database, Graph API |
| Admin UI | Direct Entra ID JWT auth (doesn't go through APIM) |

### Additional Security Controls

- **Entra ID authentication** for Admin UI (interactive login)
- **Managed Identity** for all Azure resource access (no stored credentials)
- **Key Vault** for secrets (connection strings, Graph client secret)
- **Entra-only SQL auth** (no SQL passwords — MCAPS compliant)
- **Audit logging** for all policy changes and device interactions
- **CORS** restricted to Admin UI origin only
- **Service Bus** for async device report processing (202 Accepted pattern)
- **Backend restriction**: device endpoints reject calls not originating from APIM

## 📈 Scaling to 100k+ Devices

The solution is designed to handle large-scale enterprise environments (100,000+ devices) with minimal infrastructure cost. Three key optimizations make this possible:

### 1. ETag / 304 Not Modified

The `GET /devices/{id}/effective-policy` endpoint returns an `ETag` header containing the policy hash. On subsequent requests, the client sends `If-None-Match` with its cached hash:

```
Client → API: GET /effective-policy  (If-None-Match: "abc123")
API → Client: 304 Not Modified       ← No body, minimal compute

Only when policy actually changes:
Client → API: GET /effective-policy  (If-None-Match: "abc123")
API → Client: 200 OK + full payload  (ETag: "def456")
```

**Impact:** At 100k devices/hour with ~90% steady state → only ~10k full responses/hour carry a payload.

### 2. Graph Change Notifications (Webhooks)

Instead of calling Microsoft Graph for every device check-in (which would hit throttling limits at scale), the API subscribes to **real-time webhook notifications** for group membership changes:

```
┌─────────────┐     Webhook: "Group X changed"     ┌─────────────┐
│ Microsoft   │ ──────────────────────────────────▶ │  CPM API    │
│ Graph       │                                     │  (marks     │
└─────────────┘                                     │  group as   │
                                                    │  dirty)     │
                                                    └──────┬──────┘
                                                           │
Device check-in:                                           ▼
  - Device in Group X → Graph call (real-time, fresh data)
  - Device in Group Y (unchanged) → use cached membership
```

**Implementation:**
- `GroupChangeNotificationService` (BackgroundService) maintains subscriptions for all groups used in policy assignments
- Subscriptions auto-renew before the 4230-minute Graph limit (~3 days)
- `/api/webhooks/group-change` receives notifications and marks affected groups
- `WebhookEndpoints.HasGroupChanged()` allows the effective policy resolver to skip Graph calls for unchanged groups

**Impact:** Reduces Graph API calls from **100,000/hour** to **~50-100/hour** (only devices in groups that actually changed), while maintaining **zero-latency reactivity** — policy changes propagate within minutes, not hours like Intune.

### 3. Azure SQL S2 (50 DTU)

Upgraded from Basic (5 DTU) to Standard S2 to handle sustained write throughput:
- 100k device reports/hour = ~28 writes/sec sustained
- S2 provides 50 DTU → comfortable headroom for reads + writes + indexes

### Scaling Summary

| Metric | Without optimizations | With optimizations |
|--------|----------------------|-------------------|
| Graph API calls/hour | 100,000 (throttled) | 50-100 |
| Full policy responses/hour | 100,000 | ~10,000 |
| Network bandwidth/hour | ~500 MB | ~50 MB |
| SQL write pressure | 100k full reports | 100k lightweight + 10k full |
| Reactivity | N/A (was polling) | **Real-time** (webhook push) |

### Recommended SKUs for 100k+ Devices

The default Bicep deployment uses development-friendly SKUs. For production scale, upgrade to:

| Component | Default (Bicep) | Recommended (100k+) | Monthly Cost (est.) |
|-----------|----------------|---------------------|-------------------|
| App Service | B1 | S2 or P1v3 | €70-140 |
| Azure SQL | Basic (5 DTU) | S2 (50 DTU) | €60-150 |
| Service Bus | Basic | Standard | €10 |
| API Management | Developer | Consumption or Standard | €50-300 |
| App Configuration | Free | Standard | €35 |
| Total | | | **~€225-635/month** |

## 📦 Technology Stack

| Component | Technology |
|-----------|-----------|
| API | .NET 10, Minimal API, Entity Framework Core 10 |
| Admin UI | Blazor Server, MudBlazor 8 |
| Database | Azure SQL (Entra-only auth), SQLite fallback for development |
| Auth | Microsoft Identity Web 3.x, MSAL, Device Certificates |
| Group Resolution | Microsoft Graph SDK 5.x + Change Notifications |
| Messaging | Azure Service Bus (async device reports) |
| Config | Azure App Configuration |
| Secrets | Azure Key Vault |
| Observability | Azure Monitor OpenTelemetry |
| Hosting | Azure App Service (B1 default, scale to S2/P1v3) |
| API Gateway | Azure API Management (Developer SKU default) |
| Client | PowerShell 5.1 (Intune Proactive Remediation) |
| Policy Catalog | Chrome ADMX/ADML parser (700+ policies) |
| Validation | ChromePolicyValidator (schema validation for known policy types) |

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏷️ Keywords

`chrome-policy`, `intune`, `entra-id`, `azure-ad-joined`, `admx`, `group-policy-workaround`, `chrome-enterprise`, `mdm`, `proactive-remediation`, `browser-management`, `endpoint-management`, `registry-policy`, `blazor`, `dotnet`, `azure`

---

**Built to solve a real-world enterprise pain point — Chrome policy delivery on modern cloud-only managed devices where ADMX-based Settings Catalog fails silently.**
